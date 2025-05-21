#include "../tests.h"

int32_t curve25519_key_lshift_test(void) {
	printf("Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xFF9A7B152FDA9016ULL,
		0x9620DD3AF76A7618ULL,
		0xB181006439338D18ULL,
		0x50A234A8D4E3DD2CULL,
		0x20F786AF349D751CULL,
		0xD51FF6A4B2698DABULL,
		0x1306CEE0FDF1F531ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x80B0000000000000ULL,
		0xB0C7FCD3D8A97ED4ULL,
		0x68C4B106E9D7BB53ULL,
		0xE9658C080321C99CULL,
		0xA8E28511A546A71EULL,
		0x6D5907BC3579A4EBULL,
		0xA98EA8FFB525934CULL,
		0x000098367707EF8FULL
	}};
	int shift = 51;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE70AED73480C640EULL,
		0xAD36D4EA290FCD02ULL,
		0xC825BFACF0FE2BCDULL,
		0x38F855B7C50BE193ULL,
		0xE1C7A0EE21F6CC3BULL,
		0xCB6AC03E7E08CBB4ULL,
		0xE8654EE15473157BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAED73480C640E000ULL,
		0x6D4EA290FCD02E70ULL,
		0x5BFACF0FE2BCDAD3ULL,
		0x855B7C50BE193C82ULL,
		0x7A0EE21F6CC3B38FULL,
		0xAC03E7E08CBB4E1CULL,
		0x54EE15473157BCB6ULL,
		0x0000000000000E86ULL
	}};
	shift = 12;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45B9D4FBDA4B5D01ULL,
		0x3C560DF7967DE747ULL,
		0x37E6AE63FBF263B9ULL,
		0x50E42CCDC700AE5EULL,
		0xDA055ED24D734EABULL,
		0xC4439FDA270885DDULL,
		0x7F9C4709D8DEFC34ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE8080000000000ULL,
		0xEF3A3A2DCEA7DED2ULL,
		0x931DC9E2B06FBCB3ULL,
		0x0572F1BF35731FDFULL,
		0x9A755A8721666E38ULL,
		0x442EEED02AF6926BULL,
		0xF7E1A6221CFED138ULL,
		0x000003FCE2384EC6ULL
	}};
	shift = 43;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53893BCA2F696FA8ULL,
		0x2EE1E3D9AB5DEE1DULL,
		0xBF3498E962155533ULL,
		0x3624F7168E39B5CFULL,
		0x6E62280E60962F0EULL,
		0x978EB71AA5ADF909ULL,
		0xFEFD9AD3E3CA8E7AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EF28BDA5BEA0000ULL,
		0x78F66AD77B8754E2ULL,
		0x263A5885554CCBB8ULL,
		0x3DC5A38E6D73EFCDULL,
		0x8A0398258BC38D89ULL,
		0xADC6A96B7E425B98ULL,
		0x66B4F8F2A39EA5E3ULL,
		0x0000000000003FBFULL
	}};
	shift = 14;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51A3BD7F27AB3E08ULL,
		0x07F00F51ACAE4A7BULL,
		0xF7CBACE80595EA69ULL,
		0x0601A34DACFF319FULL,
		0x76A6C74267C98537ULL,
		0xD709E9EC090E80ECULL,
		0x27F77BF08D3BFF20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3477AFE4F567C10ULL,
		0x0FE01EA3595C94F6ULL,
		0xEF9759D00B2BD4D2ULL,
		0x0C03469B59FE633FULL,
		0xED4D8E84CF930A6EULL,
		0xAE13D3D8121D01D8ULL,
		0x4FEEF7E11A77FE41ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEB84133AA4B499BULL,
		0xC5424107C201211FULL,
		0xD1AD7B6F903365D2ULL,
		0xCFFD3BF3CF20558CULL,
		0x799D35203B7FD07DULL,
		0x36F2F3472DCCC5DBULL,
		0xC93369319A9C298BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB84133AA4B499BULL,
		0xC5424107C201211FULL,
		0xD1AD7B6F903365D2ULL,
		0xCFFD3BF3CF20558CULL,
		0x799D35203B7FD07DULL,
		0x36F2F3472DCCC5DBULL,
		0xC93369319A9C298BULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF801350E0CE9D649ULL,
		0x319E753CED7722C0ULL,
		0xC9052319711E46C9ULL,
		0x1D5509C2581247BEULL,
		0xDBAC836DAA5AEB61ULL,
		0xF99FBACDC451C225ULL,
		0xDCD0095E59FA19D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE004D43833A75924ULL,
		0xC679D4F3B5DC8B03ULL,
		0x24148C65C4791B24ULL,
		0x7554270960491EFBULL,
		0x6EB20DB6A96BAD84ULL,
		0xE67EEB3711470897ULL,
		0x7340257967E8675BULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35C53AEE5A1BAA56ULL,
		0xDD38A29209BF826AULL,
		0xCE04134CF2B8D36CULL,
		0xC488D26B01715179ULL,
		0x199897FD20C13015ULL,
		0xB24D168DC8EA41FFULL,
		0x4C447151E770DDDCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8A75DCB43754ACULL,
		0xBA714524137F04D4ULL,
		0x9C082699E571A6D9ULL,
		0x8911A4D602E2A2F3ULL,
		0x33312FFA4182602BULL,
		0x649A2D1B91D483FEULL,
		0x9888E2A3CEE1BBB9ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50FAB2BB68F86847ULL,
		0xAC14B2823E8E7048ULL,
		0xEDA1BA66A662A4C6ULL,
		0x9CAF4338F30ECC46ULL,
		0xEC88013B2FF9E8F1ULL,
		0x8A5F2B974AEB9295ULL,
		0x384E0FE1CF9AA1B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D08E0000000000ULL,
		0x1CE090A1F56576D1ULL,
		0xC5498D582965047DULL,
		0x1D988DDB4374CD4CULL,
		0xF3D1E3395E8671E6ULL,
		0xD7252BD91002765FULL,
		0x35436314BE572E95ULL,
		0x000000709C1FC39FULL
	}};
	shift = 41;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97CBF003021DE1FEULL,
		0xC324AC984D4B419CULL,
		0x19F340A9DC508EADULL,
		0x8BCFD3DA28B53893ULL,
		0x57409DE4FA02B1B5ULL,
		0x5F3ED662E76DE7ABULL,
		0x446F8B3593910499ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E006043BC3FC000ULL,
		0x959309A9683392F9ULL,
		0x68153B8A11D5B864ULL,
		0xFA7B4516A712633EULL,
		0x13BC9F405636B179ULL,
		0xDACC5CEDBCF56AE8ULL,
		0xF166B27220932BE7ULL,
		0x000000000000088DULL
	}};
	shift = 13;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75A635FF355883D8ULL,
		0x4B174DB017BEC2B3ULL,
		0xBF24CE8F4AF1EBAEULL,
		0xB97A081698595734ULL,
		0xD3AC19F7ADFD0D61ULL,
		0x8A1F9AFF6D7AC25DULL,
		0x58FD371752A7020AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5883D80000000000ULL,
		0xBEC2B375A635FF35ULL,
		0xF1EBAE4B174DB017ULL,
		0x595734BF24CE8F4AULL,
		0xFD0D61B97A081698ULL,
		0x7AC25DD3AC19F7ADULL,
		0xA7020A8A1F9AFF6DULL,
		0x00000058FD371752ULL
	}};
	shift = 40;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x643E2F73B722891FULL,
		0xD425638766D411C2ULL,
		0xF5DBD5ABD34E1F21ULL,
		0x6B3EB277A0F737DAULL,
		0xCD5F078F6EFC2326ULL,
		0xA7DD869F74731118ULL,
		0xF5A6B73B49961372ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C00000000000000ULL,
		0x0990F8BDCEDC8A24ULL,
		0x8750958E1D9B5047ULL,
		0x6BD76F56AF4D387CULL,
		0x99ACFAC9DE83DCDFULL,
		0x63357C1E3DBBF08CULL,
		0xCA9F761A7DD1CC44ULL,
		0x03D69ADCED26584DULL
	}};
	shift = 58;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5154E7CB7E3C426EULL,
		0xB99E8B8DF610451AULL,
		0x8CCB192E802A5DE8ULL,
		0x80BBE04781CC414AULL,
		0xF8954EC9906EE3B9ULL,
		0xCC8C76A506F562BFULL,
		0xE11F38DF049AACDFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E5BF1E213700000ULL,
		0x5C6FB08228D28AA7ULL,
		0xC9740152EF45CCF4ULL,
		0x023C0E620A546658ULL,
		0x764C83771DCC05DFULL,
		0xB52837AB15FFC4AAULL,
		0xC6F824D566FE6463ULL,
		0x00000000000708F9ULL
	}};
	shift = 19;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BED36F0E517FB19ULL,
		0xD10057FCD9B2DBABULL,
		0xBAC15B2BEA082224ULL,
		0x35B79E431CB022AEULL,
		0xA8990829E2B61CA6ULL,
		0xB0582ABA782C5606ULL,
		0x0970DF0629FA1455ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3945FEC640000000ULL,
		0x366CB6EADEFB4DBCULL,
		0xFA820889344015FFULL,
		0xC72C08ABAEB056CAULL,
		0x78AD87298D6DE790ULL,
		0x9E0B1581AA26420AULL,
		0x8A7E85156C160AAEULL,
		0x00000000025C37C1ULL
	}};
	shift = 30;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x438E59BF3F5377CEULL,
		0xAA123E00537BF66FULL,
		0x2516EAEA76547E3EULL,
		0xA073F19CA2D3B969ULL,
		0xFC41B4C504B15D1EULL,
		0x0E3095BC88B0F289ULL,
		0x171C1EF23863FF70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBE700000000000ULL,
		0xDFB37A1C72CDF9FAULL,
		0xA3F1F55091F0029BULL,
		0x9DCB4928B75753B2ULL,
		0x8AE8F5039F8CE516ULL,
		0x87944FE20DA62825ULL,
		0x1FFB807184ADE445ULL,
		0x000000B8E0F791C3ULL
	}};
	shift = 43;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92A403F81F05630CULL,
		0xFDE445A8C7CBBB9FULL,
		0x5867D54FA91BDE01ULL,
		0xC88D36A55B0976B7ULL,
		0xF0A5243E7CEBD97BULL,
		0x47640EC6A9FB93F2ULL,
		0xA1CA28635242DA51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5201FC0F82B18600ULL,
		0xF222D463E5DDCFC9ULL,
		0x33EAA7D48DEF00FEULL,
		0x469B52AD84BB5BACULL,
		0x52921F3E75ECBDE4ULL,
		0xB2076354FDC9F978ULL,
		0xE51431A9216D28A3ULL,
		0x0000000000000050ULL
	}};
	shift = 7;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F0E7B9DA248B4D5ULL,
		0x006A0A6B5B2BA7EFULL,
		0xBD538069F3E9805AULL,
		0xC865CA7D232EBCEEULL,
		0xC6DF7F21EC083C74ULL,
		0x88C345B5E39E693AULL,
		0x6BBC7DF3C1BFD359ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA248B4D5000000ULL,
		0x6B5B2BA7EF9F0E7BULL,
		0x69F3E9805A006A0AULL,
		0x7D232EBCEEBD5380ULL,
		0x21EC083C74C865CAULL,
		0xB5E39E693AC6DF7FULL,
		0xF3C1BFD35988C345ULL,
		0x00000000006BBC7DULL
	}};
	shift = 24;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98FE3DAD93619E11ULL,
		0x4F80754A3C2169F1ULL,
		0x4F1DFBEB13057748ULL,
		0x4459821857129A89ULL,
		0xDCF14B919BA95713ULL,
		0x1E82AF05ACE40230ULL,
		0x4F4B79B399F45C1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE3DAD93619E1100ULL,
		0x80754A3C2169F198ULL,
		0x1DFBEB130577484FULL,
		0x59821857129A894FULL,
		0xF14B919BA9571344ULL,
		0x82AF05ACE40230DCULL,
		0x4B79B399F45C1E1EULL,
		0x000000000000004FULL
	}};
	shift = 8;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1344CFAC4C11F359ULL,
		0x3430010C312F682BULL,
		0x8C72AA71112C2281ULL,
		0x5BD951A56D3C2C0AULL,
		0x0904D0F50608D241ULL,
		0x3873B615DD1358F5ULL,
		0xC4196935F830708AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFAC4C11F3590000ULL,
		0x010C312F682B1344ULL,
		0xAA71112C22813430ULL,
		0x51A56D3C2C0A8C72ULL,
		0xD0F50608D2415BD9ULL,
		0xB615DD1358F50904ULL,
		0x6935F830708A3873ULL,
		0x000000000000C419ULL
	}};
	shift = 16;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x85B6650D86111A97ULL,
		0x20830F6CA9112A62ULL,
		0xCD2B2B991EC5DAD7ULL,
		0xC5015C55379DF13BULL,
		0xAB5EFCE711D59584ULL,
		0x9AB274191A113E20ULL,
		0x0FF7A755A6424320ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4B8000000000000ULL,
		0x53142DB3286C3088ULL,
		0xD6B904187B654889ULL,
		0x89DE69595CC8F62EULL,
		0xAC26280AE2A9BCEFULL,
		0xF1055AF7E7388EACULL,
		0x1904D593A0C8D089ULL,
		0x00007FBD3AAD3212ULL
	}};
	shift = 51;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x688E495021EAECB8ULL,
		0xE8D6AF0492A68C1FULL,
		0x834BD90016F51796ULL,
		0x2BC16AA17D1E5F53ULL,
		0x3BAD42E1F69D2855ULL,
		0x5EEF63BD01ECF941ULL,
		0x6D4452A54138D5DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0x7DA239254087ABB2ULL,
		0x5BA35ABC124A9A30ULL,
		0x4E0D2F64005BD45EULL,
		0x54AF05AA85F4797DULL,
		0x04EEB50B87DA74A1ULL,
		0x757BBD8EF407B3E5ULL,
		0x01B5114A9504E357ULL
	}};
	shift = 58;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x901D97062A021E2DULL,
		0xB4A40CEDBB4AA85BULL,
		0x67E8DDE1FA59E79FULL,
		0x9B078CB87C5B6688ULL,
		0xE6B036C7B029D0A4ULL,
		0x87501829720E348EULL,
		0xF8E05D1DA25BA6D4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B40000000000000ULL,
		0x16E40765C18A8087ULL,
		0xE7ED29033B6ED2AAULL,
		0xA219FA37787E9679ULL,
		0x2926C1E32E1F16D9ULL,
		0x23B9AC0DB1EC0A74ULL,
		0xB521D4060A5C838DULL,
		0x003E3817476896E9ULL
	}};
	shift = 54;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB76900332E4D5E3ULL,
		0xD618B1148A8823DDULL,
		0x33AA9D0C05371E19ULL,
		0x889E80074CCA3876ULL,
		0xCE90C4B5DCD1BAC7ULL,
		0xBFFBF518807ECF9EULL,
		0xE23E9A37E30E67E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00CCB93578C00000ULL,
		0x4522A208F76ADDA4ULL,
		0x43014DC78675862CULL,
		0x01D3328E1D8CEAA7ULL,
		0x2D77346EB1E227A0ULL,
		0x46201FB3E7B3A431ULL,
		0x8DF8C399F8EFFEFDULL,
		0x0000000000388FA6ULL
	}};
	shift = 22;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF726EFA7645D0FBFULL,
		0x4873D36F7ACD50DCULL,
		0x95DF26F985DAC899ULL,
		0x252698F41E38D6ACULL,
		0x0FE1940371FCE639ULL,
		0xA7F2840CCFEB14F5ULL,
		0x9A9250FB84C841E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B22E87DF8000000ULL,
		0x7BD66A86E7B9377DULL,
		0xCC2ED644CA439E9BULL,
		0xA0F1C6B564AEF937ULL,
		0x1B8FE731C92934C7ULL,
		0x667F58A7A87F0CA0ULL,
		0xDC26420F2D3F9420ULL,
		0x0000000004D49287ULL
	}};
	shift = 27;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x958DBA8ECB8380BCULL,
		0xA66A6476EC09C6B0ULL,
		0x1395B2F254746C9AULL,
		0x90AA2A0510A47A06ULL,
		0x3507EB35339345C9ULL,
		0x1984FE869E6F333AULL,
		0xAE4BCDBA95225C9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x12B1B751D9707017ULL,
		0x54CD4C8EDD8138D6ULL,
		0xC272B65E4A8E8D93ULL,
		0x32154540A2148F40ULL,
		0x46A0FD66A67268B9ULL,
		0x83309FD0D3CDE667ULL,
		0x15C979B752A44B93ULL
	}};
	shift = 61;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DA85212726BED69ULL,
		0xBDD93BE6EDEBFFB4ULL,
		0xB5C22E46A648ADA0ULL,
		0xEDA26BFCAC57D70EULL,
		0xBC2E068D841439AEULL,
		0x0A90802F28D5BEC0ULL,
		0x01EE37A9B76B58A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB5A400000000000ULL,
		0xFFED036A14849C9AULL,
		0x2B682F764EF9BB7AULL,
		0xF5C3AD708B91A992ULL,
		0x0E6BBB689AFF2B15ULL,
		0x6FB02F0B81A36105ULL,
		0xD62842A4200BCA35ULL,
		0x0000007B8DEA6DDAULL
	}};
	shift = 46;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC31C05B9B0C6074ULL,
		0xC89AC7BDC27E664CULL,
		0x33C546419AB83E68ULL,
		0xB77AC0F876344038ULL,
		0x98AD5AD1B1756E8FULL,
		0xE23088405AD520DDULL,
		0x4888BF8F00C17CFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x303A000000000000ULL,
		0x33265E18E02DCD86ULL,
		0x1F34644D63DEE13FULL,
		0x201C19E2A320CD5CULL,
		0xB747DBBD607C3B1AULL,
		0x906ECC56AD68D8BAULL,
		0xBE7D711844202D6AULL,
		0x000024445FC78060ULL
	}};
	shift = 47;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA419ACE76CAC5D25ULL,
		0x821C08FC147D8218ULL,
		0xFCE1C8CA516F597BULL,
		0xFA138E7A8645D486ULL,
		0x34825D64453A1DC0ULL,
		0x8B79ADAA289CBB27ULL,
		0x696A659785C6D02BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4940000000000000ULL,
		0x8629066B39DB2B17ULL,
		0x5EE087023F051F60ULL,
		0x21BF387232945BD6ULL,
		0x703E84E39EA19175ULL,
		0xC9CD209759114E87ULL,
		0x0AE2DE6B6A8A272EULL,
		0x001A5A9965E171B4ULL
	}};
	shift = 54;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFC6668BEED42D7FULL,
		0xD9F567E3D6DC3E27ULL,
		0xD13333ED8E921C53ULL,
		0xB3CD4CFDCB230648ULL,
		0xC4318143466553D2ULL,
		0x06CAD3ADBE8EA50AULL,
		0x1A05764AB986E5BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BEED42D7F000000ULL,
		0xE3D6DC3E27EFC666ULL,
		0xED8E921C53D9F567ULL,
		0xFDCB230648D13333ULL,
		0x43466553D2B3CD4CULL,
		0xADBE8EA50AC43181ULL,
		0x4AB986E5BF06CAD3ULL,
		0x00000000001A0576ULL
	}};
	shift = 24;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0892F7B45ABC0B38ULL,
		0x77495173957F1D63ULL,
		0xC95CFF94852E6E38ULL,
		0x2478FC46CDD2A8E9ULL,
		0x034CA28202E399E2ULL,
		0xE464B947FF746031ULL,
		0x71BB3883A8461905ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF68B578167000000ULL,
		0x2E72AFE3AC61125EULL,
		0xF290A5CDC70EE92AULL,
		0x88D9BA551D392B9FULL,
		0x50405C733C448F1FULL,
		0x28FFEE8C06206994ULL,
		0x107508C320BC8C97ULL,
		0x00000000000E3767ULL
	}};
	shift = 21;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECBA1A0082CD545DULL,
		0xF3152A14E4FF6C26ULL,
		0x5075205B8EE55BBAULL,
		0x94F29CC845E945ADULL,
		0x29282F4FE33FACE8ULL,
		0xE910CA12095475CFULL,
		0xFFA6BEB2F80074EFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E868020B3551740ULL,
		0xC54A85393FDB09BBULL,
		0x1D4816E3B956EEBCULL,
		0x3CA732117A516B54ULL,
		0x4A0BD3F8CFEB3A25ULL,
		0x44328482551D73CAULL,
		0xE9AFACBE001D3BFAULL,
		0x000000000000003FULL
	}};
	shift = 6;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C7A0D2CD51F0911ULL,
		0x55A9101CD9065602ULL,
		0x5157E7BA9A8C1651ULL,
		0x18760D71095236F3ULL,
		0x979F70FC68C0EDC6ULL,
		0x7CA854E066EB0AF3ULL,
		0xB48180047137AB11ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9110000000000000ULL,
		0x6025C7A0D2CD51F0ULL,
		0x65155A9101CD9065ULL,
		0x6F35157E7BA9A8C1ULL,
		0xDC618760D7109523ULL,
		0xAF3979F70FC68C0EULL,
		0xB117CA854E066EB0ULL,
		0x000B48180047137AULL
	}};
	shift = 52;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A2C2A4CD29D0229ULL,
		0x3A5ABCBCA3E74179ULL,
		0x855EEA7FF5F1F0ACULL,
		0x68637AE336DC1B02ULL,
		0xC79B88BA976C1B75ULL,
		0x3BF55C0375D8A61EULL,
		0x59305B77C22C0FD3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x694E811480000000ULL,
		0x51F3A0BC95161526ULL,
		0xFAF8F8561D2D5E5EULL,
		0x9B6E0D8142AF753FULL,
		0x4BB60DBAB431BD71ULL,
		0xBAEC530F63CDC45DULL,
		0xE11607E99DFAAE01ULL,
		0x000000002C982DBBULL
	}};
	shift = 31;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0BA440D619F9BCFULL,
		0x4133FCA63F8876D7ULL,
		0x0352D406B714CFC2ULL,
		0x6690F30FEFEC36BAULL,
		0x76BF1ABB0E952A4EULL,
		0x9836C1D2D0C350CEULL,
		0xE76F748E2B5830E8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA440D619F9BCF000ULL,
		0x3FCA63F8876D7E0BULL,
		0x2D406B714CFC2413ULL,
		0x0F30FEFEC36BA035ULL,
		0xF1ABB0E952A4E669ULL,
		0x6C1D2D0C350CE76BULL,
		0xF748E2B5830E8983ULL,
		0x0000000000000E76ULL
	}};
	shift = 12;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD120A57B3811DB2ULL,
		0x7F0A5811773C888FULL,
		0xA50C8ADDFA07157CULL,
		0x573872ED56C78D4BULL,
		0x912BBD9AD0475FDDULL,
		0x8669A0261EA8617BULL,
		0x76BC78F0E5DFFC91ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295ECE0476C80000ULL,
		0x6045DCF2223EB448ULL,
		0x2B77E81C55F1FC29ULL,
		0xCBB55B1E352E9432ULL,
		0xF66B411D7F755CE1ULL,
		0x80987AA185EE44AEULL,
		0xE3C3977FF24619A6ULL,
		0x000000000001DAF1ULL
	}};
	shift = 18;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC1AC705BB6E3B96ULL,
		0xB4675065FB476AC9ULL,
		0xAC0F0D437891D3D1ULL,
		0x2BF58FD7913C264EULL,
		0x1411DD38EE1079E3ULL,
		0xAF54ECB99D6603DBULL,
		0xCD30EA75840496F8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E3B96000000000ULL,
		0xB476AC9CC1AC705BULL,
		0x891D3D1B4675065FULL,
		0x13C264EAC0F0D437ULL,
		0xE1079E32BF58FD79ULL,
		0xD6603DB1411DD38EULL,
		0x40496F8AF54ECB99ULL,
		0x0000000CD30EA758ULL
	}};
	shift = 36;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x355B69489BA59205ULL,
		0x8882F8393CD96E00ULL,
		0x391E3285EC20D19BULL,
		0xB7AD7B4A598A1443ULL,
		0x7A13C1B829C4B335ULL,
		0x81E2C01CE57F5753ULL,
		0x68170B1F9079A35DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2050000000000000ULL,
		0xE00355B69489BA59ULL,
		0x19B8882F8393CD96ULL,
		0x443391E3285EC20DULL,
		0x335B7AD7B4A598A1ULL,
		0x7537A13C1B829C4BULL,
		0x35D81E2C01CE57F5ULL,
		0x00068170B1F9079AULL
	}};
	shift = 52;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5F36670E2E905F3ULL,
		0xD274B0FE5E4135EDULL,
		0x2E4AB3089362A6A5ULL,
		0xB9EACD41B714295BULL,
		0x4F1CEF21601B4398ULL,
		0x091A2929815275BEULL,
		0xF1AF433C5AF1554DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE905F30000000000ULL,
		0x4135EDF5F36670E2ULL,
		0x62A6A5D274B0FE5EULL,
		0x14295B2E4AB30893ULL,
		0x1B4398B9EACD41B7ULL,
		0x5275BE4F1CEF2160ULL,
		0xF1554D091A292981ULL,
		0x000000F1AF433C5AULL
	}};
	shift = 40;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EAA88C4268B299DULL,
		0xAE9C2505718DD40FULL,
		0x392091F7EB4CB18BULL,
		0x957D73F1A4050852ULL,
		0x2A62849FE19D78F1ULL,
		0x033B7210B3C53505ULL,
		0x784A17FF753B4BA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x884D16533A000000ULL,
		0x0AE31BA81F3D5511ULL,
		0xEFD69963175D384AULL,
		0xE3480A10A4724123ULL,
		0x3FC33AF1E32AFAE7ULL,
		0x21678A6A0A54C509ULL,
		0xFEEA7697480676E4ULL,
		0x0000000000F0942FULL
	}};
	shift = 25;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB13C648DD9078CAEULL,
		0xB2CAA52C45E4412EULL,
		0x64D05209BE58DE0BULL,
		0x79EFA4C906DB6498ULL,
		0xD19F5BB5AD7D9891ULL,
		0x84CC69EE50A86777ULL,
		0x90F6F7AC22D6E7BAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DD9078CAE000000ULL,
		0x2C45E4412EB13C64ULL,
		0x09BE58DE0BB2CAA5ULL,
		0xC906DB649864D052ULL,
		0xB5AD7D989179EFA4ULL,
		0xEE50A86777D19F5BULL,
		0xAC22D6E7BA84CC69ULL,
		0x000000000090F6F7ULL
	}};
	shift = 24;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68301CC9B7168972ULL,
		0x6468C9B588D97492ULL,
		0xDAABA6C943A7D0C7ULL,
		0xD945E7E793F0E69BULL,
		0xF7B4D8B5E3A124C7ULL,
		0x8F062C580B97AB73ULL,
		0x35E644FE0ADD38D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB8B44B90000000ULL,
		0xAC46CBA4934180E6ULL,
		0x4A1D3E863B23464DULL,
		0x3C9F8734DED55D36ULL,
		0xAF1D09263ECA2F3FULL,
		0xC05CBD5B9FBDA6C5ULL,
		0xF056E9C684783162ULL,
		0x0000000001AF3227ULL
	}};
	shift = 27;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD60E8D70881197AFULL,
		0x6481B2BB25CA51A5ULL,
		0x09C6C21608FABBBBULL,
		0xDFF51C49E6238344ULL,
		0x84977CB497CD9E2EULL,
		0xF80F8A95EB0BD2A1ULL,
		0x5B672E3ADECA1452ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408CBD7800000000ULL,
		0x2E528D2EB0746B84ULL,
		0x47D5DDDB240D95D9ULL,
		0x311C1A204E3610B0ULL,
		0xBE6CF176FFA8E24FULL,
		0x585E950C24BBE5A4ULL,
		0xF650A297C07C54AFULL,
		0x00000002DB3971D6ULL
	}};
	shift = 35;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42313D5934D8A0BAULL,
		0x827872038334EF8BULL,
		0x82051E70735E5313ULL,
		0x9B83A0978E5021DBULL,
		0xA1019EF7FDA0048AULL,
		0x5B6B07DE3855CBDDULL,
		0x74E670B787D922FAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505D000000000000ULL,
		0x77C5A1189EAC9A6CULL,
		0x2989C13C3901C19AULL,
		0x10EDC1028F3839AFULL,
		0x02454DC1D04BC728ULL,
		0xE5EED080CF7BFED0ULL,
		0x917D2DB583EF1C2AULL,
		0x00003A73385BC3ECULL
	}};
	shift = 47;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB57D2882F98ECF8ULL,
		0xCA3CCD92956822BEULL,
		0xBD0A425CEF2382ABULL,
		0x7DE16CEDF548AED8ULL,
		0xF40170515F1D7625ULL,
		0xECD01FFFCE220D77ULL,
		0x48EA37706F3D2C36ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDF6AFA5105F31D9FULL,
		0x794799B252AD0457ULL,
		0x17A1484B9DE47055ULL,
		0xAFBC2D9DBEA915DBULL,
		0xFE802E0A2BE3AEC4ULL,
		0xDD9A03FFF9C441AEULL,
		0x091D46EE0DE7A586ULL
	}};
	shift = 61;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x589C84B4E9D1953AULL,
		0x355B9847BAA93267ULL,
		0x02A2B7FFEE7AF58EULL,
		0xA001F75F822364DFULL,
		0x691922C761EC2815ULL,
		0xA18800820D678B22ULL,
		0x784FD364EBFA2C52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0969D3A32A740000ULL,
		0x308F755264CEB139ULL,
		0x6FFFDCF5EB1C6AB7ULL,
		0xEEBF0446C9BE0545ULL,
		0x458EC3D8502B4003ULL,
		0x01041ACF1644D232ULL,
		0xA6C9D7F458A54310ULL,
		0x000000000000F09FULL
	}};
	shift = 17;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A807FD3E5145CCBULL,
		0xF2BF8BAA0D76389BULL,
		0x2341E2A1E4885FAEULL,
		0x25EA83A045BF883FULL,
		0xDD4FCFFA641FC39DULL,
		0xF760DC13B0AB2C86ULL,
		0xA0B47C1036DEFD20ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA28B99600000000ULL,
		0x1AEC71365500FFA7ULL,
		0xC910BF5DE57F1754ULL,
		0x8B7F107E4683C543ULL,
		0xC83F873A4BD50740ULL,
		0x6156590DBA9F9FF4ULL,
		0x6DBDFA41EEC1B827ULL,
		0x000000014168F820ULL
	}};
	shift = 33;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC73A6F7C8F0182E9ULL,
		0xEF3BBC4090F48A3CULL,
		0xD62BFE0B7E428279ULL,
		0x50EB5181F762F4F1ULL,
		0x7400FAB003A41320ULL,
		0x9D454647954EA981ULL,
		0xA84CF9EA5806BE46ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD200000000000000ULL,
		0x798E74DEF91E0305ULL,
		0xF3DE77788121E914ULL,
		0xE3AC57FC16FC8504ULL,
		0x40A1D6A303EEC5E9ULL,
		0x02E801F560074826ULL,
		0x8D3A8A8C8F2A9D53ULL,
		0x015099F3D4B00D7CULL
	}};
	shift = 57;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06ADF3B1F43433B6ULL,
		0x143690F95DC5AD95ULL,
		0x529C51EF0825BFBCULL,
		0xA2E866CF44C78F4FULL,
		0xEB077E5BDFC075D3ULL,
		0x7B024061180B790DULL,
		0xE37A47E69D2D2044ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A19DB000000000ULL,
		0xEE2D6CA8356F9D8FULL,
		0x412DFDE0A1B487CAULL,
		0x263C7A7A94E28F78ULL,
		0xFE03AE9D1743367AULL,
		0xC05BC86F583BF2DEULL,
		0xE9690223D8120308ULL,
		0x000000071BD23F34ULL
	}};
	shift = 35;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7105D517E3416519ULL,
		0x82559152C7316108ULL,
		0x418D1EAA6F8AA478ULL,
		0x2A0A808A8587F9A4ULL,
		0x22ECAB0FA08DC8EEULL,
		0x734B368C20099BCBULL,
		0xF10B8B507E8448BBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D05946400000000ULL,
		0x1CC58421C417545FULL,
		0xBE2A91E20956454BULL,
		0x161FE69106347AA9ULL,
		0x823723B8A82A022AULL,
		0x80266F2C8BB2AC3EULL,
		0xFA1122EDCD2CDA30ULL,
		0x00000003C42E2D41ULL
	}};
	shift = 34;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91426F9B0DAED01AULL,
		0xE1DA157D8520B2C2ULL,
		0x08D4FCD841795133ULL,
		0x64E630609670E5B4ULL,
		0xDD219919C2E5F642ULL,
		0x594589C6AC747D47ULL,
		0x3EFE24612FFC2943ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7680D00000000000ULL,
		0x0596148A137CD86DULL,
		0xCA899F0ED0ABEC29ULL,
		0x872DA046A7E6C20BULL,
		0x2FB21327318304B3ULL,
		0xA3EA3EE90CC8CE17ULL,
		0xE14A1ACA2C4E3563ULL,
		0x000001F7F123097FULL
	}};
	shift = 43;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8DDFF023CFE6A36ULL,
		0xF5ACF1DBF49F3053ULL,
		0x58CAD968890B5E50ULL,
		0xCEEC569C673044D7ULL,
		0x53209209C49FBDE7ULL,
		0x95DDB1D661B1EDD3ULL,
		0x0AC4CF449FBB824BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FC08F3F9A8D800ULL,
		0xB3C76FD27CC14FE3ULL,
		0x2B65A2242D7943D6ULL,
		0xB15A719CC1135D63ULL,
		0x824827127EF79F3BULL,
		0x76C75986C7B74D4CULL,
		0x133D127EEE092E57ULL,
		0x000000000000002BULL
	}};
	shift = 10;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA9FC081E716A749ULL,
		0x3171FDA2981CF343ULL,
		0xD2916295880B4397ULL,
		0x9480F57C23B621C1ULL,
		0xD5FA1BEEC3DF96C2ULL,
		0xE34EAAED7948C539ULL,
		0x2722010026C3D4F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x7753F8103CE2D4E9ULL,
		0xE62E3FB453039E68ULL,
		0x3A522C52B1016872ULL,
		0x52901EAF8476C438ULL,
		0x3ABF437DD87BF2D8ULL,
		0x3C69D55DAF2918A7ULL,
		0x04E4402004D87A9EULL
	}};
	shift = 61;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3D86E7221CBC214ULL,
		0x6E3C9CB8CA7405E0ULL,
		0x72913344E498165FULL,
		0x40519E0A8F1E48EBULL,
		0x18BDD5E0643DACE6ULL,
		0xCE8ED4CB79B372EFULL,
		0x950298533D1539CFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4397842800000000ULL,
		0x94E80BC1A7B0DCE4ULL,
		0xC9302CBEDC793971ULL,
		0x1E3C91D6E5226689ULL,
		0xC87B59CC80A33C15ULL,
		0xF366E5DE317BABC0ULL,
		0x7A2A739F9D1DA996ULL,
		0x000000012A0530A6ULL
	}};
	shift = 33;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF3015DEA70E8D09ULL,
		0xB29EE1982AD064FFULL,
		0xC5AD002E2013D06CULL,
		0xFD4EBB33B7FEE379ULL,
		0xF04237384F413837ULL,
		0xD1CC0A3242B0A22DULL,
		0xC079F1E25E24DB7DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3015DEA70E8D090ULL,
		0x29EE1982AD064FFAULL,
		0x5AD002E2013D06CBULL,
		0xD4EBB33B7FEE379CULL,
		0x04237384F413837FULL,
		0x1CC0A3242B0A22DFULL,
		0x079F1E25E24DB7DDULL,
		0x000000000000000CULL
	}};
	shift = 4;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD93AC5BEA05F7BAULL,
		0xA190582B3600F104ULL,
		0xDC6D4E7FBC0CAAC7ULL,
		0xF6D912D3815688F4ULL,
		0x5D3CE2B1674BAC95ULL,
		0xEC4D4F534304B3D6ULL,
		0x65C1F80F395F0D6BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF502FBDD0000000ULL,
		0x59B00788266C9D62ULL,
		0xFDE065563D0C82C1ULL,
		0x9C0AB447A6E36A73ULL,
		0x8B3A5D64AFB6C896ULL,
		0x9A18259EB2E9E715ULL,
		0x79CAF86B5F626A7AULL,
		0x00000000032E0FC0ULL
	}};
	shift = 27;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1326A03254D2B082ULL,
		0x265CA0D0F496ADC5ULL,
		0x6FABA3FF33E92F2FULL,
		0x097CC702450EF36AULL,
		0x7FAB086A238D77FFULL,
		0x2B385C188131EF47ULL,
		0x5047F2810C23D246ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4064A9A56104000ULL,
		0x941A1E92D5B8A264ULL,
		0x747FE67D25E5E4CBULL,
		0x98E048A1DE6D4DF5ULL,
		0x610D4471AEFFE12FULL,
		0x0B8310263DE8EFF5ULL,
		0xFE5021847A48C567ULL,
		0x0000000000000A08ULL
	}};
	shift = 13;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FBD4AFD3D3429B2ULL,
		0x1C5509101AE80D05ULL,
		0x9C306E3C6EC6B643ULL,
		0x12CB6A79707286DFULL,
		0x8171BF20A82DF0CDULL,
		0x0ACD05585AB57065ULL,
		0xB21A0743E59C7CE8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8FDEA57E9E9A14D9ULL,
		0x8E2A84880D740682ULL,
		0xCE18371E37635B21ULL,
		0x8965B53CB839436FULL,
		0xC0B8DF905416F866ULL,
		0x056682AC2D5AB832ULL,
		0x590D03A1F2CE3E74ULL
	}};
	shift = 63;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AEEDCF6355A62AEULL,
		0xB6F3A88DE3A0CD48ULL,
		0x2A303AFBF783B7FDULL,
		0xA878BCE91003D17CULL,
		0x933FB4A1379CDC2BULL,
		0xC60A22D184794AC3ULL,
		0x27957956DE3529F2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB9EC6AB4C55C000ULL,
		0x7511BC7419A90F5DULL,
		0x075F7EF076FFB6DEULL,
		0x179D22007A2F8546ULL,
		0xF69426F39B85750FULL,
		0x445A308F29587267ULL,
		0xAF2ADBC6A53E58C1ULL,
		0x00000000000004F2ULL
	}};
	shift = 13;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A11B3DC93692015ULL,
		0xABFBB88796FDC0E0ULL,
		0x41A4EF7083C1662DULL,
		0x70A8F29566866F45ULL,
		0xEA9A933936102D46ULL,
		0x1A6A049BBEB79EA6ULL,
		0x821995DF8BC16FF3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB926D2402A000000ULL,
		0x0F2DFB81C0F42367ULL,
		0xE10782CC5B57F771ULL,
		0x2ACD0CDE8A8349DEULL,
		0x726C205A8CE151E5ULL,
		0x377D6F3D4DD53526ULL,
		0xBF1782DFE634D409ULL,
		0x000000000104332BULL
	}};
	shift = 25;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B5CE78099521328ULL,
		0x9CEEB1A7A3B542ECULL,
		0x649BA66EE9CB8EDEULL,
		0xA67C01CC3A3ECAD4ULL,
		0x615B2B3B26641755ULL,
		0x9352BD695C2552B5ULL,
		0xFDD3DB646C3FB242ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5000000000000000ULL,
		0xD856B9CF0132A426ULL,
		0xBD39DD634F476A85ULL,
		0xA8C9374CDDD3971DULL,
		0xAB4CF80398747D95ULL,
		0x6AC2B656764CC82EULL,
		0x8526A57AD2B84AA5ULL,
		0x01FBA7B6C8D87F64ULL
	}};
	shift = 57;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2E06C6E3B1D3673ULL,
		0x6142969A82A70B65ULL,
		0x3D6F5DEFB999C982ULL,
		0xF9646E0098C9614FULL,
		0x64B7E7EA2740EB4CULL,
		0xDE2CA591D6EDBD2CULL,
		0x9B58D6AF95D56E6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B8EC74D9CC0000ULL,
		0x5A6A0A9C2D968B81ULL,
		0x77BEE6672609850AULL,
		0xB8026325853CF5BDULL,
		0x9FA89D03AD33E591ULL,
		0x96475BB6F4B192DFULL,
		0x5ABE5755B9BB78B2ULL,
		0x0000000000026D63ULL
	}};
	shift = 18;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8883253F3BEE05FULL,
		0x26B94017698B7A1BULL,
		0x5343A268EDA7D1E8ULL,
		0x93102B099422C6FCULL,
		0x6C3169C4E9D64D41ULL,
		0xDB6ACA763E66905DULL,
		0x1F0C4B0A0ADCE881ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F80000000000000ULL,
		0x0DE4441929F9DF70ULL,
		0xF4135CA00BB4C5BDULL,
		0x7E29A1D13476D3E8ULL,
		0xA0C9881584CA1163ULL,
		0x2EB618B4E274EB26ULL,
		0x40EDB5653B1F3348ULL,
		0x000F862585056E74ULL
	}};
	shift = 55;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B5F9F5970C27151ULL,
		0xE72F6C91C869DB5DULL,
		0xB9A9D3847AD0C3D0ULL,
		0xC97F152B59A9EAE4ULL,
		0x429E2BCC028C7A49ULL,
		0xAEC83B01E3367920ULL,
		0xF1DE28929727C3B9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA880000000000000ULL,
		0xAEC5AFCFACB86138ULL,
		0xE87397B648E434EDULL,
		0x725CD4E9C23D6861ULL,
		0x24E4BF8A95ACD4F5ULL,
		0x90214F15E601463DULL,
		0xDCD7641D80F19B3CULL,
		0x0078EF14494B93E1ULL
	}};
	shift = 55;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AFBAAEB6FD28657ULL,
		0x51A01EA6A4BC841DULL,
		0x7E08999F8128DDECULL,
		0x97DA5FA44E166E35ULL,
		0x23EABFFD737FED48ULL,
		0x8A5E8EA6B27AC2EBULL,
		0x6E5FC4B600ACBD42ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C00000000000000ULL,
		0x74ABEEABADBF4A19ULL,
		0xB146807A9A92F210ULL,
		0xD5F822667E04A377ULL,
		0x225F697E913859B8ULL,
		0xAC8FAAFFF5CDFFB5ULL,
		0x0A297A3A9AC9EB0BULL,
		0x01B97F12D802B2F5ULL
	}};
	shift = 58;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91409DA31968DAF2ULL,
		0xC8CABCED60F3765DULL,
		0xE9EF3035DD41AC36ULL,
		0xD9D39E2E3682FCBFULL,
		0xD5894B230CC674E5ULL,
		0x1EEBF7ACD422AEA0ULL,
		0xC4AC19742256A8AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA04ED18CB46D7900ULL,
		0x655E76B079BB2EC8ULL,
		0xF7981AEEA0D61B64ULL,
		0xE9CF171B417E5FF4ULL,
		0xC4A59186633A72ECULL,
		0x75FBD66A1157506AULL,
		0x560CBA112B54578FULL,
		0x0000000000000062ULL
	}};
	shift = 7;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B2370480E07E99FULL,
		0x41B262FB32581615ULL,
		0x5D4FEEBFADC4C212ULL,
		0x5B8469E30D420BDEULL,
		0x954CFFA5E1721869ULL,
		0x8B8477CCF2B362D0ULL,
		0x7E120F3E83934AD6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0901C0FD33E00000ULL,
		0x5F664B02C2A1646EULL,
		0xD7F5B8984248364CULL,
		0x3C61A8417BCBA9FDULL,
		0xF4BC2E430D2B708DULL,
		0xF99E566C5A12A99FULL,
		0xE7D072695AD1708EULL,
		0x00000000000FC241ULL
	}};
	shift = 21;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C02965AD9FE0186ULL,
		0x8057C0AD9396B6ADULL,
		0x61AFF041DCD293ADULL,
		0xFF496C3BE58E27DDULL,
		0x5B333CADE18AC3A7ULL,
		0xCDAAF48294B4B432ULL,
		0x4C7C2630EEA7FAD6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C00000000000000ULL,
		0x5B18052CB5B3FC03ULL,
		0x5B00AF815B272D6DULL,
		0xBAC35FE083B9A527ULL,
		0x4FFE92D877CB1C4FULL,
		0x64B666795BC31587ULL,
		0xAD9B55E905296968ULL,
		0x0098F84C61DD4FF5ULL
	}};
	shift = 57;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AD78B555717DDC2ULL,
		0x98E83C1822C37B12ULL,
		0xE772A3EADD13D722ULL,
		0xED9D5E5F682E069AULL,
		0xC21FF9F5C0D8CAE3ULL,
		0x7185426B8E92B9A3ULL,
		0xB19D30E77A9FB6F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDC2000000000000ULL,
		0x7B124AD78B555717ULL,
		0xD72298E83C1822C3ULL,
		0x069AE772A3EADD13ULL,
		0xCAE3ED9D5E5F682EULL,
		0xB9A3C21FF9F5C0D8ULL,
		0xB6F47185426B8E92ULL,
		0x0000B19D30E77A9FULL
	}};
	shift = 48;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51781AAC72A9E526ULL,
		0x9BFC80A3D08D1697ULL,
		0xA1E9178AE05CA9E6ULL,
		0xD3162CF249606309ULL,
		0xC71960BABD21EA1FULL,
		0xA069F5117689D2A3ULL,
		0x03DD6AC00F46FF70ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE06AB1CAA7949800ULL,
		0xF2028F42345A5D45ULL,
		0xA45E2B8172A79A6FULL,
		0x58B3C925818C2687ULL,
		0x6582EAF487A87F4CULL,
		0xA7D445DA274A8F1CULL,
		0x75AB003D1BFDC281ULL,
		0x000000000000000FULL
	}};
	shift = 10;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDB5E99AB60D50BCULL,
		0xC185C3A6D67F2305ULL,
		0xC36D7816A79FF070ULL,
		0x27DCB6DF21CCAAD3ULL,
		0xB786EA60A793198EULL,
		0xE440CA24950C7C7CULL,
		0x1B2C94E27AE0EDEFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD83542F00000000ULL,
		0xB59FC8C17B6D7A66ULL,
		0xA9E7FC1C306170E9ULL,
		0xC8732AB4F0DB5E05ULL,
		0x29E4C66389F72DB7ULL,
		0x25431F1F2DE1BA98ULL,
		0x9EB83B7BF9103289ULL,
		0x0000000006CB2538ULL
	}};
	shift = 30;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58117D2CFEB044D7ULL,
		0x3657912DEF882E64ULL,
		0xE6C01A921557709AULL,
		0xC283D8C6D547FF48ULL,
		0xF004FC62C1317D7CULL,
		0x7D6C65F8F9B27A27ULL,
		0x86BC673EE69C57D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1135C0000000000ULL,
		0x20B9916045F4B3FAULL,
		0x5DC268D95E44B7BEULL,
		0x1FFD239B006A4855ULL,
		0xC5F5F30A0F631B55ULL,
		0xC9E89FC013F18B04ULL,
		0x715F59F5B197E3E6ULL,
		0x0000021AF19CFB9AULL
	}};
	shift = 42;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x356A44D9975F7C99ULL,
		0x9385EEF16A592C74ULL,
		0xD0A030B97F52CBACULL,
		0x5ADC4FB978F6EB05ULL,
		0x1D5D0B7968BFD577ULL,
		0xB1A2797D35C8AFBBULL,
		0x2E816B75184A65BFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32EBEF932000000ULL,
		0xE2D4B258E86AD489ULL,
		0x72FEA59759270BDDULL,
		0x72F1EDD60BA14061ULL,
		0xF2D17FAAEEB5B89FULL,
		0xFA6B915F763ABA16ULL,
		0xEA3094CB7F6344F2ULL,
		0x00000000005D02D6ULL
	}};
	shift = 25;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0629564F70B2F958ULL,
		0x6E7A33AB28316594ULL,
		0x445C9EA7CB9C9DDAULL,
		0xFFCD3B51B35C8D43ULL,
		0x7F9D6697230EE8D3ULL,
		0x61D6E44FC2E141CFULL,
		0x5D67E7F94E2351DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x314AB27B8597CAC0ULL,
		0x73D19D59418B2CA0ULL,
		0x22E4F53E5CE4EED3ULL,
		0xFE69DA8D9AE46A1AULL,
		0xFCEB34B91877469FULL,
		0x0EB7227E170A0E7BULL,
		0xEB3F3FCA711A8EEBULL,
		0x0000000000000002ULL
	}};
	shift = 3;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC78C9F0400883A96ULL,
		0xAD1C243C8D355FFEULL,
		0xEE7593830245B383ULL,
		0x583ECDF269A1CDF2ULL,
		0xE3D09B6A2F1B1B22ULL,
		0x8C7B2CE25F6C1B47ULL,
		0x978A0FFF37C91096ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C00000000000000ULL,
		0xFD8F193E08011075ULL,
		0x075A3848791A6ABFULL,
		0xE5DCEB2706048B67ULL,
		0x44B07D9BE4D3439BULL,
		0x8FC7A136D45E3636ULL,
		0x2D18F659C4BED836ULL,
		0x012F141FFE6F9221ULL
	}};
	shift = 57;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A4F30CDB847FF87ULL,
		0x9B8A535E5BCF7010ULL,
		0x934EC1F3FA60813EULL,
		0x6DFDF26C7409E319ULL,
		0xB2895186C4C43F48ULL,
		0x2BEC9656B6BFBF10ULL,
		0x4F59B76763518D28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1C000000000000ULL,
		0xC041A93CC336E11FULL,
		0x04FA6E294D796F3DULL,
		0x8C664D3B07CFE982ULL,
		0xFD21B7F7C9B1D027ULL,
		0xFC42CA25461B1310ULL,
		0x34A0AFB2595ADAFEULL,
		0x00013D66DD9D8D46ULL
	}};
	shift = 50;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF54974C37473A8BCULL,
		0x210B9C61F58A8678ULL,
		0x1109CF0D6A34A346ULL,
		0xAEA178619A75E734ULL,
		0xDFB31522122A5CFCULL,
		0xF0770CC0E4FD4E5BULL,
		0xA5D51F35A65DABFFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA39D45E00000000ULL,
		0xFAC5433C7AA4BA61ULL,
		0xB51A51A31085CE30ULL,
		0xCD3AF39A0884E786ULL,
		0x09152E7E5750BC30ULL,
		0x727EA72DEFD98A91ULL,
		0xD32ED5FFF83B8660ULL,
		0x0000000052EA8F9AULL
	}};
	shift = 31;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB15AC52B5C5B064ULL,
		0x3DF79F8480E88FA1ULL,
		0xC89482A4E6A4362CULL,
		0xC5311837C1E07C06ULL,
		0x884DEC1C3FE9C437ULL,
		0xE6C10D57B6EA168EULL,
		0xE13AA93BFB927411ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58A56B8B60C8000ULL,
		0xF3F0901D11F43B62ULL,
		0x90549CD486C587BEULL,
		0x2306F83C0F80D912ULL,
		0xBD8387FD3886F8A6ULL,
		0x21AAF6DD42D1D109ULL,
		0x55277F724E823CD8ULL,
		0x0000000000001C27ULL
	}};
	shift = 13;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3428E7E7F7551F1ULL,
		0x58382AE076F939A8ULL,
		0x814FCC7A63F9B4DFULL,
		0xB0DCEB67C8FDAF39ULL,
		0x7CA3D4E887738D4BULL,
		0xB75C95A1380B310FULL,
		0xEDD116ED2D8A6F51ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAA3E20000000000ULL,
		0xF2735166851CFCFEULL,
		0xF369BEB07055C0EDULL,
		0xFB5E73029F98F4C7ULL,
		0xE71A9761B9D6CF91ULL,
		0x16621EF947A9D10EULL,
		0x14DEA36EB92B4270ULL,
		0x000001DBA22DDA5BULL
	}};
	shift = 41;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86D990E7971A6BDBULL,
		0xB0860C7511491B93ULL,
		0x0AD54F64FBA261A7ULL,
		0xCDB2A605DA395529ULL,
		0xF5EA870274CCB3B7ULL,
		0x8A73E8035E8BE224ULL,
		0x87D1F45A67086BFDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BDB000000000000ULL,
		0x1B9386D990E7971AULL,
		0x61A7B0860C751149ULL,
		0x55290AD54F64FBA2ULL,
		0xB3B7CDB2A605DA39ULL,
		0xE224F5EA870274CCULL,
		0x6BFD8A73E8035E8BULL,
		0x000087D1F45A6708ULL
	}};
	shift = 48;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D5279B61F4BAAD6ULL,
		0x075DC39FD2245288ULL,
		0xA7ADB24F454CB07EULL,
		0x9223857A61230FCBULL,
		0x31BD37A2E352C838ULL,
		0xE5D99E2634795B08ULL,
		0x202CBDCEA2C4C5A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5279B61F4BAAD6ULL,
		0x075DC39FD2245288ULL,
		0xA7ADB24F454CB07EULL,
		0x9223857A61230FCBULL,
		0x31BD37A2E352C838ULL,
		0xE5D99E2634795B08ULL,
		0x202CBDCEA2C4C5A6ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C9910E7A6726133ULL,
		0xD7B6A66BDF98CB3AULL,
		0x50689E81F1178312ULL,
		0x991AEC7CB7F17345ULL,
		0x48F67EA6D307F9A8ULL,
		0x35A1BC0E7296820CULL,
		0x1C4DCE188922CF6EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0xA3264439E99C984CULL,
		0xB5EDA99AF7E632CEULL,
		0x541A27A07C45E0C4ULL,
		0x2646BB1F2DFC5CD1ULL,
		0x123D9FA9B4C1FE6AULL,
		0x8D686F039CA5A083ULL,
		0x071373862248B3DBULL
	}};
	shift = 62;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x431487CB7439594DULL,
		0x4F653AD712050149ULL,
		0x7CD3485F9120B72FULL,
		0x2D7C8E74F33D662CULL,
		0xA1EFB057A8B14C41ULL,
		0x09C3AE497638DFFAULL,
		0x8F103C0EA8BD2099ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B29A00000000000ULL,
		0xA029286290F96E87ULL,
		0x16E5E9ECA75AE240ULL,
		0xACC58F9A690BF224ULL,
		0x298825AF91CE9E67ULL,
		0x1BFF543DF60AF516ULL,
		0xA413213875C92EC7ULL,
		0x000011E20781D517ULL
	}};
	shift = 45;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD65F09D6D47C581CULL,
		0x06CD80236E796CD1ULL,
		0xA1C686FB85EC20C3ULL,
		0x1CE7DE27BDC0010AULL,
		0x32D63D85D33FD1C7ULL,
		0xFA02A68B4151697BULL,
		0xD795ABF59F81CDA6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0E000000000000ULL,
		0xB668EB2F84EB6A3EULL,
		0x10618366C011B73CULL,
		0x008550E3437DC2F6ULL,
		0xE8E38E73EF13DEE0ULL,
		0xB4BD996B1EC2E99FULL,
		0xE6D37D015345A0A8ULL,
		0x00006BCAD5FACFC0ULL
	}};
	shift = 47;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x907D239C56E2ABBBULL,
		0xB857BBB2E2961030ULL,
		0x253C3D394DDB2747ULL,
		0x97891F08CC6FCC58ULL,
		0xCBC8A557F7C1EC61ULL,
		0x85B805C0CE4A86DEULL,
		0x7D449611BE4F038BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48E715B8AAEEC000ULL,
		0xEEECB8A5840C241FULL,
		0x0F4E5376C9D1EE15ULL,
		0x47C2331BF316094FULL,
		0x2955FDF07B1865E2ULL,
		0x01703392A1B7B2F2ULL,
		0x25846F93C0E2E16EULL,
		0x0000000000001F51ULL
	}};
	shift = 14;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E59CC9312F69A8DULL,
		0x3F98396B0C0EBDB5ULL,
		0x4B859D8E8D8C10A1ULL,
		0x9BF7C617EB622DEFULL,
		0xED9F9CBF48722666ULL,
		0x3B86A7C20CA698CFULL,
		0xD31614688B0F50C6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3992625ED351A00ULL,
		0x3072D6181D7B6B1CULL,
		0x0B3B1D1B1821427FULL,
		0xEF8C2FD6C45BDE97ULL,
		0x3F397E90E44CCD37ULL,
		0x0D4F84194D319FDBULL,
		0x2C28D1161EA18C77ULL,
		0x00000000000001A6ULL
	}};
	shift = 9;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7B73C409765C39BULL,
		0x74A42B7171376488ULL,
		0xB0F8BFCF3F4D644FULL,
		0x59F9956C2CAD0BC1ULL,
		0xCCE5D96BD6BFA4EDULL,
		0x0605E5E553AAA571ULL,
		0x0B378517DA3BF41BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B73C409765C39B0ULL,
		0x4A42B7171376488CULL,
		0x0F8BFCF3F4D644F7ULL,
		0x9F9956C2CAD0BC1BULL,
		0xCE5D96BD6BFA4ED5ULL,
		0x605E5E553AAA571CULL,
		0xB378517DA3BF41B0ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35281E8C7ED15FCEULL,
		0xD30586AB0B1413CCULL,
		0x9912CAE1567A163DULL,
		0xDCFF86E04BD116B5ULL,
		0x19CC9E402CD6D159ULL,
		0x61EC590D9D77DB71ULL,
		0x5F6C93A9F45FC711ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF9C00000000000ULL,
		0x827986A503D18FDAULL,
		0x42C7BA60B0D56162ULL,
		0x22D6B322595C2ACFULL,
		0xDA2B3B9FF0DC097AULL,
		0xFB6E233993C8059AULL,
		0xF8E22C3D8B21B3AEULL,
		0x00000BED92753E8BULL
	}};
	shift = 45;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B5002ECACCDEC44ULL,
		0x1EC91CF8ABA0F223ULL,
		0x7AEB18D4D09B6628ULL,
		0x6057E409AE881CE1ULL,
		0x102C2810E20A58F4ULL,
		0xD19C0D9F3E0ABC5BULL,
		0xCB59887ED8FF57D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666F622000000000ULL,
		0x5D0791185A801765ULL,
		0x84DB3140F648E7C5ULL,
		0x7440E70BD758C6A6ULL,
		0x1052C7A302BF204DULL,
		0xF055E2D881614087ULL,
		0xC7FABE9E8CE06CF9ULL,
		0x000000065ACC43F6ULL
	}};
	shift = 35;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A37F56683699EB2ULL,
		0xE242D38ADAA340A1ULL,
		0xB007D930C8154056ULL,
		0x0AB6C21711E13686ULL,
		0x86416872172AE922ULL,
		0x01C279E2FA77341DULL,
		0xF6B6596400FEACE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BFAB341B4CF5900ULL,
		0x2169C56D51A0508DULL,
		0x03EC98640AA02B71ULL,
		0x5B610B88F09B4358ULL,
		0x20B4390B95749105ULL,
		0xE13CF17D3B9A0EC3ULL,
		0x5B2CB2007F567000ULL,
		0x000000000000007BULL
	}};
	shift = 7;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F7FA45F1773F8A3ULL,
		0x816EDFB96487C690ULL,
		0x01EBE6FA192BBEB2ULL,
		0x86F38DFFAEC4D53FULL,
		0x9341A6A1125F0B26ULL,
		0xBE65807680ED3DA1ULL,
		0x631D7B1351826C73ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5DCFE28C000000ULL,
		0xE5921F1A40BDFE91ULL,
		0xE864AEFACA05BB7EULL,
		0xFEBB1354FC07AF9BULL,
		0x84497C2C9A1BCE37ULL,
		0xDA03B4F6864D069AULL,
		0x4D4609B1CEF99601ULL,
		0x00000000018C75ECULL
	}};
	shift = 26;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75A47FA5CC4DB1FDULL,
		0x72A857C4A69A2311ULL,
		0x0E7A257AC5F9501BULL,
		0x60A57DE550669B2DULL,
		0xD0369AFEF799EB5AULL,
		0xF41B203D2482F041ULL,
		0x4AC47B3BFBB2CDDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D8FE80000000000ULL,
		0xD1188BAD23FD2E62ULL,
		0xCA80DB9542BE2534ULL,
		0x34D96873D12BD62FULL,
		0xCF5AD3052BEF2A83ULL,
		0x17820E81B4D7F7BCULL,
		0x966ED7A0D901E924ULL,
		0x0000025623D9DFDDULL
	}};
	shift = 43;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABBB8ADFEFC5E998ULL,
		0xF661AF73C63F1070ULL,
		0x7F84D7A0D48EC34BULL,
		0x37DF41DA4535381FULL,
		0x051021E4C96B43A2ULL,
		0xA85777CDD03DACE8ULL,
		0xFDB20DD5B2A3893FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9980000000000000ULL,
		0x070ABBB8ADFEFC5EULL,
		0x34BF661AF73C63F1ULL,
		0x81F7F84D7A0D48ECULL,
		0x3A237DF41DA45353ULL,
		0xCE8051021E4C96B4ULL,
		0x93FA85777CDD03DAULL,
		0x000FDB20DD5B2A38ULL
	}};
	shift = 52;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9DB9DBE1B691326ULL,
		0x055302F20A87E81CULL,
		0xB01AC74C44FF3AC3ULL,
		0xD8DB24D9E912DBEEULL,
		0x80B26B546C4A0C0FULL,
		0x2FBFB645F25C782CULL,
		0x26AADBE122DB4AC1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76E76F86DA44C980ULL,
		0x54C0BC82A1FA073AULL,
		0x06B1D3113FCEB0C1ULL,
		0x36C9367A44B6FBACULL,
		0x2C9AD51B128303F6ULL,
		0xEFED917C971E0B20ULL,
		0xAAB6F848B6D2B04BULL,
		0x0000000000000009ULL
	}};
	shift = 6;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8FC54E9E0CFC9F5ULL,
		0x46563EB8C103236DULL,
		0xF339D2DBA9290465ULL,
		0xEB0F45F1229B5B0CULL,
		0x9F853E89CD32A4ACULL,
		0xD2C118E297E8FE65ULL,
		0xE797113D19265ADAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2A74F067E4FA80ULL,
		0x2B1F5C608191B6E4ULL,
		0x9CE96DD4948232A3ULL,
		0x87A2F8914DAD8679ULL,
		0xC29F44E699525675ULL,
		0x608C714BF47F32CFULL,
		0xCB889E8C932D6D69ULL,
		0x0000000000000073ULL
	}};
	shift = 7;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA77F17ABA1E7B52ULL,
		0x19B35876F73F7A3AULL,
		0x48BFB004E6745897ULL,
		0x31D028C58C18EF9CULL,
		0xE9FFC21C5688DA48ULL,
		0xE4197DC8E2787D65ULL,
		0x94205F8503C0BC40ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ED4800000000000ULL,
		0xDE8EBA9DFC5EAE87ULL,
		0x1625C66CD61DBDCFULL,
		0x3BE7122FEC01399DULL,
		0x36920C740A316306ULL,
		0x1F597A7FF08715A2ULL,
		0x2F1039065F72389EULL,
		0x0000250817E140F0ULL
	}};
	shift = 46;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC502484F814BB73ULL,
		0xB03820B95FBC7676ULL,
		0xC3DA5E587ED1AF33ULL,
		0x0EAED556E47F8DA4ULL,
		0x85942AD194F9E41DULL,
		0x811922CA5BD25CFDULL,
		0x25A1CD3EC4534EB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2812427C0A5DB980ULL,
		0x1C105CAFDE3B3B76ULL,
		0xED2F2C3F68D799D8ULL,
		0x576AAB723FC6D261ULL,
		0xCA1568CA7CF20E87ULL,
		0x8C91652DE92E7EC2ULL,
		0xD0E69F6229A75B40ULL,
		0x0000000000000012ULL
	}};
	shift = 7;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB4610EB4A2A247EULL,
		0x1F09BACAE019648DULL,
		0xD3B1185829FE9647ULL,
		0x6054C4FA170AB976ULL,
		0xA2881BCD9D37F822ULL,
		0x88D287FB595AA377ULL,
		0xB95EA0AC818248F4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xDCB4610EB4A2A247ULL,
		0x71F09BACAE019648ULL,
		0x6D3B1185829FE964ULL,
		0x26054C4FA170AB97ULL,
		0x7A2881BCD9D37F82ULL,
		0x488D287FB595AA37ULL,
		0x0B95EA0AC818248FULL
	}};
	shift = 60;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2513130C3A9FCAEBULL,
		0x53F4298027F68A3AULL,
		0xB7CC50855B012706ULL,
		0x95A429ACCBE4EDACULL,
		0x0E40171B0D4F9C10ULL,
		0x38349B183A395DBEULL,
		0x608FBEA24D2370B4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE575800000000000ULL,
		0x451D128989861D4FULL,
		0x938329FA14C013FBULL,
		0x76D65BE62842AD80ULL,
		0xCE084AD214D665F2ULL,
		0xAEDF07200B8D86A7ULL,
		0xB85A1C1A4D8C1D1CULL,
		0x00003047DF512691ULL
	}};
	shift = 47;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34BC69DC7B23A117ULL,
		0xBED488BF223AE72FULL,
		0x5FDA759983B8F956ULL,
		0xE25EBC305EC35F4CULL,
		0x5DA20C382177E6C6ULL,
		0xC331F987F1522998ULL,
		0xB5B11F640BE4E652ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8F647422E00000ULL,
		0x17E4475CE5E6978DULL,
		0xB330771F2AD7DA91ULL,
		0x860BD86BE98BFB4EULL,
		0x87042EFCD8DC4BD7ULL,
		0x30FE2A45330BB441ULL,
		0xEC817C9CCA58663FULL,
		0x000000000016B623ULL
	}};
	shift = 21;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8263C8BB446F5A2ULL,
		0xCF667E1CC3BBBCE3ULL,
		0x15447A470DEBD3D3ULL,
		0xB00C14BF196541B9ULL,
		0x7D9233EFF3012D01ULL,
		0x5074BE0A3EBB021CULL,
		0xBB963A0B5982C81CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BB446F5A2000000ULL,
		0x1CC3BBBCE3A8263CULL,
		0x470DEBD3D3CF667EULL,
		0xBF196541B915447AULL,
		0xEFF3012D01B00C14ULL,
		0x0A3EBB021C7D9233ULL,
		0x0B5982C81C5074BEULL,
		0x0000000000BB963AULL
	}};
	shift = 24;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BDBABA7C76D6971ULL,
		0x4BE9B56991C6DB31ULL,
		0xD938D2E813A0C161ULL,
		0x54C1A52531EDCFEEULL,
		0x1C3A5ECFC4BB7C0AULL,
		0x9203B0BEDFDBB64AULL,
		0x579F7ED5B5FACA52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE9F1DB5A5C4000ULL,
		0x6D5A6471B6CC56F6ULL,
		0x34BA04E8305852FAULL,
		0x69494C7B73FBB64EULL,
		0x97B3F12EDF029530ULL,
		0xEC2FB7F6ED92870EULL,
		0xDFB56D7EB294A480ULL,
		0x00000000000015E7ULL
	}};
	shift = 14;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279FA1624C2AF468ULL,
		0x26BC99A78498FBE9ULL,
		0x21F0C30A26A4DDF1ULL,
		0x925A6496CE4E293CULL,
		0xC20DF3BB6BC7C50EULL,
		0x920613FA9CED3984ULL,
		0xC717D756E5C146A8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF4680000000000ULL,
		0x98FBE9279FA1624CULL,
		0xA4DDF126BC99A784ULL,
		0x4E293C21F0C30A26ULL,
		0xC7C50E925A6496CEULL,
		0xED3984C20DF3BB6BULL,
		0xC146A8920613FA9CULL,
		0x000000C717D756E5ULL
	}};
	shift = 40;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1054D887E8298FC2ULL,
		0x3BFA80B1DA58982AULL,
		0xAF99E15889EB5606ULL,
		0xCF52A415CA89938AULL,
		0xF3AF70A126C29219ULL,
		0xAD13F606024774B8ULL,
		0x3AF36EDB176BD61FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A6C43F414C7E10ULL,
		0xDFD4058ED2C4C150ULL,
		0x7CCF0AC44F5AB031ULL,
		0x7A9520AE544C9C55ULL,
		0x9D7B8509361490CEULL,
		0x689FB030123BA5C7ULL,
		0xD79B76D8BB5EB0FDULL,
		0x0000000000000001ULL
	}};
	shift = 3;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC669B597582CE67ULL,
		0x14FDF5A45B845B71ULL,
		0x65BF2E2ACABAA139ULL,
		0xC7D5CCDA9A1F81C1ULL,
		0xAA5241D1B34C6751ULL,
		0xFFEC19D6451061BAULL,
		0x39352D6E1D02B724ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2EB059CCE000000ULL,
		0x48B708B6E398CD36ULL,
		0x559575427229FBEBULL,
		0xB5343F0382CB7E5CULL,
		0xA36698CEA38FAB99ULL,
		0xAC8A20C37554A483ULL,
		0xDC3A056E49FFD833ULL,
		0x0000000000726A5AULL
	}};
	shift = 25;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97C7D83859649859ULL,
		0x642A67FA63D2877FULL,
		0x13C743FB2D0AEA58ULL,
		0xEEEE7D5417344373ULL,
		0xC065CFC5A9D5779BULL,
		0x9C68B258F7DDE27CULL,
		0xFC12ACAD5A9E6A53ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5926164000000000ULL,
		0xF4A1DFE5F1F60E16ULL,
		0x42BA96190A99FE98ULL,
		0xCD10DCC4F1D0FECBULL,
		0x755DE6FBBB9F5505ULL,
		0xF7789F301973F16AULL,
		0xA79A94E71A2C963DULL,
		0x0000003F04AB2B56ULL
	}};
	shift = 38;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4E65890694A601EULL,
		0xC0A5EB3DA8442F4BULL,
		0x5D7F259BD8174B6FULL,
		0xF50AF68DE1D217A6ULL,
		0xE0FE733B0C21293CULL,
		0xD0EF5AC95287142FULL,
		0xEED1E2FFB36079DDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A5300F000000000ULL,
		0x42217A5FA732C483ULL,
		0xC0BA5B7E052F59EDULL,
		0x0E90BD32EBF92CDEULL,
		0x610949E7A857B46FULL,
		0x9438A17F07F399D8ULL,
		0x9B03CEEE877AD64AULL,
		0x00000007768F17FDULL
	}};
	shift = 35;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2E80068C89348ABULL,
		0x0CD5684230667381ULL,
		0xB5E7020715DF4B0EULL,
		0x2D7EF1F2B23D4E90ULL,
		0x956A2D43EF24D512ULL,
		0xF46CF5473C855D55ULL,
		0x012F2CDA0860B7FCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46449A4558000000ULL,
		0x1183339C0D174003ULL,
		0x38AEFA587066AB42ULL,
		0x9591EA7485AF3810ULL,
		0x1F7926A8916BF78FULL,
		0x39E42AEAACAB516AULL,
		0xD04305BFE7A367AAULL,
		0x0000000000097966ULL
	}};
	shift = 27;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC178A928E7EC30E8ULL,
		0x99A3DD7811FDD308ULL,
		0x4FBA55D0985EDB8AULL,
		0x148C2AC7CA6D8FD3ULL,
		0xEBBB09346DCE7E68ULL,
		0x05E75A332666BFA2ULL,
		0x9AA78D3BC9711C7DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC549473F61874000ULL,
		0x1EEBC08FEE98460BULL,
		0xD2AE84C2F6DC54CDULL,
		0x61563E536C7E9A7DULL,
		0xD849A36E73F340A4ULL,
		0x3AD1993335FD175DULL,
		0x3C69DE4B88E3E82FULL,
		0x00000000000004D5ULL
	}};
	shift = 11;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE4A8D4F7CAE41E3ULL,
		0x4FC0ECF92A3428BCULL,
		0xA03C82AE157E91F5ULL,
		0x8F2C29C34BB7DC2AULL,
		0x0F5D9240C397803DULL,
		0xC53BDEB94B76A467ULL,
		0x5E4A70DCB479E850ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F7CAE41E300000ULL,
		0xCF92A3428BCBE4A8ULL,
		0x2AE157E91F54FC0EULL,
		0x9C34BB7DC2AA03C8ULL,
		0x240C397803D8F2C2ULL,
		0xEB94B76A4670F5D9ULL,
		0x0DCB479E850C53BDULL,
		0x000000000005E4A7ULL
	}};
	shift = 20;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x214E56BED7C2B908ULL,
		0xCD1281F9F339758AULL,
		0xC51F618718F381AEULL,
		0x1D34C5B597C01D13ULL,
		0xAA851EC4D8DCCFEEULL,
		0x1A97C385C227F738ULL,
		0x00E1CF16A0976216ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x885395AFB5F0AE42ULL,
		0xB344A07E7CCE5D62ULL,
		0xF147D861C63CE06BULL,
		0x874D316D65F00744ULL,
		0x2AA147B1363733FBULL,
		0x86A5F0E17089FDCEULL,
		0x003873C5A825D885ULL
	}};
	shift = 62;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x693AC5532E526072ULL,
		0x6C5D05EE0D563BDFULL,
		0x9D3BA88F0C9DAB5EULL,
		0xCC040C3BA97690E1ULL,
		0x51F641F7D10A862AULL,
		0x2BA13B4A42B72A1BULL,
		0x725D3FB3D741C7C7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0720000000000000ULL,
		0xBDF693AC5532E526ULL,
		0xB5E6C5D05EE0D563ULL,
		0x0E19D3BA88F0C9DAULL,
		0x62ACC040C3BA9769ULL,
		0xA1B51F641F7D10A8ULL,
		0x7C72BA13B4A42B72ULL,
		0x000725D3FB3D741CULL
	}};
	shift = 52;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDFF0E8DA55AAF52ULL,
		0xE9CAD4C3C8DB4B53ULL,
		0x3D3D48E70D34DE98ULL,
		0xE517004AB5430C94ULL,
		0x4273701F37D93864ULL,
		0x7B014EAE0F7E651EULL,
		0x638CFF41363E1CEEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5200000000000000ULL,
		0x53EDFF0E8DA55AAFULL,
		0x98E9CAD4C3C8DB4BULL,
		0x943D3D48E70D34DEULL,
		0x64E517004AB5430CULL,
		0x1E4273701F37D938ULL,
		0xEE7B014EAE0F7E65ULL,
		0x00638CFF41363E1CULL
	}};
	shift = 56;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78FA653C8845FCB1ULL,
		0x6B206E93EDCF6FDAULL,
		0x7A60BC5D8CAFE3F1ULL,
		0x369E94D41D0B2D6DULL,
		0x9E682CF6895DFCF4ULL,
		0xEBE71B7A2E0174EBULL,
		0x19F1CD6093271B85ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA653C8845FCB100ULL,
		0x206E93EDCF6FDA78ULL,
		0x60BC5D8CAFE3F16BULL,
		0x9E94D41D0B2D6D7AULL,
		0x682CF6895DFCF436ULL,
		0xE71B7A2E0174EB9EULL,
		0xF1CD6093271B85EBULL,
		0x0000000000000019ULL
	}};
	shift = 8;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6276E5F1E92C9643ULL,
		0x87C93384E90DB622ULL,
		0x600D45E122B9AE80ULL,
		0x1FED3EE3F1ACC3D2ULL,
		0x99F5D4A66EF3A197ULL,
		0x9AD9F0C9671ADA94ULL,
		0x18613651F073D30BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B21800000000000ULL,
		0xDB11313B72F8F496ULL,
		0xD74043E499C27486ULL,
		0x61E93006A2F0915CULL,
		0xD0CB8FF69F71F8D6ULL,
		0x6D4A4CFAEA533779ULL,
		0xE985CD6CF864B38DULL,
		0x00000C309B28F839ULL
	}};
	shift = 47;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB0925366DB55FCFULL,
		0x821D4BD3145256EFULL,
		0x04734607836F6D4BULL,
		0x75D2CE4A39140788ULL,
		0xA6260DFB0D2219B1ULL,
		0xE4529971C10600B8ULL,
		0x92B4C53DF186592FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929B36DAAFE78000ULL,
		0xA5E98A292B77F584ULL,
		0xA303C1B7B6A5C10EULL,
		0x67251C8A03C40239ULL,
		0x06FD86910CD8BAE9ULL,
		0x4CB8E083005C5313ULL,
		0x629EF8C32C97F229ULL,
		0x000000000000495AULL
	}};
	shift = 15;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2834CE97D19E0732ULL,
		0x5EBD1D753757B4DEULL,
		0xB7A28F2D20DEABCAULL,
		0xF1BA899BC8FB4DA2ULL,
		0x7E684C97491C152AULL,
		0xFFEB6F094127CEC3ULL,
		0xFEA1336CE3AF7E54ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF0399000000000ULL,
		0xBABDA6F141A674BEULL,
		0x06F55E52F5E8EBA9ULL,
		0x47DA6D15BD147969ULL,
		0x48E0A9578DD44CDEULL,
		0x093E761BF34264BAULL,
		0x1D7BF2A7FF5B784AULL,
		0x00000007F5099B67ULL
	}};
	shift = 35;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DCE8FF74921E4DFULL,
		0xB6E31199E6C0610BULL,
		0x973C42EF05CE617DULL,
		0x3DE9BD137142C63AULL,
		0xF13D8C799327C723ULL,
		0x4035575AF09B8C96ULL,
		0xA6D616165252EFBEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C9BE00000000000ULL,
		0x0C216BB9D1FEE924ULL,
		0xCC2FB6DC62333CD8ULL,
		0x58C752E7885DE0B9ULL,
		0xF8E467BD37A26E28ULL,
		0x7192DE27B18F3264ULL,
		0x5DF7C806AAEB5E13ULL,
		0x000014DAC2C2CA4AULL
	}};
	shift = 45;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C18C4C0AD20DECFULL,
		0xB55AD45EEBCD2D98ULL,
		0x758F3317AD4C2AD8ULL,
		0xA1A5741A008E4FFDULL,
		0x3E713DF32F3447FAULL,
		0xF88931A5DD0DCE62ULL,
		0x5BA49A11B6219E19ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DECF0000000000ULL,
		0xCD2D981C18C4C0ADULL,
		0x4C2AD8B55AD45EEBULL,
		0x8E4FFD758F3317ADULL,
		0x3447FAA1A5741A00ULL,
		0x0DCE623E713DF32FULL,
		0x219E19F88931A5DDULL,
		0x0000005BA49A11B6ULL
	}};
	shift = 40;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEDBE81AA011D66AULL,
		0x5AFF3F5B188AEDD1ULL,
		0x696203DAD4CC4D59ULL,
		0xE95763D7998ED85BULL,
		0xF79DE52B572B4F57ULL,
		0x114D89EC720AFF5AULL,
		0x49FD0EE769BC25B0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4759A80000000000ULL,
		0x2BB746BB6FA06A80ULL,
		0x3135656BFCFD6C62ULL,
		0x3B616DA5880F6B53ULL,
		0xAD3D5FA55D8F5E66ULL,
		0x2BFD6BDE7794AD5CULL,
		0xF096C0453627B1C8ULL,
		0x00000127F43B9DA6ULL
	}};
	shift = 42;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F04BD37E437FEAEULL,
		0x267A71A3D905AE4AULL,
		0x75245577114AAA4BULL,
		0x2D669B239E20EB72ULL,
		0xC103A8EFFE8ABFC2ULL,
		0xFCCC57E0CDA85D35ULL,
		0x36DFD84768CD8CD3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE0000000000000ULL,
		0xE4A1F04BD37E437FULL,
		0xA4B267A71A3D905AULL,
		0xB7275245577114AAULL,
		0xFC22D669B239E20EULL,
		0xD35C103A8EFFE8ABULL,
		0xCD3FCCC57E0CDA85ULL,
		0x00036DFD84768CD8ULL
	}};
	shift = 52;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49D1C642C6B9CD01ULL,
		0x69ED7EE0EF2408D8ULL,
		0x19AA2AE8EEF76B06ULL,
		0x6D4D142C0B787256ULL,
		0x12AB8AE72E9FA138ULL,
		0xF89471A3427E8D93ULL,
		0xD4B090BE14FB4D74ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0200000000000000ULL,
		0xB093A38C858D739AULL,
		0x0CD3DAFDC1DE4811ULL,
		0xAC335455D1DDEED6ULL,
		0x70DA9A285816F0E4ULL,
		0x26255715CE5D3F42ULL,
		0xE9F128E34684FD1BULL,
		0x01A961217C29F69AULL
	}};
	shift = 57;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA733D1903192C6E5ULL,
		0xA74B7C4FF0326FDEULL,
		0x459EBCBCA1D04A94ULL,
		0xF653486FA1B2DDC6ULL,
		0xB7DA79641705F56CULL,
		0x1615391CD895C29FULL,
		0x16350C5366F83644ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC963728000000000ULL,
		0x1937EF5399E8C818ULL,
		0xE8254A53A5BE27F8ULL,
		0xD96EE322CF5E5E50ULL,
		0x82FAB67B29A437D0ULL,
		0x4AE14FDBED3CB20BULL,
		0x7C1B220B0A9C8E6CULL,
		0x0000000B1A8629B3ULL
	}};
	shift = 39;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC2595ACF71595BFULL,
		0x50DFDF015EC40590ULL,
		0x6D6F53DB59FBBB69ULL,
		0x69416E3BAB394C50ULL,
		0x46A582B831B9453FULL,
		0x96094EB01876F694ULL,
		0xFAED59B8BE475C58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE2B2B7E00000000ULL,
		0xBD880B21F84B2B59ULL,
		0xB3F776D2A1BFBE02ULL,
		0x567298A0DADEA7B6ULL,
		0x63728A7ED282DC77ULL,
		0x30EDED288D4B0570ULL,
		0x7C8EB8B12C129D60ULL,
		0x00000001F5DAB371ULL
	}};
	shift = 33;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB5F811CF2F9ED50ULL,
		0xA43AF1DB63DCA600ULL,
		0xEFD968973AC32006ULL,
		0xAFF7CB675EEB276AULL,
		0xD2294EC2F455120AULL,
		0x3DDB2D13D1996000ULL,
		0x6A05E428ED4037C0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0473CBE7B540000ULL,
		0xBC76D8F7298032D7ULL,
		0x5A25CEB0C801A90EULL,
		0xF2D9D7BAC9DABBF6ULL,
		0x53B0BD154482ABFDULL,
		0xCB44F4665800348AULL,
		0x790A3B500DF00F76ULL,
		0x0000000000001A81ULL
	}};
	shift = 14;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAC2C978BBD06418ULL,
		0xC05E87520E705370ULL,
		0xA1B0755F6696E4CCULL,
		0xD98384C1E4BD9238ULL,
		0x6EE29D60EF59531CULL,
		0xCB2AA106289143F4ULL,
		0x2584D2517D4D4EDDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F177A0C8300000ULL,
		0x0EA41CE0A6E1D585ULL,
		0xEABECD2DC99980BDULL,
		0x0983C97B24714360ULL,
		0x3AC1DEB2A639B307ULL,
		0x420C512287E8DDC5ULL,
		0xA4A2FA9A9DBB9655ULL,
		0x0000000000004B09ULL
	}};
	shift = 17;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B50847DCB336DF1ULL,
		0x54100F58C0BB36D6ULL,
		0xB523E64D907ABBB7ULL,
		0x12E4AD5A5BEFA02CULL,
		0x3643DB429B3AD4F6ULL,
		0x4105D950C02BA177ULL,
		0xC4686CFFCC36D87EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B6F88000000000ULL,
		0x5D9B6B35A8423EE5ULL,
		0x3D5DDBAA0807AC60ULL,
		0xF7D0165A91F326C8ULL,
		0x9D6A7B097256AD2DULL,
		0x15D0BB9B21EDA14DULL,
		0x1B6C3F2082ECA860ULL,
		0x0000006234367FE6ULL
	}};
	shift = 39;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5517459809BF3C98ULL,
		0x056ED2DE7F631C5DULL,
		0xA2ABE2D937E416AEULL,
		0x9DB8A81071332798ULL,
		0x1A17925AD84B2EF0ULL,
		0xC6BEF33594AD9B74ULL,
		0x1C2BAB973B2051BEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E79300000000000ULL,
		0xC638BAAA2E8B3013ULL,
		0xC82D5C0ADDA5BCFEULL,
		0x664F314557C5B26FULL,
		0x965DE13B715020E2ULL,
		0x5B36E8342F24B5B0ULL,
		0x40A37D8D7DE66B29ULL,
		0x0000003857572E76ULL
	}};
	shift = 41;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46C8333C63F80353ULL,
		0x2E30B8ED84E72C04ULL,
		0x4C1859D0F6DA80DAULL,
		0xEB88C3FFFB81DB5FULL,
		0xD4FA42520AAC6486ULL,
		0x1AEB84686C26A81AULL,
		0x1B69930A20824672ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F006A6000000000ULL,
		0x9CE58088D906678CULL,
		0xDB501B45C6171DB0ULL,
		0x703B6BE9830B3A1EULL,
		0x558C90DD71187FFFULL,
		0x84D5035A9F484A41ULL,
		0x1048CE435D708D0DULL,
		0x000000036D326144ULL
	}};
	shift = 37;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBE01F3AA6476C54ULL,
		0x6E073DAA892A778DULL,
		0x98B0A7EF45437875ULL,
		0x9D1AB9965E1E9CAFULL,
		0x55002F2572C5D024ULL,
		0x9CBEC0AEDA5B2E30ULL,
		0x397FB091BBB1359AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB1500000000000ULL,
		0xA9DE37AF807CEA99ULL,
		0x0DE1D5B81CF6AA24ULL,
		0x7A72BE62C29FBD15ULL,
		0x174092746AE65978ULL,
		0x6CB8C15400BC95CBULL,
		0xC4D66A72FB02BB69ULL,
		0x000000E5FEC246EEULL
	}};
	shift = 42;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59883D235FB26301ULL,
		0x91FAC204F47D153FULL,
		0xCCC7234416011CC8ULL,
		0x2752805B9848E53AULL,
		0x221F61B46B36B292ULL,
		0xCB5EAB4AF5EC9B99ULL,
		0x5FFC2B289983719DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7EC98C040000000ULL,
		0x3D1F454FD6620F48ULL,
		0x05804732247EB081ULL,
		0xE612394EB331C8D1ULL,
		0x1ACDACA489D4A016ULL,
		0xBD7B26E64887D86DULL,
		0x2660DC6772D7AAD2ULL,
		0x0000000017FF0ACAULL
	}};
	shift = 30;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65E375B5C538F6FDULL,
		0x430E6BE75CCD51E2ULL,
		0x45CEE3189258E903ULL,
		0x01200C932131F3FCULL,
		0xA535135C4CA83A6BULL,
		0x976D12A84625B255ULL,
		0x403DFC407523AFDBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38F6FD0000000000ULL,
		0xCD51E265E375B5C5ULL,
		0x58E903430E6BE75CULL,
		0x31F3FC45CEE31892ULL,
		0xA83A6B01200C9321ULL,
		0x25B255A535135C4CULL,
		0x23AFDB976D12A846ULL,
		0x000000403DFC4075ULL
	}};
	shift = 40;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75F26B7C475A6F4AULL,
		0x4C60B0B2425FD8CAULL,
		0x7C483487DF63EF08ULL,
		0xE532302814922FF8ULL,
		0xA89441AF889AEEB1ULL,
		0xA3FDD879C53E105FULL,
		0x9674A1A7BEF9985DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD37A5000000000ULL,
		0x12FEC653AF935BE2ULL,
		0xFB1F784263058592ULL,
		0xA4917FC3E241A43EULL,
		0x44D7758F29918140ULL,
		0x29F082FD44A20D7CULL,
		0xF7CCC2ED1FEEC3CEULL,
		0x00000004B3A50D3DULL
	}};
	shift = 35;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92D2CA110CAB8001ULL,
		0xCA5468037427C7EAULL,
		0x5F9EDC1660AC79D1ULL,
		0x0045553548F47A0EULL,
		0x1CF66B4BFA4CC53DULL,
		0x391816C71EAC3879ULL,
		0x2A807832F108643DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0100000000000000ULL,
		0xEA92D2CA110CAB80ULL,
		0xD1CA5468037427C7ULL,
		0x0E5F9EDC1660AC79ULL,
		0x3D0045553548F47AULL,
		0x791CF66B4BFA4CC5ULL,
		0x3D391816C71EAC38ULL,
		0x002A807832F10864ULL
	}};
	shift = 56;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F476CE337F6E10CULL,
		0x45094BB15CEF4D3BULL,
		0x7EF9000446AFA8CCULL,
		0xE03002FC8F35975AULL,
		0x32225BC33B196B8EULL,
		0xD9B10D62D6AAE8E8ULL,
		0x716A23E43970C892ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6E10C000000000ULL,
		0xCEF4D3B3F476CE33ULL,
		0x6AFA8CC45094BB15ULL,
		0xF35975A7EF900044ULL,
		0xB196B8EE03002FC8ULL,
		0x6AAE8E832225BC33ULL,
		0x970C892D9B10D62DULL,
		0x0000000716A23E43ULL
	}};
	shift = 36;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00838CA263B8D225ULL,
		0xFC3535E945539977ULL,
		0xAE748498649226FFULL,
		0x52684E262E9358CBULL,
		0xDBB05149216CF082ULL,
		0x7F81E4A2F96B44C8ULL,
		0xB4399523A722B6DCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x131DC69128000000ULL,
		0x4A2A9CCBB8041C65ULL,
		0xC3249137FFE1A9AFULL,
		0x31749AC65D73A424ULL,
		0x490B678412934271ULL,
		0x17CB5A2646DD828AULL,
		0x1D3915B6E3FC0F25ULL,
		0x0000000005A1CCA9ULL
	}};
	shift = 27;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77BBA1192347D02FULL,
		0xEB74119790AC2286ULL,
		0x53D457F330CB84AFULL,
		0xCA3210A6E2201800ULL,
		0x891C3AA216A0F13FULL,
		0xA96C89CEF7AFFA91ULL,
		0xA4B326035863F7FFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F40BC0000000000ULL,
		0xB08A19DEEE84648DULL,
		0x2E12BFADD0465E42ULL,
		0x8060014F515FCCC3ULL,
		0x83C4FF28C8429B88ULL,
		0xBFEA462470EA885AULL,
		0x8FDFFEA5B2273BDEULL,
		0x00000292CC980D61ULL
	}};
	shift = 42;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5298D812046C668CULL,
		0x527380CC2FEDBF7CULL,
		0x698EC7E1039CC979ULL,
		0x9D31E073B8B12771ULL,
		0x4231938A97B8B2A2ULL,
		0xCC1263E2AEF1A554ULL,
		0xBEF033C56D6A5B4BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4600000000000000ULL,
		0xBE294C6C09023633ULL,
		0xBCA939C06617F6DFULL,
		0xB8B4C763F081CE64ULL,
		0x514E98F039DC5893ULL,
		0xAA2118C9C54BDC59ULL,
		0xA5E60931F15778D2ULL,
		0x005F7819E2B6B52DULL
	}};
	shift = 55;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23C7414B09862ECEULL,
		0x33D1929CA15E8DF6ULL,
		0x58DDCF2EE64844B5ULL,
		0xE9A51A44C206CF7DULL,
		0x470BB395AB57018DULL,
		0x8319847338C926B5ULL,
		0xE18D8E780ACA4DF4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BB3800000000000ULL,
		0xA37D88F1D052C261ULL,
		0x112D4CF464A72857ULL,
		0xB3DF563773CBB992ULL,
		0xC0637A6946913081ULL,
		0x49AD51C2ECE56AD5ULL,
		0x937D20C6611CCE32ULL,
		0x00003863639E02B2ULL
	}};
	shift = 46;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE2ED85DC0A7ECC4ULL,
		0xD1BFB5E0310D8548ULL,
		0x0842930C7F5A48AEULL,
		0xC9D8BA3A2BF3C86AULL,
		0x8E3D34BF5CE263B1ULL,
		0xA85C2677ED62C3E9ULL,
		0x500B13B6262E5D94ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ED85DC0A7ECC400ULL,
		0xBFB5E0310D8548CEULL,
		0x42930C7F5A48AED1ULL,
		0xD8BA3A2BF3C86A08ULL,
		0x3D34BF5CE263B1C9ULL,
		0x5C2677ED62C3E98EULL,
		0x0B13B6262E5D94A8ULL,
		0x0000000000000050ULL
	}};
	shift = 8;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8169E20AC1BAF872ULL,
		0x4BD5E6651D89294DULL,
		0xF4D9C61223FD9AF3ULL,
		0x707E358A75FB5298ULL,
		0x4209B4F0396EAC2CULL,
		0xDC6880989D8B8873ULL,
		0xF8F81AE49A967E93ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AC1BAF87200000ULL,
		0x6651D89294D8169EULL,
		0x61223FD9AF34BD5EULL,
		0x58A75FB5298F4D9CULL,
		0x4F0396EAC2C707E3ULL,
		0x0989D8B88734209BULL,
		0xAE49A967E93DC688ULL,
		0x00000000000F8F81ULL
	}};
	shift = 20;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0190D6FDCDDFEA7EULL,
		0x9673A489B0AB14B9ULL,
		0x7DEF7AA5C750A48BULL,
		0xBA1754D61FD4A0C2ULL,
		0xC225CDC847839D28ULL,
		0x502E75BA707A9D04ULL,
		0x4EF42E474FB5161FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6FDCDDFEA7E0000ULL,
		0xA489B0AB14B90190ULL,
		0x7AA5C750A48B9673ULL,
		0x54D61FD4A0C27DEFULL,
		0xCDC847839D28BA17ULL,
		0x75BA707A9D04C225ULL,
		0x2E474FB5161F502EULL,
		0x0000000000004EF4ULL
	}};
	shift = 16;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F124A49F2561D4AULL,
		0x27DCD71D86B1DD74ULL,
		0xEF9CB8DE4216C2C3ULL,
		0xB30424683576E13AULL,
		0x3B7121E432A2DC25ULL,
		0xF23AB4DADFF41643ULL,
		0x8EFECE5B70386CE0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124A49F2561D4A00ULL,
		0xDCD71D86B1DD749FULL,
		0x9CB8DE4216C2C327ULL,
		0x0424683576E13AEFULL,
		0x7121E432A2DC25B3ULL,
		0x3AB4DADFF416433BULL,
		0xFECE5B70386CE0F2ULL,
		0x000000000000008EULL
	}};
	shift = 8;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75D754BBA525CDBEULL,
		0xA7CCFE17C2392AE7ULL,
		0x1418FC2B1A1962B3ULL,
		0x056C5AC5968D35CBULL,
		0x7CE5929E3EF5AB3BULL,
		0xF6BDDC3298553068ULL,
		0x2A0ECA52665FA78FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9774A4B9B7C00000ULL,
		0xC2F847255CEEBAEAULL,
		0x8563432C5674F99FULL,
		0x58B2D1A6B962831FULL,
		0x53C7DEB56760AD8BULL,
		0x86530AA60D0F9CB2ULL,
		0x4A4CCBF4F1FED7BBULL,
		0x00000000000541D9ULL
	}};
	shift = 21;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865EF1A15B040AECULL,
		0x5DDEE8FC6361DA06ULL,
		0x88F8F4160F56C2C3ULL,
		0x6ED4BDEE218A0F38ULL,
		0x44DF893E98048399ULL,
		0x6BC20A016B8F67B7ULL,
		0x91C160A7C693FA91ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F78D0AD82057600ULL,
		0xEF747E31B0ED0343ULL,
		0x7C7A0B07AB6161AEULL,
		0x6A5EF710C5079C44ULL,
		0x6FC49F4C0241CCB7ULL,
		0xE10500B5C7B3DBA2ULL,
		0xE0B053E349FD48B5ULL,
		0x0000000000000048ULL
	}};
	shift = 7;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C08C844FF834A4DULL,
		0xAF0738C43BD07541ULL,
		0x57C47DA854B9A3CDULL,
		0x61337CED4F854E2EULL,
		0xF0F84261F99CD679ULL,
		0xDA9F7D8777DDF06FULL,
		0x81CBEC101F4BDDFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4D0000000000000ULL,
		0x5416C08C844FF834ULL,
		0x3CDAF0738C43BD07ULL,
		0xE2E57C47DA854B9AULL,
		0x67961337CED4F854ULL,
		0x06FF0F84261F99CDULL,
		0xDFADA9F7D8777DDFULL,
		0x00081CBEC101F4BDULL
	}};
	shift = 52;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AE5C3D6EEF0C339ULL,
		0x305F1EF8B396C17AULL,
		0x1DB659A7C38C5AF0ULL,
		0xAC2E12992B61B558ULL,
		0x32375CB329C3D5C0ULL,
		0x5857E6B787DCF283ULL,
		0x46311B452C5053C3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C80000000000000ULL,
		0xBD2D72E1EB777861ULL,
		0x78182F8F7C59CB60ULL,
		0xAC0EDB2CD3E1C62DULL,
		0xE05617094C95B0DAULL,
		0x41991BAE5994E1EAULL,
		0xE1AC2BF35BC3EE79ULL,
		0x0023188DA2962829ULL
	}};
	shift = 55;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CF44991A82EDA74ULL,
		0xC431A4505459CE96ULL,
		0xA2122F7202DD3A8CULL,
		0x1829A350F0DF536BULL,
		0xFA3ED5A32FB51366ULL,
		0x02C5320613710B82ULL,
		0x5DDE9C5457C96864ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EDA74000000000ULL,
		0x459CE963CF44991AULL,
		0x2DD3A8CC431A4505ULL,
		0x0DF536BA2122F720ULL,
		0xFB513661829A350FULL,
		0x3710B82FA3ED5A32ULL,
		0x7C9686402C532061ULL,
		0x00000005DDE9C545ULL
	}};
	shift = 36;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE96E060BB42C1C35ULL,
		0x2BF8092BB5364997ULL,
		0xD94516C7A56D1451ULL,
		0x526349F8A977886DULL,
		0xB5A260A88B1B5366ULL,
		0x5B1CC0E1F8397478ULL,
		0x3E506A6AE1F7849AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858386A000000000ULL,
		0xA6C932FD2DC0C176ULL,
		0xADA28A257F012576ULL,
		0x2EF10DBB28A2D8F4ULL,
		0x636A6CCA4C693F15ULL,
		0x072E8F16B44C1511ULL,
		0x3EF0934B63981C3FULL,
		0x00000007CA0D4D5CULL
	}};
	shift = 37;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0197FD8FFC4DDDDULL,
		0x3A14DEF0AE61F911ULL,
		0x79E4CB73B57C3CC1ULL,
		0x63AF0E26857A708CULL,
		0x50D1DAB3D63223B6ULL,
		0x3D124E804EA29A9AULL,
		0xE36AD7FBB5899B5BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x197FD8FFC4DDDD00ULL,
		0x14DEF0AE61F911A0ULL,
		0xE4CB73B57C3CC13AULL,
		0xAF0E26857A708C79ULL,
		0xD1DAB3D63223B663ULL,
		0x124E804EA29A9A50ULL,
		0x6AD7FBB5899B5B3DULL,
		0x00000000000000E3ULL
	}};
	shift = 8;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x985C27F875B37D8DULL,
		0xF9E19A064793947BULL,
		0x93077661B98D9BC0ULL,
		0xBE53A919080B75A3ULL,
		0x5E0315743FA632C5ULL,
		0x2F70532894D89ED0ULL,
		0xEFE9E7F513678537ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61709FE1D6CDF634ULL,
		0xE78668191E4E51EEULL,
		0x4C1DD986E6366F03ULL,
		0xF94EA464202DD68EULL,
		0x780C55D0FE98CB16ULL,
		0xBDC14CA253627B41ULL,
		0xBFA79FD44D9E14DCULL,
		0x0000000000000003ULL
	}};
	shift = 2;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03BDD7EC82695A29ULL,
		0xA1E1DC6253962885ULL,
		0x10EEF6BFA8A9135CULL,
		0x8E201CD72CA97E45ULL,
		0xCB7BBCD7460AE4DDULL,
		0x015713623F530375ULL,
		0xBD0711A6D82967A4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x81DEEBF64134AD14ULL,
		0x50F0EE3129CB1442ULL,
		0x88777B5FD45489AEULL,
		0xC7100E6B9654BF22ULL,
		0xE5BDDE6BA305726EULL,
		0x00AB89B11FA981BAULL,
		0x5E8388D36C14B3D2ULL
	}};
	shift = 63;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61EEF03743D58F39ULL,
		0xB5BFE2EA1E8B626CULL,
		0x9C6850F47F51D868ULL,
		0x9A450B5E60497D30ULL,
		0xE405D6C91796BABFULL,
		0x9CDA8190D5EA9D3CULL,
		0x3C1B2D9B49EC0132ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA1EAC79C800000ULL,
		0x750F45B13630F778ULL,
		0x7A3FA8EC345ADFF1ULL,
		0xAF3024BE984E3428ULL,
		0x648BCB5D5FCD2285ULL,
		0xC86AF54E9E7202EBULL,
		0xCDA4F600994E6D40ULL,
		0x00000000001E0D96ULL
	}};
	shift = 23;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FDB4408AD3878D2ULL,
		0xB8B267BC5405A4ACULL,
		0x2FE1BB50BAEFCCB1ULL,
		0x0A3CC34053935544ULL,
		0xB77489D9C42B8EB9ULL,
		0xAD4924176A1878C3ULL,
		0x0D0139A65A5EA30DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4E1E34800000000ULL,
		0x501692B13F6D1022ULL,
		0xEBBF32C6E2C99EF1ULL,
		0x4E4D5510BF86ED42ULL,
		0x10AE3AE428F30D01ULL,
		0xA861E30EDDD22767ULL,
		0x697A8C36B524905DULL,
		0x000000003404E699ULL
	}};
	shift = 34;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBEF4130460844C3ULL,
		0x12D6E95596709B2CULL,
		0xF02E9C45EBB99620ULL,
		0x107AD0BBF91BF825ULL,
		0x39205739C25FA920ULL,
		0x043B139345AC324FULL,
		0xB3B04B985711A5C1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x3AFBD04C11821130ULL,
		0x04B5BA55659C26CBULL,
		0x7C0BA7117AEE6588ULL,
		0x041EB42EFE46FE09ULL,
		0xCE4815CE7097EA48ULL,
		0x410EC4E4D16B0C93ULL,
		0x2CEC12E615C46970ULL
	}};
	shift = 62;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA715B31D5D2BD67DULL,
		0xEDD433FDB5B74F09ULL,
		0x24D24A39E02A0A9FULL,
		0x07582E535FB38B5DULL,
		0x4FBF948FB245FA42ULL,
		0x4A23411B7D8526C1ULL,
		0x2AFBD0E8D929B5F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D5D2BD67D00000ULL,
		0x3FDB5B74F09A715BULL,
		0xA39E02A0A9FEDD43ULL,
		0xE535FB38B5D24D24ULL,
		0x48FB245FA4207582ULL,
		0x11B7D8526C14FBF9ULL,
		0x0E8D929B5F94A234ULL,
		0x000000000002AFBDULL
	}};
	shift = 20;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD38F9FBCF037BB45ULL,
		0x3E50D0914BDA21C4ULL,
		0xAD4A02EA848D18DFULL,
		0x7AAA0487D76AE675ULL,
		0xD7F12C0F647D6FB0ULL,
		0x902C0CC50CF148D1ULL,
		0x53E3A623D8FD7807ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768A000000000000ULL,
		0x4389A71F3F79E06FULL,
		0x31BE7CA1A12297B4ULL,
		0xCCEB5A9405D5091AULL,
		0xDF60F554090FAED5ULL,
		0x91A3AFE2581EC8FAULL,
		0xF00F2058198A19E2ULL,
		0x0000A7C74C47B1FAULL
	}};
	shift = 49;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF925BB3E90CC7132ULL,
		0xB2026E952BB17CE2ULL,
		0xB7606EEC8C50998AULL,
		0xF30C5866EFA14C97ULL,
		0x2297B2C8E6495386ULL,
		0xC6018FD9D73D93C8ULL,
		0xE7B924037EB18107ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C4C80000000000ULL,
		0xC5F38BE496ECFA43ULL,
		0x42662AC809BA54AEULL,
		0x85325EDD81BBB231ULL,
		0x254E1BCC31619BBEULL,
		0xF64F208A5ECB2399ULL,
		0xC6041F18063F675CULL,
		0x0000039EE4900DFAULL
	}};
	shift = 42;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC3B7BC84732F5A8ULL,
		0xF04F5EF342CAA0EFULL,
		0x6DC1DA3B39865B1FULL,
		0x08884BE360401883ULL,
		0x5201AA93E4F859D3ULL,
		0xF6300DFB8408FDBAULL,
		0x85D1E4177F17128FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB500000000000000ULL,
		0x1DFD876F7908E65EULL,
		0x63FE09EBDE685954ULL,
		0x106DB83B476730CBULL,
		0x3A6111097C6C0803ULL,
		0xB74A4035527C9F0BULL,
		0x51FEC601BF70811FULL,
		0x0010BA3C82EFE2E2ULL
	}};
	shift = 53;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x814696A54EA2AAEBULL,
		0x969F3B8DD3C90311ULL,
		0xCC661E843DD19F8EULL,
		0x49436B0AE2D5FB2DULL,
		0xEBC77F62851712E9ULL,
		0x0947B316B12FD2EAULL,
		0x2596D3A932A34AD7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A54EA2AAEB0000ULL,
		0x3B8DD3C903118146ULL,
		0x1E843DD19F8E969FULL,
		0x6B0AE2D5FB2DCC66ULL,
		0x7F62851712E94943ULL,
		0xB316B12FD2EAEBC7ULL,
		0xD3A932A34AD70947ULL,
		0x0000000000002596ULL
	}};
	shift = 16;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C6CFFF2418F2A97ULL,
		0x9AA982A01957D273ULL,
		0x19032549DEE7CAFAULL,
		0x287E5EB3A30ACADBULL,
		0x772DA001472BCF7CULL,
		0x98C38D73DF76CCFBULL,
		0xAEFF1F4BF874F214ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC9063CAA5C0000ULL,
		0x0A80655F49CD31B3ULL,
		0x95277B9F2BEA6AA6ULL,
		0x7ACE8C2B2B6C640CULL,
		0x80051CAF3DF0A1F9ULL,
		0x35CF7DDB33EDDCB6ULL,
		0x7D2FE1D3C852630EULL,
		0x000000000002BBFCULL
	}};
	shift = 18;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98B61623023AD079ULL,
		0x02738C5DF36DB64AULL,
		0x9985D9F82A7A065AULL,
		0x6127E6FF68C7E61CULL,
		0xFCE2ABFD646D5C23ULL,
		0x36B8C6FA6FA43081ULL,
		0xF4A44F81C259BA78ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0475A0F200000000ULL,
		0xE6DB6C95316C2C46ULL,
		0x54F40CB404E718BBULL,
		0xD18FCC39330BB3F0ULL,
		0xC8DAB846C24FCDFEULL,
		0xDF486103F9C557FAULL,
		0x84B374F06D718DF4ULL,
		0x00000001E9489F03ULL
	}};
	shift = 33;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0AE7F1C91CF1DA8ULL,
		0x1C4F64AD38E46765ULL,
		0xE83E33D935AF337BULL,
		0x75975DC28A6062FDULL,
		0xA3A338E8D810AA77ULL,
		0x79CECEE7623240BBULL,
		0xE8743F997F545963ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE7F1C91CF1DA800ULL,
		0x4F64AD38E46765F0ULL,
		0x3E33D935AF337B1CULL,
		0x975DC28A6062FDE8ULL,
		0xA338E8D810AA7775ULL,
		0xCECEE7623240BBA3ULL,
		0x743F997F54596379ULL,
		0x00000000000000E8ULL
	}};
	shift = 8;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40031F7B70EB31F6ULL,
		0xB11D95F35F24F1DCULL,
		0x5399DD70381B6311ULL,
		0x46A99E6486A84FD3ULL,
		0x78AA350BC2A8163DULL,
		0xAF108B1BB1B86630ULL,
		0x466A2F0628EEFAEFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB70EB31F60000000ULL,
		0x35F24F1DC40031F7ULL,
		0x0381B6311B11D95FULL,
		0x486A84FD35399DD7ULL,
		0xBC2A8163D46A99E6ULL,
		0xBB1B8663078AA350ULL,
		0x628EEFAEFAF108B1ULL,
		0x000000000466A2F0ULL
	}};
	shift = 28;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD238FCFD03AC3C33ULL,
		0xE733C843AD34E026ULL,
		0xB83B908341C8775BULL,
		0x0ED5B3BCE891F53EULL,
		0xC9547E8DBACFC2F3ULL,
		0x40CE09FF678A494DULL,
		0x42E2DAA7BE01F9F0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFD03AC3C3300000ULL,
		0x843AD34E026D238FULL,
		0x08341C8775BE733CULL,
		0x3BCE891F53EB83B9ULL,
		0xE8DBACFC2F30ED5BULL,
		0x9FF678A494DC9547ULL,
		0xAA7BE01F9F040CE0ULL,
		0x0000000000042E2DULL
	}};
	shift = 20;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A6D4BA6FA95E0AULL,
		0x39D0880E73E88969ULL,
		0x9033F071C0D368F9ULL,
		0x139CA6F869596CD4ULL,
		0x56DE811A947BC697ULL,
		0x8613DA79FA0D873DULL,
		0xF52BEE8C75A61FB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D4BA6FA95E0A000ULL,
		0x0880E73E8896915AULL,
		0x3F071C0D368F939DULL,
		0xCA6F869596CD4903ULL,
		0xE811A947BC697139ULL,
		0x3DA79FA0D873D56DULL,
		0xBEE8C75A61FB4861ULL,
		0x0000000000000F52ULL
	}};
	shift = 12;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5190B80124D80FCAULL,
		0x75A6BA95643D8ACAULL,
		0xFBCA19C80EFB7498ULL,
		0xA071383607C30586ULL,
		0x456CF631727031CFULL,
		0xF248171A7C19DD56ULL,
		0xB3DA87A853E9F7E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5190B80124D80FCAULL,
		0x75A6BA95643D8ACAULL,
		0xFBCA19C80EFB7498ULL,
		0xA071383607C30586ULL,
		0x456CF631727031CFULL,
		0xF248171A7C19DD56ULL,
		0xB3DA87A853E9F7E5ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC47B8BD171DD395CULL,
		0x44385F3E7DA5F3EAULL,
		0xCBC1CC9F77C56343ULL,
		0x6E485ED3DB973CEFULL,
		0x6D9C6440E29B9FE6ULL,
		0x67799B31D08D81C9ULL,
		0x012D742D7F901FC0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD395C00000000000ULL,
		0x5F3EAC47B8BD171DULL,
		0x5634344385F3E7DAULL,
		0x73CEFCBC1CC9F77CULL,
		0xB9FE66E485ED3DB9ULL,
		0xD81C96D9C6440E29ULL,
		0x01FC067799B31D08ULL,
		0x00000012D742D7F9ULL
	}};
	shift = 44;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE3B5D8BFAB40CD0ULL,
		0x51488C2B223DCB9EULL,
		0x407C4FA6AD7D9D14ULL,
		0x3319D2A6C631FFA6ULL,
		0x93DDBF1727B1A050ULL,
		0x7A1AE915A239CEF2ULL,
		0x5F14D2A48989DE35ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC5FD5A06680000ULL,
		0x4615911EE5CF5F1DULL,
		0x27D356BECE8A28A4ULL,
		0xE9536318FFD3203EULL,
		0xDF8B93D8D028198CULL,
		0x748AD11CE77949EEULL,
		0x695244C4EF1ABD0DULL,
		0x0000000000002F8AULL
	}};
	shift = 15;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x643382A56AEF1FC4ULL,
		0xAB4F8A0BCBB4D68EULL,
		0x0E110A118CDC61B6ULL,
		0x035EC4FC2FF40AFBULL,
		0x157C139A89436AF6ULL,
		0x140774F48798217AULL,
		0x1C0E9F78467AF49FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xE643382A56AEF1FCULL,
		0x6AB4F8A0BCBB4D68ULL,
		0xB0E110A118CDC61BULL,
		0x6035EC4FC2FF40AFULL,
		0xA157C139A89436AFULL,
		0xF140774F48798217ULL,
		0x01C0E9F78467AF49ULL
	}};
	shift = 60;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0FB3435156D4ED5ULL,
		0x733F2CC4CB6C14FDULL,
		0xE96D767D5BA7E006ULL,
		0x4D250BABA987C4DAULL,
		0x2D2C1925BE533DFFULL,
		0xB054D87154F70995ULL,
		0x9E99070032627E10ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D9A1A8AB6A76A8ULL,
		0x99F966265B60A7EFULL,
		0x4B6BB3EADD3F0033ULL,
		0x69285D5D4C3E26D7ULL,
		0x6960C92DF299EFFAULL,
		0x82A6C38AA7B84CA9ULL,
		0xF4C838019313F085ULL,
		0x0000000000000004ULL
	}};
	shift = 3;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4660739C4035F56ULL,
		0xE9E43A3D1D007B16ULL,
		0x270EA60E763ECC70ULL,
		0x2D992A2C31A91807ULL,
		0xB29327C74ACD42A3ULL,
		0xEA177069A1F632CAULL,
		0x7B9821D5A94D4DBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7100D7D580000000ULL,
		0x47401EC5BD1981CEULL,
		0x9D8FB31C3A790E8FULL,
		0x0C6A4601C9C3A983ULL,
		0xD2B350A8CB664A8BULL,
		0x687D8CB2ACA4C9F1ULL,
		0x6A53536F3A85DC1AULL,
		0x000000001EE60875ULL
	}};
	shift = 30;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1D3431EC1A683DULL,
		0x899EEDB8ADF66CC0ULL,
		0xF1F35568D51B1EE9ULL,
		0x1A3D9B71148C763CULL,
		0xF63237137293499DULL,
		0x2F9501303FEDD15AULL,
		0x6EE56A01DEE9A1F9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18F60D341E80000ULL,
		0x6DC56FB36603E0E9ULL,
		0xAB46A8D8F74C4CF7ULL,
		0xDB88A463B1E78F9AULL,
		0xB89B949A4CE8D1ECULL,
		0x0981FF6E8AD7B191ULL,
		0x500EF74D0FC97CA8ULL,
		0x000000000003772BULL
	}};
	shift = 19;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6444EA66FABB9697ULL,
		0x6984825AB5F88639ULL,
		0x8F8F9A2CEFD26FA4ULL,
		0x01DD99C3FAAFCBE9ULL,
		0xCC00578E899F5D1DULL,
		0x74485A1657E56B2BULL,
		0xB03E724259489342ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB969700000000000ULL,
		0x886396444EA66FABULL,
		0x26FA46984825AB5FULL,
		0xFCBE98F8F9A2CEFDULL,
		0xF5D1D01DD99C3FAAULL,
		0x56B2BCC00578E899ULL,
		0x8934274485A1657EULL,
		0x00000B03E7242594ULL
	}};
	shift = 44;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81B746D33D6770BEULL,
		0x745670C22CD1438EULL,
		0x8FE81A0411983BACULL,
		0x5D40C9C81EF7BBB7ULL,
		0x6B2E41AAC323810BULL,
		0xBC598EEC2FAB3630ULL,
		0x33E4ED078466A59DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B746D33D6770BE0ULL,
		0x45670C22CD1438E8ULL,
		0xFE81A0411983BAC7ULL,
		0xD40C9C81EF7BBB78ULL,
		0xB2E41AAC323810B5ULL,
		0xC598EEC2FAB36306ULL,
		0x3E4ED078466A59DBULL,
		0x0000000000000003ULL
	}};
	shift = 4;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A0F6B52E00BFE1DULL,
		0x93CA5D7DFCFA9D0DULL,
		0xF2671502148530DBULL,
		0x264945283060F902ULL,
		0x9EA119F2AF59982FULL,
		0xD5AD258AC8B0B27BULL,
		0x62C4266BD9C9A7CAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3A000000000000ULL,
		0x3A1AD41ED6A5C017ULL,
		0x61B72794BAFBF9F5ULL,
		0xF205E4CE2A04290AULL,
		0x305E4C928A5060C1ULL,
		0x64F73D4233E55EB3ULL,
		0x4F95AB5A4B159161ULL,
		0x0000C5884CD7B393ULL
	}};
	shift = 49;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E9B26385CA16E8ULL,
		0xFABA47B6FD8E0D29ULL,
		0x0FC3201B70DEA224ULL,
		0x87AE65041E1F8358ULL,
		0x198D8A3D23E173BEULL,
		0xA35CE55703859208ULL,
		0xEDBEE9DFFCE4B656ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC70B942DD0000000ULL,
		0x6DFB1C1A5205D364ULL,
		0x36E1BD4449F5748FULL,
		0x083C3F06B01F8640ULL,
		0x7A47C2E77D0F5CCAULL,
		0xAE070B2410331B14ULL,
		0xBFF9C96CAD46B9CAULL,
		0x0000000001DB7DD3ULL
	}};
	shift = 25;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D0928FB445F7273ULL,
		0xAB1CD253ECF2B32AULL,
		0xAC16335F8C18358AULL,
		0xF1A70582068CA4E9ULL,
		0xA2EF409AE8EEC3ECULL,
		0x531A405728C8AA86ULL,
		0xF7D764E7187CB984ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FB9398000000000ULL,
		0x7959951E84947DA2ULL,
		0x0C1AC5558E6929F6ULL,
		0x465274D60B19AFC6ULL,
		0x7761F678D382C103ULL,
		0x6455435177A04D74ULL,
		0x3E5CC2298D202B94ULL,
		0x0000007BEBB2738CULL
	}};
	shift = 39;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC779634344AF8DD6ULL,
		0xF02233E388F2F1A9ULL,
		0x2F1FE478441BAA75ULL,
		0x981CA319FA85830EULL,
		0xC02834442BD6306EULL,
		0x8BCBD0FD0CD8CF17ULL,
		0xFF863B621B6C883CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC0000000000000ULL,
		0x3538EF2C686895F1ULL,
		0x4EBE04467C711E5EULL,
		0x61C5E3FC8F088375ULL,
		0x0DD30394633F50B0ULL,
		0xE2F8050688857AC6ULL,
		0x0791797A1FA19B19ULL,
		0x001FF0C76C436D91ULL
	}};
	shift = 53;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98021DE57F63DEFDULL,
		0x0CC9886B23FA9BF7ULL,
		0xB18C82B132DD6EACULL,
		0x3DD3715458D3649CULL,
		0xC89860680D481BACULL,
		0x15A789EC6E4EE001ULL,
		0x47890D966FFAC293ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21DE57F63DEFD000ULL,
		0x9886B23FA9BF7980ULL,
		0xC82B132DD6EAC0CCULL,
		0x3715458D3649CB18ULL,
		0x860680D481BAC3DDULL,
		0x789EC6E4EE001C89ULL,
		0x90D966FFAC29315AULL,
		0x0000000000000478ULL
	}};
	shift = 12;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43B4FD70FFB4FA5FULL,
		0x5A87393EB7A80718ULL,
		0x579EC25F0E553CFAULL,
		0x840C99F6963BF573ULL,
		0xE7CCB8128B353205ULL,
		0xD159E1074E26462FULL,
		0x1329B9FF3C56E34FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FDA7D2F80000000ULL,
		0x5BD4038C21DA7EB8ULL,
		0x872A9E7D2D439C9FULL,
		0x4B1DFAB9ABCF612FULL,
		0x459A9902C2064CFBULL,
		0xA7132317F3E65C09ULL,
		0x9E2B71A7E8ACF083ULL,
		0x000000000994DCFFULL
	}};
	shift = 31;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED1BA0FA0073A928ULL,
		0x9B3824F59CB774E6ULL,
		0x9A93A852A1966909ULL,
		0x87FCE66F1463FBAFULL,
		0x45DA8BF873887402ULL,
		0x0C4887D2FAA69AA0ULL,
		0x1DD7CC914A81BF0CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A92800000000000ULL,
		0x774E6ED1BA0FA007ULL,
		0x669099B3824F59CBULL,
		0x3FBAF9A93A852A19ULL,
		0x8740287FCE66F146ULL,
		0x69AA045DA8BF8738ULL,
		0x1BF0C0C4887D2FAAULL,
		0x000001DD7CC914A8ULL
	}};
	shift = 44;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87427B8195EAF5D1ULL,
		0x94969075DAE6B478ULL,
		0x748C8C36E9C25CE4ULL,
		0x3F75EDEC4A9B350DULL,
		0xC3635B626973444BULL,
		0x1243ED57F54C040BULL,
		0x9B98238A917A5FFAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x10E84F7032BD5EBAULL,
		0x9292D20EBB5CD68FULL,
		0xAE919186DD384B9CULL,
		0x67EEBDBD895366A1ULL,
		0x786C6B6C4D2E6889ULL,
		0x42487DAAFEA98081ULL,
		0x13730471522F4BFFULL
	}};
	shift = 61;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76ABF0D27E72DC52ULL,
		0x9602618B7A782CF9ULL,
		0xC87F1B1DF785DFD6ULL,
		0x79D2240E315BC3C9ULL,
		0xF2676EA77EFA7455ULL,
		0xE9CA1F1E9646D264ULL,
		0x66B621A60698EBB6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB7148000000000ULL,
		0x9E0B3E5DAAFC349FULL,
		0xE177F5A5809862DEULL,
		0x56F0F2721FC6C77DULL,
		0xBE9D155E7489038CULL,
		0x91B4993C99DBA9DFULL,
		0xA63AEDBA7287C7A5ULL,
		0x00000019AD886981ULL
	}};
	shift = 38;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F92799AC79AAFF9ULL,
		0x5402039776C2A542ULL,
		0xD4C735B2D67395C4ULL,
		0xE979B26137A3F225ULL,
		0xB94A221AB288F58CULL,
		0x408142094D1E995CULL,
		0x51F8BD406DC988F2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFF9000000000000ULL,
		0xA5426F92799AC79AULL,
		0x95C45402039776C2ULL,
		0xF225D4C735B2D673ULL,
		0xF58CE979B26137A3ULL,
		0x995CB94A221AB288ULL,
		0x88F2408142094D1EULL,
		0x000051F8BD406DC9ULL
	}};
	shift = 48;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD83FBF6911BB9058ULL,
		0x521AD266F371DD23ULL,
		0xBAA7472468001932ULL,
		0x345B5DBF813A51FDULL,
		0x74144BD0F5E13967ULL,
		0xB34A62ECBDF85B1EULL,
		0xA6CE3152C04AF4AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F7ED2237720B00ULL,
		0x435A4CDE6E3BA47BULL,
		0x54E8E48D0003264AULL,
		0x8B6BB7F0274A3FB7ULL,
		0x82897A1EBC272CE6ULL,
		0x694C5D97BF0B63CEULL,
		0xD9C62A58095E95D6ULL,
		0x0000000000000014ULL
	}};
	shift = 5;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC63BCFABD545A782ULL,
		0x833DB816597C9816ULL,
		0x83AAE2F4C5F7B15AULL,
		0xD9A445D6A049717FULL,
		0xEF319087E2C3E0A3ULL,
		0x2C0B80B806708101ULL,
		0x641ADD34B9F4DB4FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF3EAF55169E080ULL,
		0xCF6E05965F2605B1ULL,
		0xEAB8BD317DEC56A0ULL,
		0x691175A8125C5FE0ULL,
		0xCC6421F8B0F828F6ULL,
		0x02E02E019C20407BULL,
		0x06B74D2E7D36D3CBULL,
		0x0000000000000019ULL
	}};
	shift = 6;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B7DBDAC05CDD9C3ULL,
		0xFA6350C3418914B5ULL,
		0x1B2547DD8EB11B12ULL,
		0x4675E8C208E8FF1CULL,
		0xEACA236A13187C25ULL,
		0x2C580712442E9B5EULL,
		0x81764F59C927CF5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F6B01737670C000ULL,
		0xD430D062452D62DFULL,
		0x51F763AC46C4BE98ULL,
		0x7A30823A3FC706C9ULL,
		0x88DA84C61F09519DULL,
		0x01C4910BA6D7BAB2ULL,
		0x93D67249F3D68B16ULL,
		0x000000000000205DULL
	}};
	shift = 14;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E3110ACFB7B0CB0ULL,
		0xED7879FDCABF1738ULL,
		0xE58C9EBF5A7B07ACULL,
		0x6D4DEE103DCF41B9ULL,
		0xBB1AEE4E5B18B6B5ULL,
		0xB15729E6946611F5ULL,
		0xA58B9AB5A24F14AAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71888567DBD86580ULL,
		0x6BC3CFEE55F8B9C0ULL,
		0x2C64F5FAD3D83D67ULL,
		0x6A6F7081EE7A0DCFULL,
		0xD8D77272D8C5B5ABULL,
		0x8AB94F34A3308FADULL,
		0x2C5CD5AD1278A555ULL,
		0x0000000000000005ULL
	}};
	shift = 3;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD5D4D505084B246ULL,
		0x233273F78FC41F5FULL,
		0x82832C26652186ECULL,
		0x409B1A25F2560CFFULL,
		0x4489A3D7891AD7B7ULL,
		0xD7E652F2656D2A36ULL,
		0x85E46110D4FD2D9CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDEAEA6A828425923ULL,
		0x119939FBC7E20FAFULL,
		0xC14196133290C376ULL,
		0xA04D8D12F92B067FULL,
		0x2244D1EBC48D6BDBULL,
		0x6BF3297932B6951BULL,
		0x42F230886A7E96CEULL
	}};
	shift = 63;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C865EF3447F1397ULL,
		0xD0C4CED88E61431AULL,
		0x95FBBFFE09123319ULL,
		0x23ECC0ABF9724D3EULL,
		0x9214C066AC0FD845ULL,
		0xB2020AB821FA9163ULL,
		0xAB5C82FAAB440B8BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A23F89CB800000ULL,
		0x6C4730A18D4E432FULL,
		0xFF0489198CE86267ULL,
		0x55FCB9269F4AFDDFULL,
		0x335607EC2291F660ULL,
		0x5C10FD48B1C90A60ULL,
		0x7D55A205C5D90105ULL,
		0x000000000055AE41ULL
	}};
	shift = 23;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3ABAA9076679B6EULL,
		0xD9D08F6B1B6111F5ULL,
		0x77BA9A52C163C220ULL,
		0x8EF2CE0670BC40D6ULL,
		0x8E1984C8005C65D9ULL,
		0x98AAEEC207553E66ULL,
		0x7B9AFE0F3F1E9079ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC00000000000000ULL,
		0xEBA7575520ECCF36ULL,
		0x41B3A11ED636C223ULL,
		0xACEF7534A582C784ULL,
		0xB31DE59C0CE17881ULL,
		0xCD1C33099000B8CBULL,
		0xF33155DD840EAA7CULL,
		0x00F735FC1E7E3D20ULL
	}};
	shift = 57;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE54FC57CF408BD31ULL,
		0x5C3CDA19C8F01BD3ULL,
		0x65D4D1F1467C787BULL,
		0xEDB7835CF054B82FULL,
		0x3D04C14D1D91A5ADULL,
		0xA15FD5749F6D1917ULL,
		0x671F714357137C30ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7E2BE7A045E9880ULL,
		0x1E6D0CE4780DE9F2ULL,
		0xEA68F8A33E3C3DAEULL,
		0xDBC1AE782A5C17B2ULL,
		0x8260A68EC8D2D6F6ULL,
		0xAFEABA4FB68C8B9EULL,
		0x8FB8A1AB89BE1850ULL,
		0x0000000000000033ULL
	}};
	shift = 7;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DBB54BEC253FDFULL,
		0x3B7F0036D35C40E4ULL,
		0x5E1D9CAD93E93FD5ULL,
		0xC1DA57422B538513ULL,
		0x807554F3DD7CD703ULL,
		0xEC2757AA323FC671ULL,
		0x9D3BD4FD95BF3DE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A97D84A7FBE000ULL,
		0xE006DA6B881C8AFBULL,
		0xB395B27D27FAA76FULL,
		0x4AE8456A70A26BC3ULL,
		0xAA9E7BAF9AE0783BULL,
		0xEAF54647F8CE300EULL,
		0x7A9FB2B7E7BCDD84ULL,
		0x00000000000013A7ULL
	}};
	shift = 13;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD28E90AC29770C9ULL,
		0xFC6ADD25F560EAC1ULL,
		0xE16E7C3D88BF07B9ULL,
		0xB2F6413DD25A0968ULL,
		0x9D1011BC8AFB3E2EULL,
		0x489D3A196D677400ULL,
		0x68DAE02BBF19AEFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA51D215852EE1920ULL,
		0x8D5BA4BEAC1D583BULL,
		0x2DCF87B117E0F73FULL,
		0x5EC827BA4B412D1CULL,
		0xA20237915F67C5D6ULL,
		0x13A7432DACEE8013ULL,
		0x1B5C0577E335DF89ULL,
		0x000000000000000DULL
	}};
	shift = 5;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6214560C9CDD66BULL,
		0x0FD32E0E50FECC80ULL,
		0x624A600DCC5F3633ULL,
		0x2BFC916723E6F93DULL,
		0x0EA51845C84B3B49ULL,
		0x6849F9D79A23AEC8ULL,
		0xB86055B0A71AC53FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3759AC0000000000ULL,
		0xFB32029885158327ULL,
		0x7CD8CC3F4CB83943ULL,
		0x9BE4F58929803731ULL,
		0x2CED24AFF2459C8FULL,
		0x8EBB203A94611721ULL,
		0x6B14FDA127E75E68ULL,
		0x000002E18156C29CULL
	}};
	shift = 42;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD91595CF716851CULL,
		0xE328171625C3889EULL,
		0x6ADA111898239340ULL,
		0x7E92A53DB1A18D18ULL,
		0xAFF5783F49C3F2A6ULL,
		0x6CF8C479E07E20C9ULL,
		0xBE2433304E8E9180ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD91595CF716851CULL,
		0xE328171625C3889EULL,
		0x6ADA111898239340ULL,
		0x7E92A53DB1A18D18ULL,
		0xAFF5783F49C3F2A6ULL,
		0x6CF8C479E07E20C9ULL,
		0xBE2433304E8E9180ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD91B7A76BD839501ULL,
		0xC3C6CBEAD672E7A8ULL,
		0x265A476BA21251DFULL,
		0xB811A9604A0AA424ULL,
		0x97F79EEAC473B10AULL,
		0xEC0D4951301C3F33ULL,
		0xE0BA565804ACF9E9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A76BD8395010000ULL,
		0xCBEAD672E7A8D91BULL,
		0x476BA21251DFC3C6ULL,
		0xA9604A0AA424265AULL,
		0x9EEAC473B10AB811ULL,
		0x4951301C3F3397F7ULL,
		0x565804ACF9E9EC0DULL,
		0x000000000000E0BAULL
	}};
	shift = 16;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x706D0C791E849783ULL,
		0xC51C1747119C0320ULL,
		0xA9174C61AA105AE5ULL,
		0x8BAFCD46BA32F825ULL,
		0x5D8827C0328984C5ULL,
		0xDD96727C277E45D0ULL,
		0x50B8FC80551D30D3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863C8F424BC18000ULL,
		0x0BA388CE01903836ULL,
		0xA630D5082D72E28EULL,
		0xE6A35D197C12D48BULL,
		0x13E01944C262C5D7ULL,
		0x393E13BF22E82EC4ULL,
		0x7E402A8E9869EECBULL,
		0x000000000000285CULL
	}};
	shift = 15;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF71DFC6A8A1887ADULL,
		0x1CFC4A5059C9183DULL,
		0xDE17B7C45D33EC5CULL,
		0x57F6CFF800609953ULL,
		0xEF39E98057875352ULL,
		0xA4A46FCCACF7EE4FULL,
		0xD8FD9D69EA9E3AC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD514310F5A000000ULL,
		0xA0B392307BEE3BF8ULL,
		0x88BA67D8B839F894ULL,
		0xF000C132A7BC2F6FULL,
		0x00AF0EA6A4AFED9FULL,
		0x9959EFDC9FDE73D3ULL,
		0xD3D53C75874948DFULL,
		0x0000000001B1FB3AULL
	}};
	shift = 25;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4D4F69CAB32F9D6ULL,
		0x6F0E76990A2AB114ULL,
		0x68FD49E409F20B86ULL,
		0xB965423B0E802BA5ULL,
		0xC6A0B3909876D001ULL,
		0xCAFC50073DF61FB8ULL,
		0xC88472CFD3C3C924ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395665F3AC000000ULL,
		0x321455622989A9EDULL,
		0xC813E4170CDE1CEDULL,
		0x761D00574AD1FA93ULL,
		0x2130EDA00372CA84ULL,
		0x0E7BEC3F718D4167ULL,
		0x9FA787924995F8A0ULL,
		0x00000000019108E5ULL
	}};
	shift = 25;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}