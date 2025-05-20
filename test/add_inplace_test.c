#include "tests.h"

int32_t curve25519_key_add_inplace_test(void) {
	printf("Add Inplace Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA39E03797AB3F9A1ULL,
		0x91559866DE654DE2ULL,
		0x168F799588B6DC43ULL,
		0x194FB10C8ED0D282ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x27573309E3B8F891ULL,
		0xD317EE20255A84A0ULL,
		0x5B0D950EC2830360ULL,
		0x4852B45EA4C1C7ACULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xCAF536835E6CF232ULL,
		0x646D868703BFD282ULL,
		0x719D0EA44B39DFA4ULL,
		0x61A2656B33929A2EULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC365426E8539B052ULL,
		0x10C1CF76085781E4ULL,
		0x5479A47FE562264CULL,
		0x48BC9889D0CEC411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18D89741B464078BULL,
		0x117E06D5173C8C0EULL,
		0x1E238665439C27E9ULL,
		0x77B53DE067414600ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC3DD9B0399DB7F0ULL,
		0x223FD64B1F940DF2ULL,
		0x729D2AE528FE4E35ULL,
		0x4071D66A38100A11ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7B4E52A9DE58A00ULL,
		0x580F2E9E162E9FF9ULL,
		0x307E52002A09EC2AULL,
		0x51DBFB94EB7C27E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FF0AD3FCEBE8F0ULL,
		0xA3F068CA1E365F62ULL,
		0x5339B9DB149C05F7ULL,
		0x67762BCFB49A2787ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00B3EFFE9AD17303ULL,
		0xFBFF97683464FF5CULL,
		0x83B80BDB3EA5F221ULL,
		0x39522764A0164F67ULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DFDC2CA8D1061A2ULL,
		0xF5FBBFCF0839BD87ULL,
		0x4F0A6B39BE07621AULL,
		0x4508E24DDAA91301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D84C7F20922DFE7ULL,
		0x01B3911C763F8696ULL,
		0x9D54EAFDDC479DF7ULL,
		0x28D7135CC84C3F86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB828ABC96334189ULL,
		0xF7AF50EB7E79441DULL,
		0xEC5F56379A4F0011ULL,
		0x6DDFF5AAA2F55287ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFD0C6E1AD489AD7ULL,
		0xE66B6F9459A7B074ULL,
		0xFF0384130400BA51ULL,
		0x740809828A24808CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B61E1B908893285ULL,
		0x581BFEFAD8A4BC06ULL,
		0xF496F5AEAC425415ULL,
		0x75F29D0ADCD7B156ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B32A89AB5D1CD6FULL,
		0x3E876E8F324C6C7BULL,
		0xF39A79C1B0430E67ULL,
		0x69FAA68D66FC31E3ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B12D4450BDB4941ULL,
		0x6E2E506CBFC038DBULL,
		0xE1F05F5DC4D35DB5ULL,
		0x12DCC7B1FD1A9095ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE011A53E5FB78B9ULL,
		0x68E1B9507AAB39B9ULL,
		0x56C4CC633EE814E6ULL,
		0x71E5E055BCCA90B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4913EE98F1D6C20DULL,
		0xD71009BD3A6B7295ULL,
		0x38B52BC103BB729BULL,
		0x04C2A807B9E5214BULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x138B527F00CF4B76ULL,
		0x93D6A2FD7B851760ULL,
		0x7774E7051D156336ULL,
		0x19730408BC23E2D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31779E1F5009580BULL,
		0xF54E83EA3FCFBDC9ULL,
		0xCA32B3D8D624672AULL,
		0x49D0493A8A212F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4502F09E50D8A381ULL,
		0x892526E7BB54D529ULL,
		0x41A79ADDF339CA61ULL,
		0x63434D434645126CULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5541614BB2316E5AULL,
		0x9D68D19C18C91154ULL,
		0x3411EB38153E6B3FULL,
		0x2B87FC861947D70DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x250960C7CAAF089AULL,
		0x9D7308DA4E903BB7ULL,
		0x07AA50A0D93FB67BULL,
		0x7D256C72E244400AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A4AC2137CE07707ULL,
		0x3ADBDA7667594D0BULL,
		0x3BBC3BD8EE7E21BBULL,
		0x28AD68F8FB8C1717ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA101E80D8AC14DFCULL,
		0xEE860C75A303E376ULL,
		0x85EDC33EB3FBA0B2ULL,
		0x53FBB4359BE6C9BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7832F2A29FF7C348ULL,
		0xA9E30C6730439094ULL,
		0xC69DD246C0ACA2CEULL,
		0x58E8D5555C787292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1934DAB02AB91157ULL,
		0x986918DCD347740BULL,
		0x4C8B958574A84381ULL,
		0x2CE4898AF85F3C4EULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13F71135C008197FULL,
		0xFBE1E73F39A53222ULL,
		0xA7A25A93517C2661ULL,
		0x0526BF1BF61BAEE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00AB38473AD89188ULL,
		0xE0ED5D0FA720DA37ULL,
		0xB075F72EDD26523DULL,
		0x6D50E54BE28C5A0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14A2497CFAE0AB07ULL,
		0xDCCF444EE0C60C59ULL,
		0x581851C22EA2789FULL,
		0x7277A467D8A808F7ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7DD8BB69D796F94ULL,
		0xC136C3BB32394FCEULL,
		0xE2820C33AB941323ULL,
		0x67EE6B33CD35A014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FCC8FA0B6FDB570ULL,
		0xBCA426DDF9836166ULL,
		0xB3D6873B1D78BBAAULL,
		0x5A9590822616D819ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17AA1B5754772517ULL,
		0x7DDAEA992BBCB135ULL,
		0x9658936EC90CCECEULL,
		0x4283FBB5F34C782EULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x391BABC6486628A9ULL,
		0xFDC0B0039C337220ULL,
		0xC1A191D8DE4C5A62ULL,
		0x24BB43C8F2A26A60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77A3FA107C33986BULL,
		0x04876E6E4B03927CULL,
		0x3E87A7F8BE93EB24ULL,
		0x18C642B47ABEE48FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0BFA5D6C499C114ULL,
		0x02481E71E737049CULL,
		0x002939D19CE04587ULL,
		0x3D81867D6D614EF0ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0794F7AEAF907E1ULL,
		0x819FCE8EC5C536CEULL,
		0xCE099313EAC3FC0BULL,
		0x034BA40084FCFD9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE52216F84800765ULL,
		0x496A48438FBB75F3ULL,
		0xCEF422607C328702ULL,
		0x58FACF3DE7006199ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ECB70EA6F790F46ULL,
		0xCB0A16D25580ACC2ULL,
		0x9CFDB57466F6830DULL,
		0x5C46733E6BFD5F38ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B19FE1BDCC58464ULL,
		0x6DB5AE5C26B5DBC3ULL,
		0xA3FC2384A3CE6BBBULL,
		0x3567BF6192D0FBB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62CBC15153635B0ULL,
		0xED0C0F28ED6335E7ULL,
		0x8344368AB3420D5AULL,
		0x36E6D13E38FBA237ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7146BA30F1FBBA14ULL,
		0x5AC1BD85141911ABULL,
		0x27405A0F57107916ULL,
		0x6C4E909FCBCC9DEDULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FA796C13ABAC5FFULL,
		0x70B865FEC3D976E8ULL,
		0x734DCFC61792C96DULL,
		0x5C5697A48A52FB3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05EEB9E23EEF748ULL,
		0x9707036375C4E8A0ULL,
		0x29061A78CC6FC43EULL,
		0x234222BFDD5E2A9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7006825F5EA9BD47ULL,
		0x07BF6962399E5F89ULL,
		0x9C53EA3EE4028DACULL,
		0x7F98BA6467B125DBULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B0DD55F9EE6EC5CULL,
		0x01066A049AF6F47AULL,
		0x413713030337F8A7ULL,
		0x174D82591E02E273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5EA66002FAA9B8ULL,
		0x3A09244785D0BF68ULL,
		0x797E82DEB412FC57ULL,
		0x0245CFB1ACEBFAD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956C7BBFA1E19614ULL,
		0x3B0F8E4C20C7B3E3ULL,
		0xBAB595E1B74AF4FEULL,
		0x1993520ACAEEDD43ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F4E9F170E04BCCDULL,
		0x11BE533394C445B3ULL,
		0x742810298CE815A2ULL,
		0x3661115DC51B9848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE465F22D810D725BULL,
		0x8C33A34CA8762AB2ULL,
		0x24E177D1A62AB328ULL,
		0x5D6D75969EDBA3EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3B491448F122F3BULL,
		0x9DF1F6803D3A7065ULL,
		0x990987FB3312C8CAULL,
		0x13CE86F463F73C37ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9155FA8D2A606971ULL,
		0x9AA5EE7C10EA5374ULL,
		0x123B90C3A86B1AADULL,
		0x17192335D809D9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58A8FCA247D8F213ULL,
		0x427BBC795BA7A2C4ULL,
		0x76407A4E836692F5ULL,
		0x496D958E49AD86F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9FEF72F72395B84ULL,
		0xDD21AAF56C91F638ULL,
		0x887C0B122BD1ADA2ULL,
		0x6086B8C421B760DAULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD2D14D07C48CE50ULL,
		0x443D33F96EC8328DULL,
		0x4E6D91CF1F6AE17BULL,
		0x252ED3183DF5458CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362259E1594B6388ULL,
		0x3F6AF3ADB6C6E7BEULL,
		0xC0A111631A055059ULL,
		0x500BC82FB524A2E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE34F6EB1D59431D8ULL,
		0x83A827A7258F1A4BULL,
		0x0F0EA332397031D4ULL,
		0x753A9B47F319E873ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22792A2D01380C21ULL,
		0x869C770990A8AA48ULL,
		0xE6ADE9968289089FULL,
		0x125C3AF075D17561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE3F7DEA16B3282ULL,
		0x7950F163547320CAULL,
		0xBE7BB371B96BA106ULL,
		0x3276DD75CA5CA05FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x525D220BA2A33EA3ULL,
		0xFFED686CE51BCB12ULL,
		0xA5299D083BF4A9A5ULL,
		0x44D31866402E15C1ULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ECC3A53939FC14EULL,
		0xF14F2EA91EBA18F8ULL,
		0xB5032086E8ADA8F9ULL,
		0x22F0BD74DD68E00FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EDC4768D69F1B47ULL,
		0x0CF3B616382A7FF4ULL,
		0x3E5C092AA4A501D7ULL,
		0x5A946A76B3E3D558ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA881BC6A3EDC95ULL,
		0xFE42E4BF56E498ECULL,
		0xF35F29B18D52AAD0ULL,
		0x7D8527EB914CB567ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0ABDE5962CCBF947ULL,
		0x9A566996626C522DULL,
		0xFD50EF622B470DA2ULL,
		0x52252655CD169EC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x804E41103F7A1089ULL,
		0x99B00C461A80AC0EULL,
		0x77142DAFF24143F7ULL,
		0x437047F2816088F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B0C26A66C4609E3ULL,
		0x340675DC7CECFE3BULL,
		0x74651D121D88519AULL,
		0x15956E484E7727B6ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48300837796E0B8BULL,
		0x13F32DFBB7256A44ULL,
		0x711AD03F6B02D3E0ULL,
		0x299F1C676C92B9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FADE67A020B4EF5ULL,
		0xB38BCFDE27ECBAD3ULL,
		0x883B6615B213C500ULL,
		0x35F75FBC2159DA18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67DDEEB17B795A80ULL,
		0xC77EFDD9DF122517ULL,
		0xF95636551D1698E0ULL,
		0x5F967C238DEC9412ULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7826422D2981EDCULL,
		0x66F520954E8F45D6ULL,
		0x991D489DB889766AULL,
		0x22D63C3FB6AC4880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15560BCFB18D05B9ULL,
		0x5D1B6AB683732EB7ULL,
		0x28560CD2091391BDULL,
		0x64FB6E8A17F3F0B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCD86FF2842524A8ULL,
		0xC4108B4BD202748DULL,
		0xC173556FC19D0827ULL,
		0x07D1AAC9CEA03933ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB963FDEEEE9A9F9DULL,
		0xE44E9F0CA198BBB5ULL,
		0x2BC4572B0C82CC0AULL,
		0x414F1DA15E663DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65762F6EECC37D5FULL,
		0xF06CD32BE26C1925ULL,
		0xB47BB957BE1BE471ULL,
		0x138B834BC4DCEB8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EDA2D5DDB5E1CFCULL,
		0xD4BB72388404D4DBULL,
		0xE0401082CA9EB07CULL,
		0x54DAA0ED23432970ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF740BDFC95D74F14ULL,
		0xE6C11CD48D22E315ULL,
		0x18F5C8B97D4944C8ULL,
		0x7EDCC8AA2FEB649BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC42E8442B9E3141ULL,
		0x5E24D4500E4D3291ULL,
		0xB5C9B746C1024857ULL,
		0x0E5AD7F56DF7BC90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC383A640C1758068ULL,
		0x44E5F1249B7015A7ULL,
		0xCEBF80003E4B8D20ULL,
		0x0D37A09F9DE3212BULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A22127F4F3608ACULL,
		0xC8F95F8A29B51F20ULL,
		0x0FE41BF9C3AA05E3ULL,
		0x7C29CAA84EC5118DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA69AA49A3957E5ULL,
		0xD20CFD0EADAE32A5ULL,
		0xD44C944B9F5AE1D9ULL,
		0x6D304A94326E3BCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7C8AD23E96F60A4ULL,
		0x9B065C98D76351C5ULL,
		0xE430B0456304E7BDULL,
		0x695A153C81334D5CULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD47C7431FA4A0A7ULL,
		0x6D7B4B64ABBF799FULL,
		0xA3497F818FC48F44ULL,
		0x06EF98F28DE9D67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D0DE9E55FD6735ULL,
		0x345E741978CCF87EULL,
		0x7BCCDB3C332DBA1BULL,
		0x7FE3531F4A9939D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0718A5E175A207EFULL,
		0xA1D9BF7E248C721EULL,
		0x1F165ABDC2F2495FULL,
		0x06D2EC11D883104FULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x896AB4984CA5AE8CULL,
		0x581606DA7AD5A23FULL,
		0x1FE02EC16047E83CULL,
		0x115F4074202D1627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFC3F85030FB2E4ULL,
		0x421EE2547DD47FDEULL,
		0x178BDF976B776A3AULL,
		0x3F33AA3483992D80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9866F41D4FB56170ULL,
		0x9A34E92EF8AA221DULL,
		0x376C0E58CBBF5276ULL,
		0x5092EAA8A3C643A7ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C7C9DEB8DE0983DULL,
		0xD9EEEE5DBDABD820ULL,
		0x312FAF0F9AA1258AULL,
		0x150E30D6971C93BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B63C32C20649DF5ULL,
		0x6786CFF02DD749B8ULL,
		0xB92726BAD594F5C3ULL,
		0x342F006F7A7094D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97E06117AE453632ULL,
		0x4175BE4DEB8321D8ULL,
		0xEA56D5CA70361B4EULL,
		0x493D3146118D288BULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB90B9922547F096ULL,
		0xA7239BA4ADF2D5C0ULL,
		0x81B0076A6FDCE27CULL,
		0x5C1FDA7DE2964B5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF77402E1CB5D39DCULL,
		0x7E74552884700757ULL,
		0xA780555B6A5499E4ULL,
		0x564E3CD7D9400E85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD304BC73F0A52A85ULL,
		0x2597F0CD3262DD18ULL,
		0x29305CC5DA317C61ULL,
		0x326E1755BBD659E5ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CB8AC34EA6CF738ULL,
		0xBEE136E550F09539ULL,
		0x17C2FBE820C8F27CULL,
		0x654FD29032478922ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x642E4CA22AFCD87BULL,
		0x5704C046B3234056ULL,
		0x75277A77A7EFA5EFULL,
		0x17F6AAA7EEED1F5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E6F8D71569CFB3ULL,
		0x15E5F72C0413D58FULL,
		0x8CEA765FC8B8986CULL,
		0x7D467D382134A87FULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C9C11F10D8B00BULL,
		0x919D51C96BE8D3A6ULL,
		0x886549794E842AB9ULL,
		0x5F2B9145FD44D064ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9CB7E7DF8566FCULL,
		0x74526AD2359BCF73ULL,
		0x1A1FC289FDB7A2F3ULL,
		0x0321EF554F94DA0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8667906F05E1707ULL,
		0x05EFBC9BA184A319ULL,
		0xA2850C034C3BCDADULL,
		0x624D809B4CD9AA72ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x765BA7EE1C6B9808ULL,
		0x4EA24E3E2653A6E4ULL,
		0x041399540B78E93CULL,
		0x4EA25A1356D7B50DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C5DFBFB931942AEULL,
		0x08B4E4469AAEC73DULL,
		0x07BFD2544EAE3328ULL,
		0x4B9CBC433571F921ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2B9A3E9AF84DAC9ULL,
		0x57573284C1026E21ULL,
		0x0BD36BA85A271C64ULL,
		0x1A3F16568C49AE2EULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC86ACEBC4A68B71EULL,
		0xAFCCD68A3D6478AAULL,
		0xF5D69DE5A7E70E12ULL,
		0x4A9E31B852BF610FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8339A67DB0984A04ULL,
		0xD256BF73C93CAF25ULL,
		0xEB3099ED80B59BB1ULL,
		0x2493B65816CB41EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA47539FB010122ULL,
		0x822395FE06A127D0ULL,
		0xE10737D3289CA9C4ULL,
		0x6F31E810698AA2FFULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4CF59183E5FC679ULL,
		0xCDD43E4D4B919FF3ULL,
		0x5874C78AA42256E9ULL,
		0x38A845ABF0E6B666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342A643FC561B683ULL,
		0x587A0F305B3F564DULL,
		0xD12BDF962855F4ABULL,
		0x61DB94225F9E4818ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8F9BD5803C17D0FULL,
		0x264E4D7DA6D0F640ULL,
		0x29A0A720CC784B95ULL,
		0x1A83D9CE5084FE7FULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79870BD2ADDF82BDULL,
		0xB3C2B8D2DE7BC36BULL,
		0x92A58AC7518EBA62ULL,
		0x60E40944C60CEA34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE576C3000BA3245FULL,
		0x63740830A9071080ULL,
		0xC34B4791975E2957ULL,
		0x3772818C865B6E28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5EFDCED2B982A72FULL,
		0x1736C1038782D3ECULL,
		0x55F0D258E8ECE3BAULL,
		0x18568AD14C68585DULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6EB198D928671BEULL,
		0x7D293214506DB715ULL,
		0x56FE13F94F6C84F9ULL,
		0x544C24E4713B02FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FAF3F124C51E3C5ULL,
		0x901460491CF71B53ULL,
		0x08AE02204014EB14ULL,
		0x283F593F842E897FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x469A589FDED85583ULL,
		0x0D3D925D6D64D269ULL,
		0x5FAC16198F81700EULL,
		0x7C8B7E23F5698C7AULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x562C0AF6C4AAEBDDULL,
		0x74F107320B6066DAULL,
		0xC4E240C085200CB5ULL,
		0x1B745F8EF0B0DE30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x533F1C718FDA230BULL,
		0x930639389A21E8B2ULL,
		0x3C2DD61A657254B9ULL,
		0x047C8D67730EDFD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA96B276854850EE8ULL,
		0x07F7406AA5824F8CULL,
		0x011016DAEA92616FULL,
		0x1FF0ECF663BFBE05ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9237AA831843E229ULL,
		0xBEE8F630FBC8BECBULL,
		0x1EA827A55A47F06FULL,
		0x6D67E8751C938C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C068A527476AEBEULL,
		0x86F026DCA15BFE30ULL,
		0xB8B518289BC56D03ULL,
		0x20BBFDB795727069ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE3E34D58CBA90FAULL,
		0x45D91D0D9D24BCFBULL,
		0xD75D3FCDF60D5D73ULL,
		0x0E23E62CB205FC98ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ACFE1AF3199F780ULL,
		0x8C0072EB2F494B92ULL,
		0x34B5BDB89626B58EULL,
		0x2D71DAD578F41F5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CED3A6BBF50386ULL,
		0x53BE3FB4B666D9FEULL,
		0x59BF0100FD362F36ULL,
		0x6520F8441F58AA54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C9EB555ED8EFB19ULL,
		0xDFBEB29FE5B02590ULL,
		0x8E74BEB9935CE4C4ULL,
		0x1292D319984CC9AEULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F009064B4C7F5DDULL,
		0xFD37961E6007259EULL,
		0x95C1C0169C20009CULL,
		0x0C7914CE86C33BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59E389EFF8FD1C6ULL,
		0xFC18AC7AE9DD5BECULL,
		0x49B42C79CD7B5C7EULL,
		0x015B7B3CA0BE99E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x449EC903B457C7A3ULL,
		0xF950429949E4818BULL,
		0xDF75EC90699B5D1BULL,
		0x0DD4900B2781D593ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C1062BE9F2D4BB1ULL,
		0x0EC78950F9054AF7ULL,
		0x2AE96C25108E6715ULL,
		0x0451DAF73964D388ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C8CA8C35E764A2DULL,
		0xD560BEC5BF22FF53ULL,
		0x79D53D540DCBE4D5ULL,
		0x6B4DA6FF5970D532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x889D0B81FDA395DEULL,
		0xE4284816B8284A4AULL,
		0xA4BEA9791E5A4BEAULL,
		0x6F9F81F692D5A8BAULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB6018B9BFDB3913ULL,
		0xEEDEA90DF340E6E6ULL,
		0x0F175184ECA4FDBDULL,
		0x58E1B932C945157EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3835D4A716B73D19ULL,
		0x275117A4BF8CF308ULL,
		0x5C4CAE2F3E6D63A3ULL,
		0x5648D191B7056322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1395ED60D692763FULL,
		0x162FC0B2B2CDD9EFULL,
		0x6B63FFB42B126161ULL,
		0x2F2A8AC4804A78A0ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10C0ED2818366E11ULL,
		0x1E944862915CA049ULL,
		0x182E2ED70560D5FEULL,
		0x608D15447FAB48CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD80629ACCDCD22BULL,
		0xEE2E683BA5D8B8F1ULL,
		0x33DE34BF9AC7D4ADULL,
		0x7E27BD5303B5AD4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE414FC2E513404FULL,
		0x0CC2B09E3735593AULL,
		0x4C0C6396A028AAACULL,
		0x5EB4D2978360F61AULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE3F0293E9F8E8DEULL,
		0xCF3DA5C1B192B36DULL,
		0xDEA8D1CB189B2519ULL,
		0x1ACE5AB9564A4DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FDBA6916E06E971ULL,
		0x849ED261D2668C46ULL,
		0x6FAA60B5EF9A7BE5ULL,
		0x4E0DDE35DDB79ECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E1AA92557FFD24FULL,
		0x53DC782383F93FB4ULL,
		0x4E5332810835A0FFULL,
		0x68DC38EF3401EC7AULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66573A0996CBDC41ULL,
		0xF646682ECD03F6F9ULL,
		0xB5618CE31EFC3ECCULL,
		0x1ACF7EF42B2868DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x155ADAAACF4D7878ULL,
		0xB0B7B02AC6FEB43AULL,
		0x99CFDCEBD091D041ULL,
		0x18CC7D0B861B4654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BB214B4661954B9ULL,
		0xA6FE18599402AB33ULL,
		0x4F3169CEEF8E0F0EULL,
		0x339BFBFFB143AF33ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBD26F442D29CB7EULL,
		0x5B3D5EFBFB486AECULL,
		0xCF52BB85F78447FBULL,
		0x6789F853DE087FF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FA874DF2C9FB35ULL,
		0x28463C7EC586CE15ULL,
		0xCFBB81BEEA0B73DEULL,
		0x3476B5E0CDA9CD76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33CCF6921FF3C6C6ULL,
		0x83839B7AC0CF3902ULL,
		0x9F0E3D44E18FBBD9ULL,
		0x1C00AE34ABB24D6FULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEF17124E0FC1160ULL,
		0x040465538D3F10C8ULL,
		0xED80DCA456E87928ULL,
		0x0EEC264F1F267450ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227A5901B7102822ULL,
		0x6F9E118AEF6A3216ULL,
		0xB443886C07FAD35DULL,
		0x12760EAE520610E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD16BCA26980C3982ULL,
		0x73A276DE7CA942DEULL,
		0xA1C465105EE34C85ULL,
		0x216234FD712C8532ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5C7888CA3E668CBULL,
		0x59EEB2E9595A5818ULL,
		0xFBA8DB58596A7CF8ULL,
		0x0F997DBFE6832DFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x856B904F177B79E9ULL,
		0x30553DFD1ACD14C8ULL,
		0x522E8C8E768585BAULL,
		0x0385E2D844DE2783ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B3318DBBB61E2B4ULL,
		0x8A43F0E674276CE1ULL,
		0x4DD767E6CFF002B2ULL,
		0x131F60982B615580ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE01E846E09A98E52ULL,
		0xF4C7FE5418D26450ULL,
		0xD21D0E5F9BDC5AD5ULL,
		0x413A08E5A47431CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC88FD183B26FD853ULL,
		0x2EF53A10136CF3C1ULL,
		0x74758785FD832551ULL,
		0x6EEA091C0C31F5AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8AE55F1BC1966B8ULL,
		0x23BD38642C3F5812ULL,
		0x469295E5995F8027ULL,
		0x30241201B0A62777ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A435A7885F16BD7ULL,
		0xC8AC5DE04CB08501ULL,
		0xC009F51C59E3F247ULL,
		0x0D68BBC1FC50F4A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FFC624DC1392DC8ULL,
		0xCA345A9208E0EFCAULL,
		0xB77129DE6E678B87ULL,
		0x61C19798EB14B781ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA3FBCC6472A999FULL,
		0x92E0B872559174CBULL,
		0x777B1EFAC84B7DCFULL,
		0x6F2A535AE765AC25ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF0D6B007DAA3119ULL,
		0x014A7E484B462270ULL,
		0x9BB59866021BB3CFULL,
		0x59161E8642791AC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E6683AFD3EBCC4ULL,
		0xBB8B5E5A553DBBA0ULL,
		0x6679F4A90AC935E1ULL,
		0x3D4A82DF9AA654D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1F3D33B7AE8EDF0ULL,
		0xBCD5DCA2A083DE10ULL,
		0x022F8D0F0CE4E9B0ULL,
		0x1660A165DD1F6F99ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6928AA9B5F565E63ULL,
		0x6D8F4C285B06D251ULL,
		0x34F45C99C8B430E9ULL,
		0x7366E93EE3D8682DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29FA7A9447151E4EULL,
		0xFDE81E0B878B9C56ULL,
		0x5CD96AFD048E7165ULL,
		0x2A257DC9BB15D01BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9323252FA66B7CC4ULL,
		0x6B776A33E2926EA7ULL,
		0x91CDC796CD42A24FULL,
		0x1D8C67089EEE3848ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB947D68E25A176EAULL,
		0x9F67EDC330B3FDD7ULL,
		0xC4945F5C3295339EULL,
		0x68B89F2AA5F6DBD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E3340E58155C18EULL,
		0xA387CCBA99C1A692ULL,
		0x5BDB72E47DF392A9ULL,
		0x2788E27670A698E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE77B1773A6F7388BULL,
		0x42EFBA7DCA75A469ULL,
		0x206FD240B088C648ULL,
		0x104181A1169D74B6ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C52AE57AC149641ULL,
		0x398FE9D49362BB7AULL,
		0xD2FE496E1046D9E4ULL,
		0x32717784692C2C3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E86DD7D43C45D20ULL,
		0xBB48A52602C0E740ULL,
		0x3B0C993437DCBF3AULL,
		0x2C2A0449B608DB91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAD98BD4EFD8F361ULL,
		0xF4D88EFA9623A2BAULL,
		0x0E0AE2A24823991EULL,
		0x5E9B7BCE1F3507CCULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB852041668F2992ULL,
		0x7D6A33DDF889612BULL,
		0x8FCC2D39B623621DULL,
		0x01276F041F271291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE291C36A4CB72109ULL,
		0x7DFBC791E4AF0D7BULL,
		0xB737C6D2B0C9DDBDULL,
		0x548ED3D36A44C2EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE16E3ABB3464A9BULL,
		0xFB65FB6FDD386EA7ULL,
		0x4703F40C66ED3FDAULL,
		0x55B642D7896BD581ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAD445CD2EB226DCULL,
		0x92619C3720B9CDB0ULL,
		0xF18C5F6D1BE429FBULL,
		0x37E525002AAFD1F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95A8CF7371198B8ULL,
		0xE90E48D2382417B1ULL,
		0x6CCA1C8787AACE6CULL,
		0x0B64AD88DDFFEE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x942ED2C465C3BF94ULL,
		0x7B6FE50958DDE562ULL,
		0x5E567BF4A38EF868ULL,
		0x4349D28908AFC052ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCA4F7323983FF9FULL,
		0x176DD77629F819E3ULL,
		0xDE2CF796C924CB46ULL,
		0x7ADD9F02377EA1A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16794144224CFC6ULL,
		0x6CC668B04FDDF182ULL,
		0x08E6EADA9C7EA152ULL,
		0x091AA2FDC39D63A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E0C8B467BA8CF78ULL,
		0x8434402679D60B66ULL,
		0xE713E27165A36C98ULL,
		0x03F841FFFB1C0545ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDB015ADE58869DAULL,
		0x386DF40E4A7425BAULL,
		0xF10BBDA10D4DDD2CULL,
		0x51A57196F15D90BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52DFD43FEB9E060ULL,
		0xAD2370471FC83CA4ULL,
		0x488AEB64AC4F7523ULL,
		0x0B996F2F5B3D0A69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2DE12F1E4424A3AULL,
		0xE59164556A3C625FULL,
		0x3996A905B99D524FULL,
		0x5D3EE0C64C9A9B27ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0471752EEA4F0B6CULL,
		0x3AB40827197B59E0ULL,
		0xE99C3D1524159A4BULL,
		0x4401A75179F622E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383310CF1E8EF66CULL,
		0xA9B972FFE2C2882BULL,
		0x0845DA82AE90F4EDULL,
		0x039ABA6B8AC909EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CA485FE08DE01D8ULL,
		0xE46D7B26FC3DE20BULL,
		0xF1E21797D2A68F38ULL,
		0x479C61BD04BF2CD0ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DB88A3ABF89F4BAULL,
		0xD18D0D9B52714FAEULL,
		0x2443EC889DF93CB2ULL,
		0x2946CAB04A7AD1AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D41AFF7299836D2ULL,
		0x024B52D701F17D53ULL,
		0xA6C4FB2BD8BCFF18ULL,
		0x3B9EBB4F179A5FE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAFA3A31E9222B8CULL,
		0xD3D860725462CD01ULL,
		0xCB08E7B476B63BCAULL,
		0x64E585FF6215318AULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DF4BE525390F8D5ULL,
		0x1E3547BFFE0E53EAULL,
		0x50BEA8B46311C1B1ULL,
		0x7F50932BDF976972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EDA06935A4A07D2ULL,
		0x0815925F05CFE67FULL,
		0xC372B277452F873EULL,
		0x391687F0A14EF4E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CCEC4E5ADDB00BAULL,
		0x264ADA1F03DE3A69ULL,
		0x14315B2BA84148EFULL,
		0x38671B1C80E65E57ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C8606689A3F07A8ULL,
		0x6DC2A16DFCA443D5ULL,
		0x27AF4E1823DC322EULL,
		0x580117D5E120A3EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC0467396CFF7D8ULL,
		0x1D3E160A199163A5ULL,
		0x977AA33186E66AC8ULL,
		0x7CF92F1FC0109A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A464CDC310EFF93ULL,
		0x8B00B7781635A77BULL,
		0xBF29F149AAC29CF6ULL,
		0x54FA46F5A1313E62ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3758E4E84302556ULL,
		0xFBFCAEAE3C73F3DEULL,
		0x50326CD102F0AFDEULL,
		0x012EE484658CC4C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0853DB899832425ULL,
		0xCF29DEDA043C0C08ULL,
		0x7D89B7870344236BULL,
		0x72825361EB384992ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83FACC071DB3497BULL,
		0xCB268D8840AFFFE7ULL,
		0xCDBC24580634D34AULL,
		0x73B137E650C50E5AULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC6DEB12A789B6C1ULL,
		0xB32BC9FF0B2E3EFEULL,
		0x8140EF2AEFB36304ULL,
		0x67E21069AE6F1348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x977C930F61CE1D95ULL,
		0xC97D6D6379EA762EULL,
		0x9CCD51223B619A8FULL,
		0x45D4A34C671FE87DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63EA7E220957D469ULL,
		0x7CA937628518B52DULL,
		0x1E0E404D2B14FD94ULL,
		0x2DB6B3B6158EFBC6ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x875759290524FDD5ULL,
		0xB64758E7AC3FF533ULL,
		0x25DBA294F0E5BB93ULL,
		0x6AE8059D851836F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x383E4632F980036AULL,
		0x4D2BAA95EAE26F7CULL,
		0x1326425D3FCE811EULL,
		0x6A0F4F0B9381FBEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF959F5BFEA50152ULL,
		0x0373037D972264AFULL,
		0x3901E4F230B43CB2ULL,
		0x54F754A9189A32DCULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16095C746A1C8C64ULL,
		0x27D49126CDAC8349ULL,
		0xB284BB6E64510450ULL,
		0x385D094960E0C5A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39D5B3726ACC598AULL,
		0x59C06D0195BD9D21ULL,
		0xD19B83A8FB909E74ULL,
		0x731065ABED726198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FDF0FE6D4E8E601ULL,
		0x8194FE28636A206AULL,
		0x84203F175FE1A2C4ULL,
		0x2B6D6EF54E53273BULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD03061F7646FC1E3ULL,
		0xCAB9843D442903D9ULL,
		0x059F43AB827958E3ULL,
		0x7274E0D226458C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1133938D783536C7ULL,
		0x9249592674480217ULL,
		0x425D315A54D913AFULL,
		0x1D8B2794A38CD643ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE163F584DCA4F8BDULL,
		0x5D02DD63B87105F0ULL,
		0x47FC7505D7526C93ULL,
		0x10000866C9D26244ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x024F034F25E3A218ULL,
		0x26A888EB35B806CCULL,
		0x7E5A100020CBE772ULL,
		0x40A70DD3D2E9BC79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4C2B0712432BDFULL,
		0xCFD243F0197C555DULL,
		0xAB47C40BC9A71361ULL,
		0x0F326F176AECC4EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC9B2E563826CDF7ULL,
		0xF67ACCDB4F345C29ULL,
		0x29A1D40BEA72FAD3ULL,
		0x4FD97CEB3DD68167ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E41CC414DA14ADBULL,
		0xB298703075DA1E92ULL,
		0xBEF12BE57CD27A98ULL,
		0x0297E6D2B91FA7E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C5985819F634B99ULL,
		0x0BEFF22ACDFC7731ULL,
		0x56A08A0B64DF1CE6ULL,
		0x646939BB89EEE9B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A9B51C2ED049674ULL,
		0xBE88625B43D695C3ULL,
		0x1591B5F0E1B1977EULL,
		0x6701208E430E919BULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7787F431D6F24468ULL,
		0x5E69B73A4CBEF3C1ULL,
		0x88AB2827CCF4B1F5ULL,
		0x3AB41928E63D53A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE50FDC4147FED8BULL,
		0xB81D10347F255D53ULL,
		0x0E2BF34EF6A4688FULL,
		0x7E715B13B81E3B51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55D8F1F5EB723206ULL,
		0x1686C76ECBE45115ULL,
		0x96D71B76C3991A85ULL,
		0x3925743C9E5B8EF8ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B784C404349D66EULL,
		0x77E2342C49DAF66CULL,
		0x4E0FFC42F99CF71DULL,
		0x2F3281E4EE55546CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x697B76217803176BULL,
		0x3E9BC068D6780A97ULL,
		0x1640209B926439C9ULL,
		0x175BB05999133B97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4F3C261BB4CEDD9ULL,
		0xB67DF49520530103ULL,
		0x64501CDE8C0130E6ULL,
		0x468E323E87689003ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0CCD5070D8F691AULL,
		0xEA0C7447C545465FULL,
		0x361C3D392CC75DB8ULL,
		0x7174A5094F6048CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84364E9BA6D367E1ULL,
		0x07FC66FF28CA86F7ULL,
		0x1D28AB72B4120995ULL,
		0x09FEC4F7EF5A272EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x550323A2B462D0FBULL,
		0xF208DB46EE0FCD57ULL,
		0x5344E8ABE0D9674DULL,
		0x7B736A013EBA6FF9ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD82888D182D6D98ULL,
		0x277B8AEDDC7D104AULL,
		0x8060DA0027898592ULL,
		0x1376D5F7F34D9A90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED165255CC066DBCULL,
		0xAF74DDB19AF7F5FBULL,
		0x1E6D107634219325ULL,
		0x5DF8699940F39B87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA98DAE2E433DB54ULL,
		0xD6F0689F77750646ULL,
		0x9ECDEA765BAB18B7ULL,
		0x716F3F9134413617ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BF60BD703621E52ULL,
		0xDDF49B78F4043054ULL,
		0xAFBF858F491E8CEDULL,
		0x3C0E7BD413EA58FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C497ECA9C052CFULL,
		0x5A1AD9562E422F0EULL,
		0xCAAC50920C2C44CDULL,
		0x5FAD44DACA5C22FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EBAA3C3AD227134ULL,
		0x380F74CF22465F62ULL,
		0x7A6BD621554AD1BBULL,
		0x1BBBC0AEDE467BF7ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F5A109E2D646C2BULL,
		0xF9D9041F5BD2953AULL,
		0xADA31052C7D54B30ULL,
		0x2BB2CAF82FE9DBBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0827CB29B850D80DULL,
		0x466619112B43B509ULL,
		0xBFE0548746CAFD1BULL,
		0x5032078BA99E5FA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4781DBC7E5B54438ULL,
		0x403F1D3087164A43ULL,
		0x6D8364DA0EA0484CULL,
		0x7BE4D283D9883B60ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56392EF14573E109ULL,
		0x1217BB55912D2179ULL,
		0x5BC91E00AD5376E1ULL,
		0x110BF6EC76A92A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D9B5C0D9C7D870ULL,
		0x5BC5BB2850B3920CULL,
		0x2B6CBE1891F0C5B7ULL,
		0x38A1439380266B70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9912E4B21F3BB979ULL,
		0x6DDD767DE1E0B385ULL,
		0x8735DC193F443C98ULL,
		0x49AD3A7FF6CF9607ULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EC8CD9261158D64ULL,
		0xB9D6E4D02950E379ULL,
		0x92C87D351DE75564ULL,
		0x6B9471DF1361E156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014FFA02175A9C3EULL,
		0x96902BE6C2C15A86ULL,
		0xA80060DD095178C6ULL,
		0x7CC398F9B4E87EA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3018C794787029B5ULL,
		0x506710B6EC123DFFULL,
		0x3AC8DE122738CE2BULL,
		0x68580AD8C84A5FFDULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC81B24330951183FULL,
		0x91FC07D6DDFA288AULL,
		0x8C0D66454B3217CFULL,
		0x7D8878BE6C1C83FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BD560F22AD2645ULL,
		0x6F16FF802FE36304ULL,
		0xE38BB3BEEBE5AB17ULL,
		0x7ADC5A5D06DC6F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD87A422BFE3E97ULL,
		0x011307570DDD8B8FULL,
		0x6F991A043717C2E7ULL,
		0x7864D31B72F8F30DULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x546CEAE71DCB950BULL,
		0xCB966DED5DB9253EULL,
		0xFC9C6C9A515112D2ULL,
		0x57816C18564F8F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x771D2B3407B8FCC3ULL,
		0xF2A7FE0E39C125E9ULL,
		0x74F3B4D6AA7CADE1ULL,
		0x60573592EF54673FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB8A161B258491E1ULL,
		0xBE3E6BFB977A4B27ULL,
		0x71902170FBCDC0B4ULL,
		0x37D8A1AB45A3F64DULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EF99A27C6D5FE35ULL,
		0x1D86EDACA7E68141ULL,
		0x290880C864972315ULL,
		0x435B9A0310A639CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA5BEBE854D4038ULL,
		0x6A6F36F874E23AE8ULL,
		0xA8E37F083A274A5EULL,
		0x6C802D4BF34D90B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D9F58E64C233E80ULL,
		0x87F624A51CC8BC29ULL,
		0xD1EBFFD09EBE6D73ULL,
		0x2FDBC74F03F3CA7FULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97AD1FB411AE499CULL,
		0xEFAF701044A30D9AULL,
		0x1ADAEE3236A4147BULL,
		0x179DCCC056AB243CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC846147D18CF812AULL,
		0x681D88D13AD261C3ULL,
		0x9B275334C23AB6D1ULL,
		0x02ABBA43BB0D11B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FF334312A7DCAC6ULL,
		0x57CCF8E17F756F5EULL,
		0xB6024166F8DECB4DULL,
		0x1A49870411B835F2ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41D87C1060030954ULL,
		0x3312E477002D8397ULL,
		0x78B4F79C1FE7254BULL,
		0x6EC4CDA632B5629FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ADB723F8969AD0BULL,
		0x690A1C4AEC83B64BULL,
		0x987B3E44B6213438ULL,
		0x17D9B5AD54824580ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCB3EE4FE96CB672ULL,
		0x9C1D00C1ECB139E2ULL,
		0x113035E0D6085983ULL,
		0x069E83538737A820ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5097E5B7AB40C0E0ULL,
		0x94AE558EECC59D6DULL,
		0xDA2814F1ABAA6302ULL,
		0x32CAD92F36256F9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51E3D471C1E58F53ULL,
		0x40F1A9EA7529D31EULL,
		0x1DBDFFF1CD4BFDAAULL,
		0x1E6CA273CAAE4921ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA27BBA296D265033ULL,
		0xD59FFF7961EF708BULL,
		0xF7E614E378F660ACULL,
		0x51377BA300D3B8BBULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAFB57E0CB3E59A2ULL,
		0xD74DF10A1320B63FULL,
		0x0137D4A9FAE49E3DULL,
		0x5A2879572D52F35EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5CBBF4C016FDBFULL,
		0x9081D27C2414D143ULL,
		0x265B592CB7AEEBBEULL,
		0x0E8F4B9C9D6D68F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE75813D58B555761ULL,
		0x67CFC38637358782ULL,
		0x27932DD6B29389FCULL,
		0x68B7C4F3CAC05C52ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE78C81E236EB4DAULL,
		0x5F423D9D3B6F1607ULL,
		0x461F1869F9F0C9C3ULL,
		0x08369C3DE232BDC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4BEA925743CB36AULL,
		0x0F0E2E4F6FC8932DULL,
		0x1404154F0802A357ULL,
		0x6DD2920267279739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8337714397AB6844ULL,
		0x6E506BECAB37A935ULL,
		0x5A232DB901F36D1AULL,
		0x76092E40495A54F9ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA26DED4B2B8173EEULL,
		0xC1029DB98605B2A7ULL,
		0xE662331A389238BBULL,
		0x37A9F5590A4723AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CF1F0802E4B837DULL,
		0x4961E8FACB28B7E8ULL,
		0x8A41B465D1250128ULL,
		0x28691EEBA08EB3B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF5FDDCB59CCF76BULL,
		0x0A6486B4512E6A8FULL,
		0x70A3E78009B739E4ULL,
		0x60131444AAD5D763ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D2C29147FD1E14EULL,
		0x53EDB7F0ACD5BB74ULL,
		0xA6B991D5748569DCULL,
		0x1F6CED397AB106F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66770A23FC6078CAULL,
		0x7632ABE96B6C2B05ULL,
		0x312DE95700BA047CULL,
		0x39C26337CC0DCD7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A333387C325A18ULL,
		0xCA2063DA1841E679ULL,
		0xD7E77B2C753F6E58ULL,
		0x592F507146BED46DULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB09C5AE76DD06AEDULL,
		0x44DE392CC83AF41BULL,
		0xAE183EFBB5CE9D35ULL,
		0x3C62AA56DD145A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEB785EFDCEFD5D5ULL,
		0x549FCCC0B9CA5E7AULL,
		0x9E8C04A7F3779B85ULL,
		0x246532CAA79ED6E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F53E0D74AC040C2ULL,
		0x997E05ED82055296ULL,
		0x4CA443A3A94638BAULL,
		0x60C7DD2184B33181ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17A2A29A0A2DF2D9ULL,
		0xCC788B802616E8D8ULL,
		0x90AD8FFE6A23A2CFULL,
		0x61B045DDB9235CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60401760D131412FULL,
		0xA519C86E95E7D4A2ULL,
		0x087D7F2DFD48A1BAULL,
		0x020337562A0378B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77E2B9FADB5F3408ULL,
		0x719253EEBBFEBD7AULL,
		0x992B0F2C676C448AULL,
		0x63B37D33E326D561ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B0ABE59AA8B3835ULL,
		0x9B51AA2CDE413F9AULL,
		0x96D04422BA361F3EULL,
		0x138EB06054E97B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E3003B02403CE3ULL,
		0xAEFF2AFABFF59C46ULL,
		0x4F34B050601DF363ULL,
		0x0AE086F1ABE390A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEEDBE94ACCB7518ULL,
		0x4A50D5279E36DBE0ULL,
		0xE604F4731A5412A2ULL,
		0x1E6F375200CD0BA9ULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BEFD574DF4EBA9ULL,
		0x26E179B20831619BULL,
		0x39570E9CC193B796ULL,
		0x35906D3543233C17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69334C1855D54C1AULL,
		0x04C4B16F27740E1FULL,
		0x5E04B758DB5122A0ULL,
		0x74E398EBB492C8C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDF2496FA3CA37D6ULL,
		0x2BA62B212FA56FBAULL,
		0x975BC5F59CE4DA36ULL,
		0x2A740620F7B604DDULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F65F478A57C8A2DULL,
		0x3B4DE7E5B48E6B67ULL,
		0xD7C07AD37F5F029EULL,
		0x1F7E6E82C78111CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EAC7BA2E19EA0D5ULL,
		0xF7D380C704387576ULL,
		0x4F702985AB133224ULL,
		0x2153435119DDE2F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E12701B871B2B02ULL,
		0x332168ACB8C6E0DDULL,
		0x2730A4592A7234C3ULL,
		0x40D1B1D3E15EF4C4ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x102098AA0CC77345ULL,
		0xEF779BED0DCED982ULL,
		0x12A4C4C8CFADA6BFULL,
		0x330384F13AB0A828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23239DAE3BC5DE6BULL,
		0xE6C059815FADA3A0ULL,
		0x8236819497DE053FULL,
		0x6E38FDE1C360951EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33443658488D51C3ULL,
		0xD637F56E6D7C7D22ULL,
		0x94DB465D678BABFFULL,
		0x213C82D2FE113D46ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x271A9AE81D030A0DULL,
		0x00E4F87A15091F46ULL,
		0x00F17628ACFA540BULL,
		0x7220CB95AC9E070CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6575AA973E03096DULL,
		0x9EEF2A83677D66BDULL,
		0x4ABF44C09AD907EEULL,
		0x4EED389EF933881EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C90457F5B06138DULL,
		0x9FD422FD7C868603ULL,
		0x4BB0BAE947D35BF9ULL,
		0x410E0434A5D18F2AULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CC3E151989718BCULL,
		0x601E02F1ADF3E880ULL,
		0x2F1A8E1D15324F14ULL,
		0x0209AEEE797BCD99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8F4E299A604845ULL,
		0x34D99C6CA8A6DE06ULL,
		0x32DEC6D3E611843BULL,
		0x45E5C399E50E5D34ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA532F7B32F76101ULL,
		0x94F79F5E569AC686ULL,
		0x61F954F0FB43D34FULL,
		0x47EF72885E8A2ACDULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2438A22D58ED32DULL,
		0xFBF232FAE593B6D2ULL,
		0xF6B20007C474CD7CULL,
		0x419E0CB2DFE69799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167EA7D7C923E3D6ULL,
		0x1DE7FBBD9D887DBCULL,
		0xF45C48DE0C7A3B26ULL,
		0x7F56D770B6437705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8C231FA9EB2B716ULL,
		0x19DA2EB8831C348EULL,
		0xEB0E48E5D0EF08A3ULL,
		0x40F4E423962A0E9FULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88E900C9A28331DAULL,
		0x5A1EFB2CBB5FB38FULL,
		0xEBAEA70B94D24C97ULL,
		0x38BDD9A09801B99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A8E389B59130585ULL,
		0x935438E792901D7EULL,
		0x8ACC4B34BACA16D1ULL,
		0x1C9C01BA9D98AD5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3773964FB96375FULL,
		0xED7334144DEFD10DULL,
		0x767AF2404F9C6368ULL,
		0x5559DB5B359A66F8ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C634F846F4E809DULL,
		0x7355EF9FADD17810ULL,
		0x9CFA7ACC11713E3BULL,
		0x6FF86A4EC7E6DF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF605A16F85BA02DULL,
		0xA974F803F75D2F4BULL,
		0x6FF9F71D4C204762ULL,
		0x11497EE5BF5840C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3BC3A99B67AA20DDULL,
		0x1CCAE7A3A52EA75CULL,
		0x0CF471E95D91859EULL,
		0x0141E934873F1FC7ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}