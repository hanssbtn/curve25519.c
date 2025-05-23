#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0xB1E20C2764E99C80ULL,
		0x879547E87A3191C9ULL,
		0xDE748A63A98B0E9CULL,
		0x39875D00C489349DULL,
		0xAFC714D59B54F7A2ULL,
		0xA56744B0CD61B728ULL,
		0xABA33224908C0998ULL,
		0x76FB62A889192835ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x97EAD6857870E66AULL,
		0x1159CC8F58B6A95CULL,
		0xB3ED9EC9A651BA35ULL,
		0xFD0F5F9BB8BF3EF4ULL,
		0xCDC849D71D0CD56AULL,
		0x93FD0689EE499A84ULL,
		0x0CF81B78ADB5DBDCULL,
		0x31FAE298B90721ECULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x19F735A1EC78B616ULL,
		0x763B7B59217AE86DULL,
		0x2A86EB9A03395467ULL,
		0x3C77FD650BC9F5A9ULL,
		0xE1FECAFE7E482237ULL,
		0x116A3E26DF181CA3ULL,
		0x9EAB16ABE2D62DBCULL,
		0x4500800FD0120649ULL
	}};
	int sign = 0;
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
		0x0D35B15C899C7E0BULL,
		0x6A6E4E13A9605DC9ULL,
		0x09D9F91C1FCA5983ULL,
		0x3373E1E4AD4412C3ULL,
		0x5DCE80C86E87F1C4ULL,
		0xB5E8141E849619FFULL,
		0x2F778A1E8DB626A1ULL,
		0x41BE118613ED6469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F2083927F1C66F5ULL,
		0xE3DFA1079A75C081ULL,
		0xEB885F1E639CA805ULL,
		0x2CD94808D0BE3F13ULL,
		0x45D21399FC3901A4ULL,
		0x909BD7C131ED6D05ULL,
		0x389669FAD1381277ULL,
		0x30570A22B5298D1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE152DCA0A801716ULL,
		0x868EAD0C0EEA9D47ULL,
		0x1E5199FDBC2DB17DULL,
		0x069A99DBDC85D3AFULL,
		0x17FC6D2E724EF020ULL,
		0x254C3C5D52A8ACFAULL,
		0xF6E12023BC7E142AULL,
		0x116707635EC3D749ULL
	}};
	sign = 0;
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
		0x0C812BD2A3B8797EULL,
		0xB0DDE9152D8FBFF7ULL,
		0x6D875D7AE29A9159ULL,
		0x86A507C9BD584D89ULL,
		0x6749E01D7901D46EULL,
		0x4939EB20BF8C0EE0ULL,
		0xA3EA02C7E70FD467ULL,
		0x3ED39A9EB0293ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD97228159FC656ULL,
		0xB20E806D88592875ULL,
		0x0F68EFF7B0C3E020ULL,
		0xCFDBDA1BF991319AULL,
		0x84A2184529A1C4A7ULL,
		0x060FB28755AB9D94ULL,
		0xC10E3E377726FD09ULL,
		0xE26DAF66B9D758A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A7B9AA8E18B328ULL,
		0xFECF68A7A5369781ULL,
		0x5E1E6D8331D6B138ULL,
		0xB6C92DADC3C71BEFULL,
		0xE2A7C7D84F600FC6ULL,
		0x432A389969E0714BULL,
		0xE2DBC4906FE8D75EULL,
		0x5C65EB37F651E62FULL
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
		0xE747B2A9EDDE39DBULL,
		0x257FA21E1479BCB6ULL,
		0xB6A216FCE5ADDE6CULL,
		0x2164D42758550A47ULL,
		0xAE66B40114F3A8B6ULL,
		0xD526E5D756EB2DDEULL,
		0x01B2BDCCFBA34908ULL,
		0xBEE0449459155A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5948979D61E1434ULL,
		0x6138ACF6BD8578A0ULL,
		0x6C48F247695BA669ULL,
		0xE1FD7879AFFC1CDFULL,
		0x5CEDC8FFC3FE9F3FULL,
		0xC3261AFDC6A54748ULL,
		0x1DBFA38446DA03A5ULL,
		0x750C99E5071B7431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11B3293017C025A7ULL,
		0xC446F52756F44416ULL,
		0x4A5924B57C523802ULL,
		0x3F675BADA858ED68ULL,
		0x5178EB0150F50976ULL,
		0x1200CAD99045E696ULL,
		0xE3F31A48B4C94563ULL,
		0x49D3AAAF51F9E5D6ULL
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
		0x8EE3C99043C88963ULL,
		0x5CA6EDEC98657C23ULL,
		0xD76646B7599ED38FULL,
		0xE2EB85C17005F28EULL,
		0x0E57EFA1B6988633ULL,
		0x893EAC95676BCEB6ULL,
		0x4EBD96338D4C9CE1ULL,
		0xA29D85367D38F3FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73369AA2BF751F1DULL,
		0x39494DA999017135ULL,
		0x9AC2FEB25008C06CULL,
		0x5C993A0A8A0A740DULL,
		0x07E65CE85AAC7B90ULL,
		0xDD7BDAF74A24BC65ULL,
		0x6E1D1016EE866044ULL,
		0xA761192220684FC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BAD2EED84536A46ULL,
		0x235DA042FF640AEEULL,
		0x3CA3480509961323ULL,
		0x86524BB6E5FB7E81ULL,
		0x067192B95BEC0AA3ULL,
		0xABC2D19E1D471251ULL,
		0xE0A0861C9EC63C9CULL,
		0xFB3C6C145CD0A434ULL
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
		0xCE9C58A7BDAFE86BULL,
		0x4E8C5723B33519EBULL,
		0xBE0970E9B6D42898ULL,
		0x8340D8DD61C5CBF0ULL,
		0xC52DED0ADEA3D4EEULL,
		0xF25D458AB7E5A81CULL,
		0x5CB35640592E2A79ULL,
		0xC6E3E381CDF67318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC45F394DF6344843ULL,
		0xE764B7184652674FULL,
		0xFEB0489472D26D36ULL,
		0x8C86EBD1446D7061ULL,
		0x2261086CB2A922C0ULL,
		0xDBD15704C600761DULL,
		0x76DC70D9804620F8ULL,
		0x3229F1D492B41AD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A3D1F59C77BA028ULL,
		0x6727A00B6CE2B29CULL,
		0xBF5928554401BB61ULL,
		0xF6B9ED0C1D585B8EULL,
		0xA2CCE49E2BFAB22DULL,
		0x168BEE85F1E531FFULL,
		0xE5D6E566D8E80981ULL,
		0x94B9F1AD3B425847ULL
	}};
	sign = 0;
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
		0x435A1B7B69CB1491ULL,
		0x58AB3B5FE3DC4C53ULL,
		0xDE59BB06F9606338ULL,
		0x7A4D09C769F3989DULL,
		0xACB0E309B1FE7792ULL,
		0x1F1968123A381643ULL,
		0xDD925967A362113FULL,
		0xC9E4326C0DF439C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0B8572BE34B959CULL,
		0x9C07D721F926621CULL,
		0xA1DB5657596080D8ULL,
		0x73552668F355764BULL,
		0x5908B8A8BE6FA69BULL,
		0xD1236B684E2549A3ULL,
		0xBEDBD3429B4B7191ULL,
		0x7F1609DE986879C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52A1C44F867F7EF5ULL,
		0xBCA3643DEAB5EA36ULL,
		0x3C7E64AF9FFFE25FULL,
		0x06F7E35E769E2252ULL,
		0x53A82A60F38ED0F7ULL,
		0x4DF5FCA9EC12CCA0ULL,
		0x1EB6862508169FADULL,
		0x4ACE288D758BBFFCULL
	}};
	sign = 0;
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
		0x1B5D6086739CC18BULL,
		0x027935199FF65803ULL,
		0x200079F517FBD2ADULL,
		0xC02411D444C6371FULL,
		0x49CDD69DA094728BULL,
		0x0CC26BFB57FE05FDULL,
		0x846C31A13E25658CULL,
		0x8579A58B2E532F97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B39F50470C44F20ULL,
		0x601896949A50D7DAULL,
		0x1573972E0705C1ABULL,
		0x299DA7199E004FC6ULL,
		0x799C6B327ADC076EULL,
		0x08E58D10D8BD962DULL,
		0xFAF3C017D7884B66ULL,
		0x8C47B7EEBEB3F35BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0236B8202D8726BULL,
		0xA2609E8505A58028ULL,
		0x0A8CE2C710F61101ULL,
		0x96866ABAA6C5E759ULL,
		0xD0316B6B25B86B1DULL,
		0x03DCDEEA7F406FCFULL,
		0x89787189669D1A26ULL,
		0xF931ED9C6F9F3C3BULL
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
		0x9393DA3758877462ULL,
		0xEF5D1775895441D8ULL,
		0xC72AFA806F2F5B25ULL,
		0xE733786D4E57A857ULL,
		0x9C74D3A9ADE8DF29ULL,
		0x6A6EFF2C5703E570ULL,
		0x20AF608E958B803FULL,
		0x63E87631772EB9E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF96518D4493E33DULL,
		0xB96B8180C92FEED6ULL,
		0x83F1275D55C4E1AFULL,
		0xE8D235F3EC9550F0ULL,
		0xF3A5EEB3D6DB2C7EULL,
		0x1AA343865F83F0D5ULL,
		0xC0B7B7A7DDCA5C37ULL,
		0x8C9CDF24AFAE9239ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3FD88AA13F39125ULL,
		0x35F195F4C0245301ULL,
		0x4339D323196A7976ULL,
		0xFE61427961C25767ULL,
		0xA8CEE4F5D70DB2AAULL,
		0x4FCBBBA5F77FF49AULL,
		0x5FF7A8E6B7C12408ULL,
		0xD74B970CC78027AFULL
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
		0xC5461FD0F264F582ULL,
		0x72B38D0EE6438186ULL,
		0x58A56106CD7FBF60ULL,
		0xE878914C3CFF5D9DULL,
		0x144EC935F9852F7BULL,
		0x324CFF293E37B503ULL,
		0x4B8B5E975CE2AD15ULL,
		0x346DD97652C6B9D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB34AFA5E151F92BULL,
		0xD9F5D731B556523DULL,
		0x33B085862A2683B8ULL,
		0x0210EAFA41FC7399ULL,
		0x6F3B26D719A463D9ULL,
		0x57C5C894227CFEC3ULL,
		0x2BE5538C2DC7F71BULL,
		0xB9AFEC6A90F962F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA11702B1112FC57ULL,
		0x98BDB5DD30ED2F48ULL,
		0x24F4DB80A3593BA7ULL,
		0xE667A651FB02EA04ULL,
		0xA513A25EDFE0CBA2ULL,
		0xDA8736951BBAB63FULL,
		0x1FA60B0B2F1AB5F9ULL,
		0x7ABDED0BC1CD56DDULL
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
		0x84C839D743012503ULL,
		0x4E0A72C45790F64AULL,
		0x157AE2353AA5F06EULL,
		0xB27B595A153E4D09ULL,
		0xE4BB8EC5F9E7C4D2ULL,
		0xEB594D9EF582765BULL,
		0x8522A46ED1760840ULL,
		0xA7DEB3CF39BEA8F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42425250FEF66542ULL,
		0xEEB2A954CCB9CBFEULL,
		0x075A1FCD8DE4048FULL,
		0x429546C3216F7BF7ULL,
		0x40504500CBBD0DD4ULL,
		0x264DB6F61D5F4466ULL,
		0xAC968D0A57881949ULL,
		0x225A508641465954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4285E786440ABFC1ULL,
		0x5F57C96F8AD72A4CULL,
		0x0E20C267ACC1EBDEULL,
		0x6FE61296F3CED112ULL,
		0xA46B49C52E2AB6FEULL,
		0xC50B96A8D82331F5ULL,
		0xD88C176479EDEEF7ULL,
		0x85846348F8784FA4ULL
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
		0xA254B1769CA5F74FULL,
		0x3300C2F9D36BB040ULL,
		0x891B0E93C5767D93ULL,
		0x9ECB572F8AA8BA37ULL,
		0x6E137F8FE1795F9AULL,
		0x1CDFF5BE32DA3487ULL,
		0xEA94455768FAA4A9ULL,
		0x603F9990A8F52008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E7A65FF5E565D1ULL,
		0x59E3F0B2D1F74C03ULL,
		0xC1E17E6ECB8F9819ULL,
		0x304D7ECD2E1D521DULL,
		0xAA34DFF2CB492D43ULL,
		0x1A5481A0BCED4290ULL,
		0x315FFD4A5ADCA305ULL,
		0x5956B6E525EABB5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x086D0B16A6C0917EULL,
		0xD91CD2470174643DULL,
		0xC7399024F9E6E579ULL,
		0x6E7DD8625C8B6819ULL,
		0xC3DE9F9D16303257ULL,
		0x028B741D75ECF1F6ULL,
		0xB934480D0E1E01A4ULL,
		0x06E8E2AB830A64A9ULL
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
		0xA133EF82ABE2E2E4ULL,
		0x7D7375B8C3EBFDEFULL,
		0xFABFBD1649195B80ULL,
		0x8F5ADC59C5060C14ULL,
		0x7E4D063209FB2995ULL,
		0x6BF997EF5F590B4EULL,
		0x87072487A5ECA765ULL,
		0xBF81120452980DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26CB1F0692F2DCE2ULL,
		0xDCE061AAFA86AF7DULL,
		0x95D4AD2C6524AF03ULL,
		0x81A04382DABDB4B9ULL,
		0x205FCF07BEC572ACULL,
		0x67142E385032F527ULL,
		0x9D97743FB7944C63ULL,
		0xDFC0B19A9466DC90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A68D07C18F00602ULL,
		0xA093140DC9654E72ULL,
		0x64EB0FE9E3F4AC7CULL,
		0x0DBA98D6EA48575BULL,
		0x5DED372A4B35B6E9ULL,
		0x04E569B70F261627ULL,
		0xE96FB047EE585B02ULL,
		0xDFC06069BE31313FULL
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
		0x9B01722AB5E09F9CULL,
		0x213710849E9E09E0ULL,
		0xBD50BD7AD4A48B69ULL,
		0xB47A89E8D500EDF8ULL,
		0x7E44A82C2B504A77ULL,
		0x6A70C7F62632016BULL,
		0x671D89F230A4F919ULL,
		0x3D5CF733FD3BE8B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14520D4B582D8896ULL,
		0x388B555F4C36B61FULL,
		0xF08CC1E2AD30558BULL,
		0xE24A3D862F64ED03ULL,
		0x2E49BA1DACDBC803ULL,
		0x3F55A3F89AF499BEULL,
		0xCC1283D79386B03AULL,
		0x12276BD75DECC019ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86AF64DF5DB31706ULL,
		0xE8ABBB25526753C1ULL,
		0xCCC3FB98277435DDULL,
		0xD2304C62A59C00F4ULL,
		0x4FFAEE0E7E748273ULL,
		0x2B1B23FD8B3D67ADULL,
		0x9B0B061A9D1E48DFULL,
		0x2B358B5C9F4F2896ULL
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
		0xEDE345568C2EFA6AULL,
		0x4CA0D2A7B0C1D59EULL,
		0xE8BCF69EE1BE9ED0ULL,
		0xFE4EB99C710AB40BULL,
		0x7D2FF3FBAA37EAE9ULL,
		0x8C31FAF67A75816DULL,
		0xFC3011ADED1FA4EBULL,
		0x41B400C15678E73BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E1BE7427365A160ULL,
		0x2E1D0416FFD0456BULL,
		0x7CF505DCAE4C453BULL,
		0xF0F8A6CDA715B580ULL,
		0x3AC845BC7321A0F8ULL,
		0xDB6FA582BB0D8B5FULL,
		0x5F71AD34301968BAULL,
		0xB7F1A970516C37DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FC75E1418C9590AULL,
		0x1E83CE90B0F19033ULL,
		0x6BC7F0C233725995ULL,
		0x0D5612CEC9F4FE8BULL,
		0x4267AE3F371649F1ULL,
		0xB0C25573BF67F60EULL,
		0x9CBE6479BD063C30ULL,
		0x89C25751050CAF5CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x35E647884DE8DC1CULL,
		0x7C634DFAE05252F3ULL,
		0x859231106037E1E6ULL,
		0x6E074F055C3729E3ULL,
		0xE986E0965B6251D3ULL,
		0x85462CAF615DB498ULL,
		0x460229BBD6A24BC8ULL,
		0x013E487F958B3648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9BB0839BDD9029ULL,
		0xC7CFB80D7F8AD115ULL,
		0xC3B58F54611E7596ULL,
		0x80107571588D5FD7ULL,
		0x06D6FEC7FCB830C3ULL,
		0x611C91F24FE978B2ULL,
		0x4F2B930AE2044A9FULL,
		0xB536BF2FEADD135EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB4A9704B20B4BF3ULL,
		0xB49395ED60C781DDULL,
		0xC1DCA1BBFF196C4FULL,
		0xEDF6D99403A9CA0BULL,
		0xE2AFE1CE5EAA210FULL,
		0x24299ABD11743BE6ULL,
		0xF6D696B0F49E0129ULL,
		0x4C07894FAAAE22E9ULL
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
		0x5A94473BD2FA086BULL,
		0x8978691E955AAA3EULL,
		0x50ED4E6C8F12F3F7ULL,
		0x22AEB601D968DBF8ULL,
		0x045ECF2FD765F411ULL,
		0x978744471B9BA7B3ULL,
		0x8372AA38D1B53EF2ULL,
		0x7E7C6E46CE503385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCC1C81D262D0C53ULL,
		0xAD0649BA798333DDULL,
		0x26825498741D0853ULL,
		0xC1643A68703C9C2FULL,
		0x9A0B9FF797400D28ULL,
		0x2764A25D85F246BAULL,
		0x2D24E73CBEB8AFA0ULL,
		0xAA12D93C6A90939CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD27F1EACCCFC18ULL,
		0xDC721F641BD77660ULL,
		0x2A6AF9D41AF5EBA3ULL,
		0x614A7B99692C3FC9ULL,
		0x6A532F384025E6E8ULL,
		0x7022A1E995A960F8ULL,
		0x564DC2FC12FC8F52ULL,
		0xD469950A63BF9FE9ULL
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
		0x887D9745F44417C5ULL,
		0x9DEB45AD0A9EBDC4ULL,
		0xEC4C9AD82DA3BCEBULL,
		0x8BA1B89ECD461E0CULL,
		0xCD29500513B964A8ULL,
		0xEFA20733D6330DF0ULL,
		0x9EE13FE2FCD28AB1ULL,
		0x9FA6433975E6A015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02B795714D0806E8ULL,
		0xFC4B82234B322704ULL,
		0xF28F8F8C7ABA3E3AULL,
		0xC79481027F8A78D2ULL,
		0x1BEB96401224FA22ULL,
		0xFF935DC7D2C7925FULL,
		0xBC201D0485665D83ULL,
		0x449AEA4BE2628347ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85C601D4A73C10DDULL,
		0xA19FC389BF6C96C0ULL,
		0xF9BD0B4BB2E97EB0ULL,
		0xC40D379C4DBBA539ULL,
		0xB13DB9C501946A85ULL,
		0xF00EA96C036B7B91ULL,
		0xE2C122DE776C2D2DULL,
		0x5B0B58ED93841CCDULL
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
		0x7574B2EB83BF2430ULL,
		0x2FE16FC4E687D1F6ULL,
		0x062E45C10B7FEC77ULL,
		0x4BB605218F90BB51ULL,
		0xD983AE28BB883F9CULL,
		0x4B855D7E17A46E02ULL,
		0x0B21788C42FB5908ULL,
		0x9960627D3E98F28BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21412FE5FB24E25AULL,
		0x4281957493A4A581ULL,
		0x1ACDFF80E180F0A1ULL,
		0x0A7CE82FBFDD3500ULL,
		0x0D190EB25D9D146AULL,
		0x7A45CE98DD4716C6ULL,
		0x57F294D0F98A9ED7ULL,
		0x49CDDADCE69BC000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54338305889A41D6ULL,
		0xED5FDA5052E32C75ULL,
		0xEB60464029FEFBD5ULL,
		0x41391CF1CFB38650ULL,
		0xCC6A9F765DEB2B32ULL,
		0xD13F8EE53A5D573CULL,
		0xB32EE3BB4970BA30ULL,
		0x4F9287A057FD328AULL
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
		0x54800812F3F444B0ULL,
		0x0E22DC0EBCBE1867ULL,
		0x71F22260B4ABB37CULL,
		0x00F2CF20F2AFE60FULL,
		0xB90E16776ED8B52CULL,
		0xA5F09CBF76CC1016ULL,
		0x24082ACA72596683ULL,
		0x74C43D72B9879AF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BB8F3AC82312A1ULL,
		0xEF5DB93FDAD54C5EULL,
		0xABAF74281431E58EULL,
		0x43E3B3C9873C73E4ULL,
		0xDAB6BFCABAB47066ULL,
		0xF372EE95A0A1A576ULL,
		0x5FE04F2AAF3D51B9ULL,
		0x08DB020B37B6C01BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1C478D82BD1320FULL,
		0x1EC522CEE1E8CC08ULL,
		0xC642AE38A079CDEDULL,
		0xBD0F1B576B73722AULL,
		0xDE5756ACB42444C5ULL,
		0xB27DAE29D62A6A9FULL,
		0xC427DB9FC31C14C9ULL,
		0x6BE93B6781D0DADAULL
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
		0xDA8BECD3738F4BC6ULL,
		0xB857C8288F7A5598ULL,
		0x5C2DA5E1E5046D7BULL,
		0x329526F86583508CULL,
		0x60D680CF048FA71FULL,
		0x3296B81E545EE813ULL,
		0x778D0EDBA17B8240ULL,
		0xD1E6233619D140A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF2046F7962C9DBFULL,
		0x64D9419AD8CBC412ULL,
		0xC8753A0F36C4A0DBULL,
		0x08D0B081C984D380ULL,
		0xF8D9F00100302F99ULL,
		0xA82E6F914BBD5249ULL,
		0x0E662853AAADDE4CULL,
		0xEAC90B39A32ADC53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB6BA5DBDD62AE07ULL,
		0x537E868DB6AE9185ULL,
		0x93B86BD2AE3FCCA0ULL,
		0x29C476769BFE7D0BULL,
		0x67FC90CE045F7786ULL,
		0x8A68488D08A195C9ULL,
		0x6926E687F6CDA3F3ULL,
		0xE71D17FC76A66451ULL
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
		0x2074FC3800E6E447ULL,
		0xD02758D0B1C9269DULL,
		0x05866518C19DD4FEULL,
		0x41D8011C4706E918ULL,
		0x753E8D707F6B1E14ULL,
		0xB32006B9D0DA120AULL,
		0x1A43A9438399AA79ULL,
		0xA0702E3141CF6752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21BDD0C9AB06AC99ULL,
		0x0E786251423D7F7BULL,
		0x8E96A8DC40838260ULL,
		0xFE2068FE6E4F9F32ULL,
		0xA91413083B02B906ULL,
		0x6C2D38E9D880DCADULL,
		0x3C3436BF0B35A4D4ULL,
		0x33E530D4CF71F7D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEB72B6E55E037AEULL,
		0xC1AEF67F6F8BA721ULL,
		0x76EFBC3C811A529EULL,
		0x43B7981DD8B749E5ULL,
		0xCC2A7A684468650DULL,
		0x46F2CDCFF859355CULL,
		0xDE0F7284786405A5ULL,
		0x6C8AFD5C725D6F78ULL
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
		0xF28D779F23F827F9ULL,
		0x563F38E1FB2DD5B0ULL,
		0xA4E5B9A104E6C1D7ULL,
		0x862BFB8FEF15C491ULL,
		0x6C3DDC1EA7505C56ULL,
		0x9FEEF5D984A9ED2CULL,
		0x6C5A3830BD193AC2ULL,
		0xE0F46E0BE2EA76B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3A61794807B386ULL,
		0x28FDFBEB5BA42E70ULL,
		0x8FEE77A57ADA2D70ULL,
		0xFD2A31979C02DD41ULL,
		0xE473F5DA8F8F62DFULL,
		0xDF5E2E8310D9C9C5ULL,
		0x3E68F3B47F9DD645ULL,
		0xB2EF02BC1077F13EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3531625DBF07473ULL,
		0x2D413CF69F89A740ULL,
		0x14F741FB8A0C9467ULL,
		0x8901C9F85312E750ULL,
		0x87C9E64417C0F976ULL,
		0xC090C75673D02366ULL,
		0x2DF1447C3D7B647CULL,
		0x2E056B4FD2728575ULL
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
		0x5B27C48096512B13ULL,
		0x80373A4EE22909FDULL,
		0x033B097F370088FDULL,
		0xF2E01E22C0480F98ULL,
		0xFF027152FC072EFDULL,
		0xA2D4C4B431257FB0ULL,
		0x38E348565A41121DULL,
		0x575F17C046C7CE8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x813C81C38EB1545CULL,
		0x9CFDED5AEC23F3BAULL,
		0xB64D23E0C934601EULL,
		0xE8C9EAA5D61A2049ULL,
		0x92AFC3742D16AD67ULL,
		0xC727FF2198255FD5ULL,
		0xCEAFFBBDF7DFF605ULL,
		0x663231E2F4BBD16BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9EB42BD079FD6B7ULL,
		0xE3394CF3F6051642ULL,
		0x4CEDE59E6DCC28DEULL,
		0x0A16337CEA2DEF4EULL,
		0x6C52ADDECEF08196ULL,
		0xDBACC59299001FDBULL,
		0x6A334C9862611C17ULL,
		0xF12CE5DD520BFD21ULL
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
		0xE28AB229A0D16BFFULL,
		0x833179AF7755C619ULL,
		0x0E6A967EC2E6E962ULL,
		0x3FBBE230213B6046ULL,
		0x7F4F5CF8B1AE1221ULL,
		0x76DEDC0AD9861283ULL,
		0x7A6B718FF4964AABULL,
		0xD1B522687B6E86FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81354E32B92A96D9ULL,
		0xE07346604557A28CULL,
		0xB657649467F95B57ULL,
		0xE512B9F34957276BULL,
		0x31E625B2483B7F41ULL,
		0x88E21B436F2AA7AAULL,
		0xBFB590714E2B7A86ULL,
		0xE282DA549B4681AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x615563F6E7A6D526ULL,
		0xA2BE334F31FE238DULL,
		0x581331EA5AED8E0AULL,
		0x5AA9283CD7E438DAULL,
		0x4D693746697292DFULL,
		0xEDFCC0C76A5B6AD9ULL,
		0xBAB5E11EA66AD024ULL,
		0xEF324813E028054EULL
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
		0xEA287BB143C1B251ULL,
		0xC03E6C917B22B285ULL,
		0x5872C73F3138D464ULL,
		0xA4F68D69E12C040FULL,
		0x0BADFCD01F23FEF8ULL,
		0x8F94FFE6D272EFA8ULL,
		0xD9E17FED43BEE790ULL,
		0x3BFCD8F81A713765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9457CB6A8E2F1559ULL,
		0x2E8EA18012AAAB75ULL,
		0x974AA8C3B1EC3CCFULL,
		0x86CC9DC47E3D91B8ULL,
		0x407DC287DFBE838EULL,
		0xE9C77C4FA0D7006FULL,
		0x509A25AF3A1A14B3ULL,
		0xFAC419238DA2D62BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55D0B046B5929CF8ULL,
		0x91AFCB1168780710ULL,
		0xC1281E7B7F4C9795ULL,
		0x1E29EFA562EE7256ULL,
		0xCB303A483F657B6AULL,
		0xA5CD8397319BEF38ULL,
		0x89475A3E09A4D2DCULL,
		0x4138BFD48CCE613AULL
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
		0x0687E36D94A5F0C7ULL,
		0x195C155A9E7E1F20ULL,
		0x68E478F7F1786375ULL,
		0xDD362D9B3CAF40B3ULL,
		0xFE7895E68D2472A0ULL,
		0xCBBD4714A76ED41EULL,
		0xBA00AC0349733C5BULL,
		0x4E3B8B64A4386649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F042C606CA2BF88ULL,
		0x293AB58E270E27CAULL,
		0xD8E8830F308EC60DULL,
		0x8510C511396AC91CULL,
		0x079C8E049308A1F6ULL,
		0xBDADE5E2D170B3C8ULL,
		0x2B5835499CF48A87ULL,
		0xB2531B2A475CC1FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC783B70D2803313FULL,
		0xF0215FCC776FF755ULL,
		0x8FFBF5E8C0E99D67ULL,
		0x5825688A03447796ULL,
		0xF6DC07E1FA1BD0AAULL,
		0x0E0F6131D5FE2056ULL,
		0x8EA876B9AC7EB1D4ULL,
		0x9BE8703A5CDBA44CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA3781946C036EDBAULL,
		0xEA75950DAD894896ULL,
		0x6FB69D41F041E691ULL,
		0x374401473169B411ULL,
		0x02B599C0AD790317ULL,
		0xA66091E63F425F10ULL,
		0xFA47E56781754F32ULL,
		0xA66FD72D04E7B774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FDDE4E8010D2D9BULL,
		0xD7C5C17B50AD68FCULL,
		0x67A593E108D09F67ULL,
		0xA25CCB1475F8AD42ULL,
		0x5616F575D9426918ULL,
		0x11D75947B8A576CEULL,
		0xB9CA34451AA2A0C4ULL,
		0xABD7D6178BA040D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839A345EBF29C01FULL,
		0x12AFD3925CDBDF9AULL,
		0x08110960E771472AULL,
		0x94E73632BB7106CFULL,
		0xAC9EA44AD43699FEULL,
		0x9489389E869CE841ULL,
		0x407DB12266D2AE6EULL,
		0xFA9801157947769DULL
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
		0xBEB5E5737B3D1C31ULL,
		0x7E41B40128354DA2ULL,
		0x9B2B19C6B93BC4B2ULL,
		0x78DDD3034DAD2991ULL,
		0xEEF588F7A028B1DEULL,
		0xCC92A3417B58E4ABULL,
		0xF1DB32239F2AC1F9ULL,
		0xA75A764D6D046FF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB01846A7442A5C3ULL,
		0xA0D190FA136E77EEULL,
		0xCBA2DCCDCF31EC74ULL,
		0x180D584E4F22732EULL,
		0xAA8F52C5444AF5F8ULL,
		0xB75F3B0E5F4255FBULL,
		0x39CF1E45975E87E0ULL,
		0xD6F80ED8383AFE9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13B4610906FA766EULL,
		0xDD70230714C6D5B4ULL,
		0xCF883CF8EA09D83DULL,
		0x60D07AB4FE8AB662ULL,
		0x446636325BDDBBE6ULL,
		0x153368331C168EB0ULL,
		0xB80C13DE07CC3A19ULL,
		0xD062677534C97157ULL
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
		0xF0409FA1AD8E0265ULL,
		0x1655024A01B148AEULL,
		0x2EBAA8A6FBA0BCA8ULL,
		0x5F875C9EF9D7AEEDULL,
		0xC689759139E6642DULL,
		0xB449BE25BB75B663ULL,
		0xE9729037A95FE9F5ULL,
		0xAAF9F51BEE0EFDA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF4842AE11D0E53ULL,
		0x6D91810931203B5DULL,
		0xF57FE52C206F71D9ULL,
		0x9FFBE1AD05613B6EULL,
		0x1205B79D8E73F4F7ULL,
		0xC03C9F34570925F2ULL,
		0x6B4C74A24003D7D5ULL,
		0xDF11CED9D9176E0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD34C1B76CC70F412ULL,
		0xA8C38140D0910D51ULL,
		0x393AC37ADB314ACEULL,
		0xBF8B7AF1F476737EULL,
		0xB483BDF3AB726F35ULL,
		0xF40D1EF1646C9071ULL,
		0x7E261B95695C121FULL,
		0xCBE8264214F78F9BULL
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
		0x7525200207E9ECB4ULL,
		0xF1D65C8960BD961DULL,
		0xCC37D2AC30C320FDULL,
		0x3B8878823C2CA7FBULL,
		0x6D6BE908F9998D14ULL,
		0x7D36D56DED626A79ULL,
		0xCB9AD194DD2FD647ULL,
		0xC962C766F06FF812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAAE035AC58B633DULL,
		0xCB7E87815AF95FF5ULL,
		0x41EF448EAE81DC4FULL,
		0x8FA9B35BB6B28F8EULL,
		0x2876FAC3E213717BULL,
		0xD2A4C80080A9DCF0ULL,
		0xA6DF2D78C58395C6ULL,
		0x2698934983F56B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A771CA7425E8977ULL,
		0x2657D50805C43627ULL,
		0x8A488E1D824144AEULL,
		0xABDEC526857A186DULL,
		0x44F4EE4517861B98ULL,
		0xAA920D6D6CB88D89ULL,
		0x24BBA41C17AC4080ULL,
		0xA2CA341D6C7A8CF8ULL
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
		0xDB9F7B1D2B2ADE06ULL,
		0xD6C09F865F03FC4BULL,
		0xC33D234EC12D184BULL,
		0xC06C2248097AD7D2ULL,
		0xC237A690538A5330ULL,
		0xB19C247487A4E2EDULL,
		0xD5CA61C20D4DDDB6ULL,
		0x63D00E74D7E9881FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1A3FECD7DA43752ULL,
		0x36C5604106304EB2ULL,
		0xC74BE9E18EE6C05AULL,
		0xC3E6BF65DB0D76B8ULL,
		0x9E526DAF6B5B9747ULL,
		0x4BAA3D2A5F4FE0E5ULL,
		0xD5B60D7F5FACED03ULL,
		0xC3A5304A2611D70DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19FB7C4FAD86A6B4ULL,
		0x9FFB3F4558D3AD99ULL,
		0xFBF1396D324657F1ULL,
		0xFC8562E22E6D6119ULL,
		0x23E538E0E82EBBE8ULL,
		0x65F1E74A28550208ULL,
		0x00145442ADA0F0B3ULL,
		0xA02ADE2AB1D7B112ULL
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
		0xE40F76DBAC6D32DDULL,
		0xF33BD5CA189EEB1AULL,
		0x17196D000563E546ULL,
		0x71CADADF1D19C7E4ULL,
		0xC84AC34A977E863DULL,
		0x931759FF6151FABEULL,
		0x27D3EE44BDB22C7AULL,
		0x995FB15A458B439DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53ED03E1639E16CEULL,
		0x9CC88B890A5A9DFCULL,
		0x3E2CE008E10943E3ULL,
		0x8CA3CE44B666E841ULL,
		0x0C5045D9BCFA61F8ULL,
		0x78D09CCD9F86ADA3ULL,
		0xC9105928CC59D19DULL,
		0xBF942A9771523F58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x902272FA48CF1C0FULL,
		0x56734A410E444D1EULL,
		0xD8EC8CF7245AA163ULL,
		0xE5270C9A66B2DFA2ULL,
		0xBBFA7D70DA842444ULL,
		0x1A46BD31C1CB4D1BULL,
		0x5EC3951BF1585ADDULL,
		0xD9CB86C2D4390444ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x845DC25DFAFBEB91ULL,
		0x7FD131F0DE0EC0EFULL,
		0xDF8848B064440034ULL,
		0xC9B8F19FE263B956ULL,
		0xF53898DEAC160585ULL,
		0x5C23184CE7380907ULL,
		0xD87F2DA20CB5E5FCULL,
		0xF1C606864FE65164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA8C21FA402A241EULL,
		0x82B0DA93893A9BA3ULL,
		0xD9397C2333DB9006ULL,
		0xFA240D9504ECDC3CULL,
		0xD0D995C1ACF94453ULL,
		0x52143767ED4E4F7BULL,
		0x1AC2247F583953B4ULL,
		0xCA480DB4F7D10362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9D1A063BAD1C773ULL,
		0xFD20575D54D4254BULL,
		0x064ECC8D3068702DULL,
		0xCF94E40ADD76DD1AULL,
		0x245F031CFF1CC131ULL,
		0x0A0EE0E4F9E9B98CULL,
		0xBDBD0922B47C9248ULL,
		0x277DF8D158154E02ULL
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
		0x60CBF09710433FA4ULL,
		0x34AD1A812BEC2B84ULL,
		0x7430819AD12090E0ULL,
		0x7868C3CADF4FC9FAULL,
		0x2A65D0555081F68BULL,
		0x40C7726F644FA869ULL,
		0xFCCD1F311388ADB2ULL,
		0x8EFA72E238815518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x673D83313C02EDCEULL,
		0x6E53473040B67F6AULL,
		0xAB4DF0F31391F2C1ULL,
		0xC4A1EF3E59F8BCFFULL,
		0x461D661CE3261733ULL,
		0x9D168A74B7976050ULL,
		0x15A09C9A3BC9DEDFULL,
		0xD1197CC53D41AF33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF98E6D65D44051D6ULL,
		0xC659D350EB35AC19ULL,
		0xC8E290A7BD8E9E1EULL,
		0xB3C6D48C85570CFAULL,
		0xE4486A386D5BDF57ULL,
		0xA3B0E7FAACB84818ULL,
		0xE72C8296D7BECED2ULL,
		0xBDE0F61CFB3FA5E5ULL
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
		0x4525DC848D34C728ULL,
		0xD193817B9D78B78AULL,
		0xEA54A4C01EF68BB6ULL,
		0x41DB7175BEDB0694ULL,
		0x8C4BFC4C7AB60298ULL,
		0x8D7F860444CB00D5ULL,
		0xEF140D0C2D679D3AULL,
		0xB1F0C1655BE9D72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F036CC4426386CBULL,
		0xDBB81FAD8CFC0904ULL,
		0x380FB62EF7A7DEE1ULL,
		0x188B497E2E5CC48CULL,
		0x5CC507748A33A7B5ULL,
		0x0160B17406B853F9ULL,
		0xAA7E4CFC9A32F7D1ULL,
		0x06E3802A80C28F0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26226FC04AD1405DULL,
		0xF5DB61CE107CAE86ULL,
		0xB244EE91274EACD4ULL,
		0x295027F7907E4208ULL,
		0x2F86F4D7F0825AE3ULL,
		0x8C1ED4903E12ACDCULL,
		0x4495C00F9334A569ULL,
		0xAB0D413ADB274822ULL
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
		0x06C3FFF30C8E89C3ULL,
		0xFC85C98D448707FAULL,
		0x78871EF3AF083FA6ULL,
		0xCEA14CDDD86ECDD5ULL,
		0x4FCFC108C6003372ULL,
		0x61D333A7DAB99C5AULL,
		0xD48C7048C4343E44ULL,
		0xAFD51D7474534EB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBBF234A5BFD860ULL,
		0x8D048E540A66ACDEULL,
		0x1E838612F2056AFAULL,
		0x3BEAD69BDDB9A8F1ULL,
		0x52687ADB9E35EAD0ULL,
		0xA40430A1C25B2921ULL,
		0xDC590090813B0BFFULL,
		0x6F606B11F2D440AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9080DBE66CEB163ULL,
		0x6F813B393A205B1BULL,
		0x5A0398E0BD02D4ACULL,
		0x92B67641FAB524E4ULL,
		0xFD67462D27CA48A2ULL,
		0xBDCF0306185E7338ULL,
		0xF8336FB842F93244ULL,
		0x4074B262817F0E06ULL
	}};
	sign = 0;
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
		0xF5A9DA8FAC152FD3ULL,
		0x18960B6866158709ULL,
		0xA1E4D9D358044E54ULL,
		0x8A1CAC968755009AULL,
		0x139646E2C4163479ULL,
		0x545379C2E41E03FFULL,
		0x3894572BB872C448ULL,
		0xC41547A66DD8D5A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55CB109063E8149AULL,
		0xA721718AE910A52DULL,
		0xF4A1E0307761168CULL,
		0x9A0884526E8B0153ULL,
		0xE48D237D1D135ADCULL,
		0xCE166668B78B8A15ULL,
		0x25C6E27DC462B8ADULL,
		0x42D80BD09815D1FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FDEC9FF482D1B39ULL,
		0x717499DD7D04E1DCULL,
		0xAD42F9A2E0A337C7ULL,
		0xF014284418C9FF46ULL,
		0x2F092365A702D99CULL,
		0x863D135A2C9279E9ULL,
		0x12CD74ADF4100B9AULL,
		0x813D3BD5D5C303A2ULL
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
		0x24075A5224C5062DULL,
		0xEC6F4EBE035AF89AULL,
		0x4C8A6812C00838E8ULL,
		0xB76D3054F3671AFEULL,
		0xF2A3E966BE8EC7D8ULL,
		0x35CA17BA7F6EC5CCULL,
		0x1F2A519DA4F063FEULL,
		0x892B24804421F48CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED36CD0CE253FB74ULL,
		0x1281237907021903ULL,
		0xFDECB41725DDDDDCULL,
		0x0F4346B7D40B7A7CULL,
		0x40401FF96DDC0717ULL,
		0xE3E7F86BC9C96286ULL,
		0xDA411E2D01F9FEE8ULL,
		0xA01D4AFB24980607ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36D08D4542710AB9ULL,
		0xD9EE2B44FC58DF96ULL,
		0x4E9DB3FB9A2A5B0CULL,
		0xA829E99D1F5BA081ULL,
		0xB263C96D50B2C0C1ULL,
		0x51E21F4EB5A56346ULL,
		0x44E93370A2F66515ULL,
		0xE90DD9851F89EE84ULL
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
		0x9E015CBCED74B185ULL,
		0x14A219667C13E6D3ULL,
		0x33D7355487BD04DFULL,
		0xEDDC3585EA7E6E43ULL,
		0xD9B9B0AA90B9719BULL,
		0x2E20DD9807DB9E3FULL,
		0x164DFC02C04B0CEAULL,
		0x4D6307D580EFF05FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB870830913383206ULL,
		0x8340086409D94B25ULL,
		0x56385712D53416EBULL,
		0x69EBBFC5C2953C70ULL,
		0x70FAE6647B0E54F4ULL,
		0xB0A0B2610F2CB83AULL,
		0x094A1F78D79AB6B7ULL,
		0x71FF7AA7AAF2D222ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE590D9B3DA3C7F7FULL,
		0x91621102723A9BADULL,
		0xDD9EDE41B288EDF3ULL,
		0x83F075C027E931D2ULL,
		0x68BECA4615AB1CA7ULL,
		0x7D802B36F8AEE605ULL,
		0x0D03DC89E8B05632ULL,
		0xDB638D2DD5FD1E3DULL
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
		0x29100D1144C72902ULL,
		0xD6F3EEA6A54C7C3EULL,
		0xDDD4E8A9F2215F4BULL,
		0xA1E4B69F0B23AD9FULL,
		0x7843C3445A147645ULL,
		0x7A11D3B747D44100ULL,
		0x7939508B696E0FE7ULL,
		0x76AC418C3AB00CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB61E8F2C16478B6ULL,
		0xE8F8F82624FC44ADULL,
		0x55B011E4165CD1FBULL,
		0xA3974572678366A3ULL,
		0x099314341DCCFD88ULL,
		0x43E56A5262A202CCULL,
		0xE6299E727E363D53ULL,
		0x8316325351351DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DAE241E8362B04CULL,
		0xEDFAF68080503790ULL,
		0x8824D6C5DBC48D4FULL,
		0xFE4D712CA3A046FCULL,
		0x6EB0AF103C4778BCULL,
		0x362C6964E5323E34ULL,
		0x930FB218EB37D294ULL,
		0xF3960F38E97AEEAAULL
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
		0x70E0E854C857D509ULL,
		0xBAA2CC3C409A9B6EULL,
		0x63D426D30A36D3D4ULL,
		0x44E74ABBB1E04DE9ULL,
		0xC5836E06C7A9C09AULL,
		0xE5B8F9C08199C18EULL,
		0x83D652CD4E09B917ULL,
		0x07B80BB47EB11FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF279EEDB08031FD5ULL,
		0x64B8A2173AB1458EULL,
		0x7D9C0FC3355B7BE4ULL,
		0x7E59B3F2FCE5AFDFULL,
		0xF240A4DB92E0AC19ULL,
		0x730C0DB276397740ULL,
		0xBAF7B105B666D758ULL,
		0x260348AE14AE5BC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E66F979C054B534ULL,
		0x55EA2A2505E955DFULL,
		0xE638170FD4DB57F0ULL,
		0xC68D96C8B4FA9E09ULL,
		0xD342C92B34C91480ULL,
		0x72ACEC0E0B604A4DULL,
		0xC8DEA1C797A2E1BFULL,
		0xE1B4C3066A02C424ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x732271EEFAC893DBULL,
		0x14A8892C7262D9F1ULL,
		0x04DBDC82F2981B8DULL,
		0xAFA44A7CC9364035ULL,
		0x4DE98061BB31B233ULL,
		0xA13AB82A90FB1C97ULL,
		0x65109AF2190CAE8AULL,
		0xA3243829344CCBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF43FCCE966B02348ULL,
		0x02416C543F315F34ULL,
		0xBE3DAFB893A7523CULL,
		0x4986D1DE69B406E3ULL,
		0x54FA3F9984689AFEULL,
		0xDCADE45DBF5CE382ULL,
		0x426CE05271F263C7ULL,
		0x45D1D298FF122A23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EE2A50594187093ULL,
		0x12671CD833317ABCULL,
		0x469E2CCA5EF0C951ULL,
		0x661D789E5F823951ULL,
		0xF8EF40C836C91735ULL,
		0xC48CD3CCD19E3914ULL,
		0x22A3BA9FA71A4AC2ULL,
		0x5D526590353AA19FULL
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
		0x33156B20AE6EA977ULL,
		0xCBCF70B37E219721ULL,
		0x166B4866FD24AFBAULL,
		0xF66B726FA423E766ULL,
		0x75532F74510DB2BEULL,
		0x3DBE41AD62B0B8ADULL,
		0x334F614502F0E685ULL,
		0x57B33EC92A96F988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E653994499CC7C0ULL,
		0xF912F7665707F731ULL,
		0x3AFEC1B5641FCBAFULL,
		0x158F89F4B61E03FDULL,
		0x1C1D672045E4599EULL,
		0xF0007E530C8F2395ULL,
		0x6D074765F84557D3ULL,
		0xB8F7884C71587AFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4B0318C64D1E1B7ULL,
		0xD2BC794D27199FEFULL,
		0xDB6C86B19904E40AULL,
		0xE0DBE87AEE05E368ULL,
		0x5935C8540B295920ULL,
		0x4DBDC35A56219518ULL,
		0xC64819DF0AAB8EB1ULL,
		0x9EBBB67CB93E7E8AULL
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
		0x8A6C0664C98C8F1AULL,
		0xF44E45989DCEF584ULL,
		0x06EC9D613097FA49ULL,
		0x8ADABD843EDA4F60ULL,
		0xC9FD80495CF5A2B2ULL,
		0xE3071D72C6240AACULL,
		0x9D4033D7B553D59DULL,
		0xAD05CD4C5B00E325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F2AD8C0453C10EULL,
		0xD391895827ED7497ULL,
		0x671A5CC49D1222F7ULL,
		0xB9D940F39860EC39ULL,
		0xA40D1368EC1935C3ULL,
		0xF6B6B3038FA0CFF9ULL,
		0xA7009FC23B4AF506ULL,
		0xAA16D99012891B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x797958D8C538CE0CULL,
		0x20BCBC4075E180EDULL,
		0x9FD2409C9385D752ULL,
		0xD1017C90A6796326ULL,
		0x25F06CE070DC6CEEULL,
		0xEC506A6F36833AB3ULL,
		0xF63F94157A08E096ULL,
		0x02EEF3BC4877C798ULL
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
		0x1F18275B109DF09DULL,
		0xBD0E05051D6D61ECULL,
		0xBA333C1B2083ACF2ULL,
		0x92F09B6FC1E9F36DULL,
		0x34CAABB87AB8A8D2ULL,
		0x221CC0A6FDC45928ULL,
		0xF5C0384F2346859BULL,
		0x387C02E367DC7476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F9C4A5667F5AE7ULL,
		0xC23A617275947369ULL,
		0x7CFBC4310D25F5EFULL,
		0x4B77B6C264ED0609ULL,
		0xF7275D1554FED76FULL,
		0x2E2974604AE9B1E0ULL,
		0xE49E3FB089086C2AULL,
		0xD3AF6564DE2003EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C1E62B5AA1E95B6ULL,
		0xFAD3A392A7D8EE82ULL,
		0x3D3777EA135DB702ULL,
		0x4778E4AD5CFCED64ULL,
		0x3DA34EA325B9D163ULL,
		0xF3F34C46B2DAA747ULL,
		0x1121F89E9A3E1970ULL,
		0x64CC9D7E89BC7087ULL
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
		0xB88D16463EE37E95ULL,
		0x5E572493C51A7C5AULL,
		0x34C0138DCA407E76ULL,
		0x681C30ADFE98B1CBULL,
		0xE0D34A22B6C4DE68ULL,
		0xC90288E14E8F2D1CULL,
		0x1C922D31267AD555ULL,
		0xF810F4AE18F42672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A99EB71E8C5BF6CULL,
		0x380AD5CAACD05938ULL,
		0xBF805F1F23A51AE3ULL,
		0x6B0D4848E402E736ULL,
		0xC79425507E59E8FCULL,
		0xE66068916CB4FF2DULL,
		0x9BEE776C0D89BC0AULL,
		0x622A793705C798AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DF32AD4561DBF29ULL,
		0x264C4EC9184A2322ULL,
		0x753FB46EA69B6393ULL,
		0xFD0EE8651A95CA94ULL,
		0x193F24D2386AF56BULL,
		0xE2A2204FE1DA2DEFULL,
		0x80A3B5C518F1194AULL,
		0x95E67B77132C8DC7ULL
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
		0x3E4C89EF6EC992D7ULL,
		0x4346C7C2045DBD0AULL,
		0xB802FB3A217F1F47ULL,
		0xF412216382121FD6ULL,
		0x6595D6C809CC449EULL,
		0x10EC2ECD8FD95F09ULL,
		0xE5D6A016CFE61B3FULL,
		0xF412410E45A7CFE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD3FB2B2D249563ULL,
		0x9B76A64CE68AF40DULL,
		0x535CF8B840E8C5DFULL,
		0xBD5FC2D1F6A95428ULL,
		0xE097D2516A3D426BULL,
		0x362A7DE137F8C452ULL,
		0x2193D111167E74ECULL,
		0xC1D15A03A6B6380BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1788EC441A4FD74ULL,
		0xA7D021751DD2C8FCULL,
		0x64A60281E0965967ULL,
		0x36B25E918B68CBAEULL,
		0x84FE04769F8F0233ULL,
		0xDAC1B0EC57E09AB6ULL,
		0xC442CF05B967A652ULL,
		0x3240E70A9EF197D7ULL
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
		0xF50F602DE9FB6253ULL,
		0xCDC157B0ABBA00D6ULL,
		0x5F75402F4E92B99AULL,
		0x7DDB84DAAFA7571BULL,
		0x9D894F261AD74869ULL,
		0x13FB89552B7B1B39ULL,
		0x699E738C363E023BULL,
		0xC89A18F9FD87BBFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x370B9962696DA0B2ULL,
		0xFDF373891C680E26ULL,
		0xC6CE96DD8A84E160ULL,
		0x6F3F4D57B2B44FEBULL,
		0x589FB257F60B76B6ULL,
		0x77871C1190082C3DULL,
		0x2F41FF82EA9C1A50ULL,
		0xC9ED56B0D56B82B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE03C6CB808DC1A1ULL,
		0xCFCDE4278F51F2B0ULL,
		0x98A6A951C40DD839ULL,
		0x0E9C3782FCF3072FULL,
		0x44E99CCE24CBD1B3ULL,
		0x9C746D439B72EEFCULL,
		0x3A5C74094BA1E7EAULL,
		0xFEACC249281C3943ULL
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
		0xDEBCC2CF43F0AB0FULL,
		0xE4828D6198F09364ULL,
		0xAF9D7E157BEC766DULL,
		0x5C49A34CD7B96E01ULL,
		0x6AB6FCCD61FC5945ULL,
		0x71A5363C20C452F9ULL,
		0x9975779980D66D1FULL,
		0xFC8B30CCF69D340DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE3D739F8D053E7ULL,
		0xBA72935E8F623E46ULL,
		0x7331244C7DBC5619ULL,
		0xCB07C12D099D4D93ULL,
		0xFF8D63BDB4E395EFULL,
		0x90462E735F386C28ULL,
		0xC1C33E6103C3076EULL,
		0xF6650B84ED7E0A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1D8EB954B205728ULL,
		0x2A0FFA03098E551EULL,
		0x3C6C59C8FE302054ULL,
		0x9141E21FCE1C206EULL,
		0x6B29990FAD18C355ULL,
		0xE15F07C8C18BE6D0ULL,
		0xD7B239387D1365B0ULL,
		0x06262548091F298DULL
	}};
	sign = 0;
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
		0xC2B32467BD024A78ULL,
		0x5C7737C6E81C238DULL,
		0x6F98CADE30C009A6ULL,
		0x9A459A14581F905FULL,
		0x66391D0D129D04B4ULL,
		0x13828C8728BCE687ULL,
		0x19315A7E9642515EULL,
		0xE47B51088A2EEDB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x935AB7B7B56E9AB0ULL,
		0x9D97B38B65B46AD3ULL,
		0xE633D0BA1AD3D539ULL,
		0x1FA157608678D555ULL,
		0xC0F53EC5E5C7CD7CULL,
		0x1D51B9810D17AF1BULL,
		0x8478861A26546FEAULL,
		0xCFC162EFC3D859E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F586CB00793AFC8ULL,
		0xBEDF843B8267B8BAULL,
		0x8964FA2415EC346CULL,
		0x7AA442B3D1A6BB09ULL,
		0xA543DE472CD53738ULL,
		0xF630D3061BA5376BULL,
		0x94B8D4646FEDE173ULL,
		0x14B9EE18C65693D1ULL
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
		0x3880D7DD30DA6B49ULL,
		0x47B050ED2D24B289ULL,
		0x9493BE6756B024C3ULL,
		0xA4BC5DCB48BD9D23ULL,
		0xC2171301B3946CABULL,
		0xB021DCF35CB5EFFFULL,
		0x2DA10A0091775BABULL,
		0xF581ED8311BDA94DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E0D40382E9E7D1ULL,
		0x7780FF3C95BCA3A9ULL,
		0xD7BE551B5C1D3B54ULL,
		0xB375001F807222FFULL,
		0xFB883D361E14BB62ULL,
		0xD40D7FCDF5137495ULL,
		0xE49861880F60A66BULL,
		0x8B1FF6474EA037C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FA003D9ADF08378ULL,
		0xD02F51B097680EDFULL,
		0xBCD5694BFA92E96EULL,
		0xF1475DABC84B7A23ULL,
		0xC68ED5CB957FB148ULL,
		0xDC145D2567A27B69ULL,
		0x4908A8788216B53FULL,
		0x6A61F73BC31D718CULL
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
		0xED4E33484225BCCFULL,
		0xF5BCE90C2E34A205ULL,
		0xF8D24E6FD0CBF6E7ULL,
		0x5B8A719AB3737C65ULL,
		0x385F4DE85BBDE317ULL,
		0xB95BBCE6590321E6ULL,
		0x0273E30A1CC61844ULL,
		0x79DA106B1092923CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6A41AD6F096A91ULL,
		0x1AD1F557DE9FAD59ULL,
		0xE97CE53460F45246ULL,
		0x4394D103CCFA5F7AULL,
		0xC659268044E429B7ULL,
		0x91B801167272BB68ULL,
		0x45304351BAB78EEFULL,
		0x67984884142D7A5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2E3F19AD31C523EULL,
		0xDAEAF3B44F94F4ACULL,
		0x0F55693B6FD7A4A1ULL,
		0x17F5A096E6791CEBULL,
		0x7206276816D9B960ULL,
		0x27A3BBCFE690667DULL,
		0xBD439FB8620E8955ULL,
		0x1241C7E6FC6517E1ULL
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
		0x12A1E030D0CE4148ULL,
		0x540F431FC8903374ULL,
		0x599881700812A617ULL,
		0x02A857F30B486D5AULL,
		0x7830773C007E46D0ULL,
		0xC32BD80748F984ACULL,
		0x028F519ED2CC934BULL,
		0xFB7BC786136DE869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F5752E57564CA5EULL,
		0xA1DA0236EAA1C61EULL,
		0xF24A4C83A5DE8B6BULL,
		0x44BDFAB005A71500ULL,
		0x9856A9570B2E7B1BULL,
		0x2C2C2980F7241EA4ULL,
		0xF875EEC818255774ULL,
		0xACD601F3B017D5EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x934A8D4B5B6976EAULL,
		0xB23540E8DDEE6D55ULL,
		0x674E34EC62341AABULL,
		0xBDEA5D4305A15859ULL,
		0xDFD9CDE4F54FCBB4ULL,
		0x96FFAE8651D56607ULL,
		0x0A1962D6BAA73BD7ULL,
		0x4EA5C5926356127DULL
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
		0x915FFBEFB12F8D23ULL,
		0x01B78E13BE371C2BULL,
		0x23ABE1F7EDD8581AULL,
		0xA5125521CEF6DB6CULL,
		0x07F1007DF170166BULL,
		0x1309837996270336ULL,
		0x8309B4CC1013FBD0ULL,
		0x60C2AECD818D7B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810E83A210C0FFBCULL,
		0x0D3A2EE88BB134E0ULL,
		0xC42D20B55F5950EAULL,
		0x3F2CF97411535484ULL,
		0x04BA6CD6BB8678A1ULL,
		0x217EA34A8F14682EULL,
		0x220954C4C13DD11FULL,
		0xEBB3B4763E63B876ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1051784DA06E8D67ULL,
		0xF47D5F2B3285E74BULL,
		0x5F7EC1428E7F072FULL,
		0x65E55BADBDA386E7ULL,
		0x033693A735E99DCAULL,
		0xF18AE02F07129B08ULL,
		0x610060074ED62AB0ULL,
		0x750EFA574329C2E7ULL
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
		0x0509FC70691EE2F9ULL,
		0xAE98C20F4F571DC3ULL,
		0x2365F4E5E6B39194ULL,
		0x54A0C483838C63C4ULL,
		0x4829A75AEE0ED513ULL,
		0x54F493463ED550C6ULL,
		0xD3BD3F964D7E70EAULL,
		0xACEB59FE725E3575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7202AF8538A67A1ULL,
		0xF4E094E3004E2DD3ULL,
		0xFF03EFD26A23EF88ULL,
		0xCB6719A82DAC8564ULL,
		0xC8F7B901436A9740ULL,
		0x7D032390BC38B8BFULL,
		0x1EC1CEDE3406264DULL,
		0x7A35727491DA6BCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DE9D17815947B58ULL,
		0xB9B82D2C4F08EFEFULL,
		0x246205137C8FA20BULL,
		0x8939AADB55DFDE5FULL,
		0x7F31EE59AAA43DD2ULL,
		0xD7F16FB5829C9806ULL,
		0xB4FB70B819784A9CULL,
		0x32B5E789E083C9A6ULL
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
		0x7E341BC4B8607E67ULL,
		0x9A21DFCFA5507E55ULL,
		0x3EF4E5A31FB68B9DULL,
		0x8BD9D98E4C4A266AULL,
		0x577B8F2A3B348916ULL,
		0x205845FD7E71CF12ULL,
		0x14F8657B68EB0619ULL,
		0x733E33476BBACDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5684F24D87B8DA98ULL,
		0x48DD668E1D5B7F5EULL,
		0xFC91C3DD5451DD40ULL,
		0xF73A2B06BF4AF158ULL,
		0xAA24440151A4F963ULL,
		0xEF6DE3268C56865BULL,
		0xCE04CFC5AA0BCE92ULL,
		0x6F3502633F34B63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27AF297730A7A3CFULL,
		0x5144794187F4FEF7ULL,
		0x426321C5CB64AE5DULL,
		0x949FAE878CFF3511ULL,
		0xAD574B28E98F8FB2ULL,
		0x30EA62D6F21B48B6ULL,
		0x46F395B5BEDF3786ULL,
		0x040930E42C861797ULL
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
		0x35C40BA5C7D6C595ULL,
		0xB9BD9BFD80307FF9ULL,
		0x786043E3F642569EULL,
		0x5AE7D9E37BF08E06ULL,
		0x351705262C0697DFULL,
		0x552B1CC395F7EA4EULL,
		0xC6E27A2D1969365FULL,
		0xF32F8A8B49A5CE3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B38B0D44C61470AULL,
		0x8D10A85A976A6B17ULL,
		0x03DEC99AB21E1B37ULL,
		0x127A9FEE67424239ULL,
		0xC5BF58264A34B595ULL,
		0x544221B57769A57FULL,
		0xB999C4B32B32CF96ULL,
		0x2DF5F4F2B8ABF653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA8B5AD17B757E8BULL,
		0x2CACF3A2E8C614E1ULL,
		0x74817A4944243B67ULL,
		0x486D39F514AE4BCDULL,
		0x6F57ACFFE1D1E24AULL,
		0x00E8FB0E1E8E44CEULL,
		0x0D48B579EE3666C9ULL,
		0xC539959890F9D7EAULL
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
		0x252CA9B05FDC2EDAULL,
		0x0AF3521FB5ADBBD8ULL,
		0x0369966CBB55EB9EULL,
		0xFA5419CA6AD880C4ULL,
		0xF474276B5A91D253ULL,
		0x16B04A60C68B818FULL,
		0xABEBBDF8A710935EULL,
		0x5644CE42DC9D9EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4F4FC7DE6211D37ULL,
		0xEA33237FCF8C29EEULL,
		0xFA26A721DDA10DC3ULL,
		0x7074D7D4718F100FULL,
		0x2F1596821FE44026ULL,
		0xC418FAD4B0596FDCULL,
		0x004A6DB84AB0A9F0ULL,
		0xE95361CACF8A2763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7037AD3279BB11A3ULL,
		0x20C02E9FE62191E9ULL,
		0x0942EF4ADDB4DDDAULL,
		0x89DF41F5F94970B4ULL,
		0xC55E90E93AAD922DULL,
		0x52974F8C163211B3ULL,
		0xABA150405C5FE96DULL,
		0x6CF16C780D137788ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDD9D162F3D08B16FULL,
		0x6D591A0A7D1F27D4ULL,
		0x2FC6E41A39E0D764ULL,
		0x7B8BD4EC941BBB33ULL,
		0xFE7CBBD742510962ULL,
		0xA6533CCDC9E82A66ULL,
		0x2E2AB0AA0A380764ULL,
		0x1EEC7D5E9500309CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C35DEE3C67171A9ULL,
		0xB269BCE8765DBA87ULL,
		0xBCF917AB9718A556ULL,
		0x324193C2BCEF7F62ULL,
		0x4ABA9E9938E26AF9ULL,
		0x94E67A690FF24843ULL,
		0xEA229C780B6976A7ULL,
		0x45768CA87CAD3D80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7167374B76973FC6ULL,
		0xBAEF5D2206C16D4DULL,
		0x72CDCC6EA2C8320DULL,
		0x494A4129D72C3BD0ULL,
		0xB3C21D3E096E9E69ULL,
		0x116CC264B9F5E223ULL,
		0x44081431FECE90BDULL,
		0xD975F0B61852F31BULL
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
		0x48A2FA7968FAAFB6ULL,
		0xAF4EF8D7AC47CA36ULL,
		0x4C93DD1517DE1662ULL,
		0x57A2D046D5A44537ULL,
		0x4D05BDB215D50D4BULL,
		0x130FB3AABE20CD44ULL,
		0xD4544A5D82AF332EULL,
		0xA2CDEC8CEDC22A3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x231D24988151C716ULL,
		0xB244323392305CD7ULL,
		0x72F241CB92F67F1EULL,
		0x32360A298BD410BDULL,
		0x9AFC6F6B97C7769AULL,
		0xCBB24E7F4DB7646CULL,
		0xFAF378F82DBE6478ULL,
		0x1F1C58591D29E125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2585D5E0E7A8E8A0ULL,
		0xFD0AC6A41A176D5FULL,
		0xD9A19B4984E79743ULL,
		0x256CC61D49D03479ULL,
		0xB2094E467E0D96B1ULL,
		0x475D652B706968D7ULL,
		0xD960D16554F0CEB5ULL,
		0x83B19433D0984919ULL
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
		0xA48AE894CD603BEFULL,
		0xB3661A68B6BC36B5ULL,
		0x491CD012C6371A2EULL,
		0x67A23694AFB86AA2ULL,
		0xF78151D63E6E4F2AULL,
		0xB8D969218F17FE11ULL,
		0x6C15DF42478366F4ULL,
		0xA7DA2D9FF3D15258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x571C540D3BD430A1ULL,
		0xBE4B7A02D76211EFULL,
		0x7DBE2C5F8C7BD66CULL,
		0x2619484C35DD555BULL,
		0x9784E12595A5999AULL,
		0x5E95D0886518BECBULL,
		0xB2B1C5263CF09BD6ULL,
		0xE75EFCF517434BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D6E9487918C0B4EULL,
		0xF51AA065DF5A24C6ULL,
		0xCB5EA3B339BB43C1ULL,
		0x4188EE4879DB1546ULL,
		0x5FFC70B0A8C8B590ULL,
		0x5A43989929FF3F46ULL,
		0xB9641A1C0A92CB1EULL,
		0xC07B30AADC8E065BULL
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
		0x1048F2C98148282EULL,
		0x21705EC8C52FEDFAULL,
		0x2CF62AECA7FDEC5FULL,
		0xB90377C3AE8EEE15ULL,
		0xAA92EFA044F3F193ULL,
		0xEC01A68DC38B5572ULL,
		0x3DBD032F439818DBULL,
		0xD6D82E75891D3CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D328CB2D0EEA88ULL,
		0x36542A6F7C0B09AFULL,
		0x723B1AB0482D078CULL,
		0x50A02F16F0626F79ULL,
		0x6A5B3190E7B5ADA6ULL,
		0x0F3EDB09DB520A44ULL,
		0xEF4569FF132089F6ULL,
		0x739114BBF941FE52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE75C9FE54393DA6ULL,
		0xEB1C34594924E44AULL,
		0xBABB103C5FD0E4D2ULL,
		0x686348ACBE2C7E9BULL,
		0x4037BE0F5D3E43EDULL,
		0xDCC2CB83E8394B2EULL,
		0x4E77993030778EE5ULL,
		0x634719B98FDB3E77ULL
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
		0x014257D8B4779D7CULL,
		0xF27878FC0BD19755ULL,
		0xC30EB93684B10260ULL,
		0xA337990EFABED12AULL,
		0xEF6F66311324A24DULL,
		0x89EBB48913023F18ULL,
		0x2532371E4BFCFA50ULL,
		0xE913049B699FB8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8217564F6934A0FEULL,
		0x4B4A0B9294EB3637ULL,
		0x9AD34B57A0336044ULL,
		0xAAFDACA5FC5E48B7ULL,
		0xF0439648FF9DC2CCULL,
		0x9997274B7F5DD706ULL,
		0x41C7968D5C7AA75CULL,
		0xD149E1865B59C924ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F2B01894B42FC7EULL,
		0xA72E6D6976E6611DULL,
		0x283B6DDEE47DA21CULL,
		0xF839EC68FE608873ULL,
		0xFF2BCFE81386DF80ULL,
		0xF0548D3D93A46811ULL,
		0xE36AA090EF8252F3ULL,
		0x17C923150E45EFCFULL
	}};
	sign = 0;
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
		0x8BD97CB3917C358AULL,
		0xF9B38415FCEA954AULL,
		0x75B5DA81F09158F1ULL,
		0x21F22019FA623D08ULL,
		0x2306CA732934F243ULL,
		0x7CBB5E53766FBC16ULL,
		0xC467ED7428F759DFULL,
		0x27F43A6C4312D0CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6F98E38944B7B89ULL,
		0xB4634AAA15FC62D5ULL,
		0x17FBCF7882CC0E22ULL,
		0x0A6F7315E12EB87CULL,
		0xDFA46B6C1263BE30ULL,
		0xE27589A0D35EE3F7ULL,
		0x3EBDC18ACE023596ULL,
		0xC80EDFACF9DCE4E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4DFEE7AFD30BA01ULL,
		0x4550396BE6EE3274ULL,
		0x5DBA0B096DC54ACFULL,
		0x1782AD041933848CULL,
		0x43625F0716D13413ULL,
		0x9A45D4B2A310D81EULL,
		0x85AA2BE95AF52448ULL,
		0x5FE55ABF4935EBE9ULL
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
		0x61E5234F978111F8ULL,
		0xAE9815111FDA78CEULL,
		0x739D494D8525D8BCULL,
		0xE6095CA875B5BA01ULL,
		0x045FCB0100C8C6A3ULL,
		0x389820AC8B2AC2E0ULL,
		0x9355624213D61808ULL,
		0x15E86E36DB9E902CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF418220D31B63E1DULL,
		0xA2F5C6B87C31C995ULL,
		0x78FB7A45A8B3F972ULL,
		0xCC40F15E834704F7ULL,
		0xB1B867D4780DEE69ULL,
		0x90031D7A37E8466AULL,
		0x6C7A79336AC3B7BDULL,
		0x00EF0C89BA5AA891ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DCD014265CAD3DBULL,
		0x0BA24E58A3A8AF38ULL,
		0xFAA1CF07DC71DF4AULL,
		0x19C86B49F26EB509ULL,
		0x52A7632C88BAD83AULL,
		0xA895033253427C75ULL,
		0x26DAE90EA912604AULL,
		0x14F961AD2143E79BULL
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
		0xEC6CC2D5D2C63D79ULL,
		0xEA920D0C19DC400DULL,
		0x627697DC852025BFULL,
		0xDB2B99AA9CA78FF0ULL,
		0x7F71F3E99F21CF39ULL,
		0x1C284C01EFB3B926ULL,
		0x26C58980FAE102B2ULL,
		0xBEF842EF7CF377FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3286377A51BE2438ULL,
		0x1ED55D459AA35304ULL,
		0x2C05327147C0F203ULL,
		0x315863B945B3B6EDULL,
		0x6F7CE83953BF57A5ULL,
		0x617D8C3442DF7257ULL,
		0xD46C44683E3C6280ULL,
		0x660EFF224AA2A634ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9E68B5B81081941ULL,
		0xCBBCAFC67F38ED09ULL,
		0x3671656B3D5F33BCULL,
		0xA9D335F156F3D903ULL,
		0x0FF50BB04B627794ULL,
		0xBAAABFCDACD446CFULL,
		0x52594518BCA4A031ULL,
		0x58E943CD3250D1C6ULL
	}};
	sign = 0;
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
		0xD5ACED9E7C3BBD78ULL,
		0xC8086171F5DE31C3ULL,
		0x7C792A785EF86551ULL,
		0x28EB8CDDB1B5BD63ULL,
		0x40C4B8F0D2F8C7FCULL,
		0x7B26528EA1E0386AULL,
		0xE2156E5366632691ULL,
		0x4E46500B483FF8D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0ECE19AF9776D3ULL,
		0x94604F8C500D525CULL,
		0x0705FB6333C3F7D6ULL,
		0x7EA5032D10A56B14ULL,
		0x8E1F15B551BA3972ULL,
		0xFA6F072ADB01BE71ULL,
		0xA5F99971B156DCFDULL,
		0x5A0ABCA1458FB816ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x899E1F84CCA446A5ULL,
		0x33A811E5A5D0DF67ULL,
		0x75732F152B346D7BULL,
		0xAA4689B0A110524FULL,
		0xB2A5A33B813E8E89ULL,
		0x80B74B63C6DE79F8ULL,
		0x3C1BD4E1B50C4993ULL,
		0xF43B936A02B040BEULL
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
		0xE51A96B789715301ULL,
		0x253A3059BC52CBB0ULL,
		0x9AB75D944D930DACULL,
		0xF03A2A7EFCC25384ULL,
		0x21EB60E966F715D0ULL,
		0x58455B1BDB4A301FULL,
		0x39F585D15ECA4064ULL,
		0x853D5762F0C00CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF012894D707BFAE9ULL,
		0xE0DAC2E02DBCB02FULL,
		0x2C5A0E5FD7297730ULL,
		0x604E5435799D5111ULL,
		0xC402A1019B557ED5ULL,
		0xB21CFE6198DCC797ULL,
		0xAB246111601F0521ULL,
		0xF3E6CA3A982B1F50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5080D6A18F55818ULL,
		0x445F6D798E961B80ULL,
		0x6E5D4F347669967BULL,
		0x8FEBD64983250273ULL,
		0x5DE8BFE7CBA196FBULL,
		0xA6285CBA426D6887ULL,
		0x8ED124BFFEAB3B42ULL,
		0x91568D285894ED7AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCE92C38ED5FDC5FCULL,
		0xFF569BDBA72A17C0ULL,
		0xAFC62DBAF2EA7621ULL,
		0xFC43331B1EED0490ULL,
		0xA271A95936F0428BULL,
		0x66E71F596FE25FCAULL,
		0xF42BDD436772AAD9ULL,
		0x648D6F824B26310AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6141D08704B724ULL,
		0x1313824480906A03ULL,
		0x58A0D7A9A32B3CE9ULL,
		0x3EA06BAFB17DD4A7ULL,
		0x2D3E067A5347906EULL,
		0xBF7DB073D29A726BULL,
		0x1765C69E0B0A5E14ULL,
		0xD1C86F3074DC747AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023181BE4EF90ED8ULL,
		0xEC4319972699ADBDULL,
		0x572556114FBF3938ULL,
		0xBDA2C76B6D6F2FE9ULL,
		0x7533A2DEE3A8B21DULL,
		0xA7696EE59D47ED5FULL,
		0xDCC616A55C684CC4ULL,
		0x92C50051D649BC90ULL
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
		0x9F6966CED85855C8ULL,
		0xF010F1AA1F1C2926ULL,
		0xE32A128731333796ULL,
		0x78F3E6368417386AULL,
		0x8545D83290D5C3F5ULL,
		0x8443896BEC9040CDULL,
		0x213FB6972DE59158ULL,
		0xF0549AC5CF4E686FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D178D3629F2D0D9ULL,
		0xD9A238E5C45C9A41ULL,
		0x29094A8027A4C242ULL,
		0xA5A05087E4A2F653ULL,
		0xD24A8BDBFCF67755ULL,
		0xFF5ED5CEB1B94EC9ULL,
		0x657E9AD689935088ULL,
		0x706E372CEB0FCB5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9251D998AE6584EFULL,
		0x166EB8C45ABF8EE5ULL,
		0xBA20C807098E7554ULL,
		0xD35395AE9F744217ULL,
		0xB2FB4C5693DF4C9FULL,
		0x84E4B39D3AD6F203ULL,
		0xBBC11BC0A45240CFULL,
		0x7FE66398E43E9D12ULL
	}};
	sign = 0;
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
		0xB4415548434618B9ULL,
		0x3F2CBCF7131B4035ULL,
		0x88AC44A39D34A13BULL,
		0xD547C37E1EE4CE68ULL,
		0xD5CA1303CADB54F9ULL,
		0xF8570D4BC0978CA7ULL,
		0x5637BE34D321F3ADULL,
		0x37194CCE46234FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91ADE8899890F8BULL,
		0x1E2478717CDDAB1EULL,
		0xA5663FA61F54BCBEULL,
		0x718161442A320282ULL,
		0xCBC995DF8BB6C11DULL,
		0x1C001A1B9256B043ULL,
		0xDAB3AE806058D0D8ULL,
		0xF55D2261B0986A1CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B2676BFA9BD092EULL,
		0x21084485963D9517ULL,
		0xE34604FD7DDFE47DULL,
		0x63C66239F4B2CBE5ULL,
		0x0A007D243F2493DCULL,
		0xDC56F3302E40DC64ULL,
		0x7B840FB472C922D5ULL,
		0x41BC2A6C958AE5DFULL
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
		0x4B4438BCFED06E83ULL,
		0x5022ECA48BA1BB3FULL,
		0xFA3C669544AEE821ULL,
		0xD6B324D71A8CF42EULL,
		0x6C199290186B48F2ULL,
		0x5873102C0DD128E2ULL,
		0x373A260C09551144ULL,
		0x5B754C5DB10C72F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D2D7172B964F77ULL,
		0xC5DCA087A972EF1EULL,
		0xF9206A5CBAB13FACULL,
		0x8CEA178A623A7C2EULL,
		0x656FD2B4C362F972ULL,
		0x337FD349D5D1C755ULL,
		0xDA8F72A3BEE57494ULL,
		0x7718BA88CF00A216ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB57161A5D33A1F0CULL,
		0x8A464C1CE22ECC20ULL,
		0x011BFC3889FDA874ULL,
		0x49C90D4CB8527800ULL,
		0x06A9BFDB55084F80ULL,
		0x24F33CE237FF618DULL,
		0x5CAAB3684A6F9CB0ULL,
		0xE45C91D4E20BD0E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x004555CDF747B564ULL,
		0x221B8009C7803872ULL,
		0xAD000A079BCDC375ULL,
		0xE611759B9F04752FULL,
		0x3BB31B8A52B78CCDULL,
		0xD7A9DDACD35D8A32ULL,
		0xD67B322360C1DC66ULL,
		0x06DEB509F42F87AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x208645FCA173FEF8ULL,
		0x78D4939DCD5351F3ULL,
		0xAF463E55DBFC9CEAULL,
		0x1CB0094D99D77BF7ULL,
		0x16453C8F314A20EBULL,
		0xFE31F62C0F98E314ULL,
		0x4DD144C2AF991387ULL,
		0x36C8A93268061D1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFBF0FD155D3B66CULL,
		0xA946EC6BFA2CE67EULL,
		0xFDB9CBB1BFD1268AULL,
		0xC9616C4E052CF937ULL,
		0x256DDEFB216D6BE2ULL,
		0xD977E780C3C4A71EULL,
		0x88A9ED60B128C8DEULL,
		0xD0160BD78C296A8DULL
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
		0x88731C866163609BULL,
		0x0E1D9A269D68BEA8ULL,
		0x65D389A8F950D6B7ULL,
		0x9CA36EE71BC3231CULL,
		0xA7DA10845C8268BAULL,
		0x8752763EBA744DF9ULL,
		0xDB0884A7320CCEA8ULL,
		0x1F23691E98218982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395B6606A770185AULL,
		0x6EF74BDE4B87B8A6ULL,
		0xDE15ECC0D2831AA4ULL,
		0x88428A7E9B606C59ULL,
		0xDB165FC8813D5445ULL,
		0xF227B846CCA35051ULL,
		0x3C4B3E9B48D7DDFBULL,
		0x16CC6933FCB38EFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F17B67FB9F34841ULL,
		0x9F264E4851E10602ULL,
		0x87BD9CE826CDBC12ULL,
		0x1460E4688062B6C2ULL,
		0xCCC3B0BBDB451475ULL,
		0x952ABDF7EDD0FDA7ULL,
		0x9EBD460BE934F0ACULL,
		0x0856FFEA9B6DFA83ULL
	}};
	sign = 0;
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
		0xD9852CBD9FF80320ULL,
		0x02D0CB690234AA83ULL,
		0xADFFA91C8A6F61E3ULL,
		0x8DF21AF9CA803706ULL,
		0x12D26F988B6BD17DULL,
		0xE3E8A5789B0D9ADBULL,
		0xE511541504F0D498ULL,
		0x89B76044DAFE04C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44606A23F068509BULL,
		0x49997BE0BB46D59FULL,
		0xC48A1997E417FCC3ULL,
		0xF0F769EA45004A2AULL,
		0x51EC92CA30EF2C41ULL,
		0x06652A01CC100117ULL,
		0x58B5D011487F837CULL,
		0xEC23D35C7039B92CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9524C299AF8FB285ULL,
		0xB9374F8846EDD4E4ULL,
		0xE9758F84A657651FULL,
		0x9CFAB10F857FECDBULL,
		0xC0E5DCCE5A7CA53BULL,
		0xDD837B76CEFD99C3ULL,
		0x8C5B8403BC71511CULL,
		0x9D938CE86AC44B94ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5A1493DBD8F8A259ULL,
		0x70EA1D93B523B8DEULL,
		0xD6DA9130C853F54BULL,
		0x99DD8FA0A3EC62D8ULL,
		0x52B0C1E9F7F62CF2ULL,
		0xFF4186EFD2EAC98FULL,
		0x3CA99E68ADD710DBULL,
		0x7FB61B91640EFAB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA9EB297A5FCFF5CULL,
		0x50F6F6DF3D9812C7ULL,
		0x363433574E27137CULL,
		0x68F775F1959610C8ULL,
		0x61F7BE9588F15F4CULL,
		0xC7EA0C07580063CAULL,
		0x54E07D96F9F053C3ULL,
		0x53F933E80742555CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F75E14432FBA2FDULL,
		0x1FF326B4778BA616ULL,
		0xA0A65DD97A2CE1CFULL,
		0x30E619AF0E565210ULL,
		0xF0B903546F04CDA6ULL,
		0x37577AE87AEA65C4ULL,
		0xE7C920D1B3E6BD18ULL,
		0x2BBCE7A95CCCA557ULL
	}};
	sign = 0;
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
		0x61D2471FFF9DA92DULL,
		0x8674E0D2CFB8BDEAULL,
		0x500F4F568DB2AAC7ULL,
		0x3A0D22D58083FC36ULL,
		0xF4A0F1557677F334ULL,
		0x3EB8DE4364E42768ULL,
		0x6C63B08DA209E482ULL,
		0xC3870A5FADEA3D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D48D1021EDFA1EULL,
		0x58305ECC5F4AC4DAULL,
		0x685EE0F88CFE4B97ULL,
		0x82B114BC16D56D57ULL,
		0xB2C1C7D4897C7226ULL,
		0x73282D6F06DB2EBFULL,
		0x2CECCC7A89C8C373ULL,
		0x27EEE4882C2AD83AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CFDBA0FDDAFAF0FULL,
		0x2E448206706DF910ULL,
		0xE7B06E5E00B45F30ULL,
		0xB75C0E1969AE8EDEULL,
		0x41DF2980ECFB810DULL,
		0xCB90B0D45E08F8A9ULL,
		0x3F76E4131841210EULL,
		0x9B9825D781BF64CCULL
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
		0x89D2FFADEAA354C8ULL,
		0x8B636A6CC00E1E44ULL,
		0x18C808BEBCC073BCULL,
		0x962400993A0C881BULL,
		0x3DA817DE3555D4BEULL,
		0x313BB7E69A05C1C7ULL,
		0x37F2BB7E139AA98BULL,
		0xC79680D606862FF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CD514815AF17DA1ULL,
		0x6146183646275066ULL,
		0xF3676AAA0D2BD8B1ULL,
		0xEB94A5BC4F855DD7ULL,
		0xDCC136307AE78F2BULL,
		0x09454E9DDB3CB507ULL,
		0x5B7C28AE0DE1648CULL,
		0x036D454F41452978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CFDEB2C8FB1D727ULL,
		0x2A1D523679E6CDDEULL,
		0x25609E14AF949B0BULL,
		0xAA8F5ADCEA872A43ULL,
		0x60E6E1ADBA6E4592ULL,
		0x27F66948BEC90CBFULL,
		0xDC7692D005B944FFULL,
		0xC4293B86C5410680ULL
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
		0x0C0D07F83877D80FULL,
		0x9BDFC6C1CE9A2D60ULL,
		0x1F52026F9A1F95E0ULL,
		0xB2F822DD746C7E9EULL,
		0xA982B0F29C9E14E6ULL,
		0x98D2EFA2F05E56C4ULL,
		0x2BE7B8FA73032F67ULL,
		0x54B03CF9D047219BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CCEE4DBC0C55B9BULL,
		0x3943D20117FCA2B4ULL,
		0x53FDFC12E23501B6ULL,
		0x251C91D8775B5238ULL,
		0xC2B4C122B57B67BAULL,
		0x379C0CCFD94A745FULL,
		0xD8E1BD7EA8578E5EULL,
		0xE4AA146FE0742854ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F3E231C77B27C74ULL,
		0x629BF4C0B69D8AABULL,
		0xCB54065CB7EA942AULL,
		0x8DDB9104FD112C65ULL,
		0xE6CDEFCFE722AD2CULL,
		0x6136E2D31713E264ULL,
		0x5305FB7BCAABA109ULL,
		0x70062889EFD2F946ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x16569CAE0E56E47AULL,
		0xCEC6DE15D0D761E3ULL,
		0xAAFDFF40AC64F8F7ULL,
		0xBCEE1BC89226531DULL,
		0x3CC0535722C6AD55ULL,
		0xB8AFE400B0A98FF5ULL,
		0x323FADD4B4C45F3CULL,
		0x8316ED087F48BDDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A81B4F5C6CC8B4ULL,
		0x0215DE796E566D7AULL,
		0xA19E3B6667B2D512ULL,
		0x29E0593CD515271AULL,
		0xF2D3FADCF3464787ULL,
		0x6E1EC9B42491C10EULL,
		0x12C4AF5CC3B10F58ULL,
		0x627C2AD4304CFFC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FAE815EB1EA1BC6ULL,
		0xCCB0FF9C6280F468ULL,
		0x095FC3DA44B223E5ULL,
		0x930DC28BBD112C03ULL,
		0x49EC587A2F8065CEULL,
		0x4A911A4C8C17CEE6ULL,
		0x1F7AFE77F1134FE4ULL,
		0x209AC2344EFBBE14ULL
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
		0x1B623E1F72A8CE30ULL,
		0xBD3524FEDF415D98ULL,
		0x00953CC15B207DCAULL,
		0x9B5BD9C548E68EB4ULL,
		0x524623FB59870096ULL,
		0x8BA22F87FB5F2887ULL,
		0xF34EF1A156C8B885ULL,
		0xECAFE03EAF9A8354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44BF89F4FEE73738ULL,
		0x818E9B351BB66671ULL,
		0xC5924131321BF537ULL,
		0x55BC17B52B1B63EDULL,
		0xE8967325BBEDD63CULL,
		0xE2EE65EF36DEFF16ULL,
		0x639120D2F15D1633ULL,
		0xFC88D0C93421D4E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6A2B42A73C196F8ULL,
		0x3BA689C9C38AF726ULL,
		0x3B02FB9029048893ULL,
		0x459FC2101DCB2AC6ULL,
		0x69AFB0D59D992A5AULL,
		0xA8B3C998C4802970ULL,
		0x8FBDD0CE656BA251ULL,
		0xF0270F757B78AE6EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x15173680BDD85E29ULL,
		0x8E87CC7C2D920899ULL,
		0x928DDF5DA75DBD94ULL,
		0x095A6E823E50411FULL,
		0x9408CFA527115FA4ULL,
		0x9C030AF142AE74CDULL,
		0x594A9F829BBE381DULL,
		0x8B731708D0771870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x018965C496100311ULL,
		0x5731B9EB4644BC40ULL,
		0x52150C0025F7BEB5ULL,
		0x8E03414D2BCAEB55ULL,
		0x78372C8BB6400619ULL,
		0x4C424EFD065156B3ULL,
		0x651BFEDCB8247658ULL,
		0x9C3C32BC1C94735BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x138DD0BC27C85B18ULL,
		0x37561290E74D4C59ULL,
		0x4078D35D8165FEDFULL,
		0x7B572D35128555CAULL,
		0x1BD1A31970D1598AULL,
		0x4FC0BBF43C5D1E1AULL,
		0xF42EA0A5E399C1C5ULL,
		0xEF36E44CB3E2A514ULL
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
		0x0FD54E1165C181E0ULL,
		0xEAECCFB1B40C99F7ULL,
		0xF4A4FB6FE087534EULL,
		0xC8F763378B6731B4ULL,
		0x4454AB1E785D7BBDULL,
		0xF7B4B10AF7DF5D37ULL,
		0x3C97B420FEC6148AULL,
		0xF4D38E79E9E81CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DD589FA4ED1C9DDULL,
		0x9F8956EBC5D1D474ULL,
		0x261571EC34DAC6B9ULL,
		0x7B59B6EDE9032099ULL,
		0xFABF4FCDD8EC9071ULL,
		0x216AA45B97B84295ULL,
		0x68790F5134F8A9E9ULL,
		0xA123EE7A83AB95D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81FFC41716EFB803ULL,
		0x4B6378C5EE3AC582ULL,
		0xCE8F8983ABAC8C95ULL,
		0x4D9DAC49A264111BULL,
		0x49955B509F70EB4CULL,
		0xD64A0CAF60271AA1ULL,
		0xD41EA4CFC9CD6AA1ULL,
		0x53AF9FFF663C86D8ULL
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
		0xB1D423AC8FC5F11CULL,
		0xF6D5B8773524F506ULL,
		0x4245260743735E3DULL,
		0x768EB4157FA207E0ULL,
		0xB40307CF4379B1C0ULL,
		0x17BBEDCC710285C8ULL,
		0xF4DB9FE73BD50CDAULL,
		0xA0C57A3D09F339CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A916744E6D6423BULL,
		0x7FFF9969F733C0A0ULL,
		0x03B95950E5EDB242ULL,
		0xE611E36D166CB74EULL,
		0x0AB012DB6E8E01C7ULL,
		0xCF30708B448712F4ULL,
		0xFDD453D9D689AD04ULL,
		0x569FF19EDFCF62F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA742BC67A8EFAEE1ULL,
		0x76D61F0D3DF13466ULL,
		0x3E8BCCB65D85ABFBULL,
		0x907CD0A869355092ULL,
		0xA952F4F3D4EBAFF8ULL,
		0x488B7D412C7B72D4ULL,
		0xF7074C0D654B5FD5ULL,
		0x4A25889E2A23D6DEULL
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
		0xD32608F5F2BA94AAULL,
		0x8307F28E0028EE72ULL,
		0x64FB79A3B66B7EBEULL,
		0x96BE99969AA5CBF3ULL,
		0x2A41188966725E4DULL,
		0xC6188AE2827410F9ULL,
		0xD1D1B1F1461C1165ULL,
		0xEDDC37B7892DE673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AABDA064E187D2AULL,
		0x040475A7B5F83AD0ULL,
		0x61654CD32FC3FAEDULL,
		0x7932F8C617EE5F65ULL,
		0x9F1B4D5CBF6777B9ULL,
		0x59D5196297C2FFECULL,
		0xF4BE1B441E9FEAFFULL,
		0x9874B94B89A0F905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x587A2EEFA4A21780ULL,
		0x7F037CE64A30B3A2ULL,
		0x03962CD086A783D1ULL,
		0x1D8BA0D082B76C8EULL,
		0x8B25CB2CA70AE694ULL,
		0x6C43717FEAB1110CULL,
		0xDD1396AD277C2666ULL,
		0x55677E6BFF8CED6DULL
	}};
	sign = 0;
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
		0xDF2A087CC94E9046ULL,
		0x515C3A352CB60A88ULL,
		0xD0C3B976869E30ADULL,
		0x8D186104B300A2C1ULL,
		0x40ABFADF1BAD0323ULL,
		0x3CC36BB6183EFA99ULL,
		0x760DDD57E6F8E755ULL,
		0x0BF3FDE0264DBB15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD680DE3977B90B9EULL,
		0x06579FC1B267857CULL,
		0xED47151D3A2CDF19ULL,
		0x95A6E03A1F60D473ULL,
		0x8978B4707395B028ULL,
		0xC24750F804448E6DULL,
		0xC614476C80449A3CULL,
		0x33D49EEC66535DF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A92A43519584A8ULL,
		0x4B049A737A4E850CULL,
		0xE37CA4594C715194ULL,
		0xF77180CA939FCE4DULL,
		0xB733466EA81752FAULL,
		0x7A7C1ABE13FA6C2BULL,
		0xAFF995EB66B44D18ULL,
		0xD81F5EF3BFFA5D23ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2EA05847738768E3ULL,
		0xBA4C7D6FCB22DA8EULL,
		0xE58AB66A999E6A8DULL,
		0xD6A9608367AF5B0DULL,
		0x903F4ECA24364B6BULL,
		0xE6E5CC09AD77CF36ULL,
		0xF4D13711B34D8973ULL,
		0x5171ABBF985091EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE0C7A3C9AB4DC0ULL,
		0x641F79CCFA548A13ULL,
		0x3707B53D847DD626ULL,
		0xB5CD8BB2768CD467ULL,
		0x4D86C6512895A9ADULL,
		0xA6C60C8CA4909C65ULL,
		0xE102219EB3A5931EULL,
		0x97CE21B58C1EB62BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32BF90A3A9DC1B23ULL,
		0x562D03A2D0CE507AULL,
		0xAE83012D15209467ULL,
		0x20DBD4D0F12286A6ULL,
		0x42B88878FBA0A1BEULL,
		0x401FBF7D08E732D1ULL,
		0x13CF1572FFA7F655ULL,
		0xB9A38A0A0C31DBC3ULL
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
		0xF82F1536F7E269B8ULL,
		0x68CF801DBF49803BULL,
		0x27474CEB32D74696ULL,
		0x9090E32609C12650ULL,
		0x7D889B3F1ABB8743ULL,
		0x31DC08DA33837649ULL,
		0xAB1321F0ACF24DBAULL,
		0xDFF1B7039B169542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA5250EA8DF79E9AULL,
		0xD36C1DD7357A5085ULL,
		0xE090B1ED8F8488DFULL,
		0x36BB6B0D15E2CDA2ULL,
		0x22A19A5346342533ULL,
		0x76E5DDBCAD7792F7ULL,
		0x62A5AB29FBB462C0ULL,
		0x6FDE63A15B98F8A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DDCC44C69EACB1EULL,
		0x9563624689CF2FB6ULL,
		0x46B69AFDA352BDB6ULL,
		0x59D57818F3DE58ADULL,
		0x5AE700EBD4876210ULL,
		0xBAF62B1D860BE352ULL,
		0x486D76C6B13DEAF9ULL,
		0x701353623F7D9CA0ULL
	}};
	sign = 0;
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
		0xE32AEDF71281B5F2ULL,
		0x940A23C59F0EFE21ULL,
		0x9ABD306719571510ULL,
		0x70A492BCB7090495ULL,
		0x58A46A84268D9987ULL,
		0x697357D70B681D91ULL,
		0x2154FC9CB2D35670ULL,
		0x46FF4B22DDB567BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3544FB458C749A0EULL,
		0x7E77D06595381FCDULL,
		0x6D9443C3B68F6C63ULL,
		0xD89D020FA1B278CEULL,
		0x832771938A4A6B2FULL,
		0x4A170915A24377E9ULL,
		0x6ECED9037F3EC625ULL,
		0xB94E1210B37C165AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADE5F2B1860D1BE4ULL,
		0x1592536009D6DE54ULL,
		0x2D28ECA362C7A8ADULL,
		0x980790AD15568BC7ULL,
		0xD57CF8F09C432E57ULL,
		0x1F5C4EC16924A5A7ULL,
		0xB28623993394904BULL,
		0x8DB139122A395162ULL
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
		0x8ADD56E22F6617BAULL,
		0x6BDE7A3B9ED9E14AULL,
		0xBEB38025AFA623A5ULL,
		0x15665202E2D07DC0ULL,
		0x1FC2AC0E97A41902ULL,
		0xC7AA017F4469C415ULL,
		0x6885C7EE2EF4657BULL,
		0x84EF16344FCB3207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A9992CA66A90A83ULL,
		0x0926869B87688609ULL,
		0x70B5C985FD3C53CDULL,
		0x56765CF579C3BDAEULL,
		0x979AC1FE5E644088ULL,
		0xB1CAC58389289317ULL,
		0x51A1146012BD3918ULL,
		0xB6899088C9F67EF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6043C417C8BD0D37ULL,
		0x62B7F3A017715B41ULL,
		0x4DFDB69FB269CFD8ULL,
		0xBEEFF50D690CC012ULL,
		0x8827EA10393FD879ULL,
		0x15DF3BFBBB4130FDULL,
		0x16E4B38E1C372C63ULL,
		0xCE6585AB85D4B30FULL
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
		0x67F55E9547A29A09ULL,
		0x8F8A0133C91FB789ULL,
		0x1A612E19D71DF9E8ULL,
		0xD9BBA03E4991B57DULL,
		0x3F5C68349E90ABE4ULL,
		0x138925529CD0E4CFULL,
		0xFE1A8993E7660349ULL,
		0x66F05EC85D5A3D6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFFB442F3CFD54D1ULL,
		0x87E4B33B845F264DULL,
		0xB664A8F31A4E9EB7ULL,
		0x0BEDC3FFC1ED97D9ULL,
		0x056C968C80EAD8CFULL,
		0x5B30E160643399B4ULL,
		0x67E0ECF962D76DA3ULL,
		0xDA393D288E3F38C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97FA1A660AA54538ULL,
		0x07A54DF844C0913BULL,
		0x63FC8526BCCF5B31ULL,
		0xCDCDDC3E87A41DA3ULL,
		0x39EFD1A81DA5D315ULL,
		0xB85843F2389D4B1BULL,
		0x96399C9A848E95A5ULL,
		0x8CB7219FCF1B04AEULL
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
		0x1919B42D73D531A8ULL,
		0x0DE263FC1D6DD79AULL,
		0x030A21A3FBAB2DDCULL,
		0x5B879CD9CDC6D766ULL,
		0xB86D12116B9FC64DULL,
		0xA69C7FE90759E2EDULL,
		0x2336D08BD09E843EULL,
		0xF938F7B61EFDBEFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x199BA217EDDE611CULL,
		0xFCBFC2C0D48D292DULL,
		0x0C84D13136ED7D3DULL,
		0xF0A5CC4DE143CF39ULL,
		0xFC43A3BC107D83A6ULL,
		0x3BE5747BBB02F8A0ULL,
		0xC9C0E835291C7B0AULL,
		0xDAA719A356676D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF7E121585F6D08CULL,
		0x1122A13B48E0AE6CULL,
		0xF6855072C4BDB09EULL,
		0x6AE1D08BEC83082CULL,
		0xBC296E555B2242A6ULL,
		0x6AB70B6D4C56EA4CULL,
		0x5975E856A7820934ULL,
		0x1E91DE12C89651AAULL
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
		0x0F67B56EB1DDACFBULL,
		0x02180790FD9B5BADULL,
		0xAC2831A7EB386EBAULL,
		0xD49D3E31D41E2415ULL,
		0xC81F25B6A2AE7CE2ULL,
		0xCF739264110ACAD0ULL,
		0x8AB098B4542E39A5ULL,
		0x01BB722469B70CABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB38697880558E45ULL,
		0x18437CD10060AEDDULL,
		0xD83F741CADFC3D88ULL,
		0x3C8385FF9E6299A2ULL,
		0x9BD448A5CF6C5DAEULL,
		0x046C314A6FE78DDFULL,
		0xF4060538185A2503ULL,
		0xF985FD0FCE39D10CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x142F4BF631881EB6ULL,
		0xE9D48ABFFD3AACCFULL,
		0xD3E8BD8B3D3C3131ULL,
		0x9819B83235BB8A72ULL,
		0x2C4ADD10D3421F34ULL,
		0xCB076119A1233CF1ULL,
		0x96AA937C3BD414A2ULL,
		0x083575149B7D3B9EULL
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
		0xC36B905C5B27C008ULL,
		0xE9D20D3D0D6701B1ULL,
		0x53A8D9AC3F81C0EDULL,
		0x0158F639E886246AULL,
		0x4AE548EA3582D7AEULL,
		0x0709008AB77BAB50ULL,
		0x67EA71B899254141ULL,
		0x39C48C3E4D3625F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ABE3C9B4124A202ULL,
		0x5C9F40786A0E95CEULL,
		0xD3FA3E6234E70D93ULL,
		0x8186B202494D2F1AULL,
		0x8EB3E52D94FDE155ULL,
		0x1AE4A6E31FF45A34ULL,
		0x593A87F0CC0024D8ULL,
		0x50AB9DDD8E025AA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98AD53C11A031E06ULL,
		0x8D32CCC4A3586BE3ULL,
		0x7FAE9B4A0A9AB35AULL,
		0x7FD244379F38F54FULL,
		0xBC3163BCA084F658ULL,
		0xEC2459A79787511BULL,
		0x0EAFE9C7CD251C68ULL,
		0xE918EE60BF33CB54ULL
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
		0x7246A59A53EB8930ULL,
		0x96B737C71869D71FULL,
		0x1B0409543F5AE8B8ULL,
		0x02FB136957D6A5B9ULL,
		0xD902FAE07622C2E3ULL,
		0xC17401C1860BC205ULL,
		0xA7F7C94501EF6A38ULL,
		0x9EFF32CAEEED0B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC5FA7428741606ULL,
		0x023B2B06FCB3220EULL,
		0x1E5982D5ABE63B44ULL,
		0x06AEC3D27BC5B6D6ULL,
		0xAFAF25A28976653FULL,
		0xC3B3254CCDFB31CBULL,
		0xF0ADB99A509D1EFDULL,
		0x2E2A147605BBDE55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA280AB262B77732AULL,
		0x947C0CC01BB6B510ULL,
		0xFCAA867E9374AD74ULL,
		0xFC4C4F96DC10EEE2ULL,
		0x2953D53DECAC5DA3ULL,
		0xFDC0DC74B810903AULL,
		0xB74A0FAAB1524B3AULL,
		0x70D51E54E9312D1FULL
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
		0x08E97FA78C46DE89ULL,
		0xEC3F1767946514BEULL,
		0x6D64912DA94ED483ULL,
		0xFA31CF71AF4D3EBBULL,
		0xC6F687C6ECDEC68BULL,
		0x2202E3BB77FED0D4ULL,
		0x5B6802D75228A0B9ULL,
		0x2BDA5E9E025D4E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3D5F36EC7E0470DULL,
		0xC6F051F36DA45093ULL,
		0xBA192AC723CC260DULL,
		0x5626AB5D5DA98E70ULL,
		0xF94190D30FEB0022ULL,
		0x72E3664CA8D02FAAULL,
		0xD3ACA8E5DE99F676ULL,
		0xA8E133A0F0239747ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45138C38C466977CULL,
		0x254EC57426C0C42AULL,
		0xB34B66668582AE76ULL,
		0xA40B241451A3B04AULL,
		0xCDB4F6F3DCF3C669ULL,
		0xAF1F7D6ECF2EA129ULL,
		0x87BB59F1738EAA42ULL,
		0x82F92AFD1239B716ULL
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
		0x03FEC6B7A2085829ULL,
		0x4A24C7F7D87C1E3CULL,
		0xFD4EA017AD213BAAULL,
		0xA71C35F76682E764ULL,
		0xE1B85F97C0E83301ULL,
		0xB968027156D3137DULL,
		0xA2C0D827A69C91B9ULL,
		0x32A818158C24CCACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91F2D5150F2F35FULL,
		0xD075FD3BAE664085ULL,
		0x70E509EFDA595DF5ULL,
		0xDECCEF046938C814ULL,
		0x85B82093FB56CA27ULL,
		0x771A6521B071D0A0ULL,
		0xB37A4BE646BB8E77ULL,
		0xEB5D02E747621939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ADF9966511564CAULL,
		0x79AECABC2A15DDB6ULL,
		0x8C699627D2C7DDB4ULL,
		0xC84F46F2FD4A1F50ULL,
		0x5C003F03C59168D9ULL,
		0x424D9D4FA66142DDULL,
		0xEF468C415FE10342ULL,
		0x474B152E44C2B372ULL
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
		0x4414A4B7F8FEDAEDULL,
		0x177EEA4AD9FBB2A7ULL,
		0x8015DA19958AF5F3ULL,
		0xCFB2538A977E3CE2ULL,
		0x24804A94BA9613EDULL,
		0xA84568AB3AADDAD4ULL,
		0x3FFFED99F86BAFC8ULL,
		0x043E015FE712DFBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27EC1D2166783136ULL,
		0x689C34F35E7D7839ULL,
		0xFBC79C60DF29DB4FULL,
		0xA1A1F9EC7D5D672DULL,
		0x6D349D46777BF17DULL,
		0x058229868AD437B3ULL,
		0x2AE860470F6F6DCDULL,
		0x83485DD87CD07C7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C2887969286A9B7ULL,
		0xAEE2B5577B7E3A6EULL,
		0x844E3DB8B6611AA3ULL,
		0x2E10599E1A20D5B4ULL,
		0xB74BAD4E431A2270ULL,
		0xA2C33F24AFD9A320ULL,
		0x15178D52E8FC41FBULL,
		0x80F5A3876A426343ULL
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
		0xF3B104C71D07E9B4ULL,
		0xE999E76675A119EFULL,
		0xE4B4E2D261F44720ULL,
		0x42224A8536B4F1EFULL,
		0xE6EADDEB08091A64ULL,
		0x6F4C259CA449EBBEULL,
		0x297BD1012976A274ULL,
		0x5FFB589977522C78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B7B44F6A17C050DULL,
		0x07AD4BF71A4F05F0ULL,
		0x4EAC84264E27D58EULL,
		0x00175B7119B32873ULL,
		0x4C526052E53829E4ULL,
		0x841EBEF8391033F5ULL,
		0x1F9EA0C33F3FE247ULL,
		0x30795B44ED6AA337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6835BFD07B8BE4A7ULL,
		0xE1EC9B6F5B5213FFULL,
		0x96085EAC13CC7192ULL,
		0x420AEF141D01C97CULL,
		0x9A987D9822D0F080ULL,
		0xEB2D66A46B39B7C9ULL,
		0x09DD303DEA36C02CULL,
		0x2F81FD5489E78941ULL
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
		0xCB22BDFE62B5C8DAULL,
		0xCEC3E8C354AAE85EULL,
		0xE5DB341B04A70B17ULL,
		0x324430CE026EAA66ULL,
		0x6ABB3260E06E0CCBULL,
		0x7841B8834CE988BCULL,
		0xBA21ECF0A27E3398ULL,
		0x50A9A0006A1D92DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC205836344EAA681ULL,
		0xEA08349A95D04B6EULL,
		0xA790C827AF49DB16ULL,
		0x1EDA87FA049F35E6ULL,
		0x82D6D4EEFF4BEBBDULL,
		0xA1E8A81D5389E14AULL,
		0x27F4E7024C854748ULL,
		0x278BAEF7009CB8BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x091D3A9B1DCB2259ULL,
		0xE4BBB428BEDA9CF0ULL,
		0x3E4A6BF3555D3000ULL,
		0x1369A8D3FDCF7480ULL,
		0xE7E45D71E122210EULL,
		0xD6591065F95FA771ULL,
		0x922D05EE55F8EC4FULL,
		0x291DF1096980DA1EULL
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
		0xB3D00E71B700181DULL,
		0x952B965A653A0742ULL,
		0x6028C6B70FB87B4BULL,
		0x722C3E2561E7CF94ULL,
		0x12E6BEAB29E676F6ULL,
		0x992770B51EB08A69ULL,
		0x052012B18AF53C3CULL,
		0x208C22446380E3D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x225262935EC8B752ULL,
		0x4BFA5A54A787DC49ULL,
		0x615CB09F02BFB6E4ULL,
		0x3B7FBD45770A9CBEULL,
		0x39CB1888EA3299CAULL,
		0x41DCE7E400B68DBFULL,
		0x1EC32046F5171E65ULL,
		0x1D25069B7BE8514AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x917DABDE583760CBULL,
		0x49313C05BDB22AF9ULL,
		0xFECC16180CF8C467ULL,
		0x36AC80DFEADD32D5ULL,
		0xD91BA6223FB3DD2CULL,
		0x574A88D11DF9FCA9ULL,
		0xE65CF26A95DE1DD7ULL,
		0x03671BA8E7989289ULL
	}};
	sign = 0;
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
		0xCB2649418B00BD64ULL,
		0x67802FCEB0405A34ULL,
		0x4BCA2FADF7F8DCBEULL,
		0xC85880FC100FB64FULL,
		0xB4B75F3282714283ULL,
		0x763EDA8CDC615379ULL,
		0x9A14E2BD38DC8093ULL,
		0xC88665633A0E7906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B699427A4A1C32BULL,
		0x2FFCDB93796EE462ULL,
		0x4199FDB2ACE6901FULL,
		0x2BA0C1003E0F1947ULL,
		0x578A3DA5999E0BA8ULL,
		0x355CE62159A85EE9ULL,
		0x07B5D03B9F57955EULL,
		0x01480AB58E6B9EDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FBCB519E65EFA39ULL,
		0x3783543B36D175D2ULL,
		0x0A3031FB4B124C9FULL,
		0x9CB7BFFBD2009D08ULL,
		0x5D2D218CE8D336DBULL,
		0x40E1F46B82B8F490ULL,
		0x925F12819984EB35ULL,
		0xC73E5AADABA2DA2AULL
	}};
	sign = 0;
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
		0x71FCA48D3B045FF7ULL,
		0xE4F8E0A166710BEDULL,
		0xC6D54C778EE9DA53ULL,
		0xE9C7524DB5722CA0ULL,
		0x2D4A840E23EB62BFULL,
		0x0C706C424BA1401CULL,
		0x1F8E5D56CF937EF8ULL,
		0xB74CBC9F26670D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFAC30C5A8A46D88ULL,
		0x39EBC7BF79E0F871ULL,
		0xEA68A82D2F8276B0ULL,
		0x81824ED8436849CEULL,
		0x93B291324E644636ULL,
		0x0058AB19FA9EA9ABULL,
		0x43C7C476FD3781AFULL,
		0xA88E62FD5E07103AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA25073C7925FF26FULL,
		0xAB0D18E1EC90137BULL,
		0xDC6CA44A5F6763A3ULL,
		0x684503757209E2D1ULL,
		0x9997F2DBD5871C89ULL,
		0x0C17C12851029670ULL,
		0xDBC698DFD25BFD49ULL,
		0x0EBE59A1C85FFD00ULL
	}};
	sign = 0;
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
		0x0196D9D54A539123ULL,
		0x5D571B6B96CBDAE1ULL,
		0x6AD8ABF6624D1F84ULL,
		0xAA72FB054FA1E6EBULL,
		0x7B6C34B548D46DC3ULL,
		0xB8F7C8D54652888EULL,
		0xDCFCFBB77EEEB25DULL,
		0xEEF503E8B21C0BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE09169F43E433950ULL,
		0x57C9C74A53550DC4ULL,
		0x6AD506CD7C487843ULL,
		0xAD43E2D25694AEDFULL,
		0x839C26C6B4D195AEULL,
		0xFFB726A720740151ULL,
		0x66DB0B1633C65BC7ULL,
		0xED9CBAE871598798ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21056FE10C1057D3ULL,
		0x058D54214376CD1CULL,
		0x0003A528E604A741ULL,
		0xFD2F1832F90D380CULL,
		0xF7D00DEE9402D814ULL,
		0xB940A22E25DE873CULL,
		0x7621F0A14B285695ULL,
		0x0158490040C28421ULL
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
		0x3EE7650F3131756BULL,
		0x42BA69B21EA9F900ULL,
		0xBF7C7680A6C616C6ULL,
		0x82A34409D8B05F35ULL,
		0x5C286639C37E5B0EULL,
		0xBAF064112B905D80ULL,
		0xC656F11CE098852EULL,
		0x8571C4C498107E95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82E08F506D958B58ULL,
		0x45F771D0B8DA21D7ULL,
		0x42C71857F66EBE62ULL,
		0x1250CFBC34401265ULL,
		0xFB8D1D52629A8744ULL,
		0x1E5D9C8163215A8FULL,
		0xD4A3D8EDE1A0BE40ULL,
		0x38B7F70328C49859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC06D5BEC39BEA13ULL,
		0xFCC2F7E165CFD728ULL,
		0x7CB55E28B0575863ULL,
		0x7052744DA4704CD0ULL,
		0x609B48E760E3D3CAULL,
		0x9C92C78FC86F02F0ULL,
		0xF1B3182EFEF7C6EEULL,
		0x4CB9CDC16F4BE63BULL
	}};
	sign = 0;
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
		0x8368CE2711298A72ULL,
		0x5DC22085D8C49111ULL,
		0x31D6FCAE1499BB2BULL,
		0x37A240DA223116ACULL,
		0x09B1E4904DF65F5CULL,
		0x2B87B3982181DA19ULL,
		0xDDE96EA485D0E611ULL,
		0xCF652171A29A7BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DAF8E2D5752BEBCULL,
		0xE0510BB37AF00525ULL,
		0x1EE649602183BC85ULL,
		0x47E5EF4DE16665D8ULL,
		0x0DE8E790BA9FC841ULL,
		0x958E8F194C69DEB6ULL,
		0x92643E551BB60CB0ULL,
		0x3500379D4DE40BB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45B93FF9B9D6CBB6ULL,
		0x7D7114D25DD48BECULL,
		0x12F0B34DF315FEA5ULL,
		0xEFBC518C40CAB0D4ULL,
		0xFBC8FCFF9356971AULL,
		0x95F9247ED517FB62ULL,
		0x4B85304F6A1AD960ULL,
		0x9A64E9D454B66FEEULL
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
		0x5B19F568389F7427ULL,
		0x88AF6580C08EC7DCULL,
		0x41E7F8EF43367E85ULL,
		0x96624B2BADB2E676ULL,
		0x48814774F4AC16DEULL,
		0xB1644FFB5DBA54EFULL,
		0xE84FA20326C55810ULL,
		0xE980CE0ED2F854C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55BB1287A9A910CCULL,
		0xE1DCD754332D7C76ULL,
		0xF5A71C2A8BE5AA4FULL,
		0x5B9D7F9552303995ULL,
		0xAF737F402AFE495BULL,
		0x71DBDADAFC826133ULL,
		0xE1C3D5DB8C4FCA9BULL,
		0xAABDF9F579CA96E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x055EE2E08EF6635BULL,
		0xA6D28E2C8D614B66ULL,
		0x4C40DCC4B750D435ULL,
		0x3AC4CB965B82ACE0ULL,
		0x990DC834C9ADCD83ULL,
		0x3F8875206137F3BBULL,
		0x068BCC279A758D75ULL,
		0x3EC2D419592DBDE4ULL
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
		0x20D7CA833D9F186EULL,
		0x2732F147313EFEDCULL,
		0x4F92884C4105F329ULL,
		0x0C48992146861920ULL,
		0x6411AFF5EA34318DULL,
		0x85375A94087FE1F3ULL,
		0x5AD828186233CE17ULL,
		0x23D99A5E6C176452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CDFEF6BB8FEF8DULL,
		0x2DFA537CF46005DCULL,
		0x99543296C9AB3640ULL,
		0x56D862EF9F38F827ULL,
		0xF073174CBAAA643DULL,
		0x9E67DDF47B3C4B50ULL,
		0xD9DFF2C405EEA8ECULL,
		0x31CCC253F51C62DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA09CB8C820F28E1ULL,
		0xF9389DCA3CDEF8FFULL,
		0xB63E55B5775ABCE8ULL,
		0xB5703631A74D20F8ULL,
		0x739E98A92F89CD4FULL,
		0xE6CF7C9F8D4396A2ULL,
		0x80F835545C45252AULL,
		0xF20CD80A76FB0177ULL
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
		0xD689B2DAB3CBA047ULL,
		0x45708B51610F5724ULL,
		0xDEE694053D87713AULL,
		0x406298C6C1CE9449ULL,
		0x113FB0B67685DCD3ULL,
		0xD62443E399ED7D59ULL,
		0xCDF44B1E94541A52ULL,
		0x09226F5480DC1C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE6F8260587F5D4DULL,
		0x806E0A776BC84CD6ULL,
		0x1A84566B422DD0BBULL,
		0x08C16AEA09838D61ULL,
		0x7D5A82D5143015EEULL,
		0xE018C66392D8F254ULL,
		0x667749EDF60C7FAAULL,
		0xF18CBA75CBFA23CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x281A307A5B4C42FAULL,
		0xC50280D9F5470A4EULL,
		0xC4623D99FB59A07EULL,
		0x37A12DDCB84B06E8ULL,
		0x93E52DE16255C6E5ULL,
		0xF60B7D8007148B04ULL,
		0x677D01309E479AA7ULL,
		0x1795B4DEB4E1F8CDULL
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
		0x570C7AE5A24DF93AULL,
		0x8FF0640BA4908063ULL,
		0x794DA84D5739FAA1ULL,
		0xC0DF8616A0518D3FULL,
		0xAC4CD24814A40EE7ULL,
		0x6C45770606BC412BULL,
		0xFFE94A0C449A1E7EULL,
		0x295F8FB287C90DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46AE7327FCF34B74ULL,
		0x56499DE4E42DAD6FULL,
		0x088386AC0FBE94C1ULL,
		0x977FDBE61F921109ULL,
		0x8EC392D07A213247ULL,
		0x8BFE9B5188ED6512ULL,
		0xB0325715589508F8ULL,
		0xE6B5867125AA0996ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x105E07BDA55AADC6ULL,
		0x39A6C626C062D2F4ULL,
		0x70CA21A1477B65E0ULL,
		0x295FAA3080BF7C36ULL,
		0x1D893F779A82DCA0ULL,
		0xE046DBB47DCEDC19ULL,
		0x4FB6F2F6EC051585ULL,
		0x42AA0941621F045AULL
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
		0x9E7322432811E462ULL,
		0x95DFE3D224243836ULL,
		0x1F6D43D9DE5B215AULL,
		0x37A76BC4C10F48B6ULL,
		0x12B3C8BAFDBC454DULL,
		0xAEF57E09D07C2219ULL,
		0x161995F222B43803ULL,
		0x4E8488E0A490239FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F251D9E299FF253ULL,
		0xA35BDA0DF4A5143EULL,
		0xFE5B714C3B1BE2AFULL,
		0x8A4D8317C13BFEA3ULL,
		0xBE5C09B0EBA1B815ULL,
		0xACBD3AB0665CEAB2ULL,
		0x61E7681DF26B9251ULL,
		0x747C8A95A9252BFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F4E04A4FE71F20FULL,
		0xF28409C42F7F23F8ULL,
		0x2111D28DA33F3EAAULL,
		0xAD59E8ACFFD34A12ULL,
		0x5457BF0A121A8D37ULL,
		0x023843596A1F3766ULL,
		0xB4322DD43048A5B2ULL,
		0xDA07FE4AFB6AF79FULL
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
		0xA4CBE832D6351C1CULL,
		0x732EFC2F8E87D050ULL,
		0x0BA07FB62D990CD8ULL,
		0xF263593AEFD1A3DAULL,
		0x59810C49BB594596ULL,
		0xDD66C027BFA403C0ULL,
		0xAD9E252E0D7CFB47ULL,
		0x3A6752D780FE68DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12DD27F74B7DE76ULL,
		0xC01497022438AA9DULL,
		0x75195EAEBC4051A7ULL,
		0x812E6C9F716969B5ULL,
		0x390B52FE136CCBA5ULL,
		0xD57695681C7D70EBULL,
		0x76943048886C8DEFULL,
		0x37AC48EB8B501067ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x039E15B3617D3DA6ULL,
		0xB31A652D6A4F25B3ULL,
		0x968721077158BB30ULL,
		0x7134EC9B7E683A24ULL,
		0x2075B94BA7EC79F1ULL,
		0x07F02ABFA32692D5ULL,
		0x3709F4E585106D58ULL,
		0x02BB09EBF5AE5877ULL
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
		0x29FFDE35F7C54326ULL,
		0xB02D61C1E3246CC7ULL,
		0x4D13E7F980249E74ULL,
		0x4BB773D3A3DB1AE5ULL,
		0xFEB436573A2ADD79ULL,
		0x7D4E27B8628079FAULL,
		0x364ADB63F824E8A9ULL,
		0x27DB35B3A9342B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E91E1D3328DA4BEULL,
		0xB8B10382C8144B49ULL,
		0x41693426519F774BULL,
		0x7589F560A79458B5ULL,
		0xB90A91040D450128ULL,
		0x4E1506E7AF6105C8ULL,
		0x7056C6A53DC7CF3AULL,
		0x83C39601511DCEDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB6DFC62C5379E68ULL,
		0xF77C5E3F1B10217DULL,
		0x0BAAB3D32E852728ULL,
		0xD62D7E72FC46C230ULL,
		0x45A9A5532CE5DC50ULL,
		0x2F3920D0B31F7432ULL,
		0xC5F414BEBA5D196FULL,
		0xA4179FB258165C28ULL
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
		0x13502AFC8EBE2F79ULL,
		0xE41CEBD25B15273EULL,
		0xAFADE7B908CC149AULL,
		0x7BAF5F5FFB0BDDD1ULL,
		0x9D7294E2862E2A1DULL,
		0x950FA413B3E3D3AFULL,
		0xDDBED537AB568F97ULL,
		0x59752CD01C6928CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE5F7025401641CULL,
		0x6D6ADE82AE1B4E5DULL,
		0x34F8E1EC1081940AULL,
		0x0C169CC6B0DBCA77ULL,
		0xFBECA3E1DAAC59B8ULL,
		0x525C07DB931A307AULL,
		0x8F85D415E004B0C1ULL,
		0xF7B42BE147392098ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x986A33FA3ABCCB5DULL,
		0x76B20D4FACF9D8E0ULL,
		0x7AB505CCF84A8090ULL,
		0x6F98C2994A30135AULL,
		0xA185F100AB81D065ULL,
		0x42B39C3820C9A334ULL,
		0x4E390121CB51DED6ULL,
		0x61C100EED5300832ULL
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
		0xD8CEADFAB63265A5ULL,
		0x34568ACB911A02D8ULL,
		0xEC30E105518364B7ULL,
		0x94F9682E805E50A9ULL,
		0x9C4176C297DF093BULL,
		0x9B0C9C2E27B6A447ULL,
		0x7E447F20AB4312B9ULL,
		0xE70120DEAA9D2380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D367792493CC04ULL,
		0x07395E81EEDBF263ULL,
		0x235137EDE8508D6BULL,
		0xFCDCFD8A37FFF043ULL,
		0xBBBA2A1B6CD3680AULL,
		0x6155F1527B3770C9ULL,
		0x2120EAF34CD61323ULL,
		0x4EB44949FA8D23B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66FB4681919E99A1ULL,
		0x2D1D2C49A23E1075ULL,
		0xC8DFA9176932D74CULL,
		0x981C6AA4485E6066ULL,
		0xE0874CA72B0BA130ULL,
		0x39B6AADBAC7F337DULL,
		0x5D23942D5E6CFF96ULL,
		0x984CD794B00FFFCDULL
	}};
	sign = 0;
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
		0xEEA83D4AF4F689CAULL,
		0xDFCD44F013FDCB38ULL,
		0xD32A26E93B0AEE93ULL,
		0x17CE8E447AF4EEDAULL,
		0xF6D3FEC12B0C7EFEULL,
		0x4F5A9305502BC9E7ULL,
		0x8107DF0443153EF2ULL,
		0x0E200C5A18FD4DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2FD6B8F82CE005ULL,
		0xAC0805E8D2456EB2ULL,
		0x1B021E86686BAD43ULL,
		0x550DB82E2D79F663ULL,
		0x55DDDC1B896C1D2DULL,
		0xF286A08532B08FEAULL,
		0x404E2D2A8AF017FDULL,
		0xBC95667D2C29F2F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0786691FCC9A9C5ULL,
		0x33C53F0741B85C86ULL,
		0xB8280862D29F4150ULL,
		0xC2C0D6164D7AF877ULL,
		0xA0F622A5A1A061D0ULL,
		0x5CD3F2801D7B39FDULL,
		0x40B9B1D9B82526F4ULL,
		0x518AA5DCECD35AE0ULL
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
		0x77567C6A933DB2B4ULL,
		0xD4BCFCBE3BCD25F6ULL,
		0x8B78F634420380CDULL,
		0xF95697C3B4C10B5CULL,
		0x58F1B50084B4CA8DULL,
		0x73E859D1C23E7654ULL,
		0x2AAF561FA0F27BB2ULL,
		0x2D2142F981EDDC74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C27286E9C28B1ECULL,
		0x70AA046A1A7FB1F0ULL,
		0xA49209D72504468AULL,
		0x4FE81F39E7499817ULL,
		0x20361C5640710D03ULL,
		0xECC0AB96D3314728ULL,
		0x6A903230EA52B60EULL,
		0x5D0CE083046DAC9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B2F53FBF71500C8ULL,
		0x6412F854214D7406ULL,
		0xE6E6EC5D1CFF3A43ULL,
		0xA96E7889CD777344ULL,
		0x38BB98AA4443BD8AULL,
		0x8727AE3AEF0D2F2CULL,
		0xC01F23EEB69FC5A3ULL,
		0xD01462767D802FD6ULL
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
		0x486819FCADB86E9AULL,
		0x3209C0AF86CCBC05ULL,
		0x1BDC97751283013EULL,
		0x3C34E7509999BC48ULL,
		0x89B3C4D31318F648ULL,
		0xF2D4F41C2695427BULL,
		0x4F5D45B655F0F154ULL,
		0x12370B50870B0A73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E21AAB0A39B0C47ULL,
		0x8EF5542E35EDEDF3ULL,
		0x471A83397CBFF00EULL,
		0x4AC3BE2314C1FBADULL,
		0x061E073C4D821BD2ULL,
		0xDA3F1D6FD62F6FA1ULL,
		0xB04CAEE03A9965A7ULL,
		0x1693E94650140EA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA466F4C0A1D6253ULL,
		0xA3146C8150DECE11ULL,
		0xD4C2143B95C3112FULL,
		0xF171292D84D7C09AULL,
		0x8395BD96C596DA75ULL,
		0x1895D6AC5065D2DAULL,
		0x9F1096D61B578BADULL,
		0xFBA3220A36F6FBD2ULL
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
		0x99D2DEB3535D0AEEULL,
		0x5E50298F9C22C5C5ULL,
		0x4C89521C339CC761ULL,
		0xF6E2CF9AB72DE8DCULL,
		0xF2E02347F5CFFD47ULL,
		0x4B44EF55F7349F19ULL,
		0x6935965B3FEF0F40ULL,
		0x9DD4DFDFD099E93CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58B97705777C4C6ULL,
		0xCDB4ADE08C773B63ULL,
		0xE280D30D95CCF5F8ULL,
		0xCBC3622FF6FE641EULL,
		0x08D90ED396B7C3A2ULL,
		0x4C176571CDDD7D63ULL,
		0x244C8F89FD279EC9ULL,
		0x3D4A62F236427F30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4474742FBE54628ULL,
		0x909B7BAF0FAB8A61ULL,
		0x6A087F0E9DCFD168ULL,
		0x2B1F6D6AC02F84BDULL,
		0xEA0714745F1839A5ULL,
		0xFF2D89E4295721B6ULL,
		0x44E906D142C77076ULL,
		0x608A7CED9A576A0CULL
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
		0x4BE613C758514FC1ULL,
		0xB0689BAFB831BD49ULL,
		0xB0C3F21E9A6FD2F0ULL,
		0xF4685090DA76FF38ULL,
		0x1B80736E889C9877ULL,
		0x7EFF8B71C33A2803ULL,
		0xC31FDC5938116D41ULL,
		0x12899DACFCA96442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BDE36E9D1434FFULL,
		0x80F5687BC3EA9137ULL,
		0xFEE92109E4056421ULL,
		0xDA9F6A0C2741C9E0ULL,
		0xEB50896F14FC78CAULL,
		0x4E159EFC0D20A87DULL,
		0x5B01DD03C0B6DAD7ULL,
		0x96BB8D959E001E11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66283058BB3D1AC2ULL,
		0x2F733333F4472C11ULL,
		0xB1DAD114B66A6ECFULL,
		0x19C8E684B3353557ULL,
		0x302FE9FF73A01FADULL,
		0x30E9EC75B6197F85ULL,
		0x681DFF55775A926AULL,
		0x7BCE10175EA94631ULL
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
		0x14C99832122B1FB0ULL,
		0xB5861F1B4C4B7C7FULL,
		0x8F350F889E73B899ULL,
		0x9D3C31C5D7775A45ULL,
		0xCD8EF239FEBC4400ULL,
		0x5725C7CF5A82BD54ULL,
		0x47A6702FB2E6717CULL,
		0x1BC585611E7EA7EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CFF438D3878B7DULL,
		0x775A9923A7FC01E5ULL,
		0xA2BD85529740724DULL,
		0x5AF412584E1EB7AAULL,
		0x1CEB6B0B8CF18668ULL,
		0x3C46DB197A7E5754ULL,
		0xE7A457D7E6DACAB0ULL,
		0xEB3E67CE0DCF6B1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21F9A3F93EA39433ULL,
		0x3E2B85F7A44F7A99ULL,
		0xEC778A360733464CULL,
		0x42481F6D8958A29AULL,
		0xB0A3872E71CABD98ULL,
		0x1ADEECB5E0046600ULL,
		0x60021857CC0BA6CCULL,
		0x30871D9310AF3CD0ULL
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
		0x0CBFB66C57ABEB69ULL,
		0x9CAA7B1054E4A74AULL,
		0x6D3352F99D053F62ULL,
		0x1030E6B58F84B9CBULL,
		0x116F852D4026EFE3ULL,
		0x6C2B3B0A68287F21ULL,
		0x156027D148490BE2ULL,
		0xC59C6C1512C3A2EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B9BCB1B87BFB1FULL,
		0xD5FD54EB672A29DBULL,
		0xD9D7825EDE4457B4ULL,
		0x84B9C77A7A4DF8C2ULL,
		0xA29D9428C95B1FC1ULL,
		0xC312753DD8BB96BCULL,
		0xAFF4EF288A55D333ULL,
		0xBBBC4569B84D0BFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0905F9BA9F2FF04AULL,
		0xC6AD2624EDBA7D6FULL,
		0x935BD09ABEC0E7ADULL,
		0x8B771F3B1536C108ULL,
		0x6ED1F10476CBD021ULL,
		0xA918C5CC8F6CE864ULL,
		0x656B38A8BDF338AEULL,
		0x09E026AB5A7696F2ULL
	}};
	sign = 0;
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
		0x4F555D8122B7A201ULL,
		0xAC3E201929D2E532ULL,
		0x5556B31825469E63ULL,
		0x52D642BAD3A25CB7ULL,
		0x671AE32751B1FC69ULL,
		0x4545829D530E7E7AULL,
		0x8FC431013E7EF220ULL,
		0x3866797C12FA9582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE11677274AF64FULL,
		0x3C573750F54CB91EULL,
		0x716A097131F404A7ULL,
		0x84F901557632CAA3ULL,
		0x7EB6EA9D37F7190CULL,
		0x6C57DE595BF670E4ULL,
		0xC5F3EC25123E5EEEULL,
		0x17699BFB2B74EADAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40744709FB6CABB2ULL,
		0x6FE6E8C834862C14ULL,
		0xE3ECA9A6F35299BCULL,
		0xCDDD41655D6F9213ULL,
		0xE863F88A19BAE35CULL,
		0xD8EDA443F7180D95ULL,
		0xC9D044DC2C409331ULL,
		0x20FCDD80E785AAA7ULL
	}};
	sign = 0;
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
		0x0B02C6BBA2BD1C37ULL,
		0x4D15C2D6467D9D9BULL,
		0x097EFD2E5D3AE4CDULL,
		0xEEA286618940BAC9ULL,
		0x5DF864B4753937BDULL,
		0x441549F717D0A50EULL,
		0xA85E05E229240825ULL,
		0x05218795F36F78F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F31BE653AC05CDULL,
		0x470330144874F76BULL,
		0x4C29F4A9D24197D1ULL,
		0x700D3260FF439D80ULL,
		0x4A98C1D1485DB3F4ULL,
		0x6680CF7204A321FDULL,
		0x24908781A9128B52ULL,
		0xA43A958355741337ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A0FAAD54F11166AULL,
		0x061292C1FE08A62FULL,
		0xBD5508848AF94CFCULL,
		0x7E95540089FD1D48ULL,
		0x135FA2E32CDB83C9ULL,
		0xDD947A85132D8311ULL,
		0x83CD7E6080117CD2ULL,
		0x60E6F2129DFB65C0ULL
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
		0x31AAFE5CF765EFF0ULL,
		0x42949DA49BD1BD6BULL,
		0x19643C5C196F6507ULL,
		0xD81404EA991BC7FFULL,
		0x0EDFDC33D9367A57ULL,
		0xE4E880A04575710BULL,
		0xD448FAB1F8E6AA6DULL,
		0x25D5F3082DE3A38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAD6DFDD9CFE1B60ULL,
		0xE5E4E39E64EC8515ULL,
		0x9F609509BC891FFEULL,
		0xA2511CACDE65FF5AULL,
		0xA1BAD6C6F858B7DEULL,
		0x25431B1078BE1240ULL,
		0x0D3DC56D2C1A019BULL,
		0x23926E517DB595D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46D41E7F5A67D490ULL,
		0x5CAFBA0636E53855ULL,
		0x7A03A7525CE64508ULL,
		0x35C2E83DBAB5C8A4ULL,
		0x6D25056CE0DDC279ULL,
		0xBFA5658FCCB75ECAULL,
		0xC70B3544CCCCA8D2ULL,
		0x024384B6B02E0DB6ULL
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
		0xC94261798172338CULL,
		0x9715F8CE704DF5ABULL,
		0x9A2BAAC70D17C8AEULL,
		0x9185F05D19323F44ULL,
		0x5F8588699F352C06ULL,
		0x7383ECBA855C4F81ULL,
		0xE02A72700A7EF44FULL,
		0x45AD79993B742E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5403EE25936FE5D3ULL,
		0x1DE9240CFD732CE3ULL,
		0x52C7FB8B6528A3DAULL,
		0xA72264B01B7BA3CAULL,
		0x7E9B2787FADD2AB0ULL,
		0xCE72E04AAC192288ULL,
		0x23AD4A83AE58EF7BULL,
		0x768808F12DAE1EA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x753E7353EE024DB9ULL,
		0x792CD4C172DAC8C8ULL,
		0x4763AF3BA7EF24D4ULL,
		0xEA638BACFDB69B7AULL,
		0xE0EA60E1A4580155ULL,
		0xA5110C6FD9432CF8ULL,
		0xBC7D27EC5C2604D3ULL,
		0xCF2570A80DC60F96ULL
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
		0x67E1DE46373950E0ULL,
		0xA36B4D9D1F59A06EULL,
		0xBB37CF446E7A2F88ULL,
		0x36B9A137956FAF9EULL,
		0xB5F1EF10B6DF7CD7ULL,
		0xCBA6C9345904B19DULL,
		0x7E59475311B3CFF7ULL,
		0xFCD162FC95DD0C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE23C1986B101E9ULL,
		0xCFA689E7B1551C97ULL,
		0x4E9C6323B6E6D26CULL,
		0xCB82FF092D30F79AULL,
		0x57F75D3B1AEDDF30ULL,
		0xA431BB74C3255087ULL,
		0xCBE453A7F2D86C93ULL,
		0x61804BAD9CE14B15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBFFA22CB0884EF7ULL,
		0xD3C4C3B56E0483D6ULL,
		0x6C9B6C20B7935D1BULL,
		0x6B36A22E683EB804ULL,
		0x5DFA91D59BF19DA6ULL,
		0x27750DBF95DF6116ULL,
		0xB274F3AB1EDB6364ULL,
		0x9B51174EF8FBC17EULL
	}};
	sign = 0;
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
		0x9D94E6DF24DB915EULL,
		0x733E8D60019484DFULL,
		0x975AA8466D94498DULL,
		0xB84E44D4FDE642EFULL,
		0x489C12B04482FCCDULL,
		0x94844F85AD3B2CFBULL,
		0xBDAC3B580C2AF980ULL,
		0xE88CACFCCBF18FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923A5A8D43C6EE8BULL,
		0xD882025115D93FE9ULL,
		0x6368BB147121E81DULL,
		0x557EFEFBE723199BULL,
		0x60B25910BEAE446AULL,
		0x4E1F0DF965BE3E3FULL,
		0xF172630284C49CB8ULL,
		0x62331AA33CDF7DF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B5A8C51E114A2D3ULL,
		0x9ABC8B0EEBBB44F6ULL,
		0x33F1ED31FC72616FULL,
		0x62CF45D916C32954ULL,
		0xE7E9B99F85D4B863ULL,
		0x4665418C477CEEBBULL,
		0xCC39D85587665CC8ULL,
		0x865992598F1211F1ULL
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
		0x00AD9F1DD75DD3D4ULL,
		0xA5813BFBBA8A7F95ULL,
		0x319719D6310274AFULL,
		0x31F2F1E7303B0590ULL,
		0x98A8EFF1725C5B23ULL,
		0x55BF3698331FA80CULL,
		0x7D491EA19357C4D2ULL,
		0x51E87857118062EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F8BA43782297DBULL,
		0x678C42958086D621ULL,
		0x887AA85A9BE59160ULL,
		0x6D650F1BAA2AB84EULL,
		0xC4A5037316006C8FULL,
		0x3D07A433424BB044ULL,
		0x841D1714690461B5ULL,
		0x0D2B8D8180A32B2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AB4E4DA5F3B3BF9ULL,
		0x3DF4F9663A03A973ULL,
		0xA91C717B951CE34FULL,
		0xC48DE2CB86104D41ULL,
		0xD403EC7E5C5BEE93ULL,
		0x18B79264F0D3F7C7ULL,
		0xF92C078D2A53631DULL,
		0x44BCEAD590DD37C0ULL
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
		0x857AD784B89D2FFDULL,
		0x0389A8598BF790C0ULL,
		0x7FB2E29C601A605DULL,
		0x72A2D97490B0292FULL,
		0x73D4BF7EDC00C4B4ULL,
		0xDE4390F2426DA68AULL,
		0xE0F9BAB0878D82CEULL,
		0x8792E7A1C30809E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x542A2420518704F7ULL,
		0x45DE548C5D875F5FULL,
		0x6BEBEAC4F8985C21ULL,
		0xAFE7C3FBC79A46BCULL,
		0xF1DA3493955306BDULL,
		0x8443D17F24A6EE98ULL,
		0xA34F921E7D973F6FULL,
		0xE0D14606E52FC1E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3150B36467162B06ULL,
		0xBDAB53CD2E703161ULL,
		0x13C6F7D76782043BULL,
		0xC2BB1578C915E273ULL,
		0x81FA8AEB46ADBDF6ULL,
		0x59FFBF731DC6B7F1ULL,
		0x3DAA289209F6435FULL,
		0xA6C1A19ADDD847F9ULL
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
		0xFF712E90A03645BFULL,
		0x2B9AF00AEB8F9C26ULL,
		0x54E4B2425656974AULL,
		0x75EF32C627226999ULL,
		0xD14FBC18CB09F760ULL,
		0xCACEDFE50E917362ULL,
		0x08A09AC0D6053230ULL,
		0x428F170EDA73452BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B8D47AA21472B9ULL,
		0x888A081243A00A0EULL,
		0x2BFF2A1E8BEBB746ULL,
		0x68FF5CDE84D2DAB1ULL,
		0xAB83B6E420F34ACBULL,
		0x05DDD89802DCDDA2ULL,
		0x986E3AFE13CDE0E0ULL,
		0xD73AD4FC3468646FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B85A15FE21D306ULL,
		0xA310E7F8A7EF9218ULL,
		0x28E58823CA6AE003ULL,
		0x0CEFD5E7A24F8EE8ULL,
		0x25CC0534AA16AC95ULL,
		0xC4F1074D0BB495C0ULL,
		0x70325FC2C2375150ULL,
		0x6B544212A60AE0BBULL
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
		0x3F241CAA56AEBE5DULL,
		0xB63ACD3C13DE5F70ULL,
		0x6A8BB743D891C8AFULL,
		0xBBA6778A8EACBDC0ULL,
		0xE6001EC3854E9808ULL,
		0x0180B3C9AB1A6573ULL,
		0x7026BC8F3C294A71ULL,
		0x537B2A218C2EF811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE20B0F836D0EDFBULL,
		0x9FDB79D792A908B2ULL,
		0x2BD52B1247CA0384ULL,
		0x8D4826B778EA39C2ULL,
		0x1871AAF21944CCFDULL,
		0xBFDD30261B1C364AULL,
		0xC06D6D53D89C6AFEULL,
		0x7C63E4CBDDAA5F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71036BB21FDDD062ULL,
		0x165F5364813556BDULL,
		0x3EB68C3190C7C52BULL,
		0x2E5E50D315C283FEULL,
		0xCD8E73D16C09CB0BULL,
		0x41A383A38FFE2F29ULL,
		0xAFB94F3B638CDF72ULL,
		0xD7174555AE84990FULL
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
		0x503B26554B121C1DULL,
		0x9524CE0F45B9888CULL,
		0x9693A0B4006C0945ULL,
		0x53A9627D083CFECCULL,
		0x1184AE6199D27153ULL,
		0x0936D963DFC731FCULL,
		0x905277854BB71974ULL,
		0x55D6D04E4E71F1B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE092DCFAB380798EULL,
		0xAFBE3CBAF8BE2AF7ULL,
		0x068D521CA534F588ULL,
		0xD6C8EF697D0424A4ULL,
		0xD9FACC4877ABC68FULL,
		0xA401EA6F4401C8D0ULL,
		0xBD84104E84F07C31ULL,
		0x7D45263229E345A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA8495A9791A28FULL,
		0xE56691544CFB5D94ULL,
		0x90064E975B3713BCULL,
		0x7CE073138B38DA28ULL,
		0x3789E2192226AAC3ULL,
		0x6534EEF49BC5692BULL,
		0xD2CE6736C6C69D42ULL,
		0xD891AA1C248EAC0EULL
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
		0x9B5FD539E789C397ULL,
		0x7E11823F3DB10CD3ULL,
		0x459C75BF564C458DULL,
		0x7B6279876135B762ULL,
		0x77C06522B5A7C6EDULL,
		0x9AC703B1D9011736ULL,
		0x58D57CC2EBA9AB35ULL,
		0x1C28C0C53675FC46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3AE4EBFFB47A8CULL,
		0xAA85A74F0C2F68ACULL,
		0xA99F0F7A4FD87853ULL,
		0x042D8CF160C440B7ULL,
		0x8131E2CF7CD0B3D9ULL,
		0xA54181E62F985770ULL,
		0xB630A0910B7EA348ULL,
		0x9621DF3D4D699D64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE124F04DE7D5490BULL,
		0xD38BDAF03181A426ULL,
		0x9BFD66450673CD39ULL,
		0x7734EC96007176AAULL,
		0xF68E825338D71314ULL,
		0xF58581CBA968BFC5ULL,
		0xA2A4DC31E02B07ECULL,
		0x8606E187E90C5EE1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1613D80363197017ULL,
		0x2386B6F69A5FAB3DULL,
		0xDD7BF5734CB5F402ULL,
		0x8EBF501121DA208EULL,
		0x627906439422B7A2ULL,
		0xCBB30FC3DE181D4BULL,
		0x0CEC1B4F5550685EULL,
		0x4B037AB8BFFD5129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385C05222C57F11FULL,
		0xB07843452E224416ULL,
		0x29C2711C43E89A61ULL,
		0x063D37CD31AA3000ULL,
		0x9F326560B0AC131FULL,
		0x537BC5C4C0885A66ULL,
		0x90BBFF49929AEB78ULL,
		0x1736038A32796189ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDB7D2E136C17EF8ULL,
		0x730E73B16C3D6726ULL,
		0xB3B9845708CD59A0ULL,
		0x88821843F02FF08EULL,
		0xC346A0E2E376A483ULL,
		0x783749FF1D8FC2E4ULL,
		0x7C301C05C2B57CE6ULL,
		0x33CD772E8D83EF9FULL
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
		0x2B20289FB91E2209ULL,
		0x94DC6CD8A44504CBULL,
		0x7E8E0803387859C2ULL,
		0x45F32BA8AA3C97E2ULL,
		0x450A08FFF2429495ULL,
		0x053C2C1BF68D5263ULL,
		0x014524E73B8660AFULL,
		0x282AC8B98A7C248DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCE274380080A985ULL,
		0x2C05AEFDA13FB1A3ULL,
		0x3378A5A1BB0CFF0BULL,
		0xB7B587A48F6F9CAFULL,
		0x43C1B599A3B0EB7FULL,
		0x71903D2C31D15263ULL,
		0xB149860A915D9557ULL,
		0x83DEFCB9B036BAAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E3DB467B89D7884ULL,
		0x68D6BDDB03055327ULL,
		0x4B1562617D6B5AB7ULL,
		0x8E3DA4041ACCFB33ULL,
		0x014853664E91A915ULL,
		0x93ABEEEFC4BC0000ULL,
		0x4FFB9EDCAA28CB57ULL,
		0xA44BCBFFDA4569DEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFB6597AC28DDD257ULL,
		0xB9F28DCA4663563AULL,
		0x24CDEFE503DFFA94ULL,
		0x8AEA64E72B17B4DFULL,
		0x6396005D9DE231ACULL,
		0x9568616A849B8529ULL,
		0x909FF03C59AB84ABULL,
		0x45EB38E4AF5A521DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AAEE99BD3211F7CULL,
		0xD1AC16FB4AB51BBEULL,
		0x29BF538FB894374EULL,
		0x46CAFE3B88EB26AFULL,
		0xBBBF89DAE6E73718ULL,
		0x8E04AF35419F9471ULL,
		0xE61AD2E6D974ADC8ULL,
		0xB0F296264C60E490ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60B6AE1055BCB2DBULL,
		0xE84676CEFBAE3A7CULL,
		0xFB0E9C554B4BC345ULL,
		0x441F66ABA22C8E2FULL,
		0xA7D67682B6FAFA94ULL,
		0x0763B23542FBF0B7ULL,
		0xAA851D558036D6E3ULL,
		0x94F8A2BE62F96D8CULL
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
		0xA5D1019CBEEEC8A3ULL,
		0xA2C3DAD264484D60ULL,
		0xBDF873B5053144BFULL,
		0xE561935E813D082AULL,
		0xA57039D1C10F98A5ULL,
		0x2D4F1B312C4AC95FULL,
		0x4C2FB29638BA0E95ULL,
		0x502265AC064D2234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5FB26EF539AE1ADULL,
		0xD99968198F66CAF0ULL,
		0x57C45D1542A11C23ULL,
		0x482EBFE4459C9F8FULL,
		0x16CA4F14FCE84DE4ULL,
		0x837F3BFC09C18E1AULL,
		0x6279BACF63E9923CULL,
		0x5C9A7F78E8EA6249ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFD5DAAD6B53E6F6ULL,
		0xC92A72B8D4E1826FULL,
		0x6634169FC290289BULL,
		0x9D32D37A3BA0689BULL,
		0x8EA5EABCC4274AC1ULL,
		0xA9CFDF3522893B45ULL,
		0xE9B5F7C6D4D07C58ULL,
		0xF387E6331D62BFEAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x299CF2AD7FD20DD1ULL,
		0xB28F3A991C747D60ULL,
		0x5A1B2991DAE0CC04ULL,
		0x35B4F468B0B1A478ULL,
		0xEC5D077667CC2B20ULL,
		0xBCD2F3E60E38FCD7ULL,
		0xE89B64C3707A5C90ULL,
		0xE936869CDC180F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC09886971B8F3E33ULL,
		0xBD0F0DF99DDDDA5BULL,
		0x490113CA52B2714BULL,
		0xFB35B0DAA112F569ULL,
		0x3F43E04773EBB313ULL,
		0x4BD2CDF3FEEEC1B9ULL,
		0xE5CD29033031732DULL,
		0x1AFDEA726C655C86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69046C166442CF9EULL,
		0xF5802C9F7E96A304ULL,
		0x111A15C7882E5AB8ULL,
		0x3A7F438E0F9EAF0FULL,
		0xAD19272EF3E0780CULL,
		0x710025F20F4A3B1EULL,
		0x02CE3BC04048E963ULL,
		0xCE389C2A6FB2B2B0ULL
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
		0xA14194D4E699A9AEULL,
		0x379D30E7B0426260ULL,
		0x28B2AA9F2E21BA4AULL,
		0x7E2D756F8506B9DBULL,
		0xE393FCFDB2E069FCULL,
		0x7C4701CB5995DA0EULL,
		0xD77EBE136BC1D098ULL,
		0x98F339F10C9520D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3640F4042B14D7D4ULL,
		0x35952380C9D9F2F0ULL,
		0xD23426D0631B5B7AULL,
		0x0B867F7A8FC7CA28ULL,
		0xA5DA3A69D8BE51BDULL,
		0x5063B0DFEA2308D0ULL,
		0xE2057820E5575749ULL,
		0x90A4C3EA0AF7641AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B00A0D0BB84D1DAULL,
		0x02080D66E6686F70ULL,
		0x567E83CECB065ED0ULL,
		0x72A6F5F4F53EEFB2ULL,
		0x3DB9C293DA22183FULL,
		0x2BE350EB6F72D13EULL,
		0xF57945F2866A794FULL,
		0x084E7607019DBCBBULL
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
		0xE75B668BD339EF64ULL,
		0xE7837852B2F29FACULL,
		0xAC98868687918CFDULL,
		0x9C8E25DE26D55A75ULL,
		0x63F0C3F6BEF80477ULL,
		0x94AC23E5D966EE4BULL,
		0x64FA607727DA9EF2ULL,
		0xB33997D91BD26D34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F7397FEC1E525A6ULL,
		0xB16CCDEBBC341F16ULL,
		0x7410E67F538BE254ULL,
		0x0E096F52EF81CB12ULL,
		0x170FD259205A6579ULL,
		0xCF5DBA8BF8B023D6ULL,
		0x8B836D90383608C3ULL,
		0x73EB37ADC54E3E95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7E7CE8D1154C9BEULL,
		0x3616AA66F6BE8096ULL,
		0x3887A0073405AAA9ULL,
		0x8E84B68B37538F63ULL,
		0x4CE0F19D9E9D9EFEULL,
		0xC54E6959E0B6CA75ULL,
		0xD976F2E6EFA4962EULL,
		0x3F4E602B56842E9EULL
	}};
	sign = 0;
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
		0xCEFF548035936B96ULL,
		0x4332614F45F23E03ULL,
		0xE6557357660036D2ULL,
		0x85FF155B71E74444ULL,
		0x6BCC138BABE9E219ULL,
		0xAC4128E942821DA2ULL,
		0x620ED8BA5001A8BEULL,
		0x9B90A7B8FC06566DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AEF5A4EE151920AULL,
		0xF38F14B9834CDDE9ULL,
		0x953C6B3EC64658C2ULL,
		0xF21B635F9FDA426AULL,
		0xA904FA7EA342E3C5ULL,
		0x924C28B88A86AC05ULL,
		0xC6CF8B2013EC732FULL,
		0xFFA8CABAEEC9A85AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC40FFA315441D98CULL,
		0x4FA34C95C2A5601AULL,
		0x511908189FB9DE0FULL,
		0x93E3B1FBD20D01DAULL,
		0xC2C7190D08A6FE53ULL,
		0x19F50030B7FB719CULL,
		0x9B3F4D9A3C15358FULL,
		0x9BE7DCFE0D3CAE12ULL
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
		0x16E61BC8823DF586ULL,
		0x1405ECEBE5114728ULL,
		0x5022EECC604D5811ULL,
		0x16B8110387F0C0E6ULL,
		0x4D4BB973BE690EA2ULL,
		0xA1D7950025FE5544ULL,
		0xEA5E0494F1C26A68ULL,
		0xCA7B37D5A3253784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B61DFC867B7B6EFULL,
		0x82CDB0176FF47547ULL,
		0xE191E98452648528ULL,
		0x2C61862057496BC3ULL,
		0x05D3D2FD68E4FA23ULL,
		0x7923C5ED9BD91C46ULL,
		0xB6680DD2B549C281ULL,
		0x9FCAD7E16C0DEC65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B843C001A863E97ULL,
		0x91383CD4751CD1E0ULL,
		0x6E9105480DE8D2E8ULL,
		0xEA568AE330A75522ULL,
		0x4777E6765584147EULL,
		0x28B3CF128A2538FEULL,
		0x33F5F6C23C78A7E7ULL,
		0x2AB05FF437174B1FULL
	}};
	sign = 0;
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
		0x4BEE7E2A8D59BD2AULL,
		0xF5CD44F3E87DD6F2ULL,
		0xD1F163BF75210F2CULL,
		0xB826891201A60C2EULL,
		0x7FE324C8877B063AULL,
		0xE78E3A3C0F79CF23ULL,
		0xCEF6594E984AA5F1ULL,
		0xE2316B19E561F727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6FDC07B94B785ADULL,
		0x45940B36009B0F78ULL,
		0xEDAC8EE4B2900A9FULL,
		0x394EE0FC6DC73956ULL,
		0x93935093E4CC3B58ULL,
		0xFDA6BBABE0773A90ULL,
		0x12A1490560C19014ULL,
		0xBE4B4AA1A556B0D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84F0BDAEF8A2377DULL,
		0xB03939BDE7E2C779ULL,
		0xE444D4DAC291048DULL,
		0x7ED7A81593DED2D7ULL,
		0xEC4FD434A2AECAE2ULL,
		0xE9E77E902F029492ULL,
		0xBC551049378915DCULL,
		0x23E62078400B4651ULL
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
		0x6D7DAB40CF562748ULL,
		0x8908BD7D5A5BD83FULL,
		0xD720951B94FA95B7ULL,
		0xE9909E3A1270B5ABULL,
		0x30B11BBEE7A73276ULL,
		0x3D3A72EFD3D7D29AULL,
		0x828F0AB4369EF6BBULL,
		0x90B7597E303B2276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBFA40CCCD0ED30AULL,
		0x005C9D2068CAE5D3ULL,
		0xD7E2551C925DC060ULL,
		0x4ACE1E54876E98BAULL,
		0xEDC2623A0F1CE4E7ULL,
		0x2E533622241B4844ULL,
		0x2D845AF34296B6F7ULL,
		0xF679C295A3CFBB29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1836A740247543EULL,
		0x88AC205CF190F26BULL,
		0xFF3E3FFF029CD557ULL,
		0x9EC27FE58B021CF0ULL,
		0x42EEB984D88A4D8FULL,
		0x0EE73CCDAFBC8A55ULL,
		0x550AAFC0F4083FC4ULL,
		0x9A3D96E88C6B674DULL
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
		0x4F215AED35D33BF7ULL,
		0x56587EFB5AB46781ULL,
		0xD3FB0C40E9097995ULL,
		0x76DF4CC8E717800AULL,
		0x50C679226EC490F6ULL,
		0x13669875EE40DEFEULL,
		0x6507BC3925938C31ULL,
		0x672A6B1A53556327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A0A9C46A26CA33ULL,
		0x8CE0D12ADA4A4920ULL,
		0xDDE91E74B59B2B53ULL,
		0x98DA662804C224CFULL,
		0x011A2ECC225F2462ULL,
		0x237BD373C1EE438BULL,
		0x9462172B595C44E2ULL,
		0x89EF29713507D9EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9680B128CBAC71C4ULL,
		0xC977ADD0806A1E60ULL,
		0xF611EDCC336E4E41ULL,
		0xDE04E6A0E2555B3AULL,
		0x4FAC4A564C656C93ULL,
		0xEFEAC5022C529B73ULL,
		0xD0A5A50DCC37474EULL,
		0xDD3B41A91E4D893BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x77B7F293E803F409ULL,
		0x897D98FD08526717ULL,
		0xE39D3D7C75B96DE1ULL,
		0x920539464651C769ULL,
		0xF4CD040E6135F854ULL,
		0xC98576772719B61EULL,
		0xA779AFAA1EA373D7ULL,
		0xE306269DA7B64F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x629480C203675201ULL,
		0xAB6133F457AD0B31ULL,
		0xF55A73D266E417ACULL,
		0x1956BF163B490494ULL,
		0x2BF72DBE63170F13ULL,
		0x12693ECD8BE74330ULL,
		0x36B4A4FEC0CFD0BCULL,
		0x034A0D737A68E4F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x152371D1E49CA208ULL,
		0xDE1C6508B0A55BE6ULL,
		0xEE42C9AA0ED55634ULL,
		0x78AE7A300B08C2D4ULL,
		0xC8D5D64FFE1EE941ULL,
		0xB71C37A99B3272EEULL,
		0x70C50AAB5DD3A31BULL,
		0xDFBC192A2D4D6A9FULL
	}};
	sign = 0;
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
		0x8E7CDDB732D253D4ULL,
		0x411BD1CF44EE05C9ULL,
		0x7920DCF8B5B65257ULL,
		0x40E30DC80F208BE1ULL,
		0x318E180BED5CFB69ULL,
		0x139831AB4CD9563DULL,
		0x2D6FAEA7B39E8DC2ULL,
		0x471C55029CF35C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CC5F8E3FA54108EULL,
		0x2700ECE1B4951BBFULL,
		0x94DEF463205C5A2CULL,
		0xDD808F0CD543EEEDULL,
		0x64C62B66AA8D34BCULL,
		0xA01894AA133BA425ULL,
		0x7908303DFD50E1BEULL,
		0x457ED2F11535460EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81B6E4D3387E4346ULL,
		0x1A1AE4ED9058EA0AULL,
		0xE441E8959559F82BULL,
		0x63627EBB39DC9CF3ULL,
		0xCCC7ECA542CFC6ACULL,
		0x737F9D01399DB217ULL,
		0xB4677E69B64DAC03ULL,
		0x019D821187BE165DULL
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
		0xDABD42694A42713EULL,
		0xEAF2168BC2EDBE9EULL,
		0x36E18FECD1610745ULL,
		0x51436E4550572A7EULL,
		0xD01F89D1C44BF67DULL,
		0x3D4C874AC50D5917ULL,
		0x198E1B291C0964FAULL,
		0xCAACAF310E8102B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x274094E2737F930BULL,
		0x479AB355BA8DA22BULL,
		0x2E4E90E83817A101ULL,
		0xBCD487F55BC4FC0CULL,
		0xE5D0A3A0BE01A5BDULL,
		0x3622AB02D54534F0ULL,
		0xFADF314B1E213770ULL,
		0xD0453B4773BB97EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB37CAD86D6C2DE33ULL,
		0xA357633608601C73ULL,
		0x0892FF0499496644ULL,
		0x946EE64FF4922E72ULL,
		0xEA4EE631064A50BFULL,
		0x0729DC47EFC82426ULL,
		0x1EAEE9DDFDE82D8AULL,
		0xFA6773E99AC56AC6ULL
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
		0x2F42E4EE471AFB40ULL,
		0xDEA7272A1D24596DULL,
		0x75000C0154712BBBULL,
		0x77D3410B4B0C0FA8ULL,
		0xB83FF08D2164EFAFULL,
		0x4C62A2A55170C106ULL,
		0x5CEA9E57D96F505CULL,
		0x893F2E0E1EE10954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC56BEC35507026F0ULL,
		0x3CC621D5593D5772ULL,
		0xD4768A86A56FC736ULL,
		0xAD37E5E4539D5EDDULL,
		0xECFF1984A85BDA5AULL,
		0x76C232322DF1A56FULL,
		0xB28237425999B19BULL,
		0x49CB08F668CD0B00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D6F8B8F6AAD450ULL,
		0xA1E10554C3E701FAULL,
		0xA089817AAF016485ULL,
		0xCA9B5B26F76EB0CAULL,
		0xCB40D70879091554ULL,
		0xD5A07073237F1B96ULL,
		0xAA6867157FD59EC0ULL,
		0x3F742517B613FE53ULL
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
		0x10AEC7BE0B2EE200ULL,
		0xAD3912ECAA9616E7ULL,
		0x9587F50EA52E18E3ULL,
		0x83325B5A669D0E5EULL,
		0x1C78D5DA7D0C52CBULL,
		0x83F9D1D3059B134AULL,
		0x0CD5537BF97F125DULL,
		0x45C2BAE8B2EF137DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7DB563C6ABFF61ULL,
		0x883AA8420977D858ULL,
		0x08BF7A84BCAD8516ULL,
		0xBD5EF448608D5601ULL,
		0xA562B4AC446B12BDULL,
		0xFF03369F408EEF18ULL,
		0xAF09D50B08C6D2CCULL,
		0x3AC0C773D0F43240ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB431125A4482E29FULL,
		0x24FE6AAAA11E3E8EULL,
		0x8CC87A89E88093CDULL,
		0xC5D36712060FB85DULL,
		0x7716212E38A1400DULL,
		0x84F69B33C50C2431ULL,
		0x5DCB7E70F0B83F90ULL,
		0x0B01F374E1FAE13CULL
	}};
	sign = 0;
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
		0x1A9BD860DD9D6772ULL,
		0xCAE9E7D58CBB1404ULL,
		0x059AA033E561953DULL,
		0xB1CC05E559120780ULL,
		0x07D7A9C427DC939AULL,
		0xBA40CA6A9C5858E0ULL,
		0x6DC0F1EABD9DC651ULL,
		0x372630B0B2D5F83DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BD9066D7D96745ULL,
		0x7077AD7BD4C9B90BULL,
		0x5611518D1217EC3FULL,
		0x3E7DA93BE3F51B41ULL,
		0xF81C25206D95FBC8ULL,
		0xA7F6DA188531DCF5ULL,
		0x8843BA87AFC0CA7BULL,
		0xE20FEDE6205C3BFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0DE47FA05C4002DULL,
		0x5A723A59B7F15AF8ULL,
		0xAF894EA6D349A8FEULL,
		0x734E5CA9751CEC3EULL,
		0x0FBB84A3BA4697D2ULL,
		0x1249F05217267BEAULL,
		0xE57D37630DDCFBD6ULL,
		0x551642CA9279BC40ULL
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
		0x3FBB77112097CB11ULL,
		0x93CDB81B30AC5883ULL,
		0x6E8AFB756812B73EULL,
		0x2977DD78A3623A18ULL,
		0xEC111A23B2F9649BULL,
		0xB0283DC221211409ULL,
		0x7F80FC2F635F0393ULL,
		0x477054F3A7098456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8E895D7DA691395ULL,
		0xFDC2170CD4FB10BAULL,
		0xC1A3F18DA4D57DFCULL,
		0xC7C3A307929C90DAULL,
		0x8807CAC58DF8D7D0ULL,
		0x28C6BBEB96AE627CULL,
		0x941F2F93FD07B970ULL,
		0xA711F4C84236F907ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86D2E139462EB77CULL,
		0x960BA10E5BB147C8ULL,
		0xACE709E7C33D3941ULL,
		0x61B43A7110C5A93DULL,
		0x64094F5E25008CCAULL,
		0x876181D68A72B18DULL,
		0xEB61CC9B66574A23ULL,
		0xA05E602B64D28B4EULL
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
		0xA17CD5AF14DC6B76ULL,
		0xB2D49E2E67F6AD80ULL,
		0x14C4B8B83572C0A5ULL,
		0x0DDA3CCF343D0DD0ULL,
		0xD2FAE988E75DDDCDULL,
		0x37D82DADB36D1D8EULL,
		0x57CA60B509EA1889ULL,
		0x1086053F731D7D82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DC2117353CF171ULL,
		0xA1CB35B4BE324B1BULL,
		0x3F69EC354D804351ULL,
		0x47B2AB65BA4C36A9ULL,
		0xB8F9F5174E41C73AULL,
		0xA3E5412A10544A01ULL,
		0xF8E10053F1860A18ULL,
		0x5D1E0A4DDDE1705AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFA0B497DF9F7A05ULL,
		0x11096879A9C46264ULL,
		0xD55ACC82E7F27D54ULL,
		0xC627916979F0D726ULL,
		0x1A00F471991C1692ULL,
		0x93F2EC83A318D38DULL,
		0x5EE9606118640E70ULL,
		0xB367FAF1953C0D27ULL
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
		0x4B96AAC226121D44ULL,
		0x93603A3501A79BECULL,
		0xA466EE17BE06B51FULL,
		0x7B70E635034D4AFBULL,
		0x02E879F84F8F0C4CULL,
		0x88DEF066B43D49BBULL,
		0x0635428442389095ULL,
		0xDA45555AEF45E936ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD73079B8C03D6451ULL,
		0xDD4D47A6F00105F2ULL,
		0x06B010C07AA553E2ULL,
		0x3E51FDA4BED9B7B4ULL,
		0xCC2F2F563C6B4A99ULL,
		0x5802FBF1458E3FECULL,
		0xBDDE5D5C2D1186C8ULL,
		0xB884381032D9DD83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7466310965D4B8F3ULL,
		0xB612F28E11A695F9ULL,
		0x9DB6DD574361613CULL,
		0x3D1EE89044739347ULL,
		0x36B94AA21323C1B3ULL,
		0x30DBF4756EAF09CEULL,
		0x4856E528152709CDULL,
		0x21C11D4ABC6C0BB2ULL
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
		0x3A39F83BC17EA8E9ULL,
		0x0153AE579DFE9E66ULL,
		0xB1F520E20BE98A0AULL,
		0x66E50FAD3012C557ULL,
		0xF76F5C32243121ACULL,
		0x0B5A88704C8B2993ULL,
		0xCCDE18F2DC9D4BDDULL,
		0x425D875F7158EBE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF58FD92EA9C5B5EULL,
		0x8EE5BCD5BA888F63ULL,
		0xDC77B551606343C1ULL,
		0xBA5BBFF84B6AA607ULL,
		0x6CE7D74A4C3BA829ULL,
		0x4A544188CEE36029ULL,
		0xB212410045E49029ULL,
		0x4E86DB83C6B7B321ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AE0FAA8D6E24D8BULL,
		0x726DF181E3760F02ULL,
		0xD57D6B90AB864648ULL,
		0xAC894FB4E4A81F4FULL,
		0x8A8784E7D7F57982ULL,
		0xC10646E77DA7C96AULL,
		0x1ACBD7F296B8BBB3ULL,
		0xF3D6ABDBAAA138C7ULL
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
		0xF4B75664FFA9CEC7ULL,
		0x360293735F38F899ULL,
		0x636B14BD953F1E81ULL,
		0xA1A099DF475836D1ULL,
		0xAA26F069F9F544AFULL,
		0xADD9C40AE4C60E94ULL,
		0x8C48ED8C4417377EULL,
		0xD033B0CE8CF5CB0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A0EEB9FB6AFDDFBULL,
		0xBE9CE37222313035ULL,
		0x9DB8CB2143E5F333ULL,
		0x913327D2D315CEA2ULL,
		0x0E1919DAFB785D0AULL,
		0x63E2E429DAC7BDE0ULL,
		0xFD299C03F2658BACULL,
		0x3F2B771BC8E59920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDAA86AC548F9F0CCULL,
		0x7765B0013D07C864ULL,
		0xC5B2499C51592B4DULL,
		0x106D720C7442682EULL,
		0x9C0DD68EFE7CE7A5ULL,
		0x49F6DFE109FE50B4ULL,
		0x8F1F518851B1ABD2ULL,
		0x910839B2C41031ECULL
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
		0xFE43E73E80442332ULL,
		0xC48B82257940962BULL,
		0x154A46649FF02C52ULL,
		0x0C3F3E48C272D340ULL,
		0xF817F749B5962490ULL,
		0xBD34436F0EC0483EULL,
		0x42BFC733FD7808F2ULL,
		0x520718D143FC1534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8145CAA01D591BFDULL,
		0x0F4B480E98410A15ULL,
		0x2097D6435EA74F9EULL,
		0xF2B04E716CC38CBEULL,
		0x51B751A3161C0E15ULL,
		0x6FB7198D006E54A4ULL,
		0xDD1B0D2CA403D78FULL,
		0x17BF7D7A65818F5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CFE1C9E62EB0735ULL,
		0xB5403A16E0FF8C16ULL,
		0xF4B270214148DCB4ULL,
		0x198EEFD755AF4681ULL,
		0xA660A5A69F7A167AULL,
		0x4D7D29E20E51F39AULL,
		0x65A4BA0759743163ULL,
		0x3A479B56DE7A85D5ULL
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
		0xB1219DA35741BC01ULL,
		0x96351EAB0024A15EULL,
		0x28913AD8B1FCC7B5ULL,
		0x7C163CD4310C3BE7ULL,
		0xAE9F45E265EC0A25ULL,
		0xC2CE7D0E0D59F1CAULL,
		0x6688551292AACDEAULL,
		0x4FF132CE202D0BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36AC76AC8ECF2AAULL,
		0xC80E1D98FE7D092FULL,
		0x079CE513E128FEDAULL,
		0x19E9482B4B4A2FC6ULL,
		0x105DF95E4AEB45B6ULL,
		0xD6472808B337E4CDULL,
		0xB21F1C07C6A7CB21ULL,
		0xCA6CD9D845243C0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DB6D6388E54C957ULL,
		0xCE27011201A7982FULL,
		0x20F455C4D0D3C8DAULL,
		0x622CF4A8E5C20C21ULL,
		0x9E414C841B00C46FULL,
		0xEC8755055A220CFDULL,
		0xB469390ACC0302C8ULL,
		0x858458F5DB08CFCCULL
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
		0x92F9D69614FB512AULL,
		0x0C20D9AB50799A00ULL,
		0x00D9F432A023B9D0ULL,
		0x973E0AF5C16703F5ULL,
		0x93F7BB110FB28F74ULL,
		0x0FC5F9DA3B10CF0BULL,
		0x853452D61A238FBFULL,
		0xAC81B531192234A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C437A45D83DDA67ULL,
		0xB797BA26AACA768DULL,
		0x78B9E24A53BE91D2ULL,
		0x1983170DED200F0AULL,
		0x3AD1D2405229F86AULL,
		0x142B2E6F69736F05ULL,
		0x147AD260E06F4972ULL,
		0x0F0F8F941A250F18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16B65C503CBD76C3ULL,
		0x54891F84A5AF2373ULL,
		0x882011E84C6527FDULL,
		0x7DBAF3E7D446F4EAULL,
		0x5925E8D0BD88970AULL,
		0xFB9ACB6AD19D6006ULL,
		0x70B9807539B4464CULL,
		0x9D72259CFEFD2589ULL
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
		0xEAE73AB7BDD9323AULL,
		0x8B4B4F01C4A3F0FCULL,
		0x28EDAFF6ED1AC7CBULL,
		0x3B0B5905B4FE1DCCULL,
		0xB21B5E240310E749ULL,
		0x992825FE175BABC1ULL,
		0x85AEB314943AD6C9ULL,
		0xED507B1741650520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA4C99A1A70AD84ULL,
		0xDFED5DA51BE77FE6ULL,
		0x7BD92E76A40374C8ULL,
		0xC5269DC986227A15ULL,
		0x8458AA64F5898631ULL,
		0x7C163870822192F4ULL,
		0xA75BDF3D65C55B4DULL,
		0x5341E206C5084D3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B42711DA36884B6ULL,
		0xAB5DF15CA8BC7116ULL,
		0xAD14818049175302ULL,
		0x75E4BB3C2EDBA3B6ULL,
		0x2DC2B3BF0D876117ULL,
		0x1D11ED8D953A18CDULL,
		0xDE52D3D72E757B7CULL,
		0x9A0E99107C5CB7E0ULL
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
		0xB531587361219719ULL,
		0xD968B7BADB807E0EULL,
		0x73EFD0B0DB06959EULL,
		0xF69F72BABE4C1F9BULL,
		0x5495315F9816719DULL,
		0xB5547C109D9B2413ULL,
		0x6841CF502F49AB19ULL,
		0xCD91ECF2C13ECCB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7349BD4A6D47BE69ULL,
		0x0DDC22E1F70DD27DULL,
		0xE21AE030BCAA2F3CULL,
		0x20024C9E453862ADULL,
		0x57775A4B033839BBULL,
		0xBF819026229A8C25ULL,
		0xFF0FEFAA9B45D004ULL,
		0x4CBFDCEBC6EF2E2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41E79B28F3D9D8B0ULL,
		0xCB8C94D8E472AB91ULL,
		0x91D4F0801E5C6662ULL,
		0xD69D261C7913BCEDULL,
		0xFD1DD71494DE37E2ULL,
		0xF5D2EBEA7B0097EDULL,
		0x6931DFA59403DB14ULL,
		0x80D21006FA4F9E86ULL
	}};
	sign = 0;
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
		0xE6DA26179CCD24D9ULL,
		0xF5D77412FAFBC9DDULL,
		0x43C3E7E89C6E9417ULL,
		0x8F780AEAA3450C4EULL,
		0x0E57AED7BE1B5FD4ULL,
		0x8BC3A979C5785691ULL,
		0x4DF48BFF85CC95F7ULL,
		0xC6169F414E53C5FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14751D953D9F068AULL,
		0x5805E7CABE06B1C0ULL,
		0x36809B82F347D8FDULL,
		0x436FA1F0069D7CCFULL,
		0x96C96A519C0874D6ULL,
		0x524963CD7179D91FULL,
		0x0EA35F8F1F62E212ULL,
		0x6CB8BF775F71A84BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD26508825F2E1E4FULL,
		0x9DD18C483CF5181DULL,
		0x0D434C65A926BB1AULL,
		0x4C0868FA9CA78F7FULL,
		0x778E44862212EAFEULL,
		0x397A45AC53FE7D71ULL,
		0x3F512C706669B3E5ULL,
		0x595DDFC9EEE21DB0ULL
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
		0x94A2A0C2A065CC7FULL,
		0x152A1EF3641AE8CDULL,
		0x76024A04FE204FC6ULL,
		0xBB092CF9F376DCB9ULL,
		0x8955501DC6F06F69ULL,
		0x5ABEA16F38341812ULL,
		0x50A72F8DBBD2CECBULL,
		0xD986CA5D1C303629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x354A0A7664832A71ULL,
		0xCBCD4FEEB4C88BAFULL,
		0x117C09BDA3D28141ULL,
		0x394EF8DFC939B934ULL,
		0xBC171F958B03F48FULL,
		0xA117A6565E83B7E7ULL,
		0x3AC3DB9487818B77ULL,
		0xF8DD1C2F5B772065ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F58964C3BE2A20EULL,
		0x495CCF04AF525D1EULL,
		0x648640475A4DCE84ULL,
		0x81BA341A2A3D2385ULL,
		0xCD3E30883BEC7ADAULL,
		0xB9A6FB18D9B0602AULL,
		0x15E353F934514353ULL,
		0xE0A9AE2DC0B915C4ULL
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
		0xCB1ABE6F2B029210ULL,
		0xE0A001F9F1EDB2B8ULL,
		0xB6D254760713D018ULL,
		0xA546196FA90786F5ULL,
		0x6EA708548D711C4FULL,
		0x53395A928E7638C8ULL,
		0x35F3FB9F352E5D07ULL,
		0x17E67C9D50F53213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12BF70F216241FC7ULL,
		0xC5A0D9E8E7BFAC00ULL,
		0xE6964DCEDAD0B8D3ULL,
		0xEB2983D798E1B89BULL,
		0x46057871D8A56F4FULL,
		0x54FF7C0E040FC1C1ULL,
		0x1EA8946C0390CB96ULL,
		0x2943654BE019E247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB85B4D7D14DE7249ULL,
		0x1AFF28110A2E06B8ULL,
		0xD03C06A72C431745ULL,
		0xBA1C95981025CE59ULL,
		0x28A18FE2B4CBACFFULL,
		0xFE39DE848A667707ULL,
		0x174B6733319D9170ULL,
		0xEEA3175170DB4FCCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4BDD02D940CDC5E6ULL,
		0x758ECFA1A32CF89EULL,
		0x593F2D6E659E7D8BULL,
		0xA67C496F6112D3A4ULL,
		0xE05F4A4B72E61B80ULL,
		0x62E0FAB59F30A08BULL,
		0xED8DDE637A724500ULL,
		0xB201028475FB95C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CCC42AED233074AULL,
		0x3F4176C6BF8A2E48ULL,
		0xBCD73AF2A2C0010DULL,
		0x3101CBD585F8048FULL,
		0x6AD88C4E3A7ACEFDULL,
		0xE8E83F802A76E347ULL,
		0xF471DB226353EEEEULL,
		0xDBB8510A50D4C6CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF10C02A6E9ABE9CULL,
		0x364D58DAE3A2CA55ULL,
		0x9C67F27BC2DE7C7EULL,
		0x757A7D99DB1ACF14ULL,
		0x7586BDFD386B4C83ULL,
		0x79F8BB3574B9BD44ULL,
		0xF91C0341171E5611ULL,
		0xD648B17A2526CEFAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x75848BCF8B2E67B8ULL,
		0x4B09B1D5EFD71520ULL,
		0x52960E18C1681179ULL,
		0x12C2BE4A4CE630B2ULL,
		0x4ABB14EFA0F23F59ULL,
		0xCF939BB237CA5F6AULL,
		0x841685FE2AD3B531ULL,
		0xAED8D531EFCA8F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A908BA8D3027C3ULL,
		0x47A75BD52F9C3572ULL,
		0x2F603BB3BA40D3D4ULL,
		0x19FA3B9542CFA0C1ULL,
		0x2C04FD062AF6E4EDULL,
		0x18C806490BC9AD30ULL,
		0x8694BD54CAFB41B4ULL,
		0x388C99CEBC943762ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42DB8314FDFE3FF5ULL,
		0x03625600C03ADFAEULL,
		0x2335D26507273DA5ULL,
		0xF8C882B50A168FF1ULL,
		0x1EB617E975FB5A6BULL,
		0xB6CB95692C00B23AULL,
		0xFD81C8A95FD8737DULL,
		0x764C3B63333657E6ULL
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
		0x228C6BB69CC1AC6EULL,
		0xE9B322FD9C3064C2ULL,
		0xDC9D566D75AAF587ULL,
		0x7F034982DB3FCB63ULL,
		0xA8ABD26C0F5B8AF0ULL,
		0x5B6573E871143CD4ULL,
		0xDA169CBAC8C06A6DULL,
		0x0AFAA92ECB5E3934ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EBF2DCDD70EF916ULL,
		0x8BDD75213F69A10BULL,
		0xD8813D83A066F709ULL,
		0x2BC7CD4E00542748ULL,
		0x8A2C0D75E501A2ABULL,
		0x263EAA693029158FULL,
		0x19E384875FCA17ECULL,
		0x8A7A07016E1E16BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13CD3DE8C5B2B358ULL,
		0x5DD5ADDC5CC6C3B7ULL,
		0x041C18E9D543FE7EULL,
		0x533B7C34DAEBA41BULL,
		0x1E7FC4F62A59E845ULL,
		0x3526C97F40EB2745ULL,
		0xC033183368F65281ULL,
		0x8080A22D5D402275ULL
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
		0xCF54A9ECC39DC415ULL,
		0x2F1EC75D6A48B1DDULL,
		0xE775190D61778956ULL,
		0xC4397A0F798F2EAAULL,
		0x09512F8536876CC9ULL,
		0xBAA50804CEC9DA23ULL,
		0x7D7B4CE2B8DA25FBULL,
		0x870FD5CBE731BAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212007EA531FFB98ULL,
		0x4A14212EF1226B5FULL,
		0xBDD9B6BDDD4E3B62ULL,
		0x9D5D293A2CCA991BULL,
		0x3E6B971DFACF29C4ULL,
		0xE44692A79321A081ULL,
		0x1946E9EDBB2689E0ULL,
		0x3644DB32B58424C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE34A202707DC87DULL,
		0xE50AA62E7926467EULL,
		0x299B624F84294DF3ULL,
		0x26DC50D54CC4958FULL,
		0xCAE598673BB84305ULL,
		0xD65E755D3BA839A1ULL,
		0x643462F4FDB39C1AULL,
		0x50CAFA9931AD95DBULL
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
		0xA2E32FBBC9C6A026ULL,
		0xF14E24866AF02E43ULL,
		0xBAF4A50AE1273CE5ULL,
		0x736593BA1A4975A8ULL,
		0x945C270845C7AEBDULL,
		0xE5DAC79AA77CA2E3ULL,
		0xC44AB2842EECD388ULL,
		0xC68BE5835002E682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634D1554603EA407ULL,
		0x2F27A7B9ABF8706BULL,
		0xB56464A4FCC02306ULL,
		0x2EE3A950F47B949EULL,
		0x47D9EC88E4B5F76DULL,
		0xFA7DFBCA69B23A91ULL,
		0xF26AC2F1A4650A14ULL,
		0x4C7AD43864A18AF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F961A676987FC1FULL,
		0xC2267CCCBEF7BDD8ULL,
		0x05904065E46719DFULL,
		0x4481EA6925CDE10AULL,
		0x4C823A7F6111B750ULL,
		0xEB5CCBD03DCA6852ULL,
		0xD1DFEF928A87C973ULL,
		0x7A11114AEB615B8FULL
	}};
	sign = 0;
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
		0xA7FE8F630C2F465BULL,
		0x710C007BD8991310ULL,
		0x7E9994B5A190CC52ULL,
		0x026B6D8ED2FDF200ULL,
		0xEEDFC88E35B3BC5BULL,
		0x6699E7046A57E9C1ULL,
		0x08532A75205C4032ULL,
		0xB88E961FBA84AD40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A5FF591429E04DULL,
		0xBB97278F179B6AADULL,
		0x1C670D2FEDA5CCEEULL,
		0x11980CECC5C3E86FULL,
		0x4CED0F73F0BE1CDCULL,
		0xD12D8E567122A439ULL,
		0x15E96F796E2EAF9FULL,
		0x868EFBE41D1AEBA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32589009F805660EULL,
		0xB574D8ECC0FDA863ULL,
		0x62328785B3EAFF63ULL,
		0xF0D360A20D3A0991ULL,
		0xA1F2B91A44F59F7EULL,
		0x956C58ADF9354588ULL,
		0xF269BAFBB22D9092ULL,
		0x31FF9A3B9D69C196ULL
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
		0x1DBA0EC36B2722A9ULL,
		0x2BCF4AFE4F906586ULL,
		0xEC2A49174B8DC947ULL,
		0xBFC0073A7287DF22ULL,
		0xFB16F5A46C8F06B2ULL,
		0x9956FC0ABDB3EAA9ULL,
		0x42AF9F822B41D0A6ULL,
		0x50D0E8E2A7002127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3014FD3610468604ULL,
		0xB054F90FAB8D70BAULL,
		0xFCBE93A0E12F29BDULL,
		0x3838D87230B2667EULL,
		0x076B211980507865ULL,
		0x518991A630921894ULL,
		0xAA9C59AF189C4FF0ULL,
		0xD1F50C48D0061667ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDA5118D5AE09CA5ULL,
		0x7B7A51EEA402F4CBULL,
		0xEF6BB5766A5E9F89ULL,
		0x87872EC841D578A3ULL,
		0xF3ABD48AEC3E8E4DULL,
		0x47CD6A648D21D215ULL,
		0x981345D312A580B6ULL,
		0x7EDBDC99D6FA0ABFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x64D530B6E4D7AE45ULL,
		0x7600A738032D66EEULL,
		0x94C047520195A9F9ULL,
		0x78232933663DCABFULL,
		0x43B0AD2759BFE82CULL,
		0xB74610F916CB492FULL,
		0xD7E1A6FAFAE7ECAFULL,
		0x08898B9739C496B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B5FAEBF3A20E59ULL,
		0xF41C347D99B880AEULL,
		0x7DF18B79EDA47470ULL,
		0x67851398110A2EC8ULL,
		0xAB5BE2CDF05D0ACBULL,
		0xF369ED00BFB9CC96ULL,
		0xDE66CAE821F4D5E6ULL,
		0x9A2576658666612CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x101F35CAF1359FECULL,
		0x81E472BA6974E640ULL,
		0x16CEBBD813F13588ULL,
		0x109E159B55339BF7ULL,
		0x9854CA596962DD61ULL,
		0xC3DC23F857117C98ULL,
		0xF97ADC12D8F316C8ULL,
		0x6E641531B35E3586ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4138F53B729DAC29ULL,
		0x057D953D9C396AC0ULL,
		0x63BF36A7A5F6C2ADULL,
		0xF308DF34CCCD1869ULL,
		0x02D30135965F6FB7ULL,
		0x2432EC5CF5466782ULL,
		0x45F57DBD580E62FEULL,
		0x59F546D13E493C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230DE5B36D26CA61ULL,
		0x03E46CB96F43F361ULL,
		0xEF20A8497EFCECE1ULL,
		0x54F3FB26AE050589ULL,
		0xED63C139CB466E9BULL,
		0x300153D4D631550FULL,
		0x9BA5ACD12189EAE8ULL,
		0xF0B0F0897B052AD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E2B0F880576E1C8ULL,
		0x019928842CF5775FULL,
		0x749E8E5E26F9D5CCULL,
		0x9E14E40E1EC812DFULL,
		0x156F3FFBCB19011CULL,
		0xF43198881F151272ULL,
		0xAA4FD0EC36847815ULL,
		0x69445647C34411B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB7E2D5C68E8C5121ULL,
		0xDCD96A0D3D80E8FEULL,
		0x16368AC24CD52196ULL,
		0xE7F8E65BC630094CULL,
		0x9C841943311DD663ULL,
		0x29C024908C038AB3ULL,
		0x0C5DA65C7C84F6B2ULL,
		0x123FE8403EA49889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC088D6440F1F5FE2ULL,
		0xE37BD93AE936B355ULL,
		0x988E989B5522B8A5ULL,
		0xAD444811D73D395AULL,
		0x012063442D113D1AULL,
		0x0E211A9E11267A6CULL,
		0x31C003AA8EE848E6ULL,
		0xC8B05E8E2B0812C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF759FF827F6CF13FULL,
		0xF95D90D2544A35A8ULL,
		0x7DA7F226F7B268F0ULL,
		0x3AB49E49EEF2CFF1ULL,
		0x9B63B5FF040C9949ULL,
		0x1B9F09F27ADD1047ULL,
		0xDA9DA2B1ED9CADCCULL,
		0x498F89B2139C85C8ULL
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
		0xC55A3CCE7974E880ULL,
		0x0F120E9A3423BE21ULL,
		0xF2E70D9107599E80ULL,
		0x28912F7C774D9537ULL,
		0xD0DD3C3F637737BDULL,
		0xD5CE95FAC116378AULL,
		0x8394FC7B79F3646FULL,
		0x42B85FFC35839215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DCA9E77B6AABBF2ULL,
		0x287B0926B9575CADULL,
		0x6CDF3E63B3D149ECULL,
		0x0B455240A4890F92ULL,
		0x099F1795A040E4ABULL,
		0x228F6560E9869EB2ULL,
		0x9D6D5B0A969F2AA6ULL,
		0xB3CD67F26E10979AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x478F9E56C2CA2C8EULL,
		0xE69705737ACC6174ULL,
		0x8607CF2D53885493ULL,
		0x1D4BDD3BD2C485A5ULL,
		0xC73E24A9C3365312ULL,
		0xB33F3099D78F98D8ULL,
		0xE627A170E35439C9ULL,
		0x8EEAF809C772FA7AULL
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
		0x802D6CF897612CA3ULL,
		0x1C74142F1B827620ULL,
		0x5711E5C8FE547F71ULL,
		0xECB67B6B30BD25FCULL,
		0xF7032A5B0D60C588ULL,
		0x83C829E4D30AD189ULL,
		0x02AFEF1237677B6BULL,
		0x5D96A60707668254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A4B7DA4D13FA747ULL,
		0xF32A39DC32A0B583ULL,
		0x394C5028B1AA98BFULL,
		0x603388C9CDEB7069ULL,
		0x3DEF37F50E4B2A80ULL,
		0xF53081DA50B45D1DULL,
		0x98B381BDFA94985CULL,
		0x6CABBEB2A367AAEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5E1EF53C621855CULL,
		0x2949DA52E8E1C09CULL,
		0x1DC595A04CA9E6B1ULL,
		0x8C82F2A162D1B593ULL,
		0xB913F265FF159B08ULL,
		0x8E97A80A8256746CULL,
		0x69FC6D543CD2E30EULL,
		0xF0EAE75463FED766ULL
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
		0xCB05C310A6D63EE6ULL,
		0xB5BBE9E50DEFC1FAULL,
		0x0D298C3BD1D9B110ULL,
		0x5AE893C54D61234EULL,
		0xB8A81A43043C8C32ULL,
		0x17F69F047A30EAA8ULL,
		0x5BFA2335B80F8DC6ULL,
		0xE8F2F2B1596E84BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA77C5A1C6183B034ULL,
		0xC502042B6540A036ULL,
		0xCABBFA7E0C4F9114ULL,
		0x9F8959037238504CULL,
		0x5C6A124B19A38A3CULL,
		0x70CECD29034063C4ULL,
		0x639E8131788F0833ULL,
		0xA1D32D21B0069F4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x238968F445528EB2ULL,
		0xF0B9E5B9A8AF21C4ULL,
		0x426D91BDC58A1FFBULL,
		0xBB5F3AC1DB28D301ULL,
		0x5C3E07F7EA9901F5ULL,
		0xA727D1DB76F086E4ULL,
		0xF85BA2043F808592ULL,
		0x471FC58FA967E56DULL
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
		0x6B104173014DA4C1ULL,
		0x6520B32925F0557FULL,
		0x55B2388423E69B67ULL,
		0xB5F6C91650AA1206ULL,
		0x8131D286FFB1165CULL,
		0x405ED0C2714DFE15ULL,
		0x7F7BBC7A413EB627ULL,
		0x1936A678A4952352ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F5BEDBE3A7CA5EBULL,
		0x4754FA65ED05774FULL,
		0xE787936EC2DEEFCFULL,
		0x74606EA2EA9261EAULL,
		0x046B5A6F6641D6A0ULL,
		0x28B6FB07082FD4EBULL,
		0xE9AB2FEE6D8D46ADULL,
		0x5B276463C6FF5F33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBB453B4C6D0FED6ULL,
		0x1DCBB8C338EADE2FULL,
		0x6E2AA5156107AB98ULL,
		0x41965A736617B01BULL,
		0x7CC67817996F3FBCULL,
		0x17A7D5BB691E292AULL,
		0x95D08C8BD3B16F7AULL,
		0xBE0F4214DD95C41EULL
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
		0x7F33EB3C7238A86CULL,
		0x552A78AD71FEBF6BULL,
		0xB7F54179B52D36B3ULL,
		0x69837D8CE9C7A476ULL,
		0x3700101CEC305F5DULL,
		0x8B081C7553A5CF20ULL,
		0x57684C865AEF4806ULL,
		0x9C082AB2BC3EE1CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F87FB80CCC4F4FDULL,
		0xB323B436FCD254A8ULL,
		0xF8BC491FDC5D8E3EULL,
		0x05357CD28560D201ULL,
		0xB9C72379908BF4BFULL,
		0xDA99285967BBAA04ULL,
		0x25171CC15FE67E54ULL,
		0x92EAE8ADCD81F25BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFABEFBBA573B36FULL,
		0xA206C476752C6AC2ULL,
		0xBF38F859D8CFA874ULL,
		0x644E00BA6466D274ULL,
		0x7D38ECA35BA46A9EULL,
		0xB06EF41BEBEA251BULL,
		0x32512FC4FB08C9B1ULL,
		0x091D4204EEBCEF71ULL
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
		0x9CCD6B80ABDA847EULL,
		0x4A3E7CE5F084CC62ULL,
		0xC108C04BF0E4610CULL,
		0xB8446CA83B7CECFDULL,
		0x8AF0CDD85EF520CCULL,
		0xDA3705FA92017CC5ULL,
		0x83CD795E3C393873ULL,
		0x87A0E6FD99D70DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19E228959ABF4879ULL,
		0x18C7263F1D596F0AULL,
		0x56FA30426F8FF53FULL,
		0xECC452EA092CACC5ULL,
		0x74C21A8B41260D75ULL,
		0xA53560EBE1508FACULL,
		0x4DA7C49FC9ECA7F3ULL,
		0xD5119C1B378ED87CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82EB42EB111B3C05ULL,
		0x317756A6D32B5D58ULL,
		0x6A0E900981546BCDULL,
		0xCB8019BE32504038ULL,
		0x162EB34D1DCF1356ULL,
		0x3501A50EB0B0ED19ULL,
		0x3625B4BE724C9080ULL,
		0xB28F4AE262483552ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xABC484B90F153D31ULL,
		0x9414520C1B2BBF24ULL,
		0x7D6C99F44328A92FULL,
		0x6856494CB1AAA3D7ULL,
		0x05BD7B2EB5F5B530ULL,
		0x5335F58A4B63631EULL,
		0x375C9BE7473C2A90ULL,
		0x1A9A1640A1149047ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1393C1FD892D4FFULL,
		0x831EB12DBC88CBD7ULL,
		0xCC6EF8C5F642B133ULL,
		0x58F31778DFC08F8EULL,
		0x386FB5E02B473248ULL,
		0x66EE54A7CC2FD5CFULL,
		0x3FE6A32B9B1FFC43ULL,
		0x131367673DB17018ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A8B489936826832ULL,
		0x10F5A0DE5EA2F34DULL,
		0xB0FDA12E4CE5F7FCULL,
		0x0F6331D3D1EA1448ULL,
		0xCD4DC54E8AAE82E8ULL,
		0xEC47A0E27F338D4EULL,
		0xF775F8BBAC1C2E4CULL,
		0x0786AED96363202EULL
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
		0xFEB958CC82575642ULL,
		0xB0F9F4BCC6EAF53DULL,
		0xFEE0BF6C9A7A6897ULL,
		0x1DEF118E105DB91CULL,
		0xE1D92272C4F1FF25ULL,
		0x99060B44E6F0D28BULL,
		0x43E98D3E8647AE4AULL,
		0xD42771E09C3934A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25E9FC70C8A3080ULL,
		0xDEEB8845421CCB00ULL,
		0xBDCAE1F19EF53933ULL,
		0x0D965C570C3C78A3ULL,
		0x4651CCA290F27D05ULL,
		0x30449D756915B47DULL,
		0xB1182C0E5D77F67DULL,
		0xBEDD18172B6CC14FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C5AB90575CD25C2ULL,
		0xD20E6C7784CE2A3DULL,
		0x4115DD7AFB852F63ULL,
		0x1058B53704214079ULL,
		0x9B8755D033FF8220ULL,
		0x68C16DCF7DDB1E0EULL,
		0x92D1613028CFB7CDULL,
		0x154A59C970CC7352ULL
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
		0x87E62EA089D6C1FFULL,
		0x2B071A20C7BB7468ULL,
		0xEBE7064DDE7ED054ULL,
		0x5EA358E2985A6F62ULL,
		0x6192051D6A398383ULL,
		0xEB78F9CCFECB9C3DULL,
		0x74054F1630446D51ULL,
		0x7F7811041D354E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DA785A493F66ABULL,
		0x81ACFBC4A677051EULL,
		0xFEB47DDC5C5FD109ULL,
		0xB0DBB6E345DBD4B6ULL,
		0x8CD0CD84F0BAB6EBULL,
		0x084512256F2FEC69ULL,
		0xDC1831E8C9513C22ULL,
		0x405A7F011A58DFB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD60BB64640975B54ULL,
		0xA95A1E5C21446F49ULL,
		0xED328871821EFF4AULL,
		0xADC7A1FF527E9AABULL,
		0xD4C13798797ECC97ULL,
		0xE333E7A78F9BAFD3ULL,
		0x97ED1D2D66F3312FULL,
		0x3F1D920302DC6E6BULL
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
		0xAE793A9D39FEF3C9ULL,
		0xEE52877D0379F106ULL,
		0xC0D53525D61913EBULL,
		0xFB479BCDAE1856C3ULL,
		0x3E393A308A056508ULL,
		0x461570C8608E90CDULL,
		0x17162C81713AC50DULL,
		0x1DEBCE5CD306A83CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED4A2190D2CA55A7ULL,
		0x69726C37E5627D7DULL,
		0xFE439B0621718E4FULL,
		0xC5A0CCB301103957ULL,
		0x6F4EB03B4296A112ULL,
		0x6EA20A7BA7D00753ULL,
		0x41BC4E6ED19483B4ULL,
		0x59F03D461A5A94C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC12F190C67349E22ULL,
		0x84E01B451E177388ULL,
		0xC2919A1FB4A7859CULL,
		0x35A6CF1AAD081D6BULL,
		0xCEEA89F5476EC3F6ULL,
		0xD773664CB8BE8979ULL,
		0xD559DE129FA64158ULL,
		0xC3FB9116B8AC1374ULL
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
		0x24A40778495A3347ULL,
		0x780AE30E972CD995ULL,
		0x7FB7D81F600D4DDEULL,
		0x3633C6E31FB50B06ULL,
		0xC8C8E13A2DCA51E6ULL,
		0xBB7B25BA66F6938BULL,
		0xC762876108E3DB24ULL,
		0x01F22D24373C52A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D9AD2BEF7F2FE5ULL,
		0x2690DA81AA58EBA1ULL,
		0xD901FE02DB2829F5ULL,
		0x6E36B607B67C729BULL,
		0xA2D37EB6F2D5F013ULL,
		0x5CAB46982ED16CECULL,
		0x4899471212AC1163ULL,
		0x3A7450D4E681B609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ECA5A4C59DB0362ULL,
		0x517A088CECD3EDF3ULL,
		0xA6B5DA1C84E523E9ULL,
		0xC7FD10DB6938986AULL,
		0x25F562833AF461D2ULL,
		0x5ECFDF223825269FULL,
		0x7EC9404EF637C9C1ULL,
		0xC77DDC4F50BA9C98ULL
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
		0xF5899CADF0FBAFB2ULL,
		0x882BB94A13F40B00ULL,
		0xBFEA9D1EF9D3EA71ULL,
		0x22E8706A7F3D341DULL,
		0x75E6F1564409F20CULL,
		0x5E025F9D3EBB54BFULL,
		0x83B4C6C7D0D3AE99ULL,
		0xAEE8E528A94F0652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D8739B81B4F8B2ULL,
		0x08157DB6C3E8600BULL,
		0xBACED2F997991DA2ULL,
		0x2E133FBE127A27C1ULL,
		0xA2CECFE243855F3BULL,
		0xC27B2C240183A327ULL,
		0x6EF6F5661933739BULL,
		0x8261EF5608EDF845ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13B129126F46B700ULL,
		0x80163B93500BAAF5ULL,
		0x051BCA25623ACCCFULL,
		0xF4D530AC6CC30C5CULL,
		0xD3182174008492D0ULL,
		0x9B8733793D37B197ULL,
		0x14BDD161B7A03AFDULL,
		0x2C86F5D2A0610E0DULL
	}};
	sign = 0;
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
		0xD33B36DD1C1D487BULL,
		0xDB5FB3D72C611964ULL,
		0x86BBB70379784AB5ULL,
		0x04B91C67D1972159ULL,
		0x68D4E0DC776987ACULL,
		0x5E42F027E41D8684ULL,
		0xBC1FE8977553FBC6ULL,
		0xE62C1D464870A32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2417D3908DC6CEC9ULL,
		0x5CFCD1AC11E981A2ULL,
		0xB136CC35A964A0DCULL,
		0x465C17FF09D9E7B8ULL,
		0xD7562BD3B17CCB0BULL,
		0x77E854602FBFF822ULL,
		0xFDA910A53BD2CD91ULL,
		0x958432863A02BD22ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF23634C8E5679B2ULL,
		0x7E62E22B1A7797C2ULL,
		0xD584EACDD013A9D9ULL,
		0xBE5D0468C7BD39A0ULL,
		0x917EB508C5ECBCA0ULL,
		0xE65A9BC7B45D8E61ULL,
		0xBE76D7F239812E34ULL,
		0x50A7EAC00E6DE60AULL
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
		0x45455FCCAE4D9334ULL,
		0x89B3E3890C73FB56ULL,
		0xDEF6EF079D6A1537ULL,
		0x439A5F783D36137BULL,
		0x4F9DBB77E39A73CAULL,
		0xF84948C2CC358D46ULL,
		0xE3DA24634A06A757ULL,
		0x3A2A493EE3D06F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE99E509392F551CCULL,
		0xC42FADCF6C9212E8ULL,
		0xE66FFD3AD8042A4BULL,
		0x89ADD5673E41F442ULL,
		0xBF519F341615EA94ULL,
		0x02C8ADBB060A93F9ULL,
		0x90714E503A9F9117ULL,
		0x1C3D56C669944060ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BA70F391B584168ULL,
		0xC58435B99FE1E86DULL,
		0xF886F1CCC565EAEBULL,
		0xB9EC8A10FEF41F38ULL,
		0x904C1C43CD848935ULL,
		0xF5809B07C62AF94CULL,
		0x5368D6130F671640ULL,
		0x1DECF2787A3C2F0BULL
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
		0x7F7248A2AC2340D9ULL,
		0xEF784E923AB1727EULL,
		0xA9DA8F785D340991ULL,
		0xCE855FC1A01019F2ULL,
		0x7129AC7F79733DB7ULL,
		0x6AD2246B89F4A362ULL,
		0x176B86C9A499A19EULL,
		0xBDCC5600E155EA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E38EB395C83FCAAULL,
		0x403F5C36D730A670ULL,
		0x43A0F0B9386C1802ULL,
		0x504E6A8FB24960E7ULL,
		0x263D0BC0E60962DDULL,
		0xFE40BEB271909487ULL,
		0xCB57855D2F7DAFD0ULL,
		0x9F9590EFDB3323FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1395D694F9F442FULL,
		0xAF38F25B6380CC0DULL,
		0x66399EBF24C7F18FULL,
		0x7E36F531EDC6B90BULL,
		0x4AECA0BE9369DADAULL,
		0x6C9165B918640EDBULL,
		0x4C14016C751BF1CDULL,
		0x1E36C5110622C60AULL
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
		0x96632969D2FEC9EFULL,
		0xD0556D9C3243324CULL,
		0x7F220648991AA184ULL,
		0x35C5E60371B9284AULL,
		0x637D31D3109BA6B6ULL,
		0x128BC2A5B9029944ULL,
		0xCA0A2BF3DAB36B5DULL,
		0xBBC21EC934D492C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAD7049F0ECF6F3ULL,
		0x0AFAF288A81EA59BULL,
		0xFAECB33962D5859EULL,
		0xE629E055A4A90329ULL,
		0xB79B5B84FD9D60E6ULL,
		0xEE6541E70B0015B3ULL,
		0xDD5B080E4C3D526BULL,
		0x92C74E8D8FF5AD6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BB5B91FE211D2FCULL,
		0xC55A7B138A248CB1ULL,
		0x8435530F36451BE6ULL,
		0x4F9C05ADCD102520ULL,
		0xABE1D64E12FE45CFULL,
		0x242680BEAE028390ULL,
		0xECAF23E58E7618F1ULL,
		0x28FAD03BA4DEE558ULL
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
		0xD498756E41E1D786ULL,
		0xCA0BEF06029B94F5ULL,
		0x326109A0B57ABE93ULL,
		0x23A8EBB6EF7BF109ULL,
		0x1E7289C83F1F5F3FULL,
		0x90ABC7C11705C676ULL,
		0x4F44938CD76779E3ULL,
		0xC262AB2A4E6716C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB506FEA7491EEF02ULL,
		0x691FCA9CBCFD9745ULL,
		0x2348E96F5BEDF0C1ULL,
		0x194C4FA1C0206477ULL,
		0x1AC29CAD174E7A29ULL,
		0x008788542389A3ADULL,
		0x4BFF95F00C41F4B0ULL,
		0xF6E99F73277E44DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F9176C6F8C2E884ULL,
		0x60EC2469459DFDB0ULL,
		0x0F182031598CCDD2ULL,
		0x0A5C9C152F5B8C92ULL,
		0x03AFED1B27D0E516ULL,
		0x90243F6CF37C22C9ULL,
		0x0344FD9CCB258533ULL,
		0xCB790BB726E8D1E8ULL
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
		0x3A092AFA0FA5DB8BULL,
		0x8C8E41FEF22F9AC5ULL,
		0x4553D8CF086DE708ULL,
		0x5E16EC36C6DE75C7ULL,
		0xF7559C82D46BE76CULL,
		0xCC664380F0CB6B30ULL,
		0x0AEF70DEFBCA3A4BULL,
		0xD36BC14844DF5E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574B9DDB2F4467DBULL,
		0xB19DECFC66B3330CULL,
		0xF9783E44991BFC76ULL,
		0x9495970A83C62AE6ULL,
		0x142963A7465FCC1CULL,
		0x1E67EC014A9B9984ULL,
		0x342E6217AE942E8EULL,
		0xD487007DA078F8FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2BD8D1EE06173B0ULL,
		0xDAF055028B7C67B8ULL,
		0x4BDB9A8A6F51EA91ULL,
		0xC981552C43184AE0ULL,
		0xE32C38DB8E0C1B4FULL,
		0xADFE577FA62FD1ACULL,
		0xD6C10EC74D360BBDULL,
		0xFEE4C0CAA4666571ULL
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
		0x88B6559CD1B61EA8ULL,
		0x57677F337B9C668EULL,
		0xF36B716A7411B54BULL,
		0x17A2EF48A8AC42E6ULL,
		0xD855AD46F2669E44ULL,
		0xA112CFC657C7B7CBULL,
		0x30FB3DAD078DF199ULL,
		0xA06A7E3FDBD6C4B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665DF69016BA921BULL,
		0x1421990FDE5DEE11ULL,
		0x33CA7063C7384C44ULL,
		0xA7B320F3C8F26B1DULL,
		0x132A6AC5CE511D26ULL,
		0xA90E80D90756CFD6ULL,
		0x7BF1BE2B52905190ULL,
		0x0C37F188362823DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22585F0CBAFB8C8DULL,
		0x4345E6239D3E787DULL,
		0xBFA10106ACD96907ULL,
		0x6FEFCE54DFB9D7C9ULL,
		0xC52B42812415811DULL,
		0xF8044EED5070E7F5ULL,
		0xB5097F81B4FDA008ULL,
		0x94328CB7A5AEA0D4ULL
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
		0x214727EA5EC393D8ULL,
		0x3E909A27075547E9ULL,
		0x6D475F6E82E251F7ULL,
		0x6AB5C0E9167A3477ULL,
		0x0187030F3B3AE8E5ULL,
		0x540AEFDA9C792615ULL,
		0x8A4444DA60DD44FAULL,
		0xE763642DB570D43AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x014ED5FF00937031ULL,
		0x31057BD275F5BFD6ULL,
		0xD8CB9BD19B73F994ULL,
		0x2A5D4FA2EBB83AD1ULL,
		0x95BB9287CA5A56EAULL,
		0xFED4946158A4950CULL,
		0x9AC9678553D3413DULL,
		0xEB23A681D175DBA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FF851EB5E3023A7ULL,
		0x0D8B1E54915F8813ULL,
		0x947BC39CE76E5863ULL,
		0x405871462AC1F9A5ULL,
		0x6BCB708770E091FBULL,
		0x55365B7943D49108ULL,
		0xEF7ADD550D0A03BCULL,
		0xFC3FBDABE3FAF892ULL
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
		0xB0051ADFB1FD2272ULL,
		0x622E83E9C8AA3D18ULL,
		0x7E9C8DFC3C305372ULL,
		0x1D145FB5E7BA814AULL,
		0x5A394C11195AFDDCULL,
		0x0A47AE7D0AB87E58ULL,
		0xC7CD197E79BAE9DFULL,
		0x477F893DB9324815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x122E8E3D972556ACULL,
		0xF6F651BEF9CBE996ULL,
		0xBA3532219D27B4BBULL,
		0x00B84B0CABA5878EULL,
		0x1ABB2A50280201ACULL,
		0x96425D58F90E8844ULL,
		0x1FA7405DAB07F4F4ULL,
		0xF6A82B9E89EB8F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DD68CA21AD7CBC6ULL,
		0x6B38322ACEDE5382ULL,
		0xC4675BDA9F089EB6ULL,
		0x1C5C14A93C14F9BBULL,
		0x3F7E21C0F158FC30ULL,
		0x7405512411A9F614ULL,
		0xA825D920CEB2F4EAULL,
		0x50D75D9F2F46B8D3ULL
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
		0x98B6487DB083A477ULL,
		0x267B2D65056D1799ULL,
		0xF88887B9100595CBULL,
		0x67D7D720C5E09D16ULL,
		0x42CB9C950041CD90ULL,
		0x143D69D8E94A2DF9ULL,
		0xB375B49107FC2642ULL,
		0x0A2EF55ADB8C6BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EADC5BD93F50B46ULL,
		0xF6999856E4C1A2C6ULL,
		0x975AFEA873926BABULL,
		0x5D452A96923E57C9ULL,
		0x53682BBD667B0EF2ULL,
		0xC987E99C14332AACULL,
		0x2838069410B7990EULL,
		0xE68C89CF9AAAC28EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A0882C01C8E9931ULL,
		0x2FE1950E20AB74D3ULL,
		0x612D89109C732A1FULL,
		0x0A92AC8A33A2454DULL,
		0xEF6370D799C6BE9EULL,
		0x4AB5803CD517034CULL,
		0x8B3DADFCF7448D33ULL,
		0x23A26B8B40E1A92BULL
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
		0x18F0163C930E2F23ULL,
		0xC12025DB625318A2ULL,
		0x44353930FEB0E335ULL,
		0xA0FBA99F663C327FULL,
		0xE493ACC36D8B740AULL,
		0x2F58264E11C11646ULL,
		0x392744E2A8653A7EULL,
		0x5741BEE8FCFF0ED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BF94287226AA4B9ULL,
		0x41CAF6F5CA606FD1ULL,
		0x01C285FA76CE19A5ULL,
		0xE0335DFF56E9AF79ULL,
		0xA1E1379103A391C6ULL,
		0xDDA223DD210471FDULL,
		0x91158BCD24BFC79FULL,
		0x2324411715DCD71AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCF6D3B570A38A6AULL,
		0x7F552EE597F2A8D0ULL,
		0x4272B33687E2C990ULL,
		0xC0C84BA00F528306ULL,
		0x42B2753269E7E243ULL,
		0x51B60270F0BCA449ULL,
		0xA811B91583A572DEULL,
		0x341D7DD1E72237B7ULL
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
		0x52BBE8F69A4CE4FFULL,
		0xC930C60EF3F49A50ULL,
		0x739621D8840F6085ULL,
		0xA764118CCB5FBA0EULL,
		0x5E73DB72A344285AULL,
		0x20BA87B1CB0BE18BULL,
		0xD146B4E96481A9FFULL,
		0x06B4FA2F4B4FB5A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5AAF9F74CCE805FULL,
		0x6AB61614B7930C2CULL,
		0xA47AAAEE8840B3FDULL,
		0x416E254040E8DF5EULL,
		0xF87F028DC4F7AB6EULL,
		0x6F8EC6073B3880EEULL,
		0xCDDB3AD11B61E56BULL,
		0x5222F1CEF9B5DCC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D10EEFF4D7E64A0ULL,
		0x5E7AAFFA3C618E23ULL,
		0xCF1B76E9FBCEAC88ULL,
		0x65F5EC4C8A76DAAFULL,
		0x65F4D8E4DE4C7CECULL,
		0xB12BC1AA8FD3609CULL,
		0x036B7A18491FC493ULL,
		0xB49208605199D8E4ULL
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
	return 0;
}