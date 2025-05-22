#include "../tests.h"

int32_t curve25519_key_x2_test(void) {
	printf("Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x19B30B3CAD4A3128ULL,
		0x306781FD4EA8AB80ULL,
		0xAC79DEF8E52C0EBAULL,
		0x841FCA236A26D4FBULL,
		0xCB3573F1E05DB04BULL,
		0x7B2F5564B5B78591ULL,
		0x276C2D35C90B9032ULL,
		0x2FBB509F63A72FD8ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x336616795A946250ULL,
		0x60CF03FA9D515700ULL,
		0x58F3BDF1CA581D74ULL,
		0x083F9446D44DA9F7ULL,
		0x966AE7E3C0BB6097ULL,
		0xF65EAAC96B6F0B23ULL,
		0x4ED85A6B92172064ULL,
		0x5F76A13EC74E5FB0ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB04CCB8804B3C064ULL,
		0x73BCFA51B43B3DB1ULL,
		0x2546A9BE8E9E6904ULL,
		0x27A5523E2E78CE98ULL,
		0x7577846EA28C104BULL,
		0x70983B1F5B8F18F6ULL,
		0x7E20B17F6BBDDF06ULL,
		0x2C28BAE49D396A67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60999710096780C8ULL,
		0xE779F4A368767B63ULL,
		0x4A8D537D1D3CD208ULL,
		0x4F4AA47C5CF19D30ULL,
		0xEAEF08DD45182096ULL,
		0xE130763EB71E31ECULL,
		0xFC4162FED77BBE0CULL,
		0x585175C93A72D4CEULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1C2D64E50A4532EBULL,
		0x05300A1511AEB2A7ULL,
		0x443B3AD660531374ULL,
		0x30CAAC905AE6F6A9ULL,
		0x86C085219C07CF1CULL,
		0x4052BB46EBB220D0ULL,
		0x96D584BA2AD91A2EULL,
		0x21F6B3B279EB1D2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x385AC9CA148A65D6ULL,
		0x0A60142A235D654EULL,
		0x887675ACC0A626E8ULL,
		0x61955920B5CDED52ULL,
		0x0D810A43380F9E38ULL,
		0x80A5768DD76441A1ULL,
		0x2DAB097455B2345CULL,
		0x43ED6764F3D63A57ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5FAE764990B4DA68ULL,
		0x61C4F4DB4FA22ECCULL,
		0x4AF026AD0FCBBA8EULL,
		0x9FECB6412C8C6B9DULL,
		0xEE9B7ECF07E17506ULL,
		0x34B584AC63C423A6ULL,
		0x5E2C46C3D4F3FB67ULL,
		0x06F8E8D2B73C2C36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF5CEC932169B4D0ULL,
		0xC389E9B69F445D98ULL,
		0x95E04D5A1F97751CULL,
		0x3FD96C825918D73AULL,
		0xDD36FD9E0FC2EA0DULL,
		0x696B0958C788474DULL,
		0xBC588D87A9E7F6CEULL,
		0x0DF1D1A56E78586CULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x599842019DEA5AC3ULL,
		0x64EE23E85A74E55AULL,
		0x5C4AFD73CD8BEA99ULL,
		0x903111351D738BCFULL,
		0xDD5B27A7277658CBULL,
		0xFAE9C83CFED4B0E1ULL,
		0x832E03DA0E08C2ECULL,
		0x3CAFE40DE5F9009BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB33084033BD4B586ULL,
		0xC9DC47D0B4E9CAB4ULL,
		0xB895FAE79B17D532ULL,
		0x2062226A3AE7179EULL,
		0xBAB64F4E4EECB197ULL,
		0xF5D39079FDA961C3ULL,
		0x065C07B41C1185D9ULL,
		0x795FC81BCBF20137ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9BD3C2088D533A91ULL,
		0xD61998BF90ED3089ULL,
		0x6673D14452D670D1ULL,
		0xFC1D1792BCD8A1EDULL,
		0x9147E1A5C50931E1ULL,
		0x0D78136263C4296BULL,
		0xBA8E1C43D799FF1DULL,
		0x18A00C3FAA1D7CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37A784111AA67522ULL,
		0xAC33317F21DA6113ULL,
		0xCCE7A288A5ACE1A3ULL,
		0xF83A2F2579B143DAULL,
		0x228FC34B8A1263C3ULL,
		0x1AF026C4C78852D7ULL,
		0x751C3887AF33FE3AULL,
		0x3140187F543AF9C3ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8633AB7150553E3DULL,
		0xF848DC235DA9E7EAULL,
		0xC76AA3F9E02FD453ULL,
		0xACF38C4E549CCC20ULL,
		0x3F979972919F5FA7ULL,
		0xA573353B2836CE6CULL,
		0xE41B7218BEB27580ULL,
		0x023C6D99B335402AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C6756E2A0AA7C7AULL,
		0xF091B846BB53CFD5ULL,
		0x8ED547F3C05FA8A7ULL,
		0x59E7189CA9399841ULL,
		0x7F2F32E5233EBF4FULL,
		0x4AE66A76506D9CD8ULL,
		0xC836E4317D64EB01ULL,
		0x0478DB33666A8055ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9F3706479A66BCF0ULL,
		0xCA3334BD4F3EB77AULL,
		0x5A57CE1B9B64E85AULL,
		0x9F21D8CF42777367ULL,
		0x28995524CFB3572EULL,
		0xE5561CBB0F11A3CAULL,
		0x140800B08D87F6DCULL,
		0x209ACB3FDA67DF2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E6E0C8F34CD79E0ULL,
		0x9466697A9E7D6EF5ULL,
		0xB4AF9C3736C9D0B5ULL,
		0x3E43B19E84EEE6CEULL,
		0x5132AA499F66AE5DULL,
		0xCAAC39761E234794ULL,
		0x281001611B0FEDB9ULL,
		0x4135967FB4CFBE54ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x87873546DFA0BFEBULL,
		0x2C3C6396560CEF4DULL,
		0xD5FE45E8878219D4ULL,
		0x36C8CA2D470C6D3DULL,
		0xF029880179AF0815ULL,
		0x97306BC64845E3DEULL,
		0x37D91423137640E1ULL,
		0x39E5C0591683E6EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0E6A8DBF417FD6ULL,
		0x5878C72CAC19DE9BULL,
		0xABFC8BD10F0433A8ULL,
		0x6D91945A8E18DA7BULL,
		0xE0531002F35E102AULL,
		0x2E60D78C908BC7BDULL,
		0x6FB2284626EC81C3ULL,
		0x73CB80B22D07CDDCULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0ADB13CDA7E9FAD2ULL,
		0xC7912FB7D32E37ACULL,
		0x22E523B3DA8E09F5ULL,
		0x4761ADB0FE7B4AB0ULL,
		0x181B8F277E3DACF0ULL,
		0xDDFCA6C79DC753EEULL,
		0xB56B793389E1C674ULL,
		0x3892E619ADF4A10AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15B6279B4FD3F5A4ULL,
		0x8F225F6FA65C6F58ULL,
		0x45CA4767B51C13EBULL,
		0x8EC35B61FCF69560ULL,
		0x30371E4EFC7B59E0ULL,
		0xBBF94D8F3B8EA7DCULL,
		0x6AD6F26713C38CE9ULL,
		0x7125CC335BE94215ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x48F3EA322C2237EBULL,
		0xA4DB8F080FAA1A4CULL,
		0x92D5B718D8C1DB66ULL,
		0x0DAC68CC5EC04207ULL,
		0x551DFE78B30B4D1DULL,
		0xF1C949E6C318601AULL,
		0x84BED4336F3385FDULL,
		0x085DBC5B2366E315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E7D46458446FD6ULL,
		0x49B71E101F543498ULL,
		0x25AB6E31B183B6CDULL,
		0x1B58D198BD80840FULL,
		0xAA3BFCF166169A3AULL,
		0xE39293CD8630C034ULL,
		0x097DA866DE670BFBULL,
		0x10BB78B646CDC62BULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6BAF1F016F470D7AULL,
		0x8F31C19D42110284ULL,
		0xC930B09EAB112A72ULL,
		0x1EBC967F0A6CC708ULL,
		0x7D649B514F2C4374ULL,
		0xFD27ADE94BCC9696ULL,
		0xFCB1B2B84B119F69ULL,
		0x1A8C0DECBF0470CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD75E3E02DE8E1AF4ULL,
		0x1E63833A84220508ULL,
		0x9261613D562254E5ULL,
		0x3D792CFE14D98E11ULL,
		0xFAC936A29E5886E8ULL,
		0xFA4F5BD297992D2CULL,
		0xF963657096233ED3ULL,
		0x35181BD97E08E19DULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF72394AD4B82032DULL,
		0x647CF4351F75447CULL,
		0x2A66D9F63393FD2FULL,
		0x923C45D9FA9BE1A7ULL,
		0x1E9FB0B8F0C6C3A3ULL,
		0x9FFCD61C76FB35BBULL,
		0x91DC8CBA44A011E5ULL,
		0x0B640F69D6372576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE47295A9704065AULL,
		0xC8F9E86A3EEA88F9ULL,
		0x54CDB3EC6727FA5EULL,
		0x24788BB3F537C34EULL,
		0x3D3F6171E18D8747ULL,
		0x3FF9AC38EDF66B76ULL,
		0x23B91974894023CBULL,
		0x16C81ED3AC6E4AEDULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE2237755B1DA6E11ULL,
		0xFC788021D87D5FC9ULL,
		0xC59A8BEA272B7883ULL,
		0x8C31C936B72BE291ULL,
		0x76AA7C57A9D26014ULL,
		0xDF05F6480DC24C09ULL,
		0x27A673629D98C323ULL,
		0x173DE2477DCC8622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC446EEAB63B4DC22ULL,
		0xF8F10043B0FABF93ULL,
		0x8B3517D44E56F107ULL,
		0x1863926D6E57C523ULL,
		0xED54F8AF53A4C029ULL,
		0xBE0BEC901B849812ULL,
		0x4F4CE6C53B318647ULL,
		0x2E7BC48EFB990C44ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5A55937EF005ABA9ULL,
		0x218755B1BDDA8142ULL,
		0xCBCBFFEAAA612602ULL,
		0x423C5AF619AB043BULL,
		0xBB3FF67674B92A1AULL,
		0x158034482829EF34ULL,
		0xB7DFF69541251702ULL,
		0x080B8C313823B260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AB26FDE00B5752ULL,
		0x430EAB637BB50284ULL,
		0x9797FFD554C24C04ULL,
		0x8478B5EC33560877ULL,
		0x767FECECE9725434ULL,
		0x2B0068905053DE69ULL,
		0x6FBFED2A824A2E04ULL,
		0x10171862704764C1ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x022051B8577EFD90ULL,
		0x9DA3D46FC398C099ULL,
		0xB506C577C6CA80B1ULL,
		0x68CDCD610D610BDDULL,
		0x635650BAAC1F7132ULL,
		0x226D772D4720BFCEULL,
		0xD2C5215269CBB3A7ULL,
		0x31BB3F36321F3E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0440A370AEFDFB20ULL,
		0x3B47A8DF87318132ULL,
		0x6A0D8AEF8D950163ULL,
		0xD19B9AC21AC217BBULL,
		0xC6ACA175583EE264ULL,
		0x44DAEE5A8E417F9CULL,
		0xA58A42A4D397674EULL,
		0x63767E6C643E7C33ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x30AD6F0438DF503AULL,
		0xC32D7715F9830985ULL,
		0x9428EB1F90E2DC68ULL,
		0x6BD97B20F0BDA866ULL,
		0x221F1B8EE61EEC6AULL,
		0xFFA011C3CA946E13ULL,
		0x7DBE9B888280D6FDULL,
		0x04FF01D80AF35C26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x615ADE0871BEA074ULL,
		0x865AEE2BF306130AULL,
		0x2851D63F21C5B8D1ULL,
		0xD7B2F641E17B50CDULL,
		0x443E371DCC3DD8D4ULL,
		0xFF4023879528DC26ULL,
		0xFB7D37110501ADFBULL,
		0x09FE03B015E6B84CULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA861C3289D497609ULL,
		0xD817A4DD69C7B418ULL,
		0xD79278EB3337FC81ULL,
		0x1EF96F4F6193341EULL,
		0xDA3C492C4A14DB33ULL,
		0x0737F8679F943156ULL,
		0xC3E9932059A324D2ULL,
		0x109578D4E4417A27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C386513A92EC12ULL,
		0xB02F49BAD38F6831ULL,
		0xAF24F1D6666FF903ULL,
		0x3DF2DE9EC326683DULL,
		0xB47892589429B666ULL,
		0x0E6FF0CF3F2862ADULL,
		0x87D32640B34649A4ULL,
		0x212AF1A9C882F44FULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD7814FFB01DA2941ULL,
		0xC53662DF38F6CE02ULL,
		0xB7CF7AAADB6AB56DULL,
		0x4340EA93A9F5BEE8ULL,
		0x19972B912EDA66F9ULL,
		0x9847E65D87FB72D7ULL,
		0x47FF9F0FD0BF16D8ULL,
		0x22CA618B574BC7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF029FF603B45282ULL,
		0x8A6CC5BE71ED9C05ULL,
		0x6F9EF555B6D56ADBULL,
		0x8681D52753EB7DD1ULL,
		0x332E57225DB4CDF2ULL,
		0x308FCCBB0FF6E5AEULL,
		0x8FFF3E1FA17E2DB1ULL,
		0x4594C316AE978F78ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2BF1C0BD7358BDC4ULL,
		0xF33BA1487E76EF93ULL,
		0x11856C8E83D44731ULL,
		0x8FC15498D5E87F2EULL,
		0x25EBCD9108A35F01ULL,
		0xD0F934E2F27AEFE3ULL,
		0x698AEC0D47C4B4A6ULL,
		0x225589E4E83C2481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E3817AE6B17B88ULL,
		0xE6774290FCEDDF26ULL,
		0x230AD91D07A88E63ULL,
		0x1F82A931ABD0FE5CULL,
		0x4BD79B221146BE03ULL,
		0xA1F269C5E4F5DFC6ULL,
		0xD315D81A8F89694DULL,
		0x44AB13C9D0784902ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8A9DB3364F381F2BULL,
		0xAC57E691478CBE84ULL,
		0x8362625D419ECA80ULL,
		0xF9B778C69153662EULL,
		0x731867614F66B198ULL,
		0x61B0E6DEE0307BBDULL,
		0x89267DD92EFE2128ULL,
		0x0CA874AE7F94C416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x153B666C9E703E56ULL,
		0x58AFCD228F197D09ULL,
		0x06C4C4BA833D9501ULL,
		0xF36EF18D22A6CC5DULL,
		0xE630CEC29ECD6331ULL,
		0xC361CDBDC060F77AULL,
		0x124CFBB25DFC4250ULL,
		0x1950E95CFF29882DULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x52072BD72F3B4C8FULL,
		0xC768D88D98B0F2DFULL,
		0x8FD3842D5240D134ULL,
		0x2CE443CB16EAC859ULL,
		0x9166E0E4FC6BC9ADULL,
		0xCCAC96DFCA0EB566ULL,
		0x75C26F0A986A33E2ULL,
		0x33178372BEDD151FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA40E57AE5E76991EULL,
		0x8ED1B11B3161E5BEULL,
		0x1FA7085AA481A269ULL,
		0x59C887962DD590B3ULL,
		0x22CDC1C9F8D7935AULL,
		0x99592DBF941D6ACDULL,
		0xEB84DE1530D467C5ULL,
		0x662F06E57DBA2A3EULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x412A3D476E6F1CFCULL,
		0x357BE62656CD8E3EULL,
		0x1692357D0394880EULL,
		0x2A2460101FC71DC1ULL,
		0x644FCB67B5C081ACULL,
		0xCB926F31B5AA78D4ULL,
		0x4B05B4DA3711B92CULL,
		0x08095DE7844E71F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82547A8EDCDE39F8ULL,
		0x6AF7CC4CAD9B1C7CULL,
		0x2D246AFA0729101CULL,
		0x5448C0203F8E3B82ULL,
		0xC89F96CF6B810358ULL,
		0x9724DE636B54F1A8ULL,
		0x960B69B46E237259ULL,
		0x1012BBCF089CE3E8ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9ECA95E060C67A87ULL,
		0xD78A1D9CEB779647ULL,
		0x51B4B3A4EAB2C62CULL,
		0x70CAF2AC944C63E1ULL,
		0x316F71A2AFCB615CULL,
		0x5857B7DFF31EBE8CULL,
		0x8668A8D10963AE9FULL,
		0x15902468A47C0E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D952BC0C18CF50EULL,
		0xAF143B39D6EF2C8FULL,
		0xA3696749D5658C59ULL,
		0xE195E5592898C7C2ULL,
		0x62DEE3455F96C2B8ULL,
		0xB0AF6FBFE63D7D18ULL,
		0x0CD151A212C75D3EULL,
		0x2B2048D148F81CF7ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x32F70328FC5FA786ULL,
		0x1A5EB8B7BA91CC8AULL,
		0x098302F39D253BABULL,
		0x1AC447C50D2BCC57ULL,
		0x556D111047B45626ULL,
		0xD6AAB7B0F872D90DULL,
		0xA089FA573003580CULL,
		0x1BE65DAE9232345BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EE0651F8BF4F0CULL,
		0x34BD716F75239914ULL,
		0x130605E73A4A7756ULL,
		0x35888F8A1A5798AEULL,
		0xAADA22208F68AC4CULL,
		0xAD556F61F0E5B21AULL,
		0x4113F4AE6006B019ULL,
		0x37CCBB5D246468B7ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6C72141DEA991651ULL,
		0x98D404553266ECF7ULL,
		0x12C10BDBC1566E06ULL,
		0xEB9E71D5FB8FC3DEULL,
		0x4F11235500BBB5C3ULL,
		0xD8EE811D567E4F3BULL,
		0x65DCADB1E45A870EULL,
		0x12C7ED0EE260E8D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8E4283BD5322CA2ULL,
		0x31A808AA64CDD9EEULL,
		0x258217B782ACDC0DULL,
		0xD73CE3ABF71F87BCULL,
		0x9E2246AA01776B87ULL,
		0xB1DD023AACFC9E76ULL,
		0xCBB95B63C8B50E1DULL,
		0x258FDA1DC4C1D1A4ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5748470C990DB824ULL,
		0xD4EFD03C8ECE5B2AULL,
		0x34D4D597026268D8ULL,
		0x2F89591D91C715A4ULL,
		0xC5D903B300695316ULL,
		0x9A8346DAA8F643F7ULL,
		0xB2E07D905F6086CEULL,
		0x26D9CD2983C8750AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE908E19321B7048ULL,
		0xA9DFA0791D9CB654ULL,
		0x69A9AB2E04C4D1B1ULL,
		0x5F12B23B238E2B48ULL,
		0x8BB2076600D2A62CULL,
		0x35068DB551EC87EFULL,
		0x65C0FB20BEC10D9DULL,
		0x4DB39A530790EA15ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7D97221A67259EF7ULL,
		0x3F79CB4F71784C25ULL,
		0xC772D681C6706A0EULL,
		0x0604ACD2CE7372ECULL,
		0xDCFDF3704BFA0371ULL,
		0xCE27C322EADD3786ULL,
		0xC05A2BF4C95E31F5ULL,
		0x2243AC98717A4FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2E4434CE4B3DEEULL,
		0x7EF3969EE2F0984AULL,
		0x8EE5AD038CE0D41CULL,
		0x0C0959A59CE6E5D9ULL,
		0xB9FBE6E097F406E2ULL,
		0x9C4F8645D5BA6F0DULL,
		0x80B457E992BC63EBULL,
		0x44875930E2F49FB7ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x89B492A0F8EBAC66ULL,
		0x49AFE7CF9F793924ULL,
		0x55E55BE9FD03DE73ULL,
		0x223ED7E38E1F566BULL,
		0xAEEFAC2D09DB2E28ULL,
		0xA05BFF0D558C3861ULL,
		0xBCFA6CFF9F311891ULL,
		0x214C799C0882C382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13692541F1D758CCULL,
		0x935FCF9F3EF27249ULL,
		0xABCAB7D3FA07BCE6ULL,
		0x447DAFC71C3EACD6ULL,
		0x5DDF585A13B65C50ULL,
		0x40B7FE1AAB1870C3ULL,
		0x79F4D9FF3E623123ULL,
		0x4298F33811058705ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4ED2689CCFD1811DULL,
		0x49F08E5D546168F7ULL,
		0xC3395987C3098A40ULL,
		0x97072BC56DE70DD3ULL,
		0xB0139FC815765234ULL,
		0x4885D8D66ECEB498ULL,
		0xA20D637817DA5BE5ULL,
		0x28E0E70F7C948A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA4D1399FA3023AULL,
		0x93E11CBAA8C2D1EEULL,
		0x8672B30F86131480ULL,
		0x2E0E578ADBCE1BA7ULL,
		0x60273F902AECA469ULL,
		0x910BB1ACDD9D6931ULL,
		0x441AC6F02FB4B7CAULL,
		0x51C1CE1EF9291479ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x506AA6C75DEC5A11ULL,
		0x9AC7FA963405A437ULL,
		0x61A3E41D435DF9DDULL,
		0x7910A42189E8E4BAULL,
		0x5026D56B772A04B1ULL,
		0x18F80E29E31A7125ULL,
		0x3E8C7FCDC49B69E0ULL,
		0x218023B407C0A48FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0D54D8EBBD8B422ULL,
		0x358FF52C680B486EULL,
		0xC347C83A86BBF3BBULL,
		0xF221484313D1C974ULL,
		0xA04DAAD6EE540962ULL,
		0x31F01C53C634E24AULL,
		0x7D18FF9B8936D3C0ULL,
		0x430047680F81491EULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4DFFED7346865790ULL,
		0xFC7051C2B9C41472ULL,
		0x9394CE70282E68FFULL,
		0x27C4E5BF74C2D686ULL,
		0x0DE9FD43BB17C89AULL,
		0x0BCE1ACE424EA69DULL,
		0x25E6F6463F4AE799ULL,
		0x2D6E91027C41C349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFFDAE68D0CAF20ULL,
		0xF8E0A385738828E4ULL,
		0x27299CE0505CD1FFULL,
		0x4F89CB7EE985AD0DULL,
		0x1BD3FA87762F9134ULL,
		0x179C359C849D4D3AULL,
		0x4BCDEC8C7E95CF32ULL,
		0x5ADD2204F8838692ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5CD2F9D52D9681BCULL,
		0xC8248FFA60D073EFULL,
		0xEF76EE394FFB9A33ULL,
		0x83AC5D55245667C2ULL,
		0xFF8C9B78E16F52F3ULL,
		0xE29E65F5217ACAF1ULL,
		0xD3C4C06E4C0D028AULL,
		0x2C1F54ECC0DEEB25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A5F3AA5B2D0378ULL,
		0x90491FF4C1A0E7DEULL,
		0xDEEDDC729FF73467ULL,
		0x0758BAAA48ACCF85ULL,
		0xFF1936F1C2DEA5E7ULL,
		0xC53CCBEA42F595E3ULL,
		0xA78980DC981A0515ULL,
		0x583EA9D981BDD64BULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF08E84BFCF4581E5ULL,
		0x720C19F5D0BD9328ULL,
		0xA495F76714792EC6ULL,
		0xC7626C8784626483ULL,
		0x8255EC4D71339DF9ULL,
		0x7D11FBC3606FFAD9ULL,
		0xB51F2D84DB3B414FULL,
		0x3EBD17E0B1D26B8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11D097F9E8B03CAULL,
		0xE41833EBA17B2651ULL,
		0x492BEECE28F25D8CULL,
		0x8EC4D90F08C4C907ULL,
		0x04ABD89AE2673BF3ULL,
		0xFA23F786C0DFF5B3ULL,
		0x6A3E5B09B676829EULL,
		0x7D7A2FC163A4D71FULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x741ECF6FAC6FCFDCULL,
		0x728951DA963FC591ULL,
		0x8519DD5413C729B3ULL,
		0x69AADCE0F2EE9D45ULL,
		0xD6F1469283FCED1EULL,
		0x12EF47FABDA7146DULL,
		0xF1DC97F5FEE8B36AULL,
		0x170F7B01C4CABA6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE83D9EDF58DF9FB8ULL,
		0xE512A3B52C7F8B22ULL,
		0x0A33BAA8278E5366ULL,
		0xD355B9C1E5DD3A8BULL,
		0xADE28D2507F9DA3CULL,
		0x25DE8FF57B4E28DBULL,
		0xE3B92FEBFDD166D4ULL,
		0x2E1EF603899574DBULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x15BCDF218A71EF56ULL,
		0xD46D393BE6381E45ULL,
		0x37F300F8F5E05F13ULL,
		0x121282E8D49E68C3ULL,
		0x7E155CF87DFF9E51ULL,
		0x8044F918DA4514D4ULL,
		0x37F209B9AD205242ULL,
		0x353FE5791541062EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B79BE4314E3DEACULL,
		0xA8DA7277CC703C8AULL,
		0x6FE601F1EBC0BE27ULL,
		0x242505D1A93CD186ULL,
		0xFC2AB9F0FBFF3CA2ULL,
		0x0089F231B48A29A8ULL,
		0x6FE413735A40A485ULL,
		0x6A7FCAF22A820C5CULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x590FBD75D6FB2F96ULL,
		0xDB486BD6C5B02F05ULL,
		0x42F740DB97CA999CULL,
		0x09B6CA37CBBFF948ULL,
		0x7DF55DA677CEE90EULL,
		0xDE2C9FDCD0C814D2ULL,
		0x973EB12F979BE796ULL,
		0x03F169BE02C6C65CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB21F7AEBADF65F2CULL,
		0xB690D7AD8B605E0AULL,
		0x85EE81B72F953339ULL,
		0x136D946F977FF290ULL,
		0xFBEABB4CEF9DD21CULL,
		0xBC593FB9A19029A4ULL,
		0x2E7D625F2F37CF2DULL,
		0x07E2D37C058D8CB9ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x907D48870817C659ULL,
		0x61331255B4EB666AULL,
		0xDB029C2D8AD889FFULL,
		0x0B224F0839C8A855ULL,
		0x46882491E874D383ULL,
		0x4A8BE5EE544EAC25ULL,
		0x13BBE54DE16DAF8BULL,
		0x25C1DD401DB2CB59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20FA910E102F8CB2ULL,
		0xC26624AB69D6CCD5ULL,
		0xB605385B15B113FEULL,
		0x16449E10739150ABULL,
		0x8D104923D0E9A706ULL,
		0x9517CBDCA89D584AULL,
		0x2777CA9BC2DB5F16ULL,
		0x4B83BA803B6596B2ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x511E02CA4EEAFF95ULL,
		0xF038CB64EEED0217ULL,
		0xD364F79F1E87F389ULL,
		0x08F842F2DD385DEDULL,
		0x46CAEB431F09C07CULL,
		0x07F7E4E9E7B01339ULL,
		0x56E839C555B2C041ULL,
		0x3F9A1E8AA4F966D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA23C05949DD5FF2AULL,
		0xE07196C9DDDA042EULL,
		0xA6C9EF3E3D0FE713ULL,
		0x11F085E5BA70BBDBULL,
		0x8D95D6863E1380F8ULL,
		0x0FEFC9D3CF602672ULL,
		0xADD0738AAB658082ULL,
		0x7F343D1549F2CDA2ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8193B16F3D49DAC6ULL,
		0x2D23600763A61F0FULL,
		0x211C46D94C079F73ULL,
		0x685F956A1CFF4C84ULL,
		0xB0C338730746E324ULL,
		0xA29250718D6D5137ULL,
		0x76A6659C9CD63C53ULL,
		0x16EEC614CF6C96D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x032762DE7A93B58CULL,
		0x5A46C00EC74C3E1FULL,
		0x42388DB2980F3EE6ULL,
		0xD0BF2AD439FE9908ULL,
		0x618670E60E8DC648ULL,
		0x4524A0E31ADAA26FULL,
		0xED4CCB3939AC78A7ULL,
		0x2DDD8C299ED92DAEULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAD987EB33B31584EULL,
		0x24276FB606132CEFULL,
		0x8514AF96FDB5F14DULL,
		0x80166C3115D5CD10ULL,
		0xBC97BCBA460EBC31ULL,
		0x1DAFEED3064EF9F9ULL,
		0x5660B28691118973ULL,
		0x0CA6731119C1BC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B30FD667662B09CULL,
		0x484EDF6C0C2659DFULL,
		0x0A295F2DFB6BE29AULL,
		0x002CD8622BAB9A21ULL,
		0x792F79748C1D7863ULL,
		0x3B5FDDA60C9DF3F3ULL,
		0xACC1650D222312E6ULL,
		0x194CE6223383793EULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA119C291E6087594ULL,
		0xAC8671AFB3E94F68ULL,
		0xE920CB72EF34E75EULL,
		0xD7D4BF29EBC486B1ULL,
		0xC3BAA4C93481693CULL,
		0x99AA9BA9D1CB9808ULL,
		0x6AB4E274EFEE4EF3ULL,
		0x24CBDA4219BA39D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42338523CC10EB28ULL,
		0x590CE35F67D29ED1ULL,
		0xD24196E5DE69CEBDULL,
		0xAFA97E53D7890D63ULL,
		0x877549926902D279ULL,
		0x33553753A3973011ULL,
		0xD569C4E9DFDC9DE7ULL,
		0x4997B484337473A6ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x81BFF13178FA88C4ULL,
		0x4FA9000898313DB0ULL,
		0xFDCDE91FB4D0A3B1ULL,
		0x2D966DA9A605F878ULL,
		0x3135C48321BF4942ULL,
		0xD3DB1E0CF6F1B319ULL,
		0xF0364DB339E9F148ULL,
		0x3B5E9DA7457E781DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x037FE262F1F51188ULL,
		0x9F52001130627B61ULL,
		0xFB9BD23F69A14762ULL,
		0x5B2CDB534C0BF0F1ULL,
		0x626B8906437E9284ULL,
		0xA7B63C19EDE36632ULL,
		0xE06C9B6673D3E291ULL,
		0x76BD3B4E8AFCF03BULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE87606D534E88841ULL,
		0xFB55E94835A8C3FCULL,
		0x1D16B8231BCAE5E3ULL,
		0x8BF8203E146BBAAEULL,
		0xECA23F289BAF0ED3ULL,
		0x2B0B649C3632D94BULL,
		0xBB19445F22871BECULL,
		0x0EB4234152CBD900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0EC0DAA69D11082ULL,
		0xF6ABD2906B5187F9ULL,
		0x3A2D70463795CBC7ULL,
		0x17F0407C28D7755CULL,
		0xD9447E51375E1DA7ULL,
		0x5616C9386C65B297ULL,
		0x763288BE450E37D8ULL,
		0x1D684682A597B201ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF59E0EA7BA69AA1FULL,
		0x8D899073E6B137AFULL,
		0xA22FD210C7428628ULL,
		0x75B97CF58679B9FAULL,
		0x5076AE90D48556AEULL,
		0x6C272E8650367E3FULL,
		0x6D4DE003A0461D4AULL,
		0x3DECFE0FD128E83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3C1D4F74D3543EULL,
		0x1B1320E7CD626F5FULL,
		0x445FA4218E850C51ULL,
		0xEB72F9EB0CF373F5ULL,
		0xA0ED5D21A90AAD5CULL,
		0xD84E5D0CA06CFC7EULL,
		0xDA9BC007408C3A94ULL,
		0x7BD9FC1FA251D074ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDB839E961B8D7BFAULL,
		0xDDB04638B408DF08ULL,
		0x27E13EB83CB290F1ULL,
		0xC4439E04247A3DB0ULL,
		0xC1EE74F49D9A0378ULL,
		0x8A42359056399B7AULL,
		0x2730C538B5ACE614ULL,
		0x24571B08DAC2C060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7073D2C371AF7F4ULL,
		0xBB608C716811BE11ULL,
		0x4FC27D70796521E3ULL,
		0x88873C0848F47B60ULL,
		0x83DCE9E93B3406F1ULL,
		0x14846B20AC7336F5ULL,
		0x4E618A716B59CC29ULL,
		0x48AE3611B58580C0ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x405B9355E81AE035ULL,
		0x347EE047EEA828DEULL,
		0x7507BBE71CADF144ULL,
		0x1255DAF07CDF3C87ULL,
		0x6EBFA4FFF4FFD293ULL,
		0x0531CC7A53F60234ULL,
		0x749F6791F96321D3ULL,
		0x38ABD378FA20FCE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80B726ABD035C06AULL,
		0x68FDC08FDD5051BCULL,
		0xEA0F77CE395BE288ULL,
		0x24ABB5E0F9BE790EULL,
		0xDD7F49FFE9FFA526ULL,
		0x0A6398F4A7EC0468ULL,
		0xE93ECF23F2C643A6ULL,
		0x7157A6F1F441F9D0ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAE9BBC5381EE5777ULL,
		0xBD9C590051CA8E9AULL,
		0x7654B96D3F1B5F98ULL,
		0xE063857F26AAFF9AULL,
		0xAC8E12D6EF66CA17ULL,
		0xC28A4B402637A61EULL,
		0xDEDF7552B29E39D5ULL,
		0x345A0DC1EAE79777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3778A703DCAEEEULL,
		0x7B38B200A3951D35ULL,
		0xECA972DA7E36BF31ULL,
		0xC0C70AFE4D55FF34ULL,
		0x591C25ADDECD942FULL,
		0x851496804C6F4C3DULL,
		0xBDBEEAA5653C73ABULL,
		0x68B41B83D5CF2EEFULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xCF0BD903CDA6C7D7ULL,
		0x5D706CF9D462EFCEULL,
		0x384CC8539C262064ULL,
		0xB23B70FA05138A08ULL,
		0xDE6FFCA328AE5AE9ULL,
		0x30A2E7862748EB84ULL,
		0xC9BDA4D983C4C1ABULL,
		0x01E317B2E51797FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E17B2079B4D8FAEULL,
		0xBAE0D9F3A8C5DF9DULL,
		0x709990A7384C40C8ULL,
		0x6476E1F40A271410ULL,
		0xBCDFF946515CB5D3ULL,
		0x6145CF0C4E91D709ULL,
		0x937B49B307898356ULL,
		0x03C62F65CA2F2FFFULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x34ECE337DF5E61D2ULL,
		0x856E4FBA2F2AFB15ULL,
		0x85B2B4F5C248BF03ULL,
		0x4D989422C057956FULL,
		0x04A894E9A61ABCDDULL,
		0x8DD0410214D35C92ULL,
		0xC0E2C3D2C2FF4C4CULL,
		0x283D01FA3E41E601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69D9C66FBEBCC3A4ULL,
		0x0ADC9F745E55F62AULL,
		0x0B6569EB84917E07ULL,
		0x9B31284580AF2ADFULL,
		0x095129D34C3579BAULL,
		0x1BA0820429A6B924ULL,
		0x81C587A585FE9899ULL,
		0x507A03F47C83CC03ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB241A6EE044A2A6BULL,
		0x699178DEFFDC8F0FULL,
		0x4B4DFFFA9D5C2CC1ULL,
		0xB429B4FB919590C0ULL,
		0x3760BD0D16FAC295ULL,
		0x1AD2A896182AFA49ULL,
		0x380160A770BAFD3FULL,
		0x127EE26A4323C341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64834DDC089454D6ULL,
		0xD322F1BDFFB91E1FULL,
		0x969BFFF53AB85982ULL,
		0x685369F7232B2180ULL,
		0x6EC17A1A2DF5852BULL,
		0x35A5512C3055F492ULL,
		0x7002C14EE175FA7EULL,
		0x24FDC4D486478682ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x44DBEB020B143BD7ULL,
		0x760E71FAD489AE3FULL,
		0x3C0CCB9369AF6684ULL,
		0x70EA79735970796EULL,
		0x23B1CEC0042FC0E0ULL,
		0x570DED7B091BBAFEULL,
		0x61B135E78D6D534EULL,
		0x3C526CDC74E4145CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89B7D604162877AEULL,
		0xEC1CE3F5A9135C7EULL,
		0x78199726D35ECD08ULL,
		0xE1D4F2E6B2E0F2DCULL,
		0x47639D80085F81C0ULL,
		0xAE1BDAF6123775FCULL,
		0xC3626BCF1ADAA69CULL,
		0x78A4D9B8E9C828B8ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7F74C7CAF68AFBE6ULL,
		0x9260D51A2BD3BD21ULL,
		0x4D9EB9A62B486019ULL,
		0xC1F4F96514C9DE8CULL,
		0x0DC0E7664F8CBD1BULL,
		0xBD7B7ECB876AC192ULL,
		0x5DF7D009E0742A20ULL,
		0x09CDEA9FC3E9E776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE98F95ED15F7CCULL,
		0x24C1AA3457A77A42ULL,
		0x9B3D734C5690C033ULL,
		0x83E9F2CA2993BD18ULL,
		0x1B81CECC9F197A37ULL,
		0x7AF6FD970ED58324ULL,
		0xBBEFA013C0E85441ULL,
		0x139BD53F87D3CEECULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x65BB0C9BAB1549C6ULL,
		0xD0909634C60DAEDAULL,
		0x5970719B44C022B7ULL,
		0x5A564C7D973357FFULL,
		0x7796E941C38A4B29ULL,
		0x7113D89D4B9FCD0EULL,
		0x6F497AC385DE8005ULL,
		0x33876E135DB9B7D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB761937562A938CULL,
		0xA1212C698C1B5DB4ULL,
		0xB2E0E3368980456FULL,
		0xB4AC98FB2E66AFFEULL,
		0xEF2DD28387149652ULL,
		0xE227B13A973F9A1CULL,
		0xDE92F5870BBD000AULL,
		0x670EDC26BB736FA8ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x015235EE85AA3DC7ULL,
		0x20AC66E8951C66F1ULL,
		0xC588990B5573EC5BULL,
		0xBB3560B741AA1CB5ULL,
		0x01B94BC185EB6717ULL,
		0x576C39C3D3D87FD0ULL,
		0x3B2B9F2606029567ULL,
		0x3D98B2E8E8241889ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A46BDD0B547B8EULL,
		0x4158CDD12A38CDE2ULL,
		0x8B113216AAE7D8B6ULL,
		0x766AC16E8354396BULL,
		0x037297830BD6CE2FULL,
		0xAED87387A7B0FFA0ULL,
		0x76573E4C0C052ACEULL,
		0x7B3165D1D0483112ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x95A15D3548E0B838ULL,
		0x2BCF2ECD01F5C3B9ULL,
		0xF91872F9BE228715ULL,
		0xB2AAC38FED0FA4A6ULL,
		0x0CE1BCA32628C43DULL,
		0x1A7BF9A5E2568D9CULL,
		0xBAC3DC4E20A4C7BDULL,
		0x3283A6F9F061E515ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B42BA6A91C17070ULL,
		0x579E5D9A03EB8773ULL,
		0xF230E5F37C450E2AULL,
		0x6555871FDA1F494DULL,
		0x19C379464C51887BULL,
		0x34F7F34BC4AD1B38ULL,
		0x7587B89C41498F7AULL,
		0x65074DF3E0C3CA2BULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8474249D57B255ADULL,
		0xB3D8532A992743ACULL,
		0x16A941E29AB5B0B4ULL,
		0xF59DBAB9D7EB8E20ULL,
		0xBAA3F8C844366539ULL,
		0x680D3BBA03C7F268ULL,
		0x20944ADBF19D51C4ULL,
		0x2E131F4C7B37495DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E8493AAF64AB5AULL,
		0x67B0A655324E8759ULL,
		0x2D5283C5356B6169ULL,
		0xEB3B7573AFD71C40ULL,
		0x7547F190886CCA73ULL,
		0xD01A7774078FE4D1ULL,
		0x412895B7E33AA388ULL,
		0x5C263E98F66E92BAULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5DE033E547B0F99FULL,
		0x45074D689092F1E5ULL,
		0xDAC8E2675915F561ULL,
		0xD0FB4501A70866F7ULL,
		0x741E6367E5626DC4ULL,
		0xE0159C8675F53BD2ULL,
		0x28F9FB07BB5404E4ULL,
		0x1676311EBE9E8ACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC067CA8F61F33EULL,
		0x8A0E9AD12125E3CAULL,
		0xB591C4CEB22BEAC2ULL,
		0xA1F68A034E10CDEFULL,
		0xE83CC6CFCAC4DB89ULL,
		0xC02B390CEBEA77A4ULL,
		0x51F3F60F76A809C9ULL,
		0x2CEC623D7D3D1596ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5D967619D9545CE5ULL,
		0x4EA2D5CF76963157ULL,
		0x015A3E7FC0B87B10ULL,
		0xB7915CC811E68195ULL,
		0x56E999201795D082ULL,
		0x001244E090F8F0CBULL,
		0x715358A10DCD2E40ULL,
		0x391BB18E85356720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2CEC33B2A8B9CAULL,
		0x9D45AB9EED2C62AEULL,
		0x02B47CFF8170F620ULL,
		0x6F22B99023CD032AULL,
		0xADD332402F2BA105ULL,
		0x002489C121F1E196ULL,
		0xE2A6B1421B9A5C80ULL,
		0x7237631D0A6ACE40ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x529DE6A49B075119ULL,
		0xCB06EE22AB84BDB8ULL,
		0xCFE2A906B01C713AULL,
		0x4AB9EC13E79BE327ULL,
		0x745E44218F81B5FAULL,
		0x060235157BD5E238ULL,
		0x393264C8A1D32733ULL,
		0x2989B917C234ECC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53BCD49360EA232ULL,
		0x960DDC4557097B70ULL,
		0x9FC5520D6038E275ULL,
		0x9573D827CF37C64FULL,
		0xE8BC88431F036BF4ULL,
		0x0C046A2AF7ABC470ULL,
		0x7264C99143A64E66ULL,
		0x5313722F8469D98AULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5CC69758906BF78CULL,
		0x373BDC2F2D109710ULL,
		0x180F2B461AA9D70CULL,
		0x04DAD48B84F501D5ULL,
		0x6459201453BE081EULL,
		0xD57EAC0FFD891BB4ULL,
		0x3D357999291D45E3ULL,
		0x2CE17246E4F9FEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98D2EB120D7EF18ULL,
		0x6E77B85E5A212E20ULL,
		0x301E568C3553AE18ULL,
		0x09B5A91709EA03AAULL,
		0xC8B24028A77C103CULL,
		0xAAFD581FFB123768ULL,
		0x7A6AF332523A8BC7ULL,
		0x59C2E48DC9F3FD4EULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF04572F7FA9933D6ULL,
		0xE5F9C78E5AA4CA5DULL,
		0x4CA708D9F47EA6C6ULL,
		0x9973C025D92FA469ULL,
		0x670D7DE5B359A95DULL,
		0x5F61D12B128A1726ULL,
		0x85766A3439EF150AULL,
		0x37C40F9B047055BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08AE5EFF53267ACULL,
		0xCBF38F1CB54994BBULL,
		0x994E11B3E8FD4D8DULL,
		0x32E7804BB25F48D2ULL,
		0xCE1AFBCB66B352BBULL,
		0xBEC3A25625142E4CULL,
		0x0AECD46873DE2A14ULL,
		0x6F881F3608E0AB79ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xAE1DA1CD7DC1C575ULL,
		0x7375B62382F5FF17ULL,
		0x4120D56757D9FC93ULL,
		0xE5BF679C0745FDF2ULL,
		0x8CF30CDC514D30AFULL,
		0xEDD4AC147EC8E3A3ULL,
		0xBEE852179DB60D79ULL,
		0x1ED94DE2B5395DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3B439AFB838AEAULL,
		0xE6EB6C4705EBFE2FULL,
		0x8241AACEAFB3F926ULL,
		0xCB7ECF380E8BFBE4ULL,
		0x19E619B8A29A615FULL,
		0xDBA95828FD91C747ULL,
		0x7DD0A42F3B6C1AF3ULL,
		0x3DB29BC56A72BB63ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA7267FE4F66969A6ULL,
		0x09B6E29994092D3AULL,
		0x99185457A2C94237ULL,
		0x8DEADFCE1B8EC0F1ULL,
		0xD2CA860075543A29ULL,
		0x2D8A353F2729CB03ULL,
		0x8127644472568865ULL,
		0x2792C1640A13A31CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E4CFFC9ECD2D34CULL,
		0x136DC53328125A75ULL,
		0x3230A8AF4592846EULL,
		0x1BD5BF9C371D81E3ULL,
		0xA5950C00EAA87453ULL,
		0x5B146A7E4E539607ULL,
		0x024EC888E4AD10CAULL,
		0x4F2582C814274639ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5F1C42A87DD65E16ULL,
		0xD2B0D1754501E2EFULL,
		0xBBBC0DC93BE4AEBBULL,
		0x6E809380D017EAEFULL,
		0xD696501BF0E14D19ULL,
		0x3A7192BB9D2879E1ULL,
		0x58F5479240DFCB01ULL,
		0x1C93C2DC29D06A68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE388550FBACBC2CULL,
		0xA561A2EA8A03C5DEULL,
		0x77781B9277C95D77ULL,
		0xDD012701A02FD5DFULL,
		0xAD2CA037E1C29A32ULL,
		0x74E325773A50F3C3ULL,
		0xB1EA8F2481BF9602ULL,
		0x392785B853A0D4D0ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1BF2ED7948C06078ULL,
		0x0FB71EDF88652A8CULL,
		0x47589228F06C57B7ULL,
		0x72155DA568B7C2EBULL,
		0x467EEF81605E81ECULL,
		0xA16531F02C7FC2EBULL,
		0x71D3F230654E6AA2ULL,
		0x16A6BA2B7AECA7F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E5DAF29180C0F0ULL,
		0x1F6E3DBF10CA5518ULL,
		0x8EB12451E0D8AF6EULL,
		0xE42ABB4AD16F85D6ULL,
		0x8CFDDF02C0BD03D8ULL,
		0x42CA63E058FF85D6ULL,
		0xE3A7E460CA9CD545ULL,
		0x2D4D7456F5D94FEAULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x45140CDDB8A5E0DDULL,
		0x9A437CD4047EBD7DULL,
		0xDEE9A99E7B68C023ULL,
		0x55CBE3F7F714EE2EULL,
		0xED2EDF6469816346ULL,
		0x8ADBE51FAE371200ULL,
		0x35F950FD78805A0EULL,
		0x0E4CC5453A541F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A2819BB714BC1BAULL,
		0x3486F9A808FD7AFAULL,
		0xBDD3533CF6D18047ULL,
		0xAB97C7EFEE29DC5DULL,
		0xDA5DBEC8D302C68CULL,
		0x15B7CA3F5C6E2401ULL,
		0x6BF2A1FAF100B41DULL,
		0x1C998A8A74A83E20ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3ABCBF978B24AC9BULL,
		0x97EF0FE812FEE194ULL,
		0x1D348EAB67F05A08ULL,
		0xD4EA851204A340C7ULL,
		0xA928DB312BDACB7AULL,
		0x28059B246D97CEC0ULL,
		0x578917136DCC4B3EULL,
		0x37686099B879B1D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75797F2F16495936ULL,
		0x2FDE1FD025FDC328ULL,
		0x3A691D56CFE0B411ULL,
		0xA9D50A240946818EULL,
		0x5251B66257B596F5ULL,
		0x500B3648DB2F9D81ULL,
		0xAF122E26DB98967CULL,
		0x6ED0C13370F363A2ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x03F2477164BA0DABULL,
		0x397CEF3385481983ULL,
		0xA317C8A6D6CCC4EDULL,
		0x7740B723953B18C6ULL,
		0x71A8FAA9108FD1E5ULL,
		0xB357B438A9BF49E7ULL,
		0xF7398D6D415E778CULL,
		0x3169B6EE1368E76DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E48EE2C9741B56ULL,
		0x72F9DE670A903306ULL,
		0x462F914DAD9989DAULL,
		0xEE816E472A76318DULL,
		0xE351F552211FA3CAULL,
		0x66AF6871537E93CEULL,
		0xEE731ADA82BCEF19ULL,
		0x62D36DDC26D1CEDBULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA4D647E7AE04230AULL,
		0x82343E884175F4FFULL,
		0x9B09B66672DFA790ULL,
		0xED69E3BAD27C74D3ULL,
		0x4FE725646AF36E32ULL,
		0x098E523791163FE2ULL,
		0x10C39E4601F69E51ULL,
		0x1A3D03EEC482187BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AC8FCF5C084614ULL,
		0x04687D1082EBE9FFULL,
		0x36136CCCE5BF4F21ULL,
		0xDAD3C775A4F8E9A7ULL,
		0x9FCE4AC8D5E6DC65ULL,
		0x131CA46F222C7FC4ULL,
		0x21873C8C03ED3CA2ULL,
		0x347A07DD890430F6ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x484E2396518F189BULL,
		0xFA9FA7D558CE68F0ULL,
		0x6C1EA3F03D3EAF8CULL,
		0x2B448F6E65490129ULL,
		0x50B2203826EC4BE6ULL,
		0xE3E6DD61DB7A4517ULL,
		0x0F5EFE6BF9282F3CULL,
		0x2193F21503536C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909C472CA31E3136ULL,
		0xF53F4FAAB19CD1E0ULL,
		0xD83D47E07A7D5F19ULL,
		0x56891EDCCA920252ULL,
		0xA16440704DD897CCULL,
		0xC7CDBAC3B6F48A2EULL,
		0x1EBDFCD7F2505E79ULL,
		0x4327E42A06A6D93EULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7D2929F75D6F3A95ULL,
		0xCEC64E649487A171ULL,
		0x144EF27957DA2299ULL,
		0x0A9FA99EA9BE2519ULL,
		0x5CF3E5D7B94AAC0AULL,
		0xB74CB1CBA5F5F722ULL,
		0xB76C227D7B36CA6BULL,
		0x0E51094CC31862D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA5253EEBADE752AULL,
		0x9D8C9CC9290F42E2ULL,
		0x289DE4F2AFB44533ULL,
		0x153F533D537C4A32ULL,
		0xB9E7CBAF72955814ULL,
		0x6E9963974BEBEE44ULL,
		0x6ED844FAF66D94D7ULL,
		0x1CA212998630C5A7ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4726D3AF4B219ABFULL,
		0x09C95C67CB93BFD2ULL,
		0xFDCCA0C56F315058ULL,
		0x8CA4E58DBB436691ULL,
		0xF6117989A5E11074ULL,
		0x92B00A4B8140A2FFULL,
		0x4B726C5DD38E28D8ULL,
		0x0DAD059D11251DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E4DA75E9643357EULL,
		0x1392B8CF97277FA4ULL,
		0xFB99418ADE62A0B0ULL,
		0x1949CB1B7686CD23ULL,
		0xEC22F3134BC220E9ULL,
		0x25601497028145FFULL,
		0x96E4D8BBA71C51B1ULL,
		0x1B5A0B3A224A3BE4ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x56D7A657D5EC00BAULL,
		0x222EB97259A3C6BDULL,
		0x742EA72D35F8D0BDULL,
		0xC9F851F342845ACEULL,
		0x6D54C85F7754A275ULL,
		0x077430E62C46244CULL,
		0xDBD82F1DD87D8F21ULL,
		0x088F91395136BD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADAF4CAFABD80174ULL,
		0x445D72E4B3478D7AULL,
		0xE85D4E5A6BF1A17AULL,
		0x93F0A3E68508B59CULL,
		0xDAA990BEEEA944EBULL,
		0x0EE861CC588C4898ULL,
		0xB7B05E3BB0FB1E42ULL,
		0x111F2272A26D7A39ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8648BEFF5000D76AULL,
		0xA9DBF015581255C2ULL,
		0xADF4E0DB72B45B46ULL,
		0xEA28B772719397B3ULL,
		0xBCC6AFBBA19F0C95ULL,
		0xC5EB84C7DD453B61ULL,
		0xB0F3019C633912AEULL,
		0x043AB3A2C512B971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C917DFEA001AED4ULL,
		0x53B7E02AB024AB85ULL,
		0x5BE9C1B6E568B68DULL,
		0xD4516EE4E3272F67ULL,
		0x798D5F77433E192BULL,
		0x8BD7098FBA8A76C3ULL,
		0x61E60338C672255DULL,
		0x087567458A2572E3ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0A33F26185C21AF6ULL,
		0xA39F62207F3295B6ULL,
		0x2137ADE3E6701380ULL,
		0x219B21C884437A04ULL,
		0xB573970E96BE5EBBULL,
		0xE2284039F212BB16ULL,
		0xB3EF90004D95D07AULL,
		0x38D675229A34A7B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1467E4C30B8435ECULL,
		0x473EC440FE652B6CULL,
		0x426F5BC7CCE02701ULL,
		0x433643910886F408ULL,
		0x6AE72E1D2D7CBD76ULL,
		0xC4508073E425762DULL,
		0x67DF20009B2BA0F5ULL,
		0x71ACEA4534694F67ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF79398ECEEF937D2ULL,
		0x340027A82D1FA3A2ULL,
		0xC26895E3EF8828D7ULL,
		0x263B24ED9B4EDACDULL,
		0x118DE95BB0AF4A14ULL,
		0x8AEFB9AFB143D805ULL,
		0xA5B69E26EDFEAC8EULL,
		0x122FECA9E9AF15ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF2731D9DDF26FA4ULL,
		0x68004F505A3F4745ULL,
		0x84D12BC7DF1051AEULL,
		0x4C7649DB369DB59BULL,
		0x231BD2B7615E9428ULL,
		0x15DF735F6287B00AULL,
		0x4B6D3C4DDBFD591DULL,
		0x245FD953D35E2B57ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x17EB559A06C6761AULL,
		0x2592AF4CB0092665ULL,
		0x4D70F3BC5972A51BULL,
		0xF0970DB6D6EBC428ULL,
		0xC5EE220AAFE338D1ULL,
		0x10B3F5CF1B3B98B9ULL,
		0x0D2E3FB5D1767859ULL,
		0x17BDC321DE15B209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD6AB340D8CEC34ULL,
		0x4B255E9960124CCAULL,
		0x9AE1E778B2E54A36ULL,
		0xE12E1B6DADD78850ULL,
		0x8BDC44155FC671A3ULL,
		0x2167EB9E36773173ULL,
		0x1A5C7F6BA2ECF0B2ULL,
		0x2F7B8643BC2B6412ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFAA6300BD8810F21ULL,
		0xADAC65F8FC19D960ULL,
		0xFC8825904AFD451FULL,
		0x534D0DE2A3B7A283ULL,
		0xAE2F801EFD05A686ULL,
		0x8641048240E1647BULL,
		0xFA28A6EE734A6836ULL,
		0x286C2B74011B363FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF54C6017B1021E42ULL,
		0x5B58CBF1F833B2C1ULL,
		0xF9104B2095FA8A3FULL,
		0xA69A1BC5476F4507ULL,
		0x5C5F003DFA0B4D0CULL,
		0x0C82090481C2C8F7ULL,
		0xF4514DDCE694D06DULL,
		0x50D856E802366C7FULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x880BAC6B240C2706ULL,
		0x5EBF5FBEACA18255ULL,
		0xF23B3C2079A1730DULL,
		0x2DB55A9825BCEA0EULL,
		0x2C6AB76969D61584ULL,
		0x41A132C8D34CED2FULL,
		0xE4D4347628B43775ULL,
		0x1F60A6948EF637ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x101758D648184E0CULL,
		0xBD7EBF7D594304ABULL,
		0xE4767840F342E61AULL,
		0x5B6AB5304B79D41DULL,
		0x58D56ED2D3AC2B08ULL,
		0x83426591A699DA5EULL,
		0xC9A868EC51686EEAULL,
		0x3EC14D291DEC6F59ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDF7C5BD85A9FCD01ULL,
		0x71FE6D4B4F3AE103ULL,
		0x23B6FAAF4EF83A3BULL,
		0x3A35677A4429EE69ULL,
		0x891F3B110752296AULL,
		0x4879C4F5924B097FULL,
		0xE0D2866EE3F561B7ULL,
		0x124A486669EE0B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEF8B7B0B53F9A02ULL,
		0xE3FCDA969E75C207ULL,
		0x476DF55E9DF07476ULL,
		0x746ACEF48853DCD2ULL,
		0x123E76220EA452D4ULL,
		0x90F389EB249612FFULL,
		0xC1A50CDDC7EAC36EULL,
		0x249490CCD3DC1665ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8473D0474BDBF25AULL,
		0xD04FFC431A0839E0ULL,
		0xABE07B6FF4FCAB78ULL,
		0xFD396025FF1AC2FAULL,
		0xBCD0A0C9C8E56E38ULL,
		0x9A5054014166DCC5ULL,
		0xA9FA9BFA0149713FULL,
		0x233113402102EFC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E7A08E97B7E4B4ULL,
		0xA09FF886341073C1ULL,
		0x57C0F6DFE9F956F1ULL,
		0xFA72C04BFE3585F5ULL,
		0x79A1419391CADC71ULL,
		0x34A0A80282CDB98BULL,
		0x53F537F40292E27FULL,
		0x466226804205DF8BULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA7E2F4FC9E9FDE7BULL,
		0x01F30131AE89E56AULL,
		0x9C75785F130D9034ULL,
		0x2E0AB789B2B8FCA2ULL,
		0x84F3671795C6C712ULL,
		0x51C2EC19C885EF34ULL,
		0x898B1EFA5A8D9425ULL,
		0x083F1E6BF0A47C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC5E9F93D3FBCF6ULL,
		0x03E602635D13CAD5ULL,
		0x38EAF0BE261B2068ULL,
		0x5C156F136571F945ULL,
		0x09E6CE2F2B8D8E24ULL,
		0xA385D833910BDE69ULL,
		0x13163DF4B51B284AULL,
		0x107E3CD7E148F82BULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x656A5D2CC6D13DBEULL,
		0x2A3925F913C186A3ULL,
		0x196237C800884234ULL,
		0xB0E46719959CCF6FULL,
		0xDC269B95BCB1E38EULL,
		0x0E041962259B0A81ULL,
		0x9E2B9B5C1F7798E8ULL,
		0x1DCF964B26041AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAD4BA598DA27B7CULL,
		0x54724BF227830D46ULL,
		0x32C46F9001108468ULL,
		0x61C8CE332B399EDEULL,
		0xB84D372B7963C71DULL,
		0x1C0832C44B361503ULL,
		0x3C5736B83EEF31D0ULL,
		0x3B9F2C964C0835EBULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x83F6702302728618ULL,
		0x49C6D16EF23944A1ULL,
		0x81026D5497210AA4ULL,
		0xFE3688C12719023EULL,
		0x954AC753208F461AULL,
		0xC7556BF7227213EAULL,
		0x629F2406CE2D5CE5ULL,
		0x0630D5A7251FD564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07ECE04604E50C30ULL,
		0x938DA2DDE4728943ULL,
		0x0204DAA92E421548ULL,
		0xFC6D11824E32047DULL,
		0x2A958EA6411E8C35ULL,
		0x8EAAD7EE44E427D5ULL,
		0xC53E480D9C5AB9CBULL,
		0x0C61AB4E4A3FAAC8ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x58022EF1958369BDULL,
		0xBBC71481FDCEF419ULL,
		0x055478DD26E4109EULL,
		0x2EB9775EB55853B8ULL,
		0xB472EC077F28B641ULL,
		0xA719649BC3E7E592ULL,
		0x06D5A6DA6E5B79A6ULL,
		0x1B73D806728B6A1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0045DE32B06D37AULL,
		0x778E2903FB9DE832ULL,
		0x0AA8F1BA4DC8213DULL,
		0x5D72EEBD6AB0A770ULL,
		0x68E5D80EFE516C82ULL,
		0x4E32C93787CFCB25ULL,
		0x0DAB4DB4DCB6F34DULL,
		0x36E7B00CE516D43CULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDBF8C4D69CA4BE35ULL,
		0x8F7916068A5CDE4FULL,
		0x447AEB307810B21EULL,
		0xEA4B78613294208AULL,
		0xEC01350125BB022BULL,
		0x55627A6DCA0BB157ULL,
		0x6F77EB5CFE5016E2ULL,
		0x2141EFFBFD969065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F189AD39497C6AULL,
		0x1EF22C0D14B9BC9FULL,
		0x88F5D660F021643DULL,
		0xD496F0C265284114ULL,
		0xD8026A024B760457ULL,
		0xAAC4F4DB941762AFULL,
		0xDEEFD6B9FCA02DC4ULL,
		0x4283DFF7FB2D20CAULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x984CB20AD5F27B94ULL,
		0xCFF1A982A13F4704ULL,
		0x8D1EB27D3B5E1B5CULL,
		0x52D004DFDC3BE084ULL,
		0xABC2D17D78A70D93ULL,
		0x6E555551BF625002ULL,
		0x0313D444E640D908ULL,
		0x3C96E3FA893FA1A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30996415ABE4F728ULL,
		0x9FE35305427E8E09ULL,
		0x1A3D64FA76BC36B9ULL,
		0xA5A009BFB877C109ULL,
		0x5785A2FAF14E1B26ULL,
		0xDCAAAAA37EC4A005ULL,
		0x0627A889CC81B210ULL,
		0x792DC7F5127F4352ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC176F4A38E9D4C4AULL,
		0x5022D4EA703B7F55ULL,
		0xB2423422B11DBDA6ULL,
		0x70D2B0FBE536F18CULL,
		0xF486A6EC17E0D47FULL,
		0x5016924ED202408AULL,
		0x797BA2E6697F9BA0ULL,
		0x1B476B64497910C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EDE9471D3A9894ULL,
		0xA045A9D4E076FEABULL,
		0x64846845623B7B4CULL,
		0xE1A561F7CA6DE319ULL,
		0xE90D4DD82FC1A8FEULL,
		0xA02D249DA4048115ULL,
		0xF2F745CCD2FF3740ULL,
		0x368ED6C892F22182ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7EE0F3F1F5B4C872ULL,
		0x9184AAE593D1A6D0ULL,
		0x2AF153D4BC28947AULL,
		0x48ED33723A1A01B0ULL,
		0x9DB43298C41D0CCAULL,
		0xECD081A1F7104BFBULL,
		0xF41B1310589FC7AFULL,
		0x17B1967B579D0076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC1E7E3EB6990E4ULL,
		0x230955CB27A34DA0ULL,
		0x55E2A7A9785128F5ULL,
		0x91DA66E474340360ULL,
		0x3B686531883A1994ULL,
		0xD9A10343EE2097F7ULL,
		0xE8362620B13F8F5FULL,
		0x2F632CF6AF3A00EDULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x52473D6198356AECULL,
		0xA74A57404BD8F4D5ULL,
		0xACF9F8C296061388ULL,
		0x4547BA512BF562B1ULL,
		0x47551D9704814E4FULL,
		0x7D14E43084BBDC11ULL,
		0xCFBD6F0127A8E79EULL,
		0x3302B5B4FDA6DE65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA48E7AC3306AD5D8ULL,
		0x4E94AE8097B1E9AAULL,
		0x59F3F1852C0C2711ULL,
		0x8A8F74A257EAC563ULL,
		0x8EAA3B2E09029C9EULL,
		0xFA29C8610977B822ULL,
		0x9F7ADE024F51CF3CULL,
		0x66056B69FB4DBCCBULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x66546DB664FC32F6ULL,
		0xC510634ABBC7963AULL,
		0xF0BD635E5931D645ULL,
		0x69AAC25162569E31ULL,
		0x2C794FE1BF7A6DFCULL,
		0x49CC2504220801D2ULL,
		0x8BCE3642B837568FULL,
		0x30C8DE31C42BA878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA8DB6CC9F865ECULL,
		0x8A20C695778F2C74ULL,
		0xE17AC6BCB263AC8BULL,
		0xD35584A2C4AD3C63ULL,
		0x58F29FC37EF4DBF8ULL,
		0x93984A08441003A4ULL,
		0x179C6C85706EAD1EULL,
		0x6191BC63885750F1ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x922D1AEBC356DB91ULL,
		0xAE1F9FCC389B4014ULL,
		0x17DBA3001CF8BEF6ULL,
		0xB555C29927BA8740ULL,
		0xD375DC4E305590BCULL,
		0xF6917D132458E60BULL,
		0xCFF66E2A358F723EULL,
		0x1768EC745E558763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x245A35D786ADB722ULL,
		0x5C3F3F9871368029ULL,
		0x2FB7460039F17DEDULL,
		0x6AAB85324F750E80ULL,
		0xA6EBB89C60AB2179ULL,
		0xED22FA2648B1CC17ULL,
		0x9FECDC546B1EE47DULL,
		0x2ED1D8E8BCAB0EC7ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5267BBF2D57DDB66ULL,
		0xDFC151FFC9034516ULL,
		0xEE0C5418AEF5C9A0ULL,
		0xB6D5DAA6A4EC0FDEULL,
		0x29038532E80303F0ULL,
		0x321E50C51B054538ULL,
		0x00F13DC930F9D4F2ULL,
		0x157B9F480FB38319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CF77E5AAFBB6CCULL,
		0xBF82A3FF92068A2CULL,
		0xDC18A8315DEB9341ULL,
		0x6DABB54D49D81FBDULL,
		0x52070A65D00607E1ULL,
		0x643CA18A360A8A70ULL,
		0x01E27B9261F3A9E4ULL,
		0x2AF73E901F670632ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x770D99307A039AADULL,
		0x259E5686C83FFDEAULL,
		0x3DA1BE5E5B108415ULL,
		0x0024D7DE55007AA6ULL,
		0xCFBAF64989804B2FULL,
		0x710F3637217927BDULL,
		0xF6CF48D147BBCC47ULL,
		0x1A8CE1BB89C5D968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1B3260F407355AULL,
		0x4B3CAD0D907FFBD4ULL,
		0x7B437CBCB621082AULL,
		0x0049AFBCAA00F54CULL,
		0x9F75EC931300965EULL,
		0xE21E6C6E42F24F7BULL,
		0xED9E91A28F77988EULL,
		0x3519C377138BB2D1ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC2C4CA4A47D0CD6EULL,
		0xFC2AE5A35875BA69ULL,
		0xEDB4782B94376672ULL,
		0x0D72A2012C43A066ULL,
		0x58F2C3456A01B827ULL,
		0xA2C65FE8B31BAF31ULL,
		0x63CECEEE9A6060D3ULL,
		0x2CFDC55A5FF1D1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x858994948FA19ADCULL,
		0xF855CB46B0EB74D3ULL,
		0xDB68F057286ECCE5ULL,
		0x1AE54402588740CDULL,
		0xB1E5868AD403704EULL,
		0x458CBFD166375E62ULL,
		0xC79D9DDD34C0C1A7ULL,
		0x59FB8AB4BFE3A360ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x03DBDDD336B87E6DULL,
		0x09244307FFCDD797ULL,
		0x0A0A8690EE044CE6ULL,
		0xB019B7BF4443C502ULL,
		0x38BC91FD4E77BEA6ULL,
		0xEEED35C9C7485F58ULL,
		0xB363FA7BBDA3FD9FULL,
		0x35279EECBC0F9F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07B7BBA66D70FCDAULL,
		0x1248860FFF9BAF2EULL,
		0x14150D21DC0899CCULL,
		0x60336F7E88878A04ULL,
		0x717923FA9CEF7D4DULL,
		0xDDDA6B938E90BEB0ULL,
		0x66C7F4F77B47FB3FULL,
		0x6A4F3DD9781F3E59ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1F116D01D3DD65D1ULL,
		0xEE4D8ACFA7DBD7DCULL,
		0xF5A384CDC5CA9719ULL,
		0x0CBC070308E0DCD9ULL,
		0x3B6A46A1CCD73521ULL,
		0xBA9ECD15C0DBB52DULL,
		0x839F6C3FC6ADF744ULL,
		0x1333E5A8528939D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E22DA03A7BACBA2ULL,
		0xDC9B159F4FB7AFB8ULL,
		0xEB47099B8B952E33ULL,
		0x19780E0611C1B9B3ULL,
		0x76D48D4399AE6A42ULL,
		0x753D9A2B81B76A5AULL,
		0x073ED87F8D5BEE89ULL,
		0x2667CB50A51273A3ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE16DC18AD492857AULL,
		0x6B73DF8660F8FF26ULL,
		0x36F15DFAD04FC17BULL,
		0x958DC5821E12E3CCULL,
		0xCDE0D7A69FFA0BF1ULL,
		0x372260DBA1928022ULL,
		0xE2C588AA8078D65DULL,
		0x3D377784BE8166E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2DB8315A9250AF4ULL,
		0xD6E7BF0CC1F1FE4DULL,
		0x6DE2BBF5A09F82F6ULL,
		0x2B1B8B043C25C798ULL,
		0x9BC1AF4D3FF417E3ULL,
		0x6E44C1B743250045ULL,
		0xC58B115500F1ACBAULL,
		0x7A6EEF097D02CDD3ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x802F724B924C6046ULL,
		0x440909C569C6FA6EULL,
		0xFD845C7FB296F3B6ULL,
		0x6D0AC514F2A8F40DULL,
		0x617E14134A3AB707ULL,
		0x4B8D75BABAA84AF2ULL,
		0xFA10992A15529F6CULL,
		0x21A3931864400FF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x005EE4972498C08CULL,
		0x8812138AD38DF4DDULL,
		0xFB08B8FF652DE76CULL,
		0xDA158A29E551E81BULL,
		0xC2FC282694756E0EULL,
		0x971AEB75755095E4ULL,
		0xF42132542AA53ED8ULL,
		0x43472630C8801FF1ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD5D610B39E03CB55ULL,
		0x091582F530A26170ULL,
		0x212B3503431D1317ULL,
		0xBC6BD44C866CDB3FULL,
		0x35F79CD9EAA57B14ULL,
		0x7F453025273861CDULL,
		0x5C139681BFAFA957ULL,
		0x3F4103CF325FFA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABAC21673C0796AAULL,
		0x122B05EA6144C2E1ULL,
		0x42566A06863A262EULL,
		0x78D7A8990CD9B67EULL,
		0x6BEF39B3D54AF629ULL,
		0xFE8A604A4E70C39AULL,
		0xB8272D037F5F52AEULL,
		0x7E82079E64BFF4FEULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3739F0D24984E20CULL,
		0x61AA0E39437DB3C4ULL,
		0x106068CB3522474FULL,
		0x15C5BF844B47EE5FULL,
		0x16E65D325642BE13ULL,
		0xC264E660DD0214DBULL,
		0x6083C2454E859FBAULL,
		0x38BFAA9CA1A9A687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E73E1A49309C418ULL,
		0xC3541C7286FB6788ULL,
		0x20C0D1966A448E9EULL,
		0x2B8B7F08968FDCBEULL,
		0x2DCCBA64AC857C26ULL,
		0x84C9CCC1BA0429B6ULL,
		0xC107848A9D0B3F75ULL,
		0x717F553943534D0EULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7FA2C15BBA962D3AULL,
		0x80CAFBDD0992292BULL,
		0xAC082FD02D6907A5ULL,
		0x45251B5F71C75A80ULL,
		0x7DB22689D7FB5895ULL,
		0xA5578EAAA080AE81ULL,
		0x1608100D9A03EB42ULL,
		0x3E1539E605AB3661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4582B7752C5A74ULL,
		0x0195F7BA13245256ULL,
		0x58105FA05AD20F4BULL,
		0x8A4A36BEE38EB501ULL,
		0xFB644D13AFF6B12AULL,
		0x4AAF1D5541015D02ULL,
		0x2C10201B3407D685ULL,
		0x7C2A73CC0B566CC2ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x86A0932016233F0EULL,
		0xC7B95119635188ADULL,
		0xF61868570A7FB6C5ULL,
		0xE85051B4DF712001ULL,
		0x0C6BFEF0D7C8E68CULL,
		0x8085BDF73A391D5DULL,
		0x9672B3E4BB280F61ULL,
		0x305C076E3E0F4667ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D4126402C467E1CULL,
		0x8F72A232C6A3115BULL,
		0xEC30D0AE14FF6D8BULL,
		0xD0A0A369BEE24003ULL,
		0x18D7FDE1AF91CD19ULL,
		0x010B7BEE74723ABAULL,
		0x2CE567C976501EC3ULL,
		0x60B80EDC7C1E8CCFULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9580B1FB04711B88ULL,
		0xA3BFED91014C595CULL,
		0x754026901EBE1220ULL,
		0x4BEF34CF29509C56ULL,
		0xFDDA1B89C439987DULL,
		0x3D0DF0DD70D773A1ULL,
		0xC8A6C231FE07D5E1ULL,
		0x1DFF4A7C723C4D36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B0163F608E23710ULL,
		0x477FDB220298B2B9ULL,
		0xEA804D203D7C2441ULL,
		0x97DE699E52A138ACULL,
		0xFBB43713887330FAULL,
		0x7A1BE1BAE1AEE743ULL,
		0x914D8463FC0FABC2ULL,
		0x3BFE94F8E4789A6DULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA9738DE158092020ULL,
		0x015658A04AB84B5FULL,
		0x281583FB9E0395B1ULL,
		0x2E3DEBDC89FB5F3BULL,
		0x70719277E05CE9F8ULL,
		0x90634DAD67C0BF16ULL,
		0xE69CAC3C83FF8A01ULL,
		0x13573B4D070C3AD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E71BC2B0124040ULL,
		0x02ACB140957096BFULL,
		0x502B07F73C072B62ULL,
		0x5C7BD7B913F6BE76ULL,
		0xE0E324EFC0B9D3F0ULL,
		0x20C69B5ACF817E2CULL,
		0xCD39587907FF1403ULL,
		0x26AE769A0E1875A1ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x65B49A4A7EB41F80ULL,
		0x8C8B949C2E9D272BULL,
		0x5133A34966EC1AA8ULL,
		0xBE9C97A9A15D1941ULL,
		0xF4E010048CBC54EDULL,
		0x8EB2A663BAF1B5EBULL,
		0x142F7431229D7D0CULL,
		0x25DCD4604DAF3DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB693494FD683F00ULL,
		0x191729385D3A4E56ULL,
		0xA2674692CDD83551ULL,
		0x7D392F5342BA3282ULL,
		0xE9C020091978A9DBULL,
		0x1D654CC775E36BD7ULL,
		0x285EE862453AFA19ULL,
		0x4BB9A8C09B5E7BA4ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5FDF8F290129EA52ULL,
		0x22F11EE31BB35CA8ULL,
		0xBB24A75BEA938877ULL,
		0xB5EC814C612F37FDULL,
		0xA0040A6910880818ULL,
		0x46C79A2522FD2A9AULL,
		0x927B8E358CD77CD6ULL,
		0x13018680D60B2829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFBF1E520253D4A4ULL,
		0x45E23DC63766B950ULL,
		0x76494EB7D52710EEULL,
		0x6BD90298C25E6FFBULL,
		0x400814D221101031ULL,
		0x8D8F344A45FA5535ULL,
		0x24F71C6B19AEF9ACULL,
		0x26030D01AC165053ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB4497736BEE3C4EDULL,
		0x0708E4F5D2EF72A1ULL,
		0x15872EEBD20F846BULL,
		0x75801476B6B77375ULL,
		0xD7FFCB43EC68C16BULL,
		0x58D0396D5F76FD20ULL,
		0xA1E667F7983C3313ULL,
		0x1C329EF99CCB938DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6892EE6D7DC789DAULL,
		0x0E11C9EBA5DEE543ULL,
		0x2B0E5DD7A41F08D6ULL,
		0xEB0028ED6D6EE6EAULL,
		0xAFFF9687D8D182D6ULL,
		0xB1A072DABEEDFA41ULL,
		0x43CCCFEF30786626ULL,
		0x38653DF33997271BULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB558F9EE41DEE9DEULL,
		0x8E8FBF98C105E952ULL,
		0xC810FBC41E9369ADULL,
		0x8F4474C0B35A2C29ULL,
		0xCED1242F4D604F14ULL,
		0xBAD0D92882059710ULL,
		0xCCEFE360DC4524FFULL,
		0x2A6ED782E9B51D1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AB1F3DC83BDD3BCULL,
		0x1D1F7F31820BD2A5ULL,
		0x9021F7883D26D35BULL,
		0x1E88E98166B45853ULL,
		0x9DA2485E9AC09E29ULL,
		0x75A1B251040B2E21ULL,
		0x99DFC6C1B88A49FFULL,
		0x54DDAF05D36A3A3DULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1A1E16E30077401EULL,
		0x6E840A15E42B6B34ULL,
		0xBF4A48C4D1931F3DULL,
		0xD19AC36423D5F067ULL,
		0xA149F3E60B34B223ULL,
		0x8CB2188DFC91EE91ULL,
		0x0A56B51C3DE62BB1ULL,
		0x345307D7C4057242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x343C2DC600EE803CULL,
		0xDD08142BC856D668ULL,
		0x7E949189A3263E7AULL,
		0xA33586C847ABE0CFULL,
		0x4293E7CC16696447ULL,
		0x1964311BF923DD23ULL,
		0x14AD6A387BCC5763ULL,
		0x68A60FAF880AE484ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x06BEEFD24B09BCD2ULL,
		0x8762B03429E21BECULL,
		0x0D6FBC58FB37A31AULL,
		0x693961A315812B27ULL,
		0x359E4E58E535D6E7ULL,
		0x20C62CF86810C5D2ULL,
		0x05B09123C5694621ULL,
		0x3DFB193FE27D57C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7DDFA4961379A4ULL,
		0x0EC5606853C437D8ULL,
		0x1ADF78B1F66F4635ULL,
		0xD272C3462B02564EULL,
		0x6B3C9CB1CA6BADCEULL,
		0x418C59F0D0218BA4ULL,
		0x0B6122478AD28C42ULL,
		0x7BF6327FC4FAAF90ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x72C5CCE8C924DFE0ULL,
		0x373C83B06D5C9A7BULL,
		0x1AF1FD536B0662CAULL,
		0x396819AB0A21621DULL,
		0x413143A3DCBC9B25ULL,
		0x0EABBEBA686B8EA6ULL,
		0x2BB782430A66B272ULL,
		0x35C23EADBFF75C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE58B99D19249BFC0ULL,
		0x6E790760DAB934F6ULL,
		0x35E3FAA6D60CC594ULL,
		0x72D033561442C43AULL,
		0x82628747B979364AULL,
		0x1D577D74D0D71D4CULL,
		0x576F048614CD64E4ULL,
		0x6B847D5B7FEEB836ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x04FECD5CE1456BF5ULL,
		0xC5660EB99145C7CCULL,
		0xD05791689A09ADD8ULL,
		0x4F3AB76D0F0B21F9ULL,
		0x0C0441BE63371B16ULL,
		0x0833EFFC1CE59BB8ULL,
		0xD99E3B65A82A0DDFULL,
		0x31B5C0A12AE9F1F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FD9AB9C28AD7EAULL,
		0x8ACC1D73228B8F98ULL,
		0xA0AF22D134135BB1ULL,
		0x9E756EDA1E1643F3ULL,
		0x1808837CC66E362CULL,
		0x1067DFF839CB3770ULL,
		0xB33C76CB50541BBEULL,
		0x636B814255D3E3E5ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE9A8A0767A90583CULL,
		0xB33CD014E72D35E0ULL,
		0x571C9015810B6B9AULL,
		0x0C4AAD01212B75ADULL,
		0xB326246DEE74CF7DULL,
		0x8495319EBE963123ULL,
		0x0E47668DE9CE696AULL,
		0x1436036F70112556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35140ECF520B078ULL,
		0x6679A029CE5A6BC1ULL,
		0xAE39202B0216D735ULL,
		0x18955A024256EB5AULL,
		0x664C48DBDCE99EFAULL,
		0x092A633D7D2C6247ULL,
		0x1C8ECD1BD39CD2D5ULL,
		0x286C06DEE0224AACULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8ECCCD20CA7A219FULL,
		0xE0CA79CCFD363264ULL,
		0x012DD8DF2539DAAEULL,
		0x092703D8976DDDF9ULL,
		0x974316345D071447ULL,
		0xF7A6549BA2151AFAULL,
		0x9F67E3A2D85290B3ULL,
		0x03E24A69867CD2EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D999A4194F4433EULL,
		0xC194F399FA6C64C9ULL,
		0x025BB1BE4A73B55DULL,
		0x124E07B12EDBBBF2ULL,
		0x2E862C68BA0E288EULL,
		0xEF4CA937442A35F5ULL,
		0x3ECFC745B0A52167ULL,
		0x07C494D30CF9A5D5ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x30F63E23DF7988C2ULL,
		0xE0DE13CBFB97F73EULL,
		0x182BB10C4B1A8405ULL,
		0x0F08EEE9016D07BDULL,
		0x35A5B96377636CF2ULL,
		0x7FD3559DEDAC914CULL,
		0xC10CC06DEAD220AEULL,
		0x265445D5BDEA4998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61EC7C47BEF31184ULL,
		0xC1BC2797F72FEE7CULL,
		0x305762189635080BULL,
		0x1E11DDD202DA0F7AULL,
		0x6B4B72C6EEC6D9E4ULL,
		0xFFA6AB3BDB592298ULL,
		0x821980DBD5A4415CULL,
		0x4CA88BAB7BD49331ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2BD6D74DB9A11436ULL,
		0x0075F94B946B0A54ULL,
		0x43FE8978AD92B835ULL,
		0x3029F03AE49E6C41ULL,
		0x7D49826EE31F28D5ULL,
		0xFCCCEF3F2BA36208ULL,
		0x81BF418984C35CA1ULL,
		0x39CF4B895F977025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57ADAE9B7342286CULL,
		0x00EBF29728D614A8ULL,
		0x87FD12F15B25706AULL,
		0x6053E075C93CD882ULL,
		0xFA9304DDC63E51AAULL,
		0xF999DE7E5746C410ULL,
		0x037E83130986B943ULL,
		0x739E9712BF2EE04BULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC868D200DEC55EBDULL,
		0x4BA2C78EFAA19305ULL,
		0xD82DB3BDC3F3D8F9ULL,
		0x46F35F8B5E582752ULL,
		0x8366726CC81CBE77ULL,
		0xCBF2046A8B9068C9ULL,
		0xA23069508D7DA488ULL,
		0x0D62D8D4D9AF32E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90D1A401BD8ABD7AULL,
		0x97458F1DF543260BULL,
		0xB05B677B87E7B1F2ULL,
		0x8DE6BF16BCB04EA5ULL,
		0x06CCE4D990397CEEULL,
		0x97E408D51720D193ULL,
		0x4460D2A11AFB4911ULL,
		0x1AC5B1A9B35E65CBULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x90301D9397CC1761ULL,
		0x145E66B79800B2DDULL,
		0xDBCEE873EB50F4C8ULL,
		0xEBCA645586A4452EULL,
		0xA07D9AECF8CABBAEULL,
		0x3EFC22752BC6CC5EULL,
		0xAFAFF5E910F6C1FBULL,
		0x0FE4DF13C2939438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20603B272F982EC2ULL,
		0x28BCCD6F300165BBULL,
		0xB79DD0E7D6A1E990ULL,
		0xD794C8AB0D488A5DULL,
		0x40FB35D9F195775DULL,
		0x7DF844EA578D98BDULL,
		0x5F5FEBD221ED83F6ULL,
		0x1FC9BE2785272871ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x93D58D9E014119A6ULL,
		0x1DBB7DA0EDCD3539ULL,
		0x9730EF97FEA604CCULL,
		0x7E0B47984C5573DEULL,
		0xACFE8C2E6754B46EULL,
		0x2B11BCF0151E540AULL,
		0x02E9A96F8C8C37DDULL,
		0x339773F404CEBFE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27AB1B3C0282334CULL,
		0x3B76FB41DB9A6A73ULL,
		0x2E61DF2FFD4C0998ULL,
		0xFC168F3098AAE7BDULL,
		0x59FD185CCEA968DCULL,
		0x562379E02A3CA815ULL,
		0x05D352DF19186FBAULL,
		0x672EE7E8099D7FC8ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x14E1FCE5246D57A3ULL,
		0xD1E209DBAA13AF3DULL,
		0x57D626B7FBB75912ULL,
		0x2390F3C6B90646DBULL,
		0x3142A82CFE9D3DE0ULL,
		0x94001CB0A33815C4ULL,
		0x8EBA2C95BA77B6B9ULL,
		0x3FFF79A66D95CC39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C3F9CA48DAAF46ULL,
		0xA3C413B754275E7AULL,
		0xAFAC4D6FF76EB225ULL,
		0x4721E78D720C8DB6ULL,
		0x62855059FD3A7BC0ULL,
		0x2800396146702B88ULL,
		0x1D74592B74EF6D73ULL,
		0x7FFEF34CDB2B9873ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x459FF925D4847578ULL,
		0x6AFAD560FE45DCEAULL,
		0x3984E836104422FDULL,
		0x0B157CFC7D6097FFULL,
		0x989BA0CDA40371C4ULL,
		0x2BF3871E5077DDF3ULL,
		0x6371A69BCF3D2698ULL,
		0x2767140E1078E47EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B3FF24BA908EAF0ULL,
		0xD5F5AAC1FC8BB9D4ULL,
		0x7309D06C208845FAULL,
		0x162AF9F8FAC12FFEULL,
		0x3137419B4806E388ULL,
		0x57E70E3CA0EFBBE7ULL,
		0xC6E34D379E7A4D30ULL,
		0x4ECE281C20F1C8FCULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFF941E8D7CF04D5DULL,
		0x56DAF7E032C46F2BULL,
		0x28B72AC2BCD14D4FULL,
		0x5D5AF203D735A350ULL,
		0x19AC56AF0C159B85ULL,
		0x61BA7F5C2CB4F9ADULL,
		0xC26041D8DFA3632AULL,
		0x28A917485DD79437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF283D1AF9E09ABAULL,
		0xADB5EFC06588DE57ULL,
		0x516E558579A29A9EULL,
		0xBAB5E407AE6B46A0ULL,
		0x3358AD5E182B370AULL,
		0xC374FEB85969F35AULL,
		0x84C083B1BF46C654ULL,
		0x51522E90BBAF286FULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x3EA815ECC9D7375FULL,
		0x99C1D669E6DECCEAULL,
		0x5273951C9D09BEABULL,
		0xEADAD0A338FE9DF3ULL,
		0xEEC65156429F73FCULL,
		0x881AFAB93A112A68ULL,
		0x32E69E1B145A74D5ULL,
		0x1B0138C3A34803CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D502BD993AE6EBEULL,
		0x3383ACD3CDBD99D4ULL,
		0xA4E72A393A137D57ULL,
		0xD5B5A14671FD3BE6ULL,
		0xDD8CA2AC853EE7F9ULL,
		0x1035F572742254D1ULL,
		0x65CD3C3628B4E9ABULL,
		0x360271874690079CULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6CB2C74A520D0757ULL,
		0x47F03828F5CCF893ULL,
		0xFFF311BF2E709176ULL,
		0x867148A9562CEC97ULL,
		0x880198EDBA7D36DCULL,
		0xEF529D455498E158ULL,
		0xC4EE2C24A32246BEULL,
		0x03E96FAB095135C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9658E94A41A0EAEULL,
		0x8FE07051EB99F126ULL,
		0xFFE6237E5CE122ECULL,
		0x0CE29152AC59D92FULL,
		0x100331DB74FA6DB9ULL,
		0xDEA53A8AA931C2B1ULL,
		0x89DC584946448D7DULL,
		0x07D2DF5612A26B85ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC12898789FAAD9E9ULL,
		0xCEF44158CE73BA25ULL,
		0x981EF927D4A6E16DULL,
		0x5B3E5ED083049E4BULL,
		0x1FE1F949F58BFA0BULL,
		0x3490F5622CFE5FE5ULL,
		0xABBAD3683CAF43CDULL,
		0x14A327ED38B4E2CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x825130F13F55B3D2ULL,
		0x9DE882B19CE7744BULL,
		0x303DF24FA94DC2DBULL,
		0xB67CBDA106093C97ULL,
		0x3FC3F293EB17F416ULL,
		0x6921EAC459FCBFCAULL,
		0x5775A6D0795E879AULL,
		0x29464FDA7169C595ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8CB940EC97C9F2A3ULL,
		0xC6CBF2A6CF4E711DULL,
		0xD1D37680A0B611DEULL,
		0x5D3F605F39CC7634ULL,
		0xBDD237CA2F006752ULL,
		0xC7DA7A5B9156265AULL,
		0x43A3DDAF86B84404ULL,
		0x1400BE746DB038B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x197281D92F93E546ULL,
		0x8D97E54D9E9CE23BULL,
		0xA3A6ED01416C23BDULL,
		0xBA7EC0BE7398EC69ULL,
		0x7BA46F945E00CEA4ULL,
		0x8FB4F4B722AC4CB5ULL,
		0x8747BB5F0D708809ULL,
		0x28017CE8DB60716CULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8FBFC5FC5C5B8939ULL,
		0xBF3DBDA69A0E73F3ULL,
		0x63708BA514CA6B9AULL,
		0x6CB94A19A552356BULL,
		0x3F71B1AD26E3DBD0ULL,
		0x98248F64B725DBD0ULL,
		0xA274F893BA7B61F8ULL,
		0x245E470F5AAEC1B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F7F8BF8B8B71272ULL,
		0x7E7B7B4D341CE7E7ULL,
		0xC6E1174A2994D735ULL,
		0xD97294334AA46AD6ULL,
		0x7EE3635A4DC7B7A0ULL,
		0x30491EC96E4BB7A0ULL,
		0x44E9F12774F6C3F1ULL,
		0x48BC8E1EB55D836DULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x599574E6BD4D77FEULL,
		0xB17ED1532604DE8BULL,
		0xADDF837821BD7202ULL,
		0x5D321ADB7ECBCBCCULL,
		0x69DF710A3ECD4186ULL,
		0x677BA5AB858A2009ULL,
		0xA47F2AE63BF6AAEEULL,
		0x3343B410F17F7304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32AE9CD7A9AEFFCULL,
		0x62FDA2A64C09BD16ULL,
		0x5BBF06F0437AE405ULL,
		0xBA6435B6FD979799ULL,
		0xD3BEE2147D9A830CULL,
		0xCEF74B570B144012ULL,
		0x48FE55CC77ED55DCULL,
		0x66876821E2FEE609ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xD85509C5E50DEFE9ULL,
		0x5C56BD04BE502D54ULL,
		0x8D2D80C2F0A6DDCFULL,
		0xAEE041A304E56A18ULL,
		0x47F893F9AFF5F60DULL,
		0xE192D58F1ABB8DFEULL,
		0x9CC8C8650B716587ULL,
		0x0AF08D1230463637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0AA138BCA1BDFD2ULL,
		0xB8AD7A097CA05AA9ULL,
		0x1A5B0185E14DBB9EULL,
		0x5DC0834609CAD431ULL,
		0x8FF127F35FEBEC1BULL,
		0xC325AB1E35771BFCULL,
		0x399190CA16E2CB0FULL,
		0x15E11A24608C6C6FULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x48E60A0B3087AE76ULL,
		0x2D58C8A5F03132A2ULL,
		0xD76D744262EE2BF8ULL,
		0x30BA596B914B8EABULL,
		0x64028BE1F01A5508ULL,
		0x4A57C8694B1C436CULL,
		0x4BDC8FEC264DEF84ULL,
		0x27F1151D8FD12C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91CC1416610F5CECULL,
		0x5AB1914BE0626544ULL,
		0xAEDAE884C5DC57F0ULL,
		0x6174B2D722971D57ULL,
		0xC80517C3E034AA10ULL,
		0x94AF90D2963886D8ULL,
		0x97B91FD84C9BDF08ULL,
		0x4FE22A3B1FA258CAULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xCFC3BA1BA5E932A0ULL,
		0xC79A8CA4059C8449ULL,
		0x1761770E28874C7FULL,
		0x404C18EE79A45446ULL,
		0xBBE6E3811BD5CD33ULL,
		0xB2FCA8E079B9BBB1ULL,
		0x50CC8324E431A803ULL,
		0x0354AEA7609B0E9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F8774374BD26540ULL,
		0x8F3519480B390893ULL,
		0x2EC2EE1C510E98FFULL,
		0x809831DCF348A88CULL,
		0x77CDC70237AB9A66ULL,
		0x65F951C0F3737763ULL,
		0xA1990649C8635007ULL,
		0x06A95D4EC1361D38ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xEBBC559A82FABFDBULL,
		0x66487628B761E112ULL,
		0xD5EBEFD46485B5A5ULL,
		0x5BD39D8F791143CFULL,
		0x777AB6689CCAD2A1ULL,
		0x8312D6852B550901ULL,
		0xFC95B50FC255B51EULL,
		0x3671DB0CC617EABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD778AB3505F57FB6ULL,
		0xCC90EC516EC3C225ULL,
		0xABD7DFA8C90B6B4AULL,
		0xB7A73B1EF222879FULL,
		0xEEF56CD13995A542ULL,
		0x0625AD0A56AA1202ULL,
		0xF92B6A1F84AB6A3DULL,
		0x6CE3B6198C2FD57DULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xBA8641075D9BA8D9ULL,
		0xC90822827D8BDC97ULL,
		0x8E03A5F15856CF5DULL,
		0xD5EFD68D2CB7540DULL,
		0xEF15C735D4EDE99CULL,
		0x272CB795CBEC250DULL,
		0x0D4075729FBCCEB0ULL,
		0x1DEA180D20CA9285ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x750C820EBB3751B2ULL,
		0x92104504FB17B92FULL,
		0x1C074BE2B0AD9EBBULL,
		0xABDFAD1A596EA81BULL,
		0xDE2B8E6BA9DBD339ULL,
		0x4E596F2B97D84A1BULL,
		0x1A80EAE53F799D60ULL,
		0x3BD4301A4195250AULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7F134C21DE38CCC0ULL,
		0x5CB9DEAC729E91C5ULL,
		0x7259A2EFD1008B14ULL,
		0x9BED2E10477778ABULL,
		0x3E5FA581F5D6355EULL,
		0xEA91CC580AA06233ULL,
		0x49590BC206BC930BULL,
		0x0297EBBAC02FFE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE269843BC719980ULL,
		0xB973BD58E53D238AULL,
		0xE4B345DFA2011628ULL,
		0x37DA5C208EEEF156ULL,
		0x7CBF4B03EBAC6ABDULL,
		0xD52398B01540C466ULL,
		0x92B217840D792617ULL,
		0x052FD775805FFCF2ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB48A0DEB3E9E71F7ULL,
		0xA791024804618099ULL,
		0x27279D82F85A968FULL,
		0x5B3D636028A5CEE1ULL,
		0x28F124D690680FF9ULL,
		0x0F0CA1B0870197E9ULL,
		0x1A65250E50F200BBULL,
		0x3824583728082128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69141BD67D3CE3EEULL,
		0x4F22049008C30133ULL,
		0x4E4F3B05F0B52D1FULL,
		0xB67AC6C0514B9DC2ULL,
		0x51E249AD20D01FF2ULL,
		0x1E1943610E032FD2ULL,
		0x34CA4A1CA1E40176ULL,
		0x7048B06E50104250ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x37AF0F4E61D90E99ULL,
		0x8CF806A2FD462B6BULL,
		0xA87D2BA11422488AULL,
		0x1368842F59041C27ULL,
		0x7C88195519026140ULL,
		0x8C41F071FD05885DULL,
		0xCBF61499F0B29025ULL,
		0x2C49E6BAB6FDD25FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5E1E9CC3B21D32ULL,
		0x19F00D45FA8C56D6ULL,
		0x50FA574228449115ULL,
		0x26D1085EB208384FULL,
		0xF91032AA3204C280ULL,
		0x1883E0E3FA0B10BAULL,
		0x97EC2933E165204BULL,
		0x5893CD756DFBA4BFULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x67D1CF791BE7CE99ULL,
		0x6472177FE35C05B4ULL,
		0x244E4494FE3F51C6ULL,
		0x07948A88CA246D72ULL,
		0x74B6A8CDB94FB8F5ULL,
		0x9E9005E30187F8D1ULL,
		0xC50126D8D200B179ULL,
		0x2994DB8D93784F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA39EF237CF9D32ULL,
		0xC8E42EFFC6B80B68ULL,
		0x489C8929FC7EA38CULL,
		0x0F2915119448DAE4ULL,
		0xE96D519B729F71EAULL,
		0x3D200BC6030FF1A2ULL,
		0x8A024DB1A40162F3ULL,
		0x5329B71B26F09F11ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7318803FB9F4DFBCULL,
		0x70282F7F8705E0DFULL,
		0x566651625CBD25ADULL,
		0x3F1778B17A3A9F71ULL,
		0xDAF2DB61C491BEB5ULL,
		0x0DA8203EE7736F5AULL,
		0xDB3F01C5D2810FCFULL,
		0x2A55B407E95A6CF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE631007F73E9BF78ULL,
		0xE0505EFF0E0BC1BEULL,
		0xACCCA2C4B97A4B5AULL,
		0x7E2EF162F4753EE2ULL,
		0xB5E5B6C389237D6AULL,
		0x1B50407DCEE6DEB5ULL,
		0xB67E038BA5021F9EULL,
		0x54AB680FD2B4D9E1ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9093A6FFDFD2442CULL,
		0xD0F0CEFC8B33752AULL,
		0x4E8C90945A669C02ULL,
		0xD64DF4D60219B259ULL,
		0x5261FF1F8497D280ULL,
		0x95B700C99A8FCCC9ULL,
		0x9AB67908360B2741ULL,
		0x24C04B0A37B17844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21274DFFBFA48858ULL,
		0xA1E19DF91666EA55ULL,
		0x9D192128B4CD3805ULL,
		0xAC9BE9AC043364B2ULL,
		0xA4C3FE3F092FA501ULL,
		0x2B6E0193351F9992ULL,
		0x356CF2106C164E83ULL,
		0x498096146F62F089ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x58AE9EABE922751EULL,
		0xCB127E2A6C3AA42DULL,
		0x10862C9EBC5EAF75ULL,
		0x9116068AD889A0F4ULL,
		0xFB840DB6203EDA00ULL,
		0xCFCBC90155CE3915ULL,
		0x40C43C3247B74254ULL,
		0x1594B33FB624BE2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB15D3D57D244EA3CULL,
		0x9624FC54D875485AULL,
		0x210C593D78BD5EEBULL,
		0x222C0D15B11341E8ULL,
		0xF7081B6C407DB401ULL,
		0x9F979202AB9C722BULL,
		0x818878648F6E84A9ULL,
		0x2B29667F6C497C54ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x832CF76D257C6815ULL,
		0x751F988C35A34D00ULL,
		0xE20466169A8FBE18ULL,
		0xECCCB4ED0EA01958ULL,
		0x422AD19CED18FB03ULL,
		0xC217BAF810A4EE75ULL,
		0x04812ACB51732858ULL,
		0x31F8C0E7DFB7D132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0659EEDA4AF8D02AULL,
		0xEA3F31186B469A01ULL,
		0xC408CC2D351F7C30ULL,
		0xD99969DA1D4032B1ULL,
		0x8455A339DA31F607ULL,
		0x842F75F02149DCEAULL,
		0x09025596A2E650B1ULL,
		0x63F181CFBF6FA264ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x05DC4E647DF881FDULL,
		0xC6FB2214FA5BB9C9ULL,
		0x5E5B5E54BE98F58CULL,
		0x20D7DA21319BBA39ULL,
		0x4298C35BEA48486BULL,
		0xA9E35C3428FB9DE6ULL,
		0x18A063DFD530223DULL,
		0x276C843B7E53ED2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB89CC8FBF103FAULL,
		0x8DF64429F4B77392ULL,
		0xBCB6BCA97D31EB19ULL,
		0x41AFB44263377472ULL,
		0x853186B7D49090D6ULL,
		0x53C6B86851F73BCCULL,
		0x3140C7BFAA60447BULL,
		0x4ED90876FCA7DA5EULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x8782CB4AA3DC60D9ULL,
		0x1E2FF130D71AE7FFULL,
		0xA1B9300531088AEDULL,
		0xC446348924B3B29DULL,
		0xB5542C8795F0AC49ULL,
		0x9742C5969F66B458ULL,
		0xF76BCFC342FA9CB4ULL,
		0x32296A5B41469A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F05969547B8C1B2ULL,
		0x3C5FE261AE35CFFFULL,
		0x4372600A621115DAULL,
		0x888C69124967653BULL,
		0x6AA8590F2BE15893ULL,
		0x2E858B2D3ECD68B1ULL,
		0xEED79F8685F53969ULL,
		0x6452D4B6828D3417ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB83BA36EB7F43FB0ULL,
		0xF2A5FBB72AC5571FULL,
		0xA14D2EBF34517AADULL,
		0x3B4FA3B8C5EA7A47ULL,
		0x0BD3C52FD1122E43ULL,
		0xCF2CA8D00A2A44E8ULL,
		0xCCF22CC2D6C1534CULL,
		0x301C3C93042B5419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707746DD6FE87F60ULL,
		0xE54BF76E558AAE3FULL,
		0x429A5D7E68A2F55BULL,
		0x769F47718BD4F48FULL,
		0x17A78A5FA2245C86ULL,
		0x9E5951A0145489D0ULL,
		0x99E45985AD82A699ULL,
		0x603879260856A833ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA3044E3B157BB4E3ULL,
		0x8464F76A17E9C891ULL,
		0xCFFC4C8A6007B1A3ULL,
		0x1C1A9E8C7D840CB1ULL,
		0x31CBFE0F016B7BB8ULL,
		0x614C24A43B2773B7ULL,
		0x5EC1A133FE112F69ULL,
		0x299E3B4C8AEA372CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46089C762AF769C6ULL,
		0x08C9EED42FD39123ULL,
		0x9FF89914C00F6347ULL,
		0x38353D18FB081963ULL,
		0x6397FC1E02D6F770ULL,
		0xC2984948764EE76EULL,
		0xBD834267FC225ED2ULL,
		0x533C769915D46E58ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x77AF7995C9F30179ULL,
		0x07FAABA64E2C6051ULL,
		0x659C4EC15C8D8D13ULL,
		0xA90812F70158FBAEULL,
		0xC33505785D0CCAFAULL,
		0xF6D987AB3F3A3210ULL,
		0x5262159A2CF53385ULL,
		0x064A2DD5F15579F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF5EF32B93E602F2ULL,
		0x0FF5574C9C58C0A2ULL,
		0xCB389D82B91B1A26ULL,
		0x521025EE02B1F75CULL,
		0x866A0AF0BA1995F5ULL,
		0xEDB30F567E746421ULL,
		0xA4C42B3459EA670BULL,
		0x0C945BABE2AAF3EEULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x92FB77CC733DD0B9ULL,
		0xCA581A6D5B76AE42ULL,
		0x515C1F54F78C46A5ULL,
		0x30FDEA51EBA665E1ULL,
		0x14B9C58632909091ULL,
		0x52B6387D318AF15AULL,
		0xA0F505FB078E21FEULL,
		0x0693DBC31FE7EF9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F6EF98E67BA172ULL,
		0x94B034DAB6ED5C85ULL,
		0xA2B83EA9EF188D4BULL,
		0x61FBD4A3D74CCBC2ULL,
		0x29738B0C65212122ULL,
		0xA56C70FA6315E2B4ULL,
		0x41EA0BF60F1C43FCULL,
		0x0D27B7863FCFDF39ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x43022EE88FCE44E3ULL,
		0x546F0FB9C948FF1EULL,
		0x01A5808BF6FCCD18ULL,
		0x3E54047F4C8CE1A0ULL,
		0xDF2AFB266D65F0B3ULL,
		0xAF9501AA9E89AF90ULL,
		0xAB7D4E6C6F6B7F01ULL,
		0x24226C313D34AD37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86045DD11F9C89C6ULL,
		0xA8DE1F739291FE3CULL,
		0x034B0117EDF99A30ULL,
		0x7CA808FE9919C340ULL,
		0xBE55F64CDACBE166ULL,
		0x5F2A03553D135F21ULL,
		0x56FA9CD8DED6FE03ULL,
		0x4844D8627A695A6FULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB46B8EA21DA95480ULL,
		0x815D1065E077A595ULL,
		0x4FFA349C705856D7ULL,
		0x258A3EAE8BA138BBULL,
		0x35EAD3D9F5BA3033ULL,
		0x1398E878B1698E98ULL,
		0xA8E78B325FCF95B7ULL,
		0x187979C810A1CB58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D71D443B52A900ULL,
		0x02BA20CBC0EF4B2BULL,
		0x9FF46938E0B0ADAFULL,
		0x4B147D5D17427176ULL,
		0x6BD5A7B3EB746066ULL,
		0x2731D0F162D31D30ULL,
		0x51CF1664BF9F2B6EULL,
		0x30F2F390214396B1ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1018F3F3EF2BC431ULL,
		0x0B9808CC70703E1BULL,
		0xF6639CA84A84B433ULL,
		0x4B89DCACC2FF97D2ULL,
		0xACACC613219CF9EEULL,
		0xE266CA65450CDE77ULL,
		0x171772AAFA88D502ULL,
		0x0C4E5825E625059AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2031E7E7DE578862ULL,
		0x17301198E0E07C36ULL,
		0xECC7395095096866ULL,
		0x9713B95985FF2FA5ULL,
		0x59598C264339F3DCULL,
		0xC4CD94CA8A19BCEFULL,
		0x2E2EE555F511AA05ULL,
		0x189CB04BCC4A0B34ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFAD5A0927BFCB323ULL,
		0x041A8D020DB10774ULL,
		0x55924093FF4F46A0ULL,
		0xB5409634DF27633BULL,
		0x025C916CA6394896ULL,
		0x1DF7D771220B0917ULL,
		0xB0C17924802406A1ULL,
		0x05BCD4903CA02D3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5AB4124F7F96646ULL,
		0x08351A041B620EE9ULL,
		0xAB248127FE9E8D40ULL,
		0x6A812C69BE4EC676ULL,
		0x04B922D94C72912DULL,
		0x3BEFAEE24416122EULL,
		0x6182F24900480D42ULL,
		0x0B79A92079405A7FULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE1B4FDEEC96DB884ULL,
		0x55DF355A060CF9C7ULL,
		0xCAF4C1D9DF55480CULL,
		0x7A876E539164B1ACULL,
		0x7782B2DC9D4E4EFAULL,
		0x52F2D6E16B39E927ULL,
		0x00A24BCE4DD3DC6EULL,
		0x30C91899BF29B592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC369FBDD92DB7108ULL,
		0xABBE6AB40C19F38FULL,
		0x95E983B3BEAA9018ULL,
		0xF50EDCA722C96359ULL,
		0xEF0565B93A9C9DF4ULL,
		0xA5E5ADC2D673D24EULL,
		0x0144979C9BA7B8DCULL,
		0x619231337E536B24ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xF45B0564800F6480ULL,
		0x1DD93017E6D69E83ULL,
		0x0EFFA0C812024F11ULL,
		0x55245FD167C727B9ULL,
		0xABD9E99FE59C5AA2ULL,
		0x9CE85B4523DF74C2ULL,
		0xB894C0B591361137ULL,
		0x39E4226A9520A40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B60AC9001EC900ULL,
		0x3BB2602FCDAD3D07ULL,
		0x1DFF419024049E22ULL,
		0xAA48BFA2CF8E4F72ULL,
		0x57B3D33FCB38B544ULL,
		0x39D0B68A47BEE985ULL,
		0x7129816B226C226FULL,
		0x73C844D52A41481FULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDB33260024979F46ULL,
		0x506700EE7A46ABCFULL,
		0x01FD452FF85A2C95ULL,
		0x54A0B016F4F46F86ULL,
		0x6224F28C8434D337ULL,
		0x0199DBE41EEA6D48ULL,
		0x1BDB2161057B439EULL,
		0x096FC1CC43B4E756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6664C00492F3E8CULL,
		0xA0CE01DCF48D579FULL,
		0x03FA8A5FF0B4592AULL,
		0xA941602DE9E8DF0CULL,
		0xC449E5190869A66EULL,
		0x0333B7C83DD4DA90ULL,
		0x37B642C20AF6873CULL,
		0x12DF83988769CEACULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4AD247305836ED9BULL,
		0x6596908EF21F4CC5ULL,
		0xF83D0D540618DB23ULL,
		0xACCC3F010EA2A132ULL,
		0x1CDB91B6AC8FF62AULL,
		0x92CF1E7EE8040990ULL,
		0x6458E5E3998BFB4EULL,
		0x04C0B3508FA97A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A48E60B06DDB36ULL,
		0xCB2D211DE43E998AULL,
		0xF07A1AA80C31B646ULL,
		0x59987E021D454265ULL,
		0x39B7236D591FEC55ULL,
		0x259E3CFDD0081320ULL,
		0xC8B1CBC73317F69DULL,
		0x098166A11F52F446ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA27B849E975EAFF8ULL,
		0x2B3D94479EC326E6ULL,
		0x954E8B6EE0080D03ULL,
		0xEE2F6ED01ADA4A8EULL,
		0x6658A39F76CAA523ULL,
		0x3B243F5209DBEEA9ULL,
		0x2C42EA46C23A63D4ULL,
		0x14688FB4A8E0C7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44F7093D2EBD5FF0ULL,
		0x567B288F3D864DCDULL,
		0x2A9D16DDC0101A06ULL,
		0xDC5EDDA035B4951DULL,
		0xCCB1473EED954A47ULL,
		0x76487EA413B7DD52ULL,
		0x5885D48D8474C7A8ULL,
		0x28D11F6951C18F5AULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x6B56B7401248ED23ULL,
		0x14432F302A3564DFULL,
		0x5D31F6F6C47041BFULL,
		0xECF89A5F3831DE24ULL,
		0x9D1E23284A5C1A0CULL,
		0x244A934406D5B701ULL,
		0x5F2DA64D88EE1921ULL,
		0x15ECAF751BB4E236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6AD6E802491DA46ULL,
		0x28865E60546AC9BEULL,
		0xBA63EDED88E0837EULL,
		0xD9F134BE7063BC48ULL,
		0x3A3C465094B83419ULL,
		0x489526880DAB6E03ULL,
		0xBE5B4C9B11DC3242ULL,
		0x2BD95EEA3769C46CULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE8EA27C5B76CA6FEULL,
		0x68346CB2829B3705ULL,
		0xE20010C22DCDD7FEULL,
		0x2EBD660B25E9B3A0ULL,
		0x4973D5CECE8E0287ULL,
		0x35B6F5DCA4E25249ULL,
		0x8E8A2F6B6BA85C9BULL,
		0x2AD3868E96BEA49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D44F8B6ED94DFCULL,
		0xD068D96505366E0BULL,
		0xC40021845B9BAFFCULL,
		0x5D7ACC164BD36741ULL,
		0x92E7AB9D9D1C050EULL,
		0x6B6DEBB949C4A492ULL,
		0x1D145ED6D750B936ULL,
		0x55A70D1D2D7D493FULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xE0AEE3A4369DBBF7ULL,
		0x08555D97856BB519ULL,
		0xC084ED8741B8EAFCULL,
		0xEA8FF6AB924912B9ULL,
		0xFECDA72FB86FCB19ULL,
		0x8CFB9DCE2D2CE219ULL,
		0x31D0CFA49448BC32ULL,
		0x0D32373E30C185F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15DC7486D3B77EEULL,
		0x10AABB2F0AD76A33ULL,
		0x8109DB0E8371D5F8ULL,
		0xD51FED5724922573ULL,
		0xFD9B4E5F70DF9633ULL,
		0x19F73B9C5A59C433ULL,
		0x63A19F4928917865ULL,
		0x1A646E7C61830BE8ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x11A49C8210638373ULL,
		0x83E0398B155506DFULL,
		0xB3D712BC829FD77BULL,
		0x4127171B59762F59ULL,
		0xAC3F98C934118117ULL,
		0x2B58FD4DEDB468E0ULL,
		0xCDA9B3CDDF6139C7ULL,
		0x06A14BDACA4AE6A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2349390420C706E6ULL,
		0x07C073162AAA0DBEULL,
		0x67AE2579053FAEF7ULL,
		0x824E2E36B2EC5EB3ULL,
		0x587F31926823022EULL,
		0x56B1FA9BDB68D1C1ULL,
		0x9B53679BBEC2738EULL,
		0x0D4297B59495CD41ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5653057B8FA86A5CULL,
		0x68195B8D0C2F03F6ULL,
		0xE0E94EAB9049FED7ULL,
		0xE394AFE304582E07ULL,
		0x0C6BD01B6E34DCA5ULL,
		0x6D3EC8D27EFC86C8ULL,
		0x5C1EAE576D0E6602ULL,
		0x3BCE81236DD44D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA60AF71F50D4B8ULL,
		0xD032B71A185E07ECULL,
		0xC1D29D572093FDAEULL,
		0xC7295FC608B05C0FULL,
		0x18D7A036DC69B94BULL,
		0xDA7D91A4FDF90D90ULL,
		0xB83D5CAEDA1CCC04ULL,
		0x779D0246DBA89A42ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0A2DE5004875F631ULL,
		0x41DF369A1F83B232ULL,
		0xF9AECBC14EA38D40ULL,
		0x5DE0F7FB52328B2DULL,
		0x782A92B6E435955CULL,
		0x69274CCBC4118E38ULL,
		0xB722F57487818CDDULL,
		0x20F3DB6206F47635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x145BCA0090EBEC62ULL,
		0x83BE6D343F076464ULL,
		0xF35D97829D471A80ULL,
		0xBBC1EFF6A465165BULL,
		0xF055256DC86B2AB8ULL,
		0xD24E999788231C70ULL,
		0x6E45EAE90F0319BAULL,
		0x41E7B6C40DE8EC6BULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xBAD2963EBA48E8DBULL,
		0x7C5CEC416ED93BF0ULL,
		0x4EC962FDE4DFE827ULL,
		0x0FAB208351FD28DEULL,
		0xB09851CA61662E44ULL,
		0x0B6BF0752230BD01ULL,
		0x99B47AE41ADD6612ULL,
		0x237E3FBE0CBEB5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A52C7D7491D1B6ULL,
		0xF8B9D882DDB277E1ULL,
		0x9D92C5FBC9BFD04EULL,
		0x1F564106A3FA51BCULL,
		0x6130A394C2CC5C88ULL,
		0x16D7E0EA44617A03ULL,
		0x3368F5C835BACC24ULL,
		0x46FC7F7C197D6BB7ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x57165229798A32B9ULL,
		0x1EC9836BED31316DULL,
		0x2AA8576894322020ULL,
		0xB376C4F2F7C03615ULL,
		0x8E649A19E68D6B8BULL,
		0xB32842B07C2D69AFULL,
		0xA5925CAA54B2E557ULL,
		0x26D214A651983359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE2CA452F3146572ULL,
		0x3D9306D7DA6262DAULL,
		0x5550AED128644040ULL,
		0x66ED89E5EF806C2AULL,
		0x1CC93433CD1AD717ULL,
		0x66508560F85AD35FULL,
		0x4B24B954A965CAAFULL,
		0x4DA4294CA33066B3ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x1B632A2C89BC4128ULL,
		0x67D621594C7E0E07ULL,
		0x6F8BC7508E9921FBULL,
		0xE7A95250511967CAULL,
		0xC35544E0F7139CA5ULL,
		0x369AE3A2621ECF75ULL,
		0xD93887FF1E660101ULL,
		0x3099496BECB71C41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C6545913788250ULL,
		0xCFAC42B298FC1C0EULL,
		0xDF178EA11D3243F6ULL,
		0xCF52A4A0A232CF94ULL,
		0x86AA89C1EE27394BULL,
		0x6D35C744C43D9EEBULL,
		0xB2710FFE3CCC0202ULL,
		0x613292D7D96E3883ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xC83B66A1946D728FULL,
		0x2135488F39CA7DB3ULL,
		0x7CE511EB6F38EBB1ULL,
		0x7B0B456669512A6BULL,
		0x684585E13CE5CA6CULL,
		0xE9A8ADF0D1AE696FULL,
		0x8E540BFBDE562467ULL,
		0x301396874D44553CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9076CD4328DAE51EULL,
		0x426A911E7394FB67ULL,
		0xF9CA23D6DE71D762ULL,
		0xF6168ACCD2A254D6ULL,
		0xD08B0BC279CB94D8ULL,
		0xD3515BE1A35CD2DEULL,
		0x1CA817F7BCAC48CFULL,
		0x60272D0E9A88AA79ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xDE5B86CB6118E221ULL,
		0x47DAD103362860A3ULL,
		0x2AD18F7443D00808ULL,
		0x75F409FF3E30AEAFULL,
		0x76458EE5E3088602ULL,
		0x639B0DEA89B95EC5ULL,
		0x8839581FA9D5E1E9ULL,
		0x26D9C14FBB1896B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCB70D96C231C442ULL,
		0x8FB5A2066C50C147ULL,
		0x55A31EE887A01010ULL,
		0xEBE813FE7C615D5EULL,
		0xEC8B1DCBC6110C04ULL,
		0xC7361BD51372BD8AULL,
		0x1072B03F53ABC3D2ULL,
		0x4DB3829F76312D63ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4630A1AB8E1FF3B6ULL,
		0xC1927A3DAD923F28ULL,
		0xE8A987EDE3A5B9A1ULL,
		0x6B394FFC33CEDC80ULL,
		0x2E981DFC7070398FULL,
		0xA2C01DE7FC24614BULL,
		0x5A0268E1F3B801C9ULL,
		0x3916929D24513483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C6143571C3FE76CULL,
		0x8324F47B5B247E50ULL,
		0xD1530FDBC74B7343ULL,
		0xD6729FF8679DB901ULL,
		0x5D303BF8E0E0731EULL,
		0x45803BCFF848C296ULL,
		0xB404D1C3E7700393ULL,
		0x722D253A48A26906ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x69D74319AD660C57ULL,
		0x589984D1F3D0DADBULL,
		0x7C34A6736BCF7EB2ULL,
		0xFE51457F7FD518B5ULL,
		0x8954E0DA12B466C6ULL,
		0x72CC1771ECFF2A3AULL,
		0xC8C2C229B4D444B1ULL,
		0x07E7BDBBA6044B8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3AE86335ACC18AEULL,
		0xB13309A3E7A1B5B6ULL,
		0xF8694CE6D79EFD64ULL,
		0xFCA28AFEFFAA316AULL,
		0x12A9C1B42568CD8DULL,
		0xE5982EE3D9FE5475ULL,
		0x9185845369A88962ULL,
		0x0FCF7B774C08971DULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA906789F2D7B6B9EULL,
		0x1DC03BF06BBA0804ULL,
		0x315A01D7F9A61E82ULL,
		0x2F3E7FE4C43CB6B9ULL,
		0x174BCEC521039CC1ULL,
		0x5D3CD3D02B2C287FULL,
		0x96FDBBF439439A12ULL,
		0x0098EC1E2588C154ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x520CF13E5AF6D73CULL,
		0x3B8077E0D7741009ULL,
		0x62B403AFF34C3D04ULL,
		0x5E7CFFC988796D72ULL,
		0x2E979D8A42073982ULL,
		0xBA79A7A0565850FEULL,
		0x2DFB77E872873424ULL,
		0x0131D83C4B1182A9ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x118DEA5AAF938048ULL,
		0x3C1911F5E27F9C33ULL,
		0x0A585788E9F78676ULL,
		0x0E5E9874BBCB68E6ULL,
		0x46AE356937C40159ULL,
		0xF5A162BF814E1F1BULL,
		0x163032651EA91B19ULL,
		0x391ED154C673166BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x231BD4B55F270090ULL,
		0x783223EBC4FF3866ULL,
		0x14B0AF11D3EF0CECULL,
		0x1CBD30E97796D1CCULL,
		0x8D5C6AD26F8802B2ULL,
		0xEB42C57F029C3E36ULL,
		0x2C6064CA3D523633ULL,
		0x723DA2A98CE62CD6ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x4FEC4B9A288DE5F6ULL,
		0x34FDBABED1997177ULL,
		0x1ACD23C999C011BEULL,
		0x55E02E667106E685ULL,
		0xE962F6F9D384DEDBULL,
		0xB03F1C4444DBE374ULL,
		0xB54816B879143F0FULL,
		0x2394272216824377ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD89734511BCBECULL,
		0x69FB757DA332E2EEULL,
		0x359A47933380237CULL,
		0xABC05CCCE20DCD0AULL,
		0xD2C5EDF3A709BDB6ULL,
		0x607E388889B7C6E9ULL,
		0x6A902D70F2287E1FULL,
		0x47284E442D0486EFULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xBD8465291DB2FB17ULL,
		0x85AD48D8A6509D3CULL,
		0x420F6DFB732BF170ULL,
		0x5216178BCCC9F005ULL,
		0x1C6505BF434C1DFEULL,
		0x52B744B4E65DE6A8ULL,
		0xE952FDF6C3C994EDULL,
		0x28C193E0DA3343C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B08CA523B65F62EULL,
		0x0B5A91B14CA13A79ULL,
		0x841EDBF6E657E2E1ULL,
		0xA42C2F179993E00AULL,
		0x38CA0B7E86983BFCULL,
		0xA56E8969CCBBCD50ULL,
		0xD2A5FBED879329DAULL,
		0x518327C1B4668787ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA86EF616B83DEDFBULL,
		0xE0C8EF55193B2B50ULL,
		0x779019433258BBD1ULL,
		0xEBC9801F0007EA65ULL,
		0xE959254F9F426325ULL,
		0x601E4ADE3F4AB030ULL,
		0x6B6DC10A30FFBEBBULL,
		0x179ED79F113E63A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50DDEC2D707BDBF6ULL,
		0xC191DEAA327656A1ULL,
		0xEF20328664B177A3ULL,
		0xD793003E000FD4CAULL,
		0xD2B24A9F3E84C64BULL,
		0xC03C95BC7E956061ULL,
		0xD6DB821461FF7D76ULL,
		0x2F3DAF3E227CC750ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5CBA10C807D70940ULL,
		0xA05327E371CC4275ULL,
		0x1079CD19E418C4B6ULL,
		0xA0588153D537FCB5ULL,
		0x56FFA4206A6787BAULL,
		0x1ADFB7DBC9943493ULL,
		0xAD1FE089C4863D5BULL,
		0x1B93E6B868251A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97421900FAE1280ULL,
		0x40A64FC6E39884EAULL,
		0x20F39A33C831896DULL,
		0x40B102A7AA6FF96AULL,
		0xADFF4840D4CF0F75ULL,
		0x35BF6FB793286926ULL,
		0x5A3FC113890C7AB6ULL,
		0x3727CD70D04A3509ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x94B7C04106788781ULL,
		0xA4E04A703C46DAE8ULL,
		0xEB70297AAAF9AA36ULL,
		0xD1DD484C692E0050ULL,
		0xDC7F78E60CF2012FULL,
		0xB0319EE1EC662E30ULL,
		0xECF2E42B1101B279ULL,
		0x15BD115A8CAEBE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x296F80820CF10F02ULL,
		0x49C094E0788DB5D1ULL,
		0xD6E052F555F3546DULL,
		0xA3BA9098D25C00A1ULL,
		0xB8FEF1CC19E4025FULL,
		0x60633DC3D8CC5C61ULL,
		0xD9E5C856220364F3ULL,
		0x2B7A22B5195D7CF3ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x330BDE45683745C4ULL,
		0x33F9A63FE151C49FULL,
		0xA809177BF78A6E9CULL,
		0x8B06A510104211FCULL,
		0x74ADAB49112F56AAULL,
		0x6875C877AD7A4C9DULL,
		0xC07C874171C7BA98ULL,
		0x01260B1B26F5633FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6617BC8AD06E8B88ULL,
		0x67F34C7FC2A3893EULL,
		0x50122EF7EF14DD38ULL,
		0x160D4A20208423F9ULL,
		0xE95B5692225EAD55ULL,
		0xD0EB90EF5AF4993AULL,
		0x80F90E82E38F7530ULL,
		0x024C16364DEAC67FULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x9B51971A4A399BAAULL,
		0x577F7889481D57ABULL,
		0xBB78E850A9B29492ULL,
		0xBBE09B461ECE1288ULL,
		0x15E236613AC3E771ULL,
		0x10F506FDBC8BE996ULL,
		0xF44A4C2B1D130D1FULL,
		0x1958D3909E150082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36A32E3494733754ULL,
		0xAEFEF112903AAF57ULL,
		0x76F1D0A153652924ULL,
		0x77C1368C3D9C2511ULL,
		0x2BC46CC27587CEE3ULL,
		0x21EA0DFB7917D32CULL,
		0xE89498563A261A3EULL,
		0x32B1A7213C2A0105ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0C7713735B57075BULL,
		0xF4E4D386B02247B7ULL,
		0xC4F80784F058DC34ULL,
		0x30F093EF7BBC26E4ULL,
		0xEB3D46F0C98B57F2ULL,
		0xF6747960D592BF67ULL,
		0xCC4CE5F085FAB6C3ULL,
		0x2405E5FCCB8E1D5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18EE26E6B6AE0EB6ULL,
		0xE9C9A70D60448F6EULL,
		0x89F00F09E0B1B869ULL,
		0x61E127DEF7784DC9ULL,
		0xD67A8DE19316AFE4ULL,
		0xECE8F2C1AB257ECFULL,
		0x9899CBE10BF56D87ULL,
		0x480BCBF9971C3AB5ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2DFE9427C57057F7ULL,
		0x727B5EDEC22AB799ULL,
		0xE1AC7AD2C7D99A9BULL,
		0x7D026B14809387C0ULL,
		0x0CAB8672A90D019AULL,
		0x8BDF78A093BF8735ULL,
		0xBCA89481E2F8BF32ULL,
		0x187A11021EC03058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BFD284F8AE0AFEEULL,
		0xE4F6BDBD84556F32ULL,
		0xC358F5A58FB33536ULL,
		0xFA04D62901270F81ULL,
		0x19570CE5521A0334ULL,
		0x17BEF141277F0E6AULL,
		0x79512903C5F17E65ULL,
		0x30F422043D8060B1ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x0D94F367D26B8AF4ULL,
		0x16B14F17C0CBBB6BULL,
		0x1787536E7403AD75ULL,
		0x1D5FEFDEAC9BD290ULL,
		0x45D10FBB2688B8DCULL,
		0x9D1B3B3718036DEDULL,
		0x57DB49891E68FBD5ULL,
		0x2E583214ED25804DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B29E6CFA4D715E8ULL,
		0x2D629E2F819776D6ULL,
		0x2F0EA6DCE8075AEAULL,
		0x3ABFDFBD5937A520ULL,
		0x8BA21F764D1171B8ULL,
		0x3A36766E3006DBDAULL,
		0xAFB693123CD1F7ABULL,
		0x5CB06429DA4B009AULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7BA6368BC13A178AULL,
		0xC3DAAA505CA4C352ULL,
		0xFED26F2958BE12FDULL,
		0xA6F55466850D0DD6ULL,
		0xE16A34E09D7FEEF1ULL,
		0xC7E752EF1EF6E665ULL,
		0x07610E371E81CCB6ULL,
		0x3C94CE75D62E4937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF74C6D1782742F14ULL,
		0x87B554A0B94986A4ULL,
		0xFDA4DE52B17C25FBULL,
		0x4DEAA8CD0A1A1BADULL,
		0xC2D469C13AFFDDE3ULL,
		0x8FCEA5DE3DEDCCCBULL,
		0x0EC21C6E3D03996DULL,
		0x79299CEBAC5C926EULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7ECF303AD12201D0ULL,
		0xB6E528622F7DDEB2ULL,
		0x493569F53148EF48ULL,
		0x009548A70E53EA5FULL,
		0xE61005753896D53FULL,
		0xA8F1C6297EB94C08ULL,
		0x62B912ABFF4D5A6AULL,
		0x0B5CC883A61782A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9E6075A24403A0ULL,
		0x6DCA50C45EFBBD64ULL,
		0x926AD3EA6291DE91ULL,
		0x012A914E1CA7D4BEULL,
		0xCC200AEA712DAA7EULL,
		0x51E38C52FD729811ULL,
		0xC5722557FE9AB4D5ULL,
		0x16B991074C2F054EULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7B0D37F027B32341ULL,
		0xE3A2E47992C88243ULL,
		0x92DB9EFDD460F075ULL,
		0xB4661DCAA7173900ULL,
		0x14EFB4FB681AD3F9ULL,
		0x4722147F1BF7716DULL,
		0x08A44FD6C8FCF7E0ULL,
		0x19C8DD529F09A80BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61A6FE04F664682ULL,
		0xC745C8F325910486ULL,
		0x25B73DFBA8C1E0EBULL,
		0x68CC3B954E2E7201ULL,
		0x29DF69F6D035A7F3ULL,
		0x8E4428FE37EEE2DAULL,
		0x11489FAD91F9EFC0ULL,
		0x3391BAA53E135016ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x5A6D4689FBF70F09ULL,
		0x7F6CA0265130E581ULL,
		0x6C426B09FEBD468CULL,
		0xDCF07CE24F2DC96BULL,
		0x92A109D390E7A6BDULL,
		0x941F4CBAD5928380ULL,
		0x0E84F6B8E1C889F8ULL,
		0x00F7CCADE8D78DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4DA8D13F7EE1E12ULL,
		0xFED9404CA261CB02ULL,
		0xD884D613FD7A8D18ULL,
		0xB9E0F9C49E5B92D6ULL,
		0x254213A721CF4D7BULL,
		0x283E9975AB250701ULL,
		0x1D09ED71C39113F1ULL,
		0x01EF995BD1AF1BC8ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x660F67FBC90625D8ULL,
		0x998F70DC0739753FULL,
		0xA94FD58FAB87C288ULL,
		0x47BF457B9265ACE6ULL,
		0xEFE226E9EB0602A6ULL,
		0xE64933AFEA0D23F5ULL,
		0x371CE7BE27F4F776ULL,
		0x1B7C263DBE681BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC1ECFF7920C4BB0ULL,
		0x331EE1B80E72EA7EULL,
		0x529FAB1F570F8511ULL,
		0x8F7E8AF724CB59CDULL,
		0xDFC44DD3D60C054CULL,
		0xCC92675FD41A47EBULL,
		0x6E39CF7C4FE9EEEDULL,
		0x36F84C7B7CD037AEULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x58156774E2DCC100ULL,
		0x830A7863DC02F887ULL,
		0x8D46EE781C9160D4ULL,
		0x8C4496978B62E357ULL,
		0xFA7CE07825112B4AULL,
		0x1B92782D008FA7CAULL,
		0xB8A3BCAAE830537AULL,
		0x073AA9C600FA8315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB02ACEE9C5B98200ULL,
		0x0614F0C7B805F10EULL,
		0x1A8DDCF03922C1A9ULL,
		0x18892D2F16C5C6AFULL,
		0xF4F9C0F04A225695ULL,
		0x3724F05A011F4F95ULL,
		0x71477955D060A6F4ULL,
		0x0E75538C01F5062BULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x7305120358F36C42ULL,
		0xDB23C01C4073368DULL,
		0x91B5B09A85CC6306ULL,
		0xA012ECADBD234780ULL,
		0x1EE30C3D7EBF7C99ULL,
		0x919B65F86A4AF3B0ULL,
		0x70B3CD3F45D2BE28ULL,
		0x1748F4EEB59AD492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60A2406B1E6D884ULL,
		0xB647803880E66D1AULL,
		0x236B61350B98C60DULL,
		0x4025D95B7A468F01ULL,
		0x3DC6187AFD7EF933ULL,
		0x2336CBF0D495E760ULL,
		0xE1679A7E8BA57C51ULL,
		0x2E91E9DD6B35A924ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xB15F7B730374FDB6ULL,
		0xC3569AE021629965ULL,
		0x640AEDF2A5B0675BULL,
		0xD8C6F305E57B1547ULL,
		0x7F1129EF07862733ULL,
		0xFA29BE7943EEFDC0ULL,
		0xF6D0818BD3229269ULL,
		0x29BC34D83CAAC9A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62BEF6E606E9FB6CULL,
		0x86AD35C042C532CBULL,
		0xC815DBE54B60CEB7ULL,
		0xB18DE60BCAF62A8EULL,
		0xFE2253DE0F0C4E67ULL,
		0xF4537CF287DDFB80ULL,
		0xEDA10317A64524D3ULL,
		0x537869B079559345ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xADF9ADFFBA91D6F0ULL,
		0xA386BBCE11761767ULL,
		0x66AE8FE214839777ULL,
		0x40F9643A0B6B6520ULL,
		0x8C86FCB0B88DFCF1ULL,
		0x6C4FF71D270849B6ULL,
		0xC2F4C4165E95629FULL,
		0x3E3E162AC4ED5528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF35BFF7523ADE0ULL,
		0x470D779C22EC2ECFULL,
		0xCD5D1FC429072EEFULL,
		0x81F2C87416D6CA40ULL,
		0x190DF961711BF9E2ULL,
		0xD89FEE3A4E10936DULL,
		0x85E9882CBD2AC53EULL,
		0x7C7C2C5589DAAA51ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x650C3C7A3970F34AULL,
		0x36A3B9CD648AF0A0ULL,
		0x78712024C9D71509ULL,
		0x409F3FCDF3C9C783ULL,
		0xC6CE85EB05F8F3D0ULL,
		0x1138F5A269DAC9C9ULL,
		0xC2575B335F17FDD4ULL,
		0x0D8E02794D96E198ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA1878F472E1E694ULL,
		0x6D47739AC915E140ULL,
		0xF0E2404993AE2A12ULL,
		0x813E7F9BE7938F06ULL,
		0x8D9D0BD60BF1E7A0ULL,
		0x2271EB44D3B59393ULL,
		0x84AEB666BE2FFBA8ULL,
		0x1B1C04F29B2DC331ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x92EC856B6F9F2C00ULL,
		0xDA110B61F864F0A0ULL,
		0xA874E0956BD30741ULL,
		0x3845D04D7ECB73A8ULL,
		0xBD397C6643B44F97ULL,
		0x109CABDB4F4C70DBULL,
		0xE4F51BA3C7AE51BAULL,
		0x3F0FC4FB9E93994BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D90AD6DF3E5800ULL,
		0xB42216C3F0C9E141ULL,
		0x50E9C12AD7A60E83ULL,
		0x708BA09AFD96E751ULL,
		0x7A72F8CC87689F2EULL,
		0x213957B69E98E1B7ULL,
		0xC9EA37478F5CA374ULL,
		0x7E1F89F73D273297ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x2944F730BCF5322BULL,
		0x590DDB05782A0BE1ULL,
		0x62BB83C55F02244FULL,
		0xA836BFB2F7D1CC54ULL,
		0x9DB0C3D7EDC15988ULL,
		0x559EE197557607CFULL,
		0x9E1C9A9974A26255ULL,
		0x304BAFEF2974FC4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5289EE6179EA6456ULL,
		0xB21BB60AF05417C2ULL,
		0xC577078ABE04489EULL,
		0x506D7F65EFA398A8ULL,
		0x3B6187AFDB82B311ULL,
		0xAB3DC32EAAEC0F9FULL,
		0x3C393532E944C4AAULL,
		0x60975FDE52E9F89FULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xA751AECC9F8CBAC2ULL,
		0x3FF8D80EA7815368ULL,
		0x64383E9989238534ULL,
		0xE03C1DA60BC69361ULL,
		0xC9B5C801EF51922DULL,
		0xEDEC627DB1C6D403ULL,
		0xC2CEBA846B98FC84ULL,
		0x218EC7E7E79467F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA35D993F197584ULL,
		0x7FF1B01D4F02A6D1ULL,
		0xC8707D3312470A68ULL,
		0xC0783B4C178D26C2ULL,
		0x936B9003DEA3245BULL,
		0xDBD8C4FB638DA807ULL,
		0x859D7508D731F909ULL,
		0x431D8FCFCF28CFE7ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x51FB23F4363F6024ULL,
		0xF4E02CDF216CBB6CULL,
		0x0B30A389261B5693ULL,
		0x04E8E94765F558E2ULL,
		0x3CA115310206FE03ULL,
		0x7C41D343BCA99BAEULL,
		0x376C55BCCB92DC49ULL,
		0x3B16BFF02D7C2E72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F647E86C7EC048ULL,
		0xE9C059BE42D976D8ULL,
		0x166147124C36AD27ULL,
		0x09D1D28ECBEAB1C4ULL,
		0x79422A62040DFC06ULL,
		0xF883A6877953375CULL,
		0x6ED8AB799725B892ULL,
		0x762D7FE05AF85CE4ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x10FEC9DB4CF75CC8ULL,
		0x41EDD26768C3612BULL,
		0x1184300E82ED41CDULL,
		0xB8FE2A60819E9231ULL,
		0x4D72C993821B9EA5ULL,
		0x62C68812EF371EBDULL,
		0x51709329093262FCULL,
		0x33E4C05A5A0FF8C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21FD93B699EEB990ULL,
		0x83DBA4CED186C256ULL,
		0x2308601D05DA839AULL,
		0x71FC54C1033D2462ULL,
		0x9AE5932704373D4BULL,
		0xC58D1025DE6E3D7AULL,
		0xA2E126521264C5F8ULL,
		0x67C980B4B41FF180ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0x658BA6CF9BFB7A2EULL,
		0x92DFFE29C83401D3ULL,
		0xC140D9997012E265ULL,
		0xBD8E9DEB0998D86FULL,
		0x41336D365B40EA21ULL,
		0xEDD12A5F2E4FE640ULL,
		0x52424BAE8560DEC4ULL,
		0x38C9E49641612930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB174D9F37F6F45CULL,
		0x25BFFC53906803A6ULL,
		0x8281B332E025C4CBULL,
		0x7B1D3BD61331B0DFULL,
		0x8266DA6CB681D443ULL,
		0xDBA254BE5C9FCC80ULL,
		0xA484975D0AC1BD89ULL,
		0x7193C92C82C25260ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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
		0xFC526ED78DAAD021ULL,
		0x0C21706C25AC3A30ULL,
		0xC0BC250B7F0C31A3ULL,
		0x1D38A56BBBC0C12CULL,
		0x3F68EA7F503D9243ULL,
		0x5114D92A4D1A15A4ULL,
		0x1413123F720BB8AAULL,
		0x2ECD541964460442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A4DDAF1B55A042ULL,
		0x1842E0D84B587461ULL,
		0x81784A16FE186346ULL,
		0x3A714AD777818259ULL,
		0x7ED1D4FEA07B2486ULL,
		0xA229B2549A342B48ULL,
		0x2826247EE4177154ULL,
		0x5D9AA832C88C0884ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2(&k1, &r);
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