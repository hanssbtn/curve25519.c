#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xF9AA68596F651CA8ULL,
		0x445B1561C4F8FAC9ULL,
		0x2984335E1F9C8C88ULL,
		0x4E90DA841DE7A99FULL,
		0xC7DDFDFC3C58AA3EULL,
		0xC1D571D1ABDE08DAULL,
		0x98AA7B169AE3E27AULL,
		0x3C78F05255520E10ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF354D0B2DECA3950ULL,
		0x88B62AC389F1F593ULL,
		0x530866BC3F391910ULL,
		0x9D21B5083BCF533EULL,
		0x8FBBFBF878B1547CULL,
		0x83AAE3A357BC11B5ULL,
		0x3154F62D35C7C4F5ULL,
		0x78F1E0A4AAA41C21ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA8E269DBDC9A8B5ULL,
		0x5D07D17F8D24A045ULL,
		0xEECC98C5D6755C73ULL,
		0xE1EA36355E8441B0ULL,
		0xC9A9A2C59DEC000AULL,
		0xE9E52C6319FB1FC2ULL,
		0xDEF2BB431174A8C0ULL,
		0x0F5A05202128A380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x751C4D3B7B93516AULL,
		0xBA0FA2FF1A49408BULL,
		0xDD99318BACEAB8E6ULL,
		0xC3D46C6ABD088361ULL,
		0x9353458B3BD80015ULL,
		0xD3CA58C633F63F85ULL,
		0xBDE5768622E95181ULL,
		0x1EB40A4042514701ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D20F9CC5EFC3F64ULL,
		0xDC87999013B44D18ULL,
		0x41A106A7DDCD5BF4ULL,
		0x7E368B340D3A708BULL,
		0xE52A926102FAFFEBULL,
		0x45A49F48CC89CFFEULL,
		0x5A2E66D14787AE56ULL,
		0x256130F2AD366DF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A41F398BDF87EC8ULL,
		0xB90F332027689A30ULL,
		0x83420D4FBB9AB7E9ULL,
		0xFC6D16681A74E116ULL,
		0xCA5524C205F5FFD6ULL,
		0x8B493E9199139FFDULL,
		0xB45CCDA28F0F5CACULL,
		0x4AC261E55A6CDBEAULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A5005E809B92DDAULL,
		0xE201303B07856123ULL,
		0x18878DEEAEB3B34AULL,
		0x5C8D7A4E4966A4C0ULL,
		0x7A9FEB348EDCDF3BULL,
		0xE214CE12B0B7224FULL,
		0xCEDE9173036EAC37ULL,
		0x3C0E4F7A90AF8785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4A00BD013725BB4ULL,
		0xC40260760F0AC246ULL,
		0x310F1BDD5D676695ULL,
		0xB91AF49C92CD4980ULL,
		0xF53FD6691DB9BE76ULL,
		0xC4299C25616E449EULL,
		0x9DBD22E606DD586FULL,
		0x781C9EF5215F0F0BULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97FA0CD3556877FDULL,
		0x0ECAAF89AA6C78C3ULL,
		0xB24821355797948CULL,
		0x55F5833D5C7883E1ULL,
		0x1064469E8A8636F4ULL,
		0xE190F42C573B2F5FULL,
		0x00D5847137413479ULL,
		0x15BE83CCF8E470CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FF419A6AAD0EFFAULL,
		0x1D955F1354D8F187ULL,
		0x6490426AAF2F2918ULL,
		0xABEB067AB8F107C3ULL,
		0x20C88D3D150C6DE8ULL,
		0xC321E858AE765EBEULL,
		0x01AB08E26E8268F3ULL,
		0x2B7D0799F1C8E194ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18E7FD77289AE84AULL,
		0xE0B4013001734F22ULL,
		0x0D0990E1A3339A12ULL,
		0x4D045B122B040480ULL,
		0xA86A17A5C3B83C64ULL,
		0x3DBC6495984F1880ULL,
		0x9F71B7EE57A8DE10ULL,
		0x29613F698D108DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31CFFAEE5135D094ULL,
		0xC168026002E69E44ULL,
		0x1A1321C346673425ULL,
		0x9A08B62456080900ULL,
		0x50D42F4B877078C8ULL,
		0x7B78C92B309E3101ULL,
		0x3EE36FDCAF51BC20ULL,
		0x52C27ED31A211B5BULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71DD2405C3E8C099ULL,
		0x4862BABFBFE81BA9ULL,
		0xA4D432F0E71E9C0FULL,
		0x3B01A67B888AEF62ULL,
		0x28D477B4A6F699D9ULL,
		0xA8FF6C126BC48CF8ULL,
		0x3446E456CA5A4682ULL,
		0x399FE913B5D596E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3BA480B87D18132ULL,
		0x90C5757F7FD03752ULL,
		0x49A865E1CE3D381EULL,
		0x76034CF71115DEC5ULL,
		0x51A8EF694DED33B2ULL,
		0x51FED824D78919F0ULL,
		0x688DC8AD94B48D05ULL,
		0x733FD2276BAB2DCAULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4349E3D446BEAE60ULL,
		0x4ACECB3A3838D40BULL,
		0xB4F115389F0D4C9EULL,
		0x53C4BC61E98C0461ULL,
		0x501369A69367A5BDULL,
		0x850D7866E6B35B46ULL,
		0x93392E35B617CFE2ULL,
		0x3B5F933B657C1147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8693C7A88D7D5CC0ULL,
		0x959D96747071A816ULL,
		0x69E22A713E1A993CULL,
		0xA78978C3D31808C3ULL,
		0xA026D34D26CF4B7AULL,
		0x0A1AF0CDCD66B68CULL,
		0x26725C6B6C2F9FC5ULL,
		0x76BF2676CAF8228FULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4A07F55C20E8FC7ULL,
		0x1A15C7F4E1E0C08AULL,
		0x928971099655178DULL,
		0x52AABD488FD2A5C5ULL,
		0x26AF0E906346A390ULL,
		0xB57E243D1B335A44ULL,
		0xCA5A48449710417BULL,
		0x01BEC927DC67F4C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8940FEAB841D1F8EULL,
		0x342B8FE9C3C18115ULL,
		0x2512E2132CAA2F1AULL,
		0xA5557A911FA54B8BULL,
		0x4D5E1D20C68D4720ULL,
		0x6AFC487A3666B488ULL,
		0x94B490892E2082F7ULL,
		0x037D924FB8CFE987ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B74D0E5A79B7126ULL,
		0x98AA0E578DFF3215ULL,
		0x66CE63CAD2BAE323ULL,
		0x8C900C294564C0E6ULL,
		0xF35A909513B14BDEULL,
		0xC6BBF6E54D9881B6ULL,
		0x832BA2B0FED2F802ULL,
		0x13E574346B6C1007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E9A1CB4F36E24CULL,
		0x31541CAF1BFE642AULL,
		0xCD9CC795A575C647ULL,
		0x192018528AC981CCULL,
		0xE6B5212A276297BDULL,
		0x8D77EDCA9B31036DULL,
		0x06574561FDA5F005ULL,
		0x27CAE868D6D8200FULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88BF73CBDD6DF4B0ULL,
		0xC55C71CCAEFA3EB9ULL,
		0x97237FEA9B253333ULL,
		0xF913E41B9F5C104DULL,
		0x7F97FD5242753870ULL,
		0x9F33D9EC6E703573ULL,
		0x053A2C3700F12CBCULL,
		0x0282F48E3F56AF1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117EE797BADBE960ULL,
		0x8AB8E3995DF47D73ULL,
		0x2E46FFD5364A6667ULL,
		0xF227C8373EB8209BULL,
		0xFF2FFAA484EA70E1ULL,
		0x3E67B3D8DCE06AE6ULL,
		0x0A74586E01E25979ULL,
		0x0505E91C7EAD5E34ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5740CB45937E1891ULL,
		0x427BDA29BDBDC215ULL,
		0xC519F52B5D2D0550ULL,
		0x799AC002F6B22BDCULL,
		0xDB2166B5D2669951ULL,
		0x3E112D8437F123FAULL,
		0x7576D13E8F50C059ULL,
		0x06FFD9DFF3ED386CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE81968B26FC3122ULL,
		0x84F7B4537B7B842AULL,
		0x8A33EA56BA5A0AA0ULL,
		0xF3358005ED6457B9ULL,
		0xB642CD6BA4CD32A2ULL,
		0x7C225B086FE247F5ULL,
		0xEAEDA27D1EA180B2ULL,
		0x0DFFB3BFE7DA70D8ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0C109FD47B8C2CEULL,
		0x5A6C657149B2E017ULL,
		0x265923C9D7769C09ULL,
		0x2E1766BB9862BB63ULL,
		0x6BC746D6FDBED22FULL,
		0xD4CC8C3C0CC3FEF1ULL,
		0x46B300F59A49C38BULL,
		0x38546320E79745EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x618213FA8F71859CULL,
		0xB4D8CAE29365C02FULL,
		0x4CB24793AEED3812ULL,
		0x5C2ECD7730C576C6ULL,
		0xD78E8DADFB7DA45EULL,
		0xA99918781987FDE2ULL,
		0x8D6601EB34938717ULL,
		0x70A8C641CF2E8BD4ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5877F1A1BF51FD4ULL,
		0xCF40EEF0AB121C4AULL,
		0x235D2C1E2BCB6AABULL,
		0xDF25E4CF6D8432D2ULL,
		0x1821C41D22933C37ULL,
		0xCDEB3A095DACFEC9ULL,
		0xD45E02D695E8B87AULL,
		0x06728343B60A49D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B0EFE3437EA3FA8ULL,
		0x9E81DDE156243895ULL,
		0x46BA583C5796D557ULL,
		0xBE4BC99EDB0865A4ULL,
		0x3043883A4526786FULL,
		0x9BD67412BB59FD92ULL,
		0xA8BC05AD2BD170F5ULL,
		0x0CE506876C1493B3ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C8A734CA81BEC29ULL,
		0xDBCD8F37106ABDDFULL,
		0xC0FFA777C22BB2ABULL,
		0xF1D16F4D19EE0D51ULL,
		0xFF542CAC44815E5FULL,
		0xE48C1499A1BABC42ULL,
		0x8C8B6A244503FB28ULL,
		0x119387E250B03448ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1914E6995037D852ULL,
		0xB79B1E6E20D57BBFULL,
		0x81FF4EEF84576557ULL,
		0xE3A2DE9A33DC1AA3ULL,
		0xFEA859588902BCBFULL,
		0xC918293343757885ULL,
		0x1916D4488A07F651ULL,
		0x23270FC4A1606891ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF74F6C3487FD2F76ULL,
		0xA886161485411208ULL,
		0xA64FE1E8FB91D95FULL,
		0xBF3BEA6CD1E5C5F1ULL,
		0x12CB84B1D20C36F0ULL,
		0xBE6F82F1A351B30AULL,
		0x09C0F6C3A570DB5EULL,
		0x2B53BE1FF0A7E755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9ED8690FFA5EECULL,
		0x510C2C290A822411ULL,
		0x4C9FC3D1F723B2BFULL,
		0x7E77D4D9A3CB8BE3ULL,
		0x25970963A4186DE1ULL,
		0x7CDF05E346A36614ULL,
		0x1381ED874AE1B6BDULL,
		0x56A77C3FE14FCEAAULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A6279EE18435C36ULL,
		0x15E306A5A4251BC0ULL,
		0xEAD39045BC026535ULL,
		0xF4A41E360BFC161FULL,
		0x6F12BED558B20FC1ULL,
		0x2B1CD53C1B0A3D6AULL,
		0xEDE0FC4EF9C7C2AEULL,
		0x243EDE5A37D0D716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C4F3DC3086B86CULL,
		0x2BC60D4B484A3780ULL,
		0xD5A7208B7804CA6AULL,
		0xE9483C6C17F82C3FULL,
		0xDE257DAAB1641F83ULL,
		0x5639AA7836147AD4ULL,
		0xDBC1F89DF38F855CULL,
		0x487DBCB46FA1AE2DULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F877D3391CB40B5ULL,
		0x62FCB91058636BA3ULL,
		0xE87FAAA81AD73FC6ULL,
		0x40282B0716D52E80ULL,
		0x9F93F1128F814FDCULL,
		0x6166D9ED84BC9D55ULL,
		0x7DBCCCA2A4843F96ULL,
		0x1F215C72C41C8CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0EFA672396816AULL,
		0xC5F97220B0C6D746ULL,
		0xD0FF555035AE7F8CULL,
		0x8050560E2DAA5D01ULL,
		0x3F27E2251F029FB8ULL,
		0xC2CDB3DB09793AABULL,
		0xFB79994549087F2CULL,
		0x3E42B8E5883919A8ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D8DC0F6AA7A3C4FULL,
		0x9067B62EBFCF1905ULL,
		0x21EA289887EF07FEULL,
		0x9668C13D73413CE7ULL,
		0x541192D7D45A7048ULL,
		0x95590CB501222FF4ULL,
		0xAF0AF4300A1F93ADULL,
		0x152758A4471C0C34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B1B81ED54F4789EULL,
		0x20CF6C5D7F9E320AULL,
		0x43D451310FDE0FFDULL,
		0x2CD1827AE68279CEULL,
		0xA82325AFA8B4E091ULL,
		0x2AB2196A02445FE8ULL,
		0x5E15E860143F275BULL,
		0x2A4EB1488E381869ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF83C96F57B792F74ULL,
		0xBCD4FA01762E0089ULL,
		0x9013DF34181BC6F8ULL,
		0xFF980F73A3075468ULL,
		0x6AE50F195BCDDB48ULL,
		0x7570A2FB77B6F03AULL,
		0x1582FFB05CA930D0ULL,
		0x1AEF52BA3808470FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0792DEAF6F25EE8ULL,
		0x79A9F402EC5C0113ULL,
		0x2027BE6830378DF1ULL,
		0xFF301EE7460EA8D1ULL,
		0xD5CA1E32B79BB691ULL,
		0xEAE145F6EF6DE074ULL,
		0x2B05FF60B95261A0ULL,
		0x35DEA57470108E1EULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FC76FB216851C0CULL,
		0x313B016A71AD2427ULL,
		0x24E4973524F8B4E1ULL,
		0xC4B97EEFA231D5C1ULL,
		0xD7F013574264362DULL,
		0x8C2510417BAEEE90ULL,
		0xE5960EA2E1980760ULL,
		0x3340D88829FDD8E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8EDF642D0A3818ULL,
		0x627602D4E35A484FULL,
		0x49C92E6A49F169C2ULL,
		0x8972FDDF4463AB82ULL,
		0xAFE026AE84C86C5BULL,
		0x184A2082F75DDD21ULL,
		0xCB2C1D45C3300EC1ULL,
		0x6681B11053FBB1CDULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD43B8E89505AE844ULL,
		0xF7BD442B94E94CDEULL,
		0x8BD47A6D36F4C3F3ULL,
		0xF7C71396E8289352ULL,
		0xDE92D065C51875CEULL,
		0xB70425720E6E2185ULL,
		0x85969A109CB183C5ULL,
		0x1C274B68CF9680E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8771D12A0B5D088ULL,
		0xEF7A885729D299BDULL,
		0x17A8F4DA6DE987E7ULL,
		0xEF8E272DD05126A5ULL,
		0xBD25A0CB8A30EB9DULL,
		0x6E084AE41CDC430BULL,
		0x0B2D34213963078BULL,
		0x384E96D19F2D01D1ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DE0C3CEDEE96DCBULL,
		0x722B26968CFC54BFULL,
		0xFEAFFD7F78DB9D57ULL,
		0xB84715DFBF203004ULL,
		0x8E7FBBA4F222E975ULL,
		0x08BE369345C769E5ULL,
		0x89B2F8FA6ECB5640ULL,
		0x1DD2AC813EABAB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BC1879DBDD2DB96ULL,
		0xE4564D2D19F8A97EULL,
		0xFD5FFAFEF1B73AAEULL,
		0x708E2BBF7E406009ULL,
		0x1CFF7749E445D2EBULL,
		0x117C6D268B8ED3CBULL,
		0x1365F1F4DD96AC80ULL,
		0x3BA559027D57563DULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3918263A8E9230CULL,
		0xF545061012D737B7ULL,
		0x5B80DD1DAEB65807ULL,
		0x934BDCA485EB4B10ULL,
		0x8A9C2E8E68F036B3ULL,
		0x78114B30D339827AULL,
		0x822AE8ED16425F5FULL,
		0x18AEF735C984DB5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE72304C751D24618ULL,
		0xEA8A0C2025AE6F6FULL,
		0xB701BA3B5D6CB00FULL,
		0x2697B9490BD69620ULL,
		0x15385D1CD1E06D67ULL,
		0xF0229661A67304F5ULL,
		0x0455D1DA2C84BEBEULL,
		0x315DEE6B9309B6B9ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x896B0A0576DFB454ULL,
		0xA60B89D24297E5F4ULL,
		0x04A41FD9139DE2DFULL,
		0xE0DA8221850C138BULL,
		0x1099262B1FCC9268ULL,
		0x8691FCEE3D617230ULL,
		0x7684048D460A6B8AULL,
		0x3FA8BDFAFE20860DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D6140AEDBF68A8ULL,
		0x4C1713A4852FCBE9ULL,
		0x09483FB2273BC5BFULL,
		0xC1B504430A182716ULL,
		0x21324C563F9924D1ULL,
		0x0D23F9DC7AC2E460ULL,
		0xED08091A8C14D715ULL,
		0x7F517BF5FC410C1AULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9F0DC388F2A0B18ULL,
		0x32919D37DFD0431AULL,
		0xE5F84F4FD55A5B59ULL,
		0x94411CC7973F7259ULL,
		0x143405517DEA0318ULL,
		0xFC9A23ECD6E93F8BULL,
		0x99F786508C6F5A73ULL,
		0x0F9D585BD1969904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E1B8711E541630ULL,
		0x65233A6FBFA08635ULL,
		0xCBF09E9FAAB4B6B2ULL,
		0x2882398F2E7EE4B3ULL,
		0x28680AA2FBD40631ULL,
		0xF93447D9ADD27F16ULL,
		0x33EF0CA118DEB4E7ULL,
		0x1F3AB0B7A32D3209ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE6AB1A2091FD7E4ULL,
		0x7C4FD82E2EA0AA2FULL,
		0xC6E0B13FBA1A5A62ULL,
		0x5F1FF73CF895BBB3ULL,
		0x573BF70B81CD1B20ULL,
		0x8B1CB1B801F55944ULL,
		0xA2D29DF70DD575FFULL,
		0x05A4B49FA3D52836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD56344123FAFC8ULL,
		0xF89FB05C5D41545FULL,
		0x8DC1627F7434B4C4ULL,
		0xBE3FEE79F12B7767ULL,
		0xAE77EE17039A3640ULL,
		0x1639637003EAB288ULL,
		0x45A53BEE1BAAEBFFULL,
		0x0B49693F47AA506DULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41612B13CAB5DE5EULL,
		0x90ABAA32AFEAA6C9ULL,
		0x9CC90670B708D93DULL,
		0x9FD4F53F32AC8BDBULL,
		0xC57427F01FB7E0ACULL,
		0xC5CEFEC4AFDC4F41ULL,
		0xF7A5C2AC5F91764BULL,
		0x1CF935F31F92D120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C25627956BBCBCULL,
		0x215754655FD54D92ULL,
		0x39920CE16E11B27BULL,
		0x3FA9EA7E655917B7ULL,
		0x8AE84FE03F6FC159ULL,
		0x8B9DFD895FB89E83ULL,
		0xEF4B8558BF22EC97ULL,
		0x39F26BE63F25A241ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72EACC819D6FA90ULL,
		0xEDCAEECFBD2A5C4BULL,
		0xA52DC10F8FEF8375ULL,
		0x21B6CE5C1265D7AEULL,
		0x286D928DFABEB56BULL,
		0xC9557E5ACB9806BDULL,
		0x2406B89A0B435F5EULL,
		0x125B0D0A6D64F5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE5D599033ADF520ULL,
		0xDB95DD9F7A54B897ULL,
		0x4A5B821F1FDF06EBULL,
		0x436D9CB824CBAF5DULL,
		0x50DB251BF57D6AD6ULL,
		0x92AAFCB597300D7AULL,
		0x480D71341686BEBDULL,
		0x24B61A14DAC9EBAEULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB1B7E88A7D35A30ULL,
		0xA00C5B276C074FE5ULL,
		0x82794FDFA414868DULL,
		0xB3984433ABA71A80ULL,
		0xAC4EACF351FB0F7EULL,
		0x9D70F881FBD08F44ULL,
		0xAF2B669C0010203BULL,
		0x3886EB662110DC9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB636FD114FA6B460ULL,
		0x4018B64ED80E9FCBULL,
		0x04F29FBF48290D1BULL,
		0x67308867574E3501ULL,
		0x589D59E6A3F61EFDULL,
		0x3AE1F103F7A11E89ULL,
		0x5E56CD3800204077ULL,
		0x710DD6CC4221B937ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54396450DA079D99ULL,
		0xBBD1A89805C6916AULL,
		0x645EB0EC449750A9ULL,
		0xC8B7987605E1D8D7ULL,
		0xF54053EC26F3B9E4ULL,
		0x030FE13D2CC1FE9EULL,
		0x1EF95418754F547CULL,
		0x3EBB7D9198CF1F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA872C8A1B40F3B32ULL,
		0x77A351300B8D22D4ULL,
		0xC8BD61D8892EA153ULL,
		0x916F30EC0BC3B1AEULL,
		0xEA80A7D84DE773C9ULL,
		0x061FC27A5983FD3DULL,
		0x3DF2A830EA9EA8F8ULL,
		0x7D76FB23319E3E66ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27A5D9E448C20BDAULL,
		0x73BEBF970B6638E0ULL,
		0xB5949666118CAFEBULL,
		0xEF414FE8361CE6E2ULL,
		0xA87E23AC75348D1BULL,
		0x36469E10ED0E3EDCULL,
		0xD64137B7425A12ADULL,
		0x37E46BDC4FF2ADDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F4BB3C8918417B4ULL,
		0xE77D7F2E16CC71C0ULL,
		0x6B292CCC23195FD6ULL,
		0xDE829FD06C39CDC5ULL,
		0x50FC4758EA691A37ULL,
		0x6C8D3C21DA1C7DB9ULL,
		0xAC826F6E84B4255AULL,
		0x6FC8D7B89FE55BB9ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF202A8864C978C2DULL,
		0xEEF25D34DD969053ULL,
		0x3ED4522D13B738C2ULL,
		0x98DD0A3BC3CDE48DULL,
		0x9FFEAF76D72F978FULL,
		0x170E1289FD3D2F06ULL,
		0x0FE4BE1F75A5A353ULL,
		0x175EFBA7CCA19731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE405510C992F185AULL,
		0xDDE4BA69BB2D20A7ULL,
		0x7DA8A45A276E7185ULL,
		0x31BA1477879BC91AULL,
		0x3FFD5EEDAE5F2F1FULL,
		0x2E1C2513FA7A5E0DULL,
		0x1FC97C3EEB4B46A6ULL,
		0x2EBDF74F99432E62ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF2DAD118F30EB5ULL,
		0xF73CA72FF94BA89DULL,
		0xE20069B09A7AFF16ULL,
		0x741C59A49204CA60ULL,
		0xF01D4F6784DFC04EULL,
		0x578EF883A33F970AULL,
		0x6B21FCD4167B4F08ULL,
		0x25575A0DC9526CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDE5B5A231E61D6AULL,
		0xEE794E5FF297513AULL,
		0xC400D36134F5FE2DULL,
		0xE838B349240994C1ULL,
		0xE03A9ECF09BF809CULL,
		0xAF1DF107467F2E15ULL,
		0xD643F9A82CF69E10ULL,
		0x4AAEB41B92A4D9D2ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6001EFB64E619C9DULL,
		0xEBC2938FC79121CAULL,
		0x6355190C31DADF30ULL,
		0xE12F0BDC0A5437DFULL,
		0x5B4D4BFB9C87E02EULL,
		0x2209F87B00815A10ULL,
		0xC3ECD26B4D37FC75ULL,
		0x2CF7513E63325578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC003DF6C9CC3393AULL,
		0xD785271F8F224394ULL,
		0xC6AA321863B5BE61ULL,
		0xC25E17B814A86FBEULL,
		0xB69A97F7390FC05DULL,
		0x4413F0F60102B420ULL,
		0x87D9A4D69A6FF8EAULL,
		0x59EEA27CC664AAF1ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2422801AB932719ULL,
		0x5453EB722E7B8971ULL,
		0x427EA09D139F84E6ULL,
		0xECBA054C15E1E016ULL,
		0x3129777431310FA6ULL,
		0x382C438D918871F6ULL,
		0x0DF809E91398B04DULL,
		0x09DB12E1927B0FF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4484500357264E32ULL,
		0xA8A7D6E45CF712E3ULL,
		0x84FD413A273F09CCULL,
		0xD9740A982BC3C02CULL,
		0x6252EEE862621F4DULL,
		0x7058871B2310E3ECULL,
		0x1BF013D22731609AULL,
		0x13B625C324F61FE4ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0FC78278102A9ECULL,
		0x657F881D48524D7AULL,
		0x9C7C6CBFCD052FC7ULL,
		0x2E2141047DF696A8ULL,
		0x5FE67BACB06F8AD7ULL,
		0x11994F929A7BF3F9ULL,
		0x081F363A589450B7ULL,
		0x20338D615624E734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F8F04F020553D8ULL,
		0xCAFF103A90A49AF5ULL,
		0x38F8D97F9A0A5F8EULL,
		0x5C428208FBED2D51ULL,
		0xBFCCF75960DF15AEULL,
		0x23329F2534F7E7F2ULL,
		0x103E6C74B128A16EULL,
		0x40671AC2AC49CE68ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E813B4197E4A04AULL,
		0xBF59C71125091272ULL,
		0x11AD8D441AA74902ULL,
		0xD4845A681D75E99AULL,
		0xE83C8D6AEF47F473ULL,
		0x51895D50E736FE41ULL,
		0xC69C5E4C3ECCBB74ULL,
		0x169B1B8A7E8DAAF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0276832FC94094ULL,
		0x7EB38E224A1224E4ULL,
		0x235B1A88354E9205ULL,
		0xA908B4D03AEBD334ULL,
		0xD0791AD5DE8FE8E7ULL,
		0xA312BAA1CE6DFC83ULL,
		0x8D38BC987D9976E8ULL,
		0x2D363714FD1B55E9ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933F1807B8C0EFFEULL,
		0xD4DEA75ED343E892ULL,
		0x76F47D79452027AEULL,
		0xE77FFC5B2DA6B38EULL,
		0xA2FF1B933D5338C0ULL,
		0xB6289F987DEB75B9ULL,
		0x72258AC28100B416ULL,
		0x022921F62DA6F65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267E300F7181DFFCULL,
		0xA9BD4EBDA687D125ULL,
		0xEDE8FAF28A404F5DULL,
		0xCEFFF8B65B4D671CULL,
		0x45FE37267AA67181ULL,
		0x6C513F30FBD6EB73ULL,
		0xE44B15850201682DULL,
		0x045243EC5B4DECB6ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6703987EE40AF2BEULL,
		0xED972FC0425A672FULL,
		0xED67740D16659282ULL,
		0x88C983E018746E57ULL,
		0x5E4978527FEB7A47ULL,
		0xAC53E5970782F1E5ULL,
		0x83CB76611261B213ULL,
		0x00954FA555124E9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE0730FDC815E57CULL,
		0xDB2E5F8084B4CE5EULL,
		0xDACEE81A2CCB2505ULL,
		0x119307C030E8DCAFULL,
		0xBC92F0A4FFD6F48FULL,
		0x58A7CB2E0F05E3CAULL,
		0x0796ECC224C36427ULL,
		0x012A9F4AAA249D3DULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x332DA12CBDE05383ULL,
		0xEBD9F76BC00BB06FULL,
		0xAE71501A50F64777ULL,
		0x43F00BE068FE3EACULL,
		0x6E48AA93717D5D4FULL,
		0x827848C3453EAB70ULL,
		0x67336590708DA559ULL,
		0x28F157B5BFCEE5A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665B42597BC0A706ULL,
		0xD7B3EED7801760DEULL,
		0x5CE2A034A1EC8EEFULL,
		0x87E017C0D1FC7D59ULL,
		0xDC915526E2FABA9EULL,
		0x04F091868A7D56E0ULL,
		0xCE66CB20E11B4AB3ULL,
		0x51E2AF6B7F9DCB42ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CA7A3190941E351ULL,
		0xBE2874FA9AC8FF38ULL,
		0x89CEC7E23AD0AF58ULL,
		0x2B4D218F3D3CC74BULL,
		0x52EF58A546AE0DBCULL,
		0xB8248E1A7F3CA255ULL,
		0x077CBF7CBABF14AFULL,
		0x181EA0DABB9B6F4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x794F46321283C6A2ULL,
		0x7C50E9F53591FE70ULL,
		0x139D8FC475A15EB1ULL,
		0x569A431E7A798E97ULL,
		0xA5DEB14A8D5C1B78ULL,
		0x70491C34FE7944AAULL,
		0x0EF97EF9757E295FULL,
		0x303D41B57736DE98ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23AF8B877C8AB2D9ULL,
		0xD35C3DC168158CE6ULL,
		0x6B8AE3A66C39CF63ULL,
		0xEF1D1146F28F26E8ULL,
		0xBA6BB75573BE4AA2ULL,
		0x400521FA9DE99FC0ULL,
		0x45894827C893CAD0ULL,
		0x00C66C244D288676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x475F170EF91565B2ULL,
		0xA6B87B82D02B19CCULL,
		0xD715C74CD8739EC7ULL,
		0xDE3A228DE51E4DD0ULL,
		0x74D76EAAE77C9545ULL,
		0x800A43F53BD33F81ULL,
		0x8B12904F912795A0ULL,
		0x018CD8489A510CECULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CD105DF29FF137BULL,
		0x5C3F09762A68837DULL,
		0xB5E1FB6A23540F88ULL,
		0x1655403EEF41469DULL,
		0x25037568A1A5B2E2ULL,
		0xA671E608E5F5F2C5ULL,
		0x5BD49CFC0B92836FULL,
		0x1079161C32E6DFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A20BBE53FE26F6ULL,
		0xB87E12EC54D106FAULL,
		0x6BC3F6D446A81F10ULL,
		0x2CAA807DDE828D3BULL,
		0x4A06EAD1434B65C4ULL,
		0x4CE3CC11CBEBE58AULL,
		0xB7A939F8172506DFULL,
		0x20F22C3865CDBFC6ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9761CBD84ABC05BULL,
		0xE4D4AB8B3F56E307ULL,
		0x5C5EB06C20F5F872ULL,
		0x33316B85831DB642ULL,
		0x072043EED88CCCC7ULL,
		0xA36181FDF107DF67ULL,
		0x02D46F66D6034AECULL,
		0x25B6CB1A5A9C8CFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92EC397B095780B6ULL,
		0xC9A957167EADC60FULL,
		0xB8BD60D841EBF0E5ULL,
		0x6662D70B063B6C84ULL,
		0x0E4087DDB119998EULL,
		0x46C303FBE20FBECEULL,
		0x05A8DECDAC0695D9ULL,
		0x4B6D9634B53919F4ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x956732B07259CF89ULL,
		0x334AE295D117A12BULL,
		0x8E0EFA53DFECBB54ULL,
		0x6DC124834CE7BD95ULL,
		0x11CE84525FCCD270ULL,
		0xE41343113BB7F083ULL,
		0x616D71452829D393ULL,
		0x3B9678B0EBF733D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ACE6560E4B39F12ULL,
		0x6695C52BA22F4257ULL,
		0x1C1DF4A7BFD976A8ULL,
		0xDB82490699CF7B2BULL,
		0x239D08A4BF99A4E0ULL,
		0xC8268622776FE106ULL,
		0xC2DAE28A5053A727ULL,
		0x772CF161D7EE67A8ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2CDC2D12503662DULL,
		0x721E4361CF6C87CAULL,
		0xDF8D5A1D737115D8ULL,
		0x5B326618F399FF6FULL,
		0x49EB9AB83F3F8406ULL,
		0xE15287AA6C58F2C8ULL,
		0xDA8D26E6F29BF8DBULL,
		0x22A791DDA6929C3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x859B85A24A06CC5AULL,
		0xE43C86C39ED90F95ULL,
		0xBF1AB43AE6E22BB0ULL,
		0xB664CC31E733FEDFULL,
		0x93D735707E7F080CULL,
		0xC2A50F54D8B1E590ULL,
		0xB51A4DCDE537F1B7ULL,
		0x454F23BB4D25387FULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x518025C935BBAAF6ULL,
		0x75425D9C57CAA580ULL,
		0x6A16E31254CE324BULL,
		0x27F428DCEFBB8D7FULL,
		0x1D3F67EAA9144161ULL,
		0x422ACE6C92613C0AULL,
		0x33C026587849B1D2ULL,
		0x1305317C56ECF702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3004B926B7755ECULL,
		0xEA84BB38AF954B00ULL,
		0xD42DC624A99C6496ULL,
		0x4FE851B9DF771AFEULL,
		0x3A7ECFD5522882C2ULL,
		0x84559CD924C27814ULL,
		0x67804CB0F09363A4ULL,
		0x260A62F8ADD9EE04ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFFA683FDBADB9EBULL,
		0x02A5A52A9B9F42F9ULL,
		0xADE1CB00A87F099CULL,
		0xF3C3D1E6C199EFDFULL,
		0x8C13BE6F7795AF94ULL,
		0x972BEC9EC705447AULL,
		0x82979FB2113484D8ULL,
		0x3851AEC534FE515CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF4D07FB75B73D6ULL,
		0x054B4A55373E85F3ULL,
		0x5BC3960150FE1338ULL,
		0xE787A3CD8333DFBFULL,
		0x18277CDEEF2B5F29ULL,
		0x2E57D93D8E0A88F5ULL,
		0x052F3F64226909B1ULL,
		0x70A35D8A69FCA2B9ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x409636D25685F38AULL,
		0x22EA26733B98972CULL,
		0x4BA9EF48429660ECULL,
		0x758E105474353B84ULL,
		0xE0BAD3F7B4606181ULL,
		0x46E4715AC4062D3AULL,
		0xF475FC675122058AULL,
		0x02FB2E7D3CF5A626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812C6DA4AD0BE714ULL,
		0x45D44CE677312E58ULL,
		0x9753DE90852CC1D8ULL,
		0xEB1C20A8E86A7708ULL,
		0xC175A7EF68C0C302ULL,
		0x8DC8E2B5880C5A75ULL,
		0xE8EBF8CEA2440B14ULL,
		0x05F65CFA79EB4C4DULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC54C654BB3474C4CULL,
		0x175FF4FF958E8FA5ULL,
		0xF987763775CE4754ULL,
		0xBB3BC1E57C9E2D1EULL,
		0xBF453087107E0F88ULL,
		0x70495F11F921E5C4ULL,
		0x9C7FA0BA9528C2A7ULL,
		0x225C115763868354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A98CA97668E9898ULL,
		0x2EBFE9FF2B1D1F4BULL,
		0xF30EEC6EEB9C8EA8ULL,
		0x767783CAF93C5A3DULL,
		0x7E8A610E20FC1F11ULL,
		0xE092BE23F243CB89ULL,
		0x38FF41752A51854EULL,
		0x44B822AEC70D06A9ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B8674E88BC90020ULL,
		0xA45F58075B904227ULL,
		0xAD51D750B76D609CULL,
		0xA85596572F12CD55ULL,
		0x688E5A44DA12ED31ULL,
		0x8B4F7BBDB90EA904ULL,
		0x8B3E7A845C6689D9ULL,
		0x0E2CE2DD6534BF15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB70CE9D117920040ULL,
		0x48BEB00EB720844EULL,
		0x5AA3AEA16EDAC139ULL,
		0x50AB2CAE5E259AABULL,
		0xD11CB489B425DA63ULL,
		0x169EF77B721D5208ULL,
		0x167CF508B8CD13B3ULL,
		0x1C59C5BACA697E2BULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE6A6943F804115EULL,
		0xE8A17F8A1CF6591DULL,
		0x237059CE7A26752CULL,
		0xC88D9A4CC83D0865ULL,
		0x6F3ABF78525E6550ULL,
		0x868518B584C3C984ULL,
		0x4DBDAA0853E7B93CULL,
		0x2E9CE955844ACBBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CD4D287F00822BCULL,
		0xD142FF1439ECB23BULL,
		0x46E0B39CF44CEA59ULL,
		0x911B3499907A10CAULL,
		0xDE757EF0A4BCCAA1ULL,
		0x0D0A316B09879308ULL,
		0x9B7B5410A7CF7279ULL,
		0x5D39D2AB0895977CULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4010E0942BB1AD10ULL,
		0x7F38E86BBBCED3A8ULL,
		0xFF670575C14BFF01ULL,
		0x4C6A5E7EF673ECE5ULL,
		0xCB00199C2CD9319EULL,
		0x314F519301F9DBF1ULL,
		0xADDBD241D5486AD8ULL,
		0x14AF49485ABADBA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8021C12857635A20ULL,
		0xFE71D0D7779DA750ULL,
		0xFECE0AEB8297FE02ULL,
		0x98D4BCFDECE7D9CBULL,
		0x9600333859B2633CULL,
		0x629EA32603F3B7E3ULL,
		0x5BB7A483AA90D5B0ULL,
		0x295E9290B575B741ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C216437BD025DA9ULL,
		0xA97CE9B99C812A78ULL,
		0xD2F12C159573850FULL,
		0x0833B9F6AA1BB803ULL,
		0xEB9E7352F5E4A63EULL,
		0xD72AD812E92DAF62ULL,
		0xBC4DF0DB4A630049ULL,
		0x1F5DC0AD0CF99EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3842C86F7A04BB52ULL,
		0x52F9D373390254F1ULL,
		0xA5E2582B2AE70A1FULL,
		0x106773ED54377007ULL,
		0xD73CE6A5EBC94C7CULL,
		0xAE55B025D25B5EC5ULL,
		0x789BE1B694C60093ULL,
		0x3EBB815A19F33D79ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFF46C8B2E40C6BEULL,
		0x46CFF8E87C0668C1ULL,
		0x940ECEF94C407618ULL,
		0x90B5053E90B0DE5AULL,
		0x0A0BBF52EA6C3C8BULL,
		0xAF9ADC5EA90AE76AULL,
		0x07013CE2FAF589F1ULL,
		0x268F1A99A5098773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FE8D9165C818D7CULL,
		0x8D9FF1D0F80CD183ULL,
		0x281D9DF29880EC30ULL,
		0x216A0A7D2161BCB5ULL,
		0x14177EA5D4D87917ULL,
		0x5F35B8BD5215CED4ULL,
		0x0E0279C5F5EB13E3ULL,
		0x4D1E35334A130EE6ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE95489E2A65914DCULL,
		0xBDA0B7A387D276DFULL,
		0xE5FF820FACC2B88EULL,
		0x4971A8661F5B7206ULL,
		0x8F20AE77D411CFF2ULL,
		0x36995D70AA2B0DD1ULL,
		0xB33E4B156CA4BA40ULL,
		0x2B65467C03E24B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2A913C54CB229B8ULL,
		0x7B416F470FA4EDBFULL,
		0xCBFF041F5985711DULL,
		0x92E350CC3EB6E40DULL,
		0x1E415CEFA8239FE4ULL,
		0x6D32BAE154561BA3ULL,
		0x667C962AD9497480ULL,
		0x56CA8CF807C496FDULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1732360B6E52E45BULL,
		0x3599A62058D742BAULL,
		0x4B9D26DB98DC082DULL,
		0x5A33B3B771CDACD0ULL,
		0x536F134821A54952ULL,
		0x86423B0E7D9B96FCULL,
		0x00824CE89F404881ULL,
		0x275795A2A14211DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E646C16DCA5C8B6ULL,
		0x6B334C40B1AE8574ULL,
		0x973A4DB731B8105AULL,
		0xB467676EE39B59A0ULL,
		0xA6DE2690434A92A4ULL,
		0x0C84761CFB372DF8ULL,
		0x010499D13E809103ULL,
		0x4EAF2B45428423BEULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17A44DFB749CFFD3ULL,
		0x3DFCE6B8C2248A53ULL,
		0x1DF888F1845E6B26ULL,
		0x3E4D55C1C53DBEFBULL,
		0x248E69C4081447AEULL,
		0xBB3BEE1E64C2686AULL,
		0x1F00A12088672957ULL,
		0x04BF5AC387EE215DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F489BF6E939FFA6ULL,
		0x7BF9CD71844914A6ULL,
		0x3BF111E308BCD64CULL,
		0x7C9AAB838A7B7DF6ULL,
		0x491CD38810288F5CULL,
		0x7677DC3CC984D0D4ULL,
		0x3E01424110CE52AFULL,
		0x097EB5870FDC42BAULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59DED445BB6200A3ULL,
		0x4662C9A8D15A2753ULL,
		0x362C1703D03E6DE0ULL,
		0x37EBBF0F44B3DD82ULL,
		0xDF4308C85001030CULL,
		0xFCD471FC0DD3F523ULL,
		0xC3CAF6D994E4EF3BULL,
		0x01FCACB37A0A9427ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3BDA88B76C40146ULL,
		0x8CC59351A2B44EA6ULL,
		0x6C582E07A07CDBC0ULL,
		0x6FD77E1E8967BB04ULL,
		0xBE861190A0020618ULL,
		0xF9A8E3F81BA7EA47ULL,
		0x8795EDB329C9DE77ULL,
		0x03F95966F415284FULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA3F3B1D8C2C035FULL,
		0xB70A3408F1A428DEULL,
		0x21C96986A8960542ULL,
		0x2C4AD51BA5B90D32ULL,
		0xD2F436F254545B4BULL,
		0xE66F78666E49B696ULL,
		0x5FBD13BE6997B25DULL,
		0x3A9DAEB49ABAB5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x547E763B185806BEULL,
		0x6E146811E34851BDULL,
		0x4392D30D512C0A85ULL,
		0x5895AA374B721A64ULL,
		0xA5E86DE4A8A8B696ULL,
		0xCCDEF0CCDC936D2DULL,
		0xBF7A277CD32F64BBULL,
		0x753B5D6935756BB6ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C4E82A2E305E12ULL,
		0xF16E223387930972ULL,
		0xB661E30C19C536FBULL,
		0x024A1054F00545E3ULL,
		0x2F68F1488648ED91ULL,
		0x9F0043D44181D356ULL,
		0x6D3E29CE1C292F64ULL,
		0x27DC90411C08DB4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3389D0545C60BC24ULL,
		0xE2DC44670F2612E4ULL,
		0x6CC3C618338A6DF7ULL,
		0x049420A9E00A8BC7ULL,
		0x5ED1E2910C91DB22ULL,
		0x3E0087A88303A6ACULL,
		0xDA7C539C38525EC9ULL,
		0x4FB920823811B69CULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AD8C8476FD43A97ULL,
		0x1A810DBCBE33C1D3ULL,
		0x1DB0CEC770BAAA18ULL,
		0xD46C011F8EFF6787ULL,
		0x8A8FDE09EDBDF543ULL,
		0xE24FB645FDD635F9ULL,
		0x1EE86BDF50E5D4A1ULL,
		0x13A447C0C30DF223ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35B1908EDFA8752EULL,
		0x35021B797C6783A7ULL,
		0x3B619D8EE1755430ULL,
		0xA8D8023F1DFECF0EULL,
		0x151FBC13DB7BEA87ULL,
		0xC49F6C8BFBAC6BF3ULL,
		0x3DD0D7BEA1CBA943ULL,
		0x27488F81861BE446ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E8610632C62C0A9ULL,
		0x4177096AB6E76AD5ULL,
		0x97B1400B9CF232B3ULL,
		0x95AB8E67B3E7AFB2ULL,
		0xCA97F298366B9537ULL,
		0x7168B88EF2235AD3ULL,
		0x7A82CA5004647A1FULL,
		0x10D0487E9ED0E6BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0C20C658C58152ULL,
		0x82EE12D56DCED5AAULL,
		0x2F62801739E46566ULL,
		0x2B571CCF67CF5F65ULL,
		0x952FE5306CD72A6FULL,
		0xE2D1711DE446B5A7ULL,
		0xF50594A008C8F43EULL,
		0x21A090FD3DA1CD7EULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x827C8A737A2B689BULL,
		0xADB6887EA2E01FBDULL,
		0x476BA01E3BBC4DAFULL,
		0x10F148AAF8180605ULL,
		0x3E6B41B27D90421CULL,
		0xF5DBD255D98CE7ADULL,
		0xB750D8A8AD07CD41ULL,
		0x3C9FDE5881823DD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04F914E6F456D136ULL,
		0x5B6D10FD45C03F7BULL,
		0x8ED7403C77789B5FULL,
		0x21E29155F0300C0AULL,
		0x7CD68364FB208438ULL,
		0xEBB7A4ABB319CF5AULL,
		0x6EA1B1515A0F9A83ULL,
		0x793FBCB103047BA7ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C9F8991FDECF1C2ULL,
		0x6AF2EE5515FAECA2ULL,
		0xEE101D45C228C649ULL,
		0x7F4A6EB58D0CBEEEULL,
		0xF271EF98405D0C31ULL,
		0x029840D67F3942BAULL,
		0x9B1BE4698F1749C3ULL,
		0x30FD64736DDA7D35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x193F1323FBD9E384ULL,
		0xD5E5DCAA2BF5D944ULL,
		0xDC203A8B84518C92ULL,
		0xFE94DD6B1A197DDDULL,
		0xE4E3DF3080BA1862ULL,
		0x053081ACFE728575ULL,
		0x3637C8D31E2E9386ULL,
		0x61FAC8E6DBB4FA6BULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BA047A0234B68B5ULL,
		0x62D55055CADFA1A8ULL,
		0x2E8C4A3B08D94D87ULL,
		0x3ECA32BE3D0B1305ULL,
		0x44B6349CFB7CB892ULL,
		0x52EF9C6B1CBD855BULL,
		0x3B14695AE6C313E4ULL,
		0x22E5FA04618FFC65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7408F404696D16AULL,
		0xC5AAA0AB95BF4350ULL,
		0x5D18947611B29B0EULL,
		0x7D94657C7A16260AULL,
		0x896C6939F6F97124ULL,
		0xA5DF38D6397B0AB6ULL,
		0x7628D2B5CD8627C8ULL,
		0x45CBF408C31FF8CAULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98C84017614D5E3CULL,
		0xE2976E9EC79448FAULL,
		0xD1914D643A22CE73ULL,
		0x028FFB12C4D05C80ULL,
		0x2E742140D79133CAULL,
		0xA50C09E5D7142A2FULL,
		0x90977C2465C72E20ULL,
		0x0D02269AC6AD4392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3190802EC29ABC78ULL,
		0xC52EDD3D8F2891F5ULL,
		0xA3229AC874459CE7ULL,
		0x051FF62589A0B901ULL,
		0x5CE84281AF226794ULL,
		0x4A1813CBAE28545EULL,
		0x212EF848CB8E5C41ULL,
		0x1A044D358D5A8725ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F8F8CD6A01AB1DFULL,
		0x521A51ABBDA26E75ULL,
		0x775565B0048850B4ULL,
		0x08046FD24B102541ULL,
		0x7DE7B924ED4E180AULL,
		0x822E535A3E9C8EF3ULL,
		0xB4F8C7B83B4B6105ULL,
		0x3C965AA085824336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1F19AD403563BEULL,
		0xA434A3577B44DCEAULL,
		0xEEAACB600910A168ULL,
		0x1008DFA496204A82ULL,
		0xFBCF7249DA9C3014ULL,
		0x045CA6B47D391DE6ULL,
		0x69F18F707696C20BULL,
		0x792CB5410B04866DULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EEED6F4650C2BA4ULL,
		0xD23DED2E452103DEULL,
		0xCAA5E07E6A1551CEULL,
		0xF002406DE56231EEULL,
		0xFB9957C74C1637E8ULL,
		0x4B9F0CE989685B7FULL,
		0x1DE716D1771E6044ULL,
		0x333C49538DFB2DF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DDDADE8CA185748ULL,
		0xA47BDA5C8A4207BDULL,
		0x954BC0FCD42AA39DULL,
		0xE00480DBCAC463DDULL,
		0xF732AF8E982C6FD1ULL,
		0x973E19D312D0B6FFULL,
		0x3BCE2DA2EE3CC088ULL,
		0x667892A71BF65BF0ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01B34A48F8651F34ULL,
		0xD18D3CEDC54F7005ULL,
		0xECFF60E6DDECB98DULL,
		0x5B35D8D83F83F47EULL,
		0x993914915726E6A0ULL,
		0xE2E8EF918F454522ULL,
		0x14707557F25119F8ULL,
		0x34F4B3D4F2C97027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03669491F0CA3E68ULL,
		0xA31A79DB8A9EE00AULL,
		0xD9FEC1CDBBD9731BULL,
		0xB66BB1B07F07E8FDULL,
		0x32722922AE4DCD40ULL,
		0xC5D1DF231E8A8A45ULL,
		0x28E0EAAFE4A233F1ULL,
		0x69E967A9E592E04EULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0C465ACC8DE1E6EULL,
		0x6E5A538E43443100ULL,
		0x4BD3648DC7E99DB8ULL,
		0x34EAE30266F425FDULL,
		0xB9D4F3FB43E860C2ULL,
		0x6A8E5D4CB974D043ULL,
		0x6E60B1074A59E73FULL,
		0x05E4FBAC5D2DA1F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8188CB5991BC3CDCULL,
		0xDCB4A71C86886201ULL,
		0x97A6C91B8FD33B70ULL,
		0x69D5C604CDE84BFAULL,
		0x73A9E7F687D0C184ULL,
		0xD51CBA9972E9A087ULL,
		0xDCC1620E94B3CE7EULL,
		0x0BC9F758BA5B43E8ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAB11CCD105A5328ULL,
		0xF3BC07963CDA0B98ULL,
		0x77A31D4B94B809A4ULL,
		0x6495DFE88282E3F6ULL,
		0x1EB6D3F212EE6A84ULL,
		0x2C591B3F5FA7B642ULL,
		0xD2D467F1CA23A461ULL,
		0x383CD03E1D873901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5562399A20B4A650ULL,
		0xE7780F2C79B41731ULL,
		0xEF463A9729701349ULL,
		0xC92BBFD10505C7ECULL,
		0x3D6DA7E425DCD508ULL,
		0x58B2367EBF4F6C84ULL,
		0xA5A8CFE3944748C2ULL,
		0x7079A07C3B0E7203ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA56FA86AFFDADA04ULL,
		0x75E9DE6B6D7488D8ULL,
		0x18AF8A427CC7DCE6ULL,
		0xD4033BE10D18077DULL,
		0xED7283A33890F238ULL,
		0xB1BB55B7E7FB6F37ULL,
		0x59EDABF663B172BCULL,
		0x01C5714CEA69C1D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ADF50D5FFB5B408ULL,
		0xEBD3BCD6DAE911B1ULL,
		0x315F1484F98FB9CCULL,
		0xA80677C21A300EFAULL,
		0xDAE507467121E471ULL,
		0x6376AB6FCFF6DE6FULL,
		0xB3DB57ECC762E579ULL,
		0x038AE299D4D383A8ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E6190C36AD00DDEULL,
		0x3CCC1A6EE8206F8BULL,
		0x22BA62672C7F9745ULL,
		0x71E91F21380AC530ULL,
		0x75C7A3AE7F9D5B45ULL,
		0x02D01C7F523F8DC5ULL,
		0xD3FF554D156F079FULL,
		0x06E360C3BDDC7AE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCC32186D5A01BBCULL,
		0x799834DDD040DF16ULL,
		0x4574C4CE58FF2E8AULL,
		0xE3D23E4270158A60ULL,
		0xEB8F475CFF3AB68AULL,
		0x05A038FEA47F1B8AULL,
		0xA7FEAA9A2ADE0F3EULL,
		0x0DC6C1877BB8F5C9ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5240F1D23F48F0C6ULL,
		0x1EC9FDEF9FBEEACBULL,
		0x97E71CC5DD4F4191ULL,
		0x836BF236E65DA3B9ULL,
		0xD7D1DF65258A11D5ULL,
		0xD3F92A7DE5A1F154ULL,
		0x2086BF09596D8EDEULL,
		0x2200344F3E9A0CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA481E3A47E91E18CULL,
		0x3D93FBDF3F7DD596ULL,
		0x2FCE398BBA9E8322ULL,
		0x06D7E46DCCBB4773ULL,
		0xAFA3BECA4B1423ABULL,
		0xA7F254FBCB43E2A9ULL,
		0x410D7E12B2DB1DBDULL,
		0x4400689E7D3419D2ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD51DFDDA45CB728AULL,
		0x7FEA04C4978DA69BULL,
		0xA4DA21CA377D4E79ULL,
		0x4B44FEFF81C96C8AULL,
		0x23729B6BB0001210ULL,
		0x890D72853161050CULL,
		0xDF7A477036244B5FULL,
		0x3D713B23ADC060B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3BFBB48B96E514ULL,
		0xFFD409892F1B4D37ULL,
		0x49B443946EFA9CF2ULL,
		0x9689FDFF0392D915ULL,
		0x46E536D760002420ULL,
		0x121AE50A62C20A18ULL,
		0xBEF48EE06C4896BFULL,
		0x7AE276475B80C16FULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x215E3416C6CDF3B2ULL,
		0xA41C150CFE464241ULL,
		0x0A68D50C34D50B95ULL,
		0x2AE6E1FC41498AA7ULL,
		0x1AE02052C6D0518CULL,
		0x3A86C9A704D3F7B0ULL,
		0x2499882D036AEE4BULL,
		0x04399DF836B942CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BC682D8D9BE764ULL,
		0x48382A19FC8C8482ULL,
		0x14D1AA1869AA172BULL,
		0x55CDC3F88293154EULL,
		0x35C040A58DA0A318ULL,
		0x750D934E09A7EF60ULL,
		0x4933105A06D5DC96ULL,
		0x08733BF06D728596ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCD65CEB4241BC76ULL,
		0x4565C805A4239B31ULL,
		0xAF8038405E584FD0ULL,
		0x856348CFC98E3519ULL,
		0x9BEF92F3E5F29A11ULL,
		0xC17F63EB1302AFD7ULL,
		0x1BE38E5B17E53111ULL,
		0x09627377EAB34A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9ACB9D6848378ECULL,
		0x8ACB900B48473663ULL,
		0x5F007080BCB09FA0ULL,
		0x0AC6919F931C6A33ULL,
		0x37DF25E7CBE53423ULL,
		0x82FEC7D626055FAFULL,
		0x37C71CB62FCA6223ULL,
		0x12C4E6EFD566941CULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56A92426A0128702ULL,
		0x81D042A13784EB93ULL,
		0xD2F61EA19E5BA42AULL,
		0x211DCF453B0DB2A4ULL,
		0xA26CC5E9610C0642ULL,
		0xE7EA70A880EE857BULL,
		0x682836D72BE8A799ULL,
		0x29E5F4C8DA3BE42DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD52484D40250E04ULL,
		0x03A085426F09D726ULL,
		0xA5EC3D433CB74855ULL,
		0x423B9E8A761B6549ULL,
		0x44D98BD2C2180C84ULL,
		0xCFD4E15101DD0AF7ULL,
		0xD0506DAE57D14F33ULL,
		0x53CBE991B477C85AULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A63B5D73771C022ULL,
		0x1D324EDDDB68331BULL,
		0xFCED1C6FF84C849AULL,
		0x29596E2C067C89D1ULL,
		0x79CB38784224F29EULL,
		0x1436CB099733B940ULL,
		0x9A07B9E949426070ULL,
		0x1437F845A5FA441DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54C76BAE6EE38044ULL,
		0x3A649DBBB6D06636ULL,
		0xF9DA38DFF0990934ULL,
		0x52B2DC580CF913A3ULL,
		0xF39670F08449E53CULL,
		0x286D96132E677280ULL,
		0x340F73D29284C0E0ULL,
		0x286FF08B4BF4883BULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCCD04848662DEB1ULL,
		0xB2EF6CEB9676AE61ULL,
		0xF309F838E629A744ULL,
		0xE5EB36AEF1A42A1BULL,
		0x7CE557192467ED3EULL,
		0xF05FFB4314E13AB4ULL,
		0x90AD3C5FF1BBCB51ULL,
		0x116CFAEFE2A5D525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x999A09090CC5BD62ULL,
		0x65DED9D72CED5CC3ULL,
		0xE613F071CC534E89ULL,
		0xCBD66D5DE3485437ULL,
		0xF9CAAE3248CFDA7DULL,
		0xE0BFF68629C27568ULL,
		0x215A78BFE37796A3ULL,
		0x22D9F5DFC54BAA4BULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAD251BEA7083F3FULL,
		0x4BA5FDDE178121F4ULL,
		0x969E7E157F94AE10ULL,
		0xFD87763BD5DF4F06ULL,
		0xB673468CC3D12BCCULL,
		0xD947150D16AC3FFBULL,
		0xF18C55533FA819BAULL,
		0x1C494A8B5941B48CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A4A37D4E107E7EULL,
		0x974BFBBC2F0243E9ULL,
		0x2D3CFC2AFF295C20ULL,
		0xFB0EEC77ABBE9E0DULL,
		0x6CE68D1987A25799ULL,
		0xB28E2A1A2D587FF7ULL,
		0xE318AAA67F503375ULL,
		0x38929516B2836919ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF670C86A2C661BA6ULL,
		0xF317C7C5426E2250ULL,
		0x91A6FCFD863DFFBDULL,
		0x80582F2F043ACE02ULL,
		0xE61089219F64DD9DULL,
		0xE9132D56601E0CF1ULL,
		0xEB193B8D888D282BULL,
		0x0A57FEE656922F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE190D458CC374CULL,
		0xE62F8F8A84DC44A1ULL,
		0x234DF9FB0C7BFF7BULL,
		0x00B05E5E08759C05ULL,
		0xCC2112433EC9BB3BULL,
		0xD2265AACC03C19E3ULL,
		0xD632771B111A5057ULL,
		0x14AFFDCCAD245F19ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09919FD5C563260DULL,
		0x56D87B0C6C209ED2ULL,
		0xD2305EC5683A48C2ULL,
		0x7FCD664D040BCAB5ULL,
		0x8D3CEB2F35A03EE1ULL,
		0x9FB3A94070B34A73ULL,
		0x77B3428200D0C3E4ULL,
		0x1596FF83447C8A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13233FAB8AC64C1AULL,
		0xADB0F618D8413DA4ULL,
		0xA460BD8AD0749184ULL,
		0xFF9ACC9A0817956BULL,
		0x1A79D65E6B407DC2ULL,
		0x3F675280E16694E7ULL,
		0xEF66850401A187C9ULL,
		0x2B2DFF0688F9152EULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A4B104F4CF9578DULL,
		0xC065D9C2C0369DDAULL,
		0x9998A6334C658DFBULL,
		0x196BEAF539F19E47ULL,
		0x5E00FFE65E6B404BULL,
		0x9F9F5DE81C0B1E0CULL,
		0x57F9F5ED271CB862ULL,
		0x35E3E8B3CE7D12D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1496209E99F2AF1AULL,
		0x80CBB385806D3BB5ULL,
		0x33314C6698CB1BF7ULL,
		0x32D7D5EA73E33C8FULL,
		0xBC01FFCCBCD68096ULL,
		0x3F3EBBD038163C18ULL,
		0xAFF3EBDA4E3970C5ULL,
		0x6BC7D1679CFA25B0ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8BB11617F80E5EBULL,
		0xB62EE040309BF615ULL,
		0xD583EEC6C9F2E85FULL,
		0x84B6A47C1F5E447EULL,
		0xB45393C23485B490ULL,
		0x774F01454E4B83ACULL,
		0x10520DEA77FB21BCULL,
		0x1ED036BCBF89BC79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17622C2FF01CBD6ULL,
		0x6C5DC0806137EC2BULL,
		0xAB07DD8D93E5D0BFULL,
		0x096D48F83EBC88FDULL,
		0x68A72784690B6921ULL,
		0xEE9E028A9C970759ULL,
		0x20A41BD4EFF64378ULL,
		0x3DA06D797F1378F2ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C9D9AC8CC9B1DC2ULL,
		0xBA92CF1ED8E9DCFEULL,
		0x1331E19C0C3CBB4BULL,
		0x3EA6FC4F23FF78E5ULL,
		0x00E6F21F32543689ULL,
		0xE70780D798B64C2FULL,
		0x4DD1860580CE2287ULL,
		0x2B0113F3062EBDB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993B359199363B84ULL,
		0x75259E3DB1D3B9FCULL,
		0x2663C33818797697ULL,
		0x7D4DF89E47FEF1CAULL,
		0x01CDE43E64A86D12ULL,
		0xCE0F01AF316C985EULL,
		0x9BA30C0B019C450FULL,
		0x560227E60C5D7B72ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF7C4D6E8438926ULL,
		0xA38CE2A4D0C2F7E1ULL,
		0x0A12C40350F70537ULL,
		0xE4798748A4D45733ULL,
		0x59D7FF9A0CEE9D17ULL,
		0x136BED503B74F07EULL,
		0xCDA4CF27DD1EE0ECULL,
		0x1A399E2E7E0D1FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEF89ADD087124CULL,
		0x4719C549A185EFC2ULL,
		0x14258806A1EE0A6FULL,
		0xC8F30E9149A8AE66ULL,
		0xB3AFFF3419DD3A2FULL,
		0x26D7DAA076E9E0FCULL,
		0x9B499E4FBA3DC1D8ULL,
		0x34733C5CFC1A3F9DULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1C81902C9D2A883ULL,
		0xB9F300F2C00DD030ULL,
		0x97F208CDCECBB212ULL,
		0xB5971BACFBB65BE5ULL,
		0x78CE08DB3002EF17ULL,
		0x0A0730809D0734ECULL,
		0xD87A2BF1C6F084F6ULL,
		0x363F42D4858699AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4390320593A55106ULL,
		0x73E601E5801BA061ULL,
		0x2FE4119B9D976425ULL,
		0x6B2E3759F76CB7CBULL,
		0xF19C11B66005DE2FULL,
		0x140E61013A0E69D8ULL,
		0xB0F457E38DE109ECULL,
		0x6C7E85A90B0D3355ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59222FA6EF5248F1ULL,
		0x0EA1627ACF24E936ULL,
		0x0698E5D6888E15BCULL,
		0x4374A6A8FDA2EAF7ULL,
		0xCC2098DA73CBD8B4ULL,
		0x2E3E9FB6E1302155ULL,
		0xC5DF7F0F3B27819BULL,
		0x0B5C4BF9FEB0F947ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2445F4DDEA491E2ULL,
		0x1D42C4F59E49D26CULL,
		0x0D31CBAD111C2B78ULL,
		0x86E94D51FB45D5EEULL,
		0x984131B4E797B168ULL,
		0x5C7D3F6DC26042ABULL,
		0x8BBEFE1E764F0336ULL,
		0x16B897F3FD61F28FULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE321541FA2F9613CULL,
		0xAFFA4024D963F8BFULL,
		0x238525CD2E258E88ULL,
		0x169CBF6D0521D0B4ULL,
		0xA438BFE8D9B74B69ULL,
		0xCBA0D572BB34C94BULL,
		0xA0E257A3DE4DB40AULL,
		0x074E249AB1BA8BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC642A83F45F2C278ULL,
		0x5FF48049B2C7F17FULL,
		0x470A4B9A5C4B1D11ULL,
		0x2D397EDA0A43A168ULL,
		0x48717FD1B36E96D2ULL,
		0x9741AAE576699297ULL,
		0x41C4AF47BC9B6815ULL,
		0x0E9C49356375178BULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x722F8CCAF20A3488ULL,
		0xB595C7A3C1637112ULL,
		0xF4B61BE8B4412FD1ULL,
		0xF899067D8ACB845CULL,
		0x3921A535569893E1ULL,
		0xC1A309091FF965C0ULL,
		0xB63374D55E7AE784ULL,
		0x23370DBA9048AEA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE45F1995E4146910ULL,
		0x6B2B8F4782C6E224ULL,
		0xE96C37D168825FA3ULL,
		0xF1320CFB159708B9ULL,
		0x72434A6AAD3127C3ULL,
		0x834612123FF2CB80ULL,
		0x6C66E9AABCF5CF09ULL,
		0x466E1B7520915D43ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0624B5F1E21963DULL,
		0x785755FA8C76FFD3ULL,
		0xF60013F0BBF39B64ULL,
		0xA44543873317CF6DULL,
		0x1334CF37BF19B909ULL,
		0xB20E7AE3EA06FF6FULL,
		0xD957E81DFBDF9928ULL,
		0x36AEED36F4F3A2DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C496BE3C432C7AULL,
		0xF0AEABF518EDFFA7ULL,
		0xEC0027E177E736C8ULL,
		0x488A870E662F9EDBULL,
		0x26699E6F7E337213ULL,
		0x641CF5C7D40DFEDEULL,
		0xB2AFD03BF7BF3251ULL,
		0x6D5DDA6DE9E745B5ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3907424BE018BDA9ULL,
		0x46DE7B841B89A900ULL,
		0xFAD88E8583A296DAULL,
		0x22E96072C4AB59BBULL,
		0xDCD444A60A768B21ULL,
		0x73E0A1002987AC8EULL,
		0x4A897576E9961F37ULL,
		0x1B8B29E31042D4E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x720E8497C0317B52ULL,
		0x8DBCF70837135200ULL,
		0xF5B11D0B07452DB4ULL,
		0x45D2C0E58956B377ULL,
		0xB9A8894C14ED1642ULL,
		0xE7C14200530F591DULL,
		0x9512EAEDD32C3E6EULL,
		0x371653C62085A9C2ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03D32EC2FF7761E7ULL,
		0xB7D6F683AADA567AULL,
		0x2B774FC90E94B5AAULL,
		0x4F664DEC8839B3C3ULL,
		0xBFF20BAABA41343CULL,
		0xCA9A2B3C4A5555E3ULL,
		0x5A64B81F3B01D4C4ULL,
		0x2D127D023BB055B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A65D85FEEEC3CEULL,
		0x6FADED0755B4ACF4ULL,
		0x56EE9F921D296B55ULL,
		0x9ECC9BD910736786ULL,
		0x7FE4175574826878ULL,
		0x9534567894AAABC7ULL,
		0xB4C9703E7603A989ULL,
		0x5A24FA047760AB64ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6A0AAEA6DD54B22ULL,
		0x322809FA068BAA1BULL,
		0xDAB017601719FDD2ULL,
		0xE595918475D79956ULL,
		0x1FCCDDCFA05A61E4ULL,
		0x15E088E1C4CE85EFULL,
		0x68EE7D6CFE9042D0ULL,
		0x1F1F241FE5055772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4155D4DBAA9644ULL,
		0x645013F40D175437ULL,
		0xB5602EC02E33FBA4ULL,
		0xCB2B2308EBAF32ADULL,
		0x3F99BB9F40B4C3C9ULL,
		0x2BC111C3899D0BDEULL,
		0xD1DCFAD9FD2085A0ULL,
		0x3E3E483FCA0AAEE4ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD05E0709297B855ULL,
		0x5250D83ADD802425ULL,
		0x56E78DA89ACFD542ULL,
		0x2447BD36626F5A32ULL,
		0x6D186D2E8618D0A1ULL,
		0xE69C17C46FDE15EFULL,
		0xE61804A345171FD9ULL,
		0x3FDD72D89E13CB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0BC0E1252F70AAULL,
		0xA4A1B075BB00484BULL,
		0xADCF1B51359FAA84ULL,
		0x488F7A6CC4DEB464ULL,
		0xDA30DA5D0C31A142ULL,
		0xCD382F88DFBC2BDEULL,
		0xCC3009468A2E3FB3ULL,
		0x7FBAE5B13C27971FULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EAE5141BA9D973CULL,
		0x7C18A82D4DD882A2ULL,
		0xC8BA7823C3B58018ULL,
		0x633B808437377204ULL,
		0x820F25DF451FA082ULL,
		0x3FA059E09C9D69BDULL,
		0x22AAC7AE293989FBULL,
		0x30F0FD821C714961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D5CA283753B2E78ULL,
		0xF831505A9BB10544ULL,
		0x9174F047876B0030ULL,
		0xC67701086E6EE409ULL,
		0x041E4BBE8A3F4104ULL,
		0x7F40B3C1393AD37BULL,
		0x45558F5C527313F6ULL,
		0x61E1FB0438E292C2ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BCB96E1EBC75C9FULL,
		0xBA610458352C9AB4ULL,
		0xD7EF1F02688AE505ULL,
		0x6D18B70B287579CBULL,
		0xB1F62BC4ACBB9B9CULL,
		0x5D914DE02A7ECEC7ULL,
		0x4374E8608255ABD2ULL,
		0x0BFD8817C89ACC46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57972DC3D78EB93EULL,
		0x74C208B06A593568ULL,
		0xAFDE3E04D115CA0BULL,
		0xDA316E1650EAF397ULL,
		0x63EC578959773738ULL,
		0xBB229BC054FD9D8FULL,
		0x86E9D0C104AB57A4ULL,
		0x17FB102F9135988CULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1243941C62EA6E0DULL,
		0x391A4C88B4B2AD34ULL,
		0x6CF3257EEE1B0BCAULL,
		0x332B45613FFAFBD6ULL,
		0xCBEBDD48E3E66FDFULL,
		0x4445F05E1523B713ULL,
		0xE6EB03EB1F6CA00DULL,
		0x0371A8925195FA17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24872838C5D4DC1AULL,
		0x7234991169655A68ULL,
		0xD9E64AFDDC361794ULL,
		0x66568AC27FF5F7ACULL,
		0x97D7BA91C7CCDFBEULL,
		0x888BE0BC2A476E27ULL,
		0xCDD607D63ED9401AULL,
		0x06E35124A32BF42FULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6776CE94E28714CULL,
		0x382B7675AA90FB43ULL,
		0xA795B874DA804613ULL,
		0x954EA6483332233DULL,
		0xA230A99999BC15EAULL,
		0x0822FC58F9C1EA34ULL,
		0xCEAF5590340E251EULL,
		0x08DA48FD177C139BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECEED9D29C50E298ULL,
		0x7056ECEB5521F687ULL,
		0x4F2B70E9B5008C26ULL,
		0x2A9D4C906664467BULL,
		0x4461533333782BD5ULL,
		0x1045F8B1F383D469ULL,
		0x9D5EAB20681C4A3CULL,
		0x11B491FA2EF82737ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8953B19925F53A24ULL,
		0xBF4402A940F740E3ULL,
		0xB5C95FC6A65E058FULL,
		0x8949F64E87EA5F7BULL,
		0xB09E00854163CEC8ULL,
		0xA487CB0EDCD0EE08ULL,
		0xD57CCBB9108D6EFDULL,
		0x30062B6B8B9B3B39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A763324BEA7448ULL,
		0x7E88055281EE81C7ULL,
		0x6B92BF8D4CBC0B1FULL,
		0x1293EC9D0FD4BEF7ULL,
		0x613C010A82C79D91ULL,
		0x490F961DB9A1DC11ULL,
		0xAAF99772211ADDFBULL,
		0x600C56D717367673ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95645FD6771658B4ULL,
		0x6F1CF0906F5E9954ULL,
		0xF153E0A662E4802BULL,
		0xB48A0B7758736E10ULL,
		0xC1A6994F0C558130ULL,
		0x3F391FD95C076BD0ULL,
		0x14B781D07ACCFAACULL,
		0x1AC631240995EF9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AC8BFACEE2CB168ULL,
		0xDE39E120DEBD32A9ULL,
		0xE2A7C14CC5C90056ULL,
		0x691416EEB0E6DC21ULL,
		0x834D329E18AB0261ULL,
		0x7E723FB2B80ED7A1ULL,
		0x296F03A0F599F558ULL,
		0x358C6248132BDF34ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x456B7D36CCEAC60EULL,
		0x8A163A01C68BBBB3ULL,
		0x043E092F7E02254EULL,
		0xBAEB9EB6D7CD1552ULL,
		0xC5B6C201A306B17AULL,
		0x520CB10F9824AC44ULL,
		0xD11D2EBF047C425AULL,
		0x2A90CB0C4C7FCEF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AD6FA6D99D58C1CULL,
		0x142C74038D177766ULL,
		0x087C125EFC044A9DULL,
		0x75D73D6DAF9A2AA4ULL,
		0x8B6D8403460D62F5ULL,
		0xA419621F30495889ULL,
		0xA23A5D7E08F884B4ULL,
		0x5521961898FF9DEFULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x692A70EEB882C9B5ULL,
		0x15ABA7707CAE72ABULL,
		0x0E357289AAD4D7E7ULL,
		0x89AAD50D88141659ULL,
		0x845A2CD0387A7DAAULL,
		0x3D51F27ACDE2AC93ULL,
		0x1402110553CFF41AULL,
		0x28AA8C71FC2BF562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD254E1DD7105936AULL,
		0x2B574EE0F95CE556ULL,
		0x1C6AE51355A9AFCEULL,
		0x1355AA1B10282CB2ULL,
		0x08B459A070F4FB55ULL,
		0x7AA3E4F59BC55927ULL,
		0x2804220AA79FE834ULL,
		0x515518E3F857EAC4ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB3FC42BA4874CE8ULL,
		0xE6C74D064028D7B8ULL,
		0x64BBD6F79F6A9E52ULL,
		0x18C88E6422D386A3ULL,
		0x983BF795A4AB0FC1ULL,
		0x51EF7DD4C9F1E6BDULL,
		0x5E3435A6E7E01EC5ULL,
		0x139B8B99348727F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67F8857490E99D0ULL,
		0xCD8E9A0C8051AF71ULL,
		0xC977ADEF3ED53CA5ULL,
		0x31911CC845A70D46ULL,
		0x3077EF2B49561F82ULL,
		0xA3DEFBA993E3CD7BULL,
		0xBC686B4DCFC03D8AULL,
		0x27371732690E4FE8ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07831BD45B4BE751ULL,
		0x449F18906EC790F2ULL,
		0x53D792B931542B29ULL,
		0x3DC8DF0664B4E5A2ULL,
		0x457CC75D1E46CF8FULL,
		0x93435034C6EE3685ULL,
		0xBA1ACFC32C944155ULL,
		0x168E2C78F3A811C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0637A8B697CEA2ULL,
		0x893E3120DD8F21E4ULL,
		0xA7AF257262A85652ULL,
		0x7B91BE0CC969CB44ULL,
		0x8AF98EBA3C8D9F1EULL,
		0x2686A0698DDC6D0AULL,
		0x74359F86592882ABULL,
		0x2D1C58F1E7502393ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC89C94636C9DA9DULL,
		0x2C505BDEEB20C965ULL,
		0xD25867E65500A5E1ULL,
		0x7708A0C6EE5C56D2ULL,
		0xD183DC6A3E166366ULL,
		0x239C2A13F8720D1AULL,
		0x5616C0E0329F9FE0ULL,
		0x1AEF719A7103E3C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7913928C6D93B53AULL,
		0x58A0B7BDD64192CBULL,
		0xA4B0CFCCAA014BC2ULL,
		0xEE11418DDCB8ADA5ULL,
		0xA307B8D47C2CC6CCULL,
		0x47385427F0E41A35ULL,
		0xAC2D81C0653F3FC0ULL,
		0x35DEE334E207C792ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5A7C9FAA354365AULL,
		0x2141F9D8D1912DA6ULL,
		0x59DCF2F4CE1AE41CULL,
		0xEB30587E0C631A24ULL,
		0x6078F323B486E49AULL,
		0x8EFF27EC59724B3CULL,
		0xA60ECDFFF28A1011ULL,
		0x2D1BC00EE06FE01AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4F93F546A86CB4ULL,
		0x4283F3B1A3225B4DULL,
		0xB3B9E5E99C35C838ULL,
		0xD660B0FC18C63448ULL,
		0xC0F1E647690DC935ULL,
		0x1DFE4FD8B2E49678ULL,
		0x4C1D9BFFE5142023ULL,
		0x5A37801DC0DFC035ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43A1DA57B4A43968ULL,
		0x5D4B81A4C3F2C9E8ULL,
		0x27FBAC6740CD040DULL,
		0x416E091A26E377D4ULL,
		0x241AF7AA4B8EE921ULL,
		0x44F93F11F82BECDCULL,
		0xB6154FC666BB931DULL,
		0x3B7FFD57E98E3710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8743B4AF694872D0ULL,
		0xBA97034987E593D0ULL,
		0x4FF758CE819A081AULL,
		0x82DC12344DC6EFA8ULL,
		0x4835EF54971DD242ULL,
		0x89F27E23F057D9B8ULL,
		0x6C2A9F8CCD77263AULL,
		0x76FFFAAFD31C6E21ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A914B40873930A0ULL,
		0x42B1BA99E4B4D7B2ULL,
		0x223C2FE1803463ADULL,
		0x22E034DF2C033588ULL,
		0x377CD763FBC62C46ULL,
		0x3A812CB3257B1D2DULL,
		0x9F087BA395FCFEFCULL,
		0x320F8CBA855EA216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x752296810E726140ULL,
		0x85637533C969AF64ULL,
		0x44785FC30068C75AULL,
		0x45C069BE58066B10ULL,
		0x6EF9AEC7F78C588CULL,
		0x750259664AF63A5AULL,
		0x3E10F7472BF9FDF8ULL,
		0x641F19750ABD442DULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1370D8D47138039ULL,
		0x45B4C994E5A5481DULL,
		0x369F67E74F4BBF4CULL,
		0x3D5D11E5B324D19BULL,
		0x27E5185DBCC42483ULL,
		0x5D46D2F523C7AD5EULL,
		0x8DDAC1CB87F2BB26ULL,
		0x27E1888AF537947FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE26E1B1A8E270072ULL,
		0x8B699329CB4A903BULL,
		0x6D3ECFCE9E977E98ULL,
		0x7ABA23CB6649A336ULL,
		0x4FCA30BB79884906ULL,
		0xBA8DA5EA478F5ABCULL,
		0x1BB583970FE5764CULL,
		0x4FC31115EA6F28FFULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E1907FA32E674D0ULL,
		0xE2168446A7B090F8ULL,
		0x604873BDC6BB5DD0ULL,
		0xA8BB8A91FFC9E05FULL,
		0xD2170E3F28CBEA64ULL,
		0xE9B53ABD6612AB6CULL,
		0x79736144A3EDF31BULL,
		0x1DB3AB1F5699211CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C320FF465CCE9A0ULL,
		0xC42D088D4F6121F1ULL,
		0xC090E77B8D76BBA1ULL,
		0x51771523FF93C0BEULL,
		0xA42E1C7E5197D4C9ULL,
		0xD36A757ACC2556D9ULL,
		0xF2E6C28947DBE637ULL,
		0x3B67563EAD324238ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D6107E3F0B333F9ULL,
		0x5DA5EA3F9822108CULL,
		0x94F761B2A63F689DULL,
		0x13A6E077E72EAB73ULL,
		0x278AC19DD80DF949ULL,
		0x0B5B98F25BB5D0C7ULL,
		0x5B2001BDB308D0E4ULL,
		0x238B5268BF38FA9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC20FC7E16667F2ULL,
		0xBB4BD47F30442118ULL,
		0x29EEC3654C7ED13AULL,
		0x274DC0EFCE5D56E7ULL,
		0x4F15833BB01BF292ULL,
		0x16B731E4B76BA18EULL,
		0xB640037B6611A1C8ULL,
		0x4716A4D17E71F53CULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4775ED3F3E532EFULL,
		0x20F7A2A886F4C098ULL,
		0xCAC5AC631032B94FULL,
		0xB51993B4D6FA3256ULL,
		0xD48DCB78EE7E7B5CULL,
		0xF75CCDF0E236F73CULL,
		0x5652B5F31264945BULL,
		0x25123313760A03A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68EEBDA7E7CA65DEULL,
		0x41EF45510DE98131ULL,
		0x958B58C62065729EULL,
		0x6A332769ADF464ADULL,
		0xA91B96F1DCFCF6B9ULL,
		0xEEB99BE1C46DEE79ULL,
		0xACA56BE624C928B7ULL,
		0x4A246626EC140748ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6666907C74058013ULL,
		0xBCA7B720BC353AE4ULL,
		0xAD54ABB13E22920EULL,
		0xB6BDE8E2F003C0D3ULL,
		0x1B02A203FFC166B1ULL,
		0x99488BCAA1F3DE63ULL,
		0x7A8F196D7F354663ULL,
		0x0218549F5850B9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCCD20F8E80B0026ULL,
		0x794F6E41786A75C8ULL,
		0x5AA957627C45241DULL,
		0x6D7BD1C5E00781A7ULL,
		0x36054407FF82CD63ULL,
		0x3291179543E7BCC6ULL,
		0xF51E32DAFE6A8CC7ULL,
		0x0430A93EB0A173AEULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8A113E2D9FA8CF7ULL,
		0x11697C880F9527E1ULL,
		0x2155D5EB8803EC16ULL,
		0x27A4B98D125A1ECAULL,
		0xFA0D76C49E93F41BULL,
		0x439F30B6E190DAEBULL,
		0x9B211F818F9D4650ULL,
		0x1E6C4E4E2AE8F5B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x514227C5B3F519EEULL,
		0x22D2F9101F2A4FC3ULL,
		0x42ABABD71007D82CULL,
		0x4F49731A24B43D94ULL,
		0xF41AED893D27E836ULL,
		0x873E616DC321B5D7ULL,
		0x36423F031F3A8CA0ULL,
		0x3CD89C9C55D1EB67ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x072B838CB84D8661ULL,
		0x205A51FC075A2EE3ULL,
		0x197E6BBDB3975087ULL,
		0x8A9E372929E8B1FFULL,
		0x5E8DE0EB377E2FC6ULL,
		0x3D1F6DC4A4C0E915ULL,
		0xB7E146245F1A32CDULL,
		0x064702CD830C49ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E570719709B0CC2ULL,
		0x40B4A3F80EB45DC6ULL,
		0x32FCD77B672EA10EULL,
		0x153C6E5253D163FEULL,
		0xBD1BC1D66EFC5F8DULL,
		0x7A3EDB894981D22AULL,
		0x6FC28C48BE34659AULL,
		0x0C8E059B06189359ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB57C775E0C4862C4ULL,
		0x8DAE99FAF9FB8D1EULL,
		0x60FB201958C66D76ULL,
		0x6E3C675F7CC4C6DFULL,
		0xD516EE5F978F122BULL,
		0x2ED49C58AD956F49ULL,
		0x004A04C1DE6478A2ULL,
		0x01B2C8F1C019AAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AF8EEBC1890C588ULL,
		0x1B5D33F5F3F71A3DULL,
		0xC1F64032B18CDAEDULL,
		0xDC78CEBEF9898DBEULL,
		0xAA2DDCBF2F1E2456ULL,
		0x5DA938B15B2ADE93ULL,
		0x00940983BCC8F144ULL,
		0x036591E3803355E2ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4100EDBE5962E32ULL,
		0x0BC899DC08D67A3AULL,
		0xB7BEFDE46760EC88ULL,
		0x46B873F5871A72D2ULL,
		0xFC0F9A9B5CDB74FFULL,
		0xDB04533C77C5F644ULL,
		0x51A8576DA6F5BC55ULL,
		0x1A504AD408775752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48201DB7CB2C5C64ULL,
		0x179133B811ACF475ULL,
		0x6F7DFBC8CEC1D910ULL,
		0x8D70E7EB0E34E5A5ULL,
		0xF81F3536B9B6E9FEULL,
		0xB608A678EF8BEC89ULL,
		0xA350AEDB4DEB78ABULL,
		0x34A095A810EEAEA4ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB54A908DCF8F66CDULL,
		0x538CE0DAD3DB9352ULL,
		0x3E31D0FE2C225065ULL,
		0xE6BADF4E3B152216ULL,
		0x1773253223707F18ULL,
		0x0B96D5D3D979F7CDULL,
		0x2953E904BD33549FULL,
		0x30B56A84EE98CDF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A95211B9F1ECD9AULL,
		0xA719C1B5A7B726A5ULL,
		0x7C63A1FC5844A0CAULL,
		0xCD75BE9C762A442CULL,
		0x2EE64A6446E0FE31ULL,
		0x172DABA7B2F3EF9AULL,
		0x52A7D2097A66A93EULL,
		0x616AD509DD319BE2ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE0FAF7376FEBE5ULL,
		0xDF36D632E396F740ULL,
		0xA1112826F0D5931BULL,
		0x5889CAA120F5E662ULL,
		0xBD31A0BBFD593D34ULL,
		0xC7C50D5F274D7BDEULL,
		0x652EEA10B1C8E154ULL,
		0x3A2ED5E047BABAFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C1F5EE6EDFD7CAULL,
		0xBE6DAC65C72DEE80ULL,
		0x4222504DE1AB2637ULL,
		0xB113954241EBCCC5ULL,
		0x7A634177FAB27A68ULL,
		0x8F8A1ABE4E9AF7BDULL,
		0xCA5DD4216391C2A9ULL,
		0x745DABC08F7575F8ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02D01C195B4F9467ULL,
		0x207FDBBFA4203B18ULL,
		0x4AD4762518BDF3D8ULL,
		0xABEAA4E49957D3CBULL,
		0x13685640BDE76283ULL,
		0x8AE2FEEBB27AA07AULL,
		0xE4C99CDF99E5EE3AULL,
		0x2F055E19638B58B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05A03832B69F28CEULL,
		0x40FFB77F48407630ULL,
		0x95A8EC4A317BE7B0ULL,
		0x57D549C932AFA796ULL,
		0x26D0AC817BCEC507ULL,
		0x15C5FDD764F540F4ULL,
		0xC99339BF33CBDC75ULL,
		0x5E0ABC32C716B16BULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC2C3D68DE118A9FULL,
		0xA0531EEDA30BA5CEULL,
		0xCC762ED43DC765EDULL,
		0x6FD3252B8D254A28ULL,
		0xF6B25B8EA1173526ULL,
		0x6709F392D362B15EULL,
		0xA84419A4C78A1B87ULL,
		0x30C479EC4D97BFDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98587AD1BC23153EULL,
		0x40A63DDB46174B9DULL,
		0x98EC5DA87B8ECBDBULL,
		0xDFA64A571A4A9451ULL,
		0xED64B71D422E6A4CULL,
		0xCE13E725A6C562BDULL,
		0x508833498F14370EULL,
		0x6188F3D89B2F7FB9ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C2DC7A1830E75AEULL,
		0xD8B5B7DBE7A514A7ULL,
		0x25345B0F7593DCD3ULL,
		0x1EE701C8D1C17DE4ULL,
		0x6054364B475D091BULL,
		0x15F99968E12F7AAEULL,
		0xC9FBAB00A93D5CC5ULL,
		0x09829F1CFB8EA3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD85B8F43061CEB5CULL,
		0xB16B6FB7CF4A294EULL,
		0x4A68B61EEB27B9A7ULL,
		0x3DCE0391A382FBC8ULL,
		0xC0A86C968EBA1236ULL,
		0x2BF332D1C25EF55CULL,
		0x93F75601527AB98AULL,
		0x13053E39F71D4753ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84B6B347FE9A2BB9ULL,
		0x3BB90778062CC87AULL,
		0x441909B6CE9BA4CEULL,
		0x0B66B64941B91DADULL,
		0x99323BD6C18AFFF8ULL,
		0xFF1E182F58A644D9ULL,
		0x56A137D7FF399892ULL,
		0x0DE87598F1F22FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x096D668FFD345772ULL,
		0x77720EF00C5990F5ULL,
		0x8832136D9D37499CULL,
		0x16CD6C9283723B5AULL,
		0x326477AD8315FFF0ULL,
		0xFE3C305EB14C89B3ULL,
		0xAD426FAFFE733125ULL,
		0x1BD0EB31E3E45FEEULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D5D6E8428C963DAULL,
		0x16CA6097D02B6520ULL,
		0xFF81B8778FC9650DULL,
		0x53673EB1C74D47BBULL,
		0xFE2997B67F70D944ULL,
		0x649CDA64215BE9E5ULL,
		0xA99AFCA11D21871CULL,
		0x2332EA1ABAA9CAB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ABADD085192C7B4ULL,
		0x2D94C12FA056CA41ULL,
		0xFF0370EF1F92CA1AULL,
		0xA6CE7D638E9A8F77ULL,
		0xFC532F6CFEE1B288ULL,
		0xC939B4C842B7D3CBULL,
		0x5335F9423A430E38ULL,
		0x4665D43575539565ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD76408F3E704D728ULL,
		0xB74E8AD65C5BC555ULL,
		0x5D6153580591AA4EULL,
		0x3A448E8155C66303ULL,
		0x9D0C756DE2284F71ULL,
		0x768A0D84A7A2A17FULL,
		0x742B42CCE554A61DULL,
		0x1A0A2DBF102E5999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC811E7CE09AE50ULL,
		0x6E9D15ACB8B78AABULL,
		0xBAC2A6B00B23549DULL,
		0x74891D02AB8CC606ULL,
		0x3A18EADBC4509EE2ULL,
		0xED141B094F4542FFULL,
		0xE8568599CAA94C3AULL,
		0x34145B7E205CB332ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D627BFE034A72D0ULL,
		0x09475248918E5F69ULL,
		0x19F0C856A10735B7ULL,
		0xD9B9ADC79278E871ULL,
		0xC6745EB9DF8B8859ULL,
		0xA3942E46DC2D3AECULL,
		0x96369189BDFC6A18ULL,
		0x03BB609CD25F8FE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC4F7FC0694E5A0ULL,
		0x128EA491231CBED2ULL,
		0x33E190AD420E6B6EULL,
		0xB3735B8F24F1D0E2ULL,
		0x8CE8BD73BF1710B3ULL,
		0x47285C8DB85A75D9ULL,
		0x2C6D23137BF8D431ULL,
		0x0776C139A4BF1FCBULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8568C1CF5A2AC00FULL,
		0xF8B8D4B54DCC6E0AULL,
		0xEF376E9326388AB4ULL,
		0x56F5A2F066B3EC40ULL,
		0xFE4F044A1F8E20BDULL,
		0x8E742A1942BE17E6ULL,
		0xC0EEDD31738DC32DULL,
		0x2E9969BEB1B582E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD1839EB455801EULL,
		0xF171A96A9B98DC15ULL,
		0xDE6EDD264C711569ULL,
		0xADEB45E0CD67D881ULL,
		0xFC9E08943F1C417AULL,
		0x1CE85432857C2FCDULL,
		0x81DDBA62E71B865BULL,
		0x5D32D37D636B05CDULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FA69146F4BF17C8ULL,
		0x356DF3BBD6E8A13DULL,
		0x4B21DC3B475B2A3EULL,
		0xD7A95C562B73DAE3ULL,
		0xAC6C5891D9FA433EULL,
		0x40CD6A48E2EF6C2FULL,
		0xAAFA81A8D992A6CFULL,
		0x3DA237636FC4444EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF4D228DE97E2F90ULL,
		0x6ADBE777ADD1427AULL,
		0x9643B8768EB6547CULL,
		0xAF52B8AC56E7B5C6ULL,
		0x58D8B123B3F4867DULL,
		0x819AD491C5DED85FULL,
		0x55F50351B3254D9EULL,
		0x7B446EC6DF88889DULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D8F66C401D9735CULL,
		0x4C2805B47E61C4FAULL,
		0x86C65219C7B26DDBULL,
		0x7152BA91168019C8ULL,
		0xC8B54796F9AA4AF5ULL,
		0xD0C3454F4C0935BCULL,
		0xCDFD90603D9C070BULL,
		0x0797CA629EE79900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B1ECD8803B2E6B8ULL,
		0x98500B68FCC389F4ULL,
		0x0D8CA4338F64DBB6ULL,
		0xE2A575222D003391ULL,
		0x916A8F2DF35495EAULL,
		0xA1868A9E98126B79ULL,
		0x9BFB20C07B380E17ULL,
		0x0F2F94C53DCF3201ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB92E8FA002F181BULL,
		0x837516928E22E26BULL,
		0xAC87FD0010642AC1ULL,
		0x42F5976DF067D7A5ULL,
		0xBAC63DE8897AB239ULL,
		0xC08841C3CF45B8B4ULL,
		0x85B7C430AEE8E303ULL,
		0x19827D49D1F9DCD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7725D1F4005E3036ULL,
		0x06EA2D251C45C4D7ULL,
		0x590FFA0020C85583ULL,
		0x85EB2EDBE0CFAF4BULL,
		0x758C7BD112F56472ULL,
		0x811083879E8B7169ULL,
		0x0B6F88615DD1C607ULL,
		0x3304FA93A3F3B9A3ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B485E0A1C6C9953ULL,
		0xD23A8C57F3D72EBAULL,
		0xF1C3DDD92CA91E36ULL,
		0xC0E4B47690636825ULL,
		0xB5FA5518441D13EEULL,
		0xECFF61BD150B0F54ULL,
		0xA8D56CE6A7F12FEEULL,
		0x175487D5E71EF4B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF690BC1438D932A6ULL,
		0xA47518AFE7AE5D74ULL,
		0xE387BBB259523C6DULL,
		0x81C968ED20C6D04BULL,
		0x6BF4AA30883A27DDULL,
		0xD9FEC37A2A161EA9ULL,
		0x51AAD9CD4FE25FDDULL,
		0x2EA90FABCE3DE96DULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F233A528C907902ULL,
		0x65A360051A59692DULL,
		0xBAC863C713B40D9DULL,
		0x3976D80089DBCF36ULL,
		0xDBEF754630E8B356ULL,
		0x11B8C5590E4CE7FFULL,
		0x73BD46A586C14735ULL,
		0x0ABBA0C4734521DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4674A51920F204ULL,
		0xCB46C00A34B2D25BULL,
		0x7590C78E27681B3AULL,
		0x72EDB00113B79E6DULL,
		0xB7DEEA8C61D166ACULL,
		0x23718AB21C99CFFFULL,
		0xE77A8D4B0D828E6AULL,
		0x15774188E68A43BEULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94DE7ECB0FFF6977ULL,
		0xF50BAB8D872121F0ULL,
		0x7C8EACDBA9B2E6A2ULL,
		0x772F76FF50EC0617ULL,
		0x8294CDF600852377ULL,
		0x086DA2372B95F997ULL,
		0xF4A699E1652EE16EULL,
		0x2A57EA8D627AF36EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BCFD961FFED2EEULL,
		0xEA17571B0E4243E1ULL,
		0xF91D59B75365CD45ULL,
		0xEE5EEDFEA1D80C2EULL,
		0x05299BEC010A46EEULL,
		0x10DB446E572BF32FULL,
		0xE94D33C2CA5DC2DCULL,
		0x54AFD51AC4F5E6DDULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB43A428920E1364ULL,
		0x69905DEA8350AB65ULL,
		0xA2960058340E15E8ULL,
		0x0FB37FB9A39FF2ABULL,
		0x527762CE2356BBEBULL,
		0x5F7ED6BFE3229DD2ULL,
		0x4ED2D067CB119395ULL,
		0x141028EB36C70E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96874851241C26C8ULL,
		0xD320BBD506A156CBULL,
		0x452C00B0681C2BD0ULL,
		0x1F66FF73473FE557ULL,
		0xA4EEC59C46AD77D6ULL,
		0xBEFDAD7FC6453BA4ULL,
		0x9DA5A0CF9623272AULL,
		0x282051D66D8E1C3EULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0558573ED845AC7CULL,
		0x15BFAE27DE8810E8ULL,
		0x065C40F0E075BF42ULL,
		0x0DD9487AD0EC65A4ULL,
		0xEA31F0884AB695B1ULL,
		0x26D975FFC6308311ULL,
		0x1A0A317DC8172539ULL,
		0x152577241E18B0C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB0AE7DB08B58F8ULL,
		0x2B7F5C4FBD1021D0ULL,
		0x0CB881E1C0EB7E84ULL,
		0x1BB290F5A1D8CB48ULL,
		0xD463E110956D2B62ULL,
		0x4DB2EBFF8C610623ULL,
		0x341462FB902E4A72ULL,
		0x2A4AEE483C31618EULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9062CCAD22F4D24EULL,
		0x758AC1292AEA1862ULL,
		0xCD7FB94C0D96506EULL,
		0xDF2641245F4DAF79ULL,
		0xA033593C41980C34ULL,
		0xEDBE05C8DCACB03DULL,
		0xE70445D4BA207CF7ULL,
		0x1CB5EFE515695018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C5995A45E9A49CULL,
		0xEB15825255D430C5ULL,
		0x9AFF72981B2CA0DCULL,
		0xBE4C8248BE9B5EF3ULL,
		0x4066B27883301869ULL,
		0xDB7C0B91B959607BULL,
		0xCE088BA97440F9EFULL,
		0x396BDFCA2AD2A031ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2979CDCE3C2817DULL,
		0x1DA627EF6AD8EEB8ULL,
		0x148C52232678177CULL,
		0x7B6CD131C5E21DA3ULL,
		0xC9FF11D789A3CA5BULL,
		0xD212CA50E05E32E6ULL,
		0x308691BA9E3E7081ULL,
		0x2675DB31D6A9CED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x852F39B9C78502FAULL,
		0x3B4C4FDED5B1DD71ULL,
		0x2918A4464CF02EF8ULL,
		0xF6D9A2638BC43B46ULL,
		0x93FE23AF134794B6ULL,
		0xA42594A1C0BC65CDULL,
		0x610D23753C7CE103ULL,
		0x4CEBB663AD539DA8ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D64AD3D83164F55ULL,
		0xA268537E59058775ULL,
		0x0E6C6DB15F9CCA6EULL,
		0x006958E4AFCC7491ULL,
		0x4F124432FB34878BULL,
		0xF6597BE1E5521EA2ULL,
		0x24EEE4EE78432596ULL,
		0x086C40E2B2C2C9A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AC95A7B062C9EAAULL,
		0x44D0A6FCB20B0EEBULL,
		0x1CD8DB62BF3994DDULL,
		0x00D2B1C95F98E922ULL,
		0x9E248865F6690F16ULL,
		0xECB2F7C3CAA43D44ULL,
		0x49DDC9DCF0864B2DULL,
		0x10D881C56585934CULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74596DC63853E454ULL,
		0xECBF6846CB2AB9FAULL,
		0x3EF160F94E9C293DULL,
		0xD0827758970971E4ULL,
		0xC5EC3868E9C6B62BULL,
		0x172325FC9D12DFD6ULL,
		0x78A0E8C90BD28FE4ULL,
		0x3442D27666E6A67DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8B2DB8C70A7C8A8ULL,
		0xD97ED08D965573F4ULL,
		0x7DE2C1F29D38527BULL,
		0xA104EEB12E12E3C8ULL,
		0x8BD870D1D38D6C57ULL,
		0x2E464BF93A25BFADULL,
		0xF141D19217A51FC8ULL,
		0x6885A4ECCDCD4CFAULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72DDA06DD60DC573ULL,
		0xEEB06549FB98BF50ULL,
		0xC9D704261568ACA5ULL,
		0x7DDDD7D577044197ULL,
		0x5759AD5F4F92FD78ULL,
		0x32BCE3F6F431402AULL,
		0x7B07509BB3CCF2ABULL,
		0x02C81C498E827B5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BB40DBAC1B8AE6ULL,
		0xDD60CA93F7317EA0ULL,
		0x93AE084C2AD1594BULL,
		0xFBBBAFAAEE08832FULL,
		0xAEB35ABE9F25FAF0ULL,
		0x6579C7EDE8628054ULL,
		0xF60EA1376799E556ULL,
		0x059038931D04F6B4ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2AADD18AF088394ULL,
		0x6B36E66189DC7630ULL,
		0x49CB6025BD63364FULL,
		0x46A8C64AB01B11A7ULL,
		0x2888E8FBF87EC96BULL,
		0xDC662D3A202E0851ULL,
		0x5E8E3897CC40F6C2ULL,
		0x105D8B4DCB7DBB25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8555BA315E110728ULL,
		0xD66DCCC313B8EC61ULL,
		0x9396C04B7AC66C9EULL,
		0x8D518C956036234EULL,
		0x5111D1F7F0FD92D6ULL,
		0xB8CC5A74405C10A2ULL,
		0xBD1C712F9881ED85ULL,
		0x20BB169B96FB764AULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD7A47C5F7F21684ULL,
		0x290FC9296C64F1A9ULL,
		0x2EE9A8BF8BFACEB4ULL,
		0x44EEA166A4668652ULL,
		0x6B0CE595A0E04AC6ULL,
		0x57171E5BC6ADA500ULL,
		0x109C05D0F7B1A2FAULL,
		0x1D9C381F421529C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF48F8BEFE42D08ULL,
		0x521F9252D8C9E353ULL,
		0x5DD3517F17F59D68ULL,
		0x89DD42CD48CD0CA4ULL,
		0xD619CB2B41C0958CULL,
		0xAE2E3CB78D5B4A00ULL,
		0x21380BA1EF6345F4ULL,
		0x3B38703E842A5382ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EC21827D02BCA4FULL,
		0x93E9CC271CB7FB52ULL,
		0xF9F74FD18252525CULL,
		0x4B662F616466AFD4ULL,
		0xFDA5B857DB9FFB87ULL,
		0x4D618BB628522FA3ULL,
		0x1C8F5FCCD9869771ULL,
		0x31646ED758F66DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D84304FA057949EULL,
		0x27D3984E396FF6A5ULL,
		0xF3EE9FA304A4A4B9ULL,
		0x96CC5EC2C8CD5FA9ULL,
		0xFB4B70AFB73FF70EULL,
		0x9AC3176C50A45F47ULL,
		0x391EBF99B30D2EE2ULL,
		0x62C8DDAEB1ECDBE8ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x866EAFB4C38879CFULL,
		0x32AF44AB1317323CULL,
		0xE5906A2C843547E2ULL,
		0x730AC9E2EF4DC757ULL,
		0x080064F6E623CE65ULL,
		0xC35BCD9BBE995145ULL,
		0x63C9F95A52FBC15CULL,
		0x1E0A760D315DB2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CDD5F698710F39EULL,
		0x655E8956262E6479ULL,
		0xCB20D459086A8FC4ULL,
		0xE61593C5DE9B8EAFULL,
		0x1000C9EDCC479CCAULL,
		0x86B79B377D32A28AULL,
		0xC793F2B4A5F782B9ULL,
		0x3C14EC1A62BB65E8ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864B355C7EB8067AULL,
		0x623A5CC249A96608ULL,
		0xC361E3097269FB8AULL,
		0x29A3E220D559451FULL,
		0x91481EDF9147086FULL,
		0x5829DB331A473437ULL,
		0x5B0905DDB4483A4AULL,
		0x220932CC34C57C2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C966AB8FD700CF4ULL,
		0xC474B9849352CC11ULL,
		0x86C3C612E4D3F714ULL,
		0x5347C441AAB28A3FULL,
		0x22903DBF228E10DEULL,
		0xB053B666348E686FULL,
		0xB6120BBB68907494ULL,
		0x44126598698AF854ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F58EF2D77CD66F6ULL,
		0x422C187BBB2AD032ULL,
		0x09BBCBE38FCD79ACULL,
		0x12B100BD0311D000ULL,
		0x419CF485664E02B0ULL,
		0xEAE49905F9C683B2ULL,
		0x545D8B02AF3A3CDBULL,
		0x2B85270D23B5264BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB1DE5AEF9ACDECULL,
		0x845830F77655A064ULL,
		0x137797C71F9AF358ULL,
		0x2562017A0623A000ULL,
		0x8339E90ACC9C0560ULL,
		0xD5C9320BF38D0764ULL,
		0xA8BB16055E7479B7ULL,
		0x570A4E1A476A4C96ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0DFB6FF7E434B61ULL,
		0x925AD28706897053ULL,
		0xCF928C98218919A9ULL,
		0xAD233654CFB75798ULL,
		0x5E85B374CCA015C7ULL,
		0x3E2101DF1AAC0D1FULL,
		0x928AE630D61ACEA5ULL,
		0x3F4A94B435DBB468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61BF6DFEFC8696C2ULL,
		0x24B5A50E0D12E0A7ULL,
		0x9F25193043123353ULL,
		0x5A466CA99F6EAF31ULL,
		0xBD0B66E999402B8FULL,
		0x7C4203BE35581A3EULL,
		0x2515CC61AC359D4AULL,
		0x7E9529686BB768D1ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7B527A7C112A925ULL,
		0x47EB009B7E0C3A94ULL,
		0x102370D97809F893ULL,
		0xB48589DA49D7236BULL,
		0x662A8D98D05DFD38ULL,
		0x92E63B2392995321ULL,
		0x8FC8CBB8B198F362ULL,
		0x1A5FDA8CEC15A8C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F6A4F4F8225524AULL,
		0x8FD60136FC187529ULL,
		0x2046E1B2F013F126ULL,
		0x690B13B493AE46D6ULL,
		0xCC551B31A0BBFA71ULL,
		0x25CC76472532A642ULL,
		0x1F9197716331E6C5ULL,
		0x34BFB519D82B5183ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2A7E3C4CED37F59ULL,
		0x5350F04F491E3E12ULL,
		0x137785018907083EULL,
		0x4E72A4211A27705EULL,
		0x08EAE79834A1FD92ULL,
		0x1FDDC05298A80C07ULL,
		0x4A9FC3AEBE161E0DULL,
		0x3C5D8B2007A8A14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x654FC7899DA6FEB2ULL,
		0xA6A1E09E923C7C25ULL,
		0x26EF0A03120E107CULL,
		0x9CE54842344EE0BCULL,
		0x11D5CF306943FB24ULL,
		0x3FBB80A53150180EULL,
		0x953F875D7C2C3C1AULL,
		0x78BB16400F514298ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x762745C3634174FBULL,
		0x003F3EF5F0A78BFCULL,
		0xF37E9E12F077A266ULL,
		0x6475287A8C0B7DCFULL,
		0x64E74A06005DD3FBULL,
		0x79F0A0F44D28A1B5ULL,
		0xBD0C96FD9D21F5CBULL,
		0x04657524CD6D6520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC4E8B86C682E9F6ULL,
		0x007E7DEBE14F17F8ULL,
		0xE6FD3C25E0EF44CCULL,
		0xC8EA50F51816FB9FULL,
		0xC9CE940C00BBA7F6ULL,
		0xF3E141E89A51436AULL,
		0x7A192DFB3A43EB96ULL,
		0x08CAEA499ADACA41ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D3253DCCFD68787ULL,
		0xCC29A4E628237922ULL,
		0xAC15A4FF11348694ULL,
		0xF420C602967CE6E0ULL,
		0xEEF8E9B4E9ACA686ULL,
		0x4FC983200FAB9DD3ULL,
		0x2607D0AA742F5750ULL,
		0x2FB149FFC2861AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA64A7B99FAD0F0EULL,
		0x985349CC5046F244ULL,
		0x582B49FE22690D29ULL,
		0xE8418C052CF9CDC1ULL,
		0xDDF1D369D3594D0DULL,
		0x9F9306401F573BA7ULL,
		0x4C0FA154E85EAEA0ULL,
		0x5F6293FF850C35A4ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x349324EEE93EBA66ULL,
		0xEBDC7A24403EB6FBULL,
		0x9E4D894710D7F323ULL,
		0x35E9D95AFD80022BULL,
		0x76D89C1BD72D1940ULL,
		0xA5C555605A44A9EAULL,
		0x6C383BD9B23B5C56ULL,
		0x370D146384E70335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x692649DDD27D74CCULL,
		0xD7B8F448807D6DF6ULL,
		0x3C9B128E21AFE647ULL,
		0x6BD3B2B5FB000457ULL,
		0xEDB13837AE5A3280ULL,
		0x4B8AAAC0B48953D4ULL,
		0xD87077B36476B8ADULL,
		0x6E1A28C709CE066AULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7809681642C41101ULL,
		0x153AD8CCC0F46678ULL,
		0x1880953EAD230D8EULL,
		0xA208B607BE4C3DC8ULL,
		0x6A903E0519B4FCCBULL,
		0x457D621E4A4E20CAULL,
		0x1EDB35A92E6EEE6CULL,
		0x10669573F3792F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF012D02C85882202ULL,
		0x2A75B19981E8CCF0ULL,
		0x31012A7D5A461B1CULL,
		0x44116C0F7C987B90ULL,
		0xD5207C0A3369F997ULL,
		0x8AFAC43C949C4194ULL,
		0x3DB66B525CDDDCD8ULL,
		0x20CD2AE7E6F25E92ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE04B2845B5DC0B35ULL,
		0xA183AB68855BDDF1ULL,
		0x426F8DAFB41F0AE5ULL,
		0x564B89216599F98DULL,
		0xE3452DD5D2A1A95FULL,
		0x355044C4A8AA5309ULL,
		0x80FC106EC4199C28ULL,
		0x11616294D064A139ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC096508B6BB8166AULL,
		0x430756D10AB7BBE3ULL,
		0x84DF1B5F683E15CBULL,
		0xAC971242CB33F31AULL,
		0xC68A5BABA54352BEULL,
		0x6AA089895154A613ULL,
		0x01F820DD88333850ULL,
		0x22C2C529A0C94273ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA403293DF2CA198ULL,
		0x5B3F27B32DE6F4D5ULL,
		0xB46AB963139B89CEULL,
		0xBC83089A1A0EF047ULL,
		0xF0C0AA8768299419ULL,
		0x0C9D6A47035410CAULL,
		0x67FA1C56DAD6178CULL,
		0x2B705160F7197E96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4806527BE594330ULL,
		0xB67E4F665BCDE9ABULL,
		0x68D572C62737139CULL,
		0x79061134341DE08FULL,
		0xE181550ED0532833ULL,
		0x193AD48E06A82195ULL,
		0xCFF438ADB5AC2F18ULL,
		0x56E0A2C1EE32FD2CULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E425EE43FEB66E1ULL,
		0x5AE9C62376F924C3ULL,
		0x9D7CA16578D2F723ULL,
		0xE8B8E28925881AACULL,
		0xA7933E35D6E5F539ULL,
		0x9B82F6EAC959EDB5ULL,
		0x685755D90B06689DULL,
		0x28ABD52A5DE7E4A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC84BDC87FD6CDC2ULL,
		0xB5D38C46EDF24986ULL,
		0x3AF942CAF1A5EE46ULL,
		0xD171C5124B103559ULL,
		0x4F267C6BADCBEA73ULL,
		0x3705EDD592B3DB6BULL,
		0xD0AEABB2160CD13BULL,
		0x5157AA54BBCFC94CULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0761824EECFE31E7ULL,
		0xBAB9841DB90550B7ULL,
		0xADC480EE443348EBULL,
		0x61C3205ADEA3414CULL,
		0xC211F70971BFC434ULL,
		0xDE67C6993D5014F7ULL,
		0x77ECA3EEB12FDB94ULL,
		0x1D94E5D492C78DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC3049DD9FC63CEULL,
		0x7573083B720AA16EULL,
		0x5B8901DC886691D7ULL,
		0xC38640B5BD468299ULL,
		0x8423EE12E37F8868ULL,
		0xBCCF8D327AA029EFULL,
		0xEFD947DD625FB729ULL,
		0x3B29CBA9258F1B8AULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF139BC5C0731A54DULL,
		0x8489F6180ADFA5B3ULL,
		0xFE951EFADCAE21B5ULL,
		0x5C463D06612E6B83ULL,
		0xF0EA58F87CD0030EULL,
		0xDFBCEF116304AF7FULL,
		0x0A3DB82C36ECB369ULL,
		0x2F3045A2A122FFDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE27378B80E634A9AULL,
		0x0913EC3015BF4B67ULL,
		0xFD2A3DF5B95C436BULL,
		0xB88C7A0CC25CD707ULL,
		0xE1D4B1F0F9A0061CULL,
		0xBF79DE22C6095EFFULL,
		0x147B70586DD966D3ULL,
		0x5E608B454245FFB4ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6741AA7BA682CF1EULL,
		0x53B3AA039B9E6109ULL,
		0xB9C7C55CB80D2C85ULL,
		0xABE3C2DC27280F09ULL,
		0x3B68D4A859B1C870ULL,
		0x2F4826441FAB6002ULL,
		0x49D8607278B27A5EULL,
		0x2DCDA03641FCDB7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE8354F74D059E3CULL,
		0xA7675407373CC212ULL,
		0x738F8AB9701A590AULL,
		0x57C785B84E501E13ULL,
		0x76D1A950B36390E1ULL,
		0x5E904C883F56C004ULL,
		0x93B0C0E4F164F4BCULL,
		0x5B9B406C83F9B6FCULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD7C0C8BF14D10BDULL,
		0xC81E0C05653EA201ULL,
		0xCFBA01E626C9A3EDULL,
		0xB79C81C9752A9F15ULL,
		0x4E79E019A832D810ULL,
		0x801017550A9432D5ULL,
		0x3C14BD9344047430ULL,
		0x0AA8E6C0751908C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AF81917E29A217AULL,
		0x903C180ACA7D4403ULL,
		0x9F7403CC4D9347DBULL,
		0x6F390392EA553E2BULL,
		0x9CF3C0335065B021ULL,
		0x00202EAA152865AAULL,
		0x78297B268808E861ULL,
		0x1551CD80EA321182ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BB32E24A1017080ULL,
		0x6457E0FF8584FEE1ULL,
		0x23D96D84B9158D2CULL,
		0xF583448444B55844ULL,
		0xB291F0E3A8FF97ECULL,
		0xAAC942D1F0B0EABBULL,
		0x301ECCDF0297354FULL,
		0x15054528C9985A89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97665C494202E100ULL,
		0xC8AFC1FF0B09FDC2ULL,
		0x47B2DB09722B1A58ULL,
		0xEB068908896AB088ULL,
		0x6523E1C751FF2FD9ULL,
		0x559285A3E161D577ULL,
		0x603D99BE052E6A9FULL,
		0x2A0A8A519330B512ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22445C7E5C31842BULL,
		0x4DF719A89589A9B2ULL,
		0x1F2D21B4D4879B33ULL,
		0x780AFBDECBC45DD8ULL,
		0x50BFE5002844148DULL,
		0x0AE44D38C1252A0FULL,
		0xB31FC70CB6B0C008ULL,
		0x1BD0775A6F3C8991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4488B8FCB8630856ULL,
		0x9BEE33512B135364ULL,
		0x3E5A4369A90F3666ULL,
		0xF015F7BD9788BBB0ULL,
		0xA17FCA005088291AULL,
		0x15C89A71824A541EULL,
		0x663F8E196D618010ULL,
		0x37A0EEB4DE791323ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73D06F25B9103627ULL,
		0xECDD1C2C0A9B2918ULL,
		0x963F7FA73F2246AEULL,
		0xA5BB445D2D6962F5ULL,
		0x4AC10D3798D3ABBFULL,
		0xB0140995F9CB4DE7ULL,
		0x98C8FA13D4F6AA3CULL,
		0x1C0465FC1FD9A477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7A0DE4B72206C4EULL,
		0xD9BA385815365230ULL,
		0x2C7EFF4E7E448D5DULL,
		0x4B7688BA5AD2C5EBULL,
		0x95821A6F31A7577FULL,
		0x6028132BF3969BCEULL,
		0x3191F427A9ED5479ULL,
		0x3808CBF83FB348EFULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE56D401C186F8107ULL,
		0xB174082A91680647ULL,
		0x27074CE422182785ULL,
		0xE41FC04134A6A292ULL,
		0xF28AF6AD6BA998B0ULL,
		0x8DDDEF3FD9F10688ULL,
		0x63D1E042F319B19AULL,
		0x0AB2CD3E1AFBD34CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCADA803830DF020EULL,
		0x62E8105522D00C8FULL,
		0x4E0E99C844304F0BULL,
		0xC83F8082694D4524ULL,
		0xE515ED5AD7533161ULL,
		0x1BBBDE7FB3E20D11ULL,
		0xC7A3C085E6336335ULL,
		0x15659A7C35F7A698ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6EFCF8CF75495B8ULL,
		0x61A25F61D1BA68D6ULL,
		0xBD4C23CEB3B00FE9ULL,
		0x38A0CAA56860DD29ULL,
		0x7A9ED7A26134E925ULL,
		0x9A13E11AB28ADC39ULL,
		0x16621A98AE4AA29AULL,
		0x066AC98CA6E7090EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DDF9F19EEA92B70ULL,
		0xC344BEC3A374D1ADULL,
		0x7A98479D67601FD2ULL,
		0x7141954AD0C1BA53ULL,
		0xF53DAF44C269D24AULL,
		0x3427C2356515B872ULL,
		0x2CC435315C954535ULL,
		0x0CD593194DCE121CULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFF98238023979E6ULL,
		0x594E9B673058A09CULL,
		0xA879DA553BDDD812ULL,
		0x7BD5AFCC729FF692ULL,
		0x88D8B9D0C2C457C9ULL,
		0x07A8B306EC775FB6ULL,
		0x6543A4E77D55A8FDULL,
		0x098408296695B905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFF304700472F3CCULL,
		0xB29D36CE60B14139ULL,
		0x50F3B4AA77BBB024ULL,
		0xF7AB5F98E53FED25ULL,
		0x11B173A18588AF92ULL,
		0x0F51660DD8EEBF6DULL,
		0xCA8749CEFAAB51FAULL,
		0x13081052CD2B720AULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD145889776B7A4A4ULL,
		0xBD4C1E5EEA174E3EULL,
		0x56A08632EA506270ULL,
		0x5BD98FD950C1106CULL,
		0xDC9EAA3672D6D6EEULL,
		0xA4B5931E39B7C45CULL,
		0xCED363F2820A1428ULL,
		0x2ED17BDED98FC93DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28B112EED6F4948ULL,
		0x7A983CBDD42E9C7DULL,
		0xAD410C65D4A0C4E1ULL,
		0xB7B31FB2A18220D8ULL,
		0xB93D546CE5ADADDCULL,
		0x496B263C736F88B9ULL,
		0x9DA6C7E504142851ULL,
		0x5DA2F7BDB31F927BULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x213BAEE893EDE5F7ULL,
		0x81C205E98C6C9524ULL,
		0x388631FBDB887761ULL,
		0x033718A0E7342DAEULL,
		0xE67FB2E28849493BULL,
		0xBFFB7A765DEF4EB7ULL,
		0x2C5FA12839CEAF38ULL,
		0x3E07F39A63F0C362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42775DD127DBCBEEULL,
		0x03840BD318D92A48ULL,
		0x710C63F7B710EEC3ULL,
		0x066E3141CE685B5CULL,
		0xCCFF65C510929276ULL,
		0x7FF6F4ECBBDE9D6FULL,
		0x58BF4250739D5E71ULL,
		0x7C0FE734C7E186C4ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDAD827A8AC8746CULL,
		0xEAB75ADB926E154FULL,
		0x92C5968A033C1AD5ULL,
		0x09D7FEAE555993C2ULL,
		0xFD08A03D9595CCF0ULL,
		0xA94BCC5DFAFF79B5ULL,
		0xB3FBC176BE21EB98ULL,
		0x12729B1BF2D28A07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B5B04F51590E8D8ULL,
		0xD56EB5B724DC2A9FULL,
		0x258B2D14067835ABULL,
		0x13AFFD5CAAB32785ULL,
		0xFA11407B2B2B99E0ULL,
		0x529798BBF5FEF36BULL,
		0x67F782ED7C43D731ULL,
		0x24E53637E5A5140FULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x502BEFBD837A311AULL,
		0x4ABAB43B68C5E9A4ULL,
		0x44D8765C47AC3D42ULL,
		0x06FC719C62EABBC4ULL,
		0x94556319805A839FULL,
		0x69CE8833B4BAAD01ULL,
		0x0470C407921251B5ULL,
		0x18A0A0C99E66061BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA057DF7B06F46234ULL,
		0x95756876D18BD348ULL,
		0x89B0ECB88F587A84ULL,
		0x0DF8E338C5D57788ULL,
		0x28AAC63300B5073EULL,
		0xD39D106769755A03ULL,
		0x08E1880F2424A36AULL,
		0x314141933CCC0C36ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EB5036F5B38B14FULL,
		0xB3BDABC6E4F580CAULL,
		0xDE52EFC20F9D0EC2ULL,
		0x6A6C45CA2EA7FF74ULL,
		0xA723E1538811B04CULL,
		0x5471AA0C65E5F941ULL,
		0xBFB9EB4AD8029961ULL,
		0x15F9688AAED2D6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6A06DEB671629EULL,
		0x677B578DC9EB0194ULL,
		0xBCA5DF841F3A1D85ULL,
		0xD4D88B945D4FFEE9ULL,
		0x4E47C2A710236098ULL,
		0xA8E35418CBCBF283ULL,
		0x7F73D695B00532C2ULL,
		0x2BF2D1155DA5AD43ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x505B317EBEB3140EULL,
		0x9B2BD5ACD11F6426ULL,
		0x4A3F60D4857551FAULL,
		0x7FA1CD5DBB1ED42EULL,
		0xC398E6178DB1005AULL,
		0x54E45C513EC629F9ULL,
		0x9B204DC760BECBC0ULL,
		0x0200BFB8E864EF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0B662FD7D66281CULL,
		0x3657AB59A23EC84CULL,
		0x947EC1A90AEAA3F5ULL,
		0xFF439ABB763DA85CULL,
		0x8731CC2F1B6200B4ULL,
		0xA9C8B8A27D8C53F3ULL,
		0x36409B8EC17D9780ULL,
		0x04017F71D0C9DE3FULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x458CCF69E40074DFULL,
		0x9DF0003E17FFAB49ULL,
		0xE97D54DE5D327890ULL,
		0xE9DCF9A705E534FCULL,
		0xFD552F9B5538718AULL,
		0x649AB69B13730101ULL,
		0xE239B7319C4A1D00ULL,
		0x1DCD1620D6F2DBFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B199ED3C800E9BEULL,
		0x3BE0007C2FFF5692ULL,
		0xD2FAA9BCBA64F121ULL,
		0xD3B9F34E0BCA69F9ULL,
		0xFAAA5F36AA70E315ULL,
		0xC9356D3626E60203ULL,
		0xC4736E6338943A00ULL,
		0x3B9A2C41ADE5B7FBULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DF09B583AF39AC5ULL,
		0xBB02B441A0D4D5CDULL,
		0x45A21260971B5F61ULL,
		0x253FA59E2CE1D1BCULL,
		0x4B37CC9C110E0700ULL,
		0x2ABC3E2D5A6DE198ULL,
		0x9B37E8143691B81CULL,
		0x33C809D0F4927627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE136B075E7358AULL,
		0x7605688341A9AB9AULL,
		0x8B4424C12E36BEC3ULL,
		0x4A7F4B3C59C3A378ULL,
		0x966F9938221C0E00ULL,
		0x55787C5AB4DBC330ULL,
		0x366FD0286D237038ULL,
		0x679013A1E924EC4FULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FD0231F69BAD1E2ULL,
		0xEF95FF290884CD6EULL,
		0xDFE7C9E5036D0893ULL,
		0xAC08478B4B75C901ULL,
		0x0B864D838D5CB2BDULL,
		0x143D796AE32082F6ULL,
		0xA8CBD3CD591CD14AULL,
		0x377D47C41695211FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA0463ED375A3C4ULL,
		0xDF2BFE5211099ADCULL,
		0xBFCF93CA06DA1127ULL,
		0x58108F1696EB9203ULL,
		0x170C9B071AB9657BULL,
		0x287AF2D5C64105ECULL,
		0x5197A79AB239A294ULL,
		0x6EFA8F882D2A423FULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB1AF4E7D0E31E9CULL,
		0xFEE84E25FDA8DA45ULL,
		0xF596B318D912092BULL,
		0x0DB875A5F79CFD0EULL,
		0x354D7B42D362EB73ULL,
		0x178A71791484AA97ULL,
		0x2491661483A50E82ULL,
		0x16676A022836199DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9635E9CFA1C63D38ULL,
		0xFDD09C4BFB51B48BULL,
		0xEB2D6631B2241257ULL,
		0x1B70EB4BEF39FA1DULL,
		0x6A9AF685A6C5D6E6ULL,
		0x2F14E2F22909552EULL,
		0x4922CC29074A1D04ULL,
		0x2CCED404506C333AULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0933FE0AB8E9F1AULL,
		0x095BE1F8F7C96AF0ULL,
		0x732F404439BC422BULL,
		0xDA4CA79F8A114129ULL,
		0xBF35281925CCD069ULL,
		0x319EA8E614DAF6FEULL,
		0x30C89DE5E8290627ULL,
		0x035B5E5EE5701537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41267FC1571D3E34ULL,
		0x12B7C3F1EF92D5E1ULL,
		0xE65E808873788456ULL,
		0xB4994F3F14228252ULL,
		0x7E6A50324B99A0D3ULL,
		0x633D51CC29B5EDFDULL,
		0x61913BCBD0520C4EULL,
		0x06B6BCBDCAE02A6EULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA775568DB0C87C7BULL,
		0xA05796C446599EDEULL,
		0x08B583A3A589438EULL,
		0x4D1D6EE920A951E1ULL,
		0xB7E9DA888F38D3EBULL,
		0xDDE6B7AB670B7D9EULL,
		0x768ED6FC4ECABA8DULL,
		0x38E129237539FE42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEAAD1B6190F8F6ULL,
		0x40AF2D888CB33DBDULL,
		0x116B07474B12871DULL,
		0x9A3ADDD24152A3C2ULL,
		0x6FD3B5111E71A7D6ULL,
		0xBBCD6F56CE16FB3DULL,
		0xED1DADF89D95751BULL,
		0x71C25246EA73FC84ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFF5061DE37EFFCDULL,
		0x1FA7A6BB2E37D6BDULL,
		0xC8F08066B7D07C2AULL,
		0x9EF656F6F59963F7ULL,
		0xD5BCD0045EEAC723ULL,
		0x33E486BD50D0D355ULL,
		0xBB2DCEAD2654A674ULL,
		0x018D8719BEB28884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FEA0C3BC6FDFF9AULL,
		0x3F4F4D765C6FAD7BULL,
		0x91E100CD6FA0F854ULL,
		0x3DECADEDEB32C7EFULL,
		0xAB79A008BDD58E47ULL,
		0x67C90D7AA1A1A6ABULL,
		0x765B9D5A4CA94CE8ULL,
		0x031B0E337D651109ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF401084DCF13265ULL,
		0xD3C8719861BB6F61ULL,
		0xE9689509D9D10759ULL,
		0x18C02326EA8D712EULL,
		0xAA4CD40BB929BB2DULL,
		0x1EA076B97FA35E49ULL,
		0x98082F9D378719D4ULL,
		0x1C88B8A756D1E16DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E802109B9E264CAULL,
		0xA790E330C376DEC3ULL,
		0xD2D12A13B3A20EB3ULL,
		0x3180464DD51AE25DULL,
		0x5499A8177253765AULL,
		0x3D40ED72FF46BC93ULL,
		0x30105F3A6F0E33A8ULL,
		0x3911714EADA3C2DBULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF23E103EA29D7ED4ULL,
		0xF5B8E2C28A6FB28CULL,
		0x77499B45FC083306ULL,
		0x6B454ECAC98E6E00ULL,
		0x61DFDEBE6FCE770BULL,
		0x16FE90A687AD588BULL,
		0xC029E2D02BB5CAC7ULL,
		0x1FEF3949AAD7B6B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE47C207D453AFDA8ULL,
		0xEB71C58514DF6519ULL,
		0xEE93368BF810660DULL,
		0xD68A9D95931CDC00ULL,
		0xC3BFBD7CDF9CEE16ULL,
		0x2DFD214D0F5AB116ULL,
		0x8053C5A0576B958EULL,
		0x3FDE729355AF6D6FULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04333DADAC552158ULL,
		0x8564E931A6A6092CULL,
		0x824109C021697F2AULL,
		0xF4621762B150AE58ULL,
		0xE56FA76A6639A84BULL,
		0x4F266C68134B3C01ULL,
		0x862615E1195CEDD4ULL,
		0x0A0079A7D9458A04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08667B5B58AA42B0ULL,
		0x0AC9D2634D4C1258ULL,
		0x0482138042D2FE55ULL,
		0xE8C42EC562A15CB1ULL,
		0xCADF4ED4CC735097ULL,
		0x9E4CD8D026967803ULL,
		0x0C4C2BC232B9DBA8ULL,
		0x1400F34FB28B1409ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCD77397800431A0ULL,
		0xCEABCFC34D4D9275ULL,
		0xC75C0A08B07DF8AAULL,
		0x51BCACC365825B86ULL,
		0xF7F0C99028376384ULL,
		0x06207A6CF6469BE5ULL,
		0x28139A9F31E40BD2ULL,
		0x3E92A0DA822A281AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79AEE72F00086340ULL,
		0x9D579F869A9B24EBULL,
		0x8EB8141160FBF155ULL,
		0xA3795986CB04B70DULL,
		0xEFE19320506EC708ULL,
		0x0C40F4D9EC8D37CBULL,
		0x5027353E63C817A4ULL,
		0x7D2541B504545034ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x005E1415BD277926ULL,
		0x2CE5783C634655EAULL,
		0x07697A2B77188E90ULL,
		0xD2C0838630469BE9ULL,
		0xA2303B21805F5B7BULL,
		0x9BE50F95D8C6CCCEULL,
		0xC29C6CC52413760EULL,
		0x1ED8189810B28E31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00BC282B7A4EF24CULL,
		0x59CAF078C68CABD4ULL,
		0x0ED2F456EE311D20ULL,
		0xA581070C608D37D2ULL,
		0x4460764300BEB6F7ULL,
		0x37CA1F2BB18D999DULL,
		0x8538D98A4826EC1DULL,
		0x3DB0313021651C63ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43757223DC1F41E8ULL,
		0xED06D166DDA29496ULL,
		0x55E3A0A4F2644494ULL,
		0xB0F791004666E5B1ULL,
		0x708EE6DF814B67BCULL,
		0x038E292833036F4FULL,
		0xEE4C657861ADEFF3ULL,
		0x31C03F7482B07DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86EAE447B83E83D0ULL,
		0xDA0DA2CDBB45292CULL,
		0xABC74149E4C88929ULL,
		0x61EF22008CCDCB62ULL,
		0xE11DCDBF0296CF79ULL,
		0x071C52506606DE9EULL,
		0xDC98CAF0C35BDFE6ULL,
		0x63807EE90560FB59ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA20AC590D3C8BDULL,
		0x931FC7409464CD83ULL,
		0x1DDE0D25ABA2D877ULL,
		0xF44C4703D3AAD94BULL,
		0x807FB22CF27889EFULL,
		0xD9560032AFEE4BA5ULL,
		0x1ACCB9F4748E5B52ULL,
		0x2B61731FB810C028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B44158B21A7917AULL,
		0x263F8E8128C99B06ULL,
		0x3BBC1A4B5745B0EFULL,
		0xE8988E07A755B296ULL,
		0x00FF6459E4F113DFULL,
		0xB2AC00655FDC974BULL,
		0x359973E8E91CB6A5ULL,
		0x56C2E63F70218050ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84A0562C7B27372AULL,
		0x5410AFD315670948ULL,
		0xB54E8BA30D21736AULL,
		0x6AE02D7A53FEFD00ULL,
		0xA0D8E7B0188C262BULL,
		0xC658AE99BBC65325ULL,
		0x20FF604978CB6A59ULL,
		0x39642F10E82BE1C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0940AC58F64E6E54ULL,
		0xA8215FA62ACE1291ULL,
		0x6A9D17461A42E6D4ULL,
		0xD5C05AF4A7FDFA01ULL,
		0x41B1CF6031184C56ULL,
		0x8CB15D33778CA64BULL,
		0x41FEC092F196D4B3ULL,
		0x72C85E21D057C390ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32E2C19380C13179ULL,
		0x3FA7336FFB57D85CULL,
		0xEC3A685DAEDE167DULL,
		0x7C90641749294B1CULL,
		0xECAEDDF93D1F161EULL,
		0xCA2A9C44655FCA5DULL,
		0xBB777544E04FBBCFULL,
		0x2DFB34F7E475C579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C58327018262F2ULL,
		0x7F4E66DFF6AFB0B8ULL,
		0xD874D0BB5DBC2CFAULL,
		0xF920C82E92529639ULL,
		0xD95DBBF27A3E2C3CULL,
		0x94553888CABF94BBULL,
		0x76EEEA89C09F779FULL,
		0x5BF669EFC8EB8AF3ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3944CBF80561A66DULL,
		0xB4E8C002DAC181C5ULL,
		0x78A5BA096E79A61AULL,
		0xF94AA6EC6CFE3E80ULL,
		0xFCA4A04ACF590995ULL,
		0xC19C480CA075EE99ULL,
		0x4DDA3EB5AC575528ULL,
		0x15E31047296D760DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728997F00AC34CDAULL,
		0x69D18005B583038AULL,
		0xF14B7412DCF34C35ULL,
		0xF2954DD8D9FC7D00ULL,
		0xF94940959EB2132BULL,
		0x8338901940EBDD33ULL,
		0x9BB47D6B58AEAA51ULL,
		0x2BC6208E52DAEC1AULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB54EB7AD1FCCFC8ULL,
		0xC27D4F173E6F4048ULL,
		0x98F3DF6C244E744FULL,
		0x0858BF06441D88D4ULL,
		0x34FF2E8AF9050CF0ULL,
		0x34BB4368E008B220ULL,
		0x35118B0B17A4F7ADULL,
		0x23476C0C11ABE556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A9D6F5A3F99F90ULL,
		0x84FA9E2E7CDE8091ULL,
		0x31E7BED8489CE89FULL,
		0x10B17E0C883B11A9ULL,
		0x69FE5D15F20A19E0ULL,
		0x697686D1C0116440ULL,
		0x6A2316162F49EF5AULL,
		0x468ED8182357CAACULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x652BB1E98A2AA9DFULL,
		0xB48FF3984F984C6AULL,
		0x6B5323B3913D04A8ULL,
		0xB3DF237F2B08DE35ULL,
		0x2EDA9E2FD3D5B4A5ULL,
		0xC1EAB045BE37F180ULL,
		0xF0B78AAA5944142EULL,
		0x1B1FD2FA2C736915ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA5763D3145553BEULL,
		0x691FE7309F3098D4ULL,
		0xD6A64767227A0951ULL,
		0x67BE46FE5611BC6AULL,
		0x5DB53C5FA7AB694BULL,
		0x83D5608B7C6FE300ULL,
		0xE16F1554B288285DULL,
		0x363FA5F458E6D22BULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E0B158B52D93B6BULL,
		0x883705EE623A6CEEULL,
		0xC32B826F0A5071CBULL,
		0x65182779DACF1329ULL,
		0x1712716367DD8269ULL,
		0x154D0F040AA3B6E6ULL,
		0xC64D4C8D6359536BULL,
		0x0F7CDC2A9C93CD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C162B16A5B276D6ULL,
		0x106E0BDCC474D9DDULL,
		0x865704DE14A0E397ULL,
		0xCA304EF3B59E2653ULL,
		0x2E24E2C6CFBB04D2ULL,
		0x2A9A1E0815476DCCULL,
		0x8C9A991AC6B2A6D6ULL,
		0x1EF9B85539279AC5ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC473F8E587660A9ULL,
		0x3616F4AF52E50950ULL,
		0x1DAB32EFFE6D91E1ULL,
		0x9B58317AF1445F9AULL,
		0x5E061D41B0CC80A2ULL,
		0xAE1AB1414DE7F7B3ULL,
		0x73550C6D86DEE8B4ULL,
		0x2F084A92375026C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x588E7F1CB0ECC152ULL,
		0x6C2DE95EA5CA12A1ULL,
		0x3B5665DFFCDB23C2ULL,
		0x36B062F5E288BF34ULL,
		0xBC0C3A8361990145ULL,
		0x5C3562829BCFEF66ULL,
		0xE6AA18DB0DBDD169ULL,
		0x5E1095246EA04D92ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF554F6229C8199CULL,
		0xCB016C44CF24EB9DULL,
		0x97AACDCEECC9761AULL,
		0x2CB3D9C80AEA6DC4ULL,
		0xBF7A499C2DD237F5ULL,
		0xECD6D28E900B38EDULL,
		0xBC3B9B073C019B4CULL,
		0x2E88CFEE23F927DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAA9EC453903338ULL,
		0x9602D8899E49D73BULL,
		0x2F559B9DD992EC35ULL,
		0x5967B39015D4DB89ULL,
		0x7EF493385BA46FEAULL,
		0xD9ADA51D201671DBULL,
		0x7877360E78033699ULL,
		0x5D119FDC47F24FBDULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE725F9A7B1238D24ULL,
		0x0F84919076DDDAE6ULL,
		0x9F4D1AEA907B927BULL,
		0x067ACDDAFC28507CULL,
		0x5678FECC982C7F34ULL,
		0x434D894C717C20C1ULL,
		0x231C08C152C0D1D6ULL,
		0x0ABACBAD9F232C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4BF34F62471A48ULL,
		0x1F092320EDBBB5CDULL,
		0x3E9A35D520F724F6ULL,
		0x0CF59BB5F850A0F9ULL,
		0xACF1FD993058FE68ULL,
		0x869B1298E2F84182ULL,
		0x46381182A581A3ACULL,
		0x1575975B3E465922ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF43223F5E5C44FE0ULL,
		0x5D283D7D0339F6D6ULL,
		0x37C17A4EFD9613CBULL,
		0x82508F09294F56AEULL,
		0x8A9AE5BB06508A42ULL,
		0xD87B29F44A76552EULL,
		0xAA8F9BCABE391EBCULL,
		0x10B30A4C434B4ED9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE86447EBCB889FC0ULL,
		0xBA507AFA0673EDADULL,
		0x6F82F49DFB2C2796ULL,
		0x04A11E12529EAD5CULL,
		0x1535CB760CA11485ULL,
		0xB0F653E894ECAA5DULL,
		0x551F37957C723D79ULL,
		0x2166149886969DB3ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
	res = curve25519_key_cmp(&k1, &k2);
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