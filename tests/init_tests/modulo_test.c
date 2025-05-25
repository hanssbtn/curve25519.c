#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x476427F1D1980998ULL,
		0xEEF27CAE5D8FB89AULL,
		0x33C940AFD94F6126ULL,
		0xD2DE641B20B4CD09ULL,
		0x82C97DB474C0FF36ULL,
		0x1338C67095FA4DCCULL,
		0xAB9A4E33AD5CD027ULL,
		0x98BC0150ADA0EB3BULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xB14CD0BB263DEF06ULL,
		0xC95FF164A0B744F5ULL,
		0xACB0DC5B951646F3ULL,
		0x7EC69614E697B7E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x4B7DA0B9F41B4DECULL,
		0x2FD057C23F181A35ULL,
		0xC60322607E4E9077ULL,
		0xC52B5DD5EEDF79A5ULL,
		0x6B4C518B7BB6723EULL,
		0x3485EA47575B071EULL,
		0xEE344FBB1BE36322ULL,
		0x9BDD952E6717620CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D1BB6E5130469DULL,
		0xFBB11E59369B28B9ULL,
		0x21C6F826A20F478AULL,
		0x680F82B93C580791ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6E37C90F8F38C910ULL,
		0x1C49734BF6DBB9E5ULL,
		0xE47FEBCDFE9A3A6EULL,
		0x1C15E90E8662A41EULL,
		0xC61C0E6AF42EF059ULL,
		0xAC42CCCBDD997231ULL,
		0x97C5B3B4A53C3BB4ULL,
		0x3897C788C6E0BFDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD661ECEFCE307789ULL,
		0xAE33D98EDBA2AD48ULL,
		0x6BD8989E858B173FULL,
		0x029D875C0BBF1F29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xBD13086F4E96A085ULL,
		0xC42DC45F4F1C0FB9ULL,
		0xE2128DA0D5917963ULL,
		0xBCD0941330F39BC0ULL,
		0x13CAB621DA261556ULL,
		0x58050DCD5BEA7107ULL,
		0xC5CA67DED3A6592FULL,
		0x9DC1FA2A49066F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD2A1175B03DCED9ULL,
		0xD4EDD0DAF3E8D6C6ULL,
		0x3E1DF8B44042B66AULL,
		0x279BB65A07E81B5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5AEBCFC77F33BFAEULL,
		0x1F8E7A03F4F2E295ULL,
		0x9B9E83AF38F24609ULL,
		0x1CEFC0D6D2DD4930ULL,
		0xC98905D229FEE78FULL,
		0xE57AD3ADCE8718CBULL,
		0xA5E6AAABBF20799BULL,
		0xA797D0826AA2C30DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4542ACF9BB0A228BULL,
		0x2FC9E5D09D0090D5ULL,
		0x3BDBD92D97C4532DULL,
		0x7D78B432A7063D37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x71F02F32A9F65D79ULL,
		0x67A250E8DF43C7A7ULL,
		0x069FFE814842EECCULL,
		0x54F9EF951709F0EEULL,
		0x2C1384D270D22B40ULL,
		0x44452A2A7734A101ULL,
		0x256F40985122928EULL,
		0x29CE76C4D6AB189AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCD5E66F6928C9F0ULL,
		0x89E693369113ADD3ULL,
		0x9523951D5364AFEAULL,
		0x099F90CCF46F97CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x62C67F4B43A6A6FCULL,
		0xE0A7FD6BD7CFF01CULL,
		0xA9B074E800D46E9CULL,
		0xB4A19EDB04D4A2E5ULL,
		0xBDA15064A8F59637ULL,
		0x0039F027CE5797B8ULL,
		0x4D3DE468E54DB0FBULL,
		0x78278F657FADDEE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B86E3C581AF5E5ULL,
		0xE941A35478D07588ULL,
		0x20E05C7A0A5CB3DEULL,
		0x0A80E7EBF8A3B8C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2FFA43FB0E9F25FDULL,
		0x90144F05FCF22002ULL,
		0xAEBD3C8E6D637EC4ULL,
		0xA782804A441C9BEAULL,
		0x5E9BFFC8775D0552ULL,
		0xB380A2B9C8236053ULL,
		0xB8802AA626AF544FULL,
		0x33CB16BEDDE21B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B223BBCC66DF159ULL,
		0x352C7699B2326C62ULL,
		0x11C391382B6A0299ULL,
		0x57A7E09F33ACA4DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6530220C681246CEULL,
		0x5BDA5FDDA9942FF0ULL,
		0x309F1E12BA86BBE7ULL,
		0x34AB07B90D1A2C9CULL,
		0xC3E1F5377D1EF67AULL,
		0x402C21008381852CULL,
		0x68F290E6B5A7CD15ULL,
		0x82458A71A8DD648BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78BA8848FAAADFCFULL,
		0xE26745F12ECDF495ULL,
		0xC4A0A051B16F2D0EULL,
		0x0AFD94981DF7194DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2288AEF339094C47ULL,
		0xD2E4D78FFDC4297FULL,
		0xA633745E95D42189ULL,
		0xFBED09976F8F3840ULL,
		0x381C4999ABD313A9ULL,
		0x81AAE6C4D1B4AD52ULL,
		0xFEF0A9AB9BC8BC9FULL,
		0xA323E635374EA31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76BB9BC2BA5E3B13ULL,
		0x124318C71E95E3B3ULL,
		0x7DECA3D7B5A02137ULL,
		0x3341357DA53B6EB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7AF03582C754CED5ULL,
		0xAC23D01B12830083ULL,
		0xE176AE8370120046ULL,
		0xE96594CDADB00849ULL,
		0x91A1B8D15F68CE4CULL,
		0xF816990DB558236DULL,
		0x85229AC01AAAC921ULL,
		0x7CAD4BD3F373E382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F1A496F0E370EFULL,
		0x7F7E8823FD9842C7ULL,
		0xA499A707656BDB51ULL,
		0x6B1ED643D0E3CDA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC49430A6CDA025CBULL,
		0x09598E108C414F82ULL,
		0xA46ABB48302A9A4FULL,
		0x70E43AC2757E2167ULL,
		0xA8CE18B8CFA66A7AULL,
		0x60D5062B58B237B2ULL,
		0xFE502C7F25D45DD8ULL,
		0x3A56F797A4FADA5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD32BDC15A053F53DULL,
		0x68F8787FB6B59407ULL,
		0x64515627CDB0886DULL,
		0x19CCFB44F2BA8AE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x8E0272EA343E7BA7ULL,
		0x08A49FAAA0C46897ULL,
		0x37FEEDAD4F57A515ULL,
		0xE4026C60FA18A004ULL,
		0xAE58BF713970F214ULL,
		0xD070BA92F5F88765ULL,
		0xA0D401E74E5A14B4ULL,
		0x010009BAEB12DD78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F2EDDB8BB026AC5ULL,
		0xF960517B23A881AFULL,
		0x17773602F0B6B7EBULL,
		0x0A03DE1FDEE57FECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF9725F1840E8DD3BULL,
		0x28B43914C042B62BULL,
		0xD77FFD2083476B11ULL,
		0x780ADEBA8170C1EAULL,
		0xD30A44DCFBDD1F45ULL,
		0x07175371375C2495ULL,
		0x23FEA1A4785D9316ULL,
		0xF6B249C60941732BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF897E5A3BB86F7ULL,
		0x362A9BE2F7F02469ULL,
		0x2F4BFB8A612B4056ULL,
		0x1681D21FE127DA52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x554FFBF2079DC6EAULL,
		0x49699F251129B503ULL,
		0x701FC4F1AA2B6F1BULL,
		0xB40B9006688F1EE0ULL,
		0x53695ED1354F9FA5ULL,
		0xD3DCA6B12E5749B9ULL,
		0x5CAF30EB8500485DULL,
		0x36E1AEF49771383CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F40EFFF16F7AABULL,
		0xBC2A5D71F21EA685ULL,
		0x322107E768362D08ULL,
		0x598B8854E35D77D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x024DC82DFD09BA8CULL,
		0x8195F9114CC37257ULL,
		0x3B0595628D040A64ULL,
		0xD68EE8BFE6F0A947ULL,
		0xF6A5F2A7FF61883AULL,
		0x72AB37F6E24674C6ULL,
		0x0AED50EFC1154CC5ULL,
		0xD20BCF77CB39E8BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EEFCD1DE583F7E8ULL,
		0x870047B6E338C7DFULL,
		0xDA3F98F9362D6FB3ULL,
		0x044FB488118934E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDA6C9BA53B105C6CULL,
		0x1706AC381FA89BE5ULL,
		0x36921207DAF0A730ULL,
		0x08B5D9034E2D5281ULL,
		0xDAB38299A75807B8ULL,
		0x79C2BDAD32BFC42AULL,
		0x4460A0034BD1AF5DULL,
		0xF313E56F4AD190F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5111FE7412218714ULL,
		0x29EED3EDA81FBA42ULL,
		0x5CE9D2851C10AF10ULL,
		0x1DA9E7886948D6E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xFF8348FC336C7E99ULL,
		0x75FE3B25611EE5D7ULL,
		0xB7C071FAAF162B9DULL,
		0x2DFC6A7DFAEA02C0ULL,
		0xBB068839F9F261DEULL,
		0x44A45F4483A798D2ULL,
		0x22C718BFC2395000ULL,
		0xFBA253C35775281AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC27B81974D670B1EULL,
		0xA6645F50EBFF951FULL,
		0xE14E1E7183980BA7ULL,
		0x0814D97CF64DF6A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7E2E0C6FF7024D8AULL,
		0xC1122F0F41249DFDULL,
		0xB9EB0446D7F44CF9ULL,
		0x5B6A459E57CA3F85ULL,
		0xE43C54B7F9019142ULL,
		0x4F49AC0C304793EEULL,
		0xC511B642056232EBULL,
		0x2A2E5467F946A3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F229FBEED3DDE4DULL,
		0x8601B8DE6BC49373ULL,
		0xFA8C1213A487DBE7ULL,
		0x1E4ACD0D58468B9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6C6086E478589547ULL,
		0xF1672F0AE1BE9200ULL,
		0x7CE790ECC0E2E5EBULL,
		0x36542D92D5A96AF9ULL,
		0xA275C9A93ADFBA69ULL,
		0x3E590E69595CCD49ULL,
		0xB4A2B518E42E606CULL,
		0x820DCDCB05AF74E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DC7603358E43C2ULL,
		0x329F52AE25850AEEULL,
		0x4D0E729E9FC535FDULL,
		0x0460B9B5ADB4C512ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x46CB485C2AF41F38ULL,
		0x389E8E2DA0EEBF9EULL,
		0x24721D64B08B1C5DULL,
		0xB5BF0909D6739416ULL,
		0x2D64561043E0CA9FULL,
		0x61879FF75381B73DULL,
		0x155AAD800095C461ULL,
		0x3702D02B30B19CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B00EC63E523415ULL,
		0xB2C04CE4062FF2B3ULL,
		0x4FE7DE64C6C642D1ULL,
		0x6029EF7310D0DEAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7DD744A0DAE78CA4ULL,
		0x9A76157746145D5BULL,
		0x6EF47CE4681149DFULL,
		0x13A783B79DBEC95BULL,
		0x0387075B1E59E0FDULL,
		0x63413CC818EC5624ULL,
		0x77341FE82E5AF7F8ULL,
		0x1BE0538ADFC78923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E25C275C3EF2CAULL,
		0x56251B2AF92926B4ULL,
		0x20B1395B499218BEULL,
		0x36F3EA54D55D249FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDC675B924CE42CCEULL,
		0x863EDA393B9CDE52ULL,
		0xE9FA047348B1FC0FULL,
		0xDCA7238D838FCE43ULL,
		0xF870440377FF7A7AULL,
		0x8C0973871A3A12F8ULL,
		0x67AF2C606F994EE0ULL,
		0xD13FDB3D9C1E90E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD1174161CD05F97ULL,
		0x4FA60047203BAF47ULL,
		0x4DFA9AC3D973B164ULL,
		0x6C21AEB2B019502BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x434546BEFD095579ULL,
		0xC08C083BB104CD17ULL,
		0x8EAB605E32601148ULL,
		0xF3C8F2DE57717C88ULL,
		0xB00D0F3B952FE471ULL,
		0x97FC1747C9BF5847ULL,
		0x82EA2F1DA1220622ULL,
		0x02C595EABD869F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6535899722253E65ULL,
		0x4FF77CE3A36BE7BBULL,
		0xFD6E5EC41D6CFA6BULL,
		0x5D1D33B6796D1CB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6FA618D5F2838C7EULL,
		0x4452E9684175A08AULL,
		0xF90160860A8126B2ULL,
		0xBC2879406A8B8598ULL,
		0xB052A06BAE0134E1ULL,
		0xB3D1228638C92C12ULL,
		0x061F4F0D7C63ED48ULL,
		0x0ACF3DB21DBB1B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE9E8D1C6B16630ULL,
		0xF55E0954AF522B50ULL,
		0xE1A71C8681565F7CULL,
		0x56EBA1B0D4519709ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x52BF401AAF706178ULL,
		0xDB808F3D2494936BULL,
		0xCFCD8841CED9D0A6ULL,
		0xC031AD9D748C1739ULL,
		0xCEDE496BF175E9F4ULL,
		0x4310D9A184CDB56BULL,
		0x6211704F8E56F5FDULL,
		0xB86870A853C6567DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07BE262086F11FD8ULL,
		0xD000DD36DB1D816CULL,
		0x5E643410EFC2543EULL,
		0x1FB26699E3FCEDD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1AF847F20F22B0E2ULL,
		0xEFFB696C84FC27EDULL,
		0x7E1738582FBAFC8FULL,
		0x566F11F90F72FA00ULL,
		0xD7D3FE5085329030ULL,
		0x9F657DCB01655FA6ULL,
		0xDCA78079264B645FULL,
		0x372C3E08E4586A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247007E5D4A41945ULL,
		0x990C158EBA085AB1ULL,
		0x3EF44A53DEEBE2C1ULL,
		0x0700474AF492BFEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB2D875AEE77D376AULL,
		0x9049C51B3E753720ULL,
		0x163819D5D20BADD4ULL,
		0x1A4691B6ECDFBBA8ULL,
		0xB9F21FB34A05FC1EULL,
		0x338ABC80EFE73EC9ULL,
		0xA8FCAE9EC8087BE7ULL,
		0xAD0C57EEA271AD50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC92A4BE460A7A7ULL,
		0x36E1C03EDAC88912ULL,
		0x2BBA0567834E1226ULL,
		0x4A1B9F2309BF75A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x602857428F14AC70ULL,
		0x9F605C207C74F775ULL,
		0xE3EAC6AF3FEB7298ULL,
		0xBBC7C78253D286A1ULL,
		0x012FB469F149C266ULL,
		0x033812BBAAEC948DULL,
		0xEADEEFD5EF216F9AULL,
		0x8E19088FB080FAF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3D1EFC60078AC5ULL,
		0x19B323FBDB930463ULL,
		0xC1026070BEE20375ULL,
		0x537F0CD686F7C6B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x911C7546F3ABF495ULL,
		0x88CB9B787888D653ULL,
		0xF334D39991FF5569ULL,
		0x71E440A6ABE57B92ULL,
		0x196C88CCA78DA9BBULL,
		0x0CE4B79637DB5537ULL,
		0xE14BB60ECE5CDB7BULL,
		0x9B8BCD69E44B4BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5738C3A7D2B329D4ULL,
		0x72BEDBC4C3177C81ULL,
		0x6471D9CC33C7E9ADULL,
		0x08A4BE5E8F12B92AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC2F1FB1B2A823406ULL,
		0xBFD1FA06E048EBACULL,
		0x3DC5DDD3214B4FFAULL,
		0x46738CA1FDAAB1DCULL,
		0xE90533F414B8688EULL,
		0x35258A05F06C7790ULL,
		0x6217242CB16C3094ULL,
		0x56745EBD02ED6034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B7B1563DE1BB08ULL,
		0xA36476E89062AB2FULL,
		0xCD353C75775A85FAULL,
		0x1BB99CB06CE6F9A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB59F071F28A2A17BULL,
		0x6696CE80CA8D7BAFULL,
		0xD97AAD47B2490D4EULL,
		0xEA5FD8DB09D9A1C1ULL,
		0xAFB34D9CEF847B6DULL,
		0xC0187BF628A79BE5ULL,
		0xCA846F1197AF48FEULL,
		0x3ABE3E9022956C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA3C8C6AB64CF512ULL,
		0xEA39350AD36E9FC7ULL,
		0xE92329E4364DE31EULL,
		0x229D22402C07AB81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x16E51CE0E3EA909AULL,
		0xD91BD43C66A350B7ULL,
		0x1C080419316E3FC3ULL,
		0x941D57DD8D6197ADULL,
		0x04CF4647404691B5ULL,
		0x896585AD4F21E09DULL,
		0x422DECDFA6FBEC0CULL,
		0x6A436FC4E0690526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDA98B746E6433D8ULL,
		0x3E2DABF625AAA805ULL,
		0xEED92D4BFAD349A0ULL,
		0x5A1FEF16DCF85B5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3470B34F9451AD26ULL,
		0x660A96A30EABF75BULL,
		0x1BF9155D3D2D70FEULL,
		0x17A60643A43BA6E4ULL,
		0xF955F1B39189D4B8ULL,
		0xAFB305B669973E5BULL,
		0x21CE6C24D279DE5DULL,
		0x492D5BB85F00151AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x373293F72EC74205ULL,
		0x7A9D6FB6BB1F3902ULL,
		0x209D22D47B4472E6ULL,
		0x7461A3A1BE3EC8C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB74AF6712C3CD546ULL,
		0xBDB6B6170EF7A97EULL,
		0xD8159F72CFA35F7FULL,
		0x4AA0815E85CE4564ULL,
		0x1EA2456AE9465432ULL,
		0xBECFBF66C106F9C5ULL,
		0x29083B4D515E984BULL,
		0x9A727BE5A98C435EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4361444FCCAD581CULL,
		0x108D1F57B600BCC1ULL,
		0xEF4E6CECE3ADFABEULL,
		0x379EE575B0A0455EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5BA76654A759A791ULL,
		0xC47129766947399FULL,
		0x830D0F7155953B95ULL,
		0xFEFBF862D6ADC581ULL,
		0xE99A206C68323977ULL,
		0xB762F6162687DA43ULL,
		0xF64A7F5CDF6793C0ULL,
		0x25BF4240CACE2930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0888366C1ECE3032ULL,
		0xFD21B0C021719FB4ULL,
		0x121BF73A7EF52A30ULL,
		0x195FCE00F147E2C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x9F4C218F578C8A8FULL,
		0x0D562B5DBA06297FULL,
		0x54E71A787623DE31ULL,
		0x42A3ADE88420441CULL,
		0x8D11BFDF8A9877C1ULL,
		0xBC031CAA0CDA8922ULL,
		0x92C00B68CD115E3EULL,
		0xB18644EF4C1884D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FEE9CBDEA2E5524ULL,
		0xF5CC6C9BA27684A0ULL,
		0x1D68CC06E6B7DB80ULL,
		0x1C91E96DCFC3FB38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x0DDBE7CA0047C253ULL,
		0x40C3A16B45497819ULL,
		0x005D1293FB69F9F1ULL,
		0x83C55ECFE1BB833FULL,
		0x6DBC8CA4A9D5803CULL,
		0xD0861E5B7489812BULL,
		0xB039E6650ADBC62AULL,
		0x030539BDB00D6838ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D8C83B35F8CB4EULL,
		0x34AC22FE91B2A48BULL,
		0x28F545939809644CULL,
		0x768BF0F803B8FBA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6DA13F5F2A6122C4ULL,
		0x80897F4DDBD70F18ULL,
		0xA73D64FB4B30AFDAULL,
		0xCEB32C3652D32109ULL,
		0x5BF6417B0AD05B9EULL,
		0xDB43E2F1F392DDECULL,
		0x47CBA523DF271335ULL,
		0x20D0991BC68BFD22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x142EF7A2C54EBD09ULL,
		0x0C9D2F3803A4002EULL,
		0x4F77E84E6AFD89D9ULL,
		0x2DA9E655CB9AB420ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xBA656C6A833AA819ULL,
		0x2A5A96C865FD943EULL,
		0x43FFA12379C30CE2ULL,
		0xC65F774D244EB198ULL,
		0x5F08D0482BF25E4DULL,
		0x83E5D4E8707F1818ULL,
		0x76EE08439FA67A1FULL,
		0xCD24B09D938C56B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B457210934AC21ULL,
		0xBE78314918DB27DCULL,
		0xEB54DB2D2C792D8FULL,
		0x39D1AEB10B238FC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x742609BCAA5957A7ULL,
		0xE60961136CDF661EULL,
		0x0CD07526FFD65A00ULL,
		0x2A000A01FF0E0B97ULL,
		0x6D6F5BE3E2A76ED8ULL,
		0x3B2F79DA3F5CA186ULL,
		0xAFC34CE23B9CF2D8ULL,
		0x219825448E102173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ADAD904F33CC75ULL,
		0xAF157778D49F6012ULL,
		0x23CDDEBBD9226619ULL,
		0x2695922F157302C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x47C1B44D52E3BF60ULL,
		0xD91F9F5FBA04932EULL,
		0x199D1D995B239239ULL,
		0x2E7D75A903213604ULL,
		0x00C9828F78829184ULL,
		0x04FFFA1DC524540AULL,
		0x13F45F7E2921C1E5ULL,
		0x86E379CDF6C5F50CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65AB159936455BF0ULL,
		0x971EBFCAFD690CAAULL,
		0x0FE34A5376265A38ULL,
		0x34418A3BA48395CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB2276FB32332A271ULL,
		0xB0972453F82FED0CULL,
		0xCF906D72798042BAULL,
		0xE41D004AC6ECAB59ULL,
		0xF3051563125C6222ULL,
		0xBC79964968FE0FAAULL,
		0x84632DD5B0639A6CULL,
		0xD650A977A5AE8133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4E89C67DCE93850ULL,
		0xAAA373398DE6406CULL,
		0x76493B2AA8492EDEULL,
		0x3416280D5ED3D8FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xFE6BCEDC959BB4B3ULL,
		0x14C2115C637C7526ULL,
		0xE99D0D153A735D39ULL,
		0x4D19BDE1C0B2E699ULL,
		0x15FB4C69D55BF893ULL,
		0x5AC65C49D4870047ULL,
		0x598EBE79E44382EEULL,
		0xCFA974CDEFCC0A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B9269241429F1FULL,
		0x8E33C451EF867FB4ULL,
		0x34CD532D1C78CC9AULL,
		0x2041147358FC69A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x4D07A411D46D2629ULL,
		0x60BBB8AF23575297ULL,
		0x10FD641741D2B889ULL,
		0x5530C1178FFF0398ULL,
		0x552BF49A941345CDULL,
		0x5A6FDC91E598804FULL,
		0x8A2066D20548FCC6ULL,
		0x239DBF2BFD3D8B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF18DF303CF498368ULL,
		0xCD56765737FA5E5DULL,
		0x91CCA7440AA83DFAULL,
		0x1E9B219F2721BC3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAF442520E7984A32ULL,
		0xF7F2A9BB5FD7EEF4ULL,
		0xEFF35718E66C1DA1ULL,
		0x3951F10D4A8A40BEULL,
		0x344355F1472EA11DULL,
		0x06A738B84FF4F4ACULL,
		0x9F8FE2214CDB325CULL,
		0x102CEEB3D0AAEE6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7142E6F1788434DFULL,
		0xF4C515173E344084ULL,
		0x9F4EE80A4EF5974AULL,
		0x1FFD5FBE43E9A4DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xEE231D39E06DB5A0ULL,
		0x2EF67413F439ADF8ULL,
		0x6331D8AC9C3408CDULL,
		0x0AE3BC22F008E22DULL,
		0xCA2BCEDB59292DAFULL,
		0x7DB2493A83E3214EULL,
		0xF21FCC79B2619D66ULL,
		0xD810ED534C0B28D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A3D1C91C8A825AULL,
		0xD76D52C387F09FAAULL,
		0x53EA32BD16B16603ULL,
		0x1D66F68039B0F131ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC38E4A55E9205EF5ULL,
		0xA6FBBAAFD9F3DA34ULL,
		0x3CD098A8D335FB8DULL,
		0x7C0D7968132EDF2AULL,
		0xAA75D3D879C76BBCULL,
		0xDBEF2B1FE17F96F9ULL,
		0xD4494E3BFD65541BULL,
		0xA6639650921432E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110BBC77FCBA6093ULL,
		0x4C7C216B52E44344ULL,
		0xBFB23590704077B0ULL,
		0x2ED5C95DC22E6D6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC93CEF5BCA29E4FCULL,
		0x6AE3FB8FB7BD8D4EULL,
		0x00D073E60DB502A7ULL,
		0x944275208CD6ADB0ULL,
		0x0E6B46D25EE12DC9ULL,
		0x400EDF5F71231020ULL,
		0x63E562D3B5A70160ULL,
		0x5CC6A4AD1D5EB8F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED297295DF96B2E6ULL,
		0xED1923BA82F1F210ULL,
		0xD4DD1F53047F36F0ULL,
		0x59BEE6D2E8E6221CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x988A30876C37721DULL,
		0x6E0D5E2C758DD953ULL,
		0x6B199493A3C926A0ULL,
		0xF3F9CE0C40432F79ULL,
		0xE4C0378EA7441136ULL,
		0x7D2ACE7DAA58FECEULL,
		0x77C9743F519133AAULL,
		0x2DD7ACFDBF8FB718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D126FB44052013EULL,
		0x026804D3BEC3AC09ULL,
		0x3300D5F9BF56D1EFULL,
		0x41FD7BB6AF985D1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAD1F7744A5602B97ULL,
		0x79BF2E287E788312ULL,
		0xD93F23ADA90AA4FEULL,
		0xCF914D1D4BD7E009ULL,
		0x291BCF5476FFDE32ULL,
		0x36DCAE8F27863E2EULL,
		0xC6894E4DE1CE2094ULL,
		0x6339B3A98FDA2C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7403DCE4F5B2950ULL,
		0x9E8117685C65BDECULL,
		0x51A0C33D2DA37AFEULL,
		0x0A21F848A63A75F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xCB1BACC2A81175E9ULL,
		0xE474103FF9018D86ULL,
		0x69171CCFE94F6F0FULL,
		0x61E3B1774E52D07FULL,
		0x3BA6193C23AF9C95ULL,
		0x80A714381539C8FEULL,
		0xD21A6318A5370BA6ULL,
		0x33121BD1AC70791BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5C36BAFF422B524ULL,
		0xFD4110931F956343ULL,
		0x9901D2786F7B29C6ULL,
		0x7693D296E704CAA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x81D00B92528E6A23ULL,
		0xEDF7138887D4B81CULL,
		0x27222D7ED9C9EBFAULL,
		0xD9A27727859FE71DULL,
		0xFF3F4E53516D64E0ULL,
		0x7A5B3435B40A638BULL,
		0x907E016AC16892F8ULL,
		0xD05F476475C2EBE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6535ABF068CB6810ULL,
		0x1780D381415F7EE4ULL,
		0x99D663578F4FBCDDULL,
		0x47C71011008EEB0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x51B0A54131F647BCULL,
		0x369B63F9808CDF3AULL,
		0x4E520C748EADB0A3ULL,
		0x2AB9ECC72763DF4DULL,
		0x4F6BD60E169EE4F7ULL,
		0x977520A20847C921ULL,
		0xA8620DA6BC70DE3FULL,
		0x60EC23E3572BB434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BB26B588D8C468DULL,
		0xB1FE3C06BB34BA2CULL,
		0x4CE01334876EAE13ULL,
		0x0DC7408617E09F1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xD72C8EEBDE183EE8ULL,
		0x06C801518946C576ULL,
		0x6E74E74023714C31ULL,
		0xE036FE89406EB64DULL,
		0x3E75FD6B38660B45ULL,
		0x0C0FCB3249450737ULL,
		0xF960B57A9D9B0EBDULL,
		0x19AB2E48492210AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CB02CD63D3DEBD1ULL,
		0xD1202AC86985D7AAULL,
		0x72CFD77388757C40ULL,
		0x2F9FDD441B7D2FAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x01B76D5D3D9A736BULL,
		0x5C8A953CE102C897ULL,
		0x6B4A477817FD321AULL,
		0x98CCAC7596A1FDEEULL,
		0x22720E1B84EE18D6ULL,
		0x316015688B8E8D32ULL,
		0x387C9A3C1B85B811ULL,
		0x4F582493A733A3B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EA58572F8F224F7ULL,
		0xB0CDC2C1982BBE08ULL,
		0xCDC92C642DD684A7ULL,
		0x5FE21A60684C4A62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xECC4E94455A8B067ULL,
		0x7E3DA11E564F9F02ULL,
		0x5194C5DFEF9D5658ULL,
		0xCA04FC4377AEB0D5ULL,
		0x88C1480FB818CAA5ULL,
		0x82B60296D94C1168ULL,
		0xE12FE2FD8E3056E0ULL,
		0xD83AA8DF7F62F8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39759B99A956C9B8ULL,
		0xE5420382979A3487ULL,
		0xBEB077830ACA3BABULL,
		0x62BA0D70605FA152ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF523BECABA5287E2ULL,
		0x9072C84BDC0BD484ULL,
		0x21D1983FF819575EULL,
		0x110E15AE6F71A25BULL,
		0x735E585D70A57187ULL,
		0x83996D737675CC1CULL,
		0xFD6CEC0B1712CED0ULL,
		0x5FCE48AC447A4D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1524DCA972E16400ULL,
		0x1939076F718820BEULL,
		0xBFFCA1E564E40A52ULL,
		0x49ACDF40999925E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x9AE87B91FF3E7162ULL,
		0x7657E5C74ECEA9FDULL,
		0x1462611A99F30386ULL,
		0x5E60508A66C088F2ULL,
		0x40261861D26D3C60ULL,
		0x9CCF12899FE6FBD4ULL,
		0xF1318B6B72436811ULL,
		0x498C713CD6C48C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20901A173B756944ULL,
		0xBD14A6350B180B7FULL,
		0xE1BD130D8FF47623ULL,
		0x49391F9247ED5DD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF0545F19E9317E28ULL,
		0x009F0345B93AD907ULL,
		0x5D365E095866DB9DULL,
		0x7468B89A68E405CDULL,
		0x544FC3A1ECD4DC7CULL,
		0x5A5D556300D88C6DULL,
		0xC9A50C1AC5AEDD28ULL,
		0x42881CCF4F63C9B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742B692310CA3A0CULL,
		0x6A79AFF7D95FB142ULL,
		0x4BB62A02B05BAF9AULL,
		0x549CFF6031B3F6C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x38C7C79899D31B1CULL,
		0xF9194ED079EF95B6ULL,
		0xDACE0916FF5D5E8AULL,
		0xB278882B0DC0EAF1ULL,
		0x7A33CD6C6891E050ULL,
		0x48FF4E6DDAD0CB6BULL,
		0xD2490B840C3F0245ULL,
		0xF674CE58E081CD06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C7845B01F7A6C7AULL,
		0xCEFEF31EF4EDC7AAULL,
		0x11A5BEB0D0B7B4D3ULL,
		0x47CF295C610559F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x10D85AFE81DE660CULL,
		0x1212BFE877C0D6FCULL,
		0x54BE26379577B4E4ULL,
		0x69ECF2F0E786DCEBULL,
		0x56FED9E536305796ULL,
		0xFE5AA158BE30E0E5ULL,
		0x98B88BB9214A2B12ULL,
		0xD9A7C4F63B196D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAACB3048D0B6B23ULL,
		0xD386B314B3023906ULL,
		0x0022E3B2867A19B5ULL,
		0x38D42F7DAD4D172EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3DE33C3039AAE7B4ULL,
		0x40B069FB33BC7E62ULL,
		0xBF1A6ECDDA53E233ULL,
		0xF1D691A2933CABEEULL,
		0xCB04D41972D2B2FAULL,
		0xF225DC045380718CULL,
		0xE9407E1C2AFD01E4ULL,
		0xE7A42D4679186F77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609AB7F744F17E02ULL,
		0x324F129F98CD5948ULL,
		0x5EAD26FC3BE22A2FULL,
		0x54354A188CDD37BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x0636A6CDF0B30A98ULL,
		0x2733F6553C58DDB4ULL,
		0x1AB994CAAF69A39CULL,
		0xDDD3CED6AD41555AULL,
		0xBAB05D9C515034B7ULL,
		0xA3562853B757449EULL,
		0xDFD9B964642D9070ULL,
		0xEB95C4307A48E52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC648C02029AE307ULL,
		0x65FDF2C2734D0D43ULL,
		0x550B19B18E2D1454ULL,
		0x560EEE08D4135A03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x9C39361B1F2BC91DULL,
		0xD4A75727CA8749CEULL,
		0xBFE767B1DC380F1DULL,
		0x9F3FDEAE123E6B09ULL,
		0x6D02E2D9D760FD1DULL,
		0x07FB640ED13A5745ULL,
		0xDACC013A66FEAD41ULL,
		0xCFBF3A1D411965EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAA6E27117916005ULL,
		0x03F8315AD9303E1CULL,
		0x3A2F965D2605C6C5ULL,
		0x75A27F05BC038C7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x40D828745E73CC9CULL,
		0xB7F3A4A802282624ULL,
		0xB4A8424BC2B56807ULL,
		0xCC7B63FCA81C4CDDULL,
		0x31973DB14BEA4DEBULL,
		0x46396256AE072B07ULL,
		0x779F79B430519469ULL,
		0x54A6BDD86E5166A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D4B50C5A33B5F6CULL,
		0x24783D85D7388935ULL,
		0x7654530AEED16FA8ULL,
		0x5D3B921D08318947ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB86DED022960354AULL,
		0x6EFB295C501E93D6ULL,
		0x0FE98AD5809A312DULL,
		0x8903D80ED12D3EEDULL,
		0xB97FF3F4A2AD9073ULL,
		0x26CDD1F3C68F305DULL,
		0x0C23FE6794DECBF2ULL,
		0xC87A4F6FDD71FFA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x416C23524F23AAD0ULL,
		0x3188538BC95FC1C0ULL,
		0xDD414E3599AC771FULL,
		0x4B2BA2A9B01930AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x08CA9892E0E7BFA1ULL,
		0x89D98F86935EC311ULL,
		0x75D89E05DD7D1951ULL,
		0xFF3E5EDDB1011F2FULL,
		0xEE7ABF90412DDD3AULL,
		0x395A51AF99A72133ULL,
		0x66D458256F6B3976ULL,
		0x1B422E0C7E6BEF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F0307FC8DB696FBULL,
		0x0D41AF97622DB0C6ULL,
		0xB95DB3946767A0DEULL,
		0x0B1134B875069E24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7449E4942B73B0EBULL,
		0x03AD21C7906B93E7ULL,
		0x74FC2A6DE6167546ULL,
		0xFC9BAFE76345239DULL,
		0x42310AFA2285B6F7ULL,
		0xB0DCB154549A557CULL,
		0x5A0F6739D6771545ULL,
		0xD5212A40918F8C1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x479185B54B4CDE68ULL,
		0x446F744C1F544459ULL,
		0xD3457D03BBC39D9EULL,
		0x1F87F57CFE93F01EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC84B34AFEB431DE1ULL,
		0x1C97B0FC3807B05AULL,
		0x0800980C4E1DBF66ULL,
		0xF4835415B793D96DULL,
		0x9DE59A3A55785427ULL,
		0x91330206EA7F227FULL,
		0x2E16C09A744C58C9ULL,
		0xE822A591B8405AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x386019589B1FA0DDULL,
		0xAA29FE0306E6CF4CULL,
		0xDF612EF99172ED51ULL,
		0x69A7E7B711214F93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x4FF1A94D1FA2CFBEULL,
		0x6DB15B8FF725DD17ULL,
		0x4279D35DC8501CE4ULL,
		0x66E9A00A73349733ULL,
		0xA7FBE86FD2D14A36ULL,
		0xCF4804BB8126B773ULL,
		0xBCF04699CBA51A0EULL,
		0xAE6712C5EDA3F9C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5629E66AB3D79EULL,
		0x32620F6522E51842ULL,
		0x4E244E3202D1FB17ULL,
		0x4A36696BB98BAA8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xFEF419F0ADDCDC64ULL,
		0x4859C6AC634B6BBEULL,
		0x2629F87F64E42ABFULL,
		0xBBA36E62228FBC50ULL,
		0xC65BD1B232B4B715ULL,
		0xD51CD6B074A9A23DULL,
		0x3E460D8E3AE87453ULL,
		0x0C54009868B26D5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70953A6434B009E1ULL,
		0xEAA1A4DDB47980EAULL,
		0x648FFB9C23656F30ULL,
		0x101B8501AD0BF7B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC3BB8A588CB54EDDULL,
		0x730075BEC97942D1ULL,
		0x64091C398BEB6B89ULL,
		0x6CEC2765B1EB6834ULL,
		0xDACE386EE81C153FULL,
		0x680BF75871E80D8CULL,
		0x918D18EA910C2BC0ULL,
		0xF97715B828B812E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E57EACF00E07BB5ULL,
		0xE4C72CDFB1EB45BAULL,
		0xFEFACF0B13B9EA18ULL,
		0x749960BBBD3E3621ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x957D5919994EB465ULL,
		0x3B882C444626B7A2ULL,
		0x7618FD047821D47FULL,
		0x9498321AE50DDB13ULL,
		0x68E4000FA410A4E8ULL,
		0x51D4B0325E1DBA64ULL,
		0xAF19FE43530D6E7FULL,
		0xF7EEF212437DD49EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27555B6BF3C73453ULL,
		0x611A53BE3E90628AULL,
		0x73F4BB02CC203B65ULL,
		0x621020D0E9BB6AA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1F313DC66EC390DDULL,
		0x632F8EDB78FA86E6ULL,
		0x8CC158680337323DULL,
		0xD407EC68BBE9C882ULL,
		0x89DC8FCE9056C37CULL,
		0xD9963A5DAD9D46FCULL,
		0xDB5D8609DAF7F5BAULL,
		0x364DCF266FE38BFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95EE966FDBA49688ULL,
		0xAF7C38C33E531062ULL,
		0x1CA33DDE8405ABF9ULL,
		0x6394AC1D57B09031ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3FE051E8FF75C3ACULL,
		0xDB53DD336955FD94ULL,
		0x0BC5BE77FCAE434AULL,
		0xD0ED23B82E7EEB1AULL,
		0xB04C891378EF32E7ULL,
		0x1E7962F0308AC0B5ULL,
		0xA279F9DCC73F4B30ULL,
		0x12060329EF72B0D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B3CAACCF2F75268ULL,
		0x61588CDA9DEE988CULL,
		0x29E0D53D90136C6FULL,
		0x7DD19BF1B9852AD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x856053E005D073BDULL,
		0x617E7AD4083A5CFCULL,
		0xA0DFF352F8F4A537ULL,
		0x251CEDCDCE0DF8CBULL,
		0x6D427A353184564FULL,
		0x663A708EE2CC4990ULL,
		0x275D372FCF7A08F3ULL,
		0x29CA80076E37EFF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD3E77C55F75445BULL,
		0x8E2B3009B28D486CULL,
		0x78B6246BC511F958ULL,
		0x592BEEE82A5B977BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF15888D16952348AULL,
		0x82D3D842DDABF5B2ULL,
		0x8003F0751D289ED9ULL,
		0x0E53EFC7B49439F1ULL,
		0xA93864C004A3D90FULL,
		0xD0E16EEC70DA27C4ULL,
		0x1790AAEFE54E5102ULL,
		0x46E81C23464F3042ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FB77D5219A46E53ULL,
		0x844A4F5B9E0DDCE4ULL,
		0xFF7D501126C8A544ULL,
		0x14C81D04245563C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x081B9A11E500DF22ULL,
		0xE33E5BD1E45F9C6DULL,
		0x556232B25F5BAB2DULL,
		0xA1E2E33A6B64EF3AULL,
		0xFDD8F3334DB48D29ULL,
		0xB25CB72997E102D1ULL,
		0xF52786E2FEC9B0D7ULL,
		0xE04B8B7D20E38C6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64FB3AF6DCDD831ULL,
		0x5D018BFE6FC60798ULL,
		0xB9403864314BEB32ULL,
		0x6D1997CD4D2BC740ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xE66B4FAF777A2D4DULL,
		0xAAB24B5FC11A44F5ULL,
		0x7A2A370E3473DF9EULL,
		0xD2F52E2632D385E0ULL,
		0x1D13D7BF50B3F711ULL,
		0xCB4B3E1CD4F76F5EULL,
		0xF56A216736351E19ULL,
		0xC529DD924528E9CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x375D56157230DE47ULL,
		0xD7DD83A75DD4CCEEULL,
		0xE7EB2C6040565772ULL,
		0x172C11DC76E63A00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7487A24F07E52F7DULL,
		0xDC7DD6356F10F6F0ULL,
		0x7C20E7F60DDC3011ULL,
		0x4B482D0BB192AC1DULL,
		0xF868A394761F8DFFULL,
		0xEAB1FBAB618E573CULL,
		0xACF2C3DC02F7B017ULL,
		0xE75F5A4550A4885AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x540FEA5890944876ULL,
		0xB2E931A5EA31E9FDULL,
		0x2829FA9E7EA0539EULL,
		0x236F9355A9FEE993ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6A188F7061E4080BULL,
		0x5049896726693819ULL,
		0xC0ED7745EA6DAAF0ULL,
		0xF1F1F9215EC457A7ULL,
		0x9C448EBDB62852A8ULL,
		0x3126D24BE8E22708ULL,
		0xF041AE2F60E00B10ULL,
		0x5F23A8CE5F301E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C45BF996BE04F35ULL,
		0x9C0CC0ABB7FB0360ULL,
		0x6AAD524E4BAF4F57ULL,
		0x113D07C37FE8DF63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7CE3853F03873D1BULL,
		0x3C6C80F7363DE32CULL,
		0x36A7DC4EA5CB17CDULL,
		0x3320F7A986FD0B49ULL,
		0xACCFD34CA5590A06ULL,
		0x8CE4E85932C95046ULL,
		0x45493CE65D8788D3ULL,
		0x37923D6CDDDEB50EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23BCE29F8EBEBB2FULL,
		0x2666FE34C01FCDAAULL,
		0x7F86E68087E96734ULL,
		0x72D615D2760BEB67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xCAF627615928E858ULL,
		0xCB2D5CC43FF4C0F5ULL,
		0xAA213D2032BA674EULL,
		0xC5AC3DAE11FC3802ULL,
		0xEF6DFB867C8ED48EULL,
		0xD64CBA699E4EAB23ULL,
		0xC3A4E7A287A9AA04ULL,
		0x9B3AFAB78E737A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55497D57D65C78E9ULL,
		0x9A910871BFA2284BULL,
		0xB49B9F4055E9A406ULL,
		0x506D74ED37206615ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x43962DCC319ADC41ULL,
		0xC84731938D22C732ULL,
		0x01F5CCAD9134C4C7ULL,
		0xC68DA7F12FA015AEULL,
		0x77E291EEC1E2478BULL,
		0xFFE35C060D244231ULL,
		0x4E172D55BD6BA9E3ULL,
		0x58DDB4CDCC585D23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F37D73CF9317CE4ULL,
		0xC406DA7980849A8AULL,
		0x99668767AF2FFC9FULL,
		0x77767E7D84BDE8EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF175DE42574DE36EULL,
		0x57F4850E3A60B4DAULL,
		0x492427F2115CDA2AULL,
		0x05C4230C3B61F4E6ULL,
		0x878B784AD49A0EBBULL,
		0x48D10CF359A76848ULL,
		0xA55A7F288106D0D3ULL,
		0x434555260073FB80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1029B95DE62C14ACULL,
		0x26FC712D893A2F9FULL,
		0xD49307F5385FD987ULL,
		0x020EC6B04C9949FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x40F9816CD36E261FULL,
		0x238A07FB6D9DB522ULL,
		0x14E3954EFCC6AB49ULL,
		0xBB26595523D13F36ULL,
		0xF7105210E98767F1ULL,
		0xF2FCF6A6D5372BA8ULL,
		0xCF2DC485647F175FULL,
		0x686DE32367378E3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED65AFEF7D879645ULL,
		0x3516A4BF13CE3036ULL,
		0xD5AEC11BE7A42387ULL,
		0x3B76109676105BF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAE6EEB417DBBDD24ULL,
		0x5D7BA04460EBAE84ULL,
		0x84C6C118A1711973ULL,
		0x7ED8A1F049AAC19DULL,
		0x6981B34D642ADE65ULL,
		0xB351177CB3BFDC34ULL,
		0xC0FF7FC490448BB2ULL,
		0x25175638172A9D43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57AF88BE5C18E106ULL,
		0xFB851CC70F665E4CULL,
		0x2AB3B8460B9DD5F9ULL,
		0x004F6E43B9FE19ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAE8F01FA35FDDAE8ULL,
		0x2661115C24992DD8ULL,
		0xD6DE9FD2E38AF082ULL,
		0x10F6337ECA97614CULL,
		0x1B664BC4044185DEULL,
		0x7378CC9960E01143ULL,
		0x55037D2FC40B791DULL,
		0xBFB12905A7E59605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFBE4112D7B7BE17ULL,
		0x4A4F702085DBBDCEULL,
		0x756334E9FD3EEAE1ULL,
		0x05424A55B6ABA617ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2A53209E9D10195BULL,
		0x796F8874F1D4826AULL,
		0x9E3B0431D6104CACULL,
		0xCBD73B5B003A9D9CULL,
		0x4B5CB8756BB40062ULL,
		0x02E339D78F30FC9AULL,
		0x9385A7638BE4B487ULL,
		0x419349644A9EDBBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A16820C99C82976ULL,
		0xE72A1E74331A0151ULL,
		0x8411DCF89A0318B6ULL,
		0x07B4203E13CF3B4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDB34C0EE38C0C439ULL,
		0x657541735E764C24ULL,
		0xEE54891B5B8412D5ULL,
		0xA5C665C4D7E3377DULL,
		0x2397497584A9A4E5ULL,
		0xB5F7FEE6964CAA18ULL,
		0x72BD654FDD35CD2EULL,
		0x6E973FC8E5B9EBEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A9A85FE9EF40BDULL,
		0x684517ADADD78BBAULL,
		0xF67192F6318087C4ULL,
		0x1039DD96F17C3CBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC0DFD0F97E599854ULL,
		0x0B23779B5F9614AAULL,
		0xC1900D0140A34E3DULL,
		0x9775DD9A2D5C778FULL,
		0x12B4E234AFAEF319ULL,
		0x684FBBE53E947E67ULL,
		0x96BE4017569A34D2ULL,
		0x410F0DB21D0298EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B964CB9251AF86ULL,
		0x86F95BA2A9A0D7F7ULL,
		0x21CD90781B872578ULL,
		0x3FB1E60A7BBF2AD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xFD27055428EE41AFULL,
		0x067E6E790D6A8C2CULL,
		0x5DE48940381F34A9ULL,
		0x61A0803B19D57B56ULL,
		0x8FF97F854E5AA396ULL,
		0x7BEC90EE120530BCULL,
		0xB53E7250001CB21DULL,
		0x471916DD5B8B31F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2FF31DCA628B82ULL,
		0x6B9BF1CFBA2FC82AULL,
		0x452981203C61A509ULL,
		0x6F59E516B07EE667ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xCBA9ACEA8A0459F3ULL,
		0x436C4E37D5D04BE3ULL,
		0xCE57D4C4004E1D08ULL,
		0x6C524B71A1B7DE95ULL,
		0xD5A7BA473655E0EAULL,
		0x5007E258465CC354ULL,
		0xD00182DB12C9D958ULL,
		0xF07330CEB4C36826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x828F537C9AC3C207ULL,
		0x2497E75247954A7BULL,
		0xAE914148CA446024ULL,
		0x1D6B8A2076B95458ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x317C997437B83E02ULL,
		0x51AD2D14EE8193F7ULL,
		0xC5ACF4B509572E27ULL,
		0x68006CD00A78B717ULL,
		0xBE447909D36F1BEFULL,
		0x6DC3687060F6677CULL,
		0x406752B0372EF294ULL,
		0xB9857844790CB5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FA690E99A366791ULL,
		0x9CAEADC35314F07BULL,
		0x55033ADD3A4F302FULL,
		0x71D046FA025BADC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7B0543BA11BDB8F5ULL,
		0x47C22FD438D063E7ULL,
		0x8CC6DCE49E096360ULL,
		0x7E31F5763901C4D4ULL,
		0xC8360D46B25D267FULL,
		0x40210C9C42E13D71ULL,
		0x8534DA35E8145372ULL,
		0x8826381AB82A7E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330B3C388B9172DAULL,
		0xCCAA0F06263F82CBULL,
		0x529F40E5110DC655ULL,
		0x33DE496D8F50887EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA56B65188497C712ULL,
		0xF50A355D6A62333CULL,
		0x6EC66811377B6F3CULL,
		0xB6FACC564A4ACCC8ULL,
		0xB4487A2D9DE8F458ULL,
		0xE3F0EE6F6944D7F3ULL,
		0x3A8888D843D2006AULL,
		0x9D3443A0765359D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682D87DDF52C0FB2ULL,
		0xCACD99E70A9A4169ULL,
		0x1F0AB82B48A77F1AULL,
		0x0CBCD627DAAA21FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2B52C40AD0E88A92ULL,
		0x302D1C64084FDA32ULL,
		0x0C6B017A3280FEB4ULL,
		0x90E2D7653CD6D37AULL,
		0xA133862EFF2FE11EULL,
		0x2588AD86A33FD257ULL,
		0xD56FBCD84113B703ULL,
		0xA9281A96B85830CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F8AF04B203F8CFULL,
		0xC276DE6043C91334ULL,
		0xBB010993DB6E292BULL,
		0x2CD6C9C499EE1195ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x19D9813EA90858C6ULL,
		0x17B5074172BD19E7ULL,
		0x2DF848B7AF01B602ULL,
		0x0776E2B3586B2758ULL,
		0x0D25BAAB7A1E158EULL,
		0xB1DF1D65908E6E8BULL,
		0x1CA9476DD1661BB6ULL,
		0x8100604D12B45825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7336B2C97F8EACULL,
		0x7ED36454E7E1828BULL,
		0x6F18E304C429D320ULL,
		0x2D852E241F303CDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x9F24DD5AA5E6BB3DULL,
		0x08EE316814A3EF50ULL,
		0x01928EA6F2B98823ULL,
		0x08B4E9237A5A0436ULL,
		0xE25EE986A62A5888ULL,
		0x3845E5A96B6D820FULL,
		0x1196C95755E096DBULL,
		0xCB25DDA6FE65DCB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x393B8757502FE3E1ULL,
		0x634E488E06E53DACULL,
		0x9DF4719DB20FECADULL,
		0x3053CFED3D78C716ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5BA0C9F2CF8BAFB1ULL,
		0x85CE626250708014ULL,
		0xE2AEA4EBC02AFCD4ULL,
		0xC91F5AFB4C266895ULL,
		0x46E3398EF66ADF41ULL,
		0xB135E534724FC0A1ULL,
		0x5E0108E6789CB7B1ULL,
		0x5C6D183496F2132AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE15B552B6368D57EULL,
		0xD3CE682B48471804ULL,
		0xD6D5F721A76E4134ULL,
		0x0150F2C9B41540DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x72D8B34798CBCD91ULL,
		0xBEDCDB2757DD50ADULL,
		0x0D479A3F78BC4BF9ULL,
		0x8CFB54B6835794E4ULL,
		0x937B9C9F1DDF757BULL,
		0x329DEFEC0BDB4DB6ULL,
		0x0DA87220AEAF64E9ULL,
		0xC837FEBD54E22D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5731F2E607F74247ULL,
		0x424E78311A6AD9C7ULL,
		0x14488B1966C54697ULL,
		0x454B24D11CEA43F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1B4EDF8B264445CAULL,
		0x792A1C7E648F289BULL,
		0xBC6BB461E9FAC015ULL,
		0x37D5186D0BD55B29ULL,
		0x4E61515D3192D399ULL,
		0x5D292BF980AC36ABULL,
		0x9F1CEBAACF43484DULL,
		0x3CDE60CA7C32F028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC0F360820FAFD6ULL,
		0x4D46A3877E1F4608ULL,
		0x5AB6AFBCADF77B91ULL,
		0x40D7767B7B650131ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x376D7650079D510BULL,
		0xF85238C28D3B9520ULL,
		0xD628DDD6383A9020ULL,
		0xE0BB3424445203CBULL,
		0x6DF802E0BABBE0D4ULL,
		0x181E7B773A8EC9F5ULL,
		0xBE03F74BB085084EULL,
		0xC3670B275BCAD7E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A3DE3ABBF80B4E4ULL,
		0x8CD88C753E6D8F8EULL,
		0x0ABF93126BF9CBB8ULL,
		0x6206DBFBE46E0FC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x28642C9AE6ABB689ULL,
		0x98F068E0A5C5E1DBULL,
		0x3483843D746AA4C9ULL,
		0x6360826D99A0EEB7ULL,
		0xEF864DEE3DBD8542ULL,
		0xBC218EF09B6172C8ULL,
		0x8E7A5E8D330B1EF2ULL,
		0x34C3AC5AB5BD6385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB653BDF810CD7F85ULL,
		0x85EBA097B63CEBAEULL,
		0x5AAD8D3308113CD1ULL,
		0x386C17E493BDB48AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xB03AE9250AA7FE85ULL,
		0x655B23981B1A835AULL,
		0xE373974049C78AA1ULL,
		0x82EB96C3E7C6754CULL,
		0x0E795770AAFDB1CFULL,
		0x7352A2044829166DULL,
		0x76B46058E44658FFULL,
		0x047D87A7976B139DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63DE3DE6C506365ULL,
		0x839F303AD133D78AULL,
		0x8239E4722C38C08CULL,
		0x2D8DB9A461AB5EACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x236C9515EBDEEF56ULL,
		0x1D1BDA551C6A655AULL,
		0x0A2CB8C3BDB72809ULL,
		0xA2A788FF403D0BE0ULL,
		0x3FC2A5FE83A7281EULL,
		0xF456354301BBEB81ULL,
		0x8E7B36774BBF0A5CULL,
		0x74CD8ABB0E6D79A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5138DD76AEE663ULL,
		0x61E7C2475E4F5A89ULL,
		0x3076CE78FC12B1D5ULL,
		0x792A20C3647D1B0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x4CAC67C7CCCE2426ULL,
		0x8B62BA426AC6C43CULL,
		0xD37186EDB8042A61ULL,
		0x6FF41904A1A9AEA6ULL,
		0x522ED6DE1E9FA504ULL,
		0x1FD24EE774D9AE6BULL,
		0x0D2C38F62ED3858EULL,
		0xDFFC15CD220AE416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA04CC05880A7B7ULL,
		0x449A709DC316A82AULL,
		0xC801FB78AB69FD7AULL,
		0x2F5F5577AF4789ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA93E84B48D16CEC9ULL,
		0xFA2B161FCEB4B0D3ULL,
		0x3ED05DE70DC00F14ULL,
		0x08E772B71663E53DULL,
		0xCF62E76887B39F1AULL,
		0x15257C106151ED21ULL,
		0xA0FE452E1EA0517FULL,
		0x1D9F5CDAD7C39835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71ECDE38B1C06D3DULL,
		0x1DBB808E40DDE3D8ULL,
		0x248EA2BF998C27F2ULL,
		0x6E8F3B331D6C7D33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xBA4C95D0E891A995ULL,
		0x4E3C5124C12DDEDFULL,
		0x38155BA95EFE2EACULL,
		0x529C1ACD273F527AULL,
		0x1F76CA5455309B58ULL,
		0x7B7B4CCC6A8593AFULL,
		0x33A1C93769755884ULL,
		0x519E6259A69DFC9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65EE9E558DC8BA6DULL,
		0xA289B77C9101CADEULL,
		0xE21939E306695256ULL,
		0x701EB41BE2B2D1CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xD08151BC6A57C38BULL,
		0x59948811394ED29DULL,
		0xAEE9C4A7D262DD60ULL,
		0x9537767357AC4878ULL,
		0x1F6963CB3BCD5108ULL,
		0x12AEF2BD7F21D21BULL,
		0xABC0816979BE6D9FULL,
		0xA1A6F20FFF647C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A2621E74AD1CE5EULL,
		0x1F8C9032185402A4ULL,
		0x2D7CFA4FE4A722FDULL,
		0x13FF64D34096C450ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x750135C8C68A4703ULL,
		0x444CA28B6E7CC304ULL,
		0x65FCA7B0049DF4EDULL,
		0x131F780655140E85ULL,
		0xA857832128AB1A64ULL,
		0xBF5463482A8E8E9AULL,
		0xEB19FCBBCE48D6BDULL,
		0xA2CE1E267F9877B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71FEACB4CFF0356BULL,
		0xAAD35F41BFA5EDF9ULL,
		0x4BD82B90A36DD517ULL,
		0x3DB7F1BD45B5D2C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xEB248A89DB8210C0ULL,
		0x087FA860520AC9C4ULL,
		0x1107E42112020640ULL,
		0xC71293F03CF44B0FULL,
		0xF9B054568FCD60A1ULL,
		0x1EB79CFA7AED9E36ULL,
		0xFA10A64CFAB82CCEULL,
		0xE6237FD837BA0348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB510F6333FE6DC5ULL,
		0x97C0F58E915045EDULL,
		0x2F80938E4958ACD8ULL,
		0x70578E088290C7E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1AC8F71F23E40072ULL,
		0x0D56E120373B82CBULL,
		0xF4F4ED30FD522C6BULL,
		0x9C3A9877DB479176ULL,
		0x7F752239EE7AAFC0ULL,
		0x2AB0FBED9F6E1380ULL,
		0x8E2D521DC9A50E97ULL,
		0x92E3B02A8EE9F151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062C0BB88A1A1A36ULL,
		0x639C4665E19267DEULL,
		0x0FAF1D9CEBD256DBULL,
		0x6A06BEC912016392ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC148A5974B78F4E4ULL,
		0xE756A3F6555F560BULL,
		0x664929D16E86EE31ULL,
		0x83759A24B64770C8ULL,
		0x6F2BD694FF376444ULL,
		0xEE9DAC8ADDED61B9ULL,
		0x8BD30E4B41385510ULL,
		0x97DB700DF0114BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CA7FB52DB1DA66ULL,
		0x52BE4093469BD792ULL,
		0x279D48FD1CE38EB5ULL,
		0x0E083C3658D8B41DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDB0113AF47951BDFULL,
		0xD3DBD2500CB5E8CEULL,
		0x357E28E8F68BD3E8ULL,
		0x4BBAB6E6988D553FULL,
		0x5D79F33E5D6FC7C7ULL,
		0x3A6EDD083AEBD8FBULL,
		0xAE3482707B7CD0ABULL,
		0xE66E817FC7587FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB1B2EF1262CC888ULL,
		0x8050A188CBB81E1EULL,
		0x1149859B4B12CD53ULL,
		0x0021EFDE2FB0492DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x0D243B53C7D2CE74ULL,
		0xE109A959A40EF101ULL,
		0x9967FDC2FF75E6B6ULL,
		0xBA401128437A054AULL,
		0x68D1F7D8EE9CA61BULL,
		0x79241495381556BEULL,
		0x3CB0084D29DB7FF6ULL,
		0x6FB30BC05E7B69A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C4F0587331378FCULL,
		0xDC64B77FF739D144ULL,
		0x9B893937360AE54CULL,
		0x4ED3CFB649CBB339ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x866695C998E6039FULL,
		0xACFEB96EF59C2695ULL,
		0x33464DC77A240E77ULL,
		0xEE5C2ED2055932A1ULL,
		0x74B2F4275D707D2BULL,
		0xC273955D265DF08BULL,
		0x34033CBF503E4DCDULL,
		0x3B4BE37D5BCACBF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F6D3A17798996AULL,
		0x8A26E542A78DDB48ULL,
		0xEBC1522D63639B02ULL,
		0x3B9FF36DA5737906ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x37BBFA61C5B37FFDULL,
		0x2A5A4C74B6CA7A75ULL,
		0x430349C0EAC269F1ULL,
		0x9B01D68430ECCB6AULL,
		0xC586B906F1D641D5ULL,
		0xE90589EFF6A9C5B1ULL,
		0xB4F7256DFB3BBED6ULL,
		0x425D61AC1EBB643AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BB7169AB814717ULL,
		0xC12CC61353FDD2D8ULL,
		0x1FB2D81435A0BDD7ULL,
		0x74DE5610C0BDAC21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC19D905EAF4505BCULL,
		0x419F79318812EE32ULL,
		0x30F02095486596CDULL,
		0x3E6C437726D978D4ULL,
		0x6EC60563018355F2ULL,
		0xA35643703D4DED20ULL,
		0xEE0D4D1D711DD190ULL,
		0x7567BD473D1964DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33025D10E8C3CA41ULL,
		0x806D7BDAA1A42103ULL,
		0x86E992F412D2B245ULL,
		0x2BD25C0A389E7211ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xD2A00FA7417A8F99ULL,
		0x00982572EBF1DAF7ULL,
		0xCAC2A03293D8924EULL,
		0x676EBCE70ACE484EULL,
		0x43CA4985558247B7ULL,
		0x3840923A52590E08ULL,
		0x7CBE752D949F6BF6ULL,
		0xFD82C5AE0EBB40B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2A6F971F2D13A67ULL,
		0x5A2DDA1B2529F031ULL,
		0x4F0804F6A38298DAULL,
		0x08D814BD3A99E2CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA7BE790559663A3AULL,
		0x12C4813BB97F5268ULL,
		0x95588669BE26EA56ULL,
		0x24331D8D27D8949CULL,
		0x9B7DE6207E6EB91CULL,
		0x468A105847B42EA4ULL,
		0x808AEE03E52AD58CULL,
		0x67AE3911E1349C53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC6EA1D81DD5B6AFULL,
		0x8B42EE565E3E3ED7ULL,
		0xA9F7DAFDC2829D28ULL,
		0x080F963495A7C901ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x58CADD2204EA4569ULL,
		0xF5E99D062529BDBFULL,
		0x69CA6F3B33819486ULL,
		0xA883DF9B3841E4EEULL,
		0x614547E5054B866FULL,
		0xFC3C3D8EF200A23AULL,
		0xDFD337336A47000DULL,
		0xAE1BE9CB80160B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9138920CE203DD2ULL,
		0x66DAC03E1141D269ULL,
		0xA324A0DCFA0B969AULL,
		0x00A893D03B878BCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC0A6F35168A701ECULL,
		0x16D413889C449DEDULL,
		0xA7210CB69E279BEBULL,
		0xF26CB7F8661E8485ULL,
		0x5DB93067140B1325ULL,
		0xF69EA9E6DC88F537ULL,
		0xFD317951A8C34CD1ULL,
		0x605979985541AABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA24229E624BDBA4ULL,
		0xB2614BCD58990425ULL,
		0x3C790ED5AB250315ULL,
		0x3FB4C4950DDDDD05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x68C782AAC57E204FULL,
		0xD1496A7B4BB7E523ULL,
		0x2E8927F30A7F311EULL,
		0x781F7A38CB6380D2ULL,
		0x27F5C33ECB8E192AULL,
		0x0C15D57EFE34F210ULL,
		0xBD08AF163E868846ULL,
		0x99B86DFC34E6D15DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57427DFCFC95DFF5ULL,
		0x9C871B550793D389ULL,
		0x3DD3254052776B84ULL,
		0x497FCDA8A5A694BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xCF9996D84F4FF12AULL,
		0x5CD2E2E014FDBC95ULL,
		0x5DEC2481DB0A1EB8ULL,
		0x14F03A3ECFE50BE6ULL,
		0x5DBB4FD5FD5BC373ULL,
		0x441E966955D0FDB0ULL,
		0x26D01BB63FB80CFDULL,
		0x6F6D0F51A65CD596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB967709BEAEEF6AFULL,
		0x795D3682D20364C3ULL,
		0x20D0418F505C0C50ULL,
		0x1F20805D81ACC030ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x8230BE05E4EAABAAULL,
		0x3663DAEF09087E93ULL,
		0x5A0AFFFF67EFF1EFULL,
		0x6769D424A678CD42ULL,
		0x23FFA0608BFC7F49ULL,
		0x29A5562ACC17B1ACULL,
		0x9F6D3E1BA639B889ULL,
		0x298C6341F7B37445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA228C5AAC659177ULL,
		0x64EEA549548CDE20ULL,
		0x0442381A1481564BULL,
		0x12408FEF6B1C0F98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x8C1C5717ACC91296ULL,
		0xF50C9CB140B73E56ULL,
		0x7EC061011F834F76ULL,
		0xB623CD5036F584A9ULL,
		0x6DFE11EC205F4E9DULL,
		0x9CB832BFADE7CDE3ULL,
		0x911C67AB033FB0DCULL,
		0xCF7235ED2E4061E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFD300247AEEC291ULL,
		0x38642525111FCE18ULL,
		0x08F7C4639AF79036ULL,
		0x0117CE8514840CBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x15E37815C7C6D5E2ULL,
		0x62FD5F587CAD696EULL,
		0x269460B071B855B4ULL,
		0xF6A811F49BD984CBULL,
		0xF63F8FB475228593ULL,
		0xDE3FEFF08C40A9D7ULL,
		0x4905454D692EA31DULL,
		0xE3EDEDA8C7599F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA352CCDF2AE6AED3ULL,
		0x607AFD0D4E469F7CULL,
		0xFD5CAA2E0EA48C23ULL,
		0x4BF9590233272641ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAC943D5D05B6AB4AULL,
		0xAB5A2FF6643AE962ULL,
		0x5D7AA9F6E27A6536ULL,
		0x8B965F88558FD8DFULL,
		0xF4E14921F9860A57ULL,
		0x63970D885B0ACA8EULL,
		0x0C6F3CDB86050111ULL,
		0x6A086797B12381E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060518680F9C3694ULL,
		0x73C63233E7D4FA9BULL,
		0x35FDB28CC7388DCBULL,
		0x48D5C00CA0D520B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xBED5C4E3DC925F3EULL,
		0x720C6949E9AC99AFULL,
		0x9F1920E10CFF5CD7ULL,
		0xE06CB18912478D20ULL,
		0x45C799CDDA219A1FULL,
		0x2754D9D3EDB2A9AFULL,
		0x7C80944433B56A94ULL,
		0xB39CCCE4DF9A3ACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A7699723D8F43EDULL,
		0x48A4BEBF3231C9B4ULL,
		0x1A2F2300B9ED2ED5ULL,
		0x09B31B82432C4755ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xE7295DCE0FB4BCC2ULL,
		0x9F1AB6B7A2F8A3A8ULL,
		0xEBAB2200C1353208ULL,
		0xFB36A37A9150CEECULL,
		0x78D94FD6C66B3738ULL,
		0x1712323EB9028C06ULL,
		0x58DBCD2E9DEA843EULL,
		0x59FDFBCD7A348948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD76B37AF839EF126ULL,
		0x0BCE2C0719596C9EULL,
		0x1C4B96EC3204D340ULL,
		0x56EA03FAB51D2FAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x685DFD9BAE62006EULL,
		0x48D5E3A07F413140ULL,
		0x1A024372B7345DAAULL,
		0xEA1037F354FA42AEULL,
		0x700D77BA70A41E77ULL,
		0x386730855D39FD2FULL,
		0xB482E7797CCA58F8ULL,
		0x69492FF56055CC1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A5DC34866BE888BULL,
		0xA827176C55DCC64BULL,
		0xE5709F7B3D3D9282ULL,
		0x0AED565FA1B68ECAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2A8488DE5A393C8BULL,
		0xBF208B1CCFD4A3B1ULL,
		0x1EB9045575997F79ULL,
		0x5B55489B0F2CB0BCULL,
		0xCABFD9643FF62C18ULL,
		0x29FB55831C826705ULL,
		0x0B57395D62DA7A39ULL,
		0xE6950EBF540229BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42FECDBFD8C3CD3AULL,
		0xFA6F3C930B2FEE8DULL,
		0xCDAB88322207A3F5ULL,
		0x15757901877EE2F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x920F2D33ACC98FD1ULL,
		0xFC89EF5D4B0DA4CFULL,
		0x34762D5C645C08B2ULL,
		0xBD5BF1D3FBCED25AULL,
		0x0B948EBC8D03DEA7ULL,
		0xD5C72EDD52411AE6ULL,
		0x6A13C5A28CF18EBEULL,
		0xF5AE7828B88D9BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A1C5D309B5CA219ULL,
		0xB81AE43780B7A2F5ULL,
		0xF365837D50373906ULL,
		0x3541C7DF60D3F0E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6AA6F12E61D1C4D7ULL,
		0x1633A01EC7D0EAF5ULL,
		0x16AC0231AD752A67ULL,
		0x6C3D2A883C318272ULL,
		0x1BAF4099EA39DFEEULL,
		0x9E72ACD4BB088083ULL,
		0x8ADB7B15C95DAD15ULL,
		0xF9DB70AD0E292946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86AA8807266907BCULL,
		0x9B3947B28B13FE6BULL,
		0xB340476D915CDB9CULL,
		0x02CFE438564DA2EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDD26824E717355DBULL,
		0x0597393C4F7E579BULL,
		0x0A3E3CD478E09951ULL,
		0xB8169900DC359B9FULL,
		0x22503B26C4265EB8ULL,
		0x3FA4FFFE14C14EB0ULL,
		0x1E84763CED38E0FBULL,
		0x4C75C48AC502CBE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF50F4A0F8F2566F3ULL,
		0x781538F3643005C0ULL,
		0x91E7C9DFAF51FE9CULL,
		0x1191C59A1A9FDFC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x9348DD53D280728AULL,
		0x007DA5BB496FAD09ULL,
		0xBE2E881F57F57268ULL,
		0x80BAF9884D01F803ULL,
		0xEFF3ABAAD5E9B475ULL,
		0x9F5B7FC6ABD0A8D7ULL,
		0xD6F0F9ED33336F6FULL,
		0x1F06EC4B9D80672EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x317458AF93313CA6ULL,
		0xA8129D38CA68BD17ULL,
		0xA5F3A154F197FCF9ULL,
		0x1BC20CC1AE1148F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x35398ED4C46ADBC7ULL,
		0x2123C25E93FA2819ULL,
		0xCBB7353A31DCE30DULL,
		0x21B243EC92FF9BD8ULL,
		0x4E5D8DBE3C022F99ULL,
		0x39A9F9FBA3AC0041ULL,
		0x51A8B428E55F0CC4ULL,
		0x96BD58A1DAE46EB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71C9911ACBDEFD4ULL,
		0xB05EDDB8DF8231CAULL,
		0xEAC1F34C3DF8C82DULL,
		0x01CD6BF310E80AC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x71695F735E39699EULL,
		0xE39589F33ADB00ECULL,
		0x1F49E6B6CCF31D6BULL,
		0x4F748B4377F27176ULL,
		0x763CC709E35292B5ULL,
		0x394AC33C7544BAAFULL,
		0x125CD298216F539AULL,
		0x8A0F9C81E5E48509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE6EEAEB1C7B3387ULL,
		0x64AE84ECA30EB6F7ULL,
		0xD911294BC3798650ULL,
		0x4DC5C68B97DE30CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5F79C8BB3CBA1694ULL,
		0x4D460BE36F075103ULL,
		0xD71FBF4EBD7824E0ULL,
		0xDB06B39A49B61EDEULL,
		0x4807017DB892FE70ULL,
		0x98EE59E572D88564ULL,
		0x422676B6107BC4A4ULL,
		0x04C257934D308557ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10840164A28BDB6DULL,
		0x00A763F27B2B1DE6ULL,
		0xA8D55E552FD7554FULL,
		0x0FDFB377BEE9E9D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC7DF59CBB97C0F33ULL,
		0xE049910A139C61DFULL,
		0xC6E5136590483436ULL,
		0x574ABAB3CADA7D88ULL,
		0x1D0C705EFB5E250DULL,
		0xFF4181D4BB4E89DBULL,
		0x92D229F5FB5B6B33ULL,
		0xF047C83D75686275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17B807E509759479ULL,
		0xC402D69DE144D866ULL,
		0x92174DE8DFDA1DEEULL,
		0x01F273D338591AFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAB3C820D33D0B21DULL,
		0xA7A75E2479AE2EB1ULL,
		0xADFE94DC9457EC1FULL,
		0x088C650DAEF53F96ULL,
		0xBB63BACE4C88C631ULL,
		0x95AEC30E70AE8784ULL,
		0xBFC755741D7B9C89ULL,
		0xBF8939E5A2ECC5F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0A3CAC901E218BULL,
		0xDF98524933964C65ULL,
		0x25954418F4B1288BULL,
		0x76EAFD23DE1AA19FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3C6EB8632EC09A74ULL,
		0xDC4D951D4B2500BDULL,
		0x5C2A4380946292AEULL,
		0x7D9FAE99DDED7241ULL,
		0xA6BC9F528AEF539DULL,
		0xA487980F5A051259ULL,
		0x8CB66094A685D2B8ULL,
		0x24720BD370895433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6E5EA3CE470493ULL,
		0x486E2764A7E5BA0BULL,
		0x3F3C99914C3FDA17ULL,
		0x668D6FFC924FF1E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x77A442C29B0DC61FULL,
		0x8E7066A7A6C92D09ULL,
		0xCFF8BB245F6C9B0AULL,
		0xE1AFF63BA6C5BB07ULL,
		0x8495C62E034C9403ULL,
		0x9EEBC25AA2C41F02ULL,
		0xF2D60495663527C2ULL,
		0x4B558375E37E0785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25DFAD97186BC059ULL,
		0x256F401BCFE5C769ULL,
		0xDBBD69518B5081EEULL,
		0x106179BB6B7AD8E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xADA0D22C7EFA7EF4ULL,
		0xBAE64B24CAFF58F5ULL,
		0xC312BAAC998ADA0BULL,
		0xE69E771009AC56B1ULL,
		0x0FC9903428A94647ULL,
		0x09C551039BDAAAEAULL,
		0x36621E472ED35DA9ULL,
		0x0818CF88CD64AF67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058C39EA881AEDCAULL,
		0x2E3051ADED74B7B4ULL,
		0xD5A3393D8CEAC123ULL,
		0x1A4D455E869E6003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1CC4FEF2823B2DA9ULL,
		0x7D602E9EE20D68B5ULL,
		0xCE1B3A39DBD12420ULL,
		0xE1BB919849942B85ULL,
		0xDDABCC141427C1D8ULL,
		0xB723E40B7CA0875FULL,
		0x01BBB9457523F326ULL,
		0x97C275FC724AEADEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044549ED8021F723ULL,
		0xACB4085361E180F0ULL,
		0x0FF8BA893F273BDFULL,
		0x6899151140B3087AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6F62D3E9494446FCULL,
		0x43DA25C1376C7C3FULL,
		0xA4EB9525B9A0B1FEULL,
		0x65979981A1BA157DULL,
		0x19A932E7AB846F42ULL,
		0xB8D3337A64C18F92ULL,
		0x52E0F33F0CD96F7CULL,
		0x6096FF32FC14552FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E80624CBEECCCEFULL,
		0xB333C9EC2C27CBEFULL,
		0xF24FB081A1E73E81ULL,
		0x3C017B130CBEBA83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3893E0D01C94C485ULL,
		0x07FF081C05FB1FF1ULL,
		0x46BA927150BB0B01ULL,
		0xF374BA3B66120307ULL,
		0x5178A8B9CE573550ULL,
		0x19129BC63CA5A96CULL,
		0x7173B437B9111532ULL,
		0x5C25138461D53546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x507CEC64BD86B08CULL,
		0xC0C2278906924605ULL,
		0x1DE752B6C9443070ULL,
		0x20F59FE1EBB7EB7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x837E1F9297E9F85BULL,
		0xC6F130AA69D4D845ULL,
		0x34EF697A6B6AB6DAULL,
		0xC9EDC07C2E754A10ULL,
		0x9660CF86151C9495ULL,
		0xCDDD46A67A9F51ABULL,
		0x14300AAAE4416EEEULL,
		0x24A0A57A68CD3081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5DCED79BA28075DULL,
		0x55C9AD609D7AF7BDULL,
		0x3410FED84D212E4DULL,
		0x39C650A7BCEA7D39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAA4168D1AC69C6FDULL,
		0x2DE21DD3F5E94E6DULL,
		0x1BCE3F57AE93D004ULL,
		0x65740793363D4EBFULL,
		0xB5593AD126B2AE6DULL,
		0x0A63767E748B8929ULL,
		0x80CD9F513266341CULL,
		0x4E71D339DBF90DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x958023DD6AEFACF3ULL,
		0xB8A5B499429FAA9EULL,
		0x3A53E56529BF8C2DULL,
		0x0A596229DD35560EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2B631A14A83E13B2ULL,
		0x3DA6AD6AE122D269ULL,
		0x68DE5EB5487B03AFULL,
		0x03D84703AB51D36AULL,
		0x88E9DD366437524DULL,
		0x66B5899267167808ULL,
		0xE1F6948D4CE1FF0AULL,
		0xA7AB4ECC76DEF28FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E19F02788744EC3ULL,
		0x7C9919262E78A3ADULL,
		0xF3786BAEB206DF3AULL,
		0x6745F95D5069D4C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA5AECFE75A1A3E08ULL,
		0xC91EBCC55808B1F2ULL,
		0x2F07487CC96AF886ULL,
		0xA3934D780F88EA08ULL,
		0x4F94826FAEA11EC4ULL,
		0x4FAF908D3C5D993EULL,
		0xC51F3D11D8B9A005ULL,
		0x75008207B00C355BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75BA2C7B4604D1CCULL,
		0x9D2E31BC4DED7132ULL,
		0x71AA5922F4F8B950ULL,
		0x01A69A9C3158D5A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x26497079A392464DULL,
		0x3A69BB0B0B7BCF48ULL,
		0x76E91C45D215DF4DULL,
		0x6A450C0B61296860ULL,
		0x8064D772EAB4BDAFULL,
		0xFA9BE3E8609CF726ULL,
		0x93FA94BB3B324FD5ULL,
		0x3D7C084A31C4E26BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35416B887A666FB0ULL,
		0x6D8D8F8962C87EFFULL,
		0x6E1B30109B8DB910ULL,
		0x0AAE470EC4630458ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7B73DAD4621AF0B7ULL,
		0x2B9221B2FF2B5B1BULL,
		0xDD54811910B4511AULL,
		0xC14AF6A2E333727AULL,
		0x986BF1C9C30C8533ULL,
		0x0F13A9AA4F7A6EC5ULL,
		0x5B6AB434D08DFBA8ULL,
		0x3287069293D5EB10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B79BEC755F6B779ULL,
		0x687D50FACB57CC70ULL,
		0x6F2B40F005C7AC0CULL,
		0x4155F064D4F456E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x755A3285B7658622ULL,
		0xD533551CADAD04CCULL,
		0x50941ED77ABADF9FULL,
		0x1211377E69C815FFULL,
		0x6B3920247A1166E7ULL,
		0xD71BF4DCB0EFB334ULL,
		0x6223F81613D3DD50ULL,
		0x5CD939800D193C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FD4F7EFD5FACE6DULL,
		0xC359ADDEF1419E94ULL,
		0xE1EAF21E6C2DB99FULL,
		0x5A4FC0805B870A85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x77D813A0BAD2B894ULL,
		0xAE2075D73D8C8627ULL,
		0x25F028D4AFDD3377ULL,
		0xC53F25F729980649ULL,
		0x92EC891E6F4DB035ULL,
		0x8C75AA6F33A23C2FULL,
		0xC23F712A9E8F66AAULL,
		0x868BCC34B0D87544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46F46E25405AE37DULL,
		0x8797C258E7A17537ULL,
		0xFB5AF528392670C8ULL,
		0x3DFF75C969B96E7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3BE74CDA8DC3E3F2ULL,
		0x3529C56E36440067ULL,
		0xBA772B01D0EABA8BULL,
		0x6ABC2E80C7FC7AD3ULL,
		0x3CD792C23412247DULL,
		0xB2DE999D4FDBC716ULL,
		0x076A048162493E47ULL,
		0xD8ABB60C6DED7E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E715AE48755353ULL,
		0xC23492C810E38DB4ULL,
		0xD433D63667C9F92FULL,
		0x14393459193D3004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5FE0E13B5CD37D98ULL,
		0xF42A2ABCCEFD0512ULL,
		0xA9621B9BE1F67942ULL,
		0x81DEB7A6B2F2A3B8ULL,
		0xFB07618ECAF254C6ULL,
		0xED02C9F20EBFB16DULL,
		0x2EE918CCC3619C55ULL,
		0xEF4B1BBE442AF42CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F95C6D7CCC1854ULL,
		0x229424AAFF715B65ULL,
		0x9FFBCA00E273AE04ULL,
		0x0704D5E4D152E247ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x5FEEF864F5D57912ULL,
		0x3A0A18942B14DCCFULL,
		0x102F567FCA11A201ULL,
		0xFFB6FF2F096BAD10ULL,
		0xDC601E44B5AF2331ULL,
		0x94C70F3D2AD40297ULL,
		0x6D1273D655DB6678ULL,
		0xAE25862C31C713E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16337697EDD4B647ULL,
		0x4F965BA8868D3F5AULL,
		0x40EC885088A2D7E7ULL,
		0x5948E9BE6CF8A0F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA383F24CD1C2E213ULL,
		0xB3F516F56522F683ULL,
		0xCB8B74E1ED1DFEDBULL,
		0x15B0907279D1A5B2ULL,
		0x49544451276F2892ULL,
		0xE171BB6E07950127ULL,
		0x0657CE6DCC44873FULL,
		0x7B9AE66128973A52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86061658AC42EA6BULL,
		0x2AD6E94A85412258ULL,
		0xBC94192E3F4A1257ULL,
		0x6EAEC2DE80444DDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x30DB3D40C860AABBULL,
		0xE7786D89C084785AULL,
		0x059C6D353E078D54ULL,
		0x0CB0326478479D3BULL,
		0x8EEC7D7558F1BDB0ULL,
		0xA18710C548A993CEULL,
		0x0E59E9E6043E7168ULL,
		0xF8B65B8C8EE03BD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67F5DCABFC42D846ULL,
		0xE184EAD289B06903ULL,
		0x26F52559DF4C62DCULL,
		0x77C1C941AD907F73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xCBBEEDF2CA0FE8B8ULL,
		0x2DF2DB24B9E1EF31ULL,
		0x6C89DEE58A46035AULL,
		0x62F8700B3824EFD2ULL,
		0x66E4923979E1BB2AULL,
		0x7219643AFB14170AULL,
		0x36462DE3C67ADE7EULL,
		0xD2B5961AD2577850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11ACA27AE191B5A1ULL,
		0x1DB7BBE5FEDD5ABDULL,
		0x7AF4AEB500830A1FULL,
		0x29ECB8067120CBBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xDC58450BC0DE50D1ULL,
		0x01E1D110081C5497ULL,
		0xA91AE4BA9524B86CULL,
		0xC7980D0B9AA46D29ULL,
		0x08E7B573FB4FAF33ULL,
		0x31968784EF14CB76ULL,
		0xA857122B40C1AF04ULL,
		0x2FE56472E46F0D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBD34430EB25380ULL,
		0x5E39EECB8532881DULL,
		0xA607972631E4B30BULL,
		0x63A4F61983206EB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF7767673DC91A79DULL,
		0x7DBD2F7CFE4C9C2BULL,
		0x75D302E5E4C31E0CULL,
		0xE102C1FB98D86F9CULL,
		0x3741DECB4F725FACULL,
		0x23A51F28EF923F1DULL,
		0xD1182B44CEEEF8F4ULL,
		0x868F746E39ADD048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3D88A1A78BDE30ULL,
		0xC83FCF908E01FA82ULL,
		0x7F696F1C9C3C1249ULL,
		0x5A4E0A5828A55A6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xA6DCED8229482F7DULL,
		0x5376DC6A7FAD4935ULL,
		0x6313B58BB0C93500ULL,
		0x4775967E0ACAEE87ULL,
		0x5BDA265CF4E6A834ULL,
		0xEDC50C3BCD48EA46ULL,
		0x80E27828D1FAE2DBULL,
		0x0B29CE63B4B6144AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x493E9F4E8385276EULL,
		0x9EB6AD4AF8800FA7ULL,
		0x84B18B9ADC06E1A5ULL,
		0x6FAA394ADDD1F196ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x535B50133CE49DC1ULL,
		0x963C8CCA10EE9A2DULL,
		0x755D3B2D81F8F5EAULL,
		0xCBA57BF06B1C8560ULL,
		0x03B73ECAD91E7473ULL,
		0x5A550A795FEB3CEEULL,
		0xD0E57F2351A4085CULL,
		0x74BEDDCDFC82931EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08EA22F7769E97FULL,
		0xFEDC1ACE4DD9A581ULL,
		0x776E1A6BA052339FULL,
		0x1FFA6883E67E5BF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x25CC4F0091FA3A97ULL,
		0xF328020E0798B1DBULL,
		0x19AA37A24F0C3BE2ULL,
		0x8ED545993BED6D8CULL,
		0xEA421E19FF9D1E8CULL,
		0x06535AF4DCB5F048ULL,
		0x7CB4CB1792FF3952ULL,
		0x731A210CE0097B25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB9CC6DC834CC5F8ULL,
		0xE3878266CA9A5CADULL,
		0x9C805D2220EEBE0FULL,
		0x24B62D827D55B51CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x14608A340BB4A594ULL,
		0x5F1A6C6A66CE817FULL,
		0x7663F297A1CB4E67ULL,
		0xA3BA6A421BD26A54ULL,
		0x2C9AEBFF2E28238AULL,
		0xE5A5ED98268FE9ECULL,
		0xE970F8910479EC64ULL,
		0xDE851DEEC118C1E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB35F9214E5A9F109ULL,
		0x75BBB100202B3A8DULL,
		0x1D28D81E4BE46561ULL,
		0x2B7CDBB2C57F3203ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xEA8D00ED267F0B5AULL,
		0x3427A44FD57EA040ULL,
		0x8400863F201018CDULL,
		0x3272CB6F3FCC9AA3ULL,
		0xC5D167588D7F15BAULL,
		0xCD581100FC5DB027ULL,
		0xBBB1DE3540C5E320ULL,
		0xBD7AC0ADAB2A6E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47A25812275C491EULL,
		0xAF3A2A754B66C628ULL,
		0x60678226BD6FCFABULL,
		0x52AB6536A818FBCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x290A355BCFA66075ULL,
		0xEDCEC878C177FF5AULL,
		0xD3B531BC58F7AC9EULL,
		0x4818A1571FE38FF5ULL,
		0x75F051F063B4E9B5ULL,
		0xED86456CC7DD977BULL,
		0xF1B116091C370324ULL,
		0xD2D6C88EA052EE76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB65F0A9C811600ULL,
		0x2FBD169E6C5C7BADULL,
		0xB3FE77168922241AULL,
		0x13FA6682EC32F59DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x7AD121C78810F167ULL,
		0x798F0A5BE163BD0DULL,
		0x6A95589B2495C036ULL,
		0x62FD82A1AD769802ULL,
		0xB842A84C13D82DBFULL,
		0x3197767905AF5A43ULL,
		0x871FCBE9B838E295ULL,
		0x444E8384128CB7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4B61D127A27BD50ULL,
		0xD60AA052B96B231AULL,
		0x794D9D4C7D07625BULL,
		0x06A5083C6E59E168ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xABB9C3F6A4C285DDULL,
		0x05CD2A59EBB108E9ULL,
		0x1689C23DAFD80008ULL,
		0xA733F50856DBBCA7ULL,
		0x5CAD5434117045F3ULL,
		0xDEF1B4086D9C7E08ULL,
		0xBA41AF8D2F897C20ULL,
		0xABD29981B20C013CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D7443B13B6CEBCBULL,
		0x1DADE39A30EBBE27ULL,
		0xBC49D132BE406CE9ULL,
		0x2876BE48C4A3EBAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xED8D04435550EEFAULL,
		0xDE4DE72FF6F51D67ULL,
		0xCB699AC4944DEAECULL,
		0xD3D4D60AB13CD45BULL,
		0xBD0C1AB25ED337ACULL,
		0xA41A44540A79F3C3ULL,
		0xC1DABA65620D4285ULL,
		0xF469A8856F4FB6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD58FABD68AB3800ULL,
		0x3A340BA9850F4C75ULL,
		0x91E145D12245CAC3ULL,
		0x1B83D9D93711FD22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x0F9AC4FA0A058B59ULL,
		0x49A3DD5FE57FF7FAULL,
		0xADC28ACD26366125ULL,
		0xAC3944227C82FC2BULL,
		0x6367C47F1988FFD8ULL,
		0xBFAB9182622B9830ULL,
		0x12BAA00A3FC3BDE5ULL,
		0xC106616CC56A01C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD101EFD7D45B89B7ULL,
		0xBD1B76BA77F88F28ULL,
		0x75764C529D44913FULL,
		0x532BBA47CA3F3F6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xFE26E9957DAA3E98ULL,
		0x0B20A19FF8CF6ED8ULL,
		0x34C0B782F212261FULL,
		0xCA351E89AE5D904BULL,
		0xB99ABDC5FAC827B9ULL,
		0x35ED5324F49884ECULL,
		0x27E3DCCFAD9B0826ULL,
		0x7E26447B487F51F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1F14F8B76026F3ULL,
		0x0C5AF91C477329FCULL,
		0x20937E56B7155BCBULL,
		0x03E348D67143BB47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xD8B9A566BEE7F949ULL,
		0xE45FC0EF9591FB17ULL,
		0xEA037EA813A33876ULL,
		0x17CB857E4A6CC790ULL,
		0xFBBCB6E5790AD367ULL,
		0x0E805FE36ACBDA0FULL,
		0x2C851349BC2523A8ULL,
		0xB0D8A3F8145068EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36BCCB76B6835E6FULL,
		0x0B6DFCB16FD45977ULL,
		0x85C45B9A01268369ULL,
		0x57F3DC514E5C5AC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x924177E6A71179B2ULL,
		0x3B46450A6B4C8DA6ULL,
		0x8D0706EB826684AFULL,
		0x50899D0BF09AA88EULL,
		0x160872D76399E407ULL,
		0x18939C8435588E33ULL,
		0x857DFCEA2653FE7FULL,
		0x8E5CF2E2390CAFECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD78283DF6FE955DAULL,
		0xE12F80AA5671A93BULL,
		0x5DBA91AD32DE4B8CULL,
		0x7255AAA0687CC5AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x61C4BF44F1EBCD90ULL,
		0xD3A8D3F1334AFE52ULL,
		0xE7C059C4227C3FCAULL,
		0x3C479014A5C7A5E4ULL,
		0x822F475E4E8E40F1ULL,
		0xE37F890F1154C2D9ULL,
		0x4B4E5412BE0EB65FULL,
		0x604DB30110DF193EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C957449B09737DULL,
		0x98972C2DC5DFEA9BULL,
		0x1560D48C58AB5206ULL,
		0x07D0223D26E56524ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x46CC5A71AB18767FULL,
		0x6F1483FCD84D964EULL,
		0xF50FB44D244EDD6BULL,
		0xF43559152E9E2034ULL,
		0x6667188C6D9D6296ULL,
		0x2B1F5317067A191BULL,
		0xD03B579E9C9BDC1AULL,
		0x83D26AAE05C3C0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A19FF49F0751BCEULL,
		0xD5BAD967CE6D505FULL,
		0xDDDEB5D86371894DULL,
		0x05712EEA09ACC1DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC36477222C92EA2AULL,
		0x5C5651B6072B5DEFULL,
		0x1354F0DC3214EC2EULL,
		0x2D3E72FFF2BC6F53ULL,
		0x768C44C9BB49832FULL,
		0x24956DEA2B269DD2ULL,
		0xB18B846809D39FFAULL,
		0x4C46481014503FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C36AD13F97C64C6ULL,
		0xCA84A2786EE6CB2DULL,
		0x6E0A984DA77EAB4FULL,
		0x7FAD2562F6A5E237ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xAC3E7E9557213A33ULL,
		0x7E2BA56605D42B31ULL,
		0x44B203C459F1471EULL,
		0x25BBFA4FCB37761EULL,
		0x8AEE9092AE610092ULL,
		0xDAE78FF9AF3CD2D8ULL,
		0x147611D56B12824FULL,
		0xEF8E1FEC67513D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA7F45B39875524ULL,
		0xFC8B047608DB7756ULL,
		0x4E38A9723EB09EF8ULL,
		0x34D4B76721468D55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x8A9EF5BAECB03DE3ULL,
		0xAF58BAF479C22674ULL,
		0x10FBA7A6C10A60E2ULL,
		0xB5F26F33AF97207FULL,
		0xD2733B19F538947FULL,
		0xC04C81DF9918F5FDULL,
		0x0FCD63F4CE75BED8ULL,
		0xF36DC18640EA0125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B9BB9553164E28ULL,
		0x3AB402253376AA21ULL,
		0x69787DFD6684B50FULL,
		0x583D292152534BFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x6B8FB093E7E0BC60ULL,
		0x41CF409EF8F15A2EULL,
		0x81495196FFB8A004ULL,
		0x6AA27409A6D9A691ULL,
		0xBB5D39D7C0B5D11EULL,
		0x3D3E974DCD877E62ULL,
		0x7E2CDB96A4386B32ULL,
		0xA6FF6FC20DE281FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B66469A82DDCA8AULL,
		0x5919B62B7B0E1CD6ULL,
		0x3BF1E9F360188979ULL,
		0x348D0AD7B678F258ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x8987C356A0CD2001ULL,
		0x95C9309A602B553EULL,
		0xB55A29F5BCBE984BULL,
		0x10A021FD62E91463ULL,
		0x02A9CBA9BC009232ULL,
		0x71506342D931A56DULL,
		0xB608C8913DBBCA84ULL,
		0x3CF1E4468BC95BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEBBFE8888E2D4C3ULL,
		0x67B7EC869D89E36CULL,
		0xBAA7EF84E69EA7F4ULL,
		0x1C88047622CCB1CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xC00953FBCD893526ULL,
		0xE9C555780A1797DDULL,
		0xF59BDCC311A4274CULL,
		0x211A377D7E8DA2E0ULL,
		0x1859C4B2CE2804C2ULL,
		0x052D13FCAA21D1FEULL,
		0x83A4C4AE16653790ULL,
		0x763C274B0378868DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D5C86866779EC8BULL,
		0xAE764CF94B1CC395ULL,
		0x80110E9A64AA66ADULL,
		0x2E080CA002719BE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x3E13FD064B9F65D8ULL,
		0xCD4DB5F55D76F291ULL,
		0xD4BA7D629DA4E0F7ULL,
		0x9D6A66B5D2083393ULL,
		0xE4E373F8477C4D46ULL,
		0xD14ED35941991385ULL,
		0xB25BA125771BB993ULL,
		0xB854854EAFC86B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D733E0E812E251ULL,
		0xDF0115351A2FD871ULL,
		0x4E5468F24BC26CE8ULL,
		0x79F63063E9C81FC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x741ABE3E278F4284ULL,
		0xDFD62A0C84CF4E77ULL,
		0x6C81E332731D37C8ULL,
		0x0058888268A6B066ULL,
		0x14C8CA0DA096C788ULL,
		0x5F8B2288A887E69FULL,
		0x7C52C159EDD8373BULL,
		0x1AE3FA2EDA29D8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E8BC43FDF0E139ULL,
		0x0E7D4A5588FB8A14ULL,
		0xE0CA968BC1356A99ULL,
		0x7E2FAB76CADCE16CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xE40E2C764F692266ULL,
		0xE012E7DC5FCB922FULL,
		0x7CE3E552566550E5ULL,
		0xA97BABD6A0343FF9ULL,
		0x88C1F2F4EC8DEA11ULL,
		0x10C52BF483747410ULL,
		0xE6A4D5835E0CA576ULL,
		0x58A40B0FD0021D88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D83CD16C79E2EDULL,
		0x5D576E27E314CCA4ULL,
		0xB95B96D24C45E06CULL,
		0x51D5502F8084A24BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x55D3F9A08F9A1622ULL,
		0x4361A4FA6C809CD1ULL,
		0x50CDA940A7E55F7EULL,
		0x15CB1C49C8767AE4ULL,
		0x6F779F8DB49288DCULL,
		0x2D580F5F9FE5880EULL,
		0xEA6B4BFA4B9E0675ULL,
		0x7EB4B83AFE5B5D92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE195A8A95D5A6989ULL,
		0xFE73ED2C2892CEF5ULL,
		0x1CBAF067E15A54E2ULL,
		0x649E750B8A065EB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xE7442767BDEB432BULL,
		0xC4E1F6191392FB9EULL,
		0x44E98B5FFB3EAF46ULL,
		0x67BD0598A1197A4DULL,
		0xDD5683F8C244CA3FULL,
		0x960C123FD87B8604ULL,
		0xBA12D5A5714E2B68ULL,
		0x0BD33B92618CBE33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC21BBE54942148D1ULL,
		0x0AACAB9335E8E057ULL,
		0xE3B541EECCD920CDULL,
		0x2917DD531BFDB5FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x30DF9B7F4E448CF6ULL,
		0x61BCCD3EC28DD8ACULL,
		0x88C2B9302177B7B5ULL,
		0x303F6B8FFFB576B1ULL,
		0x7C8C68DFA60AF124ULL,
		0x3622C7F59EB736B7ULL,
		0xB8CF20B342D72102ULL,
		0x03BF1D594960B69BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADB72CB1F3E45861ULL,
		0x6AE67BB451BFF7E8ULL,
		0xF78193CC0D669E09ULL,
		0x3E9DC6D0E41091CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xF7E9CA57642B208AULL,
		0x79EB6A7403FB9A4AULL,
		0x5C8655348F4A8C91ULL,
		0x364639C5A6FE6169ULL,
		0x2BAB91BF439A73A7ULL,
		0x9E04E556C366C5B2ULL,
		0x82C895B31B6B086DULL,
		0xD0ADF5AFC8DCE52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73616CBB6D184FEEULL,
		0xEEA57555053CF2BDULL,
		0xC64C8DCAA12DCCD6ULL,
		0x3018B1DD77C8662AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xABFE91DE09D073F8ULL,
		0x6E98D50D28DC3447ULL,
		0x2C33238AC0D0E499ULL,
		0xCE4314595135D30CULL,
		0x5D7AB3C97D79FC30ULL,
		0x181E0DBACFC84E14ULL,
		0xF58B9B558A034B62ULL,
		0x266F7B9A368AFDABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3541C6A9EBE40FULL,
		0x030EDEC80097CB4DULL,
		0x9EEC323D3D4E1529ULL,
		0x02CF6D3D69D77A92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0xD1E9FEB2CF701365ULL,
		0xDDF40FE23FDFE185ULL,
		0x51EC0ED8B75853D4ULL,
		0xDE5E53CD18BD70B8ULL,
		0xA5AF0199B0B27DD0ULL,
		0xB9B4D30B334FD16EULL,
		0x7873874776CF445FULL,
		0x3E8D0474FB113599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E43B8309EEC1C1ULL,
		0x6ECB638BDDB8F7F2ULL,
		0x331223745A1C7A0AULL,
		0x274CFD2A5D4B6580ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x1A2AFCD25320AE69ULL,
		0x3E6A5968C7197028ULL,
		0x514311C3D1FE1931ULL,
		0xF49B157EF697F45CULL,
		0x44075C71E1CF3509ULL,
		0x293934C91BEF6DE3ULL,
		0x9E0EAEAD0A485929ULL,
		0xBD337706F4651712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3342B5B9D7E2920DULL,
		0x5CE82F42ECA3BFE4ULL,
		0xC770FF7358BB554DULL,
		0x0A3EC0873D99611FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x2A9B807E4E458E88ULL,
		0x83436D079EBE3BFBULL,
		0x7F2F4B59B1181C95ULL,
		0x3F9D37BBEEC04C0CULL,
		0x16FADC54A05718B6ULL,
		0xFEAEC5F9A8EAAF29ULL,
		0x48A20FEA2C1A72EEULL,
		0x4020D452A8F85261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D8350E1B333AF5ULL,
		0x5134D016B1943C14ULL,
		0x473DA81C3D052C0FULL,
		0x447CBC01039C867DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x572A438ACCF2EDD3ULL,
		0xF3DEF430831A6E89ULL,
		0x9423479827493ECAULL,
		0xA5824C7E9433BF00ULL,
		0x0AC1B13F83018F63ULL,
		0x290E3C766870F42DULL,
		0x176373C82AF31CCEULL,
		0x959BFCA9258DCD1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFEA92F83F2E39DCULL,
		0x0BFBEDC403DEAD38ULL,
		0x0CE6774E875F8565ULL,
		0x5AA9CD9A27403178ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x0A18EB856804EC13ULL,
		0x97C4E4C1BD3767BBULL,
		0x1674CF8C980D730EULL,
		0x5138E5CE594D8613ULL,
		0xE1C138386D6D5E56ULL,
		0x41A380144740A003ULL,
		0x257D50F4FBC6E53BULL,
		0x5DB2817726DE3C7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC743E5A640EEEBULL,
		0x5609E7C450CF284EULL,
		0xA70ED3E9F79379DAULL,
		0x39B81D7E1E4A8034ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
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
		0x631D93E1634A3997ULL,
		0x65954DA6BA0958FCULL,
		0x6F3BF7BCCD930615ULL,
		0x7483DEE1C2785098ULL,
		0x1EA8DF416CB705C3ULL,
		0x0AF4B32B9B5141BFULL,
		0x47209A0C1C6B8B0BULL,
		0x77176B5D0FACB996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF02EB79786751735ULL,
		0x05E7E61FC8191B5AULL,
		0xFE12D5890589A9B9ULL,
		0x21FDCEB2161BDCE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E7C81315193E051ULL,
		0xCB1191D18FC506DEULL,
		0x2922B3D8561C10E5ULL,
		0xA3588EC7AC15E507ULL,
		0xB0D2479EF438BEECULL,
		0xE835B22ED51AC1FBULL,
		0x2164EA8324F1AAC4ULL,
		0x07FA647686A5BC33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB322C992003792ULL,
		0x430A04C531BDD23AULL,
		0x1E1D834FD1FB6A20ULL,
		0x5283785FA8AFD49EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A18F6D4A02BAF77ULL,
		0xFCD3E13F9D86255FULL,
		0xBA8165C9280F1A18ULL,
		0x071E79A8F59D1984ULL,
		0xDAD00C95057E09C4ULL,
		0xCCBE063B31731596ULL,
		0x9D175CD9A4B03FE3ULL,
		0xDC5632AB2B9CE316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14FAD4F370E12762ULL,
		0x6108CE08F49B59C4ULL,
		0x0BF92E179A3895E9ULL,
		0x3BE9FF116EE6CEE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3940CB09973E45FULL,
		0x65C00F1ECDBCAA04ULL,
		0xB6B3EDB13E04408AULL,
		0x405AE59AAF6A267DULL,
		0x5CEA7457F0E7983FULL,
		0xF3C27F58F5AD741AULL,
		0xFFF7D57C872D6090ULL,
		0x63486E3B3E4DD753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE6151BE5BD47FE0ULL,
		0x949EF653457BE5EEULL,
		0xB57D9E2D4EC0960EULL,
		0x7D1B4265EEF81CF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x053015189063512CULL,
		0xBAE910A9D3B1404AULL,
		0xAE1135694A9435F9ULL,
		0x49C25ECF63A9499CULL,
		0x221B5E43AE011BBEULL,
		0x829944703F39CD55ULL,
		0x15516D721C261911ULL,
		0x6263775D02A6FF06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15401324648D7187ULL,
		0x1DA939533645BAEDULL,
		0xD8277459783BEE93ULL,
		0x6486169DC8732483ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF57F14FD7E2021B2ULL,
		0x94C18978C7D0FFF8ULL,
		0xE7CF489AB636945CULL,
		0x33FCB6B07A8487D8ULL,
		0x208273A122F4A20DULL,
		0x86B76C5819880479ULL,
		0xE2F3EDD518B99A8BULL,
		0x65205B0F6D1517A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8DC3EE8AE7031DAULL,
		0x93FB9E8C9201A9F3ULL,
		0x9804963C61C38512ULL,
		0x36CA3AFAABA60A52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF14D31E739181AEULL,
		0x78B58E8066FE053BULL,
		0xFFD704A062AAD516ULL,
		0x5A6D8569F7682847ULL,
		0x69CF83A585C20CA3ULL,
		0x88CFD9CF6AB91F11ULL,
		0x928EBB6F33A09A19ULL,
		0x008026A33F2A480FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E25DB04E5F61E0ULL,
		0xC78FE34A3E78A1D1ULL,
		0xC106D7220C81B4E0ULL,
		0x6D7341A557AEDA97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9062A95256D1822ULL,
		0xCBBF373FAB101910ULL,
		0x7940489FF01B7606ULL,
		0xAE43B9EF4E0F08D2ULL,
		0x091205295A9093FCULL,
		0x614EACA45CF5D6D9ULL,
		0xF9B4D61C8385DD29ULL,
		0xC41AC5041773A96EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B2EEB896E313EBULL,
		0x3D6CD7A5778DFD48ULL,
		0x8A1810DB75FA4A2BULL,
		0x4A3CF88AC93A2F4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CBF5C1ABEDB9421ULL,
		0xD1B8D3A8518B8130ULL,
		0x4408E46B06B3F983ULL,
		0xE6512C70007B13AAULL,
		0x2E0CD86CBFEA6350ULL,
		0xD93B7F1D7385CD10ULL,
		0xBBD297894A4C136BULL,
		0xAC0A078B320FA3D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A77C3F3BA655DDULL,
		0x108DB2077767F197ULL,
		0x254B62CC0DFEDB86ULL,
		0x6FCE4B196ECD65FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEC0F4F67F11E01DULL,
		0x80501889A6080BE9ULL,
		0xA58A0CF1040B20DCULL,
		0x88D90B4FC286E24EULL,
		0x90B5D922CC8A5EDEULL,
		0xF9FCF24BD2208130ULL,
		0x18A908177D63DB86ULL,
		0x0B26C2A2D4DFE368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BF3020DB9BF55DULL,
		0x9BDC0FCAD6DB391FULL,
		0x4EA1406DA0DDB6E5ULL,
		0x3099EF7B5BC2A3C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81D678220668E30DULL,
		0xB79942D6A0823AB2ULL,
		0xA2C45950E673E065ULL,
		0x101805E4C2C59EE2ULL,
		0x1B683D65C107E7DDULL,
		0x13DB769119D3306AULL,
		0xBBA1EB08BFCCCEF1ULL,
		0xCCB7ACAE3523B45BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934F953CAD95524FULL,
		0xAA2CDC6075DB6A72ULL,
		0x7CCD3C9D5EDA982EULL,
		0x735BA7C0A6126480ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A69937B2AAFB5B5ULL,
		0x6E6906CA8570FF0AULL,
		0xF8F80E050B8424A6ULL,
		0xB479AC60A15AAD0EULL,
		0xE5127E254234C778ULL,
		0x828AA7C58456740EULL,
		0x008880897211ECB0ULL,
		0xF8F008E261DB7BE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B284D02FE855716ULL,
		0xCEFDEE1C2A463940ULL,
		0x0D3B226BFA2D46D9ULL,
		0x281AFDFB27EF1133ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69AE0F3F1BD77EF2ULL,
		0x47FE72267F8C06ACULL,
		0x6B56311BB933DE03ULL,
		0x221F83C1AFCC3C56ULL,
		0x2C2B0F38B0AF5FBDULL,
		0x0E32B207EEEFF27FULL,
		0x74867D4624D41F74ULL,
		0x0287D7CD8E52315BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF81251A955DFB513ULL,
		0x6384DF53F72A058CULL,
		0xB74CC98530B0893DULL,
		0x02498C44CFFF8FE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC8B57B275306985ULL,
		0x597D5A72EAB0263DULL,
		0xC509D5F777C3257CULL,
		0x127F10D710EC7CFDULL,
		0x3F5C1279BDDEA3DEULL,
		0xF6A7016E8C7C65FFULL,
		0x0C4C2D52EA458E59ULL,
		0x45D27A52E24DF2A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x443615C4A43CBDF5ULL,
		0xF64790DBC5274A21ULL,
		0x985890463E1646D6ULL,
		0x6FBD3924A87E8215ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0F2EBE3570D6AE6ULL,
		0x3FFB32EF888C3E63ULL,
		0xC33782BFE2EE7B4AULL,
		0xE9111F68F105435DULL,
		0x5A2E4F19B0D4D2DDULL,
		0xEBEBD85E5763C464ULL,
		0x4C9EBC8AB1F35A8CULL,
		0x6AD52F94E0611D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D2A9B396A4BA27ULL,
		0x44FD50F0815B6549ULL,
		0x22C77F564D0DEC35ULL,
		0x44B62F823F6F93EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17A4DA686886FFEBULL,
		0xC6EB194BEE6DBC21ULL,
		0x416B48D2D5D50F4BULL,
		0x65BDA501DC9FD679ULL,
		0xA20BCAE5C7278948ULL,
		0x0475435F4876FBAAULL,
		0x8CC40FFF81CECC82ULL,
		0xE4064D81F9C0E72AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2564F883F86565A7ULL,
		0x70531970B0171775ULL,
		0x2685A8C01A876A98ULL,
		0x3EAD264CEF4226CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17034BA36010637AULL,
		0xB50D11F13AC43E8CULL,
		0xDCD83F4D7C816566ULL,
		0xA521368134A73264ULL,
		0xEDF227C8BEA2F50DULL,
		0x33D95F345F14714BULL,
		0xCB6D41AD7B0F659FULL,
		0xAD65882D041ED73DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F5336FAC40C744ULL,
		0x675133B757CD0FD1ULL,
		0x0F0FFF0DC0CA7B08ULL,
		0x62336D2FD13B2591ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA707F6CA04F55BD3ULL,
		0x3B3A461FBA035A13ULL,
		0x1CF6294B21701315ULL,
		0xF24D40E12DBEB1D5ULL,
		0x0DFF362AF12D67F5ULL,
		0xA881F85AD98126BCULL,
		0x5562453E6E4BDB65ULL,
		0x4810D32AD9C96020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAEA0129D1B2CBE6ULL,
		0x3E85239C032F19FDULL,
		0xC98C708F80B2A42CULL,
		0x24CC993D81A2F6A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F609E58F620E9D3ULL,
		0x7648064CCD6787B4ULL,
		0x43D5A759C052CC13ULL,
		0x56074FF4ECE67EA1ULL,
		0x3B021DF0CAB3CAEBULL,
		0x0E990A765FE9F7ADULL,
		0xFC5BC600229BB80AULL,
		0xF30BD58FCAD1C76BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41B110170CD10E0DULL,
		0xA0FF93DF0A224B6BULL,
		0xB9750B5EE3701D91ULL,
		0x69C9034D080A18A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEBD356E76CAF5BCULL,
		0xDE24AAC692DF2B2EULL,
		0x52EE5EF7128C7D4FULL,
		0x1A518AB474C70775ULL,
		0xBC12BB7F23619C7BULL,
		0xEE91F4C348DD7090ULL,
		0xEDA5BD3B5AAC6DABULL,
		0x3709A060C9804E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9850A4DB748312EULL,
		0x47CEFFC363BDE0AAULL,
		0x998875C68824C4D5ULL,
		0x45BF59125DD2A3E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D0B94F105AA7E77ULL,
		0xE4C3DCEFA26C9404ULL,
		0xCD12AE77F89E88B8ULL,
		0x99016042868CE1D6ULL,
		0xB890C1BD8554BB7CULL,
		0x9D6F70864C562340ULL,
		0x6BF70EDB45778947ULL,
		0x96C1AD35B6F14EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2885712D03E5636ULL,
		0x434E90DEF735CF9FULL,
		0xD3BEE304485CE95AULL,
		0x79C1163BAE5E93BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9C369971CEA03F2ULL,
		0x9B5212D5AD06E9B4ULL,
		0x457F9422F878DEF7ULL,
		0x1B6999DFD95D771EULL,
		0x23FE0AE5228F2F38ULL,
		0xC7442D45B19A32B9ULL,
		0x6C2D701A0D913E6DULL,
		0xA8B4C542A2C77AC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0179079A3E2B09F8ULL,
		0x2F70CB2E09EA7130ULL,
		0x543E3800FC082343ULL,
		0x263EE1C402F9B0DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3411BCB474C12EC6ULL,
		0xE2615616DF491688ULL,
		0x75B669722D5EC1AEULL,
		0x5719D5318280D781ULL,
		0x69A32CC1089A31CDULL,
		0x9A7C089E2266349BULL,
		0x242DB5B522A34A84ULL,
		0x5AA8319EFD3528B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE24A615BBBA49535ULL,
		0xD0CA9D8FFA74E599ULL,
		0xD47F6255519BD15DULL,
		0x4C1132CB1864E2FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ABCC235362CA887ULL,
		0x7A97D6092CCB43C4ULL,
		0xBE8076D11A451035ULL,
		0xA7AA4124C42CE3CFULL,
		0x9487318F37B336B6ULL,
		0x4D8B5280E8338ABDULL,
		0x9008F17981114F4CULL,
		0x7F4B5395A00E7A49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46CE1D777AC6CA70ULL,
		0xFD46152BA471DBE8ULL,
		0x1FD44EDA42D6D588ULL,
		0x0CD8A95A86530ABBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADCAC3FE9B1860E9ULL,
		0xFB96DEC0AEF21923ULL,
		0x99D0A6CA65049ECEULL,
		0xE98A24CBCDE41BE3ULL,
		0x74FAC7F414FAF19EULL,
		0x0C8D9B8305E77A90ULL,
		0xBC6DF5208697D91AULL,
		0xD70146E02DD5D02FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B047239B8584330ULL,
		0xD89BF4338F4E4A95ULL,
		0x9223099E5F8ED8ACULL,
		0x53BAAA129BA102F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C84009EBC99077AULL,
		0x77FB0F7BEFC8A6FCULL,
		0x9A4C56A42C3D2F7CULL,
		0x49907F87123A6A83ULL,
		0x79AAEE4024DDF15EULL,
		0x931E4A76638A1D07ULL,
		0xD99614978F36F206ULL,
		0xD18CC741A9AF816EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABE35E24358AE008ULL,
		0x4E7A1D0EB648F618ULL,
		0xE69365236E651C76ULL,
		0x647613464247A0F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFE94F8CEBDEB6D4ULL,
		0x8DDF8876DB07EACCULL,
		0xCC0398CEA3FFDDC4ULL,
		0x8DB3F92F8A2DED2CULL,
		0xF768F34E3A1A6561ULL,
		0x35084CF79ADF4BBDULL,
		0xAF6EEFC4D6C8BB99ULL,
		0xCFD8F9C49BF96351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x797D6D298BC9C7D4ULL,
		0x6D1AF537D82D28FFULL,
		0xD67B300685CBB682ULL,
		0x67E90C5EB132AB4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AA6EEC4A52F54B0ULL,
		0x63ED9875C2CAB562ULL,
		0x9F185FB0492A5F1AULL,
		0x728CCFF066D1E19AULL,
		0xC1688343179D3E44ULL,
		0x2FB6656BDE7AE1E3ULL,
		0xCAC8433135419BD1ULL,
		0xE0CC792558862464ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x202A6ABA268697C1ULL,
		0x7900A678C9083D31ULL,
		0xB8D258FE30E78027ULL,
		0x50E6CB7B8ABB4890ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EB28F712D4987A0ULL,
		0x2AB55F7F5955669FULL,
		0x1934B9BE3E7131F6ULL,
		0xA1DCCF9F8CDEBEE2ULL,
		0xD419A475195E6D47ULL,
		0xCED78967C158D3D8ULL,
		0x83D0858C8C99D168ULL,
		0x3C18C75D196576A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A80F8D2F14DC193ULL,
		0xDEB3C4E60C84D8CEULL,
		0xAA288C9B1D464784ULL,
		0x0D8A677151EE5BBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E2D213A4B6FAB55ULL,
		0x5A929CA4AD92199DULL,
		0x13E8BB7C752BB5FBULL,
		0x409FD1ACC2472D74ULL,
		0x772276AD57EB4E13ULL,
		0xCB8371E1A001B62AULL,
		0x03558C290B39D550ULL,
		0x2022B3D8C46A6553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4ABEF5585D42E5ULL,
		0x901584226DD323EBULL,
		0x929B89941FC15FF9ULL,
		0x05C683D9EA1237C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC680034C786EABDULL,
		0x2D0F78B96056E745ULL,
		0xC1975CD454D37A6CULL,
		0xFE7FC4474E8C9CEAULL,
		0x39E938F3C465BF3DULL,
		0xFAD9934EAC8D977DULL,
		0xAAF60B1B8D512A30ULL,
		0x1EC99FD4C3FBA60FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55067463EEA14E9CULL,
		0x695B5666FD5B63DCULL,
		0x221D02EB4EDFBDB1ULL,
		0x106D7DDC65E7433EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E330C71513D29D4ULL,
		0xCB4B1A8198084ED7ULL,
		0x4451416014CCD7B8ULL,
		0xF5B663F7B21262DCULL,
		0x4629673DBC0292C1ULL,
		0x813C7BA335FB2972ULL,
		0x87E6A6CDE9B57D31ULL,
		0xA5E4154E99A11749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8585F9B399EF643ULL,
		0xFA4574BB9B5075CDULL,
		0x708E03F0C5BD6D11ULL,
		0x15918DA27FFBD7C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3344B8C6B102D7DULL,
		0xBCE8094907A3AE08ULL,
		0xF8684E55B8397E8DULL,
		0x298862CCC679F023ULL,
		0x29BD4D82FDB7302BULL,
		0xC0E142E412502A4AULL,
		0x636C02C8425E3967ULL,
		0xD952DF3E3F51528FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54DCCFE1441589FULL,
		0x5E57F723BF89F50AULL,
		0xBA70B80F923603F4ULL,
		0x6BD5860A2C8C316CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EB9E549298913EDULL,
		0xF92C601A7E824C31ULL,
		0xFDF2764CF5579257ULL,
		0x37DE0965A232A32EULL,
		0x5ADF9EC90E01CB0EULL,
		0x018A58B09F6E362CULL,
		0xB0AFC381F2B58344ULL,
		0x4AA7A0FCF42E6B2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBEB77213DCD39A3ULL,
		0x33B58A5228DE56C6ULL,
		0x38097B96FC490E70ULL,
		0x4CBFEEF1E1168BD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x109193C561C49E0EULL,
		0x575C554B94949108ULL,
		0xE1473A4517978BC7ULL,
		0x35FD3B57F1AF2A50ULL,
		0xEABC59444D332686ULL,
		0xFF07A5574B3FA6B7ULL,
		0x1FC1C74BC6C0B30DULL,
		0x4B720A9F44D94389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE886D3E8D75C5794ULL,
		0x327EE040C0075054ULL,
		0x980ACF8498321FDBULL,
		0x68EACEFC29EF30ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x068B6EE98ACB8AF1ULL,
		0x87DE621815109A38ULL,
		0x454CBE53191956E1ULL,
		0xF3510600DF0656A5ULL,
		0xBD349F88E57D93D3ULL,
		0x97D56373A809FECDULL,
		0x6C65654A378DD7A7ULL,
		0xA11A6ACAB9905B1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5B1D3B9B6F7FE6ULL,
		0x118B2543068C6CC2ULL,
		0x5C59C757582759C2ULL,
		0x5D3CE0186A73DCDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19889A7861F68200ULL,
		0x3A2931D592E238FCULL,
		0x1704724532FDE68FULL,
		0x4E0A9CA3003732E4ULL,
		0xE209E9EAFE9E8A84ULL,
		0xF83D4910802F5C1CULL,
		0x0ECAE31636004548ULL,
		0x98091299211850EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA701535A2D7F14EFULL,
		0x13420A4899E9E545ULL,
		0x4922279137082F64ULL,
		0x5F635F5DE9D335A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA67B288D9320A356ULL,
		0xA41B86CFBD9C7DF0ULL,
		0x9EEE7602409E9CBCULL,
		0x9A187A7A97839A43ULL,
		0xC3AD6C3E2A361EB2ULL,
		0x0691780E842FAAD6ULL,
		0x5E4FAD15ED3545A2ULL,
		0x6C6F0B9A91020DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB23939C7D7293435ULL,
		0x9DB358F75CAFD9D1ULL,
		0x9EC227437686F2C9ULL,
		0x3294336C1DD1A699ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF67AF62F6A66DBA3ULL,
		0x1D805FC06B02AF56ULL,
		0x61EB278C9A415A1DULL,
		0x71B35825019D2DCBULL,
		0xF09FCDDD4EA7D67AULL,
		0xEC4C079FC2F6FB2AULL,
		0xC8B6D72B11363A92ULL,
		0x45AB8837D93F146BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE3385091750B34EULL,
		0x30C981775BABF7B6ULL,
		0x2D0F17F1284E0BECULL,
		0x4929906F40FA35CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE58C4486531F97A6ULL,
		0x025B1B7B2EBBC22FULL,
		0x7E326648867839D1ULL,
		0x839DB263A1228B6DULL,
		0x78DABB4EE5DDE8BCULL,
		0xC1C1FF1861BF48C7ULL,
		0x21636DC36721DD00ULL,
		0x87C5F229DAA6121DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD604123C72102699ULL,
		0xC526F919B1208FCBULL,
		0x72F4B149D57F07EDULL,
		0x2AFFA49A15C93BC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x501444579F6CB6B7ULL,
		0xA998FC7464A68B88ULL,
		0xE7E0D73D12E65C07ULL,
		0x1F2C1EC8C44FED5AULL,
		0x6935A2F4901F07D5ULL,
		0x4D7ED544FFDB0964ULL,
		0xE8DBFD71F596B61CULL,
		0xD3F7D1618D5D3026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE0A74A50407E502ULL,
		0x2A6CA4B25F29F06FULL,
		0x788876278745643BULL,
		0x15F53343C0251321ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1FF7D4F7816A6B3ULL,
		0x8D6B272509CCD2CDULL,
		0x6D6C143A8DEC0AE2ULL,
		0x8E7B6E43B7A9A893ULL,
		0x6E05CA83D1FDAC10ULL,
		0x5EA436ADBF5EA30EULL,
		0x97350E41E2445346ULL,
		0xB9187906E5683883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26DB8CE0A3BE353BULL,
		0x99CB44EF71D906F2ULL,
		0xDF4C320224106754ULL,
		0x081D6549C5220C1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15220378C488BA82ULL,
		0x4309DB7535F28B94ULL,
		0x6B0325196CD183EEULL,
		0x217C30FFB31162D0ULL,
		0x880E672E16C0F2B5ULL,
		0x18136C30EB9594D9ULL,
		0xB8EBC49DF37858ADULL,
		0x94A2F5B552D4581AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47455450252CC4A4ULL,
		0xD5EBEAB82E26A3DEULL,
		0xDE02548B90AEAD9FULL,
		0x31ACA9E9FE9676C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x024336F4894D9801ULL,
		0x8820DD2880AD86F0ULL,
		0xE41BFEC45B916F2AULL,
		0x6D662677AA848B3EULL,
		0x1887FE490E5C0633ULL,
		0xE2E1BD143F299CE3ULL,
		0x321E71F3B6D9FB40ULL,
		0xC0F82174CF019663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA672F5CCAAF687E1ULL,
		0x35A2EE29E0DAD0A5ULL,
		0x54A0E8F17FECBACCULL,
		0x123B1DCE64C0DDF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67B12BA36F8FBE07ULL,
		0x1284021CFA68436EULL,
		0xF222F324E907D59BULL,
		0x7720DE81DF15FD91ULL,
		0xBD8B50AFC0F3F444ULL,
		0x61AD84146F04CEEAULL,
		0xFEBAC889E1389C33ULL,
		0x64645B11AA9742F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A5F25BA13C60259ULL,
		0x92459D25751EFA46ULL,
		0xC1DCB79C576F053BULL,
		0x5E0663213189EE61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EA06F5268B58C6FULL,
		0x46EF27FEF69264D4ULL,
		0xFA06CC930FD03DAAULL,
		0x31CB9CD04F218EE2ULL,
		0x702B9D4DA0FE1469ULL,
		0xFFDED50E7EC1149DULL,
		0x00DF569976FD55EEULL,
		0xC31F83671D1C4F2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB519C8D84E6C9853ULL,
		0x4202C825C73B7432ULL,
		0x1B2DA75AB96AFF24ULL,
		0x28791E1EA1554F1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42839822FE475A86ULL,
		0x7E18587687183E50ULL,
		0x0A3254847E7A9331ULL,
		0xFA5D78B8343CDF83ULL,
		0x17025D8FADE7F489ULL,
		0xDF7FB67D667DE3C3ULL,
		0x2EA80AE445411EC5ULL,
		0xB2F49D46BE1C27DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACDD7B76CEB5AAF1ULL,
		0xAB0D6F13BDC80D45ULL,
		0xF723F266C6252490ULL,
		0x0AACD1386C6AC9E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D70CC2ED9BCFEA6ULL,
		0xF233F0D469582416ULL,
		0x1A0AB1C9610A3918ULL,
		0xC0D744AB223DA52CULL,
		0x74E4222380AD592CULL,
		0x85139536E285EC5AULL,
		0x9D1860D50F1E7F0EULL,
		0x57BCD4E3B7BAB671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x974DDD73F3783D2FULL,
		0xB31C16FA09393983ULL,
		0x6BA911699F911540ULL,
		0x46DEDE7867F4BA09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8ED9CA04CBCC2A6ULL,
		0xE8A38C71C2A09BF3ULL,
		0x7D0EDBD97AB8DF46ULL,
		0x9375E101DBB94BC7ULL,
		0x5934E3E3D276A9CEULL,
		0xEC4FD9364F344EFFULL,
		0xEBB5507AA4F7E088ULL,
		0x233E2BB05EEB0090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16C770718A59F80BULL,
		0xFC7DCA81846455DBULL,
		0x79F8CE0DF7843399ULL,
		0x4EB05D2FF29B614AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EF3A583E97A3647ULL,
		0xC36C2824953F13DDULL,
		0xD89B9FFA1C46DDA3ULL,
		0x278802C2093DEC98ULL,
		0xB4B5078F609FE738ULL,
		0xEB7C751B7C75A53AULL,
		0x1B666A5F347BF262ULL,
		0xB7A2B8EA79D302BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11D2C4CC41368C99ULL,
		0xB7E58A390EB59A94ULL,
		0xE9CF6A1BE6ACD852ULL,
		0x69AF75901E905438ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF65732461A5BEE75ULL,
		0x5BFA7B29E920A26CULL,
		0x057CDEFE78A8B6EDULL,
		0xF8FAE2B461E76F50ULL,
		0x22D87412E59AC05BULL,
		0x99AB66539D294751ULL,
		0x486EBBC4F70DA43EULL,
		0x4BBF12ADC13069BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22786D142F547DBFULL,
		0x2B6BAB933D413878ULL,
		0xC5ECBE3B24AF1838ULL,
		0x3757A87F0F172142ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7385392A95909A6AULL,
		0x62C7838171D5980BULL,
		0xF3CCF9BF88B49210ULL,
		0xC9BBB7F7A160C6FBULL,
		0xA4E0D6308A37FDADULL,
		0xE34C178CA2C16C49ULL,
		0xF6707BAF54B89541ULL,
		0x509D40EC7B63D5C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE5045F19E043F3ULL,
		0x201302619A8BAAF9ULL,
		0x887F55C61C1AB9D8ULL,
		0x41135B11F2328238ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BEBF4370631FA0BULL,
		0x21A3A15DBB45644FULL,
		0x09806F5C9AE31213ULL,
		0x852413D076A00A65ULL,
		0x9A83107C63A99502ULL,
		0x399D21D0E69C2704ULL,
		0x74A63F239E3C245CULL,
		0xC4BBD923A57669C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB6066ADD15E1CB8ULL,
		0xAEF6A65FF6732EFDULL,
		0x5A2DCEA617D077C3ULL,
		0x39064F1B0633BD42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFE4C2B4D018E92FULL,
		0xE34B13421F5FB10BULL,
		0xD1B1D22AC3FB88A2ULL,
		0xF58FB7111DD2C70FULL,
		0x391E28BC75CB2CFFULL,
		0xAF807D536AE1506EULL,
		0xEC9F994B5D8979C5ULL,
		0xCD3D20AB8DBB1ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A5ECEAE4C419BA3ULL,
		0xF05DADA3FCD1A168ULL,
		0xF162935AA6639BFAULL,
		0x6CA2908827995AF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FCCA81AB23CB3DDULL,
		0x2AC90B41A31E7327ULL,
		0x7E1C28091E940EFAULL,
		0xD16065AF26B2CD40ULL,
		0x98A3C37AD893C55BULL,
		0x826E6971AAD1575FULL,
		0xEB4D346CD4B37F3BULL,
		0x8D561D5A8A422B82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381BAC56D82C0290ULL,
		0x872CB220FE316B58ULL,
		0x6B91F030B138F1CFULL,
		0x4C28C11FAC8542AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A2A04A53C985790ULL,
		0x2B9ACBBA550F4206ULL,
		0xB40C135B5F52B350ULL,
		0xE9B9A2AC9B4E2841ULL,
		0xEAD5784222B5F1DFULL,
		0xA1728DD42FF79F41ULL,
		0xEDADD02F9079C46EULL,
		0x83CA0A9B47A4691EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D9DE76639A41A2ULL,
		0x229BD93973D0E5CFULL,
		0xFBD8FA6AD165DBBCULL,
		0x79B735B93DB5C2D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7095A3753754A91CULL,
		0x10B5272017ACB7CAULL,
		0xFEF3C8898B9E2E6CULL,
		0xB52875CF7A797790ULL,
		0xB873082FDA69E6A9ULL,
		0x41A7CF9E6E40D68DULL,
		0xB7BAE93210F9A5E9ULL,
		0x6F9BF4318F6260FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A8DA8FA30CE8B8ULL,
		0xCF9DF8A4754C90D3ULL,
		0x44B265F810ACCF0BULL,
		0x464EB52AC313DCEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E79594E674BD3B5ULL,
		0xD81006DC3F6E7260ULL,
		0x847AC1098BB8A65CULL,
		0xAD239F657DA47033ULL,
		0x851D4533DB16B49FULL,
		0x7E1F3E3CD31CF901ULL,
		0x1183ED2F095D4334ULL,
		0x434FB3A269CF1A39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D19F00ECAAA4DEULL,
		0x90B343E395BB6899ULL,
		0x1E0FF604EF90A027ULL,
		0x2AF84981326254ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63C07EDF0FFD36E2ULL,
		0x45EAF16844993F0BULL,
		0xDE80D6768555273CULL,
		0x0668F9984C86DB8CULL,
		0xDC9D90A91D486B4AULL,
		0xAF204779FB0363FAULL,
		0x254D231D0435A969ULL,
		0x5962E8EB077323F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2323F7F968BD25CCULL,
		0x44B58D83871A1648ULL,
		0x67F40CC5254C4CECULL,
		0x4B178C7B679E317EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30EE3FE6C96E992CULL,
		0xCE37FB405B4F26BDULL,
		0x506EC5580BD74C56ULL,
		0xE2D7B6F69A3FB34BULL,
		0x7897AE65F6CF2964ULL,
		0x57ABE1313B5EB592ULL,
		0x01B4C7BAAA8EFD3EULL,
		0x333876FBB1B50396ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x177223096C2EBF34ULL,
		0xD1BB688F2B5E1A7BULL,
		0x91446B0D5D10E397ULL,
		0x7D396052FB1E3B8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x020234D7D0504FC0ULL,
		0x69F4C217142E8CEBULL,
		0xC5BEFE1DDA8101DCULL,
		0x93D97F543800327BULL,
		0x08811F4AB59EABABULL,
		0x053D207BE75F81FBULL,
		0x399A6146591A9FC1ULL,
		0xD95CDDB9F846B1C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x452CD9EEC5DDCFF5ULL,
		0x3107947B6C5BD82EULL,
		0x52A96E8F1474B883ULL,
		0x57A268EF127E959CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE632EA1F42B5DD5ULL,
		0x548DA4D6E130CA39ULL,
		0xEEAFC37221F10188ULL,
		0x96A745C693E2151BULL,
		0xADCC985173733883ULL,
		0x466DC08A6D6C8DCCULL,
		0x59B5E1253BADC22EULL,
		0xBA2941C54242FA78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC1CAB91745C56FULL,
		0xC8D839631F4DD69BULL,
		0x3FAF2EF8FDBBD466ULL,
		0x38C7090E69D342F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A7D604C508341CULL,
		0xC4AF42F0ED743707ULL,
		0xD72013B838ABF449ULL,
		0xFF38E2423D95BCDBULL,
		0x3524A4785D2BA54EULL,
		0x907B9B80E7C7F115ULL,
		0x87E3456F16CB3328ULL,
		0xC2AD268022B6A822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8183FE29982C211ULL,
		0x370858135522002CULL,
		0x02DC62359AD58C4FULL,
		0x64EC994764B2B1FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EE8D156194CECCBULL,
		0xEFB135F27FCBB096ULL,
		0x022CD39DF74EFA33ULL,
		0x0CBB8BCC1F9CCD45ULL,
		0xFE7434FEC0BB115EULL,
		0x1694DE6C73D4F385ULL,
		0x43E913F0157A3B68ULL,
		0x10A7AF3278ECA06FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0428AF26B511811EULL,
		0x49CA3A0BB167D67AULL,
		0x16C5C9412773CBA7ULL,
		0x059F8D4A12BC9DC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE543C5C694928CBULL,
		0x758E8E30F269F4D3ULL,
		0xFEBEB1CDB2343685ULL,
		0x937B9D2466DFCF18ULL,
		0x688B36B9E25997A2ULL,
		0xCCD9F22EC554038EULL,
		0xE345EC0821708C48ULL,
		0xE88718448A1D53AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42FE5BF40295B009ULL,
		0xDDE881223CE27BF7ULL,
		0xBB1FBB02A8E90953ULL,
		0x17893750E73A3B34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB18B870AB58FBFBULL,
		0x2C8B2271097D6294ULL,
		0x2A0FF5A7215789F9ULL,
		0x8ED52AF2BBF4682CULL,
		0x43DD0851E3E06AB7ULL,
		0x4BB677513102E443ULL,
		0xA4DB5391B3B2942BULL,
		0x994E914847DE5731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE7F4987EA8D68FULL,
		0x69A0D87E4FEB4490ULL,
		0xA29E5D47CDD98866ULL,
		0x507EBBAD66F5598AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF292C150291DDA4BULL,
		0xA1AD740D2732BCC0ULL,
		0x805E9F1EEBA738D6ULL,
		0xD1D00087591E7752ULL,
		0x103045BF52084472ULL,
		0x419683C49A1402DFULL,
		0x77D1FE7CB908B5D6ULL,
		0xB959023512319B79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59BD1BB65658075FULL,
		0x5E05033C062B29DDULL,
		0x498A65A262F236A4ULL,
		0x550654680C7B8B5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBB4FE971FEFA196ULL,
		0xDF626D44421AF3ABULL,
		0xB7BF8099EBA705D4ULL,
		0x27CAC02607AD218FULL,
		0x8637F1B12D568C23ULL,
		0xA2FEF1956CADADF9ULL,
		0xB436E224F34DC1DDULL,
		0x6F721D75EDE23D26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC802DEE3DAC8713BULL,
		0x113A497263E2C6B5ULL,
		0x77E512160931CCBBULL,
		0x32BB1FA75742354EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CDE3BB3F930D871ULL,
		0xADB8B96D1F41847DULL,
		0xAA96A6F791F4449EULL,
		0x4BD3EE1FE8569BE3ULL,
		0x084FD423F20647FDULL,
		0x84D5894C3AB64BD3ULL,
		0xC56C56D4AE81E0C5ULL,
		0xB4588AE623E168FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48B7B909E61F8C01ULL,
		0x656B1ABDD650C5D0ULL,
		0xF8AB8A89793BA1F0ULL,
		0x10F88C493BCC311CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEDF150D893272E4ULL,
		0x7067A70381AA0E51ULL,
		0x5D7377FD5CC05E4EULL,
		0x2B436046DDB4AA94ULL,
		0x70F00C489B4F56C6ULL,
		0xDB1E12070854E562ULL,
		0x7C1989CB545F2EB3ULL,
		0xBD1EC073B57D5D64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA280E7D496F95870ULL,
		0xF6DE540EBE441AEEULL,
		0xC93DEC2BE2E14D00ULL,
		0x3DD3F173CE50877EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x340881960F11343EULL,
		0xD7FD2DFA09265D80ULL,
		0x6EAC4FEF2637D6AEULL,
		0x5882C1426F803320ULL,
		0x01922F25159244CAULL,
		0x90AE02B61A950AD6ULL,
		0xB01FC48330B2F1CCULL,
		0x5E55E1DEF39D0582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FBB811742C76C4EULL,
		0x51D19501FB45F944ULL,
		0x93637B6860C7BB0CULL,
		0x5942485A98CF0486ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F21E31BEDB76B18ULL,
		0x3B276C2FE7B3F9C2ULL,
		0x91D8211AB3047FF6ULL,
		0xA337AF1504B72C22ULL,
		0x08649AE5FC952584ULL,
		0x2618366D5C7E2F5CULL,
		0x5A65D47B9C62BFECULL,
		0x536D4DF6F044319FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E10E13F6BDAFE9EULL,
		0xE2BF806BA26F016BULL,
		0xFCF5AB73E9ACFD03ULL,
		0x057141BCAED689C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3232614EB08627DDULL,
		0x0DBCA173E1D7806CULL,
		0x22520BE8B8AF209CULL,
		0xC216F32B9BF9E025ULL,
		0x544B5DCD28003269ULL,
		0xAB8714048D4BC3B9ULL,
		0xA842A0B0ED080399ULL,
		0x2CAADDB1B55978C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5624DC2A08DA47DULL,
		0x83C99A20DB168DEEULL,
		0x1C35E62BE7DFA96BULL,
		0x6373DB8C8741CD56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF97BBD4950D9CBDULL,
		0xFAD08F1B62E9E347ULL,
		0xDDD3758EAD5F49C9ULL,
		0xE0214987B456A385ULL,
		0x7F044C3985409926ULL,
		0x2A35870D498B74EAULL,
		0x36D8C72518BC8FBBULL,
		0x068EE796D35F29A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3B0C5E5CA4589AULL,
		0x3EC29B144D9D3E16ULL,
		0x02010510595C9F92ULL,
		0x5957A9EB1476D1E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B8DE2EFB03B2CBCULL,
		0x5AADCCEC32B1DBE7ULL,
		0x8C34C35FDE861476ULL,
		0x9DB3311FEBFC9FB6ULL,
		0x2555CE89082D845BULL,
		0x4CF4BC9A0952DB35ULL,
		0x4C8BCDB2006A43D0ULL,
		0xCCC91F82EC8ECF18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB64A8B46E6FCD6D8ULL,
		0xC701CBC994FE65CAULL,
		0xE8F54BCBEE4C2561ULL,
		0x038DDE8F092F5D51ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAB4BA5A4DA7E38DULL,
		0x6763801F66171804ULL,
		0x75836E218457B7A7ULL,
		0x4FD1FD189232BAA9ULL,
		0x493AB866209B404BULL,
		0xE051082F2E6360F1ULL,
		0xFBC3AD313620E7F8ULL,
		0x7FFF203C91056BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x896C198324B37181ULL,
		0xB36AB72048D77BD5ULL,
		0xD48F236F8D3A2698ULL,
		0x4FB0C6161900BD9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BF1E09F3E541C94ULL,
		0x0E1E911D243934ACULL,
		0xE1E0767A85FB4786ULL,
		0xD5F23D89018C60C6ULL,
		0xBC9AD97FC2567886ULL,
		0x905DE5ED501A1DDFULL,
		0xD7FD88DD68479AAAULL,
		0xFD93F0AA997BC489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AEE2996172A061CULL,
		0x7C0EB2570819A3E2ULL,
		0xF182C758009C3CD7ULL,
		0x79E7F6DBC9EB8D3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x917D6ED2CB487FDDULL,
		0x8E57760B894F3028ULL,
		0x423E403D5575FC83ULL,
		0x7FC16E39307F452CULL,
		0xC838D8A724308B2EULL,
		0xA758D740CD3151A1ULL,
		0x56CA62D067DE2197ULL,
		0xAFD2797B5EF6759AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49ED97A22A7D2CA0ULL,
		0x658769A9FEA14E2CULL,
		0x2448EB2CC06EF906ULL,
		0x18FF76894914BA15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6BCE232AD8B9A93ULL,
		0x8CB1F91BFF294067ULL,
		0x36DE286522E65692ULL,
		0x461D66E39BC688A9ULL,
		0x2E37883F4BE8476DULL,
		0x665EB18E19A10026ULL,
		0x4B2DCA03F9593189ULL,
		0xEA787A7573374039ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92FB1B97F20639F3ULL,
		0xBEC05433CD0F4612ULL,
		0x5FAA24FC2623B0F7ULL,
		0x13FF9452B5FA112AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DCE3B4B9613CDF4ULL,
		0x8F53266F6A375761ULL,
		0x98674DFF19F3F6E8ULL,
		0x623BA902C34F75C1ULL,
		0x4AEDEBA3BF0CD5B2ULL,
		0x30956796E88E74A9ULL,
		0x0EB01E579959AC93ULL,
		0xD56EFC471CC8F540ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1F3599F1FB8B20ULL,
		0xC58086D5EF5CA882ULL,
		0xC68BCEFFDD4394C1ULL,
		0x10B51B910923DD43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD77D36C66AB28893ULL,
		0x42CD9033442619EDULL,
		0xA94DF4EA86A176E5ULL,
		0xE2BD1A2E9A2F8943ULL,
		0x8F3710F440240701ULL,
		0x1155348E978B4093ULL,
		0x3B1BAB792291BDD1ULL,
		0xEA568CD1E102D041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A9BB07F00B97FEULL,
		0xD5735D5DC2D1AFD5ULL,
		0x6F6968E5A843A3EDULL,
		0x2B960156009A72F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4758F5577DCCF3E3ULL,
		0x9B4EAD1A45154074ULL,
		0x721A88E8A404FF9EULL,
		0x0EE626467F71A459ULL,
		0x41DF3F44FDA60C80ULL,
		0x12A68D26CCC397B7ULL,
		0x92B4BDE8C3911C4BULL,
		0xE18D0CC4E93A8E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E7C59952472D3DCULL,
		0x6007A0DCAA1DC5A8ULL,
		0x38EEB975AB8F32C3ULL,
		0x09D60B811E22C82BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39F0CF8F1F099F90ULL,
		0xB29B07FC6CC7FF41ULL,
		0x304E9AB1EE8C450FULL,
		0x73EB17CB22C8CDA6ULL,
		0xEA6DEFF0C9F08F53ULL,
		0x7127B1CEDDB26051ULL,
		0x6776C6B2DB485611ULL,
		0x5640A04E237E2DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06426D4D18BEE7D0ULL,
		0x7E7F6CB155424B6AULL,
		0x8BF0193E7B490BA6ULL,
		0x4182E364678399B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x556DE3EA4B7A08FFULL,
		0xDA77E558293FA3A1ULL,
		0x0E8808FA85450D3DULL,
		0xCB9250EF48486DA5ULL,
		0x24C943D719925D2AULL,
		0x1279CEBC16E29CD1ULL,
		0xB55EBFC0CBDBE598ULL,
		0xEF6DDBDE57ABC567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4DF5D81733E293ULL,
		0x988C95438EE2EAACULL,
		0xFA987F98C7E921D0ULL,
		0x55E0F3F04BC7BB09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F35C6077F2783F9ULL,
		0x9CBE1A7ACFF076AAULL,
		0xF04B308750F7E520ULL,
		0xE487EDA90DC0FBA4ULL,
		0x9864374682DF10D9ULL,
		0x1C75039234FBB360ULL,
		0x8918334393148953ULL,
		0x205422BE34264F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE15FA7EEC440500ULL,
		0xD61CA22EAD4D1700ULL,
		0x49E2CC8F26044776ULL,
		0x310515E4CB70B7A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x436643F7C08C3C66ULL,
		0x92413B72B5E25182ULL,
		0x833B7DEFA9A8EDBDULL,
		0x21EE1DFDC248D8A3ULL,
		0x34B6C80C409A08ADULL,
		0xBD12F76FAD5004DDULL,
		0x0E6F0AB63079C5C5ULL,
		0x013139D563B1F673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1687F5C957698614ULL,
		0xA311F6066FC30A58ULL,
		0xA7B714FADBBC4917ULL,
		0x4F3CB3AA8EB36DB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55E217D6963E0F1DULL,
		0x65C756A04A5D6CDFULL,
		0x761CEEC660588BF8ULL,
		0x44BAC2DAB132119FULL,
		0xA0E7185FE16E602AULL,
		0x50A2D72C8673248BULL,
		0x9AC61B1CFEBB1078ULL,
		0xEB462A8EF66022FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x382FB6120CA05A8BULL,
		0x5DF3473C3F74D999ULL,
		0x6F84F514301CFDD4ULL,
		0x31251413437742F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x727F6860C9726971ULL,
		0xFBC64AB2A7D0C54AULL,
		0x353720643F431865ULL,
		0xC205BD3F4D673518ULL,
		0x5F052E0123978C01ULL,
		0xA7A43805DBAF9F36ULL,
		0x2FA97B3EFA3E08B5ULL,
		0xC6084F1327E83D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D443C8C11F1360BULL,
		0xDE269B9143E2675CULL,
		0x485F6BBD6478635CULL,
		0x27417A1739E04E67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78A369DB4FC1F4F5ULL,
		0x9241B0B26A5FED1DULL,
		0x88E7C290775F5435ULL,
		0x1526BCD112FC4621ULL,
		0xB72AA919CC1C6E84ULL,
		0xF6AF1945A8B1BFF4ULL,
		0x45D7A2BACA9237F2ULL,
		0x1C95A85EF1CD99D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F883AF9BFA5D25ULL,
		0x303F710974C26B70ULL,
		0xE6E9EA4A8913A246ULL,
		0x535DBAE8F7811BC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7A24D889D462AE8ULL,
		0x5C2F770590CB6BA9ULL,
		0x3A6CDCCE5A10A1E3ULL,
		0x8A35A5E1B54B2F19ULL,
		0x7B7DC17E015BB10CULL,
		0x988D2AB92E1FBC7EULL,
		0x21DD33E64CC2B837ULL,
		0xAC1C0A398A46820BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC4D063CD0E2768CULL,
		0x0123CE826981666FULL,
		0x414290FDBEF7FA24ULL,
		0x165F2A6C3BC27CC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F1546AFB2697D7EULL,
		0x0EACB0BD783AA055ULL,
		0xEBD378C7F2B91C22ULL,
		0x8AC536901F4F13C5ULL,
		0xB34F270359AA67ECULL,
		0x9FE4C354AB9C9534ULL,
		0x8B148B92C7EEC87BULL,
		0xBE93C65530637747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACD5112F01B4EEC1ULL,
		0xCAA1AF4EF178C627ULL,
		0x90E03091A02ADE7BULL,
		0x54B4A7354E12C864ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6929AD1B3D068D0CULL,
		0xF14E3680C4F54729ULL,
		0x093E4A92133DE095ULL,
		0x5CBB400490E16CAAULL,
		0xAFCCB018E45D1282ULL,
		0x924AF399E3F74666ULL,
		0x33E89ED17AA3E584ULL,
		0xFDF801CADFAE1C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x818BD0CD22D751FCULL,
		0xA86E5F589BA9BA67ULL,
		0xBDC5DDAA4791F243ULL,
		0x0F8B8421C4B99D73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53C498B8DE84906CULL,
		0x1ED97F69495E6459ULL,
		0x382C2D5B8E1D0EB9ULL,
		0xCB356029820FF644ULL,
		0x4B46F92B38B52442ULL,
		0x92C81AFF17A95517ULL,
		0x27CAFD6058D95DB2ULL,
		0x70BEDD90456E9CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x804D95234967F4D1ULL,
		0xE88D8146CC8105CEULL,
		0x204DC9A8BE60F73AULL,
		0x078A4393D07B4340ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08120B00E5C1FC0CULL,
		0xF20EA59CEBE77362ULL,
		0x8878E1CD10269B3FULL,
		0xFCC09E92E3099D0BULL,
		0xE6559AB2A6CAE47DULL,
		0xC29A4A1CA07910AEULL,
		0x9A61281BF82C4D8CULL,
		0x42729B82577A95E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C70185A7DFE829ULL,
		0xD4F5A5DCBDDFED58ULL,
		0x72E4D5F3E6BA1E24ULL,
		0x59C3B3EBDF3BDCD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3551F08DBCE3DD5DULL,
		0x0D82E21D3916F2F7ULL,
		0x37E0F39CF4EAE046ULL,
		0xDF1215F92B4B76B3ULL,
		0xCB417A467BCDA9B8ULL,
		0xB4BB0357DF9427A0ULL,
		0x08B993ADB1456E83ULL,
		0xC3AC12F3FABDF649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x610A17041D6B130EULL,
		0xE14561286914D4D5ULL,
		0x836CDF65453947D2ULL,
		0x6A9CE630637E058AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B7B6AC659E0ED26ULL,
		0x55762A01F08AAFE9ULL,
		0x567AB1A8568C67F8ULL,
		0x095C1011FA764D1FULL,
		0x10E9693832FF2708ULL,
		0xAF0848497E755D10ULL,
		0xEDB2D6BAAD108650ULL,
		0x834005C5BE2BD167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E21091DEBC0BB3BULL,
		0x50B0E4EAB5F6804CULL,
		0x9F06915E070057F2ULL,
		0x04DCEB6C34F7628CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B73D4E5F431E868ULL,
		0xB61E0E452626C40BULL,
		0x5BD444E1372899F2ULL,
		0x8DEB087B932C298EULL,
		0xA50DFB3465DD20EFULL,
		0xA01E4D597600CAACULL,
		0xC90A20939247749DULL,
		0x22A397A5633418B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB871EAD1304CCB3ULL,
		0x7A9D898CAA44D9ABULL,
		0x33551AC8EDC3E958ULL,
		0x32338B084CE7D418ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D29980999DFE3CFULL,
		0x97C084A546D605ABULL,
		0xF6782C2FA6F70F2EULL,
		0x07F71F9D5039BB4AULL,
		0x7D885781E0005456ULL,
		0x23344BF82FAB86B0ULL,
		0x300DD8B4E524F70BULL,
		0x6704339D6116A1FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF669550D9EC6ACDULL,
		0xD183CB7C5A4C03DDULL,
		0x18865709AA73BAD5ULL,
		0x5296C8F9B995C706ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x165A81E531130734ULL,
		0xAC3E18AEFF72FFB6ULL,
		0x01E12B85CAEAFF11ULL,
		0xDEE28C478BB03D11ULL,
		0x5E4316EF0FA8C75FULL,
		0xF10522A108863804ULL,
		0x63D0B8DEB7E30A8CULL,
		0xB4841D141CEE13EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144FE9618420A363ULL,
		0x73013C96435F505CULL,
		0xD2DC9C95169E8FFDULL,
		0x2A7EDD43D7073273ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86AB5F5E325BE731ULL,
		0x4EC9D94959DC4869ULL,
		0x2FBC55E8A1D89528ULL,
		0xD369542292582B6CULL,
		0x6E4C26B4D5AE6B36ULL,
		0xE143F0918C7DEB03ULL,
		0x7FFC22DCAB764525ULL,
		0x4B917E90DA60378DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F91E35EA3FD2FDULL,
		0xBEDF8EE4348D2AEBULL,
		0x2F2982AA1566D8C7ULL,
		0x0B021DA2FCA06A6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F9B604AAD5717EDULL,
		0x916E227ADE7A8BBDULL,
		0xD9D3DD449FBC1824ULL,
		0x0A3C368E02C213DFULL,
		0x3A56A884A50D1E5AULL,
		0x883C5815C4A86E16ULL,
		0x0B479FFB3E059443ULL,
		0xF17244A5BFFD2A9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x287863FB2D499E8EULL,
		0xCA6335B60F7AE30AULL,
		0x86759C8FD4901A2AULL,
		0x6132672882566709ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B9C1B29D6AB5F98ULL,
		0x06C59F6D2BEDF789ULL,
		0xFDD8B2DE1DE37CBFULL,
		0x197FC9E860516391ULL,
		0x1E9029DE439B0517ULL,
		0xA30E13EA9E70C524ULL,
		0x1635FDD7B89E7525ULL,
		0x5509A77D3A3D69FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5025227DFAE22DDULL,
		0x3ADC9440B0AB3AE5ULL,
		0x49DC60E38568E055ULL,
		0x38EEA67F056F1F6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69AEA06F5049E7F9ULL,
		0x8DEEDF8E8D000A17ULL,
		0xE1D3822F4AC04948ULL,
		0xB586A83B49CE7AA0ULL,
		0x0F286AECB3106455ULL,
		0x1F6648C14FE1428DULL,
		0xC2E0EF4A9F01B75FULL,
		0x0B8D4FF0110A91E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AE7F91E4B8CCE3ULL,
		0x371DAC40686FEB07ULL,
		0xCF370742E5018167ULL,
		0x6C8085DDD1602223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC4C9B984A422DB2ULL,
		0xBDC1FA8477395A95ULL,
		0x4FEA6BBFEE80D538ULL,
		0x941308F9CFDB26CCULL,
		0x6D12C1EBA850BF85ULL,
		0xFD511C4D77F2EB55ULL,
		0x9101632DE854CED1ULL,
		0x3E4FA54211C875D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D156493463E9CD9ULL,
		0x57CC2E0445484944ULL,
		0xD61F24906B178864ULL,
		0x53E590C8739CA433ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2217DDF3129B8CA5ULL,
		0xC453C9265B87D7B6ULL,
		0x846B7D209A3E003EULL,
		0x8C001B6BCF02A0FCULL,
		0xDA2C765C76D12F1DULL,
		0x6927F325792C80FDULL,
		0xD79A98D6FAD181F7ULL,
		0x07591150A9BFF18FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84B16FACB5A88B2CULL,
		0x6041E0B65822FD64ULL,
		0x855E2D09D5574AF8ULL,
		0x2338AD6501807C56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x485372CDD5D29FD9ULL,
		0x3297F77E4A8999A9ULL,
		0x6F60ED4FAA237754ULL,
		0x488A3749E555E076ULL,
		0x9BAF68D425522D90ULL,
		0x0FC600AE89F074C6ULL,
		0xAB7F13B769241066ULL,
		0x61ED0921E52B95F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x645D024B60056560ULL,
		0x89FC1166C43AEF24ULL,
		0xE43DDA89457DE67AULL,
		0x51B99251E9CE2385ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB995C82A39DB31A9ULL,
		0xC0C06523FC79DCADULL,
		0x4F81ECDCD46BE721ULL,
		0x9FCCC1BF0A2CBEF7ULL,
		0x9992CA03ED82FD2EULL,
		0xE868AF72FDB8499FULL,
		0x040A921962F7FC93ULL,
		0xC3F3F06F9C46C701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855FC4BF7B4CCADEULL,
		0x404A7035A5D4CA5EULL,
		0xE9139CA1853B6516ULL,
		0x360272503CAE491DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD358E4ABD789297BULL,
		0x40DC28B39C8D5A14ULL,
		0xFE195B66692894AEULL,
		0x242523C8433D6F65ULL,
		0x868FFB553374FD5FULL,
		0xCEA96297550389D7ULL,
		0x87467CA9000D046AULL,
		0x838A86787EAA4AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB833517AE6C87AULL,
		0xEE00CB2A3B13D012ULL,
		0x128FDC7C6B173C88ULL,
		0x2AB519AB10848DEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5971ADBCBFFA9CA0ULL,
		0x7ED494EF87A733FAULL,
		0x12553FD27BC78E71ULL,
		0x72C05C863953AAABULL,
		0x4E04619B2F0A35D5ULL,
		0x85C6B7A19BBAF3FAULL,
		0xC966B6C1A844B8A1ULL,
		0x7F266F2FAA1CEB2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE182AC5BB7E9D10ULL,
		0x5A53D6ECA5676B21ULL,
		0xF794609175FAF66BULL,
		0x5274DD99799E9376ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B0B78C943AAE223ULL,
		0xBA11528B02DE5AA4ULL,
		0x1670B237753C6A75ULL,
		0x813BCE0B01CF0C1EULL,
		0xFB6AF7A13729CE1CULL,
		0x0B242F8EDDAE3323ULL,
		0x21A0AF170665B9D9ULL,
		0x3ED1E293C24A98FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCEC3AB773DF7BB4ULL,
		0x617061BFEAB9F1FBULL,
		0x144AAFA2685600ADULL,
		0x54636FF9D8E1C18BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E0B00F80BE3D8CEULL,
		0x60695C6CE7AD4144ULL,
		0x8DA619AC840169C6ULL,
		0xE3D7FC94E3867986ULL,
		0x935ED03A6E66EDBAULL,
		0xDAECAB10161ABCFBULL,
		0x91C6415313770F5BULL,
		0xF3BB141C143470CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1DE9A46F2B27E8ULL,
		0xDF8AC0D02FA54E9CULL,
		0x3113CC0167ADB168ULL,
		0x119CF8BFE34F37E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30FE214575F149CCULL,
		0xEDF8A114A858E115ULL,
		0xA8E11CC21F121570ULL,
		0xB6ED2F5CEE9D47ECULL,
		0x39DB9CCE80A28036ULL,
		0x3A7DBF2DB8086319ULL,
		0x876362CB14A4F5D3ULL,
		0x1AFD698272BD3017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79767EC8E10527BULL,
		0x9CA301DDF99796D3ULL,
		0xC1A1C6E72F8E92CBULL,
		0x388AD8B9F6B26B6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2075111834E5E29FULL,
		0x7F51806BCDBADD6CULL,
		0x5958603DE15F21D9ULL,
		0x1F258BD93757C773ULL,
		0x1A4A5F622AD8A1FEULL,
		0xF3E1D987BFE232C7ULL,
		0x676004CD947945E8ULL,
		0xC79D6F031770902FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077F39AA910DF2B4ULL,
		0xB2D7CA92494E66FAULL,
		0xB19916C1EB5F826DULL,
		0x4084064EB20D2E7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4496BEB93BAA48BULL,
		0xEAFD9533C5B9DDB8ULL,
		0x1A127A7E97C53FACULL,
		0x28E2604EF45B955DULL,
		0xC5C4FF324713D92DULL,
		0x6E7B14A6DB58483DULL,
		0x1C494C9A0F87F58EULL,
		0x36BB766DF68E9A73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F874D6220ACE269ULL,
		0x5142A5F854D496E4ULL,
		0x4CF3D95CE5F3B2D1ULL,
		0x48B5F4A18D868273ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98CBE7A775E375E0ULL,
		0xE8A8E14B93E3D5AFULL,
		0xD2D0EEC549457154ULL,
		0xD77A97639E1A3A98ULL,
		0xCDEE38A9CF7350B1ULL,
		0xD1BCBF072140888CULL,
		0xEF0DA631D3A0DE10ULL,
		0x9637D78F1321B1F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A2850DC41017390ULL,
		0x0AAD3C5A83781A96ULL,
		0x4ED79A2AB32667D4ULL,
		0x23C496A0751AA4CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5693E6960CD745EEULL,
		0x87F2C4B25E36D7F0ULL,
		0xE21AFCE6AA3E00C0ULL,
		0xC0999E61219B8F80ULL,
		0x4E6DEDFB0AA61524ULL,
		0x4DEB1F5F2B1D590DULL,
		0x788FCD794F0CABA8ULL,
		0xC5E6F8757504B00FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE539D9A17E6DBAULL,
		0x18D96CD2C4920FE9ULL,
		0xC7737CE8661F7BBCULL,
		0x20E27FD0804DB1CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA24EFA1E8DB87F32ULL,
		0x7323BB0566CF64C3ULL,
		0xC966061EF3C25764ULL,
		0x5AB004C5BFA1EEF0ULL,
		0xAC67EBFC734A0ED4ULL,
		0x9675693C87FA2B26ULL,
		0xEB5B73707C02C05EULL,
		0x39401A7725E9BBACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39BC0197AAB6B3EDULL,
		0xC8915A0195F1CC81ULL,
		0xB8F928D15C2AE56EULL,
		0x5A33F2756053CA9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E32A9F0823608B8ULL,
		0x2064E5A79EBAAA66ULL,
		0xAD7C2F2842D7D257ULL,
		0xC39E643D6DDE2C31ULL,
		0xCE42B40DD7BA35BBULL,
		0xBC9B6898441D99FFULL,
		0x00CE65E0C58E37A8ULL,
		0x0874CBA8AF82E505ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1963FE87DA02C6ULL,
		0x1F766C41BB1F865FULL,
		0xCC1F4E8595F41563ULL,
		0x04F49F477B4C2AEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F78BD89A1F5AE45ULL,
		0x46EF44F2669DA822ULL,
		0x216BFA4DA250E4D8ULL,
		0x519673ACF648A92FULL,
		0xB8A7BAD00A23E63EULL,
		0xB576CBD642AB0491ULL,
		0x89AB0C2C598DD1C0ULL,
		0xB2E2226D262FC169ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB85E786B2349DF68ULL,
		0x369186C04C0055C3ULL,
		0x90CFC8E2ED5E0773ULL,
		0x5F278FE0A15F5ED9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x951FC3D548385AF2ULL,
		0x971C80C5E127C88FULL,
		0xB40401EE89E3A1BDULL,
		0x68310C54DCE95DE1ULL,
		0xA283EA32B8F0F83EULL,
		0x2CB05D5BFEDB4339ULL,
		0x24D30BCEF9EFEF5BULL,
		0x3553807A93DBB8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B4875CBBFD3556ULL,
		0x394A5C6DB5B3C31DULL,
		0x2B57C2A7A3812946ULL,
		0x52961E86CF86CAB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A3ABFAC2C5C9536ULL,
		0x2F845AB147C8150CULL,
		0xA8CA5503CB718724ULL,
		0x5E10840B1DC9C817ULL,
		0x1A13BC32EF27EAE5ULL,
		0xECB6B7BDD9CB0070ULL,
		0x478C3400BAFBFF3BULL,
		0x5882FFEE87C7270AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE928AF3BAC497535ULL,
		0x52A3A0DF9BEA25AFULL,
		0x479A0D1F8CD96A09ULL,
		0x018281734559939EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5506CE20DE394DE5ULL,
		0x6BEC103444E7C5CEULL,
		0xD743BA2488A79185ULL,
		0x8B344E37B420291DULL,
		0x20FEE402E147CEC4ULL,
		0x723F18E55EE27F33ULL,
		0x7929F51766400058ULL,
		0x8CB5D75D04D47F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ADCA68E4EE2021BULL,
		0x6149C2405A86A765ULL,
		0xD37E1B9DB6279EA6ULL,
		0x6E3246066BAB1279ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BE6EECCCE7B4CB7ULL,
		0xAE5B17FEAFBFE09EULL,
		0xDAF456B50CAC3C2EULL,
		0xB34A153CBC4260C6ULL,
		0xB0076943D90AB137ULL,
		0x9B817F89FA869306ULL,
		0x35F6316FADF1C0A4ULL,
		0xABEEAF1AF95979C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D008EDF06119EBDULL,
		0xC3940679DFB9B39CULL,
		0xDD7FAD48DE8ED49DULL,
		0x38B8133DBF8A73E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD2E54833E23C43CULL,
		0x437C7FD893E63FF5ULL,
		0x6BA6DCD9D681D4A1ULL,
		0x180525C5304D6F11ULL,
		0xC95DF495A217E241ULL,
		0x80F4D0A031F7B4F6ULL,
		0x962C01C1E1604DA8ULL,
		0x6838952C546425CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC120A2B94DAF5C2FULL,
		0x67D3779FFEAB1C97ULL,
		0xB62F1FA14ACD5BA4ULL,
		0x106B4A59B72B0B49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34CA72E85A5504B4ULL,
		0x736AF0C7E414F61AULL,
		0xB338D970A814FBAFULL,
		0x8A39B384916F0B6EULL,
		0x1D0411A21ECAE2EEULL,
		0x4E0C558D29BC8ADBULL,
		0x57028B7BDF6DFBA9ULL,
		0x049E3B685CCD875DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x836510F8EC72B42EULL,
		0x093FA3BC161192A0ULL,
		0x9D998DD3D26856D1ULL,
		0x39B6850257F12349ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7000C6E5F8CE73C6ULL,
		0xEA8C5E64BBEEF5A1ULL,
		0x3FB85B8D4047E1C2ULL,
		0x1DB4D0E85DB74CB4ULL,
		0x9F71BCDC57C477F1ULL,
		0x8E0061F5AA0508E4ULL,
		0x04F5EE1E5913D36AULL,
		0xEE015AE5970BA99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AE2CF9AFFF846BEULL,
		0xFE9AE8DBF8AE4791ULL,
		0xFC39B40E79394393ULL,
		0x71E84EFCC9727A4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x438DB2CD543624E8ULL,
		0xF376C0A8E4D65CE9ULL,
		0xFE9972C41574E28CULL,
		0x159A32D3AF0C1F23ULL,
		0x11909A2584E0BBB3ULL,
		0xDB0B8A178E510B3BULL,
		0x646333FCF1243D9AULL,
		0x5BB0E4D8254C026DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF04945F0D92037BULL,
		0x772D402804DE07ADULL,
		0xE5532A4FE0D60789ULL,
		0x31DC2AE938547B60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A97281339C5F45DULL,
		0x2E6882C72042412CULL,
		0x98AACE33A0355FA9ULL,
		0xEB269BDC59F0813CULL,
		0xA388EB0CD9431C03ULL,
		0x4C978CE7B9DB3ABEULL,
		0xCAEFF7033B719DF1ULL,
		0x208AB4D1854F8516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0EA0BFB79BC1DA0ULL,
		0x8CE76D2CB6CCF978ULL,
		0xB84978AE7312D17AULL,
		0x3FBD72F623BE429EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA157658D90057F8ULL,
		0x460D8E21467DDBDBULL,
		0x569E55158ED8BE49ULL,
		0x409B2A47479B5031ULL,
		0x3D9995C4D97C4BBEULL,
		0x2A7688FA4E4213E0ULL,
		0x6AB7EEBCF72EEF91ULL,
		0xB0BD172569FFCC08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE1B19121739A08ULL,
		0x93A5E348E44CCF24ULL,
		0x2DEBC5223FD04DD5ULL,
		0x7CAC99D503939971ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DC2D5A6D2DF5370ULL,
		0x942D07DFBA0CC08AULL,
		0xB8CBB48D67BE6704ULL,
		0x549DB362D78072FEULL,
		0xB88C77A52D9CEBA6ULL,
		0xAF4CF5D7EFE53BE1ULL,
		0xE97C74B32998D56DULL,
		0xE3A125ACCDA342BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929C982B982A5320ULL,
		0x999985ED5613A40BULL,
		0x61450725946E154CULL,
		0x1E894B095DBC5B09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4FCEF3254B8BCD5ULL,
		0xD45A8FE775A7C5CCULL,
		0x8746092155F92394ULL,
		0x6DCBA06C2EA64F71ULL,
		0x17A47F7C75CA3C00ULL,
		0x083F71D6B27535B1ULL,
		0x98934D1422E3A988ULL,
		0xE741E4285B21BD7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2767DBABD0BDA9F4ULL,
		0x0DC575C5F30DBE16ULL,
		0x2D237A1E83C44DC6ULL,
		0x41937E69B5A86FA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x330051D8651CF3CCULL,
		0x90E802596453A49CULL,
		0x966C52F00328F31EULL,
		0xD9D65860F6489517ULL,
		0x6B3F98B70386D8A2ULL,
		0xB6623C46E47696E8ULL,
		0xBCEF5CDB0363D98CULL,
		0x64CC750FA2114225ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E70FD02EB211E25ULL,
		0xA37CF4DF4DEE0B1CULL,
		0xA1F41B7283FB3E01ULL,
		0x502FB8B304D866B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9871489DBD3C3ECULL,
		0xB1967D0F968CC559ULL,
		0x20193B27C98F7C54ULL,
		0xCBE6C99216D768ADULL,
		0x55DDE4DB29304008ULL,
		0xDF4CAB66783D681BULL,
		0xBEA356CDB4F53E45ULL,
		0x4355170466A8FF2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8770D11F8FD46ABULL,
		0xD6F7EE456FAA3968ULL,
		0x6C581DB0A5F6BAB3ULL,
		0x4A88343953ED499DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x346A972127158D2FULL,
		0x9EFA5CFC7B11C8A6ULL,
		0x8D9F80984BD49255ULL,
		0x847D09BF8B9F6EF2ULL,
		0x02AD865B785C667AULL,
		0xFB367D2670FAA11AULL,
		0xCFC6928DD2977E36ULL,
		0x3560F457C56A7221ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A2C88B504CCC47BULL,
		0xE910F0B14045B282ULL,
		0x651941A58E514E7EULL,
		0x70E14EC6D96C5FF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16568084ADF08B8AULL,
		0x6FC95D77EA6FFD1BULL,
		0x45134CFB857516ADULL,
		0x78E973D90CFC9F85ULL,
		0xCC55893F4FEC9ACBULL,
		0x6C170CEAA2ECCA31ULL,
		0x7ADA1BCBCB0D8B1EULL,
		0xBCD24D03170BFE98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B08DFEA8B0F89E7ULL,
		0x7B35484C1996007FULL,
		0x81736D3BA977BD31ULL,
		0x0020E24E78C46A27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x301E0CBDE399D259ULL,
		0x80891C55CEE26E5EULL,
		0xA7628ACDC76E13F9ULL,
		0x6BE884D328142043ULL,
		0x7E193905E23FB6C9ULL,
		0x906AAEC02FEE002EULL,
		0x9DBAA7539EDFD6A2ULL,
		0x1C2B901E01DDAADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7DC839D790EF4DAULL,
		0xF05F0CDCEC367544ULL,
		0x111761375CA7F01AULL,
		0x1A5FE9476EFB7CDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DE587ED12C7528DULL,
		0xAC7316F5B160FDC2ULL,
		0x5A1F8E1D3E61667CULL,
		0xD164FDBE352AA612ULL,
		0xFDE637CB13DD8D07ULL,
		0xCD7D16C22942AA2DULL,
		0x8B544A26A95C888EULL,
		0xE261DFB15193986AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E11D01205AA46A3ULL,
		0x2D0477C7D1464096ULL,
		0x08A28FDA621DABAFULL,
		0x6BEC3210511345E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7787F78FA4276BE2ULL,
		0xEB8CDF424259C4E7ULL,
		0xD68EA95839F1A50AULL,
		0x57409BCBCAC25D88ULL,
		0x78954975BD5A1419ULL,
		0x33FCDDC8B8BDBA9BULL,
		0x0EBA71469D426C4EULL,
		0x0596C886EB3C2A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DB0DF09BF8667BEULL,
		0xA315CB0DAE8377FBULL,
		0x063B79D391CDB8A6ULL,
		0x2BA25FD2B5B0A331ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BDD14AAD4DE9307ULL,
		0x7CDE0639D50243DFULL,
		0x79D17F5FF3574DCCULL,
		0x5944DD9589FA421FULL,
		0x1666CBA284D27690ULL,
		0x40486BFB27026CEAULL,
		0x7291F9DAE63F8C74ULL,
		0x3CE7A45E4444296CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1F4ECA8C1C2DBDULL,
		0x079E0D819F5E6E9EULL,
		0x7B7C95DE20C6270EULL,
		0x63A74393AC186838ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56952653026C48F6ULL,
		0x3CE5D8A019B91771ULL,
		0x475EBAFAF1575F28ULL,
		0x464ACAC45C159CCBULL,
		0xB16BC054B92F0D60ULL,
		0xB294F3C4B86B155BULL,
		0x88ABFA3E6B3807DBULL,
		0x97078C3F60077A48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC93B2E67F68488DULL,
		0xBF0207D3799E430DULL,
		0x90E5E03EDBA889C4ULL,
		0x31699C2C9D31C38FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE68317C49248BCD6ULL,
		0x693CC789DEEB79F8ULL,
		0x2BCD93AD63EC4148ULL,
		0x881D136E491E4429ULL,
		0x793077F04B088154ULL,
		0xD2E2167B2B874880ULL,
		0xA05BEF017563BEFDULL,
		0x50CF619CC265ADDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3B4E56FB58BF129ULL,
		0xB6CC1DD255003D0AULL,
		0xF9730DE4D0BA9AF5ULL,
		0x06E590B32436129CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x849B4B73A6888A0DULL,
		0x581C689E8DD0B27AULL,
		0xD0535D81C4170317ULL,
		0x8014A2E01A4799E1ULL,
		0x140D47B95CF2577FULL,
		0xC38ED73F0703C359ULL,
		0x879E373E43291514ULL,
		0xA39AECDA391753CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E93F0F772818A8AULL,
		0x5F505BF9985FB1B3ULL,
		0xF1CF90BFBC30242CULL,
		0x4913CB4493BE0A89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7900B821841E6373ULL,
		0xE44E0BE704672A10ULL,
		0x2ECBD2A296F4B94BULL,
		0xC06B7624463C90DAULL,
		0x1B65E153DE5BC6FAULL,
		0xFE5F09144127DFE4ULL,
		0xC609942BB087B93CULL,
		0xF99908FD35DF4E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A202A9485BDF220ULL,
		0xA66964E8B05265ECULL,
		0x9437D11ECB1A3859ULL,
		0x4D22CBBA45622D47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x054697040041433AULL,
		0x006C78C45962DDCBULL,
		0x7A28F41D2B217683ULL,
		0x2B61306ED67733BCULL,
		0xFB491B179CA8883EULL,
		0x9911BCADAD2AF5F0ULL,
		0x55B880868278B6C9ULL,
		0x4DFA9063AC915CE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52209C8541457E23ULL,
		0xB90E7A8C0DC35F90ULL,
		0x338C0814890C986FULL,
		0x3E929F3A740AFD7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A95D634A4761694ULL,
		0x6D06695461AB794AULL,
		0x9DF8AEC3F18E51ACULL,
		0x87E934726B501F19ULL,
		0xB9326D49995E8478ULL,
		0xC2033D2594F5EA4CULL,
		0x21B91E923199B247ULL,
		0xD8E95D25BC1A55BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88120F21687DC537ULL,
		0x39817CE87E2C40ADULL,
		0x9F7338774E5EC853ULL,
		0x3A8D080C5738D8E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5D6EA976AA76637ULL,
		0xCEC51CE727659A68ULL,
		0x1EF52C4214683FD5ULL,
		0xA810AB77A7A8B8E6ULL,
		0x48A09D9549462AC9ULL,
		0xC293C639EC5592FDULL,
		0x9F7E296B70516668ULL,
		0x801EA6163BD82EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DAE4EC04B11C2F2ULL,
		0xB0B489803C196C01ULL,
		0xCBAF5234C07D7362ULL,
		0x2C9D52C489BFAF6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90189DFCD8661087ULL,
		0xB254A7FF720E98B4ULL,
		0xDC7000B3283C7BDEULL,
		0x6F754DAB4931134FULL,
		0x570E6619AF99C83CULL,
		0x5BB133956328F336ULL,
		0xBFB823DBB9E8AD6AULL,
		0xE27AF280FDCA0143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C3BC5CCE939CE7BULL,
		0x4EA2502C2A22B2C5ULL,
		0x51C55350C0C639A8ULL,
		0x0DB54CD0F52D435EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A38B88A49961BB9ULL,
		0x19666AF38759372AULL,
		0x18EACAAEF18C9F72ULL,
		0x1386BE8A595095C4ULL,
		0xF0FF5FA036C993C0ULL,
		0x6B6A07EF8F0A740AULL,
		0x7F237FF02082E89CULL,
		0xB2DA0F01FFDBA8A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6020EA526B820E28ULL,
		0x0B239882C2E670CAULL,
		0xF82FC853C4FB26AAULL,
		0x1FE4F8D653EB9EA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x385491EE1B14E335ULL,
		0x6F3ACC25F62B5B42ULL,
		0x8D848EDECAB971E3ULL,
		0x083374DEBCFFAFD8ULL,
		0x68AB94B4ACDFBBBCULL,
		0x9AFC63AF99282CCAULL,
		0x5722BAF5476F50C7ULL,
		0x0D035A06268B5457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1CCA4BFC44AC156ULL,
		0x70B19836B222014DULL,
		0x7CAC4F47653F6F84ULL,
		0x76B2D1C875AE34CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD139AFCAF81BEC46ULL,
		0x2CF274603C2407CCULL,
		0xFA7FEF439AF1FF6DULL,
		0x7DB56E9E7EC2F9B7ULL,
		0x87A62A5146C304DAULL,
		0xB5E0923465D48149ULL,
		0xC2C451C4E7B5B036ULL,
		0x72036BCDFE491DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3E3F7DB790EA728ULL,
		0x2C48282759AF38B6ULL,
		0xE3A4127DFFEA278CULL,
		0x6A376F323D9D621AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0C59A7B603E780ULL,
		0x3164AB7630BDCE8EULL,
		0x936C7BA45AE115D1ULL,
		0x31D5301E04F3712FULL,
		0x9D60CE4DC76E4C1DULL,
		0xA55C3113610665FFULL,
		0x0F2219E9989BEBDDULL,
		0x73F2F53F919B0E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE86AF93350633654ULL,
		0xBD13F45697B0F27FULL,
		0xD27C5451020618B7ULL,
		0x67E5978DA1F79539ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92230A4ED3E26480ULL,
		0x0FE4791C3B8E6BD5ULL,
		0x75AED080986BCF81ULL,
		0x9ABF887D1CA7F5C9ULL,
		0x597BCF70589A0F6CULL,
		0x6503AFF48BDD2393ULL,
		0x67DE4E3340ADF9F8ULL,
		0xA2B1CF899E1160C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA83D4FBFAC0B22BULL,
		0x0E709768FE61B3B4ULL,
		0xE0AE6C1C323EEA60ULL,
		0x412456EA933C527EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCA7E04C74A0DEFCULL,
		0x7CB4D43A2564A335ULL,
		0x834267E3F03A24AEULL,
		0x20DB50522D703AE9ULL,
		0xF22C7B5F6DC6F8F2ULL,
		0x696F5A41D8FF3667ULL,
		0x5746825AD0FFEA89ULL,
		0xB8F7DEC38478629FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF423076C029D6FDULL,
		0x233C3A005B46B6A3ULL,
		0x77B9C15EF636F514ULL,
		0x15A66157D74EDE90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9509F42B4FEB882ULL,
		0xCFC7AB5E7399A271ULL,
		0xCEECBCE20E4CB454ULL,
		0x756FB6D02642575EULL,
		0xC7A0CF4837C802FFULL,
		0x54F17F6BB9293DE1ULL,
		0x64184153BABB70D9ULL,
		0xCD384CBFE2771E7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2F63FAFCAF2EE3ULL,
		0x6BA0955BEFB8D1F5ULL,
		0xAA866F4FC61F7497ULL,
		0x6BCB1B4BC3F0DDFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6926F0379D1E4A4AULL,
		0x048CBD804B904D74ULL,
		0xC86813624B3E469BULL,
		0x501607304E0328A5ULL,
		0x4E6F49D90EC97DDCULL,
		0xEFFCCC9CC1E47B0BULL,
		0x8AF1B2B3FF83EB71ULL,
		0x9337690FD1A2332DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DABE66FCF06FC36ULL,
		0xA4131CC5137A9122ULL,
		0x68489A1A38D33984ULL,
		0x2A4F9F896C16C168ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x159C7A9C9B725C84ULL,
		0x9A5100B81CDFF03EULL,
		0x653C2CCD77F95C48ULL,
		0xD7ECDA2346C38B14ULL,
		0xEF9B40B367665C37ULL,
		0x209BA703DD1C1BB2ULL,
		0x93A20A9A6AD44015ULL,
		0xCAA50E2DCB7FF6D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A8153DF4A41135ULL,
		0x716BCB4AEF0C0CCDULL,
		0x4F49BFB9537ADF6BULL,
		0x6C6CF4EF7BC22E0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8D0595BFF2A6F2DULL,
		0xBAB5B52874781734ULL,
		0x39DEBA1430EB95A0ULL,
		0x8F235F1DB5FAD42EULL,
		0x3F2C76E2D4F83FE9ULL,
		0xA274CA5487547CFDULL,
		0xE7E25D2ED06160F2ULL,
		0xCEC6BCF90E721C85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2969FF079C03F05DULL,
		0xD80BBDB48B02A4CCULL,
		0xA5788F071F5FF9A4ULL,
		0x40A36C15DAEB100EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B90D4298A55309EULL,
		0x995A125A326EE0E4ULL,
		0x5DDC4EB35B165C5BULL,
		0xDC6A41C30C17187EULL,
		0x886957AF78FF2294ULL,
		0x51361048D795A99FULL,
		0xF2FF3EF486C8579DULL,
		0x2C4B843B8BC7AA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B33D835803453A0ULL,
		0xA7607D2A32A60E92ULL,
		0x6FBFA6FF5CD35DB5ULL,
		0x6F9FE299CBBA5C0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x615C733AA86CBD73ULL,
		0x369177C629149B59ULL,
		0x1BA9C667F96B3035ULL,
		0x9111F743D412D83DULL,
		0x0CC6B97B30EA9507ULL,
		0xBC8EF8D57163CA62ULL,
		0x88BF2E4462A7E651ULL,
		0x4B1A1EFE6A419822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46DBFB83EB3EDE32ULL,
		0x33CA6774FDE4A5E7ULL,
		0x680AA48E9E576057ULL,
		0x36F2910799CF6D5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5483506235D9D8D2ULL,
		0x6803C06272370B3AULL,
		0xFE3DE78522AA4DD9ULL,
		0xD342AF89D28C13F2ULL,
		0x291AD582882BF92EULL,
		0x5A3D52DCC8D5D10EULL,
		0x9DC5C46D5A06D30DULL,
		0x8D0FDCCA8A11D17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7F01C26C60D8D7ULL,
		0xCD1E0D2841F41354ULL,
		0x69990FC07FADA1D4ULL,
		0x439D759A51312CBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78E91CD6495F0913ULL,
		0x1E3B448FFE8BAD14ULL,
		0x949C53136CB1CD65ULL,
		0x3F955577B2A0AD3FULL,
		0x7AB22B2ABD3796F5ULL,
		0xC81C7870DEA2FB6BULL,
		0xE514F9109BB5D5D9ULL,
		0x8EC8A23FCEDFF0F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF5B852E5F9F748FULL,
		0xD27525510ABCFF08ULL,
		0x95B94B8A89AF8BB8ULL,
		0x715D6AF067DE71E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4B392E5E67BB1B8ULL,
		0x23D37FEA63DD54DDULL,
		0x9800B7DEC5C54A38ULL,
		0x89236AEA58AFCABFULL,
		0xE44F70D9393930FBULL,
		0xE8A0F0FFA244460EULL,
		0x43C28071F2CA45A4ULL,
		0x9E1C4FE12982D8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87E532464F8FA8AULL,
		0xABB745DC79FFBB13ULL,
		0xA6DFC8C8CFCBA0B2ULL,
		0x01574656821BF451ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41A3CBBF0D8BF7F7ULL,
		0x72E3BCC187B88153ULL,
		0x3FCA4D729C3BD7EDULL,
		0x533183E3689EF867ULL,
		0x6BC64693366273C6ULL,
		0x2A43DCE32ACBD427ULL,
		0xF66E1BF265FD9544ULL,
		0xFB5DDE9BF11DA30FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4112459920292CECULL,
		0xB8F68679E1F9FF2DULL,
		0xD422736DBFE0000BULL,
		0x23208F0933052CC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23EE5741813E1156ULL,
		0x76C61AED828EFFE2ULL,
		0x70933B72DB7F6F4DULL,
		0x4ABE3999C88EC57AULL,
		0x039E5EF3699DD80AULL,
		0x230BE711C8E2614CULL,
		0x2F4C97118476BC71ULL,
		0x2565FB38B27CBF34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD706F632EAC23A3ULL,
		0xAA8A67915429712AULL,
		0x75F1A80C851F6818ULL,
		0x57E1840447132739ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC848291CCD48F35CULL,
		0x996B953AC43C65E1ULL,
		0x4D4FFD17770FA0DFULL,
		0x4284F78118A78B84ULL,
		0xA87F27376FF6C902ULL,
		0x581EC0D6D04FC14BULL,
		0x263C875F8FE780F4ULL,
		0xC321BC815AC2124FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB27FB576BEACDF6ULL,
		0xADFC351DB013171CULL,
		0xFA4C1546D36CC524ULL,
		0x3986F2B491764343ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x155568B1628DDA15ULL,
		0x94D387ADF679426EULL,
		0xC5A7A3662EAA0E14ULL,
		0x98598208B984021EULL,
		0x51EC7B0CF6548F1EULL,
		0x1F644ABA5A22A639ULL,
		0x2A3443F6D266948CULL,
		0xD57C289A16E6C717ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E6FAC9DF31B1D49ULL,
		0x3DB69F57579DEEF0ULL,
		0x0969BA0969E41AE1ULL,
		0x48C788E81FC58F8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEAF15703A6AF385ULL,
		0xB30CE88C772D1E49ULL,
		0x4D2B77CF585C953EULL,
		0xF5DA51761C0D2C97ULL,
		0x782D95DA05588B5BULL,
		0x41475304784AF917ULL,
		0x49E1F14225D7C07DULL,
		0x6BCC4DD0D273E376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC57353CD058FA57AULL,
		0x63A33B36524E17C5ULL,
		0x44B547A0F66327D6ULL,
		0x762DDE755940F026ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD759CFEBC710FB9ULL,
		0x1FD58177A9AB7DC5ULL,
		0xFCA974967F64735FULL,
		0xD0C0E5472C1836D9ULL,
		0xA370BF63837A4A56ULL,
		0x52A36608BFA5FC91ULL,
		0x443BD45ED5C0C0D1ULL,
		0x5EBA7EB39B7244C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF03205C440981AA4ULL,
		0x6416A6C41C4EFB63ULL,
		0x1D8AFAAA3A011271ULL,
		0x606FB3F03F0E6C6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE45B48B251A1C39FULL,
		0xD3A4AB18E88434F3ULL,
		0x970D1C5C71843680ULL,
		0x1EE833CE9764AE51ULL,
		0x516A7E3A3045602AULL,
		0xAA675BB2838B5DD5ULL,
		0x7D074C909965B724ULL,
		0x1D060EA48FB0DE64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA2A05557BEE0A73ULL,
		0x1EFC47986F34229DULL,
		0x262279D3369D65F2ULL,
		0x6DCE603BEBA5B13CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x157D32419EA6F5E0ULL,
		0x36F6D410389C02DDULL,
		0x3FBF3BC3AC16A9CFULL,
		0x414FC895965B9BB5ULL,
		0x6AFA458C9C4EFFD2ULL,
		0xB0242036714F1E27ULL,
		0x09DA97DAE0DB6FB2ULL,
		0xE99FC00BD3AADC7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A38520D260F42BULL,
		0x5C539C250A5A7CB6ULL,
		0xB631C6410CA93E55ULL,
		0x6F064A5701B855D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2953A5D640AB819DULL,
		0x262C80CF568902D7ULL,
		0x44574E3DA1A60073ULL,
		0x6FC2DE8BE64E6515ULL,
		0x234EFB3942E579E6ULL,
		0x78F6AD4039EF0FC1ULL,
		0xA3F91D8FD6F38D65ULL,
		0xAEAB1485DF0DEE14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x670CF0562EBB9D9DULL,
		0x1ACA3857F0055982ULL,
		0x9B51B19789CCFD83ULL,
		0x5D27EA6B025FBC25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DEF89D68093EB86ULL,
		0x3C5D97C72ADDF5CAULL,
		0xD29B2A55BB13D090ULL,
		0x2C02A0F567D4FDC5ULL,
		0x2B14AFB4C93BFA5CULL,
		0xA21614DB37CB3831ULL,
		0x905F3F6626BBB9E9ULL,
		0x718D45F0E1273EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3019EAC5F7B17B4ULL,
		0x4BA4B05173084D16ULL,
		0x40BE937F7AF1693EULL,
		0x06FB02B6D3A84B89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE3740FF82AB9675ULL,
		0x4A96ED9D42ECF2B3ULL,
		0x78540C435556F207ULL,
		0xB8D1F064C20A23F9ULL,
		0x53C4EE5AFF74D561ULL,
		0xA5C0C48D827A8AACULL,
		0xFC12B443611F7AFAULL,
		0xF40AAE01F2C22348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D72A2816E034846ULL,
		0xE5341A9EA11D8848ULL,
		0xE31ACE43C003333BULL,
		0x7267C4AECADB60CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8FE3B4D702036ABULL,
		0xD05F064B50586F65ULL,
		0x0F88A3C16E6A688EULL,
		0xF37A7135A5051D12ULL,
		0x1DBA71FAC57D3CC0ULL,
		0x20358FCE19A84F04ULL,
		0x4F398C912BE2AAC2ULL,
		0xDF0ADF9848994AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52AB2686C0B74037ULL,
		0x98525EE31F542A02ULL,
		0xD213814DF20FC15FULL,
		0x0F17A1D06BC632F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E147A45ADA931E2ULL,
		0xCDBFE4F388147E77ULL,
		0xD0557749D5ED035DULL,
		0xEDD2EED7C36AC1C6ULL,
		0x0DF0D241B5F0C8C9ULL,
		0x1DFD230D45E9EF4CULL,
		0xEDC0DEAC8D4DAEC2ULL,
		0x2AD48AD624ACCDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD3B006AF6700C2ULL,
		0x415318EBE8CE03C1ULL,
		0x1AF684E6CF74F42EULL,
		0x495F8AA135114FAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE72BF6C6A8FB1D21ULL,
		0x34FF9DA2F853792DULL,
		0x23799011AA6A659EULL,
		0x98A230D0F5327761ULL,
		0x19B3B786D89A5A68ULL,
		0xD7049B117D2F552EULL,
		0xB4F9516F31936D17ULL,
		0x6A21DA2BB2B07DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D934CACFE48AF1ULL,
		0x1FAEA23B8D5A1E05ULL,
		0x007BA693064C9728ULL,
		0x59A8934D7B651F76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x048A05965565BC26ULL,
		0xE41C45A9C2CA6244ULL,
		0x0A4FD9B209B55E4EULL,
		0x48D25BF9F1AA2A97ULL,
		0xDB4AE681BE9C928FULL,
		0x1E1C19D62BA2989CULL,
		0xF5BB1F75D1ACBC34ULL,
		0xAAA12CC23CC5303AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91A83CD8A0A38129ULL,
		0x5C481B743CED098CULL,
		0x8416852F29594E0BULL,
		0x1CBF00CEF6EF5357ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5669B45D0A0849CCULL,
		0xD019D9D3B0F98175ULL,
		0x06F3D68D704E9BFCULL,
		0x29BF112F5CF0D1CBULL,
		0x64D7947900D1B9F6ULL,
		0xEE4E7FC358A858A8ULL,
		0x874086938BA3D3C3ULL,
		0x72DC49E4F11CAAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E69BE532929E6D6ULL,
		0x2FC0D0D2D9F6AA74ULL,
		0x1A87D0742AA00B12ULL,
		0x3672092B273227B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3629375CDEC9E8BULL,
		0x916E28AB719C94C3ULL,
		0x176DE552A8CBD8A3ULL,
		0x39D79F7551B99F25ULL,
		0x4F97A6E1DF012E03ULL,
		0xF97D876A67ECE92BULL,
		0xCA5B93E3010A3129ULL,
		0xDBE8C8D5E642463EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E558FCE81977D0ULL,
		0x9A104276DEC73131ULL,
		0x2105D904D04F24DEULL,
		0x5E656F357F900C77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA6D8DC5A869FFB1ULL,
		0xE3059A6EDFFCA4D5ULL,
		0x082F4F4C3BD4FA3EULL,
		0xC3E4CC4508529530ULL,
		0x0D5063121118CF97ULL,
		0x1CFBF86E4B5F6221ULL,
		0xBBFDF566E124D175ULL,
		0xBC6B9718336567E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45C42743218D456ULL,
		0x306C7ACE102535BDULL,
		0xEFE1BC91A74C11A1ULL,
		0x3BDD39DCA9600123ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DF8199E39F6C76CULL,
		0x95A545FFCCDBC0B6ULL,
		0x80A0B012BD39F01FULL,
		0xBEE5BC716C07877CULL,
		0x5C18D99EBBD612E4ULL,
		0x632EB0E00E0FBC24ULL,
		0xFDACE322A54EBDAEULL,
		0x384DFB2103372C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A8672E1BBD969AULL,
		0x4E938741E331AE1BULL,
		0x284A673746EA1802ULL,
		0x1A790357E6382386ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD345C3B60DCE5E70ULL,
		0xC7CBB7E5185E754EULL,
		0x591FA14BD9A62942ULL,
		0x0D6F1B2246A2ECFCULL,
		0x558F53638D5BFBAFULL,
		0x851B31499C98B899ULL,
		0xCB8331FFFD7C3274ULL,
		0x4C27DAF4F10BD16FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x868C247D0975BC0CULL,
		0x89D508D25709DC11ULL,
		0x8E990D4B7A15A68EULL,
		0x5B599B7E0E640394ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x001D4315DF2D8CF1ULL,
		0x52734D8E8DF363CEULL,
		0x142FA0892E87DFC7ULL,
		0xAC60C63A77FCE79CULL,
		0x8537E918F21F13F3ULL,
		0xAF043911B0F51834ULL,
		0xB3B2BBF87A319351ULL,
		0xA4FCE7C6BD2F7AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC669DCC9CFCA86B9ULL,
		0x4D13C62ED254FB99ULL,
		0xC0B7876B51E3BDE7ULL,
		0x29EB2DBA8D091D8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03FD05E77959A38FULL,
		0xFB0D5EE48897E2C3ULL,
		0x1E8A8DB7B98E10E3ULL,
		0xFC40C50D503A2767ULL,
		0xCE90C336AD308AEBULL,
		0x4FB03C7DAD72E941ULL,
		0x9D6AC0799D8C1B66ULL,
		0x986FEA508A882B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7A00052E8E45EEULL,
		0xCF36598C47A68287ULL,
		0x7C631FC51C5A2213ULL,
		0x1CDD8D01E070A080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD838F21E0F9B4E3ULL,
		0xCAF4AFAD78BA2669ULL,
		0x247C17EC474E766EULL,
		0xB624E896A0C74845ULL,
		0x49E93741AA97AA5AULL,
		0xFCD2F655031E3BB2ULL,
		0x87D1E08894D129CDULL,
		0x3435831B83D22188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD621C2E1337CFF6FULL,
		0x5245404BEF3702E0ULL,
		0x4DA36C325E5AAB02ULL,
		0x76165EAC31F84289ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B60759D9BA333E4ULL,
		0xB7B18AE608E32022ULL,
		0xD48AFF57C42130FBULL,
		0xB30482B13A25F5ABULL,
		0x304FE0DD216F8E8CULL,
		0x1F741F0EDE59A7D6ULL,
		0xAE2FF859F3DFB2DCULL,
		0x3DCFCEDA13DC5826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x873BD67092325E15ULL,
		0x62EE271B0A3209EDULL,
		0xAFA9DCB1F755BDA8ULL,
		0x5FDD37102CDB0B69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FBEAB75A2F7A887ULL,
		0x69CE4C2DD84BA41DULL,
		0x4C50D4D4C95ADF27ULL,
		0x575C213C42A78A64ULL,
		0xD6B0A87AC2490382ULL,
		0x582774A2426C7858ULL,
		0x0723141235C14BC7ULL,
		0xB30695CDA8DF4E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF7ADAE79CE31C2ULL,
		0x7FA99C43B465814DULL,
		0x5B85CF88C40C1EBEULL,
		0x6A565DC353CD34F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0E065ED0F7E9BA5ULL,
		0x94E20A34684FBA25ULL,
		0xB97959D729ECC55FULL,
		0x06526F4C6E357371ULL,
		0xBEAB3EB9AF02692CULL,
		0xBCC012686187E64BULL,
		0x9DC548EC1A944AEFULL,
		0xCF5F6ACDE7F89657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4BB57D09DA3CB4ULL,
		0x9964C5B2E27BE963ULL,
		0x24C22CE31BEFE4F5ULL,
		0x4E7C49DCDD1BC473ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x703F84EC92BE1732ULL,
		0x1DCFA55329EC888FULL,
		0xBB942054E9AED645ULL,
		0xF5DB0C2CD01107A1ULL,
		0x66A7A9ABE630130CULL,
		0x87F3812DC509EA47ULL,
		0xA29D6F404D978FA2ULL,
		0x3969B382EDEA00A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD22B470BDE0EC50ULL,
		0x4BF4D21E69654F28ULL,
		0xDEF2A3E06E2E2865ULL,
		0x7B8BB19C20CD2083ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DEA229761E5E9F7ULL,
		0x3E93C14F0817B831ULL,
		0x32E6D749BD4D6769ULL,
		0x47A1C4C607D8E2D7ULL,
		0x2A5E13E57C794352ULL,
		0x0496021F520F1F59ULL,
		0x01BF0AC65BB08256ULL,
		0xED69BB5C9B2FAC3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E116A7DBE5ED68ULL,
		0xECD811F536565F6DULL,
		0x754270BB5980C02DULL,
		0x0553948510EC7373ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0AA1A32AC13F1B6ULL,
		0xE18E211139E8EAEBULL,
		0xF38E7A2CA910C58CULL,
		0x77A5C8A67D958022ULL,
		0x77D207F204097F34ULL,
		0x4003D8485E517D4AULL,
		0x223C9D50950CAFF2ULL,
		0xBF6E66270FFA5234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D7481F457CD7A9ULL,
		0x62203BCF3A0183F9ULL,
		0x088DD422C8F2E382ULL,
		0x6208F272DCBDB3E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF95C4D6A54D67295ULL,
		0xA5A7467762941E84ULL,
		0xF6FB1026F30CD25DULL,
		0x41E273DF8BEF7A1CULL,
		0x169C823528575E87ULL,
		0x42FEBEEF634B7256ULL,
		0xD23BCEC5532347C8ULL,
		0xCFC6100DA4F8A891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5497A14E51CE7F39ULL,
		0x97779E001FC7174CULL,
		0x2BDBC1714A497A17ULL,
		0x1948D5E608D87FC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA900B36B15126845ULL,
		0xD11C46DD94F4B5F9ULL,
		0x82C163BA03B54DE5ULL,
		0xFBA37FF6041B98F3ULL,
		0x7E4555CF79B7A9B4ULL,
		0xDF9BBCDE2A7FCE3DULL,
		0xD5676EF9A69C85C9ULL,
		0xF0065AAC80402FD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x674B703726559E68ULL,
		0x023A4FD7E3ED531AULL,
		0x301BDCC8BEF129DDULL,
		0x1C94F5910DA2B28BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2AC0CCD15A019EBULL,
		0x926BCE1BB97353ABULL,
		0x516E73A357C23F5BULL,
		0xBAEB7CC6160416BDULL,
		0x44F6FF2027CAF914ULL,
		0xAA450F489372DB11ULL,
		0x7588CA3F5F519E55ULL,
		0xEC03FB10B98A0753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F55EB92FDC11828ULL,
		0xD8AC12E19C7FD83CULL,
		0xC3BC790B7DDFC012ULL,
		0x4382C141A0812D20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51AAE493EADA575BULL,
		0x70671853D4D5C268ULL,
		0x90B6E6B62889BBCAULL,
		0xF06BB83C75C2AB43ULL,
		0xAE39698000EA58EAULL,
		0xE001D408071B2CDCULL,
		0x6D5967366A980ACEULL,
		0x5022B146DC472078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E308D940DA38BF2ULL,
		0xB0AC9184E2DE6B2AULL,
		0xCBFC38C9FB1B567FULL,
		0x559208C128517D23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D493A8C85106433ULL,
		0x09FA2279ED8B979BULL,
		0xA51572B4D852A382ULL,
		0x3ABD012F3F72F7A8ULL,
		0x241292C4B983CDB8ULL,
		0x780B540E72DAB0A2ULL,
		0xD5A0145274935CCFULL,
		0x6A06BE6F1FD2005FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC80B03C00EA0EFD0ULL,
		0xDBA89C9EFA01CFACULL,
		0x5AD876F226326A4DULL,
		0x77BD45ADF89F05E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x554C66C862CFB2C3ULL,
		0x7141A7A527940E57ULL,
		0x6026A9C66847D1A8ULL,
		0x191A44B5D16D972CULL,
		0xADC7D6E696B9A2FFULL,
		0x3E32322FBBFD35D6ULL,
		0xFDD4DFDDA2905114ULL,
		0x6AB8518E370C658EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20F64D02C25DE6EAULL,
		0xACB51ABB0F2A0C35ULL,
		0x0DBFE4AC89B3DAA9ULL,
		0x70765FD1FD44AA66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D884B09DC883989ULL,
		0x67A8CF8D94799B1FULL,
		0xDA38ECB44930F652ULL,
		0x2FD3C1E3FB7B03F3ULL,
		0xD1E835C78B03E570ULL,
		0x5FE57522B155157AULL,
		0x180E29C7C71D7FA0ULL,
		0xF569828D122CF44FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x760046A87F1C4D94ULL,
		0xA3B832B3E71ACB5AULL,
		0x6C53205BD791E820ULL,
		0x1D7D22D4AE2747B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC476FE3F8BF337FEULL,
		0xF1FF3B928B03CE73ULL,
		0x8E77A97B8970A3D1ULL,
		0xCE7725FB257478E8ULL,
		0xECC9C61BDD7A374FULL,
		0x1D8A51127CE99985ULL,
		0x5FCD7CB257A95116ULL,
		0x88FDF2642D58A8FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA6A66626C1770D6ULL,
		0x5487445115B09854ULL,
		0xC6F82BF48C92AD1AULL,
		0x242920D9E09D8E12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6D5055B369474AFULL,
		0xCC442830F73FA750ULL,
		0x67FE3EEE483B4751ULL,
		0x612CA9646C1535C6ULL,
		0x623140462DBD6F10ULL,
		0x138836AF0D45B5DAULL,
		0xD69E340727776530ULL,
		0x150146F8C586FD7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A248FC600B2F181ULL,
		0xB27C462CEF98A5BBULL,
		0x4379F7FE23F44C74ULL,
		0x7F5D3251BE1ED674ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6760EB9CF5FE6D09ULL,
		0x59808EF7BF64C536ULL,
		0x329355E1247C51A3ULL,
		0x767EB7BDEEB5E122ULL,
		0x88FA8A7C7F0AD92EULL,
		0x10F34E2756CC84BAULL,
		0xA3BBCD024F4E134CULL,
		0xF99987DBBDE5B528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC917A17D19AAF6EULL,
		0xDD9E28CEA1C078E6ULL,
		0x8073C438EA132EEDULL,
		0x0348E25C1ECEC52AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF40E04B2B4BA5596ULL,
		0xC3B348279BC37380ULL,
		0x8BB0E3FAFDA577FCULL,
		0x360AE809A69C71B5ULL,
		0x28C788C744405028ULL,
		0xF015417DD99F8F46ULL,
		0x0AB4B66A150C3F24ULL,
		0x4A08F74D3DC00647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AC5246D6463D28ULL,
		0x66DB00D5E972B7EBULL,
		0x2283F7BA1D76D778ULL,
		0x335F9D80D11D6041ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E1DB7CE8743D859ULL,
		0x77783343702EC6F6ULL,
		0xC5986937AABB7466ULL,
		0xBBDECFE628C82540ULL,
		0x24629B4E565BE464ULL,
		0x5DA02A5EFB1779FFULL,
		0xC0E83F63C7C42A5BULL,
		0x56D53DBCD46154B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84C0C56F58E7C132ULL,
		0x5D3E7D5CB5AAE2D5ULL,
		0x6811D20751D9BDF6ULL,
		0x1F85F9EDAF3AB8D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B0AE3A176FA165EULL,
		0x8B529D9D39EBE75BULL,
		0x4D50F3BFDDFEFCB0ULL,
		0xAEFCC27360E9ED41ULL,
		0xF3D4A431575300B0ULL,
		0x8333CC462432A30AULL,
		0xC814F329255E634DULL,
		0x9324A9E1693CEF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC9B42F46D4C33D5ULL,
		0x0502F00699701AFBULL,
		0x006D0BDB6A01BA32ULL,
		0x066DF9E8FFF569E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BAA86AAC3A920F8ULL,
		0x72247C2D9613A5C7ULL,
		0x247DC6714E1F0011ULL,
		0xA2ED4BBF0A581922ULL,
		0x0E08C8DD07A8D817ULL,
		0xF68736DDE8C26447ULL,
		0xC7EB13F39B86649AULL,
		0x184942A5029E974DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F85779E6B934FAULL,
		0x0A36A11E22EE8853ULL,
		0xD162BC9A6411EF12ULL,
		0x3DCD303D6DE28EADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D836AA23A12CDBFULL,
		0x0CC84D46821EEFD5ULL,
		0x90A5D2C25178D461ULL,
		0xDD0468D0D4D06C2AULL,
		0x196B4C7F08746B64ULL,
		0x9B0ED6D54AC4A5FCULL,
		0xF3BAC51FE187D7A7ULL,
		0x79AD01305058F917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0370C57D7B5AC156ULL,
		0x10FC30EF9B4F9341ULL,
		0xBE5F157DCBA2D742ULL,
		0x6CB295FCC20565B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DC764F935698C6ULL,
		0x0854AD9E8574E160ULL,
		0x4A081C2071734DA9ULL,
		0xE635B48813116325ULL,
		0xE5FD1536CAABA2F6ULL,
		0x55D0457464C51C36ULL,
		0x2C0ADA6D24ECF5CDULL,
		0xE01922534849C8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6D9C71A8D0CE56ULL,
		0xC53EFCE57AB71186ULL,
		0xD3A48853EC9FCA23ULL,
		0x29F0CCE4CE053503ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E7437B099E3AC0AULL,
		0x81D7E48F1D4DA70FULL,
		0xE94CB7296CD22314ULL,
		0x3C396A31B7851513ULL,
		0x2A0ECAE4BC4165D8ULL,
		0x914561498310A2EDULL,
		0xBEA0CEA193C13745ULL,
		0xF43538A160FAB51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA655A48B98CF72ULL,
		0x1224557891C5D643ULL,
		0x352B63255B805768ULL,
		0x7C1FD2261CBBF758ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AB21D60BFE4F3E2ULL,
		0x9E9EEEE642EBF53CULL,
		0xFE95EA6044F472D2ULL,
		0xBE3CE247F6943145ULL,
		0xE87FC55F001DA185ULL,
		0xC42EA319A92685B0ULL,
		0x674064824D457289ULL,
		0x3A009BF339EAD30DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDA9697AC44AEEF6ULL,
		0xBD8B24B55EA3CD7EULL,
		0x5224D5B7BD437345ULL,
		0x5A5408628F6F8543ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1890CB8AAB534C5ULL,
		0xA09AA895D7805045ULL,
		0x70D86A456AF0DCF6ULL,
		0x64F8988ED7F70B87ULL,
		0x8571357586727B18ULL,
		0x92740F69707B3760ULL,
		0x8D94E31301F27D44ULL,
		0xD710F97E058DBD38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB056FC2A9FB37F15ULL,
		0x5DD4F23C89CA8899ULL,
		0x74F21F17B4EF7524ULL,
		0x517DA143AB0121ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5104445DF5490337ULL,
		0x9466B00A80A9A9E5ULL,
		0xE3DD94145F7022B7ULL,
		0x27B3F795EC585D10ULL,
		0x94F79922AA0F60FDULL,
		0xFB8A8519B749B1C7ULL,
		0xAA485E80E3E1E1DEULL,
		0xF4008A1F9A152666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DC4FF8333916E1DULL,
		0xEAF671DBB59A0D85ULL,
		0x2A9B9B3632F7A9D0ULL,
		0x5FC87846CB7C104EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66DDD5B7068ED57BULL,
		0x2F40F71B4AD2BF41ULL,
		0x623706B852788517ULL,
		0xD11A5D4FF2F611F2ULL,
		0xE1A05CDC6E80B40FULL,
		0xB53156E2492CF3E2ULL,
		0xDC1DA89D821A1558ULL,
		0x5EF091037B878032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4AB9E6F6DA991DCULL,
		0x1493DCB2277EF2EEULL,
		0x0E9E0E19A257B042ULL,
		0x68CFE3D44913197FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5D15D80292AACFEULL,
		0xA8CC96F2315CEAE7ULL,
		0xE64AAE81F15D5EEDULL,
		0x8EA1612A34B074F4ULL,
		0x6B64C312F4907CC1ULL,
		0x2BF08339272D8C8CULL,
		0x1C8F0DD821224F0EULL,
		0x5547FCE99C66C48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6C65250769D3392ULL,
		0x2E80116E021FC7BFULL,
		0x2386BC96DC751B08ULL,
		0x3750EBD76BF1A1E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D9B573A1578F3B6ULL,
		0xB9B410BDF638B652ULL,
		0x83A052B0AE753A94ULL,
		0xD0498B9E34E2E141ULL,
		0x039EDCBF822B0245ULL,
		0xCF15D5324609FB5DULL,
		0x5106DDF427DC56D3ULL,
		0xCCDFA195DD9A7DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7301BA767DB4E8EULL,
		0x76F1B6345BB40620ULL,
		0x8AA544EE992A1E05ULL,
		0x397B87DD19D18FA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C2B24CA2D277926ULL,
		0x87501720B7647626ULL,
		0xD37ED2663A972146ULL,
		0x247DA34DF4F2479EULL,
		0xCCA175D575053138ULL,
		0x2D98D4BA0FE2CAB2ULL,
		0x074B0DD3EB17CDA6ULL,
		0x2E14772CA3B38A66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC22A2798BECC86DULL,
		0x4BFFAABF130E8CB0ULL,
		0xE8A2DFDB201FA7F1ULL,
		0x7B8753EE4198D2C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00658EB38DD43C8AULL,
		0x6422E761C4FC9F55ULL,
		0x7EB35CE26D14726DULL,
		0x375E869F9B612BB5ULL,
		0x79E01250ECF1A6C3ULL,
		0xA5E119AF371AD325ULL,
		0x8638B2A36551FB26ULL,
		0x90C4BF38AE0DCD4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17A846B6B9B300ADULL,
		0x038CB763F2F7F6E5ULL,
		0x6B1DE123773FBA2AULL,
		0x3492E909716DA55DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2951704FBD5ECFFAULL,
		0xAD321DBBF984AD4DULL,
		0xF89C4F28BBC01961ULL,
		0x33162B2575B23B18ULL,
		0xC7FE194C4E50DC63ULL,
		0xD0F580D3BFF22D8CULL,
		0x1D99136813B2B5DBULL,
		0xB9BBCA750B8261BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD90931A35D5F8AC1ULL,
		0xB1A33D2A77777032ULL,
		0x5D55309BA8471802ULL,
		0x44F638852B0CBD77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CB403DE5BDA0539ULL,
		0x029C2306AA4BEDAAULL,
		0x7F4D43975433CD22ULL,
		0xB78BEF45DA8ED423ULL,
		0xC41B8815453A6A27ULL,
		0x0E99A3FED4E2B867ULL,
		0xD56F1C4320443D2FULL,
		0x38AD136DDE3B589AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58CA3706A285C859ULL,
		0x2D6A7ADA43F34D11ULL,
		0x2DCB758E1E54E21EULL,
		0x213CD194D75DFB1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A3D238D79D8863CULL,
		0x728CB35DBCEF7A84ULL,
		0x980C719BD57E7E7CULL,
		0xD51AC231724EFA20ULL,
		0xFA1AA0C95C1B2C82ULL,
		0x3492380ECB26FA65ULL,
		0x62E84B5AA4E84BE9ULL,
		0x9F44B02B3550DAA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A31017125E12518ULL,
		0x4041058FE4B8A5A7ULL,
		0x4687A1104FF9C31AULL,
		0x794CE89B5C4F6F45ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC7B3934B8B2EE1CULL,
		0xDFA86F3927610DEDULL,
		0x3BAA32C63EBF2EF0ULL,
		0x6A9A3598B9AAD9FAULL,
		0x17831FA47EAFAA0CULL,
		0x68C1F13EE1691B1EULL,
		0x8E8D320BBE9F3BE6ULL,
		0x7D3D6B81D4C3A676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F1EB9F86C62EB6ULL,
		0x6C723E8E9CFB1465ULL,
		0x649FA0848A621324ULL,
		0x01B82ADE4EB58F93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAF38E513B79755CULL,
		0x9A57FDD30ABDFB3FULL,
		0x2D05359F97F2DCC2ULL,
		0xEF409A1929EAC0C4ULL,
		0xD3858456335FA175ULL,
		0xFBD815B61BFEF774ULL,
		0xA4E3B3E9DD7E2A10ULL,
		0x5C8BAF80A0C314C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C5331CDBAB6EE1ULL,
		0xFC6B36DB3296B697ULL,
		0xA6D1EA5678AD1B47ULL,
		0x2BFCA73106DFD666ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A5470BA5D502332ULL,
		0xD7594C17A8F6D861ULL,
		0x5E4E2777E524626CULL,
		0x8DC504A23C95F5CEULL,
		0x31EF8ECDF170604CULL,
		0xC1C13C5F48109F1AULL,
		0x32367D16177ACB33ULL,
		0x4D638A415825282DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E3A34C33FE7042ULL,
		0x9A08423C5B6E7645ULL,
		0xD264B8BF615E8C1BULL,
		0x0A8B8A555219EC83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5E794E131CDFEBFULL,
		0xBB99CDBD6A6D53ADULL,
		0x77F14CC7B0485F94ULL,
		0xAC2551F5D20E70C5ULL,
		0xA388604CEF066784ULL,
		0x02C89E7218554D1CULL,
		0x0E7CC4BA8E2AC79BULL,
		0x753EAFB93D6C9EE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C25E04CACC15F03ULL,
		0x256152AD0716C5EEULL,
		0x9E768078CAA20097ULL,
		0x13736774F02E06C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x046CF18FCE33A2BEULL,
		0x0D30B6F32B54952EULL,
		0x38E113EE7BD93995ULL,
		0xA37E332AF77A6F6BULL,
		0x72E74239AB70A2F2ULL,
		0x403CD0B70BA44AE0ULL,
		0x3280AF29153B7990ULL,
		0x2FA2BD5630963013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C0C61F40EBD3C7ULL,
		0x9637B21EE5B7B27FULL,
		0xB7FB1407A2AD44FEULL,
		0x35A64DF62DC59244ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64A7E5B6C02DB09FULL,
		0xAB3DC893E1A867D5ULL,
		0x9F56CE4264E6115FULL,
		0x389538AC735517B7ULL,
		0xA1CB431D96A69BE4ULL,
		0xF8854EC3A467CFC9ULL,
		0xA0998E1B52BBE091ULL,
		0x18E9C6C8AF6AEDFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D3DC1B1CE8D4FCULL,
		0x8F07799E49113FC3ULL,
		0x7621E650ACC9670AULL,
		0x6B48BA767D346B37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3C9D0D63DD4D2E3ULL,
		0xFF1234ADF0AD60D2ULL,
		0x0A9DA63DB8F5F1DDULL,
		0x37C794B9F8191531ULL,
		0x41BA1980B4300852ULL,
		0x9A8AF2DF37F9DD62ULL,
		0x3B2581BEE15A77C6ULL,
		0x98434373F98E8D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56999F0FCF61266ULL,
		0xEFB241D03FC43D68ULL,
		0xD22EE8932C63B958ULL,
		0x51C397F103420385ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAD2ACB57F5AF1E6ULL,
		0x1DE78F5FA802FA39ULL,
		0x43697F14BACA648BULL,
		0x93E28B7DC7DC5B13ULL,
		0xE31663C1255CA744ULL,
		0x5A17B48C24C7011FULL,
		0x78DB84E51AB12DE9ULL,
		0x92D03F7C2B816B28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0257B610B1BC942ULL,
		0x7D6C5C2D1D8D24F5ULL,
		0x33FF3916B117352EULL,
		0x5ECBF7EC3D124315ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x038D9F0D04C50A32ULL,
		0x42C34C863C97EAC4ULL,
		0x661142CABEE8B5B7ULL,
		0x0457255C8E020434ULL,
		0xE34D5868FB1B941FULL,
		0x80B408082BA3A405ULL,
		0x565BB7E7FFA11983ULL,
		0xE96FFC388B20BB9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC108BEA24ADD0BEBULL,
		0x5D7C7DBCB6E243A3ULL,
		0x37AE8F3AB0D27F3CULL,
		0x2AF695C134DDDD1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DA14487AB58ACD5ULL,
		0x34D7D7C7E7DB81A8ULL,
		0x18A044070141C721ULL,
		0x08B092E955F9809DULL,
		0xE403B2CFFE9F8927ULL,
		0xB516B2A8C6FAD6F1ULL,
		0xA66CECA0A3433670ULL,
		0x3AD8380C73D2D7E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062DCF67770709E2ULL,
		0x16365CD571176990ULL,
		0xCCCB63DF3D3BDBDCULL,
		0x44C8E4C287458C41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99CC27B8DD0FFD07ULL,
		0x7956064E0C82FAF9ULL,
		0xD44D251A7353A0D9ULL,
		0x8CD82DCC5F0EA784ULL,
		0x1CB95FE592916B69ULL,
		0x0AEE03157572B779ULL,
		0x4D0F95C592BB37A9ULL,
		0x7092A586FB6682B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD5063CC9EA5F123ULL,
		0x18AA7B7D7B8A36F3ULL,
		0x449D606E3B1DE3F1ULL,
		0x429CBFD5B0460F06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62C80066169BC255ULL,
		0x0D97B107C3578C9AULL,
		0x62803E3F000D5D9DULL,
		0xFE0F86DB09A599C4ULL,
		0x212B6F3538198D09ULL,
		0x15512323C6CF557BULL,
		0xF658E3B8BE09CAD4ULL,
		0x64B9FED957A3CDF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3A824C6A66B3F8ULL,
		0x37A2E857461E3CE1ULL,
		0xF3B20BAB35817918ULL,
		0x71AB5B1E0BF62CB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AE938872D6B3B01ULL,
		0x918D046161C634EEULL,
		0x6B56991E261B3139ULL,
		0x5C6C40998C98E588ULL,
		0x5E793FCF0F30EF27ULL,
		0x6980FBF7047F9F6DULL,
		0x43663E2DE09591AFULL,
		0x4369FE2CFC2BA544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90E8B1436EAEBC47ULL,
		0x3AB26B0C0CB7DF2AULL,
		0x6C83D3ED7C4ED143ULL,
		0x5E27FB46FB136DAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3175807227782375ULL,
		0x58DB93E92E0AE3C4ULL,
		0xD5E0245954267BF7ULL,
		0x10520EC458F3D8B5ULL,
		0x096CCA4E8F4FF34CULL,
		0x92B19BA8188BE2B0ULL,
		0x387DBE6B016455B1ULL,
		0xE53E342A9027F52BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979B881B6D5645C9ULL,
		0x1F38AEDCD2CE89E5ULL,
		0x388A683B890B3453ULL,
		0x178DCD15BEE23D20ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F1746D68BA91536ULL,
		0x2171BDD10120D05EULL,
		0x437C633316F46E1AULL,
		0x5FF3FB8289E36471ULL,
		0xA876DAC93BEF9250ULL,
		0xC4E394AB383F027CULL,
		0xB3DAFC46E63585F9ULL,
		0x7ACD80C0E139D067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BBC0B57138CFD5ULL,
		0x5B39CF3B5A7B2EDFULL,
		0xF5FDD5B942E6512DULL,
		0x1A751823F87853D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E178FB61954F292ULL,
		0xF785692867115CC9ULL,
		0x96B3BD067CD09B28ULL,
		0x92208D13B13310CAULL,
		0x09289BFEC096331BULL,
		0xE6E66C2E7F41CF56ULL,
		0x49687D8DD419D9ACULL,
		0xBEBFFBD8629D8D59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1EB786AFA08CCFULL,
		0x3DB9780F4AD6238EULL,
		0x7C366013F8A6EAD3ULL,
		0x629FEF3254960C0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78EA98DD0EA6313CULL,
		0x98EDBBC1832418D1ULL,
		0x733542EADC866829ULL,
		0x38DB37B215204130ULL,
		0x6CE6D14FF072B7F3ULL,
		0x0F160F0DD5A991E1ULL,
		0x409D985F5505CFA3ULL,
		0x17C311C1BB109A32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA32DAABABFAD7FD3ULL,
		0xD633F7CF3A4FC047ULL,
		0x0A99E1117B633A5DULL,
		0x3FCFDA73D99724A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35B419400EB866C0ULL,
		0x4A2097CB5E410933ULL,
		0xD3D45F5C921A31CAULL,
		0xEFDA12E1D100C299ULL,
		0x8D60470046B7D841ULL,
		0x50CBD684AB3420D5ULL,
		0xAEDDFC955D343901ULL,
		0xC38CCBBA1B331227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31FEA34A8E0284C7ULL,
		0x48626F7CC7FDE8E6ULL,
		0xC8C7DD8867DAA7FCULL,
		0x76C05081DA95747DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FACAD850EBDEB9BULL,
		0x911561B85FF7AAF4ULL,
		0x3C4C303B7313C5EAULL,
		0x85F022578D55D110ULL,
		0x74D454565A3048C7ULL,
		0xF116FE5CF12F1086ULL,
		0xF0114CDB019C4E4EULL,
		0x4BBCC77D4A2E0EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA731325671E8BADAULL,
		0x5A7F23842CF41EE9ULL,
		0xDEDD98BDB04765A2ULL,
		0x43F5BEF0902C0627ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62513964599B1418ULL,
		0xE56AB3E8C30536E6ULL,
		0xBD572202AEC4A0E6ULL,
		0xDEEA656ACB453493ULL,
		0x012805E4242C7C79ULL,
		0x96AE34D08EDFE811ULL,
		0xEB846A7641A3C69EULL,
		0xDF0E230E6DBE7318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E421941B8359307ULL,
		0x43468ADDF841A96CULL,
		0xB2FEEF906D141C71ULL,
		0x7B03998F158A4A46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE38B92736B8F01B5ULL,
		0x405219955BF94ACEULL,
		0x3E3B6AB941032586ULL,
		0x74664DC6D8C760C9ULL,
		0x634F1B209D0AC779ULL,
		0xADE5DEE107E7CC35ULL,
		0xCBA2CE558B79758FULL,
		0x77A94226A4DEB99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA149994ABB28A057ULL,
		0x10712EFC88619ABBULL,
		0x78660B6BF50A98DAULL,
		0x37861F8351D6EE35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE46CA98B431B1A60ULL,
		0x7D28853905F71DF2ULL,
		0x978D081AD9778557ULL,
		0x0761F234ED3A816DULL,
		0x05A9DF5E1ADF9582ULL,
		0xAD89A182A261B0E8ULL,
		0x35EFB94735051DE6ULL,
		0x27829E21D842B73EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA3D183404B4C7DULL,
		0x3F967E9D20776063ULL,
		0x992288ACB839F595ULL,
		0x64C56B3B0721B4A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA096EC9A4D72B4A2ULL,
		0x9D32B32B61431196ULL,
		0x9BB588353A478917ULL,
		0xA50137343680455EULL,
		0x075DC97E965AF73AULL,
		0x87143B00BF578DCEULL,
		0x813CA37BC1B0F672ULL,
		0x53F19A2E885B6B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB882D5649EF3692CULL,
		0xAA337547C8421E2BULL,
		0xCAB5CC93FA8C1E17ULL,
		0x1ADE1A1C741230A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80E0F0F3DC34930DULL,
		0xBA7C9CBBE4E305F6ULL,
		0x72C32293A2C6DAA2ULL,
		0xA8FEEBB5AA3D20D2ULL,
		0xF09C280ED1C6DE75ULL,
		0x61E69F7485EB677AULL,
		0xC019F8663230AED5ULL,
		0x44DB831F65315D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x380EE326FFB999FAULL,
		0x42B84807C5D46236ULL,
		0xF69E01BF1600CE4FULL,
		0x6194625EAF910156ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAB4DC13A0846673ULL,
		0xB36ADF9CB274D63CULL,
		0x960669CBE289875EULL,
		0xA207707BFDAE02BBULL,
		0x1A3F717AEB2E3AADULL,
		0x3909893BA0832B2DULL,
		0x7072500560DCF1B8ULL,
		0x44C1DA23AE2850F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB01FB45289611DB0ULL,
		0x2AD53E7685ED3EEEULL,
		0x46FE4A98435568B7ULL,
		0x56CDD1C7D7AA0750ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC086502C9B9A3C0ULL,
		0xB942A47C3DE98CE2ULL,
		0x0D60D618AACAD1D3ULL,
		0x9BA6E6C279BC12CCULL,
		0xDAF687F6D1294BCEULL,
		0xE8113F686875DECEULL,
		0xFF569894C7F7A373ULL,
		0x91CB6EA4C6D9ECACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CA093A5D5DAE798ULL,
		0x2BD20DFBBF689F97ULL,
		0xF43B7C2E598D1508ULL,
		0x3FD95337FE153479ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD534A00327928A16ULL,
		0xD1F824D689D9D284ULL,
		0x4E76D4B2BE971A49ULL,
		0x8CE3C6A902A48769ULL,
		0x8BA30705702DECEDULL,
		0xB79E57BE8E0B8949ULL,
		0x07839A20CD02DF2FULL,
		0x358A7D51D6936C59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F67AAD1CE63B674ULL,
		0x13792B1F9F90336FULL,
		0x6BFFB5912D043B5FULL,
		0x7F7260CEDC869CA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C37AD2477D0D11FULL,
		0x88931C9F5B4E26D8ULL,
		0xE7BE7150FEBDA9BDULL,
		0xE8BB14FD8315AF0CULL,
		0x24D47BA1E799A47DULL,
		0x5E1DD6CB44732809ULL,
		0x551CEFC4118309F8ULL,
		0xA56FE337600D9998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C2072CD89F3F63ULL,
		0x8100FECB84661834ULL,
		0x8A0A086B9831249BULL,
		0x7756CF35C51A7BA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B9B6087640A04D9ULL,
		0xE13DB2ED94DB3CB3ULL,
		0x6458F770AF44C960ULL,
		0xD3353A62556DB632ULL,
		0x56698D6653F1C8B0ULL,
		0x2B69529DFA089F75ULL,
		0x37BAC7AFBE80B55DULL,
		0x44F2EF354D0855E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F465DB7D9EDD09BULL,
		0x52DFF660B222E81EULL,
		0xAA129B86F65FB535ULL,
		0x0F44BC4BC4AA75A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24C09A8BEEF590A9ULL,
		0xDFC365DBB84CFCF9ULL,
		0xDB24F079F237B747ULL,
		0x12DD59A0A7E551E8ULL,
		0xBBC9DA4B45132BBAULL,
		0xAAF95B1C45BA0546ULL,
		0xFAF104D7969FC1A8ULL,
		0x43398F5FC9282D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04B701B82FCE0FC1ULL,
		0x40C6EC0E11E9C579ULL,
		0x1AEBA87A4DEE7651ULL,
		0x0D68A1D883DC000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6215CD15B5F76FA4ULL,
		0x104E54F3C170CA62ULL,
		0x01C6DFA34D4E5B05ULL,
		0xECC909CC199258E2ULL,
		0x232472B21A2E762AULL,
		0xA4F107C0CF47DE21ULL,
		0x43CB2CC8890103F6ULL,
		0x62514953E6F4DE73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x997ED38598DCFC2DULL,
		0x8C157B92861BC34DULL,
		0x11EF8567A374F1A1ULL,
		0x04D9EC4061EB5DFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFFE80B371C17208ULL,
		0x3C1BB7A516317F18ULL,
		0xAC7E87924238A6F9ULL,
		0xA18EF6719827F78EULL,
		0x998EE82E15B6A4D7ULL,
		0xCAD0417E5929EB0AULL,
		0xF4AE39D31038CB1BULL,
		0x29AB8F3504615878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB34F78AAADDEAE9ULL,
		0x57057066526A62ABULL,
		0xFE5B1CE6AAA6CD19ULL,
		0x510638503E9B1982ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C916C97C8186A5EULL,
		0x2C777EF453E8A183ULL,
		0x2189FD87CA75A3BAULL,
		0xA3628844ACBA3A5BULL,
		0xCB25A6A6B6A42EA4ULL,
		0xF27010F4FD0329C9ULL,
		0x809918215FEA126DULL,
		0xD8203B55DCA4B8A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4282956E4775B89ULL,
		0x291A0351E260D577ULL,
		0x3843927C0734600CULL,
		0x382B57036D2DA2ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D2D3FF00F49C423ULL,
		0xF8B9D4948758DF2CULL,
		0x634D81C1F6953179ULL,
		0x783015FC1FCAE6CFULL,
		0x528127049DB1855EULL,
		0xD1D127947C3DA364ULL,
		0xE6B5FA55B3ABD597ULL,
		0xF966BD113319FC6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C590A9F77A39595ULL,
		0x1DC5B49EF87F2010ULL,
		0xA250AA7AA216E603ULL,
		0x7D702689B5A65EF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x497B0A16A5BE5D51ULL,
		0x7AB11F825A9B2411ULL,
		0x06F59D15EE373B49ULL,
		0xBE9FB01D460AD9AAULL,
		0xF7C45F2C555ECE5EULL,
		0xE3FE8EFC4CA55918ULL,
		0xF171D51C0DEF7381ULL,
		0xA2F42DD30D4A1597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A12AAB51D102E8ULL,
		0x527A58F5BB265DC6ULL,
		0xDDDB3F3FFFC26091ULL,
		0x6EDE7D713F0A0E37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13CADBEDF255FAB4ULL,
		0xB0148F7E51120CFCULL,
		0x08C3340066EC790CULL,
		0xC1481067592D999CULL,
		0xC7F229277D7F3CB2ULL,
		0x96948E606F63B0D6ULL,
		0x3376768B9F130C6FULL,
		0xC9A48E91684E687EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BCF7CA933901A7ULL,
		0x0A21B1CED9DE4CDDULL,
		0xAC58CCBA03C0519DULL,
		0x2FB539FCD4D11C57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04A980929396DC5DULL,
		0xC6291CB5A3FEB985ULL,
		0xDF1730399E0E6F32ULL,
		0xE43084B1C99E18B9ULL,
		0x8F62A357B2AC9AEAULL,
		0x8FE91144CD2ACEC9ULL,
		0xB3C41FCC08D0411AULL,
		0xBB2B65BA3CB2166DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4DBF971935DF54ULL,
		0x22C1ACEC18596B70ULL,
		0x8E33E882ECF81924ULL,
		0x2CA19E56CC0D6D02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x845D12EAFD9773A1ULL,
		0x1C4993CCEB9FEDA5ULL,
		0x7CBBA7E93755623CULL,
		0x32D9BB51216052EFULL,
		0x842CCD70FB30B8A6ULL,
		0x413E781D2E9E0E01ULL,
		0x29F66BBE67ADDD4EULL,
		0x12B6FA51AF6CA6BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230391B046D2DCA4ULL,
		0xCB8F6821D71601DFULL,
		0xB74FA62C9B243BD9ULL,
		0x7A02E3712B8112DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x352C7B2D6E4F03F2ULL,
		0xD06EE251CAC28AE6ULL,
		0xEA186AF79A0152BBULL,
		0xF1377F73D7951591ULL,
		0x5FBE6769A3F81A53ULL,
		0x53B9E468918E2E8CULL,
		0x3BA9EE109163025DULL,
		0xAC39AE9958FFA63BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6FD4DBC522F033ULL,
		0x3E06C9D765DD73BCULL,
		0xC551C16D2EB3AC96ULL,
		0x01C76A370D87C25CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D85CF470A8DC12FULL,
		0xCCA492A15AFC304CULL,
		0xB12F655251C18C2FULL,
		0xAA5442E7585F136DULL,
		0x0596182D73B580C6ULL,
		0xB9613EF507BD75C3ULL,
		0xC26AB923911FA091ULL,
		0x9DB6BDEB287151DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41CD6606377EE223ULL,
		0x5113EB00811BAB3FULL,
		0x8D06E099DC7361D1ULL,
		0x137473CF59313A7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D814EB29F399CF0ULL,
		0xC69C834A3613FB71ULL,
		0x757C703B92C91B13ULL,
		0xB17D72ABB9C7EB34ULL,
		0xC91458C97CF10D88ULL,
		0x5DDE4DBF060DA1B2ULL,
		0x59853F115054E8D0ULL,
		0x097438C846019F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06867C9B2B019F6CULL,
		0xB59C0DA51C19FBFBULL,
		0xBF43CCCD7F63AA01ULL,
		0x18BDE0661E058671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78CAFEA88AE0BBAFULL,
		0xB549A56BEB14A656ULL,
		0xFEC93F4534A9A671ULL,
		0x4713ADDE938A0839ULL,
		0x3BED5774BC948B41ULL,
		0xF0B7DF8024975D68ULL,
		0x9AFD5CF1113B0AD7ULL,
		0x9D64E2A7368DB16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E05F9FC88ED6AD2ULL,
		0x7094D271598C83CFULL,
		0x00650B0DC36D427FULL,
		0x240D52B0AC925E0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x336C645B95736B13ULL,
		0xC04F758BB758B79EULL,
		0xA20502A7132F82F7ULL,
		0x8244DD42740817DEULL,
		0x82DA935275F7FECCULL,
		0x76D742F821DCACF1ULL,
		0x40EB9492F476AF33ULL,
		0xFB752039FABCD75AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FDE4299184342ECULL,
		0x64436660BE1A6377ULL,
		0x44FD10775CCD849BULL,
		0x55A7A5DDAC100F44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33EC5965EE81ACABULL,
		0xA34968B77D27F65FULL,
		0xEDDB18CFEB58874FULL,
		0xB1ECEA2622DB0A27ULL,
		0x733560988E62BF21ULL,
		0x8D6192498E58E794ULL,
		0x69A1C8921F89E2DFULL,
		0x9D03F34C5C62C52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD8B00B112A0F21ULL,
		0x9FC51FA29E5A5668ULL,
		0x9BDEDE8099D0347EULL,
		0x0083077BD9844EBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6714B1D9BFEA3B57ULL,
		0xDD4F683902927B1BULL,
		0x029027ABD761D143ULL,
		0x45A637599224EF6DULL,
		0x582D8FE58B7FE433ULL,
		0x940157376B747D9BULL,
		0x269C5B8DC6CA60DEULL,
		0x1D33F8F8B6C1DFB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD80DEC74E61B94ULL,
		0xD5825A72F5DD202AULL,
		0xBDC5BEB7596C324DULL,
		0x1B5D2C44B2EC2450ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED03BBFB3F14CEEDULL,
		0x6B263608734A30E1ULL,
		0x816AA2951C7B9BD6ULL,
		0x3F65FE8158523213ULL,
		0x90DE38FEB458FCECULL,
		0xAE221CB30FF95FDBULL,
		0x3CC106C9686B6E2CULL,
		0xE02B8C07A43190B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0031CA044A5EEEULL,
		0x4436789CD24E6B79ULL,
		0x8611A47A9C6DF678ULL,
		0x05DCC7A3B7ADAD46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D5BC72313776B65ULL,
		0x29648E1471BB54A2ULL,
		0x9ABA4AECF5D165E9ULL,
		0xFA3A09290805616AULL,
		0xA91AB6A4580E5A2DULL,
		0x9AE7C15678469A80ULL,
		0xB3742FF97C8E52E5ULL,
		0xD34D014CAFBDAF2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5752E3882598D2D3ULL,
		0x27CB40EA4C3643BBULL,
		0x3DF969F572F1B3FEULL,
		0x57A83A8B1E2D61C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5770C617E0C91F3ULL,
		0xBE995158BA9E8061ULL,
		0x067B54F7BAE12B6DULL,
		0x610900FBAA0A625CULL,
		0xE207C2C33200FC46ULL,
		0x1BAEDA65B2791A3CULL,
		0x6A546B9E2B18D41AULL,
		0xF477A7A1AC8EE332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329DF55AEA3209C2ULL,
		0xDA8DBC713898656BULL,
		0xCF034E722090A74DULL,
		0x2ACBE2FB47401BD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6130C812489E1A4ULL,
		0x093AE988835CA72FULL,
		0x60B06DE368F5DFEBULL,
		0xB27F0252E0E06034ULL,
		0x0296CAEAB6A8F06CULL,
		0x3FDAA6E6E3086487ULL,
		0x92B34E9682964C25ULL,
		0xC3446140F7E6BC27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38752B58419D960DULL,
		0x83AFAFCE369B933AULL,
		0x274E183ACB452D72ULL,
		0x2EA571F7AD204E14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x510AFF6229606674ULL,
		0x6FD0F7DAB516D5AFULL,
		0x05F3A56E69FC6D24ULL,
		0x79005D1882916D6BULL,
		0xC6B01760B47272C0ULL,
		0x6E6C057C60CE5151ULL,
		0x867ACCA08C330C5DULL,
		0x3A8A9A3053078B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF2E77BCF25D704AULL,
		0xD3D9C85113B6E7D2ULL,
		0xFC2E054339904302ULL,
		0x29934044D5B01C1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA48961E1B7B2BB99ULL,
		0xF0F70FCA4E8F6EEAULL,
		0xACB8EB8BAE84BC96ULL,
		0xDFE40A46601F68DDULL,
		0x7851B6AE86D83D7CULL,
		0x59DD071DFECD2CF5ULL,
		0x09DAC2B4723DFA97ULL,
		0x8DB9CCAD9BE8BA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80AA7FC9BBCBDF32ULL,
		0x47C61E3E21041B5AULL,
		0x2331D254A3B7EF0EULL,
		0x69786C0B84AB17B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83B62A2358385024ULL,
		0x8CE22B2AB8A5F5D8ULL,
		0x56055D5D27A1FE79ULL,
		0x8800F615C31FEF58ULL,
		0x3FB986E03C0EC2E5ULL,
		0xB2201EA7E84CB8FFULL,
		0xA2F724F55FB704A5ULL,
		0xF87BE72E0D5A74B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9402F6C426943A0ULL,
		0xFDA6B81734096BBBULL,
		0x86B4D9C95CCCAF11ULL,
		0x6A6546EBBE8D4274ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x910D19CE9CA07C75ULL,
		0x81B332F22D81B7FAULL,
		0xB22173DA6FC40D47ULL,
		0xB5EC6186E96E0830ULL,
		0x6D8B3896D416F177ULL,
		0x1B626681EDD33381ULL,
		0x6865B0E72C326BF9ULL,
		0x9D153AE789BDAD1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3B78032180857AFULL,
		0x924E6A3B7ADB5D30ULL,
		0x3139B62AFF401441ULL,
		0x07131FE55B95BA42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C12FE8B34E4258AULL,
		0x7B84A17E2D17C01DULL,
		0x5F8DB2547E1A8B56ULL,
		0x8FFC7D35E3AA72DDULL,
		0x4E9EAC24F4993955ULL,
		0x3817845D18762D2FULL,
		0x2B0BA2BA48FF4F2FULL,
		0x707B262262EE2EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37A08C0783A2AAAEULL,
		0xCF02474FCEA27523ULL,
		0xC347D9FB54004C58ULL,
		0x4244265093055F87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1067495401976305ULL,
		0x0CE32A41AC440BB3ULL,
		0xB571646A320AAD85ULL,
		0xD24F472DCB55457CULL,
		0xD02E388DC4FF7D81ULL,
		0xDEBFFBCE0D6CE7EDULL,
		0x7189DE65D8D73E92ULL,
		0xCAA2D267E1F36006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF743AE5F3F8408B2ULL,
		0x1D628AD7AA6E78FFULL,
		0x8FE8678861FDF752ULL,
		0x667A829955758671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74025ECD57A6B363ULL,
		0x6DAE38B116C35811ULL,
		0x7898BC89D11B520FULL,
		0x665BAEFA7E08BF30ULL,
		0x2216F6DBC045485DULL,
		0xDE5C46029D22AD36ULL,
		0x11D5E28AEA126E7EULL,
		0xE33E5D616DC25E85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x836B036BE1EF763DULL,
		0x6F609D1469E90E1AULL,
		0x1E585D288FD7B8E4ULL,
		0x219D8B70C8E2C6F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CCF2C6B3EA983FBULL,
		0xB1F739946E933972ULL,
		0x5EC4E2D5E5BC2C7BULL,
		0xDBFF2D35F4E2DCA2ULL,
		0x180BD89B9D36FE0EULL,
		0xA0F918E0B8EC1F33ULL,
		0xB1A51A5A4C53D6A8ULL,
		0x1788BB9FA43F7FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE91538494D33AA7ULL,
		0x96F0EAEFE19FDB07ULL,
		0xBD46CC3D3A2E0983ULL,
		0x5A4B06E8564FD090ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x906AA6621AC911E4ULL,
		0xDD6CD00EDBC2D7AAULL,
		0xF8A41F5D96C827B8ULL,
		0x9C02857CD6E11C88ULL,
		0x33785C20436CBA5AULL,
		0x1BAE9506A15C7E0FULL,
		0xE5D0C61C8E48F268ULL,
		0x3C8176A271647648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3448532C1CECBCA9ULL,
		0xF956EF0ACF7D8DECULL,
		0x15A1879AB59C232CULL,
		0x173A2199ABCAAB5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0426ACA7FCB5012FULL,
		0x6860EB9792FF4C23ULL,
		0xC4EF0C6C3DFF8141ULL,
		0x34238FAAEC967927ULL,
		0x9B17B43BC9E2AB69ULL,
		0x9FF4E2A3D8BAB12AULL,
		0x0B646C642C9ABF43ULL,
		0xE35564DBE72F50DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AB6D87F45A77BEULL,
		0x26BA8FE9BEB59876ULL,
		0x75D7234ADCF7E54BULL,
		0x72D0884F3D9C7985ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A237695F0406A7BULL,
		0x57F3EAFE98B09D18ULL,
		0x4585AA2E764C973AULL,
		0x778D08BFB777E9FAULL,
		0xDCB5518565B693D2ULL,
		0x9FE829E8D5935AF0ULL,
		0x9B461A214507ABDFULL,
		0x981DFEE27DD5F6A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0D9063095A5F11ULL,
		0x146A238E4C901CD9ULL,
		0x51ED8B1EB5701A6CULL,
		0x0C00DE5E653A8701ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21213E744DE376C9ULL,
		0x3FBB2C1AD3C9F106ULL,
		0x8CD41E28FF24E849ULL,
		0x0D0BFF055FDD134CULL,
		0xC61382D733CE57E2ULL,
		0x93E5E944B1ECE6ACULL,
		0x99197E89D5DFABC2ULL,
		0xBBE24D4173A6E0A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8806AA65FE84866AULL,
		0x33DBCC4D3CF42EABULL,
		0x469CE69EBE58672BULL,
		0x70A376BC8AA26C07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C70B7F323E26443ULL,
		0x02FE2C8CAFB2B8C9ULL,
		0xA9B19D55FBB3F8BCULL,
		0x62455D125D892EEFULL,
		0xEB5587C6D0C78D4CULL,
		0x01AD9622C23FE15DULL,
		0x56CECF8545BCE7B7ULL,
		0xCC2ABFD6C797CBCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B22DF7621816212ULL,
		0x42C275B5852E2CBAULL,
		0x8C646B1E55BE5DE6ULL,
		0x309DD6F3FE116F1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE69B8B19CFE3EF1FULL,
		0x7C06AA4E0CFF1CD8ULL,
		0x9B5D11418C3F7892ULL,
		0x4CA5A2FDAF85C062ULL,
		0x1E1229C160799ACCULL,
		0xD613586776351186ULL,
		0x0584F33CC537D27BULL,
		0xB21DA6E7CE0F7BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D4DBDCE21F0ED56ULL,
		0x42E5C9A998DFB6C1ULL,
		0x6D192C46D288B6F4ULL,
		0x3D0C696645D21FEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36CEF97D3EAE3F4EULL,
		0xA833E4DE80978CDEULL,
		0xBD77BD5F3D4C079FULL,
		0x95A24B807135609EULL,
		0x09DE7A376D5159FCULL,
		0x7F47750A342724E4ULL,
		0xFD52C3C14298E16FULL,
		0xA129730595F56F9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD51DB778C19E59ULL,
		0x8CCF44623E6706B7ULL,
		0x57C0CC0F1FFD7E2CULL,
		0x01C95E54B3A3F1A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28EF306357FB0089ULL,
		0x3BEA48367088C4A6ULL,
		0x58A4B0B8B69E8A8DULL,
		0xAF3B623B5553BB3FULL,
		0x75EE4E41F733D50CULL,
		0x23FAFCF3C4EDD732ULL,
		0xBFD796BEF642B6CAULL,
		0xA7BF27C7F648695AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4ECE2E09ACA41AULL,
		0x932BD465ABD6B623ULL,
		0xD2A511114485AC8EULL,
		0x159B49E9E4135EB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B487AAE4921C9ADULL,
		0xCD5D43C2E67DF608ULL,
		0x3E7032C486642100ULL,
		0x6261FBB34E987875ULL,
		0x2C4FC46020758B77ULL,
		0x8C64A1088041FD69ULL,
		0xD32592D247EA2514ULL,
		0x7E05727CCABEC110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1FA0F31A948029ULL,
		0xA44D2B05F04993A5ULL,
		0x9603FDFB3325A20DULL,
		0x1730FA3966E920F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3825412C2F56EAC9ULL,
		0xE492ADF05C4B88F6ULL,
		0xAB9ED4909FBAE6B5ULL,
		0xD4D17CC61A9742DBULL,
		0x48570CFD7D6E5C43ULL,
		0xAA690C24A4DBD46DULL,
		0xA999A69EF5C0B64CULL,
		0xDE4ED802006E9C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5112ECCCDB8A1B4ULL,
		0x302A7B60D4ED112EULL,
		0xD86D90291A55F617ULL,
		0x54858D122B027C2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA67B6B688FBFC528ULL,
		0x44C591D3F9D9CE05ULL,
		0x77917F48FF4D8CEFULL,
		0xDDD15C823BEAEABBULL,
		0xE8E37D348231A10CULL,
		0x4B4993D629941C05ULL,
		0xFE8A3F010EE1E95BULL,
		0x05AACCF0EE533BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38400133E31DAD29ULL,
		0x71B1839E25D5F6E6ULL,
		0x4016D97134D6307CULL,
		0x352BC8459C45C987ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24806EC8E4B04100ULL,
		0x0556D7501E52BC7DULL,
		0xC92F5FE8C26EE7C7ULL,
		0x427411655D55202EULL,
		0xAA005F3D4B1E78A4ULL,
		0x6BCE50C3395BADB9ULL,
		0x3F2D6111C3934CDEULL,
		0xA60F414132B29E0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x608E91E20B362CFBULL,
		0x05F6D44AA1EE860CULL,
		0x29EBC88BCA4C50CBULL,
		0x68B7C112E3D89600ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B3C2A2A9F10BE42ULL,
		0x39D69954592DE6F4ULL,
		0xDDE1641AF2B0B141ULL,
		0xD7BC63B69EB7A088ULL,
		0x53B2EBEFBA4C8DC1ULL,
		0xC62F61D5CE8BFBF9ULL,
		0x5E119F9DDB355A0EULL,
		0x12E4FB7F2F9A5619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77CB2FC0466DC96DULL,
		0xA4DF1F1101F54DF6ULL,
		0xD47F15897C9C0F72ULL,
		0x25B9B897AFA0684CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF5C6425F81FFB9ULL,
		0x655F26B49866426FULL,
		0x45599A83C5735D02ULL,
		0xAD2CD74B4D51B87DULL,
		0x93D3BE87CDA89068ULL,
		0xA40DF28A4DFF41D0ULL,
		0xD3C6F149C27F0533ULL,
		0x88D60AECE7466B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61640E6AE6877234ULL,
		0xBF71273C2C4A0765ULL,
		0xB4E16B76A44E22ACULL,
		0x7CF27675A1C5A0B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8F74E60640C1360ULL,
		0x4E8AA5A7CF94BA65ULL,
		0x5F9D560EA6B70867ULL,
		0x5714A240034892C9ULL,
		0xBFC88DC6ABD82D3CULL,
		0xF2EB0479F3309084ULL,
		0xFE1D4F19BA6FC3A6ULL,
		0x0D67B85259A1F66BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70BC59DDE622CA94ULL,
		0x5D6D4FC1E8CA2E1AULL,
		0x17F713E0534E132FULL,
		0x5479FE79515326D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C19DBA3A6B79911ULL,
		0x5CC89A5E0E93A3FBULL,
		0x36BF78ED83EE055CULL,
		0x3B435D77294E8224ULL,
		0x55F2B18B6B09020EULL,
		0x209010CB34F37E6EULL,
		0xB4E1AFA0FADEE4FCULL,
		0xA298AB5CE57038EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E2036558A0DEAB5ULL,
		0x322B1887EAB8685CULL,
		0x103F8AD2C10402C9ULL,
		0x5DECCD4137F6F5B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5287E92BF353CE4DULL,
		0xE07D0A5FB94CBB4AULL,
		0x1190060D26D46AB5ULL,
		0x07DE53D3F9626207ULL,
		0xC5237C37D6C57F99ULL,
		0xB3A522ABDF8A597FULL,
		0xE10898BDC537F345ULL,
		0x3F057E0FCE44B3FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CC5975D4A4C059ULL,
		0x8B002FE2E7D60441ULL,
		0x78D6B2386D22870EULL,
		0x62AF0A2C979519B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3EAF97B0ADBE140ULL,
		0x9B77ABBE5AFC366EULL,
		0x3D878DF7C55B453BULL,
		0x1BA5CC96850A3FECULL,
		0xD087A49DE7CB1C42ULL,
		0xFC3A6C4388DD0F9BULL,
		0x874AEB731B7F9D27ULL,
		0xD792FB0D6421B6C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB80D68EB730217CCULL,
		0x0C23BDC4ABCC878FULL,
		0x52A6810DDA4C992BULL,
		0x1B771093620B61D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE02A053152CE35E9ULL,
		0x90CCB5D936A9954CULL,
		0x9E8A9468E1D9B72EULL,
		0x1D4A7F2BB476C7F9ULL,
		0xA859F8D3D15617A2ULL,
		0xC961367B68CCEB6FULL,
		0x73FCB1CDCCAAFAE7ULL,
		0xF3D45D4FDD398DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD84F4A26595BD4DULL,
		0x753ACC2AC51487DFULL,
		0xD60CF8F5433AF596ULL,
		0x4ED059068B01DA8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FA042E70A52C955ULL,
		0xA77B1A8DCD534067ULL,
		0xCB380DB2379AA7B3ULL,
		0xFEC73F993DB4ED58ULL,
		0x37A458704E256EE2ULL,
		0x92B64D6D027344A8ULL,
		0x276FEFEA018E9B4EULL,
		0x161D878898C709ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52056392A3E13F79ULL,
		0x6E8A98BC2A6F715FULL,
		0xA5D5AA6E72C5B55DULL,
		0x47295DDFEB405CE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A810F4F0C43D3FEULL,
		0xD67D46EE2C4D2F9FULL,
		0xAA580B5765592CA9ULL,
		0xDD0EFAD0E47D1BD2ULL,
		0xDA86838CE1DE66FFULL,
		0xF971CEB64AA070CAULL,
		0xBB6E0B7D2DD16A80ULL,
		0x9B488294591EFB97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA78963893472155ULL,
		0xDD61F5FD401DEDBBULL,
		0x7CADBFEC326EFBCEULL,
		0x69D25CD61F167458ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0170904BDEE128BEULL,
		0x19FB3FAF01F4BEBFULL,
		0xDCF4E4CD85F6DBE9ULL,
		0x8E3E6270AE9645D0ULL,
		0x8C9C3E5A0F7A2CA2ULL,
		0xDCF6FD5FCC352EA7ULL,
		0x5520FB6936555633ULL,
		0x2B26C4C53BFA9630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A1D1AA2B03C9C1ULL,
		0xE6A4DBE751D9AB9DULL,
		0x7FDA366B96A1A79BULL,
		0x75FF97B795C890FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABDC9805F9EC8410ULL,
		0x6F6F17AE96F06BA2ULL,
		0x173759B8D1E503B7ULL,
		0x3E29AB4937533A72ULL,
		0x783D5CCDD7D91CE8ULL,
		0x5A44FAD96BBB31E8ULL,
		0xF35306E9DE1CE505ULL,
		0xC972FAB004F99B25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F85E940426D2F4ULL,
		0xD5AC53F494B9D424ULL,
		0x358A606FCA2F0282ULL,
		0x253AE169F4604214ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55ED79047284EE77ULL,
		0x1174442CC80862EAULL,
		0x7BF756FDB3BB2B39ULL,
		0xC2D1BADDB162B748ULL,
		0x6CCA1163C31323B4ULL,
		0x9FCA32AFC213C1E0ULL,
		0x1408E3340472B353ULL,
		0x8D25EBDBD89E0FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BEC0DD3675C3E60ULL,
		0xC977CA4396F72A3AULL,
		0x754910B65CC1C9A2ULL,
		0x3672BD7FD8D9136FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC3E0F1B3D09A79D7ULL,
		0x808D08FACECD1AEEULL,
		0x5BEAD6E743AD1BC7ULL,
		0x82B5FB4071B1B6A7ULL,
		0x205D9F95D0657647ULL,
		0x527C00C173AE7CB2ULL,
		0xCC42D9838D068E19ULL,
		0xE446ADFE405FF228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C6A1F0BFAA0D6DULL,
		0xBEF525B1FAB39D5FULL,
		0xADD7206E32A63389ULL,
		0x6533CEFDFFEFA8B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_compute_modulo(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}