#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xB7307063FE2F2486ULL,
		0xAA1E58E040F994A3ULL,
		0xA546348198AFC27EULL,
		0x6644C5010BBCA7A4ULL,
		0x706A637ACD3008C5ULL,
		0x356043F3A118A5E1ULL,
		0x032DBE585234FD57ULL,
		0x34CD94821987177AULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x6E60E0C7FC5E490CULL,
		0x543CB1C081F32947ULL,
		0x4A8C6903315F84FDULL,
		0xCC898A0217794F49ULL,
		0xE0D4C6F59A60118AULL,
		0x6AC087E742314BC2ULL,
		0x065B7CB0A469FAAEULL,
		0x699B2904330E2EF4ULL
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
		0x2415BC7431592155ULL,
		0xF757FCC0E573216CULL,
		0x660C973952A462AEULL,
		0x070E9073D213BFB3ULL,
		0x310E019A10DFC2DDULL,
		0xBC7BDDD9009C2341ULL,
		0x5C801DCE3351C88EULL,
		0x12AB3D64F6B13BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x482B78E862B242AAULL,
		0xEEAFF981CAE642D8ULL,
		0xCC192E72A548C55DULL,
		0x0E1D20E7A4277F66ULL,
		0x621C033421BF85BAULL,
		0x78F7BBB201384682ULL,
		0xB9003B9C66A3911DULL,
		0x25567AC9ED627792ULL
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
		0xB028DE266636FF5CULL,
		0xF98F3BF6F8791129ULL,
		0xABF6C6A5CCF8BAC3ULL,
		0xD1B4D43FECACD235ULL,
		0xF6368C37719391A2ULL,
		0x325545717ACE9223ULL,
		0x38BC785C3A8F2609ULL,
		0x117629C07C87099BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6051BC4CCC6DFEB8ULL,
		0xF31E77EDF0F22253ULL,
		0x57ED8D4B99F17587ULL,
		0xA369A87FD959A46BULL,
		0xEC6D186EE3272345ULL,
		0x64AA8AE2F59D2447ULL,
		0x7178F0B8751E4C12ULL,
		0x22EC5380F90E1336ULL
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
		0x15E83CAEFDBD22A1ULL,
		0x302EC54AFF789DAAULL,
		0x884D85C3B7C5E5EBULL,
		0xE641DF52B2DC0B35ULL,
		0xF80ACCDF7BAD9735ULL,
		0xCFC3B55C06C991B0ULL,
		0x455F39ADF1163B15ULL,
		0x06CBD835251FCAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BD0795DFB7A4542ULL,
		0x605D8A95FEF13B54ULL,
		0x109B0B876F8BCBD6ULL,
		0xCC83BEA565B8166BULL,
		0xF01599BEF75B2E6BULL,
		0x9F876AB80D932361ULL,
		0x8ABE735BE22C762BULL,
		0x0D97B06A4A3F95DAULL
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
		0x8A34025BF41289BBULL,
		0x74A60CF0A81F3A65ULL,
		0xEEE91FBACF10EBC7ULL,
		0x64878C03A9176812ULL,
		0x4F26951B4AEC4EC2ULL,
		0x3F5A7AEA205E1092ULL,
		0xE59242F9BC690DE5ULL,
		0x077569DD3ED4EB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146804B7E8251376ULL,
		0xE94C19E1503E74CBULL,
		0xDDD23F759E21D78EULL,
		0xC90F1807522ED025ULL,
		0x9E4D2A3695D89D84ULL,
		0x7EB4F5D440BC2124ULL,
		0xCB2485F378D21BCAULL,
		0x0EEAD3BA7DA9D737ULL
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
		0xA6CECD72E47AEBB2ULL,
		0x13641B6F21A734ABULL,
		0x45D278B19BE80FB2ULL,
		0xB98137D01DD3E169ULL,
		0x66115E25E4048CC2ULL,
		0x594882CEF1952C26ULL,
		0x9A92F346641587E0ULL,
		0x0BC8247DF2E04C6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9D9AE5C8F5D764ULL,
		0x26C836DE434E6957ULL,
		0x8BA4F16337D01F64ULL,
		0x73026FA03BA7C2D2ULL,
		0xCC22BC4BC8091985ULL,
		0xB291059DE32A584CULL,
		0x3525E68CC82B0FC0ULL,
		0x179048FBE5C098DFULL
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
		0xD7251A26A655C0D9ULL,
		0x1DFF73C4F271D739ULL,
		0x01A2829BEC15E765ULL,
		0xC40BB90046C32D11ULL,
		0x06D77D9ACDA383E1ULL,
		0x23289DB6172F2094ULL,
		0x4E1A2EF19D57B789ULL,
		0x0CD17A4197BA8BF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE4A344D4CAB81B2ULL,
		0x3BFEE789E4E3AE73ULL,
		0x03450537D82BCECAULL,
		0x881772008D865A22ULL,
		0x0DAEFB359B4707C3ULL,
		0x46513B6C2E5E4128ULL,
		0x9C345DE33AAF6F12ULL,
		0x19A2F4832F7517EEULL
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
		0x735C5D76F9D22BEBULL,
		0x4CDB9AB388BF29E8ULL,
		0x92B48DC80C466FD7ULL,
		0xC2B3C575FE97DD9AULL,
		0x39873B1E5BF958B9ULL,
		0x732D241A98C6E5A4ULL,
		0xE0B26455A2F1F2D7ULL,
		0x357B31681A4553F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B8BAEDF3A457D6ULL,
		0x99B73567117E53D0ULL,
		0x25691B90188CDFAEULL,
		0x85678AEBFD2FBB35ULL,
		0x730E763CB7F2B173ULL,
		0xE65A4835318DCB48ULL,
		0xC164C8AB45E3E5AEULL,
		0x6AF662D0348AA7EFULL
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
		0x4BE068A394F85B51ULL,
		0xD79BB1B26DB425A0ULL,
		0x17F9CBE23BC7F6D4ULL,
		0x625E11C32094C00BULL,
		0xADAF54B90A1DF77EULL,
		0xECE5EE34F0A37C4EULL,
		0x2B43FFFE18111286ULL,
		0x1B7CD91FB4BB92A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C0D14729F0B6A2ULL,
		0xAF376364DB684B40ULL,
		0x2FF397C4778FEDA9ULL,
		0xC4BC238641298016ULL,
		0x5B5EA972143BEEFCULL,
		0xD9CBDC69E146F89DULL,
		0x5687FFFC3022250DULL,
		0x36F9B23F69772546ULL
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
		0x07E19B051F9CB72DULL,
		0xC2691CD5BD1B956CULL,
		0x470632599EC55389ULL,
		0xB1AF0AB81C292E9CULL,
		0x60E6639682916D7DULL,
		0xF6CECBA88C2E328CULL,
		0x28B0AADAC54F1EB5ULL,
		0x0F92B15491459A99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FC3360A3F396E5AULL,
		0x84D239AB7A372AD8ULL,
		0x8E0C64B33D8AA713ULL,
		0x635E157038525D38ULL,
		0xC1CCC72D0522DAFBULL,
		0xED9D9751185C6518ULL,
		0x516155B58A9E3D6BULL,
		0x1F2562A9228B3532ULL
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
		0x692FF26E65044BB6ULL,
		0x4E5DA75A333EA9B0ULL,
		0xD965C2A62F83FA04ULL,
		0xBD3547F2D6CA0C2BULL,
		0xB7BBB478894A8122ULL,
		0x3C9AE426E692CA20ULL,
		0x8B1BCD5B6E6B829CULL,
		0x0CA6221F9983EFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD25FE4DCCA08976CULL,
		0x9CBB4EB4667D5360ULL,
		0xB2CB854C5F07F408ULL,
		0x7A6A8FE5AD941857ULL,
		0x6F7768F112950245ULL,
		0x7935C84DCD259441ULL,
		0x16379AB6DCD70538ULL,
		0x194C443F3307DF57ULL
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
		0x4C3DA80A8D05BC43ULL,
		0x1610D44A3FDA09C5ULL,
		0xE47F7F18E6A96B04ULL,
		0x2675ECAAAFFC967EULL,
		0x37360DFF6A28CA3CULL,
		0xC31ECF0442F11E8DULL,
		0x453D06377A467C4AULL,
		0x0726457CBC1F002AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x987B50151A0B7886ULL,
		0x2C21A8947FB4138AULL,
		0xC8FEFE31CD52D608ULL,
		0x4CEBD9555FF92CFDULL,
		0x6E6C1BFED4519478ULL,
		0x863D9E0885E23D1AULL,
		0x8A7A0C6EF48CF895ULL,
		0x0E4C8AF9783E0054ULL
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
		0x998FF3831C57923CULL,
		0xCED53BEB6DD2631BULL,
		0x78947BCBC6953857ULL,
		0x1508F4B41A8826ACULL,
		0xC105789DF67398F7ULL,
		0x1D1990467DB7FECAULL,
		0x3FBD96F8B6B5994EULL,
		0x27C892B65F1F641BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x331FE70638AF2478ULL,
		0x9DAA77D6DBA4C637ULL,
		0xF128F7978D2A70AFULL,
		0x2A11E96835104D58ULL,
		0x820AF13BECE731EEULL,
		0x3A33208CFB6FFD95ULL,
		0x7F7B2DF16D6B329CULL,
		0x4F91256CBE3EC836ULL
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
		0xEF61AF14023807C0ULL,
		0x2B04FBA5A760AD89ULL,
		0xFF823FD24D6DEACBULL,
		0x6BC4517E7903FDB1ULL,
		0x48D7D580332A6D31ULL,
		0xBF0F47BECA295709ULL,
		0x80098E982219225CULL,
		0x293F5492A903FA42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC35E2804700F80ULL,
		0x5609F74B4EC15B13ULL,
		0xFF047FA49ADBD596ULL,
		0xD788A2FCF207FB63ULL,
		0x91AFAB006654DA62ULL,
		0x7E1E8F7D9452AE12ULL,
		0x00131D30443244B9ULL,
		0x527EA9255207F485ULL
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
		0x8FD15E3A52070014ULL,
		0x1306E2EFBDED37EFULL,
		0x525748C62852BEC4ULL,
		0x48798F04075D3DA2ULL,
		0xBC329DAB48E01EA7ULL,
		0x261A40F2F2D77100ULL,
		0x0350FC3437F698FEULL,
		0x2B487B539DECD571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FA2BC74A40E0028ULL,
		0x260DC5DF7BDA6FDFULL,
		0xA4AE918C50A57D88ULL,
		0x90F31E080EBA7B44ULL,
		0x78653B5691C03D4EULL,
		0x4C3481E5E5AEE201ULL,
		0x06A1F8686FED31FCULL,
		0x5690F6A73BD9AAE2ULL
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
		0x44987CDBDBCE8478ULL,
		0x59BEF6BB95D40289ULL,
		0x29A80DF1A9E85B80ULL,
		0x5A795A8182A99A02ULL,
		0x1C21B9926688640AULL,
		0x67AA5BF9F51E57C3ULL,
		0x9DE83DD9299AD444ULL,
		0x1573B0EE7B734637ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8930F9B7B79D08F0ULL,
		0xB37DED772BA80512ULL,
		0x53501BE353D0B700ULL,
		0xB4F2B50305533404ULL,
		0x38437324CD10C814ULL,
		0xCF54B7F3EA3CAF86ULL,
		0x3BD07BB25335A888ULL,
		0x2AE761DCF6E68C6FULL
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
		0x07CA042164EB2C25ULL,
		0x236248BFE32DDF07ULL,
		0x51DC2AD780F2A6E7ULL,
		0x8DCE2F762882C4B3ULL,
		0x6FDCAFDAF843C073ULL,
		0x4A0CCE0B7E9578B2ULL,
		0x98E404418AE3D79AULL,
		0x2F74E921CE771C51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F940842C9D6584AULL,
		0x46C4917FC65BBE0EULL,
		0xA3B855AF01E54DCEULL,
		0x1B9C5EEC51058966ULL,
		0xDFB95FB5F08780E7ULL,
		0x94199C16FD2AF164ULL,
		0x31C8088315C7AF34ULL,
		0x5EE9D2439CEE38A3ULL
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
		0xB5C81AF935FB7848ULL,
		0x9C96945B06F2DA5DULL,
		0x9412A317BA333CA2ULL,
		0xF4C7A606113A4D41ULL,
		0xB67E22D87B16C7C7ULL,
		0x7328B42DDAA2C374ULL,
		0x8B31EB9F34578DCFULL,
		0x142C74DED023117BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B9035F26BF6F090ULL,
		0x392D28B60DE5B4BBULL,
		0x2825462F74667945ULL,
		0xE98F4C0C22749A83ULL,
		0x6CFC45B0F62D8F8FULL,
		0xE651685BB54586E9ULL,
		0x1663D73E68AF1B9EULL,
		0x2858E9BDA04622F7ULL
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
		0x954576D7CEBC2F18ULL,
		0x3A7C3A012326AF18ULL,
		0x80E15651D82D828DULL,
		0x4357874429E41E64ULL,
		0x1DF1B4E2D950592CULL,
		0xFD351D452ACD6C0DULL,
		0x2884FBE60029AEDBULL,
		0x154D722A1506E863ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A8AEDAF9D785E30ULL,
		0x74F87402464D5E31ULL,
		0x01C2ACA3B05B051AULL,
		0x86AF0E8853C83CC9ULL,
		0x3BE369C5B2A0B258ULL,
		0xFA6A3A8A559AD81AULL,
		0x5109F7CC00535DB7ULL,
		0x2A9AE4542A0DD0C6ULL
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
		0xF1B96193D59B351FULL,
		0x5A4A24B8174A3435ULL,
		0xCE49A04DDB491084ULL,
		0x8B7BEB6C081C9033ULL,
		0xC3095AFEDA7EE1E0ULL,
		0xE03857730B4A5BCDULL,
		0x6A262475B0B3902EULL,
		0x3948339F325BB04FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE372C327AB366A3EULL,
		0xB49449702E94686BULL,
		0x9C93409BB6922108ULL,
		0x16F7D6D810392067ULL,
		0x8612B5FDB4FDC3C1ULL,
		0xC070AEE61694B79BULL,
		0xD44C48EB6167205DULL,
		0x7290673E64B7609EULL
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
		0x99E719404B856561ULL,
		0xF5F083E155711810ULL,
		0x0836630EB9F8050DULL,
		0x5DDF6D616368FB8FULL,
		0xF3A90E4CAAA05C10ULL,
		0xCD77289850C779FAULL,
		0x21D2FE5236395FFBULL,
		0x050C10C04CC9AD6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CE3280970ACAC2ULL,
		0xEBE107C2AAE23021ULL,
		0x106CC61D73F00A1BULL,
		0xBBBEDAC2C6D1F71EULL,
		0xE7521C995540B820ULL,
		0x9AEE5130A18EF3F5ULL,
		0x43A5FCA46C72BFF7ULL,
		0x0A18218099935AD8ULL
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
		0x28AEC5E70C4E9085ULL,
		0x88D84EA2338373F9ULL,
		0x03B36974EABC0497ULL,
		0x94FE0A7BF7844CB8ULL,
		0xCBE5B085DAFAF6C7ULL,
		0x5069A226BB9BF3E7ULL,
		0x9E73B172290E9AEDULL,
		0x3F7739A53EA03ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x515D8BCE189D210AULL,
		0x11B09D446706E7F2ULL,
		0x0766D2E9D578092FULL,
		0x29FC14F7EF089970ULL,
		0x97CB610BB5F5ED8FULL,
		0xA0D3444D7737E7CFULL,
		0x3CE762E4521D35DAULL,
		0x7EEE734A7D40757DULL
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
		0x2873091CC2360508ULL,
		0x516D93CD2D9E8E8BULL,
		0xFA72D91D129A458DULL,
		0x017184BC0FA9991BULL,
		0x4CBC052BAC29B8BDULL,
		0x46307D5B50B2AF34ULL,
		0xC75497B86F40F94FULL,
		0x134C8FB5016E1C3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E61239846C0A10ULL,
		0xA2DB279A5B3D1D16ULL,
		0xF4E5B23A25348B1AULL,
		0x02E309781F533237ULL,
		0x99780A575853717AULL,
		0x8C60FAB6A1655E68ULL,
		0x8EA92F70DE81F29EULL,
		0x26991F6A02DC387FULL
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
		0x683741C83D7025C0ULL,
		0x918983A9AB65818AULL,
		0x64EFBCCC322F5BA5ULL,
		0x5200EBC1C145415EULL,
		0x1601BBC95798DF34ULL,
		0x9ABD4FD228D01B51ULL,
		0x8B76C29B1E39EF99ULL,
		0x3981A38AC9AC9945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06E83907AE04B80ULL,
		0x2313075356CB0314ULL,
		0xC9DF7998645EB74BULL,
		0xA401D783828A82BCULL,
		0x2C037792AF31BE68ULL,
		0x357A9FA451A036A2ULL,
		0x16ED85363C73DF33ULL,
		0x730347159359328BULL
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
		0x7E1882C1E3633B8CULL,
		0x8B3B19918F72E5A5ULL,
		0xBCA33AD065777215ULL,
		0x792A3DD3FACB89B1ULL,
		0xB72764A7743E04F2ULL,
		0x1FB7063B12703064ULL,
		0xD87F3338844C7C62ULL,
		0x009E030CE08EB4E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC310583C6C67718ULL,
		0x167633231EE5CB4AULL,
		0x794675A0CAEEE42BULL,
		0xF2547BA7F5971363ULL,
		0x6E4EC94EE87C09E4ULL,
		0x3F6E0C7624E060C9ULL,
		0xB0FE66710898F8C4ULL,
		0x013C0619C11D69CBULL
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
		0xCE1A30B243560EA5ULL,
		0x3BCCAB6FA25746B6ULL,
		0xB07258B4AE5871DFULL,
		0x8BD68863F0130850ULL,
		0xCD1C1C045F4C754EULL,
		0x7CB24A74461E9AA3ULL,
		0xF0CEAA2BE6F49C95ULL,
		0x1E7CD6E85A26089EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C34616486AC1D4AULL,
		0x779956DF44AE8D6DULL,
		0x60E4B1695CB0E3BEULL,
		0x17AD10C7E02610A1ULL,
		0x9A383808BE98EA9DULL,
		0xF96494E88C3D3547ULL,
		0xE19D5457CDE9392AULL,
		0x3CF9ADD0B44C113DULL
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
		0x8DB3ABE1C312DE9BULL,
		0xAB660DE6336252B1ULL,
		0xDC7BD4A86FB71E63ULL,
		0x7A9C1586DB43EC42ULL,
		0x4A54B6394E8FC7F5ULL,
		0x592B81E0148B445FULL,
		0x3E0CEB1EC193FD79ULL,
		0x348727DE9587E0E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6757C38625BD36ULL,
		0x56CC1BCC66C4A563ULL,
		0xB8F7A950DF6E3CC7ULL,
		0xF5382B0DB687D885ULL,
		0x94A96C729D1F8FEAULL,
		0xB25703C0291688BEULL,
		0x7C19D63D8327FAF2ULL,
		0x690E4FBD2B0FC1C4ULL
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
		0x2718FF785428EAEAULL,
		0x5A6C1A11FEEDD398ULL,
		0xFF1863C40BFEA83DULL,
		0xD3F665096A3D3BDFULL,
		0x8270F9D322004994ULL,
		0xA3CF0C99254561FBULL,
		0xA9F1113704CF2CD3ULL,
		0x00BC555046A79871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E31FEF0A851D5D4ULL,
		0xB4D83423FDDBA730ULL,
		0xFE30C78817FD507AULL,
		0xA7ECCA12D47A77BFULL,
		0x04E1F3A644009329ULL,
		0x479E19324A8AC3F7ULL,
		0x53E2226E099E59A7ULL,
		0x0178AAA08D4F30E3ULL
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
		0x69E78D98D9B1A21EULL,
		0x2D5E8D76A4AFD6A5ULL,
		0x83856B83CFA6ACDAULL,
		0x1CA978856105C5FAULL,
		0x7C5481A2F64BE1B0ULL,
		0x4363CD45DC47C4A6ULL,
		0xCE2FFBB7D53420F5ULL,
		0x34A52AEF6E82FF5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3CF1B31B363443CULL,
		0x5ABD1AED495FAD4AULL,
		0x070AD7079F4D59B4ULL,
		0x3952F10AC20B8BF5ULL,
		0xF8A90345EC97C360ULL,
		0x86C79A8BB88F894CULL,
		0x9C5FF76FAA6841EAULL,
		0x694A55DEDD05FEBBULL
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
		0x444A756E1619C57AULL,
		0xB8BC4B44F630CC74ULL,
		0xD4761D8CA439817DULL,
		0xDC8C2E33C6633A57ULL,
		0x433A4A5B82851F74ULL,
		0x89B62019791E09B5ULL,
		0xA8757A4867E7A302ULL,
		0x3B348A4E8242546EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8894EADC2C338AF4ULL,
		0x71789689EC6198E8ULL,
		0xA8EC3B19487302FBULL,
		0xB9185C678CC674AFULL,
		0x867494B7050A3EE9ULL,
		0x136C4032F23C136AULL,
		0x50EAF490CFCF4605ULL,
		0x7669149D0484A8DDULL
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
		0xD7530AA1E7C7D154ULL,
		0x44D90C6C8B999686ULL,
		0x1457B459711D4D5FULL,
		0x94B135B7D28C1183ULL,
		0x2096D9BC31E22B92ULL,
		0x5715B0999E6E49ADULL,
		0xAABD5239A4BC2288ULL,
		0x384359FFD3F32693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEA61543CF8FA2A8ULL,
		0x89B218D917332D0DULL,
		0x28AF68B2E23A9ABEULL,
		0x29626B6FA5182306ULL,
		0x412DB37863C45725ULL,
		0xAE2B61333CDC935AULL,
		0x557AA47349784510ULL,
		0x7086B3FFA7E64D27ULL
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
		0xA386AB5DFDC2B705ULL,
		0xA2F596ED73FB03C2ULL,
		0x3C0BD63EC0288BFFULL,
		0x7710F40E0F331970ULL,
		0x79D6BCF3C0CDA241ULL,
		0x73A97141DF2DFBF5ULL,
		0x3EAB9F6244B2BD59ULL,
		0x3F405DAF7BC22703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470D56BBFB856E0AULL,
		0x45EB2DDAE7F60785ULL,
		0x7817AC7D805117FFULL,
		0xEE21E81C1E6632E0ULL,
		0xF3AD79E7819B4482ULL,
		0xE752E283BE5BF7EAULL,
		0x7D573EC489657AB2ULL,
		0x7E80BB5EF7844E06ULL
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
		0x430AAA4AC7AE1F6EULL,
		0x85D1C3E055601437ULL,
		0x9F1738148CE95A08ULL,
		0x4E5EF28194AD1EB5ULL,
		0xDAAD3F4548F7278EULL,
		0x70D8F4816DE97E52ULL,
		0x1EEA970884492A08ULL,
		0x2D2928AE32396F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x861554958F5C3EDCULL,
		0x0BA387C0AAC0286EULL,
		0x3E2E702919D2B411ULL,
		0x9CBDE503295A3D6BULL,
		0xB55A7E8A91EE4F1CULL,
		0xE1B1E902DBD2FCA5ULL,
		0x3DD52E1108925410ULL,
		0x5A52515C6472DE6CULL
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
		0x5CD33439655AC02EULL,
		0xB91BA5E5D57ED4FEULL,
		0x9E8F26953EDEB1A9ULL,
		0xEB794AA2BD2278F4ULL,
		0x229EDFADED8D13D7ULL,
		0x2B9CC9060C12E3E9ULL,
		0x4367AC71C347A3D7ULL,
		0x1C6ABDB620A5DEE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A66872CAB5805CULL,
		0x72374BCBAAFDA9FCULL,
		0x3D1E4D2A7DBD6353ULL,
		0xD6F295457A44F1E9ULL,
		0x453DBF5BDB1A27AFULL,
		0x5739920C1825C7D2ULL,
		0x86CF58E3868F47AEULL,
		0x38D57B6C414BBDCAULL
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
		0xDD70D3163C0BF1DFULL,
		0xBE7069EAF58DD1FDULL,
		0xBA78A3B6868B4EE6ULL,
		0x786E81FDF141F6B7ULL,
		0x59D67F85C6864842ULL,
		0xE39BACEF7E9FF01CULL,
		0x92D6BAD6D1741BDFULL,
		0x3B2C462182A56C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAE1A62C7817E3BEULL,
		0x7CE0D3D5EB1BA3FBULL,
		0x74F1476D0D169DCDULL,
		0xF0DD03FBE283ED6FULL,
		0xB3ACFF0B8D0C9084ULL,
		0xC73759DEFD3FE038ULL,
		0x25AD75ADA2E837BFULL,
		0x76588C43054AD823ULL
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
		0xC984801EE0CFB6E8ULL,
		0xC4CC44DD0D091E1DULL,
		0x34A66FFB33C317BCULL,
		0x4EDEADEC6966DBB6ULL,
		0x2802805EBE6B5E00ULL,
		0xCA4ED3797AD52424ULL,
		0x2DFA08C81E2F92EFULL,
		0x044ECF9989E34EE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9309003DC19F6DD0ULL,
		0x899889BA1A123C3BULL,
		0x694CDFF667862F79ULL,
		0x9DBD5BD8D2CDB76CULL,
		0x500500BD7CD6BC00ULL,
		0x949DA6F2F5AA4848ULL,
		0x5BF411903C5F25DFULL,
		0x089D9F3313C69DC4ULL
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
		0x04D9FDBED05DF063ULL,
		0x20C12C635ED5AFC1ULL,
		0x747CC52F4E25CAC4ULL,
		0x21DA31FB7EAE1FC9ULL,
		0x18A29D68BB4BB4E0ULL,
		0x36913DB0E9DB027EULL,
		0xE4201ECC093EF584ULL,
		0x3F5C0FA0D7F4061EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09B3FB7DA0BBE0C6ULL,
		0x418258C6BDAB5F82ULL,
		0xE8F98A5E9C4B9588ULL,
		0x43B463F6FD5C3F92ULL,
		0x31453AD1769769C0ULL,
		0x6D227B61D3B604FCULL,
		0xC8403D98127DEB08ULL,
		0x7EB81F41AFE80C3DULL
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
		0x28B772531B19735DULL,
		0xD77801EA76CA34CCULL,
		0x20030F8E79396222ULL,
		0x3E75BB3057897130ULL,
		0xF73CAE14AD6DCF02ULL,
		0x5CD991374B3A7C77ULL,
		0xF736329AA7FA231FULL,
		0x20DD7DAF90A15919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516EE4A63632E6BAULL,
		0xAEF003D4ED946998ULL,
		0x40061F1CF272C445ULL,
		0x7CEB7660AF12E260ULL,
		0xEE795C295ADB9E04ULL,
		0xB9B3226E9674F8EFULL,
		0xEE6C65354FF4463EULL,
		0x41BAFB5F2142B233ULL
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
		0x8ABC7445841499E0ULL,
		0x9B441952ED7894A0ULL,
		0x326A11210E116E91ULL,
		0xBB9B9D010FC1F7D6ULL,
		0x7C9AB593F7A3BCA4ULL,
		0x19F245CEDAE53822ULL,
		0x534AA1193CDBA9F9ULL,
		0x06B22DC14121EF7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1578E88B082933C0ULL,
		0x368832A5DAF12941ULL,
		0x64D422421C22DD23ULL,
		0x77373A021F83EFACULL,
		0xF9356B27EF477949ULL,
		0x33E48B9DB5CA7044ULL,
		0xA695423279B753F2ULL,
		0x0D645B828243DEF4ULL
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
		0x3B68905BD9038139ULL,
		0x603B145D7E29C69DULL,
		0x3B6697D60E90AF31ULL,
		0x4875C099A2771200ULL,
		0x2F43E5DEEBD529EDULL,
		0xD51857B6431C95C4ULL,
		0x149EB7076C5B3A95ULL,
		0x2FE76A711490725EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76D120B7B2070272ULL,
		0xC07628BAFC538D3AULL,
		0x76CD2FAC1D215E62ULL,
		0x90EB813344EE2400ULL,
		0x5E87CBBDD7AA53DAULL,
		0xAA30AF6C86392B88ULL,
		0x293D6E0ED8B6752BULL,
		0x5FCED4E22920E4BCULL
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
		0xFB11A0CBFF67DA70ULL,
		0xCB961330A5F5E96AULL,
		0xBF9CD9D5ADEBC82AULL,
		0x3F10D1BF27EADF54ULL,
		0x7E448D3047C575A2ULL,
		0xA6CCDE01CEE70572ULL,
		0x1F552993FA67A6C2ULL,
		0x0D4729DCB8CE730CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6234197FECFB4E0ULL,
		0x972C26614BEBD2D5ULL,
		0x7F39B3AB5BD79055ULL,
		0x7E21A37E4FD5BEA9ULL,
		0xFC891A608F8AEB44ULL,
		0x4D99BC039DCE0AE4ULL,
		0x3EAA5327F4CF4D85ULL,
		0x1A8E53B9719CE618ULL
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
		0x6C7BF18FBD29BBC1ULL,
		0x985BC0481B766AA9ULL,
		0xCB5B3AB3B555B9C7ULL,
		0xCAE42F1861CA7051ULL,
		0x2D539D050448BC04ULL,
		0x62BDE56E0E605AD7ULL,
		0xF36526E7F1FD3780ULL,
		0x01DAB4D72B99BDFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F7E31F7A537782ULL,
		0x30B7809036ECD552ULL,
		0x96B675676AAB738FULL,
		0x95C85E30C394E0A3ULL,
		0x5AA73A0A08917809ULL,
		0xC57BCADC1CC0B5AEULL,
		0xE6CA4DCFE3FA6F00ULL,
		0x03B569AE57337BFFULL
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
		0x91A134C3FEADB843ULL,
		0x412564B6A44C680DULL,
		0xD2B1B863CCDD033EULL,
		0xCB271C954A3E574FULL,
		0x489ED254F8151949ULL,
		0xE544B2DB38D19BCDULL,
		0x90978B8E639AFBE5ULL,
		0x0C3C1386ECE6A5A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23426987FD5B7086ULL,
		0x824AC96D4898D01BULL,
		0xA56370C799BA067CULL,
		0x964E392A947CAE9FULL,
		0x913DA4A9F02A3293ULL,
		0xCA8965B671A3379AULL,
		0x212F171CC735F7CBULL,
		0x1878270DD9CD4B47ULL
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
		0xB145581D62D7202BULL,
		0xE6FBB5831063C7ACULL,
		0x47E9A1A0D7A116DDULL,
		0x72DE73F1EF1FDCBDULL,
		0x92E7227492AEAE9AULL,
		0xE1435E731423BECFULL,
		0x569AAC8AA3D3DFA6ULL,
		0x1096FA8E9A2CD43EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x628AB03AC5AE4056ULL,
		0xCDF76B0620C78F59ULL,
		0x8FD34341AF422DBBULL,
		0xE5BCE7E3DE3FB97AULL,
		0x25CE44E9255D5D34ULL,
		0xC286BCE628477D9FULL,
		0xAD35591547A7BF4DULL,
		0x212DF51D3459A87CULL
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
		0xC463EB07D61DD2BBULL,
		0x1C31AB0DFD809A7DULL,
		0x0EDD6199C0096AD5ULL,
		0xB057772C6F2FE649ULL,
		0x5B895E6A05675B85ULL,
		0xA5740DCCFF084017ULL,
		0x49F484A93B801841ULL,
		0x25AB62EABC7D1F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C7D60FAC3BA576ULL,
		0x3863561BFB0134FBULL,
		0x1DBAC3338012D5AAULL,
		0x60AEEE58DE5FCC92ULL,
		0xB712BCD40ACEB70BULL,
		0x4AE81B99FE10802EULL,
		0x93E9095277003083ULL,
		0x4B56C5D578FA3F2AULL
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
		0xD1D89A8BC8D351DCULL,
		0xAD65805549912E0EULL,
		0xD938BF623B9BD0E3ULL,
		0x79797DAFB98D81FBULL,
		0xDEE61F238834B9AFULL,
		0x82FB4FA2CBA1CC9CULL,
		0x5C4EA8613F0CCE3EULL,
		0x18C84BBE9D0ECD02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3B1351791A6A3B8ULL,
		0x5ACB00AA93225C1DULL,
		0xB2717EC47737A1C7ULL,
		0xF2F2FB5F731B03F7ULL,
		0xBDCC3E471069735EULL,
		0x05F69F4597439939ULL,
		0xB89D50C27E199C7DULL,
		0x3190977D3A1D9A04ULL
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
		0xBBE9166348AA3F3BULL,
		0xEBF9C6D1F8EFF244ULL,
		0x4C591BEF6C6B8C60ULL,
		0xD0C90EAA05144D7DULL,
		0x55CCDF2E9B9E0B00ULL,
		0x6F722ED35B71AAABULL,
		0x730D5F91B07A378CULL,
		0x1CB871074862B642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77D22CC691547E76ULL,
		0xD7F38DA3F1DFE489ULL,
		0x98B237DED8D718C1ULL,
		0xA1921D540A289AFAULL,
		0xAB99BE5D373C1601ULL,
		0xDEE45DA6B6E35556ULL,
		0xE61ABF2360F46F18ULL,
		0x3970E20E90C56C84ULL
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
		0xED57838201CB4C64ULL,
		0x0E8DDAC097CC7D48ULL,
		0xA8D873499718E4C5ULL,
		0x5BC40E5374BBC727ULL,
		0x9FAAC9E5AAB6E0F2ULL,
		0x8D627464BB22D572ULL,
		0x145BAE34E0598942ULL,
		0x299381CE32F730DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAAF0704039698C8ULL,
		0x1D1BB5812F98FA91ULL,
		0x51B0E6932E31C98AULL,
		0xB7881CA6E9778E4FULL,
		0x3F5593CB556DC1E4ULL,
		0x1AC4E8C97645AAE5ULL,
		0x28B75C69C0B31285ULL,
		0x5327039C65EE61B8ULL
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
		0x0A5DD4874A987E30ULL,
		0xC7EAAC723C52970BULL,
		0x46EE0C6E3ED04B7BULL,
		0x576A5D7BF343FD0FULL,
		0x86B7A249B3F8D5C1ULL,
		0xBA456C4889E5E252ULL,
		0x0FB8D678234CD991ULL,
		0x1A22C046E72CD8E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14BBA90E9530FC60ULL,
		0x8FD558E478A52E16ULL,
		0x8DDC18DC7DA096F7ULL,
		0xAED4BAF7E687FA1EULL,
		0x0D6F449367F1AB82ULL,
		0x748AD89113CBC4A5ULL,
		0x1F71ACF04699B323ULL,
		0x3445808DCE59B1C4ULL
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
		0x4758A758BEE26C89ULL,
		0xED10E124B1091184ULL,
		0x0CC246E34DFC93F6ULL,
		0x7F5DDC6AE9BE2357ULL,
		0x4A391EEAD8A4FDB0ULL,
		0x7CB5E3B415BE5BFDULL,
		0x605143E9FF8FD27AULL,
		0x0116338ECA4685D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EB14EB17DC4D912ULL,
		0xDA21C24962122308ULL,
		0x19848DC69BF927EDULL,
		0xFEBBB8D5D37C46AEULL,
		0x94723DD5B149FB60ULL,
		0xF96BC7682B7CB7FAULL,
		0xC0A287D3FF1FA4F4ULL,
		0x022C671D948D0BACULL
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
		0x40DA5375E7D78681ULL,
		0x1EF796578FE5D5FCULL,
		0x2529AFBEF12F4200ULL,
		0x85EB68A5DE968CADULL,
		0xF45743662E2BDF23ULL,
		0x6A0370565E18D463ULL,
		0x5A4FD04DD2307870ULL,
		0x0DEB563D5C3F4EB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81B4A6EBCFAF0D02ULL,
		0x3DEF2CAF1FCBABF8ULL,
		0x4A535F7DE25E8400ULL,
		0x0BD6D14BBD2D195AULL,
		0xE8AE86CC5C57BE47ULL,
		0xD406E0ACBC31A8C7ULL,
		0xB49FA09BA460F0E0ULL,
		0x1BD6AC7AB87E9D72ULL
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
		0x1F49E48F79F07E01ULL,
		0x802DADE9C15DA026ULL,
		0x30C734C8C80BD442ULL,
		0xB1F0FA65C32ED4CDULL,
		0x068BDC638FAEB50BULL,
		0xA7770F35D4D10A19ULL,
		0x388F793D8E9D1937ULL,
		0x126BD2ABA886FE69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E93C91EF3E0FC02ULL,
		0x005B5BD382BB404CULL,
		0x618E69919017A885ULL,
		0x63E1F4CB865DA99AULL,
		0x0D17B8C71F5D6A17ULL,
		0x4EEE1E6BA9A21432ULL,
		0x711EF27B1D3A326FULL,
		0x24D7A557510DFCD2ULL
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
		0x99252D100B97F6D4ULL,
		0x263BFCEAA3CEDF20ULL,
		0x716D1E1DB5B1771FULL,
		0x74701C349BDD7D73ULL,
		0x40AD160C1D036128ULL,
		0x72D93C17779B277FULL,
		0x589CF03DA0C8714AULL,
		0x101D4E76115452D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324A5A20172FEDA8ULL,
		0x4C77F9D5479DBE41ULL,
		0xE2DA3C3B6B62EE3EULL,
		0xE8E0386937BAFAE6ULL,
		0x815A2C183A06C250ULL,
		0xE5B2782EEF364EFEULL,
		0xB139E07B4190E294ULL,
		0x203A9CEC22A8A5AAULL
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
		0x63779BEC1C56A8F0ULL,
		0xC9BEEB7E0DB2C84CULL,
		0x5307BBE5601AC927ULL,
		0x6887B53BF661BBC6ULL,
		0xEFABEAED7DBED6F3ULL,
		0x43DE29AE1A7878E9ULL,
		0xFB05170EC17E4D68ULL,
		0x3CFAE46DD3F9B48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6EF37D838AD51E0ULL,
		0x937DD6FC1B659098ULL,
		0xA60F77CAC035924FULL,
		0xD10F6A77ECC3778CULL,
		0xDF57D5DAFB7DADE6ULL,
		0x87BC535C34F0F1D3ULL,
		0xF60A2E1D82FC9AD0ULL,
		0x79F5C8DBA7F3691BULL
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
		0x7E4F0617EA72364BULL,
		0x9AF7876968500C17ULL,
		0x7EB32AEF5EA1CEAAULL,
		0xB08599A59C72504FULL,
		0x13C6C61D69D2178BULL,
		0xFA6DE810A296265EULL,
		0xEFACB99537D29AC4ULL,
		0x1CF3DEF92A6C53C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9E0C2FD4E46C96ULL,
		0x35EF0ED2D0A0182EULL,
		0xFD6655DEBD439D55ULL,
		0x610B334B38E4A09EULL,
		0x278D8C3AD3A42F17ULL,
		0xF4DBD021452C4CBCULL,
		0xDF59732A6FA53589ULL,
		0x39E7BDF254D8A78BULL
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
		0x91CE2EE30ECBAE94ULL,
		0x0803146FEA6C895DULL,
		0xF276E62970301484ULL,
		0x32098AA8F2B828FBULL,
		0x5F527CF5628C6390ULL,
		0x175EDF99AAE8795FULL,
		0xB27F467F8FB26DC8ULL,
		0x2F5081BFD1D2500DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x239C5DC61D975D28ULL,
		0x100628DFD4D912BBULL,
		0xE4EDCC52E0602908ULL,
		0x64131551E57051F7ULL,
		0xBEA4F9EAC518C720ULL,
		0x2EBDBF3355D0F2BEULL,
		0x64FE8CFF1F64DB90ULL,
		0x5EA1037FA3A4A01BULL
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
		0x517A96F7BA76BAEFULL,
		0x227D0FE02FCCDD4BULL,
		0xDE1233DD27CBABD9ULL,
		0x793BD70FB3262D24ULL,
		0xBC7DB0780DCA2C97ULL,
		0x28EAD99B5D67A1FFULL,
		0xCA8B9C6BB2687C80ULL,
		0x1A8F0BD7F769007BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F52DEF74ED75DEULL,
		0x44FA1FC05F99BA96ULL,
		0xBC2467BA4F9757B2ULL,
		0xF277AE1F664C5A49ULL,
		0x78FB60F01B94592EULL,
		0x51D5B336BACF43FFULL,
		0x951738D764D0F900ULL,
		0x351E17AFEED200F7ULL
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
		0x0EF99A8C6D5C7CBFULL,
		0xA90F3C57E7B34404ULL,
		0x508CF8D9343DFA37ULL,
		0x5B1F5E4ED843E0ECULL,
		0x201C71A2E4443504ULL,
		0xBD23B3184044EE53ULL,
		0x9AC5762E21F42793ULL,
		0x3F0568585D55138DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF33518DAB8F97EULL,
		0x521E78AFCF668808ULL,
		0xA119F1B2687BF46FULL,
		0xB63EBC9DB087C1D8ULL,
		0x4038E345C8886A08ULL,
		0x7A4766308089DCA6ULL,
		0x358AEC5C43E84F27ULL,
		0x7E0AD0B0BAAA271BULL
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
		0xCDFF55B0FCE6A0E2ULL,
		0xD16B8084CA290CFBULL,
		0x7CABFE2D329D9FDEULL,
		0xC1D37CDC90DDD526ULL,
		0x76DA7C328BD92D8FULL,
		0xE8436B04F6442C56ULL,
		0x60A3ADD1392564BFULL,
		0x23FD4EF5571EF244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BFEAB61F9CD41C4ULL,
		0xA2D70109945219F7ULL,
		0xF957FC5A653B3FBDULL,
		0x83A6F9B921BBAA4CULL,
		0xEDB4F86517B25B1FULL,
		0xD086D609EC8858ACULL,
		0xC1475BA2724AC97FULL,
		0x47FA9DEAAE3DE488ULL
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
		0xAEC6CC9D840E9142ULL,
		0x19EED9A3E052CC1BULL,
		0x18083E82D29C1F52ULL,
		0x9B783ACE895531D2ULL,
		0xA41C60BA440AFDB4ULL,
		0x35B2D7FD3561B20BULL,
		0xBBA21A33F869B15AULL,
		0x07BDBA82237DB0CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D8D993B081D2284ULL,
		0x33DDB347C0A59837ULL,
		0x30107D05A5383EA4ULL,
		0x36F0759D12AA63A4ULL,
		0x4838C1748815FB69ULL,
		0x6B65AFFA6AC36417ULL,
		0x77443467F0D362B4ULL,
		0x0F7B750446FB6199ULL
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
		0x38493F9FA39A8172ULL,
		0x8E6DC8DF80F5D00DULL,
		0xC9BE67B5D496DD70ULL,
		0x4EB2D8AA530DAE4EULL,
		0xAD73E9A4CF11324AULL,
		0x275F90AE5F4F2E1CULL,
		0xAC6CC86757242D63ULL,
		0x2BB01AE82BC60BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70927F3F473502E4ULL,
		0x1CDB91BF01EBA01AULL,
		0x937CCF6BA92DBAE1ULL,
		0x9D65B154A61B5C9DULL,
		0x5AE7D3499E226494ULL,
		0x4EBF215CBE9E5C39ULL,
		0x58D990CEAE485AC6ULL,
		0x576035D0578C179FULL
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
		0x5CAB5DCF29235DD3ULL,
		0xC7D9E0FC7F0A612DULL,
		0xF3896028D6616B86ULL,
		0x7549584A842D0218ULL,
		0x0ADB147A8F87709CULL,
		0x38DC65AE013CEE0FULL,
		0x211EE4CF6E319FF5ULL,
		0x23905DF0D50D1032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB956BB9E5246BBA6ULL,
		0x8FB3C1F8FE14C25AULL,
		0xE712C051ACC2D70DULL,
		0xEA92B095085A0431ULL,
		0x15B628F51F0EE138ULL,
		0x71B8CB5C0279DC1EULL,
		0x423DC99EDC633FEAULL,
		0x4720BBE1AA1A2064ULL
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
		0x2BAC42AAF06CBED2ULL,
		0x255E87D65DC2BAFFULL,
		0xB2B16DF42578853CULL,
		0xD8522332D9C8A41AULL,
		0x5F32A7E10FD4F144ULL,
		0xA18300946D3B9A11ULL,
		0xFECF36C6FC620816ULL,
		0x14B9F10631865DADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57588555E0D97DA4ULL,
		0x4ABD0FACBB8575FEULL,
		0x6562DBE84AF10A78ULL,
		0xB0A44665B3914835ULL,
		0xBE654FC21FA9E289ULL,
		0x43060128DA773422ULL,
		0xFD9E6D8DF8C4102DULL,
		0x2973E20C630CBB5BULL
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
		0x2939B41B9DCFCD86ULL,
		0x6DC3BDE58FC9D0A4ULL,
		0x309C8AA0DC22A233ULL,
		0xF0DB38486C2194E4ULL,
		0xA3B217A8121D692AULL,
		0x8C1B6F2E75E4FEE6ULL,
		0xBB2207B9D7DFD2C0ULL,
		0x0028BFA2B9AADDE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527368373B9F9B0CULL,
		0xDB877BCB1F93A148ULL,
		0x61391541B8454466ULL,
		0xE1B67090D84329C8ULL,
		0x47642F50243AD255ULL,
		0x1836DE5CEBC9FDCDULL,
		0x76440F73AFBFA581ULL,
		0x00517F457355BBCBULL
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
		0xEB30C713A5D13E13ULL,
		0x866E56C2B1A3D48AULL,
		0x776164F7454B4045ULL,
		0x782381046B5C2EBFULL,
		0xE7AD5B38E1FDF9EAULL,
		0x9DEE3C0FC22607FAULL,
		0x33DCE5D96003FC36ULL,
		0x39578DD117D04DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6618E274BA27C26ULL,
		0x0CDCAD856347A915ULL,
		0xEEC2C9EE8A96808BULL,
		0xF0470208D6B85D7EULL,
		0xCF5AB671C3FBF3D4ULL,
		0x3BDC781F844C0FF5ULL,
		0x67B9CBB2C007F86DULL,
		0x72AF1BA22FA09B8AULL
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
		0x779B866DB282FA31ULL,
		0x844577625EC33CF0ULL,
		0x03AD8C1A4BB16DEAULL,
		0xF4B924C55971F66EULL,
		0x0879EEAFDBF47552ULL,
		0x59C8035C502AB40FULL,
		0xFBCAA3DED1909EABULL,
		0x10E0CB60BD2E21DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF370CDB6505F462ULL,
		0x088AEEC4BD8679E0ULL,
		0x075B18349762DBD5ULL,
		0xE972498AB2E3ECDCULL,
		0x10F3DD5FB7E8EAA5ULL,
		0xB39006B8A055681EULL,
		0xF79547BDA3213D56ULL,
		0x21C196C17A5C43B9ULL
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
		0x6105C79118D9F2BEULL,
		0xF62D7912997C8D15ULL,
		0x73D42F8E0D64F3C8ULL,
		0x92AC1B52F46D9D85ULL,
		0x28821838E0A9F242ULL,
		0x85497C834FC84D26ULL,
		0x2F5E81A2D898082DULL,
		0x119F27978CC4D4EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20B8F2231B3E57CULL,
		0xEC5AF22532F91A2AULL,
		0xE7A85F1C1AC9E791ULL,
		0x255836A5E8DB3B0AULL,
		0x51043071C153E485ULL,
		0x0A92F9069F909A4CULL,
		0x5EBD0345B130105BULL,
		0x233E4F2F1989A9DEULL
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
		0xEEC0F377BB708E3FULL,
		0xD97BBAE2036A424FULL,
		0x24F1B5486270B3D5ULL,
		0xDCCD0083530EEE8CULL,
		0x5D00F04C2F62E667ULL,
		0x1F877DE87DA91BFEULL,
		0x28A41B60E19CD537ULL,
		0x1EF81AFEB525CAD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD81E6EF76E11C7EULL,
		0xB2F775C406D4849FULL,
		0x49E36A90C4E167ABULL,
		0xB99A0106A61DDD18ULL,
		0xBA01E0985EC5CCCFULL,
		0x3F0EFBD0FB5237FCULL,
		0x514836C1C339AA6EULL,
		0x3DF035FD6A4B95AAULL
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
		0xB5727C9AA02AFBB2ULL,
		0xFB18DAE8E56A0B29ULL,
		0xA78AEBC6DEDA3E3AULL,
		0x1553C3B52820361DULL,
		0x6796CC86220EC083ULL,
		0x59E7DA3BF9DB97C8ULL,
		0xF45A3412CAF16D3AULL,
		0x37A897629BDDD8BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE4F9354055F764ULL,
		0xF631B5D1CAD41653ULL,
		0x4F15D78DBDB47C75ULL,
		0x2AA7876A50406C3BULL,
		0xCF2D990C441D8106ULL,
		0xB3CFB477F3B72F90ULL,
		0xE8B4682595E2DA74ULL,
		0x6F512EC537BBB177ULL
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
		0x6D80800E0905B78CULL,
		0x005941BCEBE587C0ULL,
		0xAE22C2DE13D3528BULL,
		0x4B31713117379F2FULL,
		0xB758031802A9F692ULL,
		0x7A26FCE0FFA63E6DULL,
		0x1AC8E5A04063E2F2ULL,
		0x059EF9E246B709BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB01001C120B6F18ULL,
		0x00B28379D7CB0F80ULL,
		0x5C4585BC27A6A516ULL,
		0x9662E2622E6F3E5FULL,
		0x6EB006300553ED24ULL,
		0xF44DF9C1FF4C7CDBULL,
		0x3591CB4080C7C5E4ULL,
		0x0B3DF3C48D6E1378ULL
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
		0xDCA891CDEDB6A81AULL,
		0x91FA65FFBC16CD80ULL,
		0xBEE2595E855FD729ULL,
		0xE45E9BCCF9BF3D75ULL,
		0xB550126FAF285F50ULL,
		0xAA2C6E14D202D69DULL,
		0x4768E745042FB341ULL,
		0x1C62E3CC04CAFE64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB951239BDB6D5034ULL,
		0x23F4CBFF782D9B01ULL,
		0x7DC4B2BD0ABFAE53ULL,
		0xC8BD3799F37E7AEBULL,
		0x6AA024DF5E50BEA1ULL,
		0x5458DC29A405AD3BULL,
		0x8ED1CE8A085F6683ULL,
		0x38C5C7980995FCC8ULL
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
		0x26804D76B394FF68ULL,
		0x427E876EB6D1CC2FULL,
		0x52929103034B9701ULL,
		0x813DD427D94AC004ULL,
		0xB930D76D04A110A5ULL,
		0xD626F891F8240F1BULL,
		0x0CEBF5ED6BBD0793ULL,
		0x2FFBCC2AEBE07069ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D009AED6729FED0ULL,
		0x84FD0EDD6DA3985EULL,
		0xA525220606972E02ULL,
		0x027BA84FB2958008ULL,
		0x7261AEDA0942214BULL,
		0xAC4DF123F0481E37ULL,
		0x19D7EBDAD77A0F27ULL,
		0x5FF79855D7C0E0D2ULL
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
		0x30EDE53ACD359314ULL,
		0xB866EB4DABCDECCCULL,
		0x89828F866175B389ULL,
		0xDA641CBA1B55C27CULL,
		0x914DBC74DD14FD47ULL,
		0xA70C7BF0790D6B5BULL,
		0x12801A48606C5A82ULL,
		0x17C81096E19FC522ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DBCA759A6B2628ULL,
		0x70CDD69B579BD998ULL,
		0x13051F0CC2EB6713ULL,
		0xB4C8397436AB84F9ULL,
		0x229B78E9BA29FA8FULL,
		0x4E18F7E0F21AD6B7ULL,
		0x25003490C0D8B505ULL,
		0x2F90212DC33F8A44ULL
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
		0x24973D6931F40E68ULL,
		0x4A47913BE607CA5BULL,
		0x47A11954C7D8D84EULL,
		0x6FBA8163359D3185ULL,
		0xA35B55057EDABA87ULL,
		0x3E55412BD19A177BULL,
		0x351D38488F12C8C1ULL,
		0x31701B6778CA1D37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x492E7AD263E81CD0ULL,
		0x948F2277CC0F94B6ULL,
		0x8F4232A98FB1B09CULL,
		0xDF7502C66B3A630AULL,
		0x46B6AA0AFDB5750EULL,
		0x7CAA8257A3342EF7ULL,
		0x6A3A70911E259182ULL,
		0x62E036CEF1943A6EULL
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
		0x4BA65195E78ABC8FULL,
		0x44F0640E4EF1BD7DULL,
		0x7008004C1B69E7F7ULL,
		0xB4471909806375F8ULL,
		0xE2411B1569CFCA4FULL,
		0xABAFB8D75F5DD4A4ULL,
		0xFFC741BAD97398FFULL,
		0x32A8081CE11814EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x974CA32BCF15791EULL,
		0x89E0C81C9DE37AFAULL,
		0xE010009836D3CFEEULL,
		0x688E321300C6EBF0ULL,
		0xC482362AD39F949FULL,
		0x575F71AEBEBBA949ULL,
		0xFF8E8375B2E731FFULL,
		0x65501039C23029D5ULL
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
		0x168BC5A6C89DDA56ULL,
		0x311AC63B68F4FCC4ULL,
		0x4995743B62A33255ULL,
		0xDE22A80FBF9FA36BULL,
		0x684AA505EEE5AF9AULL,
		0xAFC853AA260CD191ULL,
		0x31397676B6658CFEULL,
		0x13325A51ED1125B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D178B4D913BB4ACULL,
		0x62358C76D1E9F988ULL,
		0x932AE876C54664AAULL,
		0xBC45501F7F3F46D6ULL,
		0xD0954A0BDDCB5F35ULL,
		0x5F90A7544C19A322ULL,
		0x6272ECED6CCB19FDULL,
		0x2664B4A3DA224B64ULL
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
		0x1CAF6B659805BE7FULL,
		0x247CF9A9C36FA6DBULL,
		0xC8FDCC1070C3637FULL,
		0xF7EA77F408FA8AE0ULL,
		0xCC7C4F22736B40AFULL,
		0x118BEBE36006EE67ULL,
		0xDE6D641C4A76D0DBULL,
		0x253D2092ED19C0C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395ED6CB300B7CFEULL,
		0x48F9F35386DF4DB6ULL,
		0x91FB9820E186C6FEULL,
		0xEFD4EFE811F515C1ULL,
		0x98F89E44E6D6815FULL,
		0x2317D7C6C00DDCCFULL,
		0xBCDAC83894EDA1B6ULL,
		0x4A7A4125DA338185ULL
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
		0xDFF299060B66CD10ULL,
		0x25C0304F712793E9ULL,
		0xFAC7EB3D90E2D870ULL,
		0x0A5A060BC2CF1615ULL,
		0x42351CECAFC92026ULL,
		0x7526670A08C64B16ULL,
		0x509591EAD548D57AULL,
		0x089D674713A58893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFE5320C16CD9A20ULL,
		0x4B80609EE24F27D3ULL,
		0xF58FD67B21C5B0E0ULL,
		0x14B40C17859E2C2BULL,
		0x846A39D95F92404CULL,
		0xEA4CCE14118C962CULL,
		0xA12B23D5AA91AAF4ULL,
		0x113ACE8E274B1126ULL
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
		0xF5D947B2E39C5E96ULL,
		0xC309A1E679695212ULL,
		0x29376AA1FBE73B28ULL,
		0x3A3A475C3155B34EULL,
		0xD735F6AD2C3384A4ULL,
		0x87A7E534EA147DB8ULL,
		0x7B3A4E80624A2B51ULL,
		0x17EFE7018308F0A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBB28F65C738BD2CULL,
		0x861343CCF2D2A425ULL,
		0x526ED543F7CE7651ULL,
		0x74748EB862AB669CULL,
		0xAE6BED5A58670948ULL,
		0x0F4FCA69D428FB71ULL,
		0xF6749D00C49456A3ULL,
		0x2FDFCE030611E14CULL
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
		0x8247AD6BC82F35E2ULL,
		0xBE5489E573385777ULL,
		0x1EFF6E283529E158ULL,
		0x2B1FF32885AB24E4ULL,
		0x0675BF434310086CULL,
		0x45AE7F60DA933816ULL,
		0x131532D693904EF6ULL,
		0x17911DF68D794E2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048F5AD7905E6BC4ULL,
		0x7CA913CAE670AEEFULL,
		0x3DFEDC506A53C2B1ULL,
		0x563FE6510B5649C8ULL,
		0x0CEB7E86862010D8ULL,
		0x8B5CFEC1B526702CULL,
		0x262A65AD27209DECULL,
		0x2F223BED1AF29C54ULL
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
		0xF40A18AF5469793EULL,
		0x83273A8830C402B7ULL,
		0x9ECC456127ACBE00ULL,
		0x742FF691F3753ED4ULL,
		0x2381205079C1D263ULL,
		0x77300F9B7D7F5B4FULL,
		0x8FAF17BA0677931AULL,
		0x18505239ACB2CB37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE814315EA8D2F27CULL,
		0x064E75106188056FULL,
		0x3D988AC24F597C01ULL,
		0xE85FED23E6EA7DA9ULL,
		0x470240A0F383A4C6ULL,
		0xEE601F36FAFEB69EULL,
		0x1F5E2F740CEF2634ULL,
		0x30A0A4735965966FULL
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
		0x8428669232EE065BULL,
		0x810E38E4249B2158ULL,
		0x3342C9ECE544F378ULL,
		0x3E73667305F8DAA5ULL,
		0x1EF5BE0765C52CB5ULL,
		0x9AD00F0371AADBD6ULL,
		0xB0939634901E8957ULL,
		0x38E5EE4CC5B643B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0850CD2465DC0CB6ULL,
		0x021C71C8493642B1ULL,
		0x668593D9CA89E6F1ULL,
		0x7CE6CCE60BF1B54AULL,
		0x3DEB7C0ECB8A596AULL,
		0x35A01E06E355B7ACULL,
		0x61272C69203D12AFULL,
		0x71CBDC998B6C876FULL
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
		0xC9915922C8805D06ULL,
		0x1D78FD75E0BD7338ULL,
		0x2011954AFF7577FFULL,
		0x913B449AA0ACAA26ULL,
		0xEB655FA658CF9378ULL,
		0x6D8CA9036F3246FCULL,
		0xFDD8E2D258EF0387ULL,
		0x07F0B9BAE25900C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9322B2459100BA0CULL,
		0x3AF1FAEBC17AE671ULL,
		0x40232A95FEEAEFFEULL,
		0x227689354159544CULL,
		0xD6CABF4CB19F26F1ULL,
		0xDB195206DE648DF9ULL,
		0xFBB1C5A4B1DE070EULL,
		0x0FE17375C4B20185ULL
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
		0x30B710E66C130F86ULL,
		0x58E9CE1559808A02ULL,
		0x74B83E56DC28C1BAULL,
		0xB25837CE456B4465ULL,
		0x751B384705CC6C61ULL,
		0x0B49F7FA2C30ABB0ULL,
		0xEDE8823B9EBF770BULL,
		0x35EA83BD3F421AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x616E21CCD8261F0CULL,
		0xB1D39C2AB3011404ULL,
		0xE9707CADB8518374ULL,
		0x64B06F9C8AD688CAULL,
		0xEA36708E0B98D8C3ULL,
		0x1693EFF458615760ULL,
		0xDBD104773D7EEE16ULL,
		0x6BD5077A7E8435F3ULL
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
		0x58A25DC5342BA426ULL,
		0xE1D86543FDEA49EBULL,
		0x1DC65638EA804498ULL,
		0xF11FEF6821E57109ULL,
		0xF1CF081A64F88A5CULL,
		0xDAB37F88CDBC633AULL,
		0x4E2FB4F6AF9917E4ULL,
		0x127934BE2F7F2DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB144BB8A6857484CULL,
		0xC3B0CA87FBD493D6ULL,
		0x3B8CAC71D5008931ULL,
		0xE23FDED043CAE212ULL,
		0xE39E1034C9F114B9ULL,
		0xB566FF119B78C675ULL,
		0x9C5F69ED5F322FC9ULL,
		0x24F2697C5EFE5BA0ULL
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
		0x4DC5E291D0B25ABFULL,
		0x02DA914F748B8CEDULL,
		0x9FDA39380E8ADF48ULL,
		0x80F02D959EB3DC58ULL,
		0x9D1AE7A20BCC0273ULL,
		0x01FDADF2CD5DBC78ULL,
		0x716EBEAD39E20270ULL,
		0x2AA3E51500CADD31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B8BC523A164B57EULL,
		0x05B5229EE91719DAULL,
		0x3FB472701D15BE90ULL,
		0x01E05B2B3D67B8B1ULL,
		0x3A35CF44179804E7ULL,
		0x03FB5BE59ABB78F1ULL,
		0xE2DD7D5A73C404E0ULL,
		0x5547CA2A0195BA62ULL
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
		0x317866527E8720DDULL,
		0xCE4646C042C39B93ULL,
		0x453A1A35765170A3ULL,
		0xABC1D1CBAF611F14ULL,
		0x6C02CEF498B4DD0CULL,
		0xA182BA8181DFB983ULL,
		0x0E7305BD268A0C94ULL,
		0x2313DC90C34E887CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F0CCA4FD0E41BAULL,
		0x9C8C8D8085873726ULL,
		0x8A74346AECA2E147ULL,
		0x5783A3975EC23E28ULL,
		0xD8059DE93169BA19ULL,
		0x4305750303BF7306ULL,
		0x1CE60B7A4D141929ULL,
		0x4627B921869D10F8ULL
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
		0x11D645B6EE051F28ULL,
		0x097AE6A526D8A7AAULL,
		0xDEECA407694F75B5ULL,
		0x08D42F9B3048A3A8ULL,
		0x370FF9F405FC6478ULL,
		0x789B567F163BFF66ULL,
		0xA0B3C6ACBC5D88C6ULL,
		0x3D39E6F9EA8E95C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AC8B6DDC0A3E50ULL,
		0x12F5CD4A4DB14F54ULL,
		0xBDD9480ED29EEB6AULL,
		0x11A85F3660914751ULL,
		0x6E1FF3E80BF8C8F0ULL,
		0xF136ACFE2C77FECCULL,
		0x41678D5978BB118CULL,
		0x7A73CDF3D51D2B83ULL
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
		0x553DF929DFE87832ULL,
		0x7DE30F5814E5F9ADULL,
		0x613F235BC9A4D275ULL,
		0xEABA2F46B7D42110ULL,
		0x8C527D3D66804F95ULL,
		0x0509B6BBFD942438ULL,
		0x0D8FEA732856D92EULL,
		0x270DC2C58DB09FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA7BF253BFD0F064ULL,
		0xFBC61EB029CBF35AULL,
		0xC27E46B79349A4EAULL,
		0xD5745E8D6FA84220ULL,
		0x18A4FA7ACD009F2BULL,
		0x0A136D77FB284871ULL,
		0x1B1FD4E650ADB25CULL,
		0x4E1B858B1B613F8CULL
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
		0x29CBFC9C756A3270ULL,
		0xA5C84EE6ED0399ECULL,
		0x968A0B96E89DC110ULL,
		0xF62EF5620B183994ULL,
		0xBC829B1ECBE70217ULL,
		0x4BDA9DAB28CC155FULL,
		0x68FC03761DA86E92ULL,
		0x12E62FBFF8CC5C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5397F938EAD464E0ULL,
		0x4B909DCDDA0733D8ULL,
		0x2D14172DD13B8221ULL,
		0xEC5DEAC416307329ULL,
		0x7905363D97CE042FULL,
		0x97B53B5651982ABFULL,
		0xD1F806EC3B50DD24ULL,
		0x25CC5F7FF198B8DAULL
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
		0x9483CFAE5FB0E93AULL,
		0xEEB840F0F485F924ULL,
		0xF901DBC3C362DCAAULL,
		0x521BCDF0B9A89190ULL,
		0xA01E8346DCBDA2E9ULL,
		0xEE1BDEBB26E1E8C2ULL,
		0x6EF597FF6EEE9989ULL,
		0x1AA3B6FD7DBF6D0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29079F5CBF61D274ULL,
		0xDD7081E1E90BF249ULL,
		0xF203B78786C5B955ULL,
		0xA4379BE173512321ULL,
		0x403D068DB97B45D2ULL,
		0xDC37BD764DC3D185ULL,
		0xDDEB2FFEDDDD3313ULL,
		0x35476DFAFB7EDA1AULL
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
		0xB1B52D89FDE19D13ULL,
		0x0AF05C8CF5583991ULL,
		0xF675ABB6C292DBB4ULL,
		0xC9FB65029267807BULL,
		0x19336CAF655FB341ULL,
		0xD3BB4F86058148A4ULL,
		0xD74477B6B607566DULL,
		0x1E783C38B53792ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x636A5B13FBC33A26ULL,
		0x15E0B919EAB07323ULL,
		0xECEB576D8525B768ULL,
		0x93F6CA0524CF00F7ULL,
		0x3266D95ECABF6683ULL,
		0xA7769F0C0B029148ULL,
		0xAE88EF6D6C0EACDBULL,
		0x3CF078716A6F2559ULL
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
		0x585162B750923C33ULL,
		0xDBA68501F40CA049ULL,
		0x23A347460C663206ULL,
		0xA4BF2D30663BCEEEULL,
		0x03B96847509428C3ULL,
		0x5ED41E0FD6DCC1C0ULL,
		0x1994BDA1654BCA5CULL,
		0x072509D3723EAA7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0A2C56EA1247866ULL,
		0xB74D0A03E8194092ULL,
		0x47468E8C18CC640DULL,
		0x497E5A60CC779DDCULL,
		0x0772D08EA1285187ULL,
		0xBDA83C1FADB98380ULL,
		0x33297B42CA9794B8ULL,
		0x0E4A13A6E47D54F8ULL
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
		0x6570E2F91A396E4BULL,
		0xEE924505F5511355ULL,
		0x59C512A1E5598B84ULL,
		0xED278C646398D01DULL,
		0xF399F79CCD950284ULL,
		0x50CADE4BF8EEF918ULL,
		0xE0FA4FA37BCEFC92ULL,
		0x2A47B7D1AB436718ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE1C5F23472DC96ULL,
		0xDD248A0BEAA226AAULL,
		0xB38A2543CAB31709ULL,
		0xDA4F18C8C731A03AULL,
		0xE733EF399B2A0509ULL,
		0xA195BC97F1DDF231ULL,
		0xC1F49F46F79DF924ULL,
		0x548F6FA35686CE31ULL
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
		0x9D1E625021DBCA64ULL,
		0x7C4357702D0B0CB6ULL,
		0x7D1AFBE3A52199F6ULL,
		0xAEACCD19DF43E604ULL,
		0x66A7BE5B2078E255ULL,
		0x9314138DB27BBBA3ULL,
		0x54125F68D48B45ABULL,
		0x1E8FC3FE03324F0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A3CC4A043B794C8ULL,
		0xF886AEE05A16196DULL,
		0xFA35F7C74A4333ECULL,
		0x5D599A33BE87CC08ULL,
		0xCD4F7CB640F1C4ABULL,
		0x2628271B64F77746ULL,
		0xA824BED1A9168B57ULL,
		0x3D1F87FC06649E1AULL
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
		0xEB589D91D80D9E0FULL,
		0x38FBFD0B8A228C41ULL,
		0x83A95122DE229335ULL,
		0x0202841B42399CC9ULL,
		0xE29A11AEAD988D60ULL,
		0x053ACD4E260994B4ULL,
		0x213C196353A5BF3EULL,
		0x04A63880D8EA5125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6B13B23B01B3C1EULL,
		0x71F7FA1714451883ULL,
		0x0752A245BC45266AULL,
		0x0405083684733993ULL,
		0xC534235D5B311AC0ULL,
		0x0A759A9C4C132969ULL,
		0x427832C6A74B7E7CULL,
		0x094C7101B1D4A24AULL
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
		0x56CDA19D46812BA9ULL,
		0x2EA2D312349502F9ULL,
		0x171198AD6699381DULL,
		0x65DFA756CDD2B812ULL,
		0x42F4FD1164BB24BBULL,
		0x95D11B017C937091ULL,
		0xCFA4D8B508E51F80ULL,
		0x12D487111FF5436EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9B433A8D025752ULL,
		0x5D45A624692A05F2ULL,
		0x2E23315ACD32703AULL,
		0xCBBF4EAD9BA57024ULL,
		0x85E9FA22C9764976ULL,
		0x2BA23602F926E122ULL,
		0x9F49B16A11CA3F01ULL,
		0x25A90E223FEA86DDULL
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
		0x865BBABAB341869AULL,
		0x23F67CCAB4AA23DDULL,
		0x7ECA1F188E947B64ULL,
		0x5945CE54D035B73FULL,
		0xABBFF3BAF57C4FE5ULL,
		0xDD31D2A5187B2585ULL,
		0xA86FB9A632C6AF0CULL,
		0x29E7F11A99B15750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CB7757566830D34ULL,
		0x47ECF995695447BBULL,
		0xFD943E311D28F6C8ULL,
		0xB28B9CA9A06B6E7EULL,
		0x577FE775EAF89FCAULL,
		0xBA63A54A30F64B0BULL,
		0x50DF734C658D5E19ULL,
		0x53CFE2353362AEA1ULL
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
		0x808A6ECC2AA55C37ULL,
		0x95DD11A85E4CE228ULL,
		0xE0BE53F4099475C8ULL,
		0x474A3431BB6A79E7ULL,
		0x30B40B7D5668F804ULL,
		0xE3EE3C39D4C75A5FULL,
		0xBCE352ED3DF235B8ULL,
		0x01F2C30E179082D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0114DD98554AB86EULL,
		0x2BBA2350BC99C451ULL,
		0xC17CA7E81328EB91ULL,
		0x8E94686376D4F3CFULL,
		0x616816FAACD1F008ULL,
		0xC7DC7873A98EB4BEULL,
		0x79C6A5DA7BE46B71ULL,
		0x03E5861C2F2105A5ULL
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
		0x9EAE20F545B5BADFULL,
		0xEC5E14EE2CE96F1AULL,
		0xBE99B726FD69459EULL,
		0xE2ECD05F6EEF7B08ULL,
		0x14F733EE50EFD789ULL,
		0xFD240B1C14766D01ULL,
		0xD2EC23C293861DF2ULL,
		0x0223F8492A1E564BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5C41EA8B6B75BEULL,
		0xD8BC29DC59D2DE35ULL,
		0x7D336E4DFAD28B3DULL,
		0xC5D9A0BEDDDEF611ULL,
		0x29EE67DCA1DFAF13ULL,
		0xFA48163828ECDA02ULL,
		0xA5D84785270C3BE5ULL,
		0x0447F092543CAC97ULL
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
		0xC7231F35EC1FF08AULL,
		0xD1E8A189928CE718ULL,
		0x971E8EE444D6E5DCULL,
		0x718070E0AF696D4EULL,
		0xC352B67109E6B364ULL,
		0x5C0FC7178A99A811ULL,
		0xB6DA8FF3330F8F73ULL,
		0x3A8AEEF4AAEE26B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E463E6BD83FE114ULL,
		0xA3D143132519CE31ULL,
		0x2E3D1DC889ADCBB9ULL,
		0xE300E1C15ED2DA9DULL,
		0x86A56CE213CD66C8ULL,
		0xB81F8E2F15335023ULL,
		0x6DB51FE6661F1EE6ULL,
		0x7515DDE955DC4D67ULL
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
		0x0564AEF185AF332AULL,
		0x21DB726EDC62214AULL,
		0xEF831181B792988BULL,
		0x4B26DD7E2F057960ULL,
		0xD5BFFAF386531637ULL,
		0x3A9BE4EF49A296BCULL,
		0xDEC641F60868DA9EULL,
		0x39095DB8BEE752B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AC95DE30B5E6654ULL,
		0x43B6E4DDB8C44294ULL,
		0xDF0623036F253116ULL,
		0x964DBAFC5E0AF2C1ULL,
		0xAB7FF5E70CA62C6EULL,
		0x7537C9DE93452D79ULL,
		0xBD8C83EC10D1B53CULL,
		0x7212BB717DCEA573ULL
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
		0x7588CB62F710392EULL,
		0x6C92A7F8B61C8819ULL,
		0x58EE54595E32B969ULL,
		0xD306FE0220D452E3ULL,
		0x89ECCFD8A9F28A83ULL,
		0x668AD1CC06B26F19ULL,
		0x8898017CB0551AC4ULL,
		0x10B9CC7CB25D3937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB1196C5EE20725CULL,
		0xD9254FF16C391032ULL,
		0xB1DCA8B2BC6572D2ULL,
		0xA60DFC0441A8A5C6ULL,
		0x13D99FB153E51507ULL,
		0xCD15A3980D64DE33ULL,
		0x113002F960AA3588ULL,
		0x217398F964BA726FULL
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
		0x14A37D7326DF1EC1ULL,
		0x7102FE2139846D94ULL,
		0x703269DD84AFD7DBULL,
		0xD7E1BE0CC1E50C22ULL,
		0x774894B064209295ULL,
		0x671BD6B3845EB944ULL,
		0x5CBDD552CC1FBA2EULL,
		0x201D49BBD33C4D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2946FAE64DBE3D82ULL,
		0xE205FC427308DB28ULL,
		0xE064D3BB095FAFB6ULL,
		0xAFC37C1983CA1844ULL,
		0xEE912960C841252BULL,
		0xCE37AD6708BD7288ULL,
		0xB97BAAA5983F745CULL,
		0x403A9377A6789A24ULL
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
		0xA22F8F75996C675EULL,
		0x3BACDB77C6FE0A5FULL,
		0x6AD6F76035C4E88EULL,
		0x267E58B354116F26ULL,
		0x219B1397262B1611ULL,
		0x9AA92282B72962E2ULL,
		0x520E223BAB588601ULL,
		0x3EE299A594C7D3F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x445F1EEB32D8CEBCULL,
		0x7759B6EF8DFC14BFULL,
		0xD5ADEEC06B89D11CULL,
		0x4CFCB166A822DE4CULL,
		0x4336272E4C562C22ULL,
		0x355245056E52C5C4ULL,
		0xA41C447756B10C03ULL,
		0x7DC5334B298FA7EAULL
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
		0x026B77DDF6712A36ULL,
		0x18D00D1E55A47232ULL,
		0x033BF1C67A0B7A1BULL,
		0x546BD6778C17EBC0ULL,
		0xD43B5ECF27B892C9ULL,
		0x8541B4837069B1CEULL,
		0x37A64A426EBCDC7FULL,
		0x25DA30F39A874A69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04D6EFBBECE2546CULL,
		0x31A01A3CAB48E464ULL,
		0x0677E38CF416F436ULL,
		0xA8D7ACEF182FD780ULL,
		0xA876BD9E4F712592ULL,
		0x0A836906E0D3639DULL,
		0x6F4C9484DD79B8FFULL,
		0x4BB461E7350E94D2ULL
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
		0xDAA0780AF9770999ULL,
		0x6F07C37B6955CAD8ULL,
		0x4C60C2B5590EA1DAULL,
		0x670813C21CF4430DULL,
		0xB64D88F0741A602EULL,
		0x2EF3C0BBB4FEB464ULL,
		0x5CDCA0C7C36CF5DFULL,
		0x1B934602F7AB9B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB540F015F2EE1332ULL,
		0xDE0F86F6D2AB95B1ULL,
		0x98C1856AB21D43B4ULL,
		0xCE10278439E8861AULL,
		0x6C9B11E0E834C05CULL,
		0x5DE7817769FD68C9ULL,
		0xB9B9418F86D9EBBEULL,
		0x37268C05EF573732ULL
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
		0xD457A61F7DC4FDD6ULL,
		0x2970D216B86975E5ULL,
		0xA85E3F5CA204BB36ULL,
		0x1C730487003450D5ULL,
		0xCB3596206D71D8B4ULL,
		0xA11102AFC92673C5ULL,
		0x743B340BFE3FB177ULL,
		0x13515EA5DED61514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8AF4C3EFB89FBACULL,
		0x52E1A42D70D2EBCBULL,
		0x50BC7EB94409766CULL,
		0x38E6090E0068A1ABULL,
		0x966B2C40DAE3B168ULL,
		0x4222055F924CE78BULL,
		0xE8766817FC7F62EFULL,
		0x26A2BD4BBDAC2A28ULL
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
		0x5F183D9BC4CE87D0ULL,
		0x27F75D109C521A40ULL,
		0x3E4AFD97876790ACULL,
		0xF94979F03CE6ABE7ULL,
		0xAFB64EB21A5A119DULL,
		0xD1891FDC7B80646FULL,
		0x95BE1A1A7D2858F8ULL,
		0x0DCEA71D50C4F7B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE307B37899D0FA0ULL,
		0x4FEEBA2138A43480ULL,
		0x7C95FB2F0ECF2158ULL,
		0xF292F3E079CD57CEULL,
		0x5F6C9D6434B4233BULL,
		0xA3123FB8F700C8DFULL,
		0x2B7C3434FA50B1F1ULL,
		0x1B9D4E3AA189EF65ULL
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
		0x50A82BE92E0F0B5CULL,
		0xA4C0B2CA3AEDAA05ULL,
		0x52317F48E0C09D84ULL,
		0x78457128348F6EF2ULL,
		0x4A0A1FC2DDC0E0ACULL,
		0x6B6F7578976186CCULL,
		0xC79386F9E4E4BBF7ULL,
		0x1A1FA6536DD4BFD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15057D25C1E16B8ULL,
		0x4981659475DB540AULL,
		0xA462FE91C1813B09ULL,
		0xF08AE250691EDDE4ULL,
		0x94143F85BB81C158ULL,
		0xD6DEEAF12EC30D98ULL,
		0x8F270DF3C9C977EEULL,
		0x343F4CA6DBA97FA9ULL
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
		0x824126CB4286C32FULL,
		0x537764B460B43C78ULL,
		0x6052AC2A4945AD6CULL,
		0xD3E0DCC5B804148FULL,
		0xDC84E04E36A38411ULL,
		0x46FD2ADD47E5581DULL,
		0xDE5D792A2CC3DD7EULL,
		0x34B5060A30E0E964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04824D96850D865EULL,
		0xA6EEC968C16878F1ULL,
		0xC0A55854928B5AD8ULL,
		0xA7C1B98B7008291EULL,
		0xB909C09C6D470823ULL,
		0x8DFA55BA8FCAB03BULL,
		0xBCBAF2545987BAFCULL,
		0x696A0C1461C1D2C9ULL
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
		0x8C76A951036FAA0EULL,
		0xDB7BE9374243FCE2ULL,
		0x118735CB3541B90FULL,
		0x4AF3FAB56E09872DULL,
		0x16AF78151A803690ULL,
		0x6BE99805251801D3ULL,
		0x981F8A7EFECDD192ULL,
		0x3E4A6E6F9295AFC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18ED52A206DF541CULL,
		0xB6F7D26E8487F9C5ULL,
		0x230E6B966A83721FULL,
		0x95E7F56ADC130E5AULL,
		0x2D5EF02A35006D20ULL,
		0xD7D3300A4A3003A6ULL,
		0x303F14FDFD9BA324ULL,
		0x7C94DCDF252B5F89ULL
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
		0x70E1352038AD16B0ULL,
		0x0DD8987DE0647CC1ULL,
		0xD6F066F6F365DB69ULL,
		0x8C4D6A66CC149E95ULL,
		0x40A5E69346E5904BULL,
		0xA84AD34E33907691ULL,
		0x9A332920FCF41663ULL,
		0x26467C8F9D3D14BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1C26A40715A2D60ULL,
		0x1BB130FBC0C8F982ULL,
		0xADE0CDEDE6CBB6D2ULL,
		0x189AD4CD98293D2BULL,
		0x814BCD268DCB2097ULL,
		0x5095A69C6720ED22ULL,
		0x34665241F9E82CC7ULL,
		0x4C8CF91F3A7A2977ULL
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
		0x71E25C6E25A50802ULL,
		0x21203A2C7578B3C6ULL,
		0x1078B2CE107EC9AFULL,
		0x37A4477A106660A5ULL,
		0xAA2DD74119079B0AULL,
		0x379411C67796311FULL,
		0x78C1497A564979EDULL,
		0x3879B2440558282FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C4B8DC4B4A1004ULL,
		0x42407458EAF1678CULL,
		0x20F1659C20FD935EULL,
		0x6F488EF420CCC14AULL,
		0x545BAE82320F3614ULL,
		0x6F28238CEF2C623FULL,
		0xF18292F4AC92F3DAULL,
		0x70F364880AB0505EULL
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
		0x34EFEB820F10F5BFULL,
		0xF776AB274AADA9D0ULL,
		0xDAD8124BB1B4A43FULL,
		0x26D41F8D77A55350ULL,
		0x9486DE75E25B7CB7ULL,
		0x61A50007E47A7DB2ULL,
		0xA36610953947ECA1ULL,
		0x13BF653EFF744FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69DFD7041E21EB7EULL,
		0xEEED564E955B53A0ULL,
		0xB5B024976369487FULL,
		0x4DA83F1AEF4AA6A1ULL,
		0x290DBCEBC4B6F96EULL,
		0xC34A000FC8F4FB65ULL,
		0x46CC212A728FD942ULL,
		0x277ECA7DFEE89FE7ULL
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
		0xE46E2B5AD5C1E5DBULL,
		0xE59A30092558DDD6ULL,
		0x2E5FB96390E6880FULL,
		0x793FED139CF579A2ULL,
		0x8EF733AF3A25E2FFULL,
		0xD006A64892E689C7ULL,
		0x922D3C9D3167FE8FULL,
		0x3D12748C45DCD5C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8DC56B5AB83CBB6ULL,
		0xCB3460124AB1BBADULL,
		0x5CBF72C721CD101FULL,
		0xF27FDA2739EAF344ULL,
		0x1DEE675E744BC5FEULL,
		0xA00D4C9125CD138FULL,
		0x245A793A62CFFD1FULL,
		0x7A24E9188BB9AB89ULL
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
		0xF0E6EEE9CF7EFB2CULL,
		0xFDDB55B8B60DC67EULL,
		0xDE8A28EF3A6A535CULL,
		0xDA7EBDD9D2855A3AULL,
		0xB8EBECF677E6E1EBULL,
		0x34F1009E7F57D8F7ULL,
		0xBC914E65D9E748FDULL,
		0x0A0039B810E86615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1CDDDD39EFDF658ULL,
		0xFBB6AB716C1B8CFDULL,
		0xBD1451DE74D4A6B9ULL,
		0xB4FD7BB3A50AB475ULL,
		0x71D7D9ECEFCDC3D7ULL,
		0x69E2013CFEAFB1EFULL,
		0x79229CCBB3CE91FAULL,
		0x1400737021D0CC2BULL
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
		0x00F3A3B8DDC84D03ULL,
		0x0E1F17100542A18AULL,
		0x22CF0542B8060A65ULL,
		0xA424702D05F9B376ULL,
		0xBA758951E090F445ULL,
		0xCF722429DEA74B73ULL,
		0xDBEBDF9BD70C8506ULL,
		0x252A1DED8F99A4EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E74771BB909A06ULL,
		0x1C3E2E200A854314ULL,
		0x459E0A85700C14CAULL,
		0x4848E05A0BF366ECULL,
		0x74EB12A3C121E88BULL,
		0x9EE44853BD4E96E7ULL,
		0xB7D7BF37AE190A0DULL,
		0x4A543BDB1F3349DFULL
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
		0xF609F88A4AD7BFFCULL,
		0xA4114FC174E481B8ULL,
		0x894D2FBD51A7429CULL,
		0x8476E0B67367B93BULL,
		0xE8A6EBD21624D7FAULL,
		0x0A2AF9D11B6B4033ULL,
		0x92828032DFDA4687ULL,
		0x331DC836CB44C315ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC13F11495AF7FF8ULL,
		0x48229F82E9C90371ULL,
		0x129A5F7AA34E8539ULL,
		0x08EDC16CE6CF7277ULL,
		0xD14DD7A42C49AFF5ULL,
		0x1455F3A236D68067ULL,
		0x25050065BFB48D0EULL,
		0x663B906D9689862BULL
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
		0x364908DCD1AA5944ULL,
		0x97E73166B483C836ULL,
		0xBC0EE91C9C6155B6ULL,
		0x3F127CDDCF01A9A7ULL,
		0x09A3B9ECCFC57AA1ULL,
		0x5DDD919AD9311C83ULL,
		0x034B2C82EEE72B59ULL,
		0x307987E4678C09EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C9211B9A354B288ULL,
		0x2FCE62CD6907906CULL,
		0x781DD23938C2AB6DULL,
		0x7E24F9BB9E03534FULL,
		0x134773D99F8AF542ULL,
		0xBBBB2335B2623906ULL,
		0x06965905DDCE56B2ULL,
		0x60F30FC8CF1813D6ULL
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
		0x349A3D186A01CFAEULL,
		0x3668A2433B93382AULL,
		0x15F7ECDD5823A27DULL,
		0x48D54E4E82CD153EULL,
		0x393B91E912D3B00DULL,
		0xA22C8242470F42D8ULL,
		0xE85E7BE8993D8F6DULL,
		0x19B81DF91E72ACB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69347A30D4039F5CULL,
		0x6CD1448677267054ULL,
		0x2BEFD9BAB04744FAULL,
		0x91AA9C9D059A2A7CULL,
		0x727723D225A7601AULL,
		0x445904848E1E85B0ULL,
		0xD0BCF7D1327B1EDBULL,
		0x33703BF23CE55973ULL
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
		0x73BA7AD637D88B6CULL,
		0x80246E3F900CA704ULL,
		0xD091DAD414A3DC4CULL,
		0xB09B0DF4DFD7BF9CULL,
		0x7EACF8A279A1C45CULL,
		0xA1BB0C582D9D49CCULL,
		0xEB05F2677C4D6965ULL,
		0x19147A193FD3C4DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE774F5AC6FB116D8ULL,
		0x0048DC7F20194E08ULL,
		0xA123B5A82947B899ULL,
		0x61361BE9BFAF7F39ULL,
		0xFD59F144F34388B9ULL,
		0x437618B05B3A9398ULL,
		0xD60BE4CEF89AD2CBULL,
		0x3228F4327FA789B5ULL
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
		0x85EB8023C91550ACULL,
		0x984112E21DCD7E2AULL,
		0x1F2AFDC146407671ULL,
		0x29D7C90984DD2C76ULL,
		0x09740E94D0C8E1BEULL,
		0x2C33481C294A2A2DULL,
		0xD1B12C3756EF894DULL,
		0x2D40488BAA0C8C7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BD70047922AA158ULL,
		0x308225C43B9AFC55ULL,
		0x3E55FB828C80ECE3ULL,
		0x53AF921309BA58ECULL,
		0x12E81D29A191C37CULL,
		0x586690385294545AULL,
		0xA362586EADDF129AULL,
		0x5A809117541918F7ULL
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
		0xCE123A4629CB9CF8ULL,
		0xBFCEC979D84E313BULL,
		0x4C015706F4CB5A15ULL,
		0x1643645C1439CBEAULL,
		0x73CBB7007846D7A1ULL,
		0x79D98262181051E6ULL,
		0xDE0F2650B13F5AB8ULL,
		0x1E751E9E1EDD28D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C24748C539739F0ULL,
		0x7F9D92F3B09C6277ULL,
		0x9802AE0DE996B42BULL,
		0x2C86C8B8287397D4ULL,
		0xE7976E00F08DAF42ULL,
		0xF3B304C43020A3CCULL,
		0xBC1E4CA1627EB570ULL,
		0x3CEA3D3C3DBA51ABULL
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
		0x2A583710D07103F1ULL,
		0x8B01A7BBFA007C24ULL,
		0xC86296B73BC8E307ULL,
		0x8F93BC99B52D13B6ULL,
		0x114645C1D8C10E35ULL,
		0x7ED8900BF81541BEULL,
		0x9CFDB5D3E3EE836FULL,
		0x33A43C87B9E202E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B06E21A0E207E2ULL,
		0x16034F77F400F848ULL,
		0x90C52D6E7791C60FULL,
		0x1F2779336A5A276DULL,
		0x228C8B83B1821C6BULL,
		0xFDB12017F02A837CULL,
		0x39FB6BA7C7DD06DEULL,
		0x6748790F73C405D1ULL
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
		0xD8E4AB7D48F26887ULL,
		0x2B9FAE2010736668ULL,
		0xD2C273A40435F23CULL,
		0x0531A0C3DE62AC65ULL,
		0xF8EEC6277794EEFCULL,
		0x2F0074EB82BA9997ULL,
		0xCF7C6EDDC30EE62DULL,
		0x34FBD0337C85B4BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1C956FA91E4D10EULL,
		0x573F5C4020E6CCD1ULL,
		0xA584E748086BE478ULL,
		0x0A634187BCC558CBULL,
		0xF1DD8C4EEF29DDF8ULL,
		0x5E00E9D70575332FULL,
		0x9EF8DDBB861DCC5AULL,
		0x69F7A066F90B697DULL
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
		0x19D6DF1AD7933CF5ULL,
		0x027E033E14DF3934ULL,
		0xE88990EE3B820326ULL,
		0x9EDA9345985E1702ULL,
		0x858B49866E0D4A5BULL,
		0x4358C3C52C8ED23AULL,
		0x58A2B6255D7E36A5ULL,
		0x15ED6F87EE23D1B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33ADBE35AF2679EAULL,
		0x04FC067C29BE7268ULL,
		0xD11321DC7704064CULL,
		0x3DB5268B30BC2E05ULL,
		0x0B16930CDC1A94B7ULL,
		0x86B1878A591DA475ULL,
		0xB1456C4ABAFC6D4AULL,
		0x2BDADF0FDC47A366ULL
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
		0x75DF20805A4123C6ULL,
		0xDB4A42B789F7A35FULL,
		0xA0B199869565688CULL,
		0x4BAC0C481152918DULL,
		0xC3B32CBEE84C5EDEULL,
		0xEFC0A3E6C424FC26ULL,
		0xA91C7068AECBB3B9ULL,
		0x040D8DD97619B3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBE4100B482478CULL,
		0xB694856F13EF46BEULL,
		0x4163330D2ACAD119ULL,
		0x9758189022A5231BULL,
		0x8766597DD098BDBCULL,
		0xDF8147CD8849F84DULL,
		0x5238E0D15D976773ULL,
		0x081B1BB2EC3367D3ULL
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
		0xD6DF31D1FBEDAB46ULL,
		0xC73157ECCB2F956AULL,
		0x12F823A5CEB21A46ULL,
		0x54B63C883F64305EULL,
		0x18C81E3D0B7471BFULL,
		0xCEA93F77C519C0D9ULL,
		0xA2DE9DFD23755A24ULL,
		0x35F4277B0C576937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADBE63A3F7DB568CULL,
		0x8E62AFD9965F2AD5ULL,
		0x25F0474B9D64348DULL,
		0xA96C79107EC860BCULL,
		0x31903C7A16E8E37EULL,
		0x9D527EEF8A3381B2ULL,
		0x45BD3BFA46EAB449ULL,
		0x6BE84EF618AED26FULL
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
		0x2A806C85A1ECC4F0ULL,
		0x318EB671F569077AULL,
		0xCDD2C48970B6BC6DULL,
		0x797EDC438FF74EE0ULL,
		0xD46E12F0DCEAA02EULL,
		0xE4214DAE8B009B0BULL,
		0x3FE90335E5E7FFCAULL,
		0x163BC346A2337AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5500D90B43D989E0ULL,
		0x631D6CE3EAD20EF4ULL,
		0x9BA58912E16D78DAULL,
		0xF2FDB8871FEE9DC1ULL,
		0xA8DC25E1B9D5405CULL,
		0xC8429B5D16013617ULL,
		0x7FD2066BCBCFFF95ULL,
		0x2C77868D4466F5CEULL
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
		0x8F8E21BA8B511679ULL,
		0x6B1E36F5B627E1B1ULL,
		0x38E60F35DFAC06EEULL,
		0x542298458E2C6AB2ULL,
		0x3D6EB422AF764C68ULL,
		0xC94E0AB73BAEB550ULL,
		0xEBD9AF2DD800EC3FULL,
		0x3E9C5C7428D08112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1C437516A22CF2ULL,
		0xD63C6DEB6C4FC363ULL,
		0x71CC1E6BBF580DDCULL,
		0xA845308B1C58D564ULL,
		0x7ADD68455EEC98D0ULL,
		0x929C156E775D6AA0ULL,
		0xD7B35E5BB001D87FULL,
		0x7D38B8E851A10225ULL
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
		0x3D1BA605B65E2B0EULL,
		0xE3263FF78BD43AA8ULL,
		0x88EF315173C97121ULL,
		0x803F2398660A7F93ULL,
		0xABFADF0D55B671C1ULL,
		0x495BA379D0AFD01BULL,
		0x367C36FC44A49A07ULL,
		0x19EF3650C7302E0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A374C0B6CBC561CULL,
		0xC64C7FEF17A87550ULL,
		0x11DE62A2E792E243ULL,
		0x007E4730CC14FF27ULL,
		0x57F5BE1AAB6CE383ULL,
		0x92B746F3A15FA037ULL,
		0x6CF86DF88949340EULL,
		0x33DE6CA18E605C1AULL
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
		0xD6B4D0AD5040C9E3ULL,
		0x7E2F5F2BD4C485F5ULL,
		0x31E13D0D11DF7717ULL,
		0x064D97D6C4A43073ULL,
		0x6EF8B50DF4685C80ULL,
		0x2A63919B982A6B94ULL,
		0x08FF477BD9F94C42ULL,
		0x2D571B39DD9203B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD69A15AA08193C6ULL,
		0xFC5EBE57A9890BEBULL,
		0x63C27A1A23BEEE2EULL,
		0x0C9B2FAD894860E6ULL,
		0xDDF16A1BE8D0B900ULL,
		0x54C723373054D728ULL,
		0x11FE8EF7B3F29884ULL,
		0x5AAE3673BB24076CULL
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
		0xD9EBEC0DD35F0247ULL,
		0xE2F0750479CCB186ULL,
		0x23A7701580555E49ULL,
		0x74A8FF2835629357ULL,
		0xE389045BC4168D2AULL,
		0x6C38EA5A54902D99ULL,
		0xCF8DBBC583AE7210ULL,
		0x2DD74F5E3380AA3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D7D81BA6BE048EULL,
		0xC5E0EA08F399630DULL,
		0x474EE02B00AABC93ULL,
		0xE951FE506AC526AEULL,
		0xC71208B7882D1A54ULL,
		0xD871D4B4A9205B33ULL,
		0x9F1B778B075CE420ULL,
		0x5BAE9EBC6701547FULL
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
		0x08888047C0963E16ULL,
		0x5C959D15F53E867CULL,
		0x95F4E4506AF1372FULL,
		0x008EE6D5A0A5C17DULL,
		0x8A394151F0A75444ULL,
		0xB7D9CC2DA76DC6E9ULL,
		0xC2B735F98FA4FDD8ULL,
		0x1C19C21FD9FE13ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1111008F812C7C2CULL,
		0xB92B3A2BEA7D0CF8ULL,
		0x2BE9C8A0D5E26E5EULL,
		0x011DCDAB414B82FBULL,
		0x147282A3E14EA888ULL,
		0x6FB3985B4EDB8DD3ULL,
		0x856E6BF31F49FBB1ULL,
		0x3833843FB3FC275BULL
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
		0x7B07470AE3C67FD0ULL,
		0xBBF874793777235EULL,
		0x8D0EBC775008C4CEULL,
		0x27CEDE5456EE7994ULL,
		0xB6BE8A15F0771872ULL,
		0xDAF52E1517F3531DULL,
		0x8F84128AD0DE26D9ULL,
		0x3C63E3EC03BC27D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF60E8E15C78CFFA0ULL,
		0x77F0E8F26EEE46BCULL,
		0x1A1D78EEA011899DULL,
		0x4F9DBCA8ADDCF329ULL,
		0x6D7D142BE0EE30E4ULL,
		0xB5EA5C2A2FE6A63BULL,
		0x1F082515A1BC4DB3ULL,
		0x78C7C7D807784FA3ULL
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
		0x00FE04E31A834A90ULL,
		0xFAFAB53E7E6FF930ULL,
		0x10B3F06CFF7EB653ULL,
		0x20927A18C8571EECULL,
		0xDF9B3AE3B0524FF5ULL,
		0xDBB12AB7A05741DDULL,
		0x9E87F240C7516CCAULL,
		0x0F53F208AEF80A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FC09C635069520ULL,
		0xF5F56A7CFCDFF260ULL,
		0x2167E0D9FEFD6CA7ULL,
		0x4124F43190AE3DD8ULL,
		0xBF3675C760A49FEAULL,
		0xB762556F40AE83BBULL,
		0x3D0FE4818EA2D995ULL,
		0x1EA7E4115DF014C3ULL
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
		0x47E15454191F00EBULL,
		0x0530E5500315554EULL,
		0xA07E69E9E12485EFULL,
		0x9D2F866A821C5975ULL,
		0x998106B3BF5F3C79ULL,
		0xDF9B077DEC44683CULL,
		0xB3B575149C056759ULL,
		0x2BEEF9102E19B43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC2A8A8323E01D6ULL,
		0x0A61CAA0062AAA9CULL,
		0x40FCD3D3C2490BDEULL,
		0x3A5F0CD50438B2EBULL,
		0x33020D677EBE78F3ULL,
		0xBF360EFBD888D079ULL,
		0x676AEA29380ACEB3ULL,
		0x57DDF2205C33687FULL
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
		0x3E2E4FB0BD956899ULL,
		0x81794E98285525A7ULL,
		0x6C1C3073A00EF9C5ULL,
		0xE07358B050EB097AULL,
		0xF08133D33D62F117ULL,
		0xB9DC6E3B4A8377FEULL,
		0xE4B959F3402C2667ULL,
		0x133B7658FFA1F5DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C5C9F617B2AD132ULL,
		0x02F29D3050AA4B4EULL,
		0xD83860E7401DF38BULL,
		0xC0E6B160A1D612F4ULL,
		0xE10267A67AC5E22FULL,
		0x73B8DC769506EFFDULL,
		0xC972B3E680584CCFULL,
		0x2676ECB1FF43EBBDULL
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
		0x16F00431515CD9CCULL,
		0x849EECE1B4B72FE4ULL,
		0xD3EAD0C4BB998EF3ULL,
		0x787BD0E1DA75841AULL,
		0x36F68B924B7DCA90ULL,
		0xA318A34E7C8B53A7ULL,
		0x044FBE2E713A8430ULL,
		0x2DB7A5DC897E3C50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE00862A2B9B398ULL,
		0x093DD9C3696E5FC8ULL,
		0xA7D5A18977331DE7ULL,
		0xF0F7A1C3B4EB0835ULL,
		0x6DED172496FB9520ULL,
		0x4631469CF916A74EULL,
		0x089F7C5CE2750861ULL,
		0x5B6F4BB912FC78A0ULL
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
		0xB0EF4D44D84B818DULL,
		0x1734FAE24D94DE5CULL,
		0x8E65AE8A6D856F7EULL,
		0x2AD4012BB9A5D29AULL,
		0xDC85A41723D120F6ULL,
		0x45ADD8B8913D55D8ULL,
		0xDD6F10C2ED29594DULL,
		0x30C67FA020AFF144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DE9A89B097031AULL,
		0x2E69F5C49B29BCB9ULL,
		0x1CCB5D14DB0ADEFCULL,
		0x55A80257734BA535ULL,
		0xB90B482E47A241ECULL,
		0x8B5BB171227AABB1ULL,
		0xBADE2185DA52B29AULL,
		0x618CFF40415FE289ULL
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
		0xB3E724C4F256F798ULL,
		0x984C883EF163FCC5ULL,
		0xFF6D735B6EE7CAB6ULL,
		0x7AC6CB92048CD5AEULL,
		0xE52B43C0181D89BCULL,
		0xCBD50C595E85A1FCULL,
		0xBA3A0171A2BB71D1ULL,
		0x0FBDA53140AC9DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67CE4989E4ADEF30ULL,
		0x3099107DE2C7F98BULL,
		0xFEDAE6B6DDCF956DULL,
		0xF58D97240919AB5DULL,
		0xCA568780303B1378ULL,
		0x97AA18B2BD0B43F9ULL,
		0x747402E34576E3A3ULL,
		0x1F7B4A6281593BA1ULL
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
		0xCBEEF02E7383CE22ULL,
		0x06A986260088AF71ULL,
		0x8414F900CA725852ULL,
		0xF43AC1233F410443ULL,
		0x1D22956F90361F27ULL,
		0x88C9FD841C94B47AULL,
		0x712F5133562404B1ULL,
		0x3330880243A7A34CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DDE05CE7079C44ULL,
		0x0D530C4C01115EE3ULL,
		0x0829F20194E4B0A4ULL,
		0xE87582467E820887ULL,
		0x3A452ADF206C3E4FULL,
		0x1193FB08392968F4ULL,
		0xE25EA266AC480963ULL,
		0x66611004874F4698ULL
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
		0xB705F75A7B83D09CULL,
		0x71C40A8CD29C463BULL,
		0x7CAC45D32D744ED2ULL,
		0x6BDAA4F27AB71060ULL,
		0x1EE650799A26D585ULL,
		0x4C01C7BF312A4442ULL,
		0x56E26611DB4AF32CULL,
		0x2FE9C283FEACAFFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0BEEB4F707A138ULL,
		0xE3881519A5388C77ULL,
		0xF9588BA65AE89DA4ULL,
		0xD7B549E4F56E20C0ULL,
		0x3DCCA0F3344DAB0AULL,
		0x98038F7E62548884ULL,
		0xADC4CC23B695E658ULL,
		0x5FD38507FD595FFEULL
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
		0xC43AF1411A1DC02BULL,
		0x3BE08C5966CD4F85ULL,
		0x4220FCDBF3A38635ULL,
		0xEF0B2E942C8ABFE6ULL,
		0x299035FE4BDE2312ULL,
		0x0FBBA6FA4459D73BULL,
		0xB747100EC04DE07FULL,
		0x01C08C47F058A7B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8875E282343B8056ULL,
		0x77C118B2CD9A9F0BULL,
		0x8441F9B7E7470C6AULL,
		0xDE165D2859157FCCULL,
		0x53206BFC97BC4625ULL,
		0x1F774DF488B3AE76ULL,
		0x6E8E201D809BC0FEULL,
		0x0381188FE0B14F63ULL
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
		0x34F4BA54C1EBAA70ULL,
		0xE0552100CA34BD1FULL,
		0xBA25CD8510AD59B7ULL,
		0x8DC1ED7EAD37FC3AULL,
		0x39148570A2B991B5ULL,
		0x2DAE990C88327091ULL,
		0x9311FA446088CA29ULL,
		0x07E008452486A84AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69E974A983D754E0ULL,
		0xC0AA420194697A3EULL,
		0x744B9B0A215AB36FULL,
		0x1B83DAFD5A6FF875ULL,
		0x72290AE14573236BULL,
		0x5B5D32191064E122ULL,
		0x2623F488C1119452ULL,
		0x0FC0108A490D5095ULL
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
		0x2773E62254287225ULL,
		0x3607D4697D7EA354ULL,
		0x226D717ABE43B0F5ULL,
		0x1867EC8D696D4ABFULL,
		0x3E019A55867ADBDDULL,
		0x14E19FDEBE38E137ULL,
		0x067E80583B7655ACULL,
		0x10B07F1DBCBA510EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE7CC44A850E44AULL,
		0x6C0FA8D2FAFD46A8ULL,
		0x44DAE2F57C8761EAULL,
		0x30CFD91AD2DA957EULL,
		0x7C0334AB0CF5B7BAULL,
		0x29C33FBD7C71C26EULL,
		0x0CFD00B076ECAB58ULL,
		0x2160FE3B7974A21CULL
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
		0x223477F5676C7CF1ULL,
		0x23599BBC408937ECULL,
		0xA16AE0400E6781ACULL,
		0x3CA81A332A348C64ULL,
		0xF84649D0F826D4D3ULL,
		0xE6791FA1E21322D9ULL,
		0xFB3DE23A49C14C33ULL,
		0x121135510669F4D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4468EFEACED8F9E2ULL,
		0x46B3377881126FD8ULL,
		0x42D5C0801CCF0358ULL,
		0x79503466546918C9ULL,
		0xF08C93A1F04DA9A6ULL,
		0xCCF23F43C42645B3ULL,
		0xF67BC47493829867ULL,
		0x24226AA20CD3E9A7ULL
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
		0xA4A37028E8242847ULL,
		0xDCEB06D375FCE9E4ULL,
		0x4EC54D2A44B357ABULL,
		0x7D142C383726896CULL,
		0x6FAFB37CE1EC7ABFULL,
		0x4E8C0B298DCB3A95ULL,
		0xE410596F7AD216ECULL,
		0x3DAE4FA47E5ACBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4946E051D048508EULL,
		0xB9D60DA6EBF9D3C9ULL,
		0x9D8A9A548966AF57ULL,
		0xFA2858706E4D12D8ULL,
		0xDF5F66F9C3D8F57EULL,
		0x9D1816531B96752AULL,
		0xC820B2DEF5A42DD8ULL,
		0x7B5C9F48FCB5974BULL
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
		0x542EC2FAD8C38489ULL,
		0x02C420075D548347ULL,
		0xB4063F452A54D188ULL,
		0x8540AC4920B0DEBCULL,
		0xB5A849FE65B24166ULL,
		0xD3703F5DB6F23F2AULL,
		0xD621918E4EA71E0DULL,
		0x057BB5EFC23FCE20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA85D85F5B1870912ULL,
		0x0588400EBAA9068EULL,
		0x680C7E8A54A9A310ULL,
		0x0A8158924161BD79ULL,
		0x6B5093FCCB6482CDULL,
		0xA6E07EBB6DE47E55ULL,
		0xAC43231C9D4E3C1BULL,
		0x0AF76BDF847F9C41ULL
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
		0xE763F45FD4145048ULL,
		0x115EA78826A80DCDULL,
		0x25B7FD184A523354ULL,
		0x7C32829869BE90E2ULL,
		0xF163C4E272033B9FULL,
		0x39816798A4B452E7ULL,
		0x072FD5F3D42AD273ULL,
		0x0DBD8359D960B438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC7E8BFA828A090ULL,
		0x22BD4F104D501B9BULL,
		0x4B6FFA3094A466A8ULL,
		0xF8650530D37D21C4ULL,
		0xE2C789C4E406773EULL,
		0x7302CF314968A5CFULL,
		0x0E5FABE7A855A4E6ULL,
		0x1B7B06B3B2C16870ULL
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
		0x44EE26889CF92253ULL,
		0x5DA18E1CB14E132FULL,
		0x9B094181395EE797ULL,
		0x6F021A1F5386FC4EULL,
		0x88D35BBCF4FF7E5DULL,
		0x76624F19EBB5B262ULL,
		0xA97048C2E623F78DULL,
		0x16861EF8B0E41F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DC4D1139F244A6ULL,
		0xBB431C39629C265EULL,
		0x3612830272BDCF2EULL,
		0xDE04343EA70DF89DULL,
		0x11A6B779E9FEFCBAULL,
		0xECC49E33D76B64C5ULL,
		0x52E09185CC47EF1AULL,
		0x2D0C3DF161C83E2DULL
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
		0x26241035730EB5F8ULL,
		0x3DBB97033F2AC056ULL,
		0xF8C30EDCF40E1250ULL,
		0xC3775F7EE64AA394ULL,
		0xFEDE080A5C48B203ULL,
		0x6A96BA5CFBE37885ULL,
		0x84AEF9C0D92617D6ULL,
		0x3A95E7936DC75B48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C48206AE61D6BF0ULL,
		0x7B772E067E5580ACULL,
		0xF1861DB9E81C24A0ULL,
		0x86EEBEFDCC954729ULL,
		0xFDBC1014B8916407ULL,
		0xD52D74B9F7C6F10BULL,
		0x095DF381B24C2FACULL,
		0x752BCF26DB8EB691ULL
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
		0x7B8175AB5ACD5C3BULL,
		0xBD776726F98283C6ULL,
		0x30CC70AF4226CB73ULL,
		0x0E3429C83F67104AULL,
		0x79E1A7A953890D3FULL,
		0xC65A24A13B7D80DEULL,
		0xB5F78526B4CEA63AULL,
		0x2C076069C190FC86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF702EB56B59AB876ULL,
		0x7AEECE4DF305078CULL,
		0x6198E15E844D96E7ULL,
		0x1C6853907ECE2094ULL,
		0xF3C34F52A7121A7EULL,
		0x8CB4494276FB01BCULL,
		0x6BEF0A4D699D4C75ULL,
		0x580EC0D38321F90DULL
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
		0x4BD246BBEFE8BDA7ULL,
		0x48DFFE33ECC8FC82ULL,
		0x1299631026558C90ULL,
		0x1E774D705D1E44C6ULL,
		0xC539C6822245DC42ULL,
		0x2AAFEE4236F0AA0FULL,
		0x9A10ECC32943C5A4ULL,
		0x25100FEBD2B342EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97A48D77DFD17B4EULL,
		0x91BFFC67D991F904ULL,
		0x2532C6204CAB1920ULL,
		0x3CEE9AE0BA3C898CULL,
		0x8A738D04448BB884ULL,
		0x555FDC846DE1541FULL,
		0x3421D98652878B48ULL,
		0x4A201FD7A56685DFULL
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
		0xE629BD123C9875D7ULL,
		0x28174B2251888B8AULL,
		0x69C0BC29B4315BD7ULL,
		0xDDEA9CFC4B98A8E8ULL,
		0x6648B347BC91B3C2ULL,
		0x54DAD1867D53F16FULL,
		0xDBB8986475FC725CULL,
		0x1CF3A46F58DF66EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC537A247930EBAEULL,
		0x502E9644A3111715ULL,
		0xD38178536862B7AEULL,
		0xBBD539F8973151D0ULL,
		0xCC91668F79236785ULL,
		0xA9B5A30CFAA7E2DEULL,
		0xB77130C8EBF8E4B8ULL,
		0x39E748DEB1BECDD7ULL
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
		0xC1D1D96296D2BA89ULL,
		0xA809F3F26E140F77ULL,
		0xA1C38B6E70270464ULL,
		0x61102CFA1A3731DAULL,
		0xD5F4B4033D3F75ACULL,
		0xEAB948A643B16F32ULL,
		0x86FFE46DEFE2F066ULL,
		0x0E1A9B2305A0F2D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83A3B2C52DA57512ULL,
		0x5013E7E4DC281EEFULL,
		0x438716DCE04E08C9ULL,
		0xC22059F4346E63B5ULL,
		0xABE968067A7EEB58ULL,
		0xD572914C8762DE65ULL,
		0x0DFFC8DBDFC5E0CDULL,
		0x1C3536460B41E5A1ULL
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
		0xFBD7C350391BE1BAULL,
		0x98ED5E7D9EF396A5ULL,
		0x08FFDAD2644FE9B6ULL,
		0x439DD5D87FB0F44DULL,
		0x542575B9A223464DULL,
		0x954F92A75C21A061ULL,
		0x2389490837E4F9B9ULL,
		0x3D76D4B5BF0CF697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7AF86A07237C374ULL,
		0x31DABCFB3DE72D4BULL,
		0x11FFB5A4C89FD36DULL,
		0x873BABB0FF61E89AULL,
		0xA84AEB7344468C9AULL,
		0x2A9F254EB84340C2ULL,
		0x471292106FC9F373ULL,
		0x7AEDA96B7E19ED2EULL
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
		0x1E1020DB481067C3ULL,
		0x8D4C75280E2E7CABULL,
		0x0836A0C8B44F7EDAULL,
		0x7E5755E0A37222F8ULL,
		0x6EEEFE917D6A4FCBULL,
		0x35158CD0377B17F7ULL,
		0xB79FE3CEB9BB93DCULL,
		0x000F1CDD4CEAF99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C2041B69020CF86ULL,
		0x1A98EA501C5CF956ULL,
		0x106D4191689EFDB5ULL,
		0xFCAEABC146E445F0ULL,
		0xDDDDFD22FAD49F96ULL,
		0x6A2B19A06EF62FEEULL,
		0x6F3FC79D737727B8ULL,
		0x001E39BA99D5F335ULL
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
		0x44F7F534A0C70071ULL,
		0x95D08D4D7C382C7FULL,
		0x9DECA6267E12E174ULL,
		0x6CD745FCB5EE73DAULL,
		0x46EBDEC9ABE49AAFULL,
		0x38D2FE77F14A6231ULL,
		0x86279A8F8D590015ULL,
		0x1E8C2AD2D88986EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EFEA69418E00E2ULL,
		0x2BA11A9AF87058FEULL,
		0x3BD94C4CFC25C2E9ULL,
		0xD9AE8BF96BDCE7B5ULL,
		0x8DD7BD9357C9355EULL,
		0x71A5FCEFE294C462ULL,
		0x0C4F351F1AB2002AULL,
		0x3D1855A5B1130DD5ULL
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
		0x316658383158EDCAULL,
		0x9D5D2083B552F472ULL,
		0xB7B8B8D88A35060BULL,
		0xEF3B91F82429E1C2ULL,
		0x7BD3E785DD8C880FULL,
		0x4396995486775492ULL,
		0x432A726409C85A74ULL,
		0x07733D4DFE62D48FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62CCB07062B1DB94ULL,
		0x3ABA41076AA5E8E4ULL,
		0x6F7171B1146A0C17ULL,
		0xDE7723F04853C385ULL,
		0xF7A7CF0BBB19101FULL,
		0x872D32A90CEEA924ULL,
		0x8654E4C81390B4E8ULL,
		0x0EE67A9BFCC5A91EULL
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
		0x2FC56874F5371866ULL,
		0x88EBF9E9889D681AULL,
		0x026A04FD754B3FEFULL,
		0x530A9D31A198D2FBULL,
		0x694CB14528FAD400ULL,
		0x2111C42C9825D698ULL,
		0x5B96B68DD8C8F91EULL,
		0x163F28EE96E2FD71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F8AD0E9EA6E30CCULL,
		0x11D7F3D3113AD034ULL,
		0x04D409FAEA967FDFULL,
		0xA6153A634331A5F6ULL,
		0xD299628A51F5A800ULL,
		0x42238859304BAD30ULL,
		0xB72D6D1BB191F23CULL,
		0x2C7E51DD2DC5FAE2ULL
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
		0xE4515280E5C691E5ULL,
		0x3A80C6BD8963B6C9ULL,
		0x36EB275396FADF3DULL,
		0x728187B66663E997ULL,
		0x6DD119E9AA610833ULL,
		0x7886FA5E52DFECC0ULL,
		0xB2E7FA6F3F447B6FULL,
		0x32550B7C84A8DF6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8A2A501CB8D23CAULL,
		0x75018D7B12C76D93ULL,
		0x6DD64EA72DF5BE7AULL,
		0xE5030F6CCCC7D32EULL,
		0xDBA233D354C21066ULL,
		0xF10DF4BCA5BFD980ULL,
		0x65CFF4DE7E88F6DEULL,
		0x64AA16F90951BEDDULL
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
		0xFBEC37D3A2D8E2D7ULL,
		0x3630948F20DA603DULL,
		0xAC7AE87B0549587DULL,
		0x27B0BAFA2FB299A4ULL,
		0x095BF2924B09444EULL,
		0x0445B4985823918FULL,
		0x5B22E35F31CF9891ULL,
		0x2C0A040C112C2356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7D86FA745B1C5AEULL,
		0x6C61291E41B4C07BULL,
		0x58F5D0F60A92B0FAULL,
		0x4F6175F45F653349ULL,
		0x12B7E5249612889CULL,
		0x088B6930B047231EULL,
		0xB645C6BE639F3122ULL,
		0x58140818225846ACULL
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
		0x700C9BDFC0708BB8ULL,
		0x57B5303153E8059DULL,
		0xA71E3D1E12007AC4ULL,
		0x732BF58FEE870979ULL,
		0x0055BA44167788E6ULL,
		0xA7DA895757F8DF3FULL,
		0x9B261845B287BA1AULL,
		0x361F4C6B1DFBF9DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE01937BF80E11770ULL,
		0xAF6A6062A7D00B3AULL,
		0x4E3C7A3C2400F588ULL,
		0xE657EB1FDD0E12F3ULL,
		0x00AB74882CEF11CCULL,
		0x4FB512AEAFF1BE7EULL,
		0x364C308B650F7435ULL,
		0x6C3E98D63BF7F3B9ULL
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
		0x314AE5BADCB82328ULL,
		0xBCC35D3EECFEA73CULL,
		0x82F4620BE6B9EA7BULL,
		0x1EE3E7DD6C9F11A3ULL,
		0xB667CDFA9C67CD28ULL,
		0x7CBC3030A8C226A6ULL,
		0x804A714053ACC96CULL,
		0x20747D0453691A2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6295CB75B9704650ULL,
		0x7986BA7DD9FD4E78ULL,
		0x05E8C417CD73D4F7ULL,
		0x3DC7CFBAD93E2347ULL,
		0x6CCF9BF538CF9A50ULL,
		0xF978606151844D4DULL,
		0x0094E280A75992D8ULL,
		0x40E8FA08A6D23457ULL
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
		0xBD68412D7770BC79ULL,
		0x038B5A737134725BULL,
		0xE0903C5DB5B351CCULL,
		0x2C86D21DF0987693ULL,
		0xF33BA99FEE4B449EULL,
		0xA548B5CFE1F81E56ULL,
		0x009CA8AD391B3D2CULL,
		0x3F909336824DC15FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD0825AEEE178F2ULL,
		0x0716B4E6E268E4B7ULL,
		0xC12078BB6B66A398ULL,
		0x590DA43BE130ED27ULL,
		0xE677533FDC96893CULL,
		0x4A916B9FC3F03CADULL,
		0x0139515A72367A59ULL,
		0x7F21266D049B82BEULL
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
		0xB1D0F7DD0C979534ULL,
		0x4B6E3426D3DF2B3FULL,
		0x0C5BE0B34FA90FECULL,
		0x1C5368961318C466ULL,
		0xB2BE8E335664918BULL,
		0x2290710C0BD86ED4ULL,
		0xF7840E7162F97E03ULL,
		0x0FD8BC95CD5383E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63A1EFBA192F2A68ULL,
		0x96DC684DA7BE567FULL,
		0x18B7C1669F521FD8ULL,
		0x38A6D12C263188CCULL,
		0x657D1C66ACC92316ULL,
		0x4520E21817B0DDA9ULL,
		0xEF081CE2C5F2FC06ULL,
		0x1FB1792B9AA707CFULL
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
		0xA42E70F9C029574AULL,
		0x161BC3FBD8AB1748ULL,
		0x3E2BCEBD6431BEB4ULL,
		0x44124FC2CE4A6ED1ULL,
		0x504B9EFFE6D9C07CULL,
		0xFBF5D0FE9A912AD3ULL,
		0xC0B6D32250AE7440ULL,
		0x16D767DF0A95D654ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x485CE1F38052AE94ULL,
		0x2C3787F7B1562E91ULL,
		0x7C579D7AC8637D68ULL,
		0x88249F859C94DDA2ULL,
		0xA0973DFFCDB380F8ULL,
		0xF7EBA1FD352255A6ULL,
		0x816DA644A15CE881ULL,
		0x2DAECFBE152BACA9ULL
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
		0xE68970B46BD43097ULL,
		0xC0C8E648959EF009ULL,
		0xE590EE5070440C46ULL,
		0x64A8C422EEBD4D6EULL,
		0xD5164B1F7C5E4DFBULL,
		0x02FEDC8645694AE7ULL,
		0x9A50C4BC8677C02CULL,
		0x053A2E177F36D853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD12E168D7A8612EULL,
		0x8191CC912B3DE013ULL,
		0xCB21DCA0E088188DULL,
		0xC9518845DD7A9ADDULL,
		0xAA2C963EF8BC9BF6ULL,
		0x05FDB90C8AD295CFULL,
		0x34A189790CEF8058ULL,
		0x0A745C2EFE6DB0A7ULL
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
		0xFAB5A25666CF1358ULL,
		0x9A405B842698CAF7ULL,
		0x3B0AD831C5F1DC16ULL,
		0x6AC2CCC2DDFB2A85ULL,
		0x2DDCC238BE757FF3ULL,
		0x4699B21B7E4C9A7AULL,
		0xE59CCC50820F11C5ULL,
		0x1E2539E067B9F778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF56B44ACCD9E26B0ULL,
		0x3480B7084D3195EFULL,
		0x7615B0638BE3B82DULL,
		0xD5859985BBF6550AULL,
		0x5BB984717CEAFFE6ULL,
		0x8D336436FC9934F4ULL,
		0xCB3998A1041E238AULL,
		0x3C4A73C0CF73EEF1ULL
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
		0xE8D3A0EE9095D377ULL,
		0x28FBD13BBC4A109EULL,
		0xD6E5D08D11321C13ULL,
		0x2717AD2D02FA829AULL,
		0x93428C3E70CD9F47ULL,
		0x02C0DE6B9BC99BC5ULL,
		0xDC837BE9055C470CULL,
		0x347FDFDD024A0EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A741DD212BA6EEULL,
		0x51F7A2777894213DULL,
		0xADCBA11A22643826ULL,
		0x4E2F5A5A05F50535ULL,
		0x2685187CE19B3E8EULL,
		0x0581BCD73793378BULL,
		0xB906F7D20AB88E18ULL,
		0x68FFBFBA04941D6FULL
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
		0xA1EDFB95F8047A59ULL,
		0x4D2DCCA24E12E3B1ULL,
		0x78FBDA90C86C943AULL,
		0x5BBF32F1A9680DA0ULL,
		0xA982E413DB4BD342ULL,
		0x3441683CBA764942ULL,
		0xB9FE72F9F3DCC107ULL,
		0x264BAC08D245E1DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43DBF72BF008F4B2ULL,
		0x9A5B99449C25C763ULL,
		0xF1F7B52190D92874ULL,
		0xB77E65E352D01B40ULL,
		0x5305C827B697A684ULL,
		0x6882D07974EC9285ULL,
		0x73FCE5F3E7B9820EULL,
		0x4C975811A48BC3B5ULL
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
		0xDA8BED5B8575424FULL,
		0xFAD9C4FF94C74A1BULL,
		0x20C24FA2A82CC7D4ULL,
		0x55C266F6ACCD18B8ULL,
		0xC826D7B1F98D5B11ULL,
		0xFA10CD8A7CF83093ULL,
		0xF841061A483D0AD6ULL,
		0x17CC9FD763B7AE54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB517DAB70AEA849EULL,
		0xF5B389FF298E9437ULL,
		0x41849F4550598FA9ULL,
		0xAB84CDED599A3170ULL,
		0x904DAF63F31AB622ULL,
		0xF4219B14F9F06127ULL,
		0xF0820C34907A15ADULL,
		0x2F993FAEC76F5CA9ULL
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
		0x4FD034BD2AC998D8ULL,
		0x6AC2770376BF84EAULL,
		0x297119E42DD188C6ULL,
		0x64D7964447FCE171ULL,
		0x49FF9CCEE8A4450BULL,
		0xFB12B15FF9E4E552ULL,
		0x2DEC206B26DE45FAULL,
		0x1AE00F6DC89D36BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA0697A559331B0ULL,
		0xD584EE06ED7F09D4ULL,
		0x52E233C85BA3118CULL,
		0xC9AF2C888FF9C2E2ULL,
		0x93FF399DD1488A16ULL,
		0xF62562BFF3C9CAA4ULL,
		0x5BD840D64DBC8BF5ULL,
		0x35C01EDB913A6D7EULL
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
		0xE712FC0FCBE06738ULL,
		0xD384E145BDB42DA1ULL,
		0xED10FB45752494ECULL,
		0x654D8717C73FDE02ULL,
		0xFE8ED4930E34E028ULL,
		0xAF0D1EF276842EBFULL,
		0x14AB65DD8F973A43ULL,
		0x3E9A63AAAE958D3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE25F81F97C0CE70ULL,
		0xA709C28B7B685B43ULL,
		0xDA21F68AEA4929D9ULL,
		0xCA9B0E2F8E7FBC05ULL,
		0xFD1DA9261C69C050ULL,
		0x5E1A3DE4ED085D7FULL,
		0x2956CBBB1F2E7487ULL,
		0x7D34C7555D2B1A78ULL
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
		0xB1101E88CF47586FULL,
		0xED07A4864159D2DEULL,
		0x6C03CFE88B8B140DULL,
		0x6FA4013D6330BD48ULL,
		0xB4409DC96C4FB553ULL,
		0xFE77A91A42A81731ULL,
		0x83429E7261A23F00ULL,
		0x2DCD14B10B9868CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62203D119E8EB0DEULL,
		0xDA0F490C82B3A5BDULL,
		0xD8079FD11716281BULL,
		0xDF48027AC6617A90ULL,
		0x68813B92D89F6AA6ULL,
		0xFCEF523485502E63ULL,
		0x06853CE4C3447E01ULL,
		0x5B9A29621730D19DULL
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
		0xC663E1CC05A30E2AULL,
		0x25890F29601C540AULL,
		0x712DAAE0D172A087ULL,
		0x6784DB6059A0163DULL,
		0x392E7B2C93C3E9E5ULL,
		0x291E5EFD0FD8548FULL,
		0x8C139951FE326A66ULL,
		0x2B0FE778D1CA855FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CC7C3980B461C54ULL,
		0x4B121E52C038A815ULL,
		0xE25B55C1A2E5410EULL,
		0xCF09B6C0B3402C7AULL,
		0x725CF6592787D3CAULL,
		0x523CBDFA1FB0A91EULL,
		0x182732A3FC64D4CCULL,
		0x561FCEF1A3950ABFULL
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
		0x97DF93CECFEC52A3ULL,
		0x2F1E90601CAC2C71ULL,
		0xCB0C2E6EA893072EULL,
		0x844257FAB55FF234ULL,
		0xADE66BEAEA9444ABULL,
		0x9C9A2EAB90B5E8ACULL,
		0x380B3F4D4552CC92ULL,
		0x23FC3F807876F21FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FBF279D9FD8A546ULL,
		0x5E3D20C0395858E3ULL,
		0x96185CDD51260E5CULL,
		0x0884AFF56ABFE469ULL,
		0x5BCCD7D5D5288957ULL,
		0x39345D57216BD159ULL,
		0x70167E9A8AA59925ULL,
		0x47F87F00F0EDE43EULL
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
		0x8A1FD6F9A194DB96ULL,
		0x0CA05DA82E8C1A45ULL,
		0xCCED98C8FE91A14CULL,
		0x2E1B4CD23041CB18ULL,
		0x8F7CD4504BD3D459ULL,
		0x8A258D32AAF4AFB8ULL,
		0x8F7EAA3E4EEBF11CULL,
		0x1C6EC41938D402C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143FADF34329B72CULL,
		0x1940BB505D18348BULL,
		0x99DB3191FD234298ULL,
		0x5C3699A460839631ULL,
		0x1EF9A8A097A7A8B2ULL,
		0x144B1A6555E95F71ULL,
		0x1EFD547C9DD7E239ULL,
		0x38DD883271A80581ULL
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
		0x86DA1F00B6B100E9ULL,
		0xE2E2105A2E5B74EEULL,
		0x336309C86E6B26E4ULL,
		0xF4641FEDDB086E02ULL,
		0xA17059CE1EE79E05ULL,
		0x47D9BF857AC0A493ULL,
		0x807FC943265E03B0ULL,
		0x2D2344B87B1266ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DB43E016D6201D2ULL,
		0xC5C420B45CB6E9DDULL,
		0x66C61390DCD64DC9ULL,
		0xE8C83FDBB610DC04ULL,
		0x42E0B39C3DCF3C0BULL,
		0x8FB37F0AF5814927ULL,
		0x00FF92864CBC0760ULL,
		0x5A468970F624CDD9ULL
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
		0x6377DA7846611871ULL,
		0x03DA4749B09028E3ULL,
		0x2B11D40521F99E95ULL,
		0x54EF8961AFD85A5DULL,
		0x43B82968BCA47916ULL,
		0xDB72F65293E71C69ULL,
		0x9782D9500F208EA1ULL,
		0x2F4619A3F325203CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6EFB4F08CC230E2ULL,
		0x07B48E93612051C6ULL,
		0x5623A80A43F33D2AULL,
		0xA9DF12C35FB0B4BAULL,
		0x877052D17948F22CULL,
		0xB6E5ECA527CE38D2ULL,
		0x2F05B2A01E411D43ULL,
		0x5E8C3347E64A4079ULL
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
		0x14AF7C9F97CF2AA7ULL,
		0x5C7DC611B7321337ULL,
		0x06CC63BE93566C5BULL,
		0xD39BABD83A5D96E8ULL,
		0xBADA82B88AF8B869ULL,
		0xF4B9DB9B2547B008ULL,
		0xAEE27AE5B8150035ULL,
		0x09CD9DAE6940CA69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295EF93F2F9E554EULL,
		0xB8FB8C236E64266EULL,
		0x0D98C77D26ACD8B6ULL,
		0xA73757B074BB2DD0ULL,
		0x75B5057115F170D3ULL,
		0xE973B7364A8F6011ULL,
		0x5DC4F5CB702A006BULL,
		0x139B3B5CD28194D3ULL
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
		0x4231B7AF47DD7656ULL,
		0x7C1D28027A320B7EULL,
		0xEDD55030D4F73EC2ULL,
		0x4C95978999802F31ULL,
		0x8DB89FF90D2EAF32ULL,
		0x68D66CA64FD05976ULL,
		0x9A06792FEF5A8EA3ULL,
		0x0D98086BD0D2E523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84636F5E8FBAECACULL,
		0xF83A5004F46416FCULL,
		0xDBAAA061A9EE7D84ULL,
		0x992B2F1333005E63ULL,
		0x1B713FF21A5D5E64ULL,
		0xD1ACD94C9FA0B2EDULL,
		0x340CF25FDEB51D46ULL,
		0x1B3010D7A1A5CA47ULL
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
		0x2C72EFCB7412DCD8ULL,
		0x49B6D3482E4A8A77ULL,
		0x31718C3F9F9E0B9AULL,
		0x7ADB4B91D8DBADA5ULL,
		0x9C5F16E287BFDFC6ULL,
		0x65CED5918D735094ULL,
		0x306874CF235E0ED8ULL,
		0x0BF36D6A63F34072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E5DF96E825B9B0ULL,
		0x936DA6905C9514EEULL,
		0x62E3187F3F3C1734ULL,
		0xF5B69723B1B75B4AULL,
		0x38BE2DC50F7FBF8CULL,
		0xCB9DAB231AE6A129ULL,
		0x60D0E99E46BC1DB0ULL,
		0x17E6DAD4C7E680E4ULL
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
		0xFA637B827875B41CULL,
		0x089896CF0E156ED6ULL,
		0x17DDAB094FDF6D9DULL,
		0xE97ABAA9C4D8EF30ULL,
		0xE567052875E867E4ULL,
		0xFD67389C1AAB83F8ULL,
		0x6091474A81234CCCULL,
		0x380B74434834DEFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4C6F704F0EB6838ULL,
		0x11312D9E1C2ADDADULL,
		0x2FBB56129FBEDB3AULL,
		0xD2F5755389B1DE60ULL,
		0xCACE0A50EBD0CFC9ULL,
		0xFACE7138355707F1ULL,
		0xC1228E9502469999ULL,
		0x7016E8869069BDFAULL
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
		0xEFE002F34410EB38ULL,
		0x6E8AB3A081A42F1DULL,
		0x0508AA4335A6BE0AULL,
		0x73B9FB224AF276D0ULL,
		0x10F69BA9C9F7483AULL,
		0xCE769CA5F3D6A634ULL,
		0xDC62DA23E294D0A5ULL,
		0x1261FDCD81C9A6BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFC005E68821D670ULL,
		0xDD15674103485E3BULL,
		0x0A1154866B4D7C14ULL,
		0xE773F64495E4EDA0ULL,
		0x21ED375393EE9074ULL,
		0x9CED394BE7AD4C68ULL,
		0xB8C5B447C529A14BULL,
		0x24C3FB9B03934D7BULL
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
		0xCC704D93E6AA5CE5ULL,
		0x23D5C964EE64B80FULL,
		0x9CDD030FAC9F5B53ULL,
		0x47F3EC41DCD97CC8ULL,
		0xC1C3D6C8314D4F03ULL,
		0xDA6A43C4A7FE76BCULL,
		0x873148B853F12CF8ULL,
		0x1551C3771C86CD39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98E09B27CD54B9CAULL,
		0x47AB92C9DCC9701FULL,
		0x39BA061F593EB6A6ULL,
		0x8FE7D883B9B2F991ULL,
		0x8387AD90629A9E06ULL,
		0xB4D487894FFCED79ULL,
		0x0E629170A7E259F1ULL,
		0x2AA386EE390D9A73ULL
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
		0x26E624C0FFC23042ULL,
		0xA45B66FB132D5183ULL,
		0x1C7C045B5E5228FFULL,
		0x734D66AD60CB8204ULL,
		0x9878FA5BC117E1FEULL,
		0xF944AEA1E845F0E0ULL,
		0x29B7F298EA866793ULL,
		0x3092BA9CAC6CFCE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCC4981FF846084ULL,
		0x48B6CDF6265AA306ULL,
		0x38F808B6BCA451FFULL,
		0xE69ACD5AC1970408ULL,
		0x30F1F4B7822FC3FCULL,
		0xF2895D43D08BE1C1ULL,
		0x536FE531D50CCF27ULL,
		0x6125753958D9F9C4ULL
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
		0xE90FD0616B8696F2ULL,
		0xCA7907BEF97DC86EULL,
		0x647F8A9C98FBF1C6ULL,
		0xD96F9CF85C0AE96CULL,
		0xF60F9F2BF5F8F8EBULL,
		0xE91203541DA351D0ULL,
		0xFA8381C769AD1747ULL,
		0x2F3EB35BFE823E7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21FA0C2D70D2DE4ULL,
		0x94F20F7DF2FB90DDULL,
		0xC8FF153931F7E38DULL,
		0xB2DF39F0B815D2D8ULL,
		0xEC1F3E57EBF1F1D7ULL,
		0xD22406A83B46A3A1ULL,
		0xF507038ED35A2E8FULL,
		0x5E7D66B7FD047CF9ULL
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
		0x07B5E5CAA1AFCACCULL,
		0xDBFD8CE88509D582ULL,
		0x1DDE6D21304B28F6ULL,
		0xE6BB23392163C2B0ULL,
		0xBD369A07685FC772ULL,
		0x0AF56ABFB8B2C8B1ULL,
		0xE28B4F6E7F9DBBF1ULL,
		0x0CF4C4F0D8F71A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F6BCB95435F9598ULL,
		0xB7FB19D10A13AB04ULL,
		0x3BBCDA42609651EDULL,
		0xCD76467242C78560ULL,
		0x7A6D340ED0BF8EE5ULL,
		0x15EAD57F71659163ULL,
		0xC5169EDCFF3B77E2ULL,
		0x19E989E1B1EE3483ULL
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
		0x708274C6A36FF7A7ULL,
		0x1B726AF7E75AB3A9ULL,
		0xC2DA3038FBB34FCEULL,
		0x0362A2CBFEC0C6EAULL,
		0x29D4945E9C781262ULL,
		0xC1B5A877424B9E2FULL,
		0xF9B7E5484A3CC614ULL,
		0x2EBA4AD79EA9957CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE104E98D46DFEF4EULL,
		0x36E4D5EFCEB56752ULL,
		0x85B46071F7669F9CULL,
		0x06C54597FD818DD5ULL,
		0x53A928BD38F024C4ULL,
		0x836B50EE84973C5EULL,
		0xF36FCA9094798C29ULL,
		0x5D7495AF3D532AF9ULL
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
		0x14D8834845916E54ULL,
		0xC139406B81D5DB2EULL,
		0xA7F1C9AF6E0963BCULL,
		0x01EF2196281FB5C2ULL,
		0x004CED79D2FAA0BBULL,
		0xFDD6B1F6D3BA255FULL,
		0x3F3F9DBFDE7C42A8ULL,
		0x3AE4E45378CEA9EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29B106908B22DCA8ULL,
		0x827280D703ABB65CULL,
		0x4FE3935EDC12C779ULL,
		0x03DE432C503F6B85ULL,
		0x0099DAF3A5F54176ULL,
		0xFBAD63EDA7744ABEULL,
		0x7E7F3B7FBCF88551ULL,
		0x75C9C8A6F19D53DEULL
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
		0xBC1ECCDD122B2E22ULL,
		0x078751D0652C33B4ULL,
		0xE1B3400A97A1DA84ULL,
		0x4C78A6169820C4BEULL,
		0xB9E2232031EFF827ULL,
		0x586A9F04BBDC8397ULL,
		0xEBFAE153DB1795A9ULL,
		0x3AC38B05FCED6516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x783D99BA24565C44ULL,
		0x0F0EA3A0CA586769ULL,
		0xC36680152F43B508ULL,
		0x98F14C2D3041897DULL,
		0x73C4464063DFF04EULL,
		0xB0D53E0977B9072FULL,
		0xD7F5C2A7B62F2B52ULL,
		0x7587160BF9DACA2DULL
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
		0xAE02108157E1AF1CULL,
		0x2DD5899DE8EE2A29ULL,
		0xF963C8EE650E4099ULL,
		0x6D70D1D1595BDFBEULL,
		0x57D843A24540546AULL,
		0x32CC1F17CC855F8DULL,
		0x4402264D92FE22E8ULL,
		0x2847F57D05DDB823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C042102AFC35E38ULL,
		0x5BAB133BD1DC5453ULL,
		0xF2C791DCCA1C8132ULL,
		0xDAE1A3A2B2B7BF7DULL,
		0xAFB087448A80A8D4ULL,
		0x65983E2F990ABF1AULL,
		0x88044C9B25FC45D0ULL,
		0x508FEAFA0BBB7046ULL
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
		0xADFBB0E64BE84AADULL,
		0x37E9B165CD8F9C59ULL,
		0x22C13755B2E4AF5AULL,
		0x070BE7D1D2B89187ULL,
		0x2A67B15D47110773ULL,
		0x8705A2F8BCA30A76ULL,
		0x04A4F92CF90391AFULL,
		0x2D488AB725652894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF761CC97D0955AULL,
		0x6FD362CB9B1F38B3ULL,
		0x45826EAB65C95EB4ULL,
		0x0E17CFA3A571230EULL,
		0x54CF62BA8E220EE6ULL,
		0x0E0B45F1794614ECULL,
		0x0949F259F207235FULL,
		0x5A91156E4ACA5128ULL
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
		0xC5E0914196F26E9EULL,
		0x44E63A363135E824ULL,
		0x9D6FF1790F438F52ULL,
		0x7D6B24BF7149974AULL,
		0x4BEAFC38DF651CC5ULL,
		0x68AD3F953CA136ECULL,
		0xFA696B20FCE19E0AULL,
		0x3F991EA20D69EF76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BC122832DE4DD3CULL,
		0x89CC746C626BD049ULL,
		0x3ADFE2F21E871EA4ULL,
		0xFAD6497EE2932E95ULL,
		0x97D5F871BECA398AULL,
		0xD15A7F2A79426DD8ULL,
		0xF4D2D641F9C33C14ULL,
		0x7F323D441AD3DEEDULL
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
		0x2E5A7976B828CC71ULL,
		0x1FD54CB9A9DC42FEULL,
		0xBC0836E253ABF3EBULL,
		0x8661D326352E777DULL,
		0x6E3062C08CC5A728ULL,
		0x28251429A1122962ULL,
		0x4EB0D13747DD6234ULL,
		0x1BECCAAEA61BCF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB4F2ED705198E2ULL,
		0x3FAA997353B885FCULL,
		0x78106DC4A757E7D6ULL,
		0x0CC3A64C6A5CEEFBULL,
		0xDC60C581198B4E51ULL,
		0x504A2853422452C4ULL,
		0x9D61A26E8FBAC468ULL,
		0x37D9955D4C379E42ULL
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
		0x304D6DB5B4DDA0DDULL,
		0xCC95B1819A29A7ABULL,
		0x6607BF749EB9F697ULL,
		0x2596BDFA20677618ULL,
		0x55234C634375DE8EULL,
		0xB7433298E05225D2ULL,
		0x4AB05C498F385B71ULL,
		0x31BDC89F101036CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609ADB6B69BB41BAULL,
		0x992B630334534F56ULL,
		0xCC0F7EE93D73ED2FULL,
		0x4B2D7BF440CEEC30ULL,
		0xAA4698C686EBBD1CULL,
		0x6E866531C0A44BA4ULL,
		0x9560B8931E70B6E3ULL,
		0x637B913E20206D98ULL
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
		0x5CA96AB7255B63F3ULL,
		0x1A81CA2B4C5E5BA5ULL,
		0x1E0BAEB505DA4377ULL,
		0xB8A583BC4A758BA6ULL,
		0xE9223F09B705D68EULL,
		0xF05F6B0A02A05D8EULL,
		0x70E25C68B78CDC0CULL,
		0x1BFFD61976A0520FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB952D56E4AB6C7E6ULL,
		0x3503945698BCB74AULL,
		0x3C175D6A0BB486EEULL,
		0x714B077894EB174CULL,
		0xD2447E136E0BAD1DULL,
		0xE0BED6140540BB1DULL,
		0xE1C4B8D16F19B819ULL,
		0x37FFAC32ED40A41EULL
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