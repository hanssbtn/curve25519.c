#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xCB147F82C86E5CF3ULL,
		0xA659BC9167BF9C14ULL,
		0xA35E4022A4E1A2C0ULL,
		0x0652AE5BB5D7DBCEULL,
		0x24813F263CBB01F4ULL,
		0xFF2E8D7084ECE5BDULL,
		0xA803C090349F8CC5ULL,
		0x0C641790B5566DC1ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x9628FF0590DCB9E6ULL,
		0x4CB37922CF7F3829ULL,
		0x46BC804549C34581ULL,
		0x0CA55CB76BAFB79DULL,
		0x49027E4C797603E8ULL,
		0xFE5D1AE109D9CB7AULL,
		0x50078120693F198BULL,
		0x18C82F216AACDB83ULL
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
		0x3B11EBB73524797BULL,
		0x8A0659446AADB39AULL,
		0x06C1E046814265F4ULL,
		0x92ACC4C92880BE65ULL,
		0x9B23E18CDD78A853ULL,
		0xD294600C45CCF30CULL,
		0x5968B5E7A9DC5663ULL,
		0x0EBC3D87CFEEA1F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7623D76E6A48F2F6ULL,
		0x140CB288D55B6734ULL,
		0x0D83C08D0284CBE9ULL,
		0x2559899251017CCAULL,
		0x3647C319BAF150A7ULL,
		0xA528C0188B99E619ULL,
		0xB2D16BCF53B8ACC7ULL,
		0x1D787B0F9FDD43F0ULL
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
		0xC0F3E2387F848A4BULL,
		0x8F4F12E89D232DFDULL,
		0xB72280F7935BACA4ULL,
		0x2393F1A56FFE2484ULL,
		0x98C060C62A5ECD69ULL,
		0xC07AC97AD5089AFAULL,
		0x99E20B0853617B16ULL,
		0x0DC490F44AF93132ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E7C470FF091496ULL,
		0x1E9E25D13A465BFBULL,
		0x6E4501EF26B75949ULL,
		0x4727E34ADFFC4909ULL,
		0x3180C18C54BD9AD2ULL,
		0x80F592F5AA1135F5ULL,
		0x33C41610A6C2F62DULL,
		0x1B8921E895F26265ULL
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
		0x15BBBCD16453385DULL,
		0x12DD134E61B7B447ULL,
		0x1092E26D500A8313ULL,
		0xAA6F21198C99023AULL,
		0xED3DF365598327ADULL,
		0x6E5BEF7A7FF34938ULL,
		0x5616FE970445277EULL,
		0x20B12FB9B9D2D38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7779A2C8A670BAULL,
		0x25BA269CC36F688EULL,
		0x2125C4DAA0150626ULL,
		0x54DE423319320474ULL,
		0xDA7BE6CAB3064F5BULL,
		0xDCB7DEF4FFE69271ULL,
		0xAC2DFD2E088A4EFCULL,
		0x41625F7373A5A718ULL
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
		0xAAC24F4E274EBC06ULL,
		0x5BCC4FD941E0FE15ULL,
		0x569C62713D434402ULL,
		0x0E9E6A8A9E951E7DULL,
		0xDA05E62D3354C480ULL,
		0x77992464890F13A3ULL,
		0xC5144DE54CD9A368ULL,
		0x39E420F0D53123FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55849E9C4E9D780CULL,
		0xB7989FB283C1FC2BULL,
		0xAD38C4E27A868804ULL,
		0x1D3CD5153D2A3CFAULL,
		0xB40BCC5A66A98900ULL,
		0xEF3248C9121E2747ULL,
		0x8A289BCA99B346D0ULL,
		0x73C841E1AA6247FBULL
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
		0xCA680581633E8AF7ULL,
		0xC95C7EF53E68959CULL,
		0x523A0A2817AE5CFDULL,
		0x2CF8A56E338533CCULL,
		0xC2026C50855A7D66ULL,
		0x19B860D69435D090ULL,
		0xA63623DD8E09DDEEULL,
		0x34AE33D713837C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D00B02C67D15EEULL,
		0x92B8FDEA7CD12B39ULL,
		0xA47414502F5CB9FBULL,
		0x59F14ADC670A6798ULL,
		0x8404D8A10AB4FACCULL,
		0x3370C1AD286BA121ULL,
		0x4C6C47BB1C13BBDCULL,
		0x695C67AE2706F805ULL
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
		0x24A73FE58FC0B1C7ULL,
		0xBF58B05316B63C6FULL,
		0xDC7BF8ED3C96AC4BULL,
		0x2143B15781ABBD8BULL,
		0xCC7DFD06BD5B433EULL,
		0x8F94324783640CD7ULL,
		0xE70F1EF7836E216CULL,
		0x17B86945281B6EE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x494E7FCB1F81638EULL,
		0x7EB160A62D6C78DEULL,
		0xB8F7F1DA792D5897ULL,
		0x428762AF03577B17ULL,
		0x98FBFA0D7AB6867CULL,
		0x1F28648F06C819AFULL,
		0xCE1E3DEF06DC42D9ULL,
		0x2F70D28A5036DDC1ULL
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
		0x2949468CDE98D924ULL,
		0x420BAB87311E48FEULL,
		0x4B04D79CCC0BBCC2ULL,
		0x8A2DC7AC499CB84AULL,
		0x46BFF6323E7C3583ULL,
		0xA618BB59D9F4D688ULL,
		0x594C7505B085EC98ULL,
		0x2CAA78FA88EC9555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52928D19BD31B248ULL,
		0x8417570E623C91FCULL,
		0x9609AF3998177984ULL,
		0x145B8F5893397094ULL,
		0x8D7FEC647CF86B07ULL,
		0x4C3176B3B3E9AD10ULL,
		0xB298EA0B610BD931ULL,
		0x5954F1F511D92AAAULL
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
		0xFF06B1FD4F99A926ULL,
		0x9B3ACDAD29DA0428ULL,
		0xF7ADCC5BB3BDD170ULL,
		0x2903F5B3A84F797CULL,
		0x9983C48ACB525DC0ULL,
		0x3520EC435B2BB8DCULL,
		0xC30979039C352072ULL,
		0x1936DF2142C0A823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0D63FA9F33524CULL,
		0x36759B5A53B40851ULL,
		0xEF5B98B7677BA2E1ULL,
		0x5207EB67509EF2F9ULL,
		0x3307891596A4BB80ULL,
		0x6A41D886B65771B9ULL,
		0x8612F207386A40E4ULL,
		0x326DBE4285815047ULL
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
		0xF155BE29180E2051ULL,
		0x4C9652E544310153ULL,
		0x13E52BE5859CA112ULL,
		0x33623C8CF28BCA50ULL,
		0x225E85167F5D0196ULL,
		0x464B41309B0876F4ULL,
		0xBF1FEFD19DBADAB3ULL,
		0x3E181A879C554034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AB7C52301C40A2ULL,
		0x992CA5CA886202A7ULL,
		0x27CA57CB0B394224ULL,
		0x66C47919E51794A0ULL,
		0x44BD0A2CFEBA032CULL,
		0x8C9682613610EDE8ULL,
		0x7E3FDFA33B75B566ULL,
		0x7C30350F38AA8069ULL
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
		0x7687651AD71318EFULL,
		0x1E3CF60B0DDF4604ULL,
		0x7244114F847C1934ULL,
		0xF9794D4D1B779D1DULL,
		0x3CD347AB84A4E759ULL,
		0x000B58B4D3C6BBFFULL,
		0x4E6E76B697F44470ULL,
		0x314E64ED84B97DF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED0ECA35AE2631DEULL,
		0x3C79EC161BBE8C08ULL,
		0xE488229F08F83268ULL,
		0xF2F29A9A36EF3A3AULL,
		0x79A68F570949CEB3ULL,
		0x0016B169A78D77FEULL,
		0x9CDCED6D2FE888E0ULL,
		0x629CC9DB0972FBE6ULL
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
		0x57FE4C802D212114ULL,
		0xBBA3B6812F1ABEB4ULL,
		0x7D345D253887D775ULL,
		0x605309D232A37E3FULL,
		0xB828F7C86968548EULL,
		0xFA4FBCB59C48EFCEULL,
		0xE1337C09D34A0935ULL,
		0x28079D838F93C2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFFC99005A424228ULL,
		0x77476D025E357D68ULL,
		0xFA68BA4A710FAEEBULL,
		0xC0A613A46546FC7EULL,
		0x7051EF90D2D0A91CULL,
		0xF49F796B3891DF9DULL,
		0xC266F813A694126BULL,
		0x500F3B071F278561ULL
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
		0x9498FF792D3B7DC5ULL,
		0x496271850E6BE906ULL,
		0xE6FAAE93C560EF12ULL,
		0x0CF82317C9B937B2ULL,
		0x383A559763FEDEAEULL,
		0x94CF381F8692ABC2ULL,
		0x02041DBB21125893ULL,
		0x1D2CC526CE8DB672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2931FEF25A76FB8AULL,
		0x92C4E30A1CD7D20DULL,
		0xCDF55D278AC1DE24ULL,
		0x19F0462F93726F65ULL,
		0x7074AB2EC7FDBD5CULL,
		0x299E703F0D255784ULL,
		0x04083B764224B127ULL,
		0x3A598A4D9D1B6CE4ULL
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
		0xA1C36352DE2BEE16ULL,
		0x7D51AC7EA403364AULL,
		0x3F64B28538585C13ULL,
		0x1C33F959137505FEULL,
		0xE4383CF3438936F9ULL,
		0xAFCA466C8BC2147BULL,
		0x7899EB5E1179BD45ULL,
		0x20C7FA363C44ACDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4386C6A5BC57DC2CULL,
		0xFAA358FD48066C95ULL,
		0x7EC9650A70B0B826ULL,
		0x3867F2B226EA0BFCULL,
		0xC87079E687126DF2ULL,
		0x5F948CD9178428F7ULL,
		0xF133D6BC22F37A8BULL,
		0x418FF46C788959BCULL
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
		0x87BC2E33C506305AULL,
		0xA8F26A8F97AB20A0ULL,
		0x21971EB488AB341CULL,
		0x0356FDF98A1230D9ULL,
		0xC3D52240F4A31AA7ULL,
		0x21F1643AD577D206ULL,
		0xC2FECED4ECB26917ULL,
		0x0F4399B5726F232FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F785C678A0C60B4ULL,
		0x51E4D51F2F564141ULL,
		0x432E3D6911566839ULL,
		0x06ADFBF3142461B2ULL,
		0x87AA4481E946354EULL,
		0x43E2C875AAEFA40DULL,
		0x85FD9DA9D964D22EULL,
		0x1E87336AE4DE465FULL
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
		0xAA3206D3373245E2ULL,
		0x0ACA4A4B9043D7B3ULL,
		0xA2644175936DE320ULL,
		0x9FA749903F991CC3ULL,
		0xDB4197561F7C8A6EULL,
		0xCE0DB9FD17407F89ULL,
		0x1710E253B64AF41AULL,
		0x2ED4F13800A98984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54640DA66E648BC4ULL,
		0x159494972087AF67ULL,
		0x44C882EB26DBC640ULL,
		0x3F4E93207F323987ULL,
		0xB6832EAC3EF914DDULL,
		0x9C1B73FA2E80FF13ULL,
		0x2E21C4A76C95E835ULL,
		0x5DA9E27001531308ULL
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
		0x3323F96806E791DEULL,
		0x5C9186C61B2A00ABULL,
		0xAA037A80A3473CB4ULL,
		0x0D1FEE1E0277BECFULL,
		0x24442A4B3EF6C8A1ULL,
		0xD7C150410637D903ULL,
		0x2079E6E0F839F0BFULL,
		0x3B9135715624E233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6647F2D00DCF23BCULL,
		0xB9230D8C36540156ULL,
		0x5406F501468E7968ULL,
		0x1A3FDC3C04EF7D9FULL,
		0x488854967DED9142ULL,
		0xAF82A0820C6FB206ULL,
		0x40F3CDC1F073E17FULL,
		0x77226AE2AC49C466ULL
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
		0x2FAB48C5E15E2916ULL,
		0x4B90A858FE616818ULL,
		0xF841D5871333703FULL,
		0x563E266F0CB67E0BULL,
		0x91CFF6BFC5882788ULL,
		0x001AD3508EE7DB6AULL,
		0x5D8D096F04A35C48ULL,
		0x027E3E0F93C3F036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F56918BC2BC522CULL,
		0x972150B1FCC2D030ULL,
		0xF083AB0E2666E07EULL,
		0xAC7C4CDE196CFC17ULL,
		0x239FED7F8B104F10ULL,
		0x0035A6A11DCFB6D5ULL,
		0xBB1A12DE0946B890ULL,
		0x04FC7C1F2787E06CULL
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
		0xAAD7FA5A0E807224ULL,
		0xB27ABB1E6C65E6CBULL,
		0xE92A06A05347DA2EULL,
		0x4F65517FC3DC13CDULL,
		0x1C1121E9F54415B0ULL,
		0x211ABC7F3B77E194ULL,
		0x337E837BB99CB560ULL,
		0x3293F5077147FAD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55AFF4B41D00E448ULL,
		0x64F5763CD8CBCD97ULL,
		0xD2540D40A68FB45DULL,
		0x9ECAA2FF87B8279BULL,
		0x382243D3EA882B60ULL,
		0x423578FE76EFC328ULL,
		0x66FD06F773396AC0ULL,
		0x6527EA0EE28FF5AAULL
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
		0x11D541022B55DEB9ULL,
		0xD7BB284A69BA6EC5ULL,
		0xAA25DA291B38045CULL,
		0xC2B9665D6E362C3FULL,
		0x9BCEE2F7F910B48FULL,
		0x96807C08F913F336ULL,
		0xE27A9011894FB9DFULL,
		0x18536382793FB397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23AA820456ABBD72ULL,
		0xAF765094D374DD8AULL,
		0x544BB452367008B9ULL,
		0x8572CCBADC6C587FULL,
		0x379DC5EFF221691FULL,
		0x2D00F811F227E66DULL,
		0xC4F52023129F73BFULL,
		0x30A6C704F27F672FULL
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
		0x586AA866A19730DAULL,
		0x051172C56C1E12A9ULL,
		0x0E29FD64D2068523ULL,
		0xD95E2C3E76C3288DULL,
		0x8F4F14A9B9C360AEULL,
		0x4994ADA81E5CF956ULL,
		0xB1217C3019B533DDULL,
		0x285F32AE7F7214CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0D550CD432E61B4ULL,
		0x0A22E58AD83C2552ULL,
		0x1C53FAC9A40D0A46ULL,
		0xB2BC587CED86511AULL,
		0x1E9E29537386C15DULL,
		0x93295B503CB9F2ADULL,
		0x6242F860336A67BAULL,
		0x50BE655CFEE4299FULL
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
		0x02C32E92FB747824ULL,
		0x74D3BA4841638F9CULL,
		0xC3B64584989CD46BULL,
		0x2E4A4DCFB08773C0ULL,
		0xCFC15A048A42779DULL,
		0x9BDAB51853F720BBULL,
		0x131A1AAD04FAA5A1ULL,
		0x34F35A7EBA9F938CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05865D25F6E8F048ULL,
		0xE9A7749082C71F38ULL,
		0x876C8B093139A8D6ULL,
		0x5C949B9F610EE781ULL,
		0x9F82B4091484EF3AULL,
		0x37B56A30A7EE4177ULL,
		0x2634355A09F54B43ULL,
		0x69E6B4FD753F2718ULL
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
		0x3CEE32E80E342FD5ULL,
		0xBBBEF13C600AD547ULL,
		0xD2B521784CFEF9E2ULL,
		0xC51E352C42AB6737ULL,
		0x6C1C9A79701CFC26ULL,
		0x6A8D72BAEB6F7738ULL,
		0x14FA74C2DE331787ULL,
		0x055C77AEE468541EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79DC65D01C685FAAULL,
		0x777DE278C015AA8EULL,
		0xA56A42F099FDF3C5ULL,
		0x8A3C6A588556CE6FULL,
		0xD83934F2E039F84DULL,
		0xD51AE575D6DEEE70ULL,
		0x29F4E985BC662F0EULL,
		0x0AB8EF5DC8D0A83CULL
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
		0x1D2B560E7290D694ULL,
		0xA8B9673BA37D9BFDULL,
		0x7C3E0055F00D4737ULL,
		0xEB6BCD5718AF85BAULL,
		0xC1A59CA64012A453ULL,
		0xF75891DCB47138FAULL,
		0x2A2D09C1590B9649ULL,
		0x2CD78EFCC4532CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A56AC1CE521AD28ULL,
		0x5172CE7746FB37FAULL,
		0xF87C00ABE01A8E6FULL,
		0xD6D79AAE315F0B74ULL,
		0x834B394C802548A7ULL,
		0xEEB123B968E271F5ULL,
		0x545A1382B2172C93ULL,
		0x59AF1DF988A659E2ULL
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
		0x14DE843DD1E5ED3EULL,
		0x0B6B1E0636C1BD28ULL,
		0xF1DF9F6DCBD1081BULL,
		0x33BBA869A4BDAEC4ULL,
		0x8F4C2B8C510E50D7ULL,
		0xFDB6A80AFEB4DE7FULL,
		0x0D7A475F6746AF06ULL,
		0x37AEC92152FB0874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BD087BA3CBDA7CULL,
		0x16D63C0C6D837A50ULL,
		0xE3BF3EDB97A21036ULL,
		0x677750D3497B5D89ULL,
		0x1E985718A21CA1AEULL,
		0xFB6D5015FD69BCFFULL,
		0x1AF48EBECE8D5E0DULL,
		0x6F5D9242A5F610E8ULL
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
		0xA60431FD1E53BCD1ULL,
		0x869C7AC6092DDF61ULL,
		0x9CA2AD41E729ECB4ULL,
		0x04DA36D941620A28ULL,
		0x7CBDDDFB24C0D384ULL,
		0x990E586DA6CB7612ULL,
		0x47CEEBA526C1ED34ULL,
		0x357B839611B3F676ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C0863FA3CA779A2ULL,
		0x0D38F58C125BBEC3ULL,
		0x39455A83CE53D969ULL,
		0x09B46DB282C41451ULL,
		0xF97BBBF64981A708ULL,
		0x321CB0DB4D96EC24ULL,
		0x8F9DD74A4D83DA69ULL,
		0x6AF7072C2367ECECULL
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
		0xD4D52674AE25F879ULL,
		0xE9DEB691AA21D845ULL,
		0xB6D7E1019CB1EAFEULL,
		0x64A8DDFDC444A2FFULL,
		0xB13365DEE8C14EAFULL,
		0xA1DF8E43880D5596ULL,
		0x0FE75632E37B5762ULL,
		0x1FBB04D3E47BF9E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9AA4CE95C4BF0F2ULL,
		0xD3BD6D235443B08BULL,
		0x6DAFC2033963D5FDULL,
		0xC951BBFB888945FFULL,
		0x6266CBBDD1829D5EULL,
		0x43BF1C87101AAB2DULL,
		0x1FCEAC65C6F6AEC5ULL,
		0x3F7609A7C8F7F3CAULL
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
		0x46A1FAD125A5D359ULL,
		0x32E125400A030471ULL,
		0xD7DDDA98066F9331ULL,
		0xB4278AAE2623DB7DULL,
		0x18CD97C5D4A53DA3ULL,
		0xC4957824244C2BF8ULL,
		0x6D5A0DEAE21C0044ULL,
		0x18B970E237728E24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D43F5A24B4BA6B2ULL,
		0x65C24A80140608E2ULL,
		0xAFBBB5300CDF2662ULL,
		0x684F155C4C47B6FBULL,
		0x319B2F8BA94A7B47ULL,
		0x892AF048489857F0ULL,
		0xDAB41BD5C4380089ULL,
		0x3172E1C46EE51C48ULL
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
		0x14710AADC8070F17ULL,
		0xDB7AC2158A8E5742ULL,
		0x9C7EBA1F623A1324ULL,
		0xEE949C19D0AF28D8ULL,
		0xE4B3C1DCC1021D2CULL,
		0xDF94151EB6902ADAULL,
		0x96E195DF12041CF1ULL,
		0x361A93650D71891FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E2155B900E1E2EULL,
		0xB6F5842B151CAE84ULL,
		0x38FD743EC4742649ULL,
		0xDD293833A15E51B1ULL,
		0xC96783B982043A59ULL,
		0xBF282A3D6D2055B5ULL,
		0x2DC32BBE240839E3ULL,
		0x6C3526CA1AE3123FULL
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
		0x56CD8FD6EF2F04F5ULL,
		0x50CF17AA76F2AEC1ULL,
		0x167C2542B2FE7FA7ULL,
		0xDFE5319AFB0E672FULL,
		0xBEB38A96D36B1301ULL,
		0x8F7326ED42DFA63AULL,
		0x7B553F9FAE65B7ECULL,
		0x1D65EF9202FF5EE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD9B1FADDE5E09EAULL,
		0xA19E2F54EDE55D82ULL,
		0x2CF84A8565FCFF4EULL,
		0xBFCA6335F61CCE5EULL,
		0x7D67152DA6D62603ULL,
		0x1EE64DDA85BF4C75ULL,
		0xF6AA7F3F5CCB6FD9ULL,
		0x3ACBDF2405FEBDD0ULL
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
		0x22AE05A812C400EFULL,
		0x24C2F561330C9FCFULL,
		0x84F05EBE3F151EBCULL,
		0xC411614D3E857410ULL,
		0x520A4E9B2624BE46ULL,
		0xDAD77B7974E058EAULL,
		0x53F04963C02DB49BULL,
		0x18F1805CDB1FFF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x455C0B50258801DEULL,
		0x4985EAC266193F9EULL,
		0x09E0BD7C7E2A3D78ULL,
		0x8822C29A7D0AE821ULL,
		0xA4149D364C497C8DULL,
		0xB5AEF6F2E9C0B1D4ULL,
		0xA7E092C7805B6937ULL,
		0x31E300B9B63FFEE0ULL
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
		0xB968FED62E109AFEULL,
		0x3F627F95E1809674ULL,
		0xD13FA462A862A802ULL,
		0xABD75CED3656BA87ULL,
		0xFE326CEF7E6FFCBAULL,
		0xF83CA2F27A25D2B2ULL,
		0x5EF199E3721203EBULL,
		0x13F751551996E092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72D1FDAC5C2135FCULL,
		0x7EC4FF2BC3012CE9ULL,
		0xA27F48C550C55004ULL,
		0x57AEB9DA6CAD750FULL,
		0xFC64D9DEFCDFF975ULL,
		0xF07945E4F44BA565ULL,
		0xBDE333C6E42407D7ULL,
		0x27EEA2AA332DC124ULL
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
		0x8C427526B1C1E6DEULL,
		0x1AF0CA7B293DD137ULL,
		0xBB5043350CD4C5C4ULL,
		0x80C71C7D2BED51FEULL,
		0x3A753C00688ECF28ULL,
		0xA20A6DBE3ABC64AEULL,
		0x0EFBC6108E19376CULL,
		0x1534DE91A95D0D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1884EA4D6383CDBCULL,
		0x35E194F6527BA26FULL,
		0x76A0866A19A98B88ULL,
		0x018E38FA57DAA3FDULL,
		0x74EA7800D11D9E51ULL,
		0x4414DB7C7578C95CULL,
		0x1DF78C211C326ED9ULL,
		0x2A69BD2352BA1A34ULL
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
		0xF9E8B5B84B032244ULL,
		0x48511DC0C963C659ULL,
		0x1B5F0129ED7E4CE6ULL,
		0x78C452EDCAFB79A9ULL,
		0x49B40552D6801DBEULL,
		0x2F0D6CA053A08E3AULL,
		0x8E546957CDBCB458ULL,
		0x1FA28E6878402296ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3D16B7096064488ULL,
		0x90A23B8192C78CB3ULL,
		0x36BE0253DAFC99CCULL,
		0xF188A5DB95F6F352ULL,
		0x93680AA5AD003B7CULL,
		0x5E1AD940A7411C74ULL,
		0x1CA8D2AF9B7968B0ULL,
		0x3F451CD0F080452DULL
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
		0x422D605A7E11CDD9ULL,
		0xBCA9CAAC71C50913ULL,
		0x8907645564989D7DULL,
		0xF3D6C0497A4B7938ULL,
		0x60C17FA973354BEBULL,
		0x638B010933D80F9DULL,
		0x5E8B3E2F82DAD261ULL,
		0x1A24C614F5C165E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x845AC0B4FC239BB2ULL,
		0x79539558E38A1226ULL,
		0x120EC8AAC9313AFBULL,
		0xE7AD8092F496F271ULL,
		0xC182FF52E66A97D7ULL,
		0xC716021267B01F3AULL,
		0xBD167C5F05B5A4C2ULL,
		0x34498C29EB82CBC4ULL
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
		0xC7B02EFCFF17F45CULL,
		0x25BCB14EE9D21136ULL,
		0x901594281FF1F2BDULL,
		0x1B147CB73C0FEFE2ULL,
		0x33C58593BD530474ULL,
		0x6AC88F8EE10EC510ULL,
		0x6AE98377F8B6C85EULL,
		0x21880FD703BB7A4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F605DF9FE2FE8B8ULL,
		0x4B79629DD3A4226DULL,
		0x202B28503FE3E57AULL,
		0x3628F96E781FDFC5ULL,
		0x678B0B277AA608E8ULL,
		0xD5911F1DC21D8A20ULL,
		0xD5D306EFF16D90BCULL,
		0x43101FAE0776F498ULL
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
		0x74E2F339256FB487ULL,
		0x85B9B185A09746D9ULL,
		0x88F400DB43B8E012ULL,
		0xF50F4048A9F8DA44ULL,
		0xA1E4434A6A8C0DFEULL,
		0x89C38C3108F83A41ULL,
		0xC4A30A8A1903DBCBULL,
		0x14167F39C60528CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C5E6724ADF690EULL,
		0x0B73630B412E8DB2ULL,
		0x11E801B68771C025ULL,
		0xEA1E809153F1B489ULL,
		0x43C88694D5181BFDULL,
		0x1387186211F07483ULL,
		0x894615143207B797ULL,
		0x282CFE738C0A5197ULL
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
		0xABA5BBE64A2D3CD3ULL,
		0x4B7C358C1352FA29ULL,
		0xAAA904B1982FC690ULL,
		0xAE8BF1A77AE12E35ULL,
		0xE3F3ED6CC3257F5FULL,
		0x1E2B8F1D4F1E721CULL,
		0x55EE07B28C82371CULL,
		0x32A3EBCBC532EF74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574B77CC945A79A6ULL,
		0x96F86B1826A5F453ULL,
		0x55520963305F8D20ULL,
		0x5D17E34EF5C25C6BULL,
		0xC7E7DAD9864AFEBFULL,
		0x3C571E3A9E3CE439ULL,
		0xABDC0F6519046E38ULL,
		0x6547D7978A65DEE8ULL
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
		0x31AB6B9E50FFB314ULL,
		0x40010A661F4E5306ULL,
		0xB2D023210A236995ULL,
		0x0FBCAC1388AF908BULL,
		0x9363247385D38366ULL,
		0x8D07B80D5D41EDBCULL,
		0xF22C61BFFB4E6EBAULL,
		0x3A1315BEE0C8DCD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6356D73CA1FF6628ULL,
		0x800214CC3E9CA60CULL,
		0x65A046421446D32AULL,
		0x1F795827115F2117ULL,
		0x26C648E70BA706CCULL,
		0x1A0F701ABA83DB79ULL,
		0xE458C37FF69CDD75ULL,
		0x74262B7DC191B9A1ULL
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
		0xDFE0B50FD0B3274EULL,
		0xDEA2E0587DE6A713ULL,
		0xB785D21F651C2801ULL,
		0xE1825EF3E57E6419ULL,
		0x145D5CA484AB31C0ULL,
		0x3DC8B8FE27816B92ULL,
		0xAFC5711BA3323B50ULL,
		0x38C3FAB7EF189072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFC16A1FA1664E9CULL,
		0xBD45C0B0FBCD4E27ULL,
		0x6F0BA43ECA385003ULL,
		0xC304BDE7CAFCC833ULL,
		0x28BAB94909566381ULL,
		0x7B9171FC4F02D724ULL,
		0x5F8AE237466476A0ULL,
		0x7187F56FDE3120E5ULL
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
		0xCED3797694B5844BULL,
		0x18259E2BC8C9B0F9ULL,
		0x46C75D57A3F8B6C4ULL,
		0x38A1387535F0E92BULL,
		0x64C7C620C3F74EEBULL,
		0xB630621909D2E4B7ULL,
		0xFA0220D48C1DA342ULL,
		0x049DA70F21BDDA4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA6F2ED296B0896ULL,
		0x304B3C57919361F3ULL,
		0x8D8EBAAF47F16D88ULL,
		0x714270EA6BE1D256ULL,
		0xC98F8C4187EE9DD6ULL,
		0x6C60C43213A5C96EULL,
		0xF40441A9183B4685ULL,
		0x093B4E1E437BB497ULL
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
		0x05D29CDCD3B85C6EULL,
		0x73EE1E720597F9CDULL,
		0x72BDAC6A71CFCC55ULL,
		0x6D8597B41082A138ULL,
		0xF2B9D58787D8D062ULL,
		0xB7E1365CF3A1BEFDULL,
		0x2A09D8AF25BAD220ULL,
		0x086B74137614A3C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BA539B9A770B8DCULL,
		0xE7DC3CE40B2FF39AULL,
		0xE57B58D4E39F98AAULL,
		0xDB0B2F6821054270ULL,
		0xE573AB0F0FB1A0C4ULL,
		0x6FC26CB9E7437DFBULL,
		0x5413B15E4B75A441ULL,
		0x10D6E826EC29478EULL
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
		0xB2DCA493E5DF6B9DULL,
		0x3C21C89FBD30F68BULL,
		0x61C7B81EF307A55DULL,
		0x3D52CD581620C14BULL,
		0xF5F7BBEC050DA59FULL,
		0xD579B2C5CE305746ULL,
		0x6668C9514FD90F46ULL,
		0x272E796F069179F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B94927CBBED73AULL,
		0x7843913F7A61ED17ULL,
		0xC38F703DE60F4ABAULL,
		0x7AA59AB02C418296ULL,
		0xEBEF77D80A1B4B3EULL,
		0xAAF3658B9C60AE8DULL,
		0xCCD192A29FB21E8DULL,
		0x4E5CF2DE0D22F3E8ULL
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
		0x953D3433F66DC283ULL,
		0x5E50D98312DE1B2EULL,
		0x888679B020790959ULL,
		0x5FE4C0C2EA0B64CDULL,
		0xB2AE40FE85E015BAULL,
		0xD8FD09021D53FD76ULL,
		0xBE631E0D1013B76EULL,
		0x27D5BFAF4F0797ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A7A6867ECDB8506ULL,
		0xBCA1B30625BC365DULL,
		0x110CF36040F212B2ULL,
		0xBFC98185D416C99BULL,
		0x655C81FD0BC02B74ULL,
		0xB1FA12043AA7FAEDULL,
		0x7CC63C1A20276EDDULL,
		0x4FAB7F5E9E0F2F57ULL
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
		0x0CA811FE2135564AULL,
		0x515BAC4A3BCC7644ULL,
		0x83DD452D5C403CC0ULL,
		0x782E2D6AA798969FULL,
		0x588AD21D685F7FFDULL,
		0x098C86D3FD7EA503ULL,
		0x78CBDF11B108B23AULL,
		0x346E3509EC4A82AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195023FC426AAC94ULL,
		0xA2B758947798EC88ULL,
		0x07BA8A5AB8807980ULL,
		0xF05C5AD54F312D3FULL,
		0xB115A43AD0BEFFFAULL,
		0x13190DA7FAFD4A06ULL,
		0xF197BE2362116474ULL,
		0x68DC6A13D895055CULL
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
		0xE6B69C7B6D8D39D3ULL,
		0x12BA9DE39961315BULL,
		0x6040F5FDAC8B4097ULL,
		0xF25510BBAAAF32ECULL,
		0xEEAF9B3ECCB8B506ULL,
		0x26AA72D9A3F2EBFCULL,
		0x505E8696A238A577ULL,
		0x0487130A24D29096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD6D38F6DB1A73A6ULL,
		0x25753BC732C262B7ULL,
		0xC081EBFB5916812EULL,
		0xE4AA2177555E65D8ULL,
		0xDD5F367D99716A0DULL,
		0x4D54E5B347E5D7F9ULL,
		0xA0BD0D2D44714AEEULL,
		0x090E261449A5212CULL
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
		0x43A5D802E8ADF2D2ULL,
		0xEC56465B8763CBBBULL,
		0x84C0861EED72AFCDULL,
		0x4CEDCDC45C1895DBULL,
		0x6895F953F092E74BULL,
		0x70D02523C88E52C0ULL,
		0xB63490F24D1190BBULL,
		0x0E33FDEE803CF252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x874BB005D15BE5A4ULL,
		0xD8AC8CB70EC79776ULL,
		0x09810C3DDAE55F9BULL,
		0x99DB9B88B8312BB7ULL,
		0xD12BF2A7E125CE96ULL,
		0xE1A04A47911CA580ULL,
		0x6C6921E49A232176ULL,
		0x1C67FBDD0079E4A5ULL
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
		0x617F2DBD8A48786BULL,
		0x47154F076CA47929ULL,
		0xF3851897D5ADFF38ULL,
		0xE7403CE3819159C0ULL,
		0x101648D06EC100F2ULL,
		0x0E5000BCE5ABB0BAULL,
		0xBF86EDBA799D28B1ULL,
		0x301DEC20638CA1D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FE5B7B1490F0D6ULL,
		0x8E2A9E0ED948F252ULL,
		0xE70A312FAB5BFE70ULL,
		0xCE8079C70322B381ULL,
		0x202C91A0DD8201E5ULL,
		0x1CA00179CB576174ULL,
		0x7F0DDB74F33A5162ULL,
		0x603BD840C71943B3ULL
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
		0x29925E44904467A4ULL,
		0x4D7D69310BFEA156ULL,
		0x72DB1B64F4D89F69ULL,
		0xBDB3C11ECF0A0E27ULL,
		0x239A4AD77AAA5E3EULL,
		0x21E0A1B9C21B4CEBULL,
		0x92FAFC05AAB3A8BEULL,
		0x11E2475819F21454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5324BC892088CF48ULL,
		0x9AFAD26217FD42ACULL,
		0xE5B636C9E9B13ED2ULL,
		0x7B67823D9E141C4EULL,
		0x473495AEF554BC7DULL,
		0x43C14373843699D6ULL,
		0x25F5F80B5567517CULL,
		0x23C48EB033E428A9ULL
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
		0x98E2A0D3D4A17971ULL,
		0x5CE43D3CF013F2F9ULL,
		0x34644EF2EB7283EAULL,
		0x8097AA5C734C79BBULL,
		0x640FFFE5D8832782ULL,
		0x300783EE1EF6FC14ULL,
		0x53FA87CA7C73CDA8ULL,
		0x34AFA5EEA59784EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31C541A7A942F2E2ULL,
		0xB9C87A79E027E5F3ULL,
		0x68C89DE5D6E507D4ULL,
		0x012F54B8E698F376ULL,
		0xC81FFFCBB1064F05ULL,
		0x600F07DC3DEDF828ULL,
		0xA7F50F94F8E79B50ULL,
		0x695F4BDD4B2F09DAULL
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
		0xF4D241AF164E1868ULL,
		0xBB04FFFED743DF73ULL,
		0x713BCE391060D32DULL,
		0xD0BC03F0DB695F52ULL,
		0x8544554CFDA201EFULL,
		0x20CA585CE7565904ULL,
		0xBD8CB2B6B36301C0ULL,
		0x009B99A53689592FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A4835E2C9C30D0ULL,
		0x7609FFFDAE87BEE7ULL,
		0xE2779C7220C1A65BULL,
		0xA17807E1B6D2BEA4ULL,
		0x0A88AA99FB4403DFULL,
		0x4194B0B9CEACB209ULL,
		0x7B19656D66C60380ULL,
		0x0137334A6D12B25FULL
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
		0xA32034855080776DULL,
		0xE6E76844B9C27767ULL,
		0xB02CF051EB618901ULL,
		0x247CBEEC50180B01ULL,
		0x08DCBB40AE9DB979ULL,
		0xDF5145E9536F0948ULL,
		0x115CF3247F285D0EULL,
		0x0146272D558D74AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4640690AA100EEDAULL,
		0xCDCED0897384EECFULL,
		0x6059E0A3D6C31203ULL,
		0x48F97DD8A0301603ULL,
		0x11B976815D3B72F2ULL,
		0xBEA28BD2A6DE1290ULL,
		0x22B9E648FE50BA1DULL,
		0x028C4E5AAB1AE95EULL
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
		0x076ED58FA6D5D66DULL,
		0x88DA8D5F73D0C525ULL,
		0xE1A484ED9F364B97ULL,
		0x98242F909FB7F7E1ULL,
		0xF8314260FBE16ED3ULL,
		0x0986CD77DE211E72ULL,
		0x59B539EF5E1BB191ULL,
		0x3163B403A7A086E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EDDAB1F4DABACDAULL,
		0x11B51ABEE7A18A4AULL,
		0xC34909DB3E6C972FULL,
		0x30485F213F6FEFC3ULL,
		0xF06284C1F7C2DDA7ULL,
		0x130D9AEFBC423CE5ULL,
		0xB36A73DEBC376322ULL,
		0x62C768074F410DC6ULL
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
		0x00DD36F00CCD2CE9ULL,
		0x142B90F39656B0AFULL,
		0x0FED52B6D287297EULL,
		0xE6A4DAE8F6BADDC8ULL,
		0xED29E1616FDDB55AULL,
		0x9BA1E696F021FD38ULL,
		0xC89677C40C5FC818ULL,
		0x243BF3DE0FA8E52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BA6DE0199A59D2ULL,
		0x285721E72CAD615EULL,
		0x1FDAA56DA50E52FCULL,
		0xCD49B5D1ED75BB90ULL,
		0xDA53C2C2DFBB6AB5ULL,
		0x3743CD2DE043FA71ULL,
		0x912CEF8818BF9031ULL,
		0x4877E7BC1F51CA5BULL
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
		0xA17EE7B3F8034705ULL,
		0x59C8DD60FCD4D514ULL,
		0x4F83A4B0165DD7EAULL,
		0xCA40A632C67022C2ULL,
		0x40C928404736EC68ULL,
		0x16C7A22AAE57103EULL,
		0xB9DD65E3C11AD95CULL,
		0x15A5D9046666AE97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42FDCF67F0068E0AULL,
		0xB391BAC1F9A9AA29ULL,
		0x9F0749602CBBAFD4ULL,
		0x94814C658CE04584ULL,
		0x819250808E6DD8D1ULL,
		0x2D8F44555CAE207CULL,
		0x73BACBC78235B2B8ULL,
		0x2B4BB208CCCD5D2FULL
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
		0x1E2F3B96B18C75AEULL,
		0xDF8AEC10FEF9C226ULL,
		0x9442161102433538ULL,
		0xF2961F4444CF9156ULL,
		0x905A4CC9EC441BB0ULL,
		0xC245FF5484CE8637ULL,
		0x4868521B0A5DF408ULL,
		0x3B216623BC7BA399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5E772D6318EB5CULL,
		0xBF15D821FDF3844CULL,
		0x28842C2204866A71ULL,
		0xE52C3E88899F22ADULL,
		0x20B49993D8883761ULL,
		0x848BFEA9099D0C6FULL,
		0x90D0A43614BBE811ULL,
		0x7642CC4778F74732ULL
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
		0x7B046B43768AD291ULL,
		0x6ABAEEFD5A7ABEE7ULL,
		0xF92745D431AB3445ULL,
		0xB42C522BDE1144AAULL,
		0x45853D0B75A96563ULL,
		0xC051B73147AAEFCDULL,
		0x9918996F64A5C4F7ULL,
		0x260BED8C94B7CF96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF608D686ED15A522ULL,
		0xD575DDFAB4F57DCEULL,
		0xF24E8BA86356688AULL,
		0x6858A457BC228955ULL,
		0x8B0A7A16EB52CAC7ULL,
		0x80A36E628F55DF9AULL,
		0x323132DEC94B89EFULL,
		0x4C17DB19296F9F2DULL
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
		0x3A7229EC154DF166ULL,
		0xC21935216514F016ULL,
		0x33EB9B37F7520A5DULL,
		0x1CF10A4B6A8B5C66ULL,
		0xAC8527C3D5AFE4CCULL,
		0x395D16D6BC425B3EULL,
		0xF871167C71158B8BULL,
		0x1DC7E234E753D4AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E453D82A9BE2CCULL,
		0x84326A42CA29E02CULL,
		0x67D7366FEEA414BBULL,
		0x39E21496D516B8CCULL,
		0x590A4F87AB5FC998ULL,
		0x72BA2DAD7884B67DULL,
		0xF0E22CF8E22B1716ULL,
		0x3B8FC469CEA7A95FULL
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
		0x302ABAF59BCCC81DULL,
		0x0642AF17C7300F77ULL,
		0x4DBCC9C82A251D44ULL,
		0xC61D9ABB387B01BBULL,
		0x1870D6153714DE54ULL,
		0xB7F43198D3444364ULL,
		0xF07F04AFE774A865ULL,
		0x122CF620A35E538AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605575EB3799903AULL,
		0x0C855E2F8E601EEEULL,
		0x9B799390544A3A88ULL,
		0x8C3B357670F60376ULL,
		0x30E1AC2A6E29BCA9ULL,
		0x6FE86331A68886C8ULL,
		0xE0FE095FCEE950CBULL,
		0x2459EC4146BCA715ULL
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
		0xABBEFE048051A309ULL,
		0xC3C9F75ABD00368BULL,
		0x9D9DC7BA23E16BD9ULL,
		0x941A09151B187FB6ULL,
		0xF59B4A0169B4E5F4ULL,
		0x85C184C95B03E101ULL,
		0x110A7342AD233FE1ULL,
		0x1E4A5E71E7550A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x577DFC0900A34612ULL,
		0x8793EEB57A006D17ULL,
		0x3B3B8F7447C2D7B3ULL,
		0x2834122A3630FF6DULL,
		0xEB369402D369CBE9ULL,
		0x0B830992B607C203ULL,
		0x2214E6855A467FC3ULL,
		0x3C94BCE3CEAA14AAULL
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
		0x5167E650CEF53EADULL,
		0x70D2BCEB67470A88ULL,
		0x490DDAD96861454EULL,
		0x8BD2FDA3F6FE569FULL,
		0xD8BDEA186C90A0B9ULL,
		0xC1BD69C6EAD9D43EULL,
		0x7A3BC838EBC2EE73ULL,
		0x3CE69A1F86A30332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2CFCCA19DEA7D5AULL,
		0xE1A579D6CE8E1510ULL,
		0x921BB5B2D0C28A9CULL,
		0x17A5FB47EDFCAD3EULL,
		0xB17BD430D9214173ULL,
		0x837AD38DD5B3A87DULL,
		0xF4779071D785DCE7ULL,
		0x79CD343F0D460664ULL
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
		0x4F92D65B8EA5D4FFULL,
		0xB9A014BF71510BBEULL,
		0x6244841FF100D608ULL,
		0x4A1455CF93D5958BULL,
		0x0CDC84A26FE622B0ULL,
		0xB697536B0F0096BFULL,
		0xFC84C1736BCE13D8ULL,
		0x0BDF2056F9BB8975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F25ACB71D4BA9FEULL,
		0x7340297EE2A2177CULL,
		0xC489083FE201AC11ULL,
		0x9428AB9F27AB2B16ULL,
		0x19B90944DFCC4560ULL,
		0x6D2EA6D61E012D7EULL,
		0xF90982E6D79C27B1ULL,
		0x17BE40ADF37712EBULL
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
		0x73CDE1918D8A189BULL,
		0xEEC25DD6A1246B1DULL,
		0xF2251AA8C2DCEAF3ULL,
		0xAABB3253BBCE3B52ULL,
		0xBD4BE1C4FDD52A49ULL,
		0x6F406EC8D87D8EE8ULL,
		0x0D91A8BB98C4B525ULL,
		0x34AF7FA50B96C977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE79BC3231B143136ULL,
		0xDD84BBAD4248D63AULL,
		0xE44A355185B9D5E7ULL,
		0x557664A7779C76A5ULL,
		0x7A97C389FBAA5493ULL,
		0xDE80DD91B0FB1DD1ULL,
		0x1B23517731896A4AULL,
		0x695EFF4A172D92EEULL
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
		0x8B8ECC87D0EA39CDULL,
		0xB12AE4A4B2144E20ULL,
		0x5E0D424BE676FF32ULL,
		0xB8CF45065BF8EF78ULL,
		0x51CDA03B9402824DULL,
		0x50729E5CAD2A4609ULL,
		0x01EE907E6032FCAAULL,
		0x1F9DAD20865D9AE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171D990FA1D4739AULL,
		0x6255C94964289C41ULL,
		0xBC1A8497CCEDFE65ULL,
		0x719E8A0CB7F1DEF0ULL,
		0xA39B40772805049BULL,
		0xA0E53CB95A548C12ULL,
		0x03DD20FCC065F954ULL,
		0x3F3B5A410CBB35CAULL
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
		0xA8E4F4EDB1687B19ULL,
		0xD8AF9CEF6FF2ED18ULL,
		0x2874F18670391DE1ULL,
		0x2F9849C0A0176E44ULL,
		0x85315A5D7CFFCC6BULL,
		0x72C3F175B97FFA5EULL,
		0x367390C0245C15A1ULL,
		0x2C7A9074B4B728D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51C9E9DB62D0F632ULL,
		0xB15F39DEDFE5DA31ULL,
		0x50E9E30CE0723BC3ULL,
		0x5F309381402EDC88ULL,
		0x0A62B4BAF9FF98D6ULL,
		0xE587E2EB72FFF4BDULL,
		0x6CE7218048B82B42ULL,
		0x58F520E9696E51A6ULL
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
		0x2488B589ACF64F08ULL,
		0xB59EDC4344C5DD85ULL,
		0x33B9658E125B06C8ULL,
		0x38EBD7259CE6016FULL,
		0x3F23EE450F5B1FC5ULL,
		0x1F189A8F15A9B9CAULL,
		0x001134630F4095CBULL,
		0x2156D5F02E006287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49116B1359EC9E10ULL,
		0x6B3DB886898BBB0AULL,
		0x6772CB1C24B60D91ULL,
		0x71D7AE4B39CC02DEULL,
		0x7E47DC8A1EB63F8AULL,
		0x3E31351E2B537394ULL,
		0x002268C61E812B96ULL,
		0x42ADABE05C00C50EULL
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
		0x8820DCFC822A5E05ULL,
		0xA33236C146C1B1F7ULL,
		0xEA5C177C777C92B5ULL,
		0xA01EE09869082F38ULL,
		0x73661029009709DAULL,
		0xA01AA1C58E64EEC0ULL,
		0xEC042F070F2159FAULL,
		0x1B102CD19A8A48ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1041B9F90454BC0AULL,
		0x46646D828D8363EFULL,
		0xD4B82EF8EEF9256BULL,
		0x403DC130D2105E71ULL,
		0xE6CC2052012E13B5ULL,
		0x4035438B1CC9DD80ULL,
		0xD8085E0E1E42B3F5ULL,
		0x362059A33514915BULL
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
		0x055FCCECB6ABC9B0ULL,
		0x4D2A51C583747E5CULL,
		0x1878D4D43E4037D7ULL,
		0xEE12BCA421EB7614ULL,
		0x00B7BE74FE32AEB9ULL,
		0x52467F4D1D02E9BCULL,
		0x117CE5C7B6281652ULL,
		0x2A24399F35A04499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ABF99D96D579360ULL,
		0x9A54A38B06E8FCB8ULL,
		0x30F1A9A87C806FAEULL,
		0xDC25794843D6EC28ULL,
		0x016F7CE9FC655D73ULL,
		0xA48CFE9A3A05D378ULL,
		0x22F9CB8F6C502CA4ULL,
		0x5448733E6B408932ULL
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
		0xC36CF2E2475C750DULL,
		0x7D7FDE9FE6BBC229ULL,
		0x2AF8B56914FA1AB5ULL,
		0x249BC93F296A7AB9ULL,
		0x15091953FD361600ULL,
		0x74ACC6BD396D7421ULL,
		0x1B7872D737B420F3ULL,
		0x3B2A8435B86AE49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D9E5C48EB8EA1AULL,
		0xFAFFBD3FCD778453ULL,
		0x55F16AD229F4356AULL,
		0x4937927E52D4F572ULL,
		0x2A1232A7FA6C2C00ULL,
		0xE9598D7A72DAE842ULL,
		0x36F0E5AE6F6841E6ULL,
		0x7655086B70D5C93EULL
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
		0x1FC1B8784A583F43ULL,
		0xFA8D46DBFBCFD064ULL,
		0xF112E50D59AAA07FULL,
		0xA3181749581580DAULL,
		0xC4DBE73AAFC111BDULL,
		0xE3D12B5458C9377CULL,
		0xB509F61409D501A5ULL,
		0x2C8C738B950CA606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8370F094B07E86ULL,
		0xF51A8DB7F79FA0C8ULL,
		0xE225CA1AB35540FFULL,
		0x46302E92B02B01B5ULL,
		0x89B7CE755F82237BULL,
		0xC7A256A8B1926EF9ULL,
		0x6A13EC2813AA034BULL,
		0x5918E7172A194C0DULL
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
		0x3D0B0486C1D53932ULL,
		0x4FC84C0574B5B7E5ULL,
		0x422272B1ABBD6B72ULL,
		0x2334A9324D528D42ULL,
		0xF665846A4469EEBFULL,
		0x647B17602FAAF2BDULL,
		0x8AB4B2310E1D084BULL,
		0x052470594A10E3F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A16090D83AA7264ULL,
		0x9F90980AE96B6FCAULL,
		0x8444E563577AD6E4ULL,
		0x466952649AA51A84ULL,
		0xECCB08D488D3DD7EULL,
		0xC8F62EC05F55E57BULL,
		0x156964621C3A1096ULL,
		0x0A48E0B29421C7F1ULL
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
		0x07808FAEA3736427ULL,
		0x30A4526D4C04F499ULL,
		0xEE76CB4554E85CFAULL,
		0x096AEADF11F18EFDULL,
		0xADDF78F3D86BE890ULL,
		0x374CBBC87A617C71ULL,
		0x9AF5B075DA31B139ULL,
		0x0D2CBDBAC82D343BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F011F5D46E6C84EULL,
		0x6148A4DA9809E932ULL,
		0xDCED968AA9D0B9F4ULL,
		0x12D5D5BE23E31DFBULL,
		0x5BBEF1E7B0D7D120ULL,
		0x6E997790F4C2F8E3ULL,
		0x35EB60EBB4636272ULL,
		0x1A597B75905A6877ULL
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
		0xCD42046B1548CD1AULL,
		0x2B5046EFC29F8211ULL,
		0xBD1D04FE57785D5EULL,
		0xB1B5FF669F904F44ULL,
		0xCCF54571B5AC44DAULL,
		0x8C200B8B5E4CA297ULL,
		0x1E809A9F79AF0ECAULL,
		0x1EF1A19B46311EE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A8408D62A919A34ULL,
		0x56A08DDF853F0423ULL,
		0x7A3A09FCAEF0BABCULL,
		0x636BFECD3F209E89ULL,
		0x99EA8AE36B5889B5ULL,
		0x18401716BC99452FULL,
		0x3D01353EF35E1D95ULL,
		0x3DE343368C623DD2ULL
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
		0xDC634B3D5255800DULL,
		0x81F600C4C631BD28ULL,
		0x79C5DCEF7CA86DCBULL,
		0xEF2ABAF85F325673ULL,
		0xBFA42FECA856E80DULL,
		0x409B565D21A22507ULL,
		0x8E1289C5DAEA4112ULL,
		0x02E858A1B9451753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8C6967AA4AB001AULL,
		0x03EC01898C637A51ULL,
		0xF38BB9DEF950DB97ULL,
		0xDE5575F0BE64ACE6ULL,
		0x7F485FD950ADD01BULL,
		0x8136ACBA43444A0FULL,
		0x1C25138BB5D48224ULL,
		0x05D0B143728A2EA7ULL
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
		0x267E7F3EAD43C291ULL,
		0xE72DBE3B61C50BADULL,
		0xF8D0C55D6FCBCDE4ULL,
		0x8D4AA1941591514BULL,
		0xF09F5D6EEA856E0AULL,
		0xF9B01741B50420C1ULL,
		0xA4EE5262C1C271E1ULL,
		0x281D608EA155BE1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CFCFE7D5A878522ULL,
		0xCE5B7C76C38A175AULL,
		0xF1A18ABADF979BC9ULL,
		0x1A9543282B22A297ULL,
		0xE13EBADDD50ADC15ULL,
		0xF3602E836A084183ULL,
		0x49DCA4C58384E3C3ULL,
		0x503AC11D42AB7C3DULL
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
		0x574FBD37B7777962ULL,
		0x10EB635BEE06BFAEULL,
		0xD24E82ADC899DF6AULL,
		0x90C465DEFAEDDA29ULL,
		0xBD616A90A4673987ULL,
		0xBF226DCDA1D85D15ULL,
		0x39D79266977F571BULL,
		0x2D525C87332A6F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE9F7A6F6EEEF2C4ULL,
		0x21D6C6B7DC0D7F5CULL,
		0xA49D055B9133BED4ULL,
		0x2188CBBDF5DBB453ULL,
		0x7AC2D52148CE730FULL,
		0x7E44DB9B43B0BA2BULL,
		0x73AF24CD2EFEAE37ULL,
		0x5AA4B90E6654DE6AULL
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
		0xE68DEC8675B09F30ULL,
		0x4D49DC263B9EE309ULL,
		0x6DE214636EC7551EULL,
		0x412908452C2CA12FULL,
		0xBCBD5EA37750B53DULL,
		0x3C111D268EF62F82ULL,
		0x56CD1B11A18B2A99ULL,
		0x3212C694C5131E93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD1BD90CEB613E60ULL,
		0x9A93B84C773DC613ULL,
		0xDBC428C6DD8EAA3CULL,
		0x8252108A5859425EULL,
		0x797ABD46EEA16A7AULL,
		0x78223A4D1DEC5F05ULL,
		0xAD9A362343165532ULL,
		0x64258D298A263D26ULL
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
		0xA11309B54D7EA333ULL,
		0x6B7CC7E68169AB98ULL,
		0xD344726D35C9A19CULL,
		0x80E4E65605E3E368ULL,
		0x5FC4FF48AAC322A4ULL,
		0xA32D9FF22B782804ULL,
		0x0D0E24F166531B0FULL,
		0x3828C36F4FA94216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4226136A9AFD4666ULL,
		0xD6F98FCD02D35731ULL,
		0xA688E4DA6B934338ULL,
		0x01C9CCAC0BC7C6D1ULL,
		0xBF89FE9155864549ULL,
		0x465B3FE456F05008ULL,
		0x1A1C49E2CCA6361FULL,
		0x705186DE9F52842CULL
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
		0x2D44F496DCCC2EC4ULL,
		0x66A707C9053C68E1ULL,
		0xB196A5A2506148B3ULL,
		0x57037193E292A5E9ULL,
		0x278BE21A162C1E09ULL,
		0x6244724258656EF9ULL,
		0xB1ECC0A0F52E06E6ULL,
		0x3359E9B76F76EF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A89E92DB9985D88ULL,
		0xCD4E0F920A78D1C2ULL,
		0x632D4B44A0C29166ULL,
		0xAE06E327C5254BD3ULL,
		0x4F17C4342C583C12ULL,
		0xC488E484B0CADDF2ULL,
		0x63D98141EA5C0DCCULL,
		0x66B3D36EDEEDDE3FULL
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
		0x210C0951F267E16DULL,
		0xE96C1DF3470D6DB2ULL,
		0x18588D49E79FCFF6ULL,
		0x3F77B708124C8E90ULL,
		0x36409D2E9BE31119ULL,
		0x7CF327043E536148ULL,
		0xD2466823B13A02A0ULL,
		0x3A6FAE0DE82E165BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421812A3E4CFC2DAULL,
		0xD2D83BE68E1ADB64ULL,
		0x30B11A93CF3F9FEDULL,
		0x7EEF6E1024991D20ULL,
		0x6C813A5D37C62232ULL,
		0xF9E64E087CA6C290ULL,
		0xA48CD04762740540ULL,
		0x74DF5C1BD05C2CB7ULL
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
		0xE5498401D8FDF1C5ULL,
		0x47A35BBD009BA2FEULL,
		0x6124AE82E0770FCBULL,
		0x0E9D910771600436ULL,
		0xE8723E656B22ABF7ULL,
		0x9026C498604AE116ULL,
		0x099355D5CBDC2B18ULL,
		0x28CBB8C326AF45BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA930803B1FBE38AULL,
		0x8F46B77A013745FDULL,
		0xC2495D05C0EE1F96ULL,
		0x1D3B220EE2C0086CULL,
		0xD0E47CCAD64557EEULL,
		0x204D8930C095C22DULL,
		0x1326ABAB97B85631ULL,
		0x519771864D5E8B76ULL
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
		0xD5DEB312A5417044ULL,
		0x3EBF427B50051A5FULL,
		0x80340C2D274D2D9FULL,
		0x96442FF1ACA5DCE9ULL,
		0xB90C8781DF90F76FULL,
		0x627FFEBB9F75F2B9ULL,
		0x35CB9EEF544406A4ULL,
		0x29882A775C4E9946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABBD66254A82E088ULL,
		0x7D7E84F6A00A34BFULL,
		0x0068185A4E9A5B3EULL,
		0x2C885FE3594BB9D3ULL,
		0x72190F03BF21EEDFULL,
		0xC4FFFD773EEBE573ULL,
		0x6B973DDEA8880D48ULL,
		0x531054EEB89D328CULL
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
		0x9F6925A7B3EF18DDULL,
		0xAD31BEF5FA486549ULL,
		0xCB7D57BF9D0659B9ULL,
		0x9472107630E1CAA5ULL,
		0xAE31AEFE2728B577ULL,
		0x14DFAD4F8B6DC555ULL,
		0xD40695CE580A02D0ULL,
		0x0C596BE1E8322027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED24B4F67DE31BAULL,
		0x5A637DEBF490CA93ULL,
		0x96FAAF7F3A0CB373ULL,
		0x28E420EC61C3954BULL,
		0x5C635DFC4E516AEFULL,
		0x29BF5A9F16DB8AABULL,
		0xA80D2B9CB01405A0ULL,
		0x18B2D7C3D064404FULL
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
		0xB9F3D562798E8349ULL,
		0xBDD9B6029EA8D558ULL,
		0x8C3DEE642E437275ULL,
		0x196D7A3BDB9DFA26ULL,
		0x7905D0B0B4256ED6ULL,
		0x85F49D458E5DA709ULL,
		0xB8ECEBE258564848ULL,
		0x26AC135B62FA9EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E7AAC4F31D0692ULL,
		0x7BB36C053D51AAB1ULL,
		0x187BDCC85C86E4EBULL,
		0x32DAF477B73BF44DULL,
		0xF20BA161684ADDACULL,
		0x0BE93A8B1CBB4E12ULL,
		0x71D9D7C4B0AC9091ULL,
		0x4D5826B6C5F53D65ULL
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
		0x2FE463FD0B182BB2ULL,
		0x42B0343813DFDBB3ULL,
		0xED392C657B303ABEULL,
		0x4CC919BBADA1EB08ULL,
		0x828C4A7CACF89C0DULL,
		0x91EC142B05AFE1EDULL,
		0x628E10ECE5551CEFULL,
		0x33F08552281609ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC8C7FA16305764ULL,
		0x8560687027BFB766ULL,
		0xDA7258CAF660757CULL,
		0x999233775B43D611ULL,
		0x051894F959F1381AULL,
		0x23D828560B5FC3DBULL,
		0xC51C21D9CAAA39DFULL,
		0x67E10AA4502C1358ULL
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
		0xF4D4D4F19AA39FC8ULL,
		0x2BD9DD4CC1619B3FULL,
		0xBF059C77841E6017ULL,
		0x144A58A54F8DBF18ULL,
		0xF4469F212B495631ULL,
		0x47AE535E72C25837ULL,
		0x1AC5ED7F11BA7495ULL,
		0x10C8E990687EE508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9A9A9E335473F90ULL,
		0x57B3BA9982C3367FULL,
		0x7E0B38EF083CC02EULL,
		0x2894B14A9F1B7E31ULL,
		0xE88D3E425692AC62ULL,
		0x8F5CA6BCE584B06FULL,
		0x358BDAFE2374E92AULL,
		0x2191D320D0FDCA10ULL
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
		0xA7671EE9C9BA46D7ULL,
		0x23F0115D1D5A6372ULL,
		0x2F7C6CBB31CDB4F3ULL,
		0x9B5AB3772CA4294BULL,
		0x54D3CD7CC136FD97ULL,
		0x60800A33FB027116ULL,
		0x387B7E4E3745FB39ULL,
		0x0F89E9BEAAC6E7FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ECE3DD393748DAEULL,
		0x47E022BA3AB4C6E5ULL,
		0x5EF8D976639B69E6ULL,
		0x36B566EE59485296ULL,
		0xA9A79AF9826DFB2FULL,
		0xC1001467F604E22CULL,
		0x70F6FC9C6E8BF672ULL,
		0x1F13D37D558DCFFAULL
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
		0x95D9E6CE5AD1A99BULL,
		0xFD4CCF24DE2B0BA2ULL,
		0x6C80057F4DFA9832ULL,
		0x7BC7BC13304E125AULL,
		0x6CBCDDE684133B8BULL,
		0xBBE32969DAD8B324ULL,
		0x4244E9A3A20F481BULL,
		0x0AAF3BDA7425FDB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BB3CD9CB5A35336ULL,
		0xFA999E49BC561745ULL,
		0xD9000AFE9BF53065ULL,
		0xF78F7826609C24B4ULL,
		0xD979BBCD08267716ULL,
		0x77C652D3B5B16648ULL,
		0x8489D347441E9037ULL,
		0x155E77B4E84BFB66ULL
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
		0xF34C2AA6773C3972ULL,
		0x2715F11F075780B2ULL,
		0xC2EC9C9AF8A3E4F5ULL,
		0x4DE5F0776ED8653AULL,
		0x27706867B581C9B3ULL,
		0x8239B07F941DECBFULL,
		0xDE558CD19350944EULL,
		0x18C2C2DB794223F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE698554CEE7872E4ULL,
		0x4E2BE23E0EAF0165ULL,
		0x85D93935F147C9EAULL,
		0x9BCBE0EEDDB0CA75ULL,
		0x4EE0D0CF6B039366ULL,
		0x047360FF283BD97EULL,
		0xBCAB19A326A1289DULL,
		0x318585B6F28447EFULL
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
		0xD1265F93C2717148ULL,
		0xDD6A653F35057773ULL,
		0x870FA461C9A89B3CULL,
		0xD334124B4AD83BF8ULL,
		0x646D0CE898E18F48ULL,
		0x4758D3C435EFA86AULL,
		0x3FA5D18C633F93E4ULL,
		0x2D2A72904E53B65FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA24CBF2784E2E290ULL,
		0xBAD4CA7E6A0AEEE7ULL,
		0x0E1F48C393513679ULL,
		0xA668249695B077F1ULL,
		0xC8DA19D131C31E91ULL,
		0x8EB1A7886BDF50D4ULL,
		0x7F4BA318C67F27C8ULL,
		0x5A54E5209CA76CBEULL
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
		0xB493D2D9A65C8AE2ULL,
		0x5F9BCD5F86185E3FULL,
		0x76C99E1F9F725D1DULL,
		0x9943415900A41D2DULL,
		0xA77D49F2276CF2F2ULL,
		0xFC7252DE618C9432ULL,
		0xBC8637B1557763A8ULL,
		0x1F5E10C0C3CB10A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6927A5B34CB915C4ULL,
		0xBF379ABF0C30BC7FULL,
		0xED933C3F3EE4BA3AULL,
		0x328682B201483A5AULL,
		0x4EFA93E44ED9E5E5ULL,
		0xF8E4A5BCC3192865ULL,
		0x790C6F62AAEEC751ULL,
		0x3EBC218187962153ULL
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
		0x05ED1604E0589CD7ULL,
		0x6FAC5C63460BC37EULL,
		0x1C0365C4CBDA6C45ULL,
		0x8D790F65EADF724BULL,
		0x9A852CCC05D035B7ULL,
		0x33A4277FC847033CULL,
		0x50D201AB8F6C3C23ULL,
		0x1FF70AD20FDC6871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BDA2C09C0B139AEULL,
		0xDF58B8C68C1786FCULL,
		0x3806CB8997B4D88AULL,
		0x1AF21ECBD5BEE496ULL,
		0x350A59980BA06B6FULL,
		0x67484EFF908E0679ULL,
		0xA1A403571ED87846ULL,
		0x3FEE15A41FB8D0E2ULL
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
		0x48F99096B69655FDULL,
		0x72FF0B2E973286E7ULL,
		0xEA983ABB46BB378FULL,
		0xAA84A81C5E42DD59ULL,
		0xAEB61A78D160784AULL,
		0x8D7769D107A69805ULL,
		0xD9E02C3B2C709A54ULL,
		0x2CA932B1CCC1FCC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91F3212D6D2CABFAULL,
		0xE5FE165D2E650DCEULL,
		0xD53075768D766F1EULL,
		0x55095038BC85BAB3ULL,
		0x5D6C34F1A2C0F095ULL,
		0x1AEED3A20F4D300BULL,
		0xB3C0587658E134A9ULL,
		0x595265639983F985ULL
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
		0xE5A945B1E64F1EF7ULL,
		0xB16425D3C0F584B1ULL,
		0xA7EFDCECA269A620ULL,
		0x56080148881C677EULL,
		0x2C8554372D7200BAULL,
		0xBD07FDE42447F380ULL,
		0x891E83D5641E9C3AULL,
		0x2F962A6506C2399AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB528B63CC9E3DEEULL,
		0x62C84BA781EB0963ULL,
		0x4FDFB9D944D34C41ULL,
		0xAC1002911038CEFDULL,
		0x590AA86E5AE40174ULL,
		0x7A0FFBC8488FE700ULL,
		0x123D07AAC83D3875ULL,
		0x5F2C54CA0D847335ULL
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
		0x17C36625D6CED24FULL,
		0x34643837EBBDA9CDULL,
		0x3F4D547951F8D0EDULL,
		0x67EAE375094001B5ULL,
		0x7231C32939F69919ULL,
		0x4ECE894AD7AC11E9ULL,
		0xBDB411EA8A4E26AAULL,
		0x11DFC0DAA6AAA425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F86CC4BAD9DA49EULL,
		0x68C8706FD77B539AULL,
		0x7E9AA8F2A3F1A1DAULL,
		0xCFD5C6EA1280036AULL,
		0xE463865273ED3232ULL,
		0x9D9D1295AF5823D2ULL,
		0x7B6823D5149C4D54ULL,
		0x23BF81B54D55484BULL
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
		0xA3BBD9CBE5E6E1C0ULL,
		0xB747C112BA087EE5ULL,
		0x0254FEDC7E65B43BULL,
		0x4593A96C6424F604ULL,
		0x909B85359B2B5116ULL,
		0x84857AC5C05D90A5ULL,
		0xE26FC12B1FB299FAULL,
		0x14F3F4075003C3B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4777B397CBCDC380ULL,
		0x6E8F82257410FDCBULL,
		0x04A9FDB8FCCB6877ULL,
		0x8B2752D8C849EC08ULL,
		0x21370A6B3656A22CULL,
		0x090AF58B80BB214BULL,
		0xC4DF82563F6533F5ULL,
		0x29E7E80EA0078761ULL
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
		0x58A2981426E100D4ULL,
		0x99719CB7334D4794ULL,
		0x3F33133C158248F2ULL,
		0xD408EAE92089B3A9ULL,
		0x598636224745CA40ULL,
		0x9B64F54A8CF69A57ULL,
		0xA2BD9015C5033802ULL,
		0x0F8C2038B272FE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB14530284DC201A8ULL,
		0x32E3396E669A8F28ULL,
		0x7E6626782B0491E5ULL,
		0xA811D5D241136752ULL,
		0xB30C6C448E8B9481ULL,
		0x36C9EA9519ED34AEULL,
		0x457B202B8A067005ULL,
		0x1F18407164E5FCCFULL
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
		0x6B53C62B5DD6F105ULL,
		0xD6BD72237B8FEBBDULL,
		0x233E34AFA7E9633EULL,
		0x94DD715A0F6FD778ULL,
		0xB39543F78325A5E6ULL,
		0x65837E63641B875DULL,
		0x82EA3983771BB626ULL,
		0x2AD2F410A3665836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6A78C56BBADE20AULL,
		0xAD7AE446F71FD77AULL,
		0x467C695F4FD2C67DULL,
		0x29BAE2B41EDFAEF0ULL,
		0x672A87EF064B4BCDULL,
		0xCB06FCC6C8370EBBULL,
		0x05D47306EE376C4CULL,
		0x55A5E82146CCB06DULL
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
		0xFC87304127EBBE96ULL,
		0xF0E8CC9ECE54D380ULL,
		0x51D27EC1A53FA465ULL,
		0x1863CCAF056B1707ULL,
		0x62B8736EDFAA37FBULL,
		0xABC11FD759BA5732ULL,
		0x99353F0BB6993CF9ULL,
		0x2C0A72CE38C639EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF90E60824FD77D2CULL,
		0xE1D1993D9CA9A701ULL,
		0xA3A4FD834A7F48CBULL,
		0x30C7995E0AD62E0EULL,
		0xC570E6DDBF546FF6ULL,
		0x57823FAEB374AE64ULL,
		0x326A7E176D3279F3ULL,
		0x5814E59C718C73DDULL
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
		0x6321E68D8095F12EULL,
		0xC3CC73B80AF1B4E3ULL,
		0xD28CE254D51C1C4EULL,
		0xB0C6A0E6B94036C8ULL,
		0x9E7C8969C33440A0ULL,
		0x32EFEF90ED315726ULL,
		0xD4F8113D3701BC62ULL,
		0x28E77D8D071898F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC643CD1B012BE25CULL,
		0x8798E77015E369C6ULL,
		0xA519C4A9AA38389DULL,
		0x618D41CD72806D91ULL,
		0x3CF912D386688141ULL,
		0x65DFDF21DA62AE4DULL,
		0xA9F0227A6E0378C4ULL,
		0x51CEFB1A0E3131EFULL
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
		0xFDA6330B1CD1C3E5ULL,
		0x1B9FC2337403766BULL,
		0xD8420242AB81A75EULL,
		0x8F3B22E33AA2642CULL,
		0x7AC6DEE5F6808907ULL,
		0x7B9C6A21C7F22ABAULL,
		0x56BC307D047867B6ULL,
		0x0FEC5B7C357D5BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB4C661639A387CAULL,
		0x373F8466E806ECD7ULL,
		0xB084048557034EBCULL,
		0x1E7645C67544C859ULL,
		0xF58DBDCBED01120FULL,
		0xF738D4438FE45574ULL,
		0xAD7860FA08F0CF6CULL,
		0x1FD8B6F86AFAB79EULL
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
		0x0141B9B667E7CF98ULL,
		0x7784DEECF1086ACAULL,
		0xDAFB9D4F5D44BAF0ULL,
		0xFB82A77B8E29978AULL,
		0xDC37E8FF5D751E80ULL,
		0x87C3E2BCDBEC3FDCULL,
		0xF9DDBAAC22A49B06ULL,
		0x196748B1FB1C0503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0283736CCFCF9F30ULL,
		0xEF09BDD9E210D594ULL,
		0xB5F73A9EBA8975E0ULL,
		0xF7054EF71C532F15ULL,
		0xB86FD1FEBAEA3D01ULL,
		0x0F87C579B7D87FB9ULL,
		0xF3BB75584549360DULL,
		0x32CE9163F6380A07ULL
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
		0x2216D02DEDAF7922ULL,
		0xAC41B0737AE2A68BULL,
		0xA97F63324EF50A65ULL,
		0xE9841713AF62DE91ULL,
		0x4F8F2B0EC4B58261ULL,
		0xF5C65738B8769833ULL,
		0x235D4056323E0476ULL,
		0x18E93CC4B86A5BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x442DA05BDB5EF244ULL,
		0x588360E6F5C54D16ULL,
		0x52FEC6649DEA14CBULL,
		0xD3082E275EC5BD23ULL,
		0x9F1E561D896B04C3ULL,
		0xEB8CAE7170ED3066ULL,
		0x46BA80AC647C08EDULL,
		0x31D2798970D4B7DAULL
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
		0x1E3A785B6CB72F4AULL,
		0x4304882219CFF1BDULL,
		0xC6110D9FF84A6CC5ULL,
		0x26FDC90ADAFF4C49ULL,
		0x17C7E6FFFC99634CULL,
		0x302F53E99FC6A6D5ULL,
		0x69DE955047F39FA1ULL,
		0x2E326E90671FA541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C74F0B6D96E5E94ULL,
		0x86091044339FE37AULL,
		0x8C221B3FF094D98AULL,
		0x4DFB9215B5FE9893ULL,
		0x2F8FCDFFF932C698ULL,
		0x605EA7D33F8D4DAAULL,
		0xD3BD2AA08FE73F42ULL,
		0x5C64DD20CE3F4A82ULL
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
		0xC6A18A7009345FF4ULL,
		0x8823C09B91DFF28EULL,
		0xE5319517A6C2EFB4ULL,
		0xF59E3826DB96B05AULL,
		0xD56ADE0EC4C90319ULL,
		0x75B08988BAF57750ULL,
		0x4BCFCBE11DBB11F9ULL,
		0x2883AD6E9EFD213EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D4314E01268BFE8ULL,
		0x1047813723BFE51DULL,
		0xCA632A2F4D85DF69ULL,
		0xEB3C704DB72D60B5ULL,
		0xAAD5BC1D89920633ULL,
		0xEB61131175EAEEA1ULL,
		0x979F97C23B7623F2ULL,
		0x51075ADD3DFA427CULL
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
		0xF4DAFC8EBB91740EULL,
		0xA28C93576A7A6886ULL,
		0x97C3B13111A15D22ULL,
		0x08E150FDC0E3C376ULL,
		0x3C54804C13998913ULL,
		0x2F894BF19C29CA59ULL,
		0xDFC91018EBCE3B1DULL,
		0x03717A816C2484BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9B5F91D7722E81CULL,
		0x451926AED4F4D10DULL,
		0x2F8762622342BA45ULL,
		0x11C2A1FB81C786EDULL,
		0x78A9009827331226ULL,
		0x5F1297E3385394B2ULL,
		0xBF922031D79C763AULL,
		0x06E2F502D8490979ULL
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
		0x5C54539365ABA6E8ULL,
		0x407290EE1EB01394ULL,
		0x011C05DB1D85DC2CULL,
		0x6180CED2A35634D4ULL,
		0x9044A4A6EB7DD1AEULL,
		0x3C422AEECA9725BFULL,
		0x8ED717A89A0C039AULL,
		0x17ECA01243190826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A8A726CB574DD0ULL,
		0x80E521DC3D602728ULL,
		0x02380BB63B0BB858ULL,
		0xC3019DA546AC69A8ULL,
		0x2089494DD6FBA35CULL,
		0x788455DD952E4B7FULL,
		0x1DAE2F5134180734ULL,
		0x2FD940248632104DULL
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
		0xA8D08C8C3E725883ULL,
		0x88D84A57379B7B69ULL,
		0xBC2F6E7F539A6216ULL,
		0xBD69C4068C1A3B89ULL,
		0xD5FCD1BB6E7D44C0ULL,
		0x6370957C8A113E05ULL,
		0x6FE985692C394E5CULL,
		0x39057FE4BDED9520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51A119187CE4B106ULL,
		0x11B094AE6F36F6D3ULL,
		0x785EDCFEA734C42DULL,
		0x7AD3880D18347713ULL,
		0xABF9A376DCFA8981ULL,
		0xC6E12AF914227C0BULL,
		0xDFD30AD258729CB8ULL,
		0x720AFFC97BDB2A40ULL
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
		0x27F2C35D5273DF83ULL,
		0x8E316F73A897D951ULL,
		0xDFF27A7191E05B49ULL,
		0xEE9C861B271CB7A7ULL,
		0x6CF20CB762067C64ULL,
		0x52207604B23237D3ULL,
		0xCC84F2882D55B992ULL,
		0x3A1A078263018EA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE586BAA4E7BF06ULL,
		0x1C62DEE7512FB2A2ULL,
		0xBFE4F4E323C0B693ULL,
		0xDD390C364E396F4FULL,
		0xD9E4196EC40CF8C9ULL,
		0xA440EC0964646FA6ULL,
		0x9909E5105AAB7324ULL,
		0x74340F04C6031D43ULL
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
		0x89E24A93DC8AFD47ULL,
		0xD4050836D9E456F4ULL,
		0x0D4619BD61B1215CULL,
		0x274214E09290C558ULL,
		0xC416D7639B2058B8ULL,
		0xE31EBBFDED6119EFULL,
		0xD660B0943F4B16C6ULL,
		0x25BD404516FDAC7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C49527B915FA8EULL,
		0xA80A106DB3C8ADE9ULL,
		0x1A8C337AC36242B9ULL,
		0x4E8429C125218AB0ULL,
		0x882DAEC73640B170ULL,
		0xC63D77FBDAC233DFULL,
		0xACC161287E962D8DULL,
		0x4B7A808A2DFB58F7ULL
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
		0x629A0D9393535E8AULL,
		0xC920BA8DEB111540ULL,
		0x7EBF91E87F15DD95ULL,
		0xD3EA63E4C65FFE7EULL,
		0x3416CAF3587DC22DULL,
		0x9E58729DD5D29552ULL,
		0x2FE43D8B1AE4DD9EULL,
		0x216557001C312D74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5341B2726A6BD14ULL,
		0x9241751BD6222A80ULL,
		0xFD7F23D0FE2BBB2BULL,
		0xA7D4C7C98CBFFCFCULL,
		0x682D95E6B0FB845BULL,
		0x3CB0E53BABA52AA4ULL,
		0x5FC87B1635C9BB3DULL,
		0x42CAAE0038625AE8ULL
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
		0xB47FDE76FFC8F015ULL,
		0x5BDF218E914974AAULL,
		0xFB6DD7D5B06CFC31ULL,
		0x6D96FC7042900B24ULL,
		0x63FF0297B9CA6D7DULL,
		0x28520F2B353098E9ULL,
		0xE8105AAD5AA25AE5ULL,
		0x1789548999A708E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FFBCEDFF91E02AULL,
		0xB7BE431D2292E955ULL,
		0xF6DBAFAB60D9F862ULL,
		0xDB2DF8E085201649ULL,
		0xC7FE052F7394DAFAULL,
		0x50A41E566A6131D2ULL,
		0xD020B55AB544B5CAULL,
		0x2F12A913334E11CBULL
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
		0x53658B64DBCF6DD1ULL,
		0x5F8781BD998B15A4ULL,
		0x40309D065628DE25ULL,
		0x8D371E22A199D4DBULL,
		0xF36145F2F186A2DFULL,
		0x0D775098D97DB65CULL,
		0x7F528289240B07A2ULL,
		0x056AAC25B908B253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6CB16C9B79EDBA2ULL,
		0xBF0F037B33162B48ULL,
		0x80613A0CAC51BC4AULL,
		0x1A6E3C454333A9B6ULL,
		0xE6C28BE5E30D45BFULL,
		0x1AEEA131B2FB6CB9ULL,
		0xFEA5051248160F44ULL,
		0x0AD5584B721164A6ULL
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
		0xE011F335EB25C5D6ULL,
		0x0F1AE90F023C8D0CULL,
		0xAFE7CB38C1FC1E87ULL,
		0xE026B3958FB81046ULL,
		0x57F86BA6E2D4FBEFULL,
		0xEFF6FA51260DF882ULL,
		0x63E38F7791121617ULL,
		0x203438D0FCFE0006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC023E66BD64B8BACULL,
		0x1E35D21E04791A19ULL,
		0x5FCF967183F83D0EULL,
		0xC04D672B1F70208DULL,
		0xAFF0D74DC5A9F7DFULL,
		0xDFEDF4A24C1BF104ULL,
		0xC7C71EEF22242C2FULL,
		0x406871A1F9FC000CULL
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
		0xCC7514B2815B3C6EULL,
		0xF4318B328F6036F8ULL,
		0x1039B9AC72F39308ULL,
		0xF9471E20531B7C6CULL,
		0xC80E1AF63BDAE840ULL,
		0x689E26E2FAB4EA8BULL,
		0x3D92781DCC44CCC5ULL,
		0x3D6143F90D6389B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98EA296502B678DCULL,
		0xE86316651EC06DF1ULL,
		0x20737358E5E72611ULL,
		0xF28E3C40A636F8D8ULL,
		0x901C35EC77B5D081ULL,
		0xD13C4DC5F569D517ULL,
		0x7B24F03B9889998AULL,
		0x7AC287F21AC71372ULL
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
		0x4D794AB92C4C785AULL,
		0x0777792B322AD42DULL,
		0xD1AAEBB9FFF9301CULL,
		0xA0E6C9AC934B4A18ULL,
		0x22124212921B83F8ULL,
		0x965CB1F7E5C2217AULL,
		0xF41D234209BCA705ULL,
		0x2B094B368AE390DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF295725898F0B4ULL,
		0x0EEEF2566455A85AULL,
		0xA355D773FFF26038ULL,
		0x41CD935926969431ULL,
		0x44248425243707F1ULL,
		0x2CB963EFCB8442F4ULL,
		0xE83A468413794E0BULL,
		0x5612966D15C721BBULL
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
		0x6E6D407759F05E1FULL,
		0x0D877B968F9ACFD0ULL,
		0x4C388B7CDB99E010ULL,
		0xCC1BABD4A65AE802ULL,
		0x7FAACF4E1F8B3693ULL,
		0x4EE7F0316AB95549ULL,
		0x4C10A59DC863A0E5ULL,
		0x2C0FDD737972AB1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCDA80EEB3E0BC3EULL,
		0x1B0EF72D1F359FA0ULL,
		0x987116F9B733C020ULL,
		0x983757A94CB5D004ULL,
		0xFF559E9C3F166D27ULL,
		0x9DCFE062D572AA92ULL,
		0x98214B3B90C741CAULL,
		0x581FBAE6F2E5563CULL
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
		0x53973C4503AC6649ULL,
		0xD0F5A6CF66EAB038ULL,
		0x063DC9A784AD9E94ULL,
		0x032E3F5D04DECA74ULL,
		0x58783DD1F7528833ULL,
		0x4732CC79C5A1D074ULL,
		0x3BB5C528DA67B73AULL,
		0x2EB639960F8202C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72E788A0758CC92ULL,
		0xA1EB4D9ECDD56070ULL,
		0x0C7B934F095B3D29ULL,
		0x065C7EBA09BD94E8ULL,
		0xB0F07BA3EEA51066ULL,
		0x8E6598F38B43A0E8ULL,
		0x776B8A51B4CF6E74ULL,
		0x5D6C732C1F040592ULL
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
		0x549F2BD95C14DC2BULL,
		0x5FC04048244FE6B6ULL,
		0xF0145A74C8656CE7ULL,
		0xB504FDBC131F2F7EULL,
		0x2C8FDABBB944E7D5ULL,
		0x4CA70FF515699007ULL,
		0x70FB92B2D03008C8ULL,
		0x32E26EC2370C3983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA93E57B2B829B856ULL,
		0xBF808090489FCD6CULL,
		0xE028B4E990CAD9CEULL,
		0x6A09FB78263E5EFDULL,
		0x591FB5777289CFABULL,
		0x994E1FEA2AD3200EULL,
		0xE1F72565A0601190ULL,
		0x65C4DD846E187306ULL
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
		0xF1BB0ACA3482AB12ULL,
		0x2A57BE141A580BC7ULL,
		0xCE89540D12088E9FULL,
		0x7152A5088C45ACFCULL,
		0xD97DF893FA669424ULL,
		0x1D1CDF858B6E0416ULL,
		0xA17FB24D1A216E49ULL,
		0x171C7FDE6E52BAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE376159469055624ULL,
		0x54AF7C2834B0178FULL,
		0x9D12A81A24111D3EULL,
		0xE2A54A11188B59F9ULL,
		0xB2FBF127F4CD2848ULL,
		0x3A39BF0B16DC082DULL,
		0x42FF649A3442DC92ULL,
		0x2E38FFBCDCA575DBULL
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
		0xB1F6F42E6C9F46BFULL,
		0x1A93EF493A3D3410ULL,
		0x557D5FCE6CD394EBULL,
		0xB31D970F915AB994ULL,
		0xBF4A55282FC02A0DULL,
		0x98ED5C99E391C10DULL,
		0xC290809D13BBDD9EULL,
		0x09AB5A9A617F688BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63EDE85CD93E8D7EULL,
		0x3527DE92747A6821ULL,
		0xAAFABF9CD9A729D6ULL,
		0x663B2E1F22B57328ULL,
		0x7E94AA505F80541BULL,
		0x31DAB933C723821BULL,
		0x8521013A2777BB3DULL,
		0x1356B534C2FED117ULL
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
		0x804341DD9E76AFFEULL,
		0x735748B6BA263FB0ULL,
		0xC269755212E99DFBULL,
		0x2296F8020DB6FC70ULL,
		0x77ED9733C753EE99ULL,
		0xA2139C7B24A02A48ULL,
		0x7ADA27E2AF368EAEULL,
		0x3262E91B2350D493ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x008683BB3CED5FFCULL,
		0xE6AE916D744C7F61ULL,
		0x84D2EAA425D33BF6ULL,
		0x452DF0041B6DF8E1ULL,
		0xEFDB2E678EA7DD32ULL,
		0x442738F649405490ULL,
		0xF5B44FC55E6D1D5DULL,
		0x64C5D23646A1A926ULL
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
		0xC86218F31BEF2067ULL,
		0xB4E1039507DE56DAULL,
		0x35D4DD68988672F5ULL,
		0x6187937F0095EAEAULL,
		0xA06771B6D5F95682ULL,
		0x3D35A48F3740E270ULL,
		0x2E79878E7607E9EFULL,
		0x3C50449944DDC352ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90C431E637DE40CEULL,
		0x69C2072A0FBCADB5ULL,
		0x6BA9BAD1310CE5EBULL,
		0xC30F26FE012BD5D4ULL,
		0x40CEE36DABF2AD04ULL,
		0x7A6B491E6E81C4E1ULL,
		0x5CF30F1CEC0FD3DEULL,
		0x78A0893289BB86A4ULL
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
		0x06552956D36DC070ULL,
		0xA55EED8BED9AFD76ULL,
		0x950CBDFEE2B1665BULL,
		0xCBB13C85F44B8521ULL,
		0x6111FD32F7E0D2F2ULL,
		0x41FE9052C22FF4DAULL,
		0x4FCA78D13A8ADD23ULL,
		0x2B4BD8E9B7C4649EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CAA52ADA6DB80E0ULL,
		0x4ABDDB17DB35FAECULL,
		0x2A197BFDC562CCB7ULL,
		0x9762790BE8970A43ULL,
		0xC223FA65EFC1A5E5ULL,
		0x83FD20A5845FE9B4ULL,
		0x9F94F1A27515BA46ULL,
		0x5697B1D36F88C93CULL
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
		0x3BA9DE14E69E6C00ULL,
		0x64C007E6B65D8E61ULL,
		0x21063831F8DA4A11ULL,
		0x35C3799176F2F662ULL,
		0x55502C7723AF0EFDULL,
		0xD55CC5D8778866E6ULL,
		0xF5955241B2A0BA70ULL,
		0x0DE378362049861DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7753BC29CD3CD800ULL,
		0xC9800FCD6CBB1CC2ULL,
		0x420C7063F1B49422ULL,
		0x6B86F322EDE5ECC4ULL,
		0xAAA058EE475E1DFAULL,
		0xAAB98BB0EF10CDCCULL,
		0xEB2AA483654174E1ULL,
		0x1BC6F06C40930C3BULL
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
		0x2092CC077D4C2BF0ULL,
		0x15ABE384714F25A5ULL,
		0xC053695DFC477383ULL,
		0xFB31FC8B4E65F339ULL,
		0x50FE5DD45FBE02C5ULL,
		0xB660ADE3E3152750ULL,
		0x0DE8A17907C162F9ULL,
		0x1C4B8CC6E9306203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4125980EFA9857E0ULL,
		0x2B57C708E29E4B4AULL,
		0x80A6D2BBF88EE706ULL,
		0xF663F9169CCBE673ULL,
		0xA1FCBBA8BF7C058BULL,
		0x6CC15BC7C62A4EA0ULL,
		0x1BD142F20F82C5F3ULL,
		0x3897198DD260C406ULL
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
		0x82A74D78D1F0D909ULL,
		0x83996F62A5EE292CULL,
		0x66A9C0416D72BE0EULL,
		0xFC5DAD7625BC76C2ULL,
		0xECA1E1DCBC7ED131ULL,
		0x16BADA15CCF51C93ULL,
		0x55BC9CF83835473EULL,
		0x316C083405B78403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x054E9AF1A3E1B212ULL,
		0x0732DEC54BDC5259ULL,
		0xCD538082DAE57C1DULL,
		0xF8BB5AEC4B78ED84ULL,
		0xD943C3B978FDA263ULL,
		0x2D75B42B99EA3927ULL,
		0xAB7939F0706A8E7CULL,
		0x62D810680B6F0806ULL
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
		0x45523436DBE19DDFULL,
		0x657CCB27C76E4CC9ULL,
		0x17E4437563CA78DAULL,
		0x1D68CF0B3F068046ULL,
		0xA6B892DABFB46678ULL,
		0x6220A71F3D3E50EBULL,
		0xB34F8AC10AF9F044ULL,
		0x2283F14E9755D1E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA4686DB7C33BBEULL,
		0xCAF9964F8EDC9992ULL,
		0x2FC886EAC794F1B4ULL,
		0x3AD19E167E0D008CULL,
		0x4D7125B57F68CCF0ULL,
		0xC4414E3E7A7CA1D7ULL,
		0x669F158215F3E088ULL,
		0x4507E29D2EABA3CDULL
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
		0x42BD4B46AC96FDC7ULL,
		0xBA77E6C7E0E4EB3FULL,
		0x9C4F771480BD7898ULL,
		0x0BAD05E7FE4D6E27ULL,
		0x7050C27635F4B3AFULL,
		0x6FB7500EE000A8B1ULL,
		0xC2C2B3FA0BFFFC78ULL,
		0x2A15FE4E7D3D7DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857A968D592DFB8EULL,
		0x74EFCD8FC1C9D67EULL,
		0x389EEE29017AF131ULL,
		0x175A0BCFFC9ADC4FULL,
		0xE0A184EC6BE9675EULL,
		0xDF6EA01DC0015162ULL,
		0x858567F417FFF8F0ULL,
		0x542BFC9CFA7AFB6DULL
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
		0x98CE0A077FD31F7AULL,
		0x304F527A60491EC1ULL,
		0xAEEC69D7E9833E58ULL,
		0xF9FAF101225EA3A5ULL,
		0x2FB3174E8E1D6502ULL,
		0x9582F16D15AA77D7ULL,
		0x95FB9999E8EF58E5ULL,
		0x1041C890A2B78762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x319C140EFFA63EF4ULL,
		0x609EA4F4C0923D83ULL,
		0x5DD8D3AFD3067CB0ULL,
		0xF3F5E20244BD474BULL,
		0x5F662E9D1C3ACA05ULL,
		0x2B05E2DA2B54EFAEULL,
		0x2BF73333D1DEB1CBULL,
		0x20839121456F0EC5ULL
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
		0x9AF495EFCEB6DB97ULL,
		0xE9EB51804744808CULL,
		0x9BC586F0DE523953ULL,
		0xE58E307D2FFA1C9DULL,
		0xFEE00FFA4A61369CULL,
		0x8B9CB523EBBED276ULL,
		0xADA3E5854CB959CCULL,
		0x0F08582447FB30A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35E92BDF9D6DB72EULL,
		0xD3D6A3008E890119ULL,
		0x378B0DE1BCA472A7ULL,
		0xCB1C60FA5FF4393BULL,
		0xFDC01FF494C26D39ULL,
		0x17396A47D77DA4EDULL,
		0x5B47CB0A9972B399ULL,
		0x1E10B0488FF66141ULL
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
		0xA38471BF2D7C5492ULL,
		0x52FE1C04907B671DULL,
		0x5159C8F0DD51EFF3ULL,
		0x6B4387E6D5BAEB82ULL,
		0xFA9EC012A4C3ACB2ULL,
		0x24DD713DEEA95533ULL,
		0xA01087289545E636ULL,
		0x0897A5B3769E5FACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4708E37E5AF8A924ULL,
		0xA5FC380920F6CE3BULL,
		0xA2B391E1BAA3DFE6ULL,
		0xD6870FCDAB75D704ULL,
		0xF53D802549875964ULL,
		0x49BAE27BDD52AA67ULL,
		0x40210E512A8BCC6CULL,
		0x112F4B66ED3CBF59ULL
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
		0x25E1F3177588A943ULL,
		0xF1E9C9C039877783ULL,
		0x20D26C246C85BA94ULL,
		0x0FB8F42AD72B8DDEULL,
		0x99A2F4D96C9E4214ULL,
		0xD36907C9AA1E1A68ULL,
		0x4AC293786B432A48ULL,
		0x3376805305B37EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BC3E62EEB115286ULL,
		0xE3D39380730EEF06ULL,
		0x41A4D848D90B7529ULL,
		0x1F71E855AE571BBCULL,
		0x3345E9B2D93C8428ULL,
		0xA6D20F93543C34D1ULL,
		0x958526F0D6865491ULL,
		0x66ED00A60B66FDE0ULL
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
		0xA1BA9D3F7338A3A1ULL,
		0x32BD195D176D0A6FULL,
		0x0E4E8339A7E80F42ULL,
		0x4DC55E97C571F95AULL,
		0xE8D3A758E81D2E73ULL,
		0x69D59E945BB3FE8CULL,
		0x5067E09A235B0DD0ULL,
		0x3FD10DC3BB5652CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43753A7EE6714742ULL,
		0x657A32BA2EDA14DFULL,
		0x1C9D06734FD01E84ULL,
		0x9B8ABD2F8AE3F2B4ULL,
		0xD1A74EB1D03A5CE6ULL,
		0xD3AB3D28B767FD19ULL,
		0xA0CFC13446B61BA0ULL,
		0x7FA21B8776ACA598ULL
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
		0xD7885021F09CE2AEULL,
		0x4360255897082B07ULL,
		0x750C311A49695024ULL,
		0xB874BA65086FE2BBULL,
		0xBA204F934F533845ULL,
		0xDF6989E55D7C7865ULL,
		0x1383AF98086C3D70ULL,
		0x1FB206DD5744418DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF10A043E139C55CULL,
		0x86C04AB12E10560FULL,
		0xEA18623492D2A048ULL,
		0x70E974CA10DFC576ULL,
		0x74409F269EA6708BULL,
		0xBED313CABAF8F0CBULL,
		0x27075F3010D87AE1ULL,
		0x3F640DBAAE88831AULL
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
		0xA8055BFF90F90B50ULL,
		0xB751E7FE6E5FBDE1ULL,
		0x68B743584464C2ACULL,
		0xC555019C0996B47AULL,
		0xBE27D4A1D5ED851BULL,
		0xB68FF38664EF11DCULL,
		0xD8D2B5A0BBED54EEULL,
		0x1FBF802BA9B7556DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x500AB7FF21F216A0ULL,
		0x6EA3CFFCDCBF7BC3ULL,
		0xD16E86B088C98559ULL,
		0x8AAA0338132D68F4ULL,
		0x7C4FA943ABDB0A37ULL,
		0x6D1FE70CC9DE23B9ULL,
		0xB1A56B4177DAA9DDULL,
		0x3F7F0057536EAADBULL
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
		0x6C6A687255ACDF80ULL,
		0xA9A74DDEFE63BE19ULL,
		0x2D266BBCE5E8C0E8ULL,
		0xC5FA1BB4B08E91F8ULL,
		0x7C660E3BA8D7DC68ULL,
		0x9BEEE8F79111A952ULL,
		0x4C9D08796B13F6FEULL,
		0x2B33222877464F9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D4D0E4AB59BF00ULL,
		0x534E9BBDFCC77C32ULL,
		0x5A4CD779CBD181D1ULL,
		0x8BF43769611D23F0ULL,
		0xF8CC1C7751AFB8D1ULL,
		0x37DDD1EF222352A4ULL,
		0x993A10F2D627EDFDULL,
		0x56664450EE8C9F34ULL
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
		0x68DA9D19C427B7E0ULL,
		0x5A87B956573C6AA9ULL,
		0x30B2745233031C19ULL,
		0x376FA22DB8B0026BULL,
		0xA103E5DD477ACC83ULL,
		0x7D66D8756600E4BAULL,
		0x843E7E383D57E249ULL,
		0x3C8FEC80E79606D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B53A33884F6FC0ULL,
		0xB50F72ACAE78D552ULL,
		0x6164E8A466063832ULL,
		0x6EDF445B716004D6ULL,
		0x4207CBBA8EF59906ULL,
		0xFACDB0EACC01C975ULL,
		0x087CFC707AAFC492ULL,
		0x791FD901CF2C0DA3ULL
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
		0x67C9BE72AD718E1DULL,
		0xA30209A36689002AULL,
		0x10545AE69BB280A9ULL,
		0x73DEBCEFF26C71E6ULL,
		0x28A79A0B16F08A7EULL,
		0x7EE87CB4005CEDA3ULL,
		0x91327F90E17C33BDULL,
		0x2710E4AACA9C1940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF937CE55AE31C3AULL,
		0x46041346CD120054ULL,
		0x20A8B5CD37650153ULL,
		0xE7BD79DFE4D8E3CCULL,
		0x514F34162DE114FCULL,
		0xFDD0F96800B9DB46ULL,
		0x2264FF21C2F8677AULL,
		0x4E21C95595383281ULL
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
		0xAC82685A7B13BA18ULL,
		0x9CDBB8CAC958DD4EULL,
		0xE1BD15DBE2E82779ULL,
		0x1F4618D04930C83DULL,
		0xD25788168812DB2EULL,
		0xC4A23F56FD0923AFULL,
		0x2E879B7CF043C6DBULL,
		0x3E64A387482AD376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5904D0B4F6277430ULL,
		0x39B7719592B1BA9DULL,
		0xC37A2BB7C5D04EF3ULL,
		0x3E8C31A09261907BULL,
		0xA4AF102D1025B65CULL,
		0x89447EADFA12475FULL,
		0x5D0F36F9E0878DB7ULL,
		0x7CC9470E9055A6ECULL
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
		0xEE03BDC2128CD69AULL,
		0x1158F7B3C45ACBCAULL,
		0xEAD2E0E38C5CC77EULL,
		0xE8EF4EC774018FC0ULL,
		0xC686F616627C520DULL,
		0x996DD862AC92DCAAULL,
		0x8548621EE294E1B5ULL,
		0x1ABD45E8A081F7C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC077B842519AD34ULL,
		0x22B1EF6788B59795ULL,
		0xD5A5C1C718B98EFCULL,
		0xD1DE9D8EE8031F81ULL,
		0x8D0DEC2CC4F8A41BULL,
		0x32DBB0C55925B955ULL,
		0x0A90C43DC529C36BULL,
		0x357A8BD14103EF87ULL
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
		0x99AF06950135CD8EULL,
		0xAB3AAC4C1075759BULL,
		0x33777B2B82F90D63ULL,
		0xA3B9C0604F6F5ED3ULL,
		0x41431809191F10B4ULL,
		0x4392940458960E59ULL,
		0x6F69F60C212C173FULL,
		0x00F9212E4C3350EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x335E0D2A026B9B1CULL,
		0x5675589820EAEB37ULL,
		0x66EEF65705F21AC7ULL,
		0x477380C09EDEBDA6ULL,
		0x82863012323E2169ULL,
		0x87252808B12C1CB2ULL,
		0xDED3EC1842582E7EULL,
		0x01F2425C9866A1DEULL
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
		0x2B7B748A217A11AFULL,
		0x30D9333689584417ULL,
		0xE3EBBE4E29EBEB5EULL,
		0x9E341CC64483E129ULL,
		0xFC90B24B85CA143BULL,
		0xF22DA57E7950CE29ULL,
		0x8B544DA74AD337CCULL,
		0x14B31778AFE79662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F6E91442F4235EULL,
		0x61B2666D12B0882EULL,
		0xC7D77C9C53D7D6BCULL,
		0x3C68398C8907C253ULL,
		0xF92164970B942877ULL,
		0xE45B4AFCF2A19C53ULL,
		0x16A89B4E95A66F99ULL,
		0x29662EF15FCF2CC5ULL
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
		0x97D16578518C3EC5ULL,
		0x9294936022922E03ULL,
		0x19474E1D6C20D5D1ULL,
		0xD4BF80C29F87DE21ULL,
		0x02175E01E5E65BBFULL,
		0x562DDD8565AC702FULL,
		0xE7631D2C28A2BE83ULL,
		0x0E517E5E657BEF0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA2CAF0A3187D8AULL,
		0x252926C045245C07ULL,
		0x328E9C3AD841ABA3ULL,
		0xA97F01853F0FBC42ULL,
		0x042EBC03CBCCB77FULL,
		0xAC5BBB0ACB58E05EULL,
		0xCEC63A5851457D06ULL,
		0x1CA2FCBCCAF7DE1DULL
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
		0x62815F2A1812B63FULL,
		0x06ABC0FC60560AECULL,
		0xFE53D3A7A502957BULL,
		0x960E65B7893D24DEULL,
		0x9488B028804E66B7ULL,
		0xD37769AEDC996FB8ULL,
		0x153C3A05B47CF628ULL,
		0x10EFB95393CEEF84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC502BE5430256C7EULL,
		0x0D5781F8C0AC15D8ULL,
		0xFCA7A74F4A052AF6ULL,
		0x2C1CCB6F127A49BDULL,
		0x29116051009CCD6FULL,
		0xA6EED35DB932DF71ULL,
		0x2A78740B68F9EC51ULL,
		0x21DF72A7279DDF08ULL
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
		0x0BAF25A996E0E896ULL,
		0x9C95E40E94C43650ULL,
		0xE9DD827D6DA8F0B3ULL,
		0xF056B8035EE58D92ULL,
		0x103515EC22A94CDEULL,
		0x7B4638D6D09FC66EULL,
		0x1017DEECE16079A3ULL,
		0x2BEC69B13F857579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x175E4B532DC1D12CULL,
		0x392BC81D29886CA0ULL,
		0xD3BB04FADB51E167ULL,
		0xE0AD7006BDCB1B25ULL,
		0x206A2BD8455299BDULL,
		0xF68C71ADA13F8CDCULL,
		0x202FBDD9C2C0F346ULL,
		0x57D8D3627F0AEAF2ULL
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
		0x20A2F0A47D6CCF2BULL,
		0x667E7F8F9DAF600AULL,
		0xD5F69451006B07CFULL,
		0x0E6BAD094F6246CCULL,
		0x3B9EEDBA5925313BULL,
		0xC2D69FAFE38D34BEULL,
		0x5D091B09AD10327CULL,
		0x17829C87A236FD15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4145E148FAD99E56ULL,
		0xCCFCFF1F3B5EC014ULL,
		0xABED28A200D60F9EULL,
		0x1CD75A129EC48D99ULL,
		0x773DDB74B24A6276ULL,
		0x85AD3F5FC71A697CULL,
		0xBA1236135A2064F9ULL,
		0x2F05390F446DFA2AULL
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
		0x2645D2B74AA1FE70ULL,
		0x6A51236AB82272C4ULL,
		0xFC5EA2DAFAF8EC69ULL,
		0x915229DEB8EC0817ULL,
		0x74BFAD46E54027B6ULL,
		0xC3693944936BAC33ULL,
		0x9894E87CEC898EDAULL,
		0x152D531685BD9347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8BA56E9543FCE0ULL,
		0xD4A246D57044E588ULL,
		0xF8BD45B5F5F1D8D2ULL,
		0x22A453BD71D8102FULL,
		0xE97F5A8DCA804F6DULL,
		0x86D2728926D75866ULL,
		0x3129D0F9D9131DB5ULL,
		0x2A5AA62D0B7B268FULL
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
		0xB10AB414C664E9AFULL,
		0x15D5DE2DFB19C540ULL,
		0x45DAC704220F8C7FULL,
		0xA9789E51E7474EC9ULL,
		0x082DAB7984F667D7ULL,
		0xA371CAC7EB17A3A0ULL,
		0xCA8E2D32DEA6807DULL,
		0x3046A9E064ECE8D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x621568298CC9D35EULL,
		0x2BABBC5BF6338A81ULL,
		0x8BB58E08441F18FEULL,
		0x52F13CA3CE8E9D92ULL,
		0x105B56F309ECCFAFULL,
		0x46E3958FD62F4740ULL,
		0x951C5A65BD4D00FBULL,
		0x608D53C0C9D9D1B1ULL
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
		0x9FFF8561F8CC27D8ULL,
		0x3447D7577DCC9BDEULL,
		0xB0E235FA99A1A175ULL,
		0x13B9E48B47EE6097ULL,
		0x87091B0761EE8A3CULL,
		0x466370E2EF314140ULL,
		0xD06E6089400E39DBULL,
		0x0E56929C3E89E3FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FFF0AC3F1984FB0ULL,
		0x688FAEAEFB9937BDULL,
		0x61C46BF5334342EAULL,
		0x2773C9168FDCC12FULL,
		0x0E12360EC3DD1478ULL,
		0x8CC6E1C5DE628281ULL,
		0xA0DCC112801C73B6ULL,
		0x1CAD25387D13C7FBULL
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
		0xF83FD57324450B71ULL,
		0xB175536AE385C00FULL,
		0x6811F6457EAFD9C4ULL,
		0xDEC48E649E5E83A3ULL,
		0x9E1799CC0753F415ULL,
		0x9D05C67A64065C94ULL,
		0x00713B4C435E39E1ULL,
		0x090B8008AC4AFB81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF07FAAE6488A16E2ULL,
		0x62EAA6D5C70B801FULL,
		0xD023EC8AFD5FB389ULL,
		0xBD891CC93CBD0746ULL,
		0x3C2F33980EA7E82BULL,
		0x3A0B8CF4C80CB929ULL,
		0x00E2769886BC73C3ULL,
		0x121700115895F702ULL
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
		0xF5ED521AC620A848ULL,
		0x71FF63C8CFA24E57ULL,
		0xF578646F163751EEULL,
		0xDC174503BDCF67F3ULL,
		0x877EED59A558A53DULL,
		0x40CD623EF4F2BF21ULL,
		0xBDBAB81C188A2518ULL,
		0x2C6A96CEC676F18EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBDAA4358C415090ULL,
		0xE3FEC7919F449CAFULL,
		0xEAF0C8DE2C6EA3DCULL,
		0xB82E8A077B9ECFE7ULL,
		0x0EFDDAB34AB14A7BULL,
		0x819AC47DE9E57E43ULL,
		0x7B75703831144A30ULL,
		0x58D52D9D8CEDE31DULL
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
		0x6E55F7E98110F6ABULL,
		0xB426767D0DB73D8DULL,
		0x24F2B4299B3DB426ULL,
		0xFE3B79AFE48E388EULL,
		0xE2DD384339B67BB2ULL,
		0x60326F6EB6AC8465ULL,
		0xBD2A646B8008EF6EULL,
		0x3C57ED6A6C2291F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCABEFD30221ED56ULL,
		0x684CECFA1B6E7B1AULL,
		0x49E56853367B684DULL,
		0xFC76F35FC91C711CULL,
		0xC5BA7086736CF765ULL,
		0xC064DEDD6D5908CBULL,
		0x7A54C8D70011DEDCULL,
		0x78AFDAD4D84523EBULL
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
		0x07BBBDD027F65D7FULL,
		0xD96AED15E936596BULL,
		0xEC3F48C25FCCE2D8ULL,
		0xE1C8796A31EC3FFFULL,
		0xA51390A6298AFBA5ULL,
		0x64A03FA14535D427ULL,
		0x7032DDD145853F57ULL,
		0x219B64ADDF865415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F777BA04FECBAFEULL,
		0xB2D5DA2BD26CB2D6ULL,
		0xD87E9184BF99C5B1ULL,
		0xC390F2D463D87FFFULL,
		0x4A27214C5315F74BULL,
		0xC9407F428A6BA84FULL,
		0xE065BBA28B0A7EAEULL,
		0x4336C95BBF0CA82AULL
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
		0x6C736ABAB748483CULL,
		0xBE95D7A4D251D05FULL,
		0xE58A911213976CC7ULL,
		0xA2BC42F98421322EULL,
		0x9422BB4D383CD493ULL,
		0x82CA60154276E318ULL,
		0x795209A8F09345F1ULL,
		0x1FEE43D1CADCEE2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8E6D5756E909078ULL,
		0x7D2BAF49A4A3A0BEULL,
		0xCB152224272ED98FULL,
		0x457885F30842645DULL,
		0x2845769A7079A927ULL,
		0x0594C02A84EDC631ULL,
		0xF2A41351E1268BE3ULL,
		0x3FDC87A395B9DC5EULL
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
		0x022C71BA73CA5E01ULL,
		0x1A23C8F9D45E4CFBULL,
		0xB7D559B9084AA71CULL,
		0x573709A116E17BD3ULL,
		0x29D76C0734B4EEC0ULL,
		0xCC3C248BBC42565AULL,
		0xEC58FC02BE4778C4ULL,
		0x25C37D0BB7677558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0458E374E794BC02ULL,
		0x344791F3A8BC99F6ULL,
		0x6FAAB37210954E38ULL,
		0xAE6E13422DC2F7A7ULL,
		0x53AED80E6969DD80ULL,
		0x987849177884ACB4ULL,
		0xD8B1F8057C8EF189ULL,
		0x4B86FA176ECEEAB1ULL
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
		0xEA0B98691C105682ULL,
		0xE4FC679824CA788BULL,
		0x9B4A80BB07C846FBULL,
		0xC81C05590BB147A7ULL,
		0x9D6E62DC6DBCD9FCULL,
		0x71AE747A60A5D5B1ULL,
		0xA796440533C6E075ULL,
		0x0B4F75DA0D95122EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41730D23820AD04ULL,
		0xC9F8CF304994F117ULL,
		0x369501760F908DF7ULL,
		0x90380AB217628F4FULL,
		0x3ADCC5B8DB79B3F9ULL,
		0xE35CE8F4C14BAB63ULL,
		0x4F2C880A678DC0EAULL,
		0x169EEBB41B2A245DULL
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
		0x415B135F74E4D0B4ULL,
		0xD44E58034A081C0CULL,
		0xAA2400FBC440ABADULL,
		0x7E1601D7020BC279ULL,
		0xEA0E7CAD571B040FULL,
		0x9ACD6B176B5B1455ULL,
		0x7B2A7DAE066E6C10ULL,
		0x1E81FD6CCFBB4795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B626BEE9C9A168ULL,
		0xA89CB00694103818ULL,
		0x544801F78881575BULL,
		0xFC2C03AE041784F3ULL,
		0xD41CF95AAE36081EULL,
		0x359AD62ED6B628ABULL,
		0xF654FB5C0CDCD821ULL,
		0x3D03FAD99F768F2AULL
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
		0xAFD67A04FF907C0BULL,
		0x1121D43D1971FE3EULL,
		0x09778E12A8BC97B2ULL,
		0x51B6F0480AA5CA51ULL,
		0x30B4DDD37371F3C0ULL,
		0xF2F30B71D0C228E5ULL,
		0x9E0C53E116D15937ULL,
		0x38654A677E7CAFDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FACF409FF20F816ULL,
		0x2243A87A32E3FC7DULL,
		0x12EF1C2551792F64ULL,
		0xA36DE090154B94A2ULL,
		0x6169BBA6E6E3E780ULL,
		0xE5E616E3A18451CAULL,
		0x3C18A7C22DA2B26FULL,
		0x70CA94CEFCF95FBDULL
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
		0x6B289C7B7FBEAD05ULL,
		0x0E465C9016FB88E2ULL,
		0x0B2CFA82752F9B01ULL,
		0xA1F25B52300962CDULL,
		0x71A8F7BC1C016BBEULL,
		0xE8551B901CDDC3B9ULL,
		0xF78542C200D6B0C1ULL,
		0x038FBAF38B68E5FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65138F6FF7D5A0AULL,
		0x1C8CB9202DF711C4ULL,
		0x1659F504EA5F3602ULL,
		0x43E4B6A46012C59AULL,
		0xE351EF783802D77DULL,
		0xD0AA372039BB8772ULL,
		0xEF0A858401AD6183ULL,
		0x071F75E716D1CBF9ULL
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
		0xFA95F5A89F18C9C0ULL,
		0x33BDB5365FD2082DULL,
		0x22DB55193EBE25C7ULL,
		0xB7F66187FAEC2938ULL,
		0x3B3A126ADF8DB6E2ULL,
		0x13D9DCBC0CA76A05ULL,
		0x87D1A703F17496AAULL,
		0x3B14A51827F26C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF52BEB513E319380ULL,
		0x677B6A6CBFA4105BULL,
		0x45B6AA327D7C4B8EULL,
		0x6FECC30FF5D85270ULL,
		0x767424D5BF1B6DC5ULL,
		0x27B3B978194ED40AULL,
		0x0FA34E07E2E92D54ULL,
		0x76294A304FE4D8C3ULL
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
		0xC350A79ABFD22E0AULL,
		0x35D82B8D0A51F91CULL,
		0x83AC4DC9F882A848ULL,
		0x672907E387E24D40ULL,
		0x62D1F401DD964FBFULL,
		0xCABACFFFFB9A960DULL,
		0x3E24571272A56EC8ULL,
		0x097C26D6E6C6AA35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A14F357FA45C14ULL,
		0x6BB0571A14A3F239ULL,
		0x07589B93F1055090ULL,
		0xCE520FC70FC49A81ULL,
		0xC5A3E803BB2C9F7EULL,
		0x95759FFFF7352C1AULL,
		0x7C48AE24E54ADD91ULL,
		0x12F84DADCD8D546AULL
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
		0xE7CCECD31BD44C0DULL,
		0xC6DC8E73DE9F39BDULL,
		0xA255F683D4143904ULL,
		0x358DBE9A3A176AA9ULL,
		0xA1635C61412F6902ULL,
		0xFD2B5020DD36EA14ULL,
		0x61210913F89D1F4DULL,
		0x22863D9046C29BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF99D9A637A8981AULL,
		0x8DB91CE7BD3E737BULL,
		0x44ABED07A8287209ULL,
		0x6B1B7D34742ED553ULL,
		0x42C6B8C2825ED204ULL,
		0xFA56A041BA6DD429ULL,
		0xC2421227F13A3E9BULL,
		0x450C7B208D8537A8ULL
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
		0x5C974ABD24881605ULL,
		0x4E6019A0049A7940ULL,
		0x0EE552324CF8B598ULL,
		0x89B323FAC4899C1DULL,
		0xFBA6E64E1987BEBBULL,
		0xDB350EAF1FD94B5DULL,
		0x13F14DFE39471F4FULL,
		0x02D7FB3566C3E297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB92E957A49102C0AULL,
		0x9CC033400934F280ULL,
		0x1DCAA46499F16B30ULL,
		0x136647F58913383AULL,
		0xF74DCC9C330F7D77ULL,
		0xB66A1D5E3FB296BBULL,
		0x27E29BFC728E3E9FULL,
		0x05AFF66ACD87C52EULL
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
		0xD84EEE7E6850D11EULL,
		0xF61768650CD958AEULL,
		0x5BBF36518C03C1D1ULL,
		0xB3B8A8946A1B601BULL,
		0xE16483AEF994AE11ULL,
		0xADBB0F6B1880C308ULL,
		0xCED56BC7C693FE2CULL,
		0x3C07B2E0C54CB301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09DDCFCD0A1A23CULL,
		0xEC2ED0CA19B2B15DULL,
		0xB77E6CA3180783A3ULL,
		0x67715128D436C036ULL,
		0xC2C9075DF3295C23ULL,
		0x5B761ED631018611ULL,
		0x9DAAD78F8D27FC59ULL,
		0x780F65C18A996603ULL
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
		0xE360DDA05D0B1BF3ULL,
		0x78EA549AC2C9FF5BULL,
		0x4CD0CD54D2743A80ULL,
		0xC3FB120A50E19AFFULL,
		0x0A5961080C2F8A40ULL,
		0xC90C76718D0BA710ULL,
		0x18C81F18A778311AULL,
		0x3D259DC12FFFC9E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C1BB40BA1637E6ULL,
		0xF1D4A9358593FEB7ULL,
		0x99A19AA9A4E87500ULL,
		0x87F62414A1C335FEULL,
		0x14B2C210185F1481ULL,
		0x9218ECE31A174E20ULL,
		0x31903E314EF06235ULL,
		0x7A4B3B825FFF93C8ULL
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
		0x4B17A8DF13440CDBULL,
		0x43FA2B4C35BFDA49ULL,
		0x9868CBB0F18ED259ULL,
		0x1847203B492BCC1FULL,
		0x18BA4151AC1643E3ULL,
		0xE9868A4388F3AB5FULL,
		0xB26A538DD8093436ULL,
		0x18471464CFA1FB16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962F51BE268819B6ULL,
		0x87F456986B7FB492ULL,
		0x30D19761E31DA4B2ULL,
		0x308E40769257983FULL,
		0x317482A3582C87C6ULL,
		0xD30D148711E756BEULL,
		0x64D4A71BB012686DULL,
		0x308E28C99F43F62DULL
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
		0x05BE76D8C9D959AAULL,
		0x5D483702E79240B7ULL,
		0xA73D8F330C5536E8ULL,
		0x3BFF45747AB50764ULL,
		0x57E862665D6D1327ULL,
		0x70A6136D027E69FFULL,
		0x7D97773303057D4FULL,
		0x3FE56C05AAED796CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B7CEDB193B2B354ULL,
		0xBA906E05CF24816EULL,
		0x4E7B1E6618AA6DD0ULL,
		0x77FE8AE8F56A0EC9ULL,
		0xAFD0C4CCBADA264EULL,
		0xE14C26DA04FCD3FEULL,
		0xFB2EEE66060AFA9EULL,
		0x7FCAD80B55DAF2D8ULL
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
		0x9D590642E6D2E373ULL,
		0x8205CB732B57FBC7ULL,
		0xB998D3B48D8BBFBBULL,
		0x93A0EEC8D61002B3ULL,
		0xC74116E823A9064BULL,
		0x58AE4858C54BC50BULL,
		0x9C7187F719145FB3ULL,
		0x0D28764AD30E18ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AB20C85CDA5C6E6ULL,
		0x040B96E656AFF78FULL,
		0x7331A7691B177F77ULL,
		0x2741DD91AC200567ULL,
		0x8E822DD047520C97ULL,
		0xB15C90B18A978A17ULL,
		0x38E30FEE3228BF66ULL,
		0x1A50EC95A61C31D9ULL
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
		0xD14BD5243BD3C168ULL,
		0x11085012473D1D53ULL,
		0x3D7305C1D2FEB5CEULL,
		0x0BE4E1BCB3BC76D8ULL,
		0x9437FE23E07291B8ULL,
		0x5F8A69FE5177E79AULL,
		0x90E54D150F024ECDULL,
		0x257083203802CA48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA297AA4877A782D0ULL,
		0x2210A0248E7A3AA7ULL,
		0x7AE60B83A5FD6B9CULL,
		0x17C9C3796778EDB0ULL,
		0x286FFC47C0E52370ULL,
		0xBF14D3FCA2EFCF35ULL,
		0x21CA9A2A1E049D9AULL,
		0x4AE1064070059491ULL
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
		0x19929FA47A5A75E4ULL,
		0xA3E39CEDBD9CF616ULL,
		0xC09417EA6F7BABAFULL,
		0x7171F914E2B2E510ULL,
		0x8E44009F1005053BULL,
		0xC87F68FFD328BF11ULL,
		0xF3B525F91DDA892EULL,
		0x1F69553DFB270DF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33253F48F4B4EBC8ULL,
		0x47C739DB7B39EC2CULL,
		0x81282FD4DEF7575FULL,
		0xE2E3F229C565CA21ULL,
		0x1C88013E200A0A76ULL,
		0x90FED1FFA6517E23ULL,
		0xE76A4BF23BB5125DULL,
		0x3ED2AA7BF64E1BE9ULL
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
		0xF1B4E957CB924EBAULL,
		0xFBA36EFFA885605AULL,
		0x14A507E4A131C804ULL,
		0x06C9DB56CD0C81F8ULL,
		0x85E5E23564695670ULL,
		0x2F0EA646E9F6D966ULL,
		0xC12DE406A6FF5F75ULL,
		0x27605B279B73ABACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE369D2AF97249D74ULL,
		0xF746DDFF510AC0B5ULL,
		0x294A0FC942639009ULL,
		0x0D93B6AD9A1903F0ULL,
		0x0BCBC46AC8D2ACE0ULL,
		0x5E1D4C8DD3EDB2CDULL,
		0x825BC80D4DFEBEEAULL,
		0x4EC0B64F36E75759ULL
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
		0x98A56DC1F7DCA532ULL,
		0xA3585465E4B2F12EULL,
		0xBEB2324DEC21022CULL,
		0x91B70ECAB33FF680ULL,
		0x8A59D31785B53A94ULL,
		0xEE8AC2F410C3EF6CULL,
		0xBE78FC4EBDC8D144ULL,
		0x0544B8E28676077EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x314ADB83EFB94A64ULL,
		0x46B0A8CBC965E25DULL,
		0x7D64649BD8420459ULL,
		0x236E1D95667FED01ULL,
		0x14B3A62F0B6A7529ULL,
		0xDD1585E82187DED9ULL,
		0x7CF1F89D7B91A289ULL,
		0x0A8971C50CEC0EFDULL
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
		0x104C773997B033AFULL,
		0x2EC0D0ACEE1550BEULL,
		0x8B4C77DFD4B891F3ULL,
		0x7D20488A76C7C1C5ULL,
		0xF5E128AA57EF6CB6ULL,
		0x11FADAFCA8A67E91ULL,
		0x41FD3E96A6589EB5ULL,
		0x0E3A5C3E59480434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2098EE732F60675EULL,
		0x5D81A159DC2AA17CULL,
		0x1698EFBFA97123E6ULL,
		0xFA409114ED8F838BULL,
		0xEBC25154AFDED96CULL,
		0x23F5B5F9514CFD23ULL,
		0x83FA7D2D4CB13D6AULL,
		0x1C74B87CB2900868ULL
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
		0x5135C899FF7550C8ULL,
		0xF4A822FFD3E4312FULL,
		0x697BAE01B44137E7ULL,
		0xFDF7006CA9A0CEDCULL,
		0x8070AA2CFAED03C9ULL,
		0x36E3C1BABA12A4ACULL,
		0x987965FB71CE241DULL,
		0x0A19C204DA68A5D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26B9133FEEAA190ULL,
		0xE95045FFA7C8625EULL,
		0xD2F75C0368826FCFULL,
		0xFBEE00D953419DB8ULL,
		0x00E15459F5DA0793ULL,
		0x6DC7837574254959ULL,
		0x30F2CBF6E39C483AULL,
		0x14338409B4D14BB3ULL
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
		0x82DC10E3E8EB0830ULL,
		0x48FFDEC151744530ULL,
		0x9B47023DD4768F69ULL,
		0x284C52156B48CC85ULL,
		0x56922F5EB6C8D5C8ULL,
		0x8A7675936D656376ULL,
		0x8AF993B0114FE580ULL,
		0x038DAAB64F4F2E43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05B821C7D1D61060ULL,
		0x91FFBD82A2E88A61ULL,
		0x368E047BA8ED1ED2ULL,
		0x5098A42AD691990BULL,
		0xAD245EBD6D91AB90ULL,
		0x14ECEB26DACAC6ECULL,
		0x15F32760229FCB01ULL,
		0x071B556C9E9E5C87ULL
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
		0xC594119BBBB05C20ULL,
		0x5FF9C12AC6E3FCEEULL,
		0xC39C191E53D53523ULL,
		0x6399DA40412BD0BCULL,
		0x8DF6A005EED49364ULL,
		0xB43BE7C9531858E0ULL,
		0x3AED543117BB338CULL,
		0x178765032920766DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2823377760B840ULL,
		0xBFF382558DC7F9DDULL,
		0x8738323CA7AA6A46ULL,
		0xC733B4808257A179ULL,
		0x1BED400BDDA926C8ULL,
		0x6877CF92A630B1C1ULL,
		0x75DAA8622F766719ULL,
		0x2F0ECA065240ECDAULL
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
		0xC5B457CD78DDBCACULL,
		0x977F8DD303D6690AULL,
		0x2834FCDC8ACB4C93ULL,
		0x944D619D91B4AF10ULL,
		0x003763A19B5EB7CDULL,
		0xFFD42F172701AD18ULL,
		0xB06BF9CB9B98A6AFULL,
		0x3B730612040F7AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B68AF9AF1BB7958ULL,
		0x2EFF1BA607ACD215ULL,
		0x5069F9B915969927ULL,
		0x289AC33B23695E20ULL,
		0x006EC74336BD6F9BULL,
		0xFFA85E2E4E035A30ULL,
		0x60D7F39737314D5FULL,
		0x76E60C24081EF569ULL
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
		0xAA51E23FBC6C1B24ULL,
		0x344E993857329C7BULL,
		0x3767073996AF061CULL,
		0x8E6F2016B1B9C307ULL,
		0xB02314EABC56D12AULL,
		0x136F790AE3B97362ULL,
		0x4728E95C2AAA6C73ULL,
		0x395999B1EC51AE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A3C47F78D83648ULL,
		0x689D3270AE6538F7ULL,
		0x6ECE0E732D5E0C38ULL,
		0x1CDE402D6373860EULL,
		0x604629D578ADA255ULL,
		0x26DEF215C772E6C5ULL,
		0x8E51D2B85554D8E6ULL,
		0x72B33363D8A35C48ULL
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
		0x0B791DAB753C969CULL,
		0x9F0D6106B4342F73ULL,
		0x5C4EF4D3E5715186ULL,
		0x89B3F8F19830EBD2ULL,
		0x13F645340E4EF3E8ULL,
		0x77CC6979FCF41BDCULL,
		0x8A86C48B1973C02DULL,
		0x2C49D5F94B3995F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F23B56EA792D38ULL,
		0x3E1AC20D68685EE6ULL,
		0xB89DE9A7CAE2A30DULL,
		0x1367F1E33061D7A4ULL,
		0x27EC8A681C9DE7D1ULL,
		0xEF98D2F3F9E837B8ULL,
		0x150D891632E7805AULL,
		0x5893ABF296732BE7ULL
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
		0x98A43D71B87D4F83ULL,
		0xF61FF6238D4CDFFBULL,
		0xB19A1DC465416531ULL,
		0xA0E551BA5C65F96CULL,
		0xD0782E3C98C0AEBFULL,
		0x6A18F59359899F71ULL,
		0x001A705460D60968ULL,
		0x084696B24FC324BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31487AE370FA9F06ULL,
		0xEC3FEC471A99BFF7ULL,
		0x63343B88CA82CA63ULL,
		0x41CAA374B8CBF2D9ULL,
		0xA0F05C7931815D7FULL,
		0xD431EB26B3133EE3ULL,
		0x0034E0A8C1AC12D0ULL,
		0x108D2D649F864976ULL
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
		0x0905C9DFE040ED2DULL,
		0x4F0214C7C472A748ULL,
		0xE0EC4C6572DE855AULL,
		0x3B2051D1F1087177ULL,
		0xC9387EF9F30EA548ULL,
		0x3717124C84712E64ULL,
		0xB84BDD7F72140020ULL,
		0x2CEC1B6CF1964308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120B93BFC081DA5AULL,
		0x9E04298F88E54E90ULL,
		0xC1D898CAE5BD0AB4ULL,
		0x7640A3A3E210E2EFULL,
		0x9270FDF3E61D4A90ULL,
		0x6E2E249908E25CC9ULL,
		0x7097BAFEE4280040ULL,
		0x59D836D9E32C8611ULL
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
		0xA14561156356F1C5ULL,
		0xE44345B205D68426ULL,
		0x461E6C759C61B32AULL,
		0xAA99B69C5ED37FF0ULL,
		0xA84AADCEBE385C1EULL,
		0x2E3857BA1552FFBAULL,
		0x0FD5CDCDF04DB451ULL,
		0x091DBC5FAC6CE63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428AC22AC6ADE38AULL,
		0xC8868B640BAD084DULL,
		0x8C3CD8EB38C36655ULL,
		0x55336D38BDA6FFE0ULL,
		0x50955B9D7C70B83DULL,
		0x5C70AF742AA5FF75ULL,
		0x1FAB9B9BE09B68A2ULL,
		0x123B78BF58D9CC7AULL
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
		0x9316C89F76CEAB54ULL,
		0x67ACA4AACB0953E8ULL,
		0xD68FBE379D1BC9A0ULL,
		0x03708BFF89925B2EULL,
		0x1F97D41D925F240FULL,
		0xA4B4559B7606F9F4ULL,
		0x0CE83DCF857C601DULL,
		0x288052A69585696CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x262D913EED9D56A8ULL,
		0xCF5949559612A7D1ULL,
		0xAD1F7C6F3A379340ULL,
		0x06E117FF1324B65DULL,
		0x3F2FA83B24BE481EULL,
		0x4968AB36EC0DF3E8ULL,
		0x19D07B9F0AF8C03BULL,
		0x5100A54D2B0AD2D8ULL
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
		0x0F70B66476FAB7B3ULL,
		0xD60FAA1417777032ULL,
		0xFD03D6AD701E5942ULL,
		0xE4323647F2B21A7BULL,
		0xA0CAE9A3B1A6DB16ULL,
		0xE356909B550BC2C9ULL,
		0x45C403E6B1422F23ULL,
		0x2433C2C6071200F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE16CC8EDF56F66ULL,
		0xAC1F54282EEEE064ULL,
		0xFA07AD5AE03CB285ULL,
		0xC8646C8FE56434F7ULL,
		0x4195D347634DB62DULL,
		0xC6AD2136AA178593ULL,
		0x8B8807CD62845E47ULL,
		0x4867858C0E2401F2ULL
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
		0x72EF213FAD676F0BULL,
		0xDD9548D87D99B6BAULL,
		0x553EE5F71B711F39ULL,
		0x28EF254A75589EC8ULL,
		0x35DD0CA20358D3BCULL,
		0xEE78E1219844EFF8ULL,
		0xA6FE112161336DE5ULL,
		0x316A6173D7711A5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DE427F5ACEDE16ULL,
		0xBB2A91B0FB336D74ULL,
		0xAA7DCBEE36E23E73ULL,
		0x51DE4A94EAB13D90ULL,
		0x6BBA194406B1A778ULL,
		0xDCF1C2433089DFF0ULL,
		0x4DFC2242C266DBCBULL,
		0x62D4C2E7AEE234BFULL
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
		0x4DC18166F67C4DC1ULL,
		0x2A6A3BBD744962D8ULL,
		0x5A5A11CB4F09478CULL,
		0x696DC0C53594C2DAULL,
		0xF6083BF9BCC207ECULL,
		0xB87A46522EE31519ULL,
		0x5C352D451D35A5A0ULL,
		0x26236E63C450ECB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B8302CDECF89B82ULL,
		0x54D4777AE892C5B0ULL,
		0xB4B423969E128F18ULL,
		0xD2DB818A6B2985B4ULL,
		0xEC1077F379840FD8ULL,
		0x70F48CA45DC62A33ULL,
		0xB86A5A8A3A6B4B41ULL,
		0x4C46DCC788A1D962ULL
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
		0xD6B98F0E538D4BD1ULL,
		0x66B525D936CE52D1ULL,
		0x8BBD631180C2F1EAULL,
		0x88239D206305B81AULL,
		0xEFFF527957A31D94ULL,
		0xB7B6AF03E3FCBAF0ULL,
		0x1717A405989FAD34ULL,
		0x3D57379073792DF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD731E1CA71A97A2ULL,
		0xCD6A4BB26D9CA5A3ULL,
		0x177AC6230185E3D4ULL,
		0x10473A40C60B7035ULL,
		0xDFFEA4F2AF463B29ULL,
		0x6F6D5E07C7F975E1ULL,
		0x2E2F480B313F5A69ULL,
		0x7AAE6F20E6F25BEEULL
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
		0x9D38AB77C2D7EA93ULL,
		0x6A0F06116839986EULL,
		0xAC159A2C582963F6ULL,
		0xD94F544717CA061CULL,
		0x94135DF6C14BDD66ULL,
		0x6F5C464901850604ULL,
		0x75395489FFABBB13ULL,
		0x219CD562540027D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A7156EF85AFD526ULL,
		0xD41E0C22D07330DDULL,
		0x582B3458B052C7ECULL,
		0xB29EA88E2F940C39ULL,
		0x2826BBED8297BACDULL,
		0xDEB88C92030A0C09ULL,
		0xEA72A913FF577626ULL,
		0x4339AAC4A8004FB0ULL
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
		0xEAE96C0E29463443ULL,
		0x31C231C4A40D2C1AULL,
		0xFF61E4E663F6EEC9ULL,
		0xDFD8F26B039AC5B2ULL,
		0xFAFE8F6213FECF77ULL,
		0x69A8BB0BA03D391DULL,
		0x1703C42F63ACEBB9ULL,
		0x32537BD839BB3535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D2D81C528C6886ULL,
		0x63846389481A5835ULL,
		0xFEC3C9CCC7EDDD92ULL,
		0xBFB1E4D607358B65ULL,
		0xF5FD1EC427FD9EEFULL,
		0xD3517617407A723BULL,
		0x2E07885EC759D772ULL,
		0x64A6F7B073766A6AULL
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
		0xB8F6B5FBEE9A9011ULL,
		0xD7F40089CE3E68C1ULL,
		0xF431A15324B9BC41ULL,
		0x6794938F2E2365DFULL,
		0x68E7BE812C77B06EULL,
		0x0955F7998FFE791FULL,
		0x73C7141EBFCFBBB2ULL,
		0x0698909360B548CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71ED6BF7DD352022ULL,
		0xAFE801139C7CD183ULL,
		0xE86342A649737883ULL,
		0xCF29271E5C46CBBFULL,
		0xD1CF7D0258EF60DCULL,
		0x12ABEF331FFCF23EULL,
		0xE78E283D7F9F7764ULL,
		0x0D312126C16A9194ULL
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
		0x7B41C585C8F8838AULL,
		0xAB43597F840E077AULL,
		0x0138202790E5AC1AULL,
		0x32E50DB7C67DC78AULL,
		0xFDB19176166F4E30ULL,
		0x5DF66D98908C039CULL,
		0xF708146DEF2815B6ULL,
		0x17E2E75A163B795AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6838B0B91F10714ULL,
		0x5686B2FF081C0EF4ULL,
		0x0270404F21CB5835ULL,
		0x65CA1B6F8CFB8F14ULL,
		0xFB6322EC2CDE9C60ULL,
		0xBBECDB3121180739ULL,
		0xEE1028DBDE502B6CULL,
		0x2FC5CEB42C76F2B5ULL
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
		0x0B45017501CED374ULL,
		0xFDE21912570DFFD4ULL,
		0xA6FDD8CABCF70F30ULL,
		0xA6BB233A9F210226ULL,
		0x6D534E08943C8B9EULL,
		0x6844ABFC211F18CEULL,
		0x9348F6EDA3AF25A7ULL,
		0x201BC36D2A28C70CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x168A02EA039DA6E8ULL,
		0xFBC43224AE1BFFA8ULL,
		0x4DFBB19579EE1E61ULL,
		0x4D7646753E42044DULL,
		0xDAA69C112879173DULL,
		0xD08957F8423E319CULL,
		0x2691EDDB475E4B4EULL,
		0x403786DA54518E19ULL
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
		0x2EBEA9734DF83ABBULL,
		0xD8B2D42720068BDCULL,
		0x166DC7F600858225ULL,
		0x3E602F0C6493AA03ULL,
		0xF80D1E16DDECAAD9ULL,
		0xED27F7D1A2B00EEBULL,
		0x3003B7E480EA170DULL,
		0x313F47EF25BF08F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D7D52E69BF07576ULL,
		0xB165A84E400D17B8ULL,
		0x2CDB8FEC010B044BULL,
		0x7CC05E18C9275406ULL,
		0xF01A3C2DBBD955B2ULL,
		0xDA4FEFA345601DD7ULL,
		0x60076FC901D42E1BULL,
		0x627E8FDE4B7E11F0ULL
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
		0xAC223C8A8C0344BBULL,
		0xBD2E88992190A8B0ULL,
		0x3CE1A12CBFC04AC7ULL,
		0xD90262976E90927FULL,
		0xE09EBA771E3A4CDCULL,
		0xAE667DFC4D55D55DULL,
		0x5480303378F6F7DCULL,
		0x0D882037F10897E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5844791518068976ULL,
		0x7A5D113243215161ULL,
		0x79C342597F80958FULL,
		0xB204C52EDD2124FEULL,
		0xC13D74EE3C7499B9ULL,
		0x5CCCFBF89AABAABBULL,
		0xA9006066F1EDEFB9ULL,
		0x1B10406FE2112FD0ULL
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
		0x1A85903F24DFB0D0ULL,
		0x84ACB7D24517655AULL,
		0x467D80E7911884ACULL,
		0x015CFC334D495A7AULL,
		0x2654C66CA33DEADBULL,
		0x08F919BEDF71788DULL,
		0x527436C93C590D51ULL,
		0x0E5D4D5F8D650E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x350B207E49BF61A0ULL,
		0x09596FA48A2ECAB4ULL,
		0x8CFB01CF22310959ULL,
		0x02B9F8669A92B4F4ULL,
		0x4CA98CD9467BD5B6ULL,
		0x11F2337DBEE2F11AULL,
		0xA4E86D9278B21AA2ULL,
		0x1CBA9ABF1ACA1C14ULL
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
		0x46E148122F7E1976ULL,
		0xC37999D0B1091F97ULL,
		0x4F0F6B2D8A86B715ULL,
		0xCA447E07E9118806ULL,
		0xA89CC5E223C05F95ULL,
		0x46F51428A943ACF1ULL,
		0x19D4AF2F654EF63DULL,
		0x293F3652955A1532ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC290245EFC32ECULL,
		0x86F333A162123F2EULL,
		0x9E1ED65B150D6E2BULL,
		0x9488FC0FD223100CULL,
		0x51398BC44780BF2BULL,
		0x8DEA2851528759E3ULL,
		0x33A95E5ECA9DEC7AULL,
		0x527E6CA52AB42A64ULL
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
		0xA1A601FEDD15588CULL,
		0xE30040E0085CFA46ULL,
		0x0755B883B0C9E2C6ULL,
		0x0A945ECD6E4928C8ULL,
		0x685478759A0F6D21ULL,
		0x8A458C88E737AD01ULL,
		0x9C08AB1747C9E0BBULL,
		0x04BB3C51EE12930FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x434C03FDBA2AB118ULL,
		0xC60081C010B9F48DULL,
		0x0EAB71076193C58DULL,
		0x1528BD9ADC925190ULL,
		0xD0A8F0EB341EDA42ULL,
		0x148B1911CE6F5A02ULL,
		0x3811562E8F93C177ULL,
		0x097678A3DC25261FULL
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
		0xE257E7366B706B31ULL,
		0x068D780BBD3FD7DCULL,
		0xF39F3AE69FC4DE2DULL,
		0x7679C30455B82FA7ULL,
		0xEA95DFB56090F1A2ULL,
		0xF258AE93C3AE3B6BULL,
		0x0A592A47E7422F10ULL,
		0x27CAA1DCF2ABD005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4AFCE6CD6E0D662ULL,
		0x0D1AF0177A7FAFB9ULL,
		0xE73E75CD3F89BC5AULL,
		0xECF38608AB705F4FULL,
		0xD52BBF6AC121E344ULL,
		0xE4B15D27875C76D7ULL,
		0x14B2548FCE845E21ULL,
		0x4F9543B9E557A00AULL
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
		0x84557B8409AD943AULL,
		0x49258E66C08042ECULL,
		0xDB1001501179DECDULL,
		0x691076284FB056ECULL,
		0xB20787C01F10D02EULL,
		0xBFADB43AAD79F88AULL,
		0x0E97688B00EF0A1CULL,
		0x34CBCF0729B6DAE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AAF708135B2874ULL,
		0x924B1CCD810085D9ULL,
		0xB62002A022F3BD9AULL,
		0xD220EC509F60ADD9ULL,
		0x640F0F803E21A05CULL,
		0x7F5B68755AF3F115ULL,
		0x1D2ED11601DE1439ULL,
		0x69979E0E536DB5D2ULL
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