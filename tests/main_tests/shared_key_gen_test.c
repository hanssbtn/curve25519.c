#include "../tests.h"

int32_t curve25519_shared_key_gen_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t priv_key1 = {
		.key64 = {
			0xC121DCF3E2025C88ULL,
			0xB6D6062B8ECBFC88ULL,
			0x1025DA67D4E073ECULL,
			0x7FAEC0811A24A6F2ULL
		}
	};
	curve25519_key_t pub_key1 = {
		.key64 = {
			0x5D6F61FAC595C5C2ULL,
			0x0407780F1C764070ULL,
			0x5DC401359157C410ULL,
			0x382A265FC9E543EEULL
		}
	};
	curve25519_key_t priv_key2 = {
		.key64 = {
			0x0EC39815E31046A0ULL,
			0x4AA9E069DA330D1EULL,
			0xA2EF2CDAE786D138ULL,
			0x6A383E785D4EBFB0ULL
		}
	};
	curve25519_key_t pub_key2 = {
		.key64 = {
			0x85437A31A15B8E75ULL,
			0x0D0C3678B007B26BULL,
			0xAC26D4ACD2FB9282ULL,
			0x38008D7B9A0FC6B4ULL
		}
	};
	curve25519_key_t shared_key = {
		.key64 = {
			0xF4735B9E0EB7F7CDULL,
			0xD21A3DD5C404B67DULL,
			0x26DB9CD0AEDC4B9CULL,
			0x3E5DAFAAEDF3D463ULL
		}
	};
	curve25519_key_t r1 = { .key64 = { } };
	curve25519_key_t r2 = { .key64 = { } };
	printf("Test Case 1\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	int res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x31EF7D6DD9B6B6B8ULL,
			0xEA0E3128B5CA6014ULL,
			0x41E4C74702D7AEA8ULL,
			0x52A7635D07590FC6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF8659F1F3B5AC0A7ULL,
			0x4713CC0F16216386ULL,
			0x7C733DA7BD8D6089ULL,
			0x3D228A83F4FC29A1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3EEA2B516DEA2D40ULL,
			0xF94DBFDD04EC1BDEULL,
			0x373318A1F4411CD4ULL,
			0x6849442CC5DED5E7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F6D71307E0B2CBBULL,
			0x73CF88E3F018B55FULL,
			0xF1102A587E050093ULL,
			0x0FE71366AA01C3CCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3F171749CAFCFABULL,
			0x5B8034F99D165D17ULL,
			0x8E23379CEE3D4467ULL,
			0x178560298F7D239AULL
		}
	};
	printf("Test Case 2\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCD58477D53285360ULL,
			0x3EE3F2707AFCDDF5ULL,
			0xD49978CE0172427FULL,
			0x468943498F46FCE5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x92F4CDFEC24E798FULL,
			0x2B1FE858A53B5C36ULL,
			0x1755E6D1DB452B03ULL,
			0x77B61E5110E29521ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF2438FE31BD67F00ULL,
			0xCF9C82EFB4C74747ULL,
			0x62442A1BEF155E60ULL,
			0x7D9B64FADDF572C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7D74CFF29C7ED0E1ULL,
			0xE8BCF29F8704E63CULL,
			0x8B11012E119C92BDULL,
			0x0D5C1EB7F83E0110ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x84FEEC642E79CD62ULL,
			0x74DC216E71A7F2F4ULL,
			0xEF67D9ED7B849212ULL,
			0x4845BD6CB54F9833ULL
		}
	};
	printf("Test Case 3\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4E64DF72C8077A00ULL,
			0xFCE1733F48ADD323ULL,
			0x2E2006324E23176AULL,
			0x7BFCD6CBB93629FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D990116A9636F00ULL,
			0x1EA656D52AB5FCF2ULL,
			0x55FCBECA13FECF52ULL,
			0x479838B15E6A4CEEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x20575D7D7CC65730ULL,
			0x10B49DCEF327D634ULL,
			0x2A804CB57D2EBE62ULL,
			0x6447201E263D4EBFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD266C87BCF4B9C87ULL,
			0xE7FB0B030EE9188BULL,
			0x76D4B81051D8783CULL,
			0x098C60DA436D9882ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x66CF212C4B83BE84ULL,
			0xC0EF86C6057A79F0ULL,
			0xDB8A50CA78E062E3ULL,
			0x0FA4957006585DF8ULL
		}
	};
	printf("Test Case 4\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3DF4456B216C07C8ULL,
			0xC3692CDC253CB941ULL,
			0xA5D539D5F9853ACAULL,
			0x48E1F5FF852379C8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6FABFA8C1A69B2A9ULL,
			0xDFA3331C625C5179ULL,
			0xA93EE6D9F0A31F84ULL,
			0x115123FCEF4EFAE2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD0106B39085CBAE8ULL,
			0x4CC3F7BAE0F88FDEULL,
			0xD455C79FD820B2BCULL,
			0x7F3A25CF4165F00BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8CEFF3966489E068ULL,
			0x507562D70470CF93ULL,
			0xFDD9C94CF0454015ULL,
			0x534A6616604B8E6FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCAAFC8FC768C8869ULL,
			0xE4236294B059CA9DULL,
			0x8050C8E039742B1FULL,
			0x78A21F97D8BEB948ULL
		}
	};
	printf("Test Case 5\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFD95F66842759710ULL,
			0x1667A876819E8520ULL,
			0x14FD2F4FE68417A1ULL,
			0x4185F23B2EC02CA7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x27D3110F13776BA8ULL,
			0x9FD06470D2921E4DULL,
			0x65362A8D13A9B998ULL,
			0x7388F68BDAC06A71ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x38702A7737064AA8ULL,
			0x3B3CEC871D446228ULL,
			0x14334F25DD80CD18ULL,
			0x4A998D192B7AA17EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4D9FBB45FC3F9F8DULL,
			0x7FCADE7A484C3A93ULL,
			0xBC25D22917C7F4D9ULL,
			0x4EDF7E34B044CB73ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x343988AFE5208619ULL,
			0x381B266043F28AFEULL,
			0x75EAB618CC33C020ULL,
			0x143F79EDB6807A84ULL
		}
	};
	printf("Test Case 6\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x45AAE73189E63538ULL,
			0xCECD7CD0043F4233ULL,
			0x77BEEF74663AED7AULL,
			0x790165EB19CE23ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEE51D96BED9B22DAULL,
			0x37ABE4369ED96D1BULL,
			0x909174044DD8619BULL,
			0x1DD42312476CF048ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB9ADE64650621108ULL,
			0x3340EDA0E99A30CCULL,
			0x014005D73E0EA9C6ULL,
			0x64A9E4F9FBF2CBCDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2E23EFE37476C57FULL,
			0x628624C00D80BA57ULL,
			0x4DCA30A00AC7C242ULL,
			0x70D03EF73653EE5FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x224DC743CF15E193ULL,
			0x22A297A1310DAA68ULL,
			0x714063BB90ECB3D6ULL,
			0x5F0F2685814BFD60ULL
		}
	};
	printf("Test Case 7\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAC88DD4761567FC0ULL,
			0x4336626757CD7740ULL,
			0x0D6829ECE9E62DF3ULL,
			0x79E67151BD9AB2DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA063190BE5DB8AFULL,
			0x9973B0385F7839F4ULL,
			0x5F07AB666CA0BDC6ULL,
			0x6F6AB2A8255DF908ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52F273D5F7EF0C50ULL,
			0x18EF4350A1D4CC1AULL,
			0xA5F1FFEAA784C736ULL,
			0x6E35B554E4DBF9BBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB17DF794A57D5E37ULL,
			0x15F3732CC014FF85ULL,
			0x60960D97482F74C4ULL,
			0x0F0F4756B0592DD9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1ABDC75F55AC93C6ULL,
			0xAA3E157F800C682DULL,
			0xCD688F64562FB882ULL,
			0x212656CA119A88ACULL
		}
	};
	printf("Test Case 8\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x99DE5069DF081B30ULL,
			0x45B99C28D78B3B16ULL,
			0x7039FDD164B66258ULL,
			0x48C547C4AF75691EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7EC694C52F754E3ULL,
			0xA306220A51F4DCF2ULL,
			0xF836665D53A94623ULL,
			0x4EB083460AE52303ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5AAC9C366E836448ULL,
			0x3EC3B371449932C4ULL,
			0xE7CA2A1A9F9FD9D2ULL,
			0x5FAA435CB4DFA54FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF6EBA7800135F07BULL,
			0xC6F871B384DA1684ULL,
			0x6956DFA968786990ULL,
			0x62F0F96DA979B3E1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x40BFF12DAE21673BULL,
			0xDEB7F34F98580EB6ULL,
			0x6EFD164C90F11A07ULL,
			0x1F88BA09C5D2A51FULL
		}
	};
	printf("Test Case 9\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x07F9D2A32C1BF7A0ULL,
			0x1B01F8821FABC5FFULL,
			0xA4A0554BEBAEC1F8ULL,
			0x68C9A3A64A8B67C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4DFEEBBDFD65F68FULL,
			0xEAD8A2BD6D6F9CAAULL,
			0x433D0F27F3A2C6ABULL,
			0x0ED1180EEB274B43ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD25C44578F45F990ULL,
			0x4EA03E6207ADF711ULL,
			0x6005DCABDC2145A6ULL,
			0x46B76C24D5FB82A1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8E0C8F9AE0E61A10ULL,
			0x7C4F49576DEFACA0ULL,
			0x22853C6F38C7896CULL,
			0x7D608DF719D48FEBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8FAB58535F8A52AULL,
			0x34EE86FD76E6CB39ULL,
			0xD36D97231193560DULL,
			0x21F60F7F1CBF966EULL
		}
	};
	printf("Test Case 10\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E5B982D64758AA0ULL,
			0xF2BEF6E032EF6FFBULL,
			0x1168D6E0F5E7F2E8ULL,
			0x4910F17BAF3EE891ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4AC86B6791DC0AAAULL,
			0x6B531D32A8985FE7ULL,
			0xF3D39A4345010595ULL,
			0x610510EC8F736002ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52CCA0DAF2837388ULL,
			0xFD4F6C40DC5D54D2ULL,
			0x11014B7F4E277D09ULL,
			0x6BA2A9E32943DA66ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0E039EACCF96E2AAULL,
			0xAEB69155A6C93818ULL,
			0x840784E06ED87197ULL,
			0x4A38FC4F6A1CE24CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3D0705C39F1435EULL,
			0x1227C94BC631E808ULL,
			0xDF5262D8423954E3ULL,
			0x5AEE08EF3EF150B5ULL
		}
	};
	printf("Test Case 11\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x04BAFA1989C444F8ULL,
			0xBF632D219D19A8D9ULL,
			0x1970A85C22D3B8DFULL,
			0x40088B7E8524448DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D1857FBBD54C3F3ULL,
			0x5AD68C20CB98C82BULL,
			0x7307AE696052770DULL,
			0x533CBEB84EF242A5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE05699C9DED80958ULL,
			0x3CFA2D490F51F08DULL,
			0x60353061EA20015DULL,
			0x6F38254B5A51A7ABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9A9D047DE23C7D2FULL,
			0x4629CE037013241EULL,
			0x424D5569DAD91E99ULL,
			0x3ABC2B94211859B5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5ADCAC9A3674C6DULL,
			0x247CCC0FB74EDA01ULL,
			0x67AC3F03E7A84530ULL,
			0x3E871C89B140CCC9ULL
		}
	};
	printf("Test Case 12\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x286DFB05AE6F9620ULL,
			0x03DFAF42D2824E3DULL,
			0x02B197429264B682ULL,
			0x52DBEBBFE672D2C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x644FB1F67F9706F8ULL,
			0xB8A090FD7E489F03ULL,
			0xFF2F3C8B1A3B71B9ULL,
			0x16E07BB5C74E25C9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5B524C721A8C4770ULL,
			0xFF345E80C16386C8ULL,
			0x6ADBC9492305585FULL,
			0x4976188A97B22BF6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF9384525C310D011ULL,
			0x7C19EE281FFC1DE0ULL,
			0x85DE83BEA6891017ULL,
			0x4D8B4DCFD2B8981CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61973A8783040821ULL,
			0x5FFA3C48DBE8FF00ULL,
			0x41F96DAE2F61191FULL,
			0x37465B8D31DC8EB2ULL
		}
	};
	printf("Test Case 13\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58D3CD6B57F509B0ULL,
			0xB5C52C8D8508D8BEULL,
			0x144E4479571500A2ULL,
			0x7C8E27A031C5F59DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x727EA92A4FD08A27ULL,
			0xACDC4F65BE2B10D0ULL,
			0x6E2E776D504819DFULL,
			0x7BE63B0EBED34311ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C56B0234FBAC080ULL,
			0xB69D453A1A308F0CULL,
			0xFA76484E5FA10D67ULL,
			0x56D65C0FC34224D6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2F7A5A03722ED619ULL,
			0x9B81C63DBDE908B5ULL,
			0xF0A66253BC5296AFULL,
			0x1AB287BCC3FD52A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x670D0C5472105587ULL,
			0xC0FCF6462D368E23ULL,
			0x3E6A0519C70B28D1ULL,
			0x247F9449226FE36CULL
		}
	};
	printf("Test Case 14\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x60FBD5A020C00820ULL,
			0xB1A03D007967F32DULL,
			0x69D62CC38560F332ULL,
			0x648368E5AA0F3DC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCFA437BF3D77E2F2ULL,
			0x10707E3EC51BF593ULL,
			0x1CD900D7F39D1336ULL,
			0x613A9B0722983BF9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x275F5594869062D8ULL,
			0x5827DFBBD7573BACULL,
			0xFDCE1188F6CC6FE2ULL,
			0x6D68D082B13FAD73ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x98FA32CEF735A45CULL,
			0x58AF3F676C055739ULL,
			0x00D201E97D9FB06AULL,
			0x22D7BC517C8C690BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC945F23E2181049DULL,
			0x9EA5970D19A17381ULL,
			0x06B81846411CFC71ULL,
			0x48D5CAFD6F3CD8B2ULL
		}
	};
	printf("Test Case 15\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x91CFE2A8F79ED100ULL,
			0x6086E38E91092CBBULL,
			0x9D1092A36304DA7DULL,
			0x7A537D2C2232FB0EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA91A32A5891035AFULL,
			0x9AEB8FC5A9648C25ULL,
			0xF91BA158BE7A8554ULL,
			0x6F5FBA2AE5392538ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8EA2EF90BB80F690ULL,
			0xD59475D81FAA7B4FULL,
			0xDF41DC0B0434BBC5ULL,
			0x47D7B26044DDC488ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBC91E5B7C55178E4ULL,
			0xD17F5274844BEDF8ULL,
			0xFAE3F049E9CCC26BULL,
			0x77C7AEAA37D769B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2C38227FC97AF63BULL,
			0xE4CA093A15949FABULL,
			0xF7A8086551CC64BBULL,
			0x5A6111CEE4EFFED5ULL
		}
	};
	printf("Test Case 16\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF21089BDE6BC5ED0ULL,
			0xF44B6077B05CBB3EULL,
			0x006CEB49A0985378ULL,
			0x67677FDAE7171CB3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB219381D1C95B8B0ULL,
			0xC3FD2E7FEB4E31D0ULL,
			0xAAFF6BDA957A0941ULL,
			0x21DD9D172EC30197ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3E29CAB635015B70ULL,
			0x7DDA5A5F89E94E31ULL,
			0xEE97283019BF8EC4ULL,
			0x6300EA19E27A7621ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x784D06E677DAC669ULL,
			0x5737537D538B304AULL,
			0x08A46CEB40F902D2ULL,
			0x30E49BD385C978F8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3E57A213AD68C3DBULL,
			0x83C838265CA09937ULL,
			0xB4B053719C2250CBULL,
			0x72C44218D3F55BBCULL
		}
	};
	printf("Test Case 17\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFED85B4598495780ULL,
			0xF779C45D84792057ULL,
			0x08B207B98C404195ULL,
			0x7010F48E15041DC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D6DAB77BBEB3DE6ULL,
			0x5E1C309A977B6EC7ULL,
			0x4D2A8CF3ADA05F72ULL,
			0x1B7D0F2456CF5535ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC9477D5569B97CF0ULL,
			0x30DBB82C1151CA2DULL,
			0x43BB1AA11201F054ULL,
			0x4EB6D6939B848390ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2E7DDC3246F411D6ULL,
			0x5BAEE8175F6A59BBULL,
			0x5FC2B593AAEE5218ULL,
			0x3EF1353A6E89FF89ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD07B82CEF04E4B8DULL,
			0xA99D74FCA43DAD3FULL,
			0xF671D50242EA031FULL,
			0x45543E078A6599DAULL
		}
	};
	printf("Test Case 18\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x03C9DFFCA5E08FA8ULL,
			0xA93B7503BD4AF138ULL,
			0x4453020BFED936CFULL,
			0x718E4CE07813985BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC31A7D61605249B9ULL,
			0xF6CE75A297AA0A22ULL,
			0x71D8BC1D35C96B10ULL,
			0x4E6DC1D2CCF4FEC0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B1C1BFE82BA90A8ULL,
			0x458CA9E7116CECF2ULL,
			0xC573D859F5105AE7ULL,
			0x79DC8F79FE848AD1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x342A3D44AF52F66CULL,
			0x3927D6F2E18762AAULL,
			0xDB4D1B6F5079FB98ULL,
			0x4908C59CBD1BE2C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x737C6C3455C1C751ULL,
			0x054409B41223E319ULL,
			0x08A1172498A8875CULL,
			0x46E425200E4A718FULL
		}
	};
	printf("Test Case 19\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x54D05152F72BCC90ULL,
			0x1395EB6C8B702AB6ULL,
			0x61D85F7D3BB68C1BULL,
			0x4F3871CD8A93F49DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB9AA29B43571D57DULL,
			0x9BBFCB87CB63BA17ULL,
			0x99CE8F4743799AE1ULL,
			0x7EFB743280274D17ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x587AD73DD3EE1E78ULL,
			0x853F7C87E4A8792AULL,
			0x45A9ADBF82571AFFULL,
			0x7C29B39C69B741F3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0D73E406576C3C35ULL,
			0x40565E2136F6A759ULL,
			0x87B1B5107B22DFBBULL,
			0x71691711BA0885AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2AF625E9AA1E33D8ULL,
			0xEEFE22D9B2313FB6ULL,
			0xFB290371C2443474ULL,
			0x46D29F88682D6A30ULL
		}
	};
	printf("Test Case 20\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF515A1926885EE58ULL,
			0x2BB1D4FB03C36F5EULL,
			0x5B5EEFC4E93EB119ULL,
			0x6317097DD35025DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x30F144682F5A3253ULL,
			0x3BBEEEA64F1242A3ULL,
			0xD1BE825DFFB2E375ULL,
			0x07A87796EE1896A4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x64447F74926F25D8ULL,
			0x4933F717A47CFD89ULL,
			0x5680BEAB03145CB3ULL,
			0x74788B99AB7F79E3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0DB0F420D910F613ULL,
			0x7750DDF12F84BC30ULL,
			0x385485051F510CDEULL,
			0x2509C6C13EF24783ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AB433BAE2E1F71FULL,
			0x289B7BE3CEAE2FE0ULL,
			0xC3B9E6B5D30D2308ULL,
			0x1342F26DED764B05ULL
		}
	};
	printf("Test Case 21\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F1A4DDBF1936200ULL,
			0xE41C2A95A49FCDBBULL,
			0xC0A8A62C12DEA905ULL,
			0x680A356AFE96E7E6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x11F1BDDB22B3B45BULL,
			0xD4362E21E172C33DULL,
			0x2AB10785A763410EULL,
			0x1FC4CC2464348BDDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD5328BE806580138ULL,
			0x19AB2A51759E441EULL,
			0x1B2CCE2AE70BD658ULL,
			0x6DBBEBEEE029E2D4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBE5EF9E6EC0719CEULL,
			0x4E13A02D44BC37DDULL,
			0xE313794D75BAB165ULL,
			0x02CC46E97EC5404CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6FF834EEAA9E9F6CULL,
			0xB8E6B14A32D7BA55ULL,
			0x9ED251FBE48430A0ULL,
			0x59B39BF7C8A39B87ULL
		}
	};
	printf("Test Case 22\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x53B258C25898B5F8ULL,
			0x3FBFAB3BCE6054C8ULL,
			0x101D11ED379A3B51ULL,
			0x4CFDCBA1690D0536ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA4FF2BA962AED273ULL,
			0xBAE9B09D30D9DB28ULL,
			0x6EBE2B7F992CF219ULL,
			0x3D15F413A227D544ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x18F2A034138A3D18ULL,
			0xB69B27C7298E7414ULL,
			0xE77FC919170C65D4ULL,
			0x681CD3678989D3BFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE28E0CA755532B5FULL,
			0x49E3086E9B804897ULL,
			0x381C890437773F74ULL,
			0x7BA25526E566246FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA29366BF3E2A4E2BULL,
			0xD72697B0821DCEE6ULL,
			0x9ABB8F10CBF3AE8BULL,
			0x06274E51CBAD4069ULL
		}
	};
	printf("Test Case 23\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE83FEF3BBCCCE048ULL,
			0x86F13743FC2E21B1ULL,
			0xDF62A647851FAC27ULL,
			0x531DC145ED654B9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFA68DA35DC1CDCB5ULL,
			0xB1521B017448D67DULL,
			0xBCCBBC8C6891C634ULL,
			0x223E1F26296219C0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD1D807C8CB1D8D00ULL,
			0xAFFD18EFB3B42339ULL,
			0xC87BCF8F8A7BCFC0ULL,
			0x6DE53D786A10861EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x460351EB8433EB5EULL,
			0x48C796DF640B9A67ULL,
			0xB4123C45713379D3ULL,
			0x42D458CE567011DDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD1FF658DF635EA3AULL,
			0x11256ADFFF3D1EFFULL,
			0x432E6AE673A9403CULL,
			0x62DEBE03FDF9C127ULL
		}
	};
	printf("Test Case 24\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x44B06F76258DB8C0ULL,
			0xA0F30E7568B38C8FULL,
			0xDA679CA178133C87ULL,
			0x7029F6E8223E198BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE8344F55AE4C279CULL,
			0x7D945FEADB04D878ULL,
			0xB48724F8086E51BBULL,
			0x649E8F1357E61536ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C6691A78F1FDCE8ULL,
			0xAB445FAA9355C427ULL,
			0x62A4A9C0ED2CE4EFULL,
			0x4BE83EBA05EC77B9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC812F7591BFA0AADULL,
			0x1C22812AF5326520ULL,
			0xD64DCA0DDE14C98FULL,
			0x691C3EFD01071B8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x192C25789C9678D4ULL,
			0xBDCC5126F717C1E1ULL,
			0xA379E4EDAE843121ULL,
			0x6D1C8E33E9E42137ULL
		}
	};
	printf("Test Case 25\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x33AF7F8127ACFC00ULL,
			0xF70EE562C3A3B3E7ULL,
			0x5BADE49E5FCAC662ULL,
			0x50112F73C190D670ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB49AB47BA33132E6ULL,
			0x4FB5E249C6F20924ULL,
			0x598395F6B4711628ULL,
			0x4E56641EE6994BA1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x61D2EAF858BA6420ULL,
			0x7A7D1655944E93C6ULL,
			0xAD0BAAE2272E6ECBULL,
			0x6F589E706D9D6228ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5E64109103923BB9ULL,
			0xA859994B2B360CA4ULL,
			0x17CDE596645D9304ULL,
			0x2D10A50BCFC2DA6CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE08EC08E525EB5FAULL,
			0xED889D5F5BA826F9ULL,
			0xED93BEEFA353558AULL,
			0x2D17067C9DB1269CULL
		}
	};
	printf("Test Case 26\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC4ECF7B80B890290ULL,
			0x808424E637B07078ULL,
			0xED97D98E39E8E235ULL,
			0x56CF7824032F0F74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8DFEE6F3645276A9ULL,
			0x4558438D1D4C673CULL,
			0x7C28D525C49E28EFULL,
			0x37F4920FBACC15CEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C25BDD25A082798ULL,
			0x1AD35BE7A3C44CDEULL,
			0xEEC0C191F2CB7876ULL,
			0x74D097B42FABEC48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEB6E993515C3694BULL,
			0x543EBA6EFF13D5D9ULL,
			0xAF2E69FAF17D11ECULL,
			0x2760103D4880B002ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6CC813B6FF4E2B0CULL,
			0xEC799FF5F2FC30FAULL,
			0xA29F5CBFD0191332ULL,
			0x48134B3BFC6D853FULL
		}
	};
	printf("Test Case 27\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE963F5791F9A34F0ULL,
			0x3AF01001389CCD62ULL,
			0xA62195C06130967AULL,
			0x5B853DFBB256C214ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x364386F2F7E3836EULL,
			0x12D8F400E234F85DULL,
			0x2FEE8CA6BF1AA007ULL,
			0x4BC8EA0909A35742ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x957C20400A0F1170ULL,
			0xD459D6213A331E63ULL,
			0xA3BB66FB66B64D4CULL,
			0x457BB835B986C97FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCAF13B0E70E4920EULL,
			0xC68C745AD9A15BD1ULL,
			0x3F2EEAB24316300DULL,
			0x44A789540A49720CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2DCF7923054AE596ULL,
			0x25828AE93976A82AULL,
			0x2D220C32E8DE52F6ULL,
			0x55906A92F728E4B5ULL
		}
	};
	printf("Test Case 28\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3BBBFC80C7814818ULL,
			0x0C2CEBD00C310112ULL,
			0xE74BEA3C03BF5DA3ULL,
			0x4BCA3E08C0745AABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF0AF66405D97080AULL,
			0x54A13291CF80A3AFULL,
			0x42BF2E81132ACB8AULL,
			0x6F43C7C4F8A346F4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD33402A0960A310ULL,
			0x81C5E560D1821B9CULL,
			0x711BBB8CFF5EC04BULL,
			0x529B81B888F067E5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9F58D787888EC34ULL,
			0xE16B175769838494ULL,
			0x81EC626400454B0AULL,
			0x1945844C5861909FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC8D2FB6456B8633AULL,
			0x1CCAD42A7DC08733ULL,
			0xC7863336809B406AULL,
			0x5DA028D4789E9EAAULL
		}
	};
	printf("Test Case 29\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E1769CF817A6368ULL,
			0xC4BCB3EBE4DD19F2ULL,
			0x19B8F60D3FF068F0ULL,
			0x66798EAE6479C647ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAA6C6CA3749BC451ULL,
			0xD5C2A231CC940A78ULL,
			0xDD810D421DDB5E28ULL,
			0x6CAFEECD01D31F06ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12081407B6B4E078ULL,
			0x3D809813D2884486ULL,
			0x04C37D44010C460BULL,
			0x4785A16E50DB8A17ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFD184F66D3FC1A2ULL,
			0x965D0BAC0A527BA3ULL,
			0xEF26E110A88AC61EULL,
			0x5B0D675D61AFB41AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6F9B82BB7E76155ULL,
			0x3983F95972034B60ULL,
			0x6817DC5D9D4BC261ULL,
			0x0ACD437DC2BE3FF5ULL
		}
	};
	printf("Test Case 30\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE656504256FEB520ULL,
			0xEEC175F91C912B78ULL,
			0xC315527709DC1D71ULL,
			0x7B72BE57D2164115ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x702049E3EBEE38B4ULL,
			0x05343CA2BF386BDAULL,
			0x6AC4163256C8B8E8ULL,
			0x67FAF108AB96D71FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5DF8A7B3CC61BFA0ULL,
			0xA101903511127692ULL,
			0x6F85905A7F5CE285ULL,
			0x7DE97A3DD95234B4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0AC7783CB7DDA94CULL,
			0xD1DBA05893392DA9ULL,
			0x9FB52E34A151F38CULL,
			0x1AC534E003BADC3BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x085F2E4879985AACULL,
			0xC1E501A5F751562EULL,
			0x5244D0D96C2A6B4EULL,
			0x018228920BD269BCULL
		}
	};
	printf("Test Case 31\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9DFF587C35B80D58ULL,
			0x9F091E7F87CA0438ULL,
			0xC1D505F847D6067FULL,
			0x5BEE751EA1EC15ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7FE09B3EF79CAE8FULL,
			0x493C66612899C8C3ULL,
			0xEACE033D295D8F48ULL,
			0x1E7369F309E4742AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5A1114F564DDE138ULL,
			0x40AAF09811966832ULL,
			0x0C06EB9E8A1932BAULL,
			0x722F2AFBCDB2DECDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE4F1E80E60CEFE46ULL,
			0xBA5040C05DFD17E7ULL,
			0xD4C3924BEE4188BAULL,
			0x481537B7B2F3D700ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x01C21C582355F559ULL,
			0x1A4598EC68123C03ULL,
			0x39BEE85B5B64E246ULL,
			0x3F098666420CD546ULL
		}
	};
	printf("Test Case 32\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x42C8051A279CCCD8ULL,
			0x2D2200A7C4D91DC9ULL,
			0x8DA9B472E103BD71ULL,
			0x6DBC64BB33E5FCFBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1BA3B2B4847CA352ULL,
			0x2DB728CDD8C87CEDULL,
			0x71EE6488A53BDF48ULL,
			0x008C45D9F2D5B84DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEE8F0E2B0D105168ULL,
			0x1CC48A12B11B5A40ULL,
			0x170DA4F8F56769DEULL,
			0x739DF093DECEC6BFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x85EA5F74A416D779ULL,
			0xDA26661C08F06FB8ULL,
			0xE2C4D57AE00905EFULL,
			0x67E5C45EB1D4007AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC194E34E3CA9D0AAULL,
			0x80037006ACDCCB7BULL,
			0xC4449D0F0A018A7CULL,
			0x673E19EA0E0E308AULL
		}
	};
	printf("Test Case 33\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x135BF041746B1C20ULL,
			0x929BA394A36F7594ULL,
			0x4C3EA16D81E5B0B9ULL,
			0x5DBFAC091C46A113ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x27C8DB720829E0D4ULL,
			0xE5F81B3A59113400ULL,
			0xEF4D60129517AC87ULL,
			0x538903259063028CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x447F96EC46AFCF88ULL,
			0xB5499ED44BF0C952ULL,
			0x5566BB9FEBA380FFULL,
			0x4ADE08566F3A47F8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF9E84F7A71DE94AFULL,
			0xE312C234C4F7D3DBULL,
			0x258B27FCA09287FEULL,
			0x7CB126162A082ECDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6387C8082EDAD802ULL,
			0x2AB938C976721F7EULL,
			0xE88CB0B60763D90DULL,
			0x430D9E2A21C1C708ULL
		}
	};
	printf("Test Case 34\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD63C1765F22C7128ULL,
			0x070B8B74B9E2F82FULL,
			0x2D9B7F9BD28A014AULL,
			0x4F862BA3DCEDE7CCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAC1D29C22FF61F78ULL,
			0x640B265824647A86ULL,
			0xE9EC31D9ADB0856BULL,
			0x6FCC8EC1C805DFFFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEA6A4894F7D317F8ULL,
			0xB1687FC4D75B14FAULL,
			0x0087CCF0D87AF1CCULL,
			0x64747330D76D6D36ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE2B8290BDACDEBECULL,
			0x5C0CE3C425E93D45ULL,
			0xB5983DE21314D07CULL,
			0x6FAB8AEABEA4F82AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3A714FB266E0F86ULL,
			0xA4F26AB078A966D9ULL,
			0x004B9B608CB1A1DEULL,
			0x22AFDF4344F16FEEULL
		}
	};
	printf("Test Case 35\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x67C6126FBBAF5948ULL,
			0xC8F5373F2CA7C228ULL,
			0x8C35D8F3DFACC012ULL,
			0x7797A8A34170F8CCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x21860181137DC4E5ULL,
			0xBC8EB55B3FA1EA6BULL,
			0x717E59FEBFA5B8FDULL,
			0x2188284F04F7B28EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF35A0767E4C12ED8ULL,
			0x013F43958A3AF6C8ULL,
			0xB86AC30F4F0848B7ULL,
			0x64F674FBFFA7DA6CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4B4855B6A2F95038ULL,
			0x540139AB95DA6215ULL,
			0xFFE95D5DCAE777CDULL,
			0x55B8B7FB70803859ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFC015287ED99BB96ULL,
			0xBB34D76396708C11ULL,
			0x039398461500438BULL,
			0x5F4A025749870384ULL
		}
	};
	printf("Test Case 36\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDE0EF263B0377948ULL,
			0x63F6BED671F437EEULL,
			0x434E47629365EF15ULL,
			0x46DE48224FD026A6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E683865FCC243FCULL,
			0xD5F8FC5784685FBBULL,
			0xA28BF0BFC5ECAB9AULL,
			0x7300520D5A26C2F1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDC942589B8F6B9A0ULL,
			0xE8817C3535FAE431ULL,
			0xEA9BD5B33E1F4263ULL,
			0x655D8947323866F2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2B3A58D92DEF22B1ULL,
			0x1E27DD40D519BDFCULL,
			0xCB540417067E6E9EULL,
			0x5A251AF00040812AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0B56C5320CB723ACULL,
			0xAAA457284A799B67ULL,
			0x28DF8748D344EC56ULL,
			0x46A76EB3F5883C83ULL
		}
	};
	printf("Test Case 37\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5155B54DC745EA00ULL,
			0x51E7FBB6391B9873ULL,
			0x351E228337656475ULL,
			0x79D707B5145720AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x60FC336D136AF0A7ULL,
			0x44DE47579FD54350ULL,
			0x889C31BB3BF8635BULL,
			0x791A65D5F8861CCFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x56F1462F8FA06EB8ULL,
			0x8E4709051143E1D1ULL,
			0x9CF3816336822335ULL,
			0x5BEEC989D6892795ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFDA1E5BF7C9D0DCCULL,
			0xA60C804E4EC76FD8ULL,
			0xAA6CEA8794D7F07FULL,
			0x1797FCF4D609FA5CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE976D2D2ECB8B877ULL,
			0x3CA24BC270C8424DULL,
			0xAAD48E7D3CAF149FULL,
			0x4A4A2D6AD15924E1ULL
		}
	};
	printf("Test Case 38\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8C4E6EDC9457EB40ULL,
			0x777F12C6E7D6EB9CULL,
			0xBAE9747E74A03ACEULL,
			0x67A175B965CCA352ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB5FFE6EACD9D1DE5ULL,
			0xF05328E3BEB44428ULL,
			0xCE7FF3A03D480DECULL,
			0x5CEC742622209E11ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9203EF56CAE1CB98ULL,
			0x4C59CB411D1DE17AULL,
			0xD3D004F8FC451A27ULL,
			0x45F5FC5C889F58F0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4BA85C5FD63A551CULL,
			0xD338AA9984695993ULL,
			0xB693BC14AB416878ULL,
			0x7DFBA4060A3DF3A1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x29D50E525A7D6E0EULL,
			0xB52E5B9341E837A3ULL,
			0x9FB7128B473E3B5FULL,
			0x29F20371F9A8E912ULL
		}
	};
	printf("Test Case 39\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA277FD4274F58380ULL,
			0x13F1E77B45EB883CULL,
			0xF05206AFD8596682ULL,
			0x7F41F8328DB419B0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDBB00B0E2ADB0663ULL,
			0x19745936976CFE6CULL,
			0x0D95E55D572D1148ULL,
			0x6FC2E081C2B689D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x95773A00B94F58B0ULL,
			0x9278E3F6751DFF91ULL,
			0x7A2BE4EEED3573B1ULL,
			0x547827342383FA98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8F69B53D9EF2675AULL,
			0x4EFE05B521BEB51EULL,
			0xC6EFCD7B81DFC7DBULL,
			0x79D9770C9166F668ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x339BC12E176B212FULL,
			0x18E602D724B667A2ULL,
			0xAA03F376E7CEEB22ULL,
			0x708AC5FA8D12ACCEULL
		}
	};
	printf("Test Case 40\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDAAB30D620B6A1C8ULL,
			0xEBC21D83552238B2ULL,
			0x251AF7DA38F43BE8ULL,
			0x52C1CF2278E5194DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3FE75D7A6A49423FULL,
			0xDB633B6EC35A6D71ULL,
			0xF797DC753804AA56ULL,
			0x0E2B56360F623272ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCB722951C99D0F70ULL,
			0x8419F1F94838EEDEULL,
			0x9CAF154CE0B2A848ULL,
			0x7E2E21582AA0F564ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2DD322B8FB3E8118ULL,
			0xEB6DA45F6D27C8D6ULL,
			0x0673127955592083ULL,
			0x040F7ECB862D6E9FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x43E7B34953B3AD63ULL,
			0x2BBEA5CAB7D66F16ULL,
			0x2ACCDC8058E165F2ULL,
			0x266C7A1DD068D1E2ULL
		}
	};
	printf("Test Case 41\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x423A1340032CE838ULL,
			0x9DEB1DBF63B4D9C0ULL,
			0x1D80E6BF6B050B14ULL,
			0x60EB12BFB0CC8B3BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C649B2A0B9F223EULL,
			0xC35B3C11DE457EA6ULL,
			0x61ED6EDBE720CB21ULL,
			0x77861342BE827EEEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE8E27C02ADF43248ULL,
			0xD2BCDCC9106B1784ULL,
			0x24E4D6082A2E3651ULL,
			0x563FF52EAA330975ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x46B24360B1434C50ULL,
			0x7B07FC9BF44DA094ULL,
			0x77F67AB410685058ULL,
			0x08ABF8409D7368D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x77069908109E45A1ULL,
			0x55835C3D753ED054ULL,
			0x7DBAD22EA1643814ULL,
			0x4E0CDC04F374477EULL
		}
	};
	printf("Test Case 42\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEBE87D60DFD30750ULL,
			0x84FF377DC4DFDAD6ULL,
			0x250E44C518DD9E04ULL,
			0x47C19DB515E58CB8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x456088A39E8DE5D4ULL,
			0x06A9919292507C95ULL,
			0x672EA836B50EA726ULL,
			0x18759909BE1E2915ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC2EF677A216FFC48ULL,
			0x65D855A44145CDD3ULL,
			0xB588ED06D4E18D5DULL,
			0x710965DE1CA2F237ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B93FB68307B8A4EULL,
			0xECDEE5408F548C37ULL,
			0xFC782B83D9455493ULL,
			0x5B42763971CC0EA1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x77900F166664657BULL,
			0xA01B1D6239AFB410ULL,
			0xF3003B587A09CE26ULL,
			0x7B98879255DEDC23ULL
		}
	};
	printf("Test Case 43\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x560F09DDE9BEBD28ULL,
			0x6FD0D250626C3206ULL,
			0x61E6B4FC29CDCC69ULL,
			0x4057E22C660AFC2CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x06B89AC3A96A2F20ULL,
			0x8CA0FEC8ED0CA75DULL,
			0x494AF1B65710E334ULL,
			0x1784858E36094322ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB615D12C03BFB250ULL,
			0x70266BC899D04381ULL,
			0x0BD943326662D0D8ULL,
			0x4027C4872D8FA950ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x35550720A5E523A8ULL,
			0x30F7F9932CDA53E4ULL,
			0xD8222CCEAFEB3D56ULL,
			0x71BA39CC66B2F659ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x82AB508AD0580133ULL,
			0x051A4EF002013B3AULL,
			0xCCDDCA5AA178D30AULL,
			0x4DAA2164AE453F61ULL
		}
	};
	printf("Test Case 44\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0D7A6B558F22DA78ULL,
			0xD729571B2F753465ULL,
			0xB1AC767CBA26CE66ULL,
			0x52489529BA778D79ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7ABF3A6C4BB0D789ULL,
			0xBC650EE1F7AF9ACEULL,
			0x697F418F7B2F5C11ULL,
			0x2FF38AE7A62C4C10ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7CB024400C7D4B58ULL,
			0x0E003B48F0DCED98ULL,
			0x97A2BFA7C1630DC1ULL,
			0x7EB85C15E09DCF04ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA19E32808A070F0BULL,
			0xF58E6A5B623517F4ULL,
			0xD7A2699729E6CBF7ULL,
			0x397A22EA4B4FAED0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x627276EBA0EC8897ULL,
			0x7D4C27B9DF7D4AC9ULL,
			0x6E187840E82538D2ULL,
			0x60D1626A348B100EULL
		}
	};
	printf("Test Case 45\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE9D0D40AA4233810ULL,
			0xB8B7BC2A8C525C6BULL,
			0x955792F9A8F428B3ULL,
			0x5D72471C7D6416B8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x83A095716360447AULL,
			0x22E0BA7EC9D085D9ULL,
			0xB7D02A0F98C756C3ULL,
			0x0DE2A72AE7300351ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01D310760820FAD0ULL,
			0xC6F47E98DCED9D2FULL,
			0x86CB5B3DC04FA428ULL,
			0x7B909D1B0D37949FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEBC30B8B3DE3DBEBULL,
			0x6E635576D29B1C0EULL,
			0xE4B50BC8D060EE1FULL,
			0x31E29E9433605291ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD3F17337CE538B09ULL,
			0x2EB6CCA015106666ULL,
			0x0930AA5C33680437ULL,
			0x35E5B1152854EBEDULL
		}
	};
	printf("Test Case 46\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x87BFA49EF6F44218ULL,
			0x7597B31F61CBCA9EULL,
			0x5005EF2B319CF45DULL,
			0x744D69F45C4B6B69ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09D78A17264F51CEULL,
			0x3CD2FF0B82551C40ULL,
			0xBD5B51C6EFB34D7EULL,
			0x7BBB857270EE7394ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x216EB3AE4750CD38ULL,
			0x621AFD4FC903B7E1ULL,
			0x6A7858D7A83AD14DULL,
			0x4DDD4D888647BAD7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42F1A4F0D241EDBDULL,
			0x1607D0DB92ED8DDCULL,
			0x51C023CF9C003F9EULL,
			0x2193E8AD404B2C73ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0736096726CD63A1ULL,
			0xEA3FBFF282E8DA24ULL,
			0x049DC9DC13AB565BULL,
			0x797F759DD19FCADEULL
		}
	};
	printf("Test Case 47\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEEB470DB6BA05010ULL,
			0x30BF4DE880BD9E31ULL,
			0x93321D6B8E12723CULL,
			0x564773263B5BBB17ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x382BC8B8718446EFULL,
			0xA458D7D5091951B7ULL,
			0x4B4E7B6C26D2AA45ULL,
			0x3D3B232AC0C3065CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB4E5B7038EF80498ULL,
			0x15CF090F41545513ULL,
			0x8A31211E582AE00DULL,
			0x4CE38AF70EEE7AAFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x09C95B34E3E62C9EULL,
			0x60CA110B8F739A1BULL,
			0x13473E37CD21C046ULL,
			0x6114AE48176CC49DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7DE17C4B9D5F5F0DULL,
			0x6F67A2095569BC89ULL,
			0xC5845FCE7A643F79ULL,
			0x5D23EF8468BA6C7EULL
		}
	};
	printf("Test Case 48\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4AD55F803DBF3D40ULL,
			0xB91D7AA86AB30AA5ULL,
			0xAA3E1F6A552E3150ULL,
			0x61DD053740EFFE0EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x959E3F1E858568D7ULL,
			0x0E801CECB9136A05ULL,
			0x4A2C4F3BFF6E9DA6ULL,
			0x48CA635F0D313E86ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x25E0CB3B919558F8ULL,
			0xEA3D551FDCA4590EULL,
			0xA4F45377E6B7543FULL,
			0x485D611BA51E5914ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x111A40EBA50BFB2EULL,
			0xB0AA4F0D2B0B43B7ULL,
			0x9D3471EC2EC3A1A5ULL,
			0x72FAA0CD72C4BD2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x738E1AE964AEC12EULL,
			0xF5E83DA02F29E643ULL,
			0xAC4907CE468060BDULL,
			0x3FDEADBF7516AA6EULL
		}
	};
	printf("Test Case 49\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x131568C144F98FB8ULL,
			0xF7C2E9DD42C01E7AULL,
			0x87C5DCDF3E3E41CCULL,
			0x6EA8F60FC187E475ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8CE55CC8B52BF16DULL,
			0xBFACAD8D4F6F1632ULL,
			0xBBA281670F25E994ULL,
			0x36A89BA181855D2DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x62F0C5C7B36BB550ULL,
			0x4B789276AEFC53B0ULL,
			0x26F9ED2ACB95C30BULL,
			0x6D05A6F8C7899634ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x88423C150BB9CD5AULL,
			0xF64BFE128A8D2CDFULL,
			0x91EF8199A873A7B4ULL,
			0x1BD67A4354EB5661ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC80CAC0C0755B618ULL,
			0x41EF28585AD29404ULL,
			0x3C7D2073DA0FDE54ULL,
			0x69E14C170B94173CULL
		}
	};
	printf("Test Case 50\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3FFBBD3DC7D8CCB8ULL,
			0xB0AE999F487407AEULL,
			0xA8D0970C4B9C8007ULL,
			0x44E5194B594A658EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFB339F7FEF06C8C0ULL,
			0xBF98C0EDDD4277FEULL,
			0xDFBE64024BACE4CDULL,
			0x6352CCEA82273A8BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE95482EB11F87620ULL,
			0x025E0AE88E7E76F1ULL,
			0x67AF45FB911A6E95ULL,
			0x44A6FE519EA9A2F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB12B172B56BB1BF8ULL,
			0x65D38084FD23E7BCULL,
			0x38005CFA5174E036ULL,
			0x6A91B9CC2A40E578ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x37103AFAD5BEA588ULL,
			0x4BE4277748FE761DULL,
			0x71BC33034F215D34ULL,
			0x43EEC2057BE04F23ULL
		}
	};
	printf("Test Case 51\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D519C6FAE4FACC0ULL,
			0x1A0BB09F8E350907ULL,
			0x68DCAD2F57C3D3D6ULL,
			0x5357395022B7BDEFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF63A5935CED84BBAULL,
			0x0CFA75AB3DFCF516ULL,
			0xFD9E66DAE769EFF2ULL,
			0x5F50A1D89912B762ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7872C4EF73C3E2A8ULL,
			0x60D00DE288D3BF5BULL,
			0x66CB2AF724D63BD0ULL,
			0x7CF57A85AC1B0139ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x144FD4A01E600911ULL,
			0x5BE4A383C3053530ULL,
			0xE722DEAE299CE195ULL,
			0x21467BAFA853A25EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7B2624BCB274AEFDULL,
			0x1979262C1BAD44C0ULL,
			0x2EA022BF6116754CULL,
			0x3A11B9FED0C41965ULL
		}
	};
	printf("Test Case 52\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x740A0ECB26EAE2C0ULL,
			0xA813C26BE93118C0ULL,
			0xB4A8AFFC942EC5B8ULL,
			0x68850CF24145CE80ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC0ACD611D90F2DFEULL,
			0x7A11B64D898161D1ULL,
			0x97501F3096150D3FULL,
			0x04E7DDBFB1B06A56ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD9C6A89031B887F8ULL,
			0x0DCDA3980F4F3BC5ULL,
			0x94E21DCFC45B0020ULL,
			0x40F6F4CBA44B7C51ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDB0D45E7407D3AC1ULL,
			0x1EF1A614B2EA9CA1ULL,
			0x979B214AF66028DFULL,
			0x094E8A429D1D43CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCEA4C0CB3AD02109ULL,
			0xEA5189D6A4138532ULL,
			0x50EF5E0989868FCDULL,
			0x2D0A3F931E5B53B5ULL
		}
	};
	printf("Test Case 53\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x149BD44BE9F55C70ULL,
			0x81AA1A2B7025A19CULL,
			0xB92C6C2C5D69F45EULL,
			0x6644053A65011B65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD5BEEE0FCC476E5DULL,
			0x4CAAE7B00543C8B1ULL,
			0x0426B3E34F0A8AA9ULL,
			0x7FABFFD905A8D654ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC51E65AF95A85478ULL,
			0x092D69C4339C535CULL,
			0x0F2F6C83AC7E3FFFULL,
			0x56792210085519D8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA3E6F94042516C49ULL,
			0x8828BCC3E1B6B767ULL,
			0x61C1E7B0735B2F6DULL,
			0x1ACDD8541774E0BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x34CF594EFE56EDDBULL,
			0xE0DC0E333B6DC162ULL,
			0x03BF680DDA15E486ULL,
			0x7EFD2FF0098457B8ULL
		}
	};
	printf("Test Case 54\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCBB68DE0D087ECA0ULL,
			0xABA61A1CF777EEA9ULL,
			0xD46CD4E9A06A2D55ULL,
			0x7A124B29814FC2FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x79AD1921266BA72AULL,
			0x0BC8D8693D92F900ULL,
			0x79AB54EFA87631AAULL,
			0x5A0DB7B0F174284CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8214C5AA486A53D0ULL,
			0x989D7654BC3ED983ULL,
			0xE094B6A35284AE01ULL,
			0x5B363D9FB6E0BC84ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x837924A70677ABA9ULL,
			0xB3C5ED6036E3549CULL,
			0xC38E3DFDE6EECACCULL,
			0x41695E27168D6557ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2B0908DC3B96A3AEULL,
			0xD84E1FA2A45FA42DULL,
			0x7EDDD35DEEA97EFCULL,
			0x79C3FF6A4DFDACA7ULL
		}
	};
	printf("Test Case 55\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC0B6EC35340CDCF0ULL,
			0x5BA0437A151F292FULL,
			0x75F2136A22722A7BULL,
			0x6790BE2B0198A162ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3D3A8870DC8A7F0CULL,
			0x384A6DA6F5C48589ULL,
			0xD4964C04C8B4C2DBULL,
			0x451F6B45011D891BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8CEDD79FF5A17328ULL,
			0x8E7623707F8E4FB2ULL,
			0x73A925EB6E0C9133ULL,
			0x66A81DB340209D42ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8A016D828DD63A5BULL,
			0xFD6BE9C00B0CF87AULL,
			0xD528FA0B3356BC79ULL,
			0x43FC5506DC4A2A71ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x233DC096AAE07E81ULL,
			0x255FB832F710DBD3ULL,
			0x5DF29ECFBB47BFE6ULL,
			0x29EA83C92ED499F1ULL
		}
	};
	printf("Test Case 56\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9717F6D8B3630818ULL,
			0xFF5DEA3C50D17894ULL,
			0xD867F1B8191C0657ULL,
			0x5FF3EC49DEB56D2AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDC8EDFC1456F4813ULL,
			0xE00B774B63A5DDAAULL,
			0x883FDF1E6F0B7430ULL,
			0x507F8078B58CEABCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2BF48D09E13E9348ULL,
			0x16F5EB8DBEDFA836ULL,
			0xD32412FA2DE9E85CULL,
			0x7A8A14A658766DD0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0614B007212646CAULL,
			0xC29CE3D271A451CFULL,
			0x5895CD47582A08A3ULL,
			0x2F4C14374345CB74ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF20447918B7AE98BULL,
			0x7532BB8F492850F3ULL,
			0xD7A2F3FD2994AA7AULL,
			0x20B62D61DE902325ULL
		}
	};
	printf("Test Case 57\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0CF5819710176A60ULL,
			0xD6539F605D17803FULL,
			0x6B0713FA05F3F16DULL,
			0x60789685F4E7D41CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4EE1A2CCB9432514ULL,
			0x8CFEE31B9FF2F7C7ULL,
			0xB958A145F7D0BFE5ULL,
			0x0CB43745EF0E77F0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x33A69553C576FD00ULL,
			0x9347ED7D3E82A0DBULL,
			0xC1BE53224390ACC6ULL,
			0x6E0B6EEF6436BA82ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x62FB90CD698EE422ULL,
			0x715B6EC393BF5989ULL,
			0x2F43A05C157854C3ULL,
			0x119F09F663D0E401ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x565B9E25D9CC4A37ULL,
			0x530FD3B94625EBBEULL,
			0x110E04CA9B7F6E5EULL,
			0x12726FB8065AB425ULL
		}
	};
	printf("Test Case 58\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF27D8219D57F9A60ULL,
			0xB5B37D6C1A6880D9ULL,
			0x030F2D6E9ED60CFBULL,
			0x67BC1988B66A83C3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1BD8B8D82D7A5C8CULL,
			0xECC51CC8C6698925ULL,
			0x2251584671F6B216ULL,
			0x64E839EFB4072A68ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA33B5683D795D18ULL,
			0x589CDBD53D7D4000ULL,
			0xE5E02098F7F418F2ULL,
			0x631DC3622143D353ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4DE77F0E9CE4AC11ULL,
			0x3DAFB23C8F04F61EULL,
			0x6C5EB7947BA2734FULL,
			0x6AA03B3EF2BF1074ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6980F4285887DA8CULL,
			0x9DEEAF5E8B3A438AULL,
			0xE3F64A93578828EDULL,
			0x12ADB5651863B7F8ULL
		}
	};
	printf("Test Case 59\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6508E57F4FF08750ULL,
			0x42C4C4CC3E0FB6F3ULL,
			0x16AA1290540E367DULL,
			0x609C0FC12B17B157ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x24CC0AE1CBA764CDULL,
			0xC16A42F641538C44ULL,
			0x149494D04E5E3CEDULL,
			0x76596CB3E719E1FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7C1F592DE47484C0ULL,
			0x2D62157170983F42ULL,
			0x9758BE1586E104FFULL,
			0x610D1A0A0E1EC368ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD4D12DACC2683CDFULL,
			0x4AC64ADF5391BBA3ULL,
			0x6EECA7932F28E421ULL,
			0x1B33903DC5623465ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x842B28C1B03E5015ULL,
			0x07B661AC354A9A3DULL,
			0x6D90401681315AAAULL,
			0x7246AE96FC68E937ULL
		}
	};
	printf("Test Case 60\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x29629F8D91C15CB0ULL,
			0xABDABA42447D1AE0ULL,
			0x006A8E17E78AF610ULL,
			0x7388EC8CB58F01E4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD6114D3CAB7C6A1EULL,
			0xD6C57179FFBEF4CCULL,
			0xA1AB6429EA13793EULL,
			0x084112D398E2DC7DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F0A0B45E30FB5B8ULL,
			0xDC1B78A7324EC2A9ULL,
			0x775840981E7D1513ULL,
			0x7172D2B36AD0E274ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC9F596B4E8B73BC7ULL,
			0xF06A0A19C7BBD31EULL,
			0xAF3183F645BF542BULL,
			0x72A56CC65CF74AC2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2DBEC4B647A2CE9DULL,
			0xC6D50B868E56FE3AULL,
			0x26D0A533383740E7ULL,
			0x1CDCCF3C38113415ULL
		}
	};
	printf("Test Case 61\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x39F427DAEBE58268ULL,
			0x6C8047467D08539EULL,
			0x9C246BEDE25554DFULL,
			0x73682C9C15114005ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAA314E29BB249D96ULL,
			0xE6C907AC819DDD54ULL,
			0xF3C556EAD0302DF5ULL,
			0x38CB0E05812D1663ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB5399EE3C7CB0F0ULL,
			0x62A4FF0EC098DBE1ULL,
			0xE285D049529B477FULL,
			0x57BC0CDECD64CEDCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF239C674ADFA281ULL,
			0xC38E1D44B163D8D7ULL,
			0x458E18AF75CD13B5ULL,
			0x6F0377820EA516BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC2ACB1DE365511A5ULL,
			0x46EC3291F83CF2FDULL,
			0x61EAB927F570162FULL,
			0x7CDC5325B2200A9BULL
		}
	};
	printf("Test Case 62\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x210752880F93A7E8ULL,
			0xAD0552903A61D4A1ULL,
			0x8F28BAA13A369BFEULL,
			0x40FBBA4603441B36ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE5EC0413BD10BE2DULL,
			0x9C6A6FF513CA84E6ULL,
			0x539CA0DA9282EDFEULL,
			0x60BCB0373E5C51BCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE302A41F6BA75B50ULL,
			0xF457E2A7F3B8096FULL,
			0xBDF22B967E4B6759ULL,
			0x4B78EEDE23DFDC27ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC58F5E29F7C82543ULL,
			0x14F8B6D188E5BD95ULL,
			0x6144DAEA280BB758ULL,
			0x74F2761213796FE2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEC353105A95F951EULL,
			0xF1AC22C3C53BAC1CULL,
			0x3BB406389F5F47D6ULL,
			0x5B0C013B616FC41EULL
		}
	};
	printf("Test Case 63\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x858792A3A865AEB0ULL,
			0xA41026000DB4C305ULL,
			0xF25E7BDF2780BCF8ULL,
			0x461AC9138A9C3B7BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF5743FF15D412ADULL,
			0xD62FECC82031203FULL,
			0x53F5DC9DD73F3511ULL,
			0x08172912770E4EF0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5D610FB56CBE5390ULL,
			0xA3FEB7A7994EAD8BULL,
			0x3D627CB6090D2A85ULL,
			0x7A52DCCC5B8E986BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEB084B15A7831608ULL,
			0xA046F117EAE6890BULL,
			0xADF96F562AABA7EAULL,
			0x200FC926F1AE19F2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFDC6F85EE6D5737FULL,
			0x4689E7944233290EULL,
			0xE51A964654834955ULL,
			0x543D3BD9333972BDULL
		}
	};
	printf("Test Case 64\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF93EEC9749F617D8ULL,
			0x9EB1D62AAA8F2643ULL,
			0x72817F19B9978D95ULL,
			0x44D77EDA55F158B3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x26DDE873FE37A828ULL,
			0x5C772D63471C7E3EULL,
			0x385FBE1C55249D7EULL,
			0x4E4D5F066F3DDA70ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E77E322C7B8D490ULL,
			0xF9F73FA288367BD3ULL,
			0x4DF38B75B1DEE950ULL,
			0x5ADBF15FFBAB07C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x705922BF1D4ED1DDULL,
			0x82EBD6F7516ECF9DULL,
			0xBBC981EFBB4ED221ULL,
			0x2A0BE12831744E60ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x58860C1A1B92B9A5ULL,
			0x9352988F08FBA6E0ULL,
			0xD29FB4CD9896C975ULL,
			0x371E4BC0402CDB5BULL
		}
	};
	printf("Test Case 65\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2C5ED5836C16F1D8ULL,
			0x4E47066C9D85EBBAULL,
			0x46D22468994A48DCULL,
			0x6B454470279354F2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEB37988BCCD0EF5FULL,
			0x0697735FDC3E7C6BULL,
			0xEC24014A9A4B4D58ULL,
			0x1F5A571474E59FA3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB91480D0EA8A4210ULL,
			0x1007693DCD6721FCULL,
			0x8D59F0213CAF55C1ULL,
			0x459E5F0883358D12ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x25F8183552CFB063ULL,
			0x29BD5E736C1372B0ULL,
			0x30989BA3C372E020ULL,
			0x7C91D7E1ABDDACFEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF0F1205C235695E0ULL,
			0x2E64A7D5C6CEBFABULL,
			0xFD1B8922F237C510ULL,
			0x219E32E9385AA4B6ULL
		}
	};
	printf("Test Case 66\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB1EBC3EECF475A08ULL,
			0xE98A4EC967AA5E4CULL,
			0x6C884EAE9FAF2F4FULL,
			0x520BE582DC08CB29ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x87C11DAFEFD8E144ULL,
			0x68CFD9C15D0256ABULL,
			0x4EBD3512B6CF97C4ULL,
			0x1EB9BFB6F8C20F4EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC1BD7F098A4BC708ULL,
			0x8B5B9B70E8CCB0BBULL,
			0xAD792547DD942BCEULL,
			0x41F5E136471DC010ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5A90084CD1C0F79EULL,
			0x759306651D22D524ULL,
			0x874DB69121943ED4ULL,
			0x66D001E95192CE79ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9DE8B3895BA61420ULL,
			0x9B5E6BEA70E402B9ULL,
			0xEAD922BA7E25D91AULL,
			0x390FE23DF332D05DULL
		}
	};
	printf("Test Case 67\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2116D9891EC6DFF0ULL,
			0x6F2E572EBD216E5AULL,
			0x36EF7DBCD8FF7725ULL,
			0x6CA8E949B62EF07EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB1DB4A978A027DD1ULL,
			0x4AF2230459A794A7ULL,
			0x1405A04943830D34ULL,
			0x3B55CC56CA87D1FBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFD77578626F972A0ULL,
			0x2F1FB5530582AB03ULL,
			0x764FE1CD34D42FF1ULL,
			0x4A475BA92D85F7E1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD874AD706C770EB0ULL,
			0xF22295EA2BB1C8F6ULL,
			0x6325B49E5354EA71ULL,
			0x1D515254483D6536ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x68F9AA3DB2FEBD22ULL,
			0x7DFC324375785C3EULL,
			0xFBBC96BEAA2065DDULL,
			0x5FDECA94C71AD8C0ULL
		}
	};
	printf("Test Case 68\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x47855E47C4F4FDD0ULL,
			0xD8F1497391A186CDULL,
			0x95F2B8AD6F953150ULL,
			0x5176237B1E2975AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B54C2BF2ABDFF75ULL,
			0x4AEFA8B2323CE290ULL,
			0xD4997FFB606E4C98ULL,
			0x08741CACEB898D36ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF21AEF3B8D49CBA0ULL,
			0xD2FC4652F431BA91ULL,
			0x7D76DBC843E256EDULL,
			0x7167C2B5A116A1B1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDBD4D2B44927E626ULL,
			0x031DB2CD7EFC1EBBULL,
			0x2F80CB121BFD8040ULL,
			0x1C597C0ECA9AF605ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9DEEE27C64CF5852ULL,
			0x2E0D9BA6B5FB749DULL,
			0xFE5E12B3B8C19B98ULL,
			0x32381889DA8582D3ULL
		}
	};
	printf("Test Case 69\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4038D7552140E7F8ULL,
			0x40A18FD95ECB5ECDULL,
			0x6B2FBD2296CFB13BULL,
			0x444DF8EAB346F48FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x836076D3B71BFC54ULL,
			0xF13A52EA028E4914ULL,
			0xDEE60D4A880B0C02ULL,
			0x181E9B114FE556A0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF76B457C60988A58ULL,
			0xEC795F76F02F6ABEULL,
			0x999F4F46F0FE94CFULL,
			0x76DDAA1DF4C3F6BEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9CAD52A7267213F5ULL,
			0x4DEAF6DFFB8AF76FULL,
			0xB76367A6903AED33ULL,
			0x33705B37588C248EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x23C126468B660C72ULL,
			0x4C0C136F35A6C3E0ULL,
			0x75CE47A8A53FFD13ULL,
			0x5A01EDE80993A8E0ULL
		}
	};
	printf("Test Case 70\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA03DC720EF0308C8ULL,
			0x36704218EF9C2B29ULL,
			0x66403E1B674BC400ULL,
			0x6601D417F38C4CF3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x117DE01F26B8C467ULL,
			0x63FBC802DE67D4D5ULL,
			0x4C4E6BD0B3AE67BCULL,
			0x3A1A2A128368DBC2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x40B94942C7EC9E68ULL,
			0xE1371657CFFD61DAULL,
			0x4D037F189CB7041FULL,
			0x76D52485A66E5093ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2C03CD0230600185ULL,
			0x1F804471F287036DULL,
			0xD163AE0209843F43ULL,
			0x3C0FDE39EA09C4D2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB95E2C12B70030A3ULL,
			0x8405CC97584FB932ULL,
			0x91A47183D06FE491ULL,
			0x4CC6196F11FE0DCBULL
		}
	};
	printf("Test Case 71\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x387DFE6DD57071B8ULL,
			0xBAB53B5F6867B963ULL,
			0x710AA6F0E9053767ULL,
			0x68AC1EA6CAAAC2B4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8C663232C7759F20ULL,
			0x6AEB0CE36FD2369BULL,
			0x43099223D1860F17ULL,
			0x55C7F8F0AF2E70D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x70BB4F885E673128ULL,
			0xD6AB873966FF7C3CULL,
			0x43C353446CC3EB9EULL,
			0x4E304270E021C7D7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0D1FBD62CF75C82FULL,
			0xC5651D4C7CFC5495ULL,
			0x8B6EF93E2D6C48CFULL,
			0x3425FBE222864E00ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E762116BA321FE8ULL,
			0xC71B08C681AFB9AAULL,
			0xC2DFC66FB89D08F8ULL,
			0x22D573A3A778306CULL
		}
	};
	printf("Test Case 72\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE6DD901628514398ULL,
			0x9A9571FB85AACB1EULL,
			0xF3343C461782FAD7ULL,
			0x55E51DED2918133CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x86A8095E7EF42721ULL,
			0x10F200B2A2BB8062ULL,
			0xD1B8AE628DD3B6E8ULL,
			0x6ED4F00366494EABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x19467916B46B4AC0ULL,
			0x855F8BDAD5418D74ULL,
			0xE5A880E78ECC13FDULL,
			0x6E8961FE1959C694ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFF9BBBAD28BEE23ULL,
			0x8A9CF7BB749F9B17ULL,
			0x244F7A2E9788E3CCULL,
			0x6FA0F4CCB433352FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0C23C89E53DE31CAULL,
			0xBAECDDC0E18650C1ULL,
			0x8720888289EDAF70ULL,
			0x6509CA73FFF7E643ULL
		}
	};
	printf("Test Case 73\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB15FA9BFA411CC58ULL,
			0x6B9239F4F74F0EADULL,
			0x37B3946EB678769DULL,
			0x73248B30F3522941ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4264D7729F3AB3A0ULL,
			0x9A28AF6A5BB8E5E4ULL,
			0x5D15B6757913B18AULL,
			0x4AC046253BE55108ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x07ACB6A654D1EFC0ULL,
			0xF4859796CF457878ULL,
			0x041D97558C55425EULL,
			0x7087FBF440C4DF07ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x32644926A721E3E7ULL,
			0xDC72BC7E4DC37C1EULL,
			0xB4444133E5FE0574ULL,
			0x3D1B245425228047ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE5AE66DE322DD9A2ULL,
			0x6A0E96BBDA3FF98DULL,
			0x8098B0DBE2CCC217ULL,
			0x15579892E84E8206ULL
		}
	};
	printf("Test Case 74\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8EF7E14F9DB10B0ULL,
			0x9E0378FD4AA007A9ULL,
			0x8554AFAB8C3F36A5ULL,
			0x7CD23332B7F0366BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x343A450BFD969FD0ULL,
			0xCFD544FB3F24FED2ULL,
			0xDA2F944DF2B01BB6ULL,
			0x3FEC65B45FB6EA5FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAC6B7C3E5061CB88ULL,
			0xFD84E2E3A16CF811ULL,
			0x240474B99407CF05ULL,
			0x43712DF9CA14F70EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x50630759654207B0ULL,
			0xBD1F34656A5F1046ULL,
			0x5C29BD2361EC87F7ULL,
			0x62C0DD329B6BB36AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x368A9619B18B8E05ULL,
			0xB2BD462EDE69D552ULL,
			0xC1AE48AAEC4E3211ULL,
			0x10CEDEC80EE48DBFULL
		}
	};
	printf("Test Case 75\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7844B7D84F408120ULL,
			0x25C3F0481A7983A4ULL,
			0xD43BE2B213709FAAULL,
			0x5AB34428B55008B8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD26E44D88C32C41DULL,
			0x9B47A92107F47027ULL,
			0x98BC5F45942E6CD0ULL,
			0x59442131F1AD15ABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9390B18BDCC08EC8ULL,
			0x4BD872EEAFB248A9ULL,
			0x75040BF1B7B1081CULL,
			0x73A01390F1B9D288ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE7CBC391ABAE5605ULL,
			0x139108B7C17EFF9CULL,
			0x9619B3DF0F934E08ULL,
			0x5EB98EC67D3DAD76ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x57095A3F6C2911B0ULL,
			0xCC789C3B8D387B44ULL,
			0xDB2F3B74F951D46BULL,
			0x34BA21F8860C06AEULL
		}
	};
	printf("Test Case 76\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEFC3F5664E94BA88ULL,
			0xD59D99F04E948CB3ULL,
			0xA231F9E1CD3B0F65ULL,
			0x7C6F1D89A3C37088ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BB41BF16ECA4048ULL,
			0x48343EF79655CBDDULL,
			0x0144640239B82794ULL,
			0x0A19C4108BBF9F48ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x89E25E56AAB38B80ULL,
			0xD5DEB38EB3F0C387ULL,
			0x26364D9E7E866591ULL,
			0x40507FFC715EF0DCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6DA9A74E47B1579AULL,
			0x97ECA99187062E27ULL,
			0x916A94BC8ED96E8BULL,
			0x68F36A5965550A28ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x06A86A60AD4DC84BULL,
			0x1B408FAA2ADA9155ULL,
			0xDF31326A9B2C7B07ULL,
			0x1AE557384E58935AULL
		}
	};
	printf("Test Case 77\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x589C9383402663C0ULL,
			0x5ADB2D227FC6D574ULL,
			0xDFFF578E3F47F538ULL,
			0x514CC1D0EACEAFDFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1696F38C050DC54EULL,
			0xF5779DAD670EC275ULL,
			0xA8A5D542F1132677ULL,
			0x6B587DFD76448B4FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60A00AE35098C300ULL,
			0xD54E77B955C6C146ULL,
			0x6169EE60D117E0E7ULL,
			0x7078F6C6D5B1E1ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9A910C5B784579A5ULL,
			0x2002F1F7E175AC7EULL,
			0x19BDE6379B034124ULL,
			0x562741FFC9E55E46ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBA1F5530D10275AEULL,
			0x776A102E6BF8E6E1ULL,
			0x1FC37E66AD68EF90ULL,
			0x4EDECA3EAEAA02F7ULL
		}
	};
	printf("Test Case 78\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0098138DEE132208ULL,
			0xB3F7A416B5649A4BULL,
			0x87E5F07E0FF9C0BBULL,
			0x4C5EF71DFD515DA3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x27F948E2E9E45AE4ULL,
			0xDD49DD917CD1D8AAULL,
			0x6386372D560BE0A8ULL,
			0x2390A2F889F93873ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x50A548447F3A53D0ULL,
			0x3C0573015E4CA681ULL,
			0xCE4B8F703A4ED757ULL,
			0x575FFC81361CC884ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6798F730EACF70E2ULL,
			0x8B5085F3FDFE02F4ULL,
			0x5884206E5B62E3FBULL,
			0x2691C26E1184CD22ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA3E9C38A9CD4B57AULL,
			0xFD6A110FF34F0A6CULL,
			0x6148F01BDA2CB1CEULL,
			0x1A3BFDA052747359ULL
		}
	};
	printf("Test Case 79\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA1CC7B226F231DF8ULL,
			0xABDE5ACC1BE6BE69ULL,
			0x266DCEB3F054B8CFULL,
			0x57DBA0332CFE42C2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D74FF090688B55CULL,
			0x7691C46887A4AEB2ULL,
			0x0D1E9FA82EADB7BBULL,
			0x2C1927561ADB3073ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC489265CC5C04828ULL,
			0x96720C1B6014831BULL,
			0x3E3413CE4E0DC8ACULL,
			0x7B361D5D6169A386ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x613146AE9AEF94FCULL,
			0xC35A4C2F99FD889DULL,
			0x1DD0F68E4C6C8117ULL,
			0x4D9EC3286476841BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCEA3F401724D841AULL,
			0xBEE1205523B10AE0ULL,
			0xDFC444D3D0F68079ULL,
			0x192A4A1D59604B75ULL
		}
	};
	printf("Test Case 80\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E517ED4ED2A4D10ULL,
			0x87E8958C8AC0C0FDULL,
			0x3B738FB7587EDCA4ULL,
			0x41D4AD40B85CD6BEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6440BBC47E2C6E69ULL,
			0x1D64AF8938599400ULL,
			0xC8E1ECDB980DDE5EULL,
			0x3E5E89D89609B5F1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF3C02C94A7B286B0ULL,
			0x08AACD5E51B96D94ULL,
			0xCC717428CB7EAB28ULL,
			0x7ACD9248C3DC6941ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x01D9A9A4654AD6FFULL,
			0xC345D328CF57454EULL,
			0x1C2BCCBF37FE299EULL,
			0x018B2DB57B103800ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCC0FAD4D5180D9EEULL,
			0x9CB106F8ABE1080AULL,
			0x081E3ADF24BF702AULL,
			0x6D61E47C289F20E2ULL
		}
	};
	printf("Test Case 81\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD5E0491FADE16228ULL,
			0xBC41C2C0E4DD8694ULL,
			0x9BD9F344D172A2D3ULL,
			0x43A4AF3A6F627516ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x53D472D7F4F47901ULL,
			0x7847B1701FB45A32ULL,
			0x7A3730A32B3E1246ULL,
			0x16E2711531019267ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A59A06B54B74BC0ULL,
			0x672552EFFDBD3AACULL,
			0x08A1624D3B821F09ULL,
			0x552CF126D7BC4AB5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA246AE23A471C95FULL,
			0x4E4C65DBE0B75453ULL,
			0xADF483396A7F332AULL,
			0x1E1B0A8A3AD8A245ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBBB4348D34382FE9ULL,
			0x03D377D1E3F33AF8ULL,
			0x4D48A5F414657626ULL,
			0x430113E6F8786229ULL
		}
	};
	printf("Test Case 82\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5194F8EBEC1089B8ULL,
			0xEAF9C497F43BBCADULL,
			0x35F261C7BFFD375BULL,
			0x76CFD3183E7EB58CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x473BFB2933DA47F1ULL,
			0xA94B88CC62A47C72ULL,
			0xFF6BF6175C330EE1ULL,
			0x7BD5BFE6517DA508ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDC63FFCF797DA0D0ULL,
			0x93C2F8A08ED55F33ULL,
			0x97958AE8CDD7312AULL,
			0x6FB54DA1E4B14D4FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7728547E2F037A1FULL,
			0xDB84A1DD1BA701B5ULL,
			0xA05180C49EE98DFCULL,
			0x238E7EB6EF2D1A33ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5CB1CB42D6D83AD0ULL,
			0x604CE061778512C5ULL,
			0x6C653CA208001548ULL,
			0x6341A6673F8B6C50ULL
		}
	};
	printf("Test Case 83\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x230DA7A24B9E17F8ULL,
			0xBE82A9BA9EC74C75ULL,
			0xA061C9958EA1EC38ULL,
			0x6425FD2B565E5B32ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0D6332E19D015FC8ULL,
			0x3400EA28213226FBULL,
			0x508D396BE30A3129ULL,
			0x6B9884EDC7674924ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC3EE1CFB0FEB35E8ULL,
			0x288742D4D177F1C0ULL,
			0x819E30CA724118D1ULL,
			0x7DAD8F9D1A5117E1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5353B1368F04E20EULL,
			0x647A20180CF3CA74ULL,
			0xE2FA8EE23B3E41CEULL,
			0x0EEC31BFE1B75C19ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x50A3220E793021BBULL,
			0x3B1DCD76099691CDULL,
			0xB1603815B3FB92E5ULL,
			0x60D7F0EAEF47A55DULL
		}
	};
	printf("Test Case 84\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAAB27614A90829D8ULL,
			0x3B081D0C13E8BEDAULL,
			0xFB0472BF02075D78ULL,
			0x599A565024C6BBDCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x435F4996C15F44FCULL,
			0xB99AF62FA40CADA9ULL,
			0x65BCB16E23A46234ULL,
			0x29A07F18D2B7AB9FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x41DDB06D4EF669F8ULL,
			0xF33F7582D9E75075ULL,
			0x0A2D3A8EDB27D322ULL,
			0x617998F7CBB218C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x407446AAC97FE5C3ULL,
			0x09B050B28FAFA488ULL,
			0x2F660EC4704CB96AULL,
			0x5DCC3E5DBC798631ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2E787A6B92CBE1BAULL,
			0xDCD5718E94E0C832ULL,
			0xD7EEB8AB3E5CADD4ULL,
			0x3795FB6F847D5436ULL
		}
	};
	printf("Test Case 85\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCD029A3E1BF70110ULL,
			0x2A5FEBA4B36F0B1FULL,
			0xFC1BCBC8D79AA5C8ULL,
			0x6839A517297D6957ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8CF7C0F0969EBF07ULL,
			0xA1770CA42BB44716ULL,
			0x283AEA7D28C68588ULL,
			0x18FCEBC77A762219ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x98AB5CA44532AB40ULL,
			0xBB9005337E3119A5ULL,
			0xDF3FCE6F8E876163ULL,
			0x6BB32735E53A2962ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x569D89D25292CC10ULL,
			0x9F60EA08CFB683C9ULL,
			0x74E3A9A789DFD512ULL,
			0x132AC9D034BE8410ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABBE16A588F15A65ULL,
			0x5B928C1495108C80ULL,
			0xB91591F8C93FFAF0ULL,
			0x7EB765B19E92D85EULL
		}
	};
	printf("Test Case 86\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x118FF47AF659D350ULL,
			0xB263F4823996AEBAULL,
			0x82109519AC3802F5ULL,
			0x6CE7BEDC78D43AB9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE920FE0B7B8F08FEULL,
			0xC2594C53F1859BE1ULL,
			0x2FBA1EE870D3A26FULL,
			0x6799E4D712A281A5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A7C998FFE20FE98ULL,
			0xFA08D6D5C085B38BULL,
			0x3CA1CE8650BD5B68ULL,
			0x5A93A7FECDE504D3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA5A3F7E6B5F5BEA4ULL,
			0x780950E3C0F374E2ULL,
			0x033E9C565B8F2301ULL,
			0x3C2FEE12AB0FA4FDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61403780AC510536ULL,
			0xE5CA4DD6A24257DBULL,
			0xB18D6169F0FFA54CULL,
			0x529F5831B88D4C30ULL
		}
	};
	printf("Test Case 87\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9107998EDA529188ULL,
			0x78CD18EB7C76C6F6ULL,
			0xA30814AF97E1E3A2ULL,
			0x4D122600AF7EC66FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xACA297309745CBDFULL,
			0x8FAAAD29F70118BDULL,
			0xC8043B8C8ECAD041ULL,
			0x07FD18F496BF50D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC7433A962D23C328ULL,
			0xCD641BE4EE145FB4ULL,
			0xB499BF2F52848E49ULL,
			0x6F2A8483A425A671ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x38B5E2167884E0FBULL,
			0x9A4FB5A677B3AF8EULL,
			0x5E045D33CB8FA26EULL,
			0x033B5549BF0C6DCEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDF74F7722DF166FAULL,
			0xC13A194B27DBC28CULL,
			0x0223BA5C2F4A22E5ULL,
			0x057F41C932C64C62ULL
		}
	};
	printf("Test Case 88\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD741184A6B1BEED8ULL,
			0x7C062625CACFA630ULL,
			0xBFDED5FC0676F2A5ULL,
			0x4BCF6E55B6DB8810ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEDA68FC5CD30B862ULL,
			0xC1C8BD23FAD386C0ULL,
			0xC9DD68926246F2F2ULL,
			0x264C0060CBECF1C9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5752C6CD64DD50F8ULL,
			0xAB7DA1749876724FULL,
			0x886A8172671A99A8ULL,
			0x5398C1C58E97B9F2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x76CC38249C901222ULL,
			0x8BA36DB50641F590ULL,
			0xEE7859E67765DA88ULL,
			0x473DDCFA96D10BAFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3BCC32F6ACA985FEULL,
			0xF96FC253D5F49362ULL,
			0xDDCF60323A512580ULL,
			0x40B2D07FF47500B0ULL
		}
	};
	printf("Test Case 89\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB7DD7B2CC1AE5138ULL,
			0x4F01250E9C24D8BFULL,
			0x4179D98AD60A8ED7ULL,
			0x5CC9B0AB71FF65FEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x973C6B106423BE73ULL,
			0x810534E37ED2E158ULL,
			0x8D07E8CBEDA3DE34ULL,
			0x449C9A6CC16200F7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x22298B18D1594778ULL,
			0xE72464D23ADCA185ULL,
			0x0983F60A884EC83DULL,
			0x5D6A95C3C8AAB4C7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x264595FF8718ACC2ULL,
			0xE9DC693F7DA101B2ULL,
			0xF5514FA43FBDF778ULL,
			0x005ED9AF1C2ADFF7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEE4EC6D9610988E6ULL,
			0x2D0D7F2A8805AC6BULL,
			0x153780340B9CDC99ULL,
			0x337970C457AF922BULL
		}
	};
	printf("Test Case 90\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6FD940D5B2D09558ULL,
			0xD91BA0B1CF87079EULL,
			0xF82F2B3CDF163396ULL,
			0x7425EB8DBA9D4DB2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC91238C5CD79F590ULL,
			0x80638E8C721981ADULL,
			0xBE5D093D63D28092ULL,
			0x3F4D95385D33363CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA5CE133545D6B1A0ULL,
			0x03E674A9A07A65E7ULL,
			0xEF2A6C6E0E169749ULL,
			0x75CA8BF75B885EC7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x434400051CE0E8CEULL,
			0x84CB8B68471754E2ULL,
			0x530DDF7F702265CAULL,
			0x2D55F056AA83A8CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x119569E9E62B72E3ULL,
			0xA8ECFEE277265B79ULL,
			0x007C6BEE9511A660ULL,
			0x0B92E7F0919A6DEAULL
		}
	};
	printf("Test Case 91\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6660901CA59334D0ULL,
			0xC5ED3E2F06BAB3B1ULL,
			0xC772007120022C06ULL,
			0x52C4FE13F3F598C0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x30EB73CE281B596EULL,
			0x0A2F2F5098A3A6A3ULL,
			0xF006FF71DF5D2593ULL,
			0x7924326881D58782ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x37A6010EBB9619A0ULL,
			0xF0EFEB4A6D75F322ULL,
			0x6F23159E6936093DULL,
			0x532286A606F004ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFDDF4121369AD987ULL,
			0x7BF7B9A6C77AFD5CULL,
			0xE2688904F468E684ULL,
			0x30D65D2D484E4906ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF6FE94D3E40771C6ULL,
			0x25F4C2F070504D96ULL,
			0xD1537DE73B249B7AULL,
			0x5A6E1CB5E1B6325FULL
		}
	};
	printf("Test Case 92\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2F3391CEEE1A8900ULL,
			0xD4094941F137FBF5ULL,
			0xBF62E5D17FD8C1E7ULL,
			0x45FE6B3AABB7BC93ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFCF5576059039699ULL,
			0xAA37DF4928E03068ULL,
			0x71EF8DF4A3D44B16ULL,
			0x03F18AAD90C260B0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7B76CA7E515502E8ULL,
			0x66B567C39D24D20DULL,
			0xB54D40E75A3F780FULL,
			0x548720A59040BA57ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1D76B00A3A2052C3ULL,
			0x718EE1431EB37C7CULL,
			0x4771993DC548F6AAULL,
			0x5F23D6AD3F4B5BA2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9E1D9E56C12871A6ULL,
			0x46A0526E2E55CA2DULL,
			0xDB50B1624B71C1A4ULL,
			0x219AB8D7396BCE5CULL
		}
	};
	printf("Test Case 93\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x588DB2D3802BA228ULL,
			0xC0CF4563D521D924ULL,
			0xFD07AA0FFCB66005ULL,
			0x514615669D662CF4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4D92249732A00C4EULL,
			0x18887E70B79B7E13ULL,
			0x114492A66CDEC72EULL,
			0x09217191212E5036ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x44FFD7CD239101D0ULL,
			0x7490112E7846CA64ULL,
			0xF6DE767EA4905899ULL,
			0x47D83BE96FB8B609ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDE18AA14890F88C1ULL,
			0x07C1CE32F5682F6CULL,
			0x29DB14E1ADE6D404ULL,
			0x77D07B8EDFCA834FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF70F9BD7D67B5A8BULL,
			0xFF74D414BD9A9DC0ULL,
			0x1DC3EDEB2423D920ULL,
			0x352AB3168E51B4A4ULL
		}
	};
	printf("Test Case 94\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD4F3D59DF14E9F50ULL,
			0xC46D9AB88815AA95ULL,
			0x2025FBC6D3674712ULL,
			0x7FA462322361B689ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC69C431CA9609FF3ULL,
			0x1DD3E3CB6A253877ULL,
			0xD13224931FA6B378ULL,
			0x7F7CE73E375DB1CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2680382866044BB8ULL,
			0x46A2D7A832D17DFEULL,
			0x275CB3416706F565ULL,
			0x6CF0F5A2E67D0DEEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x05B6C475BDE02D78ULL,
			0xE474B57340DF643EULL,
			0xEE23CE9CC735A2E5ULL,
			0x12FA780517E11DF8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFE0108662C5B1A72ULL,
			0xE63BB4BB5587FD99ULL,
			0x9E024A2DAAAEBAB4ULL,
			0x3315930AA93B5A56ULL
		}
	};
	printf("Test Case 95\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCE01212FC9C82CC0ULL,
			0xE06B754605A4CAEEULL,
			0x7763DBB134DC0F89ULL,
			0x71D95B32642F5441ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8BF6153BEEDA24CULL,
			0x6421130552FD4F71ULL,
			0xA7BD10C381F93DA9ULL,
			0x46F7BBAD924A9C28ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x291232436336F380ULL,
			0x50AD279F84E045F3ULL,
			0xA23D41EA44087D6FULL,
			0x614B864A6B7490B0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB2AB591EFF71C374ULL,
			0xA016213D1436567BULL,
			0x86B92D994B08DFA9ULL,
			0x28CF9CC11C22F1FAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9D448CD72381E531ULL,
			0x5026ECF1B0F19DC1ULL,
			0x6211816B8C559A6CULL,
			0x250032DDA15DDE85ULL
		}
	};
	printf("Test Case 96\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x97D3CD930C838A90ULL,
			0x66457761C105C91FULL,
			0x1A7CCFA741C114A3ULL,
			0x6877959C7C8BAA86ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x539FF2BDA850B053ULL,
			0x1767331D200E999AULL,
			0x2D709F8C6947826DULL,
			0x5E715D383BBA42B7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x85C1B01E5FFF5B18ULL,
			0xEB480786B2708AA8ULL,
			0xC4075D8070A24150ULL,
			0x5C8F8F634FD9D119ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBEFA8D49A14D6B0EULL,
			0xDE87A0E8A5B862EAULL,
			0x324FB32184F0E869ULL,
			0x097D40F45E56BD2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD0E8ABE1385BAB9AULL,
			0x3ED9AD8D1A64630EULL,
			0xDE45CFFB63FCD601ULL,
			0x6DBDAF35C1D1DB05ULL
		}
	};
	printf("Test Case 97\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF7FD3A7D9867A298ULL,
			0xF53E7C71E3F4C6B1ULL,
			0xEFD3E615A1B68DD3ULL,
			0x66DB8BCC3A926404ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA6BBF955C9BF7633ULL,
			0x6868FCA7B726A7F8ULL,
			0x554BA32EE7EF2EACULL,
			0x2551AF14BF557846ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9B386F4D8976AE68ULL,
			0x88406741262DC7D0ULL,
			0xDCA3AABD66B39415ULL,
			0x6E2F9995818D194DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1786BDEE80ADB203ULL,
			0x9EC95EB995A1EFE2ULL,
			0x1F66EA908CF0394BULL,
			0x470F731B135F6E5AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9886A80695EA1325ULL,
			0xB6D68BAE7FCB44ADULL,
			0xB6A9906410238B69ULL,
			0x7827BCD46112F755ULL
		}
	};
	printf("Test Case 98\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9F6F635FAF356838ULL,
			0xE5C276D1D6E2F230ULL,
			0x7EBD1CC6402B0BAFULL,
			0x6FF59822E8A086DCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD01CE56D19427142ULL,
			0x69B2217857A7A0F1ULL,
			0x4FBC87332DFA0324ULL,
			0x33137F4AD7840F0DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFC8BC57D95D3C298ULL,
			0xFDDFA65721269A62ULL,
			0x16311A37A33395F7ULL,
			0x40FD79F4733631ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0B1FA5DC4C045A4BULL,
			0xD81404BEE72AE589ULL,
			0xBE7E777C59B02AE8ULL,
			0x4A229FBB80970D62ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1115A60A4C7106C5ULL,
			0x7C6597F7FB26D4A5ULL,
			0xB06154BDA1057728ULL,
			0x6CBDCE344B96053CULL
		}
	};
	printf("Test Case 99\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x46EBE3A0088EF0C0ULL,
			0x87F43D6D3409C8F1ULL,
			0xCDD4567BA51B3337ULL,
			0x7324F3124CEA83BEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x289D011AFEDA955FULL,
			0xAD85FCB954D165B4ULL,
			0xA640C9AB47022727ULL,
			0x55451E7D884EF183ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB7AC257E16E233B8ULL,
			0x0E3511C31D11B284ULL,
			0x26C496B14F5C167EULL,
			0x7732B68533FA419EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB6E5D4C81850320EULL,
			0x6BA89FEC77A9A9ECULL,
			0xA2D66665C153B8EDULL,
			0x67CA74C20422F646ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7BE37E52698B6EE4ULL,
			0x69CC1BF697BBBF7CULL,
			0x66E278CA775E6D68ULL,
			0x46C9B5723BAB498AULL
		}
	};
	printf("Test Case 100\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD39937A46DAEBFD8ULL,
			0xC22178EB3A3FF1ACULL,
			0x3589AA1411BEEB04ULL,
			0x6FC3E03765091DB2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x592F22DBDCECBC74ULL,
			0x5D5A1844BB11E861ULL,
			0xBED0039361F397CEULL,
			0x4BED9514EC71DAACULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4554C4B3DEC2C078ULL,
			0xB8D1128E36E4B24FULL,
			0xD8248A21283C796BULL,
			0x5AD4BBF639C096FFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x78EDB8F9F69168E3ULL,
			0x27EE4DEC8459BE6EULL,
			0x161859A443B13EF6ULL,
			0x2A9724BAB5CCDC7CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E8C4EE742EAE479ULL,
			0x9E8B5148F0048FCDULL,
			0xB00EE6DBE8D53B52ULL,
			0x54ACB3B65C88CB3AULL
		}
	};
	printf("Test Case 101\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE86419A65D0FBE80ULL,
			0xD62A71A496B0B917ULL,
			0x55BF98B77CE99680ULL,
			0x7C49D05CC21EEF63ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEEA893FB0BBB5528ULL,
			0xE1CA32027E43A2ABULL,
			0x40D50150B8982B3FULL,
			0x2A593D8E12506AC0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAE8A9C9230D1BEB8ULL,
			0x42FC7479FF685C8EULL,
			0x647FA346D2420523ULL,
			0x40E76106A1E27EC5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x659D5CB96FA2EF0DULL,
			0xC12F998858681B61ULL,
			0x3A53292F88E41C79ULL,
			0x21098E2974A1B225ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C6DC4E9314BF367ULL,
			0x4231EC2C61A17F80ULL,
			0x76B626A8BE844A3DULL,
			0x683AF84F5B4A9474ULL
		}
	};
	printf("Test Case 102\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFCCFC87FFB15D0E0ULL,
			0x11F7EEE822B6342FULL,
			0xB0BEC142FA69B5EDULL,
			0x7387D785220B8DE5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x59D1FF7A60D42D89ULL,
			0x8E099DFA84FAA95DULL,
			0x43FAE6DB902F7A8EULL,
			0x09FEEF633D1564ABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA9756B5E1D4D6868ULL,
			0xB628C1A3A1965F6FULL,
			0x222B3B9C38029D6EULL,
			0x5AD63902057F2291ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x97AC5C5CC2E3B106ULL,
			0xF9B86BCD76BF629DULL,
			0xFE74C3A3D9F3D8FCULL,
			0x37AC47B5DA716150ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCEB9C48927C677E3ULL,
			0x98E524674AF91CA9ULL,
			0x1140D5C8B6AFF53CULL,
			0x1B7265BCAF5CEBE6ULL
		}
	};
	printf("Test Case 103\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x436A34FDC0E61B70ULL,
			0x966E3C7AC81EBB2EULL,
			0xCAA73A3827A9A2ADULL,
			0x42AB94C0F099FCDFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C498790FBE1D740ULL,
			0x6E0EE9E3A722E18CULL,
			0x2D906234E7268E5BULL,
			0x48250936D5FEFF93ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1C0327EECB9D02A8ULL,
			0x285F726E74408AEFULL,
			0x5715BA282CFDB1A0ULL,
			0x7DCBA430AF461037ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x231D8F7E11FA81A3ULL,
			0xCB69DB42C2B724E0ULL,
			0x9E1945051B6F7EC7ULL,
			0x5197EB1A3B4174FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0E1D6F47E9D2DB12ULL,
			0x73955744F51D1720ULL,
			0x9CDBE29AC77A36AAULL,
			0x26AD4A727C9BDEBDULL
		}
	};
	printf("Test Case 104\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB3A98DE377B47680ULL,
			0x9A095CE1EA7BAAF0ULL,
			0x530E1EFE29053E8CULL,
			0x5D73C75C92830D47ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC6C51AD15A0171CULL,
			0xC34688C784942BA4ULL,
			0x2CDD3E4C1030AFF8ULL,
			0x6CB3BB8F8632BD1BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x27183F8844358378ULL,
			0xD4630039FB26C69AULL,
			0xE83021930F07ADFCULL,
			0x648D9948B0EA569DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14385D4F6E7E87B6ULL,
			0x73510AB91D91DE91ULL,
			0xBB2C3DEF9373C962ULL,
			0x4840326D7629ABB1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x85D25FD4B0D91745ULL,
			0xE4A3DC249E397651ULL,
			0x884A9196259EEE31ULL,
			0x3CB3CFE818DD745BULL
		}
	};
	printf("Test Case 105\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB22BFBB5B4CF3D10ULL,
			0x3EF7BF588AFFB6AFULL,
			0xF6D4D97FCF9224EFULL,
			0x622C5F48FE589042ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F7D94A35C03520FULL,
			0x4141A31D02064F7FULL,
			0x7D2DC0838AADBCEDULL,
			0x5287CFCF11222BD4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7E1E0BB725681388ULL,
			0xBAA1CA35822D9A33ULL,
			0x21A65D3D0F9B7904ULL,
			0x68EF756BF6756289ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCAFA8AA85084CF32ULL,
			0xB18A382D987F822CULL,
			0x8DBA6FA1F05780B3ULL,
			0x69646F919978E0EDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x900A15B24D368D11ULL,
			0xA132C2FF71F10BBEULL,
			0xDB4322CF4D54B8F9ULL,
			0x2FF3665211CDDA49ULL
		}
	};
	printf("Test Case 106\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2A34EB95EBBEF810ULL,
			0x9C26A4C856914DB1ULL,
			0x78203F43BD8D2CA2ULL,
			0x7C34EC9B64A2E9D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA0A325EE3FCC3D89ULL,
			0x9954950AA7062AE0ULL,
			0x36FA088D0887DBB5ULL,
			0x320264ED75BF50A9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A84F12E162F6F28ULL,
			0x8E0E155B88EE9234ULL,
			0x05E42A7D07A63EE5ULL,
			0x6756086304009FF2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C7553DBD650AF76ULL,
			0xD92696515560E63AULL,
			0xEE888584D558D03FULL,
			0x2065648CE6F801EDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8B60D88D97417D3CULL,
			0x516B11C9D4262569ULL,
			0xB2DD962F0264E8A4ULL,
			0x4D43426A0935AF73ULL
		}
	};
	printf("Test Case 107\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x429156F170ECBFD8ULL,
			0x1559CA21202B06A0ULL,
			0xC42C6D757FFAA1A6ULL,
			0x538B46FBE322DAC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96653160DE1CE8BDULL,
			0x2F0837D8CF4CC818ULL,
			0xF39C61599EF9FD5BULL,
			0x1CBAD91C0F70240EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD47BB83D2597B8B0ULL,
			0x44ED1E47149ED16FULL,
			0x1052E99B134E7062ULL,
			0x4A2B7DA1493F157AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFBCD60BA6E6640DBULL,
			0x7C072A99414A2A2AULL,
			0xBF66079A584A057BULL,
			0x39A9299E9176E9FEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x78E6374A650A4908ULL,
			0x67ED0298F8EE0B15ULL,
			0x1A6B96CA28A52AB7ULL,
			0x0D1B820E80D63E96ULL
		}
	};
	printf("Test Case 108\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x108DA5F2D131BDA0ULL,
			0x3EB146EEE211646AULL,
			0x1841F72F51E47F6CULL,
			0x5088C7DC955D2648ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD41106446677F4F3ULL,
			0xE7B8B8FBE74AB5BCULL,
			0x746C23181429843DULL,
			0x23AE0D24CDAFA0DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9EC33FFB7AECADE8ULL,
			0x2672E694B61F0F21ULL,
			0x82EC00FFD6C5D8E9ULL,
			0x4588E14B799C7332ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB72A3A092A428E52ULL,
			0xD2296FFE084C2585ULL,
			0xAE3BF210DE2F909AULL,
			0x06107F52B326759DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC39344679119D7F9ULL,
			0x1504608A2082F682ULL,
			0x881CA066D957FA2CULL,
			0x7CFF13DB4884D303ULL
		}
	};
	printf("Test Case 109\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x335DD4080E212748ULL,
			0xFB346F5EFC746208ULL,
			0xE376CF526ADE8E54ULL,
			0x41A3C457E0AB1B34ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC74F494DA12623EBULL,
			0x6EBD9F1D7CB70E0CULL,
			0x6FE96035E12084B0ULL,
			0x57FB4354CA63172BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x00D8CD2E13B3E278ULL,
			0xC4A9077BF41B2C86ULL,
			0xFA4526DEA7926686ULL,
			0x4E56B10291C1C75CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1AF24A9681338626ULL,
			0x3489CECE25529DE6ULL,
			0x3222FDEF06959300ULL,
			0x0FA2FA8D5657F6C0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE989CDFAD62FAD6FULL,
			0x17638CDF01AFB70FULL,
			0x4E8737172176D475ULL,
			0x5B17AFF873B79C3EULL
		}
	};
	printf("Test Case 110\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x153CD75645E849E8ULL,
			0xA0D5BBDFB9FA9356ULL,
			0x3FAD8B3A3680941EULL,
			0x630FB2CB0C327EFAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x34FF4456D61BDB79ULL,
			0x2406F11DBA556E46ULL,
			0xB8A4A035BE802590ULL,
			0x3F31541B8ECDF787ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A9B804ABA57F2B0ULL,
			0x305F912659EE5473ULL,
			0x58A0CF7A10855995ULL,
			0x50F18C4319EABB99ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x764D51F32A7AE14AULL,
			0xEBFFC6D684D711E1ULL,
			0x374DEB7370C576BDULL,
			0x785D58836E424A15ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x30CF319744F753D9ULL,
			0x7413662355849463ULL,
			0xB0651F23AC237FA5ULL,
			0x05A677FB72ABA4FAULL
		}
	};
	printf("Test Case 111\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA02C57971B63F6C8ULL,
			0xAC49BDCEED985D09ULL,
			0x21A173505E071086ULL,
			0x74A9AB73816C1D66ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x90CA8AF6DD2C4C27ULL,
			0xACE0ECE140FDA67EULL,
			0xEE3F8825E4B872F6ULL,
			0x38A8C04A0E8CEB18ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCD198CF4FB247800ULL,
			0x60CE48EBEFFF4D83ULL,
			0x34C91388EB78BB92ULL,
			0x47863BF635843D57ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF826AC9415960DB0ULL,
			0x4D99E2FEA7061DFEULL,
			0xA33336F47305218CULL,
			0x003338C8BACE75E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC716336928C29C53ULL,
			0x33837313B19C94A1ULL,
			0x43DB4C8D8CA272C4ULL,
			0x3E9A3CFD941870C9ULL
		}
	};
	printf("Test Case 112\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB0700444EC941C40ULL,
			0xAFD4F00E3562CACEULL,
			0x75714017F36CD41EULL,
			0x43DB0E60EE547388ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAA17D6F980EBE201ULL,
			0x969BDF3D851AB3DAULL,
			0xA74AE962F19D7A0AULL,
			0x566D6179CFA3354AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7C384E6E63C5E430ULL,
			0xF3B11B62F76F93D6ULL,
			0x2533B17C35E1288EULL,
			0x587D3D060801258AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42CAB1A29B0BAEF5ULL,
			0x6F877B0DE94C1EBDULL,
			0x9B013AAB137310AEULL,
			0x68D82AF221011271ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8A59AD9229F6572EULL,
			0xA51645A65BD98FD7ULL,
			0xF2B62B392B6382B1ULL,
			0x1FE9CA5455A13932ULL
		}
	};
	printf("Test Case 113\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8AE1B051E687ADC8ULL,
			0xC6F6F447B573B669ULL,
			0x0E968E5DF389614EULL,
			0x78348EF602560386ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAAFE59128B051A98ULL,
			0x442F8CA4860B9B0BULL,
			0x3A2CC74F1BB42ACFULL,
			0x0EA6C0CED84F8A8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEEB306C483E77228ULL,
			0xBEC538FE2FA4DA73ULL,
			0x1C4390D54E8849EBULL,
			0x5C26A352600138D5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA8C5EC4DED470675ULL,
			0x1C8EC1540EEAE8FAULL,
			0x4C20CAEF09E76043ULL,
			0x7129714320112290ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E1190FF098A3384ULL,
			0xED3C5E3A19A9557FULL,
			0xAA776227B5DE9FE3ULL,
			0x34EBCF83D99F4FB9ULL
		}
	};
	printf("Test Case 114\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB33D3AFB7FE48458ULL,
			0x1B71B2540B6D290EULL,
			0x47AE853EA2967870ULL,
			0x5D98E830B5463039ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x60DB3E52BAE99D48ULL,
			0x26B2098E3434E1B4ULL,
			0xD08497D5536A8DE6ULL,
			0x71D9AFE8FBC3505BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7CCE8E682FA74AA0ULL,
			0x0FB1CF94FDA405EBULL,
			0x4F7B62DB527D3368ULL,
			0x644547A33598B729ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x088D5DF722BEB4EFULL,
			0xFAB43D47412A8680ULL,
			0x0BC0EE26E26503A6ULL,
			0x04A0D21542DB21D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B5DA95522A1A9B9ULL,
			0x5886514D2770D996ULL,
			0x06C3FFF82924E942ULL,
			0x77A3B0F0BFF58EF6ULL
		}
	};
	printf("Test Case 115\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x407A57D3069DAA08ULL,
			0x3548124416C29E31ULL,
			0x8DCF0FF47EC278B0ULL,
			0x7CD7DB9303E1F91FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9372E9F1154726A0ULL,
			0xD0DEB776C8FD6100ULL,
			0x476BDE70B16C3B13ULL,
			0x3C0EB98B4CE41808ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x05170095999D9C28ULL,
			0xEF9B6D3CA2BD7D94ULL,
			0x981533D4D4CA5182ULL,
			0x50E87D2F0C61F563ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89BE8B30D3F1A5E5ULL,
			0xAAA7C8756C01F803ULL,
			0x9C2F221D83F5BDC6ULL,
			0x4876C50C5D1C7727ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF546FE9D21AC5167ULL,
			0xE4136C58A458A9E0ULL,
			0xBD7AE75BA9E5E288ULL,
			0x248E0322127C4C01ULL
		}
	};
	printf("Test Case 116\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A9A2019C3B77428ULL,
			0xB12C275E78A24294ULL,
			0xD3EFCE8694BC5E1BULL,
			0x5EDA7AD93A960B78ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0D3FD7D0AED5C376ULL,
			0x21208FBC07D28E71ULL,
			0x03F9B880474E7B5FULL,
			0x3F63A509BAA2627FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF0DF17FDB8EC228ULL,
			0x8E915B0141C8F2E3ULL,
			0x015E8D7DAE22485FULL,
			0x7DB970C4208D702FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2406C6FE7A44F2CDULL,
			0x3385B0D73159A376ULL,
			0x29D4378694458EA2ULL,
			0x649F41C9A8249CBDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x38DA9AF482C757FDULL,
			0x16A26502BF98A20DULL,
			0x8D8D17AB0630CE63ULL,
			0x217F916849127971ULL
		}
	};
	printf("Test Case 117\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1836EF8355076740ULL,
			0xAD3B90E188E7E13BULL,
			0xD854C6CECD5E6B3AULL,
			0x727C611E2A2EACA6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6284E07B49B0C108ULL,
			0x3738854D1DF69AE6ULL,
			0x18813388D1389DE5ULL,
			0x120A4A6D3DC3B7FEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A442F28FBFEA118ULL,
			0xD4A6CDC93C2CF028ULL,
			0xE6B1795B066312CEULL,
			0x6526E844E30FE191ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x524E25760E88B748ULL,
			0x3CF86E0ADCB93B35ULL,
			0x20E6CBB196B869BAULL,
			0x79BC1F3A7297C4AAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x072DB8E8A5122537ULL,
			0xFB48CEEB0ADDB329ULL,
			0x87738B41C59801E2ULL,
			0x0BC4AF58053C6534ULL
		}
	};
	printf("Test Case 118\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x10B492CA2CF7F938ULL,
			0x85CA3CF620E0B7A7ULL,
			0xC3B3D93C7E30C058ULL,
			0x6FB3470C23FA3C76ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD4CB2D081BEF0A91ULL,
			0x2A387A8C63E396DCULL,
			0xAAEA2F182A60E580ULL,
			0x35ECA034863842D6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFD79CBFF1C0FDB00ULL,
			0x545003373BA9BBE9ULL,
			0xD71AB03276581539ULL,
			0x5081503802D38D14ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB98BE317DB8F9C52ULL,
			0xA82E23457D40EE8BULL,
			0x01C5A01C22F46F58ULL,
			0x09755FE7F7910E0DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCA846275CEF1C972ULL,
			0x8C67F77E2D3DB6CAULL,
			0x26AD35B99A25A0F4ULL,
			0x0FA1934ECB8C5092ULL
		}
	};
	printf("Test Case 119\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF4A307E9EF9F1D90ULL,
			0x4B2E6B714D8301F9ULL,
			0xC9CBD276D46A5A50ULL,
			0x4072E1F29ABD70D9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x37CC97034EC3E1CFULL,
			0xDE8FCB7996754CCCULL,
			0xAC590CA66796E2EDULL,
			0x24EA7D726D5FB827ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF6E2521129AA2AD8ULL,
			0xE81831EA2351A0E4ULL,
			0x6D3B35E4C2A41F4AULL,
			0x727CB7D784810F00ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x00987BDD4E96E802ULL,
			0x72093FFC931C1E27ULL,
			0x74EAAF1E9BB604E2ULL,
			0x56C2399AE4CFB5C3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE8739F5207BD484FULL,
			0xB701A80E4B2124AFULL,
			0x52F54AAF1A550B2EULL,
			0x0755199F9C673925ULL
		}
	};
	printf("Test Case 120\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6A51D291F482BAC8ULL,
			0xBA5973A13F5E3726ULL,
			0xCB54B96E139C63A6ULL,
			0x5E3D92B97F2D526AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x360F93EC8C2E16BBULL,
			0xAC22ED0309962875ULL,
			0x47F9B96E3CD2B788ULL,
			0x1F968BD75AB0010BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA5140B9F449E3B18ULL,
			0x364E3783036AEA16ULL,
			0x6AF114D7064AA626ULL,
			0x542DBA12062EB96CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9C8BB5D4528E646EULL,
			0xA05DA9872E385955ULL,
			0xA201DDFA8680F501ULL,
			0x6CE467FFAE95C5CAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9CA4D6B63FD01A70ULL,
			0x2C630BF502A6B675ULL,
			0xD5F069BAFD275FBBULL,
			0x70EFE03E8B29330DULL
		}
	};
	printf("Test Case 121\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCED52556246575D8ULL,
			0x93BEF713A2973B0EULL,
			0xDB7D94F544966DEDULL,
			0x74C8A865D1E40C9BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE3895B1E76C827AULL,
			0x8A93C56DEB7EDAA7ULL,
			0x4FA8BA4CB0BD4059ULL,
			0x6DDCB387CC557D65ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC4BC99AFB1CA81A0ULL,
			0x1DA10257D3DC0CC6ULL,
			0x481191F432823745ULL,
			0x6882DD14A9269F13ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56A6EA485365E1F7ULL,
			0xB99EE93ED9E6D308ULL,
			0xCEF2F3293EFFA903ULL,
			0x7F9D7099565693C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCF7B255FAF977C4FULL,
			0x5566FFECFD84509BULL,
			0x059232912E33F6A8ULL,
			0x7221453B8FD62170ULL
		}
	};
	printf("Test Case 122\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0860148661E65A00ULL,
			0xF567377C168E0D05ULL,
			0x9D8D559F4733D4D2ULL,
			0x76431D47BDDB84A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9F261729277F30FULL,
			0xAF51550E200F2BDCULL,
			0xA4C0B81993AEDC75ULL,
			0x5FCFD335875B00E1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1E44DA1E33CDFF0ULL,
			0x5BDC17C2B6EB9237ULL,
			0xC522E614CCA52A74ULL,
			0x49AB6E343F6EC061ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBA0EDB38B1CE4111ULL,
			0xD071E3FEA9A8FFD9ULL,
			0x4341CCCF7C919FC8ULL,
			0x66C0CE6C3105EFE8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B3ED840268A5CC9ULL,
			0x8CD66DA35AE27E99ULL,
			0x37ACEE0E01BCB921ULL,
			0x4DE3237CACD67B88ULL
		}
	};
	printf("Test Case 123\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEF42039511132658ULL,
			0x5A0B15B65BE27BFFULL,
			0x5409DD6869172C6CULL,
			0x71F860358D2C4F43ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8D1E4317ACAD12B6ULL,
			0x42432E270B81F35AULL,
			0x8EAFF737105A9360ULL,
			0x687E737FA1D5E186ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFA567AC46563EF10ULL,
			0x9CF06B9F47B72034ULL,
			0x5A513B464DD5632FULL,
			0x7E567E0A078A3AEEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x60B3FD9202CB6DEAULL,
			0x34F2F34DD0714BD1ULL,
			0xEC7AB61EECFCF4A1ULL,
			0x2D714595F3B6A1FDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFEDD54D25AC91100ULL,
			0x94E2C0BD5530D98FULL,
			0x2977CCD2FB3F1AF5ULL,
			0x1C042506435379A4ULL
		}
	};
	printf("Test Case 124\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEBCF3B3D06BCC590ULL,
			0xE9C42373B49533EBULL,
			0x3DC39695146FC9ACULL,
			0x602419FA14FF3519ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF30507DF48EF3375ULL,
			0x12BB586461DD313AULL,
			0x82E2639E5B905B6CULL,
			0x73CA0CBDF1002D56ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCEA530423B1316D0ULL,
			0x0A639A12F33F13A5ULL,
			0x6CF258220B8E04DFULL,
			0x46754F8303B79239ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF04DAA0A8FFB4354ULL,
			0xC171500A3FC030B4ULL,
			0x49F024687CAF72EFULL,
			0x78E20C21DA0BC7C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE0C071E914A57C04ULL,
			0x39ECD57106C51F40ULL,
			0x86E8624AC1088F9DULL,
			0x412A2F0B5D7D8028ULL
		}
	};
	printf("Test Case 125\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x57ECEDB77054CC40ULL,
			0x85864C04C93662BFULL,
			0xDDC362595C21771AULL,
			0x536236D4CF24EBEEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x857C4ABD8A6035E6ULL,
			0x8DA6A816CCE90075ULL,
			0xE3AE34D1A02A2C56ULL,
			0x579B2DD3F1A31B77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2DE14A5916B16518ULL,
			0xAD31BBE49CCAF080ULL,
			0x25758C748E97C009ULL,
			0x432B42C00E6BD76FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xADE5AC67D58FF01FULL,
			0x92C6A5FBC86A3AD2ULL,
			0x349448526E541BBDULL,
			0x005D6519A85EACF2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7FE2C48E51A6DB44ULL,
			0x593CABCEA42EBFE7ULL,
			0x5FC09A0E1679C544ULL,
			0x15F3A73AC975364BULL
		}
	};
	printf("Test Case 126\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF66D3998351E4990ULL,
			0x52871124F7DCA08CULL,
			0x22C400B623E707D7ULL,
			0x7A1F2AB36BD48AACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3A77DA080C742EAAULL,
			0xC4365D9C7FB7B0D3ULL,
			0xEF99AAB37FCAB147ULL,
			0x55A48F27E0CCD11BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3ECD8CBFEB1BB3A8ULL,
			0x9795AC57E8462D99ULL,
			0xB6CCCD4B99D34B19ULL,
			0x615F26A4029600CFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0BE472823F90F8E3ULL,
			0x6ECF58D22316F1CCULL,
			0xDDB0FC46DC586E69ULL,
			0x0E90FEC42091C9FEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCD924DC9AFA2386EULL,
			0x821F974DE6F72D94ULL,
			0x4E2CD48F853428B7ULL,
			0x53A4960076AE04CAULL
		}
	};
	printf("Test Case 127\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x52312CCEDA7AA9A8ULL,
			0x359779DCB06A97D8ULL,
			0xC2C710D7627302F9ULL,
			0x401A4C86616D973BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09E9D75ECA1F81ABULL,
			0xAC890AD70D14DAF3ULL,
			0xF39B76624F479590ULL,
			0x46FD16E7D83004FFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD26C7BA449B9110ULL,
			0x3983050208C83FDCULL,
			0xA0180177E1B9D9FBULL,
			0x5FC319113DFEC728ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x16F5198C27B060DEULL,
			0xF9F85E3CCD3A8B44ULL,
			0x84DBE32046156F20ULL,
			0x1080300E76A17822ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA85CB8005F7524FFULL,
			0x2C35FF53960C22FFULL,
			0x3A68D72BA223F18BULL,
			0x4AC9E877C28CAB6DULL
		}
	};
	printf("Test Case 128\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4454239BE746C4F0ULL,
			0xF75E8E99D240CF65ULL,
			0x8B28F59F90197691ULL,
			0x5FFD63764886FC6CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1563ADCF41EA86F3ULL,
			0x87BECC0B7B316D34ULL,
			0x8A9FC3215F358664ULL,
			0x312E60505170CFECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x924E22E25879F2C8ULL,
			0x267B34415B44B3CAULL,
			0x007860AA29FF7991ULL,
			0x6B162884781F4A3AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFCFD34F5510DCAACULL,
			0x3191AC0ECB458252ULL,
			0xE66532C3CE4B118BULL,
			0x197558A14EA11579ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D0C86A67A3C9691ULL,
			0x75FBF225815F3CE2ULL,
			0xAEA9A8040AC068E3ULL,
			0x7ACDBC6E7123B869ULL
		}
	};
	printf("Test Case 129\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEA11F27D654A7848ULL,
			0x585D5E1D9005BC08ULL,
			0x8C16B90723277D16ULL,
			0x5BBC1485B2CC2CAEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B9E1C48354B3459ULL,
			0xE840C7C5A9260D8DULL,
			0xE15EB50805B7B38BULL,
			0x7EFA36AA195AED77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x69629903CFE313D8ULL,
			0x7A900AC4822F3F4CULL,
			0xDE726FF5EEBCADE4ULL,
			0x4F73513E8568F0CBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA9E2B18D97A7060CULL,
			0x1AC2E2047B58D233ULL,
			0xA39EB5E631D48CCBULL,
			0x08FFF2E3F262DD4AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7606F1E7550B1AF8ULL,
			0x3C29020E5700BD54ULL,
			0xBF1D41D8B007576CULL,
			0x73C34DFB70E311FEULL
		}
	};
	printf("Test Case 130\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3A56516834A1E870ULL,
			0x1F77509C8A19A939ULL,
			0x9D6584BB3A1DB8E7ULL,
			0x5478F083D29BAF2BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x699E5A789E9C66C7ULL,
			0x31BB4DDA748F2E0CULL,
			0x4AD289744034664AULL,
			0x50678AE847F4893FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x77D4049E2C403B90ULL,
			0x4499B0568F01E957ULL,
			0x34AC89720DCC862DULL,
			0x45AE2ABE26E131AAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA6B2A1223C47B886ULL,
			0x83AFE0025339DDD2ULL,
			0x4E76AF28197656CFULL,
			0x6C40B8DC3575F9BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5A69844F922AA207ULL,
			0xA2F3311456293008ULL,
			0x6FD04B22FFD71F01ULL,
			0x71AB82CAF4EDDE2FULL
		}
	};
	printf("Test Case 131\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x860D031AABB2BF08ULL,
			0x975AC9D482FFD1F4ULL,
			0xD3D9214BF9B247EFULL,
			0x6380E7505FD86D72ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8340BC1C7EB6FB7EULL,
			0xD4C17298233606A5ULL,
			0x0F91586B6DB9ED21ULL,
			0x6E15D203466427C1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x138D896CCAA075A8ULL,
			0x5C4B1FB5AAEA04C5ULL,
			0xD5E061F14452163EULL,
			0x46DFCAF3B7CBEB99ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD1BF4C2C45A2B096ULL,
			0x86FBCB8D9FC30523ULL,
			0x4B1B798D7AA0C296ULL,
			0x2C4D7745510BA031ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1907F8F0D65771E7ULL,
			0xA11558A3A7947C8EULL,
			0x77E99482D06C7726ULL,
			0x5FAA73098A91D4A7ULL
		}
	};
	printf("Test Case 132\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x253BEA63A37C5318ULL,
			0x99A966B21C42FDFCULL,
			0x49F0E17584D62CF5ULL,
			0x7020FF8ED4BC55F0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x06D7B2B1CBCD90F4ULL,
			0xFEFF34F3B992C117ULL,
			0x7AF5D9DB882B3D34ULL,
			0x6752E49A70E19DAAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD47456EFFE0809A8ULL,
			0xA17A81C22B2E85E7ULL,
			0x03A16F91F9ACBF6EULL,
			0x4F89EE07BB7CC57AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA446C20F5254856CULL,
			0x10273C7715A33C11ULL,
			0x3230087C2F07EABCULL,
			0x210EE698D89EEAB0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB09C025305DAA678ULL,
			0x137131C9748B20AAULL,
			0xF046F378BC195875ULL,
			0x694B387C60EAA089ULL
		}
	};
	printf("Test Case 133\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x10C769D99D6C8FF0ULL,
			0x0A43188ADAF5DFB4ULL,
			0xB39A005E46E8835CULL,
			0x4BF39DA3E715EF1BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x48A2CDA811C4F644ULL,
			0x9EE0DDC539138F13ULL,
			0x010366E33F3662D5ULL,
			0x09A52EED6A1DB4A3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A124D9EDB2C7B40ULL,
			0x10AA7BC9779BBF08ULL,
			0x017B0E165184D64AULL,
			0x632624B336B891C4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCBE3072C2882A523ULL,
			0x282443F15A4D16FFULL,
			0x250B6995FA328603ULL,
			0x6237752DCF7B7726ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x43F3091D358954E1ULL,
			0x9514E3E8D36C6965ULL,
			0x208BCAB1D56E4EC1ULL,
			0x4D15819DDFC867B6ULL
		}
	};
	printf("Test Case 134\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDC9FE84D5B52B8E8ULL,
			0x6899B1176ED66353ULL,
			0x880C399E9E4034E1ULL,
			0x6922ADE434337FD0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA6267E5B09D221CDULL,
			0x0328C52167C95C6AULL,
			0x0A51886CE0FAC97FULL,
			0x2BBB38B0E602595BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52B2AEE194069378ULL,
			0x329129EE75C1A9D5ULL,
			0x9774662E8001CF28ULL,
			0x759D320B1045F50DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x82C39C2A2909CA13ULL,
			0x67248651395654A8ULL,
			0xFCCCFF0CE9CAC0CCULL,
			0x3BD8F0CCBD62F62EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB116450890BB2318ULL,
			0xF64DC91754587AD8ULL,
			0x8E626B395F9AD2FFULL,
			0x6DEFF34671956FEEULL
		}
	};
	printf("Test Case 135\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D4CDFD25C6C01C8ULL,
			0x3076333E0DB6C245ULL,
			0x98D4530564DD2748ULL,
			0x4D151537A507753DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9C46353A6EAE70EBULL,
			0x5BA8800DC1CD5422ULL,
			0xB407B3B01486B944ULL,
			0x578E766268F847D5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAE6E982ADA6BD0C8ULL,
			0x099A08463263D265ULL,
			0x13FE11301092CFEDULL,
			0x41E72D5605D30D22ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2202C03511743D67ULL,
			0x8D1EAB5B0ED1E982ULL,
			0x3C780CDC51434966ULL,
			0x5BD00C9BBB246A2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE998A95AF7372D4DULL,
			0xA6CB1C22555EA497ULL,
			0x251BE9B3A631EA75ULL,
			0x12EB27231AC29BF5ULL
		}
	};
	printf("Test Case 136\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1BE7DD85109F6490ULL,
			0x3377A4B464C8B319ULL,
			0x046D14EDC21B90A8ULL,
			0x576FBB5E4F71010DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x50DA90B14C4A113FULL,
			0x1EA426B43DFA1C42ULL,
			0x40C49E5858A80ACDULL,
			0x7FAC3D9B334B72B1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7AB45D4CDF4F0C8ULL,
			0x9E7C9F755C6F6124ULL,
			0xA7F1962FD0A51B32ULL,
			0x764BE9F68E2EEE31ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3764AB2E1BC6440BULL,
			0xF648F9460B30CAA7ULL,
			0xCC5C17B50B72E932ULL,
			0x2C8ED1C1EAD19C91ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB8250FC08A89A472ULL,
			0x2D01DCA68BF25AA1ULL,
			0x72E9DEF41428E4C3ULL,
			0x77EE39BDE715D400ULL
		}
	};
	printf("Test Case 137\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE59FF5199D3C7350ULL,
			0xB8321DCF88F011F2ULL,
			0x78AD1056C29B245EULL,
			0x6AB162F9F5236F1AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x54064D7E67466ADDULL,
			0x4DD1DEE58F48A1AEULL,
			0x6ED0FBF3865D6D99ULL,
			0x0498399F47D58038ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA7D8F16278A31EA8ULL,
			0x9A0462973DBDC7B4ULL,
			0x2631A3AC79BF4C6AULL,
			0x74C4C8D1C7FC8979ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x32F4187CE7013684ULL,
			0x0EAE72B028266B75ULL,
			0xF8979F95E4213E3FULL,
			0x6835E24CB8DC4D59ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9E16583DBB26CD33ULL,
			0x6EA964D4640B2D50ULL,
			0xB0183A8DD6C54031ULL,
			0x054A3D4D1AAFF598ULL
		}
	};
	printf("Test Case 138\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB3DAA9C38C4F2600ULL,
			0xDDAF422A4705AF5FULL,
			0xD67942125BEBB17AULL,
			0x7B002D3C239FFF81ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB57BB13C27D5D22ULL,
			0xB825DD66B3A81B70ULL,
			0xE34E76CEC640006EULL,
			0x012E7E95D1CB9699ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52F05B3388A56F88ULL,
			0x860AA64969779309ULL,
			0x0358510CAFE52792ULL,
			0x629550003B48ABBCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6A429E8784194089ULL,
			0x7E506E877D8236A1ULL,
			0xB09E80943AB1E683ULL,
			0x68F7AFA9DDBD2760ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x97C4FCD7718A6EF5ULL,
			0x756F933C015FBCB4ULL,
			0xA03343E6DD5021E5ULL,
			0x620004A3E0A3818BULL
		}
	};
	printf("Test Case 139\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE44A3C97AF7EB9E0ULL,
			0x4969CD78BC2FFDE4ULL,
			0xDB110D076F4D6DA4ULL,
			0x7A47906E49B4C32BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBDE9E229C44D590CULL,
			0x45F229F1D01F7D7AULL,
			0xB9C587CC64CE01A5ULL,
			0x62DA166BB33A7A35ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C9E0C32862067D0ULL,
			0xB5B62D6F7FE35A60ULL,
			0x46618BAD7646DFEDULL,
			0x6C4D89D760B663ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37DF34B441D8699FULL,
			0xF099AEAF2537B7BBULL,
			0x61336B8E0718FFEEULL,
			0x1E75753D922B8B8CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1A10E4C806A1B843ULL,
			0x6A69E066CB7902A5ULL,
			0xB8C0C530551ED689ULL,
			0x0528DBC1D5443602ULL
		}
	};
	printf("Test Case 140\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xADE2685903BD0C90ULL,
			0xD3AB0D2A7DEF76E6ULL,
			0xBC58A49FE5248FA6ULL,
			0x4A58317420D8B394ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD9D7D4C1E54F9983ULL,
			0x0E07E3033E91DD37ULL,
			0x942BE28E47C904AFULL,
			0x03BDE08A3C3265AFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCEE212029D2538D0ULL,
			0x56491DAACC0004D7ULL,
			0xD195D0BA25D3B65DULL,
			0x7E7B9DA3992B7AA7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7703B544F1E75642ULL,
			0xDBB9FCD30C413240ULL,
			0xAC41DF58C07E91FBULL,
			0x565735BDD517AC48ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x71BF832B24EB84D7ULL,
			0xC5470B07950A70E9ULL,
			0x068E8E6CD02430A8ULL,
			0x586465E3F3ABEDF0ULL
		}
	};
	printf("Test Case 141\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC9370CE6928DBBB0ULL,
			0x22A6FAAF333BD237ULL,
			0x7309C93AFBCD0947ULL,
			0x7D4D2AA162701DDEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5AF5EBAF1EC4ADE9ULL,
			0x316540498CE0701FULL,
			0xA9B18C013485CACDULL,
			0x58795D964EBD37FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0F76F7B8B335CCE8ULL,
			0x357B9D5D432C121FULL,
			0x6C86C6A802F63445ULL,
			0x4EC6538B56075CF8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8F76E9ED5BC61347ULL,
			0xE87471C67FD39B3CULL,
			0x256C8D1D535B7FA8ULL,
			0x244A7C6CF8DDC7C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D3DAD96A13A5B4AULL,
			0x5A7CE4B19B34711BULL,
			0x06A01D6D5DCC0B3FULL,
			0x6847536216BAA1F7ULL
		}
	};
	printf("Test Case 142\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF84BDA91997C34F8ULL,
			0x97E97CB8BA5644C4ULL,
			0xE1103F8DC93E5580ULL,
			0x4F100CFF39EB6F81ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFAE7E6FDFF010700ULL,
			0xCA013A8A727C5A9BULL,
			0xC7D85271538F112AULL,
			0x322271C12EADE291ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE77C14E46C47B0F8ULL,
			0x81401C0A70CB3D8EULL,
			0x12831081F450609AULL,
			0x652F17518F7C9B21ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x629EF504F15200F1ULL,
			0x54BCB1467EB68A52ULL,
			0xB0EB9747DCEF3F9BULL,
			0x184BAFE069E6A20FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x760D88B7823B0AE5ULL,
			0x67B45F76843D51FAULL,
			0xBF9330C164B59165ULL,
			0x48C450F01F45D162ULL
		}
	};
	printf("Test Case 143\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x285C5AD4080B0738ULL,
			0x63E1F2C3F5509AE4ULL,
			0x9038A47D0009E0A5ULL,
			0x4A10936160CB7571ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD74141E6130A6884ULL,
			0xD5E959D2B7FEFD1EULL,
			0x53E4735A0677955BULL,
			0x0BF4EDCA4C6FE172ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDFB17F185ED38710ULL,
			0xC5DFEB0D4D15E3FFULL,
			0xC1A91B3E538A0AFFULL,
			0x67020E58FE390652ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC6B7CB54B59FA4EDULL,
			0x50A5EDD3B402656DULL,
			0x38A3FF0E29870DB9ULL,
			0x17932B71E0D6B315ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x41E8DAC1E73D8171ULL,
			0x0B8EBF1EF621590EULL,
			0x99E7120624CDBB07ULL,
			0x3D23E6A4CA285AA2ULL
		}
	};
	printf("Test Case 144\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xED24F199481D1978ULL,
			0x0A2759DFEB165C5CULL,
			0xAABD56B3157C1847ULL,
			0x63CE963845113524ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x37BB2812AD0BC922ULL,
			0xAA8B1532A7BF76E5ULL,
			0x8D37300948A1570FULL,
			0x058D6578048F88F4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4E93797567EEBC00ULL,
			0x286FBF6D4235221EULL,
			0x10242414DA9A5067ULL,
			0x728FE4C1147847C6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE42389E350A7BB6CULL,
			0xE493E398FD993DC7ULL,
			0x9B552C469B64E17AULL,
			0x658D1EF074A0BE55ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD401AACCDD525902ULL,
			0x68D7AB36912E780BULL,
			0xDC2E23E31B69AB88ULL,
			0x00E90DC2CA39AFC7ULL
		}
	};
	printf("Test Case 145\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5CAEA6739B8A9630ULL,
			0x8A5C66D5F63517F8ULL,
			0x337A992865D28EC1ULL,
			0x7A06FB50B69218A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7D09EFE1840E1B3ULL,
			0x5BEA49C87D99D033ULL,
			0x22640B78ABC1F8B1ULL,
			0x7F2600028F10CDF4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x475E12941357F820ULL,
			0x5867DAD548AC17BEULL,
			0x77BC4069AD7CF252ULL,
			0x63F2C2AC88154FF9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x87D15E5D633436BFULL,
			0x86075ED318F18D82ULL,
			0xC95F7EA8132B1B08ULL,
			0x56E421F06F3EA4EAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AD60C1AE5DC1B72ULL,
			0xEC48E49B7A8B0B42ULL,
			0x204690F60B7CAB3FULL,
			0x65F1D08B6064A459ULL
		}
	};
	printf("Test Case 146\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB32C4575D43222A0ULL,
			0x0A273263998BB214ULL,
			0x342B8663A0E52DE2ULL,
			0x5D1E53263F7F1F02ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x45848D451DEBB40CULL,
			0x10867DDCBF61BF51ULL,
			0x48F712D853A3C27BULL,
			0x7FDC6B67C35E9196ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x86433B6BA8A8A238ULL,
			0xD08CE15BED51226CULL,
			0x12BBB01164864DD4ULL,
			0x51A0FD9234A56BE0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA976D288ACE8B294ULL,
			0x2E759C8E13ED5638ULL,
			0x654C9D81D20AF7E1ULL,
			0x3DCBF161DE643078ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x372AD10EAC698453ULL,
			0x0E70705705CD6E16ULL,
			0x0EE6036DDDB4421AULL,
			0x0C49BE691A926311ULL
		}
	};
	printf("Test Case 147\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x06177DD77EE3F468ULL,
			0xA106056FD714D948ULL,
			0x24060447B782D557ULL,
			0x48A3AC2435DDD65BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3E428780BFF910B6ULL,
			0x880C8A5324B4047AULL,
			0xFC73A7C479D64CA3ULL,
			0x6F84D9E6599F2396ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F749C991CB64238ULL,
			0x9370CBF9747895C5ULL,
			0x7B5AFFD276FAA2CFULL,
			0x42B440A6F9D9DC88ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DA5A1811F045E2BULL,
			0xF2357DF2C1027C04ULL,
			0xA7A78DAA1E711681ULL,
			0x63881C93BCC7A5BFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2344680F36D22B2BULL,
			0x23F42EBC0F041C92ULL,
			0x36235632A4DEA884ULL,
			0x0BE36B295C881A62ULL
		}
	};
	printf("Test Case 148\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x921A266F0382F700ULL,
			0x1B622F1DBFC86F81ULL,
			0x774EB13A696A2A7EULL,
			0x63C308030B32A36BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1DBA7ACF0304B6FEULL,
			0xDD2CB142638A6A54ULL,
			0x5467B660B1E29F31ULL,
			0x6E96E678DA1F3625ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x04114E516C5E2200ULL,
			0x82823CA0B7FDC072ULL,
			0x2C8FD259CE5CE174ULL,
			0x71C2CA522CE0BFB0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x65EB1C4410B4C237ULL,
			0xCCCFFCA66CC4A285ULL,
			0x34E06CECC183D409ULL,
			0x4634D2CC0C1AA785ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67F38E15C66391B4ULL,
			0xE536CF3AE8C77AFFULL,
			0x4627D47ED94C882FULL,
			0x7ECC9E27C5D6CA7DULL
		}
	};
	printf("Test Case 149\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x361AEA0E7159C7A0ULL,
			0x317B3BD0C9A78C70ULL,
			0xAC40A9436F96094CULL,
			0x790CF6AD96CC12DDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3AE63D03630493E7ULL,
			0x8328E4D9F171EC2FULL,
			0x792ADB7E91FE6307ULL,
			0x4B09D4EBFAF5A540ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1FF944ED8976628ULL,
			0xB40E088D5B135727ULL,
			0x195CDE9B45DF4FA6ULL,
			0x558F12E20D023DD6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF01675867608C6CBULL,
			0x88376CC8A53FCBEFULL,
			0x6A8E7FE8B94A4236ULL,
			0x5E5DCBB6CD7E670CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D842D55BDBD13F5ULL,
			0x3293C714CCEB0E3FULL,
			0xFA2645F2B539C358ULL,
			0x0B161D6349330DB2ULL
		}
	};
	printf("Test Case 150\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9CC9F4DA68C75530ULL,
			0xA0DA7F8D5CD6C474ULL,
			0xE7F635418FB6DC44ULL,
			0x77F9BE757C809D6CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x683DD2D04A000ACEULL,
			0x2FFE7A1FFEBBF34FULL,
			0xDD25E8AB91158307ULL,
			0x0B6218B2FBBE2BBFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC28451079BB78040ULL,
			0x7DFE182479A48C80ULL,
			0xC9E051DC93262A63ULL,
			0x7F60BE7A376085F9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x143CF93E1F899CFDULL,
			0x4FCB8C7F8FDD9D44ULL,
			0x10CFEA508E52FEB8ULL,
			0x324BD35F0D1048D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x35477CCC55DE5B28ULL,
			0xFF50B6C1087B6898ULL,
			0xD6DFDE4B4C8A646CULL,
			0x491A96FDA100D659ULL
		}
	};
	printf("Test Case 151\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6252D365A9CF9588ULL,
			0xF6910C989AFFF3E6ULL,
			0x424AF75B8FFAE4ACULL,
			0x5FA529BB02B744ECULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB95508656BA91AC5ULL,
			0x7C63F54AA0568F5EULL,
			0x741C6D32AC3DB35AULL,
			0x50A1C60A6B4E9EDBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6BB86BB33CA971E0ULL,
			0x462EFE75908F4B78ULL,
			0x7A5AF041C478ECDBULL,
			0x465D80A413B36C7FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x53D6BECACA61F0BDULL,
			0x0DC142D0B1D2CA4DULL,
			0xBFEBBA419D473B14ULL,
			0x57BFA53E92F69422ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x64536BAF6A8FB6BAULL,
			0x7F967865940F1B01ULL,
			0x0265EA4747E16B41ULL,
			0x570FAEE3DFC40F39ULL
		}
	};
	printf("Test Case 152\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x106DC90E14DEAB68ULL,
			0x53A8D62A2B7BF143ULL,
			0x31F2D7AB0D0FBC8AULL,
			0x7932C0AFF3F10D00ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA0347E7A71053AE1ULL,
			0xA6A1F378B5AB446CULL,
			0x1848F74E39851542ULL,
			0x41D466E6B25D06D9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A9E24C5FF355BB8ULL,
			0x33EB5C381A3BFF15ULL,
			0x8B5A2EA80CCF0357ULL,
			0x4E9BEE567C7A3B71ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x478DDE46BB5380CEULL,
			0x86052EF389FABE8AULL,
			0x4981217925CDACE2ULL,
			0x02C52430F59FC2CFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA093824841732352ULL,
			0x70BA4710E905D8D7ULL,
			0xACC9731DA17C4AE1ULL,
			0x21C3469278CB500FULL
		}
	};
	printf("Test Case 153\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1AD963729FC3F030ULL,
			0x3388A3F76435BBECULL,
			0xDB0EB2989C187DA9ULL,
			0x400E96D0C84D1A53ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3A354F7ED0EDC248ULL,
			0xCEFA4502606BAEBBULL,
			0x2E06EB681BB06965ULL,
			0x7495EB582B35EF91ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D1CE7C01F820048ULL,
			0xB2EC7193DB368747ULL,
			0xE15C112807A2F73FULL,
			0x48525D3DC96D6CC9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B70609CF71CE7EBULL,
			0xC85A88F3C90ED7C1ULL,
			0x3484CE6144C956F4ULL,
			0x71625F49F49254BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x35C7F87B52BAC65AULL,
			0xAC3BDDA299CE194AULL,
			0x93C141DA42808CD9ULL,
			0x1E0C6E7A67D98D81ULL
		}
	};
	printf("Test Case 154\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0C5D751727723400ULL,
			0x2EDBA100C1A6C8A6ULL,
			0x4944DEFF65E6CDDBULL,
			0x6C99512E7601FF93ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE032EBFE105F93BULL,
			0x89CCBFCC5C62858AULL,
			0x97754EBAEAE134DCULL,
			0x59C7D4014D46C8C7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFF5D9761FBF094D0ULL,
			0xEDE43ABECCEE7A7DULL,
			0x0D5CF37D3BCCF1E1ULL,
			0x737FF45E03AD9450ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x01E9411438CBFCBFULL,
			0x239517E8887B9086ULL,
			0x384774A3B141A154ULL,
			0x312B888F87923345ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9EE1E0601660F289ULL,
			0x4197FF32474F5AFCULL,
			0x78055C0E0C84751DULL,
			0x4D27045BF27E397EULL
		}
	};
	printf("Test Case 155\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x67D546466D3DEB08ULL,
			0xDE530D5006FAD349ULL,
			0x14D58C629FF00C60ULL,
			0x6815929CF9974E5DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x94F49DD59B46995DULL,
			0x2FB63780CC564334ULL,
			0xC81F575F8969E688ULL,
			0x51491012B0C46B65ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0179D06AC1DE7E8ULL,
			0x42D194B84DA166C1ULL,
			0x74E677A23A3BF4FEULL,
			0x49226A38C1C57727ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5915554527DDA1F9ULL,
			0x9174F0E6BDE72950ULL,
			0xEB9364C0E1E2E4DCULL,
			0x46391CA8E5A43AB5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB84A1975ADA9BABEULL,
			0x921131D2B5E4F693ULL,
			0x2ECAC5396E391D27ULL,
			0x7CF098C4D0895C43ULL
		}
	};
	printf("Test Case 156\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4D132E754956DA98ULL,
			0x4EC7C12C98073765ULL,
			0x1D6FC2153EA252CFULL,
			0x5A02577CDEE5007BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFD2F4641785A6EC3ULL,
			0xB58EADEEDB7799CDULL,
			0x73F2DD88BADF6495ULL,
			0x40D3BFE7C68E15FFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD99740CF09144D10ULL,
			0x6924B8C065C1723BULL,
			0x81256C959C59B796ULL,
			0x6982AFAC5DE5FFACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB12686242F25B707ULL,
			0x2E5D783FB869B373ULL,
			0x3F6232D7B5797563ULL,
			0x50BFA0C43E3A6A5CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x215AB2CC0A9925B3ULL,
			0x25BB10DCE5E8CD1BULL,
			0x911302CE988340B7ULL,
			0x5BB70F283B9651EFULL
		}
	};
	printf("Test Case 157\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB7438F2107984770ULL,
			0x9E143856F8EEBAAAULL,
			0x6D1586B16A0BCAA9ULL,
			0x6463E2779D925B2FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA20AD25D6BA011FEULL,
			0xBEED9E4BDCCF0B2BULL,
			0xDCDE43D64190986CULL,
			0x4FD8C0227D5AC262ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAFF829B58A0385A8ULL,
			0x219C955570609E2CULL,
			0x55799E7D7036BE4AULL,
			0x6388984414836156ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCE0CBD3B4BCA6F11ULL,
			0xE6EDE91E12F1528DULL,
			0x60ACBFE7063F5416ULL,
			0x512355360D8194AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1755BE34FDB647CEULL,
			0x13946160E740E420ULL,
			0x4191B4FB7129308DULL,
			0x4958E4CBDE541E47ULL
		}
	};
	printf("Test Case 158\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x095CB687D6C54688ULL,
			0x44FA7D64EF7B5C1BULL,
			0x7F15CFE73DEFE1E0ULL,
			0x5B0D37C331D74E54ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5415D09551E10B59ULL,
			0x8F3B7EE6A952524BULL,
			0x18E13413F2D05782ULL,
			0x4ECEA5EE456CE02CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCD9FCF1F2B7E0950ULL,
			0xCA490D106FF9C9C3ULL,
			0x75E065B224F4DC39ULL,
			0x619DA198EE7B9B4CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD385E00F4A679F01ULL,
			0x53B93F84525F99A0ULL,
			0xFFE658A6DC36A819ULL,
			0x0C1D2443CB9AC069ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7B68D2514B6C13AULL,
			0x96C4670DF8033BA5ULL,
			0x2F0DCC7800AA9087ULL,
			0x772390392080757FULL
		}
	};
	printf("Test Case 159\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F79413E9AB816B8ULL,
			0x1BD32088707BF26EULL,
			0x170E146FD84A8E57ULL,
			0x728D76416027DB50ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x16A2F0F795A1671BULL,
			0x22C4C68649519159ULL,
			0x44E00A58778269F9ULL,
			0x6357A7551B7EBB06ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F3383E38D1B4610ULL,
			0x3AE7CC907BAFE232ULL,
			0x23E79D9696EB4C45ULL,
			0x6D347CE1B54F4A53ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x713CBED05E91DA50ULL,
			0xE73CFACCC7B6544EULL,
			0x164B566DCC58C55DULL,
			0x3E6855EA32BC0A27ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C0B0764CC53875EULL,
			0x957CDEB761E9BC62ULL,
			0x6A3771DEDE53A7B4ULL,
			0x589A08B828E62B0AULL
		}
	};
	printf("Test Case 160\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA9B68684A32133B0ULL,
			0xB5D334BA3C3714EAULL,
			0x4B94772BF8655B7BULL,
			0x598F00120A360D0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1224BBB0775DA37BULL,
			0x3627C08CC872C6EFULL,
			0xFEF54DF3E130E232ULL,
			0x44B25FC17A92D190ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3010F9C80867FD30ULL,
			0xBAD5375F0C044D76ULL,
			0xDD26205C64C06B7AULL,
			0x5CB84F241078FFFCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1AE369732CFDE012ULL,
			0xCAD30EE9A9578117ULL,
			0x4F9555A276908DD9ULL,
			0x7BF0BA6D2D00FF0AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDEE155ECBBCE7199ULL,
			0x3E444472F3E67BC9ULL,
			0x52D2744A515E8769ULL,
			0x13B6B0DDCED9304BULL
		}
	};
	printf("Test Case 161\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAB1161DE17FE9F88ULL,
			0x2E8F477D4317A024ULL,
			0x683777A9366320FDULL,
			0x46E60218E2554559ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2AD77597992AB75AULL,
			0x7047F2F4BFB5675DULL,
			0x36F85B19BFF84C0CULL,
			0x3C3196D26A43B8EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x422B55202CD84A98ULL,
			0xD7FB89041650D642ULL,
			0x629E4E68445094FEULL,
			0x71F71600D3E5B53AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x39757710BF53AD43ULL,
			0x4E2E0957376FEAF8ULL,
			0x484C52937E5093E1ULL,
			0x6CE0605F57CC1244ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E9E2A16E4C4A3FBULL,
			0x5492C7B3CE515F42ULL,
			0xF86790627A3D4FF6ULL,
			0x38F4886CC5EEE418ULL
		}
	};
	printf("Test Case 162\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x077C612B21F71150ULL,
			0x8506B0BB8D3CAFDEULL,
			0x98DB85081EF32CA9ULL,
			0x5833FDCD774BF7BBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x624D1A3B8F3AD55AULL,
			0x0F988EF7FA14035AULL,
			0x08888D889576588EULL,
			0x27C44E66F88545D9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5C4D7A18C1E18AF8ULL,
			0xB0776CE8BAC910D0ULL,
			0xA62C4DC9B0D85443ULL,
			0x61B95198F5C39136ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x159DD2BE933FBF50ULL,
			0x9DB1BFFBF73A5937ULL,
			0x98B0F3C0BBEB7D59ULL,
			0x262855634A503346ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD4BA694D8FE73382ULL,
			0xDAA193C97D87CB80ULL,
			0x4087E6231E733F34ULL,
			0x5E15BC0DFFE8EC26ULL
		}
	};
	printf("Test Case 163\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x29D1001BF79115F8ULL,
			0xA9B11A01376287FBULL,
			0x668EE36001707266ULL,
			0x4D4F5D385A057536ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1AC53F84DA6EBF8ULL,
			0xE7FC72E3DC0CA2A4ULL,
			0xF22E41A82F3E9333ULL,
			0x48157E9323C0DFAEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF40E1011717A4738ULL,
			0xDBD568E44470F07EULL,
			0x3DCA67B21ECC1EC4ULL,
			0x74902E1E34638A19ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCE69BF10600ADA4CULL,
			0xE9CA8CE03F22DE5AULL,
			0xDCC10CFB62525B9EULL,
			0x198BA320960E1722ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA52D6B18E56F6DFEULL,
			0xEC680081DA4DFD64ULL,
			0xBEABF356E8490C7CULL,
			0x73CF56C9729255FCULL
		}
	};
	printf("Test Case 164\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5CE2E81E7799A808ULL,
			0x1883FDA8E5CF6100ULL,
			0x6B2F8C5993A035D4ULL,
			0x725D9A2FAA7DB86BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5E813491470C868DULL,
			0xB7824B4AA598C395ULL,
			0x65C2994B77F93F46ULL,
			0x308259F7ECA6CB83ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4229959FD30EF0A8ULL,
			0xCCE2D8084AE6B42FULL,
			0xD89B86BC6206D3F3ULL,
			0x7A93F22D6BB3BC32ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8D1FEBC7E929728FULL,
			0x2E774CFB94D181BFULL,
			0xC4E886440AE1536DULL,
			0x4A85DD5899DC72DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB3F2CBBB2DAD2AADULL,
			0xF76FC144C31EEBF3ULL,
			0x02033E9D6F5E16D3ULL,
			0x1013B673AE733685ULL
		}
	};
	printf("Test Case 165\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCF6F5CCEE58EF800ULL,
			0x8FFF5217E38A6AC2ULL,
			0x7721B4FDDDF40C06ULL,
			0x6C4A95BDC61397A2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72868A37FB17454DULL,
			0x80660A712DB43BC5ULL,
			0xF4C59ADF1E49E1CFULL,
			0x7678D5027ADA8A8EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54243A8CD5928760ULL,
			0x685C7E652039AE05ULL,
			0xDF04402FA6D21495ULL,
			0x5CE2E8675467715EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1D0FAD1C4984B28AULL,
			0x8F377CBD77D20CE2ULL,
			0x855E66C2AFF24C2AULL,
			0x179D8D1E65DF58D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB07EF1F006E6F1EULL,
			0x025A94A91FD22067ULL,
			0xBDF45C9048ECF1ACULL,
			0x04B5246123774744ULL
		}
	};
	printf("Test Case 166\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x14CB95896A97AD98ULL,
			0x42EBDFDC122A33A5ULL,
			0xE3E75CD4185097FBULL,
			0x69E778AA3207C001ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x514F2C83315C0DE2ULL,
			0x2A52AAEE7B82FC61ULL,
			0xC8CC3FB50109A3F2ULL,
			0x7926F2493326E0BBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F79981C15286368ULL,
			0x27F4D80670AEDAB0ULL,
			0xB2B45194198440FBULL,
			0x6D51C8A9B9A0F99AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x35AC1D214C1224F1ULL,
			0xCF8EFF2B3070EBC0ULL,
			0x6423AEF05B66A932ULL,
			0x7CAF91CAEC9E7939ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF75D7F72745C11DAULL,
			0x324DFE830A9EFBA6ULL,
			0x4C0E5EF300943EBFULL,
			0x671C22AA4C88B864ULL
		}
	};
	printf("Test Case 167\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x664D1D4667012D78ULL,
			0x11B27F277B4A3E4CULL,
			0xD5D5D1F25BFFB898ULL,
			0x5EAE6F67FED1FFECULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF75C3CA2BCE7101EULL,
			0x104F11DDD7544909ULL,
			0xF637C941F296D1DEULL,
			0x6CA5B03BDAD935D6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F9339E949B5A948ULL,
			0x3D94C8BC71DC518BULL,
			0x8D2BC0D7F30DCD1EULL,
			0x5C8AB43B1868AF1BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFF365DEE117CFC5BULL,
			0xB7A5E01643E653B3ULL,
			0x5F12250A12E28C9AULL,
			0x285EF7BB7B1B0A4DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x753328E9B0BC5BFEULL,
			0xFE2F1FDF45A57C13ULL,
			0xFBE6F6E29860A592ULL,
			0x718C874E7794CF2FULL
		}
	};
	printf("Test Case 168\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x825D9241A2DD2CB8ULL,
			0x1214D670E326E365ULL,
			0x8CDDFEB6722BF242ULL,
			0x660181798F4590D2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2787BA570D5B8D50ULL,
			0x588E1807759B74E1ULL,
			0x8206D3CF5DE0D703ULL,
			0x4B820A110B66418BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB162C5218601D840ULL,
			0x3A490A1659D95E4EULL,
			0x02D9B03122716117ULL,
			0x52E07D87BABDAE99ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x18E3DDA2B88B546BULL,
			0x83DBB0874D88389FULL,
			0xE7AC344C74B55E29ULL,
			0x4AD3F3D8922093B7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE6167A3FE173A71AULL,
			0xDF0E07E4145BF600ULL,
			0xECDD860556BF54E1ULL,
			0x7BD5B295AEE29458ULL
		}
	};
	printf("Test Case 169\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCA79FB736FC09960ULL,
			0x371B3EB6D74416B0ULL,
			0x25AB82520E3FF54DULL,
			0x7926D91F7FE5D7FAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEF252685BB068B93ULL,
			0x50B495B4E586788CULL,
			0x99B4F1F1264B8D99ULL,
			0x7FB59A5537D53414ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x03D7450F2CFA2350ULL,
			0x28010489EC751F3CULL,
			0x8397CDC58CE2251EULL,
			0x69AD0723E83623E2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x23417BC6814C15ECULL,
			0xCE8248ED140A7331ULL,
			0x04EF024FE61A173CULL,
			0x6CF504251DED9EC4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x463FB2594F39FF4FULL,
			0x2B6170114605FD2BULL,
			0x274694B235857463ULL,
			0x1DE616063DF8A3FAULL
		}
	};
	printf("Test Case 170\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE052F727EFCCC460ULL,
			0x60E279BE89752CACULL,
			0x545FCD783B452137ULL,
			0x5525FE261401C445ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF149DFFA2916BB4EULL,
			0x28ED055122A37723ULL,
			0x7C656AB7DC6038CAULL,
			0x3D4DF0537532101AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x67D0D1801D759058ULL,
			0xA662F891F5CCC11CULL,
			0xB7CC9D4D9EC0AE57ULL,
			0x431B196CE6F02797ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8DB1A3AA87CCB3AEULL,
			0xDCA8F4977A761F02ULL,
			0x8A013BDCA7C6BF36ULL,
			0x5D8DA7A81F334B45ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8218537E44F47DC0ULL,
			0x5D3F08067875A9B3ULL,
			0xB0E90E3164A89A2CULL,
			0x08E9FBF0A2CEA500ULL
		}
	};
	printf("Test Case 171\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF9D8479C148E0460ULL,
			0x97DEC0CC52E5D050ULL,
			0x52CDB58DB8939511ULL,
			0x60880E14FCDAF5EFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x06100C2630E797BFULL,
			0x08FCC9FEA3398F0EULL,
			0x7D9677211347515AULL,
			0x04AAF886B0D067EEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5331B3587243CC18ULL,
			0xEF7B687F22D6375DULL,
			0x15CDBBD59A26EF3EULL,
			0x7783C2B135DCFABEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDCF77E0C40A59E91ULL,
			0xA603663BBAECCBC3ULL,
			0xBBA0C3C257BA1429ULL,
			0x72DBE498B3262AC5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4C8FBF2FD9D067EULL,
			0xB371C2C83EC602AFULL,
			0xCBEEA41C16805D67ULL,
			0x1B7B6353DE2227C7ULL
		}
	};
	printf("Test Case 172\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2E442E6A902FB490ULL,
			0xBFE82C34726705B2ULL,
			0xAA2346EB8A27AC05ULL,
			0x4DDC6E218B6331A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFEA9051C50F7C46DULL,
			0x897B92CE7910AE48ULL,
			0xAF442E5885DB8F83ULL,
			0x0B6C1535FD3E89F7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x615467CAB25D58F0ULL,
			0xEB4BA5C64E3DA0F7ULL,
			0x845070D597A04EB4ULL,
			0x6B7540CEA083C856ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C742BB3A466FF50ULL,
			0x5EE80B6C9E878F7EULL,
			0x747B5DEAD56E0628ULL,
			0x25F16C4E5761383BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x657F07A7DF982C24ULL,
			0x08D52390D5C46362ULL,
			0x3188DADE6624BB85ULL,
			0x169BC00FD81D59FFULL
		}
	};
	printf("Test Case 173\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB36C5CB3DACA2C00ULL,
			0x2B8C4F0DFAEF0E9CULL,
			0x9150930342C7CF96ULL,
			0x54E5DA40604CC9F0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF1E7A26D6618E902ULL,
			0x05F9B54EE9855C9CULL,
			0x00CC838826631EDFULL,
			0x3474D9341957D2EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA859EF14FCEC42F0ULL,
			0xCDB63CE28A8DBA64ULL,
			0x212F9C55976A2985ULL,
			0x4D6E80C597B5EC3BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B3AA3D591B0C54FULL,
			0x81480ED3BDAD9AF9ULL,
			0x768D17CF6FDA7818ULL,
			0x321CFA4E1B9D0595ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE647F08CDBD3C130ULL,
			0xE1BB15271704BA0AULL,
			0x20519F8250680E04ULL,
			0x0116ADE262560AA5ULL
		}
	};
	printf("Test Case 174\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x412C5FDF38C62C10ULL,
			0x3E8F636BF742E864ULL,
			0x4FB46E7DB457222DULL,
			0x6F724DDD301D9270ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x331F47260321EBC2ULL,
			0xE389A9442F18B95BULL,
			0x2C3386A72B6D88D1ULL,
			0x4C976DAE8DD0EC60ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0998FFD9CFB896F0ULL,
			0x12231B4C625FC6BFULL,
			0x9122F994EB914146ULL,
			0x6333E69EBB6A1D2EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7EDAFA758642ED38ULL,
			0x97164C2ACC7962BAULL,
			0xAB7121EC4A50FD1DULL,
			0x2834056ABEF25B2FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB46A8036152851B4ULL,
			0x183D43BB54514735ULL,
			0x260E4F1030876994ULL,
			0x56395690C86F5EA7ULL
		}
	};
	printf("Test Case 175\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x80F173423B6AA970ULL,
			0xBF126C23EC2E4A3CULL,
			0x5614ED05C4528D75ULL,
			0x659C08D803B38A30ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3856F59729B631D5ULL,
			0x92D6E6C5D9737572ULL,
			0x2C0FCA2B0160760BULL,
			0x30B4114C973ED92CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x44A7FA3A75A21418ULL,
			0xAFD49912B41DAF1AULL,
			0xB681F42B7495D3A6ULL,
			0x589BAC4372F89E3FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2E6FFFB002E28DEFULL,
			0x22A1CAC8A14CE6BEULL,
			0x259ECF29570AF296ULL,
			0x32F52524B3B5B3DAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x19FF77CC8DA45BBCULL,
			0x348721C658A99333ULL,
			0x458DA2C63ED5BF9DULL,
			0x3ECA3516FB051A8BULL
		}
	};
	printf("Test Case 176\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34E4E49D31317470ULL,
			0x639962FC1F06649DULL,
			0x2F793AE6343DD785ULL,
			0x7203A6978B592246ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8273E6DFCBB7FC2ULL,
			0xAE408CEE1CFFEDF9ULL,
			0x813484491B9E6CB5ULL,
			0x28A31C76AA639C50ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A5CE91A26A73690ULL,
			0x5620F2028664FDD3ULL,
			0x6BF38C143AE06BEAULL,
			0x7DA5555E5D1D5D42ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x813DE857FBEABF91ULL,
			0xD57A91B0A4E1B558ULL,
			0x3BE69B2846297C0FULL,
			0x1F56C6C45799B832ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x56058C2189D04F09ULL,
			0xAD675BA1F40BF8FFULL,
			0xA99ADD222CF8FD50ULL,
			0x57B2FB0785EE9166ULL
		}
	};
	printf("Test Case 177\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F1E554E897469C0ULL,
			0x30FC97E2C0716643ULL,
			0x555C3D47FBC4EE58ULL,
			0x6749A4BB339B953CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE4FFF5765CDC0B11ULL,
			0x088358770BB5254EULL,
			0xB5EBB06AD107632CULL,
			0x6CF69E3355AC5409ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1419F71BBB8DB220ULL,
			0x874D1109F182612EULL,
			0x56222A940EC672CEULL,
			0x598E5BCB703B3244ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8C215FEF4E547364ULL,
			0xD4C24C55BA90BA76ULL,
			0xBD48C4284CA5B323ULL,
			0x7802D3DEC883A640ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x995185E01B01A39EULL,
			0x033247283A90ACA5ULL,
			0xAD44769EF75F506CULL,
			0x2D85C75C47388FD4ULL
		}
	};
	printf("Test Case 178\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x24A57E9F13D9FAF8ULL,
			0xC17A034F3756A9FEULL,
			0x7A647FC97C97F86BULL,
			0x4BE404684A673BAEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8497110A00A873BDULL,
			0x6C02AD667426CCE8ULL,
			0xE72228837C20A1E0ULL,
			0x1655E349CDFE810FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x62204CB0C5FFD520ULL,
			0xDA0F5B986946AC68ULL,
			0x941FDE5188B99228ULL,
			0x68875AAC3BDD0DA5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9453C39AA5C9D271ULL,
			0x6CFE8BE074EB53F1ULL,
			0x37A67BC19A461A92ULL,
			0x7E68A31A61E80BC6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7ABCFE3680C7E2DCULL,
			0x39D19082EE780A11ULL,
			0xB3D5726BDAC02D5FULL,
			0x665AC16398DBCFFBULL
		}
	};
	printf("Test Case 179\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2CFB5C6E2CE2F270ULL,
			0xC355B307A2FC08D6ULL,
			0x2623BBB0F3415641ULL,
			0x589E321A42AB1833ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x18C497065D5D53F7ULL,
			0x96729382A7DA803DULL,
			0x26A46B2C88EF94FBULL,
			0x3DC0F73F101DC5F6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD476DD1039A4DB00ULL,
			0x015ED0CCD16832E9ULL,
			0x1880C2543EB3C786ULL,
			0x49EB9510EADCAA9BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x29BF04239B19B232ULL,
			0x5F0216E0389A4D27ULL,
			0xA6D6567DA4331B6FULL,
			0x6F8F838B3F463FF6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x138C072975EB6C6CULL,
			0x1D48835AF9A564B9ULL,
			0x85042520E8AEEC33ULL,
			0x0656C638F04F417AULL
		}
	};
	printf("Test Case 180\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3BF34CCE5CEA2208ULL,
			0xFA4C7F765240B34CULL,
			0xE5C58936FAD4EDBBULL,
			0x643CA47A95311C53ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B24DA609154DDC9ULL,
			0x6B4ACA624AEC6BD9ULL,
			0xE78C8B7C2C96AC7EULL,
			0x20EDD64CEDC5CA1AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB43300AFE5FD1E20ULL,
			0xD2EF74E0A3AAB2F8ULL,
			0x622306EFC43F4900ULL,
			0x524A73D9DCDC1718ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1C9DAC48F3FCE5E4ULL,
			0xD12994D248C26D50ULL,
			0x3B16C642708C615FULL,
			0x760F5A84E2CF11DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x17A6FF3918E2E752ULL,
			0x3AD7A9F250972B8FULL,
			0xE351ADA04FD08956ULL,
			0x53E6906CA48289B7ULL
		}
	};
	printf("Test Case 181\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x189205F76ADE4040ULL,
			0xA1677EC78FF71C21ULL,
			0x2ED4125FAFE57C88ULL,
			0x4A1611D77A641E8FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDFE889CFE124EF77ULL,
			0xE18AC60E7FF79B3FULL,
			0x6B1BCA6A0DB0F2FEULL,
			0x790C1CCC7F0A77C8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD0116C663AA5378ULL,
			0xBF690EF7CA4850F3ULL,
			0x89A2DB22ACD54221ULL,
			0x6A03C0C8DA5ABF8BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89839C5036B6F2A1ULL,
			0x2F07C42B74429515ULL,
			0x227610A89194A388ULL,
			0x7034A1E02C79CB10ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6950B69211246CAFULL,
			0xDA226A49D74DF54AULL,
			0xCDA66BE4C95D8766ULL,
			0x2D9BCED60D68A7EFULL
		}
	};
	printf("Test Case 182\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8AD4B46C7EE211C8ULL,
			0x2A88F73B1F83A86DULL,
			0x0A16CA017EAA04CCULL,
			0x635CE2440115DB02ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x74CFF96BE9F1DE51ULL,
			0xF3BF6E04797AA613ULL,
			0x8FE6799FDCFC249AULL,
			0x689D1D190908BAB8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1914B4D2AA2A6E70ULL,
			0xE95BE9DB8D104A00ULL,
			0x54FAB4E88A26DE13ULL,
			0x6D20AABC0AEBACBBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5ECB1E7A643AC1DAULL,
			0x3B018C245720D975ULL,
			0xDE211F0C5184DB06ULL,
			0x547A5514B232781DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEBD856478702582FULL,
			0x18EF7981D577571AULL,
			0xE58882F85A131619ULL,
			0x354FFE5F7061E9DEULL
		}
	};
	printf("Test Case 183\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4182A75A7E4DFE78ULL,
			0xD270FC8491B35031ULL,
			0x77CCB4A2BAAF8901ULL,
			0x5B14FE7A85365598ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x532DEEC89A11F8BAULL,
			0xDCB50B718957A9A3ULL,
			0x92BE789B4425299BULL,
			0x3B2709F6E666CA17ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC39B656CBBC3D1A8ULL,
			0xC30F3B88E2638DBCULL,
			0xBF6D1E963F4FAA2EULL,
			0x53AA4FE6FD230039ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11B2E7C623075E83ULL,
			0x2B1A94CB122E2394ULL,
			0xF31F1AAEFF04431DULL,
			0x5D5BD91601420790ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x17E04B85C1442241ULL,
			0x3C7ECC5DE19E72B5ULL,
			0x8938FA04ACB7EB08ULL,
			0x08BEA634B6D44711ULL
		}
	};
	printf("Test Case 184\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD33B855B0B64E350ULL,
			0xC13F1C0B9D4CDDF3ULL,
			0x7CBC4B5ED132CC04ULL,
			0x6430E453FA7579B3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0F3F12600308534AULL,
			0x8292DDD07CA0A8D7ULL,
			0xF91DEE40329949B8ULL,
			0x1727266C40BE068FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x417296930C20AA00ULL,
			0x147F4A909E02EEC0ULL,
			0x90E113A9B865A92EULL,
			0x7FBE3014DE2D9FAAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3244BC8DDAFE2B38ULL,
			0x834B600D65E8A3CEULL,
			0x09ACB45FA73BD9E0ULL,
			0x230D01EACEDCC8A0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF81CAF1F157D1A92ULL,
			0xD9CA50A7F65BC222ULL,
			0x96899FF639F9EF2DULL,
			0x2E6B2CA189D01205ULL
		}
	};
	printf("Test Case 185\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x66D0D024C135D9A8ULL,
			0x100F0624A86F560DULL,
			0x3D6083D60B77C6C3ULL,
			0x6DF1E00174462F13ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6F94753F9AD044D4ULL,
			0x54E24D5598D319B0ULL,
			0x8C0A94C2AF8DE6C2ULL,
			0x730D1AC2E9BCC2C6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB87C245A5B022640ULL,
			0x8BBDC55834FA0DB4ULL,
			0xBCB4B3E103A970E1ULL,
			0x52C15CAFEBED7127ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x39AC1D08A4A02804ULL,
			0x54EF79218D5B4F0CULL,
			0x6DBE8693615A5923ULL,
			0x2B709D62EDA9F7B4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2E852EFFADEDC6CEULL,
			0x756AC8643073E9CDULL,
			0x518A68D1548947B7ULL,
			0x540E4EECF737BDD6ULL
		}
	};
	printf("Test Case 186\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6DD24EF27C87DE60ULL,
			0xFAA60AE5F254499AULL,
			0x8FBA9E536A13BD15ULL,
			0x77E9E4FCAF852360ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B786D3A3D898F74ULL,
			0x416E8DF6BAECEE59ULL,
			0x322245FA6675BC8EULL,
			0x47123959394BCA7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB9196D9797B24528ULL,
			0xC209B25595D8B3BBULL,
			0xE59C46E00CDF9863ULL,
			0x72B865C1C0CE7AABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8AE7A198D050000EULL,
			0x41B191BA4961A549ULL,
			0xCD2E9C77C6D76383ULL,
			0x3FD3123885518DF5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x34ABB2075E1B6F46ULL,
			0xEC20B369B93DCF08ULL,
			0xC8F570CEC22D7338ULL,
			0x4BB7EE3F8A5B2B19ULL
		}
	};
	printf("Test Case 187\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x752BE1C594F56DC8ULL,
			0x4E61CD7543672F68ULL,
			0x45B7385949492C0EULL,
			0x70E16E9EEA1E3E99ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3F58575B63A1C3A4ULL,
			0xA36EECDC7A739010ULL,
			0x15B6DD8CA5891989ULL,
			0x01439536872DC014ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC4A1574DA85F4FA8ULL,
			0xBA05F7B3E8B11E1CULL,
			0x17E5E77ABD7F8F29ULL,
			0x681E736A2938BB19ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9C7EC3E88E006C6DULL,
			0x560A5CC60DE92294ULL,
			0x05C059B3D6611F7EULL,
			0x3C5CE5B5939125E7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x043665E3F358364DULL,
			0x4BFC0F19F7F1F1A3ULL,
			0x61B02C64F3205CA2ULL,
			0x616DD3460376094EULL
		}
	};
	printf("Test Case 188\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFED00D2E6F3D4958ULL,
			0x5BAD35D93C2A56D3ULL,
			0xB0F26EF609703821ULL,
			0x70424FA6ED4A026DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4752A89E319F046DULL,
			0xC2A9E66353CDD72FULL,
			0x1E37E5F874A84641ULL,
			0x19EF3E0B1DA56036ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x776C7B9D57624558ULL,
			0xF3E922CD711BEC49ULL,
			0xFD21DBAB62A26D38ULL,
			0x45EF78506944CE15ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD00943F7B2ACC4BCULL,
			0x2215DD4D500A9804ULL,
			0x4231BDE1B2E18957ULL,
			0x0F0143B64EACE4DAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFB2447DAE40D4B25ULL,
			0xC2038C1117E7C0C1ULL,
			0x0059C6703BC4CD41ULL,
			0x0D985D3BF6F4A349ULL
		}
	};
	printf("Test Case 189\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7AA934BEA0466438ULL,
			0x2BB44F9B7C35630BULL,
			0x5B4F37C2482ABF63ULL,
			0x57404326BB393165ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3155123E1071FB5AULL,
			0xF703CFF388165F7DULL,
			0x9A70EA4D2128F7A0ULL,
			0x257F866064195C3CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2361D330A6A85D30ULL,
			0xAFCB0D55A7BF7F3DULL,
			0xC2000B84DE7E845EULL,
			0x45BD6DD3503C86B9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDEF8A60150577AA3ULL,
			0xEB1F4961DB2B109CULL,
			0xB659DFF13C1F07C0ULL,
			0x06E369D9802F8C79ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD3C5AAEE519D19F0ULL,
			0xE6712C71C8D0A4C7ULL,
			0x3515336CE1257EB7ULL,
			0x49040F99D918CD2BULL
		}
	};
	printf("Test Case 190\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x912B3827BA3ECEB8ULL,
			0x24A793700CDE7CCCULL,
			0x394A2A2758CE097AULL,
			0x50CD85D6D89A0ADCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5649FB90EC5BD73EULL,
			0x22A90BAA1CDBE7DCULL,
			0xF1317B95491ED2AEULL,
			0x3D098D65AAC2CDB9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF2D0FF4993378D50ULL,
			0x79801EFF32D3ACDCULL,
			0x7AD4A73FB2A6818FULL,
			0x5FA7D59CE27A734DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFEEAD7740B029905ULL,
			0xAE1A7FF8826BA60BULL,
			0x901E019B2739517FULL,
			0x002737E9B21CA646ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABAD4D6B301581F4ULL,
			0xF23FD4BBB444DBA1ULL,
			0xF31D1A5614222904ULL,
			0x44D81AA5DE643E40ULL
		}
	};
	printf("Test Case 191\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB637DF06B97DEE30ULL,
			0x00EE114EE4EED725ULL,
			0x9EB4940C2E30652EULL,
			0x6FC58069D928076FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9827F7280DE27E18ULL,
			0x7136E00AA9497E94ULL,
			0x21D5BCED5B734F5BULL,
			0x21EB32C2E96C98BFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAACFDE2D7E46ED78ULL,
			0x5EFCC70022542D1DULL,
			0x5A6660204B7BFB7CULL,
			0x7FAFD574458EA341ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7EA8AB348B5C8770ULL,
			0xE2A47C37A239152EULL,
			0xAB34425572150170ULL,
			0x6FA73E50A99C57DCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x603F695041FB2628ULL,
			0x6F1D5328E33BB369ULL,
			0x616833DE16146361ULL,
			0x604E8F1740D7B5BFULL
		}
	};
	printf("Test Case 192\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1529E230ED6FC7A0ULL,
			0x253106992D7D443DULL,
			0x057221573F41DBC2ULL,
			0x7A3076DCF8B95A96ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4A7B09DFD940398CULL,
			0x9FF5F345F251095CULL,
			0x0B11F86F00CC1695ULL,
			0x1CC12C08A499E4BDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA7BBEDD59826E590ULL,
			0x82FBAA4DF5807D65ULL,
			0x2509E1FB1F4EEFDDULL,
			0x41612F7A0833ED8AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA2A5E94F80C561D7ULL,
			0x6F9B1955FE470C3EULL,
			0x512E7BD72C69601FULL,
			0x082B0D5CFDB0E508ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1FB3A2829C082D29ULL,
			0x154EEA4DFDEBDCAFULL,
			0xB95B5A6C0A35E8FAULL,
			0x54E73D45BEC98E90ULL
		}
	};
	printf("Test Case 193\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE642822CA5BEBC70ULL,
			0x0BD1B96F8EA27EB7ULL,
			0xBD070FA8E18DF5ADULL,
			0x549B22A37B9CE578ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCEC1DFCB1F517018ULL,
			0x5EC2AF32C7C95D46ULL,
			0xBDDBCDD30A966B06ULL,
			0x4CF7B5510122FB30ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4A076F3BED4DA5F8ULL,
			0x4A34FCEC799ABE31ULL,
			0xC0F2F012263F445EULL,
			0x5D1D274D44733D87ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x399299F9FE85A439ULL,
			0x928422BDA8DC6DD1ULL,
			0x426A819DAECAAD07ULL,
			0x2032453E8139F847ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA94592F52E53BCB5ULL,
			0x9C9166778BDF897CULL,
			0xB2C13962DD6B2E3DULL,
			0x11C622A9620B8797ULL
		}
	};
	printf("Test Case 194\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCBE3032659143128ULL,
			0xC3B2A0595BEEF8BAULL,
			0xB0173FC535792B4EULL,
			0x5B16EF356BDF5E57ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6A9F3DF1C3AB70EULL,
			0x2D439107685025C8ULL,
			0x1B1CDFD404548389ULL,
			0x2115C98EB5308351ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1AD1CD3F02A1D7E0ULL,
			0x57C106DEEAE2B182ULL,
			0x1282BDD051B60843ULL,
			0x43C8F853DB7F83F5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94B0CAF1351B766EULL,
			0x151FDF38EB04BF7AULL,
			0x59704A4DDBE0E0C3ULL,
			0x65999DAF44D957DEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C285F6D50F064DCULL,
			0x3AF2EFEFCE2502CFULL,
			0xE5FD888ABD5D0641ULL,
			0x238113C148F5CF4FULL
		}
	};
	printf("Test Case 195\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF956CFC86B34F670ULL,
			0x484C1F915B2B48C6ULL,
			0xC7F5E5400243652DULL,
			0x516831C1B55CEB7EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3CB4A0F5D74AE935ULL,
			0xF28571004E4850EEULL,
			0xE340A65F97A8E0BAULL,
			0x07F229E2BBF0BFBCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x965935ACF0606368ULL,
			0x2D96A8B6A2845AF7ULL,
			0x32AD8FE0E6B49745ULL,
			0x51EAAFEEA8A6EDABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC30FADE8BB463690ULL,
			0x12CBE427B2D6F991ULL,
			0xBC4FF7D735B60071ULL,
			0x5E3AD7AE7FF574B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61E1CD17432AA51BULL,
			0xDD71CF5C7DDC66C9ULL,
			0x134F1D6CB875580EULL,
			0x52A17152055D7EADULL
		}
	};
	printf("Test Case 196\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5D360D112C10EA38ULL,
			0xE290234DE3F87CD6ULL,
			0x4380B188C64114B3ULL,
			0x504BB461CACD8E14ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD914AC112424F353ULL,
			0x872758F8CD4C8694ULL,
			0x3F81C379773B433DULL,
			0x75D81CE74DBE16E7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x179F47F382B2D9C8ULL,
			0x2D5FFA062D6B2699ULL,
			0x138CC21CF84DF49CULL,
			0x4F491B9654517203ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x74EAEC5D58CFF472ULL,
			0x1157DDDD464A3F64ULL,
			0xC46DC0B36156D972ULL,
			0x056F9988BBE4C459ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1F36DCF087F0C2A5ULL,
			0x6B658DC3949AE74EULL,
			0xE96335BF43C0D38CULL,
			0x4DE2A6CCECC9F0F5ULL
		}
	};
	printf("Test Case 197\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF570A4B6D740FA68ULL,
			0x7D6C0D39CB8B81BBULL,
			0x4ED8EEBBAB787D75ULL,
			0x4DA0F50618FE0EA7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x00EE483E03262A3CULL,
			0x8D2E3C30A3183A33ULL,
			0xEF93E9D2ED5E4326ULL,
			0x4E1B618ECE4ED658ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7EF8D70BE22B1A8ULL,
			0x341F0C952DD5F9C2ULL,
			0xD58264AD55969943ULL,
			0x785EB661961962BBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B9EC52A24BE88FCULL,
			0x41A338E40418126EULL,
			0x4994DE5F0081C11CULL,
			0x75B39F7574E36497ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4F5E92A82B33C91EULL,
			0x1829743E70403E78ULL,
			0xB5AECFE05CF495A8ULL,
			0x7CAED19989CECAE4ULL
		}
	};
	printf("Test Case 198\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC2A0E4E160F9B000ULL,
			0x886D7BBCF5592D2DULL,
			0xE96C805ED09A312CULL,
			0x636B26BB561BAC33ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7394E1F81984BA38ULL,
			0x48117260210BA818ULL,
			0x9DE12DF54FA0A792ULL,
			0x27DD177E6DB78CD5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBAAB56E1C6434B78ULL,
			0xB5A26D59BFE32BF3ULL,
			0x15A2EAE12C703EA4ULL,
			0x79259C08905BEC06ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C33CDBBF390BF4CULL,
			0x42EDFA4E62ED338AULL,
			0x0B3A2D3679AF64DEULL,
			0x2CB46BE7607471E9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B3D5C23E6B8E111ULL,
			0x5D59C6E0144E5C6DULL,
			0x1C50913075FA786EULL,
			0x51D0D5501301E81EULL
		}
	};
	printf("Test Case 199\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x064AA8C92D27A7A0ULL,
			0xA0C0FEA9B53B3A9BULL,
			0xE341D60F1DE458C7ULL,
			0x5871A09FADCB4364ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6FFEE6DE8C7F4CFEULL,
			0x86E8EAEC1D0C9B0FULL,
			0xCA4BB1F7BC779E8DULL,
			0x719F3C8339144D1CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A0B227BB8F67C18ULL,
			0x90A5E846E37EC29EULL,
			0xB51BFDF489ED93BDULL,
			0x50F8250D2D2C1D30ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x815B1414B6F7DC05ULL,
			0xD23F90D546A5C06AULL,
			0xBE38CCD47F9354F0ULL,
			0x3CA4874C7FEC7EB5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF7AE8E86B84BADE4ULL,
			0x1F96A341D97B7B30ULL,
			0xE94FF8D8DE0BC02FULL,
			0x0F9ACAE80E677621ULL
		}
	};
	printf("Test Case 200\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9BE6AD15E1F590F0ULL,
			0xAEBAD053CC61C8E8ULL,
			0x8EC24C10F762B78CULL,
			0x4D17EC814AEAA22FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0F511DAF27D9C643ULL,
			0xC50A223C866A2107ULL,
			0xC2902CAE234C2B62ULL,
			0x74D085DA38664493ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9CE833D0B5D88FD0ULL,
			0x1ACA5C06265DD725ULL,
			0xEBFDE95A84AF585DULL,
			0x57608E9215F2FA9CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEC9E948A1DE81BC9ULL,
			0x7692CF3935801C01ULL,
			0x8D2DFC45D2EA529BULL,
			0x35048916105EA54AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC44720005834E4D4ULL,
			0x4A2CB6A3C30FFD0CULL,
			0xB7E95BC40202B4B2ULL,
			0x0A3156B686F0BE14ULL
		}
	};
	printf("Test Case 201\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA8C1F7E9F10F4EB8ULL,
			0xDA8C5BD5F4709547ULL,
			0x86F70631FC348AD4ULL,
			0x66BBFAF25B7DB0DBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3F7FDE61B77B7056ULL,
			0xDFED0797ED289C22ULL,
			0x6062DF34A3C2682DULL,
			0x77C8C884127D487FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE030BBA37A4434A8ULL,
			0xCBAB83648FF03929ULL,
			0x43BBF37DC0E774FDULL,
			0x48A0331025BE0926ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x44611E7DF813D4B2ULL,
			0x48A75F552E9F6232ULL,
			0xB88C9488BD2597CEULL,
			0x5CFE99E74ADF42A7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x14B474067EBB2955ULL,
			0x7DB69A21F0477F0BULL,
			0xE77A4F788085A4DAULL,
			0x319711C5B0FF9F2DULL
		}
	};
	printf("Test Case 202\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDFE43E3623C983C8ULL,
			0x9E4E95D483401D82ULL,
			0x785DBBD533DA8684ULL,
			0x5E1E49C98A574B1BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE919F45F49C2D0E7ULL,
			0x795FDB728C56704BULL,
			0x66AD129BC093E208ULL,
			0x49230AF611539368ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x179DC1A05CACD2A0ULL,
			0x9ECCD300E3393579ULL,
			0x1F92542B40BCA740ULL,
			0x50A1368488ED7111ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCE1C5B379824607FULL,
			0x4294EFAB55AEBB52ULL,
			0xEE0C441345E1D712ULL,
			0x6A324CE6EAD04D79ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4D184148F65A3941ULL,
			0x117C08C965AE4A3FULL,
			0x0F0BA4E89E623BBAULL,
			0x539AE7D9B4057EF0ULL
		}
	};
	printf("Test Case 203\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2DFA9A8A7AA3CC58ULL,
			0xCE933A12A72CDD24ULL,
			0x241E817B26751909ULL,
			0x7914D81A7A8EAC89ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3A53F3DB0575F8A6ULL,
			0x7A43737B87C86C7AULL,
			0x0F0CBB3F6F530784ULL,
			0x54CE860E887A9A8CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x919F4D0764F94AA8ULL,
			0x11C29C9A5C8F484DULL,
			0x7F2C7ABF2E6FF9F7ULL,
			0x6B87659BEC872ECBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE9B73D8C24FF39A0ULL,
			0x612E7E76BE3F07CEULL,
			0x35128B00F080C1CBULL,
			0x4E514FFA362DF4B5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE207DC67A1D160EFULL,
			0x2E1F200FD52E1071ULL,
			0x50CB857961F164B8ULL,
			0x5D07057FA8A5E723ULL
		}
	};
	printf("Test Case 204\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7769AE7C73AF2068ULL,
			0x59054246F4EAB172ULL,
			0x213EAD2787848456ULL,
			0x78EE49F1D641E15EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x733B8CE3D5AF2258ULL,
			0xC3BACFBB23E298A8ULL,
			0xCDF1E2A678ECDE71ULL,
			0x3CA999B4C7AFAE69ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFD69252C91EC83C0ULL,
			0xC3533AD2DD286D5FULL,
			0xDD2114C387AC7528ULL,
			0x5787CBD14589DEDBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x084F776F227BAFF6ULL,
			0xE1E4C0B3D3611C5FULL,
			0x48B6388176FF0148ULL,
			0x5BC60C23D7222822ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9F75AC860DE27387ULL,
			0x93C5F0C8B2892417ULL,
			0x6FC091B66336F636ULL,
			0x256A4C114F8A73B7ULL
		}
	};
	printf("Test Case 205\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E29E3474BE2BAA0ULL,
			0xE28B3CB71729698CULL,
			0x79673607894D4B8EULL,
			0x427291A43B766748ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF2BB77053602912DULL,
			0x4A9CA5EFCC9BAC30ULL,
			0x990A636402869DFEULL,
			0x462C93D4CB4A4DCFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA5A37FC003580210ULL,
			0x4A7F32F378F474D1ULL,
			0x2E57EC2D88938466ULL,
			0x67D7764B0FDEBABFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5EFC430F7CFB02FBULL,
			0x3ACBF12CF09D3C52ULL,
			0xE7FF8B6D8A6B57D3ULL,
			0x12B1EC3B0592783DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x413B7432BFF1E3F7ULL,
			0xFAB217EB6E5BE8BCULL,
			0xB9F7341A29165DF8ULL,
			0x7D6BD1720103C29EULL
		}
	};
	printf("Test Case 206\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF5DEBA9A5EF22360ULL,
			0x2AFCCDFB05BCA695ULL,
			0x27B667EADC05F6B1ULL,
			0x73E97DB9A9CD20C0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF8337986E4247852ULL,
			0xE6E88CA9F23DF777ULL,
			0x18A91B4CB41FDDD7ULL,
			0x071E093A6782D8BAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01E7EA760C208D40ULL,
			0xC3BD5EDB0EEE6C47ULL,
			0x3C19AE8AC8B34299ULL,
			0x62F7977FFB955493ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB05C897D359F3BC4ULL,
			0x64112EB4A5C45B86ULL,
			0x23BE7BE2CE3BA7BEULL,
			0x7880C3C90ACAE25AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD093CCC7D514A57EULL,
			0x10C8874531D380F8ULL,
			0x186FCB2941CE4D59ULL,
			0x6B28C126A2BE1C12ULL
		}
	};
	printf("Test Case 207\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x982BCD5A677A1D88ULL,
			0x5A2944F1C3764BC5ULL,
			0x7278F8C054360031ULL,
			0x7B489A741C48B9FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFB72D14B98283756ULL,
			0x4A7D3D602CDEA8E4ULL,
			0x0ACFEF1BD48FDF48ULL,
			0x00600F6011C095A3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x556E46D8FB87C3B8ULL,
			0x00076AAE8B8EB624ULL,
			0x27A96426B9BD5F1FULL,
			0x57C22C6BDF9C4D90ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x871C6703D41A2764ULL,
			0x043BAF0F53E09CC2ULL,
			0xE33F033D0BC4CA39ULL,
			0x02268494EF874D83ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x257571EAE3EEB52EULL,
			0x0D5FBE0508954EFDULL,
			0xCA53CC8730C6DE1EULL,
			0x60AE457ABF40914BULL
		}
	};
	printf("Test Case 208\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x98C96359D9DD4BE8ULL,
			0x655C20922614EC37ULL,
			0x5AE9E973850F4C48ULL,
			0x4949DDFE48D4A4ABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA39EA9826AACE56BULL,
			0x20840F7205762820ULL,
			0x28A819ACD9ED7E0AULL,
			0x5D8456205615856DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6F5CF4D0D18CEF8ULL,
			0x6C8613B461A3B3D5ULL,
			0x19850D251B37A69FULL,
			0x5C0F1126308A14E1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9213101FAFFCAC0ULL,
			0x784DA272B7081461ULL,
			0x14C0325FE25A1038ULL,
			0x52311D411BD1BD1EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x398EF6448421676FULL,
			0x649D607CA0B54668ULL,
			0x00CA599547777E75ULL,
			0x6B082605A4254085ULL
		}
	};
	printf("Test Case 209\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x57EB3BE8FDD25810ULL,
			0x6E7ACC1B0B50AB36ULL,
			0x13951E426605E8A2ULL,
			0x414E2B2799B5B798ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x59F5D975CB23E581ULL,
			0x729DB925046ADF1FULL,
			0x34BF361B2D4A8BD0ULL,
			0x6E845C27852B1EF0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x724E4804BD2282C8ULL,
			0xD0437655A5F12423ULL,
			0x3F318F0685EA449FULL,
			0x79B435AD7CE150BEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE7B396796CC2ED2BULL,
			0x707644C68EC86FBAULL,
			0x3351AB5375D06F1CULL,
			0x40E169A0E75EF7C4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x905724A6BDEC1018ULL,
			0x56E29C87A477B1E1ULL,
			0x92F56CE0586BE730ULL,
			0x532186A0755ED1B5ULL
		}
	};
	printf("Test Case 210\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x255BE1A982B432D8ULL,
			0x1FE65618B4E988F3ULL,
			0x410B2546B0A27E22ULL,
			0x52663DF59E992AD4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8CCD9A727AFEA7BULL,
			0xE18AC6F3045FBC7FULL,
			0x5CF03671749E9523ULL,
			0x5B463010735F7ADAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x808B2E382A9AC848ULL,
			0x95E1204B6BD9AE5CULL,
			0x790ACD6CE9BD5BE1ULL,
			0x5810F40DE3384277ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDAD02ED75E1946DFULL,
			0xF6EA5BD58835AD9DULL,
			0x66470938D2560A50ULL,
			0x40EAFF7765221DDCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF8C4496D3F15146EULL,
			0xA6E641DB836E0E89ULL,
			0x02DF365F68DD54D2ULL,
			0x508A29339629AC08ULL
		}
	};
	printf("Test Case 211\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE6276F82DE556A18ULL,
			0x87C8080AFBCC66D0ULL,
			0x8B20906677AB0AF1ULL,
			0x4B9813B775DD743EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x79A2FB5863957888ULL,
			0xD34AF148A31623ADULL,
			0x67D8B02C1D5CDE7BULL,
			0x10E5977502B215B6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9FC4AAD5070D86C0ULL,
			0x797A359D8BA26E0CULL,
			0x2D61145435681038ULL,
			0x43937950377C40CDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x744B2DE87BC313BEULL,
			0x339728FF1B470F21ULL,
			0x2ED32A9AB1E06B12ULL,
			0x6064D2B095FFFD00ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x447599FA2DEB95A1ULL,
			0x67DBBD9E386A8230ULL,
			0xE6AEFDBFF9E645F2ULL,
			0x03973239099E6175ULL
		}
	};
	printf("Test Case 212\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x74B7EBC3B4BB8998ULL,
			0xDBEECDDC7F6E2993ULL,
			0x04B8F42DFA75C4BFULL,
			0x6111A6629FAE28F9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x43DD2EE9EEB3B424ULL,
			0xD1D743135FAA6823ULL,
			0xEB0E0575554F2E29ULL,
			0x2B7AD1830924093FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1818D3FA5AFE420ULL,
			0x6FBE87A6CAC4BF9EULL,
			0xDE7EA2FF68D9ADF2ULL,
			0x514DDC319FC0538EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x191982E1CEA78211ULL,
			0xFB867786E5E410E1ULL,
			0x1AE650DAFA2393E7ULL,
			0x5D6243DBCEA4661CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFBAC46446A3D9356ULL,
			0x1C343BE722425BD2ULL,
			0x3161B8A432F0503FULL,
			0x18EB3CC67BFBA5B6ULL
		}
	};
	printf("Test Case 213\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD977F9975513B800ULL,
			0x428A77D2A5C82D57ULL,
			0xA142CD7E0DB6F0FEULL,
			0x6DD2B6CC55F9C8A7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7711F4FA652215E5ULL,
			0x7CDB7EE2606E034AULL,
			0x93C812E6859BCDEAULL,
			0x10852F8FD1746905ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5F5E98D5714D14D8ULL,
			0x60549F65AEDB53D7ULL,
			0x5E7E89248A1D1190ULL,
			0x47075E5BE45DD398ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF4A71B7298ACE88AULL,
			0x2BD28D00ABA2D719ULL,
			0x42EB3576EB1834A3ULL,
			0x4A798F74628668E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4F9099D325B8D614ULL,
			0x3E2C9AC7F519B392ULL,
			0x13E27F9AA002CF79ULL,
			0x5D69D7F9745E5DC8ULL
		}
	};
	printf("Test Case 214\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDC69A173E0A9C9E8ULL,
			0x6CF9008FE1806160ULL,
			0x13270F573AE6D915ULL,
			0x5AEA319E4219B664ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x22BC51ED87FFE3B3ULL,
			0xF7B5DB57E5D4155EULL,
			0x34631A916D3C46ABULL,
			0x2BE9BBDDE2272CF9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A4E8B015277EA70ULL,
			0xB157BC3CE1234276ULL,
			0x67BE53149B6D4B7DULL,
			0x4239D9A41734B30BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7C1BDE73148579B5ULL,
			0xF8BDE50EC6231ED7ULL,
			0x0B01C093E6846438ULL,
			0x3128E2A63453D941ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x351D0835FD8CAE12ULL,
			0x50E931D8FC392195ULL,
			0x3434DD7E68D831E0ULL,
			0x5295D2C3EA0F9412ULL
		}
	};
	printf("Test Case 215\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xECE4A077B51B3678ULL,
			0xEE5B84AE866DE615ULL,
			0x35E0016BBCE6F335ULL,
			0x40F867394C7A8EA3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD030E2B6F729C792ULL,
			0x4C94639C8DA33DEBULL,
			0x91541F0AC5D35EC1ULL,
			0x762D2B17B5B813BAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x133DDC6E3CC20E38ULL,
			0xFFF7A6A5DA7413CDULL,
			0x737D8248185976CDULL,
			0x49ECC23A2D3E221AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2D409AD21754D799ULL,
			0x8D8E1A2F52B1ABF8ULL,
			0x07658CB2DCC9B0E0ULL,
			0x74D73C832E102946ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x954EFCF576E56933ULL,
			0x6E773C1BF838D7EEULL,
			0xD9C128C5974A950EULL,
			0x6B0776BBED9EBE4CULL
		}
	};
	printf("Test Case 216\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x08CB9C948484E9B0ULL,
			0x74AC234B3BD90760ULL,
			0xA05BAD29E94C2394ULL,
			0x760F4893614FD9A9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6E4BA3E01F92AC25ULL,
			0xD11DD1AAE7BB221FULL,
			0xACC4DC22FA65040AULL,
			0x0344E0B44B183AF5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB2DAEF5653E3B838ULL,
			0xB90AAEB7DBCCD450ULL,
			0x27795685EE9C7027ULL,
			0x7FAD9208FDA19D0FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7D5A60B4BE190708ULL,
			0x4A7A710B6969C309ULL,
			0xEEEE2BD7720C2BF6ULL,
			0x34F61D8D01C1B595ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67756C2ED0C9F99FULL,
			0x8E8C17660EFD60E9ULL,
			0x6E8EB55110C7924FULL,
			0x2DB23AA0792C9D7EULL
		}
	};
	printf("Test Case 217\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x49B63B92DC3A67D0ULL,
			0xB4115DD34A806DC4ULL,
			0x845FF9EA4D433345ULL,
			0x7EA91C5B7EDAD441ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1A6AB6C84FE174CULL,
			0x82802552881905A4ULL,
			0x9382B5A5A91E6EC5ULL,
			0x39B161B421F6F56BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5499D050021AAEE0ULL,
			0xE8CCB022ADDD2F65ULL,
			0x06B25EA257F801FCULL,
			0x5EECF9F20B302320ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x93DFD17FD472E4C4ULL,
			0x3E91692D6B8AE127ULL,
			0xF30AD9EF17C560E1ULL,
			0x01619CC5ED498238ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7CA3601BDD2BBCB7ULL,
			0x3B0F3DE9FE0D0FFFULL,
			0x61F963DD8E8EFC52ULL,
			0x2B8613338D505947ULL
		}
	};
	printf("Test Case 218\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x29E137E6BD5260C0ULL,
			0x9131A9C3E571F34FULL,
			0x3F86D6EC2FDC6D4DULL,
			0x636E9FD80540BF40ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFD6D555ED8943DE1ULL,
			0x5EEEB1994160680FULL,
			0x6AC65D98F9B9B114ULL,
			0x648E8176F8BB6FDFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6063F9FBC390A68ULL,
			0x26D097D6100AFA0CULL,
			0x44F8DF74E9145F09ULL,
			0x6F8ACC7146D15DCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x33534DAC6831E295ULL,
			0x1F2D9CE919BF34C5ULL,
			0x65533F67604725F2ULL,
			0x40AA91973ADD80CBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B3CD9BCBA2D8A71ULL,
			0x06471FE605D49DB9ULL,
			0xCAFE1562A4DE7F94ULL,
			0x33A3F34BF301622CULL
		}
	};
	printf("Test Case 219\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCFB4DABA3E9354F8ULL,
			0xAE667E89E907588AULL,
			0xF5EEA8729BBA23C0ULL,
			0x4FE6BC4BFCA208C7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6ADE333A76406440ULL,
			0x71CB1E704196B32AULL,
			0x13053740648A8DB6ULL,
			0x18D6C3D3778D58A7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x93DAD1A3A2030B80ULL,
			0x3C849026A7C91C27ULL,
			0xCAC3618BD961D603ULL,
			0x614ABF28C092532DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9199F1142A3BA91EULL,
			0x99AF5E5DD38B2D2BULL,
			0x0B95974AD597C43DULL,
			0x0176F9CEA674C63CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x21204B34DEA6AEBCULL,
			0xDC68C05FFF804546ULL,
			0x3EFB540F9D8C9F43ULL,
			0x7765271054692B90ULL
		}
	};
	printf("Test Case 220\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x970DA32C98FA94A8ULL,
			0x2604EAA3E781C891ULL,
			0xD154436DB1510A85ULL,
			0x72B1695C6C3B9963ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEFC2CAD8C306EC13ULL,
			0xC20362C772FB7156ULL,
			0xF9500F47CBCF598AULL,
			0x7D2CE17D8FAED023ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x08E101FB0E4592D0ULL,
			0xF45D42D011449CC4ULL,
			0x2DE39003095B1135ULL,
			0x54C28AB63099427FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x01A34BCEB3DE4E96ULL,
			0x0FD073A9956E407FULL,
			0x137C406D96872398ULL,
			0x0FC75FE2DF2D8B91ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA983BC6187D5E897ULL,
			0xE427F61B73E3CDCAULL,
			0xD4E7AB4BCDDD23F3ULL,
			0x45BE55D70A46217AULL
		}
	};
	printf("Test Case 221\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x764034298BE80910ULL,
			0x0D738674273259CBULL,
			0x399FE91C59ABB878ULL,
			0x4ED71834F1D91784ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x05A78D415172E2D4ULL,
			0x4070170FE349CAADULL,
			0x2F91CCBAF0328C28ULL,
			0x76888B385C69F8E5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x154C0B56E3B78038ULL,
			0x775ABA4744EBD853ULL,
			0xAFDE9D395FCE611BULL,
			0x485D1F1936158799ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9D50BB9335D27DDBULL,
			0x499FDFAB68C11BAEULL,
			0xDD589D6E4886F842ULL,
			0x2470433C5FB510A9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x356CF32ED150CB92ULL,
			0x721C7C60F19CD902ULL,
			0xBF7EABDEEE779FBCULL,
			0x43ECF0305B3ADFD4ULL
		}
	};
	printf("Test Case 222\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB85F0E472C8C71F0ULL,
			0x82CD3337FCCC76A4ULL,
			0xE13AF2D6E98E8AA9ULL,
			0x46D7021B951EA854ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFDF6A71F5FB57FEFULL,
			0xC1B559B7D3FB99C7ULL,
			0x3B78B3F0F3124C06ULL,
			0x43E77CA6CEFF91B2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFBDBCEB3205BE8D0ULL,
			0xCEADA4E147143B0CULL,
			0x3CA4476CA95A3D40ULL,
			0x668CB8376D5FA20DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1C3AC2ED8035B779ULL,
			0x6A1DF163918399F5ULL,
			0x79CB942F04CF75BEULL,
			0x2C3979A3363F97BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9819EE61D49146BAULL,
			0xC9CF21797926C527ULL,
			0xFC9213321EC134B6ULL,
			0x46F8C60244F3E40FULL
		}
	};
	printf("Test Case 223\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9EB1BF76CE9DA568ULL,
			0xF966E054808C546DULL,
			0x2EAC9D174E2EFEA8ULL,
			0x72E13DD54605D56BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5D69421CFE957480ULL,
			0xBD746CD4186D867AULL,
			0x63639136F438896CULL,
			0x37246AAF9E0B7CB3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5191647800729D50ULL,
			0xD46536C5B882F353ULL,
			0x02D5F1BA688D4475ULL,
			0x7DFD036380EDF40AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x238346830158E4C4ULL,
			0x0E0F852E8F3BE1FAULL,
			0xC30C459338079543ULL,
			0x1C558596508D1DFEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1C25CADB9CFF4909ULL,
			0xAD20448D5EDDF9F3ULL,
			0xD3CED7BBFEC2A190ULL,
			0x45CDFC75F2EB9A4AULL
		}
	};
	printf("Test Case 224\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA209DC8F05C05438ULL,
			0x3B6D2E6A4AF564E7ULL,
			0xEB9553E4C52F6B3AULL,
			0x43C37A7B3DA61B3FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x503A60D4F8A43644ULL,
			0x8E2C310672BCB299ULL,
			0xAB324E8FEA70B577ULL,
			0x2618CBDE93A55A41ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x47143C723DB9DB40ULL,
			0x48999D4138E5A94EULL,
			0xDD97866885C2500CULL,
			0x6E0FEB2E485953A3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x062437B475310995ULL,
			0xA4EB0E47ACC3FFE0ULL,
			0xC94ED849C01FF2DAULL,
			0x3725BFDDB9658B2EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA862E1CE546D2CD9ULL,
			0xDA3823ACEDDFC7ACULL,
			0xE3FD509E8FC93795ULL,
			0x07DDE4E5CA6B73C4ULL
		}
	};
	printf("Test Case 225\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34532CEABD02B728ULL,
			0x51D0DE7723C2F1DFULL,
			0xC6B338C667EA8926ULL,
			0x7CCA3809B747B12AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDCE9C406C538175FULL,
			0x24867BD5462F2501ULL,
			0xE3C9B5A55802B63CULL,
			0x589B210259141C8CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x88A7C40FBB9069E0ULL,
			0x7BC50159B2D9D94CULL,
			0xC0FCA8DE7BE63897ULL,
			0x672D9D93186D70AFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0750A65E111C7188ULL,
			0xE60E4ABF0749F4B8ULL,
			0x27C35FD836DC3654ULL,
			0x1588532DC80E853EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4EAE612F7D0D1279ULL,
			0x297794D404AFDE45ULL,
			0x10ED0C414DFDC8B5ULL,
			0x57501385BA8F10BDULL
		}
	};
	printf("Test Case 226\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF861A09265B02CA8ULL,
			0x86180F18FCB8B0ACULL,
			0x4EAC226CC474CB20ULL,
			0x6A78FA6B7FF77409ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA3E2393C1A495A7EULL,
			0x2B47EFC30070D689ULL,
			0x99542BD43A228BBDULL,
			0x74DF0731F0A46EECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x67FA88F48E7689A0ULL,
			0x1662D027F4F2D64AULL,
			0xC6BA44A39DBCB2F8ULL,
			0x5C332D41623AD931ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4CF31D29C018B880ULL,
			0xFE1B3C8429E227F8ULL,
			0x23D44A3DEA5A23F5ULL,
			0x74543B7A5F2105E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC841EF7E836F3A22ULL,
			0x7C8E8B90422FD212ULL,
			0x2D53DEB37BA31A59ULL,
			0x2B4A7A8C1D707486ULL
		}
	};
	printf("Test Case 227\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD1FCEDE42C62A3B0ULL,
			0x7923463C13D7218EULL,
			0x152DA57818EED814ULL,
			0x4E282D504846313AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x46C941D790F27C32ULL,
			0x6344172375764B35ULL,
			0x9C4A438D107790A0ULL,
			0x71F576DD1BBD02F9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8E02F2D7E3322A08ULL,
			0x562796813BEEC4D1ULL,
			0x2BD7DCFFE7965C56ULL,
			0x59A42B6A55F69B11ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x13E1A7EB4537D7F6ULL,
			0x4086D398C5CB1877ULL,
			0x19953B5652FB5EFAULL,
			0x545967668AD050CCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA62ABFD2636B5AA8ULL,
			0xFB32C9AB4BABD2D4ULL,
			0x433EF73B34AC6B5DULL,
			0x4113C9F28F41C3ACULL
		}
	};
	printf("Test Case 228\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3A838EE5D0BAEFD0ULL,
			0xE40EE6332F880B43ULL,
			0x30E14764C85250B5ULL,
			0x58412A38F3342987ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD771BE7EA0F6C465ULL,
			0x0FF69AB520CE2BB4ULL,
			0xE1824299896F3792ULL,
			0x17A133215C121ADAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x24B5E56F40025B20ULL,
			0xA65F0B973B794620ULL,
			0xE6F7F2119ED22FEDULL,
			0x6709FDF4F4AE261CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x304458A6C44F73E9ULL,
			0xA37B51E86536171CULL,
			0x21C776C5281166F3ULL,
			0x7D11DD9618A6DA38ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCE62DBE92CB16FF5ULL,
			0xBB0AD032F4F3DF1CULL,
			0xF9FD7223D83E28E2ULL,
			0x7CB8AADBD4733B5FULL
		}
	};
	printf("Test Case 229\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x60ADCDD0A5B0D4E0ULL,
			0x1A71B70F1DD41733ULL,
			0xFAD6DBC662D4AC81ULL,
			0x7025A443F9ABDDA9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x127135BA0B879EFDULL,
			0xC950411AA04D8C14ULL,
			0x6BD280E609E904C3ULL,
			0x49A6B0D6966A22F3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB824AEC98F0AC620ULL,
			0xF1E5F7292F5D495FULL,
			0xD6B761D43F923E49ULL,
			0x4887AA0F9116BC2EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC86B4390EFE9A4DAULL,
			0xE6CAD7B01E5FAF46ULL,
			0x5213811A8A8DDF17ULL,
			0x1F0610EB270DC606ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x41B2CB9F626B4979ULL,
			0x91217457548FB7F6ULL,
			0x794C4FD5E436E611ULL,
			0x473B8F23BB4682B0ULL
		}
	};
	printf("Test Case 230\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x96B67E7766B67EB8ULL,
			0x98FEF179740EB8B8ULL,
			0x43CBBDFFFE91B092ULL,
			0x46EF79083ECF4556ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x75725265BBF01DCCULL,
			0x9721C6F51E5BA083ULL,
			0x2AA2D7282537D1B1ULL,
			0x5D9D7227E3F59F73ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x585DA529EFF16108ULL,
			0xB503C89D37BBC828ULL,
			0x72EBAF88BBCA0F47ULL,
			0x777B60E8F59D9854ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC1B34555A7140A5ULL,
			0xC465664BE740CE30ULL,
			0x7101DB7C32797E9CULL,
			0x6460ADD97AE73C7BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB6F6CF2CD7B734BULL,
			0xB0B8B011C52D3EAFULL,
			0xEDF588B2D7FF8088ULL,
			0x7D1D836E33D5554DULL
		}
	};
	printf("Test Case 231\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x474D4C859A91D6C0ULL,
			0x7D7974436C8DA123ULL,
			0x476725A8D2D72D8FULL,
			0x5D03E751CA80AF16ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x21775A8A18AA514FULL,
			0x0544A8A58C426985ULL,
			0x2057AEB5DA2607B8ULL,
			0x619EDE089EC311A3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E84145DFAF9FDD0ULL,
			0x824EFB74F41AC74EULL,
			0x400F8252B29CC484ULL,
			0x5945E8551F3E42CFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x561C856C17A487E6ULL,
			0x19CD9535CD418D22ULL,
			0x3D55184F98800A80ULL,
			0x35787FFC0C65EDCFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x782A301DDFFCC9D1ULL,
			0xB043806E5AEF325BULL,
			0xA664B2E8A567533AULL,
			0x58AA301A61E9370DULL
		}
	};
	printf("Test Case 232\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x38AE6488659BA3F8ULL,
			0xA2DFF045334A4B96ULL,
			0x097F250AE1CA8DD8ULL,
			0x60BF5C0907DD56FAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5DA15392A4218786ULL,
			0x87E3765419A2F307ULL,
			0xED10899DC6A0A368ULL,
			0x4A9C0764B080BD18ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC3EF3E49F56B3608ULL,
			0xFD0F3DC5505ECC64ULL,
			0x3CD563B61B11B404ULL,
			0x5918DCB562161662ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8C4C68711CD11A6BULL,
			0x166D716646975F7FULL,
			0x79B51E9EE95D696AULL,
			0x110AFCA4C4355FFCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0504774ADF53FEF7ULL,
			0x1E200CD6AD2DB77FULL,
			0x9198C952A3080524ULL,
			0x0A6AF035BEB77085ULL
		}
	};
	printf("Test Case 233\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x571BCB95C0F41318ULL,
			0x06BC18B59CDEB5BEULL,
			0x0D40EBCB9690E05AULL,
			0x5B146CC5E16B6DB2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA32F2E362DEE70AEULL,
			0x7BB451049DD2B064ULL,
			0xC5B48212969D037CULL,
			0x6A6A27B017646DC9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF93D00BD4CDC2338ULL,
			0xF584CCB92BD8901AULL,
			0xCE01410903A2204CULL,
			0x5B3B7843A672C28BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0867F620A77CC180ULL,
			0xDA085568C638ECE7ULL,
			0xDF9B19EE81AE0016ULL,
			0x3CDB106047865CCDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x17B00B1DBE98CAF8ULL,
			0xD19D150F32356CEEULL,
			0x4B8B5FA1201F207EULL,
			0x555C843AC61A37C8ULL
		}
	};
	printf("Test Case 234\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x470B09843062B7E0ULL,
			0x1EF99FF89D810312ULL,
			0x7D07A564D87D82A7ULL,
			0x623E7C65154B7534ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2A56B14779811220ULL,
			0x4DAEA148709013D5ULL,
			0xA2C0D30BDE8A859BULL,
			0x03E35518B3C4805BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x682CB4CDB5A30B80ULL,
			0x6E0DE5B397B65534ULL,
			0xDE48790F055066BBULL,
			0x5CA8ED5D4DA8812EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5E5F22610E321133ULL,
			0x07A8ADF51AC11D18ULL,
			0x1C3EFDC5F83F7D04ULL,
			0x5B33EF911F2890F4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7D946542DA56B48ULL,
			0xC2B0901E387C8303ULL,
			0x18CF98E61E4B5F30ULL,
			0x04CDC004C74DC4DAULL
		}
	};
	printf("Test Case 235\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFAE28FBCF4686B00ULL,
			0xD690E41C273F16B4ULL,
			0x8C1FA493F4A01C25ULL,
			0x6950A0B6BBA25739ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2611BE248A8B4A97ULL,
			0x05B37652BD5FC637ULL,
			0x2856250C01DB619DULL,
			0x6323156BF5A4630FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC486DCF2E7CD7A80ULL,
			0x48CA4E607BD4B99CULL,
			0x448E0E0196D7550FULL,
			0x7EBEA65147FD334CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBC9BC093B1BDF325ULL,
			0x6663EAA6232BF8C3ULL,
			0x62DE8D08E52A4381ULL,
			0x7610F00C16E0478AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1E919ECD31B05840ULL,
			0x0316076A4ECFE82FULL,
			0xAA44280687AF7D10ULL,
			0x4AEDF83E48D1F87EULL
		}
	};
	printf("Test Case 236\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8AF3D00547A34618ULL,
			0xF4DFF1BAD334FD3BULL,
			0xCF928F76898FC8BCULL,
			0x4DAB20FBFF6456EAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9E4E1B58C31BC48EULL,
			0x6985059EA0DF3194ULL,
			0x08EA63839243A06FULL,
			0x0216498C6D5971D3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA23E844E6C92DC70ULL,
			0x76EC67A4D3BB3640ULL,
			0x458A203CBEA3A64BULL,
			0x798E1562C66DE76AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAF3450D4248DCCD6ULL,
			0x701B3CEE541057DDULL,
			0xD8D018F0634D9A5AULL,
			0x53D2E727C2015A78ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEBAC92328FBEBDFBULL,
			0x0323EDB3D6540F5DULL,
			0x74E8F730C1577193ULL,
			0x37D0E6523FAF41D4ULL
		}
	};
	printf("Test Case 237\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4AA71F0EFC4BF878ULL,
			0x8118F48D94C971B5ULL,
			0xAC911BB9CCAB02FBULL,
			0x79F477E9A9D69641ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE79AEC1C9FB80352ULL,
			0xDE63D6CE37867056ULL,
			0xBD472A6AFC6E7758ULL,
			0x5BBAA494DFD7B443ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCC2C552423331290ULL,
			0xFD7ED4CA462BF9F6ULL,
			0x3119313D8945B080ULL,
			0x6D8D8A431F502021ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x20036EEED95BF534ULL,
			0x7659498084EA2B0EULL,
			0xF9BF0D75222756C8ULL,
			0x6DF2F17BEFC69598ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x88061D47CFF4044CULL,
			0xD33B61E865257DF7ULL,
			0xFCCAFED194A85323ULL,
			0x4E5BD0E0E1630FD2ULL
		}
	};
	printf("Test Case 238\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x24DD03ACCB9136C8ULL,
			0xC6CAF3EF021EA6DEULL,
			0x55CFD2A201F616DFULL,
			0x5CD45C1449822419ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x865BAF4F7F660BCEULL,
			0xEC2BD75B2EC7867CULL,
			0x24156E9719D8D543ULL,
			0x011205056902BA0AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF224B0F612A130D8ULL,
			0x9C1E5A4B90FAB142ULL,
			0x5CB052EF67CA25D5ULL,
			0x46BD51DE7EB9EC90ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1B895B9A66F0315ULL,
			0x9EF359C38EE7BB4BULL,
			0x9D756F509C33D23FULL,
			0x46AAF39932F0F0D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1E704128CED06F2EULL,
			0x1AE73BFEB69BCBC6ULL,
			0x02A447F82F5BE7A5ULL,
			0x4803D411CB490605ULL
		}
	};
	printf("Test Case 239\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA7F03CF8C16068E8ULL,
			0x191CCE00E7521C8EULL,
			0x36A57CC5320FA7E4ULL,
			0x4F992F63B3D86017ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF29F556228B7DB6EULL,
			0xBDE4D045E5E7F3FFULL,
			0x5330A26AB6602DC9ULL,
			0x0F8C33B69D41DE1AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4AB098C707B73A70ULL,
			0x77876E955E97F58DULL,
			0x333D2B8C30D79FC8ULL,
			0x43D492A5801F3A8AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFA2AB41B8DD6377FULL,
			0xD9830C3A67432E46ULL,
			0x8FE36C9129B406E4ULL,
			0x2B8DA1A17D278020ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCC34E2F0CBF94D36ULL,
			0x8E151C2AB580AA03ULL,
			0x34855DD22F3A0521ULL,
			0x37BD36B45C11F75AULL
		}
	};
	printf("Test Case 240\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCAB4F1BD2C8A2968ULL,
			0xEFAE0085C6AB2B80ULL,
			0xB0B0A4E5D3A358A4ULL,
			0x6050FB3544F89B0EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5F1E636D44B98D11ULL,
			0x77C82C146370E889ULL,
			0x85BE685FF8D4FC01ULL,
			0x7E4E4FB08A2D1791ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x35207E9689F51BA8ULL,
			0x33AC35B18CEB9FC1ULL,
			0x922A2AD12EFB2FBDULL,
			0x40F0F83C313E9D6CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x745783B06994335CULL,
			0x1A4D9B68A393C212ULL,
			0x9DAE25BE1EF06D9DULL,
			0x23EEA827A3060BA4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB3367F04F1A6A3A3ULL,
			0x266E9F810213A9EEULL,
			0xC0B1251CD5681436ULL,
			0x5253C8FDD4C934E4ULL
		}
	};
	printf("Test Case 241\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x16DC8E21C4231120ULL,
			0x2E61FA8C42ED6215ULL,
			0x558830174E8A6858ULL,
			0x6E6702BA97609E42ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD740D96183FDD5E1ULL,
			0x2458959B9319F869ULL,
			0xE01754CA26D9C5FDULL,
			0x3C3186F7765E5A00ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x342230713F1DA958ULL,
			0x5F8AF218668DB4A9ULL,
			0xA357D6A32A3AA3FEULL,
			0x6EDC7E3513D9FAE1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAD18338F0D0F043AULL,
			0xD82B9D0B543F111DULL,
			0xE6B6A40EA0992514ULL,
			0x24D34E03ED61E085ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x85E496A69816C7BCULL,
			0x2724A26B3E5BBF9BULL,
			0xCA978D6461E67853ULL,
			0x26A2E208FC985037ULL
		}
	};
	printf("Test Case 242\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8039CDD551BFF798ULL,
			0x82B5561F4F12E79CULL,
			0x1C27563DD9BC3A5DULL,
			0x4C429CF81A7E5209ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x729663BFF8FD150CULL,
			0xAC2910B256F295E9ULL,
			0x7C3C7CCC630325ECULL,
			0x116851C93461F98FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDC37013932237E28ULL,
			0x6F1B659AA2E5952DULL,
			0x8B554D17AC3EA8F7ULL,
			0x417942CDDEDD23C3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF316BCA9AF832919ULL,
			0x05954451D0C48B98ULL,
			0x5C2CCC7BC89FA184ULL,
			0x6589AFDB39571781ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x74A611E8B449B89FULL,
			0x9B8F618C8752985DULL,
			0x554A64290ED89A51ULL,
			0x2390E00E286CBBADULL
		}
	};
	printf("Test Case 243\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD479780DB31A5738ULL,
			0x5B3FF459E2558229ULL,
			0xE9BDF1CE1092DB6BULL,
			0x447F9B7478EEFCCDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC3D6B24E222063A8ULL,
			0xF03AB563AE761ABCULL,
			0x86D1833CF057308BULL,
			0x2694C234F3E66212ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0030EB851D2D7280ULL,
			0x85ACFE2E004F1CDAULL,
			0x11103819EFDC6A32ULL,
			0x4C845323940FD002ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56ADCCA57AE58CFFULL,
			0x11601C5533FFCE00ULL,
			0x219426D18671E72DULL,
			0x11C21895DAEC2E74ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB4F40435EE6AC789ULL,
			0x746EC507D723A611ULL,
			0x1E500A200364C0CCULL,
			0x16BF9C939C8D6C7CULL
		}
	};
	printf("Test Case 244\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB346C650B1274A58ULL,
			0x932FA277C3C8EADFULL,
			0xD702E1F1F9CAE407ULL,
			0x750DA3153EF4112EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E47FB8CD84C3AC7ULL,
			0x98DC99D70A2DBBC4ULL,
			0xB57F0879B949F807ULL,
			0x204F49B0D354C111ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F01981AEE25C098ULL,
			0xEF58A2878DC627BDULL,
			0x45F6D81FB7F2011EULL,
			0x554F1A0B2398EA2DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6581E10B8181D7BCULL,
			0x8D80C4855A280D61ULL,
			0x4328888268A5C78CULL,
			0x5476EB0CDE5A0B07ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3D18F3969ADFB0BULL,
			0x1B17F19C7E6CA923ULL,
			0x02BEAF2BA921E3E0ULL,
			0x5BDAA0E26376865DULL
		}
	};
	printf("Test Case 245\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFB8061E75A126A48ULL,
			0x2F00A237B7A39735ULL,
			0x3E0D3C1A4C5D5882ULL,
			0x5CF45861A6C582CDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x41A622C5F4374037ULL,
			0x6621763F3F9E4D4AULL,
			0xDBA71E910E89D825ULL,
			0x561D8BCC3459383CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x44CF1332F4E008C0ULL,
			0xD41543761C559857ULL,
			0x67109E7E35067632ULL,
			0x6772121FCB709313ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE6AF11E2EAF8EE63ULL,
			0x9D26AC60BA656B0CULL,
			0x10486EFDCDF85F47ULL,
			0x58A9AC5EA26BE78CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA9999FB666F096BDULL,
			0xDF455325BD2998FAULL,
			0x2D48CFBCB238B625ULL,
			0x6554F68D71E41B3AULL
		}
	};
	printf("Test Case 246\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x171B394A4333F678ULL,
			0xE905C7461782AB50ULL,
			0x81AAD4907A70C6D9ULL,
			0x5321CF85352AA66BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDC732F025D21FAF7ULL,
			0xF722E83E7F1CFD36ULL,
			0x5D4C70651322880CULL,
			0x3BFA99743EE71E2CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5FD31B5A2CAF9030ULL,
			0x98A1C9C091D0198CULL,
			0x2FD7D37D7210D5D0ULL,
			0x764EB0D6DC00658BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7EF9F8734EB59A5CULL,
			0xA50B7D7486800821ULL,
			0xD50FF88A041D88EEULL,
			0x55852F96D99EB787ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x71AF458E551FA2A8ULL,
			0x61BADE4E30ACD250ULL,
			0xF9CF9B9A1641D48CULL,
			0x629D51CE98F6A65BULL
		}
	};
	printf("Test Case 247\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA2C7ED4699F99088ULL,
			0xB9B9DB0E8B9DB5B6ULL,
			0xB0E9C07C0A75736AULL,
			0x489C290E8A8C6826ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3673DCBBAFB335A5ULL,
			0x1686420BF506DFD6ULL,
			0x45925BC34BEA6A2BULL,
			0x59D28FAD591F9AE2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x13A21CD782ABDE00ULL,
			0x06A3F50D056F9F18ULL,
			0x50E0473CA76316C1ULL,
			0x614CB60EA88DB4E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4CA629D3E6252394ULL,
			0xA2A8DDA594ADDFBDULL,
			0x1323EC11FDC8AB5AULL,
			0x5FF72FF7E3959ACDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D06F9AAC3E6E8EAULL,
			0xA9414D3B3F97FF30ULL,
			0x6BC9D10F5FCBA1F6ULL,
			0x5FD75207B7ACC983ULL
		}
	};
	printf("Test Case 248\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFE1F2DA83C3AEE08ULL,
			0x409FEEC36200A9C6ULL,
			0x6E5EAA5FA03D6193ULL,
			0x41B0569E0AD1DA48ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB758671AAB2797EDULL,
			0xEB6D104BF50BC730ULL,
			0x1A735F952DB819C8ULL,
			0x69A8EE0F8A37E97DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8373769CA9426AB0ULL,
			0xB970B64BC696F52DULL,
			0x223A6B5D50739F76ULL,
			0x75C8AB2F2AE58169ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2A440AEE53F4FB5BULL,
			0x5F4B547F6ABF68FBULL,
			0x133511F37E8026CFULL,
			0x471E5BA8F5A4E925ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D12FBAB04AE314AULL,
			0xDD9C2FB16C18990EULL,
			0x789E12F3D27B3F90ULL,
			0x16C7108BC4DF8D39ULL
		}
	};
	printf("Test Case 249\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A43D739DE3290A8ULL,
			0x7BE16161107C7B91ULL,
			0xB9A23E6376E6773FULL,
			0x683572B566289D84ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B90F2F645E79CADULL,
			0x2A21E0BAE0636691ULL,
			0x9E42279A0644253CULL,
			0x6954D91159FD1655ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC116BB41320BDDD0ULL,
			0x83E56786D3FC7044ULL,
			0x3CE94C06CFF2FE38ULL,
			0x4E87BD1EE17DE800ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA745C1192272C278ULL,
			0x0A3624401825BCE7ULL,
			0x0C5F546B34851A25ULL,
			0x00EA6880427B536BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED0344051B0E8C55ULL,
			0xA03341F959E35173ULL,
			0x899272C60CCA0B7CULL,
			0x5D3204E9187EE25EULL
		}
	};
	printf("Test Case 250\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x02CEF3985BCA5758ULL,
			0x613575BB65F30D37ULL,
			0x7447C54A6CAD4C0CULL,
			0x6D6152868F985ECAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x66285CE18B72AAC5ULL,
			0x72F9BA378C134C8FULL,
			0xD137A49C0BF25B14ULL,
			0x18988E91DED113FFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB11E5A063653BE90ULL,
			0x8964B33C96F4430DULL,
			0xEC5B5BB1828542E6ULL,
			0x40FDA2CDDC829CE5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x97B257615D66118BULL,
			0x9DC1DA5AE5708D69ULL,
			0xE474B10C1B3BF7C6ULL,
			0x4377489CD657C5B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x967449D269EED12DULL,
			0x9B95868B5D615300ULL,
			0x227597FB61922709ULL,
			0x07D158AF2F716CFAULL
		}
	};
	printf("Test Case 251\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x93CD2C6F01872680ULL,
			0x4D0B21BB8405DB1AULL,
			0xC54FF3944A0CD02CULL,
			0x65DFBF400E6CC48AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE33C53649CEE6C46ULL,
			0x373D2FD2042FD3C6ULL,
			0x466BD64CA337F510ULL,
			0x77F570D01E77C031ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC550777ECFB37B50ULL,
			0x734EAC6847992616ULL,
			0x34091788E62C985DULL,
			0x4236143DF3A233CCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEF80ECEE107481C3ULL,
			0x0A4B6E204F356898ULL,
			0x5556458E6CD8F532ULL,
			0x6EA7184F7EBB1E32ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8583BD1FC29E116AULL,
			0x2FAB1182FEF91D6CULL,
			0x2260D8C1BF607EB4ULL,
			0x7BDDF0491BCEF0B1ULL
		}
	};
	printf("Test Case 252\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x59A51ACEDAF749E8ULL,
			0x609E21053E5CD10FULL,
			0xD2F42848211AEC83ULL,
			0x7A728C3A002A25C2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEE61E746AB142C83ULL,
			0x536A48069D5F7AC0ULL,
			0x5DBB4C34AAE5ED1CULL,
			0x7121B3C28EDE2FBAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA7F24EBCCC8AF3F0ULL,
			0xC66D2CED2F4D9A03ULL,
			0x798F7F9858DDD9D5ULL,
			0x490062CC727BBA9FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x568728F2E51A8F12ULL,
			0xDA293A212D66688DULL,
			0x51EFB67B0A08DA09ULL,
			0x351FDFC423D8FD75ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3AAA396D13613CDULL,
			0x86E72DF208F9E785ULL,
			0xAC91CE38D8A1AA13ULL,
			0x0B56B122C6648357ULL
		}
	};
	printf("Test Case 253\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC7F47B0AEDB48DD8ULL,
			0xEC9A614255E78490ULL,
			0x289911C41D94F22EULL,
			0x4AA67EFAFE7F6803ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0F25B8FE40E626EFULL,
			0x38E889DCFC33A572ULL,
			0x4239A6B20EF74EC1ULL,
			0x5AEDECBE11EAEE4AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x670930F5425645B0ULL,
			0x08FD33BA0B82EE11ULL,
			0x78C343B28C06459EULL,
			0x700AAAA9107E1E37ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFDCC7FDB6A19B20BULL,
			0x17946F1E4635636CULL,
			0xDF33AB7C6FE992ADULL,
			0x04140B1B755DAA68ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x803E4DDBA79A0DCEULL,
			0xCD28AF89C49D8B7CULL,
			0xF6BEDC56AF393E87ULL,
			0x401428CDC3C11E81ULL
		}
	};
	printf("Test Case 254\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x35609592BA2415E8ULL,
			0xB542601B885733D9ULL,
			0x001919B2FD850BF1ULL,
			0x4295C9A5C99B4B4BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D0A79D0C9D25EA8ULL,
			0xF57AD1378B7CD72FULL,
			0x6BD5080C69C575BCULL,
			0x397C2A8896EA8A2DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA05131C5C5A388F8ULL,
			0x2C3A4B3A6205630CULL,
			0xBEE3F2A98AD19BE1ULL,
			0x547195DD5E7A76A4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x839BB39E89D9B9A1ULL,
			0x61084B52D5312F88ULL,
			0xCC3E6A6C59666645ULL,
			0x7C40C057A362A41BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBEC9E9A022336C0BULL,
			0xA131D0E5C429AB31ULL,
			0x9AF840E80CD9039EULL,
			0x52834A2C915917ACULL
		}
	};
	printf("Test Case 255\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB73A88EFAF0B1600ULL,
			0x18E67B30423B2AF7ULL,
			0x8886CCF2B50C098AULL,
			0x62F8A466AEFA2422ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3E03E9E7475D7AA3ULL,
			0x3F6432F8FFCD73A4ULL,
			0x30AC4E8140A4130EULL,
			0x247DBB04412ED5E8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x99493110746D2198ULL,
			0xAA71C9C5686F4E02ULL,
			0x20B3989CB7471E8CULL,
			0x4F9287BA888194A2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE2C19563C1A19DB1ULL,
			0x176FEDC3E61BBA1EULL,
			0xAAE3FEC9C9F53086ULL,
			0x62098A3915AB453EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFE4AD229274AABC4ULL,
			0xA01367B2FE7A7C8FULL,
			0x9C8F328DC33B7000ULL,
			0x248719A17A8F72B1ULL
		}
	};
	printf("Test Case 256\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x391D43AB0CF46138ULL,
			0x698B4CD8B0A1E401ULL,
			0xCBA0FE8BDF812B05ULL,
			0x6784AFAA0BCDB9F9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9A02C0847AE97A77ULL,
			0x6761AF9F1E5750B4ULL,
			0x3CA3C3AE4E8B3105ULL,
			0x301A756B63105902ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x274B0E84481EFC08ULL,
			0xF30091AD528D0F4AULL,
			0x2ADB0B9D532A99B0ULL,
			0x4528E03897D8D187ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x07DBD68D6CAB579EULL,
			0x72D290585E1E2A60ULL,
			0x90E07183DCE9B418ULL,
			0x42C3EE8B43C71099ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA87E0E6F47BBA1F7ULL,
			0x65934F7D52A1E631ULL,
			0x83FE4C49142AA094ULL,
			0x19CEB6D6F24E72B8ULL
		}
	};
	printf("Test Case 257\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x159C0593494D5390ULL,
			0xBA984A8487353110ULL,
			0x3DD3EEC07C115FD1ULL,
			0x5440D465FF70F60BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1A1DE495BAAC48B8ULL,
			0xF46B5A61087281A6ULL,
			0x4F8690190297CB9EULL,
			0x59A2A41DEC89D46AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x128F4D9B73E60098ULL,
			0x59BE00010A75DF47ULL,
			0x2F71ADA8E83EA623ULL,
			0x4853BABC50BDE463ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x72A8F43A9EA6B812ULL,
			0xC4B459A344B78F21ULL,
			0x22F7D1BEF341630DULL,
			0x178ECFABC563B0F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEE2026A6AC0DE7B4ULL,
			0xDAD9BE50374AD09BULL,
			0xD299EE6CB412129DULL,
			0x41A4B1C78D481694ULL
		}
	};
	printf("Test Case 258\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x20745CB944A52C18ULL,
			0x993B0B4F80BCEBECULL,
			0x0C789B04BD09EF07ULL,
			0x440A0B74EE9D430BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE4AE83BDB85560AULL,
			0xD5265E3A094C7958ULL,
			0x9A39ECC3C4CCB2E9ULL,
			0x49AC4E9B27DA511FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x31AA081AB84AF5C8ULL,
			0x85F11E81493C825AULL,
			0xEE98BBE729AC5CECULL,
			0x4B9C964478864504ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x486E32D43D5FEE58ULL,
			0x500ECA43DE617363ULL,
			0x8629ABD189CC2A10ULL,
			0x68EF6514CB8CD4A6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x062CF67CE3FDC0D2ULL,
			0xA4B803CBA4DA0C52ULL,
			0xB31C0098CA000423ULL,
			0x5106D694B07A9811ULL
		}
	};
	printf("Test Case 259\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58E3A542D2312758ULL,
			0x3A09202EB9351804ULL,
			0x76908A4687A9DC38ULL,
			0x4AC125CE8AEB98FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x551CE0DE3371E899ULL,
			0xC2B45DB5842D4292ULL,
			0x769516895C133A6BULL,
			0x49F874EAF57CDEB9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E60E9EEAC8A1CD0ULL,
			0x0E9DC72996A1A4D7ULL,
			0xDC1F3B29525F72A2ULL,
			0x54D803F1A738A4B7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2B906570C0DBA6E0ULL,
			0xCCA95238FAD1AAF3ULL,
			0x5B4C3CFE345F5D5DULL,
			0x5AB1D7805CB199DDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9C7AE0732165DCB5ULL,
			0x5D8BFD8201820D11ULL,
			0x9BF932E1EA7E1450ULL,
			0x0817055F18BE9600ULL
		}
	};
	printf("Test Case 260\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB0B75168B416F220ULL,
			0x9C97C75528FC7E21ULL,
			0xB687BF2183AF4653ULL,
			0x61BBDC48A6C40136ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x56FC80F93DCEC268ULL,
			0xDAA4C70A23D04341ULL,
			0xA987608B2E16AE07ULL,
			0x2698065914833A82ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4162F2C427880E10ULL,
			0xD5E0AD117A9F172BULL,
			0x776A356508E56470ULL,
			0x5CF712088BC40A1EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB0756D82F483D1DULL,
			0xC1FA0613F29C125FULL,
			0x8F15D906856BB6CDULL,
			0x5EFE50A594B2C95FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6A9A9488D73701EAULL,
			0xF03308D5A9547C30ULL,
			0x5336D69D0AB88DB6ULL,
			0x4BA35076AB0D1CF0ULL
		}
	};
	printf("Test Case 261\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x161936065CE39ED0ULL,
			0xC7793A8456194001ULL,
			0xA5EC9C6356D4910EULL,
			0x76567809362B08BDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x979FECCE845CC959ULL,
			0xAFA173C7B4887AAEULL,
			0xD8A2601CEA75844BULL,
			0x6A7E612D1EC8C4E4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x82B3BA440DAD2648ULL,
			0x9A54437D03A2A0E4ULL,
			0x802E3665D5F33821ULL,
			0x62E3280F906F383DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFD0BC88E934ADE84ULL,
			0x533284855E23BB40ULL,
			0x54F42325675FE046ULL,
			0x472D66DBBD0443D1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x82236C3D6485845EULL,
			0x58A08000D789F7BEULL,
			0xB9785D9B7B713936ULL,
			0x17FEBBC0B6318FA4ULL
		}
	};
	printf("Test Case 262\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB8929B4087EE8A10ULL,
			0xE7C7C6A0E4C33C62ULL,
			0xF5DD838DC7C390C8ULL,
			0x6029BA3B68FE052DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x577B3ABC6698008EULL,
			0x334A4C5F24ABAA05ULL,
			0x5BFBCC453FC93096ULL,
			0x690E77AB65A4FED9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6D7ED1DADF8B3B20ULL,
			0x3DCC207641B79271ULL,
			0x03C40221AC78E419ULL,
			0x79D3FF7BD0812739ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x61D47CD368AD4BC6ULL,
			0x00DA2F84B8E40765ULL,
			0x58C7843D5C9799C8ULL,
			0x597D5CF2D5AA9C15ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6D9ACCBFAEDE2822ULL,
			0x91AA6E6BF8AC9886ULL,
			0x9055EFA0C5E32BBDULL,
			0x42379B7A3441FA29ULL
		}
	};
	printf("Test Case 263\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF55CCC63548078F8ULL,
			0x242B3F5099C5E97DULL,
			0xC76A51FFC7832089ULL,
			0x41CC5C6B4AF2C8A0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1A64436FBC8DAA77ULL,
			0x5CC9A93779A0EFC8ULL,
			0x17FA9C4395464192ULL,
			0x53ED4BC730AAF351ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B2F28BE9CD8B968ULL,
			0xADE84ADDA10ACE89ULL,
			0xBB7A52B67FFBF875ULL,
			0x5DC08FC27273BAF5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F8A0A967E9D9728ULL,
			0x6567DB8318745FCFULL,
			0xA414EB4F5398063DULL,
			0x35420AF327A180D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C0AB055F8CCE788ULL,
			0x76FADE5D7154C63FULL,
			0x48D47FAB8C809F6CULL,
			0x5FA373AAE0E6D5E2ULL
		}
	};
	printf("Test Case 264\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE2E028F94735BF88ULL,
			0xE7A205281D920953ULL,
			0xF59EFB91F1C2C627ULL,
			0x41340569428C0A08ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x79CF73F3FDCE4DB6ULL,
			0x0CC9A6424E55B07CULL,
			0x8A69FDB267E64A7BULL,
			0x5B60E7FDF7651B5EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA7B0D2BDABE50830ULL,
			0xA7F645034F2E4888ULL,
			0x87EFD1119B6A04ABULL,
			0x7CB2F243BADE79FEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1FB655CD39583FE8ULL,
			0x32E075F7398C2C7DULL,
			0x1A7E589019F8E5ACULL,
			0x378823C0080F53D2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2EE5721E3E9876BCULL,
			0xA2B18CAF812AB800ULL,
			0x3CEA984EF1B5D307ULL,
			0x40D402212C030DDCULL
		}
	};
	printf("Test Case 265\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x158489E5ACAE7100ULL,
			0x1205A7769F86B7DCULL,
			0xF1C6DBD9C5F270C3ULL,
			0x54918E97FEBDAD25ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD11343AA869BA0AULL,
			0xD148A288E4B277D6ULL,
			0x6D2163B7D9CB199CULL,
			0x4044531921934057ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x11EAEB507DCD00F8ULL,
			0xF6207A38A7AC7D8AULL,
			0x95593FB96113D0E1ULL,
			0x7A9ED26713CC082EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF7164C891424A3AFULL,
			0x9105BBA51198EA8FULL,
			0x2ABCCB23A3FFCAB7ULL,
			0x0613E3AD8E7BD157ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFECC2421A3DC7C36ULL,
			0x95CEE3A96C61B734ULL,
			0x687F8CC99BAD8184ULL,
			0x1DE6F4212AFC1F14ULL
		}
	};
	printf("Test Case 266\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0A9DE3FE2FA13968ULL,
			0xABFCC6365BAF4628ULL,
			0xA4A78EE4A6D00C83ULL,
			0x70AD15C57FFC1530ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x900C9377AC780CC2ULL,
			0x941896DAFC9153C4ULL,
			0x5308C1C20AD05614ULL,
			0x428F383F03089BBDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x582F5E56D387E030ULL,
			0x12BDBA6671C10F52ULL,
			0x9A15E963CA766B11ULL,
			0x580EE81D48ED610CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC5076E2283404A27ULL,
			0x72DE28DFC61CA8E6ULL,
			0xF7E75EE4DC3D0B32ULL,
			0x41C435957D1D7D9AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7AC632951A53F8A0ULL,
			0xCD63722639300667ULL,
			0x803D314C969A558EULL,
			0x44EE2B3DB0B74B7EULL
		}
	};
	printf("Test Case 267\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB19F827612E84168ULL,
			0xE9B26082B126BA14ULL,
			0x0235CB417593A73DULL,
			0x4A579A8F14B8D95EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBFC6D5035B24709BULL,
			0xEB1D5613DF9B2782ULL,
			0xE7549BC796E6A757ULL,
			0x5EF71B97A9C4C821ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x03331BE610262C00ULL,
			0xA93E9A4F389E063DULL,
			0x510A98E8596E66F3ULL,
			0x4A528EC4E10CF65DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD3322BAE9CC18CBEULL,
			0x00F6A4F97DD2E5C9ULL,
			0xFDAFC8A3DA91FA07ULL,
			0x34FD4CBEA4DAE8DEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x421A8683B9F36A85ULL,
			0x809D16181345E18CULL,
			0xDE30FEC486869673ULL,
			0x76E7E7B58D292D6AULL
		}
	};
	printf("Test Case 268\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3F4AD910E4C1D288ULL,
			0xAAF4938AAFE1E413ULL,
			0x5252A479E9EFACC8ULL,
			0x601EE22C7CAD5B8CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0FB8DBF4F5A72F8CULL,
			0x34C475721848ED2BULL,
			0x0EFCD17F96A383A6ULL,
			0x0311B259D1C1D180ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C15EB6CFF848378ULL,
			0x63CBF0F4D4597DBEULL,
			0xA77C26A7EB196022ULL,
			0x465EDFCBD9057EABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x131FCCB3E7E2C7A2ULL,
			0x257C8DFF5968B629ULL,
			0xE91A4BF838642595ULL,
			0x7AC03C1B37850D6CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x685F544F485FB479ULL,
			0x577EFF795DB9C480ULL,
			0xC3AFBD31D145CE9BULL,
			0x01E9D4594E9721E2ULL
		}
	};
	printf("Test Case 269\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1AB1798B9856A268ULL,
			0x8BB3407F0B607D73ULL,
			0x81EFA63012F3C312ULL,
			0x674D592B4B6FCF4BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD040055451732DBCULL,
			0xDC30C6BBD384E84EULL,
			0x7CCDC3EA6DFF2FCAULL,
			0x16842361532B6A87ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x657950E8A25A8710ULL,
			0x7DBAAB389FEC3C8DULL,
			0x034A3FDB264F5E81ULL,
			0x6E76F973B41B2D44ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB903FEC6940D64E8ULL,
			0xF7917F45E2AC76C7ULL,
			0xA83567CFA3004B68ULL,
			0x5979D22DE45A5364ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA0E85C8C6C14D243ULL,
			0x9851FE69C8197611ULL,
			0xC2F776083E06520AULL,
			0x41F0C0F857F2A56CULL
		}
	};
	printf("Test Case 270\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4C72ADD7A94241C8ULL,
			0x5651B78967B68834ULL,
			0x66BEF2DD8D32C8D8ULL,
			0x4FDD96E6653946F5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x769A5F6479605E38ULL,
			0xCAA6EF5A1358170AULL,
			0x3C1E9A3FE564ABD1ULL,
			0x354CD3A3003F1094ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5BE5159E27DDB768ULL,
			0xC93280921C78A566ULL,
			0xAA8A53CB726F33ECULL,
			0x45FE9040B7997689ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE8E46AB6DA67350CULL,
			0x2BAA6FE7C6EAA906ULL,
			0x37E238D9149F7B57ULL,
			0x78EB5739A5636B09ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x453060AB1833CB5AULL,
			0x5CD03EE0E4BC2BB2ULL,
			0x8467F5D749A344AEULL,
			0x438F425E68066B94ULL
		}
	};
	printf("Test Case 271\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5A7B450444E1F8C8ULL,
			0x1670760DB21EC845ULL,
			0x20D2D22FA0BECE31ULL,
			0x7F22AEB5791ED9F6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB5E1F326A5D54762ULL,
			0x3F86F74CC1DE21B4ULL,
			0xE058F4A9A7C64F23ULL,
			0x6E3D286B2BC7E6C7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE52E752C64458630ULL,
			0x56E935F403A99415ULL,
			0x9B0A30E2949FDA9EULL,
			0x7355F82BE2FB8A20ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5EFB277B0F00A30DULL,
			0x7ADFB1220E7A47EBULL,
			0xFC003A4FAEBE40AAULL,
			0x305E54789B79BA29ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2D3B716557B89F80ULL,
			0x7615ECCBC26B954CULL,
			0x7B9377680399B0B9ULL,
			0x03C0F722ADD27424ULL
		}
	};
	printf("Test Case 272\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x24CD65329B125B58ULL,
			0x1C3FF00FD2D42159ULL,
			0x8BA13BDF38822A09ULL,
			0x7DF92374FE3CE2C7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1422A4032EBA0A72ULL,
			0xF4CA3E04100AC238ULL,
			0xF27D51D09E154BADULL,
			0x51DA0DE5F889AF12ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0FFDDA6CA09013C0ULL,
			0xDDBD00AFA45BFAC5ULL,
			0x4B7547CA9D929A10ULL,
			0x6D9D9857144849A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCE652366E35C9A4BULL,
			0x8D6FDE60754BE6B3ULL,
			0x599C1314C9D6ABC0ULL,
			0x76F76FDFC96FA3A0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3D4FCA74A08DCA43ULL,
			0x13858D5DC7DCA815ULL,
			0x91259DA1194E709FULL,
			0x7D8A6EFE7E7D3973ULL
		}
	};
	printf("Test Case 273\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB602F81CBE41E738ULL,
			0x3213E90DD98B4F62ULL,
			0x4FD651462ED34C9CULL,
			0x7456AFF85B61FFC8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE27CF73FEDA69F5FULL,
			0xBCCB3DFE6A84D92BULL,
			0xFA359746AE4A464AULL,
			0x4C6C81219A7D0F46ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8584B70B50DDE530ULL,
			0x63C4907E5B6637F6ULL,
			0x7854C748D173F424ULL,
			0x55E9A808FDAEAB1EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEE99472E1613CE44ULL,
			0x8225BC76EB09712BULL,
			0x7535324968B74FBCULL,
			0x723CFE35815D4B7AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3732F0A4E3170574ULL,
			0x4D576F5371769E98ULL,
			0xFAA7674A87384BF7ULL,
			0x7A6F05054F84061FULL
		}
	};
	printf("Test Case 274\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1D79795AE550F9B0ULL,
			0x9DC05CD9A20BCFD0ULL,
			0xAA04E37EBDB221AAULL,
			0x5F4DAC9335FA55B6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC7B6CD1F26D56E37ULL,
			0x92C4082977950D25ULL,
			0xD37E47885C5E91C3ULL,
			0x016770F278945C65ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD162836488D77C0ULL,
			0x320F9FAF4A00EC0FULL,
			0x6C925A78FF784F1AULL,
			0x7B476AA83968BF4CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EFECB4E73E0078FULL,
			0x417E7C7C18B27A94ULL,
			0x094B62A96F36A5A1ULL,
			0x2C9EA883BECFA06EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDD8AA84F7D278B3FULL,
			0x36035544D57B1946ULL,
			0x60840AA364D6FCD0ULL,
			0x364E840A7EA88C38ULL
		}
	};
	printf("Test Case 275\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8A111310D3183C28ULL,
			0xE76C85D43103DE73ULL,
			0x7F7AC749AC066248ULL,
			0x5E2085993900D092ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x86055DE18DE37E1CULL,
			0x207FEF8C549D2D3CULL,
			0xEAFBC8F5C2B1EB4EULL,
			0x64AE894972B6DC44ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3490758D9CE60148ULL,
			0x97A149B438F88624ULL,
			0xC317B2B8C3BBE729ULL,
			0x78F17D9C6A0102A8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCDE9829E1C8E69A1ULL,
			0xC789F415E6948DC3ULL,
			0x785FCE7B99F3A22DULL,
			0x2A0621E1602A112EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB9D8391050AC11FULL,
			0x7ACA12CBC59B77D5ULL,
			0x1E7820CA38D70C19ULL,
			0x1D6211921ECD1435ULL
		}
	};
	printf("Test Case 276\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x74ED7FD729010670ULL,
			0x571F72862F3761DFULL,
			0x2A8F5CEB37F72597ULL,
			0x5AC42EE593854F33ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFA85F168B19629D8ULL,
			0x59CC8AB8F2A23FB0ULL,
			0xE662E0BF344F38CBULL,
			0x06935FB85EC8D4C3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x23C32B95351D7C20ULL,
			0x28B20E8B26099B39ULL,
			0x10AD1DC491AC0C93ULL,
			0x7077AC862422B69DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4C37D10CD3CC0201ULL,
			0xE4CC968AE60B2AB7ULL,
			0xBBFB28BB0087F52AULL,
			0x7B18FB004BE0C247ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C30E45C6252D0DFULL,
			0x809196B545F62F2CULL,
			0x5E29C14031B422B5ULL,
			0x3AAF5402EA8226E3ULL
		}
	};
	printf("Test Case 277\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAFA58AD514C48668ULL,
			0x55835B6D131381A5ULL,
			0x40072D381CB094F9ULL,
			0x4CD68566B0D48AF6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEB10CA8DBF58C050ULL,
			0x28D356B8A194CA39ULL,
			0x42960B0A285274CCULL,
			0x688EA78763D0A1B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x05B51986730F0718ULL,
			0x0E717F5F80CFE6C4ULL,
			0xE7236B1CC90F6A17ULL,
			0x72B20EB7CD2513DFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0DCAD010845E4B6FULL,
			0xA684E8E256FA3BA2ULL,
			0xB5D698223A425660ULL,
			0x636031BD585EAD0DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xADDF2520BDFF5AFAULL,
			0xA501922D7588054FULL,
			0xFC948B588D6495F0ULL,
			0x251108CB38D2D98AULL
		}
	};
	printf("Test Case 278\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4C81262DE01CDAA0ULL,
			0xBAC92C820F25EE98ULL,
			0x194C36548DABD29DULL,
			0x7169CB4BEFDA5D7DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B62CAE344B73039ULL,
			0x729592770F353A95ULL,
			0x85DD27DA018927DCULL,
			0x3EF132BE3DF41482ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x737FFF601EB4BCA8ULL,
			0x67947ADA4D6AC2C4ULL,
			0xA0152A0927E9C483ULL,
			0x7429CA54A7A7C576ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9AD72F7639E47FA6ULL,
			0xA365399572D6ADEFULL,
			0x9603AEDD814475A4ULL,
			0x3C3D5F5AA491B402ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8F4B54AEC0C1B61EULL,
			0x60E798DA17C8FD82ULL,
			0x02B4E11E804D0862ULL,
			0x45D03F353FA0781FULL
		}
	};
	printf("Test Case 279\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x21DE0FE25589C000ULL,
			0x6B733298D631799DULL,
			0xEADCE392AB49273BULL,
			0x5FA17BF64C05A926ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA16DA09E474D9D04ULL,
			0xAE4E5FF132D8D3C9ULL,
			0xDA49D6D6E9681A1AULL,
			0x091E46C0AE120288ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFC066F36F4AC43A0ULL,
			0xF4609052509E12F0ULL,
			0xA25C89EE9421F9CFULL,
			0x48C27200DF620468ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFFEE892FBC28BD9DULL,
			0x1A936CF444F9305BULL,
			0x67B16AFCDBBFD21EULL,
			0x4AAE4FF62729329FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7CE9A7D5E4B21905ULL,
			0x51DE79FD98625BDAULL,
			0x5254CF1AA2544A01ULL,
			0x40F9734CA7955C29ULL
		}
	};
	printf("Test Case 280\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x68DB863C04FFEED0ULL,
			0x2C0A78F87F0C8BC0ULL,
			0x02DEBC70F8D365DEULL,
			0x655ACB6D7082C9F1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7CCD064CBD56A227ULL,
			0x92F69DCE91C6CE2BULL,
			0x581DD6098F9F77C5ULL,
			0x00D87DC3E659FC98ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x99476FD2D828F338ULL,
			0x1BAB0FCC423BC254ULL,
			0x4DD50FD54B73B83AULL,
			0x7BB23FD11EBBEB26ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5D9369689CC31B20ULL,
			0x38B216B20B3A1476ULL,
			0xFBCF66242F922CC0ULL,
			0x397FA552C5F46E58ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x76CB5D32B036539FULL,
			0xF20508D6D6AF7D8BULL,
			0xAB2894BA59B78B31ULL,
			0x08F9B31C497B3737ULL
		}
	};
	printf("Test Case 281\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFED822AD84C099B0ULL,
			0x02EF9ABB6CA787A7ULL,
			0xEBF4A36BCC11788FULL,
			0x643333471396A4B6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA575A07009FEE5E4ULL,
			0xD6E773104BE7DC31ULL,
			0x5C1CB643574F00E7ULL,
			0x5E7F5D461189014CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5342A623E7AB6438ULL,
			0x063AC13151D2D309ULL,
			0x306A4673CC6C3A19ULL,
			0x5A8BD37C4761D118ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F2DDC0EA585E050ULL,
			0x35C314B4D4DF8A87ULL,
			0xE3218E8FB99A5E4AULL,
			0x21D6944478BBD3F8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x45D3EA4F09F39813ULL,
			0x8F165B2CB5A31841ULL,
			0xD0187C79B492419AULL,
			0x5F52A101091151F6ULL
		}
	};
	printf("Test Case 282\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x61AEF36220EF9390ULL,
			0x166BF042149F88F5ULL,
			0x8053A304D5199B5DULL,
			0x7DCEA66DEBAEAB60ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B07D602ADE5E5FCULL,
			0xF25FA174569B253BULL,
			0x8547D50BB629CA39ULL,
			0x27081A347A4D49FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7120C6CB80CF7010ULL,
			0x0BC412871AEBF273ULL,
			0x5D69107B008AD325ULL,
			0x6C5FF7783ED1DF33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x876BC37AB3F36FD4ULL,
			0xD12A773EBCD9E8B5ULL,
			0x77574D6E013E0FEDULL,
			0x48305B615983E3D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE3A17335630075D2ULL,
			0x411A89C3626EF4FAULL,
			0x370B4AE69DD4DF84ULL,
			0x6BA3E42F1B4B3567ULL
		}
	};
	printf("Test Case 283\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0055D9E0A64553E8ULL,
			0x538B15ADE7CBCCB9ULL,
			0x547C613D1903EA76ULL,
			0x6740A2BF49C56F00ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6C77073FAC8F942FULL,
			0x182F1CDA13F8D1B6ULL,
			0xC82A88F2E7BA72F5ULL,
			0x5F9579B90F6BB2FFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8135CEBBD1ACDA00ULL,
			0xC4C6650C9540A809ULL,
			0x0D78798DAD785ED9ULL,
			0x776A90A72E9B6C5CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC593C1455DDE5473ULL,
			0xB9A132F53A3972CBULL,
			0x583D016BA20CA7C1ULL,
			0x654723A7F25DAFBEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE28BA789A6F23810ULL,
			0x944D8AA5C81089E7ULL,
			0x67F476E090E67FB9ULL,
			0x153DCB6703DF610FULL
		}
	};
	printf("Test Case 284\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x81D23D518DC95238ULL,
			0x7B5395C5722E1217ULL,
			0x01FB1919ED505813ULL,
			0x6AB0734E5F3CD77CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x524EF81F435D1102ULL,
			0x5635416CCD403552ULL,
			0xACCC8EA5581943A9ULL,
			0x37BAC6EAEF859380ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD579F5C493416EE0ULL,
			0xCB90CD004804C5A0ULL,
			0xE2164E93E7A6C09AULL,
			0x61ED3D1D9F69D025ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6A147B5E491CE351ULL,
			0x9BF8A0374B5EE0ECULL,
			0x13805119204AFE3DULL,
			0x3E90926BBA96E767ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3AA23227CF79D548ULL,
			0x3E5CDB8A870F8A8CULL,
			0xD65E29028E558275ULL,
			0x11D24342D98A0133ULL
		}
	};
	printf("Test Case 285\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x25CE2944F9BCF840ULL,
			0x886543C14F1F0DBBULL,
			0x4531C85EE1F5F853ULL,
			0x555E7B8723CBEF85ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA30BEBC7D87437C5ULL,
			0x5A5449425BEFE5BDULL,
			0x872C5E4CFEB84212ULL,
			0x7EDAC76B09905947ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x295F7A53B75F8D50ULL,
			0xD8ED4DFC11701AD5ULL,
			0x6AD1A7CE1FD0529EULL,
			0x58362F4F83E2FA1DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF32172727DCCBBE1ULL,
			0x68EAC19F2E6D86DCULL,
			0x6651F91591605D23ULL,
			0x79CC1F160CE10FB7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5D97F93DF069F7AULL,
			0x0FD12AE100A396C1ULL,
			0x462EA77C9793E2E2ULL,
			0x585B613FFB0AA8B6ULL
		}
	};
	printf("Test Case 286\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7296C49A4D236F18ULL,
			0x53CA591D9DB96120ULL,
			0x6B36FE6A7BCA9550ULL,
			0x7315DF39576B970EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC2D2464001A98A79ULL,
			0xACB1B2E841ECE375ULL,
			0x4CF1C518ACC4EB0EULL,
			0x56D441AFF4A9C202ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1EE6F05900AF38C0ULL,
			0xF528282CF639C296ULL,
			0x92C0FD8B3F036B98ULL,
			0x7D3F82BB6CB383CBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3AE313C21D015EFEULL,
			0x442F36A5FA96107CULL,
			0x61558CA267A6EFACULL,
			0x29C3CD9F98D2470AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x815361CFBF4E4AF0ULL,
			0x64BB35014EE93509ULL,
			0x01E9011D5F486E41ULL,
			0x29E805A2628E59AFULL
		}
	};
	printf("Test Case 287\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x472154590C3C2380ULL,
			0x4B701BB94F517696ULL,
			0x387B7329E1B5C515ULL,
			0x5E1C8C554E3824B7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9F13C32C9B993CBEULL,
			0x03ECFC8576819A88ULL,
			0x2BE8EE0F931D7D25ULL,
			0x6232357011073485ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x42356E907E603340ULL,
			0xC6065DB5C3060EAEULL,
			0x5A95532BF06DCF58ULL,
			0x548ACE4B6015E6E4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF5713D16EA54035ULL,
			0x2EDE0C65E87D7D2DULL,
			0x568D59F922894048ULL,
			0x1DF727F1C6FA2447ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE1E0372F03B3A47EULL,
			0x7E7D40231E19A6F0ULL,
			0x5C009D7D07B30794ULL,
			0x4AE01CB43CBE43F7ULL
		}
	};
	printf("Test Case 288\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x326C13E0107AA298ULL,
			0xF85F3F78942F43F5ULL,
			0x527EB04A3CEF8CB3ULL,
			0x5E0385EE8AF4D948ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x286353B2E5FFA974ULL,
			0x6AB57031D84D9C5EULL,
			0xE51E2139F1A26378ULL,
			0x4869CA71D5E0B1CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB0EF8F2750B30C18ULL,
			0xEC689C51B6F24883ULL,
			0xF4D31E54AEE8111EULL,
			0x677C304C9814A2FFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2BDE54F4C32B0CBDULL,
			0x8804DBA6B903F7E0ULL,
			0x1DF90C0EBD107942ULL,
			0x23D8DE0D652B7B06ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBF17C053865BDAFEULL,
			0x8DDDC1923F809516ULL,
			0x8A5A49F1A6D0F327ULL,
			0x4A2B528834DC49C3ULL
		}
	};
	printf("Test Case 289\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x54491EE1071551C8ULL,
			0x2C9814D62FB2A4EEULL,
			0x724B6C7EC34B0CE2ULL,
			0x77180846992C8E62ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x50E963310130DD9EULL,
			0x99EA10A96285E2D2ULL,
			0xBB573B95DC516DB2ULL,
			0x4993591E4FD6CD5DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F56CA5FCCE23580ULL,
			0x76726E4763AB9B09ULL,
			0xD9A56F98A0D33C47ULL,
			0x6A57B36BD083B585ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x26D3E722DAB44BE2ULL,
			0xEBB4E316580EBDA1ULL,
			0x1082D9B450CECB10ULL,
			0x1E33326E52D021E3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9BAF1B1B0BE172E9ULL,
			0x86631FB9CBA1E4FDULL,
			0x252CFCFD40871C00ULL,
			0x0D8C9363EB71F033ULL
		}
	};
	printf("Test Case 290\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3565CCBC7551EB28ULL,
			0x085666B6CFD0D568ULL,
			0x0D2D6E91F30C7BC5ULL,
			0x6E476E2FFA0DA719ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0132EB477C5AE275ULL,
			0x50481FF82C773E9AULL,
			0xBA1F4DA1C78AB67AULL,
			0x72917A4871E313EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7AE247DB75E8B5E8ULL,
			0xC9C1B33655308CCCULL,
			0xC2C439D169B594CDULL,
			0x66873E7B0C8AE494ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4BCA26173FF1576CULL,
			0xCB10130B3C810569ULL,
			0x4CC76EED9F5DD643ULL,
			0x2B5DA98E4E9B9C59ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB5E9DC9742E3E53AULL,
			0x7C7CBA3E6B3156C4ULL,
			0x6ECA0368954141BEULL,
			0x58AA6AD4F7FF1222ULL
		}
	};
	printf("Test Case 291\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x969D0437D48B7610ULL,
			0xC6D0D1CB506525DAULL,
			0xDA2104444CF0A13AULL,
			0x48EE10CFAC6B05C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D53ECD66D896E40ULL,
			0x1733FAD9CC2B4556ULL,
			0xFEA5ECC163FF7620ULL,
			0x391840D6F1BB2F70ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C6609320DF188A8ULL,
			0x19BC578D97AF6083ULL,
			0x234A3D65DB86C237ULL,
			0x609836E93947B69DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x30315ED36975B021ULL,
			0x8BBC2C61E7B44331ULL,
			0x4B00768C328F1BD6ULL,
			0x6276852E9DE9F308ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x190C377877EC8347ULL,
			0x3F62965AAF326D1EULL,
			0xAD1BFEFC17BCF3B3ULL,
			0x6058BFF252267B99ULL
		}
	};
	printf("Test Case 292\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF1C95919D8AE5C40ULL,
			0xA621140761F3CB1CULL,
			0x46B7323263B7D891ULL,
			0x490190654154008CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9E310F717A50BE9BULL,
			0x7D1901713CF46937ULL,
			0x7C6137C615E527D2ULL,
			0x1FC9A620A84C535AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD51AECBC419FD938ULL,
			0x924AA91EE2A9C370ULL,
			0xD2D7E03FC26BC82DULL,
			0x6067749B6E59333CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1BC6A157118864E0ULL,
			0x4EC9CF1E88DEDB3AULL,
			0x30C231BD4B691949ULL,
			0x0CD8A306CF1E1394ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDABB7DA328CAE569ULL,
			0x5003A1947C916E70ULL,
			0x4288FA8C75B83AD8ULL,
			0x61B670230787E547ULL
		}
	};
	printf("Test Case 293\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8D3536340E60A838ULL,
			0x0CE0BD5BBCD57B47ULL,
			0x887FBBD890EDC274ULL,
			0x7006A9200A9C432AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC5BFD5BF2346001ULL,
			0xAFB16E67337094E6ULL,
			0xDBFCC5C04CFF6052ULL,
			0x42121C563159894CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xECA3A8C093D22578ULL,
			0x7A641CB45B2147CCULL,
			0xEEE89439BC4620A7ULL,
			0x4891F50A0ACFA290ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFE0F1E9E1A217FF3ULL,
			0x3097D07200288F0FULL,
			0xA1D80F391C647631ULL,
			0x6864C908F2BAA6C4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC7C1969788DA39A9ULL,
			0x1469B6F53E817F15ULL,
			0x7EF3F76DEC300A78ULL,
			0x462F8B312E9CC382ULL
		}
	};
	printf("Test Case 294\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFAE1AC74EFE67518ULL,
			0xC859DFDF11ACDFD6ULL,
			0xF2591F1294D90FDCULL,
			0x4ACEE65BE1FFF4A0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6E1FDF4477DA9422ULL,
			0xD69F45B2BCD43B56ULL,
			0x3A9B3A4C0B090E6EULL,
			0x249A898CC447BA3BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x06315A1108ADB080ULL,
			0x771E341817467206ULL,
			0x66BCE5FDA11D50D5ULL,
			0x7A86700E75874BE8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1833CC3A0ADF1391ULL,
			0x788A8AEC98684FD2ULL,
			0xFE9189519FBE3AFFULL,
			0x0871DC4CCC57E903ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67E7CA3878EF35FBULL,
			0x1A05BD45C37B30CEULL,
			0x72DC7FD94C7CAFFEULL,
			0x6F1F9C94D810C919ULL
		}
	};
	printf("Test Case 295\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x14C125EC7C78DC48ULL,
			0x88B4D8D474044EA8ULL,
			0x94232483C46A72F0ULL,
			0x73F511B185CA15DEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDF69D16AF0B53C34ULL,
			0x7F11AACCCC23B089ULL,
			0xA0C0763DE10D70ADULL,
			0x2EEB35ABB42BE180ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7F6DBF753E039570ULL,
			0xDA47A4337F803A5DULL,
			0x5E12968133FF5659ULL,
			0x53EBCC1A36DAE130ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA053EB4545AE0EECULL,
			0x084BCAB4AE10D6A3ULL,
			0xD9CE13E4C051301DULL,
			0x4FE6E81BD0FAD40AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2197525BF39DD810ULL,
			0xF75F6CD68367F237ULL,
			0x1E0BEBFEF9A35531ULL,
			0x2B2821AA43596259ULL
		}
	};
	printf("Test Case 296\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1CDE5AD91F0EA598ULL,
			0x90DA0AB65F97E8AAULL,
			0x1478B9E703CA7621ULL,
			0x4AA64E08DC6ECF39ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC0E5FB7E069DDB9DULL,
			0xFC095F4D96582714ULL,
			0x61AF54B27B4D11C4ULL,
			0x15A697D2279B27F1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6D4DC5FC441DAFC0ULL,
			0xC9ECF0045BD88D5FULL,
			0xE28C254C082AC3FAULL,
			0x7608E8D713E02D93ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC7A91354D8930A36ULL,
			0x4DF3DCEC1BEC609EULL,
			0xE1C026B6DD457E72ULL,
			0x46DA99CACD2D9DD1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA1E7E2F5C4E8157DULL,
			0x863EDB970835CD7BULL,
			0x7019A05000D311AEULL,
			0x6EEFC40BEB9A4E12ULL
		}
	};
	printf("Test Case 297\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAE421B7F5C7A1368ULL,
			0x9C77594E0B581879ULL,
			0x9BA646F4140F947BULL,
			0x7FF0EAE7E0DEF48AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9E0C1A2E8B969B93ULL,
			0xD5986244318F39F0ULL,
			0x33F8CC89801FC939ULL,
			0x26958462071C4710ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x10F9C14C06256B90ULL,
			0x840BE5EE479F7836ULL,
			0xDD80FEEB82DE6B68ULL,
			0x7C45963CB84820BEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA1D8C4CB07BC1F66ULL,
			0x7CAC0379050EBB7CULL,
			0x20DC7D633018FE7BULL,
			0x530B5FA7CB1C1014ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7B6D90EE5805B6B1ULL,
			0x45DC50D3D0C9D718ULL,
			0x22AA5B4E2A4D6879ULL,
			0x5D65BAEFB9737EB5ULL
		}
	};
	printf("Test Case 298\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A860B762C7A21B8ULL,
			0xAD53D077325D1FBCULL,
			0xE6B0FB93385DF50AULL,
			0x4BB1161339E98E1DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7915D9F8D52028D0ULL,
			0x387982A311BBEA1CULL,
			0xC8CEBF3FDF134D1AULL,
			0x7A40FDC11B5B6457ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC3869864A8298A98ULL,
			0xF5E3E91055207A24ULL,
			0x75AEF036C022AA4CULL,
			0x73C136D91B0A26CCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x38BF86BBD3187FEBULL,
			0xFF5097F412111136ULL,
			0x3F226D250F84B323ULL,
			0x3C233EAE8C7484C6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB9F8E779154838BDULL,
			0xA8F7B940EC8C0CB4ULL,
			0xE5CFBEA71D18A686ULL,
			0x24EC29CCCF3B5CD9ULL
		}
	};
	printf("Test Case 299\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7BD503CC08C6BBC0ULL,
			0x8850AE2EFA1AF7D8ULL,
			0x54161EFAD78229DEULL,
			0x4C15AC936C499159ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0626C7C6958520DFULL,
			0x9E1894728991E386ULL,
			0xAFB0C29F3A1DCF80ULL,
			0x11D30AEF43205D45ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE93F38FE7E0D92D8ULL,
			0x73253F285903F9ADULL,
			0x53F907C0980D4F98ULL,
			0x5F23FE166D03975DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x77F9DE9D81EDAD46ULL,
			0xF14B33DC24615C1DULL,
			0x360FE74DD4FFC6DBULL,
			0x468BA65C9537DECFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA732F050EBBEF270ULL,
			0xB207D9A950DFBD6DULL,
			0x8759D884B5F34878ULL,
			0x0F3F0CA1E0F19C93ULL
		}
	};
	printf("Test Case 300\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x489F23C167728828ULL,
			0x9C9AC0A003CCC89CULL,
			0x1AE67AE524DB1ACCULL,
			0x501544351A440CB0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5518DECB12A21DCDULL,
			0x4DD07782DB93F261ULL,
			0x4CC213509EAAE86AULL,
			0x269DABB895DCF637ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDB1BE51472F50D68ULL,
			0x6E5605DAC8178B0DULL,
			0x28CD72B8D438D059ULL,
			0x597E6FB3FC2B7ABEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x95F3928E5711305DULL,
			0x88AFCC838634A123ULL,
			0x17337E4594BDD8A2ULL,
			0x610BF88B4254A38CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x248E24A4627E6518ULL,
			0xF82E436206A62FC4ULL,
			0x806376002336A726ULL,
			0x7E2FE908F744A5ABULL
		}
	};
	printf("Test Case 301\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9A81BD272E28D100ULL,
			0xE8EE536750E5C76CULL,
			0x49E83C31460662A4ULL,
			0x518B6EF9CBCF1387ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C2AFE281F14935BULL,
			0x88F890149F94C737ULL,
			0x7F8370DBCB1BD1A2ULL,
			0x2C72D3ECED8B29B5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x284EF924585F0F20ULL,
			0xF5A8C2BA04760944ULL,
			0x70CD1AD98CEB684FULL,
			0x78029EADF90EDB30ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2495C2229C23F86FULL,
			0xD6F3729E3030F18DULL,
			0xF5118B6A364F54A3ULL,
			0x4121E66CC0B5790DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA16AC395818AEEDCULL,
			0x8C93C2C0035120F4ULL,
			0x725FA84BE36EB6B6ULL,
			0x171F086644DAAC4BULL
		}
	};
	printf("Test Case 302\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4DC44B167391B9B8ULL,
			0xE4B4BA1045534590ULL,
			0x35E9038A9D50217DULL,
			0x5622382537AF3688ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB590C19C960E6D00ULL,
			0xDF4F33DC5553F748ULL,
			0x88C1BC0FB1824CBEULL,
			0x3E5ABB08D3D09B92ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDDA1AF38957E29F0ULL,
			0x2E0975FA8E113DB0ULL,
			0x187388572FC08ED8ULL,
			0x4900EF0577491F09ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x777932779373D388ULL,
			0x0CF184EA11642B8AULL,
			0xE54C5723F955C381ULL,
			0x38D592726260A4B2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2D3A4DB4E71D0756ULL,
			0x2D6426BC2CA7CEF5ULL,
			0x5CD9A8C7B1FDBF58ULL,
			0x217DB8FF6D6335B1ULL
		}
	};
	printf("Test Case 303\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5702BBE11FB31CE8ULL,
			0x808CED88831F3734ULL,
			0x2701761E5FD497B4ULL,
			0x528989F6610B5420ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE93A12E8EC032AF2ULL,
			0x696A2AF68636DF37ULL,
			0xB41B03BBD53CFC43ULL,
			0x6ED37400E56F130AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC679C4D6D4B54C28ULL,
			0xD7CB1E348B93F9D2ULL,
			0xD24CEC947A691FE5ULL,
			0x614609F794C8419EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEC9681E6E18C2119ULL,
			0xC9E38441CBA48584ULL,
			0x82AD6B7C377F9DD5ULL,
			0x6F544170B2A41A2AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBE4B1BE2FA5713E2ULL,
			0xC219AB01B9CC6BB8ULL,
			0xABAE1E63CC99A045ULL,
			0x7FCEBD4868CACE4BULL
		}
	};
	printf("Test Case 304\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA762186A877C1F68ULL,
			0xD8C2781C12102141ULL,
			0xDA41EC80330ED6F2ULL,
			0x68808223EFC70B02ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8156102EE9650919ULL,
			0x3886D71F8474F9C0ULL,
			0x1D12A4B602BE8BD7ULL,
			0x477355D08A797501ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C444DB269224880ULL,
			0xFC65AFD60FE4CCD6ULL,
			0x91F9AED0BA25E35DULL,
			0x640C1F205404DA27ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x943F75B37F326BCCULL,
			0xF5A8E94979009BEEULL,
			0xE76684C260176DB1ULL,
			0x172EA86E5F8661D4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD63C0E35502CB4B3ULL,
			0x60703ED86973200CULL,
			0x2B97E98F794DC70BULL,
			0x5D729693B0C1F009ULL
		}
	};
	printf("Test Case 305\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x28AD553CCD396B88ULL,
			0x7BBE2281646B48E4ULL,
			0x24F82C5A704FBF25ULL,
			0x68EE479647FD0CF7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7E209AEEA45E55E3ULL,
			0x2D8609E07DAD2907ULL,
			0x6FDA579CA4CA9EEAULL,
			0x41E192E4A0B06010ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5E5C2D11EFB19848ULL,
			0x61F60B22EA253210ULL,
			0x5A9C8794EB27BE91ULL,
			0x6AD6988B1CD3E910ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9ECF85EE7FF070A5ULL,
			0x7AC3124C6816CDB6ULL,
			0x83416FB4025EF147ULL,
			0x022FADCF50A4D2EAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5DB2FECA6AB2BB03ULL,
			0x126813DD34A210D2ULL,
			0xBAACFBFF34C1BCE8ULL,
			0x4DAE52BB30BFDB59ULL
		}
	};
	printf("Test Case 306\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x17F616167733DB30ULL,
			0x66D19AB798A23C10ULL,
			0x4C0667109DD8D6FBULL,
			0x5CF9168EFEECDAB9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE1BA760651AAAD45ULL,
			0x2249ADA7909D5E1BULL,
			0x08FFAE8EE0BFE153ULL,
			0x0BE5372FB3EE21A6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2642CC8D99731598ULL,
			0xB788F4EA5436FF28ULL,
			0x3DCF436FE94D8D7CULL,
			0x485C52BF08CDDD97ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4ACDEA6CFE320094ULL,
			0x1A8CE225C08681ECULL,
			0xBBAA11094F499C53ULL,
			0x75FC157E2F04C8CBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6F7883D3A13DFDDULL,
			0x7E5623842C5B40B0ULL,
			0xD5C051EB0D2D801BULL,
			0x1D8C7CFC91DCA0D9ULL
		}
	};
	printf("Test Case 307\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x43F3876351BA9B00ULL,
			0x85CC980375F5A5EDULL,
			0xC7F2CE1D9B0AA7C4ULL,
			0x4CBF5B278105C3F7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x356BEB7B50C16007ULL,
			0xA6B6A2F7423D7D5DULL,
			0xD40F865E005BF9E8ULL,
			0x77DBAADC32A99AF6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCE0D2B13BB5F7360ULL,
			0xED75AEA28A186224ULL,
			0x78C1D3C1801BE852ULL,
			0x525FA15610FC743CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x974DA698E12AEC0CULL,
			0x7CB48343F97938AAULL,
			0xF889AC39A608D316ULL,
			0x66F2C7345DB0D4E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD910239F0B2195E3ULL,
			0x275E5E6E21915E34ULL,
			0x7107804F69EE8C41ULL,
			0x47ECF049401DCC6BULL
		}
	};
	printf("Test Case 308\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x770DCAF55EFB6E68ULL,
			0xD556F1E283BC5248ULL,
			0x780A9A3EA4EE4812ULL,
			0x6A7706F56DD37AC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x544D95C0A93E8CCBULL,
			0xBC006DF73B5516FCULL,
			0xFF70BDCBF2676202ULL,
			0x06207ED4334C87B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9646B975CD1D0CD0ULL,
			0x46C9995D32F687FEULL,
			0x878BC6940199F176ULL,
			0x4F420A4FB8EC5713ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE4DBC722F4A2FB8CULL,
			0x385ACF6476ABEC6EULL,
			0x7ECCFC04EB046FA8ULL,
			0x1962F43C15E27C40ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3DD6E4B09C456CCAULL,
			0xF133C7FD087C9408ULL,
			0xC6822FCD93AB50A5ULL,
			0x43BDD5C7FED54C68ULL
		}
	};
	printf("Test Case 309\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7ED85593424FA360ULL,
			0x116ED7C78E9B9947ULL,
			0x587173E1ABFFF653ULL,
			0x5C8B9EC69A667AA8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x36C1FBFA4B88BC0DULL,
			0xF4C73543CC1CEF90ULL,
			0xD62B7E2F160C97C4ULL,
			0x786A0E1CC021D1E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6645B548C680C858ULL,
			0xCB74971BB8268AE3ULL,
			0x1E07F64B5CA2F372ULL,
			0x64D1FBAB8E4D9C6EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x603F858DE394069BULL,
			0x8C609561D62C7659ULL,
			0x519E49FBF9A5B150ULL,
			0x4648B36CFE3C0C7AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x12034B1945C59837ULL,
			0x5A62A731AE8FB683ULL,
			0x0A4810311E11EE72ULL,
			0x5E0958D2A1039429ULL
		}
	};
	printf("Test Case 310\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x16827E8E40CB5C78ULL,
			0xD3A4E03C1A7076BDULL,
			0x4084C0F672C6DDDBULL,
			0x41C3E031BA61E0AFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9FD35929B2350056ULL,
			0xA2D6B18A1822821DULL,
			0xB1930397F74D85ECULL,
			0x6ED3B4CB856F770AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x04F72EA0FE249C80ULL,
			0xDD5BEF46C8042A4EULL,
			0xA5704E3AE648E42DULL,
			0x57834AD7640B1482ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11EEF4153D225C51ULL,
			0xE876E4B2A1FEA6F9ULL,
			0x3E765DCEA4E2431EULL,
			0x7828CEB9A0D6A1CFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD97BD1327D8C1B77ULL,
			0xB46194BEDCFCAD22ULL,
			0x088844CB3C7243F2ULL,
			0x40F71BDE2B8D9ECFULL
		}
	};
	printf("Test Case 311\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD2B36E31C07F6EF8ULL,
			0xF134D72385A74FBCULL,
			0xF7EBCCB888CDF387ULL,
			0x4BB223EC10C9FCE4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6FCC6468D69352FULL,
			0x44A3B3C319E19618ULL,
			0xA246D4DCDF51C438ULL,
			0x3793323FBC6716B1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF6B099716E0ED390ULL,
			0x51D4A89CDE81DC12ULL,
			0x6042AE51D00E3E3AULL,
			0x4BACB5A1DDE96E0EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0F39A24128C23F9FULL,
			0xA673FF616114EC91ULL,
			0x3E732D08392CAD95ULL,
			0x7CFEA85C95B50CE7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDEE12EAC09E57FAAULL,
			0x9D0B5E651DFBD34DULL,
			0x143852BA9BBA076FULL,
			0x79953DBA0619AC8EULL
		}
	};
	printf("Test Case 312\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD78812871D9B1468ULL,
			0x261C1DFD0CD4189CULL,
			0xB0DB8F95C60ED084ULL,
			0x7D137C99476E6787ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDA2E0D342B3143C5ULL,
			0x5403612D14E17066ULL,
			0xD2A9C0FCE527055BULL,
			0x73F9B5E9F3227810ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEA83C39028129B88ULL,
			0xB3B3A50CBF184EBEULL,
			0x5CDDDA68AC144F27ULL,
			0x520C02BC26794FCFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFE66C906177490A7ULL,
			0x5047F94D4F61CF48ULL,
			0x217AC4848833D053ULL,
			0x25A00D702D586F67ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC76BD2F0EE8C788BULL,
			0x23255EA9FD386369ULL,
			0xBADE6409DB975E7EULL,
			0x1AE147926C8159EAULL
		}
	};
	printf("Test Case 313\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFAF3B99B76014ED8ULL,
			0xCFECBCECC5134EF9ULL,
			0x86D221C7F91FCF08ULL,
			0x687B299953D4156FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x93B606F32E77E509ULL,
			0xC9BD246F52B111ECULL,
			0xA7FC30665A782D2BULL,
			0x39F47B2BD5EC94DFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3D852EE455D6B6B8ULL,
			0x5590915A33B313ECULL,
			0x014D27FCA0EB5F25ULL,
			0x69FB4F10AE02861DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF26E3EF8956FAD63ULL,
			0x55E9BB90D524B0F3ULL,
			0xD15C205229F38482ULL,
			0x43517624E2B40A76ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC5498622D7500306ULL,
			0x4A1F872DF55BB762ULL,
			0x1FF954755E6A7865ULL,
			0x0144719254DFE491ULL
		}
	};
	printf("Test Case 314\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x19F99AF3D4530EA8ULL,
			0x8CFBE6298F71408CULL,
			0xD202A706E0FD6052ULL,
			0x7B3C324DC5217ECFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B7A0AD0D19AE089ULL,
			0xB319E89CBE4CC28EULL,
			0xBC96A1E3ABDDFFABULL,
			0x6C1D782D02E81385ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x165E4F3BB60BB080ULL,
			0x3BF9A50E774D3B84ULL,
			0xC38AD8B7C8B2C8C9ULL,
			0x7F20A4CC680EDD9CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA58CFA91AA98DA28ULL,
			0x736EAC360A70A9D2ULL,
			0x3679BA778EF81635ULL,
			0x6F6114300488AF78ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6261E90193A07E63ULL,
			0x76403820C45F6E49ULL,
			0xA488002D805A1FB4ULL,
			0x77B51B9BD9FBEDF3ULL
		}
	};
	printf("Test Case 315\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0BF123888692D158ULL,
			0x66114FB83FEE70BEULL,
			0xFF412DEC17562576ULL,
			0x6F99B971DD8B4714ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9E7797BF144BD8DULL,
			0x728D8796F8F9A5EAULL,
			0x11DCA7E5C744761DULL,
			0x429A2C0A6B372EBBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4987F688EE90FD18ULL,
			0x47B720A4133345C4ULL,
			0x5577D2C721ECFB32ULL,
			0x7CBC70B4BFC0D9E4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4B5E61342AEA0DFDULL,
			0x28B361248BA2D797ULL,
			0x17DD3262F2DD2A97ULL,
			0x783297AD35CD7B75ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x811FFB9D0FE23094ULL,
			0xD3FA809770A5DDD6ULL,
			0x24052DCAA281D3DBULL,
			0x3DC38DB7395B6519ULL
		}
	};
	printf("Test Case 316\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE4A8B3E00B3299B8ULL,
			0x81C499860240367BULL,
			0x22E6CA950259AA2DULL,
			0x5F21C88CDB2BCA1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB3467ECCB9260749ULL,
			0x59E6681829C9F54DULL,
			0x73E459A9A924DD48ULL,
			0x2EE78E71141B14ECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1282143194C66A38ULL,
			0x55F975B242609394ULL,
			0x8D695DEC9C0AF671ULL,
			0x569EE91EE413AFF8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x24E359A6B382DFFDULL,
			0x7C19F84DD5CBA0A4ULL,
			0x29F56FD9DACBA830ULL,
			0x4AA8A514A9DCDF0AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1A8A15A6F11679D6ULL,
			0x937292730E0B9FC3ULL,
			0x54309E19421FAB56ULL,
			0x35E39031500BA6A9ULL
		}
	};
	printf("Test Case 317\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x02F5808EABBD8A28ULL,
			0x3DBBB155F8FFBB2BULL,
			0xD19DC55886F5B65FULL,
			0x7EFC82BF521446E6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3091CC79C695B347ULL,
			0x9E7CD5ABA27265B7ULL,
			0xFEEA19BA6923E15DULL,
			0x6636475DA5BBE6A2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x347B4C335EF40130ULL,
			0x13F8324FE3992CA4ULL,
			0x2900F7B0167270D2ULL,
			0x6AD589FBD6AAA043ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x272BB948964B8E7DULL,
			0xE7C2CEC4D9FA89CDULL,
			0x201C2A982A740C56ULL,
			0x167596F9CDB8864FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4EAABC18C7FC828EULL,
			0x79A0DBBE924728B8ULL,
			0x618D0AD13C96F6BDULL,
			0x5D0D856D2D7632ABULL
		}
	};
	printf("Test Case 318\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xECD6DDD19D916CA0ULL,
			0xFAF2DEBB8574B5D9ULL,
			0xFC61EE0E0EB0E285ULL,
			0x4033D4FAB1DA0C9CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C294928E3FD0942ULL,
			0xA3124EB7B218807DULL,
			0xE0AC76D47641A848ULL,
			0x10AD001AAE672F3FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1E6D21C34D1019C0ULL,
			0x96F65D98E2DAB690ULL,
			0x4AE1A84FAB56588AULL,
			0x4DC170128007419FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x12AB8299F517B017ULL,
			0xD3DFED4D48852E49ULL,
			0x9106455DDA5C339EULL,
			0x31E5438C8D3C3F76ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE9932544FCECAABAULL,
			0x1FD934867C4695F6ULL,
			0x28E50A4181EEEC9EULL,
			0x38F986C9BBF3771CULL
		}
	};
	printf("Test Case 319\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x906D54B5F5767970ULL,
			0xF32564302D7A8D49ULL,
			0x70B6737B29091AF6ULL,
			0x50E07C9F80F7498EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC8375D236A5E1772ULL,
			0x081997A2A86EF2E7ULL,
			0x1F72FF69690D1A5CULL,
			0x71B9A43511782538ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD7BB20429CA1E648ULL,
			0xF74CA7CB7A674B6EULL,
			0x2FF2D521061B4819ULL,
			0x58822BF0072DAA03ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x039E3CC7FFDF11B0ULL,
			0x6AF128DF3635AC80ULL,
			0xCA5B75D899E18081ULL,
			0x4F7323549521D1D4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C9E420B5A6EC8E8ULL,
			0x91AC1E7E9046CA6DULL,
			0x0C0CA0A30A313B45ULL,
			0x2F28429FCE2F6CC0ULL
		}
	};
	printf("Test Case 320\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB9532FB7E9311478ULL,
			0x8FDED544FB0351FEULL,
			0x280AA19ABCCCC0DAULL,
			0x41E21A9E9C1A11E0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE5BD9A077A8A089FULL,
			0x04713768B968D9BBULL,
			0x79FF08C26AA5F10DULL,
			0x5E0D1EDDDDC8DBE4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3FA8F416DDFCD398ULL,
			0x890F5581D8315A23ULL,
			0xAF8611A4086A0F3AULL,
			0x607FEF2C0997994BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBEE67473520E0F3FULL,
			0x22AA053EE1394D2EULL,
			0x462527E3C9E20988ULL,
			0x7C7B061520F13A3BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8BE68B524CE1370ULL,
			0xA78D31CC42FA817BULL,
			0x6A33FB0B56BF3B11ULL,
			0x33C6148035DFA687ULL
		}
	};
	printf("Test Case 321\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3E5C625AF6B26470ULL,
			0xB3485074B0E5E27DULL,
			0x74EAADAF4FE9D4A4ULL,
			0x6662DDC7EEC483CEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA11240A97CAF2EEULL,
			0x4993354851B40B56ULL,
			0xC308EFBF3931B55EULL,
			0x44835A432EEDC7A1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA37FF40446AF5680ULL,
			0x71649CE0288FA2D9ULL,
			0x7DBE630754A9E66AULL,
			0x54276C61E42EB64AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7A2C63E60238D867ULL,
			0x589CB44C72D8F11EULL,
			0x16E48FFB7426D22BULL,
			0x5C65466B95D5D7B8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA9ACD5E04A3FDDCFULL,
			0xD96843B3E26F83D9ULL,
			0x83520552DA827795ULL,
			0x3442B4C4DE69BEE8ULL
		}
	};
	printf("Test Case 322\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC2F1CADAC2F44CF0ULL,
			0x71124B46AEDC8A58ULL,
			0xBFC74AE72CFC3BD1ULL,
			0x5D5B18880A123F0DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7900803CD2834864ULL,
			0x2B964BC91AE12940ULL,
			0xD1E2520232005B0DULL,
			0x4463D488813F2064ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x67DA9FE638D740F0ULL,
			0x5D4F868F4A992990ULL,
			0x38C89F45C78C84AEULL,
			0x5CBAEB52F15C4A0FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4E6C2C1EE556DC83ULL,
			0xC61623F7FB841CD4ULL,
			0x4CA37C638FB4DC7AULL,
			0x57FB91BFA69A30CBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x343D2CDC32750C42ULL,
			0x49A463230856E20DULL,
			0x23A35B8181273D82ULL,
			0x1AA4C01AA9B333D3ULL
		}
	};
	printf("Test Case 323\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x94447E77886E77F0ULL,
			0xD4AEC6BFFBC243EEULL,
			0x2259DEEEFF6155C7ULL,
			0x67096CF7E554AEB8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B37478EC624A4E0ULL,
			0x5C8E3B2FFD0517A3ULL,
			0xAFE32CDA3CEF83F4ULL,
			0x5B6162163EF845AFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5B74697C2781A8D0ULL,
			0xC7B5C86CD840A906ULL,
			0xB850F9880A9B90F4ULL,
			0x4E824864305CB7ABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1A50711B1B82F2E9ULL,
			0xB9E7C0FED98DD906ULL,
			0x960B45A767028C2DULL,
			0x2B830D18DEF6E8D7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE2C1F2186A035B5BULL,
			0x66D98473BE48CAFBULL,
			0x327B35862EC14751ULL,
			0x6E4D182C2CA22251ULL
		}
	};
	printf("Test Case 324\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5AD2EE3E1735C9D8ULL,
			0x48D762A316C733C2ULL,
			0x6970E406BBFB2890ULL,
			0x587FD33E5B320438ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72D3ED922B87A328ULL,
			0x4208D1298B854112ULL,
			0x27EF2C42319FFC5AULL,
			0x4DA57F107F979A0BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x30FBCD0DA72D9550ULL,
			0x26030DF69DCE3B11ULL,
			0x1466696407F1AC5CULL,
			0x6B98B8B9E11D693FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE1F34FC48B1F963EULL,
			0xF74E8CA2A29C43EDULL,
			0xEBBD5C951848D996ULL,
			0x5DE34CDC84AE1B5AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBF15492D1004DCF0ULL,
			0xF3D4D0DA413E2C7AULL,
			0x27120346AC703ACDULL,
			0x176115249FF75C12ULL
		}
	};
	printf("Test Case 325\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x358EB2444FD43548ULL,
			0x66DFBF49C29520A5ULL,
			0x2687931EA8F10B32ULL,
			0x5B28730A3024B6D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEAF067BE5A983ADULL,
			0x20BFD42A29E4993CULL,
			0x544B0048AF97B0F5ULL,
			0x5C4A2C1F5EC7BCADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAB74BCCE4D10E1F0ULL,
			0xE21356BCDF6765EAULL,
			0x0B8CE9ABE7214801ULL,
			0x4C382933F5D43A66ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x35633C3EF9F0E791ULL,
			0xD113A44EA8BD208BULL,
			0xAC464365EC227F6AULL,
			0x41FFC42ABAF84016ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4DE9744C724A77A8ULL,
			0x17C1F4FE41EF4BF2ULL,
			0xC5D0FA7C80FDF044ULL,
			0x4D85E26F0849ADDAULL
		}
	};
	printf("Test Case 326\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x648E773F21E658B0ULL,
			0x20E06CC1AF902415ULL,
			0xB843972C98ED074CULL,
			0x45D717D6DD440242ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBF625671DC05CA27ULL,
			0xB3AD8C36780490CFULL,
			0x3C0870CF5A73CDD2ULL,
			0x4A1089F3FE30BF03ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x233658664CC62AD8ULL,
			0x314C14B8FC18B288ULL,
			0xB59F7E669D37C873ULL,
			0x6EB13CCE275495C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB23170CA3244360BULL,
			0x618C6AFBC1619A10ULL,
			0x991F84892036603DULL,
			0x1233D2904DAE8907ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEF68725FAF4437BEULL,
			0x2685C8E9898D0438ULL,
			0xBBA91171D082650DULL,
			0x768D3D89A3176E68ULL
		}
	};
	printf("Test Case 327\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x541408E282224BE0ULL,
			0x8EEED120D6FAFAF6ULL,
			0xF27E639868DE0F73ULL,
			0x6856AF09650456E1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1818C690E2966C49ULL,
			0x125E470529BE1D4EULL,
			0xF2263FA50DCFB5F4ULL,
			0x1D2E9504902FFEB6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2560579D589F5790ULL,
			0xB7066F15693F3AADULL,
			0x5972A2E84BFB2F82ULL,
			0x4BFE18EDAC40F727ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x91492BCD6E7D36ADULL,
			0x1056B23FF6139F8BULL,
			0x791BC4A35940E4F9ULL,
			0x11260B5D2A609638ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x83B523BF19E14560ULL,
			0xE80924447D2A1286ULL,
			0x686D0B795F645277ULL,
			0x699A07A3ED430060ULL
		}
	};
	printf("Test Case 328\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEAAE557E440FEF90ULL,
			0x6C70B2B982810636ULL,
			0xCAD52DB1F37D2124ULL,
			0x4771776E5FD86568ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9B6F5D06D88F862BULL,
			0x9ABFEA0DDA816950ULL,
			0xC503E6472D245348ULL,
			0x64F78CCB4BB73B45ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8834F4BBF569AE98ULL,
			0xFCBE14D7CF6EB73DULL,
			0x6D85B4A4EA2D55D6ULL,
			0x4BF1EAED1192D3A2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAB93743F545EDB61ULL,
			0x81502CBF231B954BULL,
			0x5FECF6455ACDD1C9ULL,
			0x0CC8BCAFD3567764ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4C38EBE2974ECADFULL,
			0xED54654E28302965ULL,
			0xA04843DABBBF23E7ULL,
			0x53424865FBB426A4ULL
		}
	};
	printf("Test Case 329\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x90E3B5E998BEA280ULL,
			0x484D80ED9E6C7347ULL,
			0xF1BEEB67EC09D81BULL,
			0x5A2A922A27D79896ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB6EF3AFD382B9DB6ULL,
			0xB58E6EF86B6FC0D0ULL,
			0xD5D20D991B1D4E47ULL,
			0x41A44664C82DA277ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x84017DB6156D9658ULL,
			0x08502BFDC987E49CULL,
			0x052C8B5196E79DE0ULL,
			0x43BBDA341A9F0DCAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDE01D7BC2AB67E25ULL,
			0xE25F95317A406730ULL,
			0x9A1E7D169F813833ULL,
			0x6DE6BB6303410410ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1787B2092491053FULL,
			0xD27BE821EFBE4B09ULL,
			0x6AA31FFD6CF9C795ULL,
			0x5E10838CCF725990ULL
		}
	};
	printf("Test Case 330\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0E05E8FD1D9AE178ULL,
			0x49B404D35EB125C8ULL,
			0x2E154AC86416EEE0ULL,
			0x5120FA52C806BF8CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5D54D4BC77489480ULL,
			0x717497164CA55901ULL,
			0x009A2EA55AA01727ULL,
			0x05E048928673C6EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C6C0D7B2B983850ULL,
			0x0257D53B06007BFCULL,
			0xA7C792D2D555A796ULL,
			0x619EE5E385498270ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x393EA5480D35985CULL,
			0xD2EE586E5D578333ULL,
			0x2E69CF9F84A8D40CULL,
			0x0687CC988FDFC182ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEE702E1E8D55BEA8ULL,
			0x9460CA5D3DF03E1BULL,
			0x3C392B57A770BB79ULL,
			0x739A4AEA46C56241ULL
		}
	};
	printf("Test Case 331\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x82C5D2B454CDA1F0ULL,
			0x02DB5D4C457AE7A9ULL,
			0x2AEE46CADB4362ECULL,
			0x6512EA414B9589C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6E9099F1C29F6731ULL,
			0x1CF060FDE54E2837ULL,
			0x846D0CA22E70A21EULL,
			0x26ACE7491DB56BB6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC10EEB4D53DEF5B0ULL,
			0xE616DE966BDD5578ULL,
			0xA6585448CBD8B91EULL,
			0x40CF9DE4EFBE56D6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9D509D94E70EA426ULL,
			0x5B3A41B2A6462CE4ULL,
			0xF9F449FB04996C45ULL,
			0x6FDFB84EE0E4C04CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6BF1E58F9EE3FB3AULL,
			0x21FE5B32FF50E799ULL,
			0xF27DF5E68084FF43ULL,
			0x58A4B041A4AD0A3EULL
		}
	};
	printf("Test Case 332\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBD0BD95B7F19C180ULL,
			0x9386ADC283402126ULL,
			0xA603DC82802A5BCDULL,
			0x5C6772FF51DE13E9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAAC2D2EBEC335AB3ULL,
			0xC4CAC144415DCB41ULL,
			0x1A388F91C04A98CBULL,
			0x71DAD19B2ED4326AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEA53F3FCC93787E0ULL,
			0x0953B7C42F18E766ULL,
			0xBA455866025331CDULL,
			0x7C908742C5CFE341ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0EC29D1131D0A584ULL,
			0x14D1C1A01FF1CB4EULL,
			0xEA1331F214894F96ULL,
			0x66E9F0FB1109423AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x814EB07C232514C4ULL,
			0xC65A580B78F0C471ULL,
			0x553515B7503F2683ULL,
			0x25EDC833CB6CE36AULL
		}
	};
	printf("Test Case 333\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD759A19F3C804DB0ULL,
			0x41FF2CE8DFFFF239ULL,
			0xC05A45AE8770A1B0ULL,
			0x771EFDE42ECA093FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFEDAF77D3A4845BFULL,
			0xD8DF3D0FC1336CDEULL,
			0x1986CC74BF751640ULL,
			0x1B99AC73D77E2BEFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0036D2DCAD0E79D0ULL,
			0x8641783C601FF4C6ULL,
			0x0214FE764C04B94DULL,
			0x6EC5B34C336B6D1CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1C80EE2A05420711ULL,
			0xA1C92FA8CAB6FC62ULL,
			0xDD274FBE8DA5AAEDULL,
			0x50085405AB89E1AAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x317BA76249603AA8ULL,
			0x0A25B083B9EF5E74ULL,
			0x4838D578149AD41FULL,
			0x50D8E1D937E3ADD9ULL
		}
	};
	printf("Test Case 334\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1D17CD19E6AF4218ULL,
			0x72EC6BF9A159B1F3ULL,
			0x325750FD02A2C14EULL,
			0x78521187692F335EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x438069072062CF04ULL,
			0x04E5E0A5D3682780ULL,
			0x034DD827AA034EC1ULL,
			0x42735E2D7418893BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5AFF7FC75FED45B0ULL,
			0xE87F8F64A911E173ULL,
			0x2600E7250A8F0DD4ULL,
			0x4701594D05E77782ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x761893A3E51CABC2ULL,
			0x150459B6EF1D7DB3ULL,
			0xA5327861DE613957ULL,
			0x7D793208BFDAC37BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7EDC0F528A935DA3ULL,
			0xBD22B2AA8CA1371FULL,
			0x55487D709642E1C5ULL,
			0x70EE4D69DB7AA64FULL
		}
	};
	printf("Test Case 335\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x51BF0126A4959158ULL,
			0xDB3C95F71D3F2275ULL,
			0x1028BEDFF46612E8ULL,
			0x437BFCEBCA36B572ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9FDD64EB79065F2ULL,
			0x53FC9D365183A32CULL,
			0xD811865FEBCAD7B6ULL,
			0x69B2BF1F578EBDA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x652AA4A151174240ULL,
			0x16A18B300CF1AB9CULL,
			0x6DBA0AA897C57B54ULL,
			0x6048D5AB4ADA58ACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDB3D268237182F40ULL,
			0x59875634E6A36254ULL,
			0xB4159DD25470C26DULL,
			0x4C3D29D1DF62AEC1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAF09EB37F53D7A7CULL,
			0xF703A08E39C4260CULL,
			0x17FA78B8AF16EB8FULL,
			0x166DED017136063FULL
		}
	};
	printf("Test Case 336\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA7E1A22E51E1BCE8ULL,
			0x2457E1E2E04D0FDBULL,
			0x0D2CC9BAAB3810AFULL,
			0x4A2756A32B8653AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8239DA2458F95432ULL,
			0xB4591D0B01375FD2ULL,
			0xB192E75EF89426F1ULL,
			0x04BD6380198D028AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7F43595A35026B0ULL,
			0x804F1EFBA8400BF1ULL,
			0xA811EA2D97DF52ABULL,
			0x5C5A8EC822C1F1F3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0D319296491D38E7ULL,
			0xE86813DDDA3067A6ULL,
			0xCECEC0DBD8D76212ULL,
			0x60993900B326C7F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAFBE95D3DB8ABB7AULL,
			0x075BDFB79BB7DBCFULL,
			0xDF71240CB809A0BCULL,
			0x6ECF28B60533F6A8ULL
		}
	};
	printf("Test Case 337\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1E2290851FF31AE8ULL,
			0xC1F828149D66AB3DULL,
			0x7B479A3C0CEEC1CBULL,
			0x7770B2C96013642FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7E6FE5F1D85EDF05ULL,
			0xCF7AFF45287D14D7ULL,
			0x79879C025DC510EDULL,
			0x3D1B383700A212D3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x03402CC2218E5E50ULL,
			0xF2A414F2AAD778FDULL,
			0x1E0C8912D404494EULL,
			0x56F0535D92D8A52AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x19D2E2E316874822ULL,
			0xB865442999F97669ULL,
			0x4413AEDF2E266671ULL,
			0x4CEC4ED6563AE252ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x509C6C79E7B1D596ULL,
			0xEAEF96A7E2F72690ULL,
			0x0DC3C6C99F82C72AULL,
			0x208E756E25A0939BULL
		}
	};
	printf("Test Case 338\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4F394C140C3BE300ULL,
			0x80AC3AEC1ECC36EAULL,
			0xC00E26DCB7A15814ULL,
			0x534D645A1E8ADD7FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0B3AD440256F1169ULL,
			0x62F6546ACC37DF78ULL,
			0x5ABEA5EB429E9780ULL,
			0x5E8CCA965E76813FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2FBF62E48E4350D0ULL,
			0x78CA87EAD6C53920ULL,
			0x69F8E55292D5F4D0ULL,
			0x601344D4E75DACCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB5BF1FDCE0BCA4E4ULL,
			0xB3BA6DDA06E521EDULL,
			0xBEC869C2C1B293D1ULL,
			0x76B44FDFFE54FC0AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x76B68E44376CDBE2ULL,
			0xEC031FF87A55D3E1ULL,
			0x61EF88F343DB1B74ULL,
			0x28C5168B0DA5F5D2ULL
		}
	};
	printf("Test Case 339\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5707CC07BD4F7710ULL,
			0xB445FED5318B6937ULL,
			0xA33AC0D77D6A8B53ULL,
			0x467819F059C11496ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x93BDA4F6658C5CEFULL,
			0xC5A4003A04D0B3D8ULL,
			0xA7928D04DF90E8B7ULL,
			0x62CB7FBE4980DEF3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4112E350DF59E548ULL,
			0xEDFE1BEF8947BC3FULL,
			0xBD4867F2E260120EULL,
			0x4EB0FA282198FEE1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB0BDD356B9846178ULL,
			0x89382A35D2563234ULL,
			0x8EB235D485FABF40ULL,
			0x452C611ACD7472DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA44EA396B429DF9FULL,
			0x858F1B8145DDD96AULL,
			0xA507AA84ECF139C8ULL,
			0x790DCAA01B5E3FD5ULL
		}
	};
	printf("Test Case 340\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x308B97DBCF1081C0ULL,
			0x01FBD52C99D05DE7ULL,
			0x876536DB68BF869FULL,
			0x7EC20A54564405ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC84E0C54470E182CULL,
			0x23394176C74BE0ECULL,
			0xD55E3D74A6128B0CULL,
			0x0724A3D39D647176ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFA7EEEA9C1899D00ULL,
			0x9BA312B6DC0D2A48ULL,
			0x0DEC55C59328CF94ULL,
			0x7955A3CC70C455CCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF881D78B1CA2DC1ULL,
			0xEF7528C785A1E6E2ULL,
			0xCB2F0D8C8A312FE6ULL,
			0x38F6F55E2EE3D659ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x410C1B74513F33E8ULL,
			0xB0123E66A14D9485ULL,
			0x9D9A521D196DEB5FULL,
			0x4C06D4780FCDF882ULL
		}
	};
	printf("Test Case 341\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDF5C30A1A5A1BAD0ULL,
			0x5B9A56D9C241DE65ULL,
			0xEFFF11C63F417C06ULL,
			0x6782233365C36134ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8391017E8966C86AULL,
			0xAB2B43A795B230E3ULL,
			0x0737F406E8C5116CULL,
			0x71D9970C7ED2AC1CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1F941F166F1749A0ULL,
			0x82C0BED995DBF61FULL,
			0x2568695CCF3C4FA6ULL,
			0x5D3F02FAE8A5671FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x86BE2E43667B05E3ULL,
			0x32E511ED9E248685ULL,
			0x1DA26CF8CB066632ULL,
			0x05C322474994775AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x957927AF7D3B7754ULL,
			0x6E7DA001E6153405ULL,
			0xB42C58E176BC372DULL,
			0x60140CC581A81B23ULL
		}
	};
	printf("Test Case 342\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x102B0F04F941F5B0ULL,
			0xB2D5A243D07DE551ULL,
			0x1549483C5D49B2E8ULL,
			0x59A30358148CE265ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x74417EFB5C47B4C7ULL,
			0x11C9352E56F00D37ULL,
			0xF017632045158A23ULL,
			0x2D3455EE9E11919CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x53711310324E6C78ULL,
			0xB708437E31F84BE6ULL,
			0xD823A9B85FE659C5ULL,
			0x65FD55BBEDE471D2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1A1D8968D34044DULL,
			0xD516E3CFE82B533FULL,
			0xF9FE81200E9D53C1ULL,
			0x62E7F643198EF161ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2FAB098918E13D4FULL,
			0x69B212D103BA1B9FULL,
			0xC260EDF2E8BEE097ULL,
			0x591152E1347A2B5BULL
		}
	};
	printf("Test Case 343\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8B3AE4810C8DFA8ULL,
			0x9197E193650BFF45ULL,
			0x54FC10133CF577E4ULL,
			0x5369EF645D7FE160ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1E7271CE58F18559ULL,
			0x6EB910BCF22399D5ULL,
			0x2BB4CFBEE00B4192ULL,
			0x1796D06862259C38ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x39D1440947E6E160ULL,
			0xA278287010CE8C7DULL,
			0x6F69367DF63958A6ULL,
			0x43D7E0C76799C697ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAA81A0A6B78557DBULL,
			0xEABDE9911AE6250DULL,
			0xDE486C73B63FD085ULL,
			0x27B2D57867DB08A7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x85A122C32207E3A5ULL,
			0x95C0D11F98D60150ULL,
			0x3381AC198D1E3B1DULL,
			0x56E71D5327DC00F5ULL
		}
	};
	printf("Test Case 344\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x154FDB4167355998ULL,
			0xE0CF977A473829EAULL,
			0x4845EEF1D2EF413CULL,
			0x53018F3DE8704334ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x43DB38DAC68B4862ULL,
			0x3D0ED38876AE872BULL,
			0xBE753E8EA6C134A2ULL,
			0x011761557C4B99D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD0A5ECE1F7D79530ULL,
			0xD4AFD1B7D90E8436ULL,
			0xC7D2B59A5AC1E1C0ULL,
			0x671145B855464929ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE8D653B4B408F92DULL,
			0x53B61D58250AF7A0ULL,
			0x5D32E36D6A08BD41ULL,
			0x7291C29DFB87556FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x26ECB20889A581E7ULL,
			0xC10BF3002F3FD5DAULL,
			0xF0CBC97D963CDD14ULL,
			0x471B92B5B22D4839ULL
		}
	};
	printf("Test Case 345\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB1095B353E4B30C8ULL,
			0x19A75E65668E6566ULL,
			0xEFE32A4703DD39F3ULL,
			0x4B856AB50A93B386ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x201BD9772846D2E9ULL,
			0x81A9C951B4FA6CA0ULL,
			0x46E0E912CDAD5BA1ULL,
			0x78D4389565D84109ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7B2DD9B95E625C20ULL,
			0x1D095457747B17D6ULL,
			0xE32724DD5A766E9DULL,
			0x4BFF86629210CBC3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD4F0D6D4EEC8D63DULL,
			0x8693651EE958C38AULL,
			0xB0A316650952D68DULL,
			0x40ECE569C0811325ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x347384AEF7811EBEULL,
			0x4FF6A243D5CF232FULL,
			0x6413D56B4A9DC888ULL,
			0x628D982B5E6EA6AAULL
		}
	};
	printf("Test Case 346\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x27C549C958F330A0ULL,
			0xD07DEB59360790EEULL,
			0x94106DE02B68DB73ULL,
			0x6D7B9280D0D4DC5BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE4C874995587277DULL,
			0x885D1CB9F573FBC8ULL,
			0x81DDCC67CBC64224ULL,
			0x3852A1C917520F28ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A2DD08D53334980ULL,
			0x6E1A8A4EFE070811ULL,
			0x6A26EEE82F2D781BULL,
			0x641F15FF1163F621ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD0C2F670F03157FAULL,
			0xD87C1081047DFE6FULL,
			0xA4970C47B322BF8FULL,
			0x5809D7C76FAAB624ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE05DC22DA28DB858ULL,
			0xB7E3F8D332039B92ULL,
			0xEAECF707ECEE3226ULL,
			0x03A9CB5CFAA7EC57ULL
		}
	};
	printf("Test Case 347\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCB68D07B74B6CDC0ULL,
			0x827F3ADABD792DEAULL,
			0x6B3CF7DA6CF9C069ULL,
			0x5B815CC7A54693F2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB3D3133A80B2DB2DULL,
			0x5D19626A09DE9D56ULL,
			0x5BE6650102DD8B85ULL,
			0x567B8F96EECE12DFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB5DCCFD2797DC9D8ULL,
			0xD7FEDBE698393B9AULL,
			0x577B8D8B750E61A9ULL,
			0x7271F7A263070062ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3F5AF7E79E819C7EULL,
			0xC245B42EAF3882B9ULL,
			0x2B8958E55F731285ULL,
			0x69BF23AA21BBF6D4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8DFD58AF5BEAC23ULL,
			0x79A12F3A91EC51D4ULL,
			0x9E7414013B2D5491ULL,
			0x641802C9774128DBULL
		}
	};
	printf("Test Case 348\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9D3B56F1C6EC1650ULL,
			0x5E4C7E3F54F7B10EULL,
			0xD47B7BAAFE8DCF08ULL,
			0x47ECF0E10732C37CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4DD3E4B4A4D8EFA3ULL,
			0x77D2D05C042F4D3BULL,
			0x2B63F753D03261ADULL,
			0x0122996677AB8C59ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD97BA0F7027B9ED8ULL,
			0x22403C72B8B912DEULL,
			0x4B385B478DAB173EULL,
			0x6470B04FD9D5AAC8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5EBA45D8D11BCE02ULL,
			0x36480E91FAED8714ULL,
			0x172B9BB92C9B63D8ULL,
			0x554CCDA6132F96A4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFB3B01F99A149592ULL,
			0x038A5C4BC0D3A344ULL,
			0x4B9ECC13F1505C65ULL,
			0x3F3F0D1499526B8CULL
		}
	};
	printf("Test Case 349\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC0DF569C6B055538ULL,
			0x0D915663E3CE0F54ULL,
			0x7FF72555B8A846C8ULL,
			0x671437313D7D6407ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x07D142CD3186FDDEULL,
			0x829B868A5D6732EBULL,
			0xBA52DFB9D0013440ULL,
			0x3AF89B1E5DF50F4DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6567A341F9FC5620ULL,
			0xD66440846E602FA5ULL,
			0x4D465D31AF5C2946ULL,
			0x538639FE60AF4CE8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7AACAF23262D74E5ULL,
			0x89193BF1B517ADF6ULL,
			0xABF09B39BC16D631ULL,
			0x67D3BF977AD2EB2BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3F67EA01776970F9ULL,
			0xCFA848A20D9BF8E9ULL,
			0x0781ED308406E824ULL,
			0x1E5496E3B60555AAULL
		}
	};
	printf("Test Case 350\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x302931733AC36230ULL,
			0xA48A046E113E3088ULL,
			0xC5F11A164673E722ULL,
			0x7617A3A70506A936ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x43E5148F5F1F4767ULL,
			0x4686DEB009D81FBEULL,
			0xF2FC96AA941025C8ULL,
			0x2CBD77DC30D06F8EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xED80FB76A579A480ULL,
			0x4CC1340AE7C72BEFULL,
			0x6BA3CAB391654751ULL,
			0x7C9B80FC87F11C31ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x68094F3635039DB0ULL,
			0xAC1A2286245883CAULL,
			0x63FD72BABB61D6F0ULL,
			0x0B2EF9C65CAC2035ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x80CD19AEFB4BBDDDULL,
			0x85367E4BC5B3DCF0ULL,
			0x487263A7B03B95D2ULL,
			0x777D7BC7ADBBF690ULL
		}
	};
	printf("Test Case 351\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0581BDB79D5358C0ULL,
			0x7D82C67FC7188EA5ULL,
			0x42DB67B55018CF53ULL,
			0x55A03A9498C4DAF5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x557326199B66840CULL,
			0x37DB27DDE03272CEULL,
			0x73CB95A6A8D680A5ULL,
			0x75DD7C2FDE4A8A2AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C8B33B58F2FC2F0ULL,
			0xACD44797513B17ABULL,
			0xF1EFF95BFED65581ULL,
			0x68D67F5CAD60E095ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x36BB0896A9EF01C9ULL,
			0x76EB5DB398494F07ULL,
			0x2404D289F78924B3ULL,
			0x3CAB23C7005D7080ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6506B8F1D230EEB2ULL,
			0x8AA3C78E1B101542ULL,
			0xC3246D2115823B3DULL,
			0x63B07AF2935BB637ULL
		}
	};
	printf("Test Case 352\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE4719F57158421A0ULL,
			0xBAC29297BFE6BE1AULL,
			0x915A7142148C6600ULL,
			0x471CA15548E71DB4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x20A7ADF7C97010B9ULL,
			0xA2D798B35CE88D1CULL,
			0x9F07E816663C4D3FULL,
			0x3E72C1672556B13BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5E4ED78723EDCFA0ULL,
			0x71F3B171BCE0202EULL,
			0x01D4CA23F9EF582EULL,
			0x525B346D1979B9F8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B3FC88919D8F20DULL,
			0x317175516EF4ABDFULL,
			0xD28E973B2E63AAE9ULL,
			0x3E6D26D43C5EA5EBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x581143B6F37A9883ULL,
			0x2EE50467108BD756ULL,
			0x146019E6F4E57995ULL,
			0x5C4A01D26CD61D7AULL
		}
	};
	printf("Test Case 353\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB8668BE165072968ULL,
			0xB8AD3653468BFA39ULL,
			0x88F774227648395EULL,
			0x47DD0B3EF1A1D16DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2700E25453438563ULL,
			0xE2CBBA80A5A88C3CULL,
			0xE984DEE60F346C28ULL,
			0x0F53F4FCBD51F464ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF73299C1832111C8ULL,
			0x440472E5C605655EULL,
			0x199DBE06F1788E20ULL,
			0x66B4460547D2F8AFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6ABE2ECA1E016302ULL,
			0x9F5AFB3095187B96ULL,
			0xDB730503D5E43D77ULL,
			0x44334F9F3BD9C3E8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB014D87A624CBA3BULL,
			0xD96A87BC84F990A7ULL,
			0xC80114928D59B062ULL,
			0x29AD4468C44B7DD9ULL
		}
	};
	printf("Test Case 354\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA47B4432722A4CD8ULL,
			0x71CC63A92EA56433ULL,
			0xA3C8F6DAA2B1E202ULL,
			0x5EEBF416047218C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x00E04ACB7369C36BULL,
			0xF1EAB2266C954532ULL,
			0x178A6050CB42A5C8ULL,
			0x5904A02E2D122D5CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6E4DEB2AE136C578ULL,
			0xB55F89D48116080CULL,
			0xB5479B59A2017FFBULL,
			0x43890E4FD41CAF1DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x01B600EAC42AE872ULL,
			0x2BBDA1EF6E6BDE01ULL,
			0x5130B18E2CAFCFC1ULL,
			0x18121EFC8EEC5BEDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0CF9BE4EBDA052DCULL,
			0xF1739D2868575649ULL,
			0xDF2606F343C17F42ULL,
			0x6451FD52F22D12E9ULL
		}
	};
	printf("Test Case 355\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8E13BC8525EA2A20ULL,
			0x2ECB41941FF89B5CULL,
			0xEC5B1E89B20196A9ULL,
			0x50B9217E39A635BDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD9887430C503201CULL,
			0xD98F17595C9998DFULL,
			0x3D3B70BF15A5C2DDULL,
			0x70E28719A27F76ECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF4D9E58F2121AB0ULL,
			0x67698A8C1A5F9D22ULL,
			0xC6D0C1EABED070D5ULL,
			0x7364449B9A861F9DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x082552DA8046208EULL,
			0xDB16ABA130478053ULL,
			0xEB7359BA5ECD382EULL,
			0x10FF358AA66FC7F9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2ADE4DC90E68F36BULL,
			0xACBFD601552734FAULL,
			0x761798D30C84F416ULL,
			0x4540019B7392198FULL
		}
	};
	printf("Test Case 356\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9FE0280DF56EB180ULL,
			0x93635C4DCF1CE5AFULL,
			0x9EA8325C7E17549DULL,
			0x700382FEF581AD16ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB9432C8202685D48ULL,
			0x25E508A8E5C9F6E1ULL,
			0xD0BA805E7F3217CDULL,
			0x146CCF828745FE59ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D0076A72AF58E00ULL,
			0xE439E78966ECEEDAULL,
			0xE1256D65E4F73C09ULL,
			0x7C05B5DF0E9C3075ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD41A78A29C2574A4ULL,
			0x01FC8C65BF37F885ULL,
			0xDA505543494E00C5ULL,
			0x75C1CC3B150BC390ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x75DF6A0242AFF8F8ULL,
			0xD126E68602D3F3FFULL,
			0x7BE0D0EFD0D04C78ULL,
			0x70AAA7461E51B9EBULL
		}
	};
	printf("Test Case 357\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8471BF83DC9DAB0ULL,
			0x12271288506D391CULL,
			0xB81EE0F5CC69DF3CULL,
			0x4F074ED9C3DCFFB3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB8A468D88F7CC22AULL,
			0xE65A692B95CB2559ULL,
			0xFBD2D41AF4CCD316ULL,
			0x0D5A3BD4F11737E9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x79F1A6D0F5516A18ULL,
			0x9280D8D6AE063024ULL,
			0xC0BFB8671BEE8C3DULL,
			0x4A424D6D185F3A81ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x67678D1B63C49DFCULL,
			0x7FFE57D421A53AB0ULL,
			0xEFF4A2F1363D5D85ULL,
			0x616C163B15AC4646ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x484F8596FBFAAEFBULL,
			0x5463A32960BBCA69ULL,
			0xCEFEE2F2BFA82DA2ULL,
			0x194ECCE160007E1AULL
		}
	};
	printf("Test Case 358\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA5D990CCF9368238ULL,
			0x19133606CFEC86BCULL,
			0xFBBDFED2215C6127ULL,
			0x5C091E3E35C497ABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE31BBCF3D6777A04ULL,
			0x70BF76FB7CBE1212ULL,
			0x114E864808803E11ULL,
			0x72E521CD68DAAAD4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x14215E52AABEE0D0ULL,
			0xAABAB62FBB81FC11ULL,
			0x2D8A1CF39BC38416ULL,
			0x6306556AAB50ACA0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x023AD2F08AC754E8ULL,
			0x662B606299D615D0ULL,
			0xAA6FC93BEA12880BULL,
			0x6B596E0ED386151BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5F620C7484D43EE8ULL,
			0x2E4D233DC572EFA8ULL,
			0x28363C6C35466D32ULL,
			0x44C5842EBF3C2F71ULL
		}
	};
	printf("Test Case 359\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEA8F498D8F04AAD0ULL,
			0x953735A6C3B5FE41ULL,
			0x00ED8B441D9241DFULL,
			0x42A486D4C43290BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x949EC02D6DF1F8FBULL,
			0x5AD0090855B19964ULL,
			0xEF0DD38EC70E9D85ULL,
			0x243B3426954469DDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x38C020C5D0302548ULL,
			0x2FD50EDA507D4263ULL,
			0xABC47167AE75C08DULL,
			0x4989328E2EDAD7FAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD780E4BE5876FBADULL,
			0xDBAAE85CF86D9D18ULL,
			0xBC7DB74C9C0556EBULL,
			0x0397687D28DB52F6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1B81CFB760C31A81ULL,
			0xF4391C57D795F71BULL,
			0xF463B6A27FD5960EULL,
			0x55150B9F77C04D9EULL
		}
	};
	printf("Test Case 360\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x865938F34B3A6978ULL,
			0x2CED4EC5B7AF5BECULL,
			0xE88D13FAE9AAF211ULL,
			0x4228DFBEC6A9A103ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x700916C65415CA86ULL,
			0xC1798655B8E521FCULL,
			0xE5E32E4EBFCAE517ULL,
			0x70D6DD19BE643812ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x134D04401A71B4D0ULL,
			0x4D57E7BFEB523A5FULL,
			0xE2AA38DAFDFF1604ULL,
			0x7782959C290CA276ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC78BA0017A1C0CA8ULL,
			0xB379F2D578C70E7FULL,
			0xAC0911E26E616693ULL,
			0x36D1A94055A6BB47ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDBBDDABCB526AE29ULL,
			0xBEF490ECD28314A3ULL,
			0xAB91DE74DA1F8AE0ULL,
			0x3EBEC13576F26BBAULL
		}
	};
	printf("Test Case 361\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDCD319334A2D0258ULL,
			0xA4B1D837EA4E7D6AULL,
			0xBC4DA66A01C1C093ULL,
			0x686147ECF6B210CFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x66EBD8210EB0B1EAULL,
			0x30A01B4CDE73DF42ULL,
			0x36F2BC86E1889C6FULL,
			0x1EE0D67B17B76195ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x53D2AB0532EA73E8ULL,
			0x001D292B9BBBE127ULL,
			0x9C1CC0F655CDC2ADULL,
			0x711FC652F9837E0EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x875380D3F11EA208ULL,
			0x8ECECB237C0E6FA7ULL,
			0x8F11C72194A6F008ULL,
			0x5D73C1F9714217F8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x71923D73DEE31D7AULL,
			0xA0207ED1D1674884ULL,
			0x2D4A94FF21A3ABE8ULL,
			0x3BDF5FF7E05B1AF2ULL
		}
	};
	printf("Test Case 362\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x32316F20B10AC020ULL,
			0x498C700DCD3C01F2ULL,
			0xB4CB4EFE7BBC4D25ULL,
			0x45697D696B5A71E9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1EA5F9A2312F17AEULL,
			0x3871E262D8309674ULL,
			0xB9C048257DA8200FULL,
			0x214E5BAEFBD9F952ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1E7DCF24C5FB0858ULL,
			0x0DD24099B0BB84FDULL,
			0xB717F4A2B456B572ULL,
			0x5417C319A6AA51AAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xABD4994EDBDF5260ULL,
			0x73C98C130505FCFAULL,
			0xAEE12EB59737E069ULL,
			0x4E3762F5FB3224C8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCF0DD18984D32FE3ULL,
			0x983E611E417D97F0ULL,
			0xDFBCB83D6B811863ULL,
			0x3874539FC7E8888CULL
		}
	};
	printf("Test Case 363\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x456A2A1E8604E180ULL,
			0x91A6246C19F622E5ULL,
			0xAE75FD0974191000ULL,
			0x70218FA4440ECED4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFF3279942CA7FE80ULL,
			0x3F44D8706754CCDEULL,
			0xC6C4D764FB5CF60AULL,
			0x72B27B69220DF737ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x295077BD816E96A8ULL,
			0x2F81082238D0AF7BULL,
			0x26F2C93D144C613CULL,
			0x7E05C7455C42D3ABULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFEE302811D375905ULL,
			0xB24A744997436202ULL,
			0xB92CF028F8C5A98AULL,
			0x367C085B5B58A3FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x05D6AA918419F3C4ULL,
			0x9475598EAB030443ULL,
			0xF13DEF159658F8C6ULL,
			0x13F4E9F42C53BCD3ULL
		}
	};
	printf("Test Case 364\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x82E5FC7AF97A4668ULL,
			0x2D6D6394E634CA6DULL,
			0xE2BD900D4E323B23ULL,
			0x5428432437A1BF0DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3D8DBD289CA988B5ULL,
			0x241A4EFF9DEE0AE0ULL,
			0xA0E359F3F1EB53A7ULL,
			0x094360B838838C9BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D7126F2C53775E8ULL,
			0x71D9790DE11FD830ULL,
			0x6A716FCBE1E30883ULL,
			0x61B9A60BAECA2CD6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F7EAB6AB95F67F8ULL,
			0x69BB141546F7C09EULL,
			0x4BC40E66EF16ADC2ULL,
			0x5354C27002074813ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF6A90A8F86D7CB9BULL,
			0xF8CE46CE054E155EULL,
			0x53AAAEA36059B820ULL,
			0x53208D4281684402ULL
		}
	};
	printf("Test Case 365\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1388B7DE3AE439A0ULL,
			0x62708A75C348747DULL,
			0x50E6D51323072588ULL,
			0x53D08A17C41EBEC0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E15CECD650C5FD1ULL,
			0x7C31F41EE4CADC85ULL,
			0xC1215C0425B03969ULL,
			0x406C8755BD9DA614ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x949BFEA557B04278ULL,
			0xC6D4BFDF066C2AD2ULL,
			0x96BE6D409D5B2B48ULL,
			0x490D0502D3C48B62ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB98D113BC246D51ULL,
			0x9ED7882FC2C05DEEULL,
			0x21AE6659FB86070DULL,
			0x106A635E89324085ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA362CB914EA2BF21ULL,
			0x917E17A35BB6F2F6ULL,
			0x0E9882A43FA2DCABULL,
			0x0724B20451310D41ULL
		}
	};
	printf("Test Case 366\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6CAFE74259115118ULL,
			0x22F5A2948BEAFF57ULL,
			0x2B46D4E2031A3D87ULL,
			0x65F952CEEAD34454ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15EA1CE2E2BAB6B2ULL,
			0x3BA29DC05D21A205ULL,
			0x577D02C3C36E6326ULL,
			0x2E98010BA5DE1519ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x171777F0D8D95D00ULL,
			0x3697094629AD6BDAULL,
			0x17389C4AF8628956ULL,
			0x5127B8D74CC2AFB4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD1946CF1C86B64B8ULL,
			0x6DE651800250D21EULL,
			0x70726E9F43819220ULL,
			0x638B36AB3C3A9AB1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x57CA101AEEA44E99ULL,
			0x86DC49D852871FBEULL,
			0x58A7B36126313793ULL,
			0x66CE4F6D4234EA92ULL
		}
	};
	printf("Test Case 367\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3CD3D310EAAB4718ULL,
			0x71DFFE604F600EB1ULL,
			0x7602EAD42B0761BBULL,
			0x5E234F2CA579A6FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x474F1824DD4105B0ULL,
			0xEB86A2A6CC894D5EULL,
			0xE8D51B1F8911F960ULL,
			0x72D3064B5535362FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9FCFB1057137D9C0ULL,
			0x0330F3244A3441B8ULL,
			0x9A9ABD534F6CE43DULL,
			0x57613938784568F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEEB834E53986CADCULL,
			0x5A53254FE798D4A7ULL,
			0xB17D23483006EC23ULL,
			0x3B8DADFCE0F59F26ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3968599ED9ECAE42ULL,
			0x5801138889F3B1DEULL,
			0x6C971E07EBA2801CULL,
			0x5ADF49E2E88F53DCULL
		}
	};
	printf("Test Case 368\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x96C9D38747FFE078ULL,
			0x83953033CACF89E4ULL,
			0x44B6CEC6E81C7CAFULL,
			0x63B9AF8B76DEDD74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C7BFFB5EE519233ULL,
			0xFA883B0B13A4C10AULL,
			0x65945792E4F9AAE0ULL,
			0x0DB1DE32C7311007ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAA2CC56CE2A76558ULL,
			0x4164D04A3CE9B022ULL,
			0x61CACCCDD72251B5ULL,
			0x4BB7D712D044517FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x285638058A157885ULL,
			0xE7A93E9F6A08F22BULL,
			0xE2B8FF9647BBA166ULL,
			0x4E5155A45CE46D86ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA0E3FEFD43D3A21FULL,
			0x83B019897C49D3BBULL,
			0x1F46932AC25E4AF9ULL,
			0x2306E4057950AF71ULL
		}
	};
	printf("Test Case 369\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFF4D25FB79EDD580ULL,
			0xF2783D770FB1DED7ULL,
			0x70E752545B878D4FULL,
			0x416E7A632ABAF64CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA2ABB6E9CE61A9E6ULL,
			0x1B62A1D23F49C214ULL,
			0xD0997159463CE069ULL,
			0x2B98061FC2D7B7D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9626EB2A9DF2CC98ULL,
			0x29672080A15BBE51ULL,
			0xDE0CE06E5ACBDB21ULL,
			0x6F616B51F725A15DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9502450A133DE45BULL,
			0x844BBDAFA8BD8C48ULL,
			0x59A94EBC7A0CCD8BULL,
			0x422D4BEEE910B8E8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6D84C93572B11B82ULL,
			0x1691540BFCE7D187ULL,
			0xC4EE6DD3B470804FULL,
			0x6957093E5F08CDF1ULL
		}
	};
	printf("Test Case 370\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD271BE52C8931A38ULL,
			0x65C5E7F930784368ULL,
			0xB063AAA9BA86EE65ULL,
			0x4A979CD521DCBD69ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF5F71E11A55EC183ULL,
			0xAE27CC774756FC56ULL,
			0xC4DD607C4EA32939ULL,
			0x624E5C057B1C1EF2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x77146BB47543F1E8ULL,
			0x1D9C6B62427B5C60ULL,
			0xEAB5971036DCEE76ULL,
			0x4650CAC24E99560AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x534669551F30642BULL,
			0x69E46351CD5E00ADULL,
			0x910B73D5CA830F3FULL,
			0x05F85DA4E6212DDCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7031F727C4017EE2ULL,
			0xA4849A51A292A851ULL,
			0xFAFCBBCA93D79AD7ULL,
			0x0D8DF68D81917539ULL
		}
	};
	printf("Test Case 371\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6349567B5E934888ULL,
			0xA6B84506D3348242ULL,
			0x9C7F6C5705B69A85ULL,
			0x50324A3FEDF5EE0FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B11571C1586A862ULL,
			0x2CDCE88EFB1032A4ULL,
			0xD6083AC930717050ULL,
			0x7CC590056043E2C4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x995AB742E78D4BA0ULL,
			0xC1EC8BDE6332FB1CULL,
			0xB38A07974D39D810ULL,
			0x4392AF2A933C4843ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B023ED823BD80E6ULL,
			0x32AFA2526CE80CCBULL,
			0xE213B8694C34E54DULL,
			0x74A1D66A811F845DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA0602C5B17DFF7CDULL,
			0xFFB9C03EEF6ACD4FULL,
			0xAAAB0953C4E8F35CULL,
			0x01E1A719C7F4AA9DULL
		}
	};
	printf("Test Case 372\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0C61ACEDF2234EA0ULL,
			0x1F3037C3245AFD60ULL,
			0xA1B74865FC50D072ULL,
			0x7067786189EB8FA0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD169617C3093880ULL,
			0x1BCEE4ABDC245BCAULL,
			0x46D9CC831DC11B08ULL,
			0x638C68FE2927B764ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB9C687C27232A198ULL,
			0xB70876D211952DC6ULL,
			0x14D516A7E9EAD7D0ULL,
			0x7AFD8809D8D7638AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8D96B70BF9317057ULL,
			0x49CE86D31C81BEF4ULL,
			0x75C0B6C755895E13ULL,
			0x74530EC4D5A31DE3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x381B44E1A45DA7CBULL,
			0x9CDC563F77F03187ULL,
			0x6E8C189CD4A93008ULL,
			0x4C028FCD20518747ULL
		}
	};
	printf("Test Case 373\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x18F705DB82291278ULL,
			0x9A0B63AE81B7D3AEULL,
			0x9FBD18893E36CA97ULL,
			0x7A25C0D5A8F871DCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB3AE37EC3E2643ABULL,
			0xB026B50D41331D28ULL,
			0xC5CA35B0A6C046C1ULL,
			0x5017501D1BA91030ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x21D521984A0C7140ULL,
			0xFFA8D4D002672099ULL,
			0xFAE51A315A4C933DULL,
			0x7F49243FB6F958DEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x470CCCD9F156241FULL,
			0x53B8E35E1B310C63ULL,
			0xF5798246EF20FCDDULL,
			0x46EE402238EFE787ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x36E2E3A9897ACF20ULL,
			0xE55FCF512566EEB8ULL,
			0xDF19108CA1178D30ULL,
			0x1E07E328E3ADF23EULL
		}
	};
	printf("Test Case 374\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0E8901F311147078ULL,
			0x15A735638A3B1FFEULL,
			0xAE7143A4A7DDADF1ULL,
			0x56F9564492687777ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9E0D770F1B4FBFAULL,
			0xD4F947B6391B3338ULL,
			0x524F8C5859FBBC44ULL,
			0x1EFC6BCCF9FA0320ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7554A4E51245FE30ULL,
			0xC1A824315F663BA1ULL,
			0x8AE103BEA3F68444ULL,
			0x64CF34CACB65ECAFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB5E93FE3A5E91337ULL,
			0xE9A9BB77AFEAD4BBULL,
			0x8C03088473A6EB67ULL,
			0x3DB64E2DDCCF8879ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8FBD46B21E09122ULL,
			0x462182C21D43D0CDULL,
			0x54747AE58C20AF60ULL,
			0x7F0FC9855F334C4AULL
		}
	};
	printf("Test Case 375\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB9126D95249A6C70ULL,
			0x98AB1388F1767D9AULL,
			0x40460A8F6ECC99C5ULL,
			0x4F2AFD9A317A5FD0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE9E73F9E641AE740ULL,
			0x33ED84A8DB65E90DULL,
			0x372612802E77F7BFULL,
			0x1209BB4F23199D11ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3E25BF1318B59360ULL,
			0xA50F6DF055630A91ULL,
			0x932EBA2AEE6D9977ULL,
			0x513CCD129078F914ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x771A0A50E183858AULL,
			0xD9775B8C6F4D2CE1ULL,
			0x831358983DA4A32FULL,
			0x3D46D7B10E19B976ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1C1576F3E4D67847ULL,
			0x280A9F37CEAF5061ULL,
			0x6FF21294D581F9CDULL,
			0x3554642A0E42C2EDULL
		}
	};
	printf("Test Case 376\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2D9B143A4A230AF0ULL,
			0x28F9BB204FA1DD48ULL,
			0xA1FF8C17BF844232ULL,
			0x4028B15011948988ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA76F73E220E78D27ULL,
			0x4285DF81EED07C32ULL,
			0x063928180C241D36ULL,
			0x165D240C804CED29ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8E3E24DDEE254AC8ULL,
			0xB8BA18EDFB6D7205ULL,
			0xDCCABA2FFBE26002ULL,
			0x5774B8B7CE058E15ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x85D0A38F9D385BD0ULL,
			0x96936BBB9E986B9FULL,
			0x6BABAFE1BF35DB8AULL,
			0x705775406B372717ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD0C3053A557AE786ULL,
			0xA1480F4800692F22ULL,
			0x2E965D43DCF270B2ULL,
			0x4B72C7C687038BA9ULL
		}
	};
	printf("Test Case 377\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5FD8031AFEE53DB0ULL,
			0xC066E2ABB6BD1259ULL,
			0x66BB9051FF881A09ULL,
			0x6B7F1BB1F4A74861ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x28FBB4BB45EFA961ULL,
			0xC2A656DE5609B3ACULL,
			0xA3A9518FC51C1B42ULL,
			0x63032CC2AA870B37ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6942478FC6683348ULL,
			0x852546CA1C4D791AULL,
			0x394A01D17397579AULL,
			0x7CBF13AA3C268EA3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAAF4A5A796B69931ULL,
			0x5AA16AAAECED42B9ULL,
			0x15E03AF8A377AE5DULL,
			0x51ACD37D7F80FA1BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x26F71193072B8CBBULL,
			0xCAF8ADAF5538FC9CULL,
			0x35EBC8B691524262ULL,
			0x7AED21F81AB035A8ULL
		}
	};
	printf("Test Case 378\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4A9DC4BFA3BA7508ULL,
			0xD67F27E8DF2667EFULL,
			0x40AD5B388FDEAF78ULL,
			0x4854237C1A1A63FEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA39DBD71DE5E3737ULL,
			0x47710764EBFBD4DEULL,
			0x317DCF8B9761E74FULL,
			0x150F0CBF375C6AC3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEEE15FEABE81BB88ULL,
			0x41EFB15A6F6359BEULL,
			0xFD82A5949C68D3ADULL,
			0x480B7B78338A6C5BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6B3D31C229EA9437ULL,
			0x7AAB7E2FF2312EF0ULL,
			0xF54348422E262908ULL,
			0x671E40C12D5A3990ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x297D300F3A3033B8ULL,
			0x2CDF6AEAC3FCE44CULL,
			0x8D2A0DA3D998736DULL,
			0x57C9E59C0EEAD3EDULL
		}
	};
	printf("Test Case 379\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDB5C48BA30253DA8ULL,
			0x1E25D2CD7527F84CULL,
			0xFA775F6C9DED8A0FULL,
			0x66B89B9435A8EC71ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x583B148F79D26F69ULL,
			0xA372F045446ED9B7ULL,
			0x35818B1DA4D4E636ULL,
			0x086D79DB66C6514DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4742607212B37550ULL,
			0xD4C497C11BC417BDULL,
			0xC33962398200FDDCULL,
			0x7CC7A6325B781238ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x779AAADB6C2F3DA0ULL,
			0x3294A85C1337B933ULL,
			0x3A94A72DCD00DAD1ULL,
			0x189639C4F1430D6BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAEC8B38A84F799B9ULL,
			0xC58921E68A1263E5ULL,
			0xF8660755ABACDD63ULL,
			0x1A33C8C230CF2FC7ULL
		}
	};
	printf("Test Case 380\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x27FB5C57F8C2FDA8ULL,
			0x72D49784C99ACDB1ULL,
			0xBE985F29FE51AFE8ULL,
			0x6D48B6A0F6455B58ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E48ED7695CC42D0ULL,
			0x85470E59C4FEFB7DULL,
			0x7A6D707620F5DBEBULL,
			0x23D2D323B63A5F50ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4F9EFCF3047D1AD8ULL,
			0xE84D57510234D900ULL,
			0x913773AE716D8AA4ULL,
			0x4556DFA087A5FA90ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF5E96DA8BDBA653DULL,
			0x160968C994CAB2FDULL,
			0x32F9506FE3B317ECULL,
			0x5504DD0FE7C16107ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x492036579EC301A6ULL,
			0x068D0A88969B5660ULL,
			0xDD4F8668AACBFC32ULL,
			0x15BAF40700B8EB4FULL
		}
	};
	printf("Test Case 381\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7612CD6EC771B910ULL,
			0x2B53C93C7E858C8DULL,
			0x325733DF5E2C3498ULL,
			0x5C07A1063382386FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x431BEBE7198AC033ULL,
			0x0CE5BE3F1BDA2F8EULL,
			0x9DFF403A201952EFULL,
			0x5FE3B4EA7AF6E031ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0CA1CB45F2833910ULL,
			0x5B53F9470B887018ULL,
			0x6FBC654FC448043CULL,
			0x4B982887FB7A971DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB260C17D8036241DULL,
			0x0B91711CF5BF82CCULL,
			0xBF38D00A16D3BA10ULL,
			0x101364011C469E60ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D86C4C0C23D0BC5ULL,
			0x3DE51B7E7A99CB69ULL,
			0xB57CD66C73193DB6ULL,
			0x627091C44413E484ULL
		}
	};
	printf("Test Case 382\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6AB66BC262625058ULL,
			0x48BB4B828CF865ECULL,
			0x689D77AF36216562ULL,
			0x69ECF59660F15DFCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF1DCD698B5DB111AULL,
			0xDD9618DB6CC19855ULL,
			0xBD4E25EE0530C770ULL,
			0x0F4C3BD76E57F2CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x655A8C326ACE8868ULL,
			0xA4A38E4FFFF4916FULL,
			0x3203206074FB2DCAULL,
			0x412B15169DE4D6BAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2C316FE1E525FEF2ULL,
			0x1B5DCCB28A37C5A1ULL,
			0x67A16084B9845057ULL,
			0x1EC22A2A3D856214ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCE61368148E0CFCDULL,
			0x67FCB90DE22BEE91ULL,
			0x00441608906F837FULL,
			0x5BDC465028EA7BF6ULL
		}
	};
	printf("Test Case 383\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0244A5A4299B3550ULL,
			0xD7F4D048B6FD8AEDULL,
			0x5793BC4BF5FA346FULL,
			0x64AF77261F6043C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB0FEE83551BD0193ULL,
			0x086333466441C8C1ULL,
			0x4E3829CD1CF00C32ULL,
			0x5F2D738161917AF9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF91F739657BF87E0ULL,
			0x28399319D92B6E75ULL,
			0x846E852054B95573ULL,
			0x49A6C0DC106750B7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B60C624E1C838C0ULL,
			0xD3B9316481D9CBF7ULL,
			0xD3DCAF502A426D82ULL,
			0x6E7021D9700B88C3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x723E85AE4D1C3B0DULL,
			0x7347841B367CAD06ULL,
			0x58DF27A697BAEB13ULL,
			0x58BA20E0EC1FC2C3ULL
		}
	};
	printf("Test Case 384\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7E46796E485AD6C8ULL,
			0xB57ED8C10EB63B6BULL,
			0x1DD1D813BCF2B5A4ULL,
			0x6548A189C487ABCAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBEDE901754FFCB18ULL,
			0xE7CE9157A0A5DF58ULL,
			0xD680B4D89391D035ULL,
			0x361C3B805E0AB9D1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6FC4CEC2B2811528ULL,
			0x56EAC502CC8994D1ULL,
			0xBA18641BB8970617ULL,
			0x511950CBCC79555CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0253CF8FA9D1A03BULL,
			0x2C18E4C0147FE178ULL,
			0x9D917F223DA2C4DDULL,
			0x265A0AEF366E400AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB620C10054B222AULL,
			0x259C16C67F749156ULL,
			0x4C43A861D0FE175CULL,
			0x637FDC386B4EC532ULL
		}
	};
	printf("Test Case 385\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3C61FDC387DCF518ULL,
			0x06A8AB5E421575F0ULL,
			0x7C25C431A26A7B41ULL,
			0x6C62BB9C2445099FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA5AD96AFB12EC0C4ULL,
			0xD0CD098B542B305FULL,
			0x7B1E43D351EDDADCULL,
			0x54D47866E738A98CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x91D5DB86678D6B60ULL,
			0xADA0418F24309A92ULL,
			0xE8271CA5877627F0ULL,
			0x417C7F3EA05539CCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9A26CC9DC661CD1EULL,
			0xE38E1118DE50AF5AULL,
			0x0A9C98187429A1A1ULL,
			0x03AE610529E45FFFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B2869BFF32B538DULL,
			0x69DFFA958F18475EULL,
			0xF59B564677589C2FULL,
			0x019C4E60E22F2CBFULL
		}
	};
	printf("Test Case 386\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0BB5C23BF0B9BB00ULL,
			0x91AF1B6564A9DFCFULL,
			0xBA338F6BC5D88D49ULL,
			0x4F29B2E44BB3B630ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB64BA3C727D20FCBULL,
			0x195222DC7766DF5BULL,
			0x64B541BFB5A94640ULL,
			0x45DFE97B691CC5DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF2C87AA29CDFEA60ULL,
			0x4F5FA837E8A9F857ULL,
			0x8E6B5BE1B75BA846ULL,
			0x6AACACF5804FCB1CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDD6857C88FD012D4ULL,
			0x2CEE2B6DB26EA36BULL,
			0x15B0FB773883965BULL,
			0x2616461B6A0914D7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x12598DD76A860E9AULL,
			0xB13309966FB175BDULL,
			0x546FB75D84EE720CULL,
			0x539B03432A39E9A2ULL
		}
	};
	printf("Test Case 387\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEB5891B073BDFA60ULL,
			0x373FCFACD26F3AB2ULL,
			0x383D65DD1FF25B09ULL,
			0x66A80292A3169CADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x49010F06E46641E8ULL,
			0x0E0DAA6E1E861298ULL,
			0xAF5EC630C74FD34EULL,
			0x6283E851B3FD6845ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2592F0FE0E1F2AB8ULL,
			0x8A5CCE7E6F7DE772ULL,
			0x2D82E87E18EC9E1BULL,
			0x782795D322791E84ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2500C521F338BA12ULL,
			0x4B3E03113B3BA7D3ULL,
			0x29DC86ED1CEE0A33ULL,
			0x3A4AF85D506F2167ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4E9A2BE81503FE50ULL,
			0x9CEC744466A49B0BULL,
			0x30111D892CFBF7CAULL,
			0x4F605BD2B6A917C2ULL
		}
	};
	printf("Test Case 388\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5268E6A03CED4568ULL,
			0x482A6AC0755708B2ULL,
			0xF193E0B8C65753D9ULL,
			0x60F2599ED0122674ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE0B9021FF89D44BULL,
			0xF68B6392D38D5511ULL,
			0x8E07D9356577D1F6ULL,
			0x7109271AECEBDAF1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3E4D6B20456CA068ULL,
			0x7E50357011CE3847ULL,
			0x62C98E6B1D6581D9ULL,
			0x672D0372E9BC457BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1BBC5A56EF7AD9FAULL,
			0xFE8283915B2A81B8ULL,
			0x13413A32E95CD934ULL,
			0x013D858D8AD633C0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7B30EF04B50D1444ULL,
			0xCA4D26711E378BB3ULL,
			0xD3DEDE23893CBF30ULL,
			0x22C666AE3B284CD6ULL
		}
	};
	printf("Test Case 389\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1213D15172E3DF40ULL,
			0x1C66B494EA96A5B3ULL,
			0xF30214FCEDA0B58CULL,
			0x54371454FFDD108DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x86565DD361BFE0DBULL,
			0x97A8F50BB1F7226CULL,
			0x4AD325FFFDA66464ULL,
			0x1CD8D75CC1D32D4FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x68C31078E0FB4728ULL,
			0x86889022AA91FEA0ULL,
			0xF0B8EC41A88F931DULL,
			0x63B5B401E99CD5B9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB2BF8998060396EULL,
			0xE824683D9562DD0EULL,
			0x257A7BF50FD3C7D0ULL,
			0x7EC65740E0C8A724ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0720121A81D43B4BULL,
			0x4F76A9F9D4A23825ULL,
			0x336E43B8863F7303ULL,
			0x7B6420DE9FC6F620ULL
		}
	};
	printf("Test Case 390\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD48ECF587E369F88ULL,
			0x9D0027D4DF1AD7D4ULL,
			0xEB576E5EE036FC10ULL,
			0x46AED1E6101ED7E7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCF37B0C30C461343ULL,
			0x7D0A0B05380F8B8AULL,
			0x83343AD8FC06EDA5ULL,
			0x3FE37E0B6327E872ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x41A04537B15705B0ULL,
			0x19D94F29F6BF776DULL,
			0x55CE6D0B2DEE73F0ULL,
			0x5ECF9EE18C515723ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x02012B303381507DULL,
			0x6A670879963920C8ULL,
			0x0AF415B41D3230ABULL,
			0x73B9A5D6207E5378ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x75B38D4637B36F65ULL,
			0xAE60BF47F5F3DB10ULL,
			0x3833E0FAFD2A023FULL,
			0x2A42BBCB24EDCB68ULL
		}
	};
	printf("Test Case 391\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x42A168447F8A7118ULL,
			0x777C93CD297935AEULL,
			0x736DE5AB4F7FBDF0ULL,
			0x4253A391A02B5B38ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B000754417B1A38ULL,
			0x54A9B13F8D7B5D6EULL,
			0xBEF0492D4A7220D0ULL,
			0x1B2FE9B04207AA7BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDD98002536BE3410ULL,
			0x3B128A7FD1A26789ULL,
			0xC5352C5EE7D71481ULL,
			0x4DDCE89D1973282BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA6B2F952897BE5D9ULL,
			0xBB098D8A29B4748CULL,
			0x57A25B9ACD570469ULL,
			0x06C81D6DA7895DACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD472445B92CCD3BFULL,
			0x5EAB470667EE2C39ULL,
			0x01E5480BD22B04C1ULL,
			0x31E30EC6EDB7D7E3ULL
		}
	};
	printf("Test Case 392\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8D22C6A645ED3000ULL,
			0x1FAF796F17706C2CULL,
			0xDAD5F151CE236B5FULL,
			0x64076C8D34BB927DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x51605025D260A069ULL,
			0xD7FCAFFC7A3968FBULL,
			0x0F569319DA0F1D59ULL,
			0x7E1C0877F155F5D0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF565E78E8C1ACE18ULL,
			0xEDC73EAFF7E0B12AULL,
			0x90F3B37EA415A927ULL,
			0x412E3D5C719FF292ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x39B676013871C081ULL,
			0x2EBED93F243352A8ULL,
			0xD0CD0223E9CF34F8ULL,
			0x5E30C8F9D3FE91C7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0F28C54EC6D2E36AULL,
			0x22D806FA69224037ULL,
			0xD8589D0FEFA9C52EULL,
			0x1B678B741647CF44ULL
		}
	};
	printf("Test Case 393\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4FB6A019472C74A8ULL,
			0x673EE4BA3D14F81BULL,
			0x9FB89A47C8822B59ULL,
			0x6D1E7061AAD16F26ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9F81B46E309B917BULL,
			0x2ECC43C63DD71F03ULL,
			0x27958D682159E745ULL,
			0x384AB78ABD493574ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF4B9F851EBD27A50ULL,
			0x866852568D40A6A2ULL,
			0x8833AF84B9DE5198ULL,
			0x6129A07BF3B4D542ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB52C6A68EEEED6A3ULL,
			0x5830EAE573E00345ULL,
			0x3C80C152034A7F87ULL,
			0x5FA442D1AA0E1D42ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x04A1B9C01C4E4D20ULL,
			0x2331D7BB93EBC19DULL,
			0x58076FB1D42F2A08ULL,
			0x5ECDB0DD49B6B6F3ULL
		}
	};
	printf("Test Case 394\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA9499D2C638AE5D0ULL,
			0x29F03CB52A792F0EULL,
			0xE5F6AE4042A44746ULL,
			0x715B563BB08C79BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA12275BC2D7E07F0ULL,
			0x458702588803ABD7ULL,
			0xAC0F70AD1F7FFDB9ULL,
			0x2482C74A2C6655DAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5BE5F0AAB274CA10ULL,
			0xC880AB5A5A0ED213ULL,
			0x5A674BC3931C7335ULL,
			0x4615E4D539AD5788ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xABE40C8F716B4E02ULL,
			0xFC7C88BB64912A20ULL,
			0x25BE4951C76EB133ULL,
			0x2D2048B1FEDD7739ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED9247C3FBB32921ULL,
			0xFFF1CCE502A699A3ULL,
			0xB6CBB41F197600FDULL,
			0x53E649F2FE08E9FEULL
		}
	};
	printf("Test Case 395\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBA1386C933E001A0ULL,
			0x357BB151155842A9ULL,
			0x8A20641F7FAC6D33ULL,
			0x4B4ACF9DEF8502F6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x010613B03FF9A443ULL,
			0x1641829D230B2008ULL,
			0x8BE0B965440075F5ULL,
			0x23DCDCD331F5EE2CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x23D43F8ABB33A3F8ULL,
			0xCBEA2D9B15D7A8B8ULL,
			0x4525DB93482239F3ULL,
			0x62ECA7F4D80E217FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x405957D296E7C5FCULL,
			0xE60BAE52020D73DEULL,
			0xA6B8FB375A830328ULL,
			0x24310284646BC5BBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x446F21E7FE89CD5FULL,
			0x44BCEC51471BE80DULL,
			0xA12C1002E0B2DE38ULL,
			0x4E1BC98C5DA701B3ULL
		}
	};
	printf("Test Case 396\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x13888F2B47A872B0ULL,
			0x492DA51F3B845A89ULL,
			0x432D60BB387F2489ULL,
			0x63819BEE64317F65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEC500D481EED562ULL,
			0x8EDA48811FE9150EULL,
			0x28ABD201E3FAAA4FULL,
			0x6272B7B6301DFE8DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x79CECA6862E15528ULL,
			0x137D37A909445B4EULL,
			0x87B3E1FC74388907ULL,
			0x74518A91D135F994ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5654EED8736C8C42ULL,
			0xB826CA2666697C54ULL,
			0xDC2B16BF5B54EF35ULL,
			0x2F9A6D755D2CEF50ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE0359BAB5EBBCDEAULL,
			0xE14C1586C5128838ULL,
			0xC788B39BBDCE2DF0ULL,
			0x3D3AB9C2A56CCCBEULL
		}
	};
	printf("Test Case 397\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4B6BC87AF2267578ULL,
			0x5F2B40444F6ABE27ULL,
			0x5BDE1D01D32089EAULL,
			0x7B4A5F3CCF60D2BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9D8CA6B1CE27D54EULL,
			0x8B82BE86527198D3ULL,
			0xBDDCAEEB8E372380ULL,
			0x111360F4AEAE4FDAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCCB4820BDB42B318ULL,
			0x9C875DDBDEE7F2FDULL,
			0xEA39E9C2D9763404ULL,
			0x4BC3B6EF40DF327CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5AB598055CEB7B1DULL,
			0xCB9D0BF724F1E896ULL,
			0xEA9E99E0962CFC63ULL,
			0x42B196FC3FD9CABCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA73A7859A1587F08ULL,
			0xC36FD9A21A9D07EEULL,
			0xA71A720B1BC172FFULL,
			0x611850137A838588ULL
		}
	};
	printf("Test Case 398\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB6BEB7570FF057D0ULL,
			0x476FFA995BD574F5ULL,
			0xAEE5FB6D3FD0043DULL,
			0x4465262882867E08ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D9FDF49A2A48165ULL,
			0x5B579DE94114FAFBULL,
			0x79666FA81F6AB7E8ULL,
			0x339E61D1151E4AC8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5A33EF104096C578ULL,
			0x0F858BE184F362B0ULL,
			0xD357EC00F0DE7406ULL,
			0x70E445525D88BBE5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB21C459BE3A2D5BBULL,
			0xFBE62E17BDEF99DFULL,
			0x8C36877F5079996FULL,
			0x473585290B67848AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x93F68234BC5067D5ULL,
			0xDA3A6D6F5F4C8253ULL,
			0xC1D375605B42EC2EULL,
			0x0059A377511C1748ULL
		}
	};
	printf("Test Case 399\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34F824F678B07408ULL,
			0x29E7866C790A95B0ULL,
			0xB64188F1C396D7DBULL,
			0x7C6AA5A56E1C4EA0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x341A4872883D93DBULL,
			0x38680EA704C69382ULL,
			0x0253CE4FA6FD1C1BULL,
			0x03EDE93378210924ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEA93EFE64A709860ULL,
			0x14334ABA1E0175F1ULL,
			0xBE89C566AE04C84AULL,
			0x438B4F6FEC59CD86ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1942145E1B350A01ULL,
			0x87B5CB168CEC761EULL,
			0xD4B43F66A2BECB77ULL,
			0x65F0147F67CCD23EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x49511829E319CBB9ULL,
			0x37778EB70E37BEDAULL,
			0x34C4AC4F24C24B97ULL,
			0x7D59AD03A9B38D97ULL
		}
	};
	printf("Test Case 400\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x95519E78A1026D60ULL,
			0x509EBEF310D70250ULL,
			0xF82A969E9432886FULL,
			0x7F32F9590A2F2336ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B7D9E3AE6F82B1CULL,
			0xCBF01E38F9A17BEAULL,
			0xA10B31FCABEC7D39ULL,
			0x34B4DB3AB26D5315ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEDFE2C077454BF48ULL,
			0xCC7C6023D8B3AFDDULL,
			0x8FB158265BDA7F5EULL,
			0x40BA1F4465776AF7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB8F7E9CB35785DBULL,
			0x5EB517875F6E09A8ULL,
			0xD236846D0E82C92BULL,
			0x4773A3A39F657F26ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9F7760C05866588BULL,
			0xA28EB07D1B1EC1D4ULL,
			0x9B675786BDF7ED03ULL,
			0x30AD42B4AB68B33CULL
		}
	};
	printf("Test Case 401\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7EF4E0AC02C57550ULL,
			0x5C9C7D861E3BA967ULL,
			0xF392BFDB869C4A27ULL,
			0x468C98C4245284E7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF0E090E231052B97ULL,
			0x3E95558439404977ULL,
			0x289404FA0C6DA332ULL,
			0x2166D90F9521C2D5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD412948CA055AB58ULL,
			0xF258B517E56F8F9CULL,
			0xDF2D222F82FA4C57ULL,
			0x7050203F7CE20DDFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x83C9E70EFEFC6B85ULL,
			0x8515A1FEDBD5942CULL,
			0xB05A72B71327E4B5ULL,
			0x48CC52D8BE6360CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB2239C27C938C5CBULL,
			0xC36C59481C80B478ULL,
			0xC9367B9D72D67369ULL,
			0x4696037DD267C368ULL
		}
	};
	printf("Test Case 402\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x243E29593EBCA010ULL,
			0x9B357ED30FF25C2DULL,
			0x0718FB4394571965ULL,
			0x79F3EE413BBC03BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF46598C0176353D6ULL,
			0x90E7978A5E9276D6ULL,
			0x0AB40D6ECBB15B8EULL,
			0x512B1B4139D93415ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3D033C575509AF28ULL,
			0x0303AA2371D569FFULL,
			0x94ACA2CB8333F136ULL,
			0x568956B26D59E4D0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCA069FBF391812ECULL,
			0x42FA94E1E341687AULL,
			0x6E64310D9E8E4A0AULL,
			0x677843316622CF29ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFA75A86B8F9296A2ULL,
			0xB1D0433102B2F181ULL,
			0x3BEF04241D6A5617ULL,
			0x1DF58A5FEFE46F3CULL
		}
	};
	printf("Test Case 403\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x81398BE37DE17700ULL,
			0x718E1747A6E896A4ULL,
			0xA54F7677FF1716C1ULL,
			0x4CC317452D238A52ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8EE6CE06C6A03025ULL,
			0xC5F4AE805F8BF279ULL,
			0x5B3F58DB9B8DF562ULL,
			0x739F4F29417B1D7FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x26283E42715E1E70ULL,
			0xE97114BD8F9FFCC3ULL,
			0x7FE24407BDB6EA4EULL,
			0x776F1F22DF6F7829ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE35A669595ECCAE9ULL,
			0xCC05DD1BF57332EBULL,
			0xEB4560EE38DE41ABULL,
			0x199DB566D2827B91ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2A6F9BA05B95CCE3ULL,
			0xE47BC493FD0A77A9ULL,
			0x89A5A17B50623E9BULL,
			0x72305EFCD60361F5ULL
		}
	};
	printf("Test Case 404\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE3DE29F7D059F0E0ULL,
			0xCE2F556C611A30D7ULL,
			0xFD491C2AE49A3E01ULL,
			0x51147B5AB9AA794FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA6F6488AC7A8B047ULL,
			0x2582947DD464C82DULL,
			0x89F85066A6283B8FULL,
			0x03465E4AAADA0A64ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5AAD75E6BA570250ULL,
			0x6B35B0A17EAE9053ULL,
			0xB7137C0F799BA3C7ULL,
			0x7E3AB02844D86EC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x10FDB7D353F2292FULL,
			0x77CC02BACA9F2A5DULL,
			0xA5549FA54D9D7B36ULL,
			0x3646745553BB827FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE03B641E6798B6C2ULL,
			0x5B30DE4FB699BA01ULL,
			0xB6A2C68C3D704C66ULL,
			0x0176389525888C77ULL
		}
	};
	printf("Test Case 405\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBF377C6C703BA200ULL,
			0xDF9D37FFEE18BAC9ULL,
			0x732571002B7BE4A2ULL,
			0x4C4C7527E639B30DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF78F0E1C3810689DULL,
			0x52F8A45228884805ULL,
			0xFFC420ED807E00CCULL,
			0x7347066A14DCBB68ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9FC9A8585DF4AF18ULL,
			0x47F1F72E86F8080AULL,
			0x82CFD959E7172344ULL,
			0x41AA1BCDEA5E45E3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF0C9083DD1C2D957ULL,
			0xE8E26606FDED6673ULL,
			0x57E5E5542B9BD26FULL,
			0x6DE2E4E9A0C72531ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFDA4F27734E8CCB5ULL,
			0xD67BC6ED09FBF1F4ULL,
			0x3FEC3AD96585EE93ULL,
			0x61626935EEF7AF5CULL
		}
	};
	printf("Test Case 406\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBC46A2DB1AE7FCB8ULL,
			0x9F2F3AC0FCDE3016ULL,
			0xA4C6CF518296EBE1ULL,
			0x5629FEDBDF15D413ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE3E071665423DDCDULL,
			0x1502BEFB997E2771ULL,
			0x3ED9B40BC4CB3E55ULL,
			0x5BCBAD4D7BB2D621ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD83338CC98E71720ULL,
			0x18EDE954BE00AEB1ULL,
			0x6464E2B0FF3020E8ULL,
			0x7E62377A37D26313ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8D147793E609B4DAULL,
			0xB4DE3B9FE455EB35ULL,
			0x2BC3EB1AAC9EBE74ULL,
			0x14B08443E5B765AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D8240CCB0164CB1ULL,
			0xF7599FD72088BCECULL,
			0x80A7DB79481FB304ULL,
			0x2EC2FFB8D5F4677DULL
		}
	};
	printf("Test Case 407\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5C9884F113B245F0ULL,
			0x0995B91AE30E6D76ULL,
			0xE7346B7BBEA87E22ULL,
			0x69B0146506449B5FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x65379138F6981BB8ULL,
			0x8DA3B896A3B9CA4CULL,
			0x13C7901764D15D67ULL,
			0x79834998906C2681ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0A83DCBE906262C8ULL,
			0x6F518147CAC03D5FULL,
			0x39A435E5AB165D6CULL,
			0x7A7FD94FED66FFAAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF7EC2015FDBAD37ULL,
			0x246AA7B290DC1ED3ULL,
			0x4687718D4503A332ULL,
			0x056B01176C9A1CFDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC51A204FF5565D1DULL,
			0xFB75FA5F379B5D44ULL,
			0xFE804028DE23DD6BULL,
			0x3BDC695DDF240FE0ULL
		}
	};
	printf("Test Case 408\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x820A4B70609710B8ULL,
			0xFB9A67860FAA3626ULL,
			0xBCE64C58E426C548ULL,
			0x4109AE97E8D92DE3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1012CD0389FC8437ULL,
			0x3200ADC4F3C289CEULL,
			0xC2E11634EEDA7B80ULL,
			0x610EC333B8CFC24AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x34D8B26CD6A01848ULL,
			0x6EC75F326646E2D0ULL,
			0xF58312BADEFAE35BULL,
			0x47450264F49FD110ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB20A9470E29DA44BULL,
			0x1BB77FF8ED28EDEBULL,
			0x7A0B518C418E280CULL,
			0x0676A727AA6D1E7FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0945A24E6D24B362ULL,
			0x258DCA502E67E757ULL,
			0x4DC079E4623C7C92ULL,
			0x2EFE54469730DBC5ULL
		}
	};
	printf("Test Case 409\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0EC62069C59B4D90ULL,
			0x19B58F1F9562EA05ULL,
			0xC14CBDEA5C39A512ULL,
			0x631C450A0809A87CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x711CCDE57042CD33ULL,
			0xE8D5881DCE494275ULL,
			0x677C81D8EFE7A197ULL,
			0x4BA6F3E0C65BCB45ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6AC06D111C3993A8ULL,
			0xE9DA43AF5B87CCECULL,
			0x6D25A81B55166CEDULL,
			0x57E1C9D7C1B51727ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8D7E95032AE8EE27ULL,
			0xDB7C60F3A4DBF3C1ULL,
			0x4D695EE5A124D8C1ULL,
			0x7EEDF2E7FDEC1FBFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE001F89B729EB7B0ULL,
			0x3B86CD5FD2B45B6EULL,
			0xA584913FC110A8B5ULL,
			0x677BA061D21F9007ULL
		}
	};
	printf("Test Case 410\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2FD5460E60B37DE0ULL,
			0xB8E178913992BF7FULL,
			0x1895313DB22D52E6ULL,
			0x5AE0848D3EFAAB33ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0040680C4993C253ULL,
			0x8278830D068AB327ULL,
			0x48FF866136F6BEB6ULL,
			0x6F7361ADA0C7B1B7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8DBB95A6C7BA9958ULL,
			0x429D38566974BDC1ULL,
			0xCBF17CA5C39C8C06ULL,
			0x54B8013166670C88ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x939267FB7810EA61ULL,
			0xFF7BE30282B4C45AULL,
			0x2350A42820A20BF3ULL,
			0x64E5E2199E445877ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB4A4B0B86B594ED3ULL,
			0x6571DF3E0F06F94DULL,
			0xEB5383860674213EULL,
			0x2301D557EAC4A8FAULL
		}
	};
	printf("Test Case 411\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFD7A4075A48C6388ULL,
			0xEF7D5C184E07588AULL,
			0xD5D6EFACC7205B6CULL,
			0x478EA70BD11308BFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C78775F1AA8ADD3ULL,
			0x35C83F304EAC010FULL,
			0xA08164AE4F9AD891ULL,
			0x142DB2A066FC323BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x035FE8EDEFFB2810ULL,
			0x6DEA55AD6947F77EULL,
			0xFAEEC9A9E3A26487ULL,
			0x76807E4B42A48488ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1EBE86797FAD9BF0ULL,
			0xD1C41889E21628ADULL,
			0x2793F6CEB5DBD4C7ULL,
			0x7A250795E5DB7DD1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x076756FD3D73EFFEULL,
			0x20F9F820EC94CE36ULL,
			0x26AE2D40899A9CD7ULL,
			0x10DD7694B8BC458DULL
		}
	};
	printf("Test Case 412\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA7D4A29F89B30950ULL,
			0xA6175BA4B75F525EULL,
			0xCA54D0ADE1BCB1EDULL,
			0x79AE548359D5D250ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC5067FC5FA2E3FCEULL,
			0x98F20601B268CEBCULL,
			0xC4C613935A339048ULL,
			0x670AB2CF1BA57232ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60A203C819241B28ULL,
			0x89E1DC723F50D4B1ULL,
			0x070075B56B715104ULL,
			0x588FBD86780A4AB4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1909ED75B7571385ULL,
			0x2638F9FCE9A3E858ULL,
			0xEAAFBEBE0A67B0A5ULL,
			0x71136A2CBA99D96AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4071C788B72958B2ULL,
			0x415C55F048AE87F3ULL,
			0xA8075EAF7895ADF5ULL,
			0x6A75B6E9D6DB0976ULL
		}
	};
	printf("Test Case 413\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4784AA97A6989150ULL,
			0x02A07C4470FFFDD1ULL,
			0xB5900369EFDEAA23ULL,
			0x56AF2687B5F76C15ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE401159B511F281EULL,
			0xD4C1C16B5CF73B42ULL,
			0x4939E5B23DE92DD7ULL,
			0x080316B163D04390ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x90297B111C6247E8ULL,
			0xD20DE467297D5B44ULL,
			0xB5C4ADBB293DDB47ULL,
			0x4C95B6C709F29776ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3D12B98D8CF02594ULL,
			0x41FDCF0019E585A3ULL,
			0x285BB1A5F4957A09ULL,
			0x3E318FE488BA310DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xADACA066E0DD73D3ULL,
			0x0E638724BF04E6CEULL,
			0x552068D32544FD1AULL,
			0x5CB0FA74F84E6BACULL
		}
	};
	printf("Test Case 414\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1384561B4CBC8C40ULL,
			0x339EC0330BB94A7BULL,
			0x7D8351424E1A552CULL,
			0x4CCEC0FF322A083FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3139CAF44A816FDAULL,
			0x361E92024A4B98A3ULL,
			0x2B27C98D9BAEC395ULL,
			0x5E39FAAFE66C9EA3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0E34FD94C5FBB068ULL,
			0x077B4BF7EA41429CULL,
			0x74F5AAC9847CB41EULL,
			0x4E9B2EF835CD5FA1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD5F3FC962475A835ULL,
			0xF8F0793E57FA1E53ULL,
			0xAE5617C9F3CD9938ULL,
			0x3984C653A4FECAE3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x938DAD20FFD74B77ULL,
			0xD0CF2FBE138354D4ULL,
			0x6C4FEFEB6C52E454ULL,
			0x2D0BE2A87DD2143EULL
		}
	};
	printf("Test Case 415\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x45A5AD93CD6C4770ULL,
			0xC1EEF2FFD5344261ULL,
			0xD76551CFC434D161ULL,
			0x7C10682F51E46AF5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF890E611C5C7DC08ULL,
			0xDE4702CC7ACFF479ULL,
			0x61E40215E28C0967ULL,
			0x173BEDA759D86915ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7A1CD5D21D49D340ULL,
			0xB9DD6B8C4E31914AULL,
			0x7A721391B05F7B18ULL,
			0x57571DF08088BF96ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5B78A487D393EBBAULL,
			0xC7CFF380BDE4B192ULL,
			0xA369222B2C89A3BBULL,
			0x1594B2EC0EFC91C3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x41F6910AF171EF06ULL,
			0x3B9B924CE0C40949ULL,
			0x351273F2CD8403ABULL,
			0x6E567A033E5C7750ULL
		}
	};
	printf("Test Case 416\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x93C3D46C3BF82868ULL,
			0x7018F98F03AF4919ULL,
			0x0739B4BB133B68EEULL,
			0x45D8DD67C6D47DD5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFF0D192BD7FB45D0ULL,
			0x2197CB5BE8A4DA1FULL,
			0xAA21ECABCD945E45ULL,
			0x32F506D7C8DD4480ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x460F56DB8F46A278ULL,
			0x950D4754921927BAULL,
			0x6781917642446487ULL,
			0x790489CA5D68FFF2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD8BBC305C84F4124ULL,
			0x988257908E676368ULL,
			0x3DB9E72406C1A4EFULL,
			0x1D9DF549F243B2F2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFEA9A3B60699DE57ULL,
			0x76C3B94B7A3ABAD2ULL,
			0x712D66B3B06306C0ULL,
			0x20C74DFA8A652A92ULL
		}
	};
	printf("Test Case 417\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD71BEBD3A7DE4118ULL,
			0x3DC5208EA46BDEF1ULL,
			0x1871D7BED1295EAEULL,
			0x617FD34F29B471BDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01FE1469FB5CBC7AULL,
			0x7EC2F18373772387ULL,
			0x3A119433D3AC502AULL,
			0x7A28AB32BC02CFD8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2EDCE7572EF42778ULL,
			0xD9A8969A518C88C6ULL,
			0xDDEED4430376476FULL,
			0x6243E8ABC53D22DAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6E9A246370528427ULL,
			0xE3AEEFB2ECA2CDF7ULL,
			0x89F37913ACB682F6ULL,
			0x6CC88C674CCC987DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB998CAAD601953A3ULL,
			0x5AF9A0FD61C4F195ULL,
			0xFCA27DC87F169BB9ULL,
			0x6138DFE22D01E5EDULL
		}
	};
	printf("Test Case 418\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE2C231C96FD89330ULL,
			0xA880656B434C9988ULL,
			0xFC35D69851C63C80ULL,
			0x70F01AAE3A1725FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD1FE5B2D4C0135AULL,
			0xCCD32EE2CC258004ULL,
			0x4AFE5D9FF71C3ACFULL,
			0x5EA486418853CB4AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x70DEC7FDE2004BA8ULL,
			0xFDF7FD59BE6A1DFDULL,
			0x9B6B92D1334CDB25ULL,
			0x4CF07F5A7F3BC4AAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD97B7057DB062950ULL,
			0x3F22D6C3CB24705DULL,
			0x3C9552F9933948BAULL,
			0x1CA6476ACC8DFEF5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA228FCF770C38EF9ULL,
			0xF944733D8D3BC6A5ULL,
			0x7D576FD5AFDB1872ULL,
			0x7B3FA19BC2314553ULL
		}
	};
	printf("Test Case 419\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x7D5D9FC3A9C14C60ULL,
			0xAEA195D3CDF1404BULL,
			0x7F9DE8C5ED0A5164ULL,
			0x41272314FCF0D014ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x41D1B45D617D3D44ULL,
			0x46ED172392DC5D14ULL,
			0xFD9DC987CF8B56E7ULL,
			0x5BDAB37E1123CB63ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3EAF7DE792C2AEB8ULL,
			0xD7908E711E38B79BULL,
			0x3E04B7C9FEAA4331ULL,
			0x726A17B7D7CDB11BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37036DEBFC48CDBFULL,
			0x2E169A3F8031DB66ULL,
			0xF06CEDE6C5E33220ULL,
			0x6AEA38EAB8113745ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF8D933B54F7F7AEBULL,
			0x7CD772A0FB3BCF4CULL,
			0x2AAA723ABFA84417ULL,
			0x7304BB12E78157D7ULL
		}
	};
	printf("Test Case 420\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF13DC3AD0A917EF0ULL,
			0x6632438D6F8B89B1ULL,
			0xBEF63B1B16A74746ULL,
			0x71B4CC39CC4A1193ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x930125FD6FAC8AD5ULL,
			0xF1AF03F181C2222AULL,
			0xB0EDE466A3BCE537ULL,
			0x787DAAB3DC73A2BAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA12A1B2838BD3538ULL,
			0x7B1DA986C05E784FULL,
			0xA47FAC0FE1C721E1ULL,
			0x57F23F7BDC33F513ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDA72AA44A4D7672AULL,
			0x33F9B1C2B044FA1DULL,
			0x0B65A8C48F21994BULL,
			0x0D5D236B9283F664ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B378EEBD4043632ULL,
			0x27CFB646DE5D6445ULL,
			0x1FDB0DF18FA9B4B6ULL,
			0x7F263FB712EAAAF1ULL
		}
	};
	printf("Test Case 421\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA9CA537C1B616948ULL,
			0x8EC8EE5FF894E311ULL,
			0x6B569D80C3FC75ECULL,
			0x415A3DB0487887D7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBB471B487D43F8BBULL,
			0xE5D6F4B1D7CB5CABULL,
			0x786C4517249196F3ULL,
			0x6747B15DEC8AE572ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8D771F13D5AFA120ULL,
			0xAEA2C801E38F79D0ULL,
			0x09FDF0F880305062ULL,
			0x6C834BDBAA4177ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5AF7487FAFF2A645ULL,
			0xA5C3510FC213212BULL,
			0xC1090AE76CD76C7AULL,
			0x0FDC61FBB682A1DFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x830015C8D76E78DCULL,
			0x13D20AC1550833FAULL,
			0xD5FDC2F6DE9D8DC1ULL,
			0x47486C0828852204ULL
		}
	};
	printf("Test Case 422\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x39E398EBC5BB3538ULL,
			0x556BA847520F3980ULL,
			0x7DD8D87CED9718C9ULL,
			0x75D6CD393C46D837ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x00E5EC153A0E4A13ULL,
			0x717941EF1DCE0162ULL,
			0xE4FAA992C0B14A7DULL,
			0x6CD56B4CAC8E0BCBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9483B32A16484110ULL,
			0xDB6E5B19326A2B04ULL,
			0xBE9C57312813CB83ULL,
			0x599D4064058931FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC8BED60D77B7377ULL,
			0x1460AF167BC79B0BULL,
			0xBD798D4306DFA344ULL,
			0x17CDC4987085DE9CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE57F740D1F848F3AULL,
			0x45AEFC1477DD59F5ULL,
			0x134808A76507C3AFULL,
			0x0119BE77420EB9AAULL
		}
	};
	printf("Test Case 423\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2537C89924C2DD18ULL,
			0xA1EBE88BE7373537ULL,
			0x9474EABCD7D25516ULL,
			0x7B4B700A0F57CA0AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x039237CA2CF25ED9ULL,
			0x1742B8E0E8503931ULL,
			0x4DFF8F872C5215DEULL,
			0x4DB1D1CF4C55E31FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x98010347D5C2BE90ULL,
			0x722BC5FC9DED1EEAULL,
			0x0174ACB8C96CB0BDULL,
			0x4CF028E0E067EAC6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x255FD0A70005A601ULL,
			0xB4298E3B19D10CE9ULL,
			0xA860E7F7A9143CA6ULL,
			0x2E30BBA20193E850ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEE46A797D7CCC625ULL,
			0x84819E1803154EDCULL,
			0x7434473E8E1845A6ULL,
			0x687F32A44603EAE6ULL
		}
	};
	printf("Test Case 424\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEB250730DCDEBC80ULL,
			0xB0EDE19183AAA4BFULL,
			0xEBC12A2CDC6E0E35ULL,
			0x721C1E62A44906F9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF60A8C30FAE9535EULL,
			0x76084BD218D28228ULL,
			0xA3D68B972CD5B937ULL,
			0x47B949E926536D77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x63204543A229BCA8ULL,
			0xD698B74375DC66B8ULL,
			0xABE58480D986EFB6ULL,
			0x5AE900CD34BEAF67ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1690113D4CDDEF85ULL,
			0x06C4E83A9AE2D1F6ULL,
			0xF114D59C1E0465B9ULL,
			0x53798BD999C10E39ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2C287E3C9D7CE9B8ULL,
			0xABD64481E161AEBEULL,
			0xE501C43CBAA97580ULL,
			0x55587AA0492622B7ULL
		}
	};
	printf("Test Case 425\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5822F92B7FF15100ULL,
			0x6080F41CCF3B1C9FULL,
			0xC6D4489952A2E2B0ULL,
			0x5B363B498F88C532ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8FF157CBB1F532B7ULL,
			0xACE8562719486295ULL,
			0x351DBD4F08195FAAULL,
			0x190A17AE2E94AE9CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC4F504F156393D10ULL,
			0x14C2B017382CF85AULL,
			0xBC1C8326BA3B9300ULL,
			0x546DBB72B0D9344EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA16DF840A11BDD55ULL,
			0x8E928D1E1A12E4DCULL,
			0x51A58DEB45AF348AULL,
			0x2A6B9C8E9DB6E9E2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x979FB327DEC42BDCULL,
			0xA868BB5A4369CC57ULL,
			0x77016EBADED6CCF6ULL,
			0x41CD3E04ABDCFE51ULL
		}
	};
	printf("Test Case 426\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4096FE19FA29C5A8ULL,
			0x9DF53F788E685CC9ULL,
			0x267434209FAC6DE8ULL,
			0x4D6542868FD2C500ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2AF8B0C1A578F1D8ULL,
			0xA0D52C69ED895A86ULL,
			0x5E929C917B74EBF9ULL,
			0x159C81C4126B4E77ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB5781E6D7053E660ULL,
			0x477848ACA99A2EBAULL,
			0x83BFA14E4D9E3C88ULL,
			0x7918D5B4462C4EECULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC88C6F821B9FEE4AULL,
			0x8D424A96E446DBF4ULL,
			0x4C606531A2F22E1EULL,
			0x08719DAD207501C4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x50325FCE6AF1A9C1ULL,
			0x04918FF6AF5AC2DEULL,
			0x2EE2D967C10E0E5CULL,
			0x58D7D1CF338B952FULL
		}
	};
	printf("Test Case 427\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x15DF57BB1DDFD3D0ULL,
			0xFBBDF3747878995EULL,
			0x9672D14AF7CA5DEAULL,
			0x4ADA63B1E6390533ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x842C41CFC5480350ULL,
			0x3D58720431EBCBBBULL,
			0x2107585049E8385FULL,
			0x2E073DCA23C89323ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x619F4A150F554608ULL,
			0xD7C896425423FF1FULL,
			0xD92BC89250D6414BULL,
			0x6D884717CE22B739ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0605745BA1A86609ULL,
			0xD127EF4032A74329ULL,
			0x0F243380825D168EULL,
			0x64FAA840097FBF46ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4A65B604ED11BEE6ULL,
			0x4471AA40D2B92320ULL,
			0x0557590CC6201BE5ULL,
			0x00BB537BA9342153ULL
		}
	};
	printf("Test Case 428\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA6C163F894581A70ULL,
			0x2177E94312B04C81ULL,
			0x4319936E581D88AAULL,
			0x6F7752F42F86EE90ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAA18DF424BA3C07AULL,
			0x26B30D87A97134ADULL,
			0xFD7965362168A2D7ULL,
			0x494DFCBDE4EB5D33ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB553C2E3D160EF58ULL,
			0x06CCC4F509052C04ULL,
			0xFFC04593579E6F40ULL,
			0x44002189E5B29C33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x99C2FF67DD093E3BULL,
			0x433D53E8ED8EE2DFULL,
			0x824CD28FA7B1A97FULL,
			0x1019CF36C3754C2CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC38501F467FBE127ULL,
			0xB0F4A0699669FB87ULL,
			0x837D8CD090E4197EULL,
			0x35F9A04886E1A4B8ULL
		}
	};
	printf("Test Case 429\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x42BC36F48B5CD4D8ULL,
			0xD145D27B2CB9D673ULL,
			0x8C2C909E1861C52EULL,
			0x7A7522C0A48F6788ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x891CA177ED6E8CA9ULL,
			0x3167FF8EF24AC07AULL,
			0x955BCFAD0D037D57ULL,
			0x383284F6954E6BBDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2059E37B3067E228ULL,
			0xD64CDD0062246B84ULL,
			0x025C158AD565DE30ULL,
			0x49344E3EA654EC47ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2AC4AC0024700BA9ULL,
			0xB92C762AF1692A7FULL,
			0xC3655706DD6CC111ULL,
			0x7AB1F98F1296CE54ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xADB9FD674AAEB313ULL,
			0x372479D041CE0D96ULL,
			0xC09FA998975A0EBAULL,
			0x3EC1ED2828785EECULL
		}
	};
	printf("Test Case 430\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x8B958BE05B019EB8ULL,
			0xBB2323C4F887458DULL,
			0xEF6687320A4352B4ULL,
			0x75DB3088AB8877A9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9E2DA6B6FB58F84FULL,
			0x812055681D9CB90BULL,
			0x30D2C21946BA70A5ULL,
			0x5DCFAE08DBDF81ACULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x06BD3C7F73321790ULL,
			0xCC2A791A0D95B1E9ULL,
			0xF5E841F4C4C39C21ULL,
			0x56EFACD23236AEA6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA73AF68E2E65BC91ULL,
			0xB01DDB385F4CB56CULL,
			0xD97D523F1D451F3AULL,
			0x1DFA9BFC6115C0A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB0E34BF4450FF2E0ULL,
			0x5C6033E6BC91B5CFULL,
			0x33A1DE43E326E1B1ULL,
			0x0F529E6394086EDEULL
		}
	};
	printf("Test Case 431\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x196173417C4649B8ULL,
			0xF3A738E73E781657ULL,
			0xD1C878F0057045BBULL,
			0x5504A96257F8248EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15D47455C69A0271ULL,
			0xF6648CDDE7DC0A74ULL,
			0x843B4C4C984771BAULL,
			0x0039A855FAEADC55ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA38DF493BA9407A8ULL,
			0x3F96EBB039611227ULL,
			0x5543B686A2D28A3CULL,
			0x55B838ED33E0D743ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9F0D9449208C2C16ULL,
			0x3831701A72BB378AULL,
			0x63AC9D39BB0889D3ULL,
			0x5BE0D90168B19034ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB53FEC81F702CDEEULL,
			0x055F400866E7A958ULL,
			0x7811A807582879F4ULL,
			0x156DAB5B0A760DEFULL
		}
	};
	printf("Test Case 432\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEFC2064AF7372F40ULL,
			0xA107D07D6573FA9DULL,
			0x244046022D83C1C4ULL,
			0x76860C025043E201ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD8892DE4F56AE4A6ULL,
			0x9FE6ED5674819B4AULL,
			0x35C035602822D247ULL,
			0x2090E0BBA1F3D1F0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD4EB20394393B340ULL,
			0x0914175B06E55FCDULL,
			0x167CDFA644556C1BULL,
			0x7B6ECA76C4550369ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x25B464F028361A30ULL,
			0x4C61D37150E3216EULL,
			0x37F966FF795ED4D7ULL,
			0x1C690D2FE5F90229ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0A0910C53DBEB687ULL,
			0x56FE8EA0705C5945ULL,
			0x1AE60175C9A0BE92ULL,
			0x65500EAEEFEC46FBULL
		}
	};
	printf("Test Case 433\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x423B3D224435F670ULL,
			0x24E21D19E1BFAA64ULL,
			0x3783105BFD1B990CULL,
			0x6C7802FD4A18FDC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6D6AF456592310AAULL,
			0x8276863C95656AEAULL,
			0x6E845CA7A6834A04ULL,
			0x04D066670EB24AB2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEEE44790150B3588ULL,
			0x08BF0A15F596CB4CULL,
			0x920BB5EFBE42A7F1ULL,
			0x67D3D2CAAFAE26D6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7FB7068945C291B9ULL,
			0xA6970B86149F8A07ULL,
			0xC73677E757F08521ULL,
			0x441D39CE46588E3FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x56655781FE3FB6ACULL,
			0xD98BBA946A344BFCULL,
			0x64040CAA86D9E948ULL,
			0x43F580DE1431E255ULL
		}
	};
	printf("Test Case 434\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x188B29BCA7BE74C0ULL,
			0x49FCB60CCAB3230FULL,
			0x741E761F7250C5FDULL,
			0x5407083FB3EBB4D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x21089ECDFF738471ULL,
			0x57226BFA301F361BULL,
			0xDD6D3437C0D335D1ULL,
			0x26B649CAD9939A6FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6322BDEF1D497588ULL,
			0x56D5B2D7954477BCULL,
			0x04D41FD3CCF6D1B2ULL,
			0x49818A5727874D8EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB1E05BA0FBD4032EULL,
			0x4C3276E174AC5723ULL,
			0xDBFE2D2966F154A2ULL,
			0x6A593D0E94F2B155ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3311EF6B29008DDEULL,
			0x4D2E41729FF028EBULL,
			0xAE6B4A13C21E4797ULL,
			0x33930D03A4850BDEULL
		}
	};
	printf("Test Case 435\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD9E9C651AD266EB0ULL,
			0xB13626585441B13DULL,
			0xE313BBCD5D40CA66ULL,
			0x45F3B764F06969F0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x76C32A2279B21710ULL,
			0x0F216C9F3B865020ULL,
			0xA29F9BC7DEC66319ULL,
			0x106B3798F54E8059ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x130A0D0D5555DCC8ULL,
			0x90140F45C33E0C5BULL,
			0xDA9C1071DC1AEF40ULL,
			0x518C2DF7661CBDE5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4A8D1528CA30A862ULL,
			0x1B11D234FE8CCA7BULL,
			0xCCDFE2601AC4107AULL,
			0x6BF3483988AFE525ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB783289895C5F7B3ULL,
			0xF8A19F3F1EC2CB23ULL,
			0x3551336B29F5FF20ULL,
			0x69BC8E22DE0DC91DULL
		}
	};
	printf("Test Case 436\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAF737D5FC155D2C8ULL,
			0x7BDED9F91C6068EDULL,
			0x2D50DB2F446C2ABAULL,
			0x5761D118F327D0A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B60B430668A9B45ULL,
			0x0A3432B5F9254A3BULL,
			0x31E596A2F1090479ULL,
			0x6B8101E77D3203ECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x841390C9B2E3FAA0ULL,
			0xA06759F5FC7B7EAFULL,
			0xC4D5B74ED8AE1887ULL,
			0x506533C1CF7AB1D3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB2625FF96291BC4DULL,
			0x70BB3ACE780D07A3ULL,
			0x6FC21DB7F18A6BB7ULL,
			0x4B1CF83DF1C67575ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3EF88FD694D8D369ULL,
			0xF2A390601925A93EULL,
			0xBA96FDEDC88FA46EULL,
			0x56142E917A47C67AULL
		}
	};
	printf("Test Case 437\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5FEC432BBC5D26F8ULL,
			0x9308A54ADCD8E414ULL,
			0xDD51C9F36F48076CULL,
			0x71AB862F38CD391AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7A6D0FFB4E542A0ULL,
			0x1DCB63DEC15CE56CULL,
			0x44A609688A53ADACULL,
			0x1761278338C59E03ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3C8F063A55EA4310ULL,
			0x95BC739E86347E1CULL,
			0x12FDBFE46D35C720ULL,
			0x50F05F00958C6D29ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x00EDF6030B50A734ULL,
			0x9CB28DC2B5C5482FULL,
			0xB7E5EC581FCE7830ULL,
			0x196E9C2D2A4D10ACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3DA7996375825D05ULL,
			0xE483AE74B1B08EBFULL,
			0x9AB2FE84CA2F3570ULL,
			0x743BD79A8866D813ULL
		}
	};
	printf("Test Case 438\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x673CF269C7A52CA0ULL,
			0xC5E084D1702B01D5ULL,
			0xF97A2C11C235A784ULL,
			0x4BD7A7EEC217ADB0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BA356EB59DB0C07ULL,
			0x5B466677C4BC7BC4ULL,
			0x70961DE118803CF8ULL,
			0x018D0A6A65FC2850ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC7DA4E2C6478B3E0ULL,
			0x1573B0585DE2EFC6ULL,
			0x9DF483FA3F6F9632ULL,
			0x7FD6AD310779A0F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x75CF90B423BECA21ULL,
			0x01703BED269D04ACULL,
			0x1FF55FC4E7ED6B68ULL,
			0x107E7C2A7DA07B5EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1D320D21638C21AFULL,
			0x8582D0AA155621D7ULL,
			0xB01175989C18F344ULL,
			0x42BF9C374AF48DBBULL
		}
	};
	printf("Test Case 439\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA74C31E9596E2CB0ULL,
			0x161A650CE6316F91ULL,
			0x7481EFEF79A08001ULL,
			0x7EFDBD483F8C8DD5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEAC24811C36CCE10ULL,
			0x49EC16C603B9D770ULL,
			0x962A638B83D61DADULL,
			0x2852A5F50A03FC9CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA6C88A933238F750ULL,
			0xFDE19E7D678A85B1ULL,
			0xF67F1A9B2147F0F8ULL,
			0x4A787CE2C8CA1569ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9057D2696E90007ULL,
			0x301571C19BE911FEULL,
			0x67A09761268FDD49ULL,
			0x7784BF7D15074DEBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA37ABFE5796E6F99ULL,
			0x1E54740145C319E9ULL,
			0x6D6493CECAA5B824ULL,
			0x211D69B1FE6023A8ULL
		}
	};
	printf("Test Case 440\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD5D9377351D776D0ULL,
			0x1745AB30C88E7413ULL,
			0xF187590B26351EA7ULL,
			0x73FFF69BD2C011C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B07854393140D9FULL,
			0x8DE6F690ADF535EDULL,
			0xDEE0339BA2C720CEULL,
			0x307687C27C6298D9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x823BD9904B72CAE8ULL,
			0xA19CFC265343618FULL,
			0x6195D9439B48335AULL,
			0x69D73F447795BF0BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9F7F21E38604A30FULL,
			0x15EEE7EE9CD5D734ULL,
			0xFD9103BB1999AC15ULL,
			0x1DACB6AD645F32FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1A834E27E8421301ULL,
			0xD6E4BDD085EE8CD1ULL,
			0xFCD827C5EA0D258AULL,
			0x67E6FF2BA4683599ULL
		}
	};
	printf("Test Case 441\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFC6B1BD5906DA010ULL,
			0x457247C55F4A90E6ULL,
			0x89B9D6C4A1DFD3F0ULL,
			0x61FB681B88E93AFFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x54C11CF5666C5AC1ULL,
			0xD2E873072DBF4646ULL,
			0xE7ED373C4B0F5E0FULL,
			0x0DFD1D2A8839CDF0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60B3FED45EB9CA78ULL,
			0x9F9F230E6206517EULL,
			0xE5539849284EB6D8ULL,
			0x6A38F7CC0C98451EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDDED08E29A1DD469ULL,
			0x9E8B4914C92FA915ULL,
			0x9A71940ADA723E39ULL,
			0x503E197E0455531FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x40FE90F65B434FD8ULL,
			0x1C03DACD914C726CULL,
			0x5309C334A18A98ABULL,
			0x466B275325865D51ULL
		}
	};
	printf("Test Case 442\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x27399770DF2380C8ULL,
			0xB9C711DA8B53F77AULL,
			0xE3CDF4D316FDA965ULL,
			0x4FED418E97836B84ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C66D44581AB8946ULL,
			0x48F17E36A152565FULL,
			0xD86887814D177E01ULL,
			0x2BD5CFC9B259220BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE465AFB3DFA20AE8ULL,
			0x02C404AF9CE5E120ULL,
			0x22CB28C7705D839FULL,
			0x5B395718E740ACE3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4A1DA19117496D40ULL,
			0x82BD6F19A54B4754ULL,
			0xFA6ABDC0033436FBULL,
			0x08263FEA98C0DCD3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x01EE9389FEC49B9BULL,
			0xAF0A671E8D6944B9ULL,
			0xEE77D10199A09E1FULL,
			0x5BA71C818FB87CA6ULL
		}
	};
	printf("Test Case 443\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF60E5D9D0530E6E0ULL,
			0xA75F60C462E69283ULL,
			0x7C7255DAF58303CEULL,
			0x41A875FDAC808745ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5DA0DEB4A387CE78ULL,
			0xE0C03CBF1EF8F215ULL,
			0x4DBD0BB2E6B3D9AFULL,
			0x4244A11BA91C407AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60466D466DE4BD40ULL,
			0x89BF8F86B65318B6ULL,
			0x8BB0C6D314281642ULL,
			0x5B44D6F7DC82F1E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6C435F1A09BB8D87ULL,
			0x166B448863384040ULL,
			0x35CDA1031A399D75ULL,
			0x01CB991A0EEB6508ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8FB465A5CC2BF352ULL,
			0x0726313FA3DD24A8ULL,
			0x1A21F8F9F40E565EULL,
			0x6513B977DFEBFDA3ULL
		}
	};
	printf("Test Case 444\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x00B621D17C7FEB90ULL,
			0x48037045A2F6F0C2ULL,
			0xE24653F569A28080ULL,
			0x4E54C2090687FFFEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5DD1310A3718119AULL,
			0x39DE06825BB38A0CULL,
			0x52EB98AB18377D6EULL,
			0x33B2B4251150B01FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x795CEF8F3E4FC960ULL,
			0xAC8C7837C067EA0EULL,
			0x582DC63DCE875F4DULL,
			0x7985BB79278BDAA8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF436D319F9561CB8ULL,
			0x671FB57E2B2082E9ULL,
			0x176191C76F24F7D3ULL,
			0x0AE49B8D39D44402ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5861450CEC53E5F6ULL,
			0xD19EAF29823C8773ULL,
			0x52C20AF1E9A5498BULL,
			0x2FA37A94EBB6763FULL
		}
	};
	printf("Test Case 445\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC254282778868180ULL,
			0x3B29B9897CA26804ULL,
			0xCC287BE1F625F6E9ULL,
			0x71DEA5DF4F959E03ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE1B382BB96FA9DCDULL,
			0xC0E9C596412B18E5ULL,
			0x216952AADA47957AULL,
			0x602CE782BE67C458ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1653CD75A463D2F8ULL,
			0x9A909C76428EC7BEULL,
			0x717B2E92A8ADC3CFULL,
			0x589FE023D3C2311DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA4A6D7D16FBD756AULL,
			0xB3F63F53221E1B29ULL,
			0xBF61CB737FD654BBULL,
			0x0F04D9DDEB0E3246ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3624D303039558FAULL,
			0xF8283153B1559B06ULL,
			0x50799698F2940354ULL,
			0x07501863A619FEC5ULL
		}
	};
	printf("Test Case 446\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x27D2B5D5C14A8FA8ULL,
			0xB3DCA3F1B60DA07FULL,
			0x93956E8A61A2F440ULL,
			0x41D108303BCDC98BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD09824835FFBE68EULL,
			0x2488D26A07982D13ULL,
			0x4E07B9AB92646C23ULL,
			0x63BF49B4CFA3C5AEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDF489FF4CB694208ULL,
			0xBEA8FF9D0068E830ULL,
			0x9315D141770A7407ULL,
			0x67A9C5AA8DAFA19DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x485687B5B3FECB2FULL,
			0xF7EB348D1CEEFB2CULL,
			0x39E76C1A17E3D996ULL,
			0x2BEC570807C9966FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA04834691E5EA9E9ULL,
			0x2F3A20CE99A48A97ULL,
			0xDF17CA455BF54E03ULL,
			0x3D164D55B5BF2808ULL
		}
	};
	printf("Test Case 447\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4CAE9FF870978F60ULL,
			0x2084A13C87A644BDULL,
			0x056998B2FFC85BAEULL,
			0x5BFF0A4E87FE32BDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x586558FE928CE7CBULL,
			0x27C96DC705ADB4D2ULL,
			0xBB2EA87A76238764ULL,
			0x6A4B2168258CAE92ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE10E0FAE9B893070ULL,
			0xDE78A12EF47C7334ULL,
			0x553E38BDE6DBA6F2ULL,
			0x5D281C51B2AF3542ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7349FB1EB6F96B9AULL,
			0x9DA56C00E0F0BF4DULL,
			0xF4D332F650EBFD9AULL,
			0x2886BE214261BBFAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF254083ED91E21ABULL,
			0x184789B8B1E31CF4ULL,
			0xBEAD037F13E45611ULL,
			0x4BCBEA1FFA0E498FULL
		}
	};
	printf("Test Case 448\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF527F7D3F3DCC870ULL,
			0x46879081FDF0A932ULL,
			0xF24730C4DB2313CAULL,
			0x5082CBD367DE076BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x226695BB0FD04F74ULL,
			0x31ECFD1AA6AE81CAULL,
			0x1E248D3DFE95AA66ULL,
			0x29F419F9B3468A2EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0D8B570B87D9EC30ULL,
			0xDE60119592545107ULL,
			0x11DE95BF30D4243BULL,
			0x67D9CD576DD9B68AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37DF1959A415A145ULL,
			0xCE8385E9806389B6ULL,
			0xA80C1907E9853A38ULL,
			0x0AAF9B80E64953A0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9254D4023979130CULL,
			0x3A0C90776F63B319ULL,
			0x72170C0EA65E51DBULL,
			0x66A3B40EE4A81879ULL
		}
	};
	printf("Test Case 449\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6C25B6622A40EE48ULL,
			0x2733CA473A5EF0FDULL,
			0xBE220DEA3DAF20CCULL,
			0x5BCC7615A8734C53ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7F8831393F3968B9ULL,
			0x204986FEC60020A0ULL,
			0xA9B1533E2818E7BDULL,
			0x5291EC257D53EDCBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAECE48970AC1BF90ULL,
			0xD80E6CE20C04F868ULL,
			0x0199D23A82636F72ULL,
			0x4B3EE75C6D82D2A6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBD52D01C8CE2CF03ULL,
			0x87DD91744D9FDF24ULL,
			0x6F55CEDAA64B8A94ULL,
			0x62E5278FD91477AFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4DA26EEAD32787CBULL,
			0x5C8EA7EB709C4F03ULL,
			0xC91C5538BF029258ULL,
			0x70DCD68457C6DE46ULL
		}
	};
	printf("Test Case 450\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34D56C12347CA9D0ULL,
			0xA9E6D4B56BDC0409ULL,
			0x9C901F251C0E28ACULL,
			0x62E726661A1E6FB4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x255B8F84C09EC68BULL,
			0xCE72399536205860ULL,
			0x6EBD4E5D42B79660ULL,
			0x37E8E6D802BF9E75ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x92F082C867093120ULL,
			0x9FF1E6127863C873ULL,
			0x6286EE09E807618CULL,
			0x74A0EBDB1A57164CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x08D8685E8B5A2DBFULL,
			0x9AFDB134ECC9DB39ULL,
			0x5023983F67BDAB8DULL,
			0x44B7FC6D1565E8D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2F8393CA87C7CEC2ULL,
			0xF34A3DC6EFEC9AFCULL,
			0xA39B154DC84D6CECULL,
			0x2A9A90EB35BB1AD3ULL
		}
	};
	printf("Test Case 451\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D6F66D26C558058ULL,
			0xBED1021FE4794ADFULL,
			0xB31B34B6086DFE9EULL,
			0x750792876E7D9763ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE8F68F3718BC2FD4ULL,
			0xFF16AFC3AC77ECCAULL,
			0xD394D5F18C2342D1ULL,
			0x6489B2D0A7D79323ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF0D9CAA414BA8E78ULL,
			0x60EB4AF03B295B0AULL,
			0xC043BD13139DDFCDULL,
			0x6F6EB6CC37E702D3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE2D5659A39506D34ULL,
			0x5FFF2245B327B672ULL,
			0xFECFEA205F94D6FAULL,
			0x5E0DA15E92DA3701ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCA7B1CA4150E0AC0ULL,
			0xBCCD1FC1FF12E718ULL,
			0x4A3E0E3E78F195FEULL,
			0x767097F4BD4253CDULL
		}
	};
	printf("Test Case 452\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x993AE773EDCF5558ULL,
			0x1FD72757158B6928ULL,
			0x7AD72E9775EFC09BULL,
			0x50A08F590C3E7630ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5C3F84BD11949934ULL,
			0x4DCF31E93A16C4CAULL,
			0x4EEC325BD60C307DULL,
			0x50E61322F95ECAC9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF0E56D414328C9C8ULL,
			0x44DE134E574F84F3ULL,
			0x946C02E9D5683A65ULL,
			0x4885683732FED683ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4E3562D59EE64E30ULL,
			0xADCBFEEFE1BCEAA1ULL,
			0x2D7A0120ADD958EFULL,
			0x59A3EEB2CA94997AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x75B5AA1C4B4183FAULL,
			0x0989D9C6523F15E4ULL,
			0x6DAFEF2B6501431BULL,
			0x35CA6F6D25F5BC4AULL
		}
	};
	printf("Test Case 453\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xB90DFB2AE4C55D00ULL,
			0x411CF4342E9EEA09ULL,
			0xE981636730C86ED0ULL,
			0x5166CBF12EF47BD1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEED58F94BCC3B61ULL,
			0xD4BE28129A1FF514ULL,
			0x33C2478367DB0D12ULL,
			0x3093C1ECC3F389C6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x00B73F1D6EBDB228ULL,
			0x853EF056435DDA3DULL,
			0x66081838BBAF2B30ULL,
			0x49F8F98124F4BE5EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x58A890AFDF44A57BULL,
			0xFF2A34132C0DC6ABULL,
			0x2DE21B16112B2A37ULL,
			0x153DF231E77628C3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA672E33F3EF49BF3ULL,
			0xBE2864B0F6FA0961ULL,
			0xBCF397D77CD08559ULL,
			0x08EB217FEDA0EEE3ULL
		}
	};
	printf("Test Case 454\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDE49625F47FBD400ULL,
			0xA1FC23E93D06317FULL,
			0x01C88D4DCBA1522FULL,
			0x547318F42A922259ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF471446049E3B584ULL,
			0x1FD0014A84668C1EULL,
			0x7540E75663C5C169ULL,
			0x6E33A7395F9E80E3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x57161519B0A659A8ULL,
			0xF39C2E906FF2CAECULL,
			0x62184F03350E46D2ULL,
			0x4AC010F1C83B8654ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFAAC2118DF377C3EULL,
			0x49990393142C3A64ULL,
			0xF582244BACF81995ULL,
			0x69407EB9D2D10CC5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6FAB8165C5C57550ULL,
			0x8427E51BABECB1B5ULL,
			0x06FDF045E9619300ULL,
			0x505AF35CE12709F2ULL
		}
	};
	printf("Test Case 455\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x58A46CBEB5F13110ULL,
			0xBEF5C0EE7ECB3807ULL,
			0x3232B588A55D7F2BULL,
			0x44A4F2FB762FC413ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x77C8058C1D5BAE26ULL,
			0x779C34597C0AF8C6ULL,
			0x5673AF95CCB549D6ULL,
			0x3336A302D8328146ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA2E8FCE1122A0788ULL,
			0x4851250248AF23CCULL,
			0xEE2FFB694024173AULL,
			0x509D70D377551A39ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7D97C1D40D09A0EEULL,
			0x4A80EF408B6BF15FULL,
			0x05AA18F4AA577E65ULL,
			0x6F3CD6812784FFAFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0B31F1434E227ED2ULL,
			0x2685BF6D9D10FEDFULL,
			0x21D693E96967D5E6ULL,
			0x2918DA55A72040CCULL
		}
	};
	printf("Test Case 456\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x97E215BC9D794C08ULL,
			0x369436D051B52310ULL,
			0xFBAFA2AD1F41193FULL,
			0x7F2B513B65CE9750ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5982676A9046560EULL,
			0xEC0CAB13781A0F56ULL,
			0x71B6443EE97B4694ULL,
			0x12B33F8C62A4DD38ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x57D1C9CB5A364190ULL,
			0x6FF569A1CBB2C9A8ULL,
			0x495618C6DEB149D3ULL,
			0x763C332E1A01DE43ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1D44B2FD7F8905CFULL,
			0x9401C342DBB288F7ULL,
			0x311D9F79659D2E91ULL,
			0x3432F293489E454EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE070270471D5FDACULL,
			0x72735D645DE34134ULL,
			0x533B2B2CF90884D7ULL,
			0x55CD42030960FD97ULL
		}
	};
	printf("Test Case 457\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x850F515495A3A8A8ULL,
			0xA97DC5CDF3333A7FULL,
			0xA4B4BF63D89432F8ULL,
			0x43148AF67F53790EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB11AE5DFBA882E4ULL,
			0x605EADCF1C158313ULL,
			0x9DBD78EC35CC11B3ULL,
			0x6F71F0293B8346EDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x256C85CD03488238ULL,
			0xCD0F830246756951ULL,
			0x8CE277E1F003B392ULL,
			0x700A5C88E49CAB7DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x317968F4640AC807ULL,
			0xF532E2A8336C5B27ULL,
			0x61245CCCA32AD2B5ULL,
			0x3F43B473D0E1AFEEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC578651D5F919A40ULL,
			0x5DE241C1B07FED07ULL,
			0xE0E0A4D8ECE8C007ULL,
			0x43D2E0F0DC80D4E5ULL
		}
	};
	printf("Test Case 458\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x54370796340B0C70ULL,
			0xE9B6273ACA6A3141ULL,
			0x76BCFA44000092EDULL,
			0x7021D365F2926746ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD76118748B2D5A85ULL,
			0x5B83C7A687888E1DULL,
			0x46B62480295D60AFULL,
			0x5E19D091DBD58619ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF93968126980D920ULL,
			0x7573346F260C25DCULL,
			0xA39908851BE36E4DULL,
			0x64072B0FB1BDDEE4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x72C6FC08057460BAULL,
			0xE5F7C708DB95DAF5ULL,
			0x63A2BFDE7F5E664DULL,
			0x4AB67C60A8B92AC7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x905BADD6BD13A1D9ULL,
			0x85E886F9FF0151FEULL,
			0x04E200653392AEF1ULL,
			0x7271DA0577096802ULL
		}
	};
	printf("Test Case 459\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xA42DD2E186F976F8ULL,
			0xBD24085C591EBE1FULL,
			0x6EB8A8CBDCD60C54ULL,
			0x7EA3E98AD2CEEEDAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBDD80C426097A88AULL,
			0xDEA626DA51ADDE66ULL,
			0x8C8C15BDAF691731ULL,
			0x7D9DA15957055E8CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE62C84413E7D0640ULL,
			0xCEA9F5C9D7F7F2FCULL,
			0x81E5E6E28F57B8F5ULL,
			0x5E620C777C8AB173ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA1CA32B7B7627E23ULL,
			0x9DDF2CF0B8E91D84ULL,
			0x48D309025C3BF6E2ULL,
			0x310D538C430C9E74ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x45730071B3774861ULL,
			0xFFA9C29AF290FD5FULL,
			0x4206E01959441E4DULL,
			0x0C88BBC28A1C6A3DULL
		}
	};
	printf("Test Case 460\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x2728FAF44D455C98ULL,
			0xC1F0C9C823E8F148ULL,
			0xC5A6737829CC80B8ULL,
			0x7D53CD53CC150639ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2F1CB41E235C52B2ULL,
			0x94BE4CDAD7E65DBDULL,
			0xA4F55381307BBAFDULL,
			0x0AD90EB23134D54EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC751EFBC06E5C470ULL,
			0x1A2057EBBD103E94ULL,
			0x09D0FCC9FC78BAF2ULL,
			0x5D12C92A0F15774FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFC23C488FB10C19EULL,
			0x7C2F1079490EEF9EULL,
			0xB12B485F208E8CCDULL,
			0x38C41500C36A4008ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x11D48C74E7A83AD4ULL,
			0x80C66768635F9566ULL,
			0x1C830FBE34D6B3F5ULL,
			0x17A1E38EB2B64809ULL
		}
	};
	printf("Test Case 461\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4E72672B75BFF228ULL,
			0xC6728F434934A08AULL,
			0xC6EBA3B42FA57176ULL,
			0x62C44EAD8C492E60ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4031BF1E3019F31CULL,
			0xFC12994A46AE967FULL,
			0x2F450ED0A2893947ULL,
			0x035E13A3DB70EE74ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB33E49C24CC84158ULL,
			0xAF519C41FA359114ULL,
			0xAD94F942B027022FULL,
			0x4F9C0AFCD569ED62ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5A1FF50262527296ULL,
			0x7AC1EE31EA2701E8ULL,
			0xC68A84B9C6202A9FULL,
			0x7BB5E26ABAADCEC5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03D641E9C5F86DCBULL,
			0xFD5CA60A03E4E6EEULL,
			0xDAF02E4B80CF4E9BULL,
			0x583E37C02E598E2FULL
		}
	};
	printf("Test Case 462\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x5CC2B424D2B759F8ULL,
			0xCAD5CEC56DDE391DULL,
			0x018C27020D07E64BULL,
			0x64CFF488591BD143ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x099BCC98D0CDAFA3ULL,
			0xBE3C7D4DBBA5C5F0ULL,
			0xD0B55AF8BDC377D4ULL,
			0x46F76EB928EFF948ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4306D6D564812358ULL,
			0x6A36AFBFEAF7B13CULL,
			0x002D5C7F0B3A1995ULL,
			0x46FBE4A2C0B8A384ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x25A45995D6951104ULL,
			0xD39EF54E65B1D826ULL,
			0x225C05094D299AFEULL,
			0x2A655E07F335C5A3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBA201C9C2F804F55ULL,
			0x5F5348589A673486ULL,
			0x329E4B9E6697E915ULL,
			0x3DBAB6880B5C3D62ULL
		}
	};
	printf("Test Case 463\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xDE263856A9FDAC40ULL,
			0x3FB4BE21F47A92A3ULL,
			0xC818035954F8053BULL,
			0x50142CBB6914D9FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD81174D8D35DEA84ULL,
			0x0E2D0722F924D17CULL,
			0x788FFCA8E4A05546ULL,
			0x514DBA306B160A7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x63E61291575F8CF8ULL,
			0xB44A7C54EC8133F4ULL,
			0x94F39F7110955934ULL,
			0x65E5CD2E2127F453ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x581FE069BEB3BCFBULL,
			0x91567581C2FC98E4ULL,
			0xC9D495422F148C06ULL,
			0x43DE82E4FAAF01B9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF6590AB870E33C33ULL,
			0xE25A7494BCD0C755ULL,
			0x2935A5975D9023CAULL,
			0x157AB8AA9C1EA735ULL
		}
	};
	printf("Test Case 464\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAF8901CC566AD890ULL,
			0xC099EBE059D66DB1ULL,
			0x968BA97D3AA41A18ULL,
			0x6F2CB428FCC6B63FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCA7C3A93E9E1A9F6ULL,
			0x744C0B7A9CB716B9ULL,
			0xD22631BCB5D155CFULL,
			0x3CC8BE5698E11602ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2BB3F9FE9CD3F4D0ULL,
			0x02CF971290772991ULL,
			0x7801585704CCD917ULL,
			0x6E31C5D19E6ADC49ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3A729B7AEF457445ULL,
			0xD6D9C2E38BEF8C75ULL,
			0x450DC00A16804AC8ULL,
			0x27B1700A2F364B13ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC7D2C3658D9A4A15ULL,
			0xA82FBCCDB1DDC166ULL,
			0xB8AAA06192C91432ULL,
			0x10A9DE8522A25D3FULL
		}
	};
	printf("Test Case 465\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x84B2AFD561E54180ULL,
			0xF5C9A3FDD6DE9B4FULL,
			0xB71D107C917A0A49ULL,
			0x497CCBE9D281216DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0895954FEFF75EF1ULL,
			0x1E77DD770687AAF3ULL,
			0x81A3487FC483E472ULL,
			0x7646C67BFB3DF665ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x599A78BD91F34950ULL,
			0x3D011F69BFE5C006ULL,
			0xA67C2A2C84865F23ULL,
			0x7475D16E5D2144FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11E701056D2298B7ULL,
			0x75A75067B130ACE9ULL,
			0x21168DF8B7F04BFDULL,
			0x6A7E8E9A9726CC08ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x74FF177DD1C75855ULL,
			0xAD4734517769519CULL,
			0x34FFAC7D5BD31BA6ULL,
			0x17123238B8262908ULL
		}
	};
	printf("Test Case 466\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0F6CCA18D20D21E0ULL,
			0x61219724CD71F90FULL,
			0x442F3B16C2CEBE65ULL,
			0x76E7F2BEDA7B5F7FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF352716DE6764949ULL,
			0x32503092D83025DEULL,
			0x9FBB28FC0C56E355ULL,
			0x79FF75A206F91FC4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7DC0BA84D3C4B168ULL,
			0x7F0964B6915092FDULL,
			0xA0D2F70C9AF6BCA9ULL,
			0x684E529C4D1D0A44ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE39616AFBEF13B9FULL,
			0x446E37B476D9020FULL,
			0xE562C5DB36866772ULL,
			0x6260BDE6399A471DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5C19F896A11ECDA7ULL,
			0xB14509B31DB946EFULL,
			0xF673B397873C0E2AULL,
			0x338D085CC0C680C3ULL
		}
	};
	printf("Test Case 467\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6DA5CC034B168010ULL,
			0x65576E39085C3847ULL,
			0x366E3784D3069D35ULL,
			0x7F037121EBBAC700ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x11E07C2CF5A641FCULL,
			0x7A49A4E4BC3B3139ULL,
			0xF6D4C7B8FE143A3AULL,
			0x15102F7BBAD7B23FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6A6DCC950EF7E0A0ULL,
			0x7116541C43EE3939ULL,
			0x68E622F54082FFA8ULL,
			0x722172179E16E698ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAEBD45BA6A02E166ULL,
			0x7F640722AB9C00C9ULL,
			0xCF553147B1281E33ULL,
			0x7915B68FFD5296ABULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x68BFF589AD7E06CCULL,
			0x6E971781EAFE3485ULL,
			0xCAB61DC23CAC8D53ULL,
			0x1F41B7608F1A9A10ULL
		}
	};
	printf("Test Case 468\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0C872FACF99DCD78ULL,
			0x5521A9E351B5D14EULL,
			0xD02C70E923524193ULL,
			0x5B24BD16914E59E2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x98E097EC47001379ULL,
			0x73402F5A153F792BULL,
			0x59C64313A647FACAULL,
			0x37D18DC59192CB7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9B1683B74B58C650ULL,
			0x47A13CD5630345A1ULL,
			0x079CC69EE025571BULL,
			0x50F09750094002DEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCA1C2C3C88795A85ULL,
			0x77EE77CB704B7064ULL,
			0xD45916CC261FD759ULL,
			0x7F5C92A0F0A12743ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDDF43AC46045D3E2ULL,
			0x5A8C57273CA12BA0ULL,
			0x8803D17B1D637E4EULL,
			0x1D7EAD26829AD502ULL
		}
	};
	printf("Test Case 469\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x9DDB47FA0FE9E1B8ULL,
			0xCAD65A86094532DFULL,
			0x17457C01AADD1695ULL,
			0x725B3A04B270E5F9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5FF696F221F68664ULL,
			0x82FD9810FD86EEEDULL,
			0xDA23FDAC7DE5F748ULL,
			0x610907A0F7C63D15ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1063F08F475A4238ULL,
			0xF56259DFC9B815FDULL,
			0xE5D3A40F3EE0116DULL,
			0x6EAF0FCCE60B6F29ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC4452F7EC5376CC7ULL,
			0x6BDDA63BB1A5EC2EULL,
			0x781747100AEF2A2EULL,
			0x1FBBED9DD00F45C7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD2A557205080C611ULL,
			0xD76B2CC723EA5255ULL,
			0xE19BFCB334232F83ULL,
			0x42168E208EEF7114ULL
		}
	};
	printf("Test Case 470\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xC04B6B5A0B931CC8ULL,
			0x3B2F8B662D87EC12ULL,
			0x34DAABBAD2F3D770ULL,
			0x6F1941EDFE6C6A3FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x61439AA7FE8FFD6FULL,
			0x973BA345890A5A9BULL,
			0x7D31666BEDABC910ULL,
			0x3387D395A8D70E24ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x99BECEFA08C8B900ULL,
			0x02C726EC8DDAEFA4ULL,
			0x201CD25E5FAD6FBFULL,
			0x77CACA0804DCF023ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x345099531DE221CAULL,
			0x717095C4B7CA8A4DULL,
			0x0B0A3ECE4EB9748AULL,
			0x0E9AFD8121B2E31CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED69F31BD66430EDULL,
			0xD57E15E14390362DULL,
			0x067979EFFBCCC8ACULL,
			0x7E2A43CC8DB3E5E9ULL
		}
	};
	printf("Test Case 471\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x62BFB4856EDEB630ULL,
			0x84E160AA839F3A11ULL,
			0xD3BEED1474790E00ULL,
			0x4795BC29C9DE85F4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B426A4E7618C384ULL,
			0x14E26EA7B476CA03ULL,
			0x95F8E1C60C3112D8ULL,
			0x06C25790E6803D14ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF236E86DFA194288ULL,
			0x4A396F63A3D3DDC8ULL,
			0x08CD2B8851EB0CF9ULL,
			0x58A3D20D3EB601B3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1BA843B9EE428A15ULL,
			0x52509589A7385EAEULL,
			0x4433C9D7F424D3C9ULL,
			0x07DA32717EFE7DCAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B46BB4FE17DCCF4ULL,
			0xA34F1D9F3862019BULL,
			0x7948FA95D490AF85ULL,
			0x28100F8499386EBBULL
		}
	};
	printf("Test Case 472\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xAA24845F91448F58ULL,
			0x096EC08BF6EB6F60ULL,
			0xE6C2C9800787042EULL,
			0x5B6D3C93FCE8665CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x023026442F540741ULL,
			0xCA53D785B6ED7B18ULL,
			0x62E5172B1A6922ACULL,
			0x4AD675BD9359560DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6E6EC664F2531860ULL,
			0x97844F9A0D2F81F2ULL,
			0x164C4212E11A0AA5ULL,
			0x4570FBB78465A835ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC315B8C7FF1DC01ULL,
			0xF630FA3B55DD969EULL,
			0x94D75C7D04823F25ULL,
			0x13BC2D1247BF0D51ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x24F535C25FCF7BF5ULL,
			0x270EA82ACE2BC462ULL,
			0x6D648C4FD34627B9ULL,
			0x4AE19230D8F15B99ULL
		}
	};
	printf("Test Case 473\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE40C0B995723C7E0ULL,
			0xA96CBCA117857916ULL,
			0x6C8783E7D92B6965ULL,
			0x7FD94CF2CE7702DEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF746305F35AA92EULL,
			0xDED9F5F0D224D80AULL,
			0x91A8B3C311673757ULL,
			0x2E159297FEB6CAE9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFEC200A6CF476EA8ULL,
			0xFE4893861C369F57ULL,
			0x646290A716A25BD8ULL,
			0x7179F8C00B162D7DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x838E618D9A3955E7ULL,
			0xCB2D49517750C26DULL,
			0x9CD2AFD8A0133F4CULL,
			0x5537AB9C1AE70DE9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4FABE9FE4AE6086ULL,
			0x2F1671B011BEE058ULL,
			0x9846C255AEEFF703ULL,
			0x157706259975058FULL
		}
	};
	printf("Test Case 474\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4D9B4661E6712FD0ULL,
			0x009A6CF640662BBCULL,
			0xA0B403EA8D8EA4D0ULL,
			0x4EF7FCF34632EA7DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xADADA29CCA6F5F37ULL,
			0xB6E678073AF392AEULL,
			0x7002381BAC0BFA89ULL,
			0x39C19B0D5F7FA640ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB33D22B98C5FE168ULL,
			0xCB845FC3EBC4681FULL,
			0xCF7E68BEC5F51CB7ULL,
			0x42975186AAD90A1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x81999AD9B57E3809ULL,
			0x5D4EBB7B860CE3F9ULL,
			0xA0D1A2FFCBB44EA4ULL,
			0x439296C2B7ABBADDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDFB43F9B261A3DF8ULL,
			0x81A9D5132C46DE16ULL,
			0xFBBA1AA789C0C8F6ULL,
			0x7457637EB1E3B714ULL
		}
	};
	printf("Test Case 475\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x70120234720E9CF0ULL,
			0x7DABA5BE3C9B0606ULL,
			0x1DC28E4B17BE25A5ULL,
			0x7378990DB9C252CFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6A4F3F5D97AEF2A7ULL,
			0x9469D958031C4869ULL,
			0x13839AA1F289B132ULL,
			0x2C2B7DB5FB6CB067ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBE5F1B34B76B3670ULL,
			0xFD2453728256877FULL,
			0x0E39CC51492888BAULL,
			0x7DEC0861035758ACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3C9306771623FCE9ULL,
			0x43205E3438385CC1ULL,
			0x05CD17FFF5719132ULL,
			0x21AFB3AA447F2F25ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE93F9D5A5B4A5BD6ULL,
			0x19732B14B22C8F5EULL,
			0x640929BC7F4A2AE9ULL,
			0x242851C0072461E8ULL
		}
	};
	printf("Test Case 476\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x67EA359A9D4EEB18ULL,
			0x9FF3BC3BCB9FEE71ULL,
			0xCBA8E3542B395F49ULL,
			0x6833DDF191BB3C7CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x847F0C6355214973ULL,
			0x116490E69AD965A0ULL,
			0xBEA90B1A0238B9C6ULL,
			0x562346476ED56E00ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x84A058ECFE5DF838ULL,
			0x4F38FEC7672DE348ULL,
			0x05F46B100399BAD6ULL,
			0x7D7D2FE9EA59F73AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9262672E6182C67ULL,
			0x1FB1BD83BD3D0BCBULL,
			0x0291F4C7A9403AD0ULL,
			0x2A1C7836E56F108AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x38B4186D152D9331ULL,
			0x624F48FD765DCD3DULL,
			0x5B0B07C1482022F0ULL,
			0x3532B3E52EBAD766ULL
		}
	};
	printf("Test Case 477\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBCDDB2FB5FF857D8ULL,
			0x1048FCA2F39C2E26ULL,
			0xF7CE3194BB4A19EAULL,
			0x60CB6009EAAB252BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x81563B85A1EC63B3ULL,
			0x7E92AC1A119194F8ULL,
			0x1DFE3B66D74A36D9ULL,
			0x7E217F2D8243F1F8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA3B56FC2A78C8698ULL,
			0x236205429A9B70D3ULL,
			0xA8CA6FBADAC2BA12ULL,
			0x7BC9575408383B2AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0BDF13FA2B67EBF3ULL,
			0x6E5D98BEFB7877B1ULL,
			0xFCF8FCCF923F4B16ULL,
			0x4018BDC9BA8AF2F8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD437624FB160B8FDULL,
			0xDAC6AC538B692FB1ULL,
			0x3A25ACD2F47C129DULL,
			0x05BB5840C40E14CBULL
		}
	};
	printf("Test Case 478\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x3DADA8761213BE50ULL,
			0xA28092D91F9F363CULL,
			0x017537025298D62FULL,
			0x7B39F69A283DD03BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1856ABEE32D44907ULL,
			0x56A17BEA9A70AFD6ULL,
			0x85DC2257440440A2ULL,
			0x1895F3F06BF84CDCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x44F5E2DA7DDFAA78ULL,
			0x55E2328B69E53458ULL,
			0xC5CE5B92D592C1BDULL,
			0x738F7D97C7E48466ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x149ADB7A36A8D16CULL,
			0xD3719D303E64A0A0ULL,
			0x041FAEC7D22C14E6ULL,
			0x17C94574F03A4DB8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x382C4D21A9C248E9ULL,
			0xDCCF412A90526811ULL,
			0x0D443AE7D2538D21ULL,
			0x0904A1B00790E616ULL
		}
	};
	printf("Test Case 479\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEDB9EFA584F4C728ULL,
			0x52B78E472399098BULL,
			0xB56419D3CAA95666ULL,
			0x777D73D02E85711CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4E9113A647E72D8AULL,
			0xB406A740E749D3B4ULL,
			0xED1ED3E60AB343C9ULL,
			0x60C52DD02936FBF7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9AEDFC19B2687D60ULL,
			0xBD6728B4FE05591EULL,
			0x68E9C87B9A29E142ULL,
			0x604741DF5E7EE16EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7835BD70FC21231FULL,
			0x66EC65C3685B945FULL,
			0x3FA682059E65AE02ULL,
			0x1FEFD29064B8630AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x11B0914976ECFA70ULL,
			0x6DA628A550176A8AULL,
			0x7B5EB2475A342DDEULL,
			0x229DCEC12EEA73E9ULL
		}
	};
	printf("Test Case 480\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xBAB6A6CDA5377C10ULL,
			0xFE3196EA3DE7194FULL,
			0x402647783E67C1C6ULL,
			0x46951499535D1AC9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x402F39887086A355ULL,
			0x8892F1DD30CDFDC3ULL,
			0xFB06713A3F0CCBA1ULL,
			0x6599FC10A75B2021ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFC10FA93CB6502F0ULL,
			0xC221FBB6E5885C51ULL,
			0x400889B774D40D0FULL,
			0x6109FD5CE1F0B860ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC7957817B0E56DAULL,
			0xF167320CEED00065ULL,
			0x5E51435897001D76ULL,
			0x56B2F899074E7784ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8BE582B573B2CC44ULL,
			0x574F45DCB8F4610CULL,
			0xC43BD0EDAD333740ULL,
			0x4041A020218816A2ULL
		}
	};
	printf("Test Case 481\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x397D940B67192420ULL,
			0xBFA18A9A594789CBULL,
			0xE691688F58712F66ULL,
			0x574CE3E52DA4E07FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB231EED17567A0F1ULL,
			0x40D9BA6F09D7269AULL,
			0x178F5FA97AAD871CULL,
			0x6C6647E08FD8483CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x67EC2359C404E8C8ULL,
			0x6D5482C4D2B3A88BULL,
			0x02320F17A99D5113ULL,
			0x57CD3467EC707B67ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x05B0032F9A5D4178ULL,
			0xDB5291AEACA6EFDCULL,
			0xEB450C24C9504E1FULL,
			0x37366699652A6C99ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1AF5D47D2C163F3BULL,
			0xEA20135B75A11F4FULL,
			0x2970BE18F198C287ULL,
			0x000AA18BFD0032ECULL
		}
	};
	printf("Test Case 482\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFE8BB722CF343E88ULL,
			0x1FA742203FDF4468ULL,
			0x04C6AB60D1C2D957ULL,
			0x7353CF475188CFC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x05FEF86FAC8394E6ULL,
			0x78A04AD2E4EB1D4BULL,
			0xAE301F060303702FULL,
			0x3A4E767EB85C44ADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8C3059E541C21BF8ULL,
			0x6C44963550EED419ULL,
			0xFB55E59DBD3400A9ULL,
			0x78146F58DBEDB71CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7813F53F1E1AC09BULL,
			0x60FBE6D65056E173ULL,
			0x65D2C7D73A1C9FE0ULL,
			0x7E3C570A4B6E8614ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x49B75913F5492DCCULL,
			0x74F6E60A40225DBEULL,
			0x1D6363B42CAA6FAAULL,
			0x19D494D8A58EEBA0ULL
		}
	};
	printf("Test Case 483\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x6D439F6889E55DB0ULL,
			0xA3A2BFDB5EE7F1FEULL,
			0x5BE9EC9B4E6B1FA4ULL,
			0x54B812FEF7F14001ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFC6B933FC09CD80FULL,
			0xA4F3F39FE2AD8E5BULL,
			0x0FD8A181983AD2EFULL,
			0x5C238D35B756813CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6C33CFEB1DEF7240ULL,
			0x63BAC47497086FDAULL,
			0xA38DB655E9002B4CULL,
			0x76713418238CFAE8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6BA24ADE6A0A49EAULL,
			0xA3D17B609149FFECULL,
			0x0B94973B9DF65B89ULL,
			0x63509F97F019906DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x278ABD2C66D7DD36ULL,
			0x9A7C34C362CDBBD9ULL,
			0xB535ACE6ADF6748DULL,
			0x0141BF3C9D6FD56AULL
		}
	};
	printf("Test Case 484\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x25C32D4DB81046E8ULL,
			0x70246ADEEDD4413AULL,
			0xB41E750754BAA79AULL,
			0x4B9F811316C56181ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBDD8BDC8B6A8C8B7ULL,
			0x0FBD7FA037FE6062ULL,
			0x436192184182C024ULL,
			0x734545BEFF3F40F6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x17118BE7606142A0ULL,
			0xFC9D09E277071E03ULL,
			0x31054E6CA0BA68DDULL,
			0x5B875C0BD931F213ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF0561CF3903A4E6BULL,
			0xE130B07338A6BD2EULL,
			0xB78F8C677FF2790FULL,
			0x0FFC8B082B4560A3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x123A043D57D0FF84ULL,
			0x53DC96089A7CAB15ULL,
			0xCACF5B4E682C41BAULL,
			0x56EC1E7D92C8FDBBULL
		}
	};
	printf("Test Case 485\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE4C573DB14D07C70ULL,
			0xBE222952184FF7EAULL,
			0x4EDA63B5303E3CD2ULL,
			0x43E09E8C110AC0F2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C42714146011183ULL,
			0x5DD5C4E57B699122ULL,
			0x880121DE52C472D5ULL,
			0x7C3E6F038EBAAFF9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8198EB70E579BD30ULL,
			0x98B8EACA723311D2ULL,
			0x0446DD9FAA2AB0E1ULL,
			0x4608A0A1DE486116ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x205747FCD632B462ULL,
			0x59001EE2C56BB030ULL,
			0x7D1DEAAF76F57411ULL,
			0x0C231D692ACD49DEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x25BB39F0A6C5D2DDULL,
			0x54C9B8D3FE2FC075ULL,
			0x11409A071E2E159CULL,
			0x666B343795336E45ULL
		}
	};
	printf("Test Case 486\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x4AF07B0888CB8C68ULL,
			0x912A7D22A7D6CC1EULL,
			0x3243D2227C1DD06CULL,
			0x62A976E7E83F6AC7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9B2870C389684B75ULL,
			0x25DF83D7ADD85FA7ULL,
			0xA5D240B37A9ADE02ULL,
			0x3BE97FD9529923D3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF90BBDB820ECBAB8ULL,
			0xBC959571B0455101ULL,
			0x9145A7153607BA07ULL,
			0x7F7B9274DD4E3C65ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x07F7595129A43B41ULL,
			0x07F57BA6E2DACD3BULL,
			0x1967E6796C0E0F19ULL,
			0x7A35332F151B3810ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4DF6E8C609C53F82ULL,
			0x942C49B2175183D6ULL,
			0x590CEA9E4E567EE9ULL,
			0x645FDE17893F20F4ULL
		}
	};
	printf("Test Case 487\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x1B63001AEB11BC88ULL,
			0x927A24B3C193621FULL,
			0xD94AB5A2792F4AF2ULL,
			0x61D5D1FA7E6C7711ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6AFE00C8C140D5A5ULL,
			0x4943CD090D95A9FBULL,
			0xF518D8FB076B2E91ULL,
			0x47C2C39E63122CD9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBE3140868B55FD28ULL,
			0x0E664B61C9F0433EULL,
			0xB65ACB7B1AB5015FULL,
			0x6A41C7042D2B8007ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4D241FC7692B81FDULL,
			0xC0BE8F12CEADC926ULL,
			0xAB5F4E1B29BCA062ULL,
			0x7C4E51D23FCEAD95ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB386636B99774244ULL,
			0x13664CC55F5F50B3ULL,
			0x87647FE8855DF3BAULL,
			0x65CC8753BA5BF26CULL
		}
	};
	printf("Test Case 488\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xD5CB7D7FB1020B88ULL,
			0xFED222A003304557ULL,
			0xD5968C27144259A6ULL,
			0x71CD1C52521D69A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72B05BC948AFEB68ULL,
			0xCC62F23F11725364ULL,
			0x6BEEBCCAA313EF64ULL,
			0x185F6E90915FF9BBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7112E241E4DDBF28ULL,
			0xC913FA0792D51B82ULL,
			0xF0CE7BBE68C4E869ULL,
			0x599B49490DCF4058ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8208AD74C09FF4CBULL,
			0xABA93AB4A90D70A0ULL,
			0x9CB631570EDEB7C6ULL,
			0x78D8C20447E73EDFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6E885EAD384EA5FFULL,
			0x18BB138D6EE0A1A2ULL,
			0xB908F1ABB6B0F231ULL,
			0x5D398B544AA68991ULL
		}
	};
	printf("Test Case 489\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xE8DFFD283A5D8CA0ULL,
			0x7F7514F63B78C4D2ULL,
			0x4F5A42AF35402F20ULL,
			0x754990EB493F2234ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6070D29A63BFE2E8ULL,
			0x206881E18757AC9FULL,
			0xB2E2232B5EEB05FAULL,
			0x1133AD6E08B844CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x88138D4E3E001DC8ULL,
			0x1A4424F687C90D56ULL,
			0x394EE0DCB90B9CFCULL,
			0x406926CD492009CAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDABAFBE7339F5E26ULL,
			0x3D8360C48B03FD20ULL,
			0xCFF486E5E0EF60F9ULL,
			0x750489992C93CFACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4191459DC8B0A8E1ULL,
			0xF3B316C407B350A2ULL,
			0x326FFE5F0B115562ULL,
			0x73D0F549147BBF6CULL
		}
	};
	printf("Test Case 490\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xFFC45B6101343110ULL,
			0xC163031508E6DB36ULL,
			0xCD21C1E9CD765A4CULL,
			0x489377C87BAB3B4EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9514031884182B8CULL,
			0xB3C4AB0408C38B48ULL,
			0x5AE9884E84D44D9CULL,
			0x3A076F5054D5D627ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5E90001F69881410ULL,
			0xBE76986C45AE7F73ULL,
			0xCF1406536BE41035ULL,
			0x4663C1B598EF2530ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC5341544C9DFB704ULL,
			0xDEA896B9C8D78887ULL,
			0xCA10DFF74A9AD666ULL,
			0x29BCF1E8C875845CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABF7407BFEF1C9CCULL,
			0x418E8982647B9B5EULL,
			0x55FF0ED557DD1E42ULL,
			0x5F89CD0DE0DC8CC4ULL
		}
	};
	printf("Test Case 491\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x48D9AC76845393E8ULL,
			0xA51A2AD8FD6E973CULL,
			0xB7D9BD2166E1C1ACULL,
			0x553BEB3E3126CD01ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x783E18CF0DBBC285ULL,
			0xE3411BC582971AD0ULL,
			0x42A541DF970CF5EDULL,
			0x38FE40624BB5920BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C3359541B372B58ULL,
			0x45F8011318386349ULL,
			0x025B36FD0EFF2BE9ULL,
			0x65EC1B006DE86B22ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x44CA52D743992B80ULL,
			0x52037E93325EEDA7ULL,
			0x4082D16CBB56E396ULL,
			0x368AC9E41E17F93DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x95DF68C89B565B9DULL,
			0xC62F59A129915746ULL,
			0x5827BA3F2A318B19ULL,
			0x3A0183DD64869A78ULL
		}
	};
	printf("Test Case 492\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x0921F772B0F32E08ULL,
			0x5E1FA4A676B4DFBBULL,
			0xF663F83CBE2645D7ULL,
			0x611B8B872326682DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7C5395B820188DDULL,
			0x8853DA8585455DCAULL,
			0x0BBED8F7A9A4088AULL,
			0x7D7D5F1395F1A7C0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6A46C819D13705C0ULL,
			0xDCE4541B75952CB4ULL,
			0xCAEF3FEB3E124577ULL,
			0x776CB2F787412E1CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE7DE754D47F268F3ULL,
			0x0D045DA594686789ULL,
			0x860D438CB897C941ULL,
			0x7CC28D3E4BEE1EE9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x718DA07BD4BD06E1ULL,
			0xEBCFF5A69FAC1F08ULL,
			0xB968211A64E351FDULL,
			0x1CA7E46156D5A956ULL
		}
	};
	printf("Test Case 493\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xEC374944AD4C6F58ULL,
			0xE15D7FE1BD91DB12ULL,
			0x5CE8CA2025BD23B2ULL,
			0x43CDFBB6E4AB987DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x219565B3B22041B8ULL,
			0xEE127943DA016779ULL,
			0x0DF5C01089D78D53ULL,
			0x0E546ECDEFAAC2E3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8357A3A9FEC5EB18ULL,
			0xF2C6D98D3D71A0E1ULL,
			0x9DFC8F4D4FD8A3D6ULL,
			0x58DB47CA4C173588ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD6A6FF7CDD68DA64ULL,
			0x065AF327068CC297ULL,
			0x9E441749E48D4982ULL,
			0x2FE633F3BDFA4CC2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7F57D215FDA61A69ULL,
			0x515E2DD0BF6BFBA9ULL,
			0x54D2288AE6404CC5ULL,
			0x66F7EAA163219035ULL
		}
	};
	printf("Test Case 494\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xF121C16A765B2210ULL,
			0x451B276C27CC361DULL,
			0x657687A7B29B6C0DULL,
			0x51BBAA322BB06BAAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCE83E576AAB8367CULL,
			0x505B119AD4AE888DULL,
			0x0EB3557237FF8593ULL,
			0x56E4EBD9F2BC1D51ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x40E3DF151A360F10ULL,
			0xF0B4B615E4672767ULL,
			0x741B82C33850C63BULL,
			0x61B81D7653D585F8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFFF8F24FC84B63D4ULL,
			0x2B2003BC16DE8536ULL,
			0x718D509CEBF154EFULL,
			0x6BF109E995FEFD17ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE15C1B039E9D8E27ULL,
			0x003B360180970869ULL,
			0x814077F3E0ECB87AULL,
			0x596CFB824A773363ULL
		}
	};
	printf("Test Case 495\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x51A0A7C363EF5D20ULL,
			0xA4DA82661C5C92F3ULL,
			0xC1C51573B6D6BD0BULL,
			0x7B79AD21D71DF6C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15A0CA02E38D4AC9ULL,
			0xE57A37BE2AC94283ULL,
			0x4F3B651F5A67F24DULL,
			0x56955E3C0AC17323ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x055113A9F1817BD8ULL,
			0x3D1354711A34A9DCULL,
			0xAA769F52C5A90A41ULL,
			0x5ED6EA21D6F76E75ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DC48CAE77627BAFULL,
			0xBB400229D7D16D7FULL,
			0xD0B53418181D44E2ULL,
			0x1108A68365C5A70BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x220B23831BEAD847ULL,
			0x2FEA14811CBD559EULL,
			0x029E2A7A882DFFA1ULL,
			0x7FBEB3C7FB741AFDULL
		}
	};
	printf("Test Case 496\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x410DDFA1A1E76F60ULL,
			0xF95B243B01A267FCULL,
			0x9792E996E2B8EA89ULL,
			0x593E929DB45B1906ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6433E65BCC3A943ULL,
			0x73F23F9A3FA674B0ULL,
			0x00596FC00079F09CULL,
			0x564A80F19670B0F3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDF0EB44CE8B026F8ULL,
			0x0A15AA452AFBF404ULL,
			0x68C487BE6D628AD4ULL,
			0x733B0B99033E4067ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDCBC4D80F02F1EEBULL,
			0x251C595990D3D69AULL,
			0xB1DFD8442E4D8221ULL,
			0x2B0822A94D9472C5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE085C13FCCD3BBF5ULL,
			0x15BB48C84F258CE0ULL,
			0x4959713399197ACEULL,
			0x17E8B252F2B5B9F7ULL
		}
	};
	printf("Test Case 497\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x69AB1BE941AA46A8ULL,
			0x14E42AC160102232ULL,
			0x0A4CB1A5764DB29EULL,
			0x46D33CAB87912021ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x42A6B1E3484C7E31ULL,
			0xBD825147264957FDULL,
			0x90A65202D3E3ECF7ULL,
			0x2CF4BFC875114EDCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x25A8577838684A50ULL,
			0x89A9EE4C6D482192ULL,
			0x8386937C4338B991ULL,
			0x4635DAE2177051C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFF3E298D42231367ULL,
			0xF3F9DD17357B9B2CULL,
			0x3E466E0B0FA43CACULL,
			0x426F34BC4EE3869EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB5F1A1D6D5DB8FE1ULL,
			0xCACFE210C9033BA7ULL,
			0x4627A2B65883EF80ULL,
			0x305DC73B8B5D55E9ULL
		}
	};
	printf("Test Case 498\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0x34326A62D2D92F70ULL,
			0xD87EEE4DFD69A55DULL,
			0x318EF6118E39F208ULL,
			0x586D818BFD8DA225ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7747BF01B7918B3BULL,
			0xA996882FC7993480ULL,
			0x397DE46C14994A9AULL,
			0x4E34D71DD4295AF2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9C9EC0D7F6524BF0ULL,
			0x5368CBF60E3CBEC3ULL,
			0x48FC72957F28A32DULL,
			0x7F6AB80C7B477C23ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFA2C94BEAA23BC6ULL,
			0x300322B2B541ED66ULL,
			0xDDAE6EF2D2015C5BULL,
			0x6A922F2177DE63A5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA6CF68FB4A8C60BDULL,
			0x3034BBA0E2F62824ULL,
			0xD37E5713E6338CF6ULL,
			0x50F82DC256977B14ULL
		}
	};
	printf("Test Case 499\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}

	priv_key1 = (curve25519_key_t){
		.key64 = {
			0xCB1C33885FEC61C8ULL,
			0x4F7C3F3ABAE790C0ULL,
			0x54403377AB05B02AULL,
			0x4B4CA0EAA06AEE03ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6C86BE80E4743B83ULL,
			0x63257F9480AC9455ULL,
			0x42B0DC1283771BC6ULL,
			0x19842EDB221B789DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC9215F5965489E60ULL,
			0xF654820B4C270845ULL,
			0x854E63819F679ED1ULL,
			0x5CD9DEB6D855490FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7B6EEA3937DDB704ULL,
			0x59C9FA38643BB95FULL,
			0x086480E3477BF245ULL,
			0x7426147CB4BB2C2FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8BFEC310977D1E9DULL,
			0xB81818B9F3798A1AULL,
			0x0F73FC9618AE112DULL,
			0x505B085AF3BE2F47ULL
		}
	};
	printf("Test Case 500\n");
	printf("priv_key1:\n");
	curve25519_key_printf(&priv_key1, COMPLETE);
	printf("pub_key1:\n");
	curve25519_key_printf(&pub_key1, COMPLETE);
	printf("priv_key2:\n");
	curve25519_key_printf(&priv_key2, COMPLETE);
	printf("pub_key2:\n");
	curve25519_key_printf(&pub_key2, COMPLETE);
	printf("Expected:\n");
	curve25519_key_printf(&shared_key, COMPLETE);
	curve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);
	curve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);
	res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("r1:\n");
		curve25519_key_printf(&r1, COMPLETE);
		printf("r2:\n");
		curve25519_key_printf(&r2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}

	return 0;
}