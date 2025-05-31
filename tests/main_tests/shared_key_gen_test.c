#include "../tests.h"

int32_t curve25519_shared_key_gen_test(void) {
	printf("Public Key Generation Test\n");
	curve25519_key_t priv_key1 = {
		.key64 = {
			0x381DB21DE2AD2170ULL,
			0x6CE5CF9DA1583F9DULL,
			0x7272497AF290CF11ULL,
			0x7DF731A4B4C9A801ULL
		}
	};
	curve25519_key_t pub_key1 = {
		.key64 = {
			0xCC746F183B381D70ULL,
			0xF0DA6EB44D01C50EULL,
			0x9F842796AA32F115ULL,
			0x635B1E4337425475ULL
		}
	};
	curve25519_key_t priv_key2 = {
		.key64 = {
			0x0C960FBEF5262678ULL,
			0x10D89C906D21D1D8ULL,
			0x14A18864F413DD22ULL,
			0x51C350AED0536514ULL
		}
	};
	curve25519_key_t pub_key2 = {
		.key64 = {
			0xFA842E660610844DULL,
			0xD3D743DC86398B78ULL,
			0x5BC4CD9049CECAA5ULL,
			0x3C3C6C8F2CB6A2BCULL
		}
	};
	curve25519_key_t shared_key = {
		.key64 = {
			0xB0CFEBCD2CA72B3BULL,
			0x8BB4F35649E6E79AULL,
			0xD77AF882B72717D1ULL,
			0x06F7836704D39005ULL
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
			0x4584804E080BBC40ULL,
			0xD251C7DA5298BD9CULL,
			0xFCE32529217359CEULL,
			0x7E7E4E8D07762229ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC49A0806D8CFA917ULL,
			0xA83A2CD9F10CB798ULL,
			0x4B9BE6A5E25DD2AFULL,
			0x55831EB4DD758AFCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x080F6FCAC3609300ULL,
			0xA2EE6E3B5163EECEULL,
			0x0C4EC2388CA84E47ULL,
			0x716292083E6949F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBDBA076AAD90FBCCULL,
			0x347DBC0E60DBA40AULL,
			0xF8766559FB5F821CULL,
			0x2C8B9400BE3EF2C2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x39F3AD4925B03CBFULL,
			0x21A96C169411CBD5ULL,
			0x1ABC3D42E7F7A741ULL,
			0x0E566E955E50F91BULL
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
			0x5165F2ABEED957A0ULL,
			0x24335354C377CED2ULL,
			0xC18A4567F524D426ULL,
			0x59E06DCDB08D9E6BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAA558C4D0E8E11AAULL,
			0xB38ECBC7743EBB4EULL,
			0x4AA3D511B52C31D7ULL,
			0x6BBA3FE5A0ADD697ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x674909D5E96BFB18ULL,
			0xA7C777BE5456F4C5ULL,
			0x7FFC49C111B997EDULL,
			0x51DE9DABF067DE4AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8921CDA39A2B8EA8ULL,
			0x04DF3D4DB12523B4ULL,
			0x4CAD5DFBA599AEC4ULL,
			0x72F969464BABFCE8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9C590A0AEB5CC234ULL,
			0xF4B76D9C94C591F7ULL,
			0x3E329A04BF07DBB8ULL,
			0x2BE9AB9EFE2023AFULL
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
			0x0FE92EBBC2CEE3B8ULL,
			0xA998FEEC97FD6ACBULL,
			0xF5F2E9D69D9EA755ULL,
			0x4C55912BD2906AC3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4A14893406FA7FE3ULL,
			0xC703B01D4E275873ULL,
			0xF844C0AB96BBEE78ULL,
			0x22DE25A3CD70DB3DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x69571DD4AEF279B0ULL,
			0xF7514B05BE0512F2ULL,
			0xC30422813151D807ULL,
			0x5E89AE0A205811C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x52B379C6F873E283ULL,
			0x2FC396D6A52DACC3ULL,
			0x475DA27C4EB013DAULL,
			0x721B4F97458BB57CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFE7F7CA62B2CC9C1ULL,
			0x75AD478D8B4EB29CULL,
			0xFF68EE7B2F649117ULL,
			0x375A6B94D09A8817ULL
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
			0x3FA32DE0381D5A00ULL,
			0xD00A3D9C6451BDA5ULL,
			0xD18C223115F94038ULL,
			0x553FEE7BF3C2D039ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC3BFA5704ECD6347ULL,
			0xF08C5C26EB0F3390ULL,
			0xD6B4F0BBBFEB4BFDULL,
			0x15EFF85BBCBB3988ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD2B05F12D2F5B28ULL,
			0x8497CC4640C65702ULL,
			0xA715A18889487AA1ULL,
			0x588C855B02C0D653ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x08E37EE74C64C26FULL,
			0xE42D65782E804233ULL,
			0x3CE2A9096907B7EDULL,
			0x5B0E53BDF71B0126ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2BB50100802271F3ULL,
			0xF8D5042D29F45BC5ULL,
			0x135996318C0DC28CULL,
			0x7DA56DFD357591A7ULL
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
			0x8E2893E0CF20D588ULL,
			0xF625EE5AD82908BBULL,
			0xB4E2BAA577C29CFCULL,
			0x7AC67C6BF01DE493ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8DA3D5973C1C94A4ULL,
			0x4221E23ACFD43386ULL,
			0xFED67196275B4925ULL,
			0x57C92AAB0A609D8CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCCD3569D5BA68DE8ULL,
			0x29D05ABBC86084C4ULL,
			0x7A717A23581A0AA7ULL,
			0x473FF04FE09A8678ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0614DA8031B5D79BULL,
			0x062B2A9F42251E13ULL,
			0x9BC00367D5C98A7EULL,
			0x0E16E96D8AA3A4BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61E64BBE71F1DAC3ULL,
			0xFF22DE96E975473BULL,
			0xE20DA82AC899F59DULL,
			0x0D020C1C0F2FE501ULL
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
			0xBF79C727F4A6A4C0ULL,
			0xCC07454E6282A31AULL,
			0x8795A4426BBAC9C1ULL,
			0x522F9F4834A644A9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF2E526D97D28FB2ULL,
			0x40554B84ABA2BFBAULL,
			0x33726B7552C78B33ULL,
			0x777A5BA4543A348BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE6A8423BCBA66F90ULL,
			0x6AE481F9E0EE8DC2ULL,
			0x50AA155CA079CB10ULL,
			0x786D96ED6B0FE8AEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB80839F0D8FAE117ULL,
			0x4E3472AAA76D4FDAULL,
			0xBCC73F270908BCC1ULL,
			0x5B02ACBA10F907B6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3ED40CF0312AAFE2ULL,
			0x4E66692E8821D5ACULL,
			0x7C568F67650C2725ULL,
			0x4CB479B44CD29B15ULL
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
			0x01FC83B8FF36A238ULL,
			0xCB0A1FA36B3840E2ULL,
			0xE91B4EEC1C9FDFF7ULL,
			0x6E689F4A753F95B9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCC2F71E406341E16ULL,
			0x5278DA405C561D43ULL,
			0xB2463ACD4D6608C3ULL,
			0x0D928E1F994A5F7BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x483D1E4BC0842738ULL,
			0x6FF886DCDCB89272ULL,
			0xDAC9ADBBC1648D55ULL,
			0x7A0AAEACD5D38A85ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFC826EE335756D4AULL,
			0xB32C259238F2B778ULL,
			0xF4001E204B4A6781ULL,
			0x60F1D5793C0DBEC2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7F4B9FEC422D32D8ULL,
			0xB7C69371A77F48A0ULL,
			0x0B6A8041DB497B6AULL,
			0x60DD8BFCC2CE6739ULL
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
			0xFCA2283587AB7988ULL,
			0x758A10D4699E6F17ULL,
			0xFCD2ED82342A3A7FULL,
			0x5A2060E255E753F7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B1A1C20CA219F6AULL,
			0xF467855EADB5F8E7ULL,
			0x0512A6904594BEC6ULL,
			0x75E0DC2406385AA7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6FAC85EDD9AF3798ULL,
			0x8FF173353284721DULL,
			0x748505B663132202ULL,
			0x66C2F3942FEF17ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA2077EE3CA2ACA55ULL,
			0xB6CBB18B5446E4CAULL,
			0x3025AB7A687C1652ULL,
			0x00202CDEB1EA4A84ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6E3327306CC2D0E8ULL,
			0xDC5DCABDDCA7B1DEULL,
			0xED7E77B1AB98004DULL,
			0x14E24994ECEA6BB8ULL
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
			0x74834C2F0275BF28ULL,
			0xC4AC85E6B480235CULL,
			0x4993CCD54E824352ULL,
			0x610A99A0B1438AC6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7A850C7F0F2BD73BULL,
			0x9AB0D6C75C7A0C39ULL,
			0x546F6C6DDECB2F51ULL,
			0x61C71105C1F288D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x39F8463245C45008ULL,
			0xEF8DA05C4D01777EULL,
			0x02B0B459B6D91D9DULL,
			0x43496690F9256335ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBCDF908D72A4033CULL,
			0xD9DAEC7CD3C06F53ULL,
			0x413CD72427F41E43ULL,
			0x34B4FB05694FA17EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3242F1F578FD372ULL,
			0x852D22863A13BB9DULL,
			0x7DD42E94ADF3314FULL,
			0x237B63CC5A3EDBAAULL
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
			0x5A2BA6ECA9FECC38ULL,
			0x1C2E3A2EDC13E7C7ULL,
			0x4C72C301B57FAD4EULL,
			0x5A1459D01770D33DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x013972EECA569FACULL,
			0x4135CA4E8026110DULL,
			0xD3A83134739BE9EBULL,
			0x41B19D86F6F0CFB2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2032EE8ABA70A2A8ULL,
			0xA33A68CB4EA3685FULL,
			0xCC310235BE892B99ULL,
			0x5D02FE241F6CE92BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5CAA7E14B67629D1ULL,
			0x58EC54B9C70D13F2ULL,
			0x26242652038AADDFULL,
			0x507C363FAAB8C4B6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCDF2828C8EEFA169ULL,
			0x049B25CDF5A91334ULL,
			0xEC5E6D126709FF59ULL,
			0x4FD05F23D8218796ULL
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
			0xD18640F8C61EA5B0ULL,
			0x36EAA8AFD00CEB79ULL,
			0x2E1A05A957479DA2ULL,
			0x45EF938425409C1BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE50DDFE39D40B97AULL,
			0xBFACD127EF2EB933ULL,
			0x94F6B0124F00DD4EULL,
			0x238AD5C8AEEF84C4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDEDE902928D0B198ULL,
			0x123B672185BC56B1ULL,
			0x27F45318BBC7A7F0ULL,
			0x6A73C65E51C0D3CDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA30BF1497CA768CDULL,
			0xCF7EBB8CFC21AC54ULL,
			0x607B657AC03B454BULL,
			0x27BA9BF754F6422DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1C6962C2E00BA447ULL,
			0x9A3494415DDA2538ULL,
			0x9973405ACF133F81ULL,
			0x3C1AA6581347BFC6ULL
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
			0xFE8B6F8A00E012C8ULL,
			0xAF0907AF3A5CA6F6ULL,
			0xB737B151CCBBADCBULL,
			0x5D5D71146A0C78B9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF72BE634424F32E4ULL,
			0xE0EB945777626D96ULL,
			0x66052FCD39989F27ULL,
			0x65D6C99EC440661CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAF36A284FF27CFC0ULL,
			0x63F2782372400259ULL,
			0x58500ABD61AC7246ULL,
			0x57FFDB76ABCB6DB8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCCAFD2214EF5B47CULL,
			0x1F7D872044BD3BB2ULL,
			0x0C2D293FF924C542ULL,
			0x401CFF1CC34C3C59ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x952EDF78E7F7124EULL,
			0xA437DAF59C3C039FULL,
			0x6642560D1CEDF7B1ULL,
			0x187079060B20CB60ULL
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
			0x53C3F31302DF9B38ULL,
			0xD12D078FFA081454ULL,
			0xB9BD1BAACABDBF2EULL,
			0x4107D2CD06DEE136ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7BF6DCEC58C40649ULL,
			0x6C3F6C3CDC353FD1ULL,
			0x5763B018D1677199ULL,
			0x1ECA9B2B555FFEE3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5DEB4107D46B7DC8ULL,
			0x21FA1F4859D5AB56ULL,
			0xABEA203B6C5BB494ULL,
			0x6D7A99CD9D7194EBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4EB2D2AF07B5E41CULL,
			0x36C02616D48A7387ULL,
			0x5E6DAF76C4589A8CULL,
			0x07059BAA96B53C84ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5F16A169F03D223ULL,
			0x98A681480545F790ULL,
			0x2678F89D8B23411BULL,
			0x75A10BCDCCF94871ULL
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
			0x3D25D27E6328C1E0ULL,
			0x6C23B5A576BFAFD0ULL,
			0x33AEC07E10BF2A2FULL,
			0x7D80FB74E47E5EC7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFDD9067BF0A68BDFULL,
			0x8BDE04A0F8190CD1ULL,
			0xC3A4AF2C6509B899ULL,
			0x36E119E6FBAAB6DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7CBD1329CE10B638ULL,
			0xC428C6CFFB351BF4ULL,
			0x48A6B6607D5A2310ULL,
			0x63487E953B22096CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1505418CBCF562F3ULL,
			0xE5D20303C236249CULL,
			0x0903E0FCD983364FULL,
			0x3E07E930BA288B3AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x84D0D3BD4C4616D4ULL,
			0x51BFF89C28E8289DULL,
			0xD2128DA6C6EABAAFULL,
			0x60EB0C13B938851AULL
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
			0x5295A256BBF25A30ULL,
			0xEC45F2F975DEA744ULL,
			0xA08ECEA94E30EA03ULL,
			0x4D13DBF647CAB78CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9CC3D55554F6A005ULL,
			0xD65875D40E7868E6ULL,
			0x55A4F1450EA8F602ULL,
			0x07D466D522965B99ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF459309BC4F40EB0ULL,
			0x6CE8B6DCA612DB96ULL,
			0x69C55D5D7ECA12F6ULL,
			0x46F331411335578FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1223CF8421B3D38FULL,
			0x7CBF77CC78F46FE4ULL,
			0x543D7D3D9231B506ULL,
			0x002A963574BC3D86ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD4B96659C5261A86ULL,
			0x250A52837BADAAB3ULL,
			0xE19DC5A0A77C803BULL,
			0x12270B229CCE3AC9ULL
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
			0x86519FFF9D803A10ULL,
			0x6052B987BDE16351ULL,
			0xA62E86CF7FA9B633ULL,
			0x51EE5DA73C6C9463ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC55894C5A2529CFEULL,
			0x6C4BAD7095517EB7ULL,
			0xC6358922FAE07348ULL,
			0x35A15D4FEA571D15ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE5657CD7EE8F45E0ULL,
			0x9C453494A2041C49ULL,
			0x9A22A6FCC1A534B0ULL,
			0x5D74486572E68221ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89A9E7EA0FE1CB3DULL,
			0x81EF9865E09F279CULL,
			0xC02638550F243D42ULL,
			0x1826E3FBEDA96351ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1028F1FA0977F35EULL,
			0x5666EDA32D0AACF2ULL,
			0xE77F4E58CB5198A9ULL,
			0x74B70F5539F6518AULL
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
			0xC2CDD33A25945FA8ULL,
			0xA1619D35BE5F0AA7ULL,
			0x5998AFF82F41CC42ULL,
			0x47FA38EF60802AA0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF7DEAC98A7130938ULL,
			0x234F391F1185D7F6ULL,
			0x938BF5021DAFB042ULL,
			0x1FB31B5815776B8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8E41B5E0D77116C0ULL,
			0xB20859E3FE7FE4E3ULL,
			0x3709ADCB8B9E15C2ULL,
			0x73400C7CD7B81AE2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0B7A20255CCF3C2AULL,
			0x7029DF786B2BC4ECULL,
			0x6C9BEC4DF400FC28ULL,
			0x0D72907BD83F7722ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9FA92D8764DBE993ULL,
			0xF18F6F96DD23DFADULL,
			0xA7EA935D6C5D9CA7ULL,
			0x4E98EEA2C60BEA74ULL
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
			0x81CAB6EB9EA5D610ULL,
			0x19C51358E1A6D366ULL,
			0x5A3E532947017056ULL,
			0x7C83543BEE286B19ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCA0B90DDD8A67CBFULL,
			0x895DB59C8519DA7CULL,
			0x898981C416DDF22EULL,
			0x21E765F7BF7E9200ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x71821332DF3F78B0ULL,
			0x726E4A135A4E5BD4ULL,
			0xD182D9A54B2E4138ULL,
			0x4FD910F98A2F625FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7C05D34AD1B633B8ULL,
			0x41817F51DA2B93F7ULL,
			0xCD7C5D261A69FA3DULL,
			0x3920D1C16A074390ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42CEBAB9D1294E2BULL,
			0xC9003A59C81164D7ULL,
			0x807B5936F88EB3E0ULL,
			0x6EA841560B44B73DULL
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
			0xB5BE06D4C795D7C0ULL,
			0xF1C8CB97DED55CA5ULL,
			0x6C437DCD92DF9EDDULL,
			0x7953879CA289287FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA97D47396D552D21ULL,
			0x78DE053970F703DDULL,
			0xC33134C1B2C82B35ULL,
			0x0D4EAEED491B061FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x41E94C13B0B41DD0ULL,
			0x9D21CD81603E6EB7ULL,
			0x872F68FB7F8CC174ULL,
			0x7EC803C316A0CAB0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF69F932988AC994CULL,
			0x0F8C0D7DB968C2EBULL,
			0x3BB054201792D89CULL,
			0x739D4B4F5A35E823ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x276795D688E08A61ULL,
			0x26F62A098CA7634CULL,
			0x74F9CBF95A063D64ULL,
			0x6AFFC8F7913A9EB0ULL
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
			0xA82231282F7C1B18ULL,
			0xF6D46E2FAE2AE735ULL,
			0x2AC366C710ED2F2BULL,
			0x40EC7C93B820E866ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD30B0D74471C04B9ULL,
			0x80B89A20D1C346B0ULL,
			0x97B1746977AE7341ULL,
			0x1DF3105F3DBCD652ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD5856E36DE3E12F0ULL,
			0x587327D542A3D1F4ULL,
			0x859FE23C2BBBB0E3ULL,
			0x40A3F8D0D5E6DDEFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x62F98624AA11999BULL,
			0x7E8ACCE0022EF164ULL,
			0x005D253E81F11EF9ULL,
			0x3A018092C211EB7FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x75E3ED0BAA26AD30ULL,
			0xEE2CC126045B6AC1ULL,
			0xCC466AFAE6884E2EULL,
			0x4A6DBAD7D613791CULL
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
			0x6AF006162C9E0588ULL,
			0x3ACA91B13038B6B4ULL,
			0x76437A7517ADE899ULL,
			0x5930FF17797C94E5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x79156141CF744D5BULL,
			0xA85B8CF9610A168BULL,
			0x1934723C8E2C7E39ULL,
			0x232E906C4B9A2391ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA5E626A06861C310ULL,
			0x2781777E1EEB3895ULL,
			0x41AA59CABF7FF524ULL,
			0x44241FF27B45CE03ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x95503377D4234144ULL,
			0x5830C1CAC2A1DDEEULL,
			0x7BD946B6A958270CULL,
			0x5CCE570CBC4F0AA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8158EE405D7B6980ULL,
			0x9D70F6FEF57004ABULL,
			0xC5DE93689FAC67FBULL,
			0x2543BCAE398AD159ULL
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
			0xA52FAFA1B08C5CB0ULL,
			0x9FB43DA150C67D1FULL,
			0x63418354A8E3ADC1ULL,
			0x5B82F590FD4EAEF6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDBC22FFD7939AEAFULL,
			0x3E4996E26A049206ULL,
			0x9FECD58EFED142F0ULL,
			0x513D0ACF6A18C4B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0531F3BFCCC183C0ULL,
			0xA29D213C656B1B47ULL,
			0xD48A309CC5A9B496ULL,
			0x745212C3798086BEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE03E181774B24ADDULL,
			0x706CE531B1549DA1ULL,
			0xE7A7B6A3A416D26CULL,
			0x3083FCAD2E17761EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC1B8E48F0867E7B3ULL,
			0x52EF69DDD7429518ULL,
			0xFE3D88EBB8B012A9ULL,
			0x574BE21102320E22ULL
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
			0xCDE179B116E1F718ULL,
			0x16CCF757B735E863ULL,
			0x52DA0665C980BE9EULL,
			0x7B7B0714E10E518AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCFC40AE302CE6767ULL,
			0xAE2A1FA474606C92ULL,
			0xC8A619045F13F15FULL,
			0x06D5899A58FA4DC5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB0135AB869F8F618ULL,
			0xC9EF4E770D4B24F7ULL,
			0x9273E04293559B9DULL,
			0x7E4BFCE3F604997CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF877EEF8A09EFA43ULL,
			0x813DA36BBE2A07C3ULL,
			0xC212101EB1BB0143ULL,
			0x0DB58C356B660586ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x66D72F665A62303BULL,
			0x449678B08D91BB15ULL,
			0x381F8506732B17B3ULL,
			0x11C859189305A957ULL
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
			0xE53BB17571E6EAC8ULL,
			0x74B9CB82C67AC655ULL,
			0xCE6C95398F07C800ULL,
			0x4A96282E6D4D939CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x30F8C983C8A3E14AULL,
			0x1B31DA67A4DC8EDEULL,
			0x0624983392966A26ULL,
			0x68A4F9C0CB65445CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4AB681606659E2D8ULL,
			0x2AED1FE7EA4382EAULL,
			0x76E7D66449B2281CULL,
			0x5D2344A542595B13ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2BCDD78C19C4749BULL,
			0x1DABFE3C2964112EULL,
			0xC11F1985C6BEB413ULL,
			0x272E47E3EE820798ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF85D50AEE84B436EULL,
			0x1CA078D1D685A598ULL,
			0x801AAD747B822C5DULL,
			0x418C1F38A1C783B3ULL
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
			0x4D07D92D70B40610ULL,
			0xB41A2FB86C371C0FULL,
			0x8A9EE5D11F4DCE37ULL,
			0x421790B085299FB5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD163297F2D8E85E8ULL,
			0xB06142AE3800F1EBULL,
			0x99E229BF0789567EULL,
			0x534CE1C7669C8933ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA824D2956B6DBA20ULL,
			0x131BACC4F1B765A4ULL,
			0xD0193BB86906EE0BULL,
			0x725EB3231B8C9954ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56544AD4F2B4A15DULL,
			0x5B3CF46304D0B906ULL,
			0xD0AA09162FDC40C0ULL,
			0x6DC0055F35FCE277ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8B459E5BD7034D17ULL,
			0x4EAF725C551930B0ULL,
			0xC2B7475FAB275346ULL,
			0x2EA0B2A525223956ULL
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
			0x1729618C1DDC8FC0ULL,
			0x02EBC63D6BDD0B8FULL,
			0xD9328082101C3984ULL,
			0x790F04C9A9F08853ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C1B3543169224BAULL,
			0x062772E02FBE0855ULL,
			0x55BC500E3C1123AEULL,
			0x41C576B8859C0A32ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C9CA8A7C796F000ULL,
			0xF3D9C76FF6B6F94CULL,
			0x7F3D76879DD34E56ULL,
			0x7A9B8F1B8B935F32ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x413644E585198DF5ULL,
			0x6CEEF3A7CB88E7B5ULL,
			0xB6CF3A4353991A9FULL,
			0x328C4027527B668FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3EE384802DF5066CULL,
			0x925A96B7020703D3ULL,
			0x3DBAAF9E61FBDAB8ULL,
			0x64AA6EF6E703E9DFULL
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
			0x4F10074621872550ULL,
			0xAE1789F7B184F2A9ULL,
			0x43FBEDD35949CCC5ULL,
			0x6FDB4C43CC94D073ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE8DE7CF1790F58CULL,
			0x7C3C99BEB5D144F7ULL,
			0x056E5F1B5E0B9AD9ULL,
			0x05643F988B46C9D9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC66F65E00BE89E18ULL,
			0xF0761559DD4F4CD9ULL,
			0x60906289AD7B13DDULL,
			0x6552E5F43145519EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x70AB03914DFE062EULL,
			0x079471F695CD0C90ULL,
			0x209929822A2D0485ULL,
			0x3F901B51A322BABAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC006026FF2452B47ULL,
			0xB099690EE70DBD78ULL,
			0x7BB6D99B9CED8A15ULL,
			0x4AABA24DDAF9D019ULL
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
			0x20EF863A8B9BA038ULL,
			0x1B9A06274EC7EC66ULL,
			0x6D8357E9B0382D3BULL,
			0x5AB9603275E5A7DCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x18D5FE7C52529AF6ULL,
			0x14A0FACA25BDDE83ULL,
			0x904311C867E445BFULL,
			0x51DA6F6ABC88D563ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA9E406F1D3FE90D8ULL,
			0xD41AE3BD33930CDEULL,
			0x207CA7331702111CULL,
			0x62F4DEDF3FAAC199ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF2AFFE20BAD8245FULL,
			0x72277770F57E8DB8ULL,
			0x4423D6BA3BA4BC21ULL,
			0x397D33E4527A16C2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0CFDA72114D271E8ULL,
			0x54799EF20177883DULL,
			0xA356F83FEEA6BE0CULL,
			0x6150E4EF3EBE5C4BULL
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
			0x4851820246E19180ULL,
			0x5DE6860B70A388C9ULL,
			0x888CB894F1E58A42ULL,
			0x4ACA26D22AB76010ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7727378156F96BCDULL,
			0xB7C9BCFFA630E210ULL,
			0x4D0FFDD3E6E0F7E1ULL,
			0x5DFAA639519AD6C3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE532D784FCA19F60ULL,
			0xC47BB152EF88476FULL,
			0xEE7C14AFADE8EE8CULL,
			0x65B020FFFEFA9636ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B20E772B41340B9ULL,
			0x9C1DB087B14E9EA7ULL,
			0x9B6DBA1A5DA4E00DULL,
			0x262D39EFC8E49614ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC911B90109E28DD2ULL,
			0xA52D4C79088AD989ULL,
			0x88F1474F48536042ULL,
			0x1FF2C4F3C0B27869ULL
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
			0x9C404EBA5EB37188ULL,
			0x314F94305E7AF7A6ULL,
			0xFAF3B262E01F98CCULL,
			0x5D892FB30A3EB7E6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAFE116C171E4E9E7ULL,
			0x866176D37551CB44ULL,
			0x92832BDB68D10102ULL,
			0x71743FB683D6C3F1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE9489C9ACE099D90ULL,
			0xC26849A2A58294F0ULL,
			0xB53AAA34096C28B1ULL,
			0x7B7E970B62A6E21EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x279A5D104618251DULL,
			0x51FCA8F4617C8F10ULL,
			0xCC9FB81A0EF16A4BULL,
			0x57F5D157E4A520A9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA13944131F39A4EAULL,
			0x18D529050DE7C72AULL,
			0x9FE8569C4769FF1EULL,
			0x4FC7DF63D99A0D04ULL
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
			0x8749648017DCB6B8ULL,
			0xD502CA2422ABA169ULL,
			0xB3769A1A9B3F4659ULL,
			0x76DF656F48C89025ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x54D3CD20D1F432EFULL,
			0x3FF90F345127E405ULL,
			0xE6A44AC054125675ULL,
			0x170D71FF0FD7F6D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xED67A35BE35910D0ULL,
			0xE63EF38877F63A0AULL,
			0xB9FA5B27C2DD0E7DULL,
			0x68A412117D7574C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2D280B270651BD51ULL,
			0x762201E7C8E706FAULL,
			0x0EFE8D2B36BC04F1ULL,
			0x7415F35299DFB615ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0DA9B8542DF76B3FULL,
			0xD0CE16A50B0064D8ULL,
			0x360D5B842B7B75A6ULL,
			0x15E51E1D2416FF46ULL
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
			0x9F545A85DEBADBE0ULL,
			0x8063243ABE91053EULL,
			0xE04886AE72F0E161ULL,
			0x49CD79F698DA97EBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8AE803C7D85BBA45ULL,
			0x33DDF47B704932DFULL,
			0x1BF5AFB166D44789ULL,
			0x211ABD8AE91C813BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x359266DBDE9D03F0ULL,
			0x8502D060E663329BULL,
			0x0820CC79A3003BDFULL,
			0x42C2C6202622D7D2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB5C2872FA8447E6ULL,
			0x4930BA51D0609588ULL,
			0x395FE2ED14D4DC0BULL,
			0x51C46ACE490D0538ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD15E87E5D1908026ULL,
			0xED3FDA3E4B2DA7C6ULL,
			0xD822D320990E926FULL,
			0x54A25397DE18ACF0ULL
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
			0xF27E98AD01AB8BF0ULL,
			0x2B4E7B2E67DB2DF1ULL,
			0x85FFDB7107F92A96ULL,
			0x7DD1F7B68E7DB092ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x829987454AA1F97CULL,
			0x446FAF5810D571D3ULL,
			0x9AE7034A9DF910E9ULL,
			0x310CA15CADB3030AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC0DF538679BDC6F8ULL,
			0x5238DCED13ED813EULL,
			0x96F68B89D0213C2FULL,
			0x6EADA046FD69814BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA3CCBA27374FEE96ULL,
			0x142FA60B9157980DULL,
			0x249BBBF9A10E806CULL,
			0x3B1C297713906B2AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE4FAC4C8B2F11C86ULL,
			0x3130C124F2169982ULL,
			0xE50DF91FB42FE3E4ULL,
			0x1FCDA03C3FB1AC5AULL
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
			0x49AFCDD743C57200ULL,
			0x508FF7EE1CC017E3ULL,
			0x52BB520691AE3E71ULL,
			0x4C0DAF599260CCD0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB3C1E1D6616ECE93ULL,
			0x9E631C08C1003F23ULL,
			0xA1D08985C1EBBE09ULL,
			0x3B5D6C4C3C780FCDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x801F38AA7ECBDC98ULL,
			0xEE5DAA1116ADB5B9ULL,
			0x1AF4DED2C281873FULL,
			0x4E418348055AD239ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4CC02731EBC3A6F2ULL,
			0x02444C6FC5C922CDULL,
			0x1ACE18E147E16264ULL,
			0x3E2FC6AE672F3D56ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x631E549B411EEDD2ULL,
			0x5B7504DE057E8044ULL,
			0x145A573DA01FA4BFULL,
			0x481314ACD568D588ULL
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
			0xBA4337750558C5B8ULL,
			0x09EC7FD02185C2F1ULL,
			0x900C50B4058AD89FULL,
			0x68688000D124B235ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1FF6EE7CB6FB1B7BULL,
			0x93DC5A4EF6976EB1ULL,
			0xA454C61FDD1DFFC3ULL,
			0x1322D5CBA29029D6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDF626021C70C7E48ULL,
			0x6E3B3099F3C84168ULL,
			0x303CB61A2D8103E7ULL,
			0x45AAF8F5012E96D0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9475C9BBA3B38BBFULL,
			0x16479FC3C0CB70AAULL,
			0xA0136B3697D7D5B4ULL,
			0x50506A8959EF6DC3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7A1F2B5E7C1CC39DULL,
			0xED79EAD8F096DE0AULL,
			0x76BED33C281CBAC2ULL,
			0x498C00A189DC6F35ULL
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
			0x96EE9D73DFBD0360ULL,
			0xEC9EFD275893C230ULL,
			0x21A0D24B95F63218ULL,
			0x6658676338BE44B7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBEC436B9CB85E111ULL,
			0xF2E729FA2BF75A80ULL,
			0xE924EBC0F18BE038ULL,
			0x17E355B708F430F4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9EA9D8C6C7B5E1B8ULL,
			0xFB57BE652EB8E333ULL,
			0x595B7AAC6E5CAD8CULL,
			0x4D1B0EA28D7333DBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x651285E82EE9C0D3ULL,
			0x24ABD65A3F732AB7ULL,
			0x473E0CA82BE3971DULL,
			0x0DA872149E584782ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0D1F463E9017D9DCULL,
			0xB6C464781EE49A37ULL,
			0x59FB152D2404CA0DULL,
			0x3AD7F02510064B0FULL
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
			0x3CA8C5D5CD8918D0ULL,
			0x90FF78915735B44EULL,
			0xC1EF2AAF1BE948E5ULL,
			0x7FE7AA6A0E611DD0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC6ABF9EA270ED2FBULL,
			0xC3EC7F1BB3C2A4D2ULL,
			0x387051F967D6E08AULL,
			0x38F12FCC72EB1019ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x530BB9A3EE42F4F8ULL,
			0x4E7502DCC0F7DF47ULL,
			0x9A173DD95EF32867ULL,
			0x4C778BB3C0E369C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x839EE5BB29CBE354ULL,
			0xED9F8921027F20EDULL,
			0x97074D41127EF518ULL,
			0x23C93CCA0AB77E9BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF8DDBDAC65F063F1ULL,
			0xB9873508E6FCFA25ULL,
			0x8287562F256E9E91ULL,
			0x4446DF7DC06616AAULL
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
			0x17E822A1065249D0ULL,
			0x48C4A18316FB2366ULL,
			0x6A439D6D71321C28ULL,
			0x55268E4C41D424A8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x528DB4FDC3FFB915ULL,
			0xBBAB4CAB180BEB9EULL,
			0x7000697021B30239ULL,
			0x760DCA6FD9586F53ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD236EFBB1FF0D1A0ULL,
			0xA4544B358CD7D562ULL,
			0xCAC599D8DDFFA5D4ULL,
			0x7D1419535EE8AE20ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF8DAB8E6F9909DCAULL,
			0xC4D5B3E5C3F902D1ULL,
			0x2C4DA1013A535C41ULL,
			0x3AEF64942D19F66CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE480946EA6840BF4ULL,
			0x50CCE3872DAD9597ULL,
			0x4A0E1542D0351F39ULL,
			0x78417DE3D9C3047BULL
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
			0x4502D4A91F10C3D8ULL,
			0x63E93658FA588E29ULL,
			0x802789520CD79A2AULL,
			0x79C75344C54FA0C1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2667FEBAC8261C8BULL,
			0x69197D2AAE186C9BULL,
			0xDA6CF078BD5D05AFULL,
			0x70940CCF0A9F0E2CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB0BF539865AC09D8ULL,
			0x4B954B8A73BF2C40ULL,
			0xC191546434C0B743ULL,
			0x6CB8310686171668ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC828DA32A90A86BULL,
			0x2ECA3C16ACA22F5BULL,
			0x4ED5E5C6F92423CCULL,
			0x76C2D6FFF9F533DDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAFC9F4B9E9CE3A87ULL,
			0x6803D000EFBB5627ULL,
			0x6861B4CD46DD09C3ULL,
			0x1C50DA1176783093ULL
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
			0x62394A6DA83DD1A8ULL,
			0xF9897A9A0698E37CULL,
			0xCDDB4EF4425108D3ULL,
			0x52F02C52C69F4660ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5ABBC116092D5939ULL,
			0xFF30CDDCF46007FEULL,
			0x3581221C6CFAF200ULL,
			0x6290542F1FC1FBBCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2211A72904108420ULL,
			0xB1C1A266FBD8373CULL,
			0x9A448D8E8A538941ULL,
			0x63A1E3C2BECE9F02ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0CFEA456D77479BFULL,
			0x385F11CAAE41D99DULL,
			0x28A1153B8D9A9291ULL,
			0x68033573277BDC78ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9A2DF52270B2B704ULL,
			0xC113E2AC34BF2D71ULL,
			0x75AFEA973EA58677ULL,
			0x492EDE36914F7E3FULL
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
			0x5B5C608F86CB8700ULL,
			0xEC7E1B5C4A8BEF7AULL,
			0xEDE22C946DC38179ULL,
			0x43547AA25FD8CD1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3E3EE841BE777CACULL,
			0xD25C231E8C028453ULL,
			0x6A96B39D2CA09258ULL,
			0x2B931DAEE31C9756ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1533E2F224065DE8ULL,
			0x777C083E8D643F42ULL,
			0x6298A6C5C3539779ULL,
			0x5672E0512991CF87ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFF371A613AE7FB26ULL,
			0x10E71D89C7B1C0CCULL,
			0xD2B2F5A0EB47A260ULL,
			0x5E005B7E884157A3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x398EB56FCBAB7C6BULL,
			0x613C21855DFEACFBULL,
			0xFA788FF4A597F781ULL,
			0x60ABFE5031ADD41BULL
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
			0xD8A4817CEAE973B8ULL,
			0x06B8CFEB0A4171BCULL,
			0xBACCC7974FD6DF21ULL,
			0x648131D057420CC7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC1EACD56F1A5BD37ULL,
			0x05B5F7896F42C7B8ULL,
			0x2D93937B75577A6DULL,
			0x0F01D5F02FE8BB95ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0CB95BF282177AC0ULL,
			0x03327A060FBA3F13ULL,
			0x4CD14B27076E3473ULL,
			0x5E5489C80D4C713CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1932C12EE873162CULL,
			0xCA41907C31E5BEC5ULL,
			0xA02DCEB8B75EB93CULL,
			0x78BB2F456DCE4CA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x030C5B9A0B14A68BULL,
			0x2D5EBCEE1FA4E8F6ULL,
			0xA87155955A25ADB5ULL,
			0x6A1A723394712504ULL
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
			0x3B11CBE6322D32A0ULL,
			0x98DB8067FA06A9ACULL,
			0x99D8D4B3ABD3A54BULL,
			0x78A218A29751D975ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD7BE4B9CB3F3109EULL,
			0x536A27E74EA52233ULL,
			0x468B3F8453CE363DULL,
			0x5714F61DC1F84F16ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6B183F22F660EBF8ULL,
			0xA17BB8AEBA63B489ULL,
			0x0827D87CBF8B344CULL,
			0x60CF4BEC8819A7F6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDAC5DDD31D8BE2CCULL,
			0xE1856D02B2365AC6ULL,
			0x8AEAA126D94120BCULL,
			0x6648220CAB79AEF6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC3BA2F9BE0D70315ULL,
			0x6C56A52CA2212897ULL,
			0x41903D154540876BULL,
			0x170956A1EB9A5872ULL
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
			0xB157C38C2E006400ULL,
			0x6A64A87337F6B947ULL,
			0xA07B016C9D2B9527ULL,
			0x6B36B74778C88BBCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x553C382E8747AFEBULL,
			0xC2B187EE4DBACA0DULL,
			0xE47C4DFE3900E07EULL,
			0x7358CA7C90E3F557ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F13C0C31DB5A468ULL,
			0x0F397E80288FCE1CULL,
			0xE9B7181BB392E0FAULL,
			0x4EEC0C2652E02009ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9A4F1BCD43E12C9AULL,
			0xEF6E162F553249E6ULL,
			0x1BF45E5DCE5048BCULL,
			0x3979CCFD3CCBB889ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD7502FA86AA5A0B4ULL,
			0x5DBA298AE061E32EULL,
			0x6BE260CDFF858B41ULL,
			0x67071155C15B9190ULL
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
			0x2931C1A63C986060ULL,
			0x2F7F6D8B752BCB30ULL,
			0x9C52CA1773C2D2B1ULL,
			0x416B13321640A29CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96D83E062DEEE2EAULL,
			0x151E35C0AB7DDA12ULL,
			0xA5360A8AFA9743FCULL,
			0x5BA44E85258C112DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA2A4794BD58B2F60ULL,
			0xA28365EA7D875A19ULL,
			0x6E472959EBF7FFC4ULL,
			0x7D16F7FDAEC0CD05ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x540559068AF61B54ULL,
			0xC20BE55496BC7547ULL,
			0x1F7E9D9DA6DC2962ULL,
			0x26BD5887DD1446CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x35476F397CB4241CULL,
			0xE4FEBC2243443C5FULL,
			0xD8661B7097380F3FULL,
			0x58D0511508EAE505ULL
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
			0xE06DA2D0E8DA8A00ULL,
			0x5E7B23BA68BB4CE6ULL,
			0xDAD9E5D71AA63C65ULL,
			0x487955C7B3434E9AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5F60B79ED372B278ULL,
			0xC4073D5E47875F09ULL,
			0x962B14190EA35CC7ULL,
			0x0F42908B1AA72BD1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x97AB939970C2E0E0ULL,
			0x85040A974D5B7EC2ULL,
			0xEB04B27A565306A6ULL,
			0x459863815DE6AFCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB248C1A5FEBC9853ULL,
			0x969E97EF7F44BA14ULL,
			0xC96C587D396579ABULL,
			0x02B436DCD7C9D979ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x95591E412B3F5366ULL,
			0x48B15D006DF0F62FULL,
			0xE72E48C0F8D92DFFULL,
			0x4FA73FBCE370D08CULL
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
			0x2771B13E69736FA8ULL,
			0x01B438464BF88F35ULL,
			0x99C190B09EDAC75FULL,
			0x5083E2F25F065589ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x393FFB9298CDFE31ULL,
			0x178D950E59F32B30ULL,
			0xBC0E31D97793C6DAULL,
			0x7B7F0D2C807BF119ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5C1896558CDD42F0ULL,
			0xDBCF42879B86934EULL,
			0x5EDD09D990651B6AULL,
			0x459A6FD0EAEA8ECBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x39F5C5DADF6F955CULL,
			0x7AE7C2F027B779B7ULL,
			0xD855CBBE2CCB4555ULL,
			0x001386F925353325ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6F1DD06DFD81C316ULL,
			0x9467D93F673263F4ULL,
			0x20801BC62AF3E07FULL,
			0x287E7F45E0B3E26FULL
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
			0x55B9640825E9BB40ULL,
			0x90FF8778D8FAF6F5ULL,
			0xCEBCD5B7906FCDF6ULL,
			0x65869B0D2E4D1566ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCF844EEEF2969588ULL,
			0xBE75159235AEC598ULL,
			0x106B59B17CED6ADAULL,
			0x53111F8E26FA6A8EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEDB56CBAC4544298ULL,
			0xFEF74C43701BC50AULL,
			0xEFB7AD0813425B47ULL,
			0x55D6C18A5B3EE1A1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xABACF41A20FF5A8BULL,
			0x09A4C52F8ED25097ULL,
			0x431DE207BF120E98ULL,
			0x0C2C32AFC924FD1DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9D006F158D417A7EULL,
			0x272AEE4AC325D582ULL,
			0xFF93EC0B728B2BD6ULL,
			0x2A66A7D703BEA18CULL
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
			0xA18303AEF5002498ULL,
			0xCE5313316AC5CDBBULL,
			0xC8BA5EC79DDF73DCULL,
			0x499C9182BCE10879ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9345BD066902F6DBULL,
			0xE4325E5E8B1C1418ULL,
			0x319A288292013DD5ULL,
			0x7A859A3A960137B8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAB1599CBB64BDEA8ULL,
			0x618B2C7B15E34B69ULL,
			0x14E7E69268F16C50ULL,
			0x75AC97FFAF9EF00BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6867A5DA0D3A1BF6ULL,
			0x627D11AD636C5CACULL,
			0x15AF01220C2A3FBFULL,
			0x228259985C9EFF11ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFFDADC372C282F18ULL,
			0x9BDA3CCE7F74F9A0ULL,
			0x4495C8DBA2C8C5FEULL,
			0x41DF01ABE3023D67ULL
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
			0x2EC17B5F50439008ULL,
			0x52770DA66662C7CDULL,
			0xB143C221C530A753ULL,
			0x69DC2807323BD378ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF12A20E91D570D7EULL,
			0x56AD9412A60BF6A4ULL,
			0x8EEDD24119E9F16EULL,
			0x174059F12E511523ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE69AE818621AF4E8ULL,
			0x5473B4C2C2BCA64DULL,
			0x8DDA303C9568EE04ULL,
			0x64109A678D33A054ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEDDE457CD0084F1CULL,
			0x244B4105FD0049B5ULL,
			0x9BBB763C12B9BC8EULL,
			0x771CDE7053519A73ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA993C703F34C9404ULL,
			0xC147BAC193623914ULL,
			0x8CC7C6CC79D253B0ULL,
			0x022561DF5E23373AULL
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
			0xBEF88600718ED088ULL,
			0xCEC81B7FDE849533ULL,
			0xBC6FB30536A42C18ULL,
			0x7EC2A9AB1319C389ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x95DB9746AB697BB9ULL,
			0x9D3C81ABFDA507E0ULL,
			0x653F89D831D236E8ULL,
			0x6860294C33C04BDBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7D631E34FBCE10C0ULL,
			0x039FD3D823745DA8ULL,
			0xC45DF801BF0984B7ULL,
			0x40996770DC10D941ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x90A37B86642B12F6ULL,
			0x6CC7A4E9B95EF8F0ULL,
			0xCDEFDB0C20B5048AULL,
			0x2287C6272169FC5BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA7734F21247D6B2BULL,
			0xA4FE19B981132EBBULL,
			0x2C017B333D45E093ULL,
			0x724FD2177089AEB6ULL
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
			0xE890433EFFB15AC8ULL,
			0xEB9121692B4FAFD6ULL,
			0xF493BEB57A1FF27EULL,
			0x46B8A0E096518329ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x04613350FF1CA42DULL,
			0x7309496FCE7C8DA1ULL,
			0x9833FACD9F0D2F51ULL,
			0x681A490BD7FCA349ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2BDB5D338D3B32C8ULL,
			0xB8989A728F890BB5ULL,
			0x96BD92AA8869EC0CULL,
			0x60C64B47A0BACACEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB5D116363E296C3DULL,
			0xD6A2D052E9FE05A8ULL,
			0x28925A905F2088AFULL,
			0x64A9FCE3782BFD04ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x499AE95CABC7D4EFULL,
			0xC29FFCB29922475AULL,
			0xB3243F8E3BF8F626ULL,
			0x031E05A422363EC6ULL
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
			0x1BD58ED9E23010B8ULL,
			0xA75AAF86AB19178FULL,
			0xB8CBD961E2D54B1FULL,
			0x605C4A9D2D1C4AEFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5D1FDF34525027A4ULL,
			0xA186ED09167B167EULL,
			0x1252009D8AFCDD35ULL,
			0x76D652B4661CFDBAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6E56A19246A5EA38ULL,
			0x8ACA3DA37BCA6965ULL,
			0xE200B7B42AC3C22AULL,
			0x7E999FB1D2707710ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9CA5A991A60AFBDCULL,
			0x1E0F2BE0109647A1ULL,
			0x8A2729B9922B88A9ULL,
			0x7D7604446CE75747ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7468EFB6CD7297E4ULL,
			0xE3F7134DA4DFE789ULL,
			0x386991CBA23F7387ULL,
			0x6503BFE1AFAB0D25ULL
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
			0xDA99A5DBFB9F9D58ULL,
			0x5FE104165F074454ULL,
			0x880F5B2FC621E5E7ULL,
			0x71CEAE381ECE8B92ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x628EEA46FBEB7ADBULL,
			0xB951AB6FD916A6B8ULL,
			0x6E4FA148514A5FADULL,
			0x06162F653A73BA1FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8D6A291491DC9E70ULL,
			0x44FEC3BE7F48FD06ULL,
			0x0D1AF3AD8E75B3EFULL,
			0x6B84E2CECB82EC81ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9542E2FD1F432526ULL,
			0x3DE9DA6F1E21FD02ULL,
			0x7DC35D9E34AB1A38ULL,
			0x4C33CA0DA9B180D1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2386E9349D3E4300ULL,
			0x541098ACDEABA676ULL,
			0xE1F10DACE81C8662ULL,
			0x72AD91DF5A94E7A3ULL
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
			0xD8ABDD8673818540ULL,
			0xF38ECFB7C7D32B9EULL,
			0x6D93F700947780AEULL,
			0x4E46267943B9B40AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA281B24DB797C08ULL,
			0x9E7107E43184CB31ULL,
			0xF4A7D8442FF078CAULL,
			0x36C0B9A00798C578ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA67D0C5AAF31FF60ULL,
			0xDAF8F47C94C8728EULL,
			0x8F1E81D9D4878FA5ULL,
			0x5BE98AF2FED049C9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB3D400097B878859ULL,
			0xA087355E59126708ULL,
			0xFD3643D27E051185ULL,
			0x498A46B1914157F3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7419684A1088885EULL,
			0x25DEAC01C97F1FC7ULL,
			0x8B65DD38670C775DULL,
			0x3BDAF470D555FCADULL
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
			0x77A5D3DB4379CA70ULL,
			0x8B05EC8CB7F34BC7ULL,
			0xDAA6A98C0A3F8C95ULL,
			0x61B4E5FF884451D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x62F114CFB7C3EA55ULL,
			0xB2D723AFC3D860D3ULL,
			0x006C64858F768C66ULL,
			0x5060EFBE1980DAFEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC5CA98DB5D5FFC00ULL,
			0x16D6F86E751A820FULL,
			0x70FAA30C669A6477ULL,
			0x5CEE52853FA35474ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EBB6119B8CAE03EULL,
			0x083081C69BE7E66DULL,
			0x4EAC909F0C0210A4ULL,
			0x35C6465E7641F273ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x69EA96B359C50246ULL,
			0xB503173A4FCF409FULL,
			0x7C1D58050BAAC49DULL,
			0x08E9081C5FB1DDA8ULL
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
			0x007C6637F52FFF18ULL,
			0x815F1E7D62AE4422ULL,
			0x4B6EA97F89707964ULL,
			0x450D9088145C620BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15BF07EF9E5733D9ULL,
			0xEA2DB50F66E7B1ABULL,
			0xB5B8B1E66A9B2E24ULL,
			0x5FB9003A3D980C36ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A2A7401344879B0ULL,
			0xFA0B9DD8D1353983ULL,
			0x8846F82358DDC138ULL,
			0x7DBF2B5BF9C65EC6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD0D97363065A520FULL,
			0xC9C7E665A0728918ULL,
			0xD8F632E4226C8CF6ULL,
			0x084F81E0829B97D8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0240445B6B158E15ULL,
			0x882DF02265E3F268ULL,
			0xC9B7F4C8C9333AA5ULL,
			0x3ABF19C2E408F1B2ULL
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
			0x49656621178953C0ULL,
			0x7085B611D4AD910FULL,
			0x7B9F3F73AA5CB629ULL,
			0x7715DB950EC8C8F5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4E99CBCBFD1D39CAULL,
			0xACD72FC4E619A98FULL,
			0xE82DE97281851203ULL,
			0x32C87F23EF71AAB6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBAEC7920F4125748ULL,
			0x5ABB0A6F5B2BAB2DULL,
			0xEB760827A08DCEF5ULL,
			0x6D1DDE3BB5D4BF0AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9D22FA3BC67AFE4CULL,
			0xDFB0158EC75A4BCEULL,
			0xDA7C817D0BCD301AULL,
			0x01DAD23ACAA47CC8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x409E1A1372F44A31ULL,
			0xA4237631C8CD33C8ULL,
			0xA1466F90F3A1B2C6ULL,
			0x75A1E8199AA9E9A2ULL
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
			0xFDB5B50AA2BB9A00ULL,
			0x4CE0ADF681EA72AAULL,
			0x364AA15F8300B598ULL,
			0x7A108FFA24BCB466ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF3F524C4F6B9EA4AULL,
			0xAE4DC6C4EA711180ULL,
			0x15E3A9FEDA6770F4ULL,
			0x36AF854091D9E3CFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8CA4318B0ED736D8ULL,
			0x0CE5E579F465139CULL,
			0xF724FC33E6182840ULL,
			0x684BE1FC685C8721ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9D23F46DF8D575C9ULL,
			0x774ED5EADF73FFE7ULL,
			0xE1EB8A1568A48ABDULL,
			0x78C5EE9AAED24FFBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA61E2EB83C394745ULL,
			0x28C67568C4625A94ULL,
			0xB2A7166C26B532ABULL,
			0x225B5086A30D33B8ULL
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
			0xAE8ABCCAE5D2F820ULL,
			0x6BE5D5BA2B1E0877ULL,
			0xADC4C12D5362B1E8ULL,
			0x48EC84F26A8536E8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x75B267759D4E8B4DULL,
			0x8CA1F66701FB0564ULL,
			0xCAF90B182A46A275ULL,
			0x7919B8B56EA7EFA6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3C7A4E4AA784A928ULL,
			0x36A300C293D6F9E3ULL,
			0xA9BD9B1256D4EF16ULL,
			0x7BEFD54BEEEFC699ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC0631E221A094AF7ULL,
			0x0CD5023D1F3E9A8DULL,
			0x32439A9AAB6A55A4ULL,
			0x472CFB1E9B90A717ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3A10CFE4D2047AC2ULL,
			0x23DAAC9B39EADB33ULL,
			0x1DC385213584793EULL,
			0x090AF5AEDA895542ULL
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
			0x1E56C2355FDCB1F0ULL,
			0xEE110487BFD6947DULL,
			0xAC4962028B55E3BCULL,
			0x4469E0031CC112A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9F585294353C20EEULL,
			0x3D1979E1D29CCA3DULL,
			0x43AA3A7FC9BEAD7AULL,
			0x4619C9D5279602FBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7C26F90FD90D6538ULL,
			0x2F8B00910A34E11BULL,
			0x7B19D2863B373588ULL,
			0x7D92244E6C09355DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD633DC47CB18A864ULL,
			0x70AC50A3AC24A210ULL,
			0xF3679EC2205D4E2DULL,
			0x131C2717076F116DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9D1E7323FA3F79DDULL,
			0x9B78F087CCBB91BBULL,
			0xDC611B5E8F98361AULL,
			0x0BD213F43CB1EF63ULL
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
			0xE9A6D006201FA348ULL,
			0x1976CF9819F528B9ULL,
			0xB1585D70CCAF8AADULL,
			0x5F6F648C772787A2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE5ACF3EBBE184D4ULL,
			0xD83AC1945CF411F1ULL,
			0x8BFF961750ECEDF6ULL,
			0x69079448D3A91039ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7AD60F9BE3879DE8ULL,
			0xFADCC29D08EA0F50ULL,
			0xDF14A1F7BF49AFEAULL,
			0x4ABBEE6AAF76C5DBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x53944926B0DBFCAAULL,
			0xFFD4A649CA1E9E64ULL,
			0x9644D63BDE21F40DULL,
			0x26DEF8A7EB1C4D5AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3CF7E1024172E974ULL,
			0xE02729BEB1A331E9ULL,
			0xABBCD10FE88356C5ULL,
			0x4AAB19C40E3F13A9ULL
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
			0x334405D31BDC78C8ULL,
			0x2C8E6216161CE667ULL,
			0x93282667CFE563E6ULL,
			0x4EC9EABD4A6DFAF2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB807428E5482E37FULL,
			0x5332E0D6B5706E30ULL,
			0x7D11053AC0D792B0ULL,
			0x262473D1E898C541ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F2EC03753686090ULL,
			0xEF831CAC5C708E1EULL,
			0x43F4BA6E2FF9085EULL,
			0x6D3289756EABCF05ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAE406D31F533B8F8ULL,
			0x32EA2135345C8943ULL,
			0xC7EBD92AD4F9565FULL,
			0x02EBD4655DFC1566ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA558355D4C25B880ULL,
			0x07E0D0280134A62DULL,
			0x65F2EEAE4177CBD2ULL,
			0x17805A42F5CF7FD7ULL
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
			0xB84536FCD340FE00ULL,
			0xD979FAFC02CB43B0ULL,
			0xCA26FB2A50735AC8ULL,
			0x769B46C7085E233FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x31C2F8BFF44E6737ULL,
			0xDD5961581B8EB7A8ULL,
			0x53684DAF3A412829ULL,
			0x10431BA9175FF0B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1FC5F1EA6856AD28ULL,
			0x006986D3112407F1ULL,
			0x81A261D8B8E115D9ULL,
			0x5988A524D3546298ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0AEF889D23A8FDF4ULL,
			0x154996EEF19CA164ULL,
			0xD0933E8C69D28FF1ULL,
			0x1CA8D8276A1714A4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5082A82A45E829E9ULL,
			0x4FE01AEBF0AE6F1FULL,
			0x44D7FF097A2125F2ULL,
			0x7B957C675EF7BC94ULL
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
			0xFE46BD7C1417B5E8ULL,
			0x3F7D4879C92386E1ULL,
			0x110DDE06FB2728D9ULL,
			0x4070DC1401BD8D67ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF7B60313E4FFAF8ULL,
			0x9E5587B9E66288E4ULL,
			0x45CC775B376FDFABULL,
			0x6CB0C341C59E774BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE3DA85892FAE7378ULL,
			0x1AFDD49EBD3020DBULL,
			0x435A8EC84F70235DULL,
			0x79DA9BD08B577474ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBC0AEBD3BD638937ULL,
			0x92CE8EDF251DACE2ULL,
			0x5F4C3D0712790718ULL,
			0x6C4E82579A870B5CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCACA9B725ECC3CF0ULL,
			0x30DCF491144FE591ULL,
			0xFB01775BE836224FULL,
			0x41DAC5DF2CCAD3A6ULL
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
			0x0FD0B2D50B3A3450ULL,
			0x00428DBF9676AF72ULL,
			0xBA70AFB259512DD1ULL,
			0x4E6E7C5B165E2DC9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x38E6DB7218B1BE49ULL,
			0xEFBEC97A3B9558B4ULL,
			0xFFCD8C5A6F9D72F3ULL,
			0x79E19E4F9C228E09ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFF8B91535B6003B0ULL,
			0x1664889B0E08F76EULL,
			0xE850ED64693FACD5ULL,
			0x6AA6C5980F243C84ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFC9DCF0C49B5AA21ULL,
			0xD3171354CBD27D09ULL,
			0x5A8AED024F0334A5ULL,
			0x29EC43F40E9D5EE7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD84FD96030E82ABFULL,
			0xFEE4E377E63A9876ULL,
			0x88F0CAC4D10BA03BULL,
			0x073F00E909F659D6ULL
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
			0xB30E64082EE78EB0ULL,
			0xA2AEB80AB7AB5EBCULL,
			0x19E8EF219739DEAFULL,
			0x52DA1DCD95B4F03AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA1FE0726E3A8EE52ULL,
			0x36A6A45252B133BBULL,
			0x7799F3047852F594ULL,
			0x545DB0565FA0C239ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7519D0739F9C33B8ULL,
			0xEA062B37CF8536F6ULL,
			0xFFF11392074BA543ULL,
			0x58CF12742457A0FCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1BBA1F153C8DD74ULL,
			0x8AE7C1E562835F24ULL,
			0x01C392E55ECD6FC7ULL,
			0x20C55589BBA690FEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D5E66670B8E0595ULL,
			0x381EAA84974B090CULL,
			0x908D064C15A691FCULL,
			0x64731B10CC42C615ULL
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
			0xB6A1BC14ACD2BCC0ULL,
			0x1D115320D1194521ULL,
			0x3D7C319DB0072AAEULL,
			0x47DEF0B51A93D233ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x026E05ACCC96B524ULL,
			0x8AC0CDC578E29669ULL,
			0x8CDCD73020039969ULL,
			0x4001557D9A68567BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5BAE7085BA1C10C8ULL,
			0xBD658A26B2CD9A97ULL,
			0x94382657C05261C2ULL,
			0x4132DF259BD76134ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE45039DC0CC1C74BULL,
			0x5282692A2305E80BULL,
			0x4846084A152D8623ULL,
			0x0B7D048072462C6AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x24FC95BF8442E9B8ULL,
			0x9AA36336F0E2CC08ULL,
			0x09719BD9D0936B82ULL,
			0x45C6D26184314D2EULL
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
			0x55946251C7CF4800ULL,
			0xD1466D579346DD46ULL,
			0x9EEBCA6D159AC86CULL,
			0x7A0C49FB16FBA38BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE2231EFAFBAED77CULL,
			0xBBF6ABE3F8ACBA32ULL,
			0x958A968A0D351410ULL,
			0x0F66C5E4DDE1D03DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x28E69415DE27B888ULL,
			0x1462290F036C65AFULL,
			0xD1DBC61893041E39ULL,
			0x559E538FF1471A30ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56BFE0C54BA1DF6AULL,
			0x142548BF2182B90DULL,
			0x0F21120DA75B9AC8ULL,
			0x08270F0007768014ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD9CCB942B0838A2AULL,
			0x68D1EC9600FF52D7ULL,
			0x23D05F135AD5D04AULL,
			0x54AF4AEE1D23C428ULL
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
			0x26D02EA11E7186E0ULL,
			0x399C944B3E4C6060ULL,
			0x47EA130AD3406508ULL,
			0x6490123C1153873CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF3760C71B75CC937ULL,
			0x159A2ABA9D982961ULL,
			0x32BF6BCB0CE466B1ULL,
			0x1F6B6CA924AF2DCEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x68C5F2873EF75C18ULL,
			0xC7D4A00C00488943ULL,
			0x0B10980EBABBC9EBULL,
			0x65EBF6C4F715054BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B20D75B686F3F8FULL,
			0x344F97BBF1056CD5ULL,
			0x95AEE5AECBD23F3AULL,
			0x41997CC78C80D81BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB89B423A63525FC1ULL,
			0x4C9C93A4F76BD861ULL,
			0x5972AEDA0E9DC58EULL,
			0x7F1A7FBA63BB3E1CULL
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
			0xFE9DD5F61B46D348ULL,
			0x3C48E6EA74883744ULL,
			0xF3D9B89882D0E18BULL,
			0x6532EC5C1B8ACC4AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x49E5884589A43D7DULL,
			0x01DD8602EBB68554ULL,
			0xCE3B6D4EEB8E3FD8ULL,
			0x39963164FF4B911DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA8287D1E83CF3600ULL,
			0xBE02E2237F3C8E94ULL,
			0xE04D9B39B7140836ULL,
			0x6C964DE647EEEDE9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC25A943F39862FDEULL,
			0xB37392788461E7AEULL,
			0x8DCDB4598FB10EA1ULL,
			0x305731A19D10471CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D66C57FB1848F11ULL,
			0x06F435685E8102EAULL,
			0x09E6A6D31B22788AULL,
			0x67449ACF05AED1FDULL
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
			0x92F2FFC8D00265E0ULL,
			0xA07FB38AA63A8D4DULL,
			0xA3A2240A46699965ULL,
			0x6A429AECCFB09074ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x13F82B82EFA0E710ULL,
			0x5BEC16CE530EE64FULL,
			0xB457F33DC4164831ULL,
			0x59E515034382A03BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x16A088041ED30EF0ULL,
			0x1F59C04A4763BB79ULL,
			0x403683EBE93037CDULL,
			0x6A859585CE7966A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x642B007552739EFEULL,
			0x72F462BB91CF8717ULL,
			0x99495F2C7AFF1A4EULL,
			0x69D6AA9CB10AD79CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x84D4341CD44017B5ULL,
			0xB8F27A9FCF4F3007ULL,
			0xF9EF0944C35A14C8ULL,
			0x30314AFBE4A426F9ULL
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
			0x094F59CC2E2EBBA8ULL,
			0xD73D5BA4E7C36C2AULL,
			0x48E024CCEBD7EE8FULL,
			0x5D8D2B6E391FB76DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB5F3D7DBAFB4FC73ULL,
			0x577D43DB1B30049EULL,
			0xDAF81C1B92D81FA8ULL,
			0x465D3C922EF33F5AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE08E59E3DB79CA48ULL,
			0x92D28FD32C6F2326ULL,
			0x9D2119BA76228F94ULL,
			0x4732BE75C8D9301AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBBED91711CA312C6ULL,
			0x10BAE2A0197CD0B3ULL,
			0x97B5D0A44127595AULL,
			0x2528774AD8EB7241ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x476114110758C986ULL,
			0x0D809AEF964C88F1ULL,
			0x7FA861B419962788ULL,
			0x58398F7338AD1A22ULL
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
			0x3E9053DA07A615A0ULL,
			0x751738E6D3C7A90AULL,
			0x0FA95F64EFF99B0DULL,
			0x69480CAD49BF94A1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6E1C5915411D5823ULL,
			0xD353E2BBFBE8226DULL,
			0xEA2A2948EA0D3CFDULL,
			0x0E1A41B1FADB0376ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x979886ABC3567878ULL,
			0x9AB8F6A9962E4309ULL,
			0x858DB3F8EA53038AULL,
			0x6162787E823EC9A3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF79F3B9B1FBD8336ULL,
			0xB734EF590355A56DULL,
			0x99576F3CE60FF326ULL,
			0x037BDC78BEE1AF5CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x087AD65F50EBDA46ULL,
			0x82BE530286B0D2C5ULL,
			0x20DD61323A407775ULL,
			0x3DAB23DB3E07DC34ULL
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
			0x161B17AE19CF0E20ULL,
			0xA8B6FED85E10AF34ULL,
			0x222FB24F5FEC978AULL,
			0x4F7DCA146A020FB9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF3D08443958A078ULL,
			0x6F68C847136C45AFULL,
			0x042729B67F4A464DULL,
			0x1F59858A05E48870ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF91D8F93ABB11000ULL,
			0xF05710A1785E0356ULL,
			0xF0FB8362B8F2978EULL,
			0x6684FABF90BDD0AEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB9D26D550EB3DB22ULL,
			0x73A0AD96994B5841ULL,
			0xFE83A1200B3050D9ULL,
			0x6B31E6A8FB41C6BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4D235073D8A0DE2ULL,
			0x934432867E4A36DFULL,
			0x91BDAC4FB991773BULL,
			0x02C7D3E20CB3DD44ULL
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
			0xBEDB91E8518575D0ULL,
			0x133BF802DC997E92ULL,
			0x44C7A0D17D719810ULL,
			0x6BBB49D517D68F70ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x98B47F43F3987441ULL,
			0xE83887A3FC8C2624ULL,
			0xF1D2A4B9A326B17FULL,
			0x1B31A15B23FA8088ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x76AA2CFC3D67D088ULL,
			0x6C107526874DAA64ULL,
			0x972DD81920CD14FAULL,
			0x71FBA96427A3C55CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA37BBAEEC3676DBBULL,
			0x2638C37F61175145ULL,
			0x1625BDE3B7090F76ULL,
			0x191BA4D05B87D246ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB2E8EEFACABFCC54ULL,
			0x6AAB7231D9B433B9ULL,
			0x937FD63BF194BC80ULL,
			0x2B9A86E3995AA18EULL
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
			0x61BF5105E5BCC830ULL,
			0x6DC47C7B0185C9FCULL,
			0xC84C0B94D17F76AAULL,
			0x77BFC69728AE5FDCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6585DD3A9E80F4B6ULL,
			0x2ED8FA84B831F722ULL,
			0x6782A30E0C48B6C6ULL,
			0x1D6E69D28313C147ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x89E304FAB65BDA68ULL,
			0x41C870E1E9642F0FULL,
			0x63C56CF7F3E1A3B9ULL,
			0x49CAA2D7F84407D6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7D1C9AD753FA67A6ULL,
			0x8D03E82B215E22D9ULL,
			0xA86A19F6BCCAA586ULL,
			0x728013C18096D7B1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE51ECFA8F21CBFAFULL,
			0xD0C7476EF7A87C55ULL,
			0x5AADEAB50B5177B5ULL,
			0x305240E1C9DE4E08ULL
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
			0xA05D7C6E0AED9298ULL,
			0x1A4BB0402B23C269ULL,
			0x87B0CEA71BA8BE6AULL,
			0x4D4E9C17DD8AED53ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x67155557C9E4241DULL,
			0xE4548D9E1F8D59FDULL,
			0x6210424929179E14ULL,
			0x25105E3A47F244E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAB609A678011CEF0ULL,
			0xDBDF3578AA1A8490ULL,
			0x2686C8AFA7156DDEULL,
			0x46FD9F8EAAA87C3EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x138A6E961E6B7214ULL,
			0xB7A8B4A5CAC90B98ULL,
			0xBB198339DD27AB0CULL,
			0x4B3A414EEA6C7819ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0310D1B962B7E2A2ULL,
			0x13BA99C6860DA0B6ULL,
			0xB1CC845DE9AC4FCEULL,
			0x7187974DC9B077C4ULL
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
			0xABCBEC1B3AC6FEB0ULL,
			0xD4F3ED7FD4FFFD4CULL,
			0x8F9D7D6D5FD69E10ULL,
			0x61C8C17AA0E98F22ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x16FC4286CB498CAEULL,
			0x3896BA93107E2C81ULL,
			0xEFA07B56AFA50579ULL,
			0x502005103BBFA7F7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2CBC270B049190B8ULL,
			0x8908DA7F8FFF0D7CULL,
			0x15448B976B1042BDULL,
			0x7C0E25D321C8AA0FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x510998B27944D363ULL,
			0xEBE39D48D6ABC598ULL,
			0xD27CC0B7655755F0ULL,
			0x69EDC54635C6306CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61C166A5B522E0BFULL,
			0xA50CA62CD4C6F2E1ULL,
			0xF8B96E28C694CBDFULL,
			0x795047B1AF294B9EULL
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
			0x4C9CCF6A927F40E0ULL,
			0x11FE0AEC5C3D9248ULL,
			0x9D072D939098E7F1ULL,
			0x7924F372D33874D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF626193688B564DCULL,
			0xE107F9DE764347CFULL,
			0x8C0B5DAFA20D732FULL,
			0x1A5BA55D96E84BA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3B25D913A7BBE3D0ULL,
			0xAFDF7144206FC022ULL,
			0xB09862FBCDB5FA2DULL,
			0x7F584CCEDE535C79ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x387FEA50A5BF7F18ULL,
			0x4AA37AE924DA3F98ULL,
			0xF94B89A906AC5D26ULL,
			0x4470BBBA657543BAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x49A09CFF269A5DC9ULL,
			0xADBBFBAEB65E8D05ULL,
			0x5D83527BF8BEF358ULL,
			0x5FAFFC71CC8A157BULL
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
			0xD98A2CF05BA83A38ULL,
			0xE914396A76D1A4E7ULL,
			0xD742FA84C65B44CFULL,
			0x72379F8589D00AADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9A45DF7E19CC5ACAULL,
			0x90396024482CE7A1ULL,
			0xF70C1A48ABD5B768ULL,
			0x69BE557ED22E60B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7C591C36D5934550ULL,
			0x769B7B2C11A900F4ULL,
			0x0F6A063AE8A8AA9FULL,
			0x6BC8DC3EEA849430ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x44606D3572A52C47ULL,
			0x32F68382266A9E53ULL,
			0x539FF8E7502548BFULL,
			0x2A3C4723FD01B66DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF268A0AE7DD73472ULL,
			0xFC29689A335A670FULL,
			0x1C607A04FC924E93ULL,
			0x00A4827E0237DC19ULL
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
			0xC3726EAA9409A378ULL,
			0xDDFC2A96841EE228ULL,
			0x83A3A79FD4C319E7ULL,
			0x4757748B8A2F8063ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72EC13A4BDB42F53ULL,
			0x9C5B6CDD54AB3AD0ULL,
			0x4AF82F0BAC975BD9ULL,
			0x5D49C46C300D36DDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA883C2B6425E90E8ULL,
			0x532ACED59BF733C7ULL,
			0xB642F005011AB652ULL,
			0x40FED22209608E41ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF65D6A8B163D38A1ULL,
			0x65E313967E17E786ULL,
			0x04EF38A658B24CEBULL,
			0x63CDC15B376B4BC7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC4F1D9408E59D9ABULL,
			0x8EDB37849FC1B08CULL,
			0x54AB99588D0D7F7EULL,
			0x6F463E4574F921E0ULL
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
			0x4AF823A2FB059E30ULL,
			0x347C41D7B4509388ULL,
			0xCE73E14CB66F9296ULL,
			0x4CAF9A29150F7A00ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x52BAEDC0D0C55893ULL,
			0x884470F99A06FE50ULL,
			0xD93FCCE082C549CEULL,
			0x403ADF17DDB1383DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6ACEA6101A816730ULL,
			0x6F862227335C61C1ULL,
			0xDAA7908C59F004EBULL,
			0x408499B390334295ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x349985C2508AF4A1ULL,
			0xA4FD8644BA68C979ULL,
			0xA43E0FE4E59F1873ULL,
			0x75790B651A6CC0EAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x736490C3F9A1F480ULL,
			0x46E418B86508E39EULL,
			0x2E01E3906445629AULL,
			0x35A6DC4D726887ADULL
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
			0xD22EE557AF0944D8ULL,
			0x10A5077E79230BC3ULL,
			0x72D2B488BB8CCAFEULL,
			0x42D908A4343E83DEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x502B23557B51601FULL,
			0xD65A891E8FD5A8D7ULL,
			0xBF8C196AFE0A4EC1ULL,
			0x42BE5E333BADCB8EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1304791501478798ULL,
			0xABA0F79073942491ULL,
			0x35A22F6A19564787ULL,
			0x522A971612D9C513ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC61167AF750FD12BULL,
			0x1D6721F12DB9E2D5ULL,
			0x3E29CA1F7EE25DCDULL,
			0x5E4D83E5218C7BBDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x31727607448C98E7ULL,
			0xE5CF07377896CE88ULL,
			0xF675A43180B5F917ULL,
			0x7E1F27B5E7371631ULL
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
			0x347F7BBC766C5AF0ULL,
			0xC5AEC8972AC88357ULL,
			0x92667A137DD164D5ULL,
			0x6B6EA04F5BDFDDEAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAF9AAFC8E7506656ULL,
			0x0A703458C15D8993ULL,
			0xCADE32D366B80D77ULL,
			0x52DCC5288C8A2F06ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7E17D3AEC66F8740ULL,
			0x24BD0F8D55CFA008ULL,
			0x5B08D602B273E65CULL,
			0x7148EEDA5AB7FBBDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDBBB412FE934EF05ULL,
			0xEF6771D79C54BBB8ULL,
			0x2ADF71906C1E1847ULL,
			0x61AE97D64B164503ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCBE80CBF4E3AED39ULL,
			0x1AD7F6E125874379ULL,
			0x7517953F709D99CCULL,
			0x51C8F1464FCC8725ULL
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
			0x4E58F1A1C838A098ULL,
			0x7068F085A1166A53ULL,
			0x9521B0AF5C0A2716ULL,
			0x732E75D676659CACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x879AB5ECA8B73905ULL,
			0x4E062B7FD4A9D20CULL,
			0x4F2AA08812B6C2BFULL,
			0x784170905119DFF1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFEBA8F211F45EA10ULL,
			0x5E2828FF78A7CC26ULL,
			0xA2A2E471A68D32B8ULL,
			0x5C371A58927BF9D9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB012DC3F2671E4E8ULL,
			0x313BB9ADAFE23924ULL,
			0x263629285DE36EA7ULL,
			0x337061FF56D6993BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7D4B7AFF6A66B799ULL,
			0xB4BFD447C10CAB55ULL,
			0xFADD358DA7836075ULL,
			0x6BF5D164563E970DULL
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
			0xC34BC000DCB345F8ULL,
			0x178A1870550B2A05ULL,
			0x38CAC9D2362D2118ULL,
			0x739480D881570E08ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC8DC3B18B527AF3DULL,
			0x3862534CC2526012ULL,
			0x896D4C971684AC66ULL,
			0x020B44BAD800C4DDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF36F228574FDD08ULL,
			0xA727BF50541BCD74ULL,
			0x370907C88AD49147ULL,
			0x709DD7D5D0732D8DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4945139E1BF13A80ULL,
			0xA680B563F0606049ULL,
			0x452F6CD797E61395ULL,
			0x243A974EA35BF2BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x993B35834F783CE5ULL,
			0xD3D18731121C8143ULL,
			0xA23D8652936B2F6DULL,
			0x7C08195BDBA5E811ULL
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
			0x615C6437B913F4D0ULL,
			0xA12E4BDF1025F7EBULL,
			0x39A77072E0E09F3BULL,
			0x597122718ED816A7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDF310535F42B85A1ULL,
			0x86BB60FE82B5EE0FULL,
			0xEDFDF1FB703AC7AAULL,
			0x7EE487D12176DFE3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBA57FE5A304AC898ULL,
			0x0CA03CFEE88E47D9ULL,
			0x6E6269ECDDA4F878ULL,
			0x51C6FB235E79BFD3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD8346A5880AC0513ULL,
			0x4456AAB9065640F1ULL,
			0xA5F96D44E66715BBULL,
			0x148E9C4AD4AD2FD4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAF448AA3D9691C30ULL,
			0x27CF3DAD60BD32C6ULL,
			0x587D28F3E00B973AULL,
			0x1C3389147F0645B6ULL
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
			0x423776823903E820ULL,
			0xC4B582FB85107476ULL,
			0x6EC2317BB18B207BULL,
			0x40C50A3F59C30AF4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3EA755EE6B4CB376ULL,
			0xE60E427E27FF103BULL,
			0x628F588C49319212ULL,
			0x79A8BD63AF79D2BBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEE9388254E387958ULL,
			0x4D7A199E42917C00ULL,
			0x996BBE97B8A71391ULL,
			0x4DF6F53852B8D422ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1EE5E306EB7CDC94ULL,
			0x76653F7F17B28829ULL,
			0x11D166B101988B8CULL,
			0x0DFDD4A875F9C128ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x970BC47BEDC1EE47ULL,
			0x7B2A5B41811D3808ULL,
			0x025BEDA6BD4A5480ULL,
			0x36F001BB3A88D877ULL
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
			0xDA34628C7B474D98ULL,
			0xF7FB00D0C3CBF6CAULL,
			0xD0E33AA2730B6913ULL,
			0x5E18ABD2B5A6AE68ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC6347417DB916655ULL,
			0x6E0BD071988F7F64ULL,
			0x9982C7869FBB3521ULL,
			0x65A15262B6D10207ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA969F725FB6083C0ULL,
			0x05DC765BE40E1B2EULL,
			0xF86EF3CEF4F3AD61ULL,
			0x610CDF1850018C09ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD2B94108AFAC5B1DULL,
			0x3A14F1709F0D3D71ULL,
			0x02049E373540338CULL,
			0x5031AF1F9D061358ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x346B7B7F8A144A43ULL,
			0x8B7F413BB8F86990ULL,
			0x4A8E0C7F9F02869CULL,
			0x44C98E75D6534CD1ULL
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
			0x0DB57C1B61A448F8ULL,
			0xA5B2E746CC8F9FF6ULL,
			0x3937CC87A972E6BEULL,
			0x630A92366BF974D3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x98B237E08FA0E751ULL,
			0x336D15FE84649514ULL,
			0x00B3015771493AF7ULL,
			0x065E4160B5A2F59BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A3DFE935F8F0188ULL,
			0xF31829B2E9DE8E25ULL,
			0x872EA8A495136C4DULL,
			0x75287FDBCEE9EA5BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x068707BBC853E72AULL,
			0x646CE0F42D7F6423ULL,
			0xF8C0276A6AE98549ULL,
			0x39309FE1C3C358A2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x69D641A83E1AED70ULL,
			0xDBEDD2FF7BE142DAULL,
			0x1558971AE90A6513ULL,
			0x4CFDC538155F2FF2ULL
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
			0xCDD2E457790CA750ULL,
			0xC3E7718BF85C2CD3ULL,
			0xE3126DF89ADCFDA7ULL,
			0x6E73DFDD5405B216ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC92A212648B99BD9ULL,
			0xD99177F037CDDFC0ULL,
			0xEDD14D4E2590C38EULL,
			0x094EB71BDDE7A5FBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x600D6970D0FF72F8ULL,
			0x7D29E43FC122318DULL,
			0xF203D250C5D85E1AULL,
			0x6456F09230792713ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x038911B9794DE6F7ULL,
			0x4D086EB719E91A30ULL,
			0xE2E988CE8DB1369AULL,
			0x709AF0DE105B8ADCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6C3C05658CDD692ULL,
			0x81BF556B2071DD42ULL,
			0x725C4E9F8236A5E0ULL,
			0x68C0CBFF08A3CBB4ULL
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
			0x6096A23BDC6097A0ULL,
			0x3E28F935C0746E5BULL,
			0xB5B55E076AC8FC84ULL,
			0x4B1BF7213CECBE9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBBE721350FF57B15ULL,
			0xCDFBCC74AB5796A7ULL,
			0x0486486E37CC343CULL,
			0x41189FCADFB115BDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF40D0A297E36FD0ULL,
			0x225898FCA8B87F6FULL,
			0x379C7414ADE967EBULL,
			0x5D0D0E62ADA19682ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF592C6DC0B38F0C9ULL,
			0xF588A692A8770F00ULL,
			0x73DDF623D86E82C6ULL,
			0x410932DF78D2DBBBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7A45B2B0CAD9B009ULL,
			0xFC11BAF0655BEFB4ULL,
			0xD7ED0A45528E3793ULL,
			0x66E76D88ADE40420ULL
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
			0x1EE3307051920670ULL,
			0x4B1F3DECB6743BE7ULL,
			0x5367AFA51771E3EAULL,
			0x465810D4DE654BFEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96F881B00AC4C3F7ULL,
			0x12C0215404B82099ULL,
			0x8B8F9869812685FFULL,
			0x5E62BA82884A0C5DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAC792DDDD38728D8ULL,
			0xD36B02A0CA109E5EULL,
			0xD80AF845F447BE44ULL,
			0x44DDC9E99601B137ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x78B743B9FFE7C7B0ULL,
			0x991369B70EBB6234ULL,
			0xC4B7A32E359F33C5ULL,
			0x1AAD557C99DFF8E4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x576EFEA034DAC540ULL,
			0xE2CC608BF0732745ULL,
			0xB797D8729DAC5EC9ULL,
			0x204728DA055B333AULL
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
			0x4866E62925A37960ULL,
			0x21C63266E3F9BD80ULL,
			0xC5D2C0C594621958ULL,
			0x72C43C4B1F800686ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4D4FE77B404D9AE0ULL,
			0x2E53693979542565ULL,
			0xF78C401A945E82A2ULL,
			0x22A34CAC37274E79ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDBEF21C6192DD588ULL,
			0xFBF7F129C8828B05ULL,
			0xEAD7F6E53DC21F49ULL,
			0x4FC257EE840110D5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEFA04FFF38348825ULL,
			0x3DFA8848972F2666ULL,
			0x8DCF303E6C43841FULL,
			0x417E32F6204709B3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB50C774A9921056FULL,
			0x79F4FFDFEF577140ULL,
			0x58FBBF988D4FFEC5ULL,
			0x27FF74A0A70B6A11ULL
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
			0xE4F66CE179D3F5C8ULL,
			0xF6A7DA4AF4AD4C72ULL,
			0x58BA76C6F2C1835DULL,
			0x6E49D11E893ABF82ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x76415721B0EAC3F6ULL,
			0x51765DEAFE802E2BULL,
			0x72BB408BD04C7A3EULL,
			0x1423C32F357EB80DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDBC6637EA4D34488ULL,
			0x0A5908A8DBBEE69CULL,
			0x0076FDF56A56939AULL,
			0x6249D89FAC78761BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x81D5387042481423ULL,
			0x37B31B76053C4926ULL,
			0x83CDBA419ED4B36CULL,
			0x443DE7748E63C185ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x21C782F1AA571E5FULL,
			0xD779113BA7A37B87ULL,
			0x81418E7144B2D91DULL,
			0x52FE4B90F4957628ULL
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
			0x6A174D8EEE739578ULL,
			0x95EB33194E0DEDCFULL,
			0x66C06606701D0D98ULL,
			0x5CAD9CC17ECABC52ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EBB4FD674919137ULL,
			0xF439099B68EAAC88ULL,
			0x2ADDA9534482A3EEULL,
			0x57D62926E8A08B55ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB1C601481FE66F68ULL,
			0xB51D5F71C6C7D3DAULL,
			0xB7C3341959898F3CULL,
			0x536CE6DB0D359D35ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC520691F913B3DB9ULL,
			0xA149A9E43D8ECA4BULL,
			0xB140A2C4AA8528F8ULL,
			0x6AA520F0956A4A14ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB132533EA430F2F9ULL,
			0x1C127B91D608811CULL,
			0x9F07BA1C4412F877ULL,
			0x0344042352931432ULL
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
			0x4E6A686B6A0E4050ULL,
			0x87AD505C9A3814B2ULL,
			0xCA4709FECB80A41AULL,
			0x72F0CF5C24C01758ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x91CF8CFD2F805400ULL,
			0xB9B90218C458C227ULL,
			0x31BF68BA12E4F613ULL,
			0x681FF9789AF0F212ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4627095A9F677B78ULL,
			0xF4AD16C93B0430BAULL,
			0x77D5269A7A45AA71ULL,
			0x7F9D9ED671D19832ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF98F61DBBCCAF60CULL,
			0x5EB540DC745DEF00ULL,
			0xC9A740A5907C22FAULL,
			0x101EDC300F1A4FB2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB2DB8A838B7A3387ULL,
			0xFAB99D2EDF1BB8F2ULL,
			0xC302931A7FEF5373ULL,
			0x6CEDBC1E8C328659ULL
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
			0xAE751229894F13E0ULL,
			0x59EE9AC5F12DEDFFULL,
			0x5A983927A1A23EE5ULL,
			0x76122703D74F4242ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1F8B673CF5D3DD58ULL,
			0x3D9ACC730363D4DDULL,
			0x6F9604B976DDD094ULL,
			0x0326E6CE3856A725ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x72C3FCA61E51F9F8ULL,
			0x7557DE1A206AA9F2ULL,
			0x884A2178346BB186ULL,
			0x42ECB8B8F7536FE7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x61CC892D08BC5E96ULL,
			0xEACE55DA9755DBD7ULL,
			0xEE5FE7D1F0CD2616ULL,
			0x2C62B704725F54C9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x176BC788A93300A8ULL,
			0x7600E62C7E3C967BULL,
			0xECEE83FCE18DFAB3ULL,
			0x4128107F39354E27ULL
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
			0xD459308BA3A3E2F8ULL,
			0x63B2128A6912078DULL,
			0xB58D74357D621DE7ULL,
			0x76171D2479706E0FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF9B46A85A5907799ULL,
			0x35208AFA308194AFULL,
			0xEC7848378E682EBDULL,
			0x6C05E3472EB19916ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE2AD789C36C3EAD0ULL,
			0xE44D38338B3D92ABULL,
			0x0AF4725D229B9B40ULL,
			0x6FF7608A7EBCB086ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA8211E59AE4FADACULL,
			0xC12FD90ABE9D14ABULL,
			0x3A62A6D113FA64B2ULL,
			0x593063F6B67D5FB9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0FFF4566130A5E56ULL,
			0x51A8BB80EB1A77A8ULL,
			0x2E27EBC17BD6AFCFULL,
			0x14D44E92A12881BAULL
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
			0x6425B765C19AB048ULL,
			0xC637FE1B6C1723F2ULL,
			0x6762D36A8F217740ULL,
			0x51807EFDDFF8E607ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4327A74394ACD426ULL,
			0xAF2070AEC87B3B8EULL,
			0xBF02FB8AFEDE3997ULL,
			0x64E337686E84B049ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBDE85F120BFF5140ULL,
			0x2158D9DC4180EAC8ULL,
			0x0B5BAC27A7D8AF8AULL,
			0x4E2CB36583F17907ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBF734BE2C357642AULL,
			0x462C263A04EDB2D4ULL,
			0x2A986E5C9971EF2AULL,
			0x67BEFE293B1D2A82ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x47CE8E2D1EBB52E0ULL,
			0xBB64C35F2480D8FDULL,
			0xFC76BBE1EB733D8DULL,
			0x1F792EDCCDD5BBF4ULL
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
			0xC0E2F5109AE168B0ULL,
			0xDEA460F39C5D953FULL,
			0x0AA6E8767DE96B0CULL,
			0x481DBEE354BE3EB5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x28C1BBD36B10DD74ULL,
			0x4F4FE0CC17312377ULL,
			0xEA7FE0FD8F9EDE4FULL,
			0x0B85094357D56965ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD78A0CF2EA229F20ULL,
			0xC78E1CBA0F39F545ULL,
			0x9C02B96D55EB943CULL,
			0x51944E572D1A9C85ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC9C8EB5DC59F4A9FULL,
			0x287616EAF2E66A44ULL,
			0x47286CC17101A3DCULL,
			0x2337A0886F77C05AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x35E0E369C94CCB25ULL,
			0xB81542ACC6564CB5ULL,
			0x559542F0B9329835ULL,
			0x0CBF7865A052E385ULL
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
			0x835BBCD3BB6BC998ULL,
			0x7002BD46D6AFF161ULL,
			0xC728E925BF61B08FULL,
			0x7F553593CC7A4538ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7D69029A13ADA203ULL,
			0x4A3D29FF9DC6D9FDULL,
			0x1BC0FF1027FC7DC3ULL,
			0x4D85258F0923221FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDFFA93EF694CEF50ULL,
			0x336AA3B8F566013AULL,
			0xA5325F8EF471170CULL,
			0x6624E405EBDF2014ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA47F0EC0C0DC241ULL,
			0xBD9227CEA83B0B91ULL,
			0xA720387AED4527DFULL,
			0x3B7903DF64737408ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x07C5494D522726C3ULL,
			0x9084CA29A83A9283ULL,
			0x5FC78CFBE8376FC5ULL,
			0x179D35BD8DBF8BDEULL
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
			0x2BA11870D65E2020ULL,
			0x8358FC94A72905DCULL,
			0xDEA0A25D4E999BC5ULL,
			0x50B48D3E5BF15DD6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9BFBF8D2E4264ADEULL,
			0xCB902B2C3A109806ULL,
			0xF8812346B0EF4C8FULL,
			0x7D9831961E3F957EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66CE0DF06F6EE370ULL,
			0xAC6F5B4D14465815ULL,
			0xCE8A67D6DE2BA07AULL,
			0x54047EDAD1E07807ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBFBDD1644F722B79ULL,
			0x9932B791BF6113E5ULL,
			0x2D9042F544C8EC8BULL,
			0x645BD5820540F132ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9162DD6A9698A7C9ULL,
			0x012A7118783E2878ULL,
			0x234CAB6FD5AA71F4ULL,
			0x4E919CDAC636541BULL
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
			0x90F1E08247B6ECE8ULL,
			0xA627A59D47EEF9B7ULL,
			0x566FB8E1D97B9576ULL,
			0x435C6ACAC2B87C2DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x55289CC34635DF1EULL,
			0xC631F9A6EBC92F2CULL,
			0x1070316F6D317BD8ULL,
			0x7CC2AC76B1E22BA5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5563ED4A23E3C460ULL,
			0xCF5B0F3E1C528BE1ULL,
			0x495FC8E34EB60540ULL,
			0x4C560CD31AE50815ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x08DE6621DE812E42ULL,
			0xEB290A524FA8496EULL,
			0x77F1B31818BAFA13ULL,
			0x0C5A78B735E66AA9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0CDC8E1C4DBAB3FFULL,
			0x0A988C29F8C62F90ULL,
			0xBE9CB9AF60F09EE0ULL,
			0x64030CF5CCFFABF0ULL
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
			0x63E92D302BCC6270ULL,
			0x85BA1D8EB3FF3E7EULL,
			0x7574C5BB1BD704F2ULL,
			0x5F57D36A6ACBF6F4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x611DEFA59835462DULL,
			0xB3E676D9643B1E8AULL,
			0x0B3A364857E0A47FULL,
			0x57A8E651EA567619ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2A0D9F96EEB9E548ULL,
			0xA5416CD0561A71D5ULL,
			0x34838051CDB6CDA9ULL,
			0x7D64464E82977833ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFEF3335034390544ULL,
			0x6D351A6653A3CD95ULL,
			0x96E7F9A948DB7A3CULL,
			0x2A147B1D7447949EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x88DD143527907A89ULL,
			0xE5534835143C0D32ULL,
			0x536C3499EDA77024ULL,
			0x24260689EF1D568DULL
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
			0x54232A3F64D98770ULL,
			0x52823E8EF2C75604ULL,
			0x89E093B544CD5185ULL,
			0x485B1E4D84A022FFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC6D4E9A517D898BBULL,
			0xDCDDF9AB4047C517ULL,
			0xADEAC105508B23A0ULL,
			0x0756DEFDFC9BC59DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0434B7F08CBB7AF0ULL,
			0x8B27358FE1D442EDULL,
			0xA67C5A3756D75662ULL,
			0x7AF1A3165E639006ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x76DD0E212DA7355DULL,
			0xA06B4D8E56271A24ULL,
			0x668786B5B64A97C6ULL,
			0x501497F0065F9316ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x44D7169FE41739EBULL,
			0x3DE0DBDDAFB1AA3FULL,
			0x35D1601FED841490ULL,
			0x192B79FC315DC705ULL
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
			0x58D592D4624B17F8ULL,
			0x973AC492177D61FDULL,
			0xE3B4D0CD60498CF1ULL,
			0x625FAC684E054B16ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC16505D82A1C10B6ULL,
			0xF35ED1505ABA410FULL,
			0xB250B7DA2FB70C57ULL,
			0x3117F298A25BC772ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC251F600D6BFC8C0ULL,
			0x49332F09A921ED88ULL,
			0xA1232FE279F22D41ULL,
			0x788DD5004793F9A3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8954D23D33148EBAULL,
			0x0ED196DDADD45133ULL,
			0xF5347825CD918967ULL,
			0x5B00E080B25C8AF4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1AF3E72400257365ULL,
			0x33B1E1A58736B1DAULL,
			0x78C3F41890BD3F5CULL,
			0x7B9AB2C6209EA765ULL
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
			0xBB51D15A717FA4D0ULL,
			0xF12F10AA61A751E8ULL,
			0xAE6FE218612FD103ULL,
			0x7AB0F23EE9179C97ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B2D43F27B04F1F6ULL,
			0x9F36FE50ABCCCC68ULL,
			0xBE92BFDE3CBA2B3EULL,
			0x3623B73161898312ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD805D2C6D368C9F8ULL,
			0x8C46A77A01BDE160ULL,
			0xA8732EFE003D6AD7ULL,
			0x40A53E5DC152A096ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x756C4DEA1B67214DULL,
			0x5656BDCCE52B5C8CULL,
			0x5600110CC1A9DBB7ULL,
			0x73BA84AD6AE7EA79ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x30C57AA0B799CED5ULL,
			0xB3ED682EBF13496DULL,
			0xF619AEB8CB9ED692ULL,
			0x20122C0BE94B42D5ULL
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
			0x8191C84B01BF0D50ULL,
			0x5DDEF195197FBFF4ULL,
			0xF9E20275FEEC6499ULL,
			0x7ED217A0B48AE449ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B3D436DB739301AULL,
			0x23C650A4C3BB9565ULL,
			0x1549C0E3D2D019B0ULL,
			0x42F4D0A4B771C59EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA2475C793EBB01C8ULL,
			0x8A35010F6C052AD5ULL,
			0x36BFA7556D170296ULL,
			0x5428193D3BE22F67ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAD1476649A72D499ULL,
			0x6D2545C3089A44F0ULL,
			0x009516BCE8D46FB2ULL,
			0x5849DD6ED070209FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1B7F85A822D8263FULL,
			0x65279DD8496735EEULL,
			0x73B08ED2B1CE0601ULL,
			0x7908E826ED402CD8ULL
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
			0x2DAD14CFA6B8E4F8ULL,
			0xC708469D94F94DB9ULL,
			0x6C5E05DEE03C51F5ULL,
			0x78703F288BF0ACE8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2C7BE4706590AE0CULL,
			0x94E355C1B04864BAULL,
			0xC72B13FD4CD95482ULL,
			0x7F9312839AFA581CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x56F96B4E9B837680ULL,
			0x64CBE26F620425A5ULL,
			0xBA39FEB35693DDA7ULL,
			0x453FE903FAEB1F57ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB594AFF12CD4918ULL,
			0xFEB9B1B1AAC40AC8ULL,
			0xE80B0B150208CAB8ULL,
			0x790D56C1BDD7FE92ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAD0EF938387F93D8ULL,
			0x781941E0B5C91014ULL,
			0x5F959543CED1028BULL,
			0x5EBA09C873901B0FULL
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
			0x833860DBC49BC0C0ULL,
			0x6F8662C3EDB8769BULL,
			0x93C257906C274682ULL,
			0x47ED8881AC70F5EDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE58F4CD3C4CCF8FULL,
			0xFE49961F074920B5ULL,
			0x19E4E5AAD497E155ULL,
			0x663D3A9760DF0AAEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x97F75782E3379608ULL,
			0x21DB18DCF6FD3765ULL,
			0x34FE6E1BDBC18DDAULL,
			0x771E8303B325C1FEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2E33609D1818FDC3ULL,
			0x94AF3B6B4B2D227AULL,
			0xFB3372E8546B9FA2ULL,
			0x235F3CBAF78FE111ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03F10B216049CA1DULL,
			0xEBC6DDF3A7FF7C50ULL,
			0x8AED5FE549EC5A2AULL,
			0x2B7105AEA6AECFD8ULL
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
			0xF3FC2A840C55DE88ULL,
			0xC66819DCBEF6549DULL,
			0xB1B4DA7729C2BC03ULL,
			0x57BB0F77DEB878E6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2ECCFC481E4F18D2ULL,
			0x988F7F20223141A3ULL,
			0xC2631714C38FDD36ULL,
			0x676CC5DC9785F7E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAD2F9A52C8F2E810ULL,
			0xD3B7138B91B09261ULL,
			0x665150A32241250BULL,
			0x600A04B6F5A812FFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4F1910AFB788B449ULL,
			0x94BCD1F1F6512B26ULL,
			0x412BBBD27FCB59DDULL,
			0x1AD9582A6E031162ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB5814AE682D8B9CULL,
			0x5799076639E97FD7ULL,
			0x15AEABC2C2C90A93ULL,
			0x778A064C1BA554ADULL
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
			0x034D22B884C7A348ULL,
			0x5361A2B09D2AE873ULL,
			0x0118AE1A51DDFD88ULL,
			0x464E62D2DB568896ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2E3BD09081FC5275ULL,
			0x0EFF7C9696FBE044ULL,
			0xD8E281EA58748C47ULL,
			0x1DF3BA8940814CC6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8752FA2EC08111D0ULL,
			0x7BF31C88F81C60B5ULL,
			0x0E7349F82C77C184ULL,
			0x59A38D9CE1721D73ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3C2C454403634439ULL,
			0x0F42E368BF1B4EF8ULL,
			0x89F6A3877572865CULL,
			0x259F916595F306C6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA86187CF73FC603BULL,
			0x676C02C29E359E05ULL,
			0x16C87897444B8E94ULL,
			0x605579694A3756E7ULL
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
			0xF7D75B060776BB90ULL,
			0x7894D9E4A2E9ACABULL,
			0xE77F452AA3DE266BULL,
			0x57C22E5A74B9D2ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x90AEDBF086DA768EULL,
			0x4A0B79889433209DULL,
			0x7D0D61B20209B4E6ULL,
			0x6F0A791F428C2C46ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBE117666BAF2A920ULL,
			0x92BBE934C64591D4ULL,
			0x53DE25059430DF0DULL,
			0x59FC782598D6BCFBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8D85B4F010D188FBULL,
			0xC825DD0B5ED558F2ULL,
			0x6D18E3953D2BF0D5ULL,
			0x7FAF10ED04C1EB26ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1246CCF172791042ULL,
			0x5165868D9AB408BAULL,
			0xB0AEDD8694376F8DULL,
			0x0EC537FB094B2B60ULL
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
			0xDEB31A9078C199B8ULL,
			0x137C23A7EA091C20ULL,
			0x25FFCC6C4CAF8B00ULL,
			0x6D8E2C636A5A3939ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x543D3B9913DE4564ULL,
			0xAA1837882D474264ULL,
			0x6EE1C49B82C53A59ULL,
			0x19F4EDDBFA3B6F3FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE7DE980F06AF58B0ULL,
			0x127FCB9ACE127EA0ULL,
			0xD5788EF6D7AE6231ULL,
			0x47EC616E1B7DBFDDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE59C0F889465C8B2ULL,
			0x526EE2616EF76A06ULL,
			0xF5B788BC7AE760B7ULL,
			0x7A61EA568B4ECF30ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC726CE48690EDB92ULL,
			0xA6DD7C5C1760641AULL,
			0x3A009059D9F9819BULL,
			0x3D6CC7C5F50C987FULL
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
			0x85868FFB40281818ULL,
			0x6FA580EB9E6D8240ULL,
			0x29C48FE3F0E9A75AULL,
			0x44E0901EC2069F65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x99BCFD06E16D72DDULL,
			0x55A32AF8B66B3378ULL,
			0x60CB49A0C5E30419ULL,
			0x62441E35AFF5FB0FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6A07EB65634240E8ULL,
			0xD21D92050ECC2CBBULL,
			0x9888C14238408B06ULL,
			0x62BA5AFEF0BDBD5CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF0D635F02024FA85ULL,
			0xE68826D07A901FEEULL,
			0xF8636492FA6B38C5ULL,
			0x4F5A54F236D2B3BEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42510CDAA499A9CFULL,
			0x068FD2AF43DD6780ULL,
			0x745E0BF02DA1CA4BULL,
			0x174232570A8E023BULL
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
			0xB1D13B27D3D06C48ULL,
			0x17360DCD3928FA6EULL,
			0xB4EE43E82905971CULL,
			0x471AC0A1FD8ED7A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD024F280E0D68D41ULL,
			0x8857CF7AC6D87ECDULL,
			0x119F65672E113987ULL,
			0x51C75C01B8433950ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD6E4E9127A624130ULL,
			0x84E0C9E8881FEA4AULL,
			0xD39F059DDAA88143ULL,
			0x55D01C7944DE4809ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4E463527EE225B43ULL,
			0x689D7AD24433E04FULL,
			0xF33AF2832060386AULL,
			0x016834BEB531B3C9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAA05F4528EAE7AC1ULL,
			0x2257A34DEE0A8A82ULL,
			0xE3235D893B576252ULL,
			0x2502E3F78A320DF9ULL
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
			0x2E1021D1B1E72768ULL,
			0xA7AFE0C518157E57ULL,
			0xC1E0083304847476ULL,
			0x628797DC45DB8F3FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB243D15E9CE6449BULL,
			0xBF927864D8AE3A1DULL,
			0xE2CA5423140AAEB9ULL,
			0x42FE3228B3125D93ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAFB67A7B9D2EC010ULL,
			0xC39C9D95C44DDA97ULL,
			0x85C04133FB8F2196ULL,
			0x4893E329E97CBE72ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x155086D9ED97FCA1ULL,
			0xED766C1C25A8C32CULL,
			0xB321400121D5E919ULL,
			0x2F9F950BFA863AFDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B85528BD1B4FBAFULL,
			0xAD80D546C069D38DULL,
			0x98004F9D37FFD03FULL,
			0x149455AF29CDD5F7ULL
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
			0x2A6C7917B264DFE0ULL,
			0xEF659DB66412BBDCULL,
			0xF1312EE123FF0F9FULL,
			0x51047655FA098BE6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2769B4D3EE7810D2ULL,
			0xE1ED2D46E38DD6F5ULL,
			0xF748A9D54D594876ULL,
			0x2BDE888C2253D0A9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC9F5ACBD85C7E548ULL,
			0x0AE099441165866AULL,
			0x87C1C3E28108CFA7ULL,
			0x7650C8E603AC070DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE3DF7D636D53A7B3ULL,
			0x83794968581CEB73ULL,
			0xBD9B0B1D3138DD2CULL,
			0x672A00B90C3E69C9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1AD7F6E09657FB67ULL,
			0xC39E4A15530C0AF8ULL,
			0x131DB7C4385F14BDULL,
			0x7C27511891243BD5ULL
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
			0x0EE686311EE5B870ULL,
			0x8D573EB9FCB8308DULL,
			0x5DDF41FFC79065E1ULL,
			0x7B56321FC3633090ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA26A3A11B17339D9ULL,
			0xDD4A4937AFC83BB7ULL,
			0x5C2C25D5EBBE5F70ULL,
			0x12BE1B652ABF8D3CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x810830C192664498ULL,
			0x069B06713329785EULL,
			0xC9C5FFEC2A8A97D5ULL,
			0x7E58817BC5FD7A77ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B9213F0AE47F63FULL,
			0x03567109A122E845ULL,
			0x48D093385D3B8CC1ULL,
			0x627B9782C53DA227ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF3B52E6DDB8C39AAULL,
			0xA00DBF9435D7A2DDULL,
			0xB9FE5F935727B436ULL,
			0x470DE49DC720DECDULL
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
			0xF2C314294292EBC8ULL,
			0xFA585A7001726EDBULL,
			0x6D30B00F63604151ULL,
			0x7DBBBB0EA1188852ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x20CFD04FDC897D37ULL,
			0x1679468B2AC990D8ULL,
			0x39306724BA4BA36EULL,
			0x045AFC7C3978A67FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBBFC05635C11A9B0ULL,
			0xC4B51585E36FE147ULL,
			0xAE8C5B6F1E2CEE04ULL,
			0x5638E5FE5B270BC5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDE8FF0A7A1EDE219ULL,
			0xFB11D46606B2DB0DULL,
			0xD890A9F924818F6EULL,
			0x263CA46DCD040BDAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC5DE971AE37FB340ULL,
			0xC222D86B2251F3D9ULL,
			0x1C2F2E496DB15166ULL,
			0x32CE3B682BA9C6CAULL
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
			0x48E2307AD82EF900ULL,
			0x4A03280A251DE346ULL,
			0x9DA9E88A5A9FB037ULL,
			0x4D1469E9250DA52BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x96A8239F7F7C2AE7ULL,
			0xCF39D9F854989069ULL,
			0xC41C1894F2396150ULL,
			0x50EDF76D6AB33B7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x284578B007C28398ULL,
			0x6427B043EFC12097ULL,
			0xC65FAC434E14E6C3ULL,
			0x5342047FCC594EFAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2F4F47BE4578FAF0ULL,
			0xCAE9E8E54678C215ULL,
			0xF8E9A8A184DCF1ECULL,
			0x4438A78D3A104740ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x91E8810D85297378ULL,
			0xF1DF5D26A0247E0BULL,
			0x3F0DF57875017911ULL,
			0x03BA1796C67B709DULL
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
			0xB935A33D172B67F0ULL,
			0x4665E931C3F52F77ULL,
			0x6BA0F6C4A5D71BD6ULL,
			0x5B0E930E7A695D7BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC1D0B1E8F69BF5E3ULL,
			0x0324B4A649D245CDULL,
			0xF783E80BA6C865ABULL,
			0x6EB32F6963BDF266ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEE9954B05503E798ULL,
			0x80972E6E03637654ULL,
			0x017F564AFF5CCE16ULL,
			0x65C88821899950A0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD35B9E0F513AC5AEULL,
			0x96B5F3B3C34B9FEFULL,
			0x2C3C7D17BD9AC217ULL,
			0x775CFD9EF23B70E1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB965CDBA6FD8ADF2ULL,
			0xB33F105C6584A846ULL,
			0xCA8602F90C7C6DCCULL,
			0x5DBD83CE883AE787ULL
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
			0x3CB40A391FFEF1D8ULL,
			0xC638E1D6344372A8ULL,
			0xDAFEF3E25B7C9A48ULL,
			0x614322824F182557ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B04FD4FC0490487ULL,
			0x4F4480F25118B0C1ULL,
			0x786F022C11115B9EULL,
			0x02B2ECF03232CEEBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5FDD846DCEC274F8ULL,
			0x6F9BA2CBB27B7F50ULL,
			0xFC4D481D77A1C47DULL,
			0x78777A34A44F21A4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x24723982DF65AE84ULL,
			0x6CD23D154077D280ULL,
			0x5ED12E7178ADE146ULL,
			0x35290DD2A7AEFE3EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD99D295C3D8A68C3ULL,
			0x681CC946E5E83E03ULL,
			0xD66DDBC30E3BB9E1ULL,
			0x128B80BE9F3B4AB4ULL
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
			0x35BDC2E18D583F80ULL,
			0x7D7CA9797904BC44ULL,
			0xC01B0AD4E7D56210ULL,
			0x5E578BB1F37B2EA2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5D0437E2FB843B21ULL,
			0xF90048B3FA82B32BULL,
			0x12181CC0B5FB390DULL,
			0x0D0EF6D688936C26ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA51CD2461BC84C20ULL,
			0x05098AFD80F2764AULL,
			0x7F62DD8AB4AE0F98ULL,
			0x7C4089793FDB9625ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x36242DB7E4EF6233ULL,
			0xD7F0F9048CF68CBDULL,
			0xBEB233684962CF68ULL,
			0x21BD9534E1DAA014ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCD51498180B2EDBAULL,
			0x37F7ABFA00F1DB30ULL,
			0x3A854E0D9FFE2107ULL,
			0x27CCF76964964C6EULL
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
			0x64E0A03786426480ULL,
			0xC055DECD74BB3269ULL,
			0x878E240BB6E1A00EULL,
			0x5CE02606F7C9A6E2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2DCE0394347FC089ULL,
			0xA02C7F862A2508E6ULL,
			0x8CF54CEA6C4CD61BULL,
			0x3700C7BD92D1148DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCF113EF1CCD1E9C0ULL,
			0x500ECDE5E09468D7ULL,
			0x562893A8A21468EFULL,
			0x52F6361DF3A220A7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x45843137A973C980ULL,
			0xE90C558E03F4D180ULL,
			0xB4E4F41349F01004ULL,
			0x7A21A8765F396147ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0385400E71085367ULL,
			0x65435B540AB450EEULL,
			0x8A36603FD98AEB70ULL,
			0x6EC1949DE439AAABULL
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
			0x417459D1A51C27F8ULL,
			0xDC9417178D9A76F0ULL,
			0x8CEF960934C62AFFULL,
			0x73A7D4FFA84800FDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC108585FFFC34A37ULL,
			0x47D8F2E7175FF5E8ULL,
			0x59B6D5F4F09EDE90ULL,
			0x01A25FA8C2A2FF36ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x35352C5C08D135E8ULL,
			0xE36CEBF291DE971FULL,
			0x6CD6D18883642605ULL,
			0x4593C79198A9663CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x13E245ACFC10AF6FULL,
			0x402B97A5E2FA00BAULL,
			0x392645B9E4B5CE89ULL,
			0x0DB32AF92E5F1C75ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61313275A2476C8DULL,
			0xBAB0CC02C9FB2422ULL,
			0x1365E0C7636F977EULL,
			0x7F0331FBD5E01715ULL
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
			0xB9B43117CAF6A7D0ULL,
			0x9C4F73F45C955BC6ULL,
			0xE71D495F27CF1984ULL,
			0x5C8ED7B922284128ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3CE299AA72291DB3ULL,
			0x9F1797FECFCF9663ULL,
			0x6C687F0B1F345ECFULL,
			0x21B42ED69881FF56ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB4B00FB125333388ULL,
			0x9D365DBA01AABC1FULL,
			0xEC77771C3EB965E6ULL,
			0x5F180545ACC6348FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x627650C5D888631DULL,
			0x8C2900A824BE1A2FULL,
			0x6759B39C170E529EULL,
			0x5D14CAFCFDF8FB26ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED8EC3573CBD7688ULL,
			0xB62D82B162C9EE87ULL,
			0x6E001ED31ED919E0ULL,
			0x011D694E65AFD30CULL
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
			0x9089A88FDDCC31F0ULL,
			0x89252E7C6340FC56ULL,
			0xED6956E7B077058DULL,
			0x69E10065BD6E7059ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE667259E82C17212ULL,
			0x916632C4A2831F63ULL,
			0xC6231F321A6E4A0DULL,
			0x772B06AA0F7158E8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB7C695BEAED411A8ULL,
			0xB8ACB3F178074EBBULL,
			0x1674FC0949BA8EE1ULL,
			0x7F9185FF0ED7E1B8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14AEFF6BE4BD84D1ULL,
			0x55703E62D725283EULL,
			0xC8D56B959D081826ULL,
			0x72DF46198A6EA6FEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF64378375A002770ULL,
			0xFA2DC42E7F15A576ULL,
			0xACEBEBB1A758DD4AULL,
			0x72BF7447CEAC41CBULL
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
			0xAA6AABFA93799C20ULL,
			0xEF701A45F15475B0ULL,
			0x258DCFBA839AE9E2ULL,
			0x7DB1E265F6347CEFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4AF7B0F491C208FEULL,
			0x3F5AF14780EF0A0CULL,
			0x53036DF2B3C0A2B2ULL,
			0x74DF668E204B0BDAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9E3ED9C99611B120ULL,
			0x65B52FE20F5B220AULL,
			0x16740B1A908816AEULL,
			0x65EB2539B2E5A738ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x58DA55C274C82BF4ULL,
			0x8DBF1FEB51BE2FD1ULL,
			0x75C2B7A35A3B7C75ULL,
			0x13A82D5C734FEE97ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAD30F3AAB6F20B4AULL,
			0xE8974AC4DD590D87ULL,
			0x15F1276328B09835ULL,
			0x32264E59D16CC412ULL
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
			0x9AD499651FBB6D48ULL,
			0x965ED6FA74FB19F1ULL,
			0x8C0FE674DF53C1B2ULL,
			0x5EE8D3F83C6AB429ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC1D46EE9B3296D37ULL,
			0xEE63246697021ACBULL,
			0xC10D498DC0385835ULL,
			0x1F8C041B51415452ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEF455CBECDADA5C8ULL,
			0xB9A8D3CCF3C94869ULL,
			0x2A95649DD7C35C2BULL,
			0x76EDA75AAA7C2E9FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x41BBAAB4193ECEEDULL,
			0x0754915361DA8D51ULL,
			0x4869D47ACC0DE7AEULL,
			0x6D5E4521734E2637ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2254241E7E2AF5E0ULL,
			0x2A0604C379A99121ULL,
			0xAC4750C80047FB65ULL,
			0x12F44ABC7AC6DE9EULL
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
			0xFB3FA5057F56C548ULL,
			0x88B502EDDD85D139ULL,
			0x4DFB3996F40497EAULL,
			0x6ED9FCBD885C7E51ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF95E77F2E9286594ULL,
			0x4004E7D2DA31B617ULL,
			0x036D8951F3E68A0CULL,
			0x5741AA4E2D722FCBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x328DF007E7234768ULL,
			0x9CB8749A6069D593ULL,
			0x1D002B5F5C581063ULL,
			0x4C40406A802A81DEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4584CD66CACB20C8ULL,
			0x95786D499585D2E7ULL,
			0xAA508923E7C952F6ULL,
			0x331D990C02B7E13DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD722E6FBB8303E2EULL,
			0xABE6CDBEF9E94BF9ULL,
			0x65196C15307218F1ULL,
			0x38D09E8134C915D7ULL
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
			0x9D7AE90554D0D620ULL,
			0xABDFD7AA7E383301ULL,
			0x019BFB8D4C86817CULL,
			0x7CF664F4527B9E0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFC00637ED347ECBAULL,
			0xCE5596DB8F61E3FBULL,
			0x27C1DE25B8FC2943ULL,
			0x2A1D3846C6260819ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7FBBD48EC5BCF60ULL,
			0x0CB2E34F2CE70E8EULL,
			0xA348674B32206060ULL,
			0x457666269C435E2AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1DB988DBE8B664F9ULL,
			0x7AE353D63A60B0BAULL,
			0x51584D7A71FC4292ULL,
			0x1659C0CFB6AA13CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB51C4D2FA596374ULL,
			0x5F464DB752545D37ULL,
			0x4C0ADCE0732C2BF6ULL,
			0x4C89D9B3C199D05BULL
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
			0xF16922194D1FAEB8ULL,
			0xC38E099FAADB54F5ULL,
			0x04BE316A5D8C4FD6ULL,
			0x6907945912EF0858ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0800C51DA4150959ULL,
			0xE4C1372119272900ULL,
			0x94DB951D09E75467ULL,
			0x5555638FFA65D42AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x09C78389F852D6D0ULL,
			0xAC21BB00283DBE5AULL,
			0xBE89C1BD4E26D0B7ULL,
			0x60B6BF63789EC8B6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5B467DD408ABA255ULL,
			0x683D7B47C77C75E1ULL,
			0x8F0B994EEFBC8A19ULL,
			0x75E33C95B212DCCFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA88D762A1A85FDB9ULL,
			0xC331307BCB879E69ULL,
			0x17EFA62804414BE5ULL,
			0x35DCC6D71DA67954ULL
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
			0x8D575332F491EEB0ULL,
			0xCCF1055C2A7D3783ULL,
			0x1A8F41D4805B8F9DULL,
			0x48AB8FA0875CE044ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x73FCA0E12AE9EFBCULL,
			0xE1690CB1B32F611BULL,
			0x9CD0452A21B128F0ULL,
			0x720509185615255AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x809B49C7F6DA3960ULL,
			0x2425FBDE7E603F63ULL,
			0xD04CEBFA88B7DD05ULL,
			0x61CCC917F0A4ACC8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x26EB33A47A47592FULL,
			0xA3BE0FA81F6D0742ULL,
			0xB6819C0C788CCF49ULL,
			0x103378D498C0AB91ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB315A71DC398898ULL,
			0x65FB8080A365B551ULL,
			0xB21E06F7B99F1403ULL,
			0x4181177207E5979EULL
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
			0x5F3E1EDDF80F2F70ULL,
			0x18256BB03C9B1A4DULL,
			0xEB7FC7EA268D1ADFULL,
			0x7B10CA4F837B1BA4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xECDF92702793504AULL,
			0xAE721CAB3855F5D2ULL,
			0x233DCE332E74490FULL,
			0x340B047AF900D012ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3FD180615CC39530ULL,
			0x3FF86FE707309611ULL,
			0x75D700F8DC6B7485ULL,
			0x674E19CE0A42C24BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7122D8584E5E0EB3ULL,
			0x0FA84407CE7EEAE1ULL,
			0x511C751295C4D9AEULL,
			0x0B444CB6B528F5F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEDCB664E6564AB9BULL,
			0xC2E1EC4BEB8EDCB9ULL,
			0x71AAD6166B899791ULL,
			0x091537478936284DULL
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
			0xAB5507AA01CDB930ULL,
			0xD45B5D2A82FDAE86ULL,
			0xAD791E1511C40BC8ULL,
			0x544A358C7A1027E6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x24093C268FB17435ULL,
			0x83F7CF41FBC48465ULL,
			0x32904B07583228C9ULL,
			0x0DC07A693BA9D93DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8FC448E462A3D440ULL,
			0x3B3ED210894407FBULL,
			0x3E0EFCD6E9EBD910ULL,
			0x47A4D469A3048F02ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3F4984F7D5A9AD42ULL,
			0x6A6FB686134E870EULL,
			0xECA8FDB6CA0AB782ULL,
			0x00A01F1AB748B499ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD2C04EC704D19170ULL,
			0x0DBDA731B6F7CBF0ULL,
			0xFDBD8F338949C6EEULL,
			0x08AB1B1DFCEE61BBULL
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
			0x3D2DF660F4E179E8ULL,
			0xDA3D1978E54551F8ULL,
			0x0CBF707E22B221DAULL,
			0x5C3BD462C09B706EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD4D1DB5DBB64962CULL,
			0xA5E40BE6A81D6655ULL,
			0x42E99270A103165FULL,
			0x2DA6F6F8EDE9B88BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x49A7E5CA46728C50ULL,
			0xDFC91586D8F21137ULL,
			0xA417451FCF8FA009ULL,
			0x528D84A12E38BF91ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8A82BB82A25F2E5DULL,
			0xAC8C0B02CD982DCFULL,
			0xBBD8E844B78A44F8ULL,
			0x3B69149CEEBF8DE3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF79783D0694019D3ULL,
			0x7E0FEA5E51E64971ULL,
			0xDD4297DB9E69FC46ULL,
			0x2ECA0FD9F40784E1ULL
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
			0x7A3C42CA73EB7088ULL,
			0x777F5E0679ABF808ULL,
			0x517357ACAD5D7849ULL,
			0x52C79B0B291C4926ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2E13BB9DE280E26CULL,
			0xAF71DC5AD20CE7B1ULL,
			0x778036B4EF102120ULL,
			0x54349C4DCA5CA7CEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDFB170C46368D770ULL,
			0x2D9ECAC2BBB38A8DULL,
			0x7B74B896673F29F6ULL,
			0x430370FF84D10635ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1E699E3033DB1262ULL,
			0xFDED7E581ED7AF04ULL,
			0xE72924125AB003CFULL,
			0x21BBBBE25B43F067ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD2589D7DBE406F1EULL,
			0xCBF511804F6F9F3AULL,
			0xBCD9F7F59AB5C5ADULL,
			0x2F37663679F6BE99ULL
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
			0x9542B8DEC23C0D00ULL,
			0x0674367B6F4EE297ULL,
			0xA31276CE5CFB1BD7ULL,
			0x46F67294B0402DBAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF4D769EE20A993F2ULL,
			0xE916A475321BC8D3ULL,
			0x32E434806EBB0216ULL,
			0x17E6EC4CBCBB10ACULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF90D5ED639528678ULL,
			0x265A97085EB9747CULL,
			0xCAD179674DA3682BULL,
			0x67C61FF3F60D18B5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDF8B5234172F8006ULL,
			0x15F2514E5EC9C342ULL,
			0x15BBE15BAD80F7C4ULL,
			0x495E644020F80096ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x42C96C2BCDAAA680ULL,
			0x8DFC6BD7FE63F173ULL,
			0x9D0249F1868DD999ULL,
			0x724740934AC19ECEULL
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
			0xACA230CBB8A19200ULL,
			0xB9444FCA4E162006ULL,
			0x9FE195B4D224DDFBULL,
			0x578EFC67917588CCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7293DDC3505177B2ULL,
			0x0B63022E159C0EBCULL,
			0xDC5BBD6BC5F878C0ULL,
			0x7372A08F42C847E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x38B6D77A3FA6CC90ULL,
			0x29E7ACAD1FF8E0D9ULL,
			0xEEDB1D6F9FDBD84FULL,
			0x49B772E83B75C232ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5086A6A296741767ULL,
			0x5C120074A14F11CCULL,
			0x2DF5FDB3C8C4B143ULL,
			0x1B062B0C9FF4C69AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x605222CE7C113DF0ULL,
			0x20DDC0B4284C478AULL,
			0x86D4D7C3C6C62F57ULL,
			0x4C9FA0585E5BCED8ULL
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
			0xF8ED38EF52ADA610ULL,
			0x24C060AC8D4DBB07ULL,
			0x9337853B6CE913FAULL,
			0x756C8D33D06B48B4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0BABE1BABF4C7903ULL,
			0xEFBC811373A55118ULL,
			0x662D7C4D1281DA86ULL,
			0x6D5B7CFB524DB3CAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCE9015840DAA4910ULL,
			0x08255A7B77F38584ULL,
			0x9B8A54218B68377DULL,
			0x67C96C7808DDC4A4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6F3DC13AC574A97DULL,
			0xF132E4B3F973CA71ULL,
			0x33246856B1F60A65ULL,
			0x6C94BE9061D5479DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9FC95E51A6B98227ULL,
			0xB5FFF127E0DE8A84ULL,
			0xFA7F732316127828ULL,
			0x2C5C8AA89840D35AULL
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
			0x4C8A69BAF14ABF88ULL,
			0xF64677CC743329CCULL,
			0xBBF139B208580486ULL,
			0x7758D6CB3313D5F6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0C6BAC708BE60F1BULL,
			0xC5318CE501392F67ULL,
			0x210C5725B440AF49ULL,
			0x1091E25D0072D58AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7AC81A8A4E2686B8ULL,
			0x91260C62366174B8ULL,
			0x0CD128917979B302ULL,
			0x462689878AE31448ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x74D0FBFC3EA2CCB9ULL,
			0x40765C5C4708C679ULL,
			0xAD6AA719827E9733ULL,
			0x1D6D9BEA33D82A2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0487A95E36C342FCULL,
			0xD64F30B48121D2B7ULL,
			0xD944C709D03D47CFULL,
			0x2293667EFD51C740ULL
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
			0xAC17954102F01348ULL,
			0x0F431BEA2AF6B6D6ULL,
			0x83C28EB6B60C2C59ULL,
			0x7B8501162E9110EBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x600978DFEF6187BFULL,
			0x22A662341462BA18ULL,
			0x8DEE4E69FDE722A6ULL,
			0x6CBE270E381BE432ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB76ABF182D29B710ULL,
			0x7241C650DF310805ULL,
			0xCEF79BAAADC16FCEULL,
			0x4108196405D7ABF8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCADD832AE0A80439ULL,
			0x3C8A3A4E0D30816BULL,
			0x105513ECA408E786ULL,
			0x556D820E8E0D4295ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4220849CFD3E09FBULL,
			0x8804FB4D68536E0CULL,
			0x7E3796A5BE6C011DULL,
			0x7892E624962780C6ULL
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
			0x5331275797B2D930ULL,
			0xAEB0CCD1BCF6EAA0ULL,
			0x8CCE73D7C7B252D3ULL,
			0x4926D8C87E3A9347ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1A140CD8C0BCE71BULL,
			0x5C0F830F8C498AA0ULL,
			0x86E1E4AEC33D0681ULL,
			0x3C9DF187162B5E6DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEF314CFA9818A548ULL,
			0xE3A48F2874B2034DULL,
			0xBF2DFD1F4253262FULL,
			0x64E36A5E30159ABFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x55AA4F8141D8D05EULL,
			0x5EA4269C3FE026C3ULL,
			0x6037B0A89CB6D2AEULL,
			0x22CF0236ED8CA085ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7FC321C1AACF027AULL,
			0x74864A44CE1A5F4DULL,
			0xECF556DD9B638EEEULL,
			0x167ADE997A84F476ULL
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
			0x56057E5977687C98ULL,
			0x7BADC38DCCCDAC7CULL,
			0x44678B83EE400903ULL,
			0x5636FC1A07C833C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E863A39243436DFULL,
			0xD83C04237941CEA1ULL,
			0x1C4DDE99054535D6ULL,
			0x0C894A5ECC12C9E7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8A5B3879FADED210ULL,
			0xE447336C69DB229FULL,
			0xD6433DFAAF73E964ULL,
			0x6D6CD128D49CEBC2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B4E72F93193AC1EULL,
			0x940A9394A16E3CFDULL,
			0xD2067DA130593EBEULL,
			0x0EB693107706AC46ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x362C759AF05235A1ULL,
			0xB8DE68534FFEBFD0ULL,
			0x25DCB3B738A76069ULL,
			0x3F4B4B24731ADA80ULL
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
			0xEEDCABAA007C6708ULL,
			0x656ABBA59AE22EBBULL,
			0xA7F837D1B89F447DULL,
			0x74CF7C76FBC19964ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3C4098D7917FA0DCULL,
			0xE7CCF9B4C32FE4A7ULL,
			0x36A5ECE2D69C4535ULL,
			0x33F0B0D70AB43752ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x165BCB0A68C80278ULL,
			0xAD6B5E45E02D0937ULL,
			0xC69E4CF1A93A1009ULL,
			0x6FE658C4F878990EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x719D40EE175389F6ULL,
			0x46CA6FBC5E6F7C1CULL,
			0x4188B124F724F98BULL,
			0x2A340AA2BCBCEAB0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x919CDEE3981E1D44ULL,
			0x6402D426887129ACULL,
			0x699BAEA5E147B4DEULL,
			0x7808D4CFECE1EF1AULL
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
			0x7B3EF3E039E39C30ULL,
			0x9033FCE1BE51331EULL,
			0x0C7C6129A994DE29ULL,
			0x758C0F2E6F6023AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x97A267630EBA65BDULL,
			0x3305843EF9942AC0ULL,
			0x793C9DD34D56571EULL,
			0x774BD1F514F05CD9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F4F2F9381359278ULL,
			0x88A8C78CEFFAB1EEULL,
			0x20B63C3E05466954ULL,
			0x5A9B12F8C1628B8BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x432A0BE35923CD06ULL,
			0xB9D62F2B5DCA04FEULL,
			0x98514322A1A49C0CULL,
			0x584BE4A13A2E9F0AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x61CB7D782B0E64D8ULL,
			0xF2B5CD5310AF6FD9ULL,
			0x307869DDEC8FE2B7ULL,
			0x0C0F012AD4C7EF06ULL
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
			0xAD9148769A642E50ULL,
			0xE7E9A2164AE02ED0ULL,
			0xBCA2503EF6D252F7ULL,
			0x55023AFB945B93A5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD2875F2802D748A5ULL,
			0xBFF08C6E3D04D122ULL,
			0x0E3425DBBDEF188CULL,
			0x6777C714A11A9341ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE0CA7B7A9A4A37D0ULL,
			0x8C71E30BA2FEE892ULL,
			0x1C233B0C323D7579ULL,
			0x76ACB6B98796F35DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD925A91CB2164EDFULL,
			0xEBEBD35D79BC315BULL,
			0x9DEE5470AF214546ULL,
			0x7E7368D65C456F13ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDC8517D9C5183479ULL,
			0xACA14D010C373D66ULL,
			0xFC7C9733023E8C0CULL,
			0x2F0EE121C46A1650ULL
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
			0x57D82BE43B4A0138ULL,
			0x53793EE6504A442EULL,
			0xB5B54B3E8CD09EDFULL,
			0x47CDE46CC6B5CC29ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC3A9C036A31096A0ULL,
			0x7DD1914CD2900A7AULL,
			0x2945B2A12122CA32ULL,
			0x454E079A4EECFCC2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8BEC7D2526497058ULL,
			0xC94125456C0D4F5DULL,
			0xA6C52537F2A81EE4ULL,
			0x6B57F3C632E40AC2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x67ED33C0E27372B8ULL,
			0x4A979547BF9C3FC9ULL,
			0xE6D2D1FBE483F650ULL,
			0x0C4063C5D1A69AB6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB1D6437A93EFA934ULL,
			0x47A3B6BB2AD972C3ULL,
			0x3D7B39DB2C24CDE0ULL,
			0x2DC2EB88381AEEE4ULL
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
			0x79A3AB23107D2E68ULL,
			0x07D8DF4813390170ULL,
			0x2D2C279F6BF3480EULL,
			0x7546767F5FB73394ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x27B07D4E8ED4AA30ULL,
			0x9B2DBCAEFFBACE25ULL,
			0xB39AF6652E9173D2ULL,
			0x228AA41D6CEF112BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8766B7B4AFC57738ULL,
			0x1DE5199A1A58EC3BULL,
			0x7428BF6363346FCAULL,
			0x49FAE8E2B08CCBA6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8349AAC3D5BDD6E7ULL,
			0x5A0C50069C2CC14AULL,
			0xBDDC90D0F15A7845ULL,
			0x01A472BA0C03D365ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAFF24BC688943C1AULL,
			0x8A3F213817D19798ULL,
			0x0308B622B664FA6BULL,
			0x5C08C3A15BE07B7EULL
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
			0xDF3F9BD0ABF07058ULL,
			0x6B50F739C1A3E395ULL,
			0xE08BEA2383194E8AULL,
			0x76DFC97BD4924333ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD650AFDF67E85AB3ULL,
			0x8B79E84D8BB54ECEULL,
			0xC6519D3422379618ULL,
			0x7389205F1DC36FEAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x78F35DAD8B4F95B0ULL,
			0xC3DF4C3487D89BE9ULL,
			0x579249B8C5057AD0ULL,
			0x655013108887B0AFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94A94B4F935BDB39ULL,
			0x896016CC0B6D948AULL,
			0x7B53CF494B169C4DULL,
			0x2066F92306556D41ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCD2F95860E0D8644ULL,
			0x75F7A7C28A934B3EULL,
			0xECB3BC42CE74DA25ULL,
			0x595B2B89B35B5649ULL
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
			0x2B70588BB09F3AC8ULL,
			0xDD24AC3FC3DF9355ULL,
			0xE4BD580C5D3CE830ULL,
			0x693FBB9486FBD27BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB7B11333F4B1F489ULL,
			0x24912E9B2359A1E1ULL,
			0x3CF654471863EC9BULL,
			0x3A94E2FA6A047F0AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5F0FB5C0E711AE40ULL,
			0x36529F7BBB5C3320ULL,
			0x429C1D68D3A217B9ULL,
			0x44C946C4AE3ED187ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBDA9A515407E1384ULL,
			0x9FD584A841FF47E2ULL,
			0x024E62579FC4CCE8ULL,
			0x530A690420CFD4D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFC140FD660EB8373ULL,
			0x73168395F6AC795BULL,
			0xF0243556E4C0A0D3ULL,
			0x5C05666009AF0C87ULL
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
			0x17324C55823D8810ULL,
			0x2399D1BC862ECB41ULL,
			0x491D665DE2512353ULL,
			0x56E42516773B69A8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB8FDDF60E1C29185ULL,
			0x96C29C7CD23AD4AEULL,
			0x716D65BBE0A390D0ULL,
			0x4146214DEFF30903ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1E4DBCE2F6614F68ULL,
			0x46F613B097F5155FULL,
			0xEF65C40A073481C5ULL,
			0x6CA14023C2064E5CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1C05DAAEE3628D99ULL,
			0x753EBD8E686B0E97ULL,
			0xB17178E5280E3F50ULL,
			0x0DC464CF1CA61515ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD95151A0B8EC6B00ULL,
			0x02CFEA28F7D15D04ULL,
			0x43B3FF8E5C24B0C8ULL,
			0x635729756CEBBFEEULL
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
			0x67E06FAAD3CC0CE8ULL,
			0xBFF7066488E94C70ULL,
			0x1D861A105B142B6FULL,
			0x5B943A82DBCA9B33ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C1397B3C145E927ULL,
			0x005F7472FB6145CFULL,
			0xCDFD03FCB792C2E2ULL,
			0x461A44DB277A3228ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xED19C053B5F4CB88ULL,
			0xAF743AE51B4FE9DFULL,
			0xB645A386C4C2C3D7ULL,
			0x6044E6372E2E8077ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1A1B8C7D3DF2C547ULL,
			0x912884A1B3C96CB1ULL,
			0x43A9AA44A2DF9026ULL,
			0x3D329D1DD76C1587ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1E17C9A6BA0A359AULL,
			0x1BD4243D7C06C94FULL,
			0xB76253B38F459ED6ULL,
			0x6D6A3C871DE785FDULL
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
			0x39D8B18B4A6FCB28ULL,
			0x2B100392BC399EC2ULL,
			0xF549E0E5B26409E4ULL,
			0x5FA4BC374F33AE6AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDE20EE71001F1CA5ULL,
			0x70CD5F9612633BBDULL,
			0x9A4D8167B19F572AULL,
			0x1AACF4789C90B3C7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCBCF9B3BED17FC20ULL,
			0x53FE5D329E8D22EAULL,
			0x704BE5758393C2F9ULL,
			0x6555CDFB4E49F36FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA964E54D032163FEULL,
			0x58D3EF5370D1A37CULL,
			0x2383C54893E66075ULL,
			0x3492F93314959174ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF7D95E48356C3FBCULL,
			0xC32B404D5D141DA2ULL,
			0x8A39BC861D9B91D7ULL,
			0x35B801AD4A9EBAE1ULL
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
			0xAE1690F6CB956048ULL,
			0x7CD206C83F7A020AULL,
			0xF0FB22D3C4BFB21BULL,
			0x723A0C3188B2DA8FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDB4AF8083F50414DULL,
			0x4E489B44E9B65CB4ULL,
			0x5F7043F7904687ADULL,
			0x010B7C7AFD72321DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x15A99DD3B750A298ULL,
			0x1F7660138E6F37F6ULL,
			0x12E616CF78601AC1ULL,
			0x426EB9395E516B30ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x08CF1C86670F07C5ULL,
			0x777483EE3C834285ULL,
			0x0F08A4C88AE2E9C3ULL,
			0x37C02984153295F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5AC49E846386D3ECULL,
			0xFE213F303348D93AULL,
			0x081B8613B2AE9A55ULL,
			0x49AB126F92C949F5ULL
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
			0xD5E1B3AD65C66A10ULL,
			0x5410080C63E55A00ULL,
			0xB1DB13AF45A62F3BULL,
			0x7402D305F0DC0007ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD1989AB5CA096F8AULL,
			0x5816827B19F1C0D7ULL,
			0xE682A6C4D2629860ULL,
			0x436BD7474499770CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x775FEB41D7B5B180ULL,
			0xF6217A29EA7DC0DFULL,
			0x9909B6B18061921AULL,
			0x7F7E314DDD820ED0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x55E43A42E7972801ULL,
			0x26317BD6C9A5655DULL,
			0x3D6A67872E9C0A13ULL,
			0x074CCA56FE366C62ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE92C31C9E3FFA054ULL,
			0x8840F40EBE59EA68ULL,
			0xA28174C0885DA242ULL,
			0x5C516FF8CC403D2DULL
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
			0x34763DC86D1C9190ULL,
			0x98EC04EC108F3FBAULL,
			0x3A508E646976A282ULL,
			0x7DC7A884CE762F4CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEF1FFD35614F8ED8ULL,
			0xCC7B4EFC375D0379ULL,
			0x558D1A88E21CCB26ULL,
			0x17F24935DBF9F9EFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x571CD30DD8226E68ULL,
			0xA0AA98183686010BULL,
			0x355EF6B2B8C4FA89ULL,
			0x53F90632708BF5D5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x51A2F209B0A3C1F3ULL,
			0xB7664E5FF0BDFE0EULL,
			0x42B61681F34639DBULL,
			0x72C066AFA5211622ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCC8E1FF7E15C6530ULL,
			0xED7087C3F0BA46ACULL,
			0xFE35AF1E7158B5D5ULL,
			0x1469C7D4FA8F894AULL
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
			0xED5F9B6E8CE261E0ULL,
			0xF0E231FD0DA64BFCULL,
			0x5064DE5C05EF4FC2ULL,
			0x61D10CB66FD814A0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE93DAC060A54A2C9ULL,
			0x92F80B829A3E1E65ULL,
			0x783AB16AA2DC4AEFULL,
			0x53362C7D991FE92EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3F6761688E311C90ULL,
			0x240C05EFD0CB82B8ULL,
			0xD95C147127ABCF2AULL,
			0x70C7C84F7967781CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFD278F6717E7BFE2ULL,
			0xB22FAF51464CA91BULL,
			0x7D0E691AFEB9CC94ULL,
			0x1E2CE81C7D7B1CD8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF236ECDD251E0CFFULL,
			0x0BBE14AF4CC5D46CULL,
			0x803A6520238A17BBULL,
			0x065842A9B7D9C091ULL
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
			0x98302DA99C6DFB98ULL,
			0x4A38579E12976313ULL,
			0xB3D93F8849021DADULL,
			0x64CE2A1DCAC38419ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB08131AEFF357AAULL,
			0x0E9CCC6C31B774E3ULL,
			0x0ABC99BF71998857ULL,
			0x3F027E81D24DC70DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4BED9455547D6F68ULL,
			0xF8B30D47DDA93743ULL,
			0x4AB5312EE57C9960ULL,
			0x7D73B886B3BC9D2EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD9D8B9D83EEDC7AAULL,
			0xA5A3F2DDBF282789ULL,
			0xC8DB476A631A5732ULL,
			0x2E4D48C44883AD92ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5611530AB1C01ACBULL,
			0xA2B4F1B797B0FD5DULL,
			0x9200E008651EA7D1ULL,
			0x50586AECF03CDFC7ULL
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
			0x006F9D07CCBD0188ULL,
			0x5877C08BAB4158F0ULL,
			0x81C210036A4A5DE2ULL,
			0x7C0EC36AAD3DF804ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x045E8577CE8AE458ULL,
			0x4733691CE7AA42F2ULL,
			0x5FBE75552D0EE74CULL,
			0x5E06307C146EB348ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3170AE6C3CF84A48ULL,
			0xF114739D781DBBAFULL,
			0x95C8F2C8A87D9015ULL,
			0x41191B13EE38FA41ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x48D82B20A98984F5ULL,
			0x56BF4CDE650DD21CULL,
			0xB9EBD354F9F1695AULL,
			0x1D2F345AE679A4D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x33E5A27F00AA0CC1ULL,
			0x06EC8E96F2359F19ULL,
			0x1AB78BAA8500DD39ULL,
			0x3531F548D4300FE2ULL
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
			0x1B7ABB985DE964E0ULL,
			0x739557A322B350DEULL,
			0x33482FB2AC435FECULL,
			0x46F5C990E821DD44ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3C490A389AE7CFA8ULL,
			0x31ABF5F3982AA53FULL,
			0xDF39D54AF91B79FBULL,
			0x31F382021DF54C25ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x348763F57510CF18ULL,
			0x3A126301087CA872ULL,
			0xF63E74390C2A6F0CULL,
			0x4539A69BFEC265F3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x799B8DFAC0DB112CULL,
			0x9D0FAB8489BE4DD1ULL,
			0xCB4A39A0D7C09572ULL,
			0x3D68872D9C5AB317ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x32DC36BDF5A9146DULL,
			0x23B62225CA535737ULL,
			0x35C1FD381099D333ULL,
			0x32F12DACC7B505A9ULL
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
			0xC8B2459F21B6B228ULL,
			0x3493F67CE9EC16B3ULL,
			0x4AE503F2E023AFF3ULL,
			0x66C540FA02F9F594ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA48B852C4EFF1619ULL,
			0xA51544AB620A0D29ULL,
			0xBCF8DBDDC6602714ULL,
			0x5CCEFDA6B8E7E0FFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF28622D79B195D50ULL,
			0xA7FA4DAD4D99BBAFULL,
			0x5826DA7E003EFF31ULL,
			0x6D8B8BEF08516E75ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x616195CD93EF3842ULL,
			0x698EB68CF7B78AA4ULL,
			0x11388ADBEFD5F800ULL,
			0x44430B63465D4FE0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x45CCE968D841A12FULL,
			0xD87B57CD9E280EE2ULL,
			0xCC3EEF5EF91A948FULL,
			0x4730E874F8FABBC9ULL
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
			0xAF6ACBC29059C098ULL,
			0x50CD405162ECE78DULL,
			0x9FF3ABCA784304E6ULL,
			0x6C0B4CC3427A5676ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5148A75D98391460ULL,
			0x13977AB970FFE251ULL,
			0xF02FB73AFA3A9E79ULL,
			0x0812D6F48C47A6C5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A06C348EFB3FCE0ULL,
			0x24976D5E378A73BFULL,
			0x6D52CE1EE812E7F8ULL,
			0x5C03AE52192629FAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE8D517EE0268DF60ULL,
			0xAD55CF3FD3F2A13AULL,
			0xC2A3254D0502630DULL,
			0x78EE933C31BC19E4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C4D09F9A7344DCBULL,
			0xEC719EC746E85BD5ULL,
			0x2AEDC966A15EF781ULL,
			0x01C7BF824CB2368CULL
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
			0xEA33470B5F2E2528ULL,
			0x516A2C9D2EF4FDB8ULL,
			0x11ECDB311A33E9C3ULL,
			0x664CA93136EBC495ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAC39B0F74EAB5BC1ULL,
			0xC1F1298B1D3E5AE0ULL,
			0x2E0795BC322480DAULL,
			0x441449D1380797B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x944287FA2B92F960ULL,
			0x44C0903B2541EC48ULL,
			0x1BD919625F073C4EULL,
			0x58C74E5641838299ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x17B5860381344B74ULL,
			0x733BC2CD770C5E53ULL,
			0x3CD39F76CF25CB79ULL,
			0x188C6BB5B9555AE0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x55F7493D94B5FD1DULL,
			0xA59AD0AD4F5803A4ULL,
			0x3BF1E1B89986536AULL,
			0x2BEFA2F427C3C511ULL
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
			0xD628CCFC5A99CC88ULL,
			0x7EADBCBA8E196F38ULL,
			0x33A1E31B284D1141ULL,
			0x62D8BF2185383BBCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9147700E65BDADDCULL,
			0x56F8C2C02481FD04ULL,
			0xE76B65CEFA3371E4ULL,
			0x7CEC38F459FD7C89ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4391805B61C06D58ULL,
			0x90C8C3DE5FCC63DAULL,
			0xB05786F4D329C5C0ULL,
			0x7E740F8CA7BEAA81ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAD4195A622AD44CBULL,
			0xCCE6041F3DEC83D3ULL,
			0x09D4E82632162B12ULL,
			0x693E58FDF9CD0E3DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA380678020F305C6ULL,
			0xF451E8C0E6CF32CCULL,
			0x9386EEC56DC8A64FULL,
			0x2988ABF94C686698ULL
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
			0x43DFB93CA04C3F80ULL,
			0x8A27AF94C44CFDBFULL,
			0xB84BABD91BB1B4EBULL,
			0x56BBF36E1BE9AAA7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA760F5DF28BCC25FULL,
			0xD6A39BD61E7F0A29ULL,
			0x82A3562677B3E1B9ULL,
			0x2911FCF467A80FAEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x734B39207B9AD250ULL,
			0xFCE8D702F5EC37B9ULL,
			0x1C3FE7EB93EF5309ULL,
			0x4A866295BD40C490ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA122631FF0BB94F4ULL,
			0xAC9B240356184FEDULL,
			0x691E3FFB6733D7A6ULL,
			0x4AAC5421CB63F516ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2163E7336839BEFFULL,
			0x3D8E97D7C1058CE7ULL,
			0xEBC3DCA0CECAF6F2ULL,
			0x3434528DA4FDBFBEULL
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
			0x4097134A7C6F2D30ULL,
			0x9F25EF1C4AAAC864ULL,
			0x4CA30553B93AAF30ULL,
			0x7ADB34843F0DB89EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3F0C277DDC596345ULL,
			0x83BC59100042F148ULL,
			0xF7EBD5501CC3D181ULL,
			0x21E8249B6C4545B6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3DDA4759FCF599A0ULL,
			0xDE163C7D7327BA29ULL,
			0xE63753012248F504ULL,
			0x42FC6E8B5CCC65A3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4AD70909E6445DF0ULL,
			0x9965532D55F9EC74ULL,
			0x7D6ADEE533FF74D7ULL,
			0x54A26AC3F3EE7597ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC80924DBC5C31F20ULL,
			0x774D85488393E488ULL,
			0xF054816037D39451ULL,
			0x6E61921BAED9E55CULL
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
			0x252DC45921AE78D8ULL,
			0xDFA8D9A009CADCA2ULL,
			0xE1656D853EADFA64ULL,
			0x43F2F610F083929EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D12092EE848347BULL,
			0xAC4B8C5CBDDBFDCDULL,
			0x5FCDDC4BBCDE7BE8ULL,
			0x44E0433858CB4755ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x933CF2AD20AA1FE8ULL,
			0xF0001B4EEC3BB783ULL,
			0x622CCA8B7D0CD8DEULL,
			0x53684B41EA8AB65FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x614C68E2ACC64C14ULL,
			0x567E51E7C0F95260ULL,
			0x4129A9F0568AD902ULL,
			0x08352D2E4CC13540ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8181036F7EDA37F4ULL,
			0xEBF836929D0A367DULL,
			0xC6A1AD83448CB0D3ULL,
			0x169C800DACB6E561ULL
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
			0xF6BF3A7E300E4800ULL,
			0x184ACC47CEA0922FULL,
			0x33073EB6B2C6EFFFULL,
			0x4443C0FC0ED6910CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x38E4391FED724D7CULL,
			0x2A1B9177293C052AULL,
			0x171D8037F38518E1ULL,
			0x6363FC311EA66472ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4E9C4D8063BED150ULL,
			0xE361C96EA6D49899ULL,
			0x4478F5D01176AF2BULL,
			0x4EEBC723A895ED9FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD3124789C77ABB9AULL,
			0xB3DE907B2AE50E0AULL,
			0xE316220D868EE5DEULL,
			0x72DD11D70A4730B3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x71BAC180AEA26441ULL,
			0xEFABCED22DCDD507ULL,
			0x9B7999A6417FBE4BULL,
			0x04A1E9095297FF34ULL
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
			0x01B9BE04AE22BF58ULL,
			0xF5A7E72D8AB9D5ABULL,
			0xF1914A1D8969D4F3ULL,
			0x7767E572B3D9445AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E5B0D8A0D994B9EULL,
			0x2C267F7FCDB20951ULL,
			0x87E9307B81B12B4BULL,
			0x201A12711E3A8D69ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBDDD09150CF3D138ULL,
			0x8C87A93A5A244534ULL,
			0x4A8218FD52C581ABULL,
			0x53710520BE563F49ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x082AB64DB07B15DAULL,
			0xC1227A5A2A1C3243ULL,
			0xE94A0BECE250B035ULL,
			0x6F5FE3FBDFCE74FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x617BB47F2246662DULL,
			0x6672A785C4B3F7BFULL,
			0xBFA227C55C47ACD6ULL,
			0x132FFA050DE9CC94ULL
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
			0xF7B25EF48678DBC0ULL,
			0x397A70DE45A1BB0DULL,
			0xD51A906EC927FEB7ULL,
			0x7A0316F51D5E23C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD3F771B716CFA66DULL,
			0xF5292E4BA46EE2C6ULL,
			0xDB0EEEABDE0FB894ULL,
			0x76BCE3FE65BC7F1AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x23CA2E0092271880ULL,
			0x4FCC6789E8F775CCULL,
			0x095D61F5D43F210AULL,
			0x629851963410BF11ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF2DD093BC9B413BULL,
			0x41B5CEEE0B2338A2ULL,
			0x648A8255130100BFULL,
			0x6F535CA528695EC8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFAD00538B8A23B59ULL,
			0x6B6CCEDF8F63A99EULL,
			0x3842659C6DF18A99ULL,
			0x71814F0C77ED2355ULL
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
			0xDAB204D5363C7798ULL,
			0xA20DFD5EDB165270ULL,
			0x41CBA9A7614AB359ULL,
			0x727F75CDA4658A99ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B770810A8F6A774ULL,
			0xF5C285ED8805E309ULL,
			0xBAF5E08F6B38BF3AULL,
			0x74D0EDCACC215E8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F1BCD640B04F178ULL,
			0x4D4F4E933696D5CCULL,
			0xF191DADEA8537311ULL,
			0x72211FF20D44FB46ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x67A7B99B255A2BA1ULL,
			0x2C0B43427EC8F41EULL,
			0xC10BDB4CAE5D7D0EULL,
			0x1296EC02668EF490ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5205CA063EE51FA4ULL,
			0x30BC74CDFB9BF37EULL,
			0xCB546FDA2F0FF184ULL,
			0x281CB3E2C6F9857FULL
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
			0xF66D7CE22892BD40ULL,
			0xA32E20F72B74E176ULL,
			0x27E4AF727FB752DBULL,
			0x4D5C08F338E031ADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B4EC20516FBEDC9ULL,
			0x96355D6C67349620ULL,
			0xD97AADF17ED0D320ULL,
			0x26AE55C1F1E9B770ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7456B5120B3E9338ULL,
			0xB52A667A323E0BEDULL,
			0x39C3AFBDD6AD7C83ULL,
			0x6B76F2C81B8110C5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2435CB80A9A71905ULL,
			0x2FB388B3F48EA0FAULL,
			0x62D0DBE0BAB393B1ULL,
			0x0245E52D28D0DD88ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x20EA7A6A9D8C436BULL,
			0x5F54CE14C8495096ULL,
			0xD0D461DFE003E797ULL,
			0x0BF8FF5F68922A11ULL
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
			0x1F6B880E10DF1980ULL,
			0x61796165DDC909B6ULL,
			0x899CC13FE3834F99ULL,
			0x51D09CF37BAFFDB2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x329833FF2D0B368BULL,
			0x52A4AFC41F23E897ULL,
			0xCE134C22A5AA3695ULL,
			0x157F28ED088AE7CBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x07E7A8E716B0B058ULL,
			0x53622DD050D956B9ULL,
			0x18D7A0BC234D7340ULL,
			0x4C612FFB4D518B05ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7965CF6905E14270ULL,
			0xBCEDA7E2EFF9AD16ULL,
			0x7B8A7609C8F735A4ULL,
			0x7223EE88E8A9BC24ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6023ABDBD8A22CDULL,
			0x5904236B178EBFE2ULL,
			0x2E788D5BC1459127ULL,
			0x4C4DA4E595A9AA69ULL
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
			0x87A85C31F4347EE0ULL,
			0x17E8EA11E0F71C1AULL,
			0x996ECE0D1436A0EAULL,
			0x61B153B74A31F97CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB79E5AB5F7BD8F0ULL,
			0x01D2283F8D3B49B8ULL,
			0x194FEA7858271994ULL,
			0x165C5A357E404597ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF988AA6B7A438EE0ULL,
			0x929092C3C18BA13CULL,
			0x2A8A0A49C3C539E1ULL,
			0x4CC6200692348189ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4911CDA2B297726FULL,
			0xA1D467DD0ACBB447ULL,
			0x11E33B31FB174C6EULL,
			0x5620594DB35B8F30ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x699258768121F849ULL,
			0x2EB8B6B4F3F43F01ULL,
			0xEDA5B9D13559A10CULL,
			0x323DE8F2CB99A98FULL
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
			0xD2E7854B13235218ULL,
			0x2FD288F178A5A919ULL,
			0x3EF5AFCC58A7BC62ULL,
			0x65C4B09D20B98562ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x92826D2425367E12ULL,
			0x0351A08D83E33AEDULL,
			0xBB8B07241FEF3A71ULL,
			0x508924765A653748ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x270FC3D05625EF50ULL,
			0x5A8D0C25D19364BDULL,
			0xB3E177F19B4C5B40ULL,
			0x66DC6CC7C329140FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37C3E4D51B40ADBFULL,
			0xBBA708914684B577ULL,
			0xE7108F253556E7C6ULL,
			0x3607FCD9069BCF06ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC2EAACE542476F57ULL,
			0xB54939078BA69168ULL,
			0x7F40245C843A6318ULL,
			0x0BB077E5AB84A179ULL
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
			0x9B4567120EC335C8ULL,
			0xF286461D8FC0D10EULL,
			0x59B4810ED2A62E7DULL,
			0x4CCFA0D819360BFBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE384937667F6A3BFULL,
			0xEBF836F0C3B65729ULL,
			0x622FB99C457839FBULL,
			0x343C092F2F4D16BAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x73DD4A3F6A4823A8ULL,
			0x7EA015C7876EC99CULL,
			0xA3C189B6401004E4ULL,
			0x787825B61623AF3BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD4F13139E11B6B26ULL,
			0x68D6E4BC7812F798ULL,
			0xC4076A8A76E932CBULL,
			0x32DB5A8E811B5584ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC432527A7241E4EAULL,
			0x35690B934950C63EULL,
			0x1DEAC97252C8893FULL,
			0x700F71359B1E6080ULL
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
			0x41CD66C13C7E5A28ULL,
			0x38DDC1A1C44A3904ULL,
			0xAC400F1D087D62F7ULL,
			0x7D1CDD359C261A0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE228BAD6C9A58701ULL,
			0x78C47CCC64616678ULL,
			0x6C0E515F10E1AC48ULL,
			0x768E674134A06D39ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9176F7217158DA70ULL,
			0x98E1662431226A80ULL,
			0xE3A02247D81CC688ULL,
			0x54DA1EAC6DAA2B63ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBBB620162CBCFF8CULL,
			0xB3D73F9D092B6F33ULL,
			0xC01589B68219038FULL,
			0x5592DD93A01CD75EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDAC68EEAF95A28FCULL,
			0xC9B510B35CE9DE43ULL,
			0x0A7BB360DAAD93B1ULL,
			0x2FD7BDF5EF841B17ULL
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
			0x9D026C936E9AB258ULL,
			0x99489D538A17DE65ULL,
			0xC2583EB694F9A47AULL,
			0x701E3E29A0A40E45ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDFC83E9B983ABE49ULL,
			0x0EBC340F1A1BE894ULL,
			0x194B5B15A09C81BDULL,
			0x6E58D52A288F9DA8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE46FF3D55EE9E358ULL,
			0x7C82FC57860BE3E5ULL,
			0x74615BF10AA4BBB7ULL,
			0x4651F4F1DA440B38ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x88ED2AD273D6CD75ULL,
			0x6CC204631A2E9995ULL,
			0x42A7477E6C55ACC8ULL,
			0x7BCA4ADB118CCF08ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5FE3FF8D4A526AEULL,
			0x447DFD34B0145A9CULL,
			0x79F23CAF22C57307ULL,
			0x26FC7FD53FD79A9BULL
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
			0x3188F02558B4A580ULL,
			0x205C38CF7047D927ULL,
			0x14A4BCD51BF1A059ULL,
			0x5F0FA25E2F3B5354ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC633A6B4470A57E8ULL,
			0x304A3609AA6100B7ULL,
			0x98E3A450FBAE7D42ULL,
			0x1560BAA163452152ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE9CB62BF6CBC45B0ULL,
			0x770952D8D1F2FE69ULL,
			0x7229B130DA08CFE2ULL,
			0x4224D78A8C8F4BD5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8B14DD974B1A9223ULL,
			0x882CC86F4A7F8368ULL,
			0x96135EA4CF179DF2ULL,
			0x061D827C823FC26AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7EB7022E02D5C206ULL,
			0xE1F538BA68940B63ULL,
			0xB62AA2E0C6089AE4ULL,
			0x14A086F89B2C1FAEULL
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
			0x835678A97608E608ULL,
			0x618A8B6C9BE1E651ULL,
			0x77B13B45109D41EBULL,
			0x5357BA4FE61FF620ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x95D969E01C0005F4ULL,
			0x65C1BD09DEE923C4ULL,
			0x6FCA70AD58B0F4E1ULL,
			0x4308B7BDCE4DA624ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9C288ABA5FC67868ULL,
			0xBF700698E66E3B80ULL,
			0x3C4F7DF53EC9631FULL,
			0x691EBCBFC34EAB71ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x76A905BAF7339108ULL,
			0xAD9C8E797D63C70DULL,
			0x8FCD6F4221DD97FCULL,
			0x1744865F37CACB0AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDF020B2C44FED98FULL,
			0x36F37A2750E87E99ULL,
			0x4ECF5CF6AE4DDFF7ULL,
			0x32BC90C18584AE02ULL
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
			0x4EB593FA32CBBB30ULL,
			0x012DF9EB1E1EB204ULL,
			0x12C2590D7CEBC35AULL,
			0x630E39A1E73E6FCCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3565487DA222CE3CULL,
			0xCF6E12574F928405ULL,
			0xCD74560600CA3157ULL,
			0x66DE2C154E3B07FAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8340B91E2CA8A8E8ULL,
			0x70F8492A4520FC04ULL,
			0x98FA98277938C10FULL,
			0x64B0AE51763F17BBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC36F7A17A569E9DEULL,
			0xC14CB61FCC759C21ULL,
			0x7F056B3C414018F8ULL,
			0x07D8C10A196752A1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x58C494B46C29C709ULL,
			0xEDD6901608CAB9DEULL,
			0x4E8953A67109644FULL,
			0x3C98F2DB6118728DULL
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
			0x4B08F511EE082868ULL,
			0x35DD81B5EA522775ULL,
			0x6F9E7BB2EFC500A4ULL,
			0x69FC62A90D113553ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDBD3F7EEF7939BBEULL,
			0x6A6F131FF97ECEDAULL,
			0x9E62A9483A9541F0ULL,
			0x4939CA254BE11B8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBC9139A9FCC199F0ULL,
			0x61831C8355609983ULL,
			0x3C1E1D507B7FDC4DULL,
			0x7C4CD3AD432E65CDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3B0B3E454DD7F7B0ULL,
			0x2F4893FE0E0665FCULL,
			0xF40707C4AF7C1607ULL,
			0x2CCFE8CC5ADEF5F3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB5CC215953779D56ULL,
			0x984C3BD50997D78EULL,
			0xAA5EE5A6E4534728ULL,
			0x240EA5198A1485BCULL
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
			0x4AA1249A252B80C8ULL,
			0x9D24C77F05046C2EULL,
			0x594C579C7A815354ULL,
			0x650FC3CEC2493334ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8571F38F25FC4D20ULL,
			0x1F00D9EF27D02FCFULL,
			0x57592D2EF0ABC6CBULL,
			0x37821905CCEE98A5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6BCAA7C054AC7450ULL,
			0x59B5E88CCA1F1563ULL,
			0x64AB885612DA9CB6ULL,
			0x6B42B22431F1D2B9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DAB8857FE393825ULL,
			0x6C776A9B85F87F54ULL,
			0x06AA0201AA61034BULL,
			0x49CC097A3E5B42C0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x295C554F8FCD4CB1ULL,
			0x1E8E029046FEE0D5ULL,
			0xDE2B24CDFE202F4CULL,
			0x7A7495FA759C9239ULL
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
			0x59937D340AF617B0ULL,
			0x8483B05DE96C0BD8ULL,
			0x655EB289C44EBBD9ULL,
			0x7C1EE3E871328FE3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09AF85E95675A24AULL,
			0x3E471089E6D62EC6ULL,
			0xD30B9D54325F92F3ULL,
			0x7822DDC0E31BC589ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7F0D7A59C9AAC828ULL,
			0x6290E4A32C89ED4DULL,
			0x2D804DB884DAEC44ULL,
			0x502E3528234CFB06ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD0FD705FBB132885ULL,
			0x2AE51A16A87B11DEULL,
			0x0E0C99E13A15B582ULL,
			0x5D0163E9B7F64145ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF9DB8F9C3590BBB4ULL,
			0x4D44B0E26C1355EBULL,
			0x0330034CEA122826ULL,
			0x0DFE6330BD141585ULL
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
			0x056AB57B65C98FD8ULL,
			0x1208ECBC05E019F7ULL,
			0x63607EBDC7A3ACD3ULL,
			0x6E312CED60FD5BB6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x02E54AD81498DA45ULL,
			0x3D23ED62C6E8DFFCULL,
			0x512564F0441B2CB2ULL,
			0x3D72E4B40D743E7CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x71BBF6B864A90410ULL,
			0x327D3E58B6229111ULL,
			0x89466A2D501E88EEULL,
			0x6793DADD24E890BAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC96981DA93F938C6ULL,
			0x7D9F27340EB7EDDEULL,
			0xF77B2DB837F59FCBULL,
			0x442AA9A6AE667109ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xADF92C12F4898DC1ULL,
			0xB2E2B2AA1A84518DULL,
			0xFB5BDFBBB1BEDFC5ULL,
			0x067075763FFBD210ULL
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
			0xDE633FD8853BDC78ULL,
			0xCAB083FFC19BBA00ULL,
			0xE62D4DE285643280ULL,
			0x626E5C81C402537AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1EEB47FFCB70F856ULL,
			0x48542D512A237FADULL,
			0x45DBB6D2FD791EA0ULL,
			0x562C0842CE305E9DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54B3951623EA2150ULL,
			0x71238D1B1DE1F216ULL,
			0x7718255919D0DCF9ULL,
			0x4C95F33554F81B0EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x91D271D2040376A3ULL,
			0xAD040BDF20C1B147ULL,
			0x15A8CE32025F631CULL,
			0x51D9BBACDA5AF601ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF6216F1BE410C4EBULL,
			0x161C97F9987616CDULL,
			0x5E9D533A76D7D238ULL,
			0x67A2D3BF3A43583EULL
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
			0x5BFF3ACC9C75F9F8ULL,
			0x3FCA87BE824A6F11ULL,
			0xCC1176F519C2AACEULL,
			0x519509B23009092EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9579533A99C96676ULL,
			0x165BCB406FD537A2ULL,
			0x413A20CC4F0A9EA0ULL,
			0x4835F03C876DB878ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E9094EB9296B588ULL,
			0x22F43247D7483AE4ULL,
			0x238678EC865C34B4ULL,
			0x5908BDC8F58F816CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC78C599424295F8ULL,
			0xBD47059A6A432071ULL,
			0x7A21229EF85BA290ULL,
			0x14FA2A19509745BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2C59F069878B3973ULL,
			0xBB949EAC1186B80DULL,
			0xE5AD4D1767E704BEULL,
			0x37BBAAD45CEF3107ULL
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
			0x461D3D683EB75AE8ULL,
			0xDD3C07CF8FD220A1ULL,
			0xACE4C49CDDD256A6ULL,
			0x66281E9F5E0E3B0EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1529C5B341F574ECULL,
			0x8C367095F26F2A0BULL,
			0x667C51299AE145E4ULL,
			0x7D98B3D9D28A4D42ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE93D7C39AD3CF3D8ULL,
			0xC46095A810A4C153ULL,
			0x298EA6B33049767CULL,
			0x7BED7157753BAF0BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x850E97FDAED507FBULL,
			0x4DF9F77E5CC49A9FULL,
			0x98CEC44E0D8DC645ULL,
			0x08FAC83988DD55BDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8E6D0E538723CE61ULL,
			0x6843FCBAABF39B8EULL,
			0xB3BA3775B80283D1ULL,
			0x5565780FFC2D17C6ULL
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
			0x9E033BD5337F10D8ULL,
			0x0CDA579D76ACEBEEULL,
			0x71DED6AC276EB531ULL,
			0x592F2780A7813EC8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA8386E64566037F9ULL,
			0x4C391826F1D7EB4EULL,
			0xF2B164678CD26F44ULL,
			0x54837B11E1651755ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9578FB29A41DADF8ULL,
			0xE7F773830DBB3F7CULL,
			0x61A1E0FC47BD5992ULL,
			0x4745BD0C6A8CCE5EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF8C9146DA39FFD63ULL,
			0xBF9688B4E6350279ULL,
			0x75B51796191923D3ULL,
			0x58327A0D0E474B8BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0800A0C4D2DB4D93ULL,
			0x399C6C6ADFE3B57AULL,
			0xCA88CD17EF6649E8ULL,
			0x17D0672DC4A8D825ULL
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
			0xC7FC50DF2051E6D8ULL,
			0x5488FF7837F915EAULL,
			0xE28469EC6597E62BULL,
			0x7BF3A0D32F02B5A2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4CFF1392A335171DULL,
			0x52CA0043EC56F8B1ULL,
			0x2BE925ECC7F2EF4FULL,
			0x658E6852ABAA7273ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDBBC8B885C3BF4D8ULL,
			0xA9F25344FF25BC64ULL,
			0x594501717039E1EFULL,
			0x76B110C33AB2C986ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x210F3DCE0EB57FDCULL,
			0x5B4884FBA62182F2ULL,
			0x0EFA9353D48A9C09ULL,
			0x1497C72C97D6EED5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x562746683CED743BULL,
			0x711791455A5B3061ULL,
			0x905A200BA7F9F830ULL,
			0x2B68B2CCD67A69FAULL
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
			0xD40538172AF25118ULL,
			0x288629460825F92DULL,
			0x4E2D1D3D25900D2EULL,
			0x794DE549F544D534ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC75E65E9ADB66D28ULL,
			0x94D90482C89C7260ULL,
			0x6B20A1CADDE079A1ULL,
			0x3684349055EC1566ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBA3AA50D65EBA5B8ULL,
			0xB9775D86263D4A28ULL,
			0x9DAA795CA6B4CD53ULL,
			0x7332A9D2ECB01DA3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x58DD9AC71C8542A9ULL,
			0x8E55956E8BA0B4DAULL,
			0x1AA77DEE173DDBFAULL,
			0x36D84BACF55987F0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7F0F7079A72C20ABULL,
			0x8EB371A39CFCCFA2ULL,
			0x854867DEA57A8D3FULL,
			0x44ABCF9775E288ACULL
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
			0x3C3843A8DF4B2FC0ULL,
			0xC3B5F6EDD08ABBDAULL,
			0xD0557FA6D2F1DC74ULL,
			0x670DC6BFAFCDA89DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8F1E33523626D213ULL,
			0x4F62203E08ED26ABULL,
			0x361879F5968F7D32ULL,
			0x5C1CA42B8EB29448ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3B650F183EBA7020ULL,
			0x3E12FA60665A6E1EULL,
			0x4CADE93B413E8ABBULL,
			0x6F5633DF1E612738ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x96D40A866094456EULL,
			0x9E1AC7401F15E7A4ULL,
			0x35C1BC979600F93AULL,
			0x55E3BE6112585D76ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03B400B038309DE5ULL,
			0x6EE1456132E4EB83ULL,
			0xBBD2CAF2011FF2AFULL,
			0x2FAF882AAF57BEF4ULL
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
			0x52D98FBC419C77F0ULL,
			0x194639666C107AD6ULL,
			0x435B743887564BA4ULL,
			0x7C728F1FA2A405EEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4714DE6729584CCDULL,
			0x1FCF9DC9F00B1B94ULL,
			0x05579047166BE151ULL,
			0x5FCDC6F9017AAE20ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x769DF64BB4E18190ULL,
			0x253F94B4605DEFEDULL,
			0x996EAE5585E2B847ULL,
			0x4D23BB59807B861CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4B16B86185145A14ULL,
			0x011EAD1101B8AB92ULL,
			0x2FD2E34F806A7D8AULL,
			0x1AA42FB1E5EF65CBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB04BE9FC57803A5BULL,
			0x19FB4027DE66D5BDULL,
			0x14091D140B3D0ADCULL,
			0x6AFCBE9E35D5E904ULL
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
			0xDFDE3774AC4B85C8ULL,
			0xAE8A0ECDB0B140E2ULL,
			0x7F81CD51B915BD95ULL,
			0x4FA978988A28F7C6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x822D891802F22DFAULL,
			0x5633853F7982453DULL,
			0xA3A2A1FE96FBFC0CULL,
			0x07C97022AD92F157ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x531B364113DBFC90ULL,
			0xBB094D908E775697ULL,
			0x37117F078CE85A33ULL,
			0x6A9EC2EA94A6E2EDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6F97882363534DD8ULL,
			0xFD7F99C6B33F798DULL,
			0xB2189592049D146DULL,
			0x375424A9EE70B938ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1B00E9E68AC92D48ULL,
			0x7B83DE9416F5EDC4ULL,
			0xC90F263D4D3FE668ULL,
			0x56FEC4974BBE8F7CULL
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
			0xCA38A5E9D94E9CD0ULL,
			0x47BFEFC11A9261BEULL,
			0xB18383CB9B81DACFULL,
			0x4971DB4E0CDCB164ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7629A8FFB543CCDBULL,
			0x88C09EB5702EC3BDULL,
			0x9C8A755571CD4EC7ULL,
			0x1AD2BABCDB0A9E5AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6F8763378993F970ULL,
			0xA2C6CD2A7BBF5B14ULL,
			0xE025A937EB7C87A3ULL,
			0x64EDE316583DEB7DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2863C179EF3FFAD7ULL,
			0x58AC67DF52B1ABC8ULL,
			0xB51682A0A97E21DBULL,
			0x40F6C159509AA74FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEB1383A395576FF7ULL,
			0x4E99192838323674ULL,
			0xE2BE4D9CB8BED9C5ULL,
			0x13B10E2C73D816E2ULL
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
			0x88C4DC4634E14F78ULL,
			0xFF4187207562CD87ULL,
			0x60F157F6158E639BULL,
			0x44CAD0A9874D07F0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB9B06AF39A867FC6ULL,
			0x0DD46D43E3693AF2ULL,
			0xF6624E0DE074AF69ULL,
			0x7110D34CB63994B8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6CACD6F9AC93F068ULL,
			0x9F0B872BA2C15F10ULL,
			0xAC5225ADF3E1E7AFULL,
			0x5F94DEFF0B822CF5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAE2F2822FE795626ULL,
			0x9BCB66DD5CD32AB5ULL,
			0xF7B588FF75FA87E5ULL,
			0x732747C3AF10078FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x943EB2B417F725E0ULL,
			0x1FC73082FBD03F55ULL,
			0xF372BCD96EEC8263ULL,
			0x279932EE9C6E42F9ULL
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
			0x9D1759517DBA94E0ULL,
			0x419E1218A944B067ULL,
			0x57727EEED4970261ULL,
			0x50E8C97567156CADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x25090CDA5E6A755FULL,
			0x0293AAF39415673FULL,
			0xD3260B741BA49A8CULL,
			0x7C607F61BCB8E4BBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x53126A7FFCE39420ULL,
			0xFC6723B8C611EF35ULL,
			0x62C937F6F3F050CFULL,
			0x6FE5236A08D04BB8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2ACF1DC05F38B1F8ULL,
			0x8D0A5AA32BC434CAULL,
			0xF9355274C2D95519ULL,
			0x13BCD1590C2FB70CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7DD075234D18AD72ULL,
			0xED54CD529727C99FULL,
			0xF9E5B14B6DB55C1DULL,
			0x36B4BFF4F7428E4BULL
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
			0x52D6AE2993333E38ULL,
			0x6FD0A40F56BC4390ULL,
			0x3D0D72ECCBA67D40ULL,
			0x4EB823978F2EFCC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2205B8035DB13BE6ULL,
			0xE5A04D28F3E903A7ULL,
			0xB6F739C17C7A9146ULL,
			0x131A095782AB00EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4BBBEEDCDB551558ULL,
			0xC4FE16FBEFB284EFULL,
			0x74CCCA7B80AD42ECULL,
			0x6F85FE56850B35AFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDD3E062B496DBDECULL,
			0xF3D6B5DA027099A0ULL,
			0x135CE48D8DBE8A8AULL,
			0x49EE178729D02E1BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6FA31310D7C09163ULL,
			0xA0F84A8D95B75A01ULL,
			0xD4244C68608AFB59ULL,
			0x30F8069ECB858373ULL
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
			0xD75CA3F251D65D88ULL,
			0xA44538C46F203B81ULL,
			0x40C9AA1B56513D4CULL,
			0x5AD81329A8C6DA10ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB5BF78A6D8113EE9ULL,
			0xF22716671ABD72B3ULL,
			0xEB7C4680CBEEE963ULL,
			0x4F16472DF6A6B191ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0F6FF96DBB8CCAE8ULL,
			0x07F0FE0EE414BCAFULL,
			0x3C167B34E84B999FULL,
			0x423FD1872AE4A6D4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x47D4DE4F4FF49C0AULL,
			0x6826351D40BE881EULL,
			0xAF8580BF8A654522ULL,
			0x138DDE23ACD59D6AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x92F355658B757A16ULL,
			0xC5AC3ECAD364F520ULL,
			0xC58AA3E76DBF66DBULL,
			0x6176D2339D1389F9ULL
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
			0x29BB60C3C3E30F98ULL,
			0x8EE649B7B7FBA222ULL,
			0x1108E9780549F177ULL,
			0x5D0118D9A007807EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5855057CE282BA64ULL,
			0x51D8ABDC79ECAC39ULL,
			0x1B54B5B5317D4326ULL,
			0x5B257F5FFBF7580DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4E5360832F3EB850ULL,
			0x209DC6DCB5577FA6ULL,
			0x245CA740A04FF3D2ULL,
			0x4AF43A74526F4CCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56B5A45B2861AF33ULL,
			0x70F7E88454A8F6A0ULL,
			0x60AA1DABF58A16F5ULL,
			0x5B59FD2114B5C4CDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE1268FFE35036E66ULL,
			0x05498C226A9B1D32ULL,
			0x84D5A8A8CBE12587ULL,
			0x51956488851E61F7ULL
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
			0x8DF91F55938EBD38ULL,
			0x553CAE1CD13C93A7ULL,
			0x7ADF4A4005E9E6D2ULL,
			0x5BE2084165776AB1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB1FF0B1CBF655DFCULL,
			0x5C02D5DB0F6D5936ULL,
			0xC748B7963F9E3F79ULL,
			0x1FEEE5E50ACE9CADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x39430112618A7F30ULL,
			0x0C1081D469857C02ULL,
			0x1DAA860C89565276ULL,
			0x40A5D0B0758472FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x26C48FC6B6B155F9ULL,
			0xCFDF10DDB8140E59ULL,
			0x3ACA53E3E2E86D2EULL,
			0x358E5065A2F4A57DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x15BF0444BCB9878DULL,
			0x5CF911986DF4AB48ULL,
			0x367CBD4F72BA5341ULL,
			0x10DC01C475DFCD99ULL
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
			0x69DCFC3A83F37AB8ULL,
			0x074DD2F2745EBB3EULL,
			0x8ADB79FDE7992A2CULL,
			0x5C04BA5A0B4A5A83ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6B82B2DD3E3C8260ULL,
			0x4F23B783FCF5759EULL,
			0x7CEAB3F06DDF526DULL,
			0x3CA78843C7CF924CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1D0D480B611D9E10ULL,
			0x81CBF9AB75383A1EULL,
			0xEFE12BBEBD7956ABULL,
			0x75A0475B525FE09DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x471EBA2684329F22ULL,
			0xA009BAB83277511CULL,
			0xE51B5DE8E485570DULL,
			0x774B5BC4E3CBC0B9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2A114E4EA7B9DB35ULL,
			0x0AB6502005C3D383ULL,
			0xF12593D931293D81ULL,
			0x75C0D116196D9AF2ULL
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
			0xB058158CC9726AF8ULL,
			0x5D1FD26E17180AEBULL,
			0x2946CDED18126421ULL,
			0x7A87E19D2F649C30ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x806508F60AFAB8EFULL,
			0x30C3D63F8769EBC6ULL,
			0x681348C7226F2905ULL,
			0x61CA64BA1C1CBE8AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC66F34E7035B0F90ULL,
			0x34F131C06442322DULL,
			0xB68D09860FD110B3ULL,
			0x74AF1A9E2FD165C2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x80B5BC0A8C46E22AULL,
			0x8FE8E50545E03361ULL,
			0x03486DB2DA7E8498ULL,
			0x0B1EE974D444BB57ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCCC536B1D41CE22AULL,
			0x932387A2D28A8F8BULL,
			0xDE32207F1187CDD8ULL,
			0x65BA489A0B11A011ULL
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
			0xE736772F278C7550ULL,
			0x9967E51FA1E1076BULL,
			0x54A53B1A4A8634EDULL,
			0x5FDDB3E321CAFC01ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6418E0B5A03C9476ULL,
			0x957E3CF6E44EB706ULL,
			0xD3CB0FC57B352AFDULL,
			0x7431A34A670C5949ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA111768E7DDDA040ULL,
			0xE0201CA38BB9C4DDULL,
			0x6E1848822EBDAAF3ULL,
			0x6E51B2A979244A6BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4AE85BF7D9255F45ULL,
			0x23BF6F08B1A95A01ULL,
			0xF429C4469CB0671AULL,
			0x390F5796E32212EFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D48642D7091A1F2ULL,
			0xE5ED9CFD004EB47DULL,
			0x8D67343FF4CACF0FULL,
			0x37E80F4BCEE127EAULL
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
			0x932CBF06AD401148ULL,
			0x198A40FB89AB0B66ULL,
			0x4F019343471F7E65ULL,
			0x6B390C40422DBA75ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF718902413FEA0F5ULL,
			0x0FFFA15D1970D05CULL,
			0xEA469C8FAC3C7D50ULL,
			0x3A3D892993C930A1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA1D0FE28EA94EC88ULL,
			0x71176E80EFF89918ULL,
			0x53774A32008A1FE7ULL,
			0x41113428721E5546ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD222989E19D2A91CULL,
			0xCAC08F73E6FACA85ULL,
			0xAD051A4375145BF7ULL,
			0x34A5F282846747BEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF39D904DAB4BA6E6ULL,
			0x2B6CFC8C56A4E58DULL,
			0x271F42B40A89F2F7ULL,
			0x6E40EBEBDBFCAFCBULL
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
			0x094CAAFDC5D51800ULL,
			0x644CAA25B00B3BF0ULL,
			0x301C792074AF8E63ULL,
			0x44834741B1CDA005ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3CEB3C2B29B619B7ULL,
			0xA615A59C9C5CCA41ULL,
			0x00E36F4DBF306002ULL,
			0x2E8A247ED2583CB1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1CCAD52C2B308A8ULL,
			0x602941093A4C83C8ULL,
			0xF30FC53CDB435E11ULL,
			0x4AE9BACF6DD8959FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x360E351BF9FF3784ULL,
			0x72F6ACE3AB9259FEULL,
			0x32A9FF02A4034F65ULL,
			0x038D53073588BEECULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA2890EB27736D8FEULL,
			0x6567347193691185ULL,
			0x680DB1EF9DF60EF1ULL,
			0x637C0D639A653F87ULL
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
			0x017831FDCA5E1F28ULL,
			0x4A91905A504B893BULL,
			0xD760C45F7618F73EULL,
			0x6BC1ACD76CEEADFAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9F50C73003EF294DULL,
			0xBDD62DF69B7A62F3ULL,
			0x82CEA7F02345986BULL,
			0x27300866001C8E76ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7370F544B65E4FA8ULL,
			0x88B586BFB38F09BBULL,
			0x2EC4A65F43E0B8F3ULL,
			0x70B81EB16741AF6EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF88F63F49DF258EULL,
			0x0C4FA34AD7F8C33BULL,
			0x57D3F9C42F055CA3ULL,
			0x554D545C6204116AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC326418EFFEDC42BULL,
			0xA2D24556EA96E24FULL,
			0x6EFCD9CD8F4D96D1ULL,
			0x1E141CFCB8588344ULL
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
			0xC791D86DA547B3A0ULL,
			0x8970AAD893D4B58FULL,
			0x0BE12629CE8D6115ULL,
			0x430B9FDACCEBE2C0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x66791F180ADF92F3ULL,
			0x06EB20B21DA8FD13ULL,
			0xC78AABE7F910244FULL,
			0x66325E9B7F8E42FEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x810F91910EB88FE0ULL,
			0xB0428F368A1CA838ULL,
			0x59E95E1EBCCD3DDAULL,
			0x7725C864BD84B9CDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFFFB8011BB29B74ULL,
			0x36E793CD78A350B3ULL,
			0x2521A9740877F2EBULL,
			0x1F8AB9516782A26FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC578771F0D2C3078ULL,
			0x328EED1770D49E93ULL,
			0x71A821B11FC8EDAAULL,
			0x1E62733962D8E229ULL
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
			0x714D37E537540A98ULL,
			0x701A6D7C55163701ULL,
			0x59C947A18D1DAEB4ULL,
			0x678EBF83BF21789CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF2413F05B5C1B496ULL,
			0x068C7555022FA26FULL,
			0x70B6ED80AAB5F261ULL,
			0x5A51E9CD31B87294ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x001949ED229288F0ULL,
			0xD882933A90541EF3ULL,
			0x5315F83D1249A515ULL,
			0x50A24496F40B7D48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x426AE85DE775445FULL,
			0x3D4F318D405B7565ULL,
			0x669393EC71A43DE6ULL,
			0x4D8CDD9C71497D33ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x068257EB04016529ULL,
			0x41CC1319D0C591DAULL,
			0x82CBCCFDF8BE4660ULL,
			0x2552613D977A820BULL
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
			0x3C03CD68307F6D10ULL,
			0x0029A2435BF6637EULL,
			0x0A40638F8FA65434ULL,
			0x449E9648C0A860F3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2A31E004829EEA1EULL,
			0x04A33386536EB24DULL,
			0xC89BF4B76CE42C75ULL,
			0x44FFA5C125C4882CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x85AC533C2B235398ULL,
			0x61A6DBAFA458E324ULL,
			0xD29BCF8467BFDEA9ULL,
			0x4749C8B6695F6F83ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCABF28EACAA375FAULL,
			0x93B69176B8508C75ULL,
			0x3BE62441902E6EFBULL,
			0x63B53ABAA8A7F00DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3BA0CE041FFD98F4ULL,
			0xFE3877B540771FA4ULL,
			0x6A0E9DD44B88CD46ULL,
			0x4B677660AB7B9CDEULL
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
			0xA1623B583D68DD18ULL,
			0xC82187D677131889ULL,
			0x9C1BE7BA783AE6D6ULL,
			0x520AE3753B9CBD03ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB301ED06F5D285B0ULL,
			0x26AC56FF227C89F9ULL,
			0xE4397556B0830275ULL,
			0x45EAD5B757D4E3AEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD3CA1AABCF3DF870ULL,
			0xDC30A5C9C37C6141ULL,
			0xF15795FFD0ED1E6FULL,
			0x5B30A96597ECA559ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE912434E88EA2182ULL,
			0x40A0DCF3157B2FE4ULL,
			0xCF9B868344934EF6ULL,
			0x4492FB1995E5C65FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1D3B948488CEB93AULL,
			0xA65696242A893605ULL,
			0xA07BDA8B8265E8CAULL,
			0x1F3DC7CB37CB6651ULL
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
			0xD99804C1BA7C6678ULL,
			0xAFE123BF49881FE5ULL,
			0xA1582ECC262496B9ULL,
			0x4875BE05E47BCB66ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD236D9F8C5A10846ULL,
			0x2E01D5725B1A2474ULL,
			0x2F2959CCC43B2DA2ULL,
			0x291585C0B7FA407CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8EAC896CC511DDE0ULL,
			0x3485D7A7598B6ADFULL,
			0x2AB3988EB1CFD60CULL,
			0x54C60FC101ACA91EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF0A4646B5884F748ULL,
			0x652784CBE25ABEA0ULL,
			0xF511291D50059941ULL,
			0x348748B086172788ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6B701B13733BF587ULL,
			0x671B700B3A2295C5ULL,
			0x2F9669A70FF02125ULL,
			0x51DC41B7AD8B30A6ULL
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
			0x6AA9B594EFF953D0ULL,
			0xEC0479C9502BDE88ULL,
			0xAF36827CDB14C14BULL,
			0x75C4D1D1087427ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x52AAE575758990F1ULL,
			0x12CBD51E15D284D8ULL,
			0x9185A00C31C1ABAEULL,
			0x6A5C07C46ECA0809ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE7EE54F503AA05C8ULL,
			0x28682E9D297EA87AULL,
			0x002F962347CAF3F1ULL,
			0x57E8ED541A468D38ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE058E657D582D7CBULL,
			0xDD8FAC806C7B149FULL,
			0x9C640C242C363890ULL,
			0x4FC34753282876F3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF54C60091AD5763FULL,
			0x1A1603047AF8FCAEULL,
			0x6BFA8002656C8382ULL,
			0x39636CDB59915CB1ULL
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
			0xBD92149132B9DCE0ULL,
			0x2A42D0102567D893ULL,
			0x771BD0F5A3FDAE2AULL,
			0x559BE8A5C788AB53ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7D0F233DD3DB75DAULL,
			0xBEF06207E2A235B5ULL,
			0x212B7C9ED3A424ADULL,
			0x554AD880C5AD3472ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x417A040D16612968ULL,
			0x5CEEDEA9E43CAA55ULL,
			0x46EAC06B4B367957ULL,
			0x74BA6193C8784F14ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF97ACB6AC8E17F4FULL,
			0x8CE1778E8A853C1FULL,
			0x31FB98B61F7C77B7ULL,
			0x2EEC4529C132CB4EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x267CDFA91E258E23ULL,
			0x35FDDBA2598F2113ULL,
			0xCFA745514CB74180ULL,
			0x2F9C2D0DD1024324ULL
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
			0x06CA1D186E1990B8ULL,
			0x226AA92A7C180791ULL,
			0x6D58D7E5F2C4E6A2ULL,
			0x4CC2A5060904E56EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x848ADA93D9D93C12ULL,
			0x7AFD46A0D23D8A46ULL,
			0xA505A6EA9AEAB937ULL,
			0x52ED7598C94256D8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5EB4F4EB5B11D950ULL,
			0x232588A52AE138F6ULL,
			0xC5C55BC2A65D72BFULL,
			0x4C2AC07982810AEDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9F31DD0C9442697AULL,
			0xD06C1D25A2669F8AULL,
			0xCFD853F655F5BDADULL,
			0x74853A20985A0B3EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x87472AA5C15DAD94ULL,
			0x0BB45E38ACBF723BULL,
			0xBF8E011166BE97A4ULL,
			0x55BF5832B42A7073ULL
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
			0x06666F88A0203EB0ULL,
			0x93E5F6CA121BB31DULL,
			0xD4DEECDC22EDDDB0ULL,
			0x5B154E5F40BFB6B7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA27C11A9E39FD4DCULL,
			0xCC1F7BB3689BF8F2ULL,
			0x53B263A777310A0FULL,
			0x09F4B3956B30F32CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xACE4A545564AAF28ULL,
			0x8142DF872DF6D661ULL,
			0x34E2C765C629AF1CULL,
			0x7CEB5FB0F5C750ACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x534CB0871B811B6CULL,
			0x18036A971F1C5D53ULL,
			0x3130F3A181284B47ULL,
			0x32159DB2F71A8029ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2418D9FA7D21A76EULL,
			0xA4CC461EF2F4CC5DULL,
			0xD03BE179D59BAE28ULL,
			0x2885C9A634A08F40ULL
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
			0x97D6178FB4019920ULL,
			0x87B83DA7BEA98D10ULL,
			0x054B0449C07E0695ULL,
			0x5BA1733525D9C4C8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0FD27197AAB7537DULL,
			0x4421E68D897729F8ULL,
			0x232F37BC7D291A3EULL,
			0x190E73557F01396DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4E1789D6FE25F998ULL,
			0x91F1E77E8EBC15A1ULL,
			0x604265B999F04D7DULL,
			0x5B8A3533B9F88970ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x679008996F3A68F9ULL,
			0x995871C54FFA0561ULL,
			0x9507865A69760B8CULL,
			0x760A6A4D93DC7B12ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC90F488F3D880172ULL,
			0x8399324833EA3390ULL,
			0x6F1DC3EC90285329ULL,
			0x7478E36007C024EEULL
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
			0x08981642BF224408ULL,
			0x1AEA7550A2B52374ULL,
			0xB49A8AF85E737880ULL,
			0x7FBF336C88657ED1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x629F489880127CBBULL,
			0x42128F8935915FA0ULL,
			0x75D4C67EA8CF7D10ULL,
			0x37788838A4541174ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB4034C703CFB9C28ULL,
			0x59745890EA98B8F6ULL,
			0x8F194C0EA65BCD01ULL,
			0x437578CF24CDE390ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9E2890231889B2B1ULL,
			0xD96349072BBF6EE1ULL,
			0x708A7792AED03D69ULL,
			0x07E3F546D27DA96BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C947E0D44DD713DULL,
			0xCF616450BFB24804ULL,
			0x4F21FFEA45945612ULL,
			0x608F5E2EC8AB6A6AULL
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
			0x595B7F29E0245A30ULL,
			0x31B830DF7B7DAFE5ULL,
			0x60E04A6EF3D43C2CULL,
			0x6D85F2C76F6063C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC9059BB0F77A47FDULL,
			0x0B2D882FCB91A25DULL,
			0xA8B06CE30856F05AULL,
			0x0482D63FF4DEB4F5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x21CE8740BE0B95D8ULL,
			0x6DC3724E458A524EULL,
			0x161A5778E81E6CA8ULL,
			0x4FF042F08B9BE216ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD22E79C78BC77283ULL,
			0x0E5E0CB9A6C10FB8ULL,
			0xF8168BEA088FF79FULL,
			0x6899EE5FF8EFC420ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9332A1BFF7E522B6ULL,
			0xC31A7AC779222220ULL,
			0x81ACC0EE8D723DDBULL,
			0x17CF0795ADC819C0ULL
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
			0xC0D163F485C75F38ULL,
			0xB412F2426B85AA5DULL,
			0xECC3F24A369AC696ULL,
			0x54BAB6455E03F487ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDC417F9DDE9CA1D3ULL,
			0xD5D34A841768A7FDULL,
			0xFACE376E70E11F5DULL,
			0x065C0F9671DCB707ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x19F978E7E170A550ULL,
			0x03052723E475C5BFULL,
			0x7D4BCF5A1D903840ULL,
			0x6DE1D606A5DB9BC2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x122EF401E0469ECBULL,
			0xEB6A254390357D21ULL,
			0x13C377A8963D687EULL,
			0x662F436B2D3F5301ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x44555FD227FEF512ULL,
			0x21DB037DCF9317F8ULL,
			0x8238F4D738E1C22EULL,
			0x015EC3C3C145AD0FULL
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
			0xF553E50DB2DFF260ULL,
			0x773C0DD424C292EDULL,
			0xA401DFAB19ADE7EBULL,
			0x48603BC03C974979ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2DEFA66E269BDDDBULL,
			0xE7D15423CD9D45E7ULL,
			0xA60736B2DE2E90A4ULL,
			0x361EB123CA6DC0A8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC810D668DE014C00ULL,
			0x9E2D807FC5E03DEEULL,
			0xEBC164AB9C352737ULL,
			0x66EF257031432E54ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x60FA2CAA60CA84FFULL,
			0xFEAE906737A9572FULL,
			0xA4FBC753D3E9D530ULL,
			0x60E60799AF1F42F1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC78BF88FC4144CA9ULL,
			0x597A92A919354182ULL,
			0x113FFFA9013FE007ULL,
			0x0E17D44F907F5FC0ULL
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
			0x5288ED6B01D03A00ULL,
			0x31284D42275F46D3ULL,
			0xD6814C89AFD16613ULL,
			0x568E2A2A2EFBA275ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x60FE2823ECA815B6ULL,
			0xC354CBED514CC3D6ULL,
			0x710D51D98CF0F4BAULL,
			0x11D252E8DE37C3DEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x66C2F7F1C7E20730ULL,
			0x5677D5D4955CB836ULL,
			0x8DFF57E29EFF03D3ULL,
			0x71E9B1DFD4E3322DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x28696BE980708B09ULL,
			0x45EE3B4C21D41C4FULL,
			0x421C4AB9A5F83FF7ULL,
			0x5C6CC18F4208F714ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6DE39665DEAC5D62ULL,
			0x9887DB2DFC1CF957ULL,
			0x5D8772CBC9E639CFULL,
			0x7A38D3D67615E1B4ULL
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
			0x5ECD0C573C217388ULL,
			0x643EBEEC24468C0BULL,
			0x584E3440D8A2E8B8ULL,
			0x7862CE8B1559CED2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x38666D6C7ED5D65BULL,
			0xD0D0F8F2E75DF835ULL,
			0x8625C1C0491E4930ULL,
			0x119C4C61E3869D80ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0693494EF0B46EF8ULL,
			0x4B01A8ABCDADDAC8ULL,
			0x4870D119636A9314ULL,
			0x5D72B007EFDA23F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2954A2225192260AULL,
			0xCDD23CE8224B4C4DULL,
			0xDC8B5E26F932D036ULL,
			0x40072E8CEBC02905ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1555B73FE3BAA9C1ULL,
			0x5A42531A2DFF5803ULL,
			0x50CE9019210F2F83ULL,
			0x27DE9A7384409BBBULL
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
			0x749850EB0B109C68ULL,
			0xB150EF02BD46D339ULL,
			0xA32769878FB2EBF6ULL,
			0x636B48D28FBEBF1FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B207139A1788995ULL,
			0x5B58CA69C2EBF328ULL,
			0xC0E089A785ECF724ULL,
			0x050FB6457E0A7587ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF9A8E1F63352AD20ULL,
			0xA239F2A16656E310ULL,
			0x69A929D1C890794DULL,
			0x5CC4422EF75CBE84ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC71FD615DE1FF568ULL,
			0x7D287746688720FFULL,
			0x4670FAC1D061E5FBULL,
			0x1D79714FB7FC606FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x269B2F0638889FC6ULL,
			0x03E0DD07C5A920F5ULL,
			0x5375AFF322773D01ULL,
			0x2A7160693943F355ULL
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
			0xBEEE5395A0204708ULL,
			0xA96970FA38F22E78ULL,
			0xC4C619C17EE35B85ULL,
			0x45648417E555774FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x889DD201338D11D4ULL,
			0x489CD3266AD6ABC1ULL,
			0x7993A6A5E86C0EE0ULL,
			0x02E1EC9CC0754729ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAA8AEF3837AE01C8ULL,
			0x11C6A3CFBCF891E9ULL,
			0x7A0E440548B6F0B2ULL,
			0x46CDDCD7ED464D9CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x73BC2A10AFA5FC6FULL,
			0xB41CE7C47EC4F1E7ULL,
			0x3E054B086641D2DBULL,
			0x10A4551385140FEDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7BDBA77DF61B6FD5ULL,
			0x0C850C47DC3A4418ULL,
			0x86D1BC382410843DULL,
			0x337035269D267EE1ULL
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
			0x653BFEEDBCE1E900ULL,
			0x84D5C744DE76CD12ULL,
			0x348DCB3257ACD9F4ULL,
			0x4F86BDC609D31451ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB2879BD93CC74936ULL,
			0xAEEB219213B3D6D7ULL,
			0x182CD047BD15EDBBULL,
			0x701D59DFE37825B4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7898A645586B2EE0ULL,
			0xB16FA2AA64EE5197ULL,
			0xEAB7B9D7BB714814ULL,
			0x514D350F6653F657ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA7628D046FE74DA8ULL,
			0xF21B037654FB51A0ULL,
			0x3D451F09390FCC91ULL,
			0x705543DAFAD9ABADULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1E3DF5CADFF40395ULL,
			0x779F61B0D5F32BAEULL,
			0x722A35ABFE697A37ULL,
			0x0EEDB2205E42CD41ULL
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
			0xB8D8F3A96649D148ULL,
			0x77F431B8D9FFC186ULL,
			0xDE183F4B02C0911CULL,
			0x7542661C8192D12FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x83433A9CA207F7BFULL,
			0x81FDC2B84F9B1387ULL,
			0x913E0DA3389A7041ULL,
			0x4D5445777F18F677ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF85A259A84FD3630ULL,
			0x9DD586E69FE08500ULL,
			0xA9C5B57FA7BF2689ULL,
			0x4AFF4EBC522A3B92ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x07B4A236F6BA2953ULL,
			0x99ABBC044EC82BB4ULL,
			0x50C5DAE64DE0A2DEULL,
			0x33E0B702A17C8193ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7F828C0CB81374EEULL,
			0x386440C95C2CCC16ULL,
			0xB71F241E5F6DFF0DULL,
			0x4C94927C6FD9E0B0ULL
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
			0x4EAE072902B12DE8ULL,
			0x1C4B64E6FCEA2048ULL,
			0x17AF17B518A34C70ULL,
			0x6BFF5216D0352EA8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x985088C4E3D843EFULL,
			0xA7ED818CC4F49468ULL,
			0x4BB9F8CBBFC67A13ULL,
			0x26A722B4A75B8EA4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7004C9708E576910ULL,
			0x6EB0AE212FBF7E93ULL,
			0x1D6FE33FF8A5F330ULL,
			0x718A44D7F04326ACULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF8DACAFB7BE7629BULL,
			0xB5201AB95EE1E839ULL,
			0x8BBCE70D87EE5209ULL,
			0x2DC37F7E7C122703ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE0932BE0BB637F3BULL,
			0x99593568FB6BB805ULL,
			0xAAC9E820417AFF34ULL,
			0x6E25CE565E292649ULL
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
			0x848BD522729360A8ULL,
			0x11BEF43EF017F45CULL,
			0x14EC8F54B716BDC0ULL,
			0x468ABB91F1FFAE51ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC0DDEDB149A5357BULL,
			0x57C07DBE628F91AEULL,
			0xBA1D132723F436EDULL,
			0x3D7F402F26ADAAA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x00976F9CA6FDC278ULL,
			0x3A80B2CAB6A5EB03ULL,
			0xC440284B3981FBFFULL,
			0x7C58F524F62E4290ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEDC9803D9FC6FCB0ULL,
			0x48C2A719FACAFB7DULL,
			0xC4FECFFAE97D8601ULL,
			0x26E47DC8165DF9A7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCAB031966790B2D7ULL,
			0xE9007E05A2EF2400ULL,
			0x25991017ACABC574ULL,
			0x7E1D7071D54507BCULL
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
			0xC43F7A9933177030ULL,
			0x7BA81AF081275E00ULL,
			0x10052BA1B707E90BULL,
			0x51D32EDC883D5931ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2693AAE4E1CCF096ULL,
			0x622AC7B9C622B571ULL,
			0xF1D1E5AD4D7D3C82ULL,
			0x2065A561CEA858EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x76D0533F009E0980ULL,
			0x7BC23EFA09C5628FULL,
			0x42C7DF2ACD794AF0ULL,
			0x4085E3B6F336D415ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x72B0692DCC23F066ULL,
			0xCE60129958B28DF3ULL,
			0xE6E0897CDA3B6C69ULL,
			0x7291E25B821CF4E6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFDEE5E32FE15CCC7ULL,
			0x2F8D09A8C1349532ULL,
			0x28A416F52AB1AE17ULL,
			0x127C954497A5C2D9ULL
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
			0xA3147EE42B95CF68ULL,
			0xB3E489F20809B188ULL,
			0x6BB9F52ACF82E883ULL,
			0x4D079E04D19647DBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEAA30BB30405AB38ULL,
			0x4CA7C269F0633A94ULL,
			0xAFDB503526A76FECULL,
			0x29072AC566D255A0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAF5CBDAD4B461220ULL,
			0xC22D86E35EB694CBULL,
			0x4BBC9CB1CCE88528ULL,
			0x6A8DC323D598FAE1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2E220BED1B7770B3ULL,
			0xC1AC49DAC827AE7BULL,
			0x2593046A6DB93D2DULL,
			0x56D70C2CA473827DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1341B38C44E781A5ULL,
			0x02B0208619A23E24ULL,
			0xE34C20B332A65A34ULL,
			0x34EC00910EE81DC5ULL
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
			0x530B22ECB94CDEF8ULL,
			0x4690A6539761811BULL,
			0x13BC68557CDC80A4ULL,
			0x4A09938ABE2B24A1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x865197E404454C17ULL,
			0xCDDE327BA6EA9808ULL,
			0x1DBF1E47A7B74854ULL,
			0x3837B68CB969227BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x080FD9B6EED71098ULL,
			0xB2624B9BEA795169ULL,
			0x4EDA972EAB570E22ULL,
			0x74F80A8592539211ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA9485F0CA3302CFFULL,
			0x0668B97943BB0348ULL,
			0x97E45745EADF82A7ULL,
			0x14F9DF5326F7B048ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x96997A7A6BE1F83BULL,
			0xAED15F12C10123AEULL,
			0x9E8F327333C1E8FFULL,
			0x6D06F749BE99A3D5ULL
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
			0x3CFE627B5989AC60ULL,
			0x3F2505524F7EE5F3ULL,
			0x8350AA48A487A546ULL,
			0x7DC3DB181BAD062AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA6F08A769D4ABE33ULL,
			0x12FC5AE3A1A9C3E1ULL,
			0xDB61FEFCDAD4BF6DULL,
			0x48309061C82CE9FCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3C145854D384F630ULL,
			0x6AEA296CC4553D9AULL,
			0x5CC793B6B83E089DULL,
			0x4E322121EF2F1793ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x45A0F6721B53E52DULL,
			0x5C4A9CB83421B721ULL,
			0x5859A30AF4C77CB9ULL,
			0x60E087B96AA879E3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCDACFD9A45A43952ULL,
			0xE570DAEABFD8D082ULL,
			0x60845B53724BA81BULL,
			0x37EC3E58F4BD00BDULL
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
			0x7906A9BC23E0BD38ULL,
			0x1064AD83C94B4080ULL,
			0x3E97D2F05C450E8DULL,
			0x47FD7307B7D452BAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7041A0B59D194C03ULL,
			0x792B1FF412862840ULL,
			0x754F22D4CE8A4C3DULL,
			0x6BC5E03018D5326CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x89203F725FE75768ULL,
			0x65E987CD859A5149ULL,
			0x8282AB728F8ED865ULL,
			0x4BE99DBC6ECF254EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x51E040ED8DA35FB7ULL,
			0xCF76881517C715BFULL,
			0x9FE17DA0DDEEBDECULL,
			0x665B080D7F4D700EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDD60B771B7F0B12DULL,
			0x80E853A45251D953ULL,
			0x34E7A2C7EF5B6993ULL,
			0x3B592D7AEE1B33FAULL
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
			0x38281458C1D177C8ULL,
			0x002304EB2BC8F2BDULL,
			0x7A3C3E8387D6FB80ULL,
			0x754770371E12E6DBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0B1694F7E663C128ULL,
			0xD4325A804D31AEFAULL,
			0x4A0ED6F38167EC9CULL,
			0x76A2A43DA179ACF6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x55D780F97E19FB40ULL,
			0x74092BA1D665F475ULL,
			0x8FB61D319A9FC9D7ULL,
			0x547311E0DA0E6C33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1AA174A39549BC5FULL,
			0x1A892E59244F40C8ULL,
			0x76B4EEAB73F89CFDULL,
			0x5FF2E9ED12F0F8D8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x69CF91DCE908837CULL,
			0x23C3EC2D934E5ADCULL,
			0x8F40D69C2F0FA3B0ULL,
			0x6FA08D476E932FFFULL
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
			0xB3864E7EC34201C8ULL,
			0xCC1AC3D37662F8E5ULL,
			0x24C5A48114EF85EBULL,
			0x6B0EC6A8E5A0AA4EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x51CD86C1FAC41F11ULL,
			0xFD14B4A9E02BF549ULL,
			0x47A041470BE25878ULL,
			0x2E232E52C1578812ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF472A2868B69BD20ULL,
			0x49CBEB2A6C1FA29EULL,
			0x9F802A0EA0A500CAULL,
			0x4890B7B1C3E37038ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x139893A81BF99116ULL,
			0x3BCEC4F508B3C97BULL,
			0x4CE6A25F3FEC1242ULL,
			0x699DDCF6407DEBCCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6E5F05A44178FB2BULL,
			0x4FAC924C71A4F6A9ULL,
			0x522DDE2CA580C297ULL,
			0x44FCFF5F21663C87ULL
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
			0xD167E0DA939CFD78ULL,
			0x40D7D66DE04FB68BULL,
			0xD67BBF40D5AF0CD1ULL,
			0x67FEC22112E94A4CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x30D807DF2ECFA051ULL,
			0x3FD282DE7C4D3D53ULL,
			0x22122E68FC3410E3ULL,
			0x49F0CB08E8C5E23AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCD72C7991EFA0238ULL,
			0x339BFE92B9A48C18ULL,
			0x50896EB76E5ABD91ULL,
			0x727FDF6CD19E3117ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA4EFA26A5ED66EB8ULL,
			0xE7BA2E85B2546C76ULL,
			0xF034E033D2181108ULL,
			0x541AB97581712FBBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x400A7B0422652EF5ULL,
			0x4D0DD276DD17C24DULL,
			0x39E41FB792873FF8ULL,
			0x6042650A8BC2F38FULL
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
			0xA3CDC5DCF4EF9C68ULL,
			0x5C91FCA958E2A980ULL,
			0x248DA51BB05941C6ULL,
			0x768A6336E5C66061ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFF6FDB86B1F44DFEULL,
			0x350D02D18037A9CEULL,
			0x970C8EF5073C2ADEULL,
			0x5FAD11D9782AE731ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB5734EB0C6C87568ULL,
			0x9661C1A32D42BD68ULL,
			0x5A88561846B80D23ULL,
			0x6665714B9B9E444CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC1A41F96F732D660ULL,
			0x34BAEDE7C7BCB711ULL,
			0x4AEB949E9A008109ULL,
			0x2B1DE477B84C7D0DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3C43B43D65CC6D91ULL,
			0x32E13FA65FAEC47EULL,
			0x724DD7D2D6776AD2ULL,
			0x68BB352C0C2FC64CULL
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
			0x3EA9EB5ECB506830ULL,
			0x68A5A479D26C5503ULL,
			0x2906C3FAB683BEDAULL,
			0x57B84CDEA1507C31ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0D31F58393516C4AULL,
			0xE75C18A418144ACEULL,
			0x50C3FD4E1CDDDFFEULL,
			0x074A49121380FD93ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDA95184F4F2AE770ULL,
			0xDF1B8647E0E3B382ULL,
			0xA5D7DB81564C67ABULL,
			0x7AA7D45BFD9E8CFDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6078E49D6982AB71ULL,
			0xED0EE77BA3F983C8ULL,
			0x15E07C4A3F77206FULL,
			0x30092447A242E372ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x674C5663A296A466ULL,
			0x6F6AF02F8E4882BDULL,
			0xA5AA799F8103668FULL,
			0x72775D7CD07A5135ULL
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
			0xCF57BBA51C3F3E10ULL,
			0x47154C2B4A25E684ULL,
			0xD8640C60BB36AB9CULL,
			0x6D7B44E24D82FE0DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x540B6AD4F9CD456BULL,
			0x2C68ABB266D70E5EULL,
			0xFEF610B18501D71EULL,
			0x548453B410221DF7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x10C64CAC51EE0548ULL,
			0x91080C6E2D0D3545ULL,
			0xB14A37B31AACA7FBULL,
			0x4FDC0C95DB214C35ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA0DA1BF795CF350FULL,
			0xC2A135E475B41CA9ULL,
			0x67BDB4B01F2F63DBULL,
			0x133869C6A87F5F61ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x63D82F000E429A31ULL,
			0x06E36824AADF9726ULL,
			0x92ACC8965A9D48FEULL,
			0x6C7623833ABDCBBEULL
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
			0x04CC95A4D878F700ULL,
			0x166AE16A31C38CFCULL,
			0x294B308A2BE0DF4BULL,
			0x7F62795CFA88308AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5C04CC69E2F1275DULL,
			0xD30D361DEBE4E9EAULL,
			0x8EA8C941EA671A53ULL,
			0x6275D61E046C1616ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5F0AA121951B0F60ULL,
			0x6F7EED6F4F31E02CULL,
			0x80A0AD1C6B7C4DB9ULL,
			0x6C7BE5E092438CDAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x059A119AEED60F4EULL,
			0x66C23D8B6139B5EBULL,
			0x5CCE852100473160ULL,
			0x68F0FAB8963C019DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD3A2772C520A1A5DULL,
			0xED1349DB5C892F13ULL,
			0x945CF14C6DDAD536ULL,
			0x0256934D30D986C5ULL
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
			0xBDB56EA325003B48ULL,
			0xAEA6CBF06E47280FULL,
			0x39CFD7FCAA8030FCULL,
			0x6685855B82202CABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9001A911DEBD894BULL,
			0x7BADC9CDED78DD11ULL,
			0x6D4E96444D1227A4ULL,
			0x4CB7CA300B36ACA0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2414BE37F0822488ULL,
			0xF3EE8E19CD271D97ULL,
			0xB100E3A75CC4AC5BULL,
			0x59CA3C3AAF4240C7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5321610B15C7FF7CULL,
			0x7E88367CF74EB64AULL,
			0xA1E43F43C743406CULL,
			0x388859BA2C28C506ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD457D695E94613F2ULL,
			0xE3D275B3E6E6B108ULL,
			0x572654E2068710C0ULL,
			0x382137743710984BULL
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
			0xE57A05E2E41EC290ULL,
			0x53516AFA6A5F0748ULL,
			0xE41EB7A7268F467AULL,
			0x71DF2EE83FE2F5EAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE69A8EBD72EFD6BULL,
			0x0154471963B001B7ULL,
			0x37A7E00DB85F0B70ULL,
			0x5EC697B7398DC888ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54D88D88CE062608ULL,
			0x95864B0F6DFA8BD8ULL,
			0x1B6FE2E0078A06D9ULL,
			0x776EC0CBE908E2BFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x12B15C58CA40E396ULL,
			0x441F44DC5A9C4991ULL,
			0xCEA58054632F493DULL,
			0x354C4864051EC63FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5C467BD2F8233E57ULL,
			0x6904DEEBEB49ACE4ULL,
			0x2B0D2A7F7242809DULL,
			0x15760B69EA1BB6C8ULL
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
			0x62EF676F0A42D220ULL,
			0xB87A8DBEB129C174ULL,
			0xF366AA6F33FF87E8ULL,
			0x567D824107DA7262ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EB8E985C152DDD7ULL,
			0x4512B8A231347344ULL,
			0xF9B5CB7EEDFE207BULL,
			0x0D8E52B70229DB63ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB983D2BF74FB910ULL,
			0x07EF83B3AEE99930ULL,
			0xA4EFE82C4298E89AULL,
			0x5FD4A7605C43BC2CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0DED9B32A89FAB64ULL,
			0xE04A9FE66773BA2EULL,
			0xE02B69E19B6B0B98ULL,
			0x686459864396629FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6BA39F85DDB2C2EFULL,
			0x99D292436900CA0AULL,
			0xC04C0C4BF53D4975ULL,
			0x6F21BABCCAE3C3D3ULL
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
			0x6950D0BC35AD6A68ULL,
			0xFD6A637071593E93ULL,
			0x0A806A913AC4DE8AULL,
			0x5B86944A15BAEE5CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE357A97D7B7566BBULL,
			0x771BE074AA5843A6ULL,
			0x978C2425CC406EB6ULL,
			0x7F382E0BF33E335CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B51964E2067C708ULL,
			0x7355B80748594312ULL,
			0xA050F446899BC06AULL,
			0x78EE37BC6CF19967ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDCACA274265D55B1ULL,
			0x4B22CBA340534371ULL,
			0x218BA07F128957EBULL,
			0x5F9D812F61D5F297ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x12A67BE66F031A3CULL,
			0xC7BD5A8E3B7DC104ULL,
			0xBF6968F680532D51ULL,
			0x2F826BB1BFC2D15DULL
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
			0x3190B07E9FF72CF8ULL,
			0x4C4EBAE3280FCA35ULL,
			0x1A013C2AFC75E579ULL,
			0x6D76A890A3097DE6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD61293F98C40A259ULL,
			0xE43BB4177718F6BDULL,
			0xE26C61F9321C747DULL,
			0x2FBA0222D300D1F9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0368CD5D6A95B398ULL,
			0xADC2A1D4AB98B86EULL,
			0x528C898B06A12023ULL,
			0x49B5322A355B76DAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1FD2EF6FD0267072ULL,
			0x21D67F2593355AC4ULL,
			0x9E9502FDEC39336DULL,
			0x7E79C45E7BE40FC7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF8528C29DB843727ULL,
			0x757E638F2B867895ULL,
			0x9FB3DC0E3A6E14C6ULL,
			0x41AAFD0D232D769AULL
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
			0x9F4250213B9FEBB0ULL,
			0x8135CBDFCBCCA543ULL,
			0x90C7466085B51F48ULL,
			0x6DE1C17B48995E78ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDEDE7303D2BE4E6CULL,
			0xA3ACB0F25BD747FEULL,
			0x211B2A2EC2443A04ULL,
			0x246ABAE3742E517FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF37BA1C98E9CD018ULL,
			0x795D98FF61943157ULL,
			0x7419A6969DF3CD1FULL,
			0x5FCD53069F61AF98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EA614F8E77FFFAEULL,
			0xF59F48E10FF9CF1CULL,
			0x6CF296270270957CULL,
			0x23CCAD66FBE0FA71ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3393327CC9A4E476ULL,
			0x7BF870A96D681F1DULL,
			0x41E4A5834E38AED3ULL,
			0x18620A6A8ADC8149ULL
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
			0xC42D1D713081A5B0ULL,
			0x65BFE3DB07EB676AULL,
			0x2AC686C99509BBDFULL,
			0x47E84CCFC40BDBA8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB94B558BACD627AULL,
			0x22901851F5D732B9ULL,
			0xB6CE243F1AAEA753ULL,
			0x3D79B8064B40CE4EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8512AFB1EC7ECF30ULL,
			0xC21D345C845875E3ULL,
			0x6047D89BE5A4EE2FULL,
			0x7D79349DF0C27211ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC4923B95D7F560CAULL,
			0xAD18C4D7986C8686ULL,
			0xF71B545DF2AC6D2EULL,
			0x22B0737313D480E5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB28E24EF2F0DB72BULL,
			0xC9CA9436D804C9C1ULL,
			0xEC7D1FC0148550BCULL,
			0x19EFA41C69734B72ULL
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
			0x42538121473B6328ULL,
			0xE2B711B9765286FFULL,
			0x40A8D44956455A8CULL,
			0x510EF3563C0AF4DFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE59F723D10D1A8A2ULL,
			0x20B3FE31909245BCULL,
			0xEA7B651456167DEBULL,
			0x555D1ADEC21C4D86ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0B488A145138EDE0ULL,
			0x323F5A6ED2C28CFCULL,
			0x11670A5FB9FFDBABULL,
			0x4C0AA4103C968C34ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x874F4C6A7344F031ULL,
			0x260692DA6838ABECULL,
			0xB83F42376E01781FULL,
			0x60D8308274FB687BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5830617BCEEC7BC3ULL,
			0x8D64F2BBB22A0570ULL,
			0xAD8B5A69FBEF08F9ULL,
			0x6A14632E1F605CD8ULL
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
			0x768161BF971887D0ULL,
			0x3DD176007BA14032ULL,
			0xA62A394C40916AACULL,
			0x54773C118DC2E59EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x11E4833FCB5B878DULL,
			0xB02301B69E5F6FE9ULL,
			0x4EE50FC0F6C9DCCEULL,
			0x486269064C3DD44EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF273E2F563294358ULL,
			0x371812119F17A38CULL,
			0xE2B9E9E6DD94C1E3ULL,
			0x61E83D2A84CE12B6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB16F86D21B17823BULL,
			0x9432A2BF6AE7D530ULL,
			0x312016E51FC648FAULL,
			0x14B817682072E66EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x397CFFAFD9FD7BE3ULL,
			0xEDB6ABFDED5B5ED0ULL,
			0x94A5EF5AC362F1BFULL,
			0x56FF9966BA486CD8ULL
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
			0x2AD3D83E2D251630ULL,
			0x5C37184638A4FB16ULL,
			0xAD5195B900BFF361ULL,
			0x782DF9E199CB3A26ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD0CB679B03BFF66ULL,
			0xA11ED7BCDE78D93AULL,
			0xE363A20A89EC3593ULL,
			0x65A8AD8B4296F7B6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x480C3AA27DF10448ULL,
			0xF96D2E6EBBF739E0ULL,
			0x5B459D5A98C31364ULL,
			0x55BD1E7E69D90C33ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2C76693D12A09931ULL,
			0x5DC9487722A5C70FULL,
			0xC8AD5F8C3A8CA6A3ULL,
			0x4AA47E1257BAC1A9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6433788EE9849DCULL,
			0xAB20E8585147DA91ULL,
			0xC200FF1EC8B216A1ULL,
			0x5C632B733C38C72EULL
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
			0x7A49DE23712D2988ULL,
			0x8DBB4D3736C23A6EULL,
			0x4B6B26B372473C6FULL,
			0x550D130128EE72AFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4B3ED789BC936C96ULL,
			0x408CC193BE3F4945ULL,
			0x633B95E036A18C2DULL,
			0x6FB57A7677C03274ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xECC01A7278A9C510ULL,
			0xAFC53EEC52489CCCULL,
			0x43EBAB56B3C48C09ULL,
			0x42DCC41E7F497377ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB91CFC8EEF208E92ULL,
			0x4587853691068DB8ULL,
			0xD3FF8513A22D5A88ULL,
			0x07E7D4A7129F9011ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1421FB2FA4916434ULL,
			0x8AF958CCBC95CDE5ULL,
			0xA072153D7D4C785BULL,
			0x7196DCB8C4AF4856ULL
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
			0x33EDF635CD79E610ULL,
			0xE93463CA9A59C64DULL,
			0xDA39C347B2C2421DULL,
			0x7CD526F6B325F1F1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x002773F3A40CFE8CULL,
			0x8A0DA9BB21DC0F94ULL,
			0x912642AAA3C9367CULL,
			0x07FD7CFE103A0FFBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB92A67025767E288ULL,
			0x015FA5A1339680D5ULL,
			0x2C85FE9E7DE3D873ULL,
			0x433FDAA8D366630FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF8F506C1842F37D3ULL,
			0x5FB01DC96852DDF5ULL,
			0xE348765E02A3F526ULL,
			0x41CC03A9DEFA3F2EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7F3D761FA7A691CCULL,
			0xD8E5F927BD7241A6ULL,
			0x95FD0B3271A656B7ULL,
			0x6DF2171A22831F13ULL
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
			0xEE6254C09ED726D8ULL,
			0x1FA4A273450EF769ULL,
			0xCE5908856AA5F840ULL,
			0x4B7FE1CE410ECE7FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1356DEC4EE720BB5ULL,
			0x69C7D05E99453F4EULL,
			0xC7E4C8AB9B55A764ULL,
			0x04306A2F4096DA25ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF1248CCA824F3AC8ULL,
			0xE5D2CDD072C89A38ULL,
			0x6C5681752A52FB90ULL,
			0x59D1A1BBD76ED5C7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEFB22625ACA4E8C3ULL,
			0x53A79EA3BA3AEB11ULL,
			0x471E156C1BE6AA4EULL,
			0x0C1B244BD56A07C9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC5CF4DA217B93F72ULL,
			0x362906EC1CA1F13BULL,
			0xEF2AD69F85032DF9ULL,
			0x64CCC12A21297148ULL
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
			0x2DE8EE8A8268FD78ULL,
			0xAD6660000542EBEBULL,
			0xB39F8E6ED57995FCULL,
			0x76C56D15BE8E439EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF5E377F4A4CA48B7ULL,
			0x2F964B3309F7FB62ULL,
			0x4D9051B725A7CCFAULL,
			0x13561488E4BEED11ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0DC426D7621E7860ULL,
			0x2150C8BF0E1C6F28ULL,
			0xC66D21D5B5431E94ULL,
			0x791D8AB2E4E3474DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x938416A319B98BC6ULL,
			0x8E4DEF220888CC99ULL,
			0x8BA9ECE8F8114B73ULL,
			0x7CFC7170A4015604ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x436B6F0C0ABCA07CULL,
			0xED607AB0D5B549CAULL,
			0x56F403DC69373B6DULL,
			0x54ED024756DFD351ULL
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
			0xA8D4AAEB27185400ULL,
			0x09CF0BBCA3BDC875ULL,
			0xB47B40968EC48432ULL,
			0x42EECD6E0E4B1C65ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDC8E31AAFB5FE3D3ULL,
			0xEDE9478419153DD8ULL,
			0x8ED68B333C065A66ULL,
			0x48B52E3DED423538ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4D3705E9163225E8ULL,
			0x2FEF93DBB492C596ULL,
			0x502DFD9B688FDB85ULL,
			0x66B6C6A4E68FDEE9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA94E52075226E8EAULL,
			0xE2F6DE839062DD29ULL,
			0x42B17C92383A49DBULL,
			0x1CCE50451C3AD3AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0A9AAAA51E257A3DULL,
			0x57A8FBB6CB2BE7A5ULL,
			0x461700A6FD76E5E0ULL,
			0x4652D4B1130C1AD3ULL
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
			0xFBA95118FB4DE200ULL,
			0xA1B82175275F62EAULL,
			0x4BD84404B07DE385ULL,
			0x4E4FE0804CFB2ED8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDE5BAAE44DB28E3AULL,
			0x771C9C7C4D9A55D2ULL,
			0x0A29460206D92282ULL,
			0x276496E1FD6894F6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6829E9A0E8B61B8ULL,
			0x3F693892805E14AEULL,
			0x23C665C6317E5305ULL,
			0x6FCC21557262D27FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0EF6DD522545B043ULL,
			0xA5DF9C5560A4F70FULL,
			0xC25B3A9E79CD6FCFULL,
			0x3F9004D264352E4AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x01FCA2F66ED07489ULL,
			0xF6C7097089A7EE4DULL,
			0x0259B57BAE608229ULL,
			0x4E713FCF553AD849ULL
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
			0xD64DAC3AAF9AD3E8ULL,
			0x03131115C8031841ULL,
			0x70013D39245D9F21ULL,
			0x6A0C687964FB27CDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x640D22FF8E8F890DULL,
			0x59A919E2227C8EC8ULL,
			0xE1623729E0514FBFULL,
			0x12E38D7D4C2F6A66ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54860E232FE86358ULL,
			0x45B1B73CCC436DD1ULL,
			0x5F3FAC74C7EFE380ULL,
			0x7D67BC4AFD9101E3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x56380628BE94059AULL,
			0x0E1C4E07748B9848ULL,
			0x1D29DB8361B0C277ULL,
			0x2E16355920C94AAEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2F8786AE774BAED7ULL,
			0x2CBDC7D9B610C31DULL,
			0x27470BE03FCAE387ULL,
			0x61E6BEC3FCE5A0DFULL
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
			0x890BA969FAAF2658ULL,
			0xE7C1A22444B14AD3ULL,
			0x1C2E60C4B7CF5F26ULL,
			0x42D12B02A2589080ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x75C1D5EDC7600A13ULL,
			0x91DC9DC8E930D987ULL,
			0xFB4276B93912E513ULL,
			0x7FDB7F0D99009274ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4155F8FFD84AE528ULL,
			0xBD33638397E3896BULL,
			0x5221B1D64AD3BB63ULL,
			0x74A4F0872DDA149BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0EE259A25463B202ULL,
			0xDF429FB74085BF46ULL,
			0x439CF0683F4AED6EULL,
			0x4BAB4A7F0B25F82BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD70EA8086BAF6E74ULL,
			0x13564BBD3A3E818CULL,
			0xF98DFB895C5C4220ULL,
			0x57D842801B32A255ULL
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
			0x521F8E72E8C0EB40ULL,
			0x42B65E22BFB3CFEFULL,
			0xA8D95C2EEAC0753FULL,
			0x46D8D31BB8D72260ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7D1C353BFA1E7E5ULL,
			0x95C5B1131D9F603EULL,
			0x401A2EE7F233F2F2ULL,
			0x06D0F0CCEBAC689DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7811BDA26D384AD0ULL,
			0x20CB2D90EFE2C386ULL,
			0x112FD3888059A335ULL,
			0x6F81DFD935571154ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x783C2164D0648017ULL,
			0xEFA074B7E11AAF88ULL,
			0x1D238245D3F875EBULL,
			0x773AE0869067C83EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x03D2A1A91B8CACB6ULL,
			0xA923025488A50DBAULL,
			0xB41D946A0E0F12EAULL,
			0x13D369530ABD60A0ULL
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
			0x406F8D15614D7C90ULL,
			0x970C3FA5A231484FULL,
			0xBE7B3C0B4808B127ULL,
			0x65FC1C3EED4F5A0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA5AF5FFE162F9754ULL,
			0x45B80E5222F7DF0FULL,
			0x599313C1F09A24DAULL,
			0x7BE08BBEF7971977ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0292AF43DC9BC758ULL,
			0x2BFDA73C8E7A09F9ULL,
			0xF970F1A4D5A6C239ULL,
			0x764F8DBB60A21112ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x57257540473DDC7EULL,
			0x3E0D9EC9D3FD5312ULL,
			0x6A7C390B66615A36ULL,
			0x1497757114C93ACDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x902B4ED95BA79F38ULL,
			0x6A906D972E2F3F24ULL,
			0x8480C4084FAAEB7CULL,
			0x130FF45FF996F23CULL
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
			0x01315B48CFD3A9D8ULL,
			0x195EE48A5C1248C0ULL,
			0x00D3372F3DDE06E4ULL,
			0x6426BB3F11C54F05ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7FAC991AD83753ADULL,
			0x10EC234EA6D386C4ULL,
			0x5339D9072F66A845ULL,
			0x32980C59BF3A9D76ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x74189EF423651850ULL,
			0xCD872666A6128144ULL,
			0xA67F71EB010B8E75ULL,
			0x70369C1FBD5804E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4C81FCF385505A0FULL,
			0x28C50702AD28F46FULL,
			0x844E6A7797533A15ULL,
			0x3946CB09980A89DAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8BEC7B1C203C5F65ULL,
			0x9390BEE8FD043727ULL,
			0xCC94D6E71F650719ULL,
			0x48614D72AFA57261ULL
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
			0xABDB02E38AA740C8ULL,
			0xA88BED00753BD7EFULL,
			0xAD1BC255EB115A56ULL,
			0x6F79593902054CD8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x275DF8E4B78EE217ULL,
			0x724B869BDCEAAD08ULL,
			0x228C04CD24EBB7C9ULL,
			0x020AAC12A34BC065ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x91B2A3B31A73C830ULL,
			0x4B72B6861279375CULL,
			0x1018892346F84C65ULL,
			0x6A2A7D167C1806A8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3DC3A5B71E44761DULL,
			0x52B30EA6D8D46F0AULL,
			0xFEAEC48E51DFCF9AULL,
			0x5E264B2606BF867EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBA49A3D601685273ULL,
			0x6619F86B9063BB37ULL,
			0xBA58D949BA6D66F6ULL,
			0x46DAC6E1707F4103ULL
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
			0x8AF975C405C338E0ULL,
			0xE9E41732F10BDB49ULL,
			0x8A5DDFC06AC39B9EULL,
			0x5BDC722FF595927FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x052C7BDCC5EFC6B6ULL,
			0x1DDACF90697E11C3ULL,
			0x3D1DAC33CFE69E82ULL,
			0x0B0FCC28C698D77FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x94F9A97BEC3CF8C8ULL,
			0x49A73D7334413A43ULL,
			0x859A5A400F97D14FULL,
			0x7C0FF3519E458FF4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBB36921026C85C8BULL,
			0x6CFD6482783E621DULL,
			0x443DE502C907EAA4ULL,
			0x281724389DF9FFB6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2AD57FDEE3A5DDE0ULL,
			0xD67080EB1CDAA0B2ULL,
			0xC5C186AB9CD94317ULL,
			0x021799D54F8F2DEAULL
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
			0x302E4309F8F45460ULL,
			0xD39C6A5562A6C281ULL,
			0xECD46C581F26C742ULL,
			0x682578791F076E59ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x92EAC3AE47C8F9C6ULL,
			0x27081BD7AE72BD2CULL,
			0x5A8ED638A2B15B35ULL,
			0x238A30C2EA7AD897ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4088D469D26FEE80ULL,
			0x7569850A2A143657ULL,
			0x7D0CAF7F11B3B1F0ULL,
			0x4D77322E93513406ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8F390B1FBF556F6BULL,
			0xED06EF8DF669AD27ULL,
			0x501514B64C7183CAULL,
			0x1CA4DC5F76BE7BB0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBAA4601839CB11BCULL,
			0x87E8466D79DE451AULL,
			0x6D36AC41731AF62AULL,
			0x64090E11C1B3EC48ULL
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
			0xCB255679757EBDD8ULL,
			0x5154004004C3E80AULL,
			0x7F7CF52DF5F93DA0ULL,
			0x7EEE3109FF89251DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x12C92721A4A09C10ULL,
			0x1977CBD6B4E33E6AULL,
			0x7F56285C7A03CA6BULL,
			0x7FACB0945B2168D1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA60A3C6AED6AB6B8ULL,
			0xBD2AFF0F0E3C648DULL,
			0x694C14C88F498C97ULL,
			0x6D41A8C09AEF702EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x029B044A2ED95B87ULL,
			0xE4E23781F1436DD7ULL,
			0x94552983E9CC9F42ULL,
			0x44AB890BC2685CE6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1D9EDDDAE8E91008ULL,
			0xEFF84901BFD4461BULL,
			0xADAB361B35A1B8A4ULL,
			0x0A505C5CC5F32B59ULL
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
			0x3CFA30A24BDB56D0ULL,
			0xE1218964BE5C07C4ULL,
			0xDCFF86BFB2FF4ADEULL,
			0x6153E3F9A771C46FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x852EFC75958A4D0CULL,
			0x4CC4D56133B34CD3ULL,
			0xA668B552B9BCD551ULL,
			0x2BFB7312CA0513AEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD0670E9FA3881E98ULL,
			0xDC1B4298748C1F66ULL,
			0xB79FD4C08CB3541FULL,
			0x60A7B46F8EBA620BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7B53F04D691B7EF1ULL,
			0xBD99D67195857092ULL,
			0x9F6B141F9C7FA2F4ULL,
			0x6466E3203BE64BD9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0554BAD80D08180DULL,
			0x6A09CA6F2D987F4EULL,
			0x9D05B858FDAB45F3ULL,
			0x49FB1BB67C17A714ULL
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
			0x70CB9B8872701320ULL,
			0xF87A837D22D34BF2ULL,
			0xD587C69587F0E71AULL,
			0x7546BF113F1FC384ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x018CD91CA8E3EEF0ULL,
			0x47F6F0BF4191602EULL,
			0x54F44A775730A6CBULL,
			0x7169480B7D54366CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA28BE8021D3B1288ULL,
			0xF3DA99A3E8CA5ADFULL,
			0xB211F14355C508D6ULL,
			0x4FF8858B9880BB1DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2EC571A7644FF49FULL,
			0x49DBF0A1DFCB8378ULL,
			0x1BAAA0943C3846FBULL,
			0x284E532CB951EC65ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9A3BA00909ED21C0ULL,
			0xB60FBAFF1878CDD3ULL,
			0x3BDCC347A03F3F6DULL,
			0x3B4EFD3C2E0D7FEFULL
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
			0xC4775E656EAE4180ULL,
			0xEBB4E0A16541B812ULL,
			0x0294CF48DBD02CD4ULL,
			0x5F430E2ABBA215ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B909BF525EF138EULL,
			0x0C96C1DECDFEB50EULL,
			0x606B1D1EAD3322AAULL,
			0x42C5553F77F68527ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2E01EA42D885B328ULL,
			0x445E71EFE8738F74ULL,
			0x740931C1DB79B075ULL,
			0x7E5F5A5D8A4F5673ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1DEA06660704825ULL,
			0xA4CC55B4B0095175ULL,
			0xD0E4B2629C7EDC08ULL,
			0x3AADAF34BC0C92FAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD97544BA72E49C5EULL,
			0x25AD2B4CBE1C224AULL,
			0xEF4E330D4AC55B39ULL,
			0x30E04B7E377C4BACULL
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
			0x23201AB17C70D948ULL,
			0x3D3B47FF1897B095ULL,
			0x5F04764D7E0319BCULL,
			0x6693B2DEA1F79E50ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF505DF60663EF6DBULL,
			0x06115C3ABDC478E8ULL,
			0x9F3813BE86301FECULL,
			0x7BD60E14E015B90BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCEF13478452EFE30ULL,
			0x10B5AE8BE5D00795ULL,
			0x07921A1C1B119786ULL,
			0x6E28AB7AD0A338C8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x44A46B20D9ADFA39ULL,
			0xBD40478A73CD643FULL,
			0x3FD9055747F3BE3BULL,
			0x1C908EA5EC08B912ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1F366C911BA1257FULL,
			0x952D666128930A1DULL,
			0x2F727321CDEB0FB0ULL,
			0x083C4E61B84AAB4BULL
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
			0x13E0F45A76616698ULL,
			0x636DCF0737BBF4DCULL,
			0x1890804CBD195A69ULL,
			0x789C2C294D9482FAULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDAC4ECC86E73444AULL,
			0xBD6DDA09B57B68CDULL,
			0x65051BA0DCAE59A8ULL,
			0x0671EF63B88DB254ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0EB8D673D5DF1650ULL,
			0xE05A00FCBBBE9EBDULL,
			0x7D6924A8207BC168ULL,
			0x6E0F7C9030E6B125ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x65BAEF7D94200FEFULL,
			0x35EE3E78C5258449ULL,
			0x79423483BD5786E9ULL,
			0x3A19EEDDF39B0091ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8FE6FA603A8F6E31ULL,
			0xA4B4ACF17FC0D0AAULL,
			0x98660F57EE2741C3ULL,
			0x760DBE8D3607CCECULL
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
			0xA5F340C4DB2A3C58ULL,
			0x37220A3659A7780BULL,
			0x1EF5BDDC2B652677ULL,
			0x468AE3BE84DD0F9BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC93394D487F2634BULL,
			0x47A39C8428B11ED0ULL,
			0x7004F897112F0D8BULL,
			0x62C142597DD9D350ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x47B2A8982D90A0F8ULL,
			0x949CAF01FD8431F0ULL,
			0x80C5299505B30CA4ULL,
			0x7406E498D5099B04ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4545468D10F18202ULL,
			0x3A3BBCD0FD2FA0E1ULL,
			0xE084BF19E66904DDULL,
			0x20CDD37467F2EA4EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA74817A1EE35697EULL,
			0xF3B05B5713EAB8A9ULL,
			0x24FD57D439C4C871ULL,
			0x056CA12777815C38ULL
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
			0x0FD0B09AD5318848ULL,
			0xCB2D16BBE4947F32ULL,
			0x468FD172EAEF2A7AULL,
			0x71170FD11A1B002EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDCB1D20CAFEDC37BULL,
			0x5AD4EAC479D4F873ULL,
			0xB20FFB09778E3813ULL,
			0x20C0E3D1A98EF092ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x41CB6CFA0467F180ULL,
			0x734ED3AD7562F475ULL,
			0xA12306E53BC2D733ULL,
			0x5B57505F6FA4D105ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1E97F0098D208743ULL,
			0x49ABC2D74D1624F0ULL,
			0xCF09FCB57D3483EDULL,
			0x36211418FEA0CD44ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0B43B6A303A0E2BAULL,
			0x353CDE4725030C56ULL,
			0xB6B2DC05F84072D5ULL,
			0x0BB86112379BFB9FULL
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
			0x82CAA7F1BFEC4640ULL,
			0x9F1373802A557D8AULL,
			0xB9C81E57250882B1ULL,
			0x6D1B4361BCCE868FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D19706F18982CC4ULL,
			0x5782784C4570FF66ULL,
			0x5A2D9B9A89440FA8ULL,
			0x2735DC58ABA64173ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE9ECAFD824ABD4F0ULL,
			0x685E357A26BC6893ULL,
			0x8643D8B66A7D9357ULL,
			0x62EB125C8B47A80DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0F419CD697C8E3AEULL,
			0x74D1FD1AD4ABA9EBULL,
			0x6627621BF81FA9CDULL,
			0x5B7F4D6BBAB2CEAEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x386F04FBF6376D82ULL,
			0x38FB6FC078F789D2ULL,
			0x7E975CE555FA7A56ULL,
			0x7B9F41BA79365725ULL
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
			0x6FC3080FC211D3C8ULL,
			0xE6A6A9040F19BAD5ULL,
			0x70887CF2448CE3BCULL,
			0x65B318F73D6943C9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x240F17C425B2A002ULL,
			0xB3CEE7DC27EC2174ULL,
			0x6A006C83A2F5A268ULL,
			0x157E4C414D0F5F44ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A510A0E1A03EB10ULL,
			0x203CA18FE7AF8406ULL,
			0xB32396CFB729FD5AULL,
			0x7F2EE0D61FB0A5A5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2F32A1DA29B264A6ULL,
			0x68B7D27F4E18A300ULL,
			0xE25280693AC79D7EULL,
			0x57D1EAAACC6C56FCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4B11DFAC3B9D12A9ULL,
			0x03613A1FE18E2049ULL,
			0x08B06C5CAAEDF0F5ULL,
			0x1C30573BCEB9E40DULL
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
			0xEF8404DE7C84EF10ULL,
			0x5CF27D4AA60F8BCEULL,
			0x34961D53184478B3ULL,
			0x6ADC846C2BF92505ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC4387085395F363CULL,
			0xD5A7B95464E68E1CULL,
			0xADCF779C78FF4BB2ULL,
			0x03D9494EFBE071D2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF2B4CFE80E6C8AE8ULL,
			0x4EB171E2E9567C59ULL,
			0xE159CE2E29F4E4CCULL,
			0x4A8139FC1BFB6389ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6DD01978371D58A6ULL,
			0x5C3882F9A8C524D2ULL,
			0xC195336F8383CD5BULL,
			0x1370E4E4EEEA6A25ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x44739DF37B0941A5ULL,
			0xC50B79F4D8314056ULL,
			0x9287FD40B7EF5AB0ULL,
			0x3FE8D1297E34084AULL
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
			0x4120DD6BA4653B70ULL,
			0xD93A438A8CFAF2E3ULL,
			0xA74E8BFA8C2C044BULL,
			0x515063A8F661F8F0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x989FE519F3AFEADCULL,
			0xB812E8F8B6C956CAULL,
			0x9E119A4B03942B04ULL,
			0x1EC78F07936F3E23ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF197F269C00B11E0ULL,
			0x53930006ED2D8771ULL,
			0x134E0E84810D7E08ULL,
			0x44ECADDB72B1E556ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8A45AC7B4456AAD9ULL,
			0xAB1F1255A27264E1ULL,
			0x5A55636BE8FB8260ULL,
			0x256D9521D2AD9031ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x27F603AD0995536EULL,
			0xCF82C49BA3A95BB9ULL,
			0xD31343B2B55AD58FULL,
			0x61DC72018C3A8C53ULL
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
			0xE90A772037D69AE0ULL,
			0x7166B0F5E4C970CFULL,
			0xE9AACE13C53B9B60ULL,
			0x4482D693C9B9AAF4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD5FFE8187458A1D4ULL,
			0xD0F8CB19D32B5698ULL,
			0x051C99E5EA3BCEB1ULL,
			0x649CCD0CFEFF1792ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9BADF5E5F4656FB8ULL,
			0xB1990FF1CCD9FF6EULL,
			0x4EC5CCE695976D5AULL,
			0x50D9CBD81E3AF96DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF763EDACAB551DE9ULL,
			0xEBAA856ADC3A115AULL,
			0x81D70426ABC1A468ULL,
			0x6BA7B3676369470CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDF8DADB1EB38DAA0ULL,
			0x45DAC670A99E288AULL,
			0xE62167295C3274ACULL,
			0x0CDFE2C408365BA9ULL
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
			0x9FE98190FE979CB8ULL,
			0xF04CB5EB36EE169EULL,
			0xF6C4E86FB19D9750ULL,
			0x78CA5F68AF1162E1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0C104FEB7D0CC026ULL,
			0x1129B88A82E73FFFULL,
			0xB7BED970932D1D04ULL,
			0x2239D105C18E311CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBF5D0D85F7004BA0ULL,
			0x3A1DD0335635AFA2ULL,
			0xBB24676CF78FAC18ULL,
			0x66254CD206CDD6D2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5E7E05FAA40AA8B3ULL,
			0x2D1FFB10DB0BC4CEULL,
			0xB4E23FDEB2BEC002ULL,
			0x34582CAB82CAA95DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3708C198C9BE55FDULL,
			0x14248FD64D794486ULL,
			0xBB13477B56FCEB3DULL,
			0x45F808F643FE23A9ULL
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
			0x8E29D21E86B00B50ULL,
			0xE84D69C794C65A3AULL,
			0xC31203A3A7A1317DULL,
			0x4C696B9D7A4C08C4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC3912E68B046DFF0ULL,
			0x707707C84C89B280ULL,
			0x1614AD7127F56906ULL,
			0x7E77B4B746AA03AFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x828E6EE5863188C8ULL,
			0xC91218D8D4DD5CDDULL,
			0x53FFB75839E2C543ULL,
			0x52898262E947EDA2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x94BAB3B798C4BCAAULL,
			0xA6700D0A6B4A6BE1ULL,
			0x23F9A4BBE977A3F3ULL,
			0x3C7E38A2820E3ADAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1DB89439C2DA2564ULL,
			0xB699EB6F9917559CULL,
			0x3E438ABA0DAD1A1DULL,
			0x3AC40C3FE5366DB2ULL
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
			0x4531BB96616012E8ULL,
			0xAC03A2439629073FULL,
			0xBC16298715C697EAULL,
			0x64839E1CCD35709CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3B16EB6E3DC1DDE1ULL,
			0xD9C72FE3C856D71DULL,
			0xA3F23F8426DD0B90ULL,
			0x416E11C1DB7AB96AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x16154AD96591BFF8ULL,
			0xBC881C6F9F7C8D83ULL,
			0x327D8BD85D2BC6B6ULL,
			0x6EBC915F22747827ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB2E8C3786112AFCAULL,
			0x7535B928596730A8ULL,
			0x0943BD46F27182E3ULL,
			0x3F36490A122A9C81ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCEAB276C6635DFEEULL,
			0xEC4425690EC6C675ULL,
			0x2EC4BE53293004F6ULL,
			0x7AE9AA1E0ADFCAC7ULL
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
			0xD47AAF94F70A22F0ULL,
			0x721E35DDC15C2A86ULL,
			0x74DC27F81656ED7FULL,
			0x6C9442CF1AEFEA1EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9DF0DC58D3B6265AULL,
			0xE989109F2A84E9D8ULL,
			0x09C22751E2EED0D5ULL,
			0x7ED243FCF0B8DCA1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4F33BE5C81236728ULL,
			0x07BDAE3D16C94C0CULL,
			0xEECEFF2921D01609ULL,
			0x4269786700D397E9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x559757DFD2AF66E7ULL,
			0x64199C1F276AE0E2ULL,
			0xBA070535D5C903EAULL,
			0x17E40E729C89A852ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x82FC5EB8C924B294ULL,
			0xD7AC4439DDF9AD42ULL,
			0x65376B4B455CC1B7ULL,
			0x6DF43678E54F4057ULL
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
			0x00FCF3540F5EC1B0ULL,
			0x39312165BB559170ULL,
			0x9809DB8ABA112727ULL,
			0x5129088000D77C16ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3715CB72DEB23DF6ULL,
			0x991F93B841B636C4ULL,
			0x22AB15EF68371F4CULL,
			0x3FE19D4DAA7F3351ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6186DAE062718FD0ULL,
			0x1F6926813C8B32B5ULL,
			0xBAFD0349199B62EFULL,
			0x4431902C9C2ECFB0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA98F6088DCAF6C2AULL,
			0x7F6DDDC4C547E6D3ULL,
			0x82F513EED66A2094ULL,
			0x5789F90B4E9FD7F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D12A2086A59E36EULL,
			0x18F18559E81DABB0ULL,
			0x1E5EA94C1ADA6D8EULL,
			0x6376FF1AAD094DDDULL
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
			0x8E5D021CA0348CF0ULL,
			0xA37EAA55C23073D3ULL,
			0x572B4F2ABB6E24FAULL,
			0x488F96956438102AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD97BD0D21F1D37BCULL,
			0x397E630DC864FFB7ULL,
			0xA0523DCAD0F69422ULL,
			0x358C855A660DD503ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9B5DAC311BF889B8ULL,
			0x1A5A19ECDC654A8AULL,
			0xCCD4F83953A76984ULL,
			0x60217D492829EDAFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x90DEB1C444AEDAF3ULL,
			0x7A412E7BF98964E3ULL,
			0xE848744DC2B300F9ULL,
			0x2F52170E2BD41CEDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5E7BF50D20BC947FULL,
			0x525CF7327B55ADD9ULL,
			0xC1260A23F37B43A4ULL,
			0x19946A932FB15E62ULL
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
			0xD351D5AF6DAB8F50ULL,
			0xC060BF2DD0065940ULL,
			0xD02E2EABC29A75D1ULL,
			0x6124E439A7C83BC1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBCE117F31DA562E9ULL,
			0x6005E2AB9030FB96ULL,
			0x4D4076CE63E7B654ULL,
			0x4BD5E7D2BF5F6DE2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x33D72167AA778BF0ULL,
			0x6FE7E8DD5779BECBULL,
			0x2327B114BA432890ULL,
			0x728EB776B74E7193ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x05818EF9208CACB8ULL,
			0xF69E969A4D156C41ULL,
			0x3FBFE2E637711222ULL,
			0x62114E051679052AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6A9E00A91881A50CULL,
			0xF29AAFD741ED620FULL,
			0xE522D8A1D68404A7ULL,
			0x3F5B259FAA643501ULL
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
			0x341C97C33AE387B8ULL,
			0x91E398BF80D3E66EULL,
			0xDB2B3E4E2A14E655ULL,
			0x7AB9D397B42F227DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE4BAD0D908611650ULL,
			0xE6A61423D8DA1B72ULL,
			0xB9C35D333837BCEDULL,
			0x7033FAD4BEBF1E29ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x26CEAA4FEA28FEE8ULL,
			0x5A14A5A5BE3426C5ULL,
			0x2F1ED17642A81016ULL,
			0x5C635E13F8D8D663ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7C29A554A1073821ULL,
			0xFE2F10C74103ABDFULL,
			0x091FF549ED8829BAULL,
			0x4FE85E23A73BCE8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x710DB69FCBD850E2ULL,
			0xD8EE2384C42DCE77ULL,
			0x11D7E5B0A048FAFAULL,
			0x4B0917FACC2544CDULL
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
			0x0E503A9A9B0A7090ULL,
			0x3325AE8B0E5E2A54ULL,
			0x4E538856C715D897ULL,
			0x5278760B91499EB1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7CB7F5FAAC94D698ULL,
			0x37F87C6C78A1103EULL,
			0xBE99E395FC75F25EULL,
			0x0ECC9C9F62DED253ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBE9DCB7C231E4760ULL,
			0x0DC4C9C9487D8726ULL,
			0xB01E1F33A1289407ULL,
			0x602194716E9811F9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF64846C89AAA50B0ULL,
			0x2FCDB60E24474422ULL,
			0xACBA0EFC7CE87B64ULL,
			0x29D8B158B12CD900ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA2A816DD57E2C282ULL,
			0xAFA77EEC8055A08EULL,
			0x369014A03A3EB87AULL,
			0x5D8C9A45EBF3EA89ULL
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
			0xD2E01E68D8184878ULL,
			0x8D565D6CFE145DCCULL,
			0xEC50B1EC846129E3ULL,
			0x63DFB65396A6BA6EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1B59F598A5E41C7DULL,
			0xB91FF8CF65B37251ULL,
			0xC4B98CD6A41DEB68ULL,
			0x7814CC5D26B0A353ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x030CE45949A882E0ULL,
			0x8BD970C2FBB4D5FAULL,
			0x21DC99CA719C0F47ULL,
			0x575B0D1D64B72949ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x31F9A4AD88DABD3CULL,
			0x96FF44095F0D2F3DULL,
			0x38BEAF098D9C3F75ULL,
			0x31878CB7D498D645ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9D0ACB746153C80FULL,
			0x9436CAE6CEC12F34ULL,
			0xE9E60073098B8930ULL,
			0x4F6E26C947E4EB95ULL
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
			0xFAF92F8F654C7BB8ULL,
			0xEC7B4516DB1CDD9BULL,
			0xD639D66A1EB8F8FBULL,
			0x68B8F572F9166B6EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4F9C450F52905433ULL,
			0x89176270FE0B04CCULL,
			0x59FD7F9245FB2231ULL,
			0x7F0EDA625D027C1EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x04C56A8F7B847C08ULL,
			0x851F435CFFC78108ULL,
			0x32F63C9B523D80B1ULL,
			0x4AA411C7745B3F77ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCBC8851581DDF188ULL,
			0xF6E53617026CE63BULL,
			0x0D2AA7570D965AA2ULL,
			0x375FCB79E83404B3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA360EB8FE6C78FC5ULL,
			0x1266C8E62C81016EULL,
			0xD249338626EEC147ULL,
			0x4219F67EFF547721ULL
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
			0x83184099B58A5EA0ULL,
			0x482A4A1D78E71641ULL,
			0x316D353CB92FD742ULL,
			0x51BB8A563E333BC6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF336B6B100A26E67ULL,
			0xCBB88ADFB63336DFULL,
			0xE7BE622599C9ABBFULL,
			0x61A6BE5C9943C882ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4697D090F22DE5A0ULL,
			0x0C179096837F1B5EULL,
			0xC1A3CC063A5C78D7ULL,
			0x64020D902271831AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE9DA6C79BF7DE5DEULL,
			0x4F8A08A2B79D7A88ULL,
			0x9F22C506B4B32CBFULL,
			0x55DD843171F1AFD9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x939493452BD3157FULL,
			0xC86C83338C7CECF9ULL,
			0x7240E995F66FC35AULL,
			0x4D1B06A52417D942ULL
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
			0x61671341F0F6F310ULL,
			0x19BBB9FB5CD2BF04ULL,
			0x38BD13F1F30D5394ULL,
			0x4017B71A30F4FA58ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA9E9A1A73BE5ABDBULL,
			0xFFA3D35DDF0B97B8ULL,
			0x622273EEF37E17A4ULL,
			0x2A256684BF6907ABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8722B50F1FF130B8ULL,
			0x5DF55AE4F2AFA499ULL,
			0x4FB210C4C4669E8AULL,
			0x4E91C70BF07287A3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9662BEC874CAC7E0ULL,
			0xC3EA633068BF1185ULL,
			0xA7CDD1F3BB5ECFC6ULL,
			0x2B5BFC64B6609002ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7B0DA12134775C1ULL,
			0x59628B61CC5D0542ULL,
			0x3D88B0022E69FE6BULL,
			0x1B9D3FB4F3949B88ULL
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
			0x5056DC0BE16C2BA0ULL,
			0x7404B401A89A0E8CULL,
			0x70F22214A50ECE85ULL,
			0x71E3EC36616668D4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x300DE6848D4D1FAFULL,
			0x2A4D7599D1F4ED93ULL,
			0x0AF564294B760C04ULL,
			0x710D97E9C40103FDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEE4B3C59B53278D8ULL,
			0xAB74FB3A63F04034ULL,
			0xD887A412E3B25CFDULL,
			0x5AEB53782EE5FCDDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF265102CFFE83EBULL,
			0x1B708C4EF09A5EF9ULL,
			0x77F9294223C4307AULL,
			0x0E1E223BED9423E8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE457A02749E7D503ULL,
			0x014FC8F51D936F3FULL,
			0xED51C3148E7A3F50ULL,
			0x6ADAF402FDA0EA39ULL
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
			0x60459D679B6A9A20ULL,
			0x49D5585FDBC00A1AULL,
			0x3941A222B904A42BULL,
			0x6B7C1845BE5F3BA7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x44468349FD700B22ULL,
			0xD1362CCAF1DB8192ULL,
			0x6D34C0B8C793C5C6ULL,
			0x36B9339E576A0DC4ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x912D0EABD51EB818ULL,
			0xB607B729D2A236A0ULL,
			0x0BA8188215D47217ULL,
			0x73265E8BA92BA390ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x05A27D6C78E54A0AULL,
			0x10C2892F2FDC7331ULL,
			0xA402754770CC07D0ULL,
			0x454FAEC3118F7BB6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1C946823BBA39677ULL,
			0x73562579A9458FC1ULL,
			0x3BC79445AB6AFEB9ULL,
			0x00C23831CE245BD5ULL
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
			0xD8B298D05BDC51A8ULL,
			0xE45CEB38218FC99DULL,
			0xD40E51568D6E03CBULL,
			0x6DD0FF5BCA0EF005ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1D981558218D4345ULL,
			0x2A11E7260F2754EFULL,
			0x43D82BF66F746421ULL,
			0x428541B6FB3CF52AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0AA6FE20EA897290ULL,
			0xBA216F293D06EA3AULL,
			0x9FB4193403660271ULL,
			0x434C8508CA99C700ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x862AFE74B28EA327ULL,
			0x24880DC1024864F4ULL,
			0x986F2C6A5D465B7DULL,
			0x1DADF5DC35354567ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x49ECEF1D335C5503ULL,
			0x3A5A5CEACFE71559ULL,
			0x9387DD36E6765813ULL,
			0x391FC13E60DFAB6EULL
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
			0xCA4AE4E589C8F438ULL,
			0xB1DDE08AF9855D86ULL,
			0xB8E3DEB6DF399E99ULL,
			0x5C1EAC2FBBE38C11ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0D1AA55E94948930ULL,
			0x0BA8E25B1CC3599AULL,
			0xA6DF9CC8CF1A7E0DULL,
			0x0DCECB9050BA575EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1EBA1CA6B5A35CF0ULL,
			0x8A80D823E1DE4B5BULL,
			0x1ACB0FCB160DDA17ULL,
			0x7E92157230712095ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1141702E0C34547CULL,
			0x18EDF66FAD1FEB02ULL,
			0x52D93756E1E5F068ULL,
			0x08EC8FD86C170A2DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEF44B77894933E57ULL,
			0x409E456482F63310ULL,
			0x81D12E1C67E3760DULL,
			0x21720713045C477BULL
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
			0x24CB741F68C75608ULL,
			0xE4ED700F5A3EEC32ULL,
			0xFA45167AA9FAA70DULL,
			0x488F5FC55CD5AB26ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x693BA50288709F93ULL,
			0xAE958EC1C3FE4E91ULL,
			0xAD57BEC784A49D05ULL,
			0x10B9A4068E316D38ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xACF304CC45E4E5E0ULL,
			0xF24A00DD78B7792AULL,
			0x702B2B07CC8810A0ULL,
			0x6ABE799480B76E65ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x43533C7B939C0E26ULL,
			0xD313782983E5AA8BULL,
			0xE2832308BF217889ULL,
			0x58CB0D7BFCE3C1FFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF9C621DFC83D5DA4ULL,
			0xD88CD24E021DF308ULL,
			0xE2FDAEFE2DE318CEULL,
			0x0C95E3F0A764431FULL
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
			0xE5480BEF22EA48B0ULL,
			0xF682EC16FF4CBB86ULL,
			0x8CC61F2DEB77E023ULL,
			0x4A11C3BD14CCF2AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA2C1DC40E15E9DA7ULL,
			0xCD661689AC5064F0ULL,
			0x4FD6AE53FC21B1EEULL,
			0x4AC678BAB3ED161DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7D44DC52EE1F5E40ULL,
			0x4D6251EEB5D5F697ULL,
			0xA3B75EB08948A487ULL,
			0x46BC21D49E2EB399ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC8E5AEAB5DB71D15ULL,
			0x899CDAECE90FACBFULL,
			0x91D3BC66024D2F28ULL,
			0x6A28CC50125CBA2BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1AC6657AD3A5D985ULL,
			0xFF067C74A759ED1FULL,
			0x63470F839A07ED6FULL,
			0x7E404CBF6B6CC515ULL
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
			0xEE96F6685E829700ULL,
			0xD2F1E921A051C497ULL,
			0x8C7B39CA26BB4A02ULL,
			0x76E6334635F6A2E5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3530C97E88D0560CULL,
			0x80BCF517D3C80DBAULL,
			0x2AC9EE11D99F5CABULL,
			0x7F10B1E9C49F78B7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA407F2ACD65C66E8ULL,
			0x9D5E293DE47AFF46ULL,
			0x642B322F15280883ULL,
			0x4DAA4B7C0B4B02FFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1C5C47AD272CD31ULL,
			0x50B6AF844CA5D012ULL,
			0xE04E3BEE01121B26ULL,
			0x5106A920840A0978ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x130CD16544936C99ULL,
			0x270B96DD0EE1BAE9ULL,
			0xED6CB1BB42B0499EULL,
			0x6665313051F9AA86ULL
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
			0x918FC64EC7CBFF88ULL,
			0xA8B8D8157A16B80AULL,
			0xAC65207BB2B6A793ULL,
			0x6DBCE69F268A23C8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB0B4A87F40A4F40CULL,
			0x110B3D894371DEBAULL,
			0x0B8E3470B28EA03BULL,
			0x7E898321144BEBCDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52CE673FE8E04D80ULL,
			0xDA233EB2DDB9014FULL,
			0xE5DFE96B16989315ULL,
			0x634378BB959CC556ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA234B037F9A87C17ULL,
			0xF26A20CF5E605A7AULL,
			0xEC7EEE7786AA0A17ULL,
			0x5ABA734D747E301DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBCFDCFBAB7E4DBB8ULL,
			0xD29067C5F496C9FFULL,
			0x4DE91F24E7DDF391ULL,
			0x5A4C6F047699A098ULL
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
			0x2226F468B2F31A60ULL,
			0x4C49778A49DC4858ULL,
			0x96B9269B331B8FC1ULL,
			0x51E52C957A0DD8A4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0295534B020D7FB6ULL,
			0x749B48D4A662AB51ULL,
			0x48FDAEC267D3A5E2ULL,
			0x72051C1C600E508CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9C56D1D9533EC730ULL,
			0xF147D79A8D0D485BULL,
			0x9434B1115CEF7A72ULL,
			0x4B2C02EBAF0C85BEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCFD3FC9510D5E9C1ULL,
			0x4FB0F17DE1CCAF05ULL,
			0xD1A23DC90A995952ULL,
			0x5583E039EFA5EC47ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D893C1D3A28DDA2ULL,
			0xF660C81810DABD2FULL,
			0xF49DC4457B077CCDULL,
			0x469719E3B7ACC7B1ULL
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
			0x797AA8E9660AFAF8ULL,
			0x25031F19FACEC6DFULL,
			0xAEA3FAD173EDDAB8ULL,
			0x6A11BF9908D3FCEDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B3ED79E429E151FULL,
			0x9766DCAACF52904DULL,
			0xE97B4EE840ABA1B4ULL,
			0x5D3480457775D111ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD7D2EB77F49C4ED0ULL,
			0xA46C8C62EDF547E2ULL,
			0x073939E5253D5CAEULL,
			0x496DC32D9C33B13DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA431E07C02BDBF83ULL,
			0x5AF46B39FF5AAEC5ULL,
			0xD7C936D1B6A8B332ULL,
			0x4D7B1954F9367BB3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6E63A13422A38D4ULL,
			0x207951805D661B41ULL,
			0xA9EB81B94612C4B4ULL,
			0x0C766B0F56F1B2C4ULL
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
			0x2B0838C4C2FB6788ULL,
			0xDD6308A60094274DULL,
			0xA018D823798BA4FBULL,
			0x5BC3C01D500417C2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5754F9A6AA91111CULL,
			0x852F1629942D83EBULL,
			0x4AF2008984BBC1AFULL,
			0x430A48D977D6CABDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3BEA785C5B448A00ULL,
			0x50A2FE8AEB1D3787ULL,
			0x33CB82B22A3BC1C6ULL,
			0x5EDBEC1E07F6C84EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCEF34755ABF064B4ULL,
			0x98EB25B791FC4CB5ULL,
			0xBA9D53DE976BEC27ULL,
			0x712DB2B3E9E94050ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC500718155F3814DULL,
			0x97EA1747D933C81FULL,
			0x55CC6AC0034FDDCBULL,
			0x28918E0A2B235F75ULL
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
			0x994D503BF7638E10ULL,
			0x5D5329E3A86CB1FCULL,
			0xB0278111A32F67D8ULL,
			0x7D710421FBB15E88ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x17A053BF6606F867ULL,
			0x559F5BFE8EE8CD9FULL,
			0x691280413D205516ULL,
			0x1BECED2F263A3F5DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5762AF9A7DE9DEB0ULL,
			0xC61847F75932DF54ULL,
			0x184980D0C34CFA37ULL,
			0x57D675EE5D7952A5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x84119C1ECF60C2CEULL,
			0xD2C80D46157F1F40ULL,
			0x07930FDDF867C00CULL,
			0x68B297CD39DD4D24ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE84E34234B3B1D5FULL,
			0xA96CC61935A3FC68ULL,
			0xF4BF977A9094A87BULL,
			0x704920A0BFE7AC47ULL
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
			0xAE2DB9B7E6A4BBC0ULL,
			0xFEC12CF7E3041876ULL,
			0x5CCACF869D7B15F7ULL,
			0x57A704EE4F2CEEE4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC1B42D3B4DB34F7AULL,
			0x5DDAD7D509772658ULL,
			0x86894AE5FD468749ULL,
			0x3E93FD225BE52138ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3B47107230D6B2F8ULL,
			0xFDFE8CD7B0294A1AULL,
			0x46AB96C2F43CA924ULL,
			0x4B7A15DCBD7058B6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0B35C49974347705ULL,
			0x9F055A0BFBB7A765ULL,
			0x5E7889DAD8BE2623ULL,
			0x0399A7E040F1BA44ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x830A67323FC342ACULL,
			0xC2F72640E03DAEB8ULL,
			0x2114A677E62343E7ULL,
			0x12D03B15E44D470AULL
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
			0x88E611A2178AB298ULL,
			0x037F7A199DBD2CB5ULL,
			0xC5EEDCBD36009A28ULL,
			0x56FCA0D230AD552EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x228141FA79AFF240ULL,
			0x4A7A9BE053F062B3ULL,
			0x8FB2D3A7A9947821ULL,
			0x77B74B0B625F7814ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x08BA874A6A9FA0C0ULL,
			0x11F14096FCBC141BULL,
			0x56F2F6CD76EA8AF0ULL,
			0x5F85D6294349E083ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7DC7A0C61FBE7895ULL,
			0xBBAC205BCE6D7EC2ULL,
			0x3DF17ABE26692D9EULL,
			0x5D3A132978D2536BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF084587B9B125815ULL,
			0xBE62607C9135C555ULL,
			0x82735FC7CA00C31BULL,
			0x176B17120377592EULL
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
			0xC1957E7A01EFACD0ULL,
			0x3D9B97EF972070F1ULL,
			0x867CBF2C93B95430ULL,
			0x75CECD895636101BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x560E89FC2698E7F5ULL,
			0x82CE7BA82897E3DDULL,
			0x667D0C5964F49A2BULL,
			0x5500495C1388FFDDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6AAE8F0DACAD7C88ULL,
			0x33305B48CA94E8EDULL,
			0x801C115D0F679141ULL,
			0x7AE520B7E55BFA5BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA924117D9140114ULL,
			0xEDD5C581F6AF7D8EULL,
			0x2A61D1438946BA44ULL,
			0x7FFAF5EFB6FF6281ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA38300F12C296C5DULL,
			0x98887BFE6BCA0560ULL,
			0x4784DB053F0F8DD9ULL,
			0x1156CAC4EE894490ULL
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
			0x6DC2C97E833E1DA0ULL,
			0x06D3E7BCAFBB9D14ULL,
			0x1AA5ECA2D39CE022ULL,
			0x75F7993D7E49C9D1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x17B273F1ADCC6607ULL,
			0x57C6AB9985769461ULL,
			0x5FA85665F3B5B8A3ULL,
			0x60076D22326C2E07ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2114E00A961B94E8ULL,
			0x9F976DA9A6242CF9ULL,
			0xBCDD0EE1DDE177F2ULL,
			0x71496EE52BC6EE23ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD2F39B9CC2002C05ULL,
			0x98CE6929918CD5B6ULL,
			0xEC7D3CB4FA811A52ULL,
			0x3E5B636EBA9D1ACAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAA37C5B06DA4D1E4ULL,
			0x878982C612D6F02FULL,
			0xC559671F2DDBDD68ULL,
			0x363F79C69D3830FBULL
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
			0x1574D9EF4C0DE2D0ULL,
			0xE73E7B82E358C3FBULL,
			0x654A4147CC74761EULL,
			0x45059257179CE2FCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA3CAB6141FE20C59ULL,
			0x40890BA52F179283ULL,
			0xCEFCAC3833FB4EDDULL,
			0x08A5B49A28F35605ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x350898399DD11608ULL,
			0x38EA58D21953CE07ULL,
			0xAF894CE91957A934ULL,
			0x7333488F37E68E3DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5FB8CFF3A9B0DD40ULL,
			0x4BDD052E6BFDB457ULL,
			0x2FD91276E33DDBD2ULL,
			0x7A734866B68C44E4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x299A394ED034B93DULL,
			0x3C7306BAB1426923ULL,
			0xBBB18715A3034279ULL,
			0x164D37E7AABDDDA1ULL
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
			0x63D1CF43FFA7E100ULL,
			0xB744758724F0E1B6ULL,
			0x35C79CC033765E25ULL,
			0x74867B8132E58430ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA344F8A83F7DBDDULL,
			0xF131BFDCEF2893D2ULL,
			0x244EE996931B8D92ULL,
			0x43DFA4E0B3B7555EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0829A7D377AA1F80ULL,
			0x1643EC284A1F757CULL,
			0xD63DF8D327CD6307ULL,
			0x78E1E8A69F177C77ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4C9C8690DC092B84ULL,
			0xE7A44406F4FA98DDULL,
			0x24E78CC80C3F5B0FULL,
			0x07711EC56CC40837ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF2EF0A75BDE50AB6ULL,
			0x1D32E0AA95A73DEEULL,
			0xAE42C6CBBA7476A3ULL,
			0x0D676FB22362C5F5ULL
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
			0xE8C573E8CF736A70ULL,
			0xF79577C57129A872ULL,
			0x88B9D59CA3AB0EF3ULL,
			0x7E8D7B005CEA5689ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x48640AEE6B5060C4ULL,
			0xA31FE91C4FE13383ULL,
			0x413D5F668F45368AULL,
			0x0E62F9C26BC3F728ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x02E6F003160C12C0ULL,
			0x3E26422904C7AD6BULL,
			0x9D635BD149AE09ABULL,
			0x4A25D448E81E1C48ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCC7003052F482394ULL,
			0x5242C01D4DFB7224ULL,
			0xC9D642430035E07DULL,
			0x74500590A22FCDDCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x13D444DF7C25D078ULL,
			0xB79632290E3F060CULL,
			0xC3F29F83701C10C0ULL,
			0x18D8EFEAEA14A21EULL
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
			0x042935BA24E333A0ULL,
			0x02BC2A3F324DE49EULL,
			0x4E8EFCE9849723A1ULL,
			0x43A9CBD86872BFA4ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0B1F28C5771F30A5ULL,
			0x468C029BB27498EEULL,
			0x4E4F54540C18C598ULL,
			0x64AF6C96AAFAB3D0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x06BF2073F22FD460ULL,
			0xD474A6393AAB5649ULL,
			0x62ADD0A32582F2F8ULL,
			0x4CE31A2F6068B769ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x30781625A80B2D57ULL,
			0x0389954E14385368ULL,
			0x6EAC7B21A533F2A5ULL,
			0x3DB9AE8E0EC915F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE7E81731CC8438D3ULL,
			0x8DEF3D4B933740C9ULL,
			0xDE86DF61BC8553A1ULL,
			0x232A928B66B884D7ULL
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
			0x01B647FD6BA9B9C8ULL,
			0x9CC2EAFA2426A74AULL,
			0x8273B202C04D09F6ULL,
			0x46CB7BDA0758EDC8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8431934DD224A29BULL,
			0x5A5E0512FAA0BDC2ULL,
			0x539B7CAFDCC883E9ULL,
			0x68284A649A419150ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F7B40D90EAB5270ULL,
			0xF06F5346A4BE1DEFULL,
			0xD8A3AC0694AAB5D8ULL,
			0x4B26A316281D97A8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x49ECA399BE37E4F2ULL,
			0xA34F982BDAA488F4ULL,
			0x71AB026A2C91A77BULL,
			0x1FF894FFB16135D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xABB9E98B79C88DE8ULL,
			0xAF85FE269B4C80B1ULL,
			0xE68B63B2051FFBF4ULL,
			0x0B0832EE78B18AEDULL
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
			0xB62CF3E99FBE3FA8ULL,
			0x5096162A98B2F518ULL,
			0xF5797746177AD6A1ULL,
			0x4E2C03DA8DFE5497ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x05F15F8B65B65B83ULL,
			0x5F67B37DB8AA0255ULL,
			0x8846AC0AE786D8BBULL,
			0x0739EBCF566D926CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0FC15404854CFD68ULL,
			0x885B3401D29F52E8ULL,
			0xED1A2840F81CF898ULL,
			0x46A927BFD832578CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD17B0B45D32BFD50ULL,
			0x3C4F2BD06EA01255ULL,
			0x29B13BA2C7040277ULL,
			0x098E5EDC2A21A881ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x31B36B57B0DA5575ULL,
			0xD59EA759F84C8587ULL,
			0x997EF26F6A223399ULL,
			0x34FAE29E7B5602DFULL
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
			0x3D665721C744E0B8ULL,
			0x5EE05DED8099115BULL,
			0x861ED921E4D914F6ULL,
			0x6B13EE02A77C914AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9E8A4BEBBC4FC5DCULL,
			0xB569E3E96BB9D8E8ULL,
			0xFA193020B323AB96ULL,
			0x33C740AC93EB41DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC4CEA5EB2F786F68ULL,
			0x7031D6F3FFE903D6ULL,
			0xFD7AE06B0A340882ULL,
			0x7D910635F57FCC5AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5B2F8CD3B04B9A3DULL,
			0x6DB44FEFAAC0C182ULL,
			0xE3A3F03AA21EF585ULL,
			0x33C989408D5A3968ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67B17B7785E2A486ULL,
			0xAD77A0B5947BADB0ULL,
			0x9C9AA813DBD1B0C1ULL,
			0x78166650DEC20716ULL
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
			0x842DBA590CA9E568ULL,
			0x48D533D7A08A30B9ULL,
			0x8D54100428FCA933ULL,
			0x4EF5FD465B2B5B3EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA5475354F1C8C2BDULL,
			0xB77C55B2D4219EC4ULL,
			0x717C635EDC37E5BFULL,
			0x70A95A513CB14B07ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x027E09095E4F1B40ULL,
			0x387006F61C1012BEULL,
			0x86C59255DCD5DBC3ULL,
			0x55D8246B19BCB6F1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x42414FB15467DC26ULL,
			0x95B46D54AB327B4AULL,
			0x7DB69D699AE44215ULL,
			0x3A917342618C6C06ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE64229CB96722C77ULL,
			0x4D50FBEE7A609FB3ULL,
			0x6F795F0FB389C3A3ULL,
			0x41801B0B629DC383ULL
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
			0x1F4C7905D0CB0248ULL,
			0x67E50D6EBFC6502CULL,
			0xAA03621524174257ULL,
			0x692F6960C6EE48BBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCE9977BCD67764A9ULL,
			0xC04ECB58F74874F0ULL,
			0x1142EECDBA6589C9ULL,
			0x7AEA572E22108A93ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5163104FB7F7EE90ULL,
			0xC6883290D06DB54EULL,
			0x3003813D540D8607ULL,
			0x7AAA3EA04251590FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x05C45E368A67B7E2ULL,
			0x5E5D96E0A1E09266ULL,
			0x6412ECAC4067803BULL,
			0x36C3D92089FD61CEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x23BBDA97526393B0ULL,
			0xD88753B9841B0A47ULL,
			0x04F2F4A090F0E2B6ULL,
			0x37EEE1A593587817ULL
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
			0x8BA512E4C0031538ULL,
			0x238AB2F59764446EULL,
			0x9EE6549342ABF5F7ULL,
			0x4C7DEDDD31CE05DDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D14231A051359C6ULL,
			0x0B5FF5687F233A27ULL,
			0xD3841AFC59B58742ULL,
			0x2A2223FF930E3393ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x51E386308D802678ULL,
			0x62E550A919D8E900ULL,
			0x6B6A613A26F0FCDCULL,
			0x56EA4B516AA82FE5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAA433594E22B23EAULL,
			0x27C2CC7640808CB4ULL,
			0xE03984C9F2AD6216ULL,
			0x640604491A7CB552ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF2037E24D95C05D2ULL,
			0x7BBBB363832A5E05ULL,
			0x1502A29963657ECCULL,
			0x6EF4D65D584D6A28ULL
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
			0x0A02F6E0F84AA628ULL,
			0x521526B07E71B232ULL,
			0x838FCD8669029713ULL,
			0x4C24E718B3EF96D8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5E31FDCE2E754145ULL,
			0x39CA7521CFFA176AULL,
			0xDAD5D2905FCC733DULL,
			0x7D2874249DB6B227ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2D4502A928B78278ULL,
			0x33DD2601CEAEE0F6ULL,
			0x9867D3F9FA7998E6ULL,
			0x631B94126E37AB01ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6DFD0BCF8BAFEC74ULL,
			0xE424E34455DA1458ULL,
			0x39C06344DF47312AULL,
			0x6EE833EB3824AF58ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2B999E7CA9412F09ULL,
			0xE5461F67D8E0178CULL,
			0x114FF38C36245873ULL,
			0x1CA2764E89FC0C6CULL
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
			0x224EF5759525EAA0ULL,
			0xABEAC1C6C071EBF4ULL,
			0x7FC62AC0F729BB6BULL,
			0x506A17D3D230EBC9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE37C7FF5A88EBCB5ULL,
			0xF66DDBB2F6B18E02ULL,
			0x88935B9662698A51ULL,
			0x709BB061E7B08B2BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x913E647620ED0610ULL,
			0x6C1F7D70ACC29E13ULL,
			0x095C4B13721BD4B8ULL,
			0x437DBF8FD63A4F4DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x80B65269991A7BA8ULL,
			0xFD26A3F5B65E008DULL,
			0x5C5DF4A0EF1B066CULL,
			0x09855357B081050AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0C7DBE8BEACAB9E7ULL,
			0x9E0C023EF31B9799ULL,
			0x6136039858D1671FULL,
			0x7C9867C3F3BF9407ULL
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
			0x527878D566341B10ULL,
			0x355F393CE47E5CB6ULL,
			0x9E86873070F9A4A9ULL,
			0x7A7DA94DC47F3F08ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x50EA73D6AFFDEE82ULL,
			0x3DC564F2FE6ACC2EULL,
			0x72B0197582AD925CULL,
			0x59A1EFD2FB6489B9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0CAF4693C8F68B68ULL,
			0x5522025DF00C6156ULL,
			0x01CACEE78CE904FFULL,
			0x6BFB0EB7BC7009E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA44527CAB205395ULL,
			0x2FFF6B9F90040353ULL,
			0x5AA43847B2B8A3AEULL,
			0x4DBE369242B58F76ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAEBB2E24C0B2DF1BULL,
			0x491C8CAA272FBFEAULL,
			0xEB533D72493A518AULL,
			0x644CBF6F3AFE1CEFULL
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
			0x8FD3F9D1D06CBDC8ULL,
			0x2148AC809CB39C46ULL,
			0xFA5F777F92CFFA1AULL,
			0x6DDD148355F3B701ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFE5E701EAA946995ULL,
			0x775C06F9413A6878ULL,
			0x691A959D55C7F90DULL,
			0x6571B384935F2F8CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB9D5E42086A27968ULL,
			0x26735FC0827F27B6ULL,
			0xB15F62C0C2BF9E2DULL,
			0x6D60D6A9C69CCAD5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6C164615A3BFF1B4ULL,
			0xB3EF5EADD769590CULL,
			0x25833339DBFD74ABULL,
			0x5EB35812507A115AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA82B6B818DF1D661ULL,
			0x5AFB30FE8198D061ULL,
			0x6FEAD0384CB51DB0ULL,
			0x48283F88D7794F93ULL
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
			0x9A6754D99EC30710ULL,
			0x1CF8EFB2C3CBBD91ULL,
			0x516EACEEF17A7E28ULL,
			0x463CDFE917D8F95EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x12DBD6BA34991ADBULL,
			0x21B0C72102C854AFULL,
			0x6677275AD96298A1ULL,
			0x65ADCDC723FDFD87ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4CA1FA71D0110D10ULL,
			0xDEACB4D27FE55882ULL,
			0x22056D06709EB76EULL,
			0x678F3C3478DAC04EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1B547FE157C800D1ULL,
			0x2E11B56BA4C406BDULL,
			0x8B90F01606FE35D5ULL,
			0x781EDDB12347192EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5ED14DC9E18F391AULL,
			0x606D77B85D923D22ULL,
			0x782589B745FB484EULL,
			0x380BBE92F1BDF750ULL
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
			0xD724372BBC584D50ULL,
			0x081524F024543C93ULL,
			0x4970620D07E6433EULL,
			0x7B2F8E9AF6414F54ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9AC973EB63C93EEFULL,
			0xAE69C044289530FCULL,
			0x9A10161BC7D352FDULL,
			0x3F37B7EBCE6B2F41ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA0A15AA88EA59BA0ULL,
			0x2BF2CF66056D04C6ULL,
			0x7212C1ED8B78A381ULL,
			0x54BD98C546CCF7A2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x90ADA94BDB6089B0ULL,
			0x1F1D9A83ACFD2336ULL,
			0x1C6449D73C1218B6ULL,
			0x21ACA0AAC433DB1EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED4CE9DDA67BC99CULL,
			0x8ED7ECB936065F31ULL,
			0xC06290DB280A9F13ULL,
			0x242EE0BB3C07A932ULL
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
			0xC3962DB71EF14698ULL,
			0x6E6CC80117792CD3ULL,
			0xB699BC4716606911ULL,
			0x4460BF74C1AED53AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1089DDEABA959DD3ULL,
			0x3F11DD374B2B1C0EULL,
			0x486031BDCD16F1EEULL,
			0x2942AF0988F755C3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB4F6090DC53BE1F8ULL,
			0x613259401E5816EEULL,
			0x93FAB6841C6DAB46ULL,
			0x5BBA5C262779899DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA70925A1278CE7DULL,
			0xDB7BAE959943C4D2ULL,
			0x8CA51930F3AB4D48ULL,
			0x7C7EF373302D65FAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x335D5C05CDE5484BULL,
			0x10309316F5349395ULL,
			0x0A15CB5432E52062ULL,
			0x3A89311428D50083ULL
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
			0x5D1413EE1F7E0730ULL,
			0x77EF650B45172827ULL,
			0x780AF97DFE07AE73ULL,
			0x577C98E305C6B13DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x397CE03801C7B0C3ULL,
			0x8332F48D40C5CB4AULL,
			0x46FFC8AF15AD35DBULL,
			0x439FE1ADD6B1548AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x60FD3C6ABB74ED68ULL,
			0x7AD90E4E438BEA40ULL,
			0x3D77C39DAB31BF41ULL,
			0x7293E814E410BB2CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA29A78F8ABD11FF9ULL,
			0xA94DCADB4BE7B995ULL,
			0xE7A80C6056AAB46BULL,
			0x049892ECF7A96847ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA30B1875BAF4E701ULL,
			0x044290834103B2F2ULL,
			0x585F0AB1AE3A34A2ULL,
			0x0912AE053BABE41EULL
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
			0x05ADEA395BC683F8ULL,
			0x04CAD7711419FDB0ULL,
			0x2FC06002F3DA134EULL,
			0x75207BFC5F542B5CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5474F0D520132E26ULL,
			0xECC3C65ABD9A65E7ULL,
			0xAC42C0750EC51F63ULL,
			0x4D17A4D636E09BC3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD35A7E1499695268ULL,
			0x1A0C383CEFB0CD91ULL,
			0x9BA522C6EEF10821ULL,
			0x526E639F08419731ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x12B9280E3980114BULL,
			0x90AA74F2E814FA7EULL,
			0xE580A73ADB837576ULL,
			0x1F1E115999B5A409ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x669FF4D8F6725F6BULL,
			0xB0C0E965CEEA0513ULL,
			0xCC2427679B12E57BULL,
			0x40319BF2A8D15D13ULL
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
			0x798857E0C8725C10ULL,
			0xD1E8B4837C9458EFULL,
			0x57B50DB372856EF6ULL,
			0x62EFB243F97D0F4BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF7BC447430C2CACCULL,
			0x133A5B3159104FCDULL,
			0xB414B031F533E8BBULL,
			0x68AC876773093F51ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCE435433062CC810ULL,
			0xDE8AAA08F54A5C50ULL,
			0xA145CF2C45BD964CULL,
			0x601532E78514B3F7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x62C055C3ABCEC940ULL,
			0x3CFAAA21C3436BFAULL,
			0xFF32A1D51B295B4AULL,
			0x6B6BB46A5DDF3303ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDEB122615E6A1C0BULL,
			0x597F68B405C3FD27ULL,
			0x0AB969FAE8096852ULL,
			0x18558567C80CC098ULL
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
			0x3A149AE22472FEC0ULL,
			0x7B37C54D380E8712ULL,
			0x724DBAF28CE426FAULL,
			0x5F22223EEC1C96B5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x51B9145B6206FAD0ULL,
			0x81F3FF24A16423AAULL,
			0x8AD95B608DAC1E7AULL,
			0x3E36A7EBD6F3FB9DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1F117C6DC784C450ULL,
			0x860B82AC4FC7B7B3ULL,
			0x15549009BEEB7FB8ULL,
			0x4A869486332A8E02ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFB7E05B1B4BEB21AULL,
			0xFCD5BBD9E5F38110ULL,
			0x4767658A42ADCE26ULL,
			0x0BC4CD5C531E2138ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x31D3FF5340467594ULL,
			0xC9CCD35976ED0572ULL,
			0xFB0D6715878F14F3ULL,
			0x414AC864FF4CD96CULL
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
			0x50827D1917240A58ULL,
			0xE99440E24A43020AULL,
			0x38539C2A905F8F7FULL,
			0x66892FF9D6391239ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4EFE746623F65360ULL,
			0x399D654AAA69E2A4ULL,
			0xA4FD4D27CEBD2CBEULL,
			0x3599CBD0C67A1E65ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x723E8CFBE52D5288ULL,
			0xFCEECD80393A5DBCULL,
			0xD2EC500B48C32958ULL,
			0x7993380F8A52C97FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x43CE6390F5D17C47ULL,
			0x96F538C67A38C30BULL,
			0x4E1083FDC696E74CULL,
			0x64594011C5BC158DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5DD1B5BD8849842AULL,
			0x8D1A97C940BAE64DULL,
			0x769E569EA3B14CD1ULL,
			0x4684A3EDAF46B97AULL
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
			0xAE73C31A01F87210ULL,
			0x5902E2519C1D79D9ULL,
			0xA295150A3C6D8AA2ULL,
			0x5DFFB7CD53846370ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEA9FB08955B94C9FULL,
			0x987DF9F0E38C9C6FULL,
			0x1C333B37AFB864FAULL,
			0x06B755E4B6A2524CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x41C07CA0F75B2EE0ULL,
			0xBB02FEA3F0EBAD9DULL,
			0x8293B1EE113A49CDULL,
			0x72003F710691E901ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC00D2CDCA7B25828ULL,
			0x8CC8432FE9D89287ULL,
			0x1E2E4432433F9379ULL,
			0x12732B4B7089C96EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x171EE9C83232D170ULL,
			0x8CE8AE787324B644ULL,
			0x16DE6B64F4A413BEULL,
			0x539086EE4CBC0BB5ULL
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
			0xB5738B5B5FD7FB40ULL,
			0x8BD2D0E65615C446ULL,
			0x47F19C04EB5E1DCEULL,
			0x42086F5CEE1DAD7EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x67689228AB072B07ULL,
			0x88CF94342A4F3357ULL,
			0x1B5FE8672B169BCFULL,
			0x3F1E024D96E7EE8FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x608BD8A1BCB45A68ULL,
			0x9842E00E1A012C38ULL,
			0x110C9CCE00CBA2EAULL,
			0x6B839D3DF178A62FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEE84ADD3780AD954ULL,
			0x6FA57E9A8E49B6B2ULL,
			0x474A05AB027BF49FULL,
			0x20CCB2B6F2C9CA21ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x89F37FEDF4417B93ULL,
			0xAF55876CDA4A30F2ULL,
			0xC67A05B0E8621F96ULL,
			0x48A03B6A28282E15ULL
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
			0xBDA5E99A9CB216B8ULL,
			0x553D058D315AFF28ULL,
			0x4E45ED6E87C41F28ULL,
			0x6E7295A0AFD72C0DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDFB90BEF3B85AB2FULL,
			0x648E153F632A8ADBULL,
			0x4273A4DFC8ABB16FULL,
			0x5CB22667136AA3DCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9F369CEADF2377D8ULL,
			0x7992204806BD00EAULL,
			0x22ED6B8B5804DF84ULL,
			0x7F92FF7235961E32ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0E614E7774B1100CULL,
			0xD08AD29044A4235EULL,
			0x8FB463EF62DC964BULL,
			0x1B44EC44DFD1BC7EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6E99FAD2FFACE4B4ULL,
			0xF4C3E719F90F18E5ULL,
			0x6F11E4372D0BC3ABULL,
			0x0403315A61CCA92AULL
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
			0xEEA2C31264A986B0ULL,
			0x5A2EED28135CF8D4ULL,
			0xDC28796827532611ULL,
			0x6BEDF0099E6B8771ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9DACD0F23AC597A9ULL,
			0x62B53D6EA90EC775ULL,
			0xA0517CE6DAB97E70ULL,
			0x2DE3A7E0EC9698F3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x42C014C14F988D98ULL,
			0x23E62F816B4AC18BULL,
			0xD950C56D315D920BULL,
			0x41587605D96A9B49ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0263777DF8463769ULL,
			0x770A4A6F847C722DULL,
			0xBD124961CF339F46ULL,
			0x6C4C10B6D55D5D8FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x91F43404DA9492EAULL,
			0xD0389A323DBFD169ULL,
			0x8322887DC4608C59ULL,
			0x59DEDF68791C3556ULL
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
			0x0989909264940698ULL,
			0x28D7A9C2808C444DULL,
			0x449868F215C0B0FCULL,
			0x479C75FC0265E42FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6A1154DCA4B72F59ULL,
			0x00A1CEEF5112B5E2ULL,
			0x167BF1CC4CAEEC84ULL,
			0x6D9234C794448C2FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2096A3ED4FCE2BA8ULL,
			0x25FF3AE10EF80CA4ULL,
			0x2416C254C5C3597DULL,
			0x7955920FBD9C1899ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x690B0B1E70A17B55ULL,
			0xC45B09502DFD4E9EULL,
			0x0B34782E4EF9F56DULL,
			0x792581757908B44FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4E99C854CCB1B93EULL,
			0xD4106CEA3E0DF7A3ULL,
			0xBBD2ADDCA06D75BBULL,
			0x1ABD1A2E4739DD6AULL
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
			0xA267AB3243B3DCE0ULL,
			0x45F0779ABF9AC235ULL,
			0x9038B0E431935AF4ULL,
			0x56F650D08BEC515AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0D667FC67D7B6F4FULL,
			0xA80003D9F2A516ECULL,
			0xC3682C412AA80F70ULL,
			0x6584460BD50A3CDDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6EF6BECA33077B98ULL,
			0x2001F4CB3EBCDAF5ULL,
			0x25216C0C96CEC069ULL,
			0x6A8460EDDF77F995ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB341721432DAB4B9ULL,
			0x7A92E3D3C671200EULL,
			0x41E8CBDF97AC3518ULL,
			0x62F72417070E7500ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2BB8065BCCC4882BULL,
			0xEEF9302EB66B6654ULL,
			0xD2871B590D389E70ULL,
			0x6D4F18ABDD6C13FDULL
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
			0x64079519F041B3D0ULL,
			0xCE20169DCE730E7FULL,
			0x492F74EF0183692EULL,
			0x5B4A730D164BB48BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x3A71F62C78918150ULL,
			0x27A5046F4A043E6BULL,
			0x0BBE21B60BF5A597ULL,
			0x7864016A77FC563AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8FE79F690AA4BB58ULL,
			0x2227B2FFB468DFA7ULL,
			0xF3163537F3608EA6ULL,
			0x4D17F09DA5395383ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE900EBAFE3A63FEDULL,
			0x7B0B128F24B68D74ULL,
			0x6A66AF65397166E7ULL,
			0x66CA54C0C814F5BAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB0700B7F4FAED19ULL,
			0x3039DCAE970EB64BULL,
			0x365D81D5CA7AD700ULL,
			0x138DF2497E4F1F33ULL
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
			0xF5A01591824AA7F8ULL,
			0xF03B43D67AE8A0E3ULL,
			0xABA6F9EA603177CDULL,
			0x7A42DDA07A8922E8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8D04C258E0084A31ULL,
			0x4BB2811CF97F73EAULL,
			0x773C96EB7633B8B5ULL,
			0x2C4415376CB100DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x735FCC7680772190ULL,
			0xC48C0AC5AC4A84F6ULL,
			0xD559999DBB27A09BULL,
			0x58ED88D2CA6F13C3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x83382D9A3DFC0154ULL,
			0x14764DAFA1CA8AD2ULL,
			0x5810C1743CB0155AULL,
			0x2AD03ECF224CF354ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7EC7CAF0914A0ACFULL,
			0x3442734F5AA18B19ULL,
			0x7192F855CEB5C846ULL,
			0x7681A724B258709EULL
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
			0x6706AD57D8EBE648ULL,
			0x5CDA8B41671234BAULL,
			0xBA69DF6BAFEEEB98ULL,
			0x5D7C1C8BF4B4FC4FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC4425EC07BDF7848ULL,
			0xFDDD956DD972D131ULL,
			0x1E7ECBDDAE94A851ULL,
			0x422219981C37FC69ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9BF5A5B5235FC1F0ULL,
			0x9A33B1A75728C672ULL,
			0xB125B4207A3B02F9ULL,
			0x40E023883153CDADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA7740ABA80263F67ULL,
			0xDF2988EE55BAE383ULL,
			0x63F44A6186F5E87FULL,
			0x59F2833B9D8E17AAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB3FEDF8AE6CCF965ULL,
			0xD3EFE63E1B73B2D7ULL,
			0x2E067DE679A436E1ULL,
			0x482A8DE83D23762EULL
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
			0x3A435F4DFCEC1E38ULL,
			0x5A95634464B2E5A8ULL,
			0x57EF33038AC21F88ULL,
			0x45CA71B60AB11263ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA14DE711D460C0AAULL,
			0xCF6D560065D46FD6ULL,
			0x36CEA2DD1F85DA7FULL,
			0x6925002288E57700ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x84C9B5BBE4A89430ULL,
			0x4C16C31C9A0D0E9AULL,
			0xD332A4106AC271EBULL,
			0x6FC89342D04734F9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x71197481D29DAC4AULL,
			0x5020C75E38631EA6ULL,
			0x2200710A303C2C0AULL,
			0x66C6F9DF4B4F68E1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6167C8F5E5AF9E7ULL,
			0x5CB5F6A3D88FC907ULL,
			0x127DE9FE8D10ACF0ULL,
			0x03ED021C82C498EEULL
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
			0x5AC4F1AF739053F0ULL,
			0x2D584DB85319BA53ULL,
			0x00EE13A1D3CF9E14ULL,
			0x526FBB134260AC5CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8069D4C936B265BBULL,
			0x42068B54E05DC63DULL,
			0xD3A640676560CF9AULL,
			0x560FC783A233F49FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x30D18B3297FB2188ULL,
			0x20CF8EB095227D00ULL,
			0x598AD20E1E9CF9B0ULL,
			0x6F41DE1607504719ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x065A0DB8B3A1F459ULL,
			0x5E49F07AD3CEA899ULL,
			0x3E0704A54CDCCDD7ULL,
			0x42951B9619AECFC2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x70DF486F1817BF82ULL,
			0x5F5DA6EE997BF9F2ULL,
			0xA4C6BC9361FABB69ULL,
			0x3B9852819E9A5F06ULL
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
			0xEE03E515C6682D30ULL,
			0xD0AE566160BF481DULL,
			0x69FE0C94093ACFD7ULL,
			0x57601C24310FB3C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9C64DEDF21AC6182ULL,
			0x7F9C19EC15F86779ULL,
			0xDC43BBF206821F13ULL,
			0x704044B8566279CEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5C6E25E654A91FA0ULL,
			0x931C8DB6417CD776ULL,
			0xC2677982480CA280ULL,
			0x671BE2085BF2D3CBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9ADBCDA01743F397ULL,
			0x1CE61D162E620EB2ULL,
			0xB73EBA54F2F89706ULL,
			0x4EE703FC0696CEA8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9F0E27E62D9DE109ULL,
			0x8F884B6A1CCBE3A3ULL,
			0x7D2B08B5DB40F73DULL,
			0x3280677241912081ULL
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
			0x3B69885BD164A558ULL,
			0x852315DF8153882DULL,
			0x17C725D2F73EEE6DULL,
			0x77D65C58490FFC74ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFF3495C849AE17FBULL,
			0xB63202030FB73396ULL,
			0x255A0E91C016401DULL,
			0x635EF0B0142AA75BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC8AC6A5C0A16E940ULL,
			0x04B67DA656B5C26AULL,
			0x60989710D965BE11ULL,
			0x43D83843AB2C8D28ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x121CD390394F72F8ULL,
			0xF03D89DD47956CF5ULL,
			0xA6DF477D3ED8A637ULL,
			0x16BCEC1F76F605CFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x80922BAE76370BB9ULL,
			0xAF91A0FF84894F23ULL,
			0xB89CBDA8682D46FEULL,
			0x6B9516476D98BEE3ULL
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
			0x1BCD99A0026F51D8ULL,
			0x2CAE40E50BBF6CABULL,
			0xD2BE3362D1FFC955ULL,
			0x4BFEC632DF01714DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9570D562C2B944B9ULL,
			0x29E8E2371D2F92A9ULL,
			0xF4990B751FF0B93CULL,
			0x2585BF5D3BDB8028ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x12399431E1122DE8ULL,
			0xA3DCF4A9F2E62B36ULL,
			0xD2EA243DFCCB34F2ULL,
			0x5C64FF47D50451B2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE0B1BB4F075B1699ULL,
			0x0882BEF034295180ULL,
			0x0B5D61F368BA8398ULL,
			0x4531F599EC2403B5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD0F6908F0E581B35ULL,
			0xE75ACD50A74C3655ULL,
			0x11C944A784202002ULL,
			0x74828628302CD176ULL
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
			0xB9F234FA84ECCDC8ULL,
			0x917FA0AA12586B57ULL,
			0x74488E0E84D01B98ULL,
			0x4BD072BCEE4DF474ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF44B7B8E2EB621DAULL,
			0xA1118DB7F06C9FCCULL,
			0xE6538F52F3D56147ULL,
			0x1073F4273AAE2DF5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x394AF4104E613580ULL,
			0x8B59FF8CCE6F09DCULL,
			0x136359174E1572ADULL,
			0x5C06A515A057B5DBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0B4EF42EBC069700ULL,
			0xD1997FB5386431BDULL,
			0x65017B1933093776ULL,
			0x31904EE01D32F564ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEDD1979358C85172ULL,
			0x8F1AA34C468765B1ULL,
			0x84D6B65DEACF2502ULL,
			0x6F305B52739D3F50ULL
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
			0x809A5B16F5162EC0ULL,
			0xAFF99FEA86D02B08ULL,
			0xB06C4FDAB20BC91CULL,
			0x64FF183E03F1BE13ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB52FB5443EB882BBULL,
			0x43628543FF086915ULL,
			0x6F342CA0074E750EULL,
			0x45058947BF1C81EAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAEF21528FFE84418ULL,
			0xBF9BB7EC032EE09EULL,
			0x0F05A9BF46C19D1EULL,
			0x5C0017A658734685ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE68A926C88C8C970ULL,
			0xA0D3F4AC50F1F088ULL,
			0x4D98005197D63A31ULL,
			0x5227AA7B273AD264ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x949296D8B45AC4D5ULL,
			0xD37F6BFDE1A8BCE4ULL,
			0xF42DFD1B855B71C2ULL,
			0x0A562B8E71AD8AF2ULL
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
			0xC9E69ABCDA8B13E0ULL,
			0x7C6D55ABDFC5A661ULL,
			0x461E39182D951853ULL,
			0x51AE4F8EC0F93795ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x38B022C21BF63709ULL,
			0xBFE53FA80224283BULL,
			0xD08974390DA4428BULL,
			0x51F90609E2A40681ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x95C97C328BAC99F0ULL,
			0xA4BBE9FEC2B5EFFEULL,
			0xC49A768A20255645ULL,
			0x639889C063DC4709ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8572DDAF4367C3BCULL,
			0x274616862752C97AULL,
			0xFB4A4742EDF30A10ULL,
			0x0FDCF3D90F182D63ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5A9F8F6A303C460DULL,
			0x037864D6208621F6ULL,
			0xB0E0FA809C4E2551ULL,
			0x3A43FA9E645E443CULL
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
			0x908EF6EB448EE580ULL,
			0xA3D3F52B6C132EBDULL,
			0x9A61189F61173CFCULL,
			0x5AAEEC9097C94A5AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01CB158F779AAEE9ULL,
			0x4E85870D5B4ED943ULL,
			0x4BBCCBF171C7CC45ULL,
			0x0F0A83360E206979ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE7B39CA791478900ULL,
			0xCB1ED6026C30F28AULL,
			0xD928DDF1D0DB364BULL,
			0x470549EB3A206658ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x11B6F954F4C2D220ULL,
			0x62EAC13FC4587B3FULL,
			0xDBFD250ABDC22E32ULL,
			0x229E73225285B468ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBB1AFEEBA7E30732ULL,
			0x473DB72C27E20B54ULL,
			0x733046BA57D10B24ULL,
			0x4840AD78481EC73CULL
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
			0x2DCF27ECE07AB870ULL,
			0x238B022156A54A51ULL,
			0x18FCA6554A79D1BFULL,
			0x679C945D89A35786ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5FA8BB28E9A07AE3ULL,
			0xF7A6E8F65977AC29ULL,
			0x2A3CCA6799FBEDAAULL,
			0x26344B1A3E0BC905ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x81962BEEB588D218ULL,
			0xF490584B0AAC0B25ULL,
			0x2795C7A60820CF27ULL,
			0x684F63830CC2FE61ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE95DE7029ECDD66EULL,
			0x2F75343C478773C3ULL,
			0x6B844B4552FDB3B2ULL,
			0x26AB4BD9C6567BEFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD72D5712F2A74670ULL,
			0x1D3254B7528B4A83ULL,
			0x078951A8D1E00C73ULL,
			0x00B098A173F9F9B9ULL
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
			0x4824F3EB6B422128ULL,
			0x6165B6566A1AEE85ULL,
			0x998C72E0F4E0FC83ULL,
			0x691BF37D55CEC104ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D16DB8D93337C52ULL,
			0x71E0392802F992D6ULL,
			0x5672C3D6164F9B62ULL,
			0x7326DB654A912BF6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9E6996968B8FE2D0ULL,
			0xEF6231612B4F316EULL,
			0x76FD3F4B7EF504CEULL,
			0x7296B57A62030F6BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBD5AB8264593F383ULL,
			0xEB735858C006AA28ULL,
			0x409FA471046F9285ULL,
			0x76A6EFE1C42F6E95ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF39E799BA33CD512ULL,
			0xF25AC8A9C0037A94ULL,
			0x92D2E38597EEF1A8ULL,
			0x13A470631D4B3330ULL
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
			0x37E5C3BE459E1730ULL,
			0x1D2CFD8077EC76FFULL,
			0xD3DE37C84A256CFDULL,
			0x43D851468A156BC0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8E269E948852E355ULL,
			0xC54178DE562D84F8ULL,
			0xECEDE40FB591C482ULL,
			0x0AA194C364C8391FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFE73EF7D40524610ULL,
			0xF0EB9C02FECEBFB7ULL,
			0x8DB52FE0D314B918ULL,
			0x5053EA72E716AFB1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAC862A35DD68C11EULL,
			0xBBDF1400EFFC13A0ULL,
			0xC146BB6E4E06CE36ULL,
			0x1A1B42B9DB85639AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD2F561A6EA789717ULL,
			0x477005F0352AE969ULL,
			0x3B8E21C4BCB88AE7ULL,
			0x5C3508CE1CB3FD52ULL
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
			0xF3D821DA6EFE80C8ULL,
			0x404F52C9852301BCULL,
			0xB533E09A754CD965ULL,
			0x48D8815B93CCF61FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB0FF3AB14D1BC0DAULL,
			0xF2696AC960F2EB91ULL,
			0xAB76EDEA9A60CEECULL,
			0x3C9F1A392465BE39ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x87F9E29DCED232F0ULL,
			0xAC698B24D965C2CEULL,
			0x7598E0DCE172F923ULL,
			0x42EC76827BDA303FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1898A07C47FAE1E4ULL,
			0x3FCADFE2A5DCA949ULL,
			0xE4805055979BBF15ULL,
			0x658A4418C53C3948ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8519BF011B794A70ULL,
			0x784D93714678AD0FULL,
			0x8F9E284598FEA62FULL,
			0x6559D19DB5DE6E76ULL
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
			0xF08339E22EAA0598ULL,
			0x3ABBCAA7CAE849DDULL,
			0x57457B5B1DAC12F1ULL,
			0x683EA8F10E4F76C5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE5FDA185A200CC17ULL,
			0xEED3928CB1985861ULL,
			0xEFF8B3854FB11EEEULL,
			0x25D8FB2B331DFFB6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x75AD8BA743AC37E0ULL,
			0x5F04B8690B8497FEULL,
			0x69064C70CDB9F825ULL,
			0x4F76EAD689E5DE51ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2F81B8C00D88BF2CULL,
			0x2CC2AD6B1C8D9510ULL,
			0x19DDD59973A05129ULL,
			0x5CB69EEB4444E313ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8E957AA2B82B401AULL,
			0x1FCD2215AEB05C12ULL,
			0x87BE752C1818A4B7ULL,
			0x578691E8E9BA5716ULL
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
			0x2E9DFAE92000A050ULL,
			0xD32D26611E08C111ULL,
			0x3D03AACEB38F28EDULL,
			0x79DDC81EB54A4E19ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7ABDDB1243893BABULL,
			0x0F32AB1F7AC1A3A2ULL,
			0xA7997E7A78E0048AULL,
			0x571AC29F1EEC2AB8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEB4EBD0A3B145650ULL,
			0xA4E9A0E48B1A5FF4ULL,
			0x891B939DE54C7A49ULL,
			0x40696DE95FC03F01ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x57677EB8551B3A6BULL,
			0x220B765ADDC9002BULL,
			0xD9DDE3F26DABF42FULL,
			0x3F2F14DF8BA74AC0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7DDF4A036B98EB4AULL,
			0xFE076374FEA0E863ULL,
			0x37D157FC4A9C47F1ULL,
			0x02D8E1753958F9EEULL
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
			0xE87BE73241DDCCC8ULL,
			0x6758930BE8D26AF5ULL,
			0x55236027697A90A8ULL,
			0x4E81EEE7717CA90CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x09F762B13FC6DE14ULL,
			0xB5A7BBA8215D75B4ULL,
			0x43FD465D23BEBBD7ULL,
			0x012718CEA77729E3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x058B0EB25FB1B070ULL,
			0x17411F11FEB26998ULL,
			0xFD36CF8312A2235CULL,
			0x59AA9A89BD3EC402ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4927F1F6AFDD8768ULL,
			0x843CE9EA618839ABULL,
			0x54BF2FC287FDA95EULL,
			0x495E432C34C86C1CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0B4C666A75F3F7FBULL,
			0x6A69E11592040F8BULL,
			0x69E2732128745DA1ULL,
			0x1C2DBFFDCF815DB0ULL
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
			0x690C36203EDC1478ULL,
			0x90221CC4E34197D4ULL,
			0x6B523666822A8A5CULL,
			0x46AE804EE4665F4FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0664F2B7578D0C92ULL,
			0x428ABC1A1157BC36ULL,
			0x4E9A6BE1E8481C19ULL,
			0x54153E59492F0E57ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE404336DD79284C0ULL,
			0x9B86A4EE1668617FULL,
			0xD22213ACE0D8A115ULL,
			0x41896E7DCB819314ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5FFD28B6D975EAD9ULL,
			0xF8265F6797F92E3EULL,
			0x3E8259FA431925B9ULL,
			0x06E013071257CE8CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCAACCC346C795CAAULL,
			0x0A44225059E1ED75ULL,
			0xD71D4F4B0A7A6A3FULL,
			0x1CF1F82509DA6AB7ULL
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
			0x97A2488D373328D8ULL,
			0x7B03DD673929AD4FULL,
			0x02D010D3A6550B48ULL,
			0x6C3C7AABE7C80FCDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x00FC7EE3E0462897ULL,
			0x42F5F9990F5AF021ULL,
			0x09BCEE785714F1CEULL,
			0x15B6B8771E312F4FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6694DDA95E093BC8ULL,
			0x87C93DCB44B2D089ULL,
			0x7C2F76E2302CC4C5ULL,
			0x75AFF4BCF5397670ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2CE6CACBEC28C94DULL,
			0x09454EA917429521ULL,
			0xC07FD6648F838A08ULL,
			0x1B6CECD8A3D494DFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7DEB0551E60E987CULL,
			0x9ABB9DA6C4DD9577ULL,
			0x3E888ABA0B2911D1ULL,
			0x5F3531A2E19FBE24ULL
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
			0xC0D0FDC9B121C148ULL,
			0x5910756F5F507E72ULL,
			0xF22572556AA90A0BULL,
			0x759CE42E0B0FCA0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBEBFCB0C828537B1ULL,
			0x6738188B12A14397ULL,
			0xF4C66267A47FD7D7ULL,
			0x7C2C2834AEDF95F6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBC64A03313B52E90ULL,
			0x719D13BD2AF893C1ULL,
			0xA1F313FC2B8218AFULL,
			0x63944959A1CE1F47ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB70320E9AD4FB00FULL,
			0xC7FFDDD90C02B1FCULL,
			0xA83B6F83C23E6344ULL,
			0x0040082392201D67ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x80675F0C89F15441ULL,
			0xC166930AAC62BA77ULL,
			0xC1BE960A50E6D5D8ULL,
			0x2A6F4CCFB888312FULL
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
			0x73A138A60B91C058ULL,
			0xAF700C38272EF90BULL,
			0x846B5039398D623DULL,
			0x41A594D386753985ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B856111EDB7177FULL,
			0xB7FFD0D767E9AE17ULL,
			0xE74EDAAE4DC43D92ULL,
			0x22DC2B458C99722AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x80DCDD8154C45F38ULL,
			0x5B040C0A54852EDBULL,
			0x1E17C52AD3FFBB1FULL,
			0x51ADB444B4C96BC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x631350B0F16652DEULL,
			0xEEF3F29AAB39945BULL,
			0x3E4DF7B47F161AF3ULL,
			0x7244B7CCC0133D3FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5DF0E6A841DEA61CULL,
			0xD478CAB730C4DC13ULL,
			0xE52A556091785DB2ULL,
			0x7A6B4A106EFE8648ULL
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
			0x50472602C682BFC0ULL,
			0x422DDA85947915FFULL,
			0x8EA75E9794550A2DULL,
			0x62D7C48197933699ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x19621E7D999B6BBAULL,
			0xAA2EA429C01B1623ULL,
			0xC94E247EEDD81A44ULL,
			0x5F3F1F7B96507F7FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01F0E5796A0062D0ULL,
			0x65227541D06CBE99ULL,
			0x1C23C9233F80537EULL,
			0x7C3F778331F62613ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1AE9BC36058C8D3EULL,
			0x9CA51808A0558591ULL,
			0x69F25DC1CA53D790ULL,
			0x360EED1B62E91F55ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3218F469B5C97030ULL,
			0x27FB3D66120892DAULL,
			0x89AADF1B477B9CD8ULL,
			0x18B87A96526404F8ULL
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
			0x4C5713F033D8B790ULL,
			0x4076D24A08F05473ULL,
			0xE08145CE73F4BD85ULL,
			0x5FA9DD34922B5189ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0AB2708BA1C3885DULL,
			0x8067721728E9F9EDULL,
			0x634A4B0F8FE92C76ULL,
			0x3168574142591C85ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x715EF0286A4C3728ULL,
			0x702950D3B5950DE7ULL,
			0xAB1201E75D91ECAFULL,
			0x5B3335582715E3ADULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9F31B921D5E88D9DULL,
			0x4E718561DAC58A7FULL,
			0xD9351BC1CD103BD2ULL,
			0x0F04FB1273C3D7A6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBAB2E021D5726180ULL,
			0x075F19E49D412D2DULL,
			0x7B08ED24E92CD3A6ULL,
			0x5942BA98C0AD71F9ULL
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
			0x415C249130AE37E8ULL,
			0xCC712E4E0D701275ULL,
			0xC762877CF4B6BEFFULL,
			0x6000E57388214C2DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB441F20E0A1EC11ULL,
			0x9A58854542F9FB68ULL,
			0xBFF80F1D0ABC2CB5ULL,
			0x3E47AFDFC69FC203ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x847F91CA8E1F9D68ULL,
			0x0AB28A1EA1530ADAULL,
			0x5CEB8D801FC851BAULL,
			0x4CBE01B1A7341223ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD62272D9DA04869CULL,
			0xD7A0C26E805CC44FULL,
			0x4D1019ABC101D617ULL,
			0x2FBF9099F5FDE9B1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x59FB6E15B5AED740ULL,
			0xD6250C9392090B86ULL,
			0x057CFA15E00F1216ULL,
			0x322D804937C07A2EULL
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
			0x4373034FD35D33D0ULL,
			0xC0E755B81622C398ULL,
			0x7BA4C9730D7323ABULL,
			0x46511E70A3371B2FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x20B69D29A28A6818ULL,
			0x5F7066A1A5125933ULL,
			0x13485F57053F5C7AULL,
			0x768CC745622A4224ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x55A77240B81BC260ULL,
			0x8D49E94505A9AA9DULL,
			0x60E646FF443D0C70ULL,
			0x65503CAB6F9CD0FDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5AC00EE8F5A28B87ULL,
			0xA55262564505A42BULL,
			0xF7F7452DFAE72F78ULL,
			0x4E78DBB84EE4FE01ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE94683EDCE9035B6ULL,
			0x282C7F7936F9A2B5ULL,
			0x5484FD3D93EA196AULL,
			0x79E7BAB9C5A9AA9DULL
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
			0xC3F2ED22100F4520ULL,
			0x3C4002E9AD3D5F92ULL,
			0x81FE07DDAD685A08ULL,
			0x6826FA221D76F764ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x10255542FAD38416ULL,
			0x7D1E9C87E3EE7701ULL,
			0xD3945CFAA70E314DULL,
			0x5BE4AD9A46B99429ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x197153DE60EC87E8ULL,
			0x6E19ED962C1B93BBULL,
			0xE283F3FC74E72CC1ULL,
			0x433DF640C0153FD8ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x826542DD121F4FE6ULL,
			0x767E63890EDEF46EULL,
			0xFC9205717FC038ADULL,
			0x57E4A2BC74EF1146ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF1A33EE12E85E100ULL,
			0xC33418AE1EEE6AECULL,
			0xFF25F5D677EBA8FBULL,
			0x493E162318A1E73EULL
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
			0x1AD50026CA1F1AE0ULL,
			0xBBDE49922358D438ULL,
			0xD931C127029A15D7ULL,
			0x629A6A08C5BDC03AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x04B00091D184FE08ULL,
			0x1F830475A001A2B8ULL,
			0x2C96AE84F13B3A07ULL,
			0x198341BAAACA9B57ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE41AA592B2BD88F8ULL,
			0xE2C3E535F788D82EULL,
			0x8FEEEAEB42D5C37DULL,
			0x4C06859BD7B98EC7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE74C3AD283797946ULL,
			0x0533604EF6E6C29CULL,
			0xCD3CBF084A71B077ULL,
			0x1C1657160AFC010BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x8D55CB586ED6FEC0ULL,
			0xE8CE79E691B0F545ULL,
			0xB4F322BB87902633ULL,
			0x20825AC4E82D015BULL
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
			0x645D5EB8418A6888ULL,
			0x073A3428DAD6B332ULL,
			0xA5AB179AAFC1AAECULL,
			0x75B46F82EA65BB50ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x05525B76C5A86418ULL,
			0x46CF7C25281C7A80ULL,
			0x01024F69A6A35861ULL,
			0x7407576BC91B17E6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCDAE72B03DE30200ULL,
			0x6E10130326265D32ULL,
			0x2D7D5D18B2ED9146ULL,
			0x771F3F3630500BE1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2D38B30977EC4E3FULL,
			0xFC0FF3E99476233EULL,
			0x4D19023BACF30B6FULL,
			0x0AC022326CD5F4F1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x33604F41B6D4B49FULL,
			0x8708DE257D31C758ULL,
			0xBD48146978C71291ULL,
			0x1B272FCF8C26DD7EULL
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
			0x5367BC3C6E36A270ULL,
			0xBC3A789F5F83D8ACULL,
			0xB7C45E552C894206ULL,
			0x7BB51AB998CDC60FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE7127F04438E7624ULL,
			0x329030489FAC0E7CULL,
			0x8DF9AF52E6CEADCBULL,
			0x25952C6A00F9BA42ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x64ADC93534034DD0ULL,
			0x7E9D46B4F5A1B9C3ULL,
			0xA0CD0DBC4122087AULL,
			0x6A45DFB55F7C1D86ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8F94D348A1BC9393ULL,
			0x0FBEC72AF872B24FULL,
			0x101841335FEE621BULL,
			0x1D5D13A342ABF1DAULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x137E202FF1F567F3ULL,
			0x3BB8EACD8E55E649ULL,
			0xAB43193DCEE97B58ULL,
			0x5CC278D1C560C8C9ULL
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
			0x7554C1B547EAE170ULL,
			0x758D325E546761D2ULL,
			0x9250D85E068B1B9CULL,
			0x41D6D7EA5AD6AE2DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x52804E94636A3823ULL,
			0xEB5F021955B75CDDULL,
			0xAD564B28C9E33351ULL,
			0x46D94A1B794AA76CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFDD64BD6242E8C58ULL,
			0xDA2613D5D7317BB2ULL,
			0x7380C5FF635E55E9ULL,
			0x6627CCD31ACC38F7ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x800039D4FB58C778ULL,
			0xB61F359BAC87609EULL,
			0x9DE5268BEBBABF33ULL,
			0x4029D0BFC859C97BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6A9D844C0423CC2FULL,
			0x8F0FDD83D0B22F45ULL,
			0x1756C1B27281A0D1ULL,
			0x3CDE94E1AC008BC3ULL
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
			0x7F1D9BFB19DCEF70ULL,
			0xBC587E1E004F942AULL,
			0x3DA381B25D20DBB2ULL,
			0x798641F6CBD7CA8CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BE779A4E5443B46ULL,
			0xA55D2A64AE69C77FULL,
			0x0F49D387AA947497ULL,
			0x7DA729F81A7F2ADAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3B9A3B85E1991830ULL,
			0xCF5A51FA92BD493CULL,
			0x8D41585173D10D7CULL,
			0x6BD1E97DF4CF514EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x89E4C40DB8A64C12ULL,
			0xD82517CF134372AFULL,
			0x5544766D5143173FULL,
			0x74AABF3A002C2D6CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6DCF0B51964F064DULL,
			0xFB20F16973B1B319ULL,
			0xAA5F0411CD361171ULL,
			0x2D656F7B450022AAULL
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
			0xF8574FB7CD53C310ULL,
			0x3C714F0713102326ULL,
			0xA7B7F9613BBA20D3ULL,
			0x77DD86737509D957ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4CE69448A5F8C965ULL,
			0xF0D721F7BA7F93A2ULL,
			0x12281320F880A553ULL,
			0x30E5671262F8FE48ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x004D321F2203F310ULL,
			0x466213F07D503B09ULL,
			0xE0A474978AA5B0E0ULL,
			0x6962ACEB3CA2D89FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC3EC76ACA44E492BULL,
			0x231490E08969A356ULL,
			0xF78DF6CFEB0ECB0BULL,
			0x51FD3670959D68E3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1820FED773F24DA7ULL,
			0xA04A78A0CE36CA77ULL,
			0xEA05F6E4A407C62EULL,
			0x3836EE74334F758CULL
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
			0x0FD31A21546AC0F8ULL,
			0xBA007C58B603EB5FULL,
			0x562B61B326DB0B66ULL,
			0x4B566B2BBC60A6D0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B1866DC6F1DE3ECULL,
			0x9ABBD14EE2113EEDULL,
			0xD231B3BCE7A33EDAULL,
			0x19E70C72A0924906ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x36F682DEF045CCF0ULL,
			0x9BF8EFDC1D7FD53DULL,
			0x9BA7437D458E4D20ULL,
			0x781E7FC9A78DBB74ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x37AF6EA13FC8DBBEULL,
			0xB2325EAC7DE3DF12ULL,
			0x2A1DF0814E72063BULL,
			0x2A1C04B550347E21ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x613CE0D26DFAFEE2ULL,
			0xFD54B47BDC2E88BFULL,
			0x24B2416754915936ULL,
			0x5ED708E5518B85BEULL
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
			0x36FEB7F7AFA9BDB8ULL,
			0xB7E5CBD378D6BA4AULL,
			0xE40FAF5970AD3369ULL,
			0x6D225BEA148E3416ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5747871709D73C28ULL,
			0xFE008668C712E748ULL,
			0xC8691DA33721D4A0ULL,
			0x5A1549313B8FA888ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD9DFDA1311457ED8ULL,
			0x653BC3FD3B4934C4ULL,
			0xE7710981F89199DFULL,
			0x6B81B2E01C068059ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAA5B1D5FE386A121ULL,
			0xB6C8F7C3DA323096ULL,
			0x4E98280726C8C9D1ULL,
			0x5228CF305CB37747ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAFE7DE5E955AD3F1ULL,
			0x84CA650DC5F9FFCAULL,
			0x966B412DDEBBFEB1ULL,
			0x30C2539877C538A1ULL
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
			0x5A95AA19DC645C40ULL,
			0x7D9B1B791AC68755ULL,
			0x974CC8EF7A78D028ULL,
			0x6CF1E015D05F0743ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7EF4CDFF0FB3EF34ULL,
			0xCE8BBED979050A97ULL,
			0x730547B9892D850BULL,
			0x430729D8421A2E0BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x63E9CC47FD177018ULL,
			0x534584F69A4D08DCULL,
			0xFF59E32C8750C9BEULL,
			0x684512A7BFEC32D9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x15E4D7332F1E31A2ULL,
			0xF670C6720E130F2CULL,
			0x67A7AE3298146226ULL,
			0x7B973244DCB9D6E6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x67D832E450D7725EULL,
			0x22CF82B63C6D7C7FULL,
			0x931E324D93EC2B78ULL,
			0x4C07498BFEC2A76EULL
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
			0xE4DE5472BC58CD88ULL,
			0xE77B8C7B1E9CCEFAULL,
			0x0C0EEC39D52C4EB2ULL,
			0x64352F1B8F303A46ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C1AA1354AF7A062ULL,
			0x9EF856F580D9A5A2ULL,
			0x9583EA0E1478F039ULL,
			0x287F17CA26AF685CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4A179586B7E4200ULL,
			0xBEFD17E49AD536CEULL,
			0x044838A6ED55CFB8ULL,
			0x7434625F82EE9E1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD40A506EAAFD2EECULL,
			0x0A203AE5F6E9A642ULL,
			0x3015C189E4455CCBULL,
			0x039E18822851E954ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC0C40BBA366AFB3EULL,
			0x16E9F604966019ADULL,
			0xD9373DA4C9CFDC1CULL,
			0x62FDC80F1BA43100ULL
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
			0x757AC050D14FA620ULL,
			0xD12AD52E08AE6054ULL,
			0x0CA9F1BC2184AF38ULL,
			0x6064B3C42F848A40ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF6461FF2849FC4FAULL,
			0xF82126C523D3328CULL,
			0xF3EBEA0A1CAE0014ULL,
			0x4188DF28CF0F0720ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB70166EEE2076A10ULL,
			0x95EF0EAAB76CECE9ULL,
			0x139CD34117DF0A2AULL,
			0x723495EFE0EF9D8DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAD1A69E539475806ULL,
			0x65000249A8CECD92ULL,
			0xB74EE2A35DDDFED8ULL,
			0x7A2F295C474D3824ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4293CEA861D7924ULL,
			0xDBE76DAE70ECB56DULL,
			0x1935B6B9C903094EULL,
			0x43373F2727432E23ULL
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
			0xE1CE142A60282468ULL,
			0xBE232423ACA19A3FULL,
			0x39E1A39D52FD6F62ULL,
			0x43F392D404B6B619ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0BEC789038C6811BULL,
			0xB838BEC108DDFDEFULL,
			0xB42D1237429D1A47ULL,
			0x1787AC077DE5322CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF597F217B290B500ULL,
			0x5E5538888D63EBD9ULL,
			0xCD6368B9850AE9EEULL,
			0x59D28EC1742AC51DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0AB22D79347D864BULL,
			0x162A8FC7164024F0ULL,
			0x4C5A5A6B496DC9FBULL,
			0x1EF930ADD10E19B8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AABB12C5AF4F0EEULL,
			0x8B1730C944F8992DULL,
			0xF614164FE7CCD6AAULL,
			0x7699AFFEFC603E1BULL
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
			0x72E19973C88A75E8ULL,
			0xFCE80AD01205CDF3ULL,
			0x91B3B9909BD7E96EULL,
			0x69B1CBDC6FED96ABULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF4A0E0E61C34E245ULL,
			0x4683F8706147B530ULL,
			0x6047298E9F2D21B0ULL,
			0x52A97A2A3F921CFDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAA16E2DCEF04D900ULL,
			0xD1F9DEFD16645E0EULL,
			0xEE8581B3FD419EDCULL,
			0x5A2A0B070835172EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEA85939B83FE1514ULL,
			0x2A652B51F811CABBULL,
			0x0E3D558AE75C4645ULL,
			0x3F4F570C6DC4596BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB7E4B1D648AE0C2CULL,
			0xA1EB8ABEB158DBDBULL,
			0x367CA6A889735724ULL,
			0x1E828A1B5E59B083ULL
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
			0xC64D64FFB027D848ULL,
			0x0E101A56EC559858ULL,
			0xAC1F67EB9045883EULL,
			0x66B300E42A5EBACDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4DB684F7B5CB8834ULL,
			0xF064695556FED0E8ULL,
			0xF90B3E378D0498A6ULL,
			0x15D1E584805C3F3DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6D713BF08AB341E0ULL,
			0x142E2922BE5889A1ULL,
			0x77B1ECA40CD1A2C2ULL,
			0x75C15CC90E55985DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2258BF2FBFEA7E74ULL,
			0x5536D6F0B6232973ULL,
			0xE52CEA67E76B32FDULL,
			0x21E8BE40F515CA33ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE23DB8BA10644EEBULL,
			0xA68C589AB83744BFULL,
			0xDA604460D38C24A5ULL,
			0x7E418C1ECFB4D088ULL
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
			0x3DCF5FECB880CD98ULL,
			0x35F87783CF4707EEULL,
			0x7D615A11F79E9408ULL,
			0x5CF80083A19A5661ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2527527B791D2119ULL,
			0x2C50F32C167743ECULL,
			0x39AE612684DB9B8CULL,
			0x5E9B625864F1E002ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x01A54170A0CAC010ULL,
			0x1F8D37922EAAE001ULL,
			0x151358FCAA811E13ULL,
			0x76DC483FC2A6483DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEF76A709BD9D5AD6ULL,
			0x8F7446C210E52AF3ULL,
			0x3A0E4F18AD20F333ULL,
			0x472D86BCC58857EEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5064DE91C4175870ULL,
			0x71EBBF95D2AE2BBCULL,
			0x40C3E4E5080B3BDCULL,
			0x7BED497EC1B8F79BULL
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
			0xD9AD8A01F66617C8ULL,
			0xE8AE8E7583C39C9DULL,
			0x82621F34C6DE1B55ULL,
			0x7EE0305D5900492BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7257AC71C7DF63DDULL,
			0xB9B98530F2A61F51ULL,
			0x26E62456C9CEEDB0ULL,
			0x3447E8FA9FB22E0BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC4F15998373D6470ULL,
			0xECCA6C8718844206ULL,
			0x0228B35E78D224D9ULL,
			0x697D75BDCFF1B018ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x27EB5EA33C64F888ULL,
			0x9E1462CAE43D0F0EULL,
			0xB300DD4E7FB9F1E6ULL,
			0x76A66CC8CA7F1BF7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4D03FECC70972869ULL,
			0x9125D9F5D1155588ULL,
			0x6B7DC70EEF3AE7BEULL,
			0x3C2F01DB30C21BBFULL
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
			0x91D38718A1744158ULL,
			0xF0A2721649983132ULL,
			0xFFDF4EF893E74AE0ULL,
			0x6A6902F10D22E86EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6EC15553E11F0EA0ULL,
			0x8A08FA945B6E3A1FULL,
			0x02DDBF90DB49C069ULL,
			0x59C3D063DF50A244ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x585BFDFE23C9AA20ULL,
			0x094D1A00940519ADULL,
			0xBCBDA4DFDCC7F22BULL,
			0x6427ECF2E1DBFD02ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0477896FC428EAD5ULL,
			0x2F15D8EB6B41172EULL,
			0x25BFE568A9E7936DULL,
			0x3FB713FDD75843BCULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA938E7FF22583E52ULL,
			0xB4BA0AE753015830ULL,
			0x0142F43F11106E81ULL,
			0x3F5F5640DFDB9C2FULL
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
			0x31F43B1105E632B8ULL,
			0xE12A1CD9B43177A3ULL,
			0xEE0F959325676D68ULL,
			0x630A171C4A409172ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC4D67BEA77EC89B0ULL,
			0xD552DD0EF57F902AULL,
			0xD12B9C8BD72389BFULL,
			0x358BB82023BAFF54ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9ED5250E2A41E7A0ULL,
			0x11BE5518F6E011EBULL,
			0xF3E779B65062BFE9ULL,
			0x71264C1FBCED037DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x58B6CE42081133B2ULL,
			0x3EA95C845EE16F60ULL,
			0x85F0DAD9447E506BULL,
			0x17193524E2DD0149ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4638A97FB2C10008ULL,
			0x82A6DB8DE1EA8762ULL,
			0xBD37A1BE87E8F174ULL,
			0x17029544BF8EF760ULL
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
			0xF31F71E8FE8F8898ULL,
			0x1AD159A61B9387D9ULL,
			0xEAF60C826CE3CDA2ULL,
			0x5848B9FF11A1E30FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1E8FBBC25AE618BAULL,
			0x1A72BFB15ADDA221ULL,
			0x151D5C6D65DEF01DULL,
			0x39B440527CD90BADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2ED26C8361FA5338ULL,
			0x8ED12348A7171DFDULL,
			0x794B5D786891F38DULL,
			0x593FA9F46A1F0904ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x23DEF4A951B544F2ULL,
			0x623A2E8765876D32ULL,
			0x1B0AE4A8C70B3CABULL,
			0x2240BDE19F7605FBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAB28E6EAAF439884ULL,
			0xE4DC5EFC1D29EA74ULL,
			0x4B949D86AD041171ULL,
			0x0B407E432628EE0FULL
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
			0x8ED9286B68D498B8ULL,
			0xFD972E3E927CFD65ULL,
			0xD865AFC8CBC99A97ULL,
			0x4797B996621EADF1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF95110C6ED7E6219ULL,
			0xAD3B15EE38AA4807ULL,
			0xE5A654BC29DD0417ULL,
			0x66E55C3F1A55A30EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3C72B2A37AE8A390ULL,
			0xBB112DC3D80737A8ULL,
			0x783F507C3707C0EAULL,
			0x4787FB2A69C45413ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCB9E8F5F4AF0B3B3ULL,
			0xAC55D78A4F57B7F3ULL,
			0x7DC6EC275D14C8AAULL,
			0x2F864B416395809FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDBAA745D4B345002ULL,
			0x6B31D7B92117983BULL,
			0x3D80EBA6A8DCC0ECULL,
			0x6878DCB951015FAEULL
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
			0x856A0BFAE3E0D090ULL,
			0xDA35A16C9E2CBB7BULL,
			0x73B01C84DA4A9BAEULL,
			0x50D296DC55EFBF63ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0088496B83DC82AFULL,
			0xD69551083244A9EEULL,
			0xE477ACCB7781AE81ULL,
			0x05916969994FB5C1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD6C52C5AF272A7A0ULL,
			0xEBE1F0806EE64B8BULL,
			0x1E65ACBE8A8CB036ULL,
			0x708C7748F716107DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x51440DF631561E4BULL,
			0x6B7D5613C288C51DULL,
			0x69E43F726BE6E685ULL,
			0x3132FFA6E7838513ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDC87CC6457785FC3ULL,
			0xE9937706D1177F0CULL,
			0x3AFD35D6B26CDCA7ULL,
			0x0992D74A8F526915ULL
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
			0x6D732503FBD71E40ULL,
			0x5E2645C2AA91177BULL,
			0x4755ABF67289622CULL,
			0x64CAEAB5291E4596ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x33543079D3F51145ULL,
			0x25CFDE1B6A9D7235ULL,
			0x57438B610F165EC0ULL,
			0x0227ACE9D320CBCCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0DB2A930C7F95B00ULL,
			0xE4D328D4096C43D8ULL,
			0x4D5FAE77E4AC4AD0ULL,
			0x6FC12B12369ED607ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x49714FE985A23AABULL,
			0xF4AE255BF399BA2BULL,
			0x2574B8F0B4896496ULL,
			0x5ED9A7F1C29C04ACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x239F294D7B9A4C5AULL,
			0xA87CB810FE153331ULL,
			0xF0A76188A8951619ULL,
			0x1452C5FCF46B3B35ULL
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
			0x11AB55AED9218A38ULL,
			0xF043C95146B71282ULL,
			0x939FAF9E3661DAAEULL,
			0x40347D906322550AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x75D7DE85820042BEULL,
			0xB63E78B751E64DC4ULL,
			0xA787B740DC2A4FA5ULL,
			0x3AD4ED8F4D5AEB79ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4B0434D6FFF2A5E8ULL,
			0x8EE7D09C4EEF9BB0ULL,
			0x407B3E39DFB40F04ULL,
			0x6A9D9A387902F7BBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5C498109566A075DULL,
			0x25FFC0C387B557F9ULL,
			0xA890AFA48ED5F4C1ULL,
			0x484E926B2160E2D9ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1194A397B11D13BBULL,
			0xD6A7C30F241144CCULL,
			0x0D1791B5EC66D8BFULL,
			0x2E7ACADFF341F6E2ULL
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
			0xFB98F03820514760ULL,
			0x7D44741F9CF57F63ULL,
			0x053BDE2D025FF02EULL,
			0x4149AD5EAFE3A400ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8B72A3E842D188B9ULL,
			0x8F9E0CA7EA267D5EULL,
			0x3AAA81D9A69BD47BULL,
			0x2435521ED5B788BDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD1D538A07B87E98ULL,
			0x5D0540CC93AB9CC2ULL,
			0x038DCF39AF09AC53ULL,
			0x7E5BABC5CAEB0760ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x82EC10EBC2C0CECCULL,
			0x35B44FE216E54EA3ULL,
			0xAAEBEBCE681CFB11ULL,
			0x66A742925FB947F7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x524C7819A91BFFDEULL,
			0x301910657C8C0870ULL,
			0xDBADFD317FBFE9C3ULL,
			0x019F31A0E606D7B9ULL
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
			0xD5940449F985DAE8ULL,
			0x24F4621EE7627504ULL,
			0xABA41F6DBCC4D8BEULL,
			0x4D31AC8779496F6BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01FFD752CCAED4EFULL,
			0xE9BC0E7031233F11ULL,
			0x7F55CEBC4D794D8FULL,
			0x453412CF79BD7AAFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x978C74DCC4238F50ULL,
			0xDDBC41CA577BA71FULL,
			0x3B8D1CE4CF4AD486ULL,
			0x461AED78A9F4C5CAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDE04309035876CCEULL,
			0x7ED0EAE5F8B9B29AULL,
			0xAC170531CF8A9393ULL,
			0x6EE48C85F5C034EDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5BF29B9ECD46DC9EULL,
			0x7D48498AE5BC8990ULL,
			0x90D86E93A7E26726ULL,
			0x030D1BA64FC9DA50ULL
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
			0xF50AEC763E9ADBA8ULL,
			0x69BA517B87670057ULL,
			0x91A8409F3EF44FBBULL,
			0x741C7D1B4BEB5D89ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x77926971AFD4793CULL,
			0x7A2938F09228E00CULL,
			0x0907274ACFD8CE0BULL,
			0x29707CFE97625A39ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x16E726C6A0D7A0A8ULL,
			0x9E8A78E09ABD8DD2ULL,
			0xB545B3EA18F19B01ULL,
			0x741C219BFB8FE74DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB07AE0F1831C69B3ULL,
			0xDB10306575E4B8BCULL,
			0xAC89B942E2D55541ULL,
			0x36B0B30528420C3EULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDD8232FB5573986EULL,
			0xCEC6788A6EFE3801ULL,
			0xF1375DAE16132A09ULL,
			0x3BBE568F80F0B1AFULL
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
			0x9C91870046840DD0ULL,
			0x4FC6EEECE111351CULL,
			0x41EA897E87B7374DULL,
			0x7AA954D867B51CF1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB2F2991796F439F6ULL,
			0x6EE34FE6F1C48C26ULL,
			0xF0F7C00DF3BD4A21ULL,
			0x343FFA1B92498984ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE4959EB77E2F1B00ULL,
			0xB650D2281A77CFFBULL,
			0xE92366FB389CD423ULL,
			0x6DC29125B283C97FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA889E4D02C930E78ULL,
			0x1DDBDBA705B58F12ULL,
			0x2E9E63C32C77F901ULL,
			0x346889F0207ED28BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6843B2F889869A4ULL,
			0xEEC4E55511D9DD70ULL,
			0x10A0B0867DFEDA8BULL,
			0x5069388BCA69E7AAULL
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
			0xB49DA93E54AB8810ULL,
			0xF61A72C6AE480112ULL,
			0x363894A10A121564ULL,
			0x61540276B2458CF5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x821142E7AAD4D67CULL,
			0x974E5B9F8654750AULL,
			0xCCC3AD4534A39DFEULL,
			0x68F21862BBC9D309ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x717E5603304F6FD0ULL,
			0xD60DC3A9B62B3B16ULL,
			0x37905DC7B4E9DF87ULL,
			0x5BE6E665A2E0CD9DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x73CBF2AD12CF59D9ULL,
			0xF2B875E1161B1E05ULL,
			0x0D46BF980464AA20ULL,
			0x0F8F1272F0458976ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x050210A338E15D3EULL,
			0xC4448B17AEB15F19ULL,
			0x389991021F71B5AFULL,
			0x4EFB20B21F595545ULL
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
			0x050DFD02548E4D48ULL,
			0xE78E59DF30B8390BULL,
			0x762A68D060082E93ULL,
			0x6E3B8B2BC33E9946ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD8F21E491D0DD8FULL,
			0x8FCC695BAE190053ULL,
			0xC794A1C18B61835AULL,
			0x563B4FC4AD2C92B3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE356E1821ED58018ULL,
			0x0CAF5B49D84C7588ULL,
			0x806CC388B2ECE18FULL,
			0x61FF3ADB8AC7F0F9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1C16C84323AF53EBULL,
			0xC289CF6D97F98993ULL,
			0x648014D1E6FF790AULL,
			0x3CAE563C94D6849BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x23281BBCF53EACD2ULL,
			0xA0E3621A409F81A2ULL,
			0xCE16EC14DC2237DAULL,
			0x2EB588357DE38B6EULL
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
			0x92E8B1478395DAC8ULL,
			0x77939A00897F17F9ULL,
			0x0C099106F862944CULL,
			0x6C8D4344568D369EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x637057B96E3E933EULL,
			0x8C6888961784D6DDULL,
			0xA997F760158D6302ULL,
			0x0FD71EF99BE540AEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x70CC6542BD19E300ULL,
			0xB446FF18FA6A9C5FULL,
			0x31B84CAF423CE485ULL,
			0x7450AED76B42D69DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x074E346D656143E0ULL,
			0x32C9D4D3BFD5522BULL,
			0x9DF2DB19BF67D999ULL,
			0x67FF8108E5E7DAA2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B7DD3FA832456C7ULL,
			0x5A9FB6691DBFC86CULL,
			0x7E8F72B265EB5F0CULL,
			0x688F7AD2E78EE01FULL
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
			0x477A04B8B6FCB098ULL,
			0x75B61482B3D74E71ULL,
			0x06E1D10ED7137938ULL,
			0x54864BA842745711ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x656D1A2E5FB22150ULL,
			0x365FFEA197222906ULL,
			0xE58E80D78120AA9DULL,
			0x3FDFB98C5DE5E016ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2CB81E73FC498760ULL,
			0x9A40755B59CCBB96ULL,
			0x3B4F4ACC1BCBB788ULL,
			0x6DD339E451C69EEDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC9FB83C78A9530E8ULL,
			0x512CD6394CD9ACD6ULL,
			0x53A235E94EF28D78ULL,
			0x007CF52FD6F13A40ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD493081C6FA11FC0ULL,
			0x0CE1198D2D03DD29ULL,
			0x9F808F02434375FAULL,
			0x0950AFFFC8AA55BCULL
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
			0xE9E19A8780E7E438ULL,
			0xEE7E593E7B7F7337ULL,
			0x5E807BD028C50CAEULL,
			0x72B72A7280828828ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C53F79F275B3D31ULL,
			0x7DC7978541A680CEULL,
			0x131F91E8D0FA55B2ULL,
			0x58A3A5E6CC061695ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0A80A8D0497CDF48ULL,
			0xF91486938E674B52ULL,
			0xC0B42128FFE704BFULL,
			0x4B16EB7EFD290A5FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x398CAA0DA2305A79ULL,
			0xA70C0041FC252AF9ULL,
			0x4AFC86FBCF684200ULL,
			0x45A453619D915D04ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0E45C33FF75D92FCULL,
			0x71D9185329C7F3F2ULL,
			0xE3230CBE73C02321ULL,
			0x6D3BE6BDC99C30A1ULL
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
			0x52B9B0F2EF984510ULL,
			0x19F331535C71FB56ULL,
			0x2B50AB074522CE09ULL,
			0x5EA08D47153D56B9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE41973B13386553ULL,
			0xF54BBD7B973B2376ULL,
			0x63E4832DCEB3EA42ULL,
			0x7BD7A253BFEED4DBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC23533DC07AE38C0ULL,
			0x4575B7B659F06AFCULL,
			0xB4EA9AD12F0E447DULL,
			0x6C441EA60DA18B03ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0C91445CB7D91F0BULL,
			0xCEEDF801FCEA4D40ULL,
			0x2112640621F05768ULL,
			0x2AC007A461BE63BFULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x90D6C8FFD4ED8E43ULL,
			0xE11C0FF3C1E816B6ULL,
			0x215E640514A5B6F7ULL,
			0x7C12340A5BABE549ULL
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
			0xC29FBE0D85DAE1F8ULL,
			0xDFD2C39928BEEF66ULL,
			0x044850E42224D305ULL,
			0x5E3E6FE7D98604AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAB397F055BE70A50ULL,
			0x5C5CD11E9D0DDF68ULL,
			0xB822518EAD4B1D60ULL,
			0x0D825CBE2D4B43E2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3F225BC35EDB4870ULL,
			0x451AC6D2CFE06367ULL,
			0x180F9853B1A07940ULL,
			0x5FBC9535CF290453ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5AB57033513A41E1ULL,
			0xC2CD1730437BD479ULL,
			0x68A99E1891FC6964ULL,
			0x06A7D6C905545CA2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4AAD1061C2492432ULL,
			0x366F629CF0323C80ULL,
			0x39626AA161F8DEFDULL,
			0x28EE7C825E0DF9A1ULL
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
			0x9F4F3CC8C9C0C1C8ULL,
			0x54C426C20F7DE8DAULL,
			0x84E79C7E47791D28ULL,
			0x44CA506D87E14D03ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCD8C85D01FDD530EULL,
			0xD9D2A556656D35D2ULL,
			0xACE2F6BE199E833AULL,
			0x0450EC337EEE4C42ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x811C3AD71F691470ULL,
			0x6DD58B803AC98A1EULL,
			0x25DE55F28A3EF4B1ULL,
			0x5ACC659D9A5D79A9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD332E3A4986D38E0ULL,
			0x322581542970247DULL,
			0xFDAAB096D53C43A0ULL,
			0x01E7FFDC0D577E09ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x670E437277418783ULL,
			0x402650C5CC844EBDULL,
			0x9F35B5153A2E2EB5ULL,
			0x0950062C7CDFEC00ULL
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
			0xBC271856C978D500ULL,
			0xC896CB665F5A2856ULL,
			0xE5DB0BA17958E77EULL,
			0x5607C59853BD8E4BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xDFA44A640503A393ULL,
			0xA1743C4E1DF40291ULL,
			0x739667D52F3F02C0ULL,
			0x3D156323668F8F7DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD43B1F5746823530ULL,
			0x35FC1FE96A7F9E7DULL,
			0x3743742E73E9CBF7ULL,
			0x76CFE7A3A36000BBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA6F35C7A41E39091ULL,
			0x2C67354D2DE07B2FULL,
			0xF878FA52EA20F159ULL,
			0x2B3243F00A745DA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x81536A2D19469338ULL,
			0xC245507D7210BC98ULL,
			0xC15DB01C3205E643ULL,
			0x5E3EC2FFB1876857ULL
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
			0x013EBB3B28809CE0ULL,
			0xA23174DCB4B7D7E6ULL,
			0x59A48B147E833C36ULL,
			0x5C3BD2C47B2DF9F3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6767F53693C4DE89ULL,
			0x877867FE52D1061AULL,
			0xD81BD3963F89B829ULL,
			0x7B9F3F3B2EFB9BCFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3A72F3992CBA9830ULL,
			0x4399649BD4B31068ULL,
			0x2C06E77D5B38044DULL,
			0x4142EBF862D21A17ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF2DE36D067C439D1ULL,
			0x809989845933A04DULL,
			0xA30CDB715CB49F82ULL,
			0x5ECDD5C06D8107CBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x306EA921383DCB2EULL,
			0x176CE3155552A1DBULL,
			0x22B789539419998EULL,
			0x3A34E8055B3746C2ULL
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
			0xE0A7B6DAFFB10988ULL,
			0xD89A21A189C99524ULL,
			0x02096CE4189912FCULL,
			0x4FB02DA421C85087ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB2E8EB181D7AC3BULL,
			0x060FB19C7B7A9288ULL,
			0x72CD8B76235A28B8ULL,
			0x2DA6660C5F3980F0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA4EFFBB1EBFFEB00ULL,
			0x0CF98F37BC15B78BULL,
			0xAF8C678FED128C23ULL,
			0x6851A09DB857F3EEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD81437CE85A654BAULL,
			0x5688A4646671C9BCULL,
			0xD42DFDA22CAD8B01ULL,
			0x4C06C01ADB0737C1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC331067EF6EFD207ULL,
			0xCF0033CE0EBE9FFAULL,
			0x041903CD0F4C0373ULL,
			0x603C689641E4878DULL
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
			0x9E48BD66E42438F0ULL,
			0x33FA5112CC5DDDF8ULL,
			0x6775015DF8937459ULL,
			0x5C7B2EB15A90E81BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFF90D08067A88E00ULL,
			0x2EE71632C1C9F7CAULL,
			0xD5D00C2E14DFB0BDULL,
			0x4FE7EA4F004FD59CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC15C55391174FB98ULL,
			0x18EC5C9E640959C1ULL,
			0xB6C99894A6E51D61ULL,
			0x6EDF7093187B9A3CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x75D1138BFA79F947ULL,
			0xE1F7401FB10E72EFULL,
			0xAF80753397FF7911ULL,
			0x3F3706646B182544ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC5F7C8B31515D30CULL,
			0xA91E2AE2A0C148FCULL,
			0xD009946DF577DF15ULL,
			0x20A417216461DBA4ULL
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
			0xD88C5B2ACF1C7300ULL,
			0x2DD47CC83A74A891ULL,
			0xA803532D9665A291ULL,
			0x580064252D8185EBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1C57EB735BE3070EULL,
			0x32AECDE62D06F6D4ULL,
			0x8809F3A3799AEC86ULL,
			0x4364373EA15F8C44ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6DB182B0703213B0ULL,
			0x7BBD0F9732E6D327ULL,
			0x1B53187D35AE0E9CULL,
			0x40184D4478CAE3F4ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA31E6810151DAEFDULL,
			0x5AC88AC3BA79F302ULL,
			0x5F13C74C0C6F6718ULL,
			0x3B0629FB451F7CB4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF698E51792045C7CULL,
			0xF09B92C393E8D361ULL,
			0x809B4D7D70C49736ULL,
			0x304ED4554D18B0FCULL
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
			0x49B21D884D8DB280ULL,
			0x98DE6A87BFEFB55DULL,
			0x86BC691ADFF234A0ULL,
			0x6581D4FFF96DF3F1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBD96F7DD38468487ULL,
			0x2FC3B339AA5A6D1BULL,
			0x8D11BBB25174F352ULL,
			0x072254FD1D2DBE7BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB2520F15CBC1DFD8ULL,
			0xC256B7A6E255A22DULL,
			0xD0ED76AEFF6202A9ULL,
			0x46DE2EC7D6735718ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x91464E16C6B0EE5DULL,
			0x0ECE2CF9185A60B5ULL,
			0x46B7B5CA4AC87602ULL,
			0x3F592253320F2289ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x259811CD418518FCULL,
			0xDFCFD22DB85E38A5ULL,
			0x7A54752001D14571ULL,
			0x0E5B7313F4288F43ULL
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
			0x1F6E81EB42138100ULL,
			0x0D63A6B9116BE187ULL,
			0x968C27749256F05EULL,
			0x60684E5A62C5C8DBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x55257F52BDD438CAULL,
			0x97DB04D672C261B3ULL,
			0x13591B7F48A2B5C6ULL,
			0x68AAEEFF890ED85FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5BDD7C06D61B4120ULL,
			0x2D87BD72AC5CE97DULL,
			0xBA1CDC3EF1EE7069ULL,
			0x70534365FA89B653ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA81AC924511BB573ULL,
			0x5156069EC08D37D7ULL,
			0x8B8499AA8E009C27ULL,
			0x5392A4015F9660C2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD686F974452C5AAAULL,
			0x9787E2ED92013757ULL,
			0x7FC9DBA3BA7E41CFULL,
			0x72D8B9A96C3AEC79ULL
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
			0x60B482E46BA7C9F0ULL,
			0x6D9B16DFCE3F09CDULL,
			0xAADAB296E4F05ED1ULL,
			0x6174FDECCF2FA0B1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x99237969F3FAC1CBULL,
			0x8542242B1B0E3892ULL,
			0x14B120572D3D283BULL,
			0x3212B4E5EB4CD443ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8A66E4E6EBAEA868ULL,
			0x48ADFE98E1A5DF62ULL,
			0x45215CF1AEF9FBA6ULL,
			0x6AFE3781C748D79DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF09BA179F7698046ULL,
			0xF23092B26D97051AULL,
			0x0432963880C8C8A1ULL,
			0x3DFDFDF3809C4549ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1A1F348878A5C95AULL,
			0xED7E8453C6E4C3B9ULL,
			0x399E372ABEC91F32ULL,
			0x4C49730B8F301495ULL
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
			0x9A5C12837DCF33F8ULL,
			0x6143B883A45CB67EULL,
			0x15AD25F892E742A9ULL,
			0x7624E7FE37303D6AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5DFDF3A80892A05FULL,
			0xDEE3FDE7B8A36B7DULL,
			0xEB811E3F4FE9C3DCULL,
			0x285922B91BC44A46ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC93A3633498B3758ULL,
			0x23C92C727C26BA31ULL,
			0xF915C2B7E3F14904ULL,
			0x5CB3FF4D8C298DCEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x29E1D8991ED0DA52ULL,
			0xF80453CFF6A8419EULL,
			0xBDB83328F41B8464ULL,
			0x31617437708A1CA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCABC1D64383EA187ULL,
			0xFEA0BA458438B51AULL,
			0xF7CAA3719BFE1BD2ULL,
			0x2AE5A7F70A4C3B88ULL
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
			0xEE2D49FEB07BBC88ULL,
			0xE1B69F16AD243C47ULL,
			0x67E1697F6CBF1246ULL,
			0x515B24EA98D44651ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC55EB4440B76AE8ULL,
			0xE77DB576A5CA34AAULL,
			0xE8DF1F34ABB76564ULL,
			0x2BEF864DDDD95C3FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2BC96A10605985E8ULL,
			0xC9B4A63016A0B75CULL,
			0xE540B2AE5D8509E3ULL,
			0x71B84B6E12AAC5B1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8191A33CAFF865E3ULL,
			0x44409DD0F8EA5845ULL,
			0x307C0A801973C744ULL,
			0x1EEF09FCF89570B3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x85BED03769517484ULL,
			0xF94EF27319517D79ULL,
			0x25D07FF9524BD413ULL,
			0x0975761DFA48F641ULL
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
			0x051A7D75D501A8F0ULL,
			0xDF3646A78368FA6FULL,
			0xB7C2A1B5A5E7CA93ULL,
			0x41A6F705ECADD5BCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCB3F7A4D7F5F61EDULL,
			0x9095C48F2F1F72B1ULL,
			0x4EE1F91E9D4C41DDULL,
			0x36D62444A2367F94ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBF5AA32641969628ULL,
			0x7379CF29DA392C40ULL,
			0x8EE487F996618D6BULL,
			0x6217CCEB5D6D3BA3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x6FFD09B94AB2A78CULL,
			0x3E4F814A212E7678ULL,
			0xE44D04DB21E2075FULL,
			0x33CBA222FB721C42ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE128339AC6EBA8B0ULL,
			0x1735F7083E0018A6ULL,
			0x2BBEB7825DAE9EFAULL,
			0x11E0581C4907D53EULL
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
			0x55BF4F85CA616EB8ULL,
			0xCB135E5D200BEF65ULL,
			0x853C6D962A5A7167ULL,
			0x56FB46785715FF72ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x27BED8B8A7C8954CULL,
			0x8D93CC5583DCCAD2ULL,
			0xEC4F0EE8377639ABULL,
			0x6131231DE2F96204ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x17DECE8AC70C7F20ULL,
			0xCAA284BF177CBBE0ULL,
			0x7D577479E4989719ULL,
			0x58ACCC326508B6E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14EAAE9AA7BD853BULL,
			0xCF376426B39FDA90ULL,
			0x60FEA1290560903CULL,
			0x6421D60A843CC690ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD1930CB45796BF02ULL,
			0x069885213A854D49ULL,
			0x4598C75872E3A1ABULL,
			0x72550303BEDA8FB3ULL
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
			0xAF539A4D02B74418ULL,
			0xD1366B526DCB6C43ULL,
			0xCD8BCFC8620EADB7ULL,
			0x636110391D1FBBB7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC358D446747CCF52ULL,
			0xAABB844ADDEC75E3ULL,
			0x6155909A9E54408BULL,
			0x11968D0201E4905AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBD646E385E3E7428ULL,
			0x9F0114B626E59002ULL,
			0xA25C3E19A6577A2AULL,
			0x72C90D5569D8B970ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x301A75EB43150CE9ULL,
			0xC55347C25B6C03D4ULL,
			0x8ED5E9CE6BFBC65AULL,
			0x626AD21C2EDB1D66ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x02FD6BD908676A10ULL,
			0x1AE4282A84B68868ULL,
			0x9B3A1C3C9C5BC5DEULL,
			0x7EE47BDCB671A7A7ULL
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
			0xB9400827367C0160ULL,
			0x78FF59707C1FEB06ULL,
			0xBA97A9E51C29F245ULL,
			0x53BFF5BD099BA71EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7FFC960E1456837DULL,
			0xB122FC8208A3725AULL,
			0x31CBD5B974398CF9ULL,
			0x502B2D885E10FAE8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x54DFCD31C8A33B50ULL,
			0x834D0506367D2164ULL,
			0x8FBA0459D4988B25ULL,
			0x7B640C1C3F0E2956ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4B42973697DC88D5ULL,
			0x97253C404CCDCB77ULL,
			0x6D5F943B8F83E34CULL,
			0x5D693313E2960626ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x3F86E9B2266AF0A3ULL,
			0xD8652900EC9317A9ULL,
			0x75242002E3E39A86ULL,
			0x0BFA951E043D03A8ULL
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
			0x36508B1CBB985D60ULL,
			0x851134BD42E85A26ULL,
			0xBF9818F68AA11C75ULL,
			0x4DE6765B3DA3FE85ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x9395F2E1BAE1C2BDULL,
			0x5666584EDAD8EDC6ULL,
			0xC3EC842018AF75E0ULL,
			0x54AF6C240D293655ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x55E0768C369F0628ULL,
			0x64CAEF09B8563FA4ULL,
			0xF1DD07CEC423CC4BULL,
			0x7E292A7D7E13CC6AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x33E809B4EADA74CAULL,
			0x0105101E7A568737ULL,
			0xF11A57A8DE496C14ULL,
			0x0F76C9D977F4EA63ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x648AE75D6CC92980ULL,
			0x01120F06BF5A8285ULL,
			0xF894978E363A1F7BULL,
			0x31C6EED9A7D27111ULL
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
			0xE3DA7897A8ADA4F0ULL,
			0x76C963DFE5A3CB24ULL,
			0x5941FA013AC53A77ULL,
			0x6857C95862F748B0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFEE1E23462CBA45AULL,
			0x0E9E7B6B62619949ULL,
			0xDE2E77B5DF2AA04BULL,
			0x03B22CF9A081FDF2ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE8063939E506CA48ULL,
			0x6EB4C5E17291FEE9ULL,
			0xB94942DDE57931EBULL,
			0x508444856CFF2E58ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x883D2728387F648CULL,
			0xBEFED882AB7ECECFULL,
			0x8CEC75DDCB049186ULL,
			0x26C27E609F06AB6BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C255562A81D328BULL,
			0xB2728494763A7190ULL,
			0x6E0296AA0D3B2CDFULL,
			0x6148F9037CB1F4F8ULL
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
			0x2931659F86A98AB8ULL,
			0x418C8509184EBFCEULL,
			0x8211057A56E928B7ULL,
			0x6A4B5FE956D15BA2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD5EFBE316CC33B87ULL,
			0xAD1259F4F8F40FC3ULL,
			0xD43E0A4135FFB9B1ULL,
			0x4B3A74D8217ACF79ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1A8D365D48AC2E20ULL,
			0x3C466F293C16C4CCULL,
			0xE3C89764A15CF61DULL,
			0x62B044E9A7D02F32ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x835A0761B5F99B9AULL,
			0x4C6F3CFDC437133EULL,
			0x60801FC409F5CCE1ULL,
			0x4E8AB7AF832679D6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA2ECE417144D44A8ULL,
			0xAEFFF2F65CF902DCULL,
			0xBDF527F52AA015E5ULL,
			0x2DF19066378FA213ULL
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
			0x3A4C738E98244C98ULL,
			0x49E2391A562FF76BULL,
			0x31017B4B01EC05F9ULL,
			0x729473F6FEBE73AEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x73AA6D9DA314D2F8ULL,
			0x5420F36C8C2AEB96ULL,
			0x370BD142F8CBD6D0ULL,
			0x2BD096DA07B4A87CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9BC1A694DEF49668ULL,
			0xB7497F6C9BF60106ULL,
			0x76A635C709BCCFA5ULL,
			0x57F92C3BA9AF491BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCA8FE4103D6784B0ULL,
			0xDF7D018BAFEF82D9ULL,
			0xE2DB1A79C91C282CULL,
			0x10CD55AB3EE57002ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA8D7D93FC5065CF0ULL,
			0x3911F96906BAB9DBULL,
			0x77C1C6D8FD099C88ULL,
			0x3AFDB6BDFD4452CFULL
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
			0x650D32BE044CCCF0ULL,
			0xFB87A658201C631DULL,
			0xB77A95110F3CBC22ULL,
			0x4BFBC865B212D0EEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x72645B5F3FBFFDBAULL,
			0x776AAC513B577AEAULL,
			0x940EF4A50D758FF8ULL,
			0x5468484BEC50E859ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE8995CF1604A70B8ULL,
			0x3B1E97E16C4D1807ULL,
			0xDB1AF01205965A65ULL,
			0x585A354A1AFB4502ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8DE9BB90FE757BB0ULL,
			0x07FA5A18087727B7ULL,
			0xA4C4B70BA57FD6EBULL,
			0x52A5485E00D27C3FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x456A5AC5F69DF055ULL,
			0x38927C1E3B5D62CBULL,
			0xAD926A760D0242AFULL,
			0x589C78C59E36A150ULL
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
			0x9307EB380A700FC8ULL,
			0xD48F6C7E76A23F45ULL,
			0x2F2DC618DEA79BD2ULL,
			0x6B02D1C1228502A3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1DE643BBE131104FULL,
			0x2EA9FC58D0123C08ULL,
			0x41052646DA2E9C8BULL,
			0x2F2F1617EF1BFB90ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5CF9040E817020F0ULL,
			0xF70BD4DD5DCE693FULL,
			0xAFB409A73BC4D4D3ULL,
			0x43CB5801B015A10EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3C0B404811B5A6A9ULL,
			0x511E0F7A2C5F3AFFULL,
			0x3D932E8586423E59ULL,
			0x7C53235A74EF98D2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5ABBF67407E1AD60ULL,
			0xF84B4476BC2CD671ULL,
			0x5911B0272094D5E0ULL,
			0x5DE501E59BCD3EE4ULL
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
			0x56BA338015321A20ULL,
			0x7AF1C93890C7D497ULL,
			0x929E282088487D65ULL,
			0x7D69FB711C9AC37BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFA6AA55B528FD3E8ULL,
			0xB49B1D0B49AE6A65ULL,
			0x7589EDD7320D866AULL,
			0x6805FC5E3A568EABULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x75FC7A43F0BC6640ULL,
			0x60131FE084071AE1ULL,
			0xCC939BBD7B95CDECULL,
			0x54EC014A13400CFEULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA4D5871BA1D37999ULL,
			0xDF3F40DAA9908424ULL,
			0x5B0993B73B90E332ULL,
			0x5C1011EA72A2B1A7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5CC3E44522C94792ULL,
			0x2DA678C7AF65F108ULL,
			0x7E9660BA97F68239ULL,
			0x40505AB351B66290ULL
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
			0x9E7DDEB06C707E58ULL,
			0x749850645C225EF0ULL,
			0x41471362258295E8ULL,
			0x666131E402E1776EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB13E0CD3116E1911ULL,
			0x3DABDAA837553A6EULL,
			0x18BAC149F5FFEB33ULL,
			0x1A3B086874D9E669ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x599672BFDF43F720ULL,
			0x221993BC2AF95F3DULL,
			0xED985BCEDF5C22CFULL,
			0x47DCB2F907EBC8E2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF7B44568211F1B0CULL,
			0xF229C3D92742364EULL,
			0x2C704D994C72E68FULL,
			0x1D567439FC7D0DFEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC385EEE3AF28935CULL,
			0xE1E0FD2477A8D13DULL,
			0x38BB1E8539D35EAEULL,
			0x477AEEEDEC20D168ULL
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
			0x95ABBBB2496D90B0ULL,
			0x1E72E4DC86C0C787ULL,
			0x2472C94FF5F23FB7ULL,
			0x7306EB7A656CA73EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15C8D9B6DC583709ULL,
			0x94AF4A4C36980015ULL,
			0xF7056C1ACD2A04BBULL,
			0x05E9A3D31FC2A221ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAE3F8D352A017448ULL,
			0xAD4E67B2B8714915ULL,
			0x3CC16309AAD01295ULL,
			0x694CFF67E6074355ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC30F11ECC1F5144ULL,
			0x100892A9E249C54FULL,
			0x5B7B07617EC1EBDBULL,
			0x4CF7F10766C33A90ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x87AF03667BB30A45ULL,
			0x4E8C94E8398D5975ULL,
			0xF62D8ABB355E7F1CULL,
			0x5452B6922DEEB8C0ULL
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
			0xC2CE5B43D25618C8ULL,
			0x3E33A727B033CD49ULL,
			0xB9C63E44AA19C05BULL,
			0x556FEEADAC8B7CA0ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x85ADD694C07068F9ULL,
			0xD134B954B06B3055ULL,
			0xED1EAE8DB9968BCEULL,
			0x35BA5482F8DCF3EBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x467FB96F931F4758ULL,
			0xCC3820A2D2152133ULL,
			0xE818B7430910F95FULL,
			0x5489B31E7B3AA27FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x86AD31159E03ED5FULL,
			0x92335ABBDBB6169BULL,
			0xC961F2951C1602A5ULL,
			0x61AB4D034E6A2A82ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x114110F3D2CF6A2EULL,
			0x6D033BE84AE43D76ULL,
			0x1B2E0052136BC490ULL,
			0x02E45D097B12DEF5ULL
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
			0x05A2B20BD0D057D0ULL,
			0x868BA78961A2DCD8ULL,
			0x343906B7F3C258F7ULL,
			0x6E30C97B5ACF16ADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2B042F215875AE6CULL,
			0xBE8C2406451D9900ULL,
			0x5DEAA91588E3CCD0ULL,
			0x6E79D2A42150040EULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x269516E235CA5500ULL,
			0x53DDDEB57C68214AULL,
			0x1C0C67117084F9CBULL,
			0x66771CB53E75911FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5A5B930565E37292ULL,
			0x0F667211D7063B6DULL,
			0xBCE35DC09444F30CULL,
			0x77500649440089F5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0ED3A2D6D57A9FB0ULL,
			0xB01D641AEB325CE4ULL,
			0x0FF9745F9786BDBEULL,
			0x0FB5199D7DCF9FA6ULL
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
			0x06DD3329D615EE60ULL,
			0x3F46CD372D5B2394ULL,
			0xA2A5692F14F87F4CULL,
			0x65573E105D389E9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD4C8D76D9A9A9AA6ULL,
			0xCDDAD40B2A6DA4F9ULL,
			0xD456A7504674460AULL,
			0x62D9EF29570138E1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9A4C796C7FDDC648ULL,
			0x952E0E970822913EULL,
			0x6EB9A0414BD34F19ULL,
			0x75B984201B3A1828ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4E2EE862C2C9853CULL,
			0x9930E55952B734D9ULL,
			0x84C53A8DDB771CC2ULL,
			0x0AC5E280A19137B0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x156DD58C1EB61D8FULL,
			0x8382EDDCC4563B75ULL,
			0xBF3565587D547AA6ULL,
			0x2BDCE22EED9E6CB5ULL
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
			0x5E158539A7BC4E68ULL,
			0x416527BE062D5172ULL,
			0xB1B00D3C892A2A2FULL,
			0x4C51EF282C8CE2FBULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x056100E75297290FULL,
			0x79F11240E278A7E9ULL,
			0xA065D6931BA2FD24ULL,
			0x5D48C5D1B90317AFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD305B9BD99CB3958ULL,
			0x5E51A5488DB3BB5FULL,
			0x402D74C4BE15057EULL,
			0x61E75475D80AC8FBULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x412B088CB1BFA0C4ULL,
			0x35BC68A3735C6BE9ULL,
			0x567C2E4341368915ULL,
			0x4F05BBDF8CD883F3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF4F68AEC7D3CDAF3ULL,
			0xABB8BC62348E74F1ULL,
			0xBBF2A73794D1D918ULL,
			0x285184A2DBD9E5C7ULL
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
			0xAAFD301653DF5090ULL,
			0xD15019FAED305E8CULL,
			0x7DE785CDC43F8009ULL,
			0x503556304E70D355ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0E29F6D5E17566D4ULL,
			0x189C54209FDCF15FULL,
			0x1E1C9F1204CF1387ULL,
			0x00375119FAA7662AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB07388395FBDEAC0ULL,
			0xAF23A53F9F0C0C17ULL,
			0xB0F4EEAB3857457EULL,
			0x5EC4AFBD2A94C199ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xAF162BBDF8E5657BULL,
			0x558B104B5EBD8226ULL,
			0xC108B9519E8F3C83ULL,
			0x7150170DB1FBDDA4ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE16D8450A3E34075ULL,
			0x5C77DABAB4DA81C0ULL,
			0xECB721CA69CCD54EULL,
			0x40A9F0B03AFF834FULL
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
			0xAC87CB930D717578ULL,
			0x213494817DCBB5AFULL,
			0x57488B92262C2188ULL,
			0x6C06FEB0AB5C6542ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x002E053F77FB1F07ULL,
			0xDA9B830F28252412ULL,
			0x6B6B60427AD050DEULL,
			0x138D0332436752DFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xEC09D6867A84B9A0ULL,
			0xCB18CAACAC014C30ULL,
			0x90F30F96B3E83284ULL,
			0x4ADFA4F26108A586ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xFCCDCCAE97A662DBULL,
			0x4D121959299C3965ULL,
			0x85EBFA6A9B3D146FULL,
			0x66777486B2842D05ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x917D3BB1C27BE197ULL,
			0x4441BAB9B1C644ADULL,
			0x61C57A5F63DA6A6DULL,
			0x406698BE130B9CBCULL
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
			0x915106FDFFED21D8ULL,
			0x4C196917FF7B7AE3ULL,
			0x950FD93FAD334417ULL,
			0x53A63428F2D27FD7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x558A1212EF2E59A0ULL,
			0xEFA4B371FA699073ULL,
			0x9AD0DF25F3A70177ULL,
			0x12BB58305A0D9CF8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0896FAD6A6EF2990ULL,
			0x25D68CEFA45F7032ULL,
			0xAC9D4C3D35E2CDDDULL,
			0x486C39552D85E663ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF8C3D5CA03767473ULL,
			0x1314EE4726F4B78AULL,
			0xD3571142D6A3B32DULL,
			0x5DC3191F8BEE2C1AULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFF2D957C75B5AEB4ULL,
			0xDCAA534B298906C1ULL,
			0xB95B4678AC805A77ULL,
			0x5387DB3B91CF1215ULL
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
			0x08E630BB3928BBD0ULL,
			0xEE55E69C205FA634ULL,
			0x89915C3778677C48ULL,
			0x7F57B1DE1911FFDEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x14C9BDD73F3E241AULL,
			0x21D7F3F886B66E98ULL,
			0xFE7FCE4BAFCD814EULL,
			0x5F0BE9DFA00E06E5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF519CE63F5907A98ULL,
			0x7E4E9AD2B1FB9E92ULL,
			0x468A7D44977D62F1ULL,
			0x51788D40EF87FEFAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF665B8AE3E91B970ULL,
			0x60782AEBDF723AEAULL,
			0x6270D6D276A35C2DULL,
			0x67137CDA3CBE5898ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB1C47D73C368D3A1ULL,
			0x9AD667ADEFCC0BD3ULL,
			0x3FF66E334BF4D183ULL,
			0x3C5326B4D21ABFFFULL
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
			0xC559D799C725AD58ULL,
			0x9B02EAEA18B0F880ULL,
			0xA6B3D737032B5880ULL,
			0x50AC35C1F585EE9BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD9BF1AA7C4FD55C6ULL,
			0x5E3DC0EED11F4FDFULL,
			0xCE4956C112DD0290ULL,
			0x79D2E368EC701593ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C81242644215628ULL,
			0xA302A84187EA8D3CULL,
			0x60A72400EED66E49ULL,
			0x7C38D733283F1DFFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xEBAF7DFAFA584645ULL,
			0x3DD8DBE40D7F6450ULL,
			0x3DD3E115097A0052ULL,
			0x06FF3EF02813F917ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C2BFF946C9CDB68ULL,
			0xD8AFCA74CE2DEC88ULL,
			0xBC586FAF46BB625BULL,
			0x300286E35B091CDEULL
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
			0x6575DCB6A40ACF08ULL,
			0xAA6CF8737EAB2B71ULL,
			0x849E8BF0ADC46EA1ULL,
			0x624F2DA8741B5CADULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xE1E6D4C2FF0F0F1FULL,
			0x0B1D02766BF565B1ULL,
			0xC137ED1836546EB6ULL,
			0x7CCD27FAC3A9F0CFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x50D7581B94A951C0ULL,
			0xDF0B74F0EDE9A019ULL,
			0xDD09183B2F648D4EULL,
			0x67B04332425031E0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x3E7049080597E6BCULL,
			0xD50D0DBB9ADE497FULL,
			0x10DDCA83517D4037ULL,
			0x631014537DC86BE7ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x57E5179207C2D8CBULL,
			0x9E2A4D2E3A535745ULL,
			0xCFE136EF517E8399ULL,
			0x42D693681E68C7F2ULL
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
			0xF5B58D82C5F43558ULL,
			0x61E6550623956402ULL,
			0x8D6E2821512A13B1ULL,
			0x658F97735A82D20EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x303C52EAF4F9D232ULL,
			0xF4A3E9385A7F74C0ULL,
			0xBB93100B462D9004ULL,
			0x4F67785CA8404909ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x63AE8782CDD26B10ULL,
			0xFC1E452CB789BFA7ULL,
			0xDE5BCBF54A1D3197ULL,
			0x681E32BE5DFC3208ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA4F0FD6A43BFEC2DULL,
			0xEEC744DB2C9BD9BFULL,
			0x93C66322CCB98301ULL,
			0x436D0592BE078E4BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x082FB05256692EE7ULL,
			0xBE6B39C90DA1980AULL,
			0xFB41FBCD87F25840ULL,
			0x15F01C04CBD8C0DDULL
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
			0x345F105E4857B620ULL,
			0x321C8893BC6CEF96ULL,
			0x01DCB2174787F214ULL,
			0x674AB69DA19715ACULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC583BF08B30AEA4DULL,
			0x867AF381E5829C26ULL,
			0x67A31A9A2C355AAAULL,
			0x6F277388E24B89CDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x507FDFF05548B370ULL,
			0x722A1794B5AE452CULL,
			0x51E49A9E6C96FBD6ULL,
			0x4481C5E1B246863DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD5A4078732B64DE5ULL,
			0xE95020C499CB2A78ULL,
			0x811F6A4AF18C44A3ULL,
			0x11E29431591751AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF067F6A8235B8F41ULL,
			0x92167FDDE9A9E078ULL,
			0x06943B33B075CDFBULL,
			0x36F0E093A33A59CFULL
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
			0x21CA1BE187B19180ULL,
			0x84E017B800FCC817ULL,
			0x2A5EC2221EBC01F1ULL,
			0x614BB7D11D2EC4A6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x935634B3F3CAC67EULL,
			0x1B7684144CB42C6FULL,
			0x351EE7B5E94EBE5CULL,
			0x5447C23DFD4FF793ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1428D6793BB691A8ULL,
			0x5673194B8AB4633AULL,
			0x80E75F39244AD143ULL,
			0x5339F7A7F8DB5858ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x129B7205DB245A79ULL,
			0x27044964C7052DF1ULL,
			0x4503DDD594F01C14ULL,
			0x70FC77FD2CF82B67ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xED5373D49CB010E8ULL,
			0xE42C9924EDFC80A3ULL,
			0xF1A2D07B9E012194ULL,
			0x10B4FCB1EEF93441ULL
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
			0xEDA114D541E1B7F8ULL,
			0x105E9919B6FC6CE6ULL,
			0xDBA4D1EC9CD8688EULL,
			0x67788A49F1F656C3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x83A9348636DD052FULL,
			0x1965576F50846463ULL,
			0x4F460AFBB5F739C8ULL,
			0x048E34692E6B3117ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6C296E6614E3E5C8ULL,
			0x5E69230D6963E31FULL,
			0xB4DBB6CA691D6A81ULL,
			0x41338C224496C796ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x468E32CE19EDCA9DULL,
			0xA6A7087800F922CDULL,
			0xCE5F0627A3415D26ULL,
			0x427CAE4A12267292ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBAFC6A5CA31F9320ULL,
			0x94B220840B033682ULL,
			0xE4141CF920D0CC1CULL,
			0x308357DE6C5F908EULL
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
			0x3A6FA3E2C85CB1F8ULL,
			0xE047188B0704A783ULL,
			0xCE19DA64788720AAULL,
			0x7C861ADDB82177DEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFC581327B30C817BULL,
			0x8FFA749C90EE70ACULL,
			0x34C6C9C80DFDFF10ULL,
			0x44031FF1622614D5ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x6091B7608F08EC78ULL,
			0x3EDF0EBB2FF83B8BULL,
			0xCAA5F893FA419801ULL,
			0x52BCFAE9AB2581C1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x395EE092DD8B3183ULL,
			0x03A9A5A0D7AB1930ULL,
			0x9F3EB92B84E7167BULL,
			0x723ABD6A924BCD12ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x12181D76D37D7B4DULL,
			0x94424F7991C8FDECULL,
			0x6C495E2C1AFE5ADFULL,
			0x5A48C60A2E982AF1ULL
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
			0xAC30D6362AFEBBF8ULL,
			0x828C2DF623181E8AULL,
			0x322462844FB5DAA4ULL,
			0x5F0E8291EB23E18CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xC600CB3924C81793ULL,
			0xC0415273941EC3AEULL,
			0xE684843152530369ULL,
			0x39FB0653595AE64CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC6B2DAE466813B50ULL,
			0x602826E5AD40C9D4ULL,
			0xD019E849A0C11875ULL,
			0x4B9234E98C754401ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF9EB39F2AC32A2A6ULL,
			0x63218A233EA470F5ULL,
			0x980357CC2FD0313EULL,
			0x256E0D565DC5EB53ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD83B35AC84024C67ULL,
			0x16AC85CF3D5C0924ULL,
			0x2BF36488B6C44346ULL,
			0x2C8F1CCEDC1AC53CULL
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
			0x06F535B6185D5D20ULL,
			0xC08BDF50F4DE247EULL,
			0x5296D835CC42586CULL,
			0x6D14663DBA76F57EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBC681250C90E8DFFULL,
			0x9831261A538AF1CAULL,
			0x37E67D5BE765F9AEULL,
			0x315E2183730ADC11ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA5D75A574826F2E0ULL,
			0xE3006BB8F8D435BBULL,
			0x705F7699899569ACULL,
			0x45D32738C2FFEA6BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1F0D4FA6BBF5FEC1ULL,
			0xF29AE6230B0AE69CULL,
			0x6EA1A644A9ABEA5AULL,
			0x266A1BEFA1EA1A32ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xBA45C6F41CE3E45BULL,
			0x56433A17FD6047A9ULL,
			0x2A56F2F867B3D6B5ULL,
			0x6908E70CA35A57CDULL
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
			0x3C2C2901F0165218ULL,
			0x9C9761A04320C6E7ULL,
			0x418FFF065DF0B63EULL,
			0x7C930A4CBE275F42ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x899616027034DF91ULL,
			0x867BE49AE16CF12BULL,
			0x960FD3AEEDF00CC8ULL,
			0x3F6FA4B19B0CBBD8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE65C13ED79B5F5B0ULL,
			0x603F0EA6420FBE88ULL,
			0x44AD55C0AE2E1880ULL,
			0x7F0B728334E56F78ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x78DA07776C396AAFULL,
			0x00FDF4788844568AULL,
			0xC87DD0F10195C2E7ULL,
			0x6DBF51A40328C49DULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6958696394FAC654ULL,
			0xF0B332B621031717ULL,
			0x933DFA9281908DC8ULL,
			0x4B093D7CC06F25B4ULL
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
			0x541CB09C96274FB0ULL,
			0x7E78305BF943285FULL,
			0x60E34CC2C43D515CULL,
			0x490D263A0A15F546ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x87CA04265194DC7DULL,
			0x104377709A41E530ULL,
			0xDC568C8C64426C3FULL,
			0x5D72EE91A75165AAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x87210CC6FB586DA0ULL,
			0x735A16C33AEC7F8BULL,
			0xBCF1B6D584316F56ULL,
			0x4CEFE0E7990965B1ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x1D7086DD4D93A0CDULL,
			0xFA8D43B66F869C8EULL,
			0x6CAD9E92CB5572FAULL,
			0x74A3CAF8A5789B15ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AC115C5AA0AF16CULL,
			0xC47BEEA8B1B04BF4ULL,
			0x4E599EBBCB4FD16BULL,
			0x1BAB245F78CAAFE6ULL
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
			0x1DE922F1485875B0ULL,
			0x2DBFE53083051A72ULL,
			0x204B0519E790A05FULL,
			0x5885008069EA43A1ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x94418232DAF1C3CDULL,
			0x1058ED9988969FEEULL,
			0x7B6EA20A17D44BB4ULL,
			0x578A003EE4F3C1ECULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9328DBFEED281B70ULL,
			0x29CA0318724BED31ULL,
			0xB3D68D54F39B9738ULL,
			0x5F1718181CEC13C3ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8CA78E4E5022B99DULL,
			0xBC082132DB591D24ULL,
			0xBAD7A88B9C1DE7C6ULL,
			0x36C139D433CED645ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE0E0DCBEAB8443E6ULL,
			0x0C795E6616CC926DULL,
			0xDEEC811DEAEBC84CULL,
			0x2D49D24151D5BB38ULL
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
			0x5E842D2A47BF6C80ULL,
			0x3A684674189733B7ULL,
			0xC3666728BDD3D80BULL,
			0x5B52C6D9468FAEA9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA8A44631FE5DAA05ULL,
			0x29F33EB3575252D3ULL,
			0xF7E55BDC5F575399ULL,
			0x5F25A6F6AC3C9711ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x64F185591BC04360ULL,
			0x83DD7CE24674C5E0ULL,
			0xD766B6D6C19D4F80ULL,
			0x662D609C6C1F2DF5ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x741F8B347D1CA6EAULL,
			0x2D32B3A290261A94ULL,
			0x4F7C03B80E9FF56EULL,
			0x3CBA4909689025A8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF5E265CA8F22746CULL,
			0xA2CB1693AF4A9725ULL,
			0xFB2F9C474792DD47ULL,
			0x7C45BFEDCDBCE1C4ULL
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
			0x0A36DE1573FF0510ULL,
			0x57CB2188EC32DF53ULL,
			0x1334F1F2B710E315ULL,
			0x4D3A0A820055AB5AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x76B7A6E50A18F2FEULL,
			0xBCDADE96F8B33D0CULL,
			0x10071141F82E06A2ULL,
			0x4380139DC145F947ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x51BAD9E10687FB38ULL,
			0xC328C085EB88ABB0ULL,
			0x46633336B6C5AFD7ULL,
			0x40FCEF9183A7FE10ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB1DB5EDBD65E781DULL,
			0xC170C36154746CD1ULL,
			0xB2FC2F60A467B6DDULL,
			0x26C97A5CC68E0944ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x92FEAFDE94CE1BCFULL,
			0x6B70E70624C4CF6BULL,
			0x6E9693D755FCEFA0ULL,
			0x39636BC014B14AB5ULL
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
			0xAC309CF02406FFB0ULL,
			0xEE4108EF8BDEF410ULL,
			0x5B35CD9DD372C6B8ULL,
			0x581909559DB1052FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAD1BBB64B25AF9F5ULL,
			0x31823AFB1DD84331ULL,
			0x05951E428B838555ULL,
			0x28B28DB26D1EEAADULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x55446A571D6350F8ULL,
			0x78087BAEB104372BULL,
			0x9B3F8778999B647CULL,
			0x6FF9C30F0E3285BCULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x15B04319029228FDULL,
			0x99D692F626BA8668ULL,
			0x6773F1DE18C8945EULL,
			0x3ADB20AC932C8387ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB246DCD02D90EA1ULL,
			0x81C5F3E2DA56CC6AULL,
			0x01483923291B8F92ULL,
			0x5CD83F98015BDD62ULL
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
			0xF5757245B1609818ULL,
			0x1FDC5E0686CCE65BULL,
			0x31D0AD9223B28917ULL,
			0x7754E48DB75D0CEEULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBF491A2735826862ULL,
			0x8A1422C6531C3DB1ULL,
			0x7551BEF05FC1A181ULL,
			0x5BEC755CF3D4F1E1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4236172A8D48D778ULL,
			0xFA7E7337F2D8065DULL,
			0x4D24CACD68E669C2ULL,
			0x5E203619D9BB3E43ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE711AA0102D45FC1ULL,
			0xAB419791143C6012ULL,
			0x3EC08E61EED638A7ULL,
			0x3849261F3B748003ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x51339911F4A1337CULL,
			0xF2E92C5F29DE0A2BULL,
			0x0C8C7EC01100AA3CULL,
			0x6C02611DE63D6918ULL
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
			0x11DBC7BFB5BDC850ULL,
			0xBD844903EF4250EEULL,
			0xDAE3BEC5A60F0DE5ULL,
			0x5E6AEFFF409B0DA2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x74743B1068EEF163ULL,
			0xEFFA54BC013FACADULL,
			0x5A91BC8E643CB06AULL,
			0x3421FD687C8AFDEBULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4C35C93FD8F1D770ULL,
			0x0F0E9F5D7A5B22C6ULL,
			0xA68E5D84D96A6BCAULL,
			0x50B4FB7509EDA420ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCF4101F68AE5CE07ULL,
			0x0D48ECA5C27BA3E6ULL,
			0x5F79A3C99DF6DFF9ULL,
			0x68A4CF269A067D90ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA214B9981584232CULL,
			0x42B20F937B226FD9ULL,
			0x92D63EF1E676220BULL,
			0x4421DDA6594AB904ULL
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
			0x692F753B06DFACE0ULL,
			0x939A7C2282AEF226ULL,
			0x8D801F96A7495851ULL,
			0x5FA556A0750C2409ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xD6E9F7D4B5917732ULL,
			0x90623A179899BB0FULL,
			0x33D91CB242EEDC56ULL,
			0x61E8E2772670486AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x424D9C6984581B80ULL,
			0xE9F8339F713A2926ULL,
			0x7780A4A374173BDCULL,
			0x4F8685C1BEEE4F25ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBFA2519A91D6296FULL,
			0x047334DB01055791ULL,
			0xC6BA103646EB5FE2ULL,
			0x6D5B172502262FC5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD46D456A2FFBF519ULL,
			0x77EA80E73EC3F5E9ULL,
			0xB3561A1854909ECFULL,
			0x605C2E04C7B10814ULL
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
			0xA6E5E30F4EA78F90ULL,
			0x238A31F89BCAA206ULL,
			0x8062CFF2990797F9ULL,
			0x76D748CF1E8A0B94ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x26E9DC94D0BB6083ULL,
			0xE2A970B421F14707ULL,
			0xF040E4FBE1790FA8ULL,
			0x28D2415C48D09C48ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2C49741804F266B8ULL,
			0xF5C86A899A35F87CULL,
			0xD9A308CAF8ED7A21ULL,
			0x7AEFA5F31181E300ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x36A016B18EEBB24FULL,
			0x14C13DFB1285F5A7ULL,
			0xCA9FCA7DBC59AA35ULL,
			0x7E412A214D3F9AD6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB460E33958857EAFULL,
			0x9ABAE7A9FB722EA7ULL,
			0x9B28D29700169072ULL,
			0x4585508D38B442FBULL
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
			0xE2A001FC65DAF380ULL,
			0x6172DE624299948AULL,
			0x2FBE6764989EEEFFULL,
			0x4DFBA6BFEDC2661DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEE1DFF2AE8F9862FULL,
			0x2D8DC1678D1A695AULL,
			0xBE3501D33D5790FAULL,
			0x4CADDE9A0123EAA9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9DA8EA42C5731BE8ULL,
			0x2CD8911BB04B0407ULL,
			0xA2B5EEBB7D1996BCULL,
			0x6DF3C4A06511649FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9857D40754CC4F62ULL,
			0x0C5AF4D49923FB6EULL,
			0x03D40D5F8763EFA3ULL,
			0x3FBB1162938D3DA0ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB1D6B2200F0E180CULL,
			0x27CAE47A2832D1D8ULL,
			0x0B13878B92646DACULL,
			0x0D031639C0B163DEULL
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
			0x1EFF06D47061CE20ULL,
			0x90FEB0499C67E138ULL,
			0x591D527D52606F34ULL,
			0x7A2059935ADDAA1DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCCD5144E78FDC9C3ULL,
			0x638F61A85200498DULL,
			0xC3040F324CCF3C3EULL,
			0x2C350F5DB4B11300ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x481DCBCCFFAB8EF8ULL,
			0xD441CBFF154BD495ULL,
			0x1FEAF2C5B1CEA9F0ULL,
			0x6E1987AAF1453127ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCA3F14EDFE2B2B8BULL,
			0xC70E17B77D5AD68FULL,
			0xED88955AFC88216BULL,
			0x224FC72838105761ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x4479B236222B8636ULL,
			0xC59FCB2F715F35ABULL,
			0x87870ADE1995F5EBULL,
			0x7F812221B9681889ULL
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
			0x3215A884C258D450ULL,
			0xAB14C5AA84021D21ULL,
			0x447189EC58DB78ACULL,
			0x473331FA96AF9CD7ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x439AF66158BAC2E9ULL,
			0x61ACB64DA44EE04EULL,
			0x7D5E36B933D4983DULL,
			0x0409376F41084E3AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF7736C255CB094A0ULL,
			0xC5B76C5D451A86F7ULL,
			0xEF62CF56FB8A8BB1ULL,
			0x6FFA87B38224CB0DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x41509A68FF8ABCD7ULL,
			0x68243DFA3A15DAFAULL,
			0xB6576583CEB1DA0BULL,
			0x5D29917A92518512ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC26EA28D1F607225ULL,
			0x72149AEA071337B3ULL,
			0x5C1F9BADB92A6B6CULL,
			0x0A05C598540BC032ULL
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
			0x07B9B3F58A219D80ULL,
			0x77BD19BC7236DC3CULL,
			0xCB9E8A18373D664CULL,
			0x5A387D3F19375E67ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x509C813885C7E70FULL,
			0x1CB268A18E2AE995ULL,
			0x2BB4041B30106B4AULL,
			0x7583C3954714DF1FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBB6664EB8C4BA378ULL,
			0x1DD569FE129D3E02ULL,
			0xD48B7B92B41F8FB9ULL,
			0x7A1273A906798DDDULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x025C79534135C0E6ULL,
			0x0D77462D28EF3446ULL,
			0x2B8739A567CAD326ULL,
			0x735D44B3C7232F75ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF533E1D03BB21E60ULL,
			0x04340D7082A30F46ULL,
			0x5E0F5F1799FCA394ULL,
			0x2046C9C1D670DFA4ULL
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
			0xE79F0B150D3271B0ULL,
			0x6A05DF7E822375FBULL,
			0xB4D2725D2D353A66ULL,
			0x6B4D561E8A15ECE6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEDA2C3AFBC343207ULL,
			0x56EB3673ABE9A5D1ULL,
			0x9360589AD8CC6495ULL,
			0x3D170A26F8EC45B0ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x68D17FD0910886B8ULL,
			0x8C2E41CA2A65A49EULL,
			0x87A16C90A083B5DDULL,
			0x7ECB58785DCBCDC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDE756891E0EB55E4ULL,
			0xFF8020A525161E8BULL,
			0x58B8D957476569F6ULL,
			0x14FFF7D030039028ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x645A615AAE26C6B2ULL,
			0xD577BE6458660A61ULL,
			0x0AF4AC41E25ED4E8ULL,
			0x1CF6018BA0255091ULL
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
			0x5F457C3E0DDC71F8ULL,
			0xFFD77F4535A5421DULL,
			0x517CA0DB5AF68910ULL,
			0x53BE9F70CE91DA1CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x86B6B34684F71093ULL,
			0xF6E4B69EC22554FBULL,
			0xDA15BE248E2314ECULL,
			0x27CC44144C1F1EF3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x431B07E8C74F1598ULL,
			0x22842475612DD567ULL,
			0xA1756B8EA505E34DULL,
			0x78C2A4AADD092235ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x10A1BAF76E074ABCULL,
			0xFFFA9F5FE175E3EBULL,
			0x2A91E1F88B91841AULL,
			0x3A0293248876C4A6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xF13B92F0F803C0ABULL,
			0x076ECD8CDFF9705FULL,
			0xF0F3C61627ACCCE4ULL,
			0x79983DEB7BBFA531ULL
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
			0x49014D8AF0472B78ULL,
			0xABDE2F13DFD49918ULL,
			0x6AD0264740B63BAAULL,
			0x6BB7863D0CB3B61AULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x99B09565FB2402DDULL,
			0x2ED719ECBE66B5C5ULL,
			0x31474DDB9C1D48E2ULL,
			0x1B67541E5E4C7593ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3E6ACC358D1D2230ULL,
			0x02B436F6524C96EDULL,
			0x95083959952F0281ULL,
			0x73284CAD0D1DDF8FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF1CA7B7F9035582FULL,
			0xD192E00AC75F8EEEULL,
			0x43AAD545E4FB82BEULL,
			0x1ABE72EBD9C476FDULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB016869D61B33AB8ULL,
			0x6831A2510BC12250ULL,
			0x59EA8218709FEB4FULL,
			0x513E86F87439B146ULL
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
			0xCF23837488E89E68ULL,
			0x0DB5ADFC0FCD397BULL,
			0x6BF39C9281FA5752ULL,
			0x6FCB15904143A133ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8DB6F76F4678B112ULL,
			0x53C60EEE16ADEDF2ULL,
			0xED968E184D74B9CCULL,
			0x4E12A57209B96AB8ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7B33B005F35FCD88ULL,
			0x150EF818DEA917FDULL,
			0xF8A4268AFF6E209DULL,
			0x452DF80F68E2C7CAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x968436AAD3F27202ULL,
			0x0A450021E19C5BA2ULL,
			0xCB91E6860BE297D2ULL,
			0x20DA2591F8F132AEULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5B01BFAD6CC525E8ULL,
			0x5D3B4BCF5FBAD4C6ULL,
			0xEFCBB90FD25324DEULL,
			0x1903FAB0F2B3109EULL
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
			0x80E71EFD8DE4CE80ULL,
			0x9D5AD443B3E5BC00ULL,
			0xC3A5847ECF698822ULL,
			0x70D9FB3075E024C2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEA314481620AE6B3ULL,
			0x0B24781A9455A429ULL,
			0x2F6D629C6ED86CF6ULL,
			0x51F11028F219A499ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xAF29AEA3F3D3D918ULL,
			0xDB1FA9CC4A58AA15ULL,
			0x56F822A9C220FCA2ULL,
			0x6E090B98B93366BAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5647445D28413FEFULL,
			0x98CE433FED42A44CULL,
			0x2E5816EB5B5B3EE0ULL,
			0x227A69FB8E83DB3CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7C21F682513E1A57ULL,
			0x7A32347D1DB30EE8ULL,
			0xC7B9F6B4B43A9303ULL,
			0x016F9BFCDDB239ABULL
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
			0x92052BAB20F73000ULL,
			0xB3F25D794B8D578FULL,
			0xA6A97D6A090B6774ULL,
			0x4EE10120119DFDCDULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2F69B3AB779402B4ULL,
			0xEFB89244B45A62D2ULL,
			0x31F7DF51AA3D6FA1ULL,
			0x5172415E44BAC3BEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x2F00CC73B5495DD0ULL,
			0x2816012B68362AE5ULL,
			0xEAEF2C4617147F86ULL,
			0x716DF82BE16A738EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE3176FA7E745E769ULL,
			0xE3C5E9D38FE77E8CULL,
			0x2786188F0FB00D33ULL,
			0x70B411952DE9FF44ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE87E4E7569EB5CDDULL,
			0x303F33C63810A10BULL,
			0x0AD1C79D057FD5C5ULL,
			0x401E91C65D477CA0ULL
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
			0xCC85EDED45FDF0D0ULL,
			0xB133F64CD4786E87ULL,
			0x73D915752002AA41ULL,
			0x549E69A63CEBDFF5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2D68A7F225C62097ULL,
			0xC5B5CDD148289F07ULL,
			0xAF242665223AB315ULL,
			0x4D1930BAF7226170ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x28CE1442A5685B18ULL,
			0x6E75747038A1A324ULL,
			0x9593BF038745EB6BULL,
			0x4409BA0E7F6E9F3DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD71C7B897AF83AE4ULL,
			0x0405180BA9419044ULL,
			0xAED615E078B0E266ULL,
			0x0FC63D23B9CF7E4FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x92CDC38F2FDF6C97ULL,
			0x415F77D054B25397ULL,
			0xD2C1356502EAF8FDULL,
			0x650957B016769674ULL
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
			0x16B6535B196F24B0ULL,
			0xF8331FDA0B3EE7B7ULL,
			0x7558C5538D0EB463ULL,
			0x752D864948DB4B49ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBAF67ABDA65E964DULL,
			0x30D523FD7B941551ULL,
			0x979AB905B7FFC57AULL,
			0x4D8FB4D97044E583ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB1A3E228EDB79980ULL,
			0xEE143BD1947FC34AULL,
			0xC9F7864720CC9D14ULL,
			0x67C6674FAE0A5DCFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD6A901FD8A310DDFULL,
			0xAEE8981A7EA749AEULL,
			0xEC89AE710787E76BULL,
			0x1D3FAF1CEAF560D3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x5D29D30B6C8ECA5EULL,
			0x0324E2218E046BE7ULL,
			0xCEA014B4119D526CULL,
			0x722A6555A9369467ULL
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
			0xDBC2C4000FD0EB60ULL,
			0xAD5BB3616FF0DD78ULL,
			0x0A9CCE22625952BCULL,
			0x78FD6F39157D00A9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x01AA5B0D43FC7319ULL,
			0xA8D28018969A9B01ULL,
			0xE25D481D971D68BDULL,
			0x38353B4E65EFE493ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x51EC1F2352BE1568ULL,
			0xFCB61CF1B01FE8D1ULL,
			0x2FBEB9D65D72AC44ULL,
			0x50999F858499E6D9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC443690E9D09235AULL,
			0x7CA6DC610B1E76BDULL,
			0x3E92CAF851DE6D6CULL,
			0x5C16101677FFF9DBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x373A0DEA6DFCC860ULL,
			0x350711BA6C3DB0C0ULL,
			0xEAE7E30F18BCB712ULL,
			0x12974985E9D27191ULL
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
			0x3024F7866F3E56B0ULL,
			0x7F8F901EF7A4B555ULL,
			0x9CF7F30F3448DB71ULL,
			0x4A7C931F70CF4992ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7C127073001AC554ULL,
			0xBC4D9DF59BAB396CULL,
			0x41C05EC7D01ABBBDULL,
			0x58A76F8789C4B353ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xF3B03BF27D730ED0ULL,
			0x2067B0A1D54B9589ULL,
			0x39CAEA0B3B134547ULL,
			0x7FA4FF80ECE47B1FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DAA10A1788EF135ULL,
			0xC579B0FF58FC63E9ULL,
			0x028A3C7C52340941ULL,
			0x2E1441171DECA751ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA4AB9CC562F609C7ULL,
			0x0F2CF0BB30BCC4D7ULL,
			0x78D8FEA8DB82612FULL,
			0x7C06D142DFF2E000ULL
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
			0x7A41885894B8A740ULL,
			0x6EF0D0F07E85CC1AULL,
			0xEBD47BB92C04265FULL,
			0x6CA087E6E2401C4CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5061C9E050171D6AULL,
			0x21FD61D92E028E23ULL,
			0xD222D2D4C204D876ULL,
			0x769EF966ED3423F6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x8F367ABBDFEF2948ULL,
			0xD821EB0C76D3D89BULL,
			0xE62D276D262095DEULL,
			0x45BECA9608F8C07DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x8B5E3094BAD9EC24ULL,
			0x4D3AB1B83B2C3979ULL,
			0x5821A460A5043E08ULL,
			0x0A057E123F9B890BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x38556077BDC3CA2BULL,
			0x596164C9A450DAFAULL,
			0x6D12C937CDCF7949ULL,
			0x1A7AB5B2F27284A4ULL
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
			0xEA33F36B2135FF48ULL,
			0x7967F11292B7EC0BULL,
			0xAB2FEC06242B4CC9ULL,
			0x6C0FB73BF8E95952ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5966E601F70958B7ULL,
			0x061A91E575B0B32EULL,
			0xCA6DBE4D0EBDB28AULL,
			0x65D30B94CC275E98ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x9BF27A8F27270300ULL,
			0x8B58CF30101DAF72ULL,
			0xC74F56616E7A61F2ULL,
			0x51A90B9943294123ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0D350DFBAE3C8C9BULL,
			0x05096CD42A00B657ULL,
			0x19C45212D1C9F8EFULL,
			0x193BE1582406EB0CULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6A8CBB6010055B78ULL,
			0x24F093FF623032DDULL,
			0x14D40CEB1A5957AAULL,
			0x570309F50C9A6243ULL
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
			0xDD6AAD858DB65340ULL,
			0xCDA64EAB125512A7ULL,
			0x80B5B961B0EEBD29ULL,
			0x486ECBD6AD949D1DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x881943812FF510C0ULL,
			0x76A9AB5E903383BAULL,
			0x0AD20AF9AA4834B0ULL,
			0x58112E75AFC100C3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xA916F3D3C6F95218ULL,
			0x55C69EC3B3F21338ULL,
			0xDFF85D983C4C1A21ULL,
			0x713A3A4DF5F63D4BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0B26702C2B7ED86DULL,
			0x1711F7B700EE96F3ULL,
			0x5F65BCFF08A2A885ULL,
			0x4E947849859357C3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD58B131C8D08EC9BULL,
			0xA4FB94DAAA7F2D2BULL,
			0x812EEBF29A79A005ULL,
			0x6E8F151DDEA3C55FULL
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
			0xBC4E04B98A7ADF80ULL,
			0x136D8F11A07BEB35ULL,
			0xD7AF97D0353FE074ULL,
			0x63165145462A3341ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x38B1AB06067CCFF6ULL,
			0x0F7E1F127A7ABD34ULL,
			0x3F421CD1801B0E0BULL,
			0x58D120767DB192C1ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB32B8B7892990B98ULL,
			0x09F890AB1351CE99ULL,
			0x13021187A3724AF2ULL,
			0x6724C9EF65038DA9ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xDC81B18A13864223ULL,
			0x2CB2734526E66A53ULL,
			0x5BCCED31F0BC232FULL,
			0x7C1AD83B8F628CA5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEDD2DA6192E17E49ULL,
			0x70B2B9145A3BA2F0ULL,
			0x05A9E984048AB169ULL,
			0x51873199340F2F40ULL
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
			0x5A49550F6D9C1988ULL,
			0x6D6DAAC8C318E4A3ULL,
			0xD58A396086302509ULL,
			0x501C79F21A76D342ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xCEA78CAB513B6D81ULL,
			0xC35C2E6FB99F2424ULL,
			0x23B146E97CE2D584ULL,
			0x10FF3B3094C4030BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x4426CFF1CCD8D9A8ULL,
			0x67F7075FDB727C5CULL,
			0x7E42D2DFC6C3A359ULL,
			0x471AA3B5395320B2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xC0B856763D300A64ULL,
			0x6A3F63DB18DCCDADULL,
			0xCDEF411E87F29E99ULL,
			0x3A74C839821CE322ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x1CC394025A016C24ULL,
			0x62A1B330CD08752BULL,
			0xF29619FE7D433CF6ULL,
			0x58E4752136200DCEULL
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
			0xEB81CACA082A76B0ULL,
			0xF66BCA79505C3850ULL,
			0x5163C361CECBD3B4ULL,
			0x73CC3868C5115B78ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xF34435D39618D32EULL,
			0x6B386B281B9D6206ULL,
			0x3A0021C37445BF1AULL,
			0x2AB34205678C7A0DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xD5FD3CB16F46EAC8ULL,
			0x96373E9F53218DB7ULL,
			0x5A9D888F21BD10B2ULL,
			0x6C4EDEDF9A5F0B4CULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x4D8079E6E0DB49A3ULL,
			0xCBB75FDB5D1CBD01ULL,
			0x6CC3C49327F927B5ULL,
			0x48DFC2648A7F6B10ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA415B1BF7132ECEBULL,
			0x8EEFEC41ADE4091EULL,
			0x6EA79B351938C7A6ULL,
			0x427E3747BDB1B10DULL
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
			0x995265756E176FB8ULL,
			0x17977B67592E070DULL,
			0x75C5F3A828197B08ULL,
			0x6E380F926B67AA01ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x412DC227712C4412ULL,
			0x5FD78D6F52A2F95EULL,
			0xF3F670566897A45CULL,
			0x63E4003C77A4A233ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB6022A1C66D9FF40ULL,
			0xC4D367BAEEBEC77FULL,
			0xC178909107AB7411ULL,
			0x58DB437BC88F4526ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE09757E21906C9C7ULL,
			0xE3D03BC115D4F45BULL,
			0x24991EB32E36D766ULL,
			0x2C5AC5920143B644ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x2DB4BADC37C951CBULL,
			0x1A321C39FF6AB41CULL,
			0x0B18980AD02EEADEULL,
			0x4EA226CE67B78D4FULL
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
			0xE1A46A0CA7755AB8ULL,
			0x252EE3F5381E3F14ULL,
			0xD030E69123342D93ULL,
			0x4C97F73FCC4E7BDFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5F70423E70D0CAC6ULL,
			0x5BBD76AFEFC80C9BULL,
			0x2C6C70D1A140EBD8ULL,
			0x0E1906E9002C0ABAULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB25AFDCDC44B18E8ULL,
			0xD93F54D7F292EFDFULL,
			0x3113B4E0F7A178DDULL,
			0x4AC4272662B1ED18ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x0AD8566099E4A7A0ULL,
			0x7CAF3E5A09EF2636ULL,
			0x7A24386E498237EAULL,
			0x3E9A78B5FED03203ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x0F83B782A820C316ULL,
			0x3C9592E446AA5DD7ULL,
			0xBE4461E3BF18AEF2ULL,
			0x12C00EC19B627F68ULL
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
			0x45CCB67B1637DC98ULL,
			0xDA958462A68E7ED1ULL,
			0x67F2179B7D9E789EULL,
			0x605A975F11ACE13FULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xEC7E14D8CB6BCEACULL,
			0x056B7ADA2870D1FCULL,
			0xFCD309464F797DA7ULL,
			0x2FE12DAC8F2AB5D6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x988232B11DC08410ULL,
			0x7BD92E90911CD694ULL,
			0x17F3D204BD71B98DULL,
			0x4138C7358A2170D6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x24CE57D8AFD9E53DULL,
			0xE5DEF64AB794D97AULL,
			0xA801E48465E06488ULL,
			0x03D7D646927DD1F5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x10734EEF9EE0AF4FULL,
			0xE9779F55CE277F2DULL,
			0x7233F36795705D28ULL,
			0x049D5F37BA276214ULL
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
			0xCB83CE59CBD22E48ULL,
			0xA6A9BD29B22A6B9AULL,
			0xD67B6B1F3F5C9484ULL,
			0x4518EA29623B8225ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x913BC64BBCD5913AULL,
			0xED137F78D867559CULL,
			0x2AD46D176940B513ULL,
			0x2B207A5A9F77FDDCULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1981FA29F345D420ULL,
			0x46DE0D892DAC8CB5ULL,
			0x441188F349B18B6CULL,
			0x6F226535EA4ED39DULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5DA1CB803B734E64ULL,
			0x3BEFCC0EB5B7680AULL,
			0xDD30EEE370E123CCULL,
			0x5DAAB29895CC6B05ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB37C6AA0AF45460AULL,
			0xDDACB5BD7D8B1A46ULL,
			0x43EA9F187BE5D20AULL,
			0x7D2BE7643BFF400EULL
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
			0xA02E0FCBA271A620ULL,
			0xC2E6C7BFB925E179ULL,
			0xF67E5EB04F3DA419ULL,
			0x6DA47340C85C7716ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x7B1D98B3C0B6A6ACULL,
			0x568A5E41ECB6CEFBULL,
			0x3F0444F3CFA47D1DULL,
			0x3DEE84CC5A1C6A4AULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x5ECCA277FB3EF778ULL,
			0x827CDFFCB048E338ULL,
			0x3B8ADC10062FE07AULL,
			0x4BE45A000C563045ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBEC7778C9CA25E07ULL,
			0xE346DEF2F77BCABEULL,
			0xC7EE9B3D96215D27ULL,
			0x232B60E51B5F9165ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x166A3121F04AFC08ULL,
			0x5C30864C1B817865ULL,
			0x11CEA347105558D5ULL,
			0x61A273AEF3AAC6E7ULL
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
			0x8C14F70F25F39CC8ULL,
			0x5FB2AB9139CD8A78ULL,
			0xD4B51DC37CDA8E4BULL,
			0x57BB5E37755DEDC3ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xAE0B3461F4376942ULL,
			0x48631853EC31BA54ULL,
			0x45A48310E6D5AAB9ULL,
			0x61A1F14141C9950BULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE1163910345536A0ULL,
			0xE2CFC6F0AEE3CA78ULL,
			0xF5E8BCB679CEB584ULL,
			0x6CFB86EFDEF93D14ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD77405BCE057D3DAULL,
			0x6DD49059DAF33E82ULL,
			0x1550002D65F78BD4ULL,
			0x306EDD5A2B131FACULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x7BFFCDED25D84D0AULL,
			0x6235D29E3192FFF2ULL,
			0x45E83032DABBA79EULL,
			0x24E76ACF9E188440ULL
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
			0xACE01ED499E1EDF0ULL,
			0xD6EE97E11911EC37ULL,
			0x9E8F384C5D8C69E2ULL,
			0x79549AAAB732174CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x6FDD4DAEC0ADED8BULL,
			0x2197C24EF788EE94ULL,
			0xE7C0E716EDD9F23CULL,
			0x1E544C915E055629ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x52943429E568A630ULL,
			0x9B0525476F8C7E2AULL,
			0xF638B9951F5F305BULL,
			0x7DBD8C97B904BE77ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xCA11DA4F7975A5D2ULL,
			0x60093546D0B9EA7EULL,
			0x3F234977DF4E150BULL,
			0x3687F4A5181934BBULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xCF69CA97F2359F36ULL,
			0xC34C0F0498657B45ULL,
			0xF5D61812AF0CA4E8ULL,
			0x604AB5FE9952F879ULL
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
			0x5C14CADC394F5B38ULL,
			0xB1C6F5EEFDC0D739ULL,
			0xC711D093B03DC1C6ULL,
			0x53246F92D9ECAFAFULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xBA81319CF919F831ULL,
			0x84D7B15DEC44ED53ULL,
			0xAAB07194FD0BFEE5ULL,
			0x2086604F4C83CDD7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xBA6E2B78758B39B8ULL,
			0xBB02962B929476DBULL,
			0x03F383E0C3DFE80EULL,
			0x532A8FD3DCA0709FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x5111920A70AD9346ULL,
			0xE40C89164B4FF22CULL,
			0x33CA9B9036F59E0FULL,
			0x097C5D2F9CF36393ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB46E430A410105DFULL,
			0x5AD9E0E7F5C08C4EULL,
			0x5B1F3ADF16D045F5ULL,
			0x7B69839C93D3A260ULL
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
			0xD586DCEA20E85680ULL,
			0x9606CF521688ABBBULL,
			0x1F6CE151D584E1E1ULL,
			0x7048BCF073F36845ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB68F813020AB3331ULL,
			0x4A0F583EA58FF1C9ULL,
			0x41CF1E126D76B531ULL,
			0x5CDD3E77492CBAEDULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xC1CEA5A1AA704F88ULL,
			0x08883C7BA234C1FFULL,
			0x77B4D5E112651C61ULL,
			0x7B2365D9B9D6B41EULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x258825FE341D339BULL,
			0x769B7AD367853FADULL,
			0x4DE87CE85E439F36ULL,
			0x45B0AD1D0FB9D7ABULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE7E794482E2DFA69ULL,
			0x3D34A71A92B71043ULL,
			0x3F42825FA89ACE24ULL,
			0x328CECE4F43143A6ULL
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
			0x029E557A767B10F8ULL,
			0x813202254A444B6AULL,
			0x8F5C43D47E5F5882ULL,
			0x413011EB4CA626D6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BE8B5827F625258ULL,
			0x88CE56052652CDB1ULL,
			0xBB5D147D711C4F04ULL,
			0x45B46916B24A3A19ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x161C952A4B47DDA0ULL,
			0xA67F8F5E0AB03D80ULL,
			0x0F6F29CE35D4EBB3ULL,
			0x7CAECD986D5F2851ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7814B03DFE7CE801ULL,
			0x3901518A2996331FULL,
			0x56DF214D9FFCC983ULL,
			0x71930A54EF1D511FULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xE6A1509E7F1DE87DULL,
			0x732AF6DAA82F9E26ULL,
			0x28D41A8EA184CB8AULL,
			0x414F66C545570513ULL
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
			0xAC59D038110575F8ULL,
			0x00732197CDBE6A3EULL,
			0x7407A012B2FF209DULL,
			0x654ECDB9F1AB3A9DULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5EFD4AC2B804F7A0ULL,
			0xAB8940F91A460C5FULL,
			0x4124CD6A0533062DULL,
			0x3A31E3B1DE4F9096ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE3692F73D1F1AF78ULL,
			0xE4283C4C9EC32B7EULL,
			0xD102F6BD9F646AFBULL,
			0x5ACE8C5A233C0793ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x625FBD324CF0C467ULL,
			0xB8FE085108CE037FULL,
			0x4659E437A3BA8228ULL,
			0x6A7230AB924E7947ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x935F329DD3FF97C4ULL,
			0x7B0010C144D37A57ULL,
			0x1D0467C93862129BULL,
			0x56396365A0D22E30ULL
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
			0xD48D71C5C4F35C10ULL,
			0xB56B0510B202C86CULL,
			0x2E78B098202E10ADULL,
			0x48EED29FC80F32D9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x36D05E25FA47B3D1ULL,
			0xFC7377C3E118088FULL,
			0x663F3787BA343E9CULL,
			0x11C5BDF897F3A569ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFF407843D99B7388ULL,
			0x5B8B99B00B312779ULL,
			0xD51BC9777FD7759EULL,
			0x49E15228AB4BAFE0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9EF1CED36AD1FAB2ULL,
			0x09E55E708DC1C282ULL,
			0x403CC97CA9039146ULL,
			0x20F47DAB80C672D8ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xA52AA36C7C0C2947ULL,
			0x93F92BCD8AFFF1ECULL,
			0x1EC0984E55FAB6B6ULL,
			0x300D86165177F512ULL
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
			0xAA2B95635DB5CAE0ULL,
			0xD090B0B69CEC3FA3ULL,
			0xF32AA2E33AD9EFDAULL,
			0x7DBC6DA38F65CB0CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB934C0E217734DD8ULL,
			0x26626216E2C77872ULL,
			0xD2F0BB55561DF55CULL,
			0x79B373516CAC6CB9ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xB361AE79005E2E28ULL,
			0x70F2C5DF296A39ACULL,
			0x061639B59F64D966ULL,
			0x6E19B8D244A6CEC0ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBD5F4516163B6F2EULL,
			0x863D55F4EB53690EULL,
			0x7B4ACAC5E0EE538BULL,
			0x23389585F01E30A3ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC6DD6BEF2C8EC13DULL,
			0x9C93FA000CD3AE86ULL,
			0x8C1DF3C6788F67ADULL,
			0x3D94897C4900A5DDULL
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
			0x2230B4CCBADFA9B0ULL,
			0xA623FB50C7A4E06EULL,
			0x5B924B8DE6E90B86ULL,
			0x404E19D88645B394ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8C723706D9108C21ULL,
			0x1D8F60A7F96820CBULL,
			0xCA12E5EA5EA3DAD5ULL,
			0x518A6DF07B7D3E5FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1EB971BB65FA3C08ULL,
			0x91DAD89379AE965EULL,
			0x67FBA6F43935BF54ULL,
			0x7C63515E1D9DC76BULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x14185EF03A10922BULL,
			0xA86FDBD7C0D25714ULL,
			0x986A665409D622B8ULL,
			0x43C1821AE6B383D6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xD6EC48937DBB655DULL,
			0x2BB338525117AAAEULL,
			0x0F4D885F3E3DA60FULL,
			0x5BFC50382465340BULL
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
			0x3EF6859CC50F5CD8ULL,
			0x3988CF24283B3BBDULL,
			0xAD314EA2F269135AULL,
			0x6CCF6C65D0CDB1D8ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x2E415DD2E4B4E3BDULL,
			0x96EB78C00AE67A72ULL,
			0x05675F9912C661ECULL,
			0x6430B96E5A0EAA1CULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xE03008A871348C90ULL,
			0xFBC07D8D4182AAE3ULL,
			0x290BB98A04509B93ULL,
			0x73A5C7792239BE38ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xBC4BBE5B7B360138ULL,
			0x214A733AB05C6135ULL,
			0x6C45B8692C13166CULL,
			0x42630210C5A83649ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x433F844F3EF54948ULL,
			0xB827BFF727C9811FULL,
			0x092232FCA1B05D3FULL,
			0x3EB654C563B91EAFULL
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
			0xF7E9510B5CDC5470ULL,
			0xCF605C82EF0B1E37ULL,
			0xD9A4FBA65F156CD3ULL,
			0x5037860EFFBAFDFCULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA4D1AAA441FD8DECULL,
			0xE4EF2528F27DD2ABULL,
			0xAF9FEC5C91600534ULL,
			0x1C1EC6A8BCA89463ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x374040A9C2C2A838ULL,
			0xB853B799FA9D7120ULL,
			0x9ED4599836CBD12BULL,
			0x5303EFE8260B2792ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xD3FE518A155B77B2ULL,
			0x868551C5F6236AF2ULL,
			0xF21B686080A1557DULL,
			0x7D62AE7849ECF447ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xAAA50BCC38C71863ULL,
			0xAC6CD7C62C45C89EULL,
			0x0B24EA020BE11510ULL,
			0x7C9982E67D12E988ULL
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
			0xFDC7B2DA78F1C270ULL,
			0x04F1539B835E3EF1ULL,
			0x7378A46E4A9D9998ULL,
			0x70CFDA2CC49403D9ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xFD7B44C9895BF58BULL,
			0xE93AADD8C7D328BEULL,
			0x6362D2EF7A212B5FULL,
			0x4DE149DE694E933FULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xFF0F50BFAD0111F0ULL,
			0xBC4433F37002F886ULL,
			0x0596145B2A9BD8ADULL,
			0x4EB007D5522AC209ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9C8DA44BA3EB8094ULL,
			0x47E97C4877EA7BAEULL,
			0x83114072F02836B8ULL,
			0x0235A2A9FB0346D2ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6517C445D7ADF689ULL,
			0x76511F13D56BD966ULL,
			0xBA52B3628FB92E43ULL,
			0x01F79D1918D84176ULL
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
			0x0BE738A1AB6DC3D0ULL,
			0xDA9107568156FA4CULL,
			0x1771DBA09A3CF9CDULL,
			0x72569ECEE5E4B057ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xB22E34478BD02023ULL,
			0xB8FE017757567AC5ULL,
			0xB63B5A969FD84990ULL,
			0x7AF61214E88FD269ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x3926D65642946190ULL,
			0x9FEA48211CC6B0EEULL,
			0xEA36A89CC13BE066ULL,
			0x539ABB30A8BD6501ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x91D2258F58AC0E86ULL,
			0x49D88115B03A69FAULL,
			0x011BD6FD9F60DC8AULL,
			0x57328565D1851552ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xFAB4105A2B3662F4ULL,
			0xB8349364DC16FAE4ULL,
			0xDEC504A5D5FD9B97ULL,
			0x2DBEA37F76E6BA8BULL
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
			0xE93EAC3BB9BBAA08ULL,
			0xAEF9C4966ABED916ULL,
			0x0B38132C6C4AE6EEULL,
			0x71E5D96DE9CEEE01ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x8D5C0DF4F3833B81ULL,
			0x86CA1E3D5D65E345ULL,
			0x4D153CEFBFB16B4BULL,
			0x2A473C6B586AC5EEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x71CF7F034C088F28ULL,
			0xBD83951754A3DF75ULL,
			0x0EB067362BEF08EEULL,
			0x635D811CA0A142EFULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xB8B92F35CAED5B99ULL,
			0xD09981C90800E579ULL,
			0x7E7B5EA95A2F27F0ULL,
			0x75104F8665CB3F00ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC24146BA6EBD4789ULL,
			0xD7591084B7D4E276ULL,
			0xB6808A58923014D8ULL,
			0x5EB6A6D107DDAE97ULL
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
			0xE83BC248D5427B40ULL,
			0xA03AEDD2C03FF320ULL,
			0x5D3811FAEEA60C6FULL,
			0x6D0AF6AFC158DBC2ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4CACB9BF9A2F273DULL,
			0x7D01FF0075EE0C1EULL,
			0x302D259A110FC2D1ULL,
			0x4656DAA9BAD07A9DULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCA70A60BD4CCE600ULL,
			0x748F9EED6973F09AULL,
			0x8282FE042339EF10ULL,
			0x42D27E1FD62E846FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xA831A2BA99A19EA8ULL,
			0x77385F4FB3BF6718ULL,
			0x312E8B45342AA96DULL,
			0x26F4F5DFCC043659ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xEB9FD0672996432DULL,
			0xB85BAEAA7774FD77ULL,
			0x730A18AE74B9D563ULL,
			0x5AA99D42F5A31CF3ULL
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
			0x976AE42086475828ULL,
			0x36654789C3FE1FDCULL,
			0x81BAE981563A8EFFULL,
			0x4CBDF1A7662D29D5ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0xA715B1B1C277539BULL,
			0xA822B975662DF8D8ULL,
			0xA1D097A440CBD5BCULL,
			0x6F6BE2A0C2229ACFULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7FD9491C294C7CD0ULL,
			0x24D04112C72F6383ULL,
			0x6F61A52A308C3BF0ULL,
			0x52FCA45A98BD27F6ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x9B8599BA96E077ABULL,
			0x6AB2D457186FAF95ULL,
			0xA42EDCEAAA76DAF5ULL,
			0x0B7EC27DC4FF01A1ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x9491D0D04C17CB95ULL,
			0x76E5C0FDF4A83E09ULL,
			0x8D36EDBBF39003DEULL,
			0x229E9E8F099D04BBULL
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
			0xF2979AC3189DA530ULL,
			0xB7533E3DDF5CAA58ULL,
			0xA9A796D78FADDB03ULL,
			0x51A32CAF7C925320ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x5B064807522FAEC1ULL,
			0x44EFFC4E7EBDFD49ULL,
			0x5DBC4E59AD63936FULL,
			0x3DC5EA3436897174ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xCBEDACB77D8BDFC0ULL,
			0x102DDBF43DF663F7ULL,
			0xBF85695DD21E6AA3ULL,
			0x68BD4D9326DB0B72ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x85CBEB91D5B961CAULL,
			0xFBDE414A390A0543ULL,
			0xCE1AA3045396B0D8ULL,
			0x62EDB0E6B88E4EE6ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xC885FE18A49BC510ULL,
			0x68AC54A686C95F4FULL,
			0x33515D9FAEDC7D3EULL,
			0x5A6B7F331F545305ULL
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
			0xA02F03A475C4B6E8ULL,
			0x2B9374105B3FDE76ULL,
			0x355ED292DF194ABBULL,
			0x70D6F54988B36C2EULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x1627BF9DFE36DDF2ULL,
			0xE5ABB0EF368AED34ULL,
			0xC8865E2CCC8F03B8ULL,
			0x293949E851085DDEULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0xDE0902604201DF90ULL,
			0x5035588FA7D82E91ULL,
			0x00E5CAE3E8252483ULL,
			0x698EE32D4302614FULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xE6F9010B732BCEB8ULL,
			0xB26EADB05430433AULL,
			0x632863A8301B0C07ULL,
			0x3BFA45626C974057ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xB6F1705CE8E86C5FULL,
			0x6D05DF7BB7324BC5ULL,
			0x5B80FE282B4BB27CULL,
			0x2C884C76EF120155ULL
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
			0xF894A77EEB188278ULL,
			0xF22E14F4E67CFDB1ULL,
			0x512C9241CEEAE4DAULL,
			0x65DF135E23A78DA6ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x82A0F9A3E81729BFULL,
			0x3441401876BAFAB1ULL,
			0x3EE136CCBDC16AC5ULL,
			0x340101575509D168ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x7B7008A9891589B0ULL,
			0x1F1E8E40449F01A0ULL,
			0x4B0C397F93459B89ULL,
			0x55D53F7F48F27F98ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0xF141672D27658971ULL,
			0x90A526CB56B726A6ULL,
			0x66384630149A57C6ULL,
			0x7F048601B10AA2A5ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0xDB705409A65D5AABULL,
			0x2EDB5ED8AD4FA8AFULL,
			0x211500359C0F2066ULL,
			0x0EBC6A868C0FEDD3ULL
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
			0xF50D21B657B6D3C8ULL,
			0x1DF57054D6E15B53ULL,
			0x06F8C033C9F6B211ULL,
			0x7D46451C6AFCFE72ULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x15E528287A640703ULL,
			0x5A9D94D234A05C98ULL,
			0x22EA827C5EA951E7ULL,
			0x0B715D94113EF6D7ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x0A997E8E724B6390ULL,
			0xACD78178E633DE0CULL,
			0x2285265D32383B47ULL,
			0x6119621A8C0082C2ULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x2D6DD14CE707A96DULL,
			0x7D33DB36A6CD88E4ULL,
			0x017EFEDF0E4F40E7ULL,
			0x6DA8EDC319823134ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x62D442EAC75A23DAULL,
			0x0877B21CC24EC1D3ULL,
			0xE415D09835E3C305ULL,
			0x373EF9AB84D7BC74ULL
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
			0xCFD5729F5FE00A60ULL,
			0x26DCE5D7E290F9BFULL,
			0x5EBE6458A2836EFFULL,
			0x4DACD7751426C72BULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x0284D7929AD2EEA4ULL,
			0x0900DD1C0C7B2822ULL,
			0x1CEB32A772CEBEA7ULL,
			0x48B2FAC062213BB3ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x45D398583A0B48D8ULL,
			0x1F63741C737716DDULL,
			0xC4BDCAFE339A61B8ULL,
			0x6CC42AF1ACC978DAULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x077AB8D998733E77ULL,
			0x3A230D41FE8A4A49ULL,
			0x04675B79B5F598A3ULL,
			0x0A3B2E80B889A347ULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x6AD261FF065512D2ULL,
			0xF1A6C45338B6166CULL,
			0x19446CC33BE24176ULL,
			0x22F92F43512D7D13ULL
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
			0xDB00DBFFD788E9C0ULL,
			0x4C4669456BA24CF9ULL,
			0x08B5BAC47EA4AFBEULL,
			0x5B15AECD50BF170CULL
		}
	};
	pub_key1 = (curve25519_key_t){
		.key64 = {
			0x4BF00C0580D04FDEULL,
			0x05D3FA7BAB629A72ULL,
			0x45C5147ED4B183FCULL,
			0x0839504567B0D9B6ULL
		}
	};
	priv_key2 = (curve25519_key_t){
		.key64 = {
			0x1AF39ECBE0AEB468ULL,
			0x032270D2C0DD7896ULL,
			0x9C4AD3D425C65A08ULL,
			0x524F151830C8BD3AULL
		}
	};
	pub_key2 = (curve25519_key_t){
		.key64 = {
			0x7FAD0CF493A1E070ULL,
			0xC5BE8A18447D5FE0ULL,
			0x51FB9C2709A44B9CULL,
			0x609E694F97AF3D5BULL
		}
	};
	shared_key = (curve25519_key_t){
		.key64 = {
			0x46559D1DD878DA31ULL,
			0x5D82C760F1E99AE0ULL,
			0x7BF5CB4CDA9E8F00ULL,
			0x28B4ECC64859A907ULL
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