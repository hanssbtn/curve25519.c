#include "../tests.h"

int32_t curve25519_key_x2_inplace_test(void) {
	printf("Inplace Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x00EE97651E8513ABULL,
		0xCE8275288991834AULL,
		0x8A446D6BC917B7B5ULL,
		0x56E9954378C28B20ULL,
		0x65E7F3BC06E7DF22ULL,
		0x26ADAAF44BF2725EULL,
		0x3975121298701357ULL,
		0x1D2D883C94744159ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x01DD2ECA3D0A2756ULL,
		0x9D04EA5113230694ULL,
		0x1488DAD7922F6F6BULL,
		0xADD32A86F1851641ULL,
		0xCBCFE7780DCFBE44ULL,
		0x4D5B55E897E4E4BCULL,
		0x72EA242530E026AEULL,
		0x3A5B107928E882B2ULL
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
		0x3CDE2E85F53832C7ULL,
		0xA8F451C257EC59FCULL,
		0x2BB439F6ACE0A06BULL,
		0x65529159D1DD7FC7ULL,
		0xB17424399D99A645ULL,
		0x47B582D3A2B168EDULL,
		0xA3B61345872DC9B4ULL,
		0x18CE8040C7BD379AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79BC5D0BEA70658EULL,
		0x51E8A384AFD8B3F8ULL,
		0x576873ED59C140D7ULL,
		0xCAA522B3A3BAFF8EULL,
		0x62E848733B334C8AULL,
		0x8F6B05A74562D1DBULL,
		0x476C268B0E5B9368ULL,
		0x319D00818F7A6F35ULL
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
		0xB48266E15AB20D9CULL,
		0xE2F1F77FF5B5E6B5ULL,
		0x22AAA7AAA64410C0ULL,
		0x755A12008F592673ULL,
		0x724CC38FB0F788BAULL,
		0x8A425AF2F5F66DEDULL,
		0x53FB077AF28A9EA4ULL,
		0x02156C2003D46B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6904CDC2B5641B38ULL,
		0xC5E3EEFFEB6BCD6BULL,
		0x45554F554C882181ULL,
		0xEAB424011EB24CE6ULL,
		0xE499871F61EF1174ULL,
		0x1484B5E5EBECDBDAULL,
		0xA7F60EF5E5153D49ULL,
		0x042AD84007A8D61EULL
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
		0x4CEAFF3B6DE193DCULL,
		0xDA5E48A9ACA302CFULL,
		0xD6765780D2F53647ULL,
		0xCFF1054B327CED54ULL,
		0xEF3666273FECF98CULL,
		0xD74B26EFBDC6DC67ULL,
		0xBBD7688BFD803C7DULL,
		0x1308E911AD583FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99D5FE76DBC327B8ULL,
		0xB4BC91535946059EULL,
		0xACECAF01A5EA6C8FULL,
		0x9FE20A9664F9DAA9ULL,
		0xDE6CCC4E7FD9F319ULL,
		0xAE964DDF7B8DB8CFULL,
		0x77AED117FB0078FBULL,
		0x2611D2235AB07FD9ULL
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
		0xE30364C5FB74AE13ULL,
		0x22EDC465A8D6B322ULL,
		0x501BEF4D7956D6F9ULL,
		0x82D1E35A89FA8220ULL,
		0x3B711840D6C728F3ULL,
		0x7F9AA9CB2E6DB010ULL,
		0xE9B1F05B59C37191ULL,
		0x24655EAFB826D97FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC606C98BF6E95C26ULL,
		0x45DB88CB51AD6645ULL,
		0xA037DE9AF2ADADF2ULL,
		0x05A3C6B513F50440ULL,
		0x76E23081AD8E51E7ULL,
		0xFF3553965CDB6020ULL,
		0xD363E0B6B386E322ULL,
		0x48CABD5F704DB2FFULL
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
		0x7C21D5B690ABE004ULL,
		0x6D3D4ED18D4A4860ULL,
		0xF2909217C5F7CA97ULL,
		0xAA31B29FD095611CULL,
		0xCE2A275B7739F649ULL,
		0x6CF2C1F1822B6434ULL,
		0xD3405B6549727CB9ULL,
		0x21C393EC2F9375C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF843AB6D2157C008ULL,
		0xDA7A9DA31A9490C0ULL,
		0xE521242F8BEF952EULL,
		0x5463653FA12AC239ULL,
		0x9C544EB6EE73EC93ULL,
		0xD9E583E30456C869ULL,
		0xA680B6CA92E4F972ULL,
		0x438727D85F26EB85ULL
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
		0xC978CFB56C39A7D4ULL,
		0xF89E80119E287AF4ULL,
		0xA7CB3A212BFDAC2AULL,
		0x63FC21C07177DDA0ULL,
		0xA7955E032CBD4064ULL,
		0x5E11DD42BAA3E60CULL,
		0x91E0E0D6B6A5B140ULL,
		0x18A6575D419A85A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F19F6AD8734FA8ULL,
		0xF13D00233C50F5E9ULL,
		0x4F96744257FB5855ULL,
		0xC7F84380E2EFBB41ULL,
		0x4F2ABC06597A80C8ULL,
		0xBC23BA857547CC19ULL,
		0x23C1C1AD6D4B6280ULL,
		0x314CAEBA83350B49ULL
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
		0xB705988E5226D414ULL,
		0xA5A0548386A5B2F2ULL,
		0x10A9C90D0ACFFBF0ULL,
		0x7BDEEA62FA4CCE41ULL,
		0x9D95D7F1CA947414ULL,
		0xE5241DEDA2CD6F01ULL,
		0x0C84C6768C8D28D1ULL,
		0x0610047B62D23DDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E0B311CA44DA828ULL,
		0x4B40A9070D4B65E5ULL,
		0x2153921A159FF7E1ULL,
		0xF7BDD4C5F4999C82ULL,
		0x3B2BAFE39528E828ULL,
		0xCA483BDB459ADE03ULL,
		0x19098CED191A51A3ULL,
		0x0C2008F6C5A47BB6ULL
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
		0xB01E93400739DF0AULL,
		0x26E2ADF1E4D50A91ULL,
		0x131306A13732A153ULL,
		0x368ADC06A8458BABULL,
		0xF33994FEEFF085E3ULL,
		0xB04D209DC7A89BA1ULL,
		0x571CCD9F96528ECAULL,
		0x22264766F18A8905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603D26800E73BE14ULL,
		0x4DC55BE3C9AA1523ULL,
		0x26260D426E6542A6ULL,
		0x6D15B80D508B1756ULL,
		0xE67329FDDFE10BC6ULL,
		0x609A413B8F513743ULL,
		0xAE399B3F2CA51D95ULL,
		0x444C8ECDE315120AULL
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
		0x194D4641D4A7741EULL,
		0x30CA724D2159EBF7ULL,
		0xBBA6F2DDB9F08042ULL,
		0x1A1696C23E1CB0B8ULL,
		0x8F332C8A11C69114ULL,
		0x33D139D1C712BE4EULL,
		0x834175D30A6F0B55ULL,
		0x39F0091779E8E21FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329A8C83A94EE83CULL,
		0x6194E49A42B3D7EEULL,
		0x774DE5BB73E10084ULL,
		0x342D2D847C396171ULL,
		0x1E665914238D2228ULL,
		0x67A273A38E257C9DULL,
		0x0682EBA614DE16AAULL,
		0x73E0122EF3D1C43FULL
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
		0x31FBDB70EC16120DULL,
		0xFEA3C88AA121853DULL,
		0x2ABFFF0F5647D7B4ULL,
		0xDF7F0D0029D8442CULL,
		0xEB64B1E95B0E072BULL,
		0xC7C3F11412543EC5ULL,
		0xF6379F6199D03B3AULL,
		0x2400B2D04984CC8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F7B6E1D82C241AULL,
		0xFD47911542430A7AULL,
		0x557FFE1EAC8FAF69ULL,
		0xBEFE1A0053B08858ULL,
		0xD6C963D2B61C0E57ULL,
		0x8F87E22824A87D8BULL,
		0xEC6F3EC333A07675ULL,
		0x480165A09309991BULL
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
		0x576246A57EC71386ULL,
		0x4B474AE1988E58BDULL,
		0x2ED3A1DA6B42E9F4ULL,
		0xA1B00FC0BF951B68ULL,
		0x2B6A4DAADCF664C4ULL,
		0x3C96E4F69FE6028CULL,
		0x4B5118CAF9021155ULL,
		0x26D96D127E97CD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC48D4AFD8E270CULL,
		0x968E95C3311CB17AULL,
		0x5DA743B4D685D3E8ULL,
		0x43601F817F2A36D0ULL,
		0x56D49B55B9ECC989ULL,
		0x792DC9ED3FCC0518ULL,
		0x96A23195F20422AAULL,
		0x4DB2DA24FD2F9AB0ULL
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
		0xE689526FD1871DDFULL,
		0x0ABE81BEEFC77DC4ULL,
		0x5428DE9902AD3C8CULL,
		0x84FB7A842688222AULL,
		0x1217A550842AD5AFULL,
		0x1CF623043762170EULL,
		0x9E56B5E46CD39AB3ULL,
		0x00A90BF834A1D050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD12A4DFA30E3BBEULL,
		0x157D037DDF8EFB89ULL,
		0xA851BD32055A7918ULL,
		0x09F6F5084D104454ULL,
		0x242F4AA10855AB5FULL,
		0x39EC46086EC42E1CULL,
		0x3CAD6BC8D9A73566ULL,
		0x015217F06943A0A1ULL
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
		0x2F101701DB8B608FULL,
		0xE4CB352F1B65094FULL,
		0xB7E7CB08A6D22AEBULL,
		0xC029081574FF608FULL,
		0xEE70F7C820043552ULL,
		0x02C10BFC7ED9EBCEULL,
		0x485C7C19C4D76FBCULL,
		0x042907CB23712787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E202E03B716C11EULL,
		0xC9966A5E36CA129EULL,
		0x6FCF96114DA455D7ULL,
		0x8052102AE9FEC11FULL,
		0xDCE1EF9040086AA5ULL,
		0x058217F8FDB3D79DULL,
		0x90B8F83389AEDF78ULL,
		0x08520F9646E24F0EULL
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
		0xBB46022265DC396CULL,
		0x882DC7DAD16BEFE4ULL,
		0xC5BDCC3A737530A1ULL,
		0x12E5D97426CDCC9AULL,
		0xC70AC7F0DF896234ULL,
		0xB08C876CD4584BDFULL,
		0xC078BE211A7BEC25ULL,
		0x28AD1F0067931C87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x768C0444CBB872D8ULL,
		0x105B8FB5A2D7DFC9ULL,
		0x8B7B9874E6EA6143ULL,
		0x25CBB2E84D9B9935ULL,
		0x8E158FE1BF12C468ULL,
		0x61190ED9A8B097BFULL,
		0x80F17C4234F7D84BULL,
		0x515A3E00CF26390FULL
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
		0xCAE10F43FE49515EULL,
		0x86B87C368EA7BD13ULL,
		0xC920ABF01DC336B4ULL,
		0xE9B48B7E28003D41ULL,
		0x44635C3617C5C6C9ULL,
		0xD491DC9A30A1A5A9ULL,
		0x361703BD775C5AF3ULL,
		0x2983FA126ABEF2A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95C21E87FC92A2BCULL,
		0x0D70F86D1D4F7A27ULL,
		0x924157E03B866D69ULL,
		0xD36916FC50007A83ULL,
		0x88C6B86C2F8B8D93ULL,
		0xA923B93461434B52ULL,
		0x6C2E077AEEB8B5E7ULL,
		0x5307F424D57DE548ULL
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
		0x501658CD2F90E2BEULL,
		0xEF168CF9F83BB235ULL,
		0x33BF9E3958137E28ULL,
		0x3DDCD6FE1B484690ULL,
		0x0F2DF3C34444EEAFULL,
		0x6839D57D4F92F631ULL,
		0xAD0D351004D8076AULL,
		0x204C7B83BA3DDB26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA02CB19A5F21C57CULL,
		0xDE2D19F3F077646AULL,
		0x677F3C72B026FC51ULL,
		0x7BB9ADFC36908D20ULL,
		0x1E5BE7868889DD5EULL,
		0xD073AAFA9F25EC62ULL,
		0x5A1A6A2009B00ED4ULL,
		0x4098F707747BB64DULL
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
		0x7884D6A1ED3FB289ULL,
		0x159418661D75C1DFULL,
		0x98760FA797CD97AEULL,
		0x5AF259CC5ACBC501ULL,
		0x3BFC6AA4792B18D6ULL,
		0x0B3351A6D7C03506ULL,
		0xBBEE386AFAE48253ULL,
		0x04BFC643159726ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF109AD43DA7F6512ULL,
		0x2B2830CC3AEB83BEULL,
		0x30EC1F4F2F9B2F5CULL,
		0xB5E4B398B5978A03ULL,
		0x77F8D548F25631ACULL,
		0x1666A34DAF806A0CULL,
		0x77DC70D5F5C904A6ULL,
		0x097F8C862B2E4DD9ULL
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
		0x8F4CEC173072ADD7ULL,
		0x1A6A3FAC7D20E94EULL,
		0x1401EB50E6063125ULL,
		0x2286D068DC4A1D84ULL,
		0x5951865716B8FB5BULL,
		0x2F5E0B8DE1BFBE2DULL,
		0xCD55DABAB67A27A5ULL,
		0x1C302B170801298FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E99D82E60E55BAEULL,
		0x34D47F58FA41D29DULL,
		0x2803D6A1CC0C624AULL,
		0x450DA0D1B8943B08ULL,
		0xB2A30CAE2D71F6B6ULL,
		0x5EBC171BC37F7C5AULL,
		0x9AABB5756CF44F4AULL,
		0x3860562E1002531FULL
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
		0x1E2E7B8284397DACULL,
		0x6C81DE9FE339D513ULL,
		0xC18F7A15A32A83ACULL,
		0xE1AEB22A407A3171ULL,
		0x40A879AD1A2DFCF9ULL,
		0x8FC6FB31799131F2ULL,
		0xFB777296AE34F6DEULL,
		0x0E3E77ABC32FF7D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5CF7050872FB58ULL,
		0xD903BD3FC673AA26ULL,
		0x831EF42B46550758ULL,
		0xC35D645480F462E3ULL,
		0x8150F35A345BF9F3ULL,
		0x1F8DF662F32263E4ULL,
		0xF6EEE52D5C69EDBDULL,
		0x1C7CEF57865FEFA3ULL
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
		0xFDF5F3A45CC76FF1ULL,
		0xC19F453272CB22ECULL,
		0x534EA6EC7371352DULL,
		0x0B998CC834AB3633ULL,
		0xAFAB61F66F8E8D7EULL,
		0x4999EA0BF0A44EEFULL,
		0x5ECB6307C63C1619ULL,
		0x2EC9973B5040B01BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEBE748B98EDFE2ULL,
		0x833E8A64E59645D9ULL,
		0xA69D4DD8E6E26A5BULL,
		0x1733199069566C66ULL,
		0x5F56C3ECDF1D1AFCULL,
		0x9333D417E1489DDFULL,
		0xBD96C60F8C782C32ULL,
		0x5D932E76A0816036ULL
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
		0x5499EC04FA369001ULL,
		0x25BE1D3BC794F03DULL,
		0x00ACA8BC3BAE4DE4ULL,
		0x61574A15A7BD7B8FULL,
		0x2E86A697F0604F26ULL,
		0x0D79CBFB9E293DDBULL,
		0x24C09E986F063863ULL,
		0x0056A9511CABA101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA933D809F46D2002ULL,
		0x4B7C3A778F29E07AULL,
		0x01595178775C9BC8ULL,
		0xC2AE942B4F7AF71EULL,
		0x5D0D4D2FE0C09E4CULL,
		0x1AF397F73C527BB6ULL,
		0x49813D30DE0C70C6ULL,
		0x00AD52A239574202ULL
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
		0x2958C21112BC40E3ULL,
		0xE8A0F55E2F42992FULL,
		0x24B68604136AF6F6ULL,
		0x8CD5FE363048541EULL,
		0xEFCD749F97A226DCULL,
		0x09ABDB2C3ED62733ULL,
		0x6E5AE494A7A4A6B7ULL,
		0x08F7D886294A58CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52B18422257881C6ULL,
		0xD141EABC5E85325EULL,
		0x496D0C0826D5EDEDULL,
		0x19ABFC6C6090A83CULL,
		0xDF9AE93F2F444DB9ULL,
		0x1357B6587DAC4E67ULL,
		0xDCB5C9294F494D6EULL,
		0x11EFB10C5294B19AULL
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
		0x146134EBDC03F0B9ULL,
		0xC4C15E46C692ED02ULL,
		0xBB5BF241F65DD4E1ULL,
		0x5F58A28096FDE31CULL,
		0xA04F2203D31ED38DULL,
		0x6ACF1D7641C7D22EULL,
		0xB3564BD44CC25EFEULL,
		0x0FB9BC8E0A626114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C269D7B807E172ULL,
		0x8982BC8D8D25DA04ULL,
		0x76B7E483ECBBA9C3ULL,
		0xBEB145012DFBC639ULL,
		0x409E4407A63DA71AULL,
		0xD59E3AEC838FA45DULL,
		0x66AC97A89984BDFCULL,
		0x1F73791C14C4C229ULL
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
		0xA13A30E5E4751269ULL,
		0xDDD810C1D1B10110ULL,
		0x5C5534CCAE1B857EULL,
		0x4A793250AA655B39ULL,
		0xE47D7C5E4FF2BB27ULL,
		0x3D71F19C42626136ULL,
		0xFA68B4FC23DD4971ULL,
		0x26DF5D38B172BD43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427461CBC8EA24D2ULL,
		0xBBB02183A3620221ULL,
		0xB8AA69995C370AFDULL,
		0x94F264A154CAB672ULL,
		0xC8FAF8BC9FE5764EULL,
		0x7AE3E33884C4C26DULL,
		0xF4D169F847BA92E2ULL,
		0x4DBEBA7162E57A87ULL
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
		0x52C1FB4CE20F793AULL,
		0x0055262251872568ULL,
		0x2E880CC0DED2E3E5ULL,
		0x8710A613227965F9ULL,
		0x6CF675E629B9A60AULL,
		0xAEF1851AF7475411ULL,
		0x3633E902DABC35ECULL,
		0x205304B3B60BF0DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA583F699C41EF274ULL,
		0x00AA4C44A30E4AD0ULL,
		0x5D101981BDA5C7CAULL,
		0x0E214C2644F2CBF2ULL,
		0xD9ECEBCC53734C15ULL,
		0x5DE30A35EE8EA822ULL,
		0x6C67D205B5786BD9ULL,
		0x40A609676C17E1BCULL
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
		0xE0BDA215A35B48D1ULL,
		0x18E8E15A9333448AULL,
		0x5D16EAC9043274A3ULL,
		0x80CE88EA2AB2BB6BULL,
		0xBE53BE9F8BBDB0E4ULL,
		0x54F79A719A376621ULL,
		0xB628DDCD476ED4EAULL,
		0x01F6DD06C910918CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC17B442B46B691A2ULL,
		0x31D1C2B526668915ULL,
		0xBA2DD5920864E946ULL,
		0x019D11D4556576D6ULL,
		0x7CA77D3F177B61C9ULL,
		0xA9EF34E3346ECC43ULL,
		0x6C51BB9A8EDDA9D4ULL,
		0x03EDBA0D92212319ULL
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
		0x9807E0CB09F3BB8CULL,
		0x8E6E4E5556D1CBBEULL,
		0x96C6E2EE1CD96B67ULL,
		0x05BA4A4D50B3304EULL,
		0xAF61ADBEC4406EC2ULL,
		0xE7125BF2DECB52A7ULL,
		0xF9A0398AABCDBE56ULL,
		0x32E7E1FF82D2E5EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x300FC19613E77718ULL,
		0x1CDC9CAAADA3977DULL,
		0x2D8DC5DC39B2D6CFULL,
		0x0B74949AA166609DULL,
		0x5EC35B7D8880DD84ULL,
		0xCE24B7E5BD96A54FULL,
		0xF3407315579B7CADULL,
		0x65CFC3FF05A5CBDBULL
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
		0xC732BE59051EC7EEULL,
		0x024F6AA44F11A16EULL,
		0xA1A7CD2AF98E7261ULL,
		0x9A7F6291663A1A16ULL,
		0xC72A274761626D7EULL,
		0xE844056E9CB0F5C6ULL,
		0xC3A5E6CDEB4E6050ULL,
		0x3B8D6D267658B7F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E657CB20A3D8FDCULL,
		0x049ED5489E2342DDULL,
		0x434F9A55F31CE4C2ULL,
		0x34FEC522CC74342DULL,
		0x8E544E8EC2C4DAFDULL,
		0xD0880ADD3961EB8DULL,
		0x874BCD9BD69CC0A1ULL,
		0x771ADA4CECB16FEBULL
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
		0x7634BF8AA8D70EC2ULL,
		0x8C940BF6ED191503ULL,
		0xFB459C9FA8CD2FB7ULL,
		0x94EC8F08F27EA69BULL,
		0xDA3478D1E21CC538ULL,
		0x773B5CDA38AF6D20ULL,
		0x5E640F5172C38303ULL,
		0x087CAD4DE7405D76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC697F1551AE1D84ULL,
		0x192817EDDA322A06ULL,
		0xF68B393F519A5F6FULL,
		0x29D91E11E4FD4D37ULL,
		0xB468F1A3C4398A71ULL,
		0xEE76B9B4715EDA41ULL,
		0xBCC81EA2E5870606ULL,
		0x10F95A9BCE80BAECULL
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
		0x799CDE0CC5311235ULL,
		0x439806F4C20E8EA7ULL,
		0xDCDE276230ED09FDULL,
		0x3B6D722DDA17DF6DULL,
		0xE26D493011F2287CULL,
		0x7B893F2D81D8410BULL,
		0xA6DF3C306C2AD8C3ULL,
		0x17B5B87B24E69BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF339BC198A62246AULL,
		0x87300DE9841D1D4EULL,
		0xB9BC4EC461DA13FAULL,
		0x76DAE45BB42FBEDBULL,
		0xC4DA926023E450F8ULL,
		0xF7127E5B03B08217ULL,
		0x4DBE7860D855B186ULL,
		0x2F6B70F649CD37FDULL
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
		0xA66DD9B53F5A0955ULL,
		0x29A6D153AEC88D7AULL,
		0xCEDBCE6745B4AA1AULL,
		0x792D28B821B04683ULL,
		0x071986FB2C0C96EEULL,
		0xB9C8B2B3FA8E0690ULL,
		0x58A60AE0FD69D888ULL,
		0x2ADA20EAF3977620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CDBB36A7EB412AAULL,
		0x534DA2A75D911AF5ULL,
		0x9DB79CCE8B695434ULL,
		0xF25A517043608D07ULL,
		0x0E330DF658192DDCULL,
		0x73916567F51C0D20ULL,
		0xB14C15C1FAD3B111ULL,
		0x55B441D5E72EEC40ULL
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
		0xDDE4B59B0E7587F9ULL,
		0x8E22AE3A7F025304ULL,
		0xEDADC3B77D7A693AULL,
		0xA789FF9B35240D2DULL,
		0x13AE5242C17B29D5ULL,
		0xBE37C4F271BE98ADULL,
		0x61135CD9D6B31DFFULL,
		0x313E6FF2A108C73AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBC96B361CEB0FF2ULL,
		0x1C455C74FE04A609ULL,
		0xDB5B876EFAF4D275ULL,
		0x4F13FF366A481A5BULL,
		0x275CA48582F653ABULL,
		0x7C6F89E4E37D315AULL,
		0xC226B9B3AD663BFFULL,
		0x627CDFE542118E74ULL
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
		0xA995070DA097660CULL,
		0x93ED8C3DE0E99581ULL,
		0xFE314C1BBD0241E3ULL,
		0x52E7FCF84E165837ULL,
		0x20A6D5CF1F49821EULL,
		0xEEC73874CDE19214ULL,
		0x0859A5EBE008D7B3ULL,
		0x305526EA89E86F53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x532A0E1B412ECC18ULL,
		0x27DB187BC1D32B03ULL,
		0xFC6298377A0483C7ULL,
		0xA5CFF9F09C2CB06FULL,
		0x414DAB9E3E93043CULL,
		0xDD8E70E99BC32428ULL,
		0x10B34BD7C011AF67ULL,
		0x60AA4DD513D0DEA6ULL
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
		0xA9BE8880FC7D0614ULL,
		0x120952F00E75742EULL,
		0xA0910F78CE196C3FULL,
		0xEE96CEFB87433EF7ULL,
		0x1A8E0F0353D1C218ULL,
		0xF4EF1D59B48F8DD6ULL,
		0x3FD72A6A3D0D144BULL,
		0x17560324C0701C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x537D1101F8FA0C28ULL,
		0x2412A5E01CEAE85DULL,
		0x41221EF19C32D87EULL,
		0xDD2D9DF70E867DEFULL,
		0x351C1E06A7A38431ULL,
		0xE9DE3AB3691F1BACULL,
		0x7FAE54D47A1A2897ULL,
		0x2EAC064980E0390CULL
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
		0x0BDD1E8B7137AD4CULL,
		0x2762946F00473E06ULL,
		0x8256D90DA75915D0ULL,
		0x89D6A96B57A878B3ULL,
		0x819AB7B467224A7FULL,
		0x94FA3B8FD1811830ULL,
		0xAE8DD8E6E4D15A5CULL,
		0x24475AF18AF56404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17BA3D16E26F5A98ULL,
		0x4EC528DE008E7C0CULL,
		0x04ADB21B4EB22BA0ULL,
		0x13AD52D6AF50F167ULL,
		0x03356F68CE4494FFULL,
		0x29F4771FA3023061ULL,
		0x5D1BB1CDC9A2B4B9ULL,
		0x488EB5E315EAC809ULL
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
		0xBAF4B08AED2F2D89ULL,
		0x323084BC6E5AFB62ULL,
		0x6D9EB786DECF37F3ULL,
		0x80842D63AF8E3733ULL,
		0x4171A98D9BCD6F14ULL,
		0xDACF0BF57DBE33F3ULL,
		0x25F69AE6E3FB286AULL,
		0x221B217F7A4D9130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75E96115DA5E5B12ULL,
		0x64610978DCB5F6C5ULL,
		0xDB3D6F0DBD9E6FE6ULL,
		0x01085AC75F1C6E66ULL,
		0x82E3531B379ADE29ULL,
		0xB59E17EAFB7C67E6ULL,
		0x4BED35CDC7F650D5ULL,
		0x443642FEF49B2260ULL
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
		0xD0A8C9ED5769EC92ULL,
		0xD263EC04208591B0ULL,
		0x7F4EBEE440790FADULL,
		0x47F644085E0656DDULL,
		0x283C5643E6D12701ULL,
		0xBC6637B3D533B4F8ULL,
		0xE8299C6D683E0D8CULL,
		0x39331DBFB4AA2FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15193DAAED3D924ULL,
		0xA4C7D808410B2361ULL,
		0xFE9D7DC880F21F5BULL,
		0x8FEC8810BC0CADBAULL,
		0x5078AC87CDA24E02ULL,
		0x78CC6F67AA6769F0ULL,
		0xD05338DAD07C1B19ULL,
		0x72663B7F69545F45ULL
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
		0x887B1155CA6321F0ULL,
		0x38EFC37B1507484DULL,
		0xF80E9A420674341CULL,
		0x21C08BA6AD478983ULL,
		0xE626A9846747CCABULL,
		0xF7DF3C47FFAE1E62ULL,
		0x0C9C52FBE860FD50ULL,
		0x1AB5F46DA5924A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F622AB94C643E0ULL,
		0x71DF86F62A0E909BULL,
		0xF01D34840CE86838ULL,
		0x4381174D5A8F1307ULL,
		0xCC4D5308CE8F9956ULL,
		0xEFBE788FFF5C3CC5ULL,
		0x1938A5F7D0C1FAA1ULL,
		0x356BE8DB4B24951CULL
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
		0x1EDB0FBEFE6D7E9BULL,
		0x018F2A6BC703B5F2ULL,
		0xA7DDC33F941244CCULL,
		0x4C772CC15AB239EEULL,
		0x5D6062EE0CE0E078ULL,
		0xD6D9F3B70EA4F558ULL,
		0x46FB8E1595882117ULL,
		0x2A276EEADB9206A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DB61F7DFCDAFD36ULL,
		0x031E54D78E076BE4ULL,
		0x4FBB867F28248998ULL,
		0x98EE5982B56473DDULL,
		0xBAC0C5DC19C1C0F0ULL,
		0xADB3E76E1D49EAB0ULL,
		0x8DF71C2B2B10422FULL,
		0x544EDDD5B7240D4AULL
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
		0xA521269EC7A0A93FULL,
		0x34C2891726415B32ULL,
		0x336C700CA3AC1AD5ULL,
		0xD0193CB1C06D6774ULL,
		0x5975E2B39BAFC655ULL,
		0xDF446C25C5711D9AULL,
		0x8C6308879232C053ULL,
		0x3DCB9B0A9D99D54DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A424D3D8F41527EULL,
		0x6985122E4C82B665ULL,
		0x66D8E019475835AAULL,
		0xA032796380DACEE8ULL,
		0xB2EBC567375F8CABULL,
		0xBE88D84B8AE23B34ULL,
		0x18C6110F246580A7ULL,
		0x7B9736153B33AA9BULL
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
		0xDEC40D95FF446F7FULL,
		0x145801474BF9D031ULL,
		0x4BCBD2239867221AULL,
		0x33FC66640D043CA4ULL,
		0xFFE417D30CD7EEE4ULL,
		0x77EC12AA41497FC0ULL,
		0xD0D0CD156225762DULL,
		0x392E6564D0AA5F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD881B2BFE88DEFEULL,
		0x28B0028E97F3A063ULL,
		0x9797A44730CE4434ULL,
		0x67F8CCC81A087948ULL,
		0xFFC82FA619AFDDC8ULL,
		0xEFD825548292FF81ULL,
		0xA1A19A2AC44AEC5AULL,
		0x725CCAC9A154BEBFULL
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
		0x59F7CB5E6AE89E51ULL,
		0xE4184252EB6FBD5CULL,
		0x1AE0417E228C9378ULL,
		0x2315023C11452DB4ULL,
		0xEFB3D1367BDEADC1ULL,
		0x0220C4290047A0C1ULL,
		0x0F68F7ED6883675BULL,
		0x362B4553D33B749FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3EF96BCD5D13CA2ULL,
		0xC83084A5D6DF7AB8ULL,
		0x35C082FC451926F1ULL,
		0x462A0478228A5B68ULL,
		0xDF67A26CF7BD5B82ULL,
		0x04418852008F4183ULL,
		0x1ED1EFDAD106CEB6ULL,
		0x6C568AA7A676E93EULL
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
		0xEC536D75E1A7610FULL,
		0x7960A2B09C9BAE94ULL,
		0x4296AE06EED314D6ULL,
		0x7D64C4FCF2BD8C0BULL,
		0x0C02040163C014F0ULL,
		0x46D2D2F25A0F1BAFULL,
		0xD74970E23F838967ULL,
		0x2BD9D7FF48503D65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A6DAEBC34EC21EULL,
		0xF2C1456139375D29ULL,
		0x852D5C0DDDA629ACULL,
		0xFAC989F9E57B1816ULL,
		0x18040802C78029E0ULL,
		0x8DA5A5E4B41E375EULL,
		0xAE92E1C47F0712CEULL,
		0x57B3AFFE90A07ACBULL
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
		0x0A331F33A03BF819ULL,
		0xAC9758608F9684A9ULL,
		0xE2D79504E705777AULL,
		0x9EBD432397F6DB26ULL,
		0x6270ABE2616F1626ULL,
		0xE6F83B8C138F0433ULL,
		0x31550EF276F2168DULL,
		0x2318028FAAC80084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14663E674077F032ULL,
		0x592EB0C11F2D0952ULL,
		0xC5AF2A09CE0AEEF5ULL,
		0x3D7A86472FEDB64DULL,
		0xC4E157C4C2DE2C4DULL,
		0xCDF07718271E0866ULL,
		0x62AA1DE4EDE42D1BULL,
		0x4630051F55900108ULL
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
		0x69322EFD70312FBEULL,
		0x153E10AF10E175B3ULL,
		0x5079DA2125F3F132ULL,
		0x28A86438DB9049C8ULL,
		0xBF6AAC67C2E7DA52ULL,
		0xD0C3AAA01B6EE4CBULL,
		0x580CC1181CA0CBC2ULL,
		0x04B9E1991A3F99EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2645DFAE0625F7CULL,
		0x2A7C215E21C2EB66ULL,
		0xA0F3B4424BE7E264ULL,
		0x5150C871B7209390ULL,
		0x7ED558CF85CFB4A4ULL,
		0xA187554036DDC997ULL,
		0xB019823039419785ULL,
		0x0973C332347F33DEULL
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
		0xE22E1A6A5FCA7515ULL,
		0x956FF817A75D33DAULL,
		0xD5603575A0D32585ULL,
		0x190C5F3F16C72240ULL,
		0x572EDAF6D4FDC5E0ULL,
		0xF94BDEA034B5354FULL,
		0x3306E374901EB08CULL,
		0x070B3C4E9D22BAC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC45C34D4BF94EA2AULL,
		0x2ADFF02F4EBA67B5ULL,
		0xAAC06AEB41A64B0BULL,
		0x3218BE7E2D8E4481ULL,
		0xAE5DB5EDA9FB8BC0ULL,
		0xF297BD40696A6A9EULL,
		0x660DC6E9203D6119ULL,
		0x0E16789D3A457592ULL
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
		0x7E5B003CD9E75C87ULL,
		0x1F56CF3A4238FC1CULL,
		0xDC9F26C1D01A7455ULL,
		0xEC12FA21D0BE4872ULL,
		0xAFB805B9F21C4241ULL,
		0xE287BD42B725B706ULL,
		0xE9426D066A816A23ULL,
		0x104279F868731E8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB60079B3CEB90EULL,
		0x3EAD9E748471F838ULL,
		0xB93E4D83A034E8AAULL,
		0xD825F443A17C90E5ULL,
		0x5F700B73E4388483ULL,
		0xC50F7A856E4B6E0DULL,
		0xD284DA0CD502D447ULL,
		0x2084F3F0D0E63D1FULL
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
		0x1FC32600BB3CF8F2ULL,
		0xB8E24DACE3694493ULL,
		0xBC046AED5C4D03AFULL,
		0x7F43739B6A64E041ULL,
		0x14183D6474543923ULL,
		0x0382F6220F6F0557ULL,
		0x35CF3FBD396ECDBAULL,
		0x0604E73099E3B404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F864C017679F1E4ULL,
		0x71C49B59C6D28926ULL,
		0x7808D5DAB89A075FULL,
		0xFE86E736D4C9C083ULL,
		0x28307AC8E8A87246ULL,
		0x0705EC441EDE0AAEULL,
		0x6B9E7F7A72DD9B74ULL,
		0x0C09CE6133C76808ULL
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
		0xF1D7BB153C4455C0ULL,
		0x9DB55E3E9EF18F6BULL,
		0x9CFD2A850F9D5802ULL,
		0x4AF98B05CB3227D4ULL,
		0x8E8C47D207CAF1F2ULL,
		0x118908F234B65F41ULL,
		0xB8405436D28F9E4EULL,
		0x0C7C846113D6E8ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3AF762A7888AB80ULL,
		0x3B6ABC7D3DE31ED7ULL,
		0x39FA550A1F3AB005ULL,
		0x95F3160B96644FA9ULL,
		0x1D188FA40F95E3E4ULL,
		0x231211E4696CBE83ULL,
		0x7080A86DA51F3C9CULL,
		0x18F908C227ADD15BULL
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
		0x0D5D5F216EB1BC17ULL,
		0xCEA8C0B3F620D212ULL,
		0xABB9511C7B764C5DULL,
		0xB49F8D92E3461F7EULL,
		0xD1E8475068281C1AULL,
		0x08DB391BC286C983ULL,
		0x8C60FBBA729625FBULL,
		0x2CB3F15EE8EE1F3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ABABE42DD63782EULL,
		0x9D518167EC41A424ULL,
		0x5772A238F6EC98BBULL,
		0x693F1B25C68C3EFDULL,
		0xA3D08EA0D0503835ULL,
		0x11B67237850D9307ULL,
		0x18C1F774E52C4BF6ULL,
		0x5967E2BDD1DC3E79ULL
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
		0x082B03F3CE1691F1ULL,
		0x98646882521043E3ULL,
		0xC9FBDE2B217501DAULL,
		0xC8FD5E9E9E67EB11ULL,
		0x76DFB149C5C815EFULL,
		0x0EEE494451197FEFULL,
		0x8FC2C5B178A3371CULL,
		0x28395E2122E9827CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105607E79C2D23E2ULL,
		0x30C8D104A42087C6ULL,
		0x93F7BC5642EA03B5ULL,
		0x91FABD3D3CCFD623ULL,
		0xEDBF62938B902BDFULL,
		0x1DDC9288A232FFDEULL,
		0x1F858B62F1466E38ULL,
		0x5072BC4245D304F9ULL
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
		0xA5F81CF49A154A89ULL,
		0x62DF7FB0F8A907E2ULL,
		0xE94970CFBC8B2618ULL,
		0xF2206360D6AC4124ULL,
		0x2D889AC54401C66BULL,
		0x52966EDB18A35158ULL,
		0x66D70E18C95394DEULL,
		0x31B6B08C19D66B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF039E9342A9512ULL,
		0xC5BEFF61F1520FC5ULL,
		0xD292E19F79164C30ULL,
		0xE440C6C1AD588249ULL,
		0x5B11358A88038CD7ULL,
		0xA52CDDB63146A2B0ULL,
		0xCDAE1C3192A729BCULL,
		0x636D611833ACD70CULL
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
		0x437F2623D5D16E11ULL,
		0x16D0CF8A8FDD4E5CULL,
		0xB44D23F50A22816AULL,
		0xAF244023B7E6B857ULL,
		0xE0A4384F18A49B78ULL,
		0x1F031D1DF342276BULL,
		0x6D2AC283D5BCFF4FULL,
		0x21841DB7F93D2E51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86FE4C47ABA2DC22ULL,
		0x2DA19F151FBA9CB8ULL,
		0x689A47EA144502D4ULL,
		0x5E4880476FCD70AFULL,
		0xC148709E314936F1ULL,
		0x3E063A3BE6844ED7ULL,
		0xDA558507AB79FE9EULL,
		0x43083B6FF27A5CA2ULL
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
		0x0B17D15905E55CEFULL,
		0xEFF04AC98DEFF839ULL,
		0x6AC6F6BAB7A702E3ULL,
		0xB6E5675293FB49D9ULL,
		0x1FA0114EB78EBE23ULL,
		0xBB877184561E846FULL,
		0xABC452F2396FA4E0ULL,
		0x2244CCFF1854184CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x162FA2B20BCAB9DEULL,
		0xDFE095931BDFF072ULL,
		0xD58DED756F4E05C7ULL,
		0x6DCACEA527F693B2ULL,
		0x3F40229D6F1D7C47ULL,
		0x770EE308AC3D08DEULL,
		0x5788A5E472DF49C1ULL,
		0x448999FE30A83099ULL
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
		0xA772312AEDCA0689ULL,
		0x33413421AE086CFCULL,
		0x729A3B81A2593B10ULL,
		0x3F95CCF07BA4363CULL,
		0x0C581B5994651DCCULL,
		0xE92914FCBC8EDEC1ULL,
		0x324FD19523349B0EULL,
		0x0A987457AE16F335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EE46255DB940D12ULL,
		0x668268435C10D9F9ULL,
		0xE534770344B27620ULL,
		0x7F2B99E0F7486C78ULL,
		0x18B036B328CA3B98ULL,
		0xD25229F9791DBD82ULL,
		0x649FA32A4669361DULL,
		0x1530E8AF5C2DE66AULL
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
		0x0B58AA62A8989747ULL,
		0x733374490C21C1F7ULL,
		0x4841E5C742AD609CULL,
		0x3533E59020FF08D3ULL,
		0x76D009AA475250FFULL,
		0xB9692ED01F54FC19ULL,
		0xF2244DDDCB7F0244ULL,
		0x0AFB68BBEFB93D56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B154C551312E8EULL,
		0xE666E892184383EEULL,
		0x9083CB8E855AC138ULL,
		0x6A67CB2041FE11A6ULL,
		0xEDA013548EA4A1FEULL,
		0x72D25DA03EA9F832ULL,
		0xE4489BBB96FE0489ULL,
		0x15F6D177DF727AADULL
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
		0xF3DA062408523588ULL,
		0x401F64332C5F7968ULL,
		0x45D67D458FF243FCULL,
		0xDA0FAE92992E33CEULL,
		0x8D8A40673C4E5971ULL,
		0x94B4D5B9C8902865ULL,
		0x5CFB1B5C99FB8C48ULL,
		0x2FBD4BFA550C427AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B40C4810A46B10ULL,
		0x803EC86658BEF2D1ULL,
		0x8BACFA8B1FE487F8ULL,
		0xB41F5D25325C679CULL,
		0x1B1480CE789CB2E3ULL,
		0x2969AB73912050CBULL,
		0xB9F636B933F71891ULL,
		0x5F7A97F4AA1884F4ULL
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
		0x234C514545DC4A03ULL,
		0xEEDA32DBFC72E427ULL,
		0x9A72E8A7CEBC43E2ULL,
		0xC0FA4A7516F20399ULL,
		0x9449298293672922ULL,
		0x0E1317907943F3F5ULL,
		0xC6E496642C96FBF7ULL,
		0x0C29178CE880F45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4698A28A8BB89406ULL,
		0xDDB465B7F8E5C84EULL,
		0x34E5D14F9D7887C5ULL,
		0x81F494EA2DE40733ULL,
		0x2892530526CE5245ULL,
		0x1C262F20F287E7EBULL,
		0x8DC92CC8592DF7EEULL,
		0x18522F19D101E8B5ULL
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
		0x856A81C3D0B1C4A7ULL,
		0xE8AFC121A5BD1AE8ULL,
		0xE422B14FDC687774ULL,
		0x00B1B66C6E0E15BDULL,
		0x9A34840B69ACA113ULL,
		0xE613706D9A4F8DF7ULL,
		0xEE3EAB5A7225FD67ULL,
		0x1F0A296954C1BBB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD50387A163894EULL,
		0xD15F82434B7A35D1ULL,
		0xC845629FB8D0EEE9ULL,
		0x01636CD8DC1C2B7BULL,
		0x34690816D3594226ULL,
		0xCC26E0DB349F1BEFULL,
		0xDC7D56B4E44BFACFULL,
		0x3E1452D2A9837765ULL
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
		0x296E549EF7A58BAAULL,
		0x4A43E5798FB5BE1BULL,
		0x2F9BA0DB80A88609ULL,
		0xCD219FAF90C39515ULL,
		0xD6CDAB2A5453DB6BULL,
		0x621144438AA396C6ULL,
		0xC98F249DA05EC4FEULL,
		0x01D6699E8552F76EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DCA93DEF4B1754ULL,
		0x9487CAF31F6B7C36ULL,
		0x5F3741B701510C12ULL,
		0x9A433F5F21872A2AULL,
		0xAD9B5654A8A7B6D7ULL,
		0xC422888715472D8DULL,
		0x931E493B40BD89FCULL,
		0x03ACD33D0AA5EEDDULL
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
		0xFBD1228316566A8AULL,
		0xE574F6FCEF9422A6ULL,
		0xDE07F6154BB22292ULL,
		0x7B46121841C18397ULL,
		0xFDB1A3BB466AFECAULL,
		0xB43E94AF6FA3B2A7ULL,
		0x4EE270B1316F1D0DULL,
		0x19473196229B21F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A245062CACD514ULL,
		0xCAE9EDF9DF28454DULL,
		0xBC0FEC2A97644525ULL,
		0xF68C24308383072FULL,
		0xFB6347768CD5FD94ULL,
		0x687D295EDF47654FULL,
		0x9DC4E16262DE3A1BULL,
		0x328E632C453643E4ULL
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
		0x0EF940FE7F8159C6ULL,
		0xE265479F423E0D17ULL,
		0x03D0426511B9CE15ULL,
		0xC73A06579FBC9E19ULL,
		0x046A2F2D7CA5DBCDULL,
		0x1441A3089B1A4D66ULL,
		0xB7FF7BB5A43B42ACULL,
		0x2ED4C96318AC3BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DF281FCFF02B38CULL,
		0xC4CA8F3E847C1A2EULL,
		0x07A084CA23739C2BULL,
		0x8E740CAF3F793C32ULL,
		0x08D45E5AF94BB79BULL,
		0x2883461136349ACCULL,
		0x6FFEF76B48768558ULL,
		0x5DA992C6315877C3ULL
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
		0x923E714D492FF159ULL,
		0xFDD78ED8E6052816ULL,
		0x76EB65BD43468754ULL,
		0x2AAA11E2FBF0E648ULL,
		0x57EA51B545C3CE2AULL,
		0x254538127DD49CE7ULL,
		0x59F2695FEEDB0374ULL,
		0x314F1DCF5C7A9F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247CE29A925FE2B2ULL,
		0xFBAF1DB1CC0A502DULL,
		0xEDD6CB7A868D0EA9ULL,
		0x555423C5F7E1CC90ULL,
		0xAFD4A36A8B879C54ULL,
		0x4A8A7024FBA939CEULL,
		0xB3E4D2BFDDB606E8ULL,
		0x629E3B9EB8F53EA2ULL
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
		0x6F1ADA13DBB8137FULL,
		0x8D74DA8E2C85A800ULL,
		0xB8C8DB9232510BD3ULL,
		0xD01E7CFC7765F8EBULL,
		0x56D823B0CA346AD2ULL,
		0x10B1A614922BAFA5ULL,
		0x19AB91AF79A76BCDULL,
		0x2B7EA0F87CC7ED5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE35B427B77026FEULL,
		0x1AE9B51C590B5000ULL,
		0x7191B72464A217A7ULL,
		0xA03CF9F8EECBF1D7ULL,
		0xADB047619468D5A5ULL,
		0x21634C2924575F4AULL,
		0x3357235EF34ED79AULL,
		0x56FD41F0F98FDAB6ULL
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
		0x71AE98CF47CFDD85ULL,
		0x25FED81CA4143E37ULL,
		0xB188722689233C77ULL,
		0x1A4C3398198D08D4ULL,
		0xEF42AB47A12A6C5AULL,
		0x41DB3A331B25FCCEULL,
		0xBE16B08183351099ULL,
		0x1856D1343EE28630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE35D319E8F9FBB0AULL,
		0x4BFDB03948287C6EULL,
		0x6310E44D124678EEULL,
		0x34986730331A11A9ULL,
		0xDE85568F4254D8B4ULL,
		0x83B67466364BF99DULL,
		0x7C2D6103066A2132ULL,
		0x30ADA2687DC50C61ULL
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
		0x4BF377BF719EFC8AULL,
		0xEBE001D56EA6D93BULL,
		0x963896F7C07613F8ULL,
		0x9D52A04ED1C81E24ULL,
		0xD54C9616DA0773E6ULL,
		0x2C79CA2E597C752CULL,
		0xF6667C0555B72AF2ULL,
		0x32D13FD39DF5C38FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E6EF7EE33DF914ULL,
		0xD7C003AADD4DB276ULL,
		0x2C712DEF80EC27F1ULL,
		0x3AA5409DA3903C49ULL,
		0xAA992C2DB40EE7CDULL,
		0x58F3945CB2F8EA59ULL,
		0xECCCF80AAB6E55E4ULL,
		0x65A27FA73BEB871FULL
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
		0x5D915E0BC85EF279ULL,
		0x015BA8FBB3AD92FCULL,
		0x73E3C1D698DB47E2ULL,
		0x6CD53E8DA7A9951AULL,
		0x0E61128AC679357EULL,
		0x79F9AEAE56C6C96DULL,
		0xE3839BE3104FE667ULL,
		0x3EAB6B9E70A15136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB22BC1790BDE4F2ULL,
		0x02B751F7675B25F8ULL,
		0xE7C783AD31B68FC4ULL,
		0xD9AA7D1B4F532A34ULL,
		0x1CC225158CF26AFCULL,
		0xF3F35D5CAD8D92DAULL,
		0xC70737C6209FCCCEULL,
		0x7D56D73CE142A26DULL
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
		0x88A29454A1DE5434ULL,
		0x32B2B2F82CA38992ULL,
		0x607B8F5ED84BF060ULL,
		0xD561FC04056FDCFEULL,
		0xCBF35BD7265402F9ULL,
		0x6D210B9139E5A118ULL,
		0xFFDFB5CC013FFFC4ULL,
		0x201F2C84DD9C6627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x114528A943BCA868ULL,
		0x656565F059471325ULL,
		0xC0F71EBDB097E0C0ULL,
		0xAAC3F8080ADFB9FCULL,
		0x97E6B7AE4CA805F3ULL,
		0xDA42172273CB4231ULL,
		0xFFBF6B98027FFF88ULL,
		0x403E5909BB38CC4FULL
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
		0x8D67BE5B71F5E9C2ULL,
		0x9ECDE92BAA9B3494ULL,
		0xA489E2A89680003CULL,
		0xF722384E440F7F40ULL,
		0xD84D5338434312ABULL,
		0x4DE81A0B31380E7CULL,
		0x5FA36BE080412615ULL,
		0x1139950C02E66163ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ACF7CB6E3EBD384ULL,
		0x3D9BD25755366929ULL,
		0x4913C5512D000079ULL,
		0xEE44709C881EFE81ULL,
		0xB09AA67086862557ULL,
		0x9BD0341662701CF9ULL,
		0xBF46D7C100824C2AULL,
		0x22732A1805CCC2C6ULL
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
		0xFE62844CD197CDBDULL,
		0x6C3D861573DB3365ULL,
		0xAC1D02069FAB25F6ULL,
		0xD53F8787DAC9D98EULL,
		0x1166346C166789D9ULL,
		0x89AAE428A0D59EC9ULL,
		0x54B38F8BBBBEF19CULL,
		0x3B7CC167E574C466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCC50899A32F9B7AULL,
		0xD87B0C2AE7B666CBULL,
		0x583A040D3F564BECULL,
		0xAA7F0F0FB593B31DULL,
		0x22CC68D82CCF13B3ULL,
		0x1355C85141AB3D92ULL,
		0xA9671F17777DE339ULL,
		0x76F982CFCAE988CCULL
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
		0x999B37BCD78E3D46ULL,
		0x4EE1D35FDD22B506ULL,
		0xB9CC453E0603F23CULL,
		0x4FADBFEEF0684A1BULL,
		0x00BEB202CEB97C8AULL,
		0x14C9F3B934F31D52ULL,
		0x94B5C1993ABECAA4ULL,
		0x378C84BB4300CFE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33366F79AF1C7A8CULL,
		0x9DC3A6BFBA456A0DULL,
		0x73988A7C0C07E478ULL,
		0x9F5B7FDDE0D09437ULL,
		0x017D64059D72F914ULL,
		0x2993E77269E63AA4ULL,
		0x296B8332757D9548ULL,
		0x6F19097686019FCDULL
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
		0xCF3EFEEB55A402F6ULL,
		0xAA309B200BCF320FULL,
		0xFF9FAD857429B897ULL,
		0x2E01C82B79940621ULL,
		0x39BC54B562EAC1F2ULL,
		0xB6E2CE92E4A74689ULL,
		0x632A6EF20DF7541AULL,
		0x25597F218BF63ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E7DFDD6AB4805ECULL,
		0x54613640179E641FULL,
		0xFF3F5B0AE853712FULL,
		0x5C039056F3280C43ULL,
		0x7378A96AC5D583E4ULL,
		0x6DC59D25C94E8D12ULL,
		0xC654DDE41BEEA835ULL,
		0x4AB2FE4317EC7DACULL
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
		0x2A59E6BCC2FADFD4ULL,
		0x6914DC1B65F4FCDCULL,
		0x2D580BCBB2274ABEULL,
		0x6C89893AEB11EEE1ULL,
		0x67CCDAF7D9DFD2E0ULL,
		0xA8BF899A1591EEDCULL,
		0xCA967E4555ADB5ABULL,
		0x07E462E0DF5BD715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B3CD7985F5BFA8ULL,
		0xD229B836CBE9F9B8ULL,
		0x5AB01797644E957CULL,
		0xD9131275D623DDC2ULL,
		0xCF99B5EFB3BFA5C0ULL,
		0x517F13342B23DDB8ULL,
		0x952CFC8AAB5B6B57ULL,
		0x0FC8C5C1BEB7AE2BULL
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
		0x36A2CCA876D71E5EULL,
		0x794A37924C56AAA2ULL,
		0x9067FB03EF5CA897ULL,
		0x51C4D6493D4FF8B5ULL,
		0x8192C620EB157BD8ULL,
		0xBFB4DD6F82FA8F41ULL,
		0x2172C6670A3DC1BDULL,
		0x0D69A3CACCF5A8BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D459950EDAE3CBCULL,
		0xF2946F2498AD5544ULL,
		0x20CFF607DEB9512EULL,
		0xA389AC927A9FF16BULL,
		0x03258C41D62AF7B0ULL,
		0x7F69BADF05F51E83ULL,
		0x42E58CCE147B837BULL,
		0x1AD3479599EB5176ULL
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
		0x60FA837EFC159E69ULL,
		0x982E0C7D65F02380ULL,
		0x66ED3A90630B9FCCULL,
		0x7E2FD2C6F3E37031ULL,
		0xE2A998039FB16ED0ULL,
		0xB12A6E5062E2DB52ULL,
		0x72CF3AEDF11978D5ULL,
		0x2FBA64929159B785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1F506FDF82B3CD2ULL,
		0x305C18FACBE04700ULL,
		0xCDDA7520C6173F99ULL,
		0xFC5FA58DE7C6E062ULL,
		0xC55330073F62DDA0ULL,
		0x6254DCA0C5C5B6A5ULL,
		0xE59E75DBE232F1ABULL,
		0x5F74C92522B36F0AULL
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
		0xB8405A85B97AB73DULL,
		0xBADBAB892635CA95ULL,
		0x93A04CDE8AAB5CB1ULL,
		0xA1FE601E04B4DCD8ULL,
		0x7F27DEACF44295EEULL,
		0x795A91B3E664FF9CULL,
		0xE860A5B58A903329ULL,
		0x11855FB65D54C76AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7080B50B72F56E7AULL,
		0x75B757124C6B952BULL,
		0x274099BD1556B963ULL,
		0x43FCC03C0969B9B1ULL,
		0xFE4FBD59E8852BDDULL,
		0xF2B52367CCC9FF38ULL,
		0xD0C14B6B15206652ULL,
		0x230ABF6CBAA98ED5ULL
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
		0x1D2B084F421AAFA9ULL,
		0x9FAA4B31CD968E9EULL,
		0x3772F9A25316F62EULL,
		0x2086FCD00762841EULL,
		0xBE8FA79379DEDA7FULL,
		0x2654302232F9FB2EULL,
		0x726A0334011ECCAFULL,
		0x22188BC48A5343DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A56109E84355F52ULL,
		0x3F5496639B2D1D3CULL,
		0x6EE5F344A62DEC5DULL,
		0x410DF9A00EC5083CULL,
		0x7D1F4F26F3BDB4FEULL,
		0x4CA8604465F3F65DULL,
		0xE4D40668023D995EULL,
		0x4431178914A687BEULL
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
		0xBB1F6811041DFA20ULL,
		0x8E8E939FF0E63A05ULL,
		0x5E8126E95169C5A2ULL,
		0xEE86C80FB467EB6DULL,
		0x73239EC2EC1D99FCULL,
		0x7072AE70F952B5EFULL,
		0x03ED76FDD36785CAULL,
		0x3F69F18B4A39CCB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x763ED022083BF440ULL,
		0x1D1D273FE1CC740BULL,
		0xBD024DD2A2D38B45ULL,
		0xDD0D901F68CFD6DAULL,
		0xE6473D85D83B33F9ULL,
		0xE0E55CE1F2A56BDEULL,
		0x07DAEDFBA6CF0B94ULL,
		0x7ED3E31694739970ULL
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
		0xFF8F4C58304C69BDULL,
		0x5A54CE7C216ACB14ULL,
		0xEA63FFDDFA679196ULL,
		0xF4AE2B82200A85B3ULL,
		0xC0D14C29897BBFEDULL,
		0xAFE60846F55E8DEFULL,
		0xF01EC29CC39C707FULL,
		0x3A3D82EFAF738420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF1E98B06098D37AULL,
		0xB4A99CF842D59629ULL,
		0xD4C7FFBBF4CF232CULL,
		0xE95C570440150B67ULL,
		0x81A2985312F77FDBULL,
		0x5FCC108DEABD1BDFULL,
		0xE03D85398738E0FFULL,
		0x747B05DF5EE70841ULL
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
		0xFAD092D2CD7FB849ULL,
		0x28754831F3635635ULL,
		0xE29869CF88156627ULL,
		0xB483AC6D2F68017AULL,
		0xF29D10F13680A24CULL,
		0x2136D378242D28B0ULL,
		0x02AE2B226E99797AULL,
		0x35C7216944722BF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A125A59AFF7092ULL,
		0x50EA9063E6C6AC6BULL,
		0xC530D39F102ACC4EULL,
		0x690758DA5ED002F5ULL,
		0xE53A21E26D014499ULL,
		0x426DA6F0485A5161ULL,
		0x055C5644DD32F2F4ULL,
		0x6B8E42D288E457E6ULL
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
		0x711CAFFF44E003BCULL,
		0xDCC93B38B0C85C4FULL,
		0x592C65EEAC88302EULL,
		0xA24688177360F800ULL,
		0x201E509F02FC1C7CULL,
		0x84F6E7A06BD5555DULL,
		0xD948ABAF85B867A7ULL,
		0x29B43AEEB0A6544BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2395FFE89C00778ULL,
		0xB99276716190B89EULL,
		0xB258CBDD5910605DULL,
		0x448D102EE6C1F000ULL,
		0x403CA13E05F838F9ULL,
		0x09EDCF40D7AAAABAULL,
		0xB291575F0B70CF4FULL,
		0x536875DD614CA897ULL
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
		0x8D32C60BDD22073BULL,
		0x2575BA2FFC901CCBULL,
		0xB07B8ABFCBB40649ULL,
		0xB8A9EE58F813A4C2ULL,
		0xB774EAA7FC751ED4ULL,
		0x2954C3BAE06E142DULL,
		0x1644144138D45CCFULL,
		0x3E563657899C54E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A658C17BA440E76ULL,
		0x4AEB745FF9203997ULL,
		0x60F7157F97680C92ULL,
		0x7153DCB1F0274985ULL,
		0x6EE9D54FF8EA3DA9ULL,
		0x52A98775C0DC285BULL,
		0x2C88288271A8B99EULL,
		0x7CAC6CAF1338A9CAULL
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
		0xBAFE7D5976BE81C2ULL,
		0xBD9EA40C5B29996FULL,
		0x74B668B2548A12B8ULL,
		0xC7377B66A125A0DEULL,
		0xEEE334DA18431CECULL,
		0xB33B9224E885E777ULL,
		0x3F1B156FF91106B5ULL,
		0x0E2C8A0EB0DB78D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FCFAB2ED7D0384ULL,
		0x7B3D4818B65332DFULL,
		0xE96CD164A9142571ULL,
		0x8E6EF6CD424B41BCULL,
		0xDDC669B4308639D9ULL,
		0x66772449D10BCEEFULL,
		0x7E362ADFF2220D6BULL,
		0x1C59141D61B6F1AAULL
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
		0x8B716E4A75967775ULL,
		0x8195341ACB56D067ULL,
		0x58979A696AA6BEEBULL,
		0xAD0AC4EB1BA87D30ULL,
		0x60555768EEB2CB7AULL,
		0x9675F72806578D5CULL,
		0xFDFFCB7A759BF757ULL,
		0x3F8D47410E4431BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E2DC94EB2CEEEAULL,
		0x032A683596ADA0CFULL,
		0xB12F34D2D54D7DD7ULL,
		0x5A1589D63750FA60ULL,
		0xC0AAAED1DD6596F5ULL,
		0x2CEBEE500CAF1AB8ULL,
		0xFBFF96F4EB37EEAFULL,
		0x7F1A8E821C88637BULL
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
		0x195E826374048E96ULL,
		0xE241FAAD4EF792FBULL,
		0x8D7ABBE1643A2182ULL,
		0x04BFCA7545EF756BULL,
		0x54E732C0E1F459EEULL,
		0xD676303CE1CC588FULL,
		0xF37FF778CB356F33ULL,
		0x3E4F69FC39647AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32BD04C6E8091D2CULL,
		0xC483F55A9DEF25F6ULL,
		0x1AF577C2C8744305ULL,
		0x097F94EA8BDEEAD7ULL,
		0xA9CE6581C3E8B3DCULL,
		0xACEC6079C398B11EULL,
		0xE6FFEEF1966ADE67ULL,
		0x7C9ED3F872C8F587ULL
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
		0x2F5A8639B7F5FB55ULL,
		0x5FF2C1C34A424A45ULL,
		0xB41716976017F11BULL,
		0x8D4C882D140F6834ULL,
		0xC3DA215C2D14BBCCULL,
		0xDDD256BDA08271BAULL,
		0x28E526591B5FF76FULL,
		0x0FB4F2F17C364F36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB50C736FEBF6AAULL,
		0xBFE583869484948AULL,
		0x682E2D2EC02FE236ULL,
		0x1A99105A281ED069ULL,
		0x87B442B85A297799ULL,
		0xBBA4AD7B4104E375ULL,
		0x51CA4CB236BFEEDFULL,
		0x1F69E5E2F86C9E6CULL
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
		0x44DF56310C7F99DFULL,
		0xA8E9620EF7B1B0F8ULL,
		0x3B577751E4ED5BAEULL,
		0x2BD7A61028E89FC8ULL,
		0xAA1F5CE49A81F7C5ULL,
		0xC66F39F5511718F5ULL,
		0xFC5AD5D97DD27497ULL,
		0x15EC630101A2AAB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BEAC6218FF33BEULL,
		0x51D2C41DEF6361F0ULL,
		0x76AEEEA3C9DAB75DULL,
		0x57AF4C2051D13F90ULL,
		0x543EB9C93503EF8AULL,
		0x8CDE73EAA22E31EBULL,
		0xF8B5ABB2FBA4E92FULL,
		0x2BD8C6020345556DULL
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
		0xD36C15B3334A0ECBULL,
		0xA5B50B7D21054C4FULL,
		0xCC43C42B213DF65BULL,
		0x5E9E29AEF87097C1ULL,
		0x7B85D9317AB21A87ULL,
		0xED466333CC3E537FULL,
		0x4CA7DEFA50E9C6EDULL,
		0x100A5309772C487DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6D82B6666941D96ULL,
		0x4B6A16FA420A989FULL,
		0x98878856427BECB7ULL,
		0xBD3C535DF0E12F83ULL,
		0xF70BB262F564350EULL,
		0xDA8CC667987CA6FEULL,
		0x994FBDF4A1D38DDBULL,
		0x2014A612EE5890FAULL
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
		0x99A3AEA36F836660ULL,
		0xD6069DAD57495F16ULL,
		0x802595ABD4406F29ULL,
		0xD313B4C299E4D115ULL,
		0x54C5B8A0DFD6B082ULL,
		0xF9A2EB32FA4ED241ULL,
		0xAD4C9BFA0B4433E0ULL,
		0x05EDC3519B97C0DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33475D46DF06CCC0ULL,
		0xAC0D3B5AAE92BE2DULL,
		0x004B2B57A880DE53ULL,
		0xA627698533C9A22BULL,
		0xA98B7141BFAD6105ULL,
		0xF345D665F49DA482ULL,
		0x5A9937F4168867C1ULL,
		0x0BDB86A3372F81B5ULL
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
		0xFA872A48897ED8BDULL,
		0x4DAB4F0A21AD9614ULL,
		0x4613C191E3855A57ULL,
		0x5BFDAAA306973A8AULL,
		0xFE95CA8D518742E1ULL,
		0x1B0BA2EF797E6E81ULL,
		0x46DCF618BC66AD1CULL,
		0x380592F1FF0D3578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF50E549112FDB17AULL,
		0x9B569E14435B2C29ULL,
		0x8C278323C70AB4AEULL,
		0xB7FB55460D2E7514ULL,
		0xFD2B951AA30E85C2ULL,
		0x361745DEF2FCDD03ULL,
		0x8DB9EC3178CD5A38ULL,
		0x700B25E3FE1A6AF0ULL
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
		0x113A389517ECE013ULL,
		0x4006B27A1CB3BA30ULL,
		0x2AB18CD0B9B88165ULL,
		0x72E1B86F8A981989ULL,
		0x71AF6E1597F7D090ULL,
		0x54AF22E620850926ULL,
		0x0AEC9F1253DA8B19ULL,
		0x0F1AB0924337C4B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2274712A2FD9C026ULL,
		0x800D64F439677460ULL,
		0x556319A1737102CAULL,
		0xE5C370DF15303312ULL,
		0xE35EDC2B2FEFA120ULL,
		0xA95E45CC410A124CULL,
		0x15D93E24A7B51632ULL,
		0x1E356124866F8962ULL
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
		0xB0C7B36F5768AC0AULL,
		0xC14B274DC3755549ULL,
		0xCFC4169A13DD299BULL,
		0xB105C7513A7EF3D6ULL,
		0xAB20ADA1E192109EULL,
		0x6C6601BBC33F8E06ULL,
		0x078907D657BB7E09ULL,
		0x16DB6E724A2EDFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x618F66DEAED15814ULL,
		0x82964E9B86EAAA93ULL,
		0x9F882D3427BA5337ULL,
		0x620B8EA274FDE7ADULL,
		0x56415B43C324213DULL,
		0xD8CC0377867F1C0DULL,
		0x0F120FACAF76FC12ULL,
		0x2DB6DCE4945DBF94ULL
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
		0xE43C5A185874399CULL,
		0x7CC278D2A4528588ULL,
		0xFBCBF7A6FD91CF53ULL,
		0x62AF5B0DDE5452C9ULL,
		0x8B024ACC8B5D1008ULL,
		0x5A0252AED1E6F422ULL,
		0x9AFD7822A1EE9DEEULL,
		0x3567CDF01883E182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC878B430B0E87338ULL,
		0xF984F1A548A50B11ULL,
		0xF797EF4DFB239EA6ULL,
		0xC55EB61BBCA8A593ULL,
		0x1604959916BA2010ULL,
		0xB404A55DA3CDE845ULL,
		0x35FAF04543DD3BDCULL,
		0x6ACF9BE03107C305ULL
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
		0x032AD109D6CF2F9AULL,
		0xBC224C5D7270AD27ULL,
		0x6601A70E15DB060AULL,
		0x4600DC88BA0D3D2CULL,
		0x2C78D486C270895BULL,
		0xD85280D9DB600D4EULL,
		0x71A87D898F41A085ULL,
		0x277BD8D54B5D75C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0655A213AD9E5F34ULL,
		0x784498BAE4E15A4EULL,
		0xCC034E1C2BB60C15ULL,
		0x8C01B911741A7A58ULL,
		0x58F1A90D84E112B6ULL,
		0xB0A501B3B6C01A9CULL,
		0xE350FB131E83410BULL,
		0x4EF7B1AA96BAEB82ULL
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
		0x8B3FE49FB282AB3AULL,
		0xC66C638D9DA1F740ULL,
		0xAC06E20ADFFEFF25ULL,
		0xA8E17961C0D7FD51ULL,
		0xF1560122099EAB04ULL,
		0xD73060CBBD822F23ULL,
		0xF5AA08D728113F36ULL,
		0x1A0B088333E0EEE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x167FC93F65055674ULL,
		0x8CD8C71B3B43EE81ULL,
		0x580DC415BFFDFE4BULL,
		0x51C2F2C381AFFAA3ULL,
		0xE2AC0244133D5609ULL,
		0xAE60C1977B045E47ULL,
		0xEB5411AE50227E6DULL,
		0x3416110667C1DDCFULL
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
		0xE244C40C59C4772CULL,
		0x6CD4CE0F5F4A62C6ULL,
		0x41A67804E74FE68CULL,
		0x60DCCA6B4ECC4889ULL,
		0x9341837676A83E80ULL,
		0xAF67D28BC569792BULL,
		0x807B9EBDC4CB68F9ULL,
		0x3D8B47F297F4ACF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4898818B388EE58ULL,
		0xD9A99C1EBE94C58DULL,
		0x834CF009CE9FCD18ULL,
		0xC1B994D69D989112ULL,
		0x268306ECED507D00ULL,
		0x5ECFA5178AD2F257ULL,
		0x00F73D7B8996D1F3ULL,
		0x7B168FE52FE959E1ULL
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
		0xEBDC98618F1AAE14ULL,
		0xFB767E9FCC317CBAULL,
		0x06C1A447C9BEFF1DULL,
		0xF4D7E092A3BE7B28ULL,
		0x621F2F82413312D2ULL,
		0x31538F0884B3E48DULL,
		0xFA2C4D29D10BE8C7ULL,
		0x37867DFCBF75BC3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B930C31E355C28ULL,
		0xF6ECFD3F9862F975ULL,
		0x0D83488F937DFE3BULL,
		0xE9AFC125477CF650ULL,
		0xC43E5F04826625A5ULL,
		0x62A71E110967C91AULL,
		0xF4589A53A217D18EULL,
		0x6F0CFBF97EEB7877ULL
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
		0x1B6C8A3B4EBD8843ULL,
		0x28648CF74F805DB9ULL,
		0x45012C24B49B1453ULL,
		0x85C951C507EDDEA4ULL,
		0xA224DFE1B64B0454ULL,
		0x0B76AE354E26D5DDULL,
		0x5FF2B9BDC8C72066ULL,
		0x3CE9BA1C367AAB7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36D914769D7B1086ULL,
		0x50C919EE9F00BB72ULL,
		0x8A025849693628A6ULL,
		0x0B92A38A0FDBBD48ULL,
		0x4449BFC36C9608A9ULL,
		0x16ED5C6A9C4DABBBULL,
		0xBFE5737B918E40CCULL,
		0x79D374386CF556FAULL
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
		0xF7C9BCA571FBD659ULL,
		0x42B72DA2D4136170ULL,
		0x7E272F1DE42405E3ULL,
		0x7C6328226D0DC384ULL,
		0x415FB7F0E1126BF7ULL,
		0xE44136B70053A1A4ULL,
		0x1A06D4A9524250DFULL,
		0x0453B7AAC6447BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF93794AE3F7ACB2ULL,
		0x856E5B45A826C2E1ULL,
		0xFC4E5E3BC8480BC6ULL,
		0xF8C65044DA1B8708ULL,
		0x82BF6FE1C224D7EEULL,
		0xC8826D6E00A74348ULL,
		0x340DA952A484A1BFULL,
		0x08A76F558C88F7DEULL
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
		0xA4FC21C4AB5F87C2ULL,
		0x55E1C66F799DA84AULL,
		0x787403B25943CB3CULL,
		0xE29CF211EBF3FAE7ULL,
		0xC325F8992D1F3E37ULL,
		0xB0F194D729C995DCULL,
		0xAADF67CECD237326ULL,
		0x2DB19DA69C3B4C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F8438956BF0F84ULL,
		0xABC38CDEF33B5095ULL,
		0xF0E80764B2879678ULL,
		0xC539E423D7E7F5CEULL,
		0x864BF1325A3E7C6FULL,
		0x61E329AE53932BB9ULL,
		0x55BECF9D9A46E64DULL,
		0x5B633B4D38769911ULL
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
		0xEA9700523B1E064EULL,
		0x5ECD548EA1B2121FULL,
		0xC8389E616D9CAC20ULL,
		0x6B29766474D00A8CULL,
		0x4CC7DB135C22811EULL,
		0x65761569044CAFB3ULL,
		0xA83348D983AF3864ULL,
		0x392C79F15B8F3AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD52E00A4763C0C9CULL,
		0xBD9AA91D4364243FULL,
		0x90713CC2DB395840ULL,
		0xD652ECC8E9A01519ULL,
		0x998FB626B845023CULL,
		0xCAEC2AD208995F66ULL,
		0x506691B3075E70C8ULL,
		0x7258F3E2B71E7553ULL
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
		0x47CD7626A2324D6BULL,
		0x8BF7FF2FBB44F3E6ULL,
		0xB56DFD46DB4D5F31ULL,
		0x6B2A5FF322FDA242ULL,
		0xA1C6A4E5E87FDEC3ULL,
		0xF6BA402D3F64D9B1ULL,
		0x426FD045C42174C0ULL,
		0x00446106AA43B8C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F9AEC4D44649AD6ULL,
		0x17EFFE5F7689E7CCULL,
		0x6ADBFA8DB69ABE63ULL,
		0xD654BFE645FB4485ULL,
		0x438D49CBD0FFBD86ULL,
		0xED74805A7EC9B363ULL,
		0x84DFA08B8842E981ULL,
		0x0088C20D54877186ULL
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
		0xB4C9141DD7B7CD94ULL,
		0x8AF2AD5F76CD69B5ULL,
		0xBB180F527BCF84E8ULL,
		0xE81D79D18F686602ULL,
		0x700A4739CD97490DULL,
		0xF03BBDE2D26F6981ULL,
		0xBE42F7BEA4991E15ULL,
		0x199534C7A3D8ACA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6992283BAF6F9B28ULL,
		0x15E55ABEED9AD36BULL,
		0x76301EA4F79F09D1ULL,
		0xD03AF3A31ED0CC05ULL,
		0xE0148E739B2E921BULL,
		0xE0777BC5A4DED302ULL,
		0x7C85EF7D49323C2BULL,
		0x332A698F47B15945ULL
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
		0x6AD1BB92FA953017ULL,
		0x4B384AF3AAA83272ULL,
		0x859BE0CB05C7FEF3ULL,
		0xE78C7D5D78D53810ULL,
		0x516EF3B74BE85A2DULL,
		0x5518CEECD214F9F2ULL,
		0xBC02AE533DAA2189ULL,
		0x210E328FBE1D24A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5A37725F52A602EULL,
		0x967095E7555064E4ULL,
		0x0B37C1960B8FFDE6ULL,
		0xCF18FABAF1AA7021ULL,
		0xA2DDE76E97D0B45BULL,
		0xAA319DD9A429F3E4ULL,
		0x78055CA67B544312ULL,
		0x421C651F7C3A4951ULL
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
		0x7105867AC3ED1535ULL,
		0xEEE943A9176AD787ULL,
		0xA51894F1418DDC0DULL,
		0x15EDA44A83DC50C8ULL,
		0x816A560CB32E8A55ULL,
		0xFA54C4BEF876E31BULL,
		0xBB33E132B83919BEULL,
		0x3164C09D7CDDFEFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE20B0CF587DA2A6AULL,
		0xDDD287522ED5AF0EULL,
		0x4A3129E2831BB81BULL,
		0x2BDB489507B8A191ULL,
		0x02D4AC19665D14AAULL,
		0xF4A9897DF0EDC637ULL,
		0x7667C2657072337DULL,
		0x62C9813AF9BBFDF9ULL
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
		0xD09E1A909A676647ULL,
		0x2BA876D034441D54ULL,
		0x81B7A781EDC50338ULL,
		0x38D9992A5B1DFF04ULL,
		0xB2055FEFC22F0CA0ULL,
		0x509F05AECFE53481ULL,
		0x33A784660886E140ULL,
		0x2F4067C374F32E3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA13C352134CECC8EULL,
		0x5750EDA068883AA9ULL,
		0x036F4F03DB8A0670ULL,
		0x71B33254B63BFE09ULL,
		0x640ABFDF845E1940ULL,
		0xA13E0B5D9FCA6903ULL,
		0x674F08CC110DC280ULL,
		0x5E80CF86E9E65C7CULL
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
		0x7334E918C07D7015ULL,
		0x803A257FFD0C0F31ULL,
		0x147E0E11563E3871ULL,
		0xD1B898EFBC45F95DULL,
		0xCE032C654E6FD3D3ULL,
		0x1C8F5FB04913CDCEULL,
		0x82309877198452F9ULL,
		0x1677B06D30C2D5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE669D23180FAE02AULL,
		0x00744AFFFA181E62ULL,
		0x28FC1C22AC7C70E3ULL,
		0xA37131DF788BF2BAULL,
		0x9C0658CA9CDFA7A7ULL,
		0x391EBF6092279B9DULL,
		0x046130EE3308A5F2ULL,
		0x2CEF60DA6185ABA1ULL
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
		0x369FBCD5AAA4FA35ULL,
		0xDC2D8FA5716008F8ULL,
		0x42BD26F57724494FULL,
		0x69AEA4EA0DDDD628ULL,
		0xA4D53703A66F4D40ULL,
		0xD6492E17A57D49E6ULL,
		0xA8FF55C423ACBC3EULL,
		0x008302CE9AE1D230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D3F79AB5549F46AULL,
		0xB85B1F4AE2C011F0ULL,
		0x857A4DEAEE48929FULL,
		0xD35D49D41BBBAC50ULL,
		0x49AA6E074CDE9A80ULL,
		0xAC925C2F4AFA93CDULL,
		0x51FEAB884759787DULL,
		0x0106059D35C3A461ULL
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
		0x9B5E92C811919824ULL,
		0x38DA0DA2B20837EAULL,
		0x5EFA7D08F72B0F5AULL,
		0x48670CE3C6F45F86ULL,
		0xD2A81FB0BF20D399ULL,
		0xA8A79033B6C40D49ULL,
		0xDEC1F0E7705B30BBULL,
		0x0B7AB9845EEC3085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36BD259023233048ULL,
		0x71B41B4564106FD5ULL,
		0xBDF4FA11EE561EB4ULL,
		0x90CE19C78DE8BF0CULL,
		0xA5503F617E41A732ULL,
		0x514F20676D881A93ULL,
		0xBD83E1CEE0B66177ULL,
		0x16F57308BDD8610BULL
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
		0x1098B69EFC042398ULL,
		0x4BDF323DAB923E19ULL,
		0xEF765589A33E45FDULL,
		0x8F9FC76385310334ULL,
		0xB7E3323CB5DFE005ULL,
		0x0388B444097FFECFULL,
		0xEF0D80E86A81B715ULL,
		0x369D085662BEABCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21316D3DF8084730ULL,
		0x97BE647B57247C32ULL,
		0xDEECAB13467C8BFAULL,
		0x1F3F8EC70A620669ULL,
		0x6FC664796BBFC00BULL,
		0x0711688812FFFD9FULL,
		0xDE1B01D0D5036E2AULL,
		0x6D3A10ACC57D5799ULL
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
		0x56AE39D829C84E0AULL,
		0xCC03295C20BBCEF1ULL,
		0xC067B7C49FFB54D9ULL,
		0xD471C4CA0B26EB9EULL,
		0xFD47BB465571A946ULL,
		0xEA09EA6F3AC13F4BULL,
		0xAA0D1CBE8E16239CULL,
		0x142139E47839D174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD5C73B053909C14ULL,
		0x980652B841779DE2ULL,
		0x80CF6F893FF6A9B3ULL,
		0xA8E38994164DD73DULL,
		0xFA8F768CAAE3528DULL,
		0xD413D4DE75827E97ULL,
		0x541A397D1C2C4739ULL,
		0x284273C8F073A2E9ULL
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
		0x8C005F3FE37AB5E9ULL,
		0xB4F4FD43B0E69AE2ULL,
		0x50BE4C6D367A5139ULL,
		0xBB36357A5D045CA3ULL,
		0x212B4EC9EB41F27FULL,
		0x751A01A9AE1BC7ABULL,
		0xCDC4C0CD09CDEB6BULL,
		0x08F6C5B7CFC560EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1800BE7FC6F56BD2ULL,
		0x69E9FA8761CD35C5ULL,
		0xA17C98DA6CF4A273ULL,
		0x766C6AF4BA08B946ULL,
		0x42569D93D683E4FFULL,
		0xEA3403535C378F56ULL,
		0x9B89819A139BD6D6ULL,
		0x11ED8B6F9F8AC1D5ULL
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
		0x7A96A95D341383C5ULL,
		0x05EA07B4922E41BBULL,
		0x3975D85ADA041CDBULL,
		0x5D3C3B22D4FEB065ULL,
		0x0EB7D155EA5F6821ULL,
		0x5770EB76126EBF29ULL,
		0x7EE5C703AF9F12D4ULL,
		0x32987FD88DBD88E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF52D52BA6827078AULL,
		0x0BD40F69245C8376ULL,
		0x72EBB0B5B40839B6ULL,
		0xBA787645A9FD60CAULL,
		0x1D6FA2ABD4BED042ULL,
		0xAEE1D6EC24DD7E52ULL,
		0xFDCB8E075F3E25A8ULL,
		0x6530FFB11B7B11C2ULL
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
		0x881C9D4ED7D1FA7CULL,
		0xFD33105EA1092F48ULL,
		0x98DE263E2FDAFA58ULL,
		0x9813C7BF155D41A6ULL,
		0xE542E03E9428E0B1ULL,
		0xD1EFA7826BDDF5CCULL,
		0xB5B6FAA310109FB2ULL,
		0x253CE11A344CC2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10393A9DAFA3F4F8ULL,
		0xFA6620BD42125E91ULL,
		0x31BC4C7C5FB5F4B1ULL,
		0x30278F7E2ABA834DULL,
		0xCA85C07D2851C163ULL,
		0xA3DF4F04D7BBEB99ULL,
		0x6B6DF54620213F65ULL,
		0x4A79C23468998591ULL
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
		0x7D15D14F145DA22DULL,
		0xE485AA65DC5EC363ULL,
		0x3368D05A0487D704ULL,
		0xEDF5308C7C27950DULL,
		0xC2CB6548B295CC71ULL,
		0x6A4BC502BE0F5D9FULL,
		0xE88BD15D58FCD88BULL,
		0x33164773B13BE215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA2BA29E28BB445AULL,
		0xC90B54CBB8BD86C6ULL,
		0x66D1A0B4090FAE09ULL,
		0xDBEA6118F84F2A1AULL,
		0x8596CA91652B98E3ULL,
		0xD4978A057C1EBB3FULL,
		0xD117A2BAB1F9B116ULL,
		0x662C8EE76277C42BULL
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
		0xF41DC6390535855AULL,
		0xCD613F0AD50D1C4DULL,
		0xD024DA5DE51EEC64ULL,
		0x5F8DC94CDC288CE0ULL,
		0x058534541613C8C8ULL,
		0xA17A92F6526700BBULL,
		0x1B8510EC449F2EADULL,
		0x0F1337A278C6D0BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE83B8C720A6B0AB4ULL,
		0x9AC27E15AA1A389BULL,
		0xA049B4BBCA3DD8C9ULL,
		0xBF1B9299B85119C1ULL,
		0x0B0A68A82C279190ULL,
		0x42F525ECA4CE0176ULL,
		0x370A21D8893E5D5BULL,
		0x1E266F44F18DA17CULL
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
		0xF822770CAC9AA85AULL,
		0xC60F5D068EF3F2FDULL,
		0x1FDC5882820E2401ULL,
		0x1F855047ABE76004ULL,
		0x170749048761C1C9ULL,
		0xD9D0F0553F12D96DULL,
		0xD89B5CEE4632257DULL,
		0x303597140284F927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF044EE19593550B4ULL,
		0x8C1EBA0D1DE7E5FBULL,
		0x3FB8B105041C4803ULL,
		0x3F0AA08F57CEC008ULL,
		0x2E0E92090EC38392ULL,
		0xB3A1E0AA7E25B2DAULL,
		0xB136B9DC8C644AFBULL,
		0x606B2E280509F24FULL
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
		0x220369BAAD79066DULL,
		0x44C27C8CD66C8B25ULL,
		0x77B4DAE473492E16ULL,
		0x20B475B627CF52DAULL,
		0x8EE671C017638A72ULL,
		0x509D8DF5E205F569ULL,
		0x1BADB42B98206F20ULL,
		0x1AFCAD05341C5BE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4406D3755AF20CDAULL,
		0x8984F919ACD9164AULL,
		0xEF69B5C8E6925C2CULL,
		0x4168EB6C4F9EA5B4ULL,
		0x1DCCE3802EC714E4ULL,
		0xA13B1BEBC40BEAD3ULL,
		0x375B68573040DE40ULL,
		0x35F95A0A6838B7CAULL
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
		0x5117B35C1601CB60ULL,
		0x54BF9A70AC8CBD4FULL,
		0x3F73259805D61EF3ULL,
		0xECD6D9AD638E045FULL,
		0xAFA687CBA686C2F4ULL,
		0x3FD0F84D77D9BC1DULL,
		0xDAACEF1A0108F6D9ULL,
		0x061E067BEC3D749CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA22F66B82C0396C0ULL,
		0xA97F34E159197A9EULL,
		0x7EE64B300BAC3DE6ULL,
		0xD9ADB35AC71C08BEULL,
		0x5F4D0F974D0D85E9ULL,
		0x7FA1F09AEFB3783BULL,
		0xB559DE340211EDB2ULL,
		0x0C3C0CF7D87AE939ULL
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
		0xE1B4DCD841363F26ULL,
		0xD6BFECBE39B5BBF9ULL,
		0x5EF8419713315AE9ULL,
		0xA0D10EDCF352312DULL,
		0xA742DA8E16168A25ULL,
		0x4FCB1CFD12A820F1ULL,
		0xF9F3C8FCF2A65C79ULL,
		0x07970551B8198A41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC369B9B0826C7E4CULL,
		0xAD7FD97C736B77F3ULL,
		0xBDF0832E2662B5D3ULL,
		0x41A21DB9E6A4625AULL,
		0x4E85B51C2C2D144BULL,
		0x9F9639FA255041E3ULL,
		0xF3E791F9E54CB8F2ULL,
		0x0F2E0AA370331483ULL
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
		0xF9DA45433F485177ULL,
		0xC60997936640F9AFULL,
		0x9EDEEB269D1EDCCBULL,
		0xF6BB05BD8612D84CULL,
		0x52BDD978D92FD731ULL,
		0x4869C7AF3E499E24ULL,
		0x3E2A1E88281D690AULL,
		0x1A580E6DCB0B7995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B48A867E90A2EEULL,
		0x8C132F26CC81F35FULL,
		0x3DBDD64D3A3DB997ULL,
		0xED760B7B0C25B099ULL,
		0xA57BB2F1B25FAE63ULL,
		0x90D38F5E7C933C48ULL,
		0x7C543D10503AD214ULL,
		0x34B01CDB9616F32AULL
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
		0x16C2878B20AEE0A3ULL,
		0x4F827178EAE3D00EULL,
		0x4D22132AA439E773ULL,
		0x8F2D127A42DBD0C4ULL,
		0xBB7795E08A0ECBE8ULL,
		0x735E2D7DE6E960CEULL,
		0x197F011E57655BB2ULL,
		0x0F5B97F3FE1AC700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D850F16415DC146ULL,
		0x9F04E2F1D5C7A01CULL,
		0x9A4426554873CEE6ULL,
		0x1E5A24F485B7A188ULL,
		0x76EF2BC1141D97D1ULL,
		0xE6BC5AFBCDD2C19DULL,
		0x32FE023CAECAB764ULL,
		0x1EB72FE7FC358E00ULL
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
		0xA28681F0C4BF1856ULL,
		0xA122F6A9B204458EULL,
		0x59BA446BC0218678ULL,
		0xBA2084BAFC52D65DULL,
		0x4855AA0ABD404A51ULL,
		0x5A433399EADF151EULL,
		0x1770E07B21F6F825ULL,
		0x2FC503D84B9D39F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x450D03E1897E30ACULL,
		0x4245ED5364088B1DULL,
		0xB37488D780430CF1ULL,
		0x74410975F8A5ACBAULL,
		0x90AB54157A8094A3ULL,
		0xB4866733D5BE2A3CULL,
		0x2EE1C0F643EDF04AULL,
		0x5F8A07B0973A73F2ULL
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
		0x3EE16CECBF5472D1ULL,
		0xD6A214771DE7264EULL,
		0x3A66792512E2F79FULL,
		0x1227C8FB0EE14716ULL,
		0x63FA37F85B36626CULL,
		0x7F2201C5B99B553BULL,
		0x89A9C0377A8FAD74ULL,
		0x095ED9EF708EFC52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DC2D9D97EA8E5A2ULL,
		0xAD4428EE3BCE4C9CULL,
		0x74CCF24A25C5EF3FULL,
		0x244F91F61DC28E2CULL,
		0xC7F46FF0B66CC4D8ULL,
		0xFE44038B7336AA76ULL,
		0x1353806EF51F5AE8ULL,
		0x12BDB3DEE11DF8A5ULL
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
		0x9A20ACC1D06B9006ULL,
		0x98A30616F2686D81ULL,
		0xD07B299AF053E92EULL,
		0x97710EFF39C21C13ULL,
		0xFF899EF8867AC616ULL,
		0x645231D2B1BF6854ULL,
		0x2C89EB4D7F3F15E8ULL,
		0x2E8901AE834BDB4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34415983A0D7200CULL,
		0x31460C2DE4D0DB03ULL,
		0xA0F65335E0A7D25DULL,
		0x2EE21DFE73843827ULL,
		0xFF133DF10CF58C2DULL,
		0xC8A463A5637ED0A9ULL,
		0x5913D69AFE7E2BD0ULL,
		0x5D12035D0697B69CULL
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
		0x5E518E2DD12C353CULL,
		0xB2AEC0DF87EF7B51ULL,
		0x08C68293959751D1ULL,
		0xBD84377DE79426A9ULL,
		0x2531E8F628E604C3ULL,
		0x665ABC0801CA8672ULL,
		0xBC15A3C749D53051ULL,
		0x017D334AA2D080AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA31C5BA2586A78ULL,
		0x655D81BF0FDEF6A2ULL,
		0x118D05272B2EA3A3ULL,
		0x7B086EFBCF284D52ULL,
		0x4A63D1EC51CC0987ULL,
		0xCCB5781003950CE4ULL,
		0x782B478E93AA60A2ULL,
		0x02FA669545A1015FULL
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
		0x8B1ED25BEAE554F8ULL,
		0x8025818B3E0584A2ULL,
		0x0C196798335B2C73ULL,
		0x9A12F342A33F1145ULL,
		0x2175A13FD124A0EFULL,
		0xA6E952EEE345200DULL,
		0x720A3522F8AD8BB3ULL,
		0x1DFF3E8321277134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x163DA4B7D5CAA9F0ULL,
		0x004B03167C0B0945ULL,
		0x1832CF3066B658E7ULL,
		0x3425E685467E228AULL,
		0x42EB427FA24941DFULL,
		0x4DD2A5DDC68A401AULL,
		0xE4146A45F15B1767ULL,
		0x3BFE7D06424EE268ULL
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
		0x03ADEA4E1069DD4CULL,
		0x41680BC7945660B3ULL,
		0x7755ED208BC1FAA1ULL,
		0x7DC4D0A41053EA85ULL,
		0x022BD3DB18B294ADULL,
		0x6E96AAC6993EF9D9ULL,
		0xC46CD5B647734DEFULL,
		0x0E3E814C7709D766ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x075BD49C20D3BA98ULL,
		0x82D0178F28ACC166ULL,
		0xEEABDA411783F542ULL,
		0xFB89A14820A7D50AULL,
		0x0457A7B63165295AULL,
		0xDD2D558D327DF3B2ULL,
		0x88D9AB6C8EE69BDEULL,
		0x1C7D0298EE13AECDULL
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
		0x2DE5365D505D51EDULL,
		0xD665DB31172BC7E5ULL,
		0x76C61D92302EDA02ULL,
		0xD57BBD721E5C5FFDULL,
		0x567D9274701A7212ULL,
		0xBD17AFD31756203BULL,
		0xA87804D6A36B927EULL,
		0x09C0B36003374375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BCA6CBAA0BAA3DAULL,
		0xACCBB6622E578FCAULL,
		0xED8C3B24605DB405ULL,
		0xAAF77AE43CB8BFFAULL,
		0xACFB24E8E034E425ULL,
		0x7A2F5FA62EAC4076ULL,
		0x50F009AD46D724FDULL,
		0x138166C0066E86EBULL
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
		0xAD52ABC848672682ULL,
		0xB79B9EB4D239A2E2ULL,
		0xBE1A72DF6C603E18ULL,
		0x8E4475448CC33D80ULL,
		0x97A4AA09FC2E75E0ULL,
		0x113DDF3485733555ULL,
		0x2D49E84E27F13A5DULL,
		0x1CA8B7A06C366685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AA5579090CE4D04ULL,
		0x6F373D69A47345C5ULL,
		0x7C34E5BED8C07C31ULL,
		0x1C88EA8919867B01ULL,
		0x2F495413F85CEBC1ULL,
		0x227BBE690AE66AABULL,
		0x5A93D09C4FE274BAULL,
		0x39516F40D86CCD0AULL
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
		0xE65920D3BA01A2A2ULL,
		0x547759D7EF3C041BULL,
		0xC8F938D2AD900815ULL,
		0x223124F31E2C0FCFULL,
		0xE56569C99BEB9732ULL,
		0xB3D8F59D17DBA2C8ULL,
		0xA4AFE96296CEE76CULL,
		0x208890FE32CFAC13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCB241A774034544ULL,
		0xA8EEB3AFDE780837ULL,
		0x91F271A55B20102AULL,
		0x446249E63C581F9FULL,
		0xCACAD39337D72E64ULL,
		0x67B1EB3A2FB74591ULL,
		0x495FD2C52D9DCED9ULL,
		0x411121FC659F5827ULL
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
		0x24A556A8ED5FD09DULL,
		0xB34B01738C570400ULL,
		0xE1C43428F259EC06ULL,
		0xCE1558A76EE36B1EULL,
		0x81D02FB05031334AULL,
		0x528E51CA5E6C4197ULL,
		0x7A139D7450AFEC5CULL,
		0x06908FE96BFB0B3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x494AAD51DABFA13AULL,
		0x669602E718AE0800ULL,
		0xC3886851E4B3D80DULL,
		0x9C2AB14EDDC6D63DULL,
		0x03A05F60A0626695ULL,
		0xA51CA394BCD8832FULL,
		0xF4273AE8A15FD8B8ULL,
		0x0D211FD2D7F6167CULL
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
		0x5CFF808932E8865BULL,
		0x99F6E16AB9F91135ULL,
		0x83E37683F84C67CDULL,
		0x07A5134CB91A52D4ULL,
		0xDDDE86C961D6ECB4ULL,
		0xDF1B6879BDE1528FULL,
		0x01B582C4F30AF8D1ULL,
		0x054280770F298A2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9FF011265D10CB6ULL,
		0x33EDC2D573F2226AULL,
		0x07C6ED07F098CF9BULL,
		0x0F4A26997234A5A9ULL,
		0xBBBD0D92C3ADD968ULL,
		0xBE36D0F37BC2A51FULL,
		0x036B0589E615F1A3ULL,
		0x0A8500EE1E531458ULL
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
		0xF7DD927046873F38ULL,
		0xC99898A9868CC793ULL,
		0xF76D37FD025DE067ULL,
		0xF70C4F97AFC32F0DULL,
		0x9FDCCFA62E1BEB9DULL,
		0xAC5272AD879F9905ULL,
		0x043D719B6432BDCCULL,
		0x0E104ACBB3861E2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFBB24E08D0E7E70ULL,
		0x933131530D198F27ULL,
		0xEEDA6FFA04BBC0CFULL,
		0xEE189F2F5F865E1BULL,
		0x3FB99F4C5C37D73BULL,
		0x58A4E55B0F3F320BULL,
		0x087AE336C8657B99ULL,
		0x1C209597670C3C5AULL
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
		0x47BE1F6B51CE99FDULL,
		0x999F37E434DDECB2ULL,
		0xA470A83ECA8A44E1ULL,
		0x0F0AA15BC6CD3EC5ULL,
		0x5537A1B43927788BULL,
		0x07B01CB3C5FEA145ULL,
		0xFE1F5EBE59420C16ULL,
		0x3591993DF0776888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F7C3ED6A39D33FAULL,
		0x333E6FC869BBD964ULL,
		0x48E1507D951489C3ULL,
		0x1E1542B78D9A7D8BULL,
		0xAA6F4368724EF116ULL,
		0x0F6039678BFD428AULL,
		0xFC3EBD7CB284182CULL,
		0x6B23327BE0EED111ULL
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
		0x8874A3114691746DULL,
		0x841026FCA794EFE3ULL,
		0x56C587244B70CA95ULL,
		0x2DCAB489C532F4C7ULL,
		0x221A6264AF2B0423ULL,
		0xDD8FE44352B664FBULL,
		0x900ACD0593961BC0ULL,
		0x13CA3A554267DC09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E946228D22E8DAULL,
		0x08204DF94F29DFC7ULL,
		0xAD8B0E4896E1952BULL,
		0x5B9569138A65E98EULL,
		0x4434C4C95E560846ULL,
		0xBB1FC886A56CC9F6ULL,
		0x20159A0B272C3781ULL,
		0x279474AA84CFB813ULL
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
		0x87D4CA1FA64C85EBULL,
		0xBB6DE658270D23A0ULL,
		0xE00A1E2B1F92BC4EULL,
		0xC668B7C0812C9E78ULL,
		0xC4FCAE5C7C906E95ULL,
		0xC4FEE8D5829E31A8ULL,
		0xCFB582BC48811816ULL,
		0x389FF457E70C72C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA9943F4C990BD6ULL,
		0x76DBCCB04E1A4741ULL,
		0xC0143C563F25789DULL,
		0x8CD16F8102593CF1ULL,
		0x89F95CB8F920DD2BULL,
		0x89FDD1AB053C6351ULL,
		0x9F6B05789102302DULL,
		0x713FE8AFCE18E58DULL
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
		0xBF01B3E410E954F6ULL,
		0x583C6DFEF19CE386ULL,
		0x5DA51EB466D812E1ULL,
		0xC097A61B29C829F9ULL,
		0xA65CD1E10D9F3B81ULL,
		0x7BD679B3476413B8ULL,
		0x93E6671B7A495080ULL,
		0x2A423FC554948F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E0367C821D2A9ECULL,
		0xB078DBFDE339C70DULL,
		0xBB4A3D68CDB025C2ULL,
		0x812F4C36539053F2ULL,
		0x4CB9A3C21B3E7703ULL,
		0xF7ACF3668EC82771ULL,
		0x27CCCE36F492A100ULL,
		0x54847F8AA9291E3BULL
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
		0xB8E6E957D4B1CFCCULL,
		0x107917B4EFEED951ULL,
		0xC07DA5C98771EC82ULL,
		0xC3502356ABA2420DULL,
		0xF1EA5D0795481DB7ULL,
		0xFB3260F3CB43DD46ULL,
		0x9449B56ABBF78052ULL,
		0x32E37A62E46481C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71CDD2AFA9639F98ULL,
		0x20F22F69DFDDB2A3ULL,
		0x80FB4B930EE3D904ULL,
		0x86A046AD5744841BULL,
		0xE3D4BA0F2A903B6FULL,
		0xF664C1E79687BA8DULL,
		0x28936AD577EF00A5ULL,
		0x65C6F4C5C8C90387ULL
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
		0x5044CE7435B2B8F1ULL,
		0x780CE05EF74FD93DULL,
		0x1EBB3AD83A3EF8C1ULL,
		0x7B6324E70B517177ULL,
		0x93379198AC5F4724ULL,
		0x464547A55BB805E8ULL,
		0x5150C1B833954975ULL,
		0x0F8D51A6D840447BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0899CE86B6571E2ULL,
		0xF019C0BDEE9FB27AULL,
		0x3D7675B0747DF182ULL,
		0xF6C649CE16A2E2EEULL,
		0x266F233158BE8E48ULL,
		0x8C8A8F4AB7700BD1ULL,
		0xA2A18370672A92EAULL,
		0x1F1AA34DB08088F6ULL
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
		0xE38A46EBD4518A35ULL,
		0xC9B64514425693E1ULL,
		0x6C7C580217853833ULL,
		0xD7E9D231B8AB143DULL,
		0x4E2A8C7D60FACAA3ULL,
		0xE483AA2BF6224306ULL,
		0xEA98DF93DC8F4BAEULL,
		0x30341174178B5C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7148DD7A8A3146AULL,
		0x936C8A2884AD27C3ULL,
		0xD8F8B0042F0A7067ULL,
		0xAFD3A4637156287AULL,
		0x9C5518FAC1F59547ULL,
		0xC9075457EC44860CULL,
		0xD531BF27B91E975DULL,
		0x606822E82F16B821ULL
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
		0x69870DD66CAA1294ULL,
		0xC4E7D4EBD94FCE91ULL,
		0xEECE28F9DC837D06ULL,
		0x820F88AF6294021AULL,
		0xDEBA3332BF9E9E4FULL,
		0x1C3DB79E82D783DFULL,
		0xAE60766DD9F980B8ULL,
		0x1B93FB1E72693D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD30E1BACD9542528ULL,
		0x89CFA9D7B29F9D22ULL,
		0xDD9C51F3B906FA0DULL,
		0x041F115EC5280435ULL,
		0xBD7466657F3D3C9FULL,
		0x387B6F3D05AF07BFULL,
		0x5CC0ECDBB3F30170ULL,
		0x3727F63CE4D27AEBULL
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
		0xFC63CDD035F2A58BULL,
		0xD6E33A4A4D69190AULL,
		0x3458756B4EB1871EULL,
		0x48A5F58BDD51036AULL,
		0x8B3161DDEAF8306BULL,
		0x81BA9482D9B5BB14ULL,
		0x6D0BD2FB581770CEULL,
		0x1839107E8065B9D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8C79BA06BE54B16ULL,
		0xADC674949AD23215ULL,
		0x68B0EAD69D630E3DULL,
		0x914BEB17BAA206D4ULL,
		0x1662C3BBD5F060D6ULL,
		0x03752905B36B7629ULL,
		0xDA17A5F6B02EE19DULL,
		0x307220FD00CB73ACULL
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
		0xC72F2E1DD384FBF4ULL,
		0xCF4D2DB625AF80ABULL,
		0x9F9AA4553C0649CFULL,
		0x97B5A36B86592E1CULL,
		0x520B253182E58602ULL,
		0xE69151DE849BF76FULL,
		0x33DA6D93A2F23D23ULL,
		0x2D0BE2D165FFEA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5E5C3BA709F7E8ULL,
		0x9E9A5B6C4B5F0157ULL,
		0x3F3548AA780C939FULL,
		0x2F6B46D70CB25C39ULL,
		0xA4164A6305CB0C05ULL,
		0xCD22A3BD0937EEDEULL,
		0x67B4DB2745E47A47ULL,
		0x5A17C5A2CBFFD50AULL
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
		0xE90D7EA9657E3591ULL,
		0x616EED54C5BF1490ULL,
		0xDE7F7923A28C5E59ULL,
		0x035D9573C1A12765ULL,
		0xBB4D2C62E1AAD2B1ULL,
		0xD69758D4FADEDA4CULL,
		0x2DF5A00BD3E274A6ULL,
		0x028DED67D4BED0EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD21AFD52CAFC6B22ULL,
		0xC2DDDAA98B7E2921ULL,
		0xBCFEF2474518BCB2ULL,
		0x06BB2AE783424ECBULL,
		0x769A58C5C355A562ULL,
		0xAD2EB1A9F5BDB499ULL,
		0x5BEB4017A7C4E94DULL,
		0x051BDACFA97DA1D4ULL
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
		0x0905A6583C28E0E9ULL,
		0xF1BFBCDA523CDC4FULL,
		0x62DB10CC19511DD2ULL,
		0x6149EDAFFE0A916AULL,
		0x6CA0E4CB41F91FDCULL,
		0x2648F5D1FC3329EEULL,
		0x451886F3A811B034ULL,
		0x3FD9D7EAF9269548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120B4CB07851C1D2ULL,
		0xE37F79B4A479B89EULL,
		0xC5B6219832A23BA5ULL,
		0xC293DB5FFC1522D4ULL,
		0xD941C99683F23FB8ULL,
		0x4C91EBA3F86653DCULL,
		0x8A310DE750236068ULL,
		0x7FB3AFD5F24D2A90ULL
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
		0xD373074C04B006E5ULL,
		0x3084584AAB0FE621ULL,
		0xD17A947A3FED17E0ULL,
		0x85100B7E0B3C4F91ULL,
		0x0F07160683C6F411ULL,
		0xE30D832809AADC4DULL,
		0xEB999D55BC5F7D94ULL,
		0x229FFB7993A4E783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E60E9809600DCAULL,
		0x6108B095561FCC43ULL,
		0xA2F528F47FDA2FC0ULL,
		0x0A2016FC16789F23ULL,
		0x1E0E2C0D078DE823ULL,
		0xC61B06501355B89AULL,
		0xD7333AAB78BEFB29ULL,
		0x453FF6F32749CF07ULL
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
		0x46B818B516E7F8DFULL,
		0x993960D62DDA6B23ULL,
		0x12272C2DF9D85C63ULL,
		0x48EBB8A258C2DA4BULL,
		0x349525A488E0AC5AULL,
		0xDE9548A8902E5A9BULL,
		0xE83309B81ED1798EULL,
		0x0C625DF9609A9A22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D70316A2DCFF1BEULL,
		0x3272C1AC5BB4D646ULL,
		0x244E585BF3B0B8C7ULL,
		0x91D77144B185B496ULL,
		0x692A4B4911C158B4ULL,
		0xBD2A9151205CB536ULL,
		0xD06613703DA2F31DULL,
		0x18C4BBF2C1353445ULL
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
		0xFDE21A8AAFFAFB7FULL,
		0x401832D85B5E930CULL,
		0x37416169329A2008ULL,
		0xFA9BF2DC2F461C59ULL,
		0x626318EF2AA5A020ULL,
		0x0FFF3BEE2A080E81ULL,
		0x2DCE6F718DCB22DEULL,
		0x1F097B8E85B346D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC435155FF5F6FEULL,
		0x803065B0B6BD2619ULL,
		0x6E82C2D265344010ULL,
		0xF537E5B85E8C38B2ULL,
		0xC4C631DE554B4041ULL,
		0x1FFE77DC54101D02ULL,
		0x5B9CDEE31B9645BCULL,
		0x3E12F71D0B668DA2ULL
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
		0x6DF7B94713964F25ULL,
		0xE3AD8D71425F0C94ULL,
		0x50E8D357B85DECFCULL,
		0xFDAE3DAF1E658D0AULL,
		0x81A9F495BF9B5AB8ULL,
		0x102BDAE617DF4B3AULL,
		0x6E4B05B005960890ULL,
		0x0BD0F2B9205E1BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBEF728E272C9E4AULL,
		0xC75B1AE284BE1928ULL,
		0xA1D1A6AF70BBD9F9ULL,
		0xFB5C7B5E3CCB1A14ULL,
		0x0353E92B7F36B571ULL,
		0x2057B5CC2FBE9675ULL,
		0xDC960B600B2C1120ULL,
		0x17A1E57240BC374CULL
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
		0xA0477E658845D8C9ULL,
		0xAA82A14B61B84205ULL,
		0x63E56FEBCDC63173ULL,
		0x38695827EA8E6772ULL,
		0xCA8A53C7B26FA933ULL,
		0x5540D46D98996282ULL,
		0x4538CD0C5C139CB9ULL,
		0x3C654D0EFD569423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x408EFCCB108BB192ULL,
		0x55054296C370840BULL,
		0xC7CADFD79B8C62E7ULL,
		0x70D2B04FD51CCEE4ULL,
		0x9514A78F64DF5266ULL,
		0xAA81A8DB3132C505ULL,
		0x8A719A18B8273972ULL,
		0x78CA9A1DFAAD2846ULL
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
		0x518721FCFEFD7C5BULL,
		0x403294246B7BC1FBULL,
		0x1D901BE1E0DA6ED1ULL,
		0x821AAF0A73B94869ULL,
		0xB6BEEA34AAED2353ULL,
		0x768ED51C09F216DEULL,
		0xFAE1889EB4F7C0DFULL,
		0x37CD0AD466F8C444ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA30E43F9FDFAF8B6ULL,
		0x80652848D6F783F6ULL,
		0x3B2037C3C1B4DDA2ULL,
		0x04355E14E77290D2ULL,
		0x6D7DD46955DA46A7ULL,
		0xED1DAA3813E42DBDULL,
		0xF5C3113D69EF81BEULL,
		0x6F9A15A8CDF18889ULL
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
		0xA75070E936D261B2ULL,
		0x3C95E49206C0D2A4ULL,
		0xC4E3B8E36211FFAEULL,
		0x6A31F9CFF5A492DEULL,
		0x0BBD241E9A278668ULL,
		0x6E1F0339B9B47D1AULL,
		0x2833D6B7BB6F8088ULL,
		0x2C48B22C39390013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA0E1D26DA4C364ULL,
		0x792BC9240D81A549ULL,
		0x89C771C6C423FF5CULL,
		0xD463F39FEB4925BDULL,
		0x177A483D344F0CD0ULL,
		0xDC3E06737368FA34ULL,
		0x5067AD6F76DF0110ULL,
		0x5891645872720026ULL
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
		0xF16136F1812E82FFULL,
		0x1CC7A5B756E65671ULL,
		0x3360F97DA26D69F7ULL,
		0x9AE6C0D422D02F51ULL,
		0x8ECBEC1F823ACB85ULL,
		0x2CB9F80E0357646BULL,
		0x5BC3D61BD595084FULL,
		0x333B510A1EC027A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C26DE3025D05FEULL,
		0x398F4B6EADCCACE3ULL,
		0x66C1F2FB44DAD3EEULL,
		0x35CD81A845A05EA2ULL,
		0x1D97D83F0475970BULL,
		0x5973F01C06AEC8D7ULL,
		0xB787AC37AB2A109EULL,
		0x6676A2143D804F42ULL
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
		0xE71A4BE32CBEBB95ULL,
		0x6FA973D3C7CBEA4CULL,
		0x1E10A1856730D0A6ULL,
		0x9EA07895DFB4734AULL,
		0xFEC7527EBF344E43ULL,
		0x3F472209B7596A00ULL,
		0x5F9A0FEF3B66EE21ULL,
		0x3959D65A726E76D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE3497C6597D772AULL,
		0xDF52E7A78F97D499ULL,
		0x3C21430ACE61A14CULL,
		0x3D40F12BBF68E694ULL,
		0xFD8EA4FD7E689C87ULL,
		0x7E8E44136EB2D401ULL,
		0xBF341FDE76CDDC42ULL,
		0x72B3ACB4E4DCEDA8ULL
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
		0x3A52CF861D85529FULL,
		0x00CAFE0413F31353ULL,
		0x550355BC30F19C38ULL,
		0x11179A2BD0D3C6FCULL,
		0xFC85468A176174F9ULL,
		0x4A2BA51A68C7F94DULL,
		0xADD6955C74559CEDULL,
		0x23A32E9DFACDA110ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74A59F0C3B0AA53EULL,
		0x0195FC0827E626A6ULL,
		0xAA06AB7861E33870ULL,
		0x222F3457A1A78DF8ULL,
		0xF90A8D142EC2E9F2ULL,
		0x94574A34D18FF29BULL,
		0x5BAD2AB8E8AB39DAULL,
		0x47465D3BF59B4221ULL
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
		0x2E9F8DDE86B58045ULL,
		0x4C6F138E4A1E6BFAULL,
		0xC79B2B2B090E2606ULL,
		0x5D45F9FF915084E2ULL,
		0xC7599B1C39A76368ULL,
		0x6E6DA8931EB55866ULL,
		0xF24C7752E9684562ULL,
		0x16076BEF8C4E2DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3F1BBD0D6B008AULL,
		0x98DE271C943CD7F4ULL,
		0x8F365656121C4C0CULL,
		0xBA8BF3FF22A109C5ULL,
		0x8EB33638734EC6D0ULL,
		0xDCDB51263D6AB0CDULL,
		0xE498EEA5D2D08AC4ULL,
		0x2C0ED7DF189C5B85ULL
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
		0x9C0AECFBD1AB9F56ULL,
		0x8D0B575DE744D27DULL,
		0x41DFBAE90D1598B1ULL,
		0xD9E2705C23AA43C3ULL,
		0xE2626A6EFC3C3764ULL,
		0x093DDB7949D67626ULL,
		0xEC64DB1021D4CC17ULL,
		0x396CD0E1F94CF019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3815D9F7A3573EACULL,
		0x1A16AEBBCE89A4FBULL,
		0x83BF75D21A2B3163ULL,
		0xB3C4E0B847548786ULL,
		0xC4C4D4DDF8786EC9ULL,
		0x127BB6F293ACEC4DULL,
		0xD8C9B62043A9982EULL,
		0x72D9A1C3F299E033ULL
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
		0xBEAFB6D24E1D0DF8ULL,
		0xFDED95E7ADD605F3ULL,
		0x10B07B6FC57976E0ULL,
		0x5B1D4FEDF63E63F4ULL,
		0x7336F86496BC9275ULL,
		0x61CA2388ACF48D97ULL,
		0x1A3CD4DED934EFBCULL,
		0x06DD5824EC0A9E12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D5F6DA49C3A1BF0ULL,
		0xFBDB2BCF5BAC0BE7ULL,
		0x2160F6DF8AF2EDC1ULL,
		0xB63A9FDBEC7CC7E8ULL,
		0xE66DF0C92D7924EAULL,
		0xC394471159E91B2EULL,
		0x3479A9BDB269DF78ULL,
		0x0DBAB049D8153C24ULL
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
		0xAAF392A682000E65ULL,
		0x5B2CE5EEDF98A2F4ULL,
		0x73BFD8CBD2F4F2ACULL,
		0x8732967785341931ULL,
		0x857B2AED5D457949ULL,
		0x55611F75CFFFB4D1ULL,
		0x6479DF971375B33FULL,
		0x1CF334A1B189B856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55E7254D04001CCAULL,
		0xB659CBDDBF3145E9ULL,
		0xE77FB197A5E9E558ULL,
		0x0E652CEF0A683262ULL,
		0x0AF655DABA8AF293ULL,
		0xAAC23EEB9FFF69A3ULL,
		0xC8F3BF2E26EB667EULL,
		0x39E66943631370ACULL
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
		0xEB079C521F85FD89ULL,
		0x0C83DE976D9DBB12ULL,
		0x3A01EB927B2235E9ULL,
		0x4B0806ACCE36B37EULL,
		0x5157A8B1CDE9F6C9ULL,
		0x1DA99936D64F6FFCULL,
		0xBB64AD3D3C20E92FULL,
		0x0E67AD06AE1F9D26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD60F38A43F0BFB12ULL,
		0x1907BD2EDB3B7625ULL,
		0x7403D724F6446BD2ULL,
		0x96100D599C6D66FCULL,
		0xA2AF51639BD3ED92ULL,
		0x3B53326DAC9EDFF8ULL,
		0x76C95A7A7841D25EULL,
		0x1CCF5A0D5C3F3A4DULL
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
		0xB3EDBAD69C6CA040ULL,
		0xF4D3076A69EB7779ULL,
		0x4DCEA28BC07BE40EULL,
		0x4F702309F7D0F7BCULL,
		0x800733EE11E5005BULL,
		0xE6300E8B9C527F48ULL,
		0x223873587FE3D923ULL,
		0x38DA0A5824F99AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67DB75AD38D94080ULL,
		0xE9A60ED4D3D6EEF3ULL,
		0x9B9D451780F7C81DULL,
		0x9EE04613EFA1EF78ULL,
		0x000E67DC23CA00B6ULL,
		0xCC601D1738A4FE91ULL,
		0x4470E6B0FFC7B247ULL,
		0x71B414B049F33552ULL
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
		0x57BC6AB02BC908A5ULL,
		0x4A62D24AAD3D15E5ULL,
		0xCF473DDD9E7C54B3ULL,
		0x92B93A106B6A17F4ULL,
		0x4104CF273D7735E7ULL,
		0xE42F1FA9C799D3DAULL,
		0x3B7493EF4D050211ULL,
		0x20B108D60CF0941DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF78D5605792114AULL,
		0x94C5A4955A7A2BCAULL,
		0x9E8E7BBB3CF8A966ULL,
		0x25727420D6D42FE9ULL,
		0x82099E4E7AEE6BCFULL,
		0xC85E3F538F33A7B4ULL,
		0x76E927DE9A0A0423ULL,
		0x416211AC19E1283AULL
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
		0x1BCB2D02A8EC3B5DULL,
		0xB6D4152179B172C0ULL,
		0xC6661C6B1EE69F08ULL,
		0x04E0D017ADD0B6F6ULL,
		0xEAE1EBBFC64062F0ULL,
		0x40DFC9BA30EBFE54ULL,
		0x126207D2F81BF647ULL,
		0x0F30ABBD7BA80D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37965A0551D876BAULL,
		0x6DA82A42F362E580ULL,
		0x8CCC38D63DCD3E11ULL,
		0x09C1A02F5BA16DEDULL,
		0xD5C3D77F8C80C5E0ULL,
		0x81BF937461D7FCA9ULL,
		0x24C40FA5F037EC8EULL,
		0x1E61577AF7501AAEULL
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
		0xCADC719AE765A767ULL,
		0xF3B484269E3C58CBULL,
		0x43EEC17F63F42658ULL,
		0x6EDCF701CFD8645AULL,
		0x0254CB0DE2A606AFULL,
		0xB71BE535669178D6ULL,
		0xE910DB640CD294B0ULL,
		0x34FD3B5A1985B476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95B8E335CECB4ECEULL,
		0xE769084D3C78B197ULL,
		0x87DD82FEC7E84CB1ULL,
		0xDDB9EE039FB0C8B4ULL,
		0x04A9961BC54C0D5EULL,
		0x6E37CA6ACD22F1ACULL,
		0xD221B6C819A52961ULL,
		0x69FA76B4330B68EDULL
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
		0x0426072E70A5486CULL,
		0xD56E3AE4764870C5ULL,
		0x031E27A7E0714F07ULL,
		0x638EF89E9D656D5BULL,
		0xF5BB05CE3F489F66ULL,
		0x923046E1F2715BBAULL,
		0x2AE6DFE5B60996C9ULL,
		0x15ED104984BB13E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x084C0E5CE14A90D8ULL,
		0xAADC75C8EC90E18AULL,
		0x063C4F4FC0E29E0FULL,
		0xC71DF13D3ACADAB6ULL,
		0xEB760B9C7E913ECCULL,
		0x24608DC3E4E2B775ULL,
		0x55CDBFCB6C132D93ULL,
		0x2BDA2093097627C2ULL
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
		0xDF3AA16749BB8D13ULL,
		0x448370071DA75378ULL,
		0x1577254175707412ULL,
		0xB8C0801A7860C705ULL,
		0x1BFCA30345CDD009ULL,
		0xC0CFC742C61527FEULL,
		0xC733AEE98F0DAB6DULL,
		0x0B495ED944A94D93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE7542CE93771A26ULL,
		0x8906E00E3B4EA6F1ULL,
		0x2AEE4A82EAE0E824ULL,
		0x71810034F0C18E0AULL,
		0x37F946068B9BA013ULL,
		0x819F8E858C2A4FFCULL,
		0x8E675DD31E1B56DBULL,
		0x1692BDB289529B27ULL
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
		0x59DA05B502CA0B9BULL,
		0x330630787B8DF005ULL,
		0x929253D9D9DA140EULL,
		0xBD68897566D17624ULL,
		0x0B8A4E70CE818879ULL,
		0xE68BF3B2692FCCA4ULL,
		0x98FF5A14E65A0416ULL,
		0x11F759C6A788A8E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B40B6A05941736ULL,
		0x660C60F0F71BE00AULL,
		0x2524A7B3B3B4281CULL,
		0x7AD112EACDA2EC49ULL,
		0x17149CE19D0310F3ULL,
		0xCD17E764D25F9948ULL,
		0x31FEB429CCB4082DULL,
		0x23EEB38D4F1151C5ULL
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
		0xF8FDCC184EFFB61AULL,
		0x18193175B1C4D64AULL,
		0x788BB38D4291386DULL,
		0x6A423B060B218192ULL,
		0xCA95DC466BD08305ULL,
		0xFE735ACBEF50F594ULL,
		0xAEE032AABBC122F8ULL,
		0x27E4F731AB699B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FB98309DFF6C34ULL,
		0x303262EB6389AC95ULL,
		0xF117671A852270DAULL,
		0xD484760C16430324ULL,
		0x952BB88CD7A1060AULL,
		0xFCE6B597DEA1EB29ULL,
		0x5DC06555778245F1ULL,
		0x4FC9EE6356D3373DULL
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
		0xB3C72C54EF3A0B6CULL,
		0xD5CED83C68293995ULL,
		0xEC79ECDA6882B20DULL,
		0x5C9C2FC7918571A8ULL,
		0x1A44BF0F329DC013ULL,
		0x7A44CE561C065853ULL,
		0x78300520CEED4F3DULL,
		0x03E9F48F85290E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678E58A9DE7416D8ULL,
		0xAB9DB078D052732BULL,
		0xD8F3D9B4D105641BULL,
		0xB9385F8F230AE351ULL,
		0x34897E1E653B8026ULL,
		0xF4899CAC380CB0A6ULL,
		0xF0600A419DDA9E7AULL,
		0x07D3E91F0A521CD6ULL
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
		0x037369B5E729BD2AULL,
		0x6D9D76C73E8B48E4ULL,
		0xA58EC1CD7BFC7FA3ULL,
		0x015FE6312BA82227ULL,
		0xC0E06FC154DFAC51ULL,
		0x051FADBD321D6D94ULL,
		0x03F8A7D53853CC6FULL,
		0x1E458F13664C0E08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E6D36BCE537A54ULL,
		0xDB3AED8E7D1691C8ULL,
		0x4B1D839AF7F8FF46ULL,
		0x02BFCC625750444FULL,
		0x81C0DF82A9BF58A2ULL,
		0x0A3F5B7A643ADB29ULL,
		0x07F14FAA70A798DEULL,
		0x3C8B1E26CC981C10ULL
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
		0x9E7F13627DEEF2E1ULL,
		0xEC751C07F30B8332ULL,
		0xB027DD6C56374989ULL,
		0xD0F110A19FF0D3F1ULL,
		0x4A25BA9B43ED8F3AULL,
		0xAFC2B01B6C0F6A71ULL,
		0x7311C5E4F4B8A6CCULL,
		0x19EBA6F3D25DEA2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CFE26C4FBDDE5C2ULL,
		0xD8EA380FE6170665ULL,
		0x604FBAD8AC6E9313ULL,
		0xA1E221433FE1A7E3ULL,
		0x944B753687DB1E75ULL,
		0x5F856036D81ED4E2ULL,
		0xE6238BC9E9714D99ULL,
		0x33D74DE7A4BBD45CULL
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
		0xA13E991D7DC1697AULL,
		0x9C37F50AADA3C06CULL,
		0x490576B0915A31BCULL,
		0x750F5B79917EA2E9ULL,
		0xA32B924061E7F21BULL,
		0x4EA2135BFB820756ULL,
		0xDD116CC1009AAC8CULL,
		0x2A27C076BA381F22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x427D323AFB82D2F4ULL,
		0x386FEA155B4780D9ULL,
		0x920AED6122B46379ULL,
		0xEA1EB6F322FD45D2ULL,
		0x46572480C3CFE436ULL,
		0x9D4426B7F7040EADULL,
		0xBA22D98201355918ULL,
		0x544F80ED74703E45ULL
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
		0xF3EAFD216F58EFC5ULL,
		0xCD12C309E65A97DBULL,
		0x46B15E85303C694DULL,
		0x3710957D412DB662ULL,
		0x8DB88AC60BA000F0ULL,
		0x6A27683268B5D6F9ULL,
		0x9CEEDA563E670DBFULL,
		0x04415441294CA485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7D5FA42DEB1DF8AULL,
		0x9A258613CCB52FB7ULL,
		0x8D62BD0A6078D29BULL,
		0x6E212AFA825B6CC4ULL,
		0x1B71158C174001E0ULL,
		0xD44ED064D16BADF3ULL,
		0x39DDB4AC7CCE1B7EULL,
		0x0882A8825299490BULL
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
		0x3332FA7B6AFD08F9ULL,
		0x4A8061E532676858ULL,
		0x2ED489C53FF7B02DULL,
		0x268A387E7EA8C120ULL,
		0x76B0B0F46AEEF258ULL,
		0xA8B9994F96779063ULL,
		0x9F656AB722B9A109ULL,
		0x1E0A2C84CABD01B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6665F4F6D5FA11F2ULL,
		0x9500C3CA64CED0B0ULL,
		0x5DA9138A7FEF605AULL,
		0x4D1470FCFD518240ULL,
		0xED6161E8D5DDE4B0ULL,
		0x5173329F2CEF20C6ULL,
		0x3ECAD56E45734213ULL,
		0x3C145909957A0369ULL
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
		0x39C31520B153778CULL,
		0xEF7F89D1B67A7360ULL,
		0xA503379A30E77409ULL,
		0xD00F948B741CA5BDULL,
		0xACD15D722F555815ULL,
		0x0A7D5B6F6852EBFDULL,
		0xD9DF2AE9F8765453ULL,
		0x3AAF99445F5A71F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73862A4162A6EF18ULL,
		0xDEFF13A36CF4E6C0ULL,
		0x4A066F3461CEE813ULL,
		0xA01F2916E8394B7BULL,
		0x59A2BAE45EAAB02BULL,
		0x14FAB6DED0A5D7FBULL,
		0xB3BE55D3F0ECA8A6ULL,
		0x755F3288BEB4E3F3ULL
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
		0x48BA6340060C680EULL,
		0x9B6D81AE55DFB03EULL,
		0x282EB0ED78D6658DULL,
		0x8A40F44FA8C42C7CULL,
		0xD7C801ACD81659B2ULL,
		0x41058972701CB5D3ULL,
		0x106A727377179BD2ULL,
		0x1895F32D8A9E3BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9174C6800C18D01CULL,
		0x36DB035CABBF607CULL,
		0x505D61DAF1ACCB1BULL,
		0x1481E89F518858F8ULL,
		0xAF900359B02CB365ULL,
		0x820B12E4E0396BA7ULL,
		0x20D4E4E6EE2F37A4ULL,
		0x312BE65B153C775EULL
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
		0x27CFC70733697E96ULL,
		0x4123B201ED88D9DCULL,
		0x5144808654A881B1ULL,
		0xD369A95931045D94ULL,
		0x0D29D9CA9D164749ULL,
		0xD078B9E92BB6D91DULL,
		0xF918718C4376C0AFULL,
		0x17D1F00720F4B1CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F9F8E0E66D2FD2CULL,
		0x82476403DB11B3B8ULL,
		0xA289010CA9510362ULL,
		0xA6D352B26208BB28ULL,
		0x1A53B3953A2C8E93ULL,
		0xA0F173D2576DB23AULL,
		0xF230E31886ED815FULL,
		0x2FA3E00E41E96399ULL
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
		0x10CEDC790CFC814EULL,
		0xEE8BCFBB57E3FE51ULL,
		0xD97B6D421ED952E9ULL,
		0x85825055AE4DF6CEULL,
		0x82453F3E955F8E70ULL,
		0x22D72532347C92FAULL,
		0x4FF9737917FDDD91ULL,
		0x0857FF52DA463F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x219DB8F219F9029CULL,
		0xDD179F76AFC7FCA2ULL,
		0xB2F6DA843DB2A5D3ULL,
		0x0B04A0AB5C9BED9DULL,
		0x048A7E7D2ABF1CE1ULL,
		0x45AE4A6468F925F5ULL,
		0x9FF2E6F22FFBBB22ULL,
		0x10AFFEA5B48C7E52ULL
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
		0x7F9464010457FF71ULL,
		0x0B19BCEA7B3C55EEULL,
		0x25CADCEE921D666EULL,
		0x3906C01D375D7404ULL,
		0xE8976EE0A75BC9C4ULL,
		0x2623F3734CA88F5BULL,
		0x905A9349804DD220ULL,
		0x2DAAFFEFC2791101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF28C80208AFFEE2ULL,
		0x163379D4F678ABDCULL,
		0x4B95B9DD243ACCDCULL,
		0x720D803A6EBAE808ULL,
		0xD12EDDC14EB79388ULL,
		0x4C47E6E699511EB7ULL,
		0x20B52693009BA440ULL,
		0x5B55FFDF84F22203ULL
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
		0xC2491BF5EDC82835ULL,
		0x8EBEC5080203D220ULL,
		0x8115A1826E0A0147ULL,
		0xAEB8A77D76B874D6ULL,
		0xB57CA83E9508F759ULL,
		0x696831C3E9DA4854ULL,
		0x64DF1332F7F3EBBAULL,
		0x340EFD460528754EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849237EBDB90506AULL,
		0x1D7D8A100407A441ULL,
		0x022B4304DC14028FULL,
		0x5D714EFAED70E9ADULL,
		0x6AF9507D2A11EEB3ULL,
		0xD2D06387D3B490A9ULL,
		0xC9BE2665EFE7D774ULL,
		0x681DFA8C0A50EA9CULL
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
		0x3F13C2556E824DE1ULL,
		0x89591AEF513D4A51ULL,
		0xB0F7800D796ED9AFULL,
		0xE1890A30068B7303ULL,
		0xA335FDA1DF915018ULL,
		0xA67A31E290B3343CULL,
		0xC25E7B5F650E2804ULL,
		0x1F6FC809A8839C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E2784AADD049BC2ULL,
		0x12B235DEA27A94A2ULL,
		0x61EF001AF2DDB35FULL,
		0xC31214600D16E607ULL,
		0x466BFB43BF22A031ULL,
		0x4CF463C521666879ULL,
		0x84BCF6BECA1C5009ULL,
		0x3EDF901351073823ULL
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
		0x4BC52711C19FB627ULL,
		0x668A7BA900FF15EAULL,
		0x2A05C2B685FCDE41ULL,
		0xB1380E537C051FF8ULL,
		0xAE5BA6E1696A63ECULL,
		0xA1D32BC373C34092ULL,
		0x6D6B506737F1AAEDULL,
		0x2D04B4E82285AF51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x978A4E23833F6C4EULL,
		0xCD14F75201FE2BD4ULL,
		0x540B856D0BF9BC82ULL,
		0x62701CA6F80A3FF0ULL,
		0x5CB74DC2D2D4C7D9ULL,
		0x43A65786E7868125ULL,
		0xDAD6A0CE6FE355DBULL,
		0x5A0969D0450B5EA2ULL
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
		0x3F5B71ADE8916C8AULL,
		0x408FF23547CDF194ULL,
		0x957F394F31C053C2ULL,
		0x6216044C73715241ULL,
		0xC4A1DF15C86CBD8EULL,
		0x2A2626DB8751D3CCULL,
		0x91C85882F8D10F91ULL,
		0x32CD2D0C2834B0CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EB6E35BD122D914ULL,
		0x811FE46A8F9BE328ULL,
		0x2AFE729E6380A784ULL,
		0xC42C0898E6E2A483ULL,
		0x8943BE2B90D97B1CULL,
		0x544C4DB70EA3A799ULL,
		0x2390B105F1A21F22ULL,
		0x659A5A1850696195ULL
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
		0x263572CC0C113B2DULL,
		0xB26D917164F505F3ULL,
		0x911C0C756CD8EAE2ULL,
		0x00E55B7D96B33AFBULL,
		0xF3DE7282881338D2ULL,
		0xFD6E926CED8646AFULL,
		0xE23C6C5C96697CF9ULL,
		0x21C8EC0581A7F5E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C6AE5981822765AULL,
		0x64DB22E2C9EA0BE6ULL,
		0x223818EAD9B1D5C5ULL,
		0x01CAB6FB2D6675F7ULL,
		0xE7BCE505102671A4ULL,
		0xFADD24D9DB0C8D5FULL,
		0xC478D8B92CD2F9F3ULL,
		0x4391D80B034FEBC5ULL
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
		0xFB01F7AA02FD5A5CULL,
		0x4FD983E80383E554ULL,
		0xB15535C354FCAD99ULL,
		0x8A542CE1182CEDC5ULL,
		0x0CC6B1EF884D0855ULL,
		0x72A5FFA0E8AA4ECBULL,
		0xDFA57FAE01A53762ULL,
		0x27CE06C701032096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF603EF5405FAB4B8ULL,
		0x9FB307D00707CAA9ULL,
		0x62AA6B86A9F95B32ULL,
		0x14A859C23059DB8BULL,
		0x198D63DF109A10ABULL,
		0xE54BFF41D1549D96ULL,
		0xBF4AFF5C034A6EC4ULL,
		0x4F9C0D8E0206412DULL
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
		0xC035EBDEB4139469ULL,
		0xC92050081089D400ULL,
		0x33B3685C729E10A7ULL,
		0x4E4059CBCE4BC590ULL,
		0xD3C7A90FF1FA19C6ULL,
		0x20D151CBE546A1ADULL,
		0x896E5BEF13109FDDULL,
		0x3F5A0BAE05C22848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x806BD7BD682728D2ULL,
		0x9240A0102113A801ULL,
		0x6766D0B8E53C214FULL,
		0x9C80B3979C978B20ULL,
		0xA78F521FE3F4338CULL,
		0x41A2A397CA8D435BULL,
		0x12DCB7DE26213FBAULL,
		0x7EB4175C0B845091ULL
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
		0x85CCD3BB871C143BULL,
		0x6AEED17FE779E387ULL,
		0x5741D059B47456DAULL,
		0x46FB74B1903EFBB6ULL,
		0xECE66A98AF5DD905ULL,
		0x28F4E1F390EED183ULL,
		0x87D113BE2A1844E6ULL,
		0x17C39001D1C607DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B99A7770E382876ULL,
		0xD5DDA2FFCEF3C70FULL,
		0xAE83A0B368E8ADB4ULL,
		0x8DF6E963207DF76CULL,
		0xD9CCD5315EBBB20AULL,
		0x51E9C3E721DDA307ULL,
		0x0FA2277C543089CCULL,
		0x2F872003A38C0FB5ULL
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
		0x2626DCD7CC66C6A0ULL,
		0x94141BBFA0101646ULL,
		0xFF139A8C726FF0DAULL,
		0x13E754069579B330ULL,
		0x2AFC6213275D7C18ULL,
		0xAE1D4F97A414CEAFULL,
		0x99630377D6571F5CULL,
		0x2342A5B05BFD28C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4DB9AF98CD8D40ULL,
		0x2828377F40202C8CULL,
		0xFE273518E4DFE1B5ULL,
		0x27CEA80D2AF36661ULL,
		0x55F8C4264EBAF830ULL,
		0x5C3A9F2F48299D5EULL,
		0x32C606EFACAE3EB9ULL,
		0x46854B60B7FA518BULL
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
		0xA02B0EE4FE44118CULL,
		0xBCEFA02BA9344E2AULL,
		0x9314D5DA9BF217ECULL,
		0x8D40F1B4B24618C1ULL,
		0x82E6C6188A58A0F7ULL,
		0x8B4C2CC41B82ABB6ULL,
		0x2216F157EDA0E6C6ULL,
		0x2E8A670DBDE8C765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40561DC9FC882318ULL,
		0x79DF405752689C55ULL,
		0x2629ABB537E42FD9ULL,
		0x1A81E369648C3183ULL,
		0x05CD8C3114B141EFULL,
		0x169859883705576DULL,
		0x442DE2AFDB41CD8DULL,
		0x5D14CE1B7BD18ECAULL
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
		0x77DB2A4209B1C17CULL,
		0x120F8AF48D0736E8ULL,
		0xA87A24D4ABC681D4ULL,
		0x7E054D84ECFBBA8DULL,
		0xECC51FAD97ADB800ULL,
		0x4E382701C8475818ULL,
		0x81B14E8C8C4E1097ULL,
		0x086B6E7F056746ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFB65484136382F8ULL,
		0x241F15E91A0E6DD0ULL,
		0x50F449A9578D03A8ULL,
		0xFC0A9B09D9F7751BULL,
		0xD98A3F5B2F5B7000ULL,
		0x9C704E03908EB031ULL,
		0x03629D19189C212EULL,
		0x10D6DCFE0ACE8D59ULL
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
		0x1354E41EDF5AD528ULL,
		0x3911C71D6ADDA3C5ULL,
		0x518A398EEB706405ULL,
		0x0A3B5E257AC4E8D0ULL,
		0x2804DAE643B60B02ULL,
		0xEEC86D1E3599313AULL,
		0x7F3D7E51E579D40AULL,
		0x38BAD076C93DD105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A9C83DBEB5AA50ULL,
		0x72238E3AD5BB478AULL,
		0xA314731DD6E0C80AULL,
		0x1476BC4AF589D1A0ULL,
		0x5009B5CC876C1604ULL,
		0xDD90DA3C6B326274ULL,
		0xFE7AFCA3CAF3A815ULL,
		0x7175A0ED927BA20AULL
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
		0x3327E4DCC382F23EULL,
		0x8B448C5F18FD2133ULL,
		0x1E3573DF0FF83D6FULL,
		0x21264853E551873BULL,
		0xB7036F42EA8DCF29ULL,
		0xA840826BEDE6FBDCULL,
		0xE50892EF4EE321EBULL,
		0x08FA5C401562029FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x664FC9B98705E47CULL,
		0x168918BE31FA4266ULL,
		0x3C6AE7BE1FF07ADFULL,
		0x424C90A7CAA30E76ULL,
		0x6E06DE85D51B9E52ULL,
		0x508104D7DBCDF7B9ULL,
		0xCA1125DE9DC643D7ULL,
		0x11F4B8802AC4053FULL
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
		0xB7FB71505C6AB286ULL,
		0x73220BD0C8855F60ULL,
		0x93974457C633EC61ULL,
		0x1B79C039F24EC061ULL,
		0xD09C9B9F2F5A396DULL,
		0xEA6C96F57B8CE71AULL,
		0x0CCB4EEDC7C84973ULL,
		0x069D7DA69D544177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF6E2A0B8D5650CULL,
		0xE64417A1910ABEC1ULL,
		0x272E88AF8C67D8C2ULL,
		0x36F38073E49D80C3ULL,
		0xA139373E5EB472DAULL,
		0xD4D92DEAF719CE35ULL,
		0x19969DDB8F9092E7ULL,
		0x0D3AFB4D3AA882EEULL
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
		0x10F632FC1110425BULL,
		0x9D0E284F7B31BE43ULL,
		0xF9E225BC5BFA75AEULL,
		0xCDBAF97BB149C90BULL,
		0xD8F126B32CBAABB5ULL,
		0x83364E2A8BAEC4B9ULL,
		0xB6F6D88E04B22650ULL,
		0x3F09A53C107116EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21EC65F8222084B6ULL,
		0x3A1C509EF6637C86ULL,
		0xF3C44B78B7F4EB5DULL,
		0x9B75F2F762939217ULL,
		0xB1E24D665975576BULL,
		0x066C9C55175D8973ULL,
		0x6DEDB11C09644CA1ULL,
		0x7E134A7820E22DDDULL
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
		0xD1A0019247BB31DEULL,
		0x570BB5A84D36821BULL,
		0xD1C017B57EE29B46ULL,
		0x193F177B422F23ACULL,
		0x9C347FC0EB9EA67BULL,
		0x433304ACD0004A9FULL,
		0x9A3A25B66429B9C6ULL,
		0x267AD6BA49AD4F43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA34003248F7663BCULL,
		0xAE176B509A6D0437ULL,
		0xA3802F6AFDC5368CULL,
		0x327E2EF6845E4759ULL,
		0x3868FF81D73D4CF6ULL,
		0x86660959A000953FULL,
		0x34744B6CC853738CULL,
		0x4CF5AD74935A9E87ULL
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
		0x1EB5780398528129ULL,
		0x7D0A29F85A686356ULL,
		0x65A8416BD86A267CULL,
		0xF6B0FE67727D81CFULL,
		0x5B2210D8C1D9ECBAULL,
		0x4867C457BB4E789CULL,
		0x84170AC2D041E923ULL,
		0x276A0CA117E083BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6AF00730A50252ULL,
		0xFA1453F0B4D0C6ACULL,
		0xCB5082D7B0D44CF8ULL,
		0xED61FCCEE4FB039EULL,
		0xB64421B183B3D975ULL,
		0x90CF88AF769CF138ULL,
		0x082E1585A083D246ULL,
		0x4ED419422FC10775ULL
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
		0x020244FA5F8AEC23ULL,
		0xFD48A7A3FD6CE4FAULL,
		0xA114DBDFC4490008ULL,
		0xF655980320CCDB79ULL,
		0xEB530F9C227C6E9BULL,
		0x707F767B0C92ABD9ULL,
		0xDDF0D3ECA8044C1DULL,
		0x251973F119125D79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x040489F4BF15D846ULL,
		0xFA914F47FAD9C9F4ULL,
		0x4229B7BF88920011ULL,
		0xECAB30064199B6F3ULL,
		0xD6A61F3844F8DD37ULL,
		0xE0FEECF6192557B3ULL,
		0xBBE1A7D95008983AULL,
		0x4A32E7E23224BAF3ULL
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
		0x6194ACAB9C5F836AULL,
		0x624767F023144BA0ULL,
		0x1BFFCE464A5B82C5ULL,
		0x8D6C61834A30B87BULL,
		0x7F325FC53447EC3AULL,
		0xE0F9819902D122EFULL,
		0xB167968DA86D5223ULL,
		0x3C8195674EB7C4A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC329595738BF06D4ULL,
		0xC48ECFE046289740ULL,
		0x37FF9C8C94B7058AULL,
		0x1AD8C306946170F6ULL,
		0xFE64BF8A688FD875ULL,
		0xC1F3033205A245DEULL,
		0x62CF2D1B50DAA447ULL,
		0x79032ACE9D6F8941ULL
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
	k1 = (curve25519_key_t){.key64 = {
		0xCEC3DE084C739046ULL,
		0x50F6330ED822D185ULL,
		0x7D54A658DC7D487CULL,
		0x7EC3DC46E51CBAEEULL,
		0x0657ABE5E7FA1253ULL,
		0x76A3B87474381C1DULL,
		0x202DAFFA3E6585B5ULL,
		0x2DF9CB676B959913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D87BC1098E7208CULL,
		0xA1EC661DB045A30BULL,
		0xFAA94CB1B8FA90F8ULL,
		0xFD87B88DCA3975DCULL,
		0x0CAF57CBCFF424A6ULL,
		0xED4770E8E870383AULL,
		0x405B5FF47CCB0B6AULL,
		0x5BF396CED72B3226ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE0AB1BF4146AAF0BULL,
		0x680D982FB59E9919ULL,
		0xA75B8CD00646FEBEULL,
		0x53BB4736542AAF29ULL,
		0x88F5ED114B59A651ULL,
		0xAF402C8C6996FF34ULL,
		0xEFE0FA46E1B4EDF8ULL,
		0x17A84E16F0590135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15637E828D55E16ULL,
		0xD01B305F6B3D3233ULL,
		0x4EB719A00C8DFD7CULL,
		0xA7768E6CA8555E53ULL,
		0x11EBDA2296B34CA2ULL,
		0x5E805918D32DFE69ULL,
		0xDFC1F48DC369DBF1ULL,
		0x2F509C2DE0B2026BULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x882EBCE615F736A6ULL,
		0x18AC9608C69574AFULL,
		0xE207ADCFB7E45937ULL,
		0x9BA639BAF3CD55E8ULL,
		0xACCF0894B12F0AB8ULL,
		0xE0DB164C938B2F75ULL,
		0x62A6CEC1C3326374ULL,
		0x1FEE357D3D6968E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x105D79CC2BEE6D4CULL,
		0x31592C118D2AE95FULL,
		0xC40F5B9F6FC8B26EULL,
		0x374C7375E79AABD1ULL,
		0x599E1129625E1571ULL,
		0xC1B62C9927165EEBULL,
		0xC54D9D838664C6E9ULL,
		0x3FDC6AFA7AD2D1D0ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA73D8532131D0A3CULL,
		0xC19B85C7F6C48674ULL,
		0xEB3DFF851B746CB3ULL,
		0x47C05948370D322EULL,
		0x706ABF8AAC0A0709ULL,
		0x80F281934613ECFDULL,
		0xA8ED890FA092C4E4ULL,
		0x360B4AD52A2ABAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E7B0A64263A1478ULL,
		0x83370B8FED890CE9ULL,
		0xD67BFF0A36E8D967ULL,
		0x8F80B2906E1A645DULL,
		0xE0D57F1558140E12ULL,
		0x01E503268C27D9FAULL,
		0x51DB121F412589C9ULL,
		0x6C1695AA545575E1ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5A6F934AD80C5BFAULL,
		0x479D29E89D050B2FULL,
		0x7DF139CD705D333BULL,
		0x1AF5FC67EF513A56ULL,
		0x3552D53DDBA71373ULL,
		0x2AA8A2096384E7F5ULL,
		0x20AA8CFECC5EED26ULL,
		0x0D1B27A7682EC89FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4DF2695B018B7F4ULL,
		0x8F3A53D13A0A165EULL,
		0xFBE2739AE0BA6676ULL,
		0x35EBF8CFDEA274ACULL,
		0x6AA5AA7BB74E26E6ULL,
		0x55514412C709CFEAULL,
		0x415519FD98BDDA4CULL,
		0x1A364F4ED05D913EULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x991458785D4B111AULL,
		0x90C5386C7779E57DULL,
		0x87EF91D393DC58F3ULL,
		0xF47FF3604FFA05BEULL,
		0xC50D9FAA4D1DA9DDULL,
		0x2CD33BBA9A8BA998ULL,
		0x9FFBC5506B9CD49CULL,
		0x0109201C2FD2055FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3228B0F0BA962234ULL,
		0x218A70D8EEF3CAFBULL,
		0x0FDF23A727B8B1E7ULL,
		0xE8FFE6C09FF40B7DULL,
		0x8A1B3F549A3B53BBULL,
		0x59A6777535175331ULL,
		0x3FF78AA0D739A938ULL,
		0x021240385FA40ABFULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA0AF34DF7DA4329DULL,
		0x01B187B5C3B28D62ULL,
		0x0C5566E0BDF58FF1ULL,
		0x597521F0FF13A908ULL,
		0xED05AF94FA693C88ULL,
		0x1163F2600BF8D9ADULL,
		0x296441506E2E6DBEULL,
		0x1A8453D36403FE3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415E69BEFB48653AULL,
		0x03630F6B87651AC5ULL,
		0x18AACDC17BEB1FE2ULL,
		0xB2EA43E1FE275210ULL,
		0xDA0B5F29F4D27910ULL,
		0x22C7E4C017F1B35BULL,
		0x52C882A0DC5CDB7CULL,
		0x3508A7A6C807FC76ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x74B8309701AFED9DULL,
		0x86743B369A5198A0ULL,
		0xAE2C0A06F374477FULL,
		0x22296AFE8889F67BULL,
		0x1B1F4A1FDE1E411CULL,
		0x8E8D7DA0F94A4A09ULL,
		0x180AC6270E290294ULL,
		0x3FA290CA5DC73DFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE970612E035FDB3AULL,
		0x0CE8766D34A33140ULL,
		0x5C58140DE6E88EFFULL,
		0x4452D5FD1113ECF7ULL,
		0x363E943FBC3C8238ULL,
		0x1D1AFB41F2949412ULL,
		0x30158C4E1C520529ULL,
		0x7F452194BB8E7BFAULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF871BD4F52176FFBULL,
		0x5797E11471265783ULL,
		0x6671E1F0C9E22488ULL,
		0x58D5DB60A8F6486EULL,
		0x8CD4A8E74E1049CEULL,
		0x66B0AD130285012DULL,
		0xA48E8C3136AAEA1BULL,
		0x140EA2456280D417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E37A9EA42EDFF6ULL,
		0xAF2FC228E24CAF07ULL,
		0xCCE3C3E193C44910ULL,
		0xB1ABB6C151EC90DCULL,
		0x19A951CE9C20939CULL,
		0xCD615A26050A025BULL,
		0x491D18626D55D436ULL,
		0x281D448AC501A82FULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x102DB6266C1E0A83ULL,
		0x2BEA31B329E62852ULL,
		0x9DCB7D595ECBBB91ULL,
		0x84B38926E1721320ULL,
		0x3D0344792700FE02ULL,
		0x6D30F15D115662AAULL,
		0x6420008AFA75BFCDULL,
		0x246A4B0B93F702B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205B6C4CD83C1506ULL,
		0x57D4636653CC50A4ULL,
		0x3B96FAB2BD977722ULL,
		0x0967124DC2E42641ULL,
		0x7A0688F24E01FC05ULL,
		0xDA61E2BA22ACC554ULL,
		0xC8400115F4EB7F9AULL,
		0x48D4961727EE0572ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x31EDECAA6F52F75AULL,
		0xA4CFB9E426C27C9BULL,
		0xB45E6C2ECEAC5B86ULL,
		0x6266195468C285A0ULL,
		0x58F2241B0B8E529AULL,
		0x7A535FF50C6EF8D2ULL,
		0x3BDDEA2CE4B85AB6ULL,
		0x3663D46AB73028A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DBD954DEA5EEB4ULL,
		0x499F73C84D84F936ULL,
		0x68BCD85D9D58B70DULL,
		0xC4CC32A8D1850B41ULL,
		0xB1E44836171CA534ULL,
		0xF4A6BFEA18DDF1A4ULL,
		0x77BBD459C970B56CULL,
		0x6CC7A8D56E605150ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81BEDEBF2F3F5A80ULL,
		0x5F4DCAA5EB0A4416ULL,
		0xDAB11826C9901971ULL,
		0xD19EBBA1A0C85CCFULL,
		0xF5AE4402344350D1ULL,
		0xC4D7D888CD93E59AULL,
		0xC37E858C690F6D8AULL,
		0x37D9A10944DE7AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x037DBD7E5E7EB500ULL,
		0xBE9B954BD614882DULL,
		0xB562304D932032E2ULL,
		0xA33D77434190B99FULL,
		0xEB5C88046886A1A3ULL,
		0x89AFB1119B27CB35ULL,
		0x86FD0B18D21EDB15ULL,
		0x6FB3421289BCF5C7ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC215D70C77643A37ULL,
		0x38D787813ACD06D7ULL,
		0x760EA8F9A7B4C3AFULL,
		0x3240D03BD5130228ULL,
		0xE6FA9BAFEC53354BULL,
		0x7EEB076BC9E88B55ULL,
		0x94282968987F2A9CULL,
		0x35710369E9404D42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842BAE18EEC8746EULL,
		0x71AF0F02759A0DAFULL,
		0xEC1D51F34F69875EULL,
		0x6481A077AA260450ULL,
		0xCDF5375FD8A66A96ULL,
		0xFDD60ED793D116ABULL,
		0x285052D130FE5538ULL,
		0x6AE206D3D2809A85ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x821BC89463461D25ULL,
		0x3719CB9A5FD26105ULL,
		0x3525603134CE7629ULL,
		0x8887B77E515EFE63ULL,
		0x346D74862139FC23ULL,
		0x462AAD7BF28BCBE7ULL,
		0xA8BFBFD62C7199AAULL,
		0x1EB14AD8D32A764EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04379128C68C3A4AULL,
		0x6E339734BFA4C20BULL,
		0x6A4AC062699CEC52ULL,
		0x110F6EFCA2BDFCC6ULL,
		0x68DAE90C4273F847ULL,
		0x8C555AF7E51797CEULL,
		0x517F7FAC58E33354ULL,
		0x3D6295B1A654EC9DULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x78ABBE4EE22BF4C5ULL,
		0x4D81EE9B1BD8F243ULL,
		0xA7348185BE124A4DULL,
		0xF9D82DA44A918D30ULL,
		0x88FA06E8DEBD5947ULL,
		0x31726FABF6388AC1ULL,
		0x41A5397EE6B66CEAULL,
		0x093D63ED86C1F6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1577C9DC457E98AULL,
		0x9B03DD3637B1E486ULL,
		0x4E69030B7C24949AULL,
		0xF3B05B4895231A61ULL,
		0x11F40DD1BD7AB28FULL,
		0x62E4DF57EC711583ULL,
		0x834A72FDCD6CD9D4ULL,
		0x127AC7DB0D83ED42ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x92D860F681425E09ULL,
		0xC2872AA8A6262421ULL,
		0xD6C6F112AED4B386ULL,
		0xAACC0C7C600DBF22ULL,
		0x2F04441F49F5C891ULL,
		0x32B19C8C14345364ULL,
		0x0FFAFC789D7296F6ULL,
		0x0CC59E67413FA0C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B0C1ED0284BC12ULL,
		0x850E55514C4C4843ULL,
		0xAD8DE2255DA9670DULL,
		0x559818F8C01B7E45ULL,
		0x5E08883E93EB9123ULL,
		0x656339182868A6C8ULL,
		0x1FF5F8F13AE52DECULL,
		0x198B3CCE827F4188ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC06B4C6B86C8E92ULL,
		0x2CADBC65E42AB802ULL,
		0x8AE655D58EEAD9A4ULL,
		0x8D8FF8FF3A4E3556ULL,
		0x3BDC4606A03167A4ULL,
		0x33CE1982995A995CULL,
		0x49D1802EE77A190DULL,
		0x19420DE5EAD72396ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x580D698D70D91D24ULL,
		0x595B78CBC8557005ULL,
		0x15CCABAB1DD5B348ULL,
		0x1B1FF1FE749C6AADULL,
		0x77B88C0D4062CF49ULL,
		0x679C330532B532B8ULL,
		0x93A3005DCEF4321AULL,
		0x32841BCBD5AE472CULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3E7FE1BBD559EC0DULL,
		0xAA0D6AF56006E636ULL,
		0x4773D7B3784D380CULL,
		0x496E49338D6518F9ULL,
		0xB3C5D3ADA8A32222ULL,
		0x7CD292CF04B352AFULL,
		0x346FF0DAE28CCC56ULL,
		0x3E762BF32F1FC506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFFC377AAB3D81AULL,
		0x541AD5EAC00DCC6CULL,
		0x8EE7AF66F09A7019ULL,
		0x92DC92671ACA31F2ULL,
		0x678BA75B51464444ULL,
		0xF9A5259E0966A55FULL,
		0x68DFE1B5C51998ACULL,
		0x7CEC57E65E3F8A0CULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B49033C6978C5CFULL,
		0x782DAC9DCE5B25CCULL,
		0x9B9B442F1445684EULL,
		0xF89E7811C14E88CFULL,
		0xDB6C21EB99B0C6CAULL,
		0xDF2AE7E7677D3406ULL,
		0xD18E76E2F6408133ULL,
		0x02B38EACD0AA0347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76920678D2F18B9EULL,
		0xF05B593B9CB64B98ULL,
		0x3736885E288AD09CULL,
		0xF13CF023829D119FULL,
		0xB6D843D733618D95ULL,
		0xBE55CFCECEFA680DULL,
		0xA31CEDC5EC810267ULL,
		0x05671D59A154068FULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA5BAB62A3F43CFF6ULL,
		0x9C7D9863015C908DULL,
		0xDAA1262278746FEEULL,
		0x361A5042E9668163ULL,
		0xE4985D1E7815150FULL,
		0x40577F565B2FEC40ULL,
		0x2845856D3AD58E33ULL,
		0x28486794A533F5C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B756C547E879FECULL,
		0x38FB30C602B9211BULL,
		0xB5424C44F0E8DFDDULL,
		0x6C34A085D2CD02C7ULL,
		0xC930BA3CF02A2A1EULL,
		0x80AEFEACB65FD881ULL,
		0x508B0ADA75AB1C66ULL,
		0x5090CF294A67EB90ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x90CC3E813513D6D0ULL,
		0x299DEEF84AAAE943ULL,
		0xB0672C621D6C8A8CULL,
		0x1A823EA8F5343D74ULL,
		0xBBB15CF8EFD364F1ULL,
		0x75F6308545EF775AULL,
		0x1175E40C736EF905ULL,
		0x0F5E2DD0B74C8B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21987D026A27ADA0ULL,
		0x533BDDF09555D287ULL,
		0x60CE58C43AD91518ULL,
		0x35047D51EA687AE9ULL,
		0x7762B9F1DFA6C9E2ULL,
		0xEBEC610A8BDEEEB5ULL,
		0x22EBC818E6DDF20AULL,
		0x1EBC5BA16E9916D0ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA555B1A82FE43731ULL,
		0xC695C2A9269BCC73ULL,
		0x97AC2ACF3465FAB8ULL,
		0xC30E50D6B0F4BB3FULL,
		0x445C4946078F93D8ULL,
		0x73D7D644ED93482EULL,
		0x19285000BF05E3B4ULL,
		0x1853B29B2F0F4FACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AAB63505FC86E62ULL,
		0x8D2B85524D3798E7ULL,
		0x2F58559E68CBF571ULL,
		0x861CA1AD61E9767FULL,
		0x88B8928C0F1F27B1ULL,
		0xE7AFAC89DB26905CULL,
		0x3250A0017E0BC768ULL,
		0x30A765365E1E9F58ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4C82334F1CD825E3ULL,
		0x7D9656046C98A322ULL,
		0x1708D234B91464CDULL,
		0x3A279C6B7C890AD4ULL,
		0x58CDC2D1B434BB53ULL,
		0x2BDCE7759646F196ULL,
		0xDC444C2C62718ED9ULL,
		0x2E45279AF172DE30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9904669E39B04BC6ULL,
		0xFB2CAC08D9314644ULL,
		0x2E11A4697228C99AULL,
		0x744F38D6F91215A8ULL,
		0xB19B85A3686976A6ULL,
		0x57B9CEEB2C8DE32CULL,
		0xB8889858C4E31DB2ULL,
		0x5C8A4F35E2E5BC61ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x00070545817AD3F8ULL,
		0x3D0F88D76D8872F0ULL,
		0xC269B0BF48142A20ULL,
		0x1AFAA8177BDCEED3ULL,
		0xD5713665A7BCA99AULL,
		0x49D6E16CE9F14596ULL,
		0x6990E5711A569A9DULL,
		0x2D1BC6072A684B3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x000E0A8B02F5A7F0ULL,
		0x7A1F11AEDB10E5E0ULL,
		0x84D3617E90285440ULL,
		0x35F5502EF7B9DDA7ULL,
		0xAAE26CCB4F795334ULL,
		0x93ADC2D9D3E28B2DULL,
		0xD321CAE234AD353AULL,
		0x5A378C0E54D0967AULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x146949F0C138E42CULL,
		0xEF3BDAAA11527F2DULL,
		0x40449F518DB20E6DULL,
		0xD352E4120EAE6FDEULL,
		0xB9E2FE8F3DA18162ULL,
		0x116F551A1CB9E8F1ULL,
		0x2A655B556690152AULL,
		0x1FEF3271840FFD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D293E18271C858ULL,
		0xDE77B55422A4FE5AULL,
		0x80893EA31B641CDBULL,
		0xA6A5C8241D5CDFBCULL,
		0x73C5FD1E7B4302C5ULL,
		0x22DEAA343973D1E3ULL,
		0x54CAB6AACD202A54ULL,
		0x3FDE64E3081FFA9AULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x60E357CF02B08D0BULL,
		0x358DFCB657996AE8ULL,
		0x44576BA6C3FCF22DULL,
		0x5BF5B94BC268F7D6ULL,
		0xD62D6346D8077464ULL,
		0x24567AD8EE73F0D7ULL,
		0x6178BE02C637DD07ULL,
		0x05EF75F426F23F60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1C6AF9E05611A16ULL,
		0x6B1BF96CAF32D5D0ULL,
		0x88AED74D87F9E45AULL,
		0xB7EB729784D1EFACULL,
		0xAC5AC68DB00EE8C8ULL,
		0x48ACF5B1DCE7E1AFULL,
		0xC2F17C058C6FBA0EULL,
		0x0BDEEBE84DE47EC0ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5AEA9DFF71ADC558ULL,
		0x723EE828ABEEB824ULL,
		0x6F8F3D4FA9F786E5ULL,
		0xF0F5A8A36F2E56DBULL,
		0x52B887F58EADF0E7ULL,
		0x45ED36E8DC5F1A83ULL,
		0x7787FC5220752E9FULL,
		0x3554E2D890A8B983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D53BFEE35B8AB0ULL,
		0xE47DD05157DD7048ULL,
		0xDF1E7A9F53EF0DCAULL,
		0xE1EB5146DE5CADB6ULL,
		0xA5710FEB1D5BE1CFULL,
		0x8BDA6DD1B8BE3506ULL,
		0xEF0FF8A440EA5D3EULL,
		0x6AA9C5B121517306ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAA4551A6C6C674B7ULL,
		0x8B074B16A0AFD155ULL,
		0x88C4A21562348752ULL,
		0xB4249BFA3FAD1AF0ULL,
		0x65A5E5814871CABDULL,
		0xD3B82AFAD32170B9ULL,
		0x8817511C5E5232E5ULL,
		0x329250FCBEDB1C6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548AA34D8D8CE96EULL,
		0x160E962D415FA2ABULL,
		0x1189442AC4690EA5ULL,
		0x684937F47F5A35E1ULL,
		0xCB4BCB0290E3957BULL,
		0xA77055F5A642E172ULL,
		0x102EA238BCA465CBULL,
		0x6524A1F97DB638DBULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBEFFB7D383598A00ULL,
		0xE721E6AEEFB13DE3ULL,
		0xB49ADE6DA68A0B62ULL,
		0xA75A72712018950BULL,
		0x4C4C429B11F6642AULL,
		0xB43CC6C3B7CA8828ULL,
		0xC68815707F9AC067ULL,
		0x3F072351B1B8A091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DFF6FA706B31400ULL,
		0xCE43CD5DDF627BC7ULL,
		0x6935BCDB4D1416C5ULL,
		0x4EB4E4E240312A17ULL,
		0x9898853623ECC855ULL,
		0x68798D876F951050ULL,
		0x8D102AE0FF3580CFULL,
		0x7E0E46A363714123ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B85074A3ADE581EULL,
		0x4EA8E4320E2C068AULL,
		0x9416F3CC1DA88B2CULL,
		0x37C8ECB158265C72ULL,
		0xF0B44D6EB2B24656ULL,
		0x5F6ECA6085A2F025ULL,
		0x3C38DDE15EC15007ULL,
		0x3BE58BF1C827833EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770A0E9475BCB03CULL,
		0x9D51C8641C580D14ULL,
		0x282DE7983B511658ULL,
		0x6F91D962B04CB8E5ULL,
		0xE1689ADD65648CACULL,
		0xBEDD94C10B45E04BULL,
		0x7871BBC2BD82A00EULL,
		0x77CB17E3904F067CULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x77146FDA18AA0F76ULL,
		0xE9AB737874E69298ULL,
		0x8A04FAD90C5E7E7CULL,
		0x44E9A858FE39D5CBULL,
		0x6D786096B6B9ED8CULL,
		0xCBA7058337F2CDE7ULL,
		0x9CC3B3C9FC2EF88AULL,
		0x07C69AFA66926456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE28DFB431541EECULL,
		0xD356E6F0E9CD2530ULL,
		0x1409F5B218BCFCF9ULL,
		0x89D350B1FC73AB97ULL,
		0xDAF0C12D6D73DB18ULL,
		0x974E0B066FE59BCEULL,
		0x39876793F85DF115ULL,
		0x0F8D35F4CD24C8ADULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6BD783EF6EB43C1BULL,
		0xFCDFDD4047AEAFD0ULL,
		0x184CBB54E201B952ULL,
		0x1AE2A1D9D37D0775ULL,
		0x6B317F0BDA288156ULL,
		0xBF28846AA92B7374ULL,
		0x165DF7311EA9F8F0ULL,
		0x3D87D235D0B2A86EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7AF07DEDD687836ULL,
		0xF9BFBA808F5D5FA0ULL,
		0x309976A9C40372A5ULL,
		0x35C543B3A6FA0EEAULL,
		0xD662FE17B45102ACULL,
		0x7E5108D55256E6E8ULL,
		0x2CBBEE623D53F1E1ULL,
		0x7B0FA46BA16550DCULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3F7E1F3B35B005DULL,
		0x65AADDF3CFBE01D9ULL,
		0x161F20636107BB06ULL,
		0xB7DC0FA4BE62B983ULL,
		0x5AB3126B3A6538D8ULL,
		0xAE1D66C8025FFB15ULL,
		0x3BBAA45DEF7CE530ULL,
		0x1C7A25C5C427F410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47EFC3E766B600BAULL,
		0xCB55BBE79F7C03B3ULL,
		0x2C3E40C6C20F760CULL,
		0x6FB81F497CC57306ULL,
		0xB56624D674CA71B1ULL,
		0x5C3ACD9004BFF62AULL,
		0x777548BBDEF9CA61ULL,
		0x38F44B8B884FE820ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x40EAE1B7660F099CULL,
		0xCA56904C96D3523BULL,
		0x522213E21F0AD116ULL,
		0x98AA970DB307BC47ULL,
		0x8B216C0709F92928ULL,
		0xC2CB07B8D24F26E0ULL,
		0x644A0D411E029097ULL,
		0x36E1D978424CA692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81D5C36ECC1E1338ULL,
		0x94AD20992DA6A476ULL,
		0xA44427C43E15A22DULL,
		0x31552E1B660F788EULL,
		0x1642D80E13F25251ULL,
		0x85960F71A49E4DC1ULL,
		0xC8941A823C05212FULL,
		0x6DC3B2F084994D24ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC5EA3C7999097757ULL,
		0x86E54ACCB2B2097BULL,
		0xF32241CD3919BD5FULL,
		0xD2FDEDE55EE7B36CULL,
		0x25176ED5E1E964CFULL,
		0x080713BAE77DFA2DULL,
		0x03A3D3304B2E7686ULL,
		0x178FDB9204B4F0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD478F33212EEAEULL,
		0x0DCA9599656412F7ULL,
		0xE644839A72337ABFULL,
		0xA5FBDBCABDCF66D9ULL,
		0x4A2EDDABC3D2C99FULL,
		0x100E2775CEFBF45AULL,
		0x0747A660965CED0CULL,
		0x2F1FB7240969E142ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBC3A949E34465E74ULL,
		0x594855651315746CULL,
		0x16C2E57FD30B39D4ULL,
		0x123D9860AF8F1D75ULL,
		0x6A146241EC12DC4FULL,
		0x5C1DB1136E17E9A0ULL,
		0x84C861A56ACD0F7EULL,
		0x03A47C43DA1BB336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7875293C688CBCE8ULL,
		0xB290AACA262AE8D9ULL,
		0x2D85CAFFA61673A8ULL,
		0x247B30C15F1E3AEAULL,
		0xD428C483D825B89EULL,
		0xB83B6226DC2FD340ULL,
		0x0990C34AD59A1EFCULL,
		0x0748F887B437666DULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF312334DFF11BFD9ULL,
		0x90BBC201FCA00F82ULL,
		0x6F80394C2F5427FAULL,
		0x3F6C4F7CAB9652A1ULL,
		0x29EF056ABC15FFFBULL,
		0x85E5E0376E7AA692ULL,
		0x3F495D3DD0B2F1A4ULL,
		0x34AE5680E0E67385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE624669BFE237FB2ULL,
		0x21778403F9401F05ULL,
		0xDF0072985EA84FF5ULL,
		0x7ED89EF9572CA542ULL,
		0x53DE0AD5782BFFF6ULL,
		0x0BCBC06EDCF54D24ULL,
		0x7E92BA7BA165E349ULL,
		0x695CAD01C1CCE70AULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB9D6E989009145A4ULL,
		0x2685F343CEBED3B8ULL,
		0xEB09BF3CC25EFDD7ULL,
		0x68ACC545AD781B81ULL,
		0x978D49B0FADFA17FULL,
		0xADAB9D11665E1B0CULL,
		0xD3FF0BCB258D5C12ULL,
		0x30B110F16E3CFD30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73ADD31201228B48ULL,
		0x4D0BE6879D7DA771ULL,
		0xD6137E7984BDFBAEULL,
		0xD1598A8B5AF03703ULL,
		0x2F1A9361F5BF42FEULL,
		0x5B573A22CCBC3619ULL,
		0xA7FE17964B1AB825ULL,
		0x616221E2DC79FA61ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFE7CF383B5946CDEULL,
		0xFAE91631DF511069ULL,
		0x9B9AC06D4A08B674ULL,
		0x3D71BA08F5A1C960ULL,
		0xDC9AFEBE90CA7E7FULL,
		0x20813636086D47CEULL,
		0xB7D49DA51F59EA02ULL,
		0x01769367692CEF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCF9E7076B28D9BCULL,
		0xF5D22C63BEA220D3ULL,
		0x373580DA94116CE9ULL,
		0x7AE37411EB4392C1ULL,
		0xB935FD7D2194FCFEULL,
		0x41026C6C10DA8F9DULL,
		0x6FA93B4A3EB3D404ULL,
		0x02ED26CED259DE99ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x458FFFAB4F1D0D9EULL,
		0x305B93896A1BB3F6ULL,
		0x551F63DD5FEDB083ULL,
		0x58A2886CB2214126ULL,
		0x62BF6EE353D2A77FULL,
		0xD016BA76E9A6E778ULL,
		0x587BB467753FC43AULL,
		0x3BC8DCD01AFB3989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B1FFF569E3A1B3CULL,
		0x60B72712D43767ECULL,
		0xAA3EC7BABFDB6106ULL,
		0xB14510D96442824CULL,
		0xC57EDDC6A7A54EFEULL,
		0xA02D74EDD34DCEF0ULL,
		0xB0F768CEEA7F8875ULL,
		0x7791B9A035F67312ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFCD84E55DA4FA1E9ULL,
		0xE1F22251E39222CDULL,
		0x4A09F58C8D39EE41ULL,
		0xBE8D8DF1CED0CFB6ULL,
		0x96DEBB0648CE9A09ULL,
		0x9B6ADA1CA2C73FC8ULL,
		0xA1B626E1100D9A07ULL,
		0x0D3D4CF61FC3CB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9B09CABB49F43D2ULL,
		0xC3E444A3C724459BULL,
		0x9413EB191A73DC83ULL,
		0x7D1B1BE39DA19F6CULL,
		0x2DBD760C919D3413ULL,
		0x36D5B439458E7F91ULL,
		0x436C4DC2201B340FULL,
		0x1A7A99EC3F879635ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC3B24F401284666DULL,
		0x4B555C3420E20394ULL,
		0x8A98DEDCB5AFCD7BULL,
		0x29471A376A0A083CULL,
		0x7D101F1D4DDD9E09ULL,
		0xB0DB6402D28709EFULL,
		0x37F196D4C846BDCDULL,
		0x3C8955C3C68D9B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87649E802508CCDAULL,
		0x96AAB86841C40729ULL,
		0x1531BDB96B5F9AF6ULL,
		0x528E346ED4141079ULL,
		0xFA203E3A9BBB3C12ULL,
		0x61B6C805A50E13DEULL,
		0x6FE32DA9908D7B9BULL,
		0x7912AB878D1B36E6ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA3BA1797F61950E8ULL,
		0x8DB0A50DD004D7F2ULL,
		0xB9833B90B111060DULL,
		0xFE5D2B92AA7828EDULL,
		0xF5BF229E2433CF8FULL,
		0x443D373872758B64ULL,
		0xA33BC9A959800E3BULL,
		0x128D5CBEB37D3C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47742F2FEC32A1D0ULL,
		0x1B614A1BA009AFE5ULL,
		0x7306772162220C1BULL,
		0xFCBA572554F051DBULL,
		0xEB7E453C48679F1FULL,
		0x887A6E70E4EB16C9ULL,
		0x46779352B3001C76ULL,
		0x251AB97D66FA78F9ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x06E6D7B8B8A4491AULL,
		0x3FFB87C192812B27ULL,
		0x99F4C33D77C65E0BULL,
		0x3410A2462803E13CULL,
		0x2B44AF69FC8A68D6ULL,
		0x6AA4E642054969C9ULL,
		0x48AF5A65C2EBE3DAULL,
		0x355CCD215EC617C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DCDAF7171489234ULL,
		0x7FF70F832502564EULL,
		0x33E9867AEF8CBC16ULL,
		0x6821448C5007C279ULL,
		0x56895ED3F914D1ACULL,
		0xD549CC840A92D392ULL,
		0x915EB4CB85D7C7B4ULL,
		0x6AB99A42BD8C2F82ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2CC14E962FBDCB5EULL,
		0xD95F0009447C6B1AULL,
		0x31044D8990D45377ULL,
		0x318E88C5A2E46E1DULL,
		0xEB0D8ED2C717F3E0ULL,
		0xD819ADD91D7107F9ULL,
		0xA2F1E732BF4C8CCCULL,
		0x3DB0E472A1D90321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59829D2C5F7B96BCULL,
		0xB2BE001288F8D634ULL,
		0x62089B1321A8A6EFULL,
		0x631D118B45C8DC3AULL,
		0xD61B1DA58E2FE7C0ULL,
		0xB0335BB23AE20FF3ULL,
		0x45E3CE657E991999ULL,
		0x7B61C8E543B20643ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D905DD15023338BULL,
		0xFC5FE9E7E0CEC3B3ULL,
		0xDD21A65CE6579A7CULL,
		0xF5EEEC6942DBF51EULL,
		0x8370DF5633C36E9DULL,
		0x0A2D7644A378ADEAULL,
		0x1C59143CE41ECC4DULL,
		0x2F2E56C3A1107940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB20BBA2A0466716ULL,
		0xF8BFD3CFC19D8766ULL,
		0xBA434CB9CCAF34F9ULL,
		0xEBDDD8D285B7EA3DULL,
		0x06E1BEAC6786DD3BULL,
		0x145AEC8946F15BD5ULL,
		0x38B22879C83D989AULL,
		0x5E5CAD874220F280ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x02B54EF56CB8665DULL,
		0xCC149F9670476CD7ULL,
		0xEE490281CAC0AA38ULL,
		0x84F4BDF726AB6109ULL,
		0xC10BA8B492369305ULL,
		0x183CF541A0D885A4ULL,
		0x9F98BD6BBC80B7FCULL,
		0x33CFF6155DFA4475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056A9DEAD970CCBAULL,
		0x98293F2CE08ED9AEULL,
		0xDC92050395815471ULL,
		0x09E97BEE4D56C213ULL,
		0x82175169246D260BULL,
		0x3079EA8341B10B49ULL,
		0x3F317AD779016FF8ULL,
		0x679FEC2ABBF488EBULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1556952979FE01A5ULL,
		0x08422577DDBF5A3AULL,
		0x056C733D37E91941ULL,
		0x58CF280B3684E9DBULL,
		0x3CE3AB31C481D26AULL,
		0xF8382AC030B7EA95ULL,
		0x9CC78B90B08A74E4ULL,
		0x28C8C0D588603FDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AAD2A52F3FC034AULL,
		0x10844AEFBB7EB474ULL,
		0x0AD8E67A6FD23282ULL,
		0xB19E50166D09D3B6ULL,
		0x79C756638903A4D4ULL,
		0xF0705580616FD52AULL,
		0x398F17216114E9C9ULL,
		0x519181AB10C07FBDULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8867ADCD58FA2772ULL,
		0xD1094ECF407FFBB2ULL,
		0xF68450C8F752604BULL,
		0xB24E41A2F2C15609ULL,
		0x3C26502A1925B290ULL,
		0xD9602B0CFF4BB7C0ULL,
		0x419884FF247502CCULL,
		0x27B4F05DCBC09629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10CF5B9AB1F44EE4ULL,
		0xA2129D9E80FFF765ULL,
		0xED08A191EEA4C097ULL,
		0x649C8345E582AC13ULL,
		0x784CA054324B6521ULL,
		0xB2C05619FE976F80ULL,
		0x833109FE48EA0599ULL,
		0x4F69E0BB97812C52ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBE158C5CF0D6DE8CULL,
		0x0E1B4DB5BD025E64ULL,
		0xF875B0350091F768ULL,
		0x34DFC1143E4DC84BULL,
		0x5C2A0C38226AD886ULL,
		0x09F565B34194547AULL,
		0xDF869E76D9317D6CULL,
		0x0FC30588ACE59B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C2B18B9E1ADBD18ULL,
		0x1C369B6B7A04BCC9ULL,
		0xF0EB606A0123EED0ULL,
		0x69BF82287C9B9097ULL,
		0xB854187044D5B10CULL,
		0x13EACB668328A8F4ULL,
		0xBF0D3CEDB262FAD8ULL,
		0x1F860B1159CB3701ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE839B5D486992A59ULL,
		0x34CEFDE48D4062C0ULL,
		0x4366D204823898C2ULL,
		0x0ACFD03C06AFD1E7ULL,
		0xF80545F3E6D55FEDULL,
		0xE82A01506098E11FULL,
		0xC22D1824BFA40E91ULL,
		0x035E6B28B20C3CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0736BA90D3254B2ULL,
		0x699DFBC91A80C581ULL,
		0x86CDA40904713184ULL,
		0x159FA0780D5FA3CEULL,
		0xF00A8BE7CDAABFDAULL,
		0xD05402A0C131C23FULL,
		0x845A30497F481D23ULL,
		0x06BCD65164187977ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE58BEFEC365BECFDULL,
		0x3DA6FA0150DA0609ULL,
		0x45B633CC663DD84EULL,
		0xD43F9FE92BF7968AULL,
		0x8960F29980C8D084ULL,
		0xB00A354B5877515BULL,
		0x4435B9D6AE4C8C38ULL,
		0x1E66CD3B4766AE88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB17DFD86CB7D9FAULL,
		0x7B4DF402A1B40C13ULL,
		0x8B6C6798CC7BB09CULL,
		0xA87F3FD257EF2D14ULL,
		0x12C1E5330191A109ULL,
		0x60146A96B0EEA2B7ULL,
		0x886B73AD5C991871ULL,
		0x3CCD9A768ECD5D10ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x69FE0EB1359B1792ULL,
		0x042D39BD44759445ULL,
		0xF94161F7EF67C830ULL,
		0xF7228F01E8C8789FULL,
		0x46D2BA173E9B10A3ULL,
		0x00A7BEBF357D2F7AULL,
		0x1DCE97ADF4416234ULL,
		0x0C29CD863C9FDF58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3FC1D626B362F24ULL,
		0x085A737A88EB288AULL,
		0xF282C3EFDECF9060ULL,
		0xEE451E03D190F13FULL,
		0x8DA5742E7D362147ULL,
		0x014F7D7E6AFA5EF4ULL,
		0x3B9D2F5BE882C468ULL,
		0x18539B0C793FBEB0ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x424247C4CB204BAAULL,
		0xF1AC40963BD3356AULL,
		0xBA4C2D2929A875CFULL,
		0x7599356A66C3FB46ULL,
		0x96D3B734919F7516ULL,
		0xA1D715D4CE7914A8ULL,
		0xCAE26061E832BD0BULL,
		0x22E1C96CB8F3B602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84848F8996409754ULL,
		0xE358812C77A66AD4ULL,
		0x74985A525350EB9FULL,
		0xEB326AD4CD87F68DULL,
		0x2DA76E69233EEA2CULL,
		0x43AE2BA99CF22951ULL,
		0x95C4C0C3D0657A17ULL,
		0x45C392D971E76C05ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFA526F77A1986D76ULL,
		0xA1CC0A998DF2C6B3ULL,
		0xC03B44BEFAF4F006ULL,
		0xCE5FFFA78C62EEDBULL,
		0xE65D03A8F2E489D8ULL,
		0xABAF928423F56ABFULL,
		0x5E98D85A12775126ULL,
		0x3F2B091876358F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A4DEEF4330DAECULL,
		0x439815331BE58D67ULL,
		0x8076897DF5E9E00DULL,
		0x9CBFFF4F18C5DDB7ULL,
		0xCCBA0751E5C913B1ULL,
		0x575F250847EAD57FULL,
		0xBD31B0B424EEA24DULL,
		0x7E561230EC6B1ECCULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E76EFF3B7E9E81CULL,
		0xDB062C8246C2A571ULL,
		0x996661571CCFCF60ULL,
		0x479D3E236A1DDCA8ULL,
		0x1A450B2A4940D612ULL,
		0x84137D9A8D3445D3ULL,
		0x2DA9073CBE0B273FULL,
		0x0D86F3DF2DA794BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEDDFE76FD3D038ULL,
		0xB60C59048D854AE3ULL,
		0x32CCC2AE399F9EC1ULL,
		0x8F3A7C46D43BB951ULL,
		0x348A16549281AC24ULL,
		0x0826FB351A688BA6ULL,
		0x5B520E797C164E7FULL,
		0x1B0DE7BE5B4F297EULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6C69E311207D6D25ULL,
		0xD262EF39F876E823ULL,
		0x0013C36E8FE2C676ULL,
		0xDB154D40029DF372ULL,
		0x0AD1E9C6015EBF09ULL,
		0xD46094A1ACF22504ULL,
		0x51FFA1EF9F129695ULL,
		0x378A81165DC5159AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D3C62240FADA4AULL,
		0xA4C5DE73F0EDD046ULL,
		0x002786DD1FC58CEDULL,
		0xB62A9A80053BE6E4ULL,
		0x15A3D38C02BD7E13ULL,
		0xA8C1294359E44A08ULL,
		0xA3FF43DF3E252D2BULL,
		0x6F15022CBB8A2B34ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF50B6705A873E145ULL,
		0x6B566BC057E15C0EULL,
		0x0326A3494C9B6403ULL,
		0x0FC8CC92946183BCULL,
		0x3E9B26363FD17865ULL,
		0xCEE832DF72B327F1ULL,
		0x7412C220C43BB5B6ULL,
		0x284931FC8D863602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA16CE0B50E7C28AULL,
		0xD6ACD780AFC2B81DULL,
		0x064D46929936C806ULL,
		0x1F91992528C30778ULL,
		0x7D364C6C7FA2F0CAULL,
		0x9DD065BEE5664FE2ULL,
		0xE825844188776B6DULL,
		0x509263F91B0C6C04ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x143C7992094E81F6ULL,
		0xDA6C475AEA6AB9FEULL,
		0xCF2158D02C763337ULL,
		0x330B6BCCEBF15340ULL,
		0x7C367165985C59C3ULL,
		0xDF24142F8BF0B472ULL,
		0x8C6BECFD86000F2FULL,
		0x301286F145AD55B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2878F324129D03ECULL,
		0xB4D88EB5D4D573FCULL,
		0x9E42B1A058EC666FULL,
		0x6616D799D7E2A681ULL,
		0xF86CE2CB30B8B386ULL,
		0xBE48285F17E168E4ULL,
		0x18D7D9FB0C001E5FULL,
		0x60250DE28B5AAB71ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5C81CC8A147E3E01ULL,
		0x32DA381EAE587062ULL,
		0x64DF1BA2BD7FD117ULL,
		0x08A2BA4A010B1FFFULL,
		0x69AC64939CEC0A25ULL,
		0x3EB16AAE143C6BA8ULL,
		0x4C0D1CE38CEE18D9ULL,
		0x0292433DCAB61F6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB903991428FC7C02ULL,
		0x65B4703D5CB0E0C4ULL,
		0xC9BE37457AFFA22EULL,
		0x1145749402163FFEULL,
		0xD358C92739D8144AULL,
		0x7D62D55C2878D750ULL,
		0x981A39C719DC31B2ULL,
		0x0524867B956C3ED8ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDEC0D11E85FCE36BULL,
		0x750506EBA1C2E4D7ULL,
		0x25CAA7FC53F7C17EULL,
		0x7364B4C58A894E32ULL,
		0xE7B2B86A38F6FA0FULL,
		0x51937896AD815EB2ULL,
		0x1509E66E54CFB660ULL,
		0x33159EAAD2F97626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD81A23D0BF9C6D6ULL,
		0xEA0A0DD74385C9AFULL,
		0x4B954FF8A7EF82FCULL,
		0xE6C9698B15129C64ULL,
		0xCF6570D471EDF41EULL,
		0xA326F12D5B02BD65ULL,
		0x2A13CCDCA99F6CC0ULL,
		0x662B3D55A5F2EC4CULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1802DD4040977616ULL,
		0x605E02890B7EB5B6ULL,
		0x251146230C00504EULL,
		0x65965371B21E2F58ULL,
		0x7E46B028B64A8D05ULL,
		0x6F8802CAC9FCCF4FULL,
		0xB120778F03592148ULL,
		0x33BF9ECAD65C85C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3005BA80812EEC2CULL,
		0xC0BC051216FD6B6CULL,
		0x4A228C461800A09CULL,
		0xCB2CA6E3643C5EB0ULL,
		0xFC8D60516C951A0AULL,
		0xDF10059593F99E9EULL,
		0x6240EF1E06B24290ULL,
		0x677F3D95ACB90B8FULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7CA787D35457252ULL,
		0xB0EB2824F2A664B6ULL,
		0xC8377DFBBD6249DEULL,
		0x1126F1E550FE31A6ULL,
		0xCCC44BB4ED20BBFDULL,
		0xC7ACCB363A017E7DULL,
		0x60992C6E71C15999ULL,
		0x26A657F18041338FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF94F0FA6A8AE4A4ULL,
		0x61D65049E54CC96DULL,
		0x906EFBF77AC493BDULL,
		0x224DE3CAA1FC634DULL,
		0x99889769DA4177FAULL,
		0x8F59966C7402FCFBULL,
		0xC13258DCE382B333ULL,
		0x4D4CAFE30082671EULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDB7006B06D51C471ULL,
		0x9F95B39C1DF7480CULL,
		0xE8D2406A6615ADFCULL,
		0x24BCECAFBD73388CULL,
		0xAAD19A0A40CE3EE9ULL,
		0xC151C78F95E831B9ULL,
		0x64F777CC7731DF18ULL,
		0x256D6D05DE9CC674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E00D60DAA388E2ULL,
		0x3F2B67383BEE9019ULL,
		0xD1A480D4CC2B5BF9ULL,
		0x4979D95F7AE67119ULL,
		0x55A33414819C7DD2ULL,
		0x82A38F1F2BD06373ULL,
		0xC9EEEF98EE63BE31ULL,
		0x4ADADA0BBD398CE8ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x81E5BB8E5608462EULL,
		0x7E23419EC2DF84FEULL,
		0xB9D2880B54EC2B78ULL,
		0x0B25F7BE4FF48C38ULL,
		0xA7E3B998E44941E9ULL,
		0x4C04A39CD0C25B50ULL,
		0x325CDBC06703F155ULL,
		0x3CC527790D0E298FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03CB771CAC108C5CULL,
		0xFC46833D85BF09FDULL,
		0x73A51016A9D856F0ULL,
		0x164BEF7C9FE91871ULL,
		0x4FC77331C89283D2ULL,
		0x98094739A184B6A1ULL,
		0x64B9B780CE07E2AAULL,
		0x798A4EF21A1C531EULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x93A9BD34AE74E299ULL,
		0x97A9E3847FB7C381ULL,
		0x6D44BEAF746AA48BULL,
		0x5D526E3341810AC7ULL,
		0x57F8AF0A3D01C5C5ULL,
		0x1D824417E53A91E8ULL,
		0x58B682B6DB775A05ULL,
		0x1598411E0104CB12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27537A695CE9C532ULL,
		0x2F53C708FF6F8703ULL,
		0xDA897D5EE8D54917ULL,
		0xBAA4DC668302158EULL,
		0xAFF15E147A038B8AULL,
		0x3B04882FCA7523D0ULL,
		0xB16D056DB6EEB40AULL,
		0x2B30823C02099624ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDC59FC3185C78CB8ULL,
		0x0759D444647807F7ULL,
		0xC7608F84042A899FULL,
		0x9A45316889735D53ULL,
		0x67C3106C4A918B77ULL,
		0xA12659B4E7665453ULL,
		0xB76B179B00CAA314ULL,
		0x138B5E43C3CB4E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B3F8630B8F1970ULL,
		0x0EB3A888C8F00FEFULL,
		0x8EC11F080855133EULL,
		0x348A62D112E6BAA7ULL,
		0xCF8620D8952316EFULL,
		0x424CB369CECCA8A6ULL,
		0x6ED62F3601954629ULL,
		0x2716BC8787969C2BULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3089ABD3991A63AEULL,
		0x744A905940D3497DULL,
		0x4BEC06A357709EA4ULL,
		0x629E62E915F21D92ULL,
		0xD8F2F2A7E842716EULL,
		0xB15787ED8C8C0FC9ULL,
		0x7675B45D1B7C67FFULL,
		0x275E9581DAF9423FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x611357A73234C75CULL,
		0xE89520B281A692FAULL,
		0x97D80D46AEE13D48ULL,
		0xC53CC5D22BE43B24ULL,
		0xB1E5E54FD084E2DCULL,
		0x62AF0FDB19181F93ULL,
		0xECEB68BA36F8CFFFULL,
		0x4EBD2B03B5F2847EULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6262372FDED57C30ULL,
		0x1EB0C0567D40D285ULL,
		0x782FE239FEC11577ULL,
		0xA743EE961C482599ULL,
		0x0F8D028F75BEF4F7ULL,
		0xD36EBAE8543EFB22ULL,
		0x968C27F33318464EULL,
		0x230EBC941DACBD95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C46E5FBDAAF860ULL,
		0x3D6180ACFA81A50AULL,
		0xF05FC473FD822AEEULL,
		0x4E87DD2C38904B32ULL,
		0x1F1A051EEB7DE9EFULL,
		0xA6DD75D0A87DF644ULL,
		0x2D184FE666308C9DULL,
		0x461D79283B597B2BULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2ECC96C887C0278AULL,
		0x6C934DFEC7381FC7ULL,
		0x6EFD6B1CACD54A3EULL,
		0x97EB05388A10BCF6ULL,
		0x72009E626167C7FAULL,
		0x14C7E2F3828ECC52ULL,
		0x59933283E5373783ULL,
		0x23ACE0002992BCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D992D910F804F14ULL,
		0xD9269BFD8E703F8EULL,
		0xDDFAD63959AA947CULL,
		0x2FD60A71142179ECULL,
		0xE4013CC4C2CF8FF5ULL,
		0x298FC5E7051D98A4ULL,
		0xB3266507CA6E6F06ULL,
		0x4759C0005325794AULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC38EDCE86DAC9F30ULL,
		0x51B610770F990DE5ULL,
		0x7BB83985AAAB288BULL,
		0xEB7424F469ABEA3BULL,
		0xDC48F09195F20535ULL,
		0xC6EBF080399B4833ULL,
		0x35D688A55ABE2D0EULL,
		0x02174970E63C8316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x871DB9D0DB593E60ULL,
		0xA36C20EE1F321BCBULL,
		0xF770730B55565116ULL,
		0xD6E849E8D357D476ULL,
		0xB891E1232BE40A6BULL,
		0x8DD7E10073369067ULL,
		0x6BAD114AB57C5A1DULL,
		0x042E92E1CC79062CULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB7D73B85A5FF39E8ULL,
		0x0396BE96A9637F87ULL,
		0x99240072352A69B6ULL,
		0x46B9CDEBA1E47C85ULL,
		0x5313FA6872962C86ULL,
		0xD33435EBA38530E6ULL,
		0x9C934FFCC61794C5ULL,
		0x22DFB7B8F4B8D5F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FAE770B4BFE73D0ULL,
		0x072D7D2D52C6FF0FULL,
		0x324800E46A54D36CULL,
		0x8D739BD743C8F90BULL,
		0xA627F4D0E52C590CULL,
		0xA6686BD7470A61CCULL,
		0x39269FF98C2F298BULL,
		0x45BF6F71E971ABE9ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07893BCFD7610633ULL,
		0xB6D12532381471DAULL,
		0xDAA7894792ED0313ULL,
		0x9DCDDF724657844EULL,
		0xDB0AEA87F85D36E1ULL,
		0x4D37979B15316C0EULL,
		0xF3EED13514C755B0ULL,
		0x308781AAC177FA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F12779FAEC20C66ULL,
		0x6DA24A647028E3B4ULL,
		0xB54F128F25DA0627ULL,
		0x3B9BBEE48CAF089DULL,
		0xB615D50FF0BA6DC3ULL,
		0x9A6F2F362A62D81DULL,
		0xE7DDA26A298EAB60ULL,
		0x610F035582EFF477ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2E19087E67D3651BULL,
		0x995175CF1DA8310CULL,
		0x383947991A9382CCULL,
		0xD8BC6B7DB4DAA1B3ULL,
		0xCDF1B1B8E36F38CFULL,
		0x516DEF6AFA4542EEULL,
		0x46F0B394BB661884ULL,
		0x3ED31570B1458430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C3210FCCFA6CA36ULL,
		0x32A2EB9E3B506218ULL,
		0x70728F3235270599ULL,
		0xB178D6FB69B54366ULL,
		0x9BE36371C6DE719FULL,
		0xA2DBDED5F48A85DDULL,
		0x8DE1672976CC3108ULL,
		0x7DA62AE1628B0860ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4B0C8F16A98E1C4BULL,
		0x7329C89C84A06314ULL,
		0x136FA3FEFEE76DF9ULL,
		0xAE89280D5DCF0E27ULL,
		0xDAB45F2652EBB756ULL,
		0x5F2EED16104F7A05ULL,
		0x8C872D628B345389ULL,
		0x35B969BBDF8BAA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96191E2D531C3896ULL,
		0xE65391390940C628ULL,
		0x26DF47FDFDCEDBF2ULL,
		0x5D12501ABB9E1C4EULL,
		0xB568BE4CA5D76EADULL,
		0xBE5DDA2C209EF40BULL,
		0x190E5AC51668A712ULL,
		0x6B72D377BF17550BULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B4EA5D762B5694CULL,
		0x72F99013A7756FFCULL,
		0x36B142AECA6404C6ULL,
		0x26D05A4C940EC347ULL,
		0xBD88333BFBEF471DULL,
		0x4104675B7182321AULL,
		0x32BF6C08C004FA46ULL,
		0x066B8C1F8AFFA5C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x169D4BAEC56AD298ULL,
		0xE5F320274EEADFF8ULL,
		0x6D62855D94C8098CULL,
		0x4DA0B499281D868EULL,
		0x7B106677F7DE8E3AULL,
		0x8208CEB6E3046435ULL,
		0x657ED8118009F48CULL,
		0x0CD7183F15FF4B82ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD679054C514E516AULL,
		0xBED866155DFE9A1BULL,
		0x9DE8A783E38C1F5AULL,
		0x970829E90151E734ULL,
		0xD9AAC33797B7E8F2ULL,
		0xB87DAD1BB890E93CULL,
		0x83422EB299B48C72ULL,
		0x02DDCACA3B0C456CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF20A98A29CA2D4ULL,
		0x7DB0CC2ABBFD3437ULL,
		0x3BD14F07C7183EB5ULL,
		0x2E1053D202A3CE69ULL,
		0xB355866F2F6FD1E5ULL,
		0x70FB5A377121D279ULL,
		0x06845D65336918E5ULL,
		0x05BB959476188AD9ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB85B365EDE9060E2ULL,
		0x24976CB2298FE786ULL,
		0xF8178B70196D45B2ULL,
		0xDC6C4A4D4F97DD7FULL,
		0x3EE73A8A66196314ULL,
		0x00FA7847872C8B89ULL,
		0x6680C3699A880F7DULL,
		0x07E85F9421C93415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B66CBDBD20C1C4ULL,
		0x492ED964531FCF0DULL,
		0xF02F16E032DA8B64ULL,
		0xB8D8949A9F2FBAFFULL,
		0x7DCE7514CC32C629ULL,
		0x01F4F08F0E591712ULL,
		0xCD0186D335101EFAULL,
		0x0FD0BF284392682AULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x72A8B08841B2B9F9ULL,
		0xF54D340A6F5F00A2ULL,
		0x31AC67755B19C7B5ULL,
		0xE85AC8196746CCACULL,
		0x4F8986EF9C1C2B5EULL,
		0xE679D09F6FD89578ULL,
		0x1AFF4ECD586A6B06ULL,
		0x1215EE3DC5F0F02DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5516110836573F2ULL,
		0xEA9A6814DEBE0144ULL,
		0x6358CEEAB6338F6BULL,
		0xD0B59032CE8D9958ULL,
		0x9F130DDF383856BDULL,
		0xCCF3A13EDFB12AF0ULL,
		0x35FE9D9AB0D4D60DULL,
		0x242BDC7B8BE1E05AULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C5D108F2E709CBAULL,
		0x9E8369E32DE15B46ULL,
		0x13A5A60449DC39AEULL,
		0x87EBD0F6098301A7ULL,
		0xEA7ED7C4A2ADCE4DULL,
		0x8FBBF220BFBBCC23ULL,
		0x8A8E81B99690B916ULL,
		0x1A20E8F5FD140F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8BA211E5CE13974ULL,
		0x3D06D3C65BC2B68CULL,
		0x274B4C0893B8735DULL,
		0x0FD7A1EC1306034EULL,
		0xD4FDAF89455B9C9BULL,
		0x1F77E4417F779847ULL,
		0x151D03732D21722DULL,
		0x3441D1EBFA281F11ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8951509851CCD63EULL,
		0x02A459686DF9B5AFULL,
		0x7A1FF1F837F4712EULL,
		0x59AB05C0F4A4AC41ULL,
		0x79647B384C6B4C63ULL,
		0x3BB27098C5BF8F8CULL,
		0x543E99ED8C11AF0CULL,
		0x0D40A5064A904292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A2A130A399AC7CULL,
		0x0548B2D0DBF36B5FULL,
		0xF43FE3F06FE8E25CULL,
		0xB3560B81E9495882ULL,
		0xF2C8F67098D698C6ULL,
		0x7764E1318B7F1F18ULL,
		0xA87D33DB18235E18ULL,
		0x1A814A0C95208524ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCE95607B46204835ULL,
		0x8580C1EC3C5ACBA9ULL,
		0xCBBB565EAC6BAF5AULL,
		0x45B979979E7D0196ULL,
		0xF853640FB3023E69ULL,
		0x8CD450A6F5422C8CULL,
		0xECC542038311B865ULL,
		0x113D7E83855827D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2AC0F68C40906AULL,
		0x0B0183D878B59753ULL,
		0x9776ACBD58D75EB5ULL,
		0x8B72F32F3CFA032DULL,
		0xF0A6C81F66047CD2ULL,
		0x19A8A14DEA845919ULL,
		0xD98A8407062370CBULL,
		0x227AFD070AB04FA9ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDC4D50D8F6A6DF29ULL,
		0xDDDA218EAAE76775ULL,
		0xEB699AD8753FC511ULL,
		0xD6BE9CDB5F4D0241ULL,
		0x029A92A04599D388ULL,
		0xC4ECBC5A69DC6ECDULL,
		0xD84E114F8A964327ULL,
		0x38F4A799562B6FD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89AA1B1ED4DBE52ULL,
		0xBBB4431D55CECEEBULL,
		0xD6D335B0EA7F8A23ULL,
		0xAD7D39B6BE9A0483ULL,
		0x053525408B33A711ULL,
		0x89D978B4D3B8DD9AULL,
		0xB09C229F152C864FULL,
		0x71E94F32AC56DFA9ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x490E61B6F68DF4A0ULL,
		0xD2658C8B8CCFA989ULL,
		0x016B2401E4F121EAULL,
		0xE26044885F12FF84ULL,
		0xFC1EFD2EEAD86114ULL,
		0x46BCFA43FB3F536BULL,
		0x99A2FFBB6DACCA87ULL,
		0x3D73B82F45CFC905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x921CC36DED1BE940ULL,
		0xA4CB1917199F5312ULL,
		0x02D64803C9E243D5ULL,
		0xC4C08910BE25FF08ULL,
		0xF83DFA5DD5B0C229ULL,
		0x8D79F487F67EA6D7ULL,
		0x3345FF76DB59950EULL,
		0x7AE7705E8B9F920BULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FE879B2A36E2026ULL,
		0xC698E900A9105E93ULL,
		0xD37CA0080D3B62CFULL,
		0x34C38767322AF1D0ULL,
		0x70A536ABFEDDD2D0ULL,
		0x97052FAD6A13AF0AULL,
		0x9F0A08155BB3C533ULL,
		0x366B13ECBC20A92BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FD0F36546DC404CULL,
		0x8D31D2015220BD26ULL,
		0xA6F940101A76C59FULL,
		0x69870ECE6455E3A1ULL,
		0xE14A6D57FDBBA5A0ULL,
		0x2E0A5F5AD4275E14ULL,
		0x3E14102AB7678A67ULL,
		0x6CD627D978415257ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x89FE1105910DC7F6ULL,
		0xBC1A869C0A8EA2B7ULL,
		0x095B3E51C1320B3CULL,
		0x383E847E702109D7ULL,
		0xA6419A6CA476FEDDULL,
		0xF4C1747DBED6DBD7ULL,
		0x28B05B6EB24B5B71ULL,
		0x1BE2442123A26D0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13FC220B221B8FECULL,
		0x78350D38151D456FULL,
		0x12B67CA382641679ULL,
		0x707D08FCE04213AEULL,
		0x4C8334D948EDFDBAULL,
		0xE982E8FB7DADB7AFULL,
		0x5160B6DD6496B6E3ULL,
		0x37C488424744DA16ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6AE8318A360AE52DULL,
		0x336E6CE47986882CULL,
		0x73220DAA78F9D1E9ULL,
		0x81D5A6F8C330AB56ULL,
		0xE81FA5C9D9667BF3ULL,
		0xEDF32E69023F1620ULL,
		0x80EDE353DBE334ADULL,
		0x3DE93C61A6195D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D063146C15CA5AULL,
		0x66DCD9C8F30D1058ULL,
		0xE6441B54F1F3A3D2ULL,
		0x03AB4DF1866156ACULL,
		0xD03F4B93B2CCF7E7ULL,
		0xDBE65CD2047E2C41ULL,
		0x01DBC6A7B7C6695BULL,
		0x7BD278C34C32BB3DULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD8DB40C6E7D5B398ULL,
		0x28851DC1D83E696CULL,
		0xB8F6A1472659449AULL,
		0xC60D7BC79467F913ULL,
		0xDA997AAA12E80A7CULL,
		0xDF7BE662C90334B8ULL,
		0x6636F6977A31D244ULL,
		0x3943A9D2704BD1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B6818DCFAB6730ULL,
		0x510A3B83B07CD2D9ULL,
		0x71ED428E4CB28934ULL,
		0x8C1AF78F28CFF227ULL,
		0xB532F55425D014F9ULL,
		0xBEF7CCC592066971ULL,
		0xCC6DED2EF463A489ULL,
		0x728753A4E097A396ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD755EC26EBF61D79ULL,
		0x9AFFBA312F8FEB2AULL,
		0xA78AFC32E0146AC4ULL,
		0x92F0CEBBD333FB02ULL,
		0x91D7EFA7662B2AFFULL,
		0xF7F6A6C8DA1AF74EULL,
		0xB6A652EAB12F8182ULL,
		0x13201BC404557AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEABD84DD7EC3AF2ULL,
		0x35FF74625F1FD655ULL,
		0x4F15F865C028D589ULL,
		0x25E19D77A667F605ULL,
		0x23AFDF4ECC5655FFULL,
		0xEFED4D91B435EE9DULL,
		0x6D4CA5D5625F0305ULL,
		0x2640378808AAF561ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAF07F26E44C5AC1FULL,
		0x9D15CECB21C823C4ULL,
		0x789BA1214EFF15DCULL,
		0x418D54591DD0B617ULL,
		0xDC64C1812CDD854CULL,
		0x043934544A94DD39ULL,
		0xAC8001463B6A5A5DULL,
		0x2FB05B6065FFE45AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0FE4DC898B583EULL,
		0x3A2B9D9643904789ULL,
		0xF13742429DFE2BB9ULL,
		0x831AA8B23BA16C2EULL,
		0xB8C9830259BB0A98ULL,
		0x087268A89529BA73ULL,
		0x5900028C76D4B4BAULL,
		0x5F60B6C0CBFFC8B5ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB34F8F723F2C70E2ULL,
		0x8D48D6CB77CD0950ULL,
		0xAC6D80CD2B0A2300ULL,
		0x3BAD7C89C4149455ULL,
		0x3A2CCE817DDF32E7ULL,
		0x524E17D0279F7928ULL,
		0x950A1CFB5261F421ULL,
		0x36B18B35E4C5FAF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x669F1EE47E58E1C4ULL,
		0x1A91AD96EF9A12A1ULL,
		0x58DB019A56144601ULL,
		0x775AF913882928ABULL,
		0x74599D02FBBE65CEULL,
		0xA49C2FA04F3EF250ULL,
		0x2A1439F6A4C3E842ULL,
		0x6D63166BC98BF5F3ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5D851F2B7F4C2A56ULL,
		0x67243A729116BC6AULL,
		0x364D1D29B188D239ULL,
		0x67B3B4C748863E92ULL,
		0x883054C4F4B49549ULL,
		0x392A924A04E086A5ULL,
		0x7B11B4303EDD476BULL,
		0x2C376D249677EC3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0A3E56FE9854ACULL,
		0xCE4874E5222D78D4ULL,
		0x6C9A3A536311A472ULL,
		0xCF67698E910C7D24ULL,
		0x1060A989E9692A92ULL,
		0x7255249409C10D4BULL,
		0xF62368607DBA8ED6ULL,
		0x586EDA492CEFD87AULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A480BF395AB5440ULL,
		0xC4CA3B7C9CDFA8F8ULL,
		0x88F3F5B28DF2E203ULL,
		0x14CDD5F1FF1576D3ULL,
		0x40A0CE0778559C4BULL,
		0xF663C6CB941B0199ULL,
		0x614E574289D35F1CULL,
		0x2F2E8D2E0C363DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49017E72B56A880ULL,
		0x899476F939BF51F0ULL,
		0x11E7EB651BE5C407ULL,
		0x299BABE3FE2AEDA7ULL,
		0x81419C0EF0AB3896ULL,
		0xECC78D9728360332ULL,
		0xC29CAE8513A6BE39ULL,
		0x5E5D1A5C186C7B48ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C47142EE5B1D466ULL,
		0x4254EC2E58C19524ULL,
		0x560A739DEA737615ULL,
		0x0596084C7B12BA9FULL,
		0x23BE7FC0C74BF6A9ULL,
		0xE7FDEC4D15C7118AULL,
		0x58E124406B35ED68ULL,
		0x1C4946E298FF8A15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x188E285DCB63A8CCULL,
		0x84A9D85CB1832A49ULL,
		0xAC14E73BD4E6EC2AULL,
		0x0B2C1098F625753EULL,
		0x477CFF818E97ED52ULL,
		0xCFFBD89A2B8E2314ULL,
		0xB1C24880D66BDAD1ULL,
		0x38928DC531FF142AULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE26A973E864EFD3EULL,
		0x69DADD9B0BDA86E0ULL,
		0x3201BDCFDFACF269ULL,
		0x61BBC35597599AF5ULL,
		0x42CC425D525B31F4ULL,
		0x7B5E1DF99B45BEB4ULL,
		0x6BBB1E66DC681499ULL,
		0x33392519D1AC422AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4D52E7D0C9DFA7CULL,
		0xD3B5BB3617B50DC1ULL,
		0x64037B9FBF59E4D2ULL,
		0xC37786AB2EB335EAULL,
		0x859884BAA4B663E8ULL,
		0xF6BC3BF3368B7D68ULL,
		0xD7763CCDB8D02932ULL,
		0x66724A33A3588454ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4AC1F15094F7A053ULL,
		0x3C1045FE2DA9B7A2ULL,
		0x1E096F973564E7B2ULL,
		0x5B2398A77CA6D66EULL,
		0x988A0B372BADC762ULL,
		0x22A0E3A0FC129E28ULL,
		0x2B5757F5FB30DA1FULL,
		0x31C47B70D12D0AF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9583E2A129EF40A6ULL,
		0x78208BFC5B536F44ULL,
		0x3C12DF2E6AC9CF64ULL,
		0xB647314EF94DACDCULL,
		0x3114166E575B8EC4ULL,
		0x4541C741F8253C51ULL,
		0x56AEAFEBF661B43EULL,
		0x6388F6E1A25A15E2ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x295000E48F83C631ULL,
		0x94FDC02498D390CEULL,
		0xAAC69D2F1ED984F4ULL,
		0xE874C882F70C148BULL,
		0x868BDCDEC99262AEULL,
		0xCA8FCB58CDDBE3F0ULL,
		0xFC58EC9433B76D30ULL,
		0x044BEE0439309870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52A001C91F078C62ULL,
		0x29FB804931A7219CULL,
		0x558D3A5E3DB309E9ULL,
		0xD0E99105EE182917ULL,
		0x0D17B9BD9324C55DULL,
		0x951F96B19BB7C7E1ULL,
		0xF8B1D928676EDA61ULL,
		0x0897DC08726130E1ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6520AEED23F0C1E7ULL,
		0x3D7CD2C985433A29ULL,
		0x3B8F88CE2E1F5CB7ULL,
		0x64679E6CB4316719ULL,
		0xD9BBB4E99275FABBULL,
		0x8D2CB337041CC02DULL,
		0x5495CE2847F86DE4ULL,
		0x161527FD4736BA8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA415DDA47E183CEULL,
		0x7AF9A5930A867452ULL,
		0x771F119C5C3EB96EULL,
		0xC8CF3CD96862CE32ULL,
		0xB37769D324EBF576ULL,
		0x1A59666E0839805BULL,
		0xA92B9C508FF0DBC9ULL,
		0x2C2A4FFA8E6D7516ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x955B789397A8796CULL,
		0xBC6BC8C3231BE75DULL,
		0xA7AD4AEBD6BD1AA4ULL,
		0x7E0A2D0CF9B47733ULL,
		0xCAD8243662848F0AULL,
		0xE0C7656E57CB6DA4ULL,
		0x0175263AEE99EED4ULL,
		0x18B9DE89B5ED4CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB6F1272F50F2D8ULL,
		0x78D791864637CEBBULL,
		0x4F5A95D7AD7A3549ULL,
		0xFC145A19F368EE67ULL,
		0x95B0486CC5091E14ULL,
		0xC18ECADCAF96DB49ULL,
		0x02EA4C75DD33DDA9ULL,
		0x3173BD136BDA995AULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7F1AF6762B2B7FCAULL,
		0xF5B1A1919254B818ULL,
		0x46E423E5AB5FBA23ULL,
		0x282A92AA9E87DF35ULL,
		0x7C1211FB30CCC43EULL,
		0x3FED7D52151905CEULL,
		0x4286618F15F40E17ULL,
		0x1C56C849A71D0995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE35ECEC5656FF94ULL,
		0xEB63432324A97030ULL,
		0x8DC847CB56BF7447ULL,
		0x505525553D0FBE6AULL,
		0xF82423F66199887CULL,
		0x7FDAFAA42A320B9CULL,
		0x850CC31E2BE81C2EULL,
		0x38AD90934E3A132AULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x94AD633C259CB0CCULL,
		0xCF53A35CE2C6CE53ULL,
		0xD86CF4790723F48BULL,
		0x118E4B76EDA5AE15ULL,
		0x4BF0BBFEA587239FULL,
		0xF1B78488EA8C2DF3ULL,
		0x40A29FE6E1630EFCULL,
		0x25670B4E1A3B3291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x295AC6784B396198ULL,
		0x9EA746B9C58D9CA7ULL,
		0xB0D9E8F20E47E917ULL,
		0x231C96EDDB4B5C2BULL,
		0x97E177FD4B0E473EULL,
		0xE36F0911D5185BE6ULL,
		0x81453FCDC2C61DF9ULL,
		0x4ACE169C34766522ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A857F76DDF39313ULL,
		0x658581CF848BBF8AULL,
		0x667AC5385027B882ULL,
		0xC4CC31253208DDFDULL,
		0xCE5A4AA240A7A251ULL,
		0x2BAF2BD01853F137ULL,
		0x92D93B082FD5CDDDULL,
		0x35CB6AA6DBBAD6ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150AFEEDBBE72626ULL,
		0xCB0B039F09177F14ULL,
		0xCCF58A70A04F7104ULL,
		0x8998624A6411BBFAULL,
		0x9CB49544814F44A3ULL,
		0x575E57A030A7E26FULL,
		0x25B276105FAB9BBAULL,
		0x6B96D54DB775AD57ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA8A9E942A4181263ULL,
		0x20571CA45E6FAAA6ULL,
		0x5D8A0843A7EBD8A6ULL,
		0x3F1AABA399367D4AULL,
		0xEB383AE8F9B71E62ULL,
		0xE921081EBD93BF07ULL,
		0x1608E863F31A5C2CULL,
		0x01E54E6CD3483BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5153D285483024C6ULL,
		0x40AE3948BCDF554DULL,
		0xBB1410874FD7B14CULL,
		0x7E355747326CFA94ULL,
		0xD67075D1F36E3CC4ULL,
		0xD242103D7B277E0FULL,
		0x2C11D0C7E634B859ULL,
		0x03CA9CD9A69077B4ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB582BCA15C1BF87EULL,
		0x0476469B98D925C6ULL,
		0xEC310E186613AED4ULL,
		0x6CADBDF5D17D8FE3ULL,
		0x1623DB5BC95D8829ULL,
		0x6E5CB1AFBF8236D4ULL,
		0x5FA8FC106E2FF378ULL,
		0x0318DC876C1CC3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B057942B837F0FCULL,
		0x08EC8D3731B24B8DULL,
		0xD8621C30CC275DA8ULL,
		0xD95B7BEBA2FB1FC7ULL,
		0x2C47B6B792BB1052ULL,
		0xDCB9635F7F046DA8ULL,
		0xBF51F820DC5FE6F0ULL,
		0x0631B90ED8398788ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF900E11ADF03A4C9ULL,
		0xEE975C046C6CA39EULL,
		0x7CF95A47E5B8B5B0ULL,
		0x4E060B087CB57A8EULL,
		0xAF5AF355781100E1ULL,
		0x7D5D65E2F73EC69FULL,
		0x597377FA02BB8E29ULL,
		0x1D401ED76FC11D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF201C235BE074992ULL,
		0xDD2EB808D8D9473DULL,
		0xF9F2B48FCB716B61ULL,
		0x9C0C1610F96AF51CULL,
		0x5EB5E6AAF02201C2ULL,
		0xFABACBC5EE7D8D3FULL,
		0xB2E6EFF405771C52ULL,
		0x3A803DAEDF823A94ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x5CD3C3C8A0D24897ULL,
		0x92498554EF26AFE5ULL,
		0x81F3B35DEE1A79E2ULL,
		0xD31187FFFEBD1EE1ULL,
		0x3840A1AF5D84335CULL,
		0x32A769971595CDF0ULL,
		0x36F62C937C8811C3ULL,
		0x2859FBCE505F1CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A7879141A4912EULL,
		0x24930AA9DE4D5FCAULL,
		0x03E766BBDC34F3C5ULL,
		0xA6230FFFFD7A3DC3ULL,
		0x7081435EBB0866B9ULL,
		0x654ED32E2B2B9BE0ULL,
		0x6DEC5926F9102386ULL,
		0x50B3F79CA0BE39A8ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA20BE88FD1511118ULL,
		0x463D79194A95692EULL,
		0x24426661AF25F1CDULL,
		0xD10C8D03DAC9C512ULL,
		0x68217DEB49C97638ULL,
		0x6664361E5F6FAB8CULL,
		0x5BC05D262517A6C3ULL,
		0x24A0AF52A19D6A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4417D11FA2A22230ULL,
		0x8C7AF232952AD25DULL,
		0x4884CCC35E4BE39AULL,
		0xA2191A07B5938A24ULL,
		0xD042FBD69392EC71ULL,
		0xCCC86C3CBEDF5718ULL,
		0xB780BA4C4A2F4D86ULL,
		0x49415EA5433AD4A0ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4D891E6179980B6CULL,
		0xDFB25E456439C8AEULL,
		0xA7126E1C12391461ULL,
		0x7922420D839BBB37ULL,
		0x8CA6D92439C5B1D8ULL,
		0x5CE5D5060048B7ABULL,
		0x8A465695A1FC4A78ULL,
		0x32C183E49A55CE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B123CC2F33016D8ULL,
		0xBF64BC8AC873915CULL,
		0x4E24DC38247228C3ULL,
		0xF244841B0737766FULL,
		0x194DB248738B63B0ULL,
		0xB9CBAA0C00916F57ULL,
		0x148CAD2B43F894F0ULL,
		0x658307C934AB9D13ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB571B632C86EE757ULL,
		0xBC6423F1B01F6162ULL,
		0xBB2B2C2CF0F3F640ULL,
		0x9BCD446020D76F39ULL,
		0xAA1F2AD56FCE0604ULL,
		0xFD3BACCB1E185FDCULL,
		0x990CF506B8ECF766ULL,
		0x37176DCCC3CEABCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE36C6590DDCEAEULL,
		0x78C847E3603EC2C5ULL,
		0x76565859E1E7EC81ULL,
		0x379A88C041AEDE73ULL,
		0x543E55AADF9C0C09ULL,
		0xFA7759963C30BFB9ULL,
		0x3219EA0D71D9EECDULL,
		0x6E2EDB99879D5795ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD532E4CC91967628ULL,
		0x3BA5F79EA2F3896DULL,
		0x314FA9BAACD276E8ULL,
		0xEE05F10EA22F906CULL,
		0x42719AF838E29065ULL,
		0x82C76DE1A135DF76ULL,
		0xAA9507CCA9F53180ULL,
		0x052F6E4F43BB1D0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA65C999232CEC50ULL,
		0x774BEF3D45E712DBULL,
		0x629F537559A4EDD0ULL,
		0xDC0BE21D445F20D8ULL,
		0x84E335F071C520CBULL,
		0x058EDBC3426BBEECULL,
		0x552A0F9953EA6301ULL,
		0x0A5EDC9E87763A19ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x82FE346351AF0B3AULL,
		0xAC2C14ED0024BFF4ULL,
		0xD60494051709E5E6ULL,
		0xD0D552EF2A8A30DBULL,
		0xE095BCAE8DC44AB9ULL,
		0x4B31C0A6E2A78325ULL,
		0xB7C9BD990A6C7F8BULL,
		0x00FE1D5786C7ABD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05FC68C6A35E1674ULL,
		0x585829DA00497FE9ULL,
		0xAC09280A2E13CBCDULL,
		0xA1AAA5DE551461B7ULL,
		0xC12B795D1B889573ULL,
		0x9663814DC54F064BULL,
		0x6F937B3214D8FF16ULL,
		0x01FC3AAF0D8F57ABULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFAD217EEB1874BB5ULL,
		0x06BE3360B1ABE0B9ULL,
		0xF4336D117DA80EB8ULL,
		0x62D12336812FF4D4ULL,
		0x316477244BA1CBA7ULL,
		0xB5318E2367BEBC38ULL,
		0x6A54270C2D105BEDULL,
		0x083AB4E5A2AAAAC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A42FDD630E976AULL,
		0x0D7C66C16357C173ULL,
		0xE866DA22FB501D70ULL,
		0xC5A2466D025FE9A9ULL,
		0x62C8EE489743974EULL,
		0x6A631C46CF7D7870ULL,
		0xD4A84E185A20B7DBULL,
		0x107569CB45555580ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4BA3BB1D423AE336ULL,
		0x554193E29F179662ULL,
		0xBEFD872696A74C2EULL,
		0x88185D4E94F46D84ULL,
		0xBD4E30BB09449133ULL,
		0x2FAAB22F8405571EULL,
		0xA7C4689EC81FA8DAULL,
		0x2C37BA94357F2188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9747763A8475C66CULL,
		0xAA8327C53E2F2CC4ULL,
		0x7DFB0E4D2D4E985CULL,
		0x1030BA9D29E8DB09ULL,
		0x7A9C617612892267ULL,
		0x5F55645F080AAE3DULL,
		0x4F88D13D903F51B4ULL,
		0x586F75286AFE4311ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x26A044606063F09CULL,
		0xE557203CC106AD76ULL,
		0x823C65A80F1C50A5ULL,
		0x67B321EE9794710FULL,
		0x18774402385B9D06ULL,
		0x0247A13E7AB53B6AULL,
		0x5127A3B2768BA4BCULL,
		0x3167B6AFD7250E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4088C0C0C7E138ULL,
		0xCAAE4079820D5AECULL,
		0x0478CB501E38A14BULL,
		0xCF6643DD2F28E21FULL,
		0x30EE880470B73A0CULL,
		0x048F427CF56A76D4ULL,
		0xA24F4764ED174978ULL,
		0x62CF6D5FAE4A1D06ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF3A797EBC6178760ULL,
		0x94FBB27A8C24D16CULL,
		0x7B788A1E44386551ULL,
		0x72A8F9D36717DCB1ULL,
		0x2B35414508B6FA23ULL,
		0x19EE5866CD58034EULL,
		0x2F8157C6DF562744ULL,
		0x3BD010EACC22606FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74F2FD78C2F0EC0ULL,
		0x29F764F51849A2D9ULL,
		0xF6F1143C8870CAA3ULL,
		0xE551F3A6CE2FB962ULL,
		0x566A828A116DF446ULL,
		0x33DCB0CD9AB0069CULL,
		0x5F02AF8DBEAC4E88ULL,
		0x77A021D59844C0DEULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8C6F08B6A9E2095FULL,
		0x9219DF757F827BACULL,
		0x9884C670B1EAD8D8ULL,
		0x2C1324C02E5BBDEDULL,
		0x9D74D1AE439D16E6ULL,
		0xC702F377D544608CULL,
		0xDA3978F35039728BULL,
		0x2FB124EE70340185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DE116D53C412BEULL,
		0x2433BEEAFF04F759ULL,
		0x31098CE163D5B1B1ULL,
		0x582649805CB77BDBULL,
		0x3AE9A35C873A2DCCULL,
		0x8E05E6EFAA88C119ULL,
		0xB472F1E6A072E517ULL,
		0x5F6249DCE068030BULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9179BEE016768607ULL,
		0x6A090D1A2A9362FCULL,
		0xBA625068C98083BBULL,
		0x5F897F772C3E7495ULL,
		0xE255F37ABD25C631ULL,
		0x7E03ABE9057E700FULL,
		0x44BBF3F7A8F58276ULL,
		0x04B4E8274CD7F1BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22F37DC02CED0C0EULL,
		0xD4121A345526C5F9ULL,
		0x74C4A0D193010776ULL,
		0xBF12FEEE587CE92BULL,
		0xC4ABE6F57A4B8C62ULL,
		0xFC0757D20AFCE01FULL,
		0x8977E7EF51EB04ECULL,
		0x0969D04E99AFE37EULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE2EF120098A94013ULL,
		0x376CA393FAB2235FULL,
		0xC5DF2579EE940F22ULL,
		0xE503BC7C7DBA002FULL,
		0xDA553EA794536E8FULL,
		0x4FF7D20D0E24E4DEULL,
		0xB75E200B558A7308ULL,
		0x1DFA489488F54535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5DE240131528026ULL,
		0x6ED94727F56446BFULL,
		0x8BBE4AF3DD281E44ULL,
		0xCA0778F8FB74005FULL,
		0xB4AA7D4F28A6DD1FULL,
		0x9FEFA41A1C49C9BDULL,
		0x6EBC4016AB14E610ULL,
		0x3BF4912911EA8A6BULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4726B9DC7E27C2F6ULL,
		0xDAC3E4159EE8C15EULL,
		0x14446DB7A6DB3EDAULL,
		0x8B38B1AABA4C25FDULL,
		0x80F1E53916BF97F2ULL,
		0x240F753F5A854206ULL,
		0x1B9DF491C2F1FD32ULL,
		0x381F39BF80440ED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E4D73B8FC4F85ECULL,
		0xB587C82B3DD182BCULL,
		0x2888DB6F4DB67DB5ULL,
		0x1671635574984BFAULL,
		0x01E3CA722D7F2FE5ULL,
		0x481EEA7EB50A840DULL,
		0x373BE92385E3FA64ULL,
		0x703E737F00881DACULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD833F39ECEF2DA7CULL,
		0xAF5E61DD64FFD6CBULL,
		0xFD5CBBCF523B4A0DULL,
		0x5E36535CF3F3A926ULL,
		0x343F3EB95A49CF43ULL,
		0x65392E3E63C85CBAULL,
		0x6688F4AC0A85D3EFULL,
		0x20CC26BE3A1FA65CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB067E73D9DE5B4F8ULL,
		0x5EBCC3BAC9FFAD97ULL,
		0xFAB9779EA476941BULL,
		0xBC6CA6B9E7E7524DULL,
		0x687E7D72B4939E86ULL,
		0xCA725C7CC790B974ULL,
		0xCD11E958150BA7DEULL,
		0x41984D7C743F4CB8ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2730BBD9C34618D9ULL,
		0x23532AF1D0317762ULL,
		0x1BBBCE21F3E5B7E5ULL,
		0xA304F3D1984033F3ULL,
		0xC9DDBC39263A3A7BULL,
		0x67DC6CE4108D1523ULL,
		0xDBBBA97874158AFFULL,
		0x3B54C4366C288D15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E6177B3868C31B2ULL,
		0x46A655E3A062EEC4ULL,
		0x37779C43E7CB6FCAULL,
		0x4609E7A3308067E6ULL,
		0x93BB78724C7474F7ULL,
		0xCFB8D9C8211A2A47ULL,
		0xB77752F0E82B15FEULL,
		0x76A9886CD8511A2BULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x77D25D6C390973F8ULL,
		0xE6670075B1DB82E0ULL,
		0x6CE324D158CA1EF9ULL,
		0x472B0C9BA8DD9F6DULL,
		0x6B1997CA22B607F6ULL,
		0xAFF9115F59F1A180ULL,
		0x0715CB9AEE9B524CULL,
		0x1A363F1CE7908C93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFA4BAD87212E7F0ULL,
		0xCCCE00EB63B705C0ULL,
		0xD9C649A2B1943DF3ULL,
		0x8E56193751BB3EDAULL,
		0xD6332F94456C0FECULL,
		0x5FF222BEB3E34300ULL,
		0x0E2B9735DD36A499ULL,
		0x346C7E39CF211926ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA573FDD48B7C3261ULL,
		0xC9FE8B913A5AEB4EULL,
		0x34B3F120A4181485ULL,
		0xC862687C804216F0ULL,
		0x31E3B4A6EB1BA43DULL,
		0x098EDB2BD9905801ULL,
		0x3400A4E1F587D053ULL,
		0x09BF32777E0FB321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE7FBA916F864C2ULL,
		0x93FD172274B5D69DULL,
		0x6967E2414830290BULL,
		0x90C4D0F900842DE0ULL,
		0x63C7694DD637487BULL,
		0x131DB657B320B002ULL,
		0x680149C3EB0FA0A6ULL,
		0x137E64EEFC1F6642ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD333805E96E2D9D9ULL,
		0x79BBBCA3BC5AEAE2ULL,
		0xB78F7356C95E6935ULL,
		0x8D4824B4C0ACECFEULL,
		0x1660D371156F1573ULL,
		0xBCEE0D49141386F4ULL,
		0x83CA6951C28C2DA5ULL,
		0x1299AD7F8D3F26F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA66700BD2DC5B3B2ULL,
		0xF377794778B5D5C5ULL,
		0x6F1EE6AD92BCD26AULL,
		0x1A9049698159D9FDULL,
		0x2CC1A6E22ADE2AE7ULL,
		0x79DC1A9228270DE8ULL,
		0x0794D2A385185B4BULL,
		0x25335AFF1A7E4DE7ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCF516B3CA0399513ULL,
		0x282F81ABB26EA0C7ULL,
		0x41517086A11F5611ULL,
		0x3ABAF56A3E85493FULL,
		0x4E8E9E22E6313CF6ULL,
		0xD8866991F829587FULL,
		0x558EC4DECE9DCF0DULL,
		0x18C97341EF61E049ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA2D67940732A26ULL,
		0x505F035764DD418FULL,
		0x82A2E10D423EAC22ULL,
		0x7575EAD47D0A927EULL,
		0x9D1D3C45CC6279ECULL,
		0xB10CD323F052B0FEULL,
		0xAB1D89BD9D3B9E1BULL,
		0x3192E683DEC3C092ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8A2A07C139BBC79DULL,
		0xB4ACF8D4908A4C5CULL,
		0x246DEC85AB8B5389ULL,
		0xD86EBCD5F8C21BB0ULL,
		0x92D972BE79EFF001ULL,
		0xF8CD5316A0B5FC65ULL,
		0x6BA60132A7BD3E6FULL,
		0x3FD79190EB0F3352ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14540F8273778F3AULL,
		0x6959F1A9211498B9ULL,
		0x48DBD90B5716A713ULL,
		0xB0DD79ABF1843760ULL,
		0x25B2E57CF3DFE003ULL,
		0xF19AA62D416BF8CBULL,
		0xD74C02654F7A7CDFULL,
		0x7FAF2321D61E66A4ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB47FF804569DAF46ULL,
		0xB30538FF7307E1D5ULL,
		0x96D67A976E36A945ULL,
		0xEA37B0A096CBC26BULL,
		0x53563659BB3DF419ULL,
		0x3C5E4A111220FE1EULL,
		0xC4B6F59E8F34DA61ULL,
		0x34157702E2181B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FFF008AD3B5E8CULL,
		0x660A71FEE60FC3ABULL,
		0x2DACF52EDC6D528BULL,
		0xD46F61412D9784D7ULL,
		0xA6AC6CB3767BE833ULL,
		0x78BC94222441FC3CULL,
		0x896DEB3D1E69B4C2ULL,
		0x682AEE05C430361DULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2020C4FB3238FDD8ULL,
		0x5B59C77246EDED53ULL,
		0xC4543A45657E9F36ULL,
		0x620B7A531FDB9F15ULL,
		0x2B869BA68A8E23A4ULL,
		0xE9D9FA8B1060C989ULL,
		0xC4A4E07CB5E62007ULL,
		0x0A60891A01C6460EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x404189F66471FBB0ULL,
		0xB6B38EE48DDBDAA6ULL,
		0x88A8748ACAFD3E6CULL,
		0xC416F4A63FB73E2BULL,
		0x570D374D151C4748ULL,
		0xD3B3F51620C19312ULL,
		0x8949C0F96BCC400FULL,
		0x14C11234038C8C1DULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD629A3D259E8D1DFULL,
		0x38B0033866576708ULL,
		0xB2BCFEBB62190DC7ULL,
		0x73B7460626613041ULL,
		0xE15AFFECCD46F8DDULL,
		0xBB65281D97F00EA8ULL,
		0xAB93586704A99358ULL,
		0x2EF09A6D384528DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5347A4B3D1A3BEULL,
		0x71600670CCAECE11ULL,
		0x6579FD76C4321B8EULL,
		0xE76E8C0C4CC26083ULL,
		0xC2B5FFD99A8DF1BAULL,
		0x76CA503B2FE01D51ULL,
		0x5726B0CE095326B1ULL,
		0x5DE134DA708A51B9ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A3B0631A13138B3ULL,
		0x8F9D64A1AC6FB8A6ULL,
		0xFAAC5C4F84917FABULL,
		0x592CC56818975C67ULL,
		0xFD6D208753EA942EULL,
		0x4D2E3C1F3EE4511CULL,
		0xDF26F3F095C85654ULL,
		0x0E087991CC6D1097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14760C6342627166ULL,
		0x1F3AC94358DF714CULL,
		0xF558B89F0922FF57ULL,
		0xB2598AD0312EB8CFULL,
		0xFADA410EA7D5285CULL,
		0x9A5C783E7DC8A239ULL,
		0xBE4DE7E12B90ACA8ULL,
		0x1C10F32398DA212FULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7D4C670C432E1F5AULL,
		0x98D4EE42313AED58ULL,
		0xACA98CA20E2B3DE9ULL,
		0xCF6E1A7BF72A9407ULL,
		0xF3DC90AAC3C5902CULL,
		0x05FBAC21BC29DCD6ULL,
		0x8258085F8AC20125ULL,
		0x067C1788E02E49F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA98CE18865C3EB4ULL,
		0x31A9DC846275DAB0ULL,
		0x595319441C567BD3ULL,
		0x9EDC34F7EE55280FULL,
		0xE7B92155878B2059ULL,
		0x0BF758437853B9ADULL,
		0x04B010BF1584024AULL,
		0x0CF82F11C05C93E3ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD735FF1CF8FA1CAULL,
		0xB3B557AB6E7DAB11ULL,
		0x0DF02ACD115FA4ABULL,
		0xB64C18F260426EB9ULL,
		0xAE5AA358B5E47FA0ULL,
		0xF4209027414BC94EULL,
		0xAF0A0EC830EB9289ULL,
		0x196DC712621DB1BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AE6BFE39F1F4394ULL,
		0x676AAF56DCFB5623ULL,
		0x1BE0559A22BF4957ULL,
		0x6C9831E4C084DD72ULL,
		0x5CB546B16BC8FF41ULL,
		0xE841204E8297929DULL,
		0x5E141D9061D72513ULL,
		0x32DB8E24C43B637BULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE8270CC20FA0F86BULL,
		0x9FA45C920D954E51ULL,
		0x9A0273C0CB79594DULL,
		0x6E9293B57F9AA197ULL,
		0x04D449AF81CDCFCBULL,
		0x8A3402428D82365DULL,
		0x0F1889F4051A9436ULL,
		0x259163C2A5BD86F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD04E19841F41F0D6ULL,
		0x3F48B9241B2A9CA3ULL,
		0x3404E78196F2B29BULL,
		0xDD25276AFF35432FULL,
		0x09A8935F039B9F96ULL,
		0x146804851B046CBAULL,
		0x1E3113E80A35286DULL,
		0x4B22C7854B7B0DE6ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6FD3A7F1BDAC3686ULL,
		0x3CF331F4D39F05F9ULL,
		0xEEBE96435CDDAE8BULL,
		0x71495DA96B65D18EULL,
		0x5CF5A2DCC25BA4F9ULL,
		0xA08275B929CFD3FCULL,
		0x6481834128CD4E88ULL,
		0x11202384CFF1D76BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA74FE37B586D0CULL,
		0x79E663E9A73E0BF2ULL,
		0xDD7D2C86B9BB5D16ULL,
		0xE292BB52D6CBA31DULL,
		0xB9EB45B984B749F2ULL,
		0x4104EB72539FA7F8ULL,
		0xC9030682519A9D11ULL,
		0x224047099FE3AED6ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFCD1798BB5E04986ULL,
		0x8AA667149556869EULL,
		0xD68163AD713B3F11ULL,
		0x3FBEF73E4439CDDCULL,
		0xC9E03E0DBA69959FULL,
		0x5DF64221B4F916E3ULL,
		0xA16D8A863CEC67E5ULL,
		0x2452054069F05524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A2F3176BC0930CULL,
		0x154CCE292AAD0D3DULL,
		0xAD02C75AE2767E23ULL,
		0x7F7DEE7C88739BB9ULL,
		0x93C07C1B74D32B3EULL,
		0xBBEC844369F22DC7ULL,
		0x42DB150C79D8CFCAULL,
		0x48A40A80D3E0AA49ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x279D780534B26EABULL,
		0x329235760F41BE12ULL,
		0xD7C00A8B4A6C6C4CULL,
		0x4974D73AB09FBC0DULL,
		0xDAF94A27A186617FULL,
		0x9DD8CD83B925466CULL,
		0x4644E07365759D10ULL,
		0x38E4A102A4D0F9F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3AF00A6964DD56ULL,
		0x65246AEC1E837C24ULL,
		0xAF80151694D8D898ULL,
		0x92E9AE75613F781BULL,
		0xB5F2944F430CC2FEULL,
		0x3BB19B07724A8CD9ULL,
		0x8C89C0E6CAEB3A21ULL,
		0x71C9420549A1F3F2ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA530B88E498CCAAEULL,
		0x6DEFEC5DFEBE07EBULL,
		0xB74D48414292FB33ULL,
		0x6951C1440678068AULL,
		0xB63C337A4AAF2E24ULL,
		0x82B984D846D91EECULL,
		0xE07F8710A88A1E3AULL,
		0x1ECE3F0F0BE6C780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A61711C9319955CULL,
		0xDBDFD8BBFD7C0FD7ULL,
		0x6E9A90828525F666ULL,
		0xD2A382880CF00D15ULL,
		0x6C7866F4955E5C48ULL,
		0x057309B08DB23DD9ULL,
		0xC0FF0E2151143C75ULL,
		0x3D9C7E1E17CD8F01ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3DC3C596871E7784ULL,
		0xD2EE3F9FB7C29F76ULL,
		0xC14851C07FF55AEFULL,
		0x8C5C7B6061D05737ULL,
		0x28967F5BD6DB4043ULL,
		0x5E57B184AA7B235EULL,
		0xFF88797941836C7AULL,
		0x0AE27B595730A3F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B878B2D0E3CEF08ULL,
		0xA5DC7F3F6F853EECULL,
		0x8290A380FFEAB5DFULL,
		0x18B8F6C0C3A0AE6FULL,
		0x512CFEB7ADB68087ULL,
		0xBCAF630954F646BCULL,
		0xFF10F2F28306D8F4ULL,
		0x15C4F6B2AE6147E1ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x07164B7FD7C1648BULL,
		0x7C0B5765D02E951BULL,
		0x75A2487E46B19023ULL,
		0x84CDCF6AAFA0C418ULL,
		0xDDA604FA5D28B86EULL,
		0x97817DAF01EB9FE3ULL,
		0x2EE3E964D314C853ULL,
		0x17638AA52B626258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E2C96FFAF82C916ULL,
		0xF816AECBA05D2A36ULL,
		0xEB4490FC8D632046ULL,
		0x099B9ED55F418830ULL,
		0xBB4C09F4BA5170DDULL,
		0x2F02FB5E03D73FC7ULL,
		0x5DC7D2C9A62990A7ULL,
		0x2EC7154A56C4C4B0ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4FC28B90B402AF3FULL,
		0x325D9A4C43142D4FULL,
		0xC87DCDDF11F38DCFULL,
		0xE4BFF8BB0CEC940EULL,
		0xA288528ABCF7DEA2ULL,
		0xC1EF6C534EA1891DULL,
		0x58E2A8F60E5363FBULL,
		0x07AF7EF63B14528EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F85172168055E7EULL,
		0x64BB349886285A9EULL,
		0x90FB9BBE23E71B9EULL,
		0xC97FF17619D9281DULL,
		0x4510A51579EFBD45ULL,
		0x83DED8A69D43123BULL,
		0xB1C551EC1CA6C7F7ULL,
		0x0F5EFDEC7628A51CULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBFD8C133340428B8ULL,
		0x9DDB9E5B1CC79B70ULL,
		0xADF9165C6E165C04ULL,
		0x8CC154C4BAB9EA52ULL,
		0xB60A590A5C6439A1ULL,
		0x5470F1972FABA8D3ULL,
		0x53C37A4D04D214AEULL,
		0x0F8AE4B57DBEE100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FB1826668085170ULL,
		0x3BB73CB6398F36E1ULL,
		0x5BF22CB8DC2CB809ULL,
		0x1982A9897573D4A5ULL,
		0x6C14B214B8C87343ULL,
		0xA8E1E32E5F5751A7ULL,
		0xA786F49A09A4295CULL,
		0x1F15C96AFB7DC200ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0E07469EEDD24673ULL,
		0x38EF878A3D45B41FULL,
		0x38B5BE866977B17EULL,
		0xAFEBC91DFEFA5021ULL,
		0x777DA084B5892FA1ULL,
		0x087CDEA492DECACDULL,
		0x0FCE89E6BF07457FULL,
		0x14F099DE14CB992DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0E8D3DDBA48CE6ULL,
		0x71DF0F147A8B683EULL,
		0x716B7D0CD2EF62FCULL,
		0x5FD7923BFDF4A042ULL,
		0xEEFB41096B125F43ULL,
		0x10F9BD4925BD959AULL,
		0x1F9D13CD7E0E8AFEULL,
		0x29E133BC2997325AULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x239EB36024E5C0CCULL,
		0xCA4D7A9EDA585ADCULL,
		0x1D611C52C83C7BDDULL,
		0xD3D8E108E02C06B9ULL,
		0x24B8A424CEECCF4FULL,
		0x0610F7F8DFBF3418ULL,
		0x573B977268C0D4F7ULL,
		0x3D83F4DFD3D5EBF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x473D66C049CB8198ULL,
		0x949AF53DB4B0B5B8ULL,
		0x3AC238A59078F7BBULL,
		0xA7B1C211C0580D72ULL,
		0x497148499DD99E9FULL,
		0x0C21EFF1BF7E6830ULL,
		0xAE772EE4D181A9EEULL,
		0x7B07E9BFA7ABD7E6ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC6784A5191F2B89BULL,
		0x8FB240FC2739B51BULL,
		0x3D4D66FF9B43FC93ULL,
		0x5B2D0B3F05AB9F61ULL,
		0xAB298C69BCD32151ULL,
		0xFFE3ACE6BBBD4DD6ULL,
		0x4878E366AF3DED40ULL,
		0x2871ADA3D234D8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF094A323E57136ULL,
		0x1F6481F84E736A37ULL,
		0x7A9ACDFF3687F927ULL,
		0xB65A167E0B573EC2ULL,
		0x565318D379A642A2ULL,
		0xFFC759CD777A9BADULL,
		0x90F1C6CD5E7BDA81ULL,
		0x50E35B47A469B1BCULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBB574E4F2AC219F7ULL,
		0xACBA1C8D57545CF8ULL,
		0x2C2D2B3A8D0DFACCULL,
		0xD263E0ECE4BF914CULL,
		0xC568ACD49CC69AA6ULL,
		0xDE345D29EAE0EC07ULL,
		0x5EE470C4ECF11B3FULL,
		0x1A7F0BC17EE02917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76AE9C9E558433EEULL,
		0x5974391AAEA8B9F1ULL,
		0x585A56751A1BF599ULL,
		0xA4C7C1D9C97F2298ULL,
		0x8AD159A9398D354DULL,
		0xBC68BA53D5C1D80FULL,
		0xBDC8E189D9E2367FULL,
		0x34FE1782FDC0522EULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD0896D94BE6B135CULL,
		0x70B1B74E7281D535ULL,
		0xB9190F182043E20CULL,
		0x0874D50D0186A2CEULL,
		0xE39D70ECDF98F566ULL,
		0x5BBCF2752D156827ULL,
		0x38578E9B064A0C7EULL,
		0x2A5BFFBB85BBB834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA112DB297CD626B8ULL,
		0xE1636E9CE503AA6BULL,
		0x72321E304087C418ULL,
		0x10E9AA1A030D459DULL,
		0xC73AE1D9BF31EACCULL,
		0xB779E4EA5A2AD04FULL,
		0x70AF1D360C9418FCULL,
		0x54B7FF770B777068ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCC9ECF842E94C8EEULL,
		0x1DD56D41DA439A6BULL,
		0x8D412285AE9D9FC9ULL,
		0x7A91E2A378B67A34ULL,
		0x282D76AFC3F239FAULL,
		0x5E72E8E7C48575EFULL,
		0x8B97C6D6F0F19AEDULL,
		0x0DC2DD974F2959EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993D9F085D2991DCULL,
		0x3BAADA83B48734D7ULL,
		0x1A82450B5D3B3F92ULL,
		0xF523C546F16CF469ULL,
		0x505AED5F87E473F4ULL,
		0xBCE5D1CF890AEBDEULL,
		0x172F8DADE1E335DAULL,
		0x1B85BB2E9E52B3DBULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x05397120A9C33475ULL,
		0x8962C38BFDDA7ED3ULL,
		0xD5FA23AF1428D4B5ULL,
		0x43D5FA7216FE5BB7ULL,
		0x44A0379BF27505D8ULL,
		0x8B9D7A2F3F55C6ACULL,
		0xC3091DD817C57DBBULL,
		0x21042A245FD5A3BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A72E241538668EAULL,
		0x12C58717FBB4FDA6ULL,
		0xABF4475E2851A96BULL,
		0x87ABF4E42DFCB76FULL,
		0x89406F37E4EA0BB0ULL,
		0x173AF45E7EAB8D58ULL,
		0x86123BB02F8AFB77ULL,
		0x42085448BFAB477FULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0293B5D2520F536BULL,
		0xA5B9C3376F3D0584ULL,
		0xE81589343E6916D8ULL,
		0x0F628FA0026074EBULL,
		0x10509AD2E89AB019ULL,
		0x01B46BD6D0433E69ULL,
		0x6CDEDE9BFFB8DD6FULL,
		0x0EA96767DD969871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05276BA4A41EA6D6ULL,
		0x4B73866EDE7A0B08ULL,
		0xD02B12687CD22DB1ULL,
		0x1EC51F4004C0E9D7ULL,
		0x20A135A5D1356032ULL,
		0x0368D7ADA0867CD2ULL,
		0xD9BDBD37FF71BADEULL,
		0x1D52CECFBB2D30E2ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE472A1B3AEAFB618ULL,
		0x230F9256B52D7A6AULL,
		0x1E9A9B188F19B6AFULL,
		0xC73BDEB4CC9C8D18ULL,
		0x7E5F337B37CAF00CULL,
		0xCAA6013FF19C08B5ULL,
		0x24E5BD2E1A658AF5ULL,
		0x092127B31C8B4A0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E543675D5F6C30ULL,
		0x461F24AD6A5AF4D5ULL,
		0x3D3536311E336D5EULL,
		0x8E77BD6999391A30ULL,
		0xFCBE66F66F95E019ULL,
		0x954C027FE338116AULL,
		0x49CB7A5C34CB15EBULL,
		0x12424F663916941CULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B44F5FC49E3A3B7ULL,
		0xF3BB4D03742CA942ULL,
		0x38F4D9F67433D4C9ULL,
		0x192970BA0D62DC76ULL,
		0x446A1125B667DDBCULL,
		0x19171ADE2A27ACA7ULL,
		0x5E644176EE307FF5ULL,
		0x07A13CCBE45FB9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1689EBF893C7476EULL,
		0xE7769A06E8595284ULL,
		0x71E9B3ECE867A993ULL,
		0x3252E1741AC5B8ECULL,
		0x88D4224B6CCFBB78ULL,
		0x322E35BC544F594EULL,
		0xBCC882EDDC60FFEAULL,
		0x0F427997C8BF73EEULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFDAC6B01CEB6D051ULL,
		0xDE294183D5CC385BULL,
		0xAC86B1BBEBB32006ULL,
		0xB8A0AF42DC6786D0ULL,
		0xC50835870ECAC09DULL,
		0x17C47D63D09DB4BBULL,
		0x3423876355353944ULL,
		0x34A9922E355E04BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB58D6039D6DA0A2ULL,
		0xBC528307AB9870B7ULL,
		0x590D6377D766400DULL,
		0x71415E85B8CF0DA1ULL,
		0x8A106B0E1D95813BULL,
		0x2F88FAC7A13B6977ULL,
		0x68470EC6AA6A7288ULL,
		0x6953245C6ABC0978ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD144A13680F23043ULL,
		0x6F1F3B8D1A27C0B2ULL,
		0x29136CE84DDEC7D7ULL,
		0x16AFDCE5FE873E0EULL,
		0x639334377F54CE0CULL,
		0x3215EFE791B88669ULL,
		0x37A48A1CC7F18552ULL,
		0x286785B014805C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA289426D01E46086ULL,
		0xDE3E771A344F8165ULL,
		0x5226D9D09BBD8FAEULL,
		0x2D5FB9CBFD0E7C1CULL,
		0xC726686EFEA99C18ULL,
		0x642BDFCF23710CD2ULL,
		0x6F4914398FE30AA4ULL,
		0x50CF0B602900B804ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x06CEFC08C14D92C7ULL,
		0x3BC4566811C5766CULL,
		0x492290783A6EEC9BULL,
		0xF0C41D4CC2B27DC2ULL,
		0x8BD37C8438CD3437ULL,
		0x686732C795583BC5ULL,
		0xEEEE2434DE8C3F51ULL,
		0x081CC40870516000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D9DF811829B258EULL,
		0x7788ACD0238AECD8ULL,
		0x924520F074DDD936ULL,
		0xE1883A998564FB84ULL,
		0x17A6F908719A686FULL,
		0xD0CE658F2AB0778BULL,
		0xDDDC4869BD187EA2ULL,
		0x10398810E0A2C001ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x554C6A3E737E7E87ULL,
		0x72396BE64C789B19ULL,
		0x9E165C391E21786CULL,
		0xF6570C1D3E615057ULL,
		0x16B96BB58A88AD70ULL,
		0x7E41832A6B95018AULL,
		0xA483E4DD0119EEB0ULL,
		0x1A4D4AA6AAF765BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA98D47CE6FCFD0EULL,
		0xE472D7CC98F13632ULL,
		0x3C2CB8723C42F0D8ULL,
		0xECAE183A7CC2A0AFULL,
		0x2D72D76B15115AE1ULL,
		0xFC830654D72A0314ULL,
		0x4907C9BA0233DD60ULL,
		0x349A954D55EECB75ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x80F6AB3765B74246ULL,
		0xF85E4F3D868C8678ULL,
		0x44BCF12C7E078CAFULL,
		0xBC4CF9C5A48BC4D0ULL,
		0xA14EFE2D32C4002DULL,
		0x0E1E30E8ABC5FF2BULL,
		0x2C7D34A090B47C5AULL,
		0x25B001469AA50046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01ED566ECB6E848CULL,
		0xF0BC9E7B0D190CF1ULL,
		0x8979E258FC0F195FULL,
		0x7899F38B491789A0ULL,
		0x429DFC5A6588005BULL,
		0x1C3C61D1578BFE57ULL,
		0x58FA69412168F8B4ULL,
		0x4B60028D354A008CULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x68E30157355F1EDFULL,
		0x88C6F0475B5E2278ULL,
		0x8D1730EF2B2FEF82ULL,
		0x74EBB5E55D69D0C9ULL,
		0xAAC4C721E40DAA90ULL,
		0xB1F1FB3D8DAF6A6DULL,
		0xC942176AAC3F20A2ULL,
		0x1A0D11ED13CE251BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1C602AE6ABE3DBEULL,
		0x118DE08EB6BC44F0ULL,
		0x1A2E61DE565FDF05ULL,
		0xE9D76BCABAD3A193ULL,
		0x55898E43C81B5520ULL,
		0x63E3F67B1B5ED4DBULL,
		0x92842ED5587E4145ULL,
		0x341A23DA279C4A37ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08A8975EBE17DC73ULL,
		0x43898BFAB168F7FEULL,
		0x475CF135ECA6887CULL,
		0xA43EDA6BE0074BA3ULL,
		0xA99017FC591CFC29ULL,
		0xD37F68B46E2A6029ULL,
		0xBFFC4A65B7926FFCULL,
		0x11D641BC15C7E15FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11512EBD7C2FB8E6ULL,
		0x871317F562D1EFFCULL,
		0x8EB9E26BD94D10F8ULL,
		0x487DB4D7C00E9746ULL,
		0x53202FF8B239F853ULL,
		0xA6FED168DC54C053ULL,
		0x7FF894CB6F24DFF9ULL,
		0x23AC83782B8FC2BFULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA4538AF4FC3A9D76ULL,
		0x38B267A3B5BB9615ULL,
		0x8779D69E41E516AFULL,
		0x1B3F67E80C1D028CULL,
		0x24D4463BF1503D77ULL,
		0xA7FD2D4F44F302F0ULL,
		0x1CBEC474B6C85272ULL,
		0x3434000C2E54E4E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48A715E9F8753AECULL,
		0x7164CF476B772C2BULL,
		0x0EF3AD3C83CA2D5EULL,
		0x367ECFD0183A0519ULL,
		0x49A88C77E2A07AEEULL,
		0x4FFA5A9E89E605E0ULL,
		0x397D88E96D90A4E5ULL,
		0x686800185CA9C9C6ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEDA1F5F0FBD6F08BULL,
		0xB4BE9167A2C4A599ULL,
		0x285E44FAAD18521EULL,
		0xC7F39F5A6F924C47ULL,
		0x28C0601F8694D65CULL,
		0xA15988E250D69D6CULL,
		0xE6E3E15CBD97CD25ULL,
		0x3DA8388605FE31E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB43EBE1F7ADE116ULL,
		0x697D22CF45894B33ULL,
		0x50BC89F55A30A43DULL,
		0x8FE73EB4DF24988EULL,
		0x5180C03F0D29ACB9ULL,
		0x42B311C4A1AD3AD8ULL,
		0xCDC7C2B97B2F9A4BULL,
		0x7B50710C0BFC63C5ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAA1E945F101A80C4ULL,
		0x8C1BF4E88170C455ULL,
		0x86DED628DE450C86ULL,
		0x5018D305D1DEA4ABULL,
		0x775BDF31A0717B06ULL,
		0x945DE064A2474186ULL,
		0xABAF9C1734C8A179ULL,
		0x3D4CAF90D2F87C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x543D28BE20350188ULL,
		0x1837E9D102E188ABULL,
		0x0DBDAC51BC8A190DULL,
		0xA031A60BA3BD4957ULL,
		0xEEB7BE6340E2F60CULL,
		0x28BBC0C9448E830CULL,
		0x575F382E699142F3ULL,
		0x7A995F21A5F0F85FULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE780752B8EA60DDEULL,
		0xF83AAB438EB0A80DULL,
		0xB9434C857B4C44F2ULL,
		0x07FCD6B4E4C8ECD3ULL,
		0x2D3D5B35374B27A5ULL,
		0x4ADF44A200370367ULL,
		0xDC88008A973DDA85ULL,
		0x19E27CA415830559ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF00EA571D4C1BBCULL,
		0xF07556871D61501BULL,
		0x7286990AF69889E5ULL,
		0x0FF9AD69C991D9A7ULL,
		0x5A7AB66A6E964F4AULL,
		0x95BE8944006E06CEULL,
		0xB91001152E7BB50AULL,
		0x33C4F9482B060AB3ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB75956DCCDB35ACULL,
		0x9C7A15C7AB446363ULL,
		0xBBEB9ED2A374EAF8ULL,
		0x18C14A2F8F6CB3F1ULL,
		0x4A6A0E5840A20564ULL,
		0xD30024B5384E5A9BULL,
		0x9EFE1751204FFAC4ULL,
		0x3166DA0A537E5517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6EB2ADB99B66B58ULL,
		0x38F42B8F5688C6C7ULL,
		0x77D73DA546E9D5F1ULL,
		0x3182945F1ED967E3ULL,
		0x94D41CB081440AC8ULL,
		0xA600496A709CB536ULL,
		0x3DFC2EA2409FF589ULL,
		0x62CDB414A6FCAA2FULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9D06DB7B29C38EE1ULL,
		0xD660D7C99A20186EULL,
		0x9295200296B639EBULL,
		0x954D6E07DFD9A181ULL,
		0x1C1AE20A71C05307ULL,
		0x1BC62DDAC9D69ED7ULL,
		0x7332819674051473ULL,
		0x15FE7D38EBEA4742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A0DB6F653871DC2ULL,
		0xACC1AF93344030DDULL,
		0x252A40052D6C73D7ULL,
		0x2A9ADC0FBFB34303ULL,
		0x3835C414E380A60FULL,
		0x378C5BB593AD3DAEULL,
		0xE665032CE80A28E6ULL,
		0x2BFCFA71D7D48E84ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF88E8FF938B70D16ULL,
		0x2AEC7F01568FB572ULL,
		0x60F5DEB4613F782DULL,
		0x0F3A21B62AC8DAF1ULL,
		0x830005CA8A178B03ULL,
		0x6E16D529B3DB509DULL,
		0xD5998689B2C0A0EBULL,
		0x3B78DBDE62C08829ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF11D1FF2716E1A2CULL,
		0x55D8FE02AD1F6AE5ULL,
		0xC1EBBD68C27EF05AULL,
		0x1E74436C5591B5E2ULL,
		0x06000B95142F1606ULL,
		0xDC2DAA5367B6A13BULL,
		0xAB330D13658141D6ULL,
		0x76F1B7BCC5811053ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FFCE9DC22B7D00FULL,
		0x15A25AB9C1434342ULL,
		0x95AA5AA7561D26FCULL,
		0xFC6AFD1B2889907DULL,
		0xDC38DE0C499CB8BBULL,
		0x2053DEEDFBC909D2ULL,
		0xA43E0D1EA68F43FFULL,
		0x0F9503AD0E1E7F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF9D3B8456FA01EULL,
		0x2B44B57382868684ULL,
		0x2B54B54EAC3A4DF8ULL,
		0xF8D5FA36511320FBULL,
		0xB871BC1893397177ULL,
		0x40A7BDDBF79213A5ULL,
		0x487C1A3D4D1E87FEULL,
		0x1F2A075A1C3CFF27ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBBBD343913FA2165ULL,
		0xEEFD50B4C90BCF81ULL,
		0x5E00050A8D60E797ULL,
		0x55DF75DD5EA692CBULL,
		0x01A9234D29B680EBULL,
		0xD860BCFE03C1F1C9ULL,
		0x1D9EBB9F0673E5ECULL,
		0x1860D4C52A46DEB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777A687227F442CAULL,
		0xDDFAA16992179F03ULL,
		0xBC000A151AC1CF2FULL,
		0xABBEEBBABD4D2596ULL,
		0x0352469A536D01D6ULL,
		0xB0C179FC0783E392ULL,
		0x3B3D773E0CE7CBD9ULL,
		0x30C1A98A548DBD6EULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3A1CEDAB17945D3CULL,
		0x26C6848C645EB170ULL,
		0xA2DB92074CA58298ULL,
		0xD7D1067BF5720539ULL,
		0xFA4533550A438FFDULL,
		0x32F5E300204F9B0CULL,
		0x77C4540DD0EAD3CBULL,
		0x155E62041D077D7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7439DB562F28BA78ULL,
		0x4D8D0918C8BD62E0ULL,
		0x45B7240E994B0530ULL,
		0xAFA20CF7EAE40A73ULL,
		0xF48A66AA14871FFBULL,
		0x65EBC600409F3619ULL,
		0xEF88A81BA1D5A796ULL,
		0x2ABCC4083A0EFAFAULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBC7402DEB81EBE17ULL,
		0x89DA3BE09CECCD24ULL,
		0x2476E9F297AC87BDULL,
		0xBB49245CD35097A4ULL,
		0xF12845977500495BULL,
		0xD0A21EA08ED885DDULL,
		0xE392D34D5711E0CAULL,
		0x1AADD8A64CBDBF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E805BD703D7C2EULL,
		0x13B477C139D99A49ULL,
		0x48EDD3E52F590F7BULL,
		0x769248B9A6A12F48ULL,
		0xE2508B2EEA0092B7ULL,
		0xA1443D411DB10BBBULL,
		0xC725A69AAE23C195ULL,
		0x355BB14C997B7EF7ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8E9F59ABA3F539A6ULL,
		0xA170D48653A7A88CULL,
		0xB50D5A77D32DD94CULL,
		0xA777AA9409CCDAC0ULL,
		0xE30D8C9616F25398ULL,
		0x639F95B8B0D98CC6ULL,
		0x85A165862640DBCAULL,
		0x02D71BAF8AB1286CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D3EB35747EA734CULL,
		0x42E1A90CA74F5119ULL,
		0x6A1AB4EFA65BB299ULL,
		0x4EEF55281399B581ULL,
		0xC61B192C2DE4A731ULL,
		0xC73F2B7161B3198DULL,
		0x0B42CB0C4C81B794ULL,
		0x05AE375F156250D9ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA1CAF75A59EA4F9AULL,
		0x3F65F12F07DE1836ULL,
		0xCC58E1E4473D5238ULL,
		0x977E28F3A0F098BAULL,
		0x5B7378C1AE7E989BULL,
		0xBDB67F6760808FA8ULL,
		0xED583F045689AA37ULL,
		0x3F88B71B20E3146AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4395EEB4B3D49F34ULL,
		0x7ECBE25E0FBC306DULL,
		0x98B1C3C88E7AA470ULL,
		0x2EFC51E741E13175ULL,
		0xB6E6F1835CFD3137ULL,
		0x7B6CFECEC1011F50ULL,
		0xDAB07E08AD13546FULL,
		0x7F116E3641C628D5ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9B8C39D8AFB98571ULL,
		0x26DD0B4890A838EFULL,
		0x0F13BB18BF39C01AULL,
		0xA9D1D7B43776F68DULL,
		0xBFC4EEC4A8C71F57ULL,
		0x7735E11BB14DDE90ULL,
		0x01E3C915D7ED94B3ULL,
		0x2A3C3A36ADD4531BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x371873B15F730AE2ULL,
		0x4DBA1691215071DFULL,
		0x1E2776317E738034ULL,
		0x53A3AF686EEDED1AULL,
		0x7F89DD89518E3EAFULL,
		0xEE6BC237629BBD21ULL,
		0x03C7922BAFDB2966ULL,
		0x5478746D5BA8A636ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD2CD0D92693155DDULL,
		0x85D4E79AA50D4448ULL,
		0x50F1EA65A29FA4B1ULL,
		0x3F39FAEF81F56086ULL,
		0x2D21A7C4B6948D1CULL,
		0xC9DD4880D55FEBB5ULL,
		0x47C120FE1FAEBD95ULL,
		0x3E55539AD804E460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA59A1B24D262ABBAULL,
		0x0BA9CF354A1A8891ULL,
		0xA1E3D4CB453F4963ULL,
		0x7E73F5DF03EAC10CULL,
		0x5A434F896D291A38ULL,
		0x93BA9101AABFD76AULL,
		0x8F8241FC3F5D7B2BULL,
		0x7CAAA735B009C8C0ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7AA025B2CD3C8BC2ULL,
		0x1C01F858F53E66D6ULL,
		0x4F964424AF7FBA48ULL,
		0x37801D33136005F1ULL,
		0xD3C9ABFFEB269A17ULL,
		0xB71A0E99BB022A81ULL,
		0x8A30D87946EC6AF3ULL,
		0x22CFEC236526209DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5404B659A791784ULL,
		0x3803F0B1EA7CCDACULL,
		0x9F2C88495EFF7490ULL,
		0x6F003A6626C00BE2ULL,
		0xA79357FFD64D342EULL,
		0x6E341D3376045503ULL,
		0x1461B0F28DD8D5E7ULL,
		0x459FD846CA4C413BULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9F936C51A8DAE7EAULL,
		0xE35B96BFDA1F815FULL,
		0x1FDF236B4D3F1BA3ULL,
		0x03C68FA0C3C8FC6FULL,
		0x1347095FF19C71F4ULL,
		0xCEF293C0C9EB9D43ULL,
		0xD5A9F012A539EBD8ULL,
		0x19E28771B14F8ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F26D8A351B5CFD4ULL,
		0xC6B72D7FB43F02BFULL,
		0x3FBE46D69A7E3747ULL,
		0x078D1F418791F8DEULL,
		0x268E12BFE338E3E8ULL,
		0x9DE5278193D73A86ULL,
		0xAB53E0254A73D7B1ULL,
		0x33C50EE3629F1DAFULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x97B3B5167DF044A8ULL,
		0xBAA7E59C92ABC0FEULL,
		0x871639A7C54AABD0ULL,
		0xB9673EB6A9AC16AEULL,
		0xFBEA383680ED859DULL,
		0x6C8A2F59C4C529C1ULL,
		0xED6826CC1E663CEDULL,
		0x3CF94346F15F077AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F676A2CFBE08950ULL,
		0x754FCB39255781FDULL,
		0x0E2C734F8A9557A1ULL,
		0x72CE7D6D53582D5DULL,
		0xF7D4706D01DB0B3BULL,
		0xD9145EB3898A5383ULL,
		0xDAD04D983CCC79DAULL,
		0x79F2868DE2BE0EF5ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC4BB49D4673527DFULL,
		0x6EE22E62BE75887CULL,
		0xCC79F884E3BDC716ULL,
		0x0233F05AE884CC4AULL,
		0x0B7CB35C197DD148ULL,
		0x862A5B02AC569042ULL,
		0xDCFB35A834DA3679ULL,
		0x3838C7A4961272FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x897693A8CE6A4FBEULL,
		0xDDC45CC57CEB10F9ULL,
		0x98F3F109C77B8E2CULL,
		0x0467E0B5D1099895ULL,
		0x16F966B832FBA290ULL,
		0x0C54B60558AD2084ULL,
		0xB9F66B5069B46CF3ULL,
		0x70718F492C24E5F7ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x96CD70F3D8930F17ULL,
		0x3FD20A62A255EC29ULL,
		0xE8FE0F21130A97F3ULL,
		0x2B9EDD7AABBFDE9BULL,
		0xBDAA329141A249C6ULL,
		0xD40D21BFC4CEE780ULL,
		0x3B5A637D9CEE0659ULL,
		0x345BA12F85F6692DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D9AE1E7B1261E2EULL,
		0x7FA414C544ABD853ULL,
		0xD1FC1E4226152FE6ULL,
		0x573DBAF5577FBD37ULL,
		0x7B5465228344938CULL,
		0xA81A437F899DCF01ULL,
		0x76B4C6FB39DC0CB3ULL,
		0x68B7425F0BECD25AULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF5123EB94971DB36ULL,
		0xD180BF42BE0CC47BULL,
		0x21C48E7A922DCFF8ULL,
		0xF90E366787A104D1ULL,
		0xA000ED10113C229BULL,
		0x4EFF33CE2C578F79ULL,
		0xF5135FCA933DBA6BULL,
		0x053BB5FFF12F311CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA247D7292E3B66CULL,
		0xA3017E857C1988F7ULL,
		0x43891CF5245B9FF1ULL,
		0xF21C6CCF0F4209A2ULL,
		0x4001DA2022784537ULL,
		0x9DFE679C58AF1EF3ULL,
		0xEA26BF95267B74D6ULL,
		0x0A776BFFE25E6239ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC8868991596EC396ULL,
		0xF0048723672A2D55ULL,
		0xAD8D5246F24204A2ULL,
		0x0F8EDE8D21E79152ULL,
		0xAE77D957BD989FA6ULL,
		0x6E09DF13B19D49AAULL,
		0x16F5746AE9666945ULL,
		0x204CB006AF3EB350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x910D1322B2DD872CULL,
		0xE0090E46CE545AABULL,
		0x5B1AA48DE4840945ULL,
		0x1F1DBD1A43CF22A5ULL,
		0x5CEFB2AF7B313F4CULL,
		0xDC13BE27633A9355ULL,
		0x2DEAE8D5D2CCD28AULL,
		0x4099600D5E7D66A0ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA7DFD9C42B673CCEULL,
		0x272C4448C4A5B893ULL,
		0x8A81AD6CFFA7F5AAULL,
		0xCDC4661FD3466220ULL,
		0xD43FDBD0E85757BBULL,
		0xFBDA2CAF80BF2218ULL,
		0x21CCC7CC686E8C3FULL,
		0x2B079DB374EE3B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FBFB38856CE799CULL,
		0x4E588891894B7127ULL,
		0x15035AD9FF4FEB54ULL,
		0x9B88CC3FA68CC441ULL,
		0xA87FB7A1D0AEAF77ULL,
		0xF7B4595F017E4431ULL,
		0x43998F98D0DD187FULL,
		0x560F3B66E9DC7722ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0138F2CD4A0D6731ULL,
		0x5BEC1E4BB9313536ULL,
		0x8C3EB8B106EE2F92ULL,
		0x454316D2B667B7DBULL,
		0x2548ED0CE47A40E3ULL,
		0x2770F21243E44548ULL,
		0xABD617E9FCD20BE7ULL,
		0x04762D0DF0BAEC65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0271E59A941ACE62ULL,
		0xB7D83C9772626A6CULL,
		0x187D71620DDC5F24ULL,
		0x8A862DA56CCF6FB7ULL,
		0x4A91DA19C8F481C6ULL,
		0x4EE1E42487C88A90ULL,
		0x57AC2FD3F9A417CEULL,
		0x08EC5A1BE175D8CBULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x63037C9F608B3DF9ULL,
		0x04C299882C34E3C8ULL,
		0x9AC3236AE16E1D07ULL,
		0xE8C1F35D5C73FD70ULL,
		0xCE15986029A23116ULL,
		0xA4C79FAD8BCA713AULL,
		0xB1A4C8EB4AB79A85ULL,
		0x2E2868D1F101B17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC606F93EC1167BF2ULL,
		0x098533105869C790ULL,
		0x358646D5C2DC3A0EULL,
		0xD183E6BAB8E7FAE1ULL,
		0x9C2B30C05344622DULL,
		0x498F3F5B1794E275ULL,
		0x634991D6956F350BULL,
		0x5C50D1A3E20362FDULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBE831B6BE0DD4753ULL,
		0xFEBF56BA460A3AA4ULL,
		0xE50269D42D0A185FULL,
		0x7189EAEE7C6BC1B3ULL,
		0x157E6E3A097D8F65ULL,
		0x3CDAE9D3C646AE8AULL,
		0xFC57583B6872E0B7ULL,
		0x3084661D19B21847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D0636D7C1BA8EA6ULL,
		0xFD7EAD748C147549ULL,
		0xCA04D3A85A1430BFULL,
		0xE313D5DCF8D78367ULL,
		0x2AFCDC7412FB1ECAULL,
		0x79B5D3A78C8D5D14ULL,
		0xF8AEB076D0E5C16EULL,
		0x6108CC3A3364308FULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A79649D4C8A9697ULL,
		0x0374A933AAF91EACULL,
		0x19D447235C0B0D05ULL,
		0x5466C2E760F41C0AULL,
		0x812279FF6ED44D82ULL,
		0x3B7717660C7B8DB6ULL,
		0x3224D66503818F3AULL,
		0x11CD1A9D78CC89E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F2C93A99152D2EULL,
		0x06E9526755F23D58ULL,
		0x33A88E46B8161A0AULL,
		0xA8CD85CEC1E83814ULL,
		0x0244F3FEDDA89B04ULL,
		0x76EE2ECC18F71B6DULL,
		0x6449ACCA07031E74ULL,
		0x239A353AF19913C4ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCD04E5AE7F52B85EULL,
		0x7A96738D78DF45C8ULL,
		0x4CE0CCF8CD962CBDULL,
		0x2F03A11784F6FC01ULL,
		0xA7CA940C552E3AC5ULL,
		0xA82C0D0C9A990D52ULL,
		0xC39A4EF6DD7CFDFAULL,
		0x2A803C307CD0CEA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A09CB5CFEA570BCULL,
		0xF52CE71AF1BE8B91ULL,
		0x99C199F19B2C597AULL,
		0x5E07422F09EDF802ULL,
		0x4F952818AA5C758AULL,
		0x50581A1935321AA5ULL,
		0x87349DEDBAF9FBF5ULL,
		0x55007860F9A19D49ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1D17C3F0D02E5CD1ULL,
		0x86704B12E4020A87ULL,
		0x2FE049F7480BE142ULL,
		0x1321B075FC650D75ULL,
		0xC9E63F37AECDCA73ULL,
		0x3A240295F7DD54B2ULL,
		0x1242C59E9E748C55ULL,
		0x0825AF3978C2450DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2F87E1A05CB9A2ULL,
		0x0CE09625C804150EULL,
		0x5FC093EE9017C285ULL,
		0x264360EBF8CA1AEAULL,
		0x93CC7E6F5D9B94E6ULL,
		0x7448052BEFBAA965ULL,
		0x24858B3D3CE918AAULL,
		0x104B5E72F1848A1AULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE6C854366065AE2CULL,
		0x2F426F7CFFAF8EB8ULL,
		0xB64A70F29F017C4BULL,
		0x9DC5DE39871684A1ULL,
		0x19406B4CB27AD0F5ULL,
		0x5AEAC764E4B385ABULL,
		0xC5F9F2FC152F9190ULL,
		0x06FA8AB88D2D840FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD90A86CC0CB5C58ULL,
		0x5E84DEF9FF5F1D71ULL,
		0x6C94E1E53E02F896ULL,
		0x3B8BBC730E2D0943ULL,
		0x3280D69964F5A1EBULL,
		0xB5D58EC9C9670B56ULL,
		0x8BF3E5F82A5F2320ULL,
		0x0DF515711A5B081FULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x322F23C6FCCA8050ULL,
		0x7EF1B5DDB2A0A3A8ULL,
		0xF526F84EC001186AULL,
		0xDC82E9FA88AFF236ULL,
		0xD2E50384DBDC6854ULL,
		0x238D9A4661FF3E2CULL,
		0xC9A2A78E5848E457ULL,
		0x0725A6775A7E51DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x645E478DF99500A0ULL,
		0xFDE36BBB65414750ULL,
		0xEA4DF09D800230D4ULL,
		0xB905D3F5115FE46DULL,
		0xA5CA0709B7B8D0A9ULL,
		0x471B348CC3FE7C59ULL,
		0x93454F1CB091C8AEULL,
		0x0E4B4CEEB4FCA3BBULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB1FE31D6782AC9A4ULL,
		0x90ED1F04BDE6CAEBULL,
		0x74E1DF7B8F0E5D55ULL,
		0x57D85E268880BB24ULL,
		0xF256DAC7B2F61900ULL,
		0x14666B8A1E95488EULL,
		0x3F72EF5CF236DDBFULL,
		0x09CBFAC2A9D16509ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63FC63ACF0559348ULL,
		0x21DA3E097BCD95D7ULL,
		0xE9C3BEF71E1CBAABULL,
		0xAFB0BC4D11017648ULL,
		0xE4ADB58F65EC3200ULL,
		0x28CCD7143D2A911DULL,
		0x7EE5DEB9E46DBB7EULL,
		0x1397F58553A2CA12ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6EBB6E174DEE3C58ULL,
		0x4E1E98607F666036ULL,
		0xCC59C91A032E11FCULL,
		0x0139F7E01DD22A9BULL,
		0xAE48EDFEB4DCF58FULL,
		0xBEF54EEE2F28369CULL,
		0x5F13F0A6DB977A93ULL,
		0x0BDF815B37F76D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD76DC2E9BDC78B0ULL,
		0x9C3D30C0FECCC06CULL,
		0x98B39234065C23F8ULL,
		0x0273EFC03BA45537ULL,
		0x5C91DBFD69B9EB1EULL,
		0x7DEA9DDC5E506D39ULL,
		0xBE27E14DB72EF527ULL,
		0x17BF02B66FEEDA7AULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF17271B7892813AFULL,
		0xADF4501ED5A49366ULL,
		0x2FFF0654B7723783ULL,
		0x2A23705C37E96002ULL,
		0x9385751FB44E4FEDULL,
		0xAF0381B9C5EC4FD7ULL,
		0x414377BB1F75049CULL,
		0x0D55761F5E713572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E4E36F1250275EULL,
		0x5BE8A03DAB4926CDULL,
		0x5FFE0CA96EE46F07ULL,
		0x5446E0B86FD2C004ULL,
		0x270AEA3F689C9FDAULL,
		0x5E0703738BD89FAFULL,
		0x8286EF763EEA0939ULL,
		0x1AAAEC3EBCE26AE4ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0111D45AC5E36ECEULL,
		0xE561547B59B28E84ULL,
		0x1F114642512F5AAEULL,
		0x524863E319F7E0A1ULL,
		0x4E6B3D2AABBB1FDDULL,
		0xE00C262E30557097ULL,
		0x5D60283EF29CB7B0ULL,
		0x05225AF80C49A27DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0223A8B58BC6DD9CULL,
		0xCAC2A8F6B3651D08ULL,
		0x3E228C84A25EB55DULL,
		0xA490C7C633EFC142ULL,
		0x9CD67A5557763FBAULL,
		0xC0184C5C60AAE12EULL,
		0xBAC0507DE5396F61ULL,
		0x0A44B5F0189344FAULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFAF783604629E0BBULL,
		0xB75D3EE81EE236CBULL,
		0x8661EB202C2AE064ULL,
		0x8A5829CDE1977B83ULL,
		0x797E7303FE9FD54FULL,
		0xBE5355AF8C67C9E3ULL,
		0x3EBA7969AE36B7B0ULL,
		0x1A9DE335CBFE7BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5EF06C08C53C176ULL,
		0x6EBA7DD03DC46D97ULL,
		0x0CC3D6405855C0C9ULL,
		0x14B0539BC32EF707ULL,
		0xF2FCE607FD3FAA9FULL,
		0x7CA6AB5F18CF93C6ULL,
		0x7D74F2D35C6D6F61ULL,
		0x353BC66B97FCF78AULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD83CA9BDA3645C0BULL,
		0xF0858A21ED527E5EULL,
		0xB5262E8A607E6DA4ULL,
		0xDB650A9D624F0BFBULL,
		0xFEE0F724A844062BULL,
		0x3A4272C5D285D4F1ULL,
		0x1F8C8F63AB661619ULL,
		0x359E529F854DFED6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB079537B46C8B816ULL,
		0xE10B1443DAA4FCBDULL,
		0x6A4C5D14C0FCDB49ULL,
		0xB6CA153AC49E17F7ULL,
		0xFDC1EE4950880C57ULL,
		0x7484E58BA50BA9E3ULL,
		0x3F191EC756CC2C32ULL,
		0x6B3CA53F0A9BFDACULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD37CB3997F9CB7FULL,
		0x57AD37F41D17FB7DULL,
		0xD9465F6B4DD4D5EAULL,
		0x07ACA2CB6156D14AULL,
		0x7CF4B5351DC55B4EULL,
		0x7D597F74F393A086ULL,
		0x2AB337E982B24FA6ULL,
		0x3FA2D690B44C9401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A6F96732FF396FEULL,
		0xAF5A6FE83A2FF6FBULL,
		0xB28CBED69BA9ABD4ULL,
		0x0F594596C2ADA295ULL,
		0xF9E96A6A3B8AB69CULL,
		0xFAB2FEE9E727410CULL,
		0x55666FD305649F4CULL,
		0x7F45AD2168992802ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE59238B4C3A71A4FULL,
		0xCDFAEF0628A5E6AEULL,
		0x4B40FE0DD1ED18D5ULL,
		0xA204B4232164B053ULL,
		0xBA0B64B6723D6399ULL,
		0x21FF160DF02BB6DBULL,
		0xB1475147E987C7C9ULL,
		0x3DC3BE358FBD8229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB247169874E349EULL,
		0x9BF5DE0C514BCD5DULL,
		0x9681FC1BA3DA31ABULL,
		0x4409684642C960A6ULL,
		0x7416C96CE47AC733ULL,
		0x43FE2C1BE0576DB7ULL,
		0x628EA28FD30F8F92ULL,
		0x7B877C6B1F7B0453ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0B2A2E89011D4D35ULL,
		0x8B5AEB59369C2084ULL,
		0x366CE6B8239042C6ULL,
		0x23F273B0B4764812ULL,
		0x35A32B27D63B031DULL,
		0x99AC31F8214B5086ULL,
		0x7513A8645D52BC15ULL,
		0x1719A5C30EEBDE9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16545D12023A9A6AULL,
		0x16B5D6B26D384108ULL,
		0x6CD9CD704720858DULL,
		0x47E4E76168EC9024ULL,
		0x6B46564FAC76063AULL,
		0x335863F04296A10CULL,
		0xEA2750C8BAA5782BULL,
		0x2E334B861DD7BD38ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3BFA1E414C89B740ULL,
		0x968F1DF3637B2B43ULL,
		0x79C04973E7ED79CEULL,
		0x795D23ECD5C9B706ULL,
		0x09B6E3FF7D689792ULL,
		0xA5AF9E7CCEDF1913ULL,
		0xFEB67942D54F6CDFULL,
		0x3AF0C4A09DAEC801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F43C8299136E80ULL,
		0x2D1E3BE6C6F65686ULL,
		0xF38092E7CFDAF39DULL,
		0xF2BA47D9AB936E0CULL,
		0x136DC7FEFAD12F24ULL,
		0x4B5F3CF99DBE3226ULL,
		0xFD6CF285AA9ED9BFULL,
		0x75E189413B5D9003ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB554E8C0F4B58CADULL,
		0x92B0AE245467299EULL,
		0x5AA530380A213F21ULL,
		0x026D27071A65BDB9ULL,
		0xC585E85F150BF778ULL,
		0x23A794CBCA49063CULL,
		0x26DB024A181788CCULL,
		0x26BE31B8F3541BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA9D181E96B195AULL,
		0x25615C48A8CE533DULL,
		0xB54A607014427E43ULL,
		0x04DA4E0E34CB7B72ULL,
		0x8B0BD0BE2A17EEF0ULL,
		0x474F299794920C79ULL,
		0x4DB60494302F1198ULL,
		0x4D7C6371E6A837AAULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x321D05CE06BF9C53ULL,
		0xD1158C86C53305A0ULL,
		0x92E9F0C4AD9C9EB1ULL,
		0x7EEE9149E9E64B92ULL,
		0x16B6EEF42122FEFAULL,
		0x2ABE910331C33687ULL,
		0xC21720D5A60D8250ULL,
		0x2F7948DFBE8EAAC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643A0B9C0D7F38A6ULL,
		0xA22B190D8A660B40ULL,
		0x25D3E1895B393D63ULL,
		0xFDDD2293D3CC9725ULL,
		0x2D6DDDE84245FDF4ULL,
		0x557D220663866D0EULL,
		0x842E41AB4C1B04A0ULL,
		0x5EF291BF7D1D558DULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2791CFC93D71A2C3ULL,
		0x32F6F2DA57987940ULL,
		0x90EE00B45A027E59ULL,
		0x14D105199FF215D6ULL,
		0xCB919DC4E0128ECCULL,
		0x4B1FD74E04C7184AULL,
		0xB3A4C08A94CE69D8ULL,
		0x3F776E3B04EC0D82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F239F927AE34586ULL,
		0x65EDE5B4AF30F280ULL,
		0x21DC0168B404FCB2ULL,
		0x29A20A333FE42BADULL,
		0x97233B89C0251D98ULL,
		0x963FAE9C098E3095ULL,
		0x67498115299CD3B0ULL,
		0x7EEEDC7609D81B05ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x554694E66A137ED2ULL,
		0x07CD747BF6FE54CFULL,
		0x013979B5AC048FDFULL,
		0x6B31BD94DC406DDBULL,
		0x58016D85049AF7A7ULL,
		0x330F5F10502C62CDULL,
		0x123BA548F905C618ULL,
		0x07943371DFDBC594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8D29CCD426FDA4ULL,
		0x0F9AE8F7EDFCA99EULL,
		0x0272F36B58091FBEULL,
		0xD6637B29B880DBB6ULL,
		0xB002DB0A0935EF4EULL,
		0x661EBE20A058C59AULL,
		0x24774A91F20B8C30ULL,
		0x0F2866E3BFB78B28ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x20B58B47FDA653ABULL,
		0x99655946358CC5C6ULL,
		0x20E2B54BEB0B1126ULL,
		0x36D6C66094F4133EULL,
		0xA930E0F45C29874CULL,
		0x0F7791C463581D50ULL,
		0x146ED3756FD37D91ULL,
		0x29EBC3029E90367EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x416B168FFB4CA756ULL,
		0x32CAB28C6B198B8CULL,
		0x41C56A97D616224DULL,
		0x6DAD8CC129E8267CULL,
		0x5261C1E8B8530E98ULL,
		0x1EEF2388C6B03AA1ULL,
		0x28DDA6EADFA6FB22ULL,
		0x53D786053D206CFCULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9B3341F1C2715A84ULL,
		0x3823111FBADF6295ULL,
		0xE155BF553E4AC1C4ULL,
		0xF6FF4CE6B28BE605ULL,
		0xE4A1121E67A802AEULL,
		0xC8939FFBB41BF8DDULL,
		0xCC2FE01E0F5426B8ULL,
		0x21447B9DE808C609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x366683E384E2B508ULL,
		0x7046223F75BEC52BULL,
		0xC2AB7EAA7C958388ULL,
		0xEDFE99CD6517CC0BULL,
		0xC942243CCF50055DULL,
		0x91273FF76837F1BBULL,
		0x985FC03C1EA84D71ULL,
		0x4288F73BD0118C13ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC83729A51CB258A5ULL,
		0x285E9D1C09D50CC9ULL,
		0x1517B97BF3958D82ULL,
		0xF77243401BF3E54AULL,
		0xD925CF6D3DE52FC8ULL,
		0xC9546BDA73DFCF99ULL,
		0x2BA9C29C88D411B7ULL,
		0x08C7B9B8E64D4B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906E534A3964B14AULL,
		0x50BD3A3813AA1993ULL,
		0x2A2F72F7E72B1B04ULL,
		0xEEE4868037E7CA94ULL,
		0xB24B9EDA7BCA5F91ULL,
		0x92A8D7B4E7BF9F33ULL,
		0x5753853911A8236FULL,
		0x118F7371CC9A9620ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8632BBD8247C5662ULL,
		0x90BDFF01ED1610FAULL,
		0x88074AD219FA0378ULL,
		0x942A01505F7F77B2ULL,
		0x3F2D455874977E08ULL,
		0x0BC5CD33B225E166ULL,
		0x9BD63F20F2319E8BULL,
		0x0A4FF3540C147787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C6577B048F8ACC4ULL,
		0x217BFE03DA2C21F5ULL,
		0x100E95A433F406F1ULL,
		0x285402A0BEFEEF65ULL,
		0x7E5A8AB0E92EFC11ULL,
		0x178B9A67644BC2CCULL,
		0x37AC7E41E4633D16ULL,
		0x149FE6A81828EF0FULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x35C72998E7384089ULL,
		0x4C92A6BE890CF080ULL,
		0x79F9F7FC00820103ULL,
		0x39793EB4561D7736ULL,
		0xB78B05F1A25D5EC8ULL,
		0x6E6E4A743EBB31B1ULL,
		0x1481F9B9DCB2B2ADULL,
		0x01E6186D51CFFF93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8E5331CE708112ULL,
		0x99254D7D1219E100ULL,
		0xF3F3EFF801040206ULL,
		0x72F27D68AC3AEE6CULL,
		0x6F160BE344BABD90ULL,
		0xDCDC94E87D766363ULL,
		0x2903F373B965655AULL,
		0x03CC30DAA39FFF26ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE29E96EF5EF90836ULL,
		0x9E3E311714160CE8ULL,
		0xBDE20AEBBBAF47C3ULL,
		0xD101B6A0DB8E3107ULL,
		0x3C3FF01FFD0206A0ULL,
		0xC88FB6FD835DAFFCULL,
		0x0AE7578909CE8451ULL,
		0x20ABA7747AB64C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC53D2DDEBDF2106CULL,
		0x3C7C622E282C19D1ULL,
		0x7BC415D7775E8F87ULL,
		0xA2036D41B71C620FULL,
		0x787FE03FFA040D41ULL,
		0x911F6DFB06BB5FF8ULL,
		0x15CEAF12139D08A3ULL,
		0x41574EE8F56C989AULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAE00A8A529DBA562ULL,
		0xDB12247EE1135016ULL,
		0x8736A436975F905AULL,
		0x1DD50C21699177EDULL,
		0x5C9120B644EF3F06ULL,
		0x73190F3ACBA7B94CULL,
		0xBA242842688373C8ULL,
		0x2DEF9148E4D171A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C01514A53B74AC4ULL,
		0xB62448FDC226A02DULL,
		0x0E6D486D2EBF20B5ULL,
		0x3BAA1842D322EFDBULL,
		0xB922416C89DE7E0CULL,
		0xE6321E75974F7298ULL,
		0x74485084D106E790ULL,
		0x5BDF2291C9A2E349ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1FA4749042234E90ULL,
		0x7D34B701591F3A50ULL,
		0x17A8C0C5768CF51DULL,
		0x8AD81862948FA2F2ULL,
		0xD205B063758FFC64ULL,
		0x15742FA65DD9403FULL,
		0x6792B6826EC6193AULL,
		0x202FBAD11541B6D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F48E92084469D20ULL,
		0xFA696E02B23E74A0ULL,
		0x2F51818AED19EA3AULL,
		0x15B030C5291F45E4ULL,
		0xA40B60C6EB1FF8C9ULL,
		0x2AE85F4CBBB2807FULL,
		0xCF256D04DD8C3274ULL,
		0x405F75A22A836DB0ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x62796F1DDCA46BA6ULL,
		0xAE227038512A7EA0ULL,
		0x908D60F41DEB351CULL,
		0xA0DE3E0950719A0AULL,
		0x7E8C781438E7125CULL,
		0xE69C9AC29363FF2FULL,
		0xAAF6F65097950FE4ULL,
		0x061609466B4B989EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4F2DE3BB948D74CULL,
		0x5C44E070A254FD40ULL,
		0x211AC1E83BD66A39ULL,
		0x41BC7C12A0E33415ULL,
		0xFD18F02871CE24B9ULL,
		0xCD39358526C7FE5EULL,
		0x55EDECA12F2A1FC9ULL,
		0x0C2C128CD697313DULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2D5D6AB45E9A2EC2ULL,
		0x426CECBB5CCFE9C2ULL,
		0x9DDB7C3FF78156FFULL,
		0xFA3CCE1C552B31B3ULL,
		0xFE4F5ACE5A883A2EULL,
		0xBF04CAAD7D9A93FBULL,
		0x8CF36072B52679A8ULL,
		0x31CCABB957578E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ABAD568BD345D84ULL,
		0x84D9D976B99FD384ULL,
		0x3BB6F87FEF02ADFEULL,
		0xF4799C38AA566367ULL,
		0xFC9EB59CB510745DULL,
		0x7E09955AFB3527F7ULL,
		0x19E6C0E56A4CF351ULL,
		0x63995772AEAF1CD5ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCAABAE5AE5750A9ULL,
		0xCB913E12F44B2F5DULL,
		0xE19C67EEF2064E5AULL,
		0x280680E8977249F5ULL,
		0xBAB1FB19CC622787ULL,
		0x7945FDE90E2EBC60ULL,
		0xDD7FF3B35065739BULL,
		0x0857C2CF10EB930AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x795575CB5CAEA152ULL,
		0x97227C25E8965EBBULL,
		0xC338CFDDE40C9CB5ULL,
		0x500D01D12EE493EBULL,
		0x7563F63398C44F0EULL,
		0xF28BFBD21C5D78C1ULL,
		0xBAFFE766A0CAE736ULL,
		0x10AF859E21D72615ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAABCEA85C849185AULL,
		0x1F5722A177047545ULL,
		0x7F59F151C7CBF943ULL,
		0x80B32EA93FD0F3C9ULL,
		0x3F2D1B11E4ADDF33ULL,
		0xD89E802FB7E850BCULL,
		0xCC682872BDE27A23ULL,
		0x18D3BF70F23C4752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5579D50B909230B4ULL,
		0x3EAE4542EE08EA8BULL,
		0xFEB3E2A38F97F286ULL,
		0x01665D527FA1E792ULL,
		0x7E5A3623C95BBE67ULL,
		0xB13D005F6FD0A178ULL,
		0x98D050E57BC4F447ULL,
		0x31A77EE1E4788EA5ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x782BC59664A48984ULL,
		0xD32EEFA16B6878B2ULL,
		0x4D2DE9518B74B0F4ULL,
		0x71D1FAE609BDE4AAULL,
		0x03B9CFE6C687D866ULL,
		0x743312EA1B661BB0ULL,
		0x8A94B8E8E51932ADULL,
		0x14D46A1934967379ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0578B2CC9491308ULL,
		0xA65DDF42D6D0F164ULL,
		0x9A5BD2A316E961E9ULL,
		0xE3A3F5CC137BC954ULL,
		0x07739FCD8D0FB0CCULL,
		0xE86625D436CC3760ULL,
		0x152971D1CA32655AULL,
		0x29A8D432692CE6F3ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC5CBF2956B4DD959ULL,
		0xF9B5AAAA80C1C0E1ULL,
		0xF69CB3ED656312A9ULL,
		0xAC3ECA86749F4621ULL,
		0x5564FD429D9DD9E8ULL,
		0x05BA6A97AB95FFAAULL,
		0xDC4971FCF9563BC5ULL,
		0x2CF3DA27582924ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B97E52AD69BB2B2ULL,
		0xF36B5555018381C3ULL,
		0xED3967DACAC62553ULL,
		0x587D950CE93E8C43ULL,
		0xAAC9FA853B3BB3D1ULL,
		0x0B74D52F572BFF54ULL,
		0xB892E3F9F2AC778AULL,
		0x59E7B44EB0524957ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x23DBF368111FF93FULL,
		0x42DEF50CEB6D28D2ULL,
		0xA1DFCB47E42FD9A4ULL,
		0x0837DACA1BFEA1BBULL,
		0xE2E900C6C2D6AB4EULL,
		0x87AC57FF023D6722ULL,
		0xB710DB2960CF9705ULL,
		0x1158A674A2461762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B7E6D0223FF27EULL,
		0x85BDEA19D6DA51A4ULL,
		0x43BF968FC85FB348ULL,
		0x106FB59437FD4377ULL,
		0xC5D2018D85AD569CULL,
		0x0F58AFFE047ACE45ULL,
		0x6E21B652C19F2E0BULL,
		0x22B14CE9448C2EC5ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF6E833EFCEB3D41AULL,
		0xE49E43A60958E7EDULL,
		0xA541146E73FEAE10ULL,
		0x8A0151FFBE80D2C9ULL,
		0xC87C1B1EA4A667CCULL,
		0xCD1991C585E7B628ULL,
		0xCED47AA824391A5AULL,
		0x11CCA29ADAF7FEC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD067DF9D67A834ULL,
		0xC93C874C12B1CFDBULL,
		0x4A8228DCE7FD5C21ULL,
		0x1402A3FF7D01A593ULL,
		0x90F8363D494CCF99ULL,
		0x9A33238B0BCF6C51ULL,
		0x9DA8F550487234B5ULL,
		0x23994535B5EFFD93ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBF0C7B95D6243245ULL,
		0x3B8384884E6A6FE0ULL,
		0x4155FC98716CB115ULL,
		0x82CA9BCBD8720769ULL,
		0xE2EEA29F04488ACAULL,
		0x64ECAED1950366B0ULL,
		0x0158E8EDBE94FC9EULL,
		0x0E884F86F6B93A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E18F72BAC48648AULL,
		0x770709109CD4DFC1ULL,
		0x82ABF930E2D9622AULL,
		0x05953797B0E40ED2ULL,
		0xC5DD453E08911595ULL,
		0xC9D95DA32A06CD61ULL,
		0x02B1D1DB7D29F93CULL,
		0x1D109F0DED727488ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6A046C766765A82EULL,
		0x000EB56372410FA5ULL,
		0xACC7DD2FB5FA9775ULL,
		0x1B706264D2EC0CD4ULL,
		0xB326FF752141D265ULL,
		0xF08D84EE0B4EFFA7ULL,
		0xED0F7B00134915CFULL,
		0x3DE41673E9DE685DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD408D8ECCECB505CULL,
		0x001D6AC6E4821F4AULL,
		0x598FBA5F6BF52EEAULL,
		0x36E0C4C9A5D819A9ULL,
		0x664DFEEA4283A4CAULL,
		0xE11B09DC169DFF4FULL,
		0xDA1EF60026922B9FULL,
		0x7BC82CE7D3BCD0BBULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x608ADCCB070D4AB0ULL,
		0xDD9DDCC7135F76DDULL,
		0xA5861794D75AE752ULL,
		0x8803B6556C4EE636ULL,
		0x6A5821C3D66F85E2ULL,
		0x7A3B718CE78FF747ULL,
		0x9CCB477BD88699BAULL,
		0x33B3D4201805E818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC115B9960E1A9560ULL,
		0xBB3BB98E26BEEDBAULL,
		0x4B0C2F29AEB5CEA5ULL,
		0x10076CAAD89DCC6DULL,
		0xD4B04387ACDF0BC5ULL,
		0xF476E319CF1FEE8EULL,
		0x39968EF7B10D3374ULL,
		0x6767A840300BD031ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x61967ADFDC204134ULL,
		0x957E83508440908AULL,
		0x78B9F0D72E2D7DC0ULL,
		0x4877F128556C0CCCULL,
		0xB3C4D5116D41A778ULL,
		0x11E9480FE56204C3ULL,
		0xCB569A2B1652D5DAULL,
		0x2643ABFE78917282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32CF5BFB8408268ULL,
		0x2AFD06A108812114ULL,
		0xF173E1AE5C5AFB81ULL,
		0x90EFE250AAD81998ULL,
		0x6789AA22DA834EF0ULL,
		0x23D2901FCAC40987ULL,
		0x96AD34562CA5ABB4ULL,
		0x4C8757FCF122E505ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xCB112BE488063DB9ULL,
		0x460D12545AD853F1ULL,
		0xC0347784F7281E8DULL,
		0x6378AB880FE4073CULL,
		0xD1A163FC5EC72618ULL,
		0x7F79828E2788C2ABULL,
		0xA65A68D20C8860C6ULL,
		0x3EBE99044522A661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962257C9100C7B72ULL,
		0x8C1A24A8B5B0A7E3ULL,
		0x8068EF09EE503D1AULL,
		0xC6F157101FC80E79ULL,
		0xA342C7F8BD8E4C30ULL,
		0xFEF3051C4F118557ULL,
		0x4CB4D1A41910C18CULL,
		0x7D7D32088A454CC3ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA54991FDD4FF4143ULL,
		0x195623A1CFF0F0EDULL,
		0xBCD320BD7849A7C2ULL,
		0xA3E8B60307EDBC55ULL,
		0xEEFC5494DE050498ULL,
		0x8B2AAFDF4F088E1CULL,
		0x53B54F6C96C14F13ULL,
		0x31CFCCEA9B1651DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A9323FBA9FE8286ULL,
		0x32AC47439FE1E1DBULL,
		0x79A6417AF0934F84ULL,
		0x47D16C060FDB78ABULL,
		0xDDF8A929BC0A0931ULL,
		0x16555FBE9E111C39ULL,
		0xA76A9ED92D829E27ULL,
		0x639F99D5362CA3BEULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1DA9ECE1AC8C6B5FULL,
		0x4819E729617212BBULL,
		0x018E3FF634C87A76ULL,
		0xBD8D9DE57CB79383ULL,
		0xF703A37D0DBD109FULL,
		0x2C58E7DEC454F16CULL,
		0x731A52A628CB99CBULL,
		0x2E26BC9FA51FC083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B53D9C35918D6BEULL,
		0x9033CE52C2E42576ULL,
		0x031C7FEC6990F4ECULL,
		0x7B1B3BCAF96F2706ULL,
		0xEE0746FA1B7A213FULL,
		0x58B1CFBD88A9E2D9ULL,
		0xE634A54C51973396ULL,
		0x5C4D793F4A3F8106ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xC9F7C9119826786FULL,
		0x09F7035514583D4EULL,
		0x78EDEB7899EA3129ULL,
		0xD2C9CC112BBC5A6BULL,
		0x422E3EB8BB64061EULL,
		0x0ED3F1956C8CF6DFULL,
		0x1C2D0934EAFBDEA2ULL,
		0x2E285F7E6E77ECFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93EF9223304CF0DEULL,
		0x13EE06AA28B07A9DULL,
		0xF1DBD6F133D46252ULL,
		0xA59398225778B4D6ULL,
		0x845C7D7176C80C3DULL,
		0x1DA7E32AD919EDBEULL,
		0x385A1269D5F7BD44ULL,
		0x5C50BEFCDCEFD9FAULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x91B26D1AB2778935ULL,
		0x368A2F62D1E7936BULL,
		0x5C2E1D43C94F7196ULL,
		0x899A772CE91E6D5CULL,
		0xF651F65472FBB5E9ULL,
		0x606F44E66EC1514BULL,
		0x76560416DC260486ULL,
		0x0C4BAF3568988AE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2364DA3564EF126AULL,
		0x6D145EC5A3CF26D7ULL,
		0xB85C3A87929EE32CULL,
		0x1334EE59D23CDAB8ULL,
		0xECA3ECA8E5F76BD3ULL,
		0xC0DE89CCDD82A297ULL,
		0xECAC082DB84C090CULL,
		0x18975E6AD13115C4ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x75D49C0CA222AAF0ULL,
		0xC12900C96EE93DC6ULL,
		0x2EF0BBF39CA436E2ULL,
		0x0A8248C6730ABD17ULL,
		0x03D0339C7B1942A1ULL,
		0xE04AE213907E1913ULL,
		0x35987F97381C4A9DULL,
		0x17543A05CCD9649FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBA93819444555E0ULL,
		0x82520192DDD27B8CULL,
		0x5DE177E739486DC5ULL,
		0x1504918CE6157A2EULL,
		0x07A06738F6328542ULL,
		0xC095C42720FC3226ULL,
		0x6B30FF2E7038953BULL,
		0x2EA8740B99B2C93EULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xF87423F75281F954ULL,
		0x7E713F23021D2CEEULL,
		0xC7621C87D2341317ULL,
		0x7E83189C06649DEDULL,
		0x07F9795969AF4F0EULL,
		0x4D0494748DE70182ULL,
		0x553D88469EC04389ULL,
		0x05E913EC5BADE71CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E847EEA503F2A8ULL,
		0xFCE27E46043A59DDULL,
		0x8EC4390FA468262EULL,
		0xFD0631380CC93BDBULL,
		0x0FF2F2B2D35E9E1CULL,
		0x9A0928E91BCE0304ULL,
		0xAA7B108D3D808712ULL,
		0x0BD227D8B75BCE38ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xACA2F2FACCDFD74FULL,
		0x56B43B819B7E0A55ULL,
		0x5784EA8577D61007ULL,
		0x69A91D642D0B17EFULL,
		0xB7D5B5EC6FAC9597ULL,
		0x2B3705A2FB093637ULL,
		0xC7DC4C4FB8A2F84FULL,
		0x34B5C98D41BF0C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5945E5F599BFAE9EULL,
		0xAD68770336FC14ABULL,
		0xAF09D50AEFAC200EULL,
		0xD3523AC85A162FDEULL,
		0x6FAB6BD8DF592B2EULL,
		0x566E0B45F6126C6FULL,
		0x8FB8989F7145F09EULL,
		0x696B931A837E1897ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAC6A6DCF89BC8B0EULL,
		0x4BAC84E894AA6A5EULL,
		0x751BC921F2A5D33DULL,
		0xA7B1EA530FF6A1BEULL,
		0x6729F506B3CBA1D3ULL,
		0x9BEF9D4B7F22E159ULL,
		0xB568E380B912500BULL,
		0x115A37FFB045286CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58D4DB9F1379161CULL,
		0x975909D12954D4BDULL,
		0xEA379243E54BA67AULL,
		0x4F63D4A61FED437CULL,
		0xCE53EA0D679743A7ULL,
		0x37DF3A96FE45C2B2ULL,
		0x6AD1C7017224A017ULL,
		0x22B46FFF608A50D9ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x9FE37C72AFEC56B8ULL,
		0x52CA0A7A6A997673ULL,
		0xECEDD3BA9F493592ULL,
		0x093B7DD5A773F779ULL,
		0xD7E2D4253C69518AULL,
		0xB00201BB25713EB7ULL,
		0xC7CECEBF97D82654ULL,
		0x183BC16162924143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC6F8E55FD8AD70ULL,
		0xA59414F4D532ECE7ULL,
		0xD9DBA7753E926B24ULL,
		0x1276FBAB4EE7EEF3ULL,
		0xAFC5A84A78D2A314ULL,
		0x600403764AE27D6FULL,
		0x8F9D9D7F2FB04CA9ULL,
		0x307782C2C5248287ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x371172FC569C7FE3ULL,
		0x6470BD84F4587DB0ULL,
		0xFB5246535877136AULL,
		0xFC0888D180322546ULL,
		0x220CDDDED6BD4D65ULL,
		0x69DE6A8660F37D66ULL,
		0xA7B6C49F3F3AF1AAULL,
		0x2A9E83A9866D84C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E22E5F8AD38FFC6ULL,
		0xC8E17B09E8B0FB60ULL,
		0xF6A48CA6B0EE26D4ULL,
		0xF81111A300644A8DULL,
		0x4419BBBDAD7A9ACBULL,
		0xD3BCD50CC1E6FACCULL,
		0x4F6D893E7E75E354ULL,
		0x553D07530CDB0991ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x191B26F94676141CULL,
		0xA9452860E33569D9ULL,
		0xDF9AF0D5AB792434ULL,
		0x06C0ED2DEAF8964EULL,
		0x9C581C81CB9791FFULL,
		0x625D60EE97132CA4ULL,
		0x6B06FFBC85E41D27ULL,
		0x2A1A61F56B7048A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32364DF28CEC2838ULL,
		0x528A50C1C66AD3B2ULL,
		0xBF35E1AB56F24869ULL,
		0x0D81DA5BD5F12C9DULL,
		0x38B03903972F23FEULL,
		0xC4BAC1DD2E265949ULL,
		0xD60DFF790BC83A4EULL,
		0x5434C3EAD6E09142ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0F4873329FEDC619ULL,
		0xD81F17EAD9D32062ULL,
		0x1C8F29ACD735920AULL,
		0xAA8CD76598CDAB42ULL,
		0x3742F494D18377C6ULL,
		0x8F260564C43A36E2ULL,
		0x2997B0EB9E2CE7D5ULL,
		0x36326DB67009548AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E90E6653FDB8C32ULL,
		0xB03E2FD5B3A640C4ULL,
		0x391E5359AE6B2415ULL,
		0x5519AECB319B5684ULL,
		0x6E85E929A306EF8DULL,
		0x1E4C0AC988746DC4ULL,
		0x532F61D73C59CFABULL,
		0x6C64DB6CE012A914ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F119B8C1A844009ULL,
		0xA42DA7EF79B15858ULL,
		0x76B2FF712C55A1B7ULL,
		0xDFDCDE356214D22CULL,
		0xA4F17C88592E8F1CULL,
		0x4CC55FB0F3CD90CFULL,
		0xC5E4ABF1A5E54209ULL,
		0x3C1D89B896E0F98EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E23371835088012ULL,
		0x485B4FDEF362B0B0ULL,
		0xED65FEE258AB436FULL,
		0xBFB9BC6AC429A458ULL,
		0x49E2F910B25D1E39ULL,
		0x998ABF61E79B219FULL,
		0x8BC957E34BCA8412ULL,
		0x783B13712DC1F31DULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1C166264EDD9435EULL,
		0xB8FDBCDD6E50CF4DULL,
		0x5486591555B1470DULL,
		0x39118C2ED3C5E53BULL,
		0x1EAF6A75D5BCB3E6ULL,
		0xFF5C16F120CDD067ULL,
		0xE23209B9A4034423ULL,
		0x2CD748AE1F56123CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x382CC4C9DBB286BCULL,
		0x71FB79BADCA19E9AULL,
		0xA90CB22AAB628E1BULL,
		0x7223185DA78BCA76ULL,
		0x3D5ED4EBAB7967CCULL,
		0xFEB82DE2419BA0CEULL,
		0xC464137348068847ULL,
		0x59AE915C3EAC2479ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE5FA11D4757AAED9ULL,
		0x575A627727B83607ULL,
		0x3EE8593B973F0A68ULL,
		0xEB387683F455EE2FULL,
		0xE9B8341797F15E23ULL,
		0x351B3C32C84EBF32ULL,
		0xB535365AA9B968F2ULL,
		0x3B0078973DB4329EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBF423A8EAF55DB2ULL,
		0xAEB4C4EE4F706C0FULL,
		0x7DD0B2772E7E14D0ULL,
		0xD670ED07E8ABDC5EULL,
		0xD370682F2FE2BC47ULL,
		0x6A367865909D7E65ULL,
		0x6A6A6CB55372D1E4ULL,
		0x7600F12E7B68653DULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD2A1358DE1A9970FULL,
		0x3788B7BC03681B54ULL,
		0x5FEEA860673FD0B2ULL,
		0xD00AC1D643274B56ULL,
		0x27B105F97D732125ULL,
		0x506253885F418180ULL,
		0x48353CCFDF8C3576ULL,
		0x160D05BED826A8CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5426B1BC3532E1EULL,
		0x6F116F7806D036A9ULL,
		0xBFDD50C0CE7FA164ULL,
		0xA01583AC864E96ACULL,
		0x4F620BF2FAE6424BULL,
		0xA0C4A710BE830300ULL,
		0x906A799FBF186AECULL,
		0x2C1A0B7DB04D5194ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x03B8F6F90D6C5224ULL,
		0x090EA9405F955804ULL,
		0xBCF6D3B9F5FE00DDULL,
		0x40E4B947D48E9D5DULL,
		0x289E7F9788909DBEULL,
		0xE8F92C4C11DE5E50ULL,
		0xE9DCDD974D9673A7ULL,
		0x2249D87FD0696176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0771EDF21AD8A448ULL,
		0x121D5280BF2AB008ULL,
		0x79EDA773EBFC01BAULL,
		0x81C9728FA91D3ABBULL,
		0x513CFF2F11213B7CULL,
		0xD1F2589823BCBCA0ULL,
		0xD3B9BB2E9B2CE74FULL,
		0x4493B0FFA0D2C2EDULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x379E923FADDCFD1AULL,
		0x48BF0521C36FB9CFULL,
		0xE5B5A3DA0BC77EF3ULL,
		0x879219216436BC61ULL,
		0x7AFE960E618A3BE1ULL,
		0x1B5F67ECFBE99699ULL,
		0xB9435053B302932AULL,
		0x2887C77A5AF6CE61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F3D247F5BB9FA34ULL,
		0x917E0A4386DF739EULL,
		0xCB6B47B4178EFDE6ULL,
		0x0F243242C86D78C3ULL,
		0xF5FD2C1CC31477C3ULL,
		0x36BECFD9F7D32D32ULL,
		0x7286A0A766052654ULL,
		0x510F8EF4B5ED9CC3ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x08DA2AA94C6493AFULL,
		0x2614670FAE4C9409ULL,
		0xBBC3334DA8C45C78ULL,
		0x3ED9C7DE64DD191EULL,
		0xA4DFEBA13A66F78AULL,
		0x0E71D5895D8DB049ULL,
		0x98D5B21D39819AF6ULL,
		0x35CCB016427D00AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B4555298C9275EULL,
		0x4C28CE1F5C992812ULL,
		0x7786669B5188B8F0ULL,
		0x7DB38FBCC9BA323DULL,
		0x49BFD74274CDEF14ULL,
		0x1CE3AB12BB1B6093ULL,
		0x31AB643A730335ECULL,
		0x6B99602C84FA015FULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x116CFD63FF1346A2ULL,
		0x405B8F49E49E2C2FULL,
		0x24141CB683616BFBULL,
		0x7674B3EC6782F5B3ULL,
		0x73B53EB4A2E208B5ULL,
		0xD81C0894129A55FCULL,
		0x6189645CA8D40B11ULL,
		0x132F33760065F97CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22D9FAC7FE268D44ULL,
		0x80B71E93C93C585EULL,
		0x4828396D06C2D7F6ULL,
		0xECE967D8CF05EB66ULL,
		0xE76A7D6945C4116AULL,
		0xB03811282534ABF8ULL,
		0xC312C8B951A81623ULL,
		0x265E66EC00CBF2F8ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE4E7B7D9849459F8ULL,
		0x6EFB8BFC337B6DC2ULL,
		0x6E42AB419751FAD0ULL,
		0x9E976306CB35D3E6ULL,
		0x008A79F179BA81D1ULL,
		0x04B6F610BE704595ULL,
		0xAFC04FCD07E9B511ULL,
		0x1E4313E49C9C8313ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9CF6FB30928B3F0ULL,
		0xDDF717F866F6DB85ULL,
		0xDC8556832EA3F5A0ULL,
		0x3D2EC60D966BA7CCULL,
		0x0114F3E2F37503A3ULL,
		0x096DEC217CE08B2AULL,
		0x5F809F9A0FD36A22ULL,
		0x3C8627C939390627ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xB044BD63B3F5DC26ULL,
		0xCD1F0C6C97654605ULL,
		0x3B94C8E7D4000635ULL,
		0x48F0F037407580B3ULL,
		0x4720D9F55064B4BEULL,
		0x7835B6A6648698B6ULL,
		0x0CD7322CC26585FFULL,
		0x3EF14377850AC9F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60897AC767EBB84CULL,
		0x9A3E18D92ECA8C0BULL,
		0x772991CFA8000C6BULL,
		0x91E1E06E80EB0166ULL,
		0x8E41B3EAA0C9697CULL,
		0xF06B6D4CC90D316CULL,
		0x19AE645984CB0BFEULL,
		0x7DE286EF0A1593E8ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFD9342B857B4844AULL,
		0xB7EAEDA1E46A1CB9ULL,
		0x8EABF26762CA0230ULL,
		0x4C2A8FA5090EBC7EULL,
		0xF2F158D6BEF677F5ULL,
		0x22B054BC7E6AC47FULL,
		0x43837FB2EF23F550ULL,
		0x1882486B27DA0065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB268570AF690894ULL,
		0x6FD5DB43C8D43973ULL,
		0x1D57E4CEC5940461ULL,
		0x98551F4A121D78FDULL,
		0xE5E2B1AD7DECEFEAULL,
		0x4560A978FCD588FFULL,
		0x8706FF65DE47EAA0ULL,
		0x310490D64FB400CAULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xEDA5EA718FB44ECCULL,
		0x8C4E608A07DBE64EULL,
		0x5AB9F9B3F993C21CULL,
		0xD7445456A87FA2BEULL,
		0x4E716CCA21641E1FULL,
		0x3D25E95BFE0DAAF6ULL,
		0xAE9F8AC47A74F811ULL,
		0x359C165CCD376140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4BD4E31F689D98ULL,
		0x189CC1140FB7CC9DULL,
		0xB573F367F3278439ULL,
		0xAE88A8AD50FF457CULL,
		0x9CE2D99442C83C3FULL,
		0x7A4BD2B7FC1B55ECULL,
		0x5D3F1588F4E9F022ULL,
		0x6B382CB99A6EC281ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDFA5E75A28101AEDULL,
		0xDFCF7CBD6E90CF0BULL,
		0x8558538FE6440713ULL,
		0xA8064BFC5DA8C5F1ULL,
		0xC73FC4E4F739D0FDULL,
		0x197C69B1BCEEE211ULL,
		0x08CA5E53992A0E78ULL,
		0x23BF1869FA294395ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4BCEB4502035DAULL,
		0xBF9EF97ADD219E17ULL,
		0x0AB0A71FCC880E27ULL,
		0x500C97F8BB518BE3ULL,
		0x8E7F89C9EE73A1FBULL,
		0x32F8D36379DDC423ULL,
		0x1194BCA732541CF0ULL,
		0x477E30D3F452872AULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8F20C27E68476FD9ULL,
		0xAFEC93C6E94F07F2ULL,
		0xAA10AB3A0B62AC26ULL,
		0x2C84E8EC24D3D5FAULL,
		0x5B29405F944A2425ULL,
		0x1897914FE150CC2FULL,
		0xA18A964ADDF71543ULL,
		0x02648E3D72DB27EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E4184FCD08EDFB2ULL,
		0x5FD9278DD29E0FE5ULL,
		0x5421567416C5584DULL,
		0x5909D1D849A7ABF5ULL,
		0xB65280BF2894484AULL,
		0x312F229FC2A1985EULL,
		0x43152C95BBEE2A86ULL,
		0x04C91C7AE5B64FDFULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD87E73629E44B357ULL,
		0xFC2F2C59A87EEB2CULL,
		0x42EE94042E222C6BULL,
		0x162ACD139A187BB4ULL,
		0x94725F8EA281B466ULL,
		0xDEF61BAA333418B4ULL,
		0xA35E8184A8110886ULL,
		0x34ED33D9413FD980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0FCE6C53C8966AEULL,
		0xF85E58B350FDD659ULL,
		0x85DD28085C4458D7ULL,
		0x2C559A273430F768ULL,
		0x28E4BF1D450368CCULL,
		0xBDEC375466683169ULL,
		0x46BD03095022110DULL,
		0x69DA67B2827FB301ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE811050A58A5B1D9ULL,
		0xA85E82709B724A33ULL,
		0x53694E3F44EE7CF7ULL,
		0xA2CE4D944EBFFDC4ULL,
		0x871066494F249813ULL,
		0x829F941ED0AA9DF6ULL,
		0xACA17363CF907B54ULL,
		0x162FE2E43C3F017CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0220A14B14B63B2ULL,
		0x50BD04E136E49467ULL,
		0xA6D29C7E89DCF9EFULL,
		0x459C9B289D7FFB88ULL,
		0x0E20CC929E493027ULL,
		0x053F283DA1553BEDULL,
		0x5942E6C79F20F6A9ULL,
		0x2C5FC5C8787E02F9ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3CA2A22605A62B7BULL,
		0x488D8C090FEAB66CULL,
		0x1C1CF3F3CA91A0C3ULL,
		0xCA74C7FC6644E64DULL,
		0xFE173EC385A5D072ULL,
		0x02A3A836AF9EFA76ULL,
		0x0A08DD721F8ED2ECULL,
		0x36E7FC5763EB25F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7945444C0B4C56F6ULL,
		0x911B18121FD56CD8ULL,
		0x3839E7E795234186ULL,
		0x94E98FF8CC89CC9AULL,
		0xFC2E7D870B4BA0E5ULL,
		0x0547506D5F3DF4EDULL,
		0x1411BAE43F1DA5D8ULL,
		0x6DCFF8AEC7D64BE4ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4A153A34741B6E84ULL,
		0x95DA620B68B0D982ULL,
		0x6C3886973656FA33ULL,
		0xCD550D241CEDEE2EULL,
		0xFD800BDCA093FC1BULL,
		0x0A466285B4ED83EBULL,
		0xBFFF04487B8F4742ULL,
		0x1F75D73D8C2172D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x942A7468E836DD08ULL,
		0x2BB4C416D161B304ULL,
		0xD8710D2E6CADF467ULL,
		0x9AAA1A4839DBDC5CULL,
		0xFB0017B94127F837ULL,
		0x148CC50B69DB07D7ULL,
		0x7FFE0890F71E8E84ULL,
		0x3EEBAE7B1842E5A3ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x961D473952AFB2A7ULL,
		0x98EE1610B0C6CCBBULL,
		0x5C5ABAD5C0C7EAE2ULL,
		0x8CF96EF6EFA24722ULL,
		0xDE303C4F35878328ULL,
		0x38E9B9DC850E764EULL,
		0x249DAC6722EF016DULL,
		0x239E308634903CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C3A8E72A55F654EULL,
		0x31DC2C21618D9977ULL,
		0xB8B575AB818FD5C5ULL,
		0x19F2DDEDDF448E44ULL,
		0xBC60789E6B0F0651ULL,
		0x71D373B90A1CEC9DULL,
		0x493B58CE45DE02DAULL,
		0x473C610C6920798CULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7C827B2D0D7789C7ULL,
		0x72CB1367EEBCA3BBULL,
		0x7764AD87F925237DULL,
		0xB6CD7A7FF4381A84ULL,
		0x3102E7027AFE018CULL,
		0x3E954AEED96EB26BULL,
		0x89D51B064DB3012AULL,
		0x1C29350DB4B62269ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF904F65A1AEF138EULL,
		0xE59626CFDD794776ULL,
		0xEEC95B0FF24A46FAULL,
		0x6D9AF4FFE8703508ULL,
		0x6205CE04F5FC0319ULL,
		0x7D2A95DDB2DD64D6ULL,
		0x13AA360C9B660254ULL,
		0x38526A1B696C44D3ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFB584F4EECF60838ULL,
		0x76A26489C733EFF6ULL,
		0x2A8562D00D16430BULL,
		0xE6695EEE924362F0ULL,
		0xC9FAC8C19EB8BB2DULL,
		0xFCE64C31E21ACEE4ULL,
		0xEE48DF813A4EAE33ULL,
		0x2222BF69168D623AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6B09E9DD9EC1070ULL,
		0xED44C9138E67DFEDULL,
		0x550AC5A01A2C8616ULL,
		0xCCD2BDDD2486C5E0ULL,
		0x93F591833D71765BULL,
		0xF9CC9863C4359DC9ULL,
		0xDC91BF02749D5C67ULL,
		0x44457ED22D1AC475ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x471AEAA284215203ULL,
		0xFABAD236D350290BULL,
		0xCBFC21037D833547ULL,
		0xE116981D8889AC4BULL,
		0x5CC5448AC0AF8411ULL,
		0x5EF3EB1B4EB86C5EULL,
		0xF35694B5CD47858FULL,
		0x305A2DB44E560955ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E35D5450842A406ULL,
		0xF575A46DA6A05216ULL,
		0x97F84206FB066A8FULL,
		0xC22D303B11135897ULL,
		0xB98A8915815F0823ULL,
		0xBDE7D6369D70D8BCULL,
		0xE6AD296B9A8F0B1EULL,
		0x60B45B689CAC12ABULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE38EE33BA55A6AC3ULL,
		0x8F495C28A540FFD9ULL,
		0x69DF1E91915E4D91ULL,
		0x03F43B5CE5B75D9AULL,
		0xD78FDC798D9ED7A4ULL,
		0x6A0B55294AB97578ULL,
		0x46CB55871A7007D2ULL,
		0x3B6077FE7F4D816EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71DC6774AB4D586ULL,
		0x1E92B8514A81FFB3ULL,
		0xD3BE3D2322BC9B23ULL,
		0x07E876B9CB6EBB34ULL,
		0xAF1FB8F31B3DAF48ULL,
		0xD416AA529572EAF1ULL,
		0x8D96AB0E34E00FA4ULL,
		0x76C0EFFCFE9B02DCULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD7A1750659B754EBULL,
		0x8B6D7A8C1EA354C8ULL,
		0x13D7979794459FA5ULL,
		0xB9180860D9831717ULL,
		0x216DBB4F7E1D0812ULL,
		0x6AD557DC1F2AFDAEULL,
		0x282E7F4010F889ABULL,
		0x0EEB58BD5CA58517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF42EA0CB36EA9D6ULL,
		0x16DAF5183D46A991ULL,
		0x27AF2F2F288B3F4BULL,
		0x723010C1B3062E2EULL,
		0x42DB769EFC3A1025ULL,
		0xD5AAAFB83E55FB5CULL,
		0x505CFE8021F11356ULL,
		0x1DD6B17AB94B0A2EULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7EE29BC27102576DULL,
		0xE890E3C1B90180BCULL,
		0xC679D6A6C7689B75ULL,
		0x1949F8AC85C9CB0AULL,
		0x7E4A6FFD320760EFULL,
		0x17EC9BF77072A2FBULL,
		0xED4E33FA7F1CFBC9ULL,
		0x3689B3836A1B9BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDC53784E204AEDAULL,
		0xD121C78372030178ULL,
		0x8CF3AD4D8ED136EBULL,
		0x3293F1590B939615ULL,
		0xFC94DFFA640EC1DEULL,
		0x2FD937EEE0E545F6ULL,
		0xDA9C67F4FE39F792ULL,
		0x6D136706D437379FULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x4CA626F74133B78AULL,
		0x72752F10B24F677BULL,
		0x8F0A8D71E970D531ULL,
		0x13192EAAC5D8EE35ULL,
		0xB628FF2609C63CD5ULL,
		0x1B23BC602E20243CULL,
		0x8D2E29ED1092C7C4ULL,
		0x027061C8823CEE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994C4DEE82676F14ULL,
		0xE4EA5E21649ECEF6ULL,
		0x1E151AE3D2E1AA62ULL,
		0x26325D558BB1DC6BULL,
		0x6C51FE4C138C79AAULL,
		0x364778C05C404879ULL,
		0x1A5C53DA21258F88ULL,
		0x04E0C3910479DC83ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x0A1A03E8D082849AULL,
		0x8B428713CC138BC1ULL,
		0x1ED415715F8FA4D4ULL,
		0x1F103C9B26819B8CULL,
		0xB046EB6E37326496ULL,
		0xABC35A78EC9CC072ULL,
		0x0D5028E3841C70C7ULL,
		0x2257DE04F6BA7656ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143407D1A1050934ULL,
		0x16850E2798271782ULL,
		0x3DA82AE2BF1F49A9ULL,
		0x3E2079364D033718ULL,
		0x608DD6DC6E64C92CULL,
		0x5786B4F1D93980E5ULL,
		0x1AA051C70838E18FULL,
		0x44AFBC09ED74ECACULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7BFD6628D425BCFFULL,
		0x89EA2A1367EA341BULL,
		0xFF7D6060B5E30B4AULL,
		0x72EB9AC1F21ED786ULL,
		0xB900C9E10ABB090CULL,
		0x4458ADB008A6C22EULL,
		0x100F8F752E5665C9ULL,
		0x1569029AF6C9326BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7FACC51A84B79FEULL,
		0x13D45426CFD46836ULL,
		0xFEFAC0C16BC61695ULL,
		0xE5D73583E43DAF0DULL,
		0x720193C215761218ULL,
		0x88B15B60114D845DULL,
		0x201F1EEA5CACCB92ULL,
		0x2AD20535ED9264D6ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x098925883F9BD182ULL,
		0x5AAE3D86AC605796ULL,
		0x45FE3F9B9C81ED9EULL,
		0xEB5F3D8585271F91ULL,
		0xB01E2D499577B6B5ULL,
		0xA1FFF44C28935190ULL,
		0x033091578EFAB355ULL,
		0x3191BC3A9C5551EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13124B107F37A304ULL,
		0xB55C7B0D58C0AF2CULL,
		0x8BFC7F373903DB3CULL,
		0xD6BE7B0B0A4E3F22ULL,
		0x603C5A932AEF6D6BULL,
		0x43FFE8985126A321ULL,
		0x066122AF1DF566ABULL,
		0x6323787538AAA3DEULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x591DD7A4E21E3562ULL,
		0x2A8CD23ADB50D082ULL,
		0x3512BDA03107B92EULL,
		0x5D3F7F205E604B6EULL,
		0x5BFEF36AB8A84F16ULL,
		0x897B8BC3A90F9E34ULL,
		0xBCBEF00ACA59DFC4ULL,
		0x1E0CFB1A487CAE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB23BAF49C43C6AC4ULL,
		0x5519A475B6A1A104ULL,
		0x6A257B40620F725CULL,
		0xBA7EFE40BCC096DCULL,
		0xB7FDE6D571509E2CULL,
		0x12F71787521F3C68ULL,
		0x797DE01594B3BF89ULL,
		0x3C19F63490F95C0FULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x95BF695C2330FCF5ULL,
		0xA42726F0EBDD5363ULL,
		0xF736125F67A0748BULL,
		0xBC84C9647198F869ULL,
		0xC95A743760A1AC75ULL,
		0xD5579C4923FC4EA0ULL,
		0xBD5452EFE3D675B2ULL,
		0x10CEE63FBE3E2F16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7ED2B84661F9EAULL,
		0x484E4DE1D7BAA6C7ULL,
		0xEE6C24BECF40E917ULL,
		0x790992C8E331F0D3ULL,
		0x92B4E86EC14358EBULL,
		0xAAAF389247F89D41ULL,
		0x7AA8A5DFC7ACEB65ULL,
		0x219DCC7F7C7C5E2DULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3D05693E4CD6F039ULL,
		0x00292BADE36367E1ULL,
		0xA1B8EE6A0E1442D3ULL,
		0x94994573B1DF82F0ULL,
		0xA9519CC7624711F5ULL,
		0x86662622C24596E9ULL,
		0x9F2EBFC6E3702958ULL,
		0x2DF03FEA3D1BB57AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A0AD27C99ADE072ULL,
		0x0052575BC6C6CFC2ULL,
		0x4371DCD41C2885A6ULL,
		0x29328AE763BF05E1ULL,
		0x52A3398EC48E23EBULL,
		0x0CCC4C45848B2DD3ULL,
		0x3E5D7F8DC6E052B1ULL,
		0x5BE07FD47A376AF5ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x8835DDA0D428BD81ULL,
		0xBF5E2BDFB51D2612ULL,
		0x29DBB9C679E4CAE1ULL,
		0xF506E1298622DF3DULL,
		0x932A00F404D51965ULL,
		0x77EB8DEF31D9BA2DULL,
		0xC98DC0555194B162ULL,
		0x2E28C722EC359D87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x106BBB41A8517B02ULL,
		0x7EBC57BF6A3A4C25ULL,
		0x53B7738CF3C995C3ULL,
		0xEA0DC2530C45BE7AULL,
		0x265401E809AA32CBULL,
		0xEFD71BDE63B3745BULL,
		0x931B80AAA32962C4ULL,
		0x5C518E45D86B3B0FULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x484AC07CDF028AE9ULL,
		0x64FD3C9590B60EF5ULL,
		0x9405EF4A19E4918FULL,
		0xBB4BBC91255EC485ULL,
		0x2C0460F8032F8D90ULL,
		0x40D188BDC88D9B98ULL,
		0xC1A5E602D1555882ULL,
		0x1B55C978540EF989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909580F9BE0515D2ULL,
		0xC9FA792B216C1DEAULL,
		0x280BDE9433C9231EULL,
		0x769779224ABD890BULL,
		0x5808C1F0065F1B21ULL,
		0x81A3117B911B3730ULL,
		0x834BCC05A2AAB104ULL,
		0x36AB92F0A81DF313ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xFFE39F4FF9C2E460ULL,
		0x3FABAE25AA955C32ULL,
		0xD5388A95E1A34F4AULL,
		0x5BDE2D20402FC535ULL,
		0x9ADBCE97DF1298D3ULL,
		0x50FA865A39970D80ULL,
		0xE62D7097F59F417CULL,
		0x2DDB45948B013F5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC73E9FF385C8C0ULL,
		0x7F575C4B552AB865ULL,
		0xAA71152BC3469E94ULL,
		0xB7BC5A40805F8A6BULL,
		0x35B79D2FBE2531A6ULL,
		0xA1F50CB4732E1B01ULL,
		0xCC5AE12FEB3E82F8ULL,
		0x5BB68B2916027EB7ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x586107E269C4E66EULL,
		0xAD121426D7CA005BULL,
		0x957ADE932B7605B9ULL,
		0x4E0667A76A4ED84FULL,
		0x85C6B964AD07C85AULL,
		0x6B3BC7A57F6630D5ULL,
		0x689DC5AD1E997ABBULL,
		0x13A355058F2B1CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C20FC4D389CCDCULL,
		0x5A24284DAF9400B6ULL,
		0x2AF5BD2656EC0B73ULL,
		0x9C0CCF4ED49DB09FULL,
		0x0B8D72C95A0F90B4ULL,
		0xD6778F4AFECC61ABULL,
		0xD13B8B5A3D32F576ULL,
		0x2746AA0B1E5639E6ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xA4133A176C5F95A2ULL,
		0x70BCA0C1784CEED4ULL,
		0x8C99A78A01D4E62EULL,
		0x7B6AFBF903017013ULL,
		0x0C8D54B03863C059ULL,
		0x7B2F59735C30DDDCULL,
		0x7CFBDE818A353467ULL,
		0x189D2386E0EA494CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4826742ED8BF2B44ULL,
		0xE1794182F099DDA9ULL,
		0x19334F1403A9CC5CULL,
		0xF6D5F7F20602E027ULL,
		0x191AA96070C780B2ULL,
		0xF65EB2E6B861BBB8ULL,
		0xF9F7BD03146A68CEULL,
		0x313A470DC1D49298ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3FC27CC751A3CDC2ULL,
		0xFEEE1781AC3762CCULL,
		0xD65ED9C6B01FB6F9ULL,
		0x9B62096152123FDDULL,
		0x0717294BF694F6CCULL,
		0x2DA01752B7A75EFAULL,
		0x6597F77F9ED44E16ULL,
		0x2A918BDDA22D17CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F84F98EA3479B84ULL,
		0xFDDC2F03586EC598ULL,
		0xACBDB38D603F6DF3ULL,
		0x36C412C2A4247FBBULL,
		0x0E2E5297ED29ED99ULL,
		0x5B402EA56F4EBDF4ULL,
		0xCB2FEEFF3DA89C2CULL,
		0x552317BB445A2F98ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x1A16CF79F9A24B53ULL,
		0xAFD9E2F8630BBD6BULL,
		0xB5C6EC3C11D1C3C0ULL,
		0x77DFAA425D9DC1E1ULL,
		0xA0FA6DF97A6BD400ULL,
		0x616C019A047BE5F6ULL,
		0x4A542836355281FCULL,
		0x23B8466ACC57A0E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342D9EF3F34496A6ULL,
		0x5FB3C5F0C6177AD6ULL,
		0x6B8DD87823A38781ULL,
		0xEFBF5484BB3B83C3ULL,
		0x41F4DBF2F4D7A800ULL,
		0xC2D8033408F7CBEDULL,
		0x94A8506C6AA503F8ULL,
		0x47708CD598AF41CAULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x02D62FE675EECDF6ULL,
		0xE7D4B6AB942323FCULL,
		0xBAC0DD05F06A6DEAULL,
		0xEB18ECC0554EF7F6ULL,
		0x67191D9BAB5743BCULL,
		0x3B22D9D4E141B43CULL,
		0xE62F75A46D5771F4ULL,
		0x1B1B1B3B2CFFA128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05AC5FCCEBDD9BECULL,
		0xCFA96D57284647F8ULL,
		0x7581BA0BE0D4DBD5ULL,
		0xD631D980AA9DEFEDULL,
		0xCE323B3756AE8779ULL,
		0x7645B3A9C2836878ULL,
		0xCC5EEB48DAAEE3E8ULL,
		0x3636367659FF4251ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x169F600C0A3A9791ULL,
		0x18CDF2B05EE76318ULL,
		0x1BB9264E0E51FCA9ULL,
		0xA751D9E798AA5A5CULL,
		0xB8D84530306CDDB0ULL,
		0x1AF9B1B518FD6073ULL,
		0xF50841EA915543B9ULL,
		0x0B3DE5ED95E13ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D3EC01814752F22ULL,
		0x319BE560BDCEC630ULL,
		0x37724C9C1CA3F952ULL,
		0x4EA3B3CF3154B4B8ULL,
		0x71B08A6060D9BB61ULL,
		0x35F3636A31FAC0E7ULL,
		0xEA1083D522AA8772ULL,
		0x167BCBDB2BC27D9FULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x69D3C37149C8D059ULL,
		0x19CE84DFE6D5C529ULL,
		0x85237CFD8E26A517ULL,
		0x8E64ED8466750692ULL,
		0x5814069D05B765AEULL,
		0x25DD53D20CEB40FBULL,
		0x1E8550D603CD0F19ULL,
		0x0EEE7390CA7F17D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A786E29391A0B2ULL,
		0x339D09BFCDAB8A52ULL,
		0x0A46F9FB1C4D4A2EULL,
		0x1CC9DB08CCEA0D25ULL,
		0xB0280D3A0B6ECB5DULL,
		0x4BBAA7A419D681F6ULL,
		0x3D0AA1AC079A1E32ULL,
		0x1DDCE72194FE2FAEULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6999ACB1E1D98F9BULL,
		0xB7AB6A70F298BE40ULL,
		0xD293756C89B81E89ULL,
		0x4E39AF056EB1EA22ULL,
		0x4C3427B49139A9E0ULL,
		0xAB94BD07B5C26DEAULL,
		0xE4DDE86B447EB7B0ULL,
		0x18007765AE071F00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3335963C3B31F36ULL,
		0x6F56D4E1E5317C80ULL,
		0xA526EAD913703D13ULL,
		0x9C735E0ADD63D445ULL,
		0x98684F69227353C0ULL,
		0x57297A0F6B84DBD4ULL,
		0xC9BBD0D688FD6F61ULL,
		0x3000EECB5C0E3E01ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x633A44CD621E029EULL,
		0x488CBCDE283BFE37ULL,
		0x486F68BB637A5336ULL,
		0xC919BC64FF91EE42ULL,
		0xEAD3B7D8F66E0EEEULL,
		0xA5149DD14F983979ULL,
		0x50BD86A7DE10D9E1ULL,
		0x34A5A2E0AC156E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC674899AC43C053CULL,
		0x911979BC5077FC6EULL,
		0x90DED176C6F4A66CULL,
		0x923378C9FF23DC84ULL,
		0xD5A76FB1ECDC1DDDULL,
		0x4A293BA29F3072F3ULL,
		0xA17B0D4FBC21B3C3ULL,
		0x694B45C1582ADD06ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xD96C0BC918EFE2F2ULL,
		0xE80170B8F8A5064AULL,
		0x3B676CFBCFB56A0CULL,
		0xE9850603CAD2E526ULL,
		0x2781D4578CCF44B9ULL,
		0x89F2B1549FE71DE1ULL,
		0x2D9FC11F64AE15C2ULL,
		0x112E4C6CA291428FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D8179231DFC5E4ULL,
		0xD002E171F14A0C95ULL,
		0x76CED9F79F6AD419ULL,
		0xD30A0C0795A5CA4CULL,
		0x4F03A8AF199E8973ULL,
		0x13E562A93FCE3BC2ULL,
		0x5B3F823EC95C2B85ULL,
		0x225C98D94522851EULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x7CD1F1A9F5DE5142ULL,
		0x9EB4CFC55D5388A2ULL,
		0xC51DC62A424BB573ULL,
		0x855EAD019377F34EULL,
		0x3371394EA2122A4BULL,
		0x904517F71384AAFEULL,
		0xCCE0C411CB84932FULL,
		0x34EF45443FADC252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A3E353EBBCA284ULL,
		0x3D699F8ABAA71144ULL,
		0x8A3B8C5484976AE7ULL,
		0x0ABD5A0326EFE69DULL,
		0x66E2729D44245497ULL,
		0x208A2FEE270955FCULL,
		0x99C188239709265FULL,
		0x69DE8A887F5B84A5ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6BDCEA4FFAA69638ULL,
		0xCC4DA380938D999EULL,
		0x15324CF02D5BB2E2ULL,
		0xB10CC99D6AC5A088ULL,
		0xF4BBBFB66C8AD8B7ULL,
		0x512180C3F9F92CD6ULL,
		0x6F5FFD37052E43A3ULL,
		0x0B1D949F5DB2D503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B9D49FF54D2C70ULL,
		0x989B4701271B333CULL,
		0x2A6499E05AB765C5ULL,
		0x6219933AD58B4110ULL,
		0xE9777F6CD915B16FULL,
		0xA2430187F3F259ADULL,
		0xDEBFFA6E0A5C8746ULL,
		0x163B293EBB65AA06ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE282BEED4BFBCAF1ULL,
		0x33911F4F29A93521ULL,
		0xF5D35AB0C1707B53ULL,
		0x2B614A78EC46B42AULL,
		0x08F30FE3CD214463ULL,
		0xFD0CA5E4FD226E9CULL,
		0x8DE6D5D8B2E1581FULL,
		0x29991F2AADEC3A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5057DDA97F795E2ULL,
		0x67223E9E53526A43ULL,
		0xEBA6B56182E0F6A6ULL,
		0x56C294F1D88D6855ULL,
		0x11E61FC79A4288C6ULL,
		0xFA194BC9FA44DD38ULL,
		0x1BCDABB165C2B03FULL,
		0x53323E555BD874A7ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x6D91330058740106ULL,
		0xC3484B516402D0E3ULL,
		0x4EFE84FFB751EEE2ULL,
		0xF84FC5EB16B3F5A6ULL,
		0x41A9C05FA687DF24ULL,
		0xB5DED41AC211028FULL,
		0x34DD570920241CE4ULL,
		0x2BC315B2EB8EAD58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB226600B0E8020CULL,
		0x869096A2C805A1C6ULL,
		0x9DFD09FF6EA3DDC5ULL,
		0xF09F8BD62D67EB4CULL,
		0x835380BF4D0FBE49ULL,
		0x6BBDA8358422051EULL,
		0x69BAAE12404839C9ULL,
		0x57862B65D71D5AB0ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2F4399133C438DE2ULL,
		0xE3CC3C64A1744738ULL,
		0x5EF2504BB6A585F5ULL,
		0x3F9F3CA7E3539568ULL,
		0xEEE0CDD615CD8142ULL,
		0x5C183751F4D7B652ULL,
		0x4D6D7C5EED469524ULL,
		0x09D24A8734642525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E87322678871BC4ULL,
		0xC79878C942E88E70ULL,
		0xBDE4A0976D4B0BEBULL,
		0x7F3E794FC6A72AD0ULL,
		0xDDC19BAC2B9B0284ULL,
		0xB8306EA3E9AF6CA5ULL,
		0x9ADAF8BDDA8D2A48ULL,
		0x13A4950E68C84A4AULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3742AD352A73799AULL,
		0xBCB796ED0281F7D0ULL,
		0xE8F106EB75689C87ULL,
		0xB4B0049DDCF02F98ULL,
		0x6FA509890AFE6C38ULL,
		0xD958AA51FE842D0BULL,
		0x92B5B37284A50B82ULL,
		0x20C7498638EB933CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E855A6A54E6F334ULL,
		0x796F2DDA0503EFA0ULL,
		0xD1E20DD6EAD1390FULL,
		0x6960093BB9E05F31ULL,
		0xDF4A131215FCD871ULL,
		0xB2B154A3FD085A16ULL,
		0x256B66E5094A1705ULL,
		0x418E930C71D72679ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x12F3165D9075013BULL,
		0x966C16B9E2485A32ULL,
		0xC5BF1523D4CDBE61ULL,
		0xB4ED2D9CCA587712ULL,
		0x69971F29B1B68720ULL,
		0xCB58346F5828A28DULL,
		0x30FCA463B267C72EULL,
		0x3617E554EE922253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25E62CBB20EA0276ULL,
		0x2CD82D73C490B464ULL,
		0x8B7E2A47A99B7CC3ULL,
		0x69DA5B3994B0EE25ULL,
		0xD32E3E53636D0E41ULL,
		0x96B068DEB051451AULL,
		0x61F948C764CF8E5DULL,
		0x6C2FCAA9DD2444A6ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBC28C6DDB4D50B3DULL,
		0x4253DA195A10B777ULL,
		0x513EBB48C4DC00DDULL,
		0x2929A0A55D8AFECAULL,
		0xEA59AAED1E6F68DCULL,
		0xB2C2AFFC137C205FULL,
		0xB517F5084002D79AULL,
		0x3D4A7280BC1B0F8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78518DBB69AA167AULL,
		0x84A7B432B4216EEFULL,
		0xA27D769189B801BAULL,
		0x5253414ABB15FD94ULL,
		0xD4B355DA3CDED1B8ULL,
		0x65855FF826F840BFULL,
		0x6A2FEA108005AF35ULL,
		0x7A94E50178361F1FULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x3B849148CCE65664ULL,
		0xD417AEB95B32F1F6ULL,
		0x56E6A41DDBF38379ULL,
		0x7A79B08D52C02EABULL,
		0xFC573E8597801AD5ULL,
		0x59B01B8D602B288EULL,
		0x1092E826F8DFCF4AULL,
		0x03A184EC433D2F9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7709229199CCACC8ULL,
		0xA82F5D72B665E3ECULL,
		0xADCD483BB7E706F3ULL,
		0xF4F3611AA5805D56ULL,
		0xF8AE7D0B2F0035AAULL,
		0xB360371AC056511DULL,
		0x2125D04DF1BF9E94ULL,
		0x074309D8867A5F3EULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x37BD884F46FB56DFULL,
		0x21790FEE9627EAC7ULL,
		0xA85A91426018C99FULL,
		0xD69DFBF76463B6C8ULL,
		0x84687C82B9006C66ULL,
		0xD68AEC513A92288BULL,
		0x4C3CCEBAF4CACAD1ULL,
		0x29F7E2B67DB6FEB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F7B109E8DF6ADBEULL,
		0x42F21FDD2C4FD58EULL,
		0x50B52284C031933EULL,
		0xAD3BF7EEC8C76D91ULL,
		0x08D0F9057200D8CDULL,
		0xAD15D8A275245117ULL,
		0x98799D75E99595A3ULL,
		0x53EFC56CFB6DFD62ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBCC10BCCF92D80ADULL,
		0xDE66D008754C9305ULL,
		0xDE6714A2984F6D25ULL,
		0x4A0FDD191DD48729ULL,
		0x5626260E17E1896EULL,
		0x84069BCC15EA3AA8ULL,
		0x8594BC2030160F65ULL,
		0x1BEFC60350011430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79821799F25B015AULL,
		0xBCCDA010EA99260BULL,
		0xBCCE2945309EDA4BULL,
		0x941FBA323BA90E53ULL,
		0xAC4C4C1C2FC312DCULL,
		0x080D37982BD47550ULL,
		0x0B297840602C1ECBULL,
		0x37DF8C06A0022861ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE3F9C0A859360C6BULL,
		0x873B84709AD9B8E6ULL,
		0xEA56FCF0571C7CD5ULL,
		0xB0830251B9881FC9ULL,
		0x0A4EC53C09F1A1A3ULL,
		0x30D3B0437A18424EULL,
		0xDAE68A8FF92CD2E9ULL,
		0x09E01F529A18852CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F38150B26C18D6ULL,
		0x0E7708E135B371CDULL,
		0xD4ADF9E0AE38F9ABULL,
		0x610604A373103F93ULL,
		0x149D8A7813E34347ULL,
		0x61A76086F430849CULL,
		0xB5CD151FF259A5D2ULL,
		0x13C03EA534310A59ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x2EAC6FEF5F298F00ULL,
		0x9AABC51AF2AEC9EAULL,
		0xDD00CD9C6AD54097ULL,
		0x300BB08E0E4DAEC3ULL,
		0xB70863EB2082F2E8ULL,
		0xB1793B09F334109CULL,
		0xDB37A96A5BB51921ULL,
		0x397AB8E666E64967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D58DFDEBE531E00ULL,
		0x35578A35E55D93D4ULL,
		0xBA019B38D5AA812FULL,
		0x6017611C1C9B5D87ULL,
		0x6E10C7D64105E5D0ULL,
		0x62F27613E6682139ULL,
		0xB66F52D4B76A3243ULL,
		0x72F571CCCDCC92CFULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x67FBC03B09E256FFULL,
		0xBCEDDD2182544D1BULL,
		0x8756BFBA0C24A67DULL,
		0xB88BC1D30B46928FULL,
		0x4F565F166883886AULL,
		0xA0D7D71C30183748ULL,
		0x97A09C1BEBA2D26FULL,
		0x0B511FDE26CFDB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF7807613C4ADFEULL,
		0x79DBBA4304A89A36ULL,
		0x0EAD7F7418494CFBULL,
		0x711783A6168D251FULL,
		0x9EACBE2CD10710D5ULL,
		0x41AFAE3860306E90ULL,
		0x2F413837D745A4DFULL,
		0x16A23FBC4D9FB6A9ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xAD6177A7AB1FBC73ULL,
		0xAB847773026274D4ULL,
		0x207DF990FD9D5982ULL,
		0xA6CA179BB50AFED9ULL,
		0x7482A902BD3FA8BDULL,
		0xF2AD4634AF220B53ULL,
		0x34F654AE4C397055ULL,
		0x1210EFF435833044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC2EF4F563F78E6ULL,
		0x5708EEE604C4E9A9ULL,
		0x40FBF321FB3AB305ULL,
		0x4D942F376A15FDB2ULL,
		0xE90552057A7F517BULL,
		0xE55A8C695E4416A6ULL,
		0x69ECA95C9872E0ABULL,
		0x2421DFE86B066088ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xBA6AB80CE2493E40ULL,
		0x8FB437AF22667B2BULL,
		0x5FF355F5261F8DC1ULL,
		0x01E06F513E6ADB25ULL,
		0x6CBFE2EEF7BB4406ULL,
		0xCEFC1EC583AE32A6ULL,
		0x6EFFE13EDFB2F944ULL,
		0x26687550084A0055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D57019C4927C80ULL,
		0x1F686F5E44CCF657ULL,
		0xBFE6ABEA4C3F1B83ULL,
		0x03C0DEA27CD5B64AULL,
		0xD97FC5DDEF76880CULL,
		0x9DF83D8B075C654CULL,
		0xDDFFC27DBF65F289ULL,
		0x4CD0EAA0109400AAULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0x269D75853116F349ULL,
		0x8F286BEFE523761CULL,
		0xDA87A6511B9C3B59ULL,
		0xC26F1135DA4970A9ULL,
		0xD3E8A8E3F3D2CB7DULL,
		0x47CFE2B644016BFCULL,
		0x438B83282D1389C1ULL,
		0x18530E5F04D86D9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D3AEB0A622DE692ULL,
		0x1E50D7DFCA46EC38ULL,
		0xB50F4CA2373876B3ULL,
		0x84DE226BB492E153ULL,
		0xA7D151C7E7A596FBULL,
		0x8F9FC56C8802D7F9ULL,
		0x871706505A271382ULL,
		0x30A61CBE09B0DB3AULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xDA25D61153C8AEEDULL,
		0x62DE2ABF530A0D53ULL,
		0xD681C471E70D55DFULL,
		0x7F721260978544F1ULL,
		0x700A5D731FFAD97DULL,
		0xCFFCC6F058B8E66BULL,
		0x6A26EC1DDBE179E1ULL,
		0x1A8B90AC314766F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44BAC22A7915DDAULL,
		0xC5BC557EA6141AA7ULL,
		0xAD0388E3CE1AABBEULL,
		0xFEE424C12F0A89E3ULL,
		0xE014BAE63FF5B2FAULL,
		0x9FF98DE0B171CCD6ULL,
		0xD44DD83BB7C2F3C3ULL,
		0x35172158628ECDE6ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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
		0xE31145016CD7CAFFULL,
		0x13BCDA8A8CC8BEC1ULL,
		0xA1A6AE3099DCDE61ULL,
		0x02E2D21A45B0024DULL,
		0x5AA9FDA5A2166E85ULL,
		0xF432CABAE54A4414ULL,
		0x10F5EAF759EDEC01ULL,
		0x20E47E6EFFC84266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6228A02D9AF95FEULL,
		0x2779B51519917D83ULL,
		0x434D5C6133B9BCC2ULL,
		0x05C5A4348B60049BULL,
		0xB553FB4B442CDD0AULL,
		0xE8659575CA948828ULL,
		0x21EBD5EEB3DBD803ULL,
		0x41C8FCDDFF9084CCULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_inplace(&k1);
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