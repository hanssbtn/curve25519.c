#include "../tests.h"

int32_t curve25519_key_xor_test(void) {
	printf("Key XOR Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6F83EAA1F104B2BFULL,
		0x8B5ACA6337BCED4FULL,
		0xB8353651E84944ABULL,
		0xA68E3CEFE42F2573ULL,
		0x80F045A1C9FF6277ULL,
		0x40BEF59AB196AE9BULL,
		0xD8C3F93F165CA119ULL,
		0xA6C34FB497C41EE7ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x26916FA5757DEAF8ULL,
		0x14B8A050FEA33926ULL,
		0x2C0C1B7DAE0087F5ULL,
		0x095E4982EAAF2533ULL,
		0xF333321BDE996F5BULL,
		0xB8E73135F9123C78ULL,
		0x78A21462114AA9D3ULL,
		0xBB2338E49FAC5F03ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x4912850484795847ULL,
		0x9FE26A33C91FD469ULL,
		0x94392D2C4649C35EULL,
		0xAFD0756D0E800040ULL,
		0x73C377BA17660D2CULL,
		0xF859C4AF488492E3ULL,
		0xA061ED5D071608CAULL,
		0x1DE07750086841E4ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60CCB6621A5D917CULL,
		0x7FC9E8056F2C1C8DULL,
		0x1413548AEBC42938ULL,
		0x041E72ACFC5A6D97ULL,
		0x2B7B9AB0534F6121ULL,
		0x12935972E7EBB7E4ULL,
		0xB11BFA9F0FE880A0ULL,
		0x1A7710BC747B3E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D687342208787CULL,
		0x2DED3F8D38F6A8DAULL,
		0xE2ADD58F8F1DC4B4ULL,
		0x479C55CE6660B8DCULL,
		0x1BE26845C5178BDEULL,
		0x0ED2405463BE39E1ULL,
		0x405C03CB2254B7CEULL,
		0xE6CBEB8DA06C8253ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x741A31563855E900ULL,
		0x5224D78857DAB457ULL,
		0xF6BE810564D9ED8CULL,
		0x438227629A3AD54BULL,
		0x3099F2F59658EAFFULL,
		0x1C41192684558E05ULL,
		0xF147F9542DBC376EULL,
		0xFCBCFB31D417BC24ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90B9F98DD4137013ULL,
		0x4285E9ABFD90AD71ULL,
		0x8D03041F393CA3B7ULL,
		0x26CE8409F4DAA211ULL,
		0x879E67541EF0BF65ULL,
		0xD39393BB6E6FF245ULL,
		0x7DC743BDE13B4B03ULL,
		0x9B147F43DB269CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x458D80C0C6706099ULL,
		0xB393D55143E6F47BULL,
		0xCDD5699906E63EC2ULL,
		0xA8BE0C533CE8A283ULL,
		0xEE90AF81E8C19C11ULL,
		0xB01F91998C515CDFULL,
		0xF3FD891BCCDCDF16ULL,
		0xD7184E1347D0C9BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD534794D1263108AULL,
		0xF1163CFABE76590AULL,
		0x40D66D863FDA9D75ULL,
		0x8E70885AC8320092ULL,
		0x690EC8D5F6312374ULL,
		0x638C0222E23EAE9AULL,
		0x8E3ACAA62DE79415ULL,
		0x4C0C31509CF6555FULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0E081B03459892AULL,
		0x7BC9B2798701F26EULL,
		0x2026F4D1A7E7B0F3ULL,
		0xAF9E63E016A78F17ULL,
		0x48EEC4AB9A1FD8DEULL,
		0xBE481E18BEA28B36ULL,
		0x77ACC6C6D4E4C6EDULL,
		0x7473260BE98E8946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A1D7FDC0919E795ULL,
		0xEC9D27F55368EB6FULL,
		0xC60E794408D0622DULL,
		0x0FFE48D86A7CC937ULL,
		0xC107CF9D62CD4D8FULL,
		0x757E42BFFE710D76ULL,
		0xD8473DDE805F4818ULL,
		0xBCB436879BF96EA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AFDFE6C3D406EBFULL,
		0x9754958CD4691901ULL,
		0xE6288D95AF37D2DEULL,
		0xA0602B387CDB4620ULL,
		0x89E90B36F8D29551ULL,
		0xCB365CA740D38640ULL,
		0xAFEBFB1854BB8EF5ULL,
		0xC8C7108C7277E7E7ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE8DF24EE14B5143ULL,
		0x2DEB9E43BD389B74ULL,
		0xCB80245C8A270502ULL,
		0x78863E891B923035ULL,
		0x93F615FAFCD6D984ULL,
		0x9B0CA6E613FEAE65ULL,
		0xF4D6F9AA9F29611DULL,
		0xE94DA2E9A1314739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F42BFF2C4C74DC2ULL,
		0x73BDC407904A3E63ULL,
		0x08ABD5A80382D553ULL,
		0xA4231B0CC640DEDBULL,
		0x5C3EB0B3F745C475ULL,
		0xEDEDB0A40CFDA034ULL,
		0x03A6DCF644AF5027ULL,
		0xA476CDE17848CD65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1CF4DBC258C1C81ULL,
		0x5E565A442D72A517ULL,
		0xC32BF1F489A5D051ULL,
		0xDCA52585DDD2EEEEULL,
		0xCFC8A5490B931DF1ULL,
		0x76E116421F030E51ULL,
		0xF770255CDB86313AULL,
		0x4D3B6F08D9798A5CULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BEA10C3029AA5EAULL,
		0xBDB730C2A241CC13ULL,
		0xDE17DCF943B9C097ULL,
		0xAA0342CB7E8BBD3BULL,
		0xD0DA0897F09FA89BULL,
		0x7FCA57BB7109AB2BULL,
		0xB6757D31ED92A067ULL,
		0x88F31BF3DD84A853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF83385AE3A03B5C1ULL,
		0xFF78E33F9E073D36ULL,
		0x217CE35556141FC3ULL,
		0x229949363310450AULL,
		0xAEF9ABD4F5C1A65CULL,
		0x5449DEB07CFD6D9FULL,
		0x4E12443A5FAC90F3ULL,
		0x972DFB1FAE6D1933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3D9956D3899102BULL,
		0x42CFD3FD3C46F125ULL,
		0xFF6B3FAC15ADDF54ULL,
		0x889A0BFD4D9BF831ULL,
		0x7E23A343055E0EC7ULL,
		0x2B83890B0DF4C6B4ULL,
		0xF867390BB23E3094ULL,
		0x1FDEE0EC73E9B160ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01AF8876710C733AULL,
		0x813B69EFFDA7F078ULL,
		0xA530F0ABAAE0363BULL,
		0x3A04BC6DD31ADE93ULL,
		0x435333176EAF2B6EULL,
		0xA25944E987152722ULL,
		0x9A5C1C5451F12B30ULL,
		0xA0AB9D76606806C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC8BB6344B62BD3ULL,
		0x9B5D684C7D5192AEULL,
		0x39A526D2944D4D02ULL,
		0xF9E31D5BF5D3DADFULL,
		0x92B4A2AF75F8F357ULL,
		0x8125F7FB749F3725ULL,
		0xBB6B18A8DA8C1FB2ULL,
		0x8901D3ECED1CE368ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D67331535BA58E9ULL,
		0x1A6601A380F662D6ULL,
		0x9C95D6793EAD7B39ULL,
		0xC3E7A13626C9044CULL,
		0xD1E791B81B57D839ULL,
		0x237CB312F38A1007ULL,
		0x213704FC8B7D3482ULL,
		0x29AA4E9A8D74E5ADULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BE9BDC382D9E7A9ULL,
		0x5C8A299522930BE7ULL,
		0xC3FBD27EAE8967B8ULL,
		0x8F2FF3A00724D67FULL,
		0x2459DF875174981AULL,
		0x8FA5782CBCACA937ULL,
		0xCF6C40F7EABC8B60ULL,
		0xF18799206578D434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BDEFA57CB647BFULL,
		0x6BA0F24A3FAB1ACEULL,
		0x53D671E1BF6E3D2FULL,
		0xC7886DC67F911319ULL,
		0x8C3B1FC34421DB02ULL,
		0x4EFFBF320448658FULL,
		0xCE06E22429B52ED0ULL,
		0x91CAF634B38BEEECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48545266FE6FA016ULL,
		0x372ADBDF1D381129ULL,
		0x902DA39F11E75A97ULL,
		0x48A79E6678B5C566ULL,
		0xA862C04415554318ULL,
		0xC15AC71EB8E4CCB8ULL,
		0x016AA2D3C309A5B0ULL,
		0x604D6F14D6F33AD8ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10297E70ABD007D9ULL,
		0x7F079660478996A6ULL,
		0xF10BA14BACE1142AULL,
		0x420B60AD38357572ULL,
		0xFAE6AF32FF99A685ULL,
		0x1C8FD479BE490884ULL,
		0x83A5B8EA4294C465ULL,
		0x7359C875E1E12701ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AB390B48CF34289ULL,
		0xDC581A21DC4589ECULL,
		0x7603A4718F58914CULL,
		0x9F9821F96EF68756ULL,
		0x55689FEF563066DBULL,
		0x84EFDB3186FE93ADULL,
		0x94E4E7940EDB3F81ULL,
		0x2D9EF3C25BA55815ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A9AEEC427234550ULL,
		0xA35F8C419BCC1F4AULL,
		0x8708053A23B98566ULL,
		0xDD93415456C3F224ULL,
		0xAF8E30DDA9A9C05EULL,
		0x98600F4838B79B29ULL,
		0x17415F7E4C4FFBE4ULL,
		0x5EC73BB7BA447F14ULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D710986C9CC50D7ULL,
		0xAB40C8C04E3869F3ULL,
		0x35088420411C67ADULL,
		0xDF53FFC1BB45F757ULL,
		0xD38D89A91A432FC2ULL,
		0x7871C82D207A75C0ULL,
		0x87B5CF7BF6AA4E98ULL,
		0x58340DEAD3C2DC86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF338D3D55F90B37ULL,
		0xE418D46B63C85528ULL,
		0xE3B06BAA400911C8ULL,
		0xAE18BBABED9AFA4EULL,
		0x6D9EFC005B39DCEBULL,
		0xC28DA1919A899CC3ULL,
		0x86D9D1719FE1DA1BULL,
		0xE4D5B9B9F1403828ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x824284BB9C355BE0ULL,
		0x4F581CAB2DF03CDBULL,
		0xD6B8EF8A01157665ULL,
		0x714B446A56DF0D19ULL,
		0xBE1375A9417AF329ULL,
		0xBAFC69BCBAF3E903ULL,
		0x016C1E0A694B9483ULL,
		0xBCE1B4532282E4AEULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40451262A345C4C4ULL,
		0x756D6C6E7F1E4393ULL,
		0x1970DE9AF8E0D4E2ULL,
		0x029350822E5BEDD1ULL,
		0x4A217E809ADB4EDDULL,
		0x2386BE438EC2BDAFULL,
		0xB0CA1420916367C2ULL,
		0x1472AAA8059C3307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8A4B1D152E86DBULL,
		0xE284A08BC3B7CB88ULL,
		0x6C74D42EF63C1F40ULL,
		0x64E70FEC60758998ULL,
		0xDFB26152933B6A91ULL,
		0xCB734590124CDD26ULL,
		0xE435EDFD8EC5E41CULL,
		0xBA83DE8C0E384455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBCF597FB66B421FULL,
		0x97E9CCE5BCA9881BULL,
		0x75040AB40EDCCBA2ULL,
		0x66745F6E4E2E6449ULL,
		0x95931FD209E0244CULL,
		0xE8F5FBD39C8E6089ULL,
		0x54FFF9DD1FA683DEULL,
		0xAEF174240BA47752ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA32B36E68D31A3EBULL,
		0x97DC6762B360776FULL,
		0x5D5ADD768EE0D517ULL,
		0x9A0D64A1DBE83CE7ULL,
		0xE949008C9FDFC1C0ULL,
		0xAAEFEEE5FF2BE24FULL,
		0x2FF464A3CAA9A1FFULL,
		0x4F20AB226EDFED95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4FC939C805D442ULL,
		0x89E30FD7A98D02EDULL,
		0x4D5244114687254CULL,
		0x6186E9D8BE3DAD7CULL,
		0xDD588FB801689989ULL,
		0xCC843AC962922616ULL,
		0xA96A49EE9DA50CC4ULL,
		0x4527EAEEFAE712A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF64FFDF453477A9ULL,
		0x1E3F68B51AED7582ULL,
		0x10089967C867F05BULL,
		0xFB8B8D7965D5919BULL,
		0x34118F349EB75849ULL,
		0x666BD42C9DB9C459ULL,
		0x869E2D4D570CAD3BULL,
		0x0A0741CC9438FF34ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BD3D09E9B3C17C7ULL,
		0xC5484AF3FF8BF1D4ULL,
		0x473DC171290E4CF9ULL,
		0x6A6C55EE4D224DE7ULL,
		0xCC027ECB58969ACFULL,
		0x60C8C58F81193651ULL,
		0xA3C0039BD1A0ED31ULL,
		0x7DD96F9ED56AD2E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5C610601D344010ULL,
		0xDCE31ECE096A5BEAULL,
		0xD233159789A4C535ULL,
		0xECC200FBA0330336ULL,
		0xFC7C018A8D11C9C2ULL,
		0xC89135E9CB9FCECEULL,
		0xC4929D40074021C0ULL,
		0xD580769B0081D210ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E15C0FE860857D7ULL,
		0x19AB543DF6E1AA3EULL,
		0x950ED4E6A0AA89CCULL,
		0x86AE5515ED114ED1ULL,
		0x307E7F41D587530DULL,
		0xA859F0664A86F89FULL,
		0x67529EDBD6E0CCF1ULL,
		0xA8591905D5EB00F4ULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACCD3CB4F4D70D53ULL,
		0x312C9F38668E1E43ULL,
		0x158F549B0F60AF6FULL,
		0xF4520A385E144C16ULL,
		0x952BCE94A17E8D0CULL,
		0x2E59E1D40836B6B2ULL,
		0xE3667B4F2BAE99ADULL,
		0xDC96E1926FF18E46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA052534B64256186ULL,
		0x86965672D59BA7CFULL,
		0x3A978983B2682572ULL,
		0xEB8D0320BE080FACULL,
		0xFD5778592F168779ULL,
		0x6770BEA45AAE317CULL,
		0xD989930BFBA660F4ULL,
		0xD06D9CCADBF2FB41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C9F6FFF90F26CD5ULL,
		0xB7BAC94AB315B98CULL,
		0x2F18DD18BD088A1DULL,
		0x1FDF0918E01C43BAULL,
		0x687CB6CD8E680A75ULL,
		0x49295F70529887CEULL,
		0x3AEFE844D008F959ULL,
		0x0CFB7D58B4037507ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BC580DFBC91C5EAULL,
		0xA3DD98CF95B45883ULL,
		0xECACE8BCA00EFF5BULL,
		0x2CE7D3248DB579CDULL,
		0xB6EAC9C265B65FB7ULL,
		0xA7DA73A1A142A3B6ULL,
		0xFDF8091C91FC94F5ULL,
		0x716FE062D64D6B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC48425DE13569FULL,
		0x18D28361181B2EFAULL,
		0x0B43B71ECD2AA100ULL,
		0x02E1F6A4277DE0F7ULL,
		0x6ADB9ACCDF77B1C2ULL,
		0x2483DF2BCD42E103ULL,
		0xA448D823A50EC808ULL,
		0x4A8ADE5255AA923DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x610104FA62829375ULL,
		0xBB0F1BAE8DAF7679ULL,
		0xE7EF5FA26D245E5BULL,
		0x2E062580AAC8993AULL,
		0xDC31530EBAC1EE75ULL,
		0x8359AC8A6C0042B5ULL,
		0x59B0D13F34F25CFDULL,
		0x3BE53E3083E7F95BULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD1DF1C796FE7D256ULL,
		0x3CAA165B87ED2449ULL,
		0x2EE9520C186B2A0CULL,
		0x7138A977829D36F4ULL,
		0x97D3B85A7CA1648AULL,
		0x3CA2E74D5745334BULL,
		0x0A9B8C04E4BD57D0ULL,
		0x213751C5EDBA55FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E06C8AC17BDE149ULL,
		0x131D97E82D6B2308ULL,
		0x8CF9837770825541ULL,
		0x4C981F2669DC7B82ULL,
		0xAA132D07143F0E5DULL,
		0x9D1241695BB350F4ULL,
		0xA309A1DFE7F73532ULL,
		0x75D8C3BCAEF25FB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFD9D4D5785A331FULL,
		0x2FB781B3AA860741ULL,
		0xA210D17B68E97F4DULL,
		0x3DA0B651EB414D76ULL,
		0x3DC0955D689E6AD7ULL,
		0xA1B0A6240CF663BFULL,
		0xA9922DDB034A62E2ULL,
		0x54EF927943480A4BULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6534C2790B066D0ULL,
		0x023F44D33371A28CULL,
		0x00D0F13D98B2F805ULL,
		0x9DB3A32185727EEBULL,
		0xE29283DFE6E0CE67ULL,
		0x6E28E4245D5E8683ULL,
		0x20C64CA0A742C8FBULL,
		0xE4371C6303BE3EE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x073A4FB7D22C6B5BULL,
		0xB99BC968036705FDULL,
		0x752D973A87B654C7ULL,
		0x6054269AB9D182C5ULL,
		0x675B39FCBF2B1303ULL,
		0x9803DFF625F2435EULL,
		0xECC719228EBB2CFFULL,
		0xACB0D41CD38089B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1690390429C0D8BULL,
		0xBBA48DBB3016A771ULL,
		0x75FD66071F04ACC2ULL,
		0xFDE785BB3CA3FC2EULL,
		0x85C9BA2359CBDD64ULL,
		0xF62B3BD278ACC5DDULL,
		0xCC01558229F9E404ULL,
		0x4887C87FD03EB754ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA183901019130D47ULL,
		0x26951A81E3533C40ULL,
		0x62C3FB78A5521C8FULL,
		0x849B32B72B832C3EULL,
		0x8A92304D717C4CDBULL,
		0x4B816E5264059937ULL,
		0xF8F5B0E1C0883DE8ULL,
		0x9E8CA57760FD02BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE27D85AFC318DDBULL,
		0x538080F6190A11CFULL,
		0x09F34AC3601F12F7ULL,
		0xA9162EAA9CED0BCBULL,
		0xC1446344CFCF50C1ULL,
		0x0FE40A8C4BE42ECEULL,
		0x32BD5392EEA0546FULL,
		0xFA91F9650C4844D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA4484AE522809CULL,
		0x75159A77FA592D8FULL,
		0x6B30B1BBC54D0E78ULL,
		0x2D8D1C1DB76E27F5ULL,
		0x4BD65309BEB31C1AULL,
		0x446564DE2FE1B7F9ULL,
		0xCA48E3732E286987ULL,
		0x641D5C126CB5466CULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E2B23DFC8DB2FDEULL,
		0x31794BCE48C72422ULL,
		0x19E36341F84D5844ULL,
		0x40BC51DB881D7763ULL,
		0x949336FC32BDD02CULL,
		0x08F77095172B8610ULL,
		0xAB704A280989641FULL,
		0x87DDC3A58B095D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD79F17C72E295B3ULL,
		0x0A26DA82A4B02D6CULL,
		0x8153E3973E68CF69ULL,
		0x97E43F30EBC0E35AULL,
		0xBAF208E003144915ULL,
		0xB2F0CA63588EF58FULL,
		0x56BBDF4FAEA2C5EEULL,
		0x889E4CA98CD7AD16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7352D2A3BA39BA6DULL,
		0x3B5F914CEC77094EULL,
		0x98B080D6C625972DULL,
		0xD7586EEB63DD9439ULL,
		0x2E613E1C31A99939ULL,
		0xBA07BAF64FA5739FULL,
		0xFDCB9567A72BA1F1ULL,
		0x0F438F0C07DEF05FULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BB00FDFB64C346DULL,
		0xEB69616844ED8606ULL,
		0x70F2352090135A8FULL,
		0x65432FD8AEAB561FULL,
		0x03BB3CA362835782ULL,
		0x39DEDA2C20A93FF8ULL,
		0xF943846A4639E774ULL,
		0xF4759EBB2700DFDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD2B55ED1C3671CFULL,
		0xF126C808A3E3210AULL,
		0xC86C2CDECE4C46E5ULL,
		0xD754AFC4A7255B99ULL,
		0x5EB2952017E18624ULL,
		0x086E9B5A27080D93ULL,
		0xBC3A8B2C8E694E01ULL,
		0xF838794469F67AFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x769B5A32AA7A45A2ULL,
		0x1A4FA960E70EA70CULL,
		0xB89E19FE5E5F1C6AULL,
		0xB217801C098E0D86ULL,
		0x5D09A9837562D1A6ULL,
		0x31B0417607A1326BULL,
		0x45790F46C850A975ULL,
		0x0C4DE7FF4EF6A520ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BE80917145F63CULL,
		0x22E053A4B8B162E8ULL,
		0xE467D53532860E99ULL,
		0x9684ED610D34E094ULL,
		0x63104F49CD6E2541ULL,
		0xC65982455BA2EF42ULL,
		0x80CA90F9DF2F1CF9ULL,
		0xB657F8AF764975C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB326EB50B9A1DBDFULL,
		0x0178F43CADB08EA9ULL,
		0xC5915F84772D7A9AULL,
		0x6A2BD51B6E691D58ULL,
		0xDD1AD5E74A54914DULL,
		0x2B19461E8F2BC162ULL,
		0xD50BFB61AA4692B1ULL,
		0x51589AFDFFDB3BDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27986BC1C8E42DE3ULL,
		0x2398A7981501EC41ULL,
		0x21F68AB145AB7403ULL,
		0xFCAF387A635DFDCCULL,
		0xBE0A9AAE873AB40CULL,
		0xED40C45BD4892E20ULL,
		0x55C16B9875698E48ULL,
		0xE70F625289924E18ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBADF7CF0065AC5BFULL,
		0x76ECAD45C3E63FD3ULL,
		0x283AA30BBC37E7F8ULL,
		0xE5DCE2EB2A846584ULL,
		0x12AB0F0DB9EAC7F3ULL,
		0xBF7D9721512695A4ULL,
		0xA25EE65578F986A8ULL,
		0xF3AF9E6355528BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9627C27FEC617E22ULL,
		0x3593468351C88107ULL,
		0x6B12C122B507A0F3ULL,
		0x0654DBF356FC6FFEULL,
		0x1B1ABBC88F78B989ULL,
		0x60F4838DF24AB9A8ULL,
		0xEF6B94DD710CD616ULL,
		0xE03F90860F629890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CF8BE8FEA3BBB9DULL,
		0x437FEBC6922EBED4ULL,
		0x432862290930470BULL,
		0xE38839187C780A7AULL,
		0x09B1B4C536927E7AULL,
		0xDF8914ACA36C2C0CULL,
		0x4D35728809F550BEULL,
		0x13900EE55A30134CULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED91EEF2F1CE4D53ULL,
		0x61D567EE4643B9B3ULL,
		0x739F03C9D0895D13ULL,
		0xF63BEAC8AE783CD1ULL,
		0x72C7E5C7270FE66EULL,
		0x2C7AFBA5D6E03BCEULL,
		0x0450AE220D3C3D13ULL,
		0x572361608E8E7625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EC36F7626E7DB4ULL,
		0x77AC754812918BA9ULL,
		0xB7E7ED742B9387A5ULL,
		0xAE23A9859611B368ULL,
		0x97CFE680BB0AC1C3ULL,
		0xCF403468BAC45AF4ULL,
		0xFE5A9C15E6E63AECULL,
		0x0327AA2F646B5235ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD87DD80593A030E7ULL,
		0x167912A654D2321AULL,
		0xC478EEBDFB1ADAB6ULL,
		0x5818434D38698FB9ULL,
		0xE50803479C0527ADULL,
		0xE33ACFCD6C24613AULL,
		0xFA0A3237EBDA07FFULL,
		0x5404CB4FEAE52410ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A5958071CD49D0CULL,
		0x9FD47145DDE85359ULL,
		0xF04F9397A538B817ULL,
		0xB356C02B1B9CDBA1ULL,
		0x7B3AE08CC1DC4B90ULL,
		0x179BB2B727390F3AULL,
		0xA27AFDECA35A478AULL,
		0xC4F6D59741088BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4465D81E799C6C1ULL,
		0x6BDF9622837EA36DULL,
		0x9A0A2C8E4B58AFB8ULL,
		0x1AD6D9CEA5F7236EULL,
		0x436F18EE8307D3F3ULL,
		0x38CA8450D674B709ULL,
		0x006580C171728EB0ULL,
		0xBA2683615764D9BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE1F0586FB4D5BCDULL,
		0xF40BE7675E96F034ULL,
		0x6A45BF19EE6017AFULL,
		0xA98019E5BE6BF8CFULL,
		0x3855F86242DB9863ULL,
		0x2F5136E7F14DB833ULL,
		0xA21F7D2DD228C93AULL,
		0x7ED056F6166C5202ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCAC764CDD11928FULL,
		0xBE06029B1E642CDDULL,
		0x5A86C0193F89E99AULL,
		0x586463597A0595A7ULL,
		0x138D937808DE0A68ULL,
		0x61BAA96C5F229476ULL,
		0xB04CB85EDAA66F8FULL,
		0xA66427F5C93F0183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x931A198ACE9C9027ULL,
		0xFE5E8C758B23B342ULL,
		0x3FC3CD71EE0CADA7ULL,
		0x365A3571564B0561ULL,
		0xB9CE743E2E345522ULL,
		0x5AF458CE26EECC79ULL,
		0x7DD7F5128A57F0D6ULL,
		0x9413E7232D7ECF0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB66FC6138D02A8ULL,
		0x40588EEE95479F9FULL,
		0x65450D68D185443DULL,
		0x6E3E56282C4E90C6ULL,
		0xAA43E74626EA5F4AULL,
		0x3B4EF1A279CC580FULL,
		0xCD9B4D4C50F19F59ULL,
		0x3277C0D6E441CE8EULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F3319DBB776C7B1ULL,
		0x1505D9439E37967CULL,
		0x792C7D3FB5EF182BULL,
		0x768EFF623A8E58B2ULL,
		0xE94BFE666960729DULL,
		0x3D4FD45CE14D21BFULL,
		0x8E2511076EE09B76ULL,
		0xC2091D0389668A9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC374CC9EEA10BB3EULL,
		0x60F89FB4D86DED90ULL,
		0x5C92530EFC251151ULL,
		0xDC9E7EF6B9A2435CULL,
		0x33234FD17A8DC908ULL,
		0x1DEF800DFE107BFBULL,
		0x62DDE1B437B62610ULL,
		0x9F0EE97A41087933ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC47D5455D667C8FULL,
		0x75FD46F7465A7BECULL,
		0x25BE2E3149CA097AULL,
		0xAA108194832C1BEEULL,
		0xDA68B1B713EDBB95ULL,
		0x20A054511F5D5A44ULL,
		0xECF8F0B35956BD66ULL,
		0x5D07F479C86EF3A8ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0BEC938DB7E491FULL,
		0x0AF35E43D446F812ULL,
		0xFB43C7B1349B6DC1ULL,
		0x9C5AD3806940B8B3ULL,
		0xA4B1145178C874AFULL,
		0xE3D3071E380A6A9AULL,
		0xC1444254745573A8ULL,
		0xA63059396AC88A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00ECA3095832886ULL,
		0xE1BB3968F9485A26ULL,
		0xB9A3F48882569B72ULL,
		0x0012D7D812CEF54EULL,
		0xBD5E1B09F6C31934ULL,
		0x56FE9F440422B2F2ULL,
		0xBDCE1517A98A0D31ULL,
		0x34DC6865EB8AD40AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40B003084EFD6199ULL,
		0xEB48672B2D0EA234ULL,
		0x42E03339B6CDF6B3ULL,
		0x9C4804587B8E4DFDULL,
		0x19EF0F588E0B6D9BULL,
		0xB52D985A3C28D868ULL,
		0x7C8A5743DDDF7E99ULL,
		0x92EC315C81425E7CULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54AAB63EBD9C2060ULL,
		0xA347F6C646AA0A31ULL,
		0xE5C93BC1285F0D6AULL,
		0xFA7B0C6A28A0A36FULL,
		0xECB23AB2CC468552ULL,
		0xC599B862BA70315AULL,
		0xD59E2C4AA1825E7FULL,
		0xCA4BB33F3CD2110DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFACD51D661FDDB8ULL,
		0x169F2B1905C98D91ULL,
		0x42ED7501AF19429BULL,
		0xE793EAC44123A0B4ULL,
		0x7797186560BDAB83ULL,
		0xDA813A519A905418ULL,
		0xFB52FAC91AB208CCULL,
		0x2E159B76BA72559CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB066323DB83FDD8ULL,
		0xB5D8DDDF436387A0ULL,
		0xA7244EC087464FF1ULL,
		0x1DE8E6AE698303DBULL,
		0x9B2522D7ACFB2ED1ULL,
		0x1F18823320E06542ULL,
		0x2ECCD683BB3056B3ULL,
		0xE45E284986A04491ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2FEF2A9586BCC7CULL,
		0x8EA29A4CBEBC0F16ULL,
		0x7D5746CA4CCF1485ULL,
		0x59F547AA42EA53C2ULL,
		0x8C80C4C58181C17FULL,
		0x19C7896A6A593C8FULL,
		0xF5DB26E5305FBAEFULL,
		0x853EA18B5DB60FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22499664519A6549ULL,
		0xD018E70096AC2762ULL,
		0x84B6EC525B5E3859ULL,
		0x8FE06E6323025724ULL,
		0x4EB1F7CBD921B6C2ULL,
		0x8CF9CC70FC48222CULL,
		0x1A5CEA16928F4B66ULL,
		0x797DBE270E1A194CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0B764CD09F1A935ULL,
		0x5EBA7D4C28102874ULL,
		0xF9E1AA9817912CDCULL,
		0xD61529C961E804E6ULL,
		0xC231330E58A077BDULL,
		0x953E451A96111EA3ULL,
		0xEF87CCF3A2D0F189ULL,
		0xFC431FAC53AC1684ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8773271C67E5BA0ULL,
		0x50254005A2108FFBULL,
		0xC136B0FAA2108531ULL,
		0xA8368F6ECB77F959ULL,
		0x600EEA3C0E2EC39FULL,
		0x59AD5FF776114EDBULL,
		0xC9DBF7759F65E245ULL,
		0x6C2E2354DA09277FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5109AFA779260C86ULL,
		0xF6CFCC38C0989154ULL,
		0x47555C3B5C80A406ULL,
		0xDCA3E3D5A63CE0BFULL,
		0x3B1827AC747ABEDEULL,
		0x005F2A5BD8A712BCULL,
		0xBF025AB5506CCFE1ULL,
		0xE372CB089279CCB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE97E9DD6BF585726ULL,
		0xA6EA8C3D62881EAFULL,
		0x8663ECC1FE902137ULL,
		0x74956CBB6D4B19E6ULL,
		0x5B16CD907A547D41ULL,
		0x59F275ACAEB65C67ULL,
		0x76D9ADC0CF092DA4ULL,
		0x8F5CE85C4870EBCAULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB11BE39BA26AEC26ULL,
		0x75A387F64D98285CULL,
		0xB44C15FB56928D25ULL,
		0xF4623EAE9A953B76ULL,
		0x66ADE57722EC74A9ULL,
		0xCE3837B64FE9C0EBULL,
		0x0D59728F78B3E35FULL,
		0x7383BA2F936B629DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FCFE0130BFB84D3ULL,
		0x872F793220BA1DC7ULL,
		0x040277B53F590A56ULL,
		0x4F527061B78108A4ULL,
		0x45666181964E5239ULL,
		0x32F1962DFDCBC2EFULL,
		0x90748051F3C256EAULL,
		0x3A8F8AE7CB00DC57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDED40388A99168F5ULL,
		0xF28CFEC46D22359BULL,
		0xB04E624E69CB8773ULL,
		0xBB304ECF2D1433D2ULL,
		0x23CB84F6B4A22690ULL,
		0xFCC9A19BB2220204ULL,
		0x9D2DF2DE8B71B5B5ULL,
		0x490C30C8586BBECAULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCD14E91A1B04D21ULL,
		0xEAFB1C43543467F2ULL,
		0xDA36C070748C1EA6ULL,
		0x1073FA4D64510092ULL,
		0x90BA9CD14CE6753FULL,
		0x47B0106C451C18F3ULL,
		0xF9DF2FC57995D524ULL,
		0x3B380F6C9165F401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9A1BF861577BADULL,
		0x6268618EBFF25400ULL,
		0x93DE46A34A563F4FULL,
		0xD99DDEB69BF81AAFULL,
		0xEE0D50F28BAF4306ULL,
		0x7ACA58F1722907F3ULL,
		0xF396E778E4EBDB4BULL,
		0x445740F17738D3C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x834B5569C0E7368CULL,
		0x88937DCDEBC633F2ULL,
		0x49E886D33EDA21E9ULL,
		0xC9EE24FBFFA91A3DULL,
		0x7EB7CC23C7493639ULL,
		0x3D7A489D37351F00ULL,
		0x0A49C8BD9D7E0E6FULL,
		0x7F6F4F9DE65D27C8ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26F2587F693D5DA9ULL,
		0x8199ECA4210AF657ULL,
		0xD87F8BBA976916C9ULL,
		0x3A2CEF188586B046ULL,
		0x84E3A17D0D3D7A31ULL,
		0x0A53AB102BE73A9EULL,
		0xF331C038F23E62C0ULL,
		0xBBDDFAC33EF3A98EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF906383A07B52C29ULL,
		0x60EFC21A097CCFEEULL,
		0xE9865DAADF88CA14ULL,
		0xD96E3E6A5DC71724ULL,
		0x2374327672C0D8F5ULL,
		0xC6BBFE2608C8AE42ULL,
		0xEAB4D88FB57D2A0DULL,
		0x30484F21B471CCF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFF460456E887180ULL,
		0xE1762EBE287639B9ULL,
		0x31F9D61048E1DCDDULL,
		0xE342D172D841A762ULL,
		0xA797930B7FFDA2C4ULL,
		0xCCE85536232F94DCULL,
		0x198518B7474348CDULL,
		0x8B95B5E28A82657FULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB84D8676ACAC4F0EULL,
		0x94E7F344F9B09EFEULL,
		0xC60BE5169E1C4C83ULL,
		0x7687161835C048E7ULL,
		0x71F2F8B49FE6E957ULL,
		0x509474F620512677ULL,
		0x656C565DD3DA7636ULL,
		0xAA5680CF8BEBDD38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0579D6ED605067CFULL,
		0xFF300D86D56544B9ULL,
		0xFFB8DECA350DD37BULL,
		0x04FE787C4CF00E3DULL,
		0xD7232D0F9FF54668ULL,
		0xB26D70DA26AF13D5ULL,
		0xB73B2C0EEF75D97BULL,
		0x43D836A1D978BBB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD34509BCCFC28C1ULL,
		0x6BD7FEC22CD5DA47ULL,
		0x39B33BDCAB119FF8ULL,
		0x72796E64793046DAULL,
		0xA6D1D5BB0013AF3FULL,
		0xE2F9042C06FE35A2ULL,
		0xD2577A533CAFAF4DULL,
		0xE98EB66E52936688ULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1387BD8BE24BAEEULL,
		0x12E95218C608633AULL,
		0xB82E890432D204C7ULL,
		0x1119E5F49195D135ULL,
		0x86E5D51771D71732ULL,
		0xD2BE57C041453C29ULL,
		0x82CFDC5792BA31E8ULL,
		0x25AAD2626B52C9A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1850F674A2B2A406ULL,
		0xF3E56B4D3988FF37ULL,
		0xB54CCB106720F72CULL,
		0xB82B92063DA8C241ULL,
		0x60FD1F0ED7482276ULL,
		0xEB0BF698AA61B4CAULL,
		0xE1AB591FA300C291ULL,
		0x62B218562DB0CB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9688DAC1C961EE8ULL,
		0xE10C3955FF809C0DULL,
		0x0D62421455F2F3EBULL,
		0xA93277F2AC3D1374ULL,
		0xE618CA19A69F3544ULL,
		0x39B5A158EB2488E3ULL,
		0x6364854831BAF379ULL,
		0x4718CA3446E202F1ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D09F4EB6C67009BULL,
		0xDBA0B07EFB75DB30ULL,
		0xC3F8A8B4C3B2169EULL,
		0x548916F4D57B5FF3ULL,
		0xBCA7CB5DDCB6ADB3ULL,
		0xBB99585E326A9252ULL,
		0xF6E80166B93B6865ULL,
		0x4FBD6C2045FE14C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5720CE450E993965ULL,
		0x096134239CB410C7ULL,
		0x27EA69284D019572ULL,
		0x67E4CC11A9E7DF50ULL,
		0x66387B80D301D8C2ULL,
		0xE160A08752B74F61ULL,
		0xB0040F79F3F12BDAULL,
		0x91BF1042582B3273ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A293AAE62FE39FEULL,
		0xD2C1845D67C1CBF7ULL,
		0xE412C19C8EB383ECULL,
		0x336DDAE57C9C80A3ULL,
		0xDA9FB0DD0FB77571ULL,
		0x5AF9F8D960DDDD33ULL,
		0x46EC0E1F4ACA43BFULL,
		0xDE027C621DD526BBULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2B734BC834FD72EULL,
		0x7D7507779E4935EDULL,
		0x33F6719A8CD7C621ULL,
		0x93B8D2362F6C4150ULL,
		0x1E5CE18255CCD818ULL,
		0xE0E50BC587F005E4ULL,
		0x04218C358DB1649AULL,
		0x723E3C524A54BDD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD1D9DF0E023E87AULL,
		0xF4F4B4965A65EE54ULL,
		0x3833DCD851E02E79ULL,
		0xF51F8723422E2C88ULL,
		0x155301FF5BB44A37ULL,
		0xEA44EF34B60D6BA7ULL,
		0xD2756903F6EA33F7ULL,
		0xFA3129DDA89BA149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FAAA94C636C3F54ULL,
		0x8981B3E1C42CDBB9ULL,
		0x0BC5AD42DD37E858ULL,
		0x66A755156D426DD8ULL,
		0x0B0FE07D0E78922FULL,
		0x0AA1E4F131FD6E43ULL,
		0xD654E5367B5B576DULL,
		0x880F158FE2CF1C91ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F5DA97A04580003ULL,
		0x48DB6FF24AD7AEEAULL,
		0x7B475ADAA51D4F05ULL,
		0xE43689DCFFC9BEDBULL,
		0xDFAFCCAA71E3685AULL,
		0x4E58DCEE3110A341ULL,
		0xC96346A2CAF40CBFULL,
		0x8CFBFDF09F689042ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEADCC33978460FEBULL,
		0x32980C60DB1B57C1ULL,
		0x1BA5E0B20ABA2792ULL,
		0xD8C20878B6C3FDFAULL,
		0x3B574BB54D604D48ULL,
		0x7F18335B9389D603ULL,
		0x2AAADD7B40FB6D9CULL,
		0x00DE9B210EF4A9CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5816A437C1E0FE8ULL,
		0x7A43639291CCF92BULL,
		0x60E2BA68AFA76897ULL,
		0x3CF481A4490A4321ULL,
		0xE4F8871F3C832512ULL,
		0x3140EFB5A2997542ULL,
		0xE3C99BD98A0F6123ULL,
		0x8C2566D1919C398EULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5550E9E32FB24031ULL,
		0x9A4FEA2E6C7ED39EULL,
		0x6F09B821DE372A40ULL,
		0x9F2074A56E232051ULL,
		0x9E00F3996E5D3E0DULL,
		0xF0D3E9D824C14487ULL,
		0xAF1A18EA0CEA93BCULL,
		0xB1534323C8142542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC32E464DD1595FBDULL,
		0xDD333E78417505EFULL,
		0x3B8F53CC5D6C4ACBULL,
		0x765A0A141B71C48CULL,
		0x874727A09690E896ULL,
		0x13687783CF9685D9ULL,
		0xCA52B369084AB8FEULL,
		0x178F393AAFA9D5FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x967EAFAEFEEB1F8CULL,
		0x477CD4562D0BD671ULL,
		0x5486EBED835B608BULL,
		0xE97A7EB17552E4DDULL,
		0x1947D439F8CDD69BULL,
		0xE3BB9E5BEB57C15EULL,
		0x6548AB8304A02B42ULL,
		0xA6DC7A1967BDF0B8ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5A8DE5D7E6FADDCULL,
		0x51D9E1E295F3EBB1ULL,
		0xA78C7ADE0EEF4C5AULL,
		0xB384AB1CC09A40E5ULL,
		0x20817A269C282FA0ULL,
		0x367F86EC383E0635ULL,
		0x02FD211B9616FF51ULL,
		0xF3207BB8C917E8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B883BB2BD2C39A9ULL,
		0x1A722644CEB28F16ULL,
		0x2DFAE363048EF84EULL,
		0x5164336BE7A7B7A8ULL,
		0x18D412357F371280ULL,
		0x8D0EEB56E29168F5ULL,
		0x72F311E61846A156ULL,
		0x83F890B7C1FB8CA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE20E5EFC3439475ULL,
		0x4BABC7A65B4164A7ULL,
		0x8A7699BD0A61B414ULL,
		0xE2E09877273DF74DULL,
		0x38556813E31F3D20ULL,
		0xBB716DBADAAF6EC0ULL,
		0x700E30FD8E505E07ULL,
		0x70D8EB0F08EC6446ULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96A8C7E551B3D1C2ULL,
		0x58A160AC081BF6CDULL,
		0x84F4324E19A7217CULL,
		0x51224AA0BAFB8E02ULL,
		0x854268DA2016A581ULL,
		0x966FBF256F25821CULL,
		0x70A36D160A9D29BEULL,
		0x515F1CC3FC7A1058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59D2A6A3F1C2EB95ULL,
		0x884371B89175EBF8ULL,
		0x7E2C30B93ADFECC6ULL,
		0x976ACF66804ECFDEULL,
		0x5EEA130DB991D61AULL,
		0x9E497A85E48074D5ULL,
		0xB0038C73A651B3FBULL,
		0x868EF8516FB563A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF7A6146A0713A57ULL,
		0xD0E21114996E1D35ULL,
		0xFAD802F72378CDBAULL,
		0xC64885C63AB541DCULL,
		0xDBA87BD79987739BULL,
		0x0826C5A08BA5F6C9ULL,
		0xC0A0E165ACCC9A45ULL,
		0xD7D1E49293CF73F9ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89A1987C237A522CULL,
		0x94791A20CC7D3C32ULL,
		0x97E3AF69697249B9ULL,
		0xD08E91F259B8347FULL,
		0xA5CB077667D774B4ULL,
		0x91767F70FDEA2A59ULL,
		0x785E2FCB70348BA9ULL,
		0xBB529E4B87BC43CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE91EC0A36EDDBD51ULL,
		0xB1F0780EE8361A08ULL,
		0xD7E5BECBBCC3CC0EULL,
		0xA7ABACD1F009D195ULL,
		0xCB9FE5772AD04DCCULL,
		0x6C4ED3D08D5D3E8FULL,
		0x76581DCE1BB21BC6ULL,
		0xFAF68FBBB3A5A7AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60BF58DF4DA7EF7DULL,
		0x2589622E244B263AULL,
		0x400611A2D5B185B7ULL,
		0x77253D23A9B1E5EAULL,
		0x6E54E2014D073978ULL,
		0xFD38ACA070B714D6ULL,
		0x0E0632056B86906FULL,
		0x41A411F03419E463ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84CB47C1A8F9E2C4ULL,
		0xD01C99656B89F3C0ULL,
		0x97F3E72E48FCDDD9ULL,
		0x219539D7F79F8E7EULL,
		0x0F186209A3F32DCFULL,
		0x1058EA625215788FULL,
		0xDE03B05653DD34CBULL,
		0x1EF0F58268D9807DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74226B6216F46C6ULL,
		0x8DAEF00D537B6C49ULL,
		0x9396F9657F03A7C6ULL,
		0xDB94D4E4FB929629ULL,
		0xDED1A9AE7112C67EULL,
		0xE63BB7227002B349ULL,
		0xB0E2B380616E9925ULL,
		0x3B5E8FA2DDD3F57EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x638961778996A402ULL,
		0x5DB2696838F29F89ULL,
		0x04651E4B37FF7A1FULL,
		0xFA01ED330C0D1857ULL,
		0xD1C9CBA7D2E1EBB1ULL,
		0xF6635D402217CBC6ULL,
		0x6EE103D632B3ADEEULL,
		0x25AE7A20B50A7503ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E4016B0BA16C8FCULL,
		0x1088F4E8ECD7DC32ULL,
		0xA4FB4FC1B3A6F9B7ULL,
		0xF6A06DA56567C747ULL,
		0x034B2E137E491EE6ULL,
		0x60E4A5245637BEE4ULL,
		0xE230622550720665ULL,
		0x5679D04D0E641E91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756DF6B4E03CE041ULL,
		0xACD3147A3864A980ULL,
		0xFB9B9F71BC450BB3ULL,
		0xB2CFF214C1410612ULL,
		0x62F5DDA847B94C37ULL,
		0x38ABE2AA6D2AB92FULL,
		0x1CBC7CA4514C6B9EULL,
		0xD023DECC627DD30CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B2DE0045A2A28BDULL,
		0xBC5BE092D4B375B2ULL,
		0x5F60D0B00FE3F204ULL,
		0x446F9FB1A426C155ULL,
		0x61BEF3BB39F052D1ULL,
		0x584F478E3B1D07CBULL,
		0xFE8C1E81013E6DFBULL,
		0x865A0E816C19CD9DULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x204DFE7005E4C608ULL,
		0xF47F7E18E6CE0F93ULL,
		0xD381C94FDAB3A048ULL,
		0xC9E3A7E4D41D4D70ULL,
		0x177E969794BCA80BULL,
		0x7B20B30B7B9D6086ULL,
		0x94C429D45D30F5B7ULL,
		0x16F45789E82FE8E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7FF1ADFA0B82556ULL,
		0xEFAA31F1EE94DEA3ULL,
		0xEF4780D7655F8C63ULL,
		0xAF312BD20A476377ULL,
		0xD3C9C407132AD8C2ULL,
		0x334123275D197000ULL,
		0xED7F7816DCA31FC6ULL,
		0x3A388A389FA908BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87B2E4AFA55CE35EULL,
		0x1BD54FE9085AD130ULL,
		0x3CC64998BFEC2C2BULL,
		0x66D28C36DE5A2E07ULL,
		0xC4B75290879670C9ULL,
		0x4861902C26841086ULL,
		0x79BB51C28193EA71ULL,
		0x2CCCDDB17786E057ULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57981292B3E56080ULL,
		0x6C3906B6D3F28CAFULL,
		0x77AF7BB92CC9DD10ULL,
		0x85219F90E22151D4ULL,
		0x32F9FDD1FB8B8D84ULL,
		0x7AB6A6C094AD3D34ULL,
		0x734B199DBD9BB277ULL,
		0x6F6811F5C25D5B2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x784ADA5D7C37EC23ULL,
		0xCFEDF1A3EED5E77DULL,
		0x8D0AAA0821BA2F51ULL,
		0xBD3F42D14DDB4589ULL,
		0xB04F2D464BC0AC21ULL,
		0xB1855B4D1DDE22C9ULL,
		0xF6EBF2E468E4040AULL,
		0xF9707BC34A4554D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FD2C8CFCFD28CA3ULL,
		0xA3D4F7153D276BD2ULL,
		0xFAA5D1B10D73F241ULL,
		0x381EDD41AFFA145DULL,
		0x82B6D097B04B21A5ULL,
		0xCB33FD8D89731FFDULL,
		0x85A0EB79D57FB67DULL,
		0x96186A3688180FFCULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B870E82D92E3726ULL,
		0x9F8791950593FCBEULL,
		0x92961A9F20F33E7BULL,
		0x393FF2EC02CA3E81ULL,
		0x8BC0A207D579BC85ULL,
		0x56A6AF23973DFB8FULL,
		0xCD7974102CE57D0DULL,
		0xAA8B963573DA24E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623B5E6B040D342DULL,
		0x5796FDF95CF34FCEULL,
		0x7F91863DA19F41E7ULL,
		0x71558ED9A3F2AC5EULL,
		0xEF7B1EB596C17DABULL,
		0x0CA4C5E22A147D7CULL,
		0x14F9A37A518065B6ULL,
		0x87339C1DB33DB805ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49BC50E9DD23030BULL,
		0xC8116C6C5960B370ULL,
		0xED079CA2816C7F9CULL,
		0x486A7C35A13892DFULL,
		0x64BBBCB243B8C12EULL,
		0x5A026AC1BD2986F3ULL,
		0xD980D76A7D6518BBULL,
		0x2DB80A28C0E79CE0ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E5D61FA2D6246F9ULL,
		0x363009CCD7483F44ULL,
		0xC588F59ECDBA0F7CULL,
		0x697758D71BD0D1E0ULL,
		0x06096029F01818FCULL,
		0x5C5A70EB9BDB376FULL,
		0x5D8EF336BB4E2017ULL,
		0x2D53D4FE1E21498FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79002D1AA6BEEB53ULL,
		0x745824A8A3950583ULL,
		0x61037F10168E5C7BULL,
		0x7BEDBC8CA753521EULL,
		0xA876729C5A7D131FULL,
		0xE12A274816E89902ULL,
		0x606F85B5C7E1FC46ULL,
		0x4BCA0C833DD8F64AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x775D4CE08BDCADAAULL,
		0x42682D6474DD3AC7ULL,
		0xA48B8A8EDB345307ULL,
		0x129AE45BBC8383FEULL,
		0xAE7F12B5AA650BE3ULL,
		0xBD7057A38D33AE6DULL,
		0x3DE176837CAFDC51ULL,
		0x6699D87D23F9BFC5ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBACB47DAD2E7B378ULL,
		0xBFB196901AFBF74FULL,
		0xB45774CA3215ADEEULL,
		0xEE2D5DE2A1FF754CULL,
		0x53DB75F8DC4DA338ULL,
		0xF6B46307B4892ED4ULL,
		0xE2151043F6F765B9ULL,
		0x225352A605734304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC956AB41B9E68893ULL,
		0x3C4D672685593ACFULL,
		0xC3994168DC40806FULL,
		0x2A618CAC7C84B46BULL,
		0x0CD3E78501900AC0ULL,
		0x936FE46D2A5A4E63ULL,
		0xD974FE3B8D9276B5ULL,
		0x3DC00AFD1D8EE64FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x739DEC9B6B013BEBULL,
		0x83FCF1B69FA2CD80ULL,
		0x77CE35A2EE552D81ULL,
		0xC44CD14EDD7BC127ULL,
		0x5F08927DDDDDA9F8ULL,
		0x65DB876A9ED360B7ULL,
		0x3B61EE787B65130CULL,
		0x1F93585B18FDA54BULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB18DAB1D57404473ULL,
		0x6ED8C35F07DEDDBDULL,
		0x703608FEA29D446AULL,
		0xD059DA1075D04728ULL,
		0x44693589D4AA6E84ULL,
		0x4C1CD2007231A918ULL,
		0x69D47FE39C8BD45EULL,
		0x156D6A399564C7C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CCC392C9486C510ULL,
		0xA733FE1870FE06CEULL,
		0x9CC850C544C9FF69ULL,
		0x642B9B85936A9BE7ULL,
		0x3A4A2B9763CF0E1DULL,
		0x7EAD47E8BB8CC2FEULL,
		0x3376317755D6B28AULL,
		0x712277608A3B6E85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D419231C3C68163ULL,
		0xC9EB3D477720DB73ULL,
		0xECFE583BE654BB03ULL,
		0xB4724195E6BADCCFULL,
		0x7E231E1EB7656099ULL,
		0x32B195E8C9BD6BE6ULL,
		0x5AA24E94C95D66D4ULL,
		0x644F1D591F5FA942ULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF626AD374B10DDC5ULL,
		0xC78A355BCFE0D7F8ULL,
		0x53163060F6F40287ULL,
		0x02618693750B445BULL,
		0xA5154CD552EC7E28ULL,
		0x4D7623A46AD683B0ULL,
		0x067F0D34E5CF81DDULL,
		0xCF34B71B320A62BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60B00357163B363ULL,
		0x2D539398DE36A929ULL,
		0x17A89A795EEB9A6BULL,
		0xAD78E8361FDB2699ULL,
		0x11F05BE4599E2306ULL,
		0x4351D8EDDBB85DC0ULL,
		0xD733BECCFFE61EB5ULL,
		0xD14386612FD05A6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x102DAD023A736EA6ULL,
		0xEAD9A6C311D67ED1ULL,
		0x44BEAA19A81F98ECULL,
		0xAF196EA56AD062C2ULL,
		0xB4E517310B725D2EULL,
		0x0E27FB49B16EDE70ULL,
		0xD14CB3F81A299F68ULL,
		0x1E77317A1DDA38D1ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75BC434BC9299F07ULL,
		0x3DA67F3C8A08B1CCULL,
		0x42B3D9AD16A802AAULL,
		0x7BDD61A562306EEAULL,
		0x451798CE528920F5ULL,
		0x606558457E4699ECULL,
		0x93621C7A75BD73E0ULL,
		0xBE50C25564AA651BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x270D816B47D2B079ULL,
		0x1558F567D972B289ULL,
		0x37311CD0654BBDE0ULL,
		0x6C01BA425BE028EAULL,
		0xCA6DF28EF18F7607ULL,
		0x77FEDF10B91C4ED2ULL,
		0x641374922D5E38D8ULL,
		0x2B4AC5DE510509E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52B1C2208EFB2F7EULL,
		0x28FE8A5B537A0345ULL,
		0x7582C57D73E3BF4AULL,
		0x17DCDBE739D04600ULL,
		0x8F7A6A40A30656F2ULL,
		0x179B8755C75AD73EULL,
		0xF77168E858E34B38ULL,
		0x951A078B35AF6CFEULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29090F8E67B7B010ULL,
		0x796E5159727A8831ULL,
		0xA684249807AB65BBULL,
		0xDD88B2222C87EB88ULL,
		0x716B3F3EAF77581AULL,
		0xE6E688BF44FE2823ULL,
		0x8313442498DBAEC8ULL,
		0x0C5B501C04D6F401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E46DDA841C92D06ULL,
		0xF7B56F08AFB6F7BCULL,
		0x38D760BFA355F699ULL,
		0x871D9D667B97C068ULL,
		0x743E3148E073F332ULL,
		0x788DB19296096CB5ULL,
		0x57766A4BA4A24E7EULL,
		0xA8B25F32F7400B51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x774FD226267E9D16ULL,
		0x8EDB3E51DDCC7F8DULL,
		0x9E534427A4FE9322ULL,
		0x5A952F4457102BE0ULL,
		0x05550E764F04AB28ULL,
		0x9E6B392DD2F74496ULL,
		0xD4652E6F3C79E0B6ULL,
		0xA4E90F2EF396FF50ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x55DF93C4BE9492ABULL,
		0xA8091D3A05A04D52ULL,
		0x2A664CCA686227E9ULL,
		0xEEAB2D2EC7AD1EB7ULL,
		0x66C56274987B50CEULL,
		0xB9827F68969C922DULL,
		0x6D4D2F2D5072B142ULL,
		0x24199908A717B5A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6DE2DD2B17DE89ULL,
		0xFA2DE615F59F0221ULL,
		0xA10DDE196E4ABA79ULL,
		0x1B384E648BC983FEULL,
		0x12560A0BE0AA7224ULL,
		0xB3552FED12540B27ULL,
		0x4E9F85A9020837D2ULL,
		0x92033B83545C2B11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7EB2711995834C22ULL,
		0x5224FB2FF03F4F73ULL,
		0x8B6B92D306289D90ULL,
		0xF593634A4C649D49ULL,
		0x7493687F78D122EAULL,
		0x0AD7508584C8990AULL,
		0x23D2AA84527A8690ULL,
		0xB61AA28BF34B9EB5ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34374B9E27E2BA2ULL,
		0xD9F935AD4DEC6870ULL,
		0x3DFE0BBCD7931468ULL,
		0x402F4ECB5811180BULL,
		0x538E185E02E22B9CULL,
		0x76BE783D3E9B6AC8ULL,
		0xA3B9A164FEC646A9ULL,
		0xD118028A8A68ACD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1D2B3F9387A069ULL,
		0x03ABCDAF6C417738ULL,
		0xD593A414C09E5FD8ULL,
		0x6D0A2A555CF60FA1ULL,
		0xC863E3FFAAEDA2D1ULL,
		0xE9BF6173D59AD504ULL,
		0x696D1CB1ABA28C4EULL,
		0xEF50AE829D100328ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C5E5F8671F98BCBULL,
		0xDA52F80221AD1F48ULL,
		0xE86DAFA8170D4BB0ULL,
		0x2D25649E04E717AAULL,
		0x9BEDFBA1A80F894DULL,
		0x9F01194EEB01BFCCULL,
		0xCAD4BDD55564CAE7ULL,
		0x3E48AC081778AFFBULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D654059937340BDULL,
		0x700354589C2E9E87ULL,
		0x62A07B8DFDDA52F7ULL,
		0xFC78BDBDB44B869AULL,
		0x63079914D81A5F5EULL,
		0xAF63A8A952D22B72ULL,
		0x219770A62BDD2645ULL,
		0x395225A7CA6D0A2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x130AF265FA456556ULL,
		0xAAA7EE8049ABCCCDULL,
		0x45952F790EF90890ULL,
		0xE5534517CC02C110ULL,
		0x9AE74EB6019227A0ULL,
		0x91B225FAFC2E5DC1ULL,
		0x40DCA76D2EFC44D0ULL,
		0x677FB8B73ADDCB2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2E6FB23C693625EBULL,
		0xDAA4BAD8D585524AULL,
		0x273554F4F3235A67ULL,
		0x192BF8AA7849478AULL,
		0xF9E0D7A2D98878FEULL,
		0x3ED18D53AEFC76B3ULL,
		0x614BD7CB05216295ULL,
		0x5E2D9D10F0B0C101ULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27AF05E1D2B72A50ULL,
		0xDE358E2724F000A4ULL,
		0xAA1BC80D1B8688BCULL,
		0x822956AAA863E38AULL,
		0xFFCFCFBD83E86BD5ULL,
		0x0BDBBA77AEFD3362ULL,
		0x4A8F1B4066AB233FULL,
		0x6EB28D1AA787C247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6FDAE388EC4AF2ULL,
		0x115847C67E3C6A46ULL,
		0xFA2A8CAF65A785B3ULL,
		0xCA7FBB1C40AC8BD7ULL,
		0xE2D9B14983B5DAFAULL,
		0x18F70F522D31B27FULL,
		0x9B2CF51A4917B1BDULL,
		0x8701F2421E84544CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CC0DF025A5B60A2ULL,
		0xCF6DC9E15ACC6AE2ULL,
		0x503144A27E210D0FULL,
		0x4856EDB6E8CF685DULL,
		0x1D167EF4005DB12FULL,
		0x132CB52583CC811DULL,
		0xD1A3EE5A2FBC9282ULL,
		0xE9B37F58B903960BULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7E061F985CCD4D7ULL,
		0x25C899EDCC88BCA0ULL,
		0x21E6C195530796DBULL,
		0x155A1164B96125C5ULL,
		0xFEDF879E5BB21DB0ULL,
		0xF3EC55705B555699ULL,
		0x030D25F71AD45C8DULL,
		0xE23E25C63FFE370DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92AF2E94338873D2ULL,
		0xDB4C9307D18C5BABULL,
		0x271E8B8621CFB8F5ULL,
		0x05B17AF0A55D3424ULL,
		0x3CC4C545B71B2950ULL,
		0x5F3A4B6C68904ABAULL,
		0x6A74DE99ADFC2471ULL,
		0xA330E4B504A8D621ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x354F4F6DB644A705ULL,
		0xFE840AEA1D04E70BULL,
		0x06F84A1372C82E2EULL,
		0x10EB6B941C3C11E1ULL,
		0xC21B42DBECA934E0ULL,
		0xACD61E1C33C51C23ULL,
		0x6979FB6EB72878FCULL,
		0x410EC1733B56E12CULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC169CC405D245FEULL,
		0xEB2E080760C2B6D2ULL,
		0xB71B9EE95BB08F9FULL,
		0xD209CCD2E2732388ULL,
		0x0B5622ADDC844158ULL,
		0xAAA8AFC2956D17E5ULL,
		0x88338A30732C5DB7ULL,
		0xDF7BB1B242930F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6C0A7A7E94CCBE3ULL,
		0xFC176138E8B94825ULL,
		0x79C7B205BA5137ABULL,
		0x7B2596AEB09FC2A8ULL,
		0x7EAEFC6DBD2886D5ULL,
		0x360B1F8CB75FE0A5ULL,
		0xA39A782AA62A104DULL,
		0x122FD1BC327AB1C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AD63B63EC9E8E1DULL,
		0x1739693F887BFEF7ULL,
		0xCEDC2CECE1E1B834ULL,
		0xA92C5A7C52ECE120ULL,
		0x75F8DEC061ACC78DULL,
		0x9CA3B04E2232F740ULL,
		0x2BA9F21AD5064DFAULL,
		0xCD54600E70E9BE54ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC8A445B93DB05C8ULL,
		0x1653A99F21C7E311ULL,
		0xC91B5189CDC4B2BAULL,
		0x51A387DF560FD0D1ULL,
		0x3B5CA75FC779E3AEULL,
		0x16A5540DCBA8F6E0ULL,
		0x5C03103BF6DCCCFEULL,
		0xA954FCB5322AD5E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x050B1ED361B1E922ULL,
		0x181018F390BD382EULL,
		0x7D563E5A2760B698ULL,
		0x4FCDFA7DD78E7072ULL,
		0x8A95B0CB700BE384ULL,
		0x482B28E8F76AB4EDULL,
		0x5FF718E937BAD4B6ULL,
		0xDA4DB63EEE02E032ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9815A88F26AECEAULL,
		0x0E43B16CB17ADB3FULL,
		0xB44D6FD3EAA40422ULL,
		0x1E6E7DA28181A0A3ULL,
		0xB1C91794B772002AULL,
		0x5E8E7CE53CC2420DULL,
		0x03F408D2C1661848ULL,
		0x73194A8BDC2835DAULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9E9AA69C5C5D605ULL,
		0xE05F48611D3BB384ULL,
		0xF2145619FA103667ULL,
		0x184A0F15C7AC8BC4ULL,
		0x264D883CFD61A3D9ULL,
		0x6DBF4C01F8573693ULL,
		0x4CCADCD740A7525CULL,
		0xA6B64843D20B75F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA5B4571E253EB4ULL,
		0xDD8846D5526A568BULL,
		0x6BC0C5B7671230CAULL,
		0x47B4A3AFE3E6E6CFULL,
		0x87E4E2A42C6B6B42ULL,
		0x573EA85A8897FB10ULL,
		0x88DA14150CC46041ULL,
		0xF437E0AE9DAEAC95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x874C1E3EDBE0E8B1ULL,
		0x3DD70EB44F51E50FULL,
		0x99D493AE9D0206ADULL,
		0x5FFEACBA244A6D0BULL,
		0xA1A96A98D10AC89BULL,
		0x3A81E45B70C0CD83ULL,
		0xC410C8C24C63321DULL,
		0x5281A8ED4FA5D966ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD749EFDF3C9BDD5AULL,
		0x6B7D60B4BE30D37FULL,
		0xE62824C378DFDB47ULL,
		0x15708E2597475D16ULL,
		0x0B1E236D45224F0AULL,
		0x1166BC21ACDA0157ULL,
		0x4B32C3C10F31CE14ULL,
		0x0E6377344EBBBA76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC41C80109B7F117ULL,
		0x312543FBA7E3C44CULL,
		0x6D02EAE43A28EB9BULL,
		0x25B388CAD682D9F5ULL,
		0xD6394EDEF166CC0EULL,
		0x2791C9D9261152A9ULL,
		0x031BC8082320BA0DULL,
		0x6EAA1F02172DFF01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B0827DE352C2C4DULL,
		0x5A58234F19D31733ULL,
		0x8B2ACE2742F730DCULL,
		0x30C306EF41C584E3ULL,
		0xDD276DB3B4448304ULL,
		0x36F775F88ACB53FEULL,
		0x48290BC92C117419ULL,
		0x60C9683659964577ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B5A9731270F591AULL,
		0xDD865BCAD27E91FAULL,
		0x8BF30B1F92246549ULL,
		0xED32E2193E7EC3CEULL,
		0xE8F8B6525DAEBFC3ULL,
		0x68DFBB199FFE4B0AULL,
		0x035C0BDDE3774F9DULL,
		0x1CEDB1BC4D79ADD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E7AE8FEDBD0F3CULL,
		0xDB6352308AC194EFULL,
		0xFAEF0A932C158654ULL,
		0xB14F2F8E3869163CULL,
		0x84AB7ECE879A98DAULL,
		0xF2372E3552898666ULL,
		0xC81E1E49D15AAC04ULL,
		0x3D0EE8C238456CE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3ABD39BECAB25626ULL,
		0x06E509FA58BF0515ULL,
		0x711C018CBE31E31DULL,
		0x5C7DCD970617D5F2ULL,
		0x6C53C89CDA342719ULL,
		0x9AE8952CCD77CD6CULL,
		0xCB421594322DE399ULL,
		0x21E3597E753CC132ULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x767C1AC28F3138A1ULL,
		0x47E5B5D5C3DD5FB8ULL,
		0x6C874C51E6A7A0A8ULL,
		0xE8F39B8495897A5BULL,
		0x64D86D9F78447B50ULL,
		0x9E7D0216D5F6951DULL,
		0x2B9DB333667C419DULL,
		0x8D75063066496571ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1F711829DC1ED62ULL,
		0x47B35E1E774C4B26ULL,
		0x8475D52F646BA77CULL,
		0xF1457A50943CC951ULL,
		0x6B68065633AA7222ULL,
		0xEC79ACB4783244E7ULL,
		0x2871B797E698AF6BULL,
		0x0DD22F79EA0FC2BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x878B0B4012F0D5C3ULL,
		0x0056EBCBB491149EULL,
		0xE8F2997E82CC07D4ULL,
		0x19B6E1D401B5B30AULL,
		0x0FB06BC94BEE0972ULL,
		0x7204AEA2ADC4D1FAULL,
		0x03EC04A480E4EEF6ULL,
		0x80A729498C46A7CEULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4BF55C149CCC57BULL,
		0xBC518863B002DE4FULL,
		0x3A4A48636AA8CEA8ULL,
		0x34B7347A351D1857ULL,
		0xE5B4D0D3A288D13DULL,
		0x2318AE6DE995E46CULL,
		0x0B19556926E86077ULL,
		0xF0B72920C632E295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB96EAB09C6C44A3FULL,
		0x59035FA86014E790ULL,
		0x681C412878A4B3BFULL,
		0xFAE30E0D4DCA5DCAULL,
		0x6854AEA9590B1574ULL,
		0xCA609CC6F95920BCULL,
		0xB28885A07EB026BFULL,
		0xAB1695DCC24A95AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DD1FEC88F088F44ULL,
		0xE552D7CBD01639DFULL,
		0x5256094B120C7D17ULL,
		0xCE543A7778D7459DULL,
		0x8DE07E7AFB83C449ULL,
		0xE97832AB10CCC4D0ULL,
		0xB991D0C9585846C8ULL,
		0x5BA1BCFC0478773BULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9657F9B3DDB0A08FULL,
		0x4445FE8DB265C085ULL,
		0x254DC447FAEE4816ULL,
		0x3B56DC8E5C5EF694ULL,
		0x466975D1D6A9736FULL,
		0xC037B0E4F6D23772ULL,
		0xBD078E1E18D49462ULL,
		0xC9B5DFAE5FFA20D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60948D71A8BFEDABULL,
		0x2BEC51A8D31D7491ULL,
		0xCE9DA73CCADA7E75ULL,
		0xB8ABA73854CD68D6ULL,
		0x59ACD28DCEF5173BULL,
		0x1ED8CD7A4BACE749ULL,
		0x2FF32B0E8DD4E7DDULL,
		0xCA65D84986163D49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6C374C2750F4D24ULL,
		0x6FA9AF256178B414ULL,
		0xEBD0637B30343663ULL,
		0x83FD7BB608939E42ULL,
		0x1FC5A75C185C6454ULL,
		0xDEEF7D9EBD7ED03BULL,
		0x92F4A510950073BFULL,
		0x03D007E7D9EC1D99ULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D72F7BBDE36DD73ULL,
		0x2DB6FE9358C46741ULL,
		0xB2E6AD0895D307E8ULL,
		0xF875E252A8E06E75ULL,
		0x6131BAA20B7E8B65ULL,
		0xF54B77009FA1C7FAULL,
		0x34F1E69A99969886ULL,
		0xD7DFAA2E5E2D19CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26604791B2C8986ULL,
		0xB63D1301BA4CEA53ULL,
		0x83F7C73F965DB031ULL,
		0x728F5857B843B122ULL,
		0x03585C82D32AEDD0ULL,
		0xD9882ACF2CC25949ULL,
		0x693915BA8B682297ULL,
		0x54F7455290DF4CC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F14F3C2C51A54F5ULL,
		0x9B8BED92E2888D12ULL,
		0x31116A37038EB7D9ULL,
		0x8AFABA0510A3DF57ULL,
		0x6269E620D85466B5ULL,
		0x2CC35DCFB3639EB3ULL,
		0x5DC8F32012FEBA11ULL,
		0x8328EF7CCEF25507ULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE714F80D423B52B7ULL,
		0xA52496D1B681091BULL,
		0x86E78D5FCFFC4C44ULL,
		0xB016C626CEDCAF3AULL,
		0x365900AC30954AB9ULL,
		0xD441F787F78AAEADULL,
		0x0E8C3ABB0B36F17CULL,
		0x3ACB0A2E2F53BA8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117534DD313D2F1EULL,
		0x1BC842F321D63D6CULL,
		0xD8C463306971448DULL,
		0xDB4CFD0844093E88ULL,
		0xF940C9545763EED1ULL,
		0xD583F83A798CABF4ULL,
		0xFB258799E29D5E19ULL,
		0x52E71C3C05C91D7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF661CCD073067DA9ULL,
		0xBEECD42297573477ULL,
		0x5E23EE6FA68D08C9ULL,
		0x6B5A3B2E8AD591B2ULL,
		0xCF19C9F867F6A468ULL,
		0x01C20FBD8E060559ULL,
		0xF5A9BD22E9ABAF65ULL,
		0x682C16122A9AA7F5ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD247D3B9CD6189CULL,
		0x21CEFC70DA89A712ULL,
		0x5B873A7E2573DF5FULL,
		0xAF24C2EB14FF6407ULL,
		0x62488A2606423788ULL,
		0x2B5F2A3DCF0A7560ULL,
		0xDEA4245EE9D7666CULL,
		0x6A7E621F94380BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80AEF7567D915056ULL,
		0x215D8942A71D295FULL,
		0x551CC0DDDBBEC747ULL,
		0x369EACE1167ABCAFULL,
		0xAD18AD907DC5AD15ULL,
		0xCA9E664E4A43473CULL,
		0xB6EE22599DB60B76ULL,
		0x0E503840CD751C51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D8A8A6DE14748CAULL,
		0x009375327D948E4DULL,
		0x0E9BFAA3FECD1818ULL,
		0x99BA6E0A0285D8A8ULL,
		0xCF5027B67B879A9DULL,
		0xE1C14C738549325CULL,
		0x684A060774616D1AULL,
		0x642E5A5F594D17E8ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7FCD20DE4B50E65ULL,
		0x3B924899EB2175C3ULL,
		0x59E3548AEBDC1462ULL,
		0xE93AC979F85A923AULL,
		0xBE9FB0B8E8476030ULL,
		0x6917699B4A26573DULL,
		0x4C29F93AA22E07FBULL,
		0xB3D55C7550431DE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82E2FC95405AE9DULL,
		0xAD814C2EAC8493BAULL,
		0x02C27E2323CDB917ULL,
		0x99159A9DCF2BB4E7ULL,
		0x052EE1E6BDDE18DEULL,
		0x003999ACEFCFE95BULL,
		0x514B9C49067ED0EEULL,
		0x2F8AFDA4F06F8C01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FD2FDC4B0B0A0F8ULL,
		0x961304B747A5E679ULL,
		0x5B212AA9C811AD75ULL,
		0x702F53E4377126DDULL,
		0xBBB1515E559978EEULL,
		0x692EF037A5E9BE66ULL,
		0x1D626573A450D715ULL,
		0x9C5FA1D1A02C91E2ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03CD0457F8631604ULL,
		0x49C29BB59FA3E846ULL,
		0x39E98842B079F503ULL,
		0x576F3B6386F6696CULL,
		0x7A99E8C12ACEC346ULL,
		0x09A9F3C4F3EA8057ULL,
		0x333AE062D47C117FULL,
		0x64DBE6D22860DAC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A2C664FFDCF75FCULL,
		0xF495B4B73CBCF261ULL,
		0xD20D40C5E504907EULL,
		0x35EDC9BF1C0BA3D9ULL,
		0xF7AAAFCAADA38E16ULL,
		0xBC983220B1FD0A19ULL,
		0x17E94D4995BCD87BULL,
		0xD26F6699824B9198ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09E1621805AC63F8ULL,
		0xBD572F02A31F1A27ULL,
		0xEBE4C887557D657DULL,
		0x6282F2DC9AFDCAB5ULL,
		0x8D33470B876D4D50ULL,
		0xB531C1E442178A4EULL,
		0x24D3AD2B41C0C904ULL,
		0xB6B4804BAA2B4B51ULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2A456F6AAED7B64ULL,
		0x75B534BC0F5A7B83ULL,
		0xC0B4D9EBEE2296E8ULL,
		0xB4639061EE311CDAULL,
		0xE0AE18315A51952FULL,
		0x62596C4729069EE8ULL,
		0xF5240492385A34E3ULL,
		0x1E2B32B05006942CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x425155539E33568CULL,
		0xAB0A026DEADA48BAULL,
		0xFCC738B0CF3ADC40ULL,
		0x62718860DDE76C31ULL,
		0x1032133ADEBF717BULL,
		0xA12E07CB88E6DEC6ULL,
		0xAA18D6BF51E2FFFDULL,
		0x6B5BE07FD702A7D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0F503A534DE2DE8ULL,
		0xDEBF36D1E5803339ULL,
		0x3C73E15B21184AA8ULL,
		0xD612180133D670EBULL,
		0xF09C0B0B84EEE454ULL,
		0xC3776B8CA1E0402EULL,
		0x5F3CD22D69B8CB1EULL,
		0x7570D2CF870433FEULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x493FED1B22923DB3ULL,
		0x4729780F9DFD2854ULL,
		0x72AACBF96D4185FAULL,
		0xEC24E1B3A756C510ULL,
		0x241521DDD981DC97ULL,
		0x76253D6743818C6AULL,
		0x3DC5CBFEABAAC1A3ULL,
		0x166A5D832DB3F48AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33E3C4022EBBB021ULL,
		0xFB20BBF470BD2670ULL,
		0xEB5B6D67BA6BAC27ULL,
		0xD043F7BBF29F18FFULL,
		0xDD44A4B88BCC5ACAULL,
		0xEFBECD0F13F2E56AULL,
		0xD09D37F5C1D8A666ULL,
		0xC2EE0F35CDB53026ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ADC29190C298D92ULL,
		0xBC09C3FBED400E24ULL,
		0x99F1A69ED72A29DDULL,
		0x3C67160855C9DDEFULL,
		0xF9518565524D865DULL,
		0x999BF06850736900ULL,
		0xED58FC0B6A7267C5ULL,
		0xD48452B6E006C4ACULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE68D3E057436C87CULL,
		0x724C2B11B03C0F10ULL,
		0xD89E0398BB8039AAULL,
		0x0DCAD020A040D13BULL,
		0x3B2BF49742A5669EULL,
		0x2C7ECD0DAF44EF4BULL,
		0xADC4D5E0429778CCULL,
		0x1C3CDD321F98A2F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF06AD883545ADCAULL,
		0x33C3A7326DD084CDULL,
		0xD21F56800DE6E871ULL,
		0x68A7D31D9E88864CULL,
		0x92D750B003003955ULL,
		0x81DF81E15EABD05EULL,
		0x895BD202E4DEC126ULL,
		0xACAC1C6B1EAAE428ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x498B938D417365B6ULL,
		0x418F8C23DDEC8BDDULL,
		0x0A815518B666D1DBULL,
		0x656D033D3EC85777ULL,
		0xA9FCA42741A55FCBULL,
		0xADA14CECF1EF3F15ULL,
		0x249F07E2A649B9EAULL,
		0xB090C159013246DDULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CEDCDD1741C63C6ULL,
		0x3B1CF3886A89DD2FULL,
		0x67DAC14A23795DAEULL,
		0x43E0B3F643E30762ULL,
		0x74E1E9042090C0B8ULL,
		0xC102D9464DC1C494ULL,
		0xBE0BB7FB8E9F9568ULL,
		0x800F59C2E51B31B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58DF9AAEF424E391ULL,
		0x306259C962C37949ULL,
		0x2FFE5E6BA4B39437ULL,
		0x0B75E9E9DF23EF11ULL,
		0xB404B9A112C2C41BULL,
		0xB66CB902F0494A31ULL,
		0x509530A8D1EEBA97ULL,
		0xE1C4A2EC2CC48F52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3432577F80388057ULL,
		0x0B7EAA41084AA466ULL,
		0x48249F2187CAC999ULL,
		0x48955A1F9CC0E873ULL,
		0xC0E550A5325204A3ULL,
		0x776E6044BD888EA5ULL,
		0xEE9E87535F712FFFULL,
		0x61CBFB2EC9DFBEE1ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C5028C2FC79F4DDULL,
		0xAFE9D8442F831C78ULL,
		0x603CF4B72C7E062AULL,
		0x6B947B4DEA329527ULL,
		0x529FA13361A8747BULL,
		0x42E8AD9C2F9752C5ULL,
		0xE260F8F60AD54A65ULL,
		0x21BC1301D2DF49A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE99C88B0266C32ULL,
		0x7BE523A5B83EE2DAULL,
		0xBA757B05DE7B1166ULL,
		0x449679933E513D91ULL,
		0x0A232297509DFD53ULL,
		0x2FA0F4CF3AF973F8ULL,
		0xB74BE42D0A2A8D24ULL,
		0xCAFA3A81118DE318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02B9B44A4C5F98EFULL,
		0xD40CFBE197BDFEA2ULL,
		0xDA498FB2F205174CULL,
		0x2F0202DED463A8B6ULL,
		0x58BC83A431358928ULL,
		0x6D485953156E213DULL,
		0x552B1CDB00FFC741ULL,
		0xEB462980C352AAB8ULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x965B603E3EEFE245ULL,
		0x8BB8EF4B36D873AAULL,
		0x7660626DEECF755AULL,
		0xF269CAC47867DC65ULL,
		0xC5B42D1846C8CA7FULL,
		0x82CF0227600DC30AULL,
		0x2D5D3E551C15A5B2ULL,
		0x9BC91A5076403246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5551FE764442228ULL,
		0x3F6271C9DCE3DF7EULL,
		0x12137C910DC1D20DULL,
		0x5A0422820977B6C3ULL,
		0x1407E643988879ACULL,
		0x33AA1A5F5F91DF39ULL,
		0x4E51348CABA515DEULL,
		0xDC3340AC98B4C16BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x530E7FD95AABC06DULL,
		0xB4DA9E82EA3BACD4ULL,
		0x64731EFCE30EA757ULL,
		0xA86DE84671106AA6ULL,
		0xD1B3CB5BDE40B3D3ULL,
		0xB16518783F9C1C33ULL,
		0x630C0AD9B7B0B06CULL,
		0x47FA5AFCEEF4F32DULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B83F91E9BC30634ULL,
		0xE555E88AE331E960ULL,
		0xCFCCDB6DE16D98D6ULL,
		0x019EABF8E73D68C4ULL,
		0xC944A206EFB4C5EFULL,
		0x0F738C2EBB1806AFULL,
		0xFE495D33340D4D2FULL,
		0xC7751778401FBBD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA544433812B1E3A0ULL,
		0x3F61752E3B6A0C11ULL,
		0xF80A0BC644C710EBULL,
		0xA3DD53FDB43099FFULL,
		0xDEC827B63DBDA25CULL,
		0xEE28E34A4D99CD16ULL,
		0x722AD930418B8E15ULL,
		0x9C16CEC9741B0F7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9EC7BA268972E594ULL,
		0xDA349DA4D85BE571ULL,
		0x37C6D0ABA5AA883DULL,
		0xA243F805530DF13BULL,
		0x178C85B0D20967B3ULL,
		0xE15B6F64F681CBB9ULL,
		0x8C6384037586C33AULL,
		0x5B63D9B13404B4AAULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51C8E9F4E561C469ULL,
		0x7F057A087BE3CEA4ULL,
		0x2651520F1EE0B6DDULL,
		0xF66E54BD4654C5B7ULL,
		0x5F608AB7E2BD0443ULL,
		0x02301B5D6EA72E57ULL,
		0xFD5355DFC25DDCA2ULL,
		0x70ED2E98E4341FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE257150895EF575CULL,
		0x6E06AFED336F1A6DULL,
		0x3829CA2F0525A4A9ULL,
		0x9A2DE974F11690F1ULL,
		0xAF4B121FB0ECCA37ULL,
		0x41F15E4CF295B8C2ULL,
		0x109619A2E570147EULL,
		0xD2437632688466D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB39FFCFC708E9335ULL,
		0x1103D5E5488CD4C9ULL,
		0x1E7898201BC51274ULL,
		0x6C43BDC9B7425546ULL,
		0xF02B98A85251CE74ULL,
		0x43C145119C329695ULL,
		0xEDC54C7D272DC8DCULL,
		0xA2AE58AA8CB0791FULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F4E3B8161A4FA91ULL,
		0x02083A3586A31CF3ULL,
		0x578E7C404B459CC2ULL,
		0xF8873EC8A513008FULL,
		0xD58325B73B810904ULL,
		0x4275178F1BC379BBULL,
		0x134699027D61F50AULL,
		0x52E28402A19514D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC61F352F4D0C43BULL,
		0x764E6FE4D9071EAAULL,
		0x1818488E41C6C8C5ULL,
		0x43D15C493A413BA6ULL,
		0x70D048E626A30247ULL,
		0x4C85222B1C45368DULL,
		0xFAE4D69E42BABDF5ULL,
		0xE5DD5EB9E49B53F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD32FC8D395743EAAULL,
		0x744655D15FA40259ULL,
		0x4F9634CE0A835407ULL,
		0xBB5662819F523B29ULL,
		0xA5536D511D220B43ULL,
		0x0EF035A407864F36ULL,
		0xE9A24F9C3FDB48FFULL,
		0xB73FDABB450E472CULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA00C2E00F90D46A7ULL,
		0x51E34147445F5B82ULL,
		0xC738704AC699FD2AULL,
		0x92BE428096F65B9EULL,
		0xD2AC4C5AF1491D03ULL,
		0xDF4CF915E6452400ULL,
		0xDE44CB74619ED1EBULL,
		0x45678D0ECC208642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9493CB13CDCE8A9ULL,
		0xDC01FC6A505F9E96ULL,
		0xF4880F38B008D4AFULL,
		0xCE3A326EBFD26883ULL,
		0xE7E0602F51F7DB66ULL,
		0x6E9EB0DEB3B2A5E4ULL,
		0x4D607440FE709716ULL,
		0x52F14990DF4F0513ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x194512B1C5D1AE0EULL,
		0x8DE2BD2D1400C514ULL,
		0x33B07F7276912985ULL,
		0x5C8470EE2924331DULL,
		0x354C2C75A0BEC665ULL,
		0xB1D249CB55F781E4ULL,
		0x9324BF349FEE46FDULL,
		0x1796C49E136F8351ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE439E81795F79CBULL,
		0xEBBB87AE1058F80FULL,
		0x1267807E8C7A316FULL,
		0x1A271E12E58BB837ULL,
		0x64E8CA764547F50CULL,
		0x6309987CBB9A95FFULL,
		0x83153AC4FBA71F32ULL,
		0x97AC2F08DD702147ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB99D0D60C465BE53ULL,
		0xEA8161911FA195F5ULL,
		0x0FC5E5297EC45F19ULL,
		0x17FEC4B07B5452EEULL,
		0xC663C27B07A10B4AULL,
		0x7E76E1DFB96C8931ULL,
		0x1AB7AF0B42E0C11DULL,
		0x9AFBD3F24FC488A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77DE93E1BD3AC798ULL,
		0x013AE63F0FF96DFAULL,
		0x1DA26557F2BE6E76ULL,
		0x0DD9DAA29EDFEAD9ULL,
		0xA28B080D42E6FE46ULL,
		0x1D7F79A302F61CCEULL,
		0x99A295CFB947DE2FULL,
		0x0D57FCFA92B4A9E5ULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCD145B8A22E31B4ULL,
		0x044D78381BDD161EULL,
		0xA0FCBA34413878C5ULL,
		0x7D8BD680217CFA06ULL,
		0x25F08BFC89C2183AULL,
		0xD6EB0102BEA43E14ULL,
		0xA6D8FC6D4BCC7589ULL,
		0x215EB47137F7835BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE554802543BFD0ULL,
		0xA1C7C48A62F00D8DULL,
		0x02F40FB4173E6945ULL,
		0x075965CEA608A802ULL,
		0x799DB11BE9B688A8ULL,
		0xE3F1FD099B1F49BCULL,
		0x1EA7DC5E69FA938BULL,
		0x47BC7FC81B0B1213ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56341138876D8E64ULL,
		0xA58ABCB2792D1B93ULL,
		0xA208B58056061180ULL,
		0x7AD2B34E87745204ULL,
		0x5C6D3AE760749092ULL,
		0x351AFC0B25BB77A8ULL,
		0xB87F20332236E602ULL,
		0x66E2CBB92CFC9148ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0989066A6E571955ULL,
		0xDB311D8140CDC375ULL,
		0xD32EFC31A58A4F1AULL,
		0x73B85D63721A5263ULL,
		0x361B2F0679789BA4ULL,
		0xAC85AACA270D5CC8ULL,
		0x322AF3D47BC69C81ULL,
		0x225C54EDE622F913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x833F92B7BD7C46E3ULL,
		0x416041E0F19CAEBEULL,
		0x25692F94B853EAD7ULL,
		0x8C451E2A41EE8701ULL,
		0xAA97517F898E4329ULL,
		0xBDCF155B56C07A26ULL,
		0xB7B33DB4B2F22DE9ULL,
		0x4933A47553FF3CC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB694DDD32B5FB6ULL,
		0x9A515C61B1516DCBULL,
		0xF647D3A51DD9A5CDULL,
		0xFFFD434933F4D562ULL,
		0x9C8C7E79F0F6D88DULL,
		0x114ABF9171CD26EEULL,
		0x8599CE60C934B168ULL,
		0x6B6FF098B5DDC5D6ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A3E060AD595D11DULL,
		0xDDCE24FC1A18ADD2ULL,
		0x29ED05C2FCC68C98ULL,
		0xAF25475FAC16BA89ULL,
		0xAF7C1868B5FBB2BEULL,
		0x3DBA8925B2C9C582ULL,
		0x1B07E47F81F57162ULL,
		0xA29D7BBAF74E89EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x961A7D5AF599B854ULL,
		0x8BE022AB20CF6911ULL,
		0x100AE381D3DDFD14ULL,
		0xE1AA8B926A2E3D90ULL,
		0xBC357A549C7E903EULL,
		0xECAAEAF2594EB56DULL,
		0xE73260E258297628ULL,
		0x08C2CBCCD0379FA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC247B50200C6949ULL,
		0x562E06573AD7C4C3ULL,
		0x39E7E6432F1B718CULL,
		0x4E8FCCCDC6388719ULL,
		0x1349623C29852280ULL,
		0xD11063D7EB8770EFULL,
		0xFC35849DD9DC074AULL,
		0xAA5FB07627791648ULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40C8B7E02B45D0C1ULL,
		0x5BFEDD6FDD3152A0ULL,
		0x27BE3E0124C23A3BULL,
		0xB0E32E9E78292E83ULL,
		0xB6553EAFBD59FA77ULL,
		0x72576A2D599EFE6EULL,
		0x361F071F086D338DULL,
		0x2C81AFEA4B9B1D16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D58247F23933B6ULL,
		0x90B3E2453A64EE0CULL,
		0x2E1E0E572037FC41ULL,
		0x9DD37F80E3C08632ULL,
		0x20B25011217FF1C4ULL,
		0x12727068295E7401ULL,
		0x579027E1B0E75CEEULL,
		0x03D51B31C198E5FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x151D35A7D97CE377ULL,
		0xCB4D3F2AE755BCACULL,
		0x09A0305604F5C67AULL,
		0x2D30511E9BE9A8B1ULL,
		0x96E76EBE9C260BB3ULL,
		0x60251A4570C08A6FULL,
		0x618F20FEB88A6F63ULL,
		0x2F54B4DB8A03F8ECULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AAA343A3D80E9DEULL,
		0x89D363DF542EE96EULL,
		0xA96C9419AF7D94ECULL,
		0xEEB148FB8E755319ULL,
		0x3CF6338A993D74C6ULL,
		0x65242FCB38FFDC89ULL,
		0xBAD40D48DA20DCA5ULL,
		0xB56F9F1C20C79ED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7B99BC2325354EAULL,
		0xAE50A186FD66942FULL,
		0x7F6A78373356F625ULL,
		0xA53EA2FCF4A7128FULL,
		0x16E2DDA0357289C9ULL,
		0x08AC3C5C013B7D31ULL,
		0xFA11A2776607C096ULL,
		0x85AFBC91145D9353ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D13AFF80FD3BD34ULL,
		0x2783C259A9487D41ULL,
		0xD606EC2E9C2B62C9ULL,
		0x4B8FEA077AD24196ULL,
		0x2A14EE2AAC4FFD0FULL,
		0x6D88139739C4A1B8ULL,
		0x40C5AF3FBC271C33ULL,
		0x30C0238D349A0D87ULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCEC2729FD6E6F3CULL,
		0x5483D6ECEE315E02ULL,
		0xD8298BDA6F6E5718ULL,
		0x3D1D8B46C11B5454ULL,
		0x917D45772F36A582ULL,
		0xF0FD56F83C1E0E4CULL,
		0xF4A2AFBFF58F1873ULL,
		0x025F9E8F769C5663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFEFEF20BD82EE3CULL,
		0x6C85377E5C68D18CULL,
		0x4A2BB1DE31F25859ULL,
		0xD43207E48B7E00EDULL,
		0xE220A167C1B9662EULL,
		0x9E05B79F9B658FCCULL,
		0x185640CFF3DF311BULL,
		0x8B79B404FD9C5D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6303C80940EC8100ULL,
		0x3806E192B2598F8EULL,
		0x92023A045E9C0F41ULL,
		0xE92F8CA24A6554B9ULL,
		0x735DE410EE8FC3ACULL,
		0x6EF8E167A77B8180ULL,
		0xECF4EF7006502968ULL,
		0x89262A8B8B000B74ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE66A7A5F4B0DB66CULL,
		0xC49F9326F36AC43CULL,
		0x984C3F9BF81E4812ULL,
		0x992621431715B9A6ULL,
		0xB1036EC3E2291FCFULL,
		0x444AC782F5D017DBULL,
		0xA42B44956DFA620AULL,
		0x2FFDE180FF8102FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCAAE674B832E83DULL,
		0x79A483296977DB89ULL,
		0xBB2FE3C04988AC9CULL,
		0x34FA1D8F5C668D3AULL,
		0xC17DE6F77775514AULL,
		0x0EAF97F8B907F628ULL,
		0x7CAB607905D6DEC7ULL,
		0xD1FD5D14B8BC482DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AC09C2BF33F5E51ULL,
		0xBD3B100F9A1D1FB5ULL,
		0x2363DC5BB196E48EULL,
		0xADDC3CCC4B73349CULL,
		0x707E8834955C4E85ULL,
		0x4AE5507A4CD7E1F3ULL,
		0xD88024EC682CBCCDULL,
		0xFE00BC94473D4AD0ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA573802CA5AE751ULL,
		0x94D19DF9BD623833ULL,
		0xA76E46AD60464914ULL,
		0xCBE0DCAEDDD1A433ULL,
		0x001B330BAAFAC1A3ULL,
		0xE75917644AC57F02ULL,
		0xE2E820C36334AFC9ULL,
		0x2D72FD2895DF7B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AED064A66076708ULL,
		0x61CFF2742834A389ULL,
		0x3F352AD49FA25384ULL,
		0xBCCE7A03BB59AC38ULL,
		0xD57EE3C9134E1C60ULL,
		0xE81757B9165B2590ULL,
		0x2DA4CD732C8BFB08ULL,
		0x04EE2C49D880A06EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0BA3E48AC5D8059ULL,
		0xF51E6F8D95569BBAULL,
		0x985B6C79FFE41A90ULL,
		0x772EA6AD6688080BULL,
		0xD565D0C2B9B4DDC3ULL,
		0x0F4E40DD5C9E5A92ULL,
		0xCF4CEDB04FBF54C1ULL,
		0x299CD1614D5FDB02ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AB9CC116207155DULL,
		0xF5A206F74BA8DC84ULL,
		0x5B0C0328B1D683DEULL,
		0x16B6ECEA9ECEDF9CULL,
		0xC5322053AA53A37EULL,
		0xB30647F8F628E64DULL,
		0xA55F3110AE91A1BDULL,
		0xEE5A91807EFDE29CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC972B9D7A37E93CULL,
		0xD3508691D0377D96ULL,
		0x24C95DC0032EB7D0ULL,
		0xCAA0AE3FD77013D1ULL,
		0x41EDC5159DF2153FULL,
		0xD00C557315CA4328ULL,
		0x86E5F2301BF4E043ULL,
		0xC37BC90B5F16FBF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x562EE78C1830FC61ULL,
		0x26F280669B9FA112ULL,
		0x7FC55EE8B2F8340EULL,
		0xDC1642D549BECC4DULL,
		0x84DFE54637A1B641ULL,
		0x630A128BE3E2A565ULL,
		0x23BAC320B56541FEULL,
		0x2D21588B21EB196CULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x119CC112D475032FULL,
		0xDCCBC50D3ECA7155ULL,
		0xDB71602CDF622994ULL,
		0x60A3E8A2E7EBDF0BULL,
		0x7FBAEDDDC731786EULL,
		0xA4918266C1002B16ULL,
		0xDDA493D0A256497EULL,
		0x46F6EAA0568D66FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67DA3BD37B890B3ULL,
		0xB9FC99D118AD65DDULL,
		0x23FF0EFFAF34B931ULL,
		0xC0DDC426BAB46F23ULL,
		0x5DB4DEB3113E43A0ULL,
		0xBB019C057256D3D3ULL,
		0xEA5C1FDA08196191ULL,
		0x0D202A245B8E1A3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7E162AFE3CD939CULL,
		0x65375CDC26671488ULL,
		0xF88E6ED3705690A5ULL,
		0xA07E2C845D5FB028ULL,
		0x220E336ED60F3BCEULL,
		0x1F901E63B356F8C5ULL,
		0x37F88C0AAA4F28EFULL,
		0x4BD6C0840D037CC2ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B36198A589A42BCULL,
		0x4F62D09FD077F27FULL,
		0x64F2FAFC3F469AD2ULL,
		0x52BDE2B13E90B868ULL,
		0x8B1D0705DF83C4F3ULL,
		0xF50E7223BA2BBA15ULL,
		0xAD8BE74759F82564ULL,
		0xF74DCFF4844CFCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0147AEA74AB7272FULL,
		0x84B975337CDFC0BCULL,
		0xB8B90FA78577E170ULL,
		0x60BFAFF182350E84ULL,
		0xA22ED084A124E5F7ULL,
		0x57BE6000748FF717ULL,
		0xB079B148AA4609A4ULL,
		0x1E9E76B4CD4307FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A71B72D122D6593ULL,
		0xCBDBA5ACACA832C3ULL,
		0xDC4BF55BBA317BA2ULL,
		0x32024D40BCA5B6ECULL,
		0x2933D7817EA72104ULL,
		0xA2B01223CEA44D02ULL,
		0x1DF2560FF3BE2CC0ULL,
		0xE9D3B940490FFB5FULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5176C25D363499A5ULL,
		0x96C1F68A85794AB2ULL,
		0xD4AC357026FB62A4ULL,
		0x2D4D38A333A83192ULL,
		0x3132377BEB8E1FE3ULL,
		0x9B63F950838BE6FEULL,
		0xA7FD3F41807924CAULL,
		0x9A8B36E6D27A49BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF29A08C516EAF5B2ULL,
		0xB16C57D45D82AA40ULL,
		0x796B5A61BA4C18A8ULL,
		0xE11983F84C565C49ULL,
		0xAE4696C5B0B86994ULL,
		0x66FC578D42D37B4DULL,
		0xD28605AD05512930ULL,
		0x991BB41D5686123FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3ECCA9820DE6C17ULL,
		0x27ADA15ED8FBE0F2ULL,
		0xADC76F119CB77A0CULL,
		0xCC54BB5B7FFE6DDBULL,
		0x9F74A1BE5B367677ULL,
		0xFD9FAEDDC1589DB3ULL,
		0x757B3AEC85280DFAULL,
		0x039082FB84FC5B83ULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE17843497F87B01ULL,
		0xC7C9DBD85FB521F6ULL,
		0x33A94401A8B671F5ULL,
		0x8B40D3CF3D067417ULL,
		0x7777EA1EE9AC30A2ULL,
		0x34C508419AB839EAULL,
		0xB50C56F9A516DB6BULL,
		0xB4E9BD0B4118328FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E7E6ADE636A3D6FULL,
		0xA7B556226CEE117CULL,
		0x2D24078310FF9AB8ULL,
		0xD828706749F0B3BEULL,
		0x56B00647A66EE04CULL,
		0xA0623B790A2D2770ULL,
		0x2652AE8366FE2CAEULL,
		0xC597E51DDB0727A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC069EEEAF492466EULL,
		0x607C8DFA335B308AULL,
		0x1E8D4382B849EB4DULL,
		0x5368A3A874F6C7A9ULL,
		0x21C7EC594FC2D0EEULL,
		0x94A7333890951E9AULL,
		0x935EF87AC3E8F7C5ULL,
		0x717E58169A1F152EULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x938BE0F1E244FF52ULL,
		0xE784323207845C95ULL,
		0xB2536C308B74AFD4ULL,
		0xD8F83CD8AE339056ULL,
		0xAF3A788EAC1F5209ULL,
		0x93EF2DE937951CBCULL,
		0xB5ED5DE01471FEA0ULL,
		0xBBD509B74977385BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AFA0DAD1AA6A1E2ULL,
		0x16EF7CBE75AD0DCFULL,
		0xE766D17A50A5A7CDULL,
		0x52FF96E77D7AB9F8ULL,
		0x594A01B593EADA8BULL,
		0xE432A900F8289AF1ULL,
		0xDFCF58B89404FCE1ULL,
		0xB67D56B8B6AEDA60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB971ED5CF8E25EB0ULL,
		0xF16B4E8C7229515AULL,
		0x5535BD4ADBD10819ULL,
		0x8A07AA3FD34929AEULL,
		0xF670793B3FF58882ULL,
		0x77DD84E9CFBD864DULL,
		0x6A22055880750241ULL,
		0x0DA85F0FFFD9E23BULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD736B66C28E01BFBULL,
		0x639F58DEBD5D883DULL,
		0x350CE5E72AD18569ULL,
		0x48690D584C1C4442ULL,
		0x0699B6861C95C972ULL,
		0x557F0C198298C8EAULL,
		0x73EE536BE6A00860ULL,
		0xAA643CFF1F772FF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BD91472267342D3ULL,
		0x622F624D191A9854ULL,
		0x557DA1D7DEDBB3C1ULL,
		0x489DCC83E25017D5ULL,
		0x66C7B72BC2E2684AULL,
		0xDD5986F3A836110DULL,
		0x868AA0CDCCFD89F0ULL,
		0x9CEA6596BA130C63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACEFA21E0E935928ULL,
		0x01B03A93A4471069ULL,
		0x60714430F40A36A8ULL,
		0x00F4C1DBAE4C5397ULL,
		0x605E01ADDE77A138ULL,
		0x88268AEA2AAED9E7ULL,
		0xF564F3A62A5D8190ULL,
		0x368E5969A5642395ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70424EB2869B3F81ULL,
		0xAA90D315F6AE456BULL,
		0x87FCA928FC9A6F32ULL,
		0x417605AF491ED4DDULL,
		0x9FABF9B49AFEEF1FULL,
		0x07617AC9E8A08F0FULL,
		0xBF26943BE574F356ULL,
		0xCD98FEEEDC8659FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742EC84F0E6FD1D6ULL,
		0x4576C71EB1E064CAULL,
		0x08FAFC7D7BC1EB45ULL,
		0xA54B393F40B4DF7BULL,
		0x6C410F2B0D95B5A9ULL,
		0xCC640F49CC092374ULL,
		0xF2B07957E7BE5904ULL,
		0x5ECA61DF598533C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x046C86FD88F4EE57ULL,
		0xEFE6140B474E21A1ULL,
		0x8F065555875B8477ULL,
		0xE43D3C9009AA0BA6ULL,
		0xF3EAF69F976B5AB6ULL,
		0xCB05758024A9AC7BULL,
		0x4D96ED6C02CAAA52ULL,
		0x93529F3185036A37ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x075C4B39DC61371FULL,
		0xDF687E51B4D997D5ULL,
		0x9ADE230AA73EF2A1ULL,
		0x37B2B4EFC01DAD4EULL,
		0xAF47E39A6C7F8049ULL,
		0x0ECB1401C54D6AC1ULL,
		0x736C05F53B856698ULL,
		0x681FE3D9DB501447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB10AB57040CDBE23ULL,
		0xBAF38561E00206CFULL,
		0x0459738C0BDF258DULL,
		0xF65A80D15F17385FULL,
		0xEF00606255D38EDFULL,
		0x68F8BC786C34FD5CULL,
		0x462D999CB8D9FDC1ULL,
		0x2285A338D5A4E371ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB656FE499CAC893CULL,
		0x659BFB3054DB911AULL,
		0x9E875086ACE1D72CULL,
		0xC1E8343E9F0A9511ULL,
		0x404783F839AC0E96ULL,
		0x6633A879A979979DULL,
		0x35419C69835C9B59ULL,
		0x4A9A40E10EF4F736ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E7042BD7B8B1E43ULL,
		0xD069F493B7C20067ULL,
		0x8985E651A5182D45ULL,
		0x686B8667BEB547F4ULL,
		0xD88F7C21C4FECC16ULL,
		0x1E20D6F61ABF28B4ULL,
		0xCC812750029BADFEULL,
		0xE75D8FBFF589B065ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6D44009C04A0ABFULL,
		0xAFF0D93838793B66ULL,
		0x45F90C6DBE6D15E6ULL,
		0xC9C716B42BB0916FULL,
		0x9539C1CFAB46FE29ULL,
		0xB660E5E02BCD3E87ULL,
		0xF5FFDD6E5D1F887AULL,
		0x8C65166317655E94ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8A402B4BBC114FCULL,
		0x7F992DAB8FBB3B01ULL,
		0xCC7CEA3C1B7538A3ULL,
		0xA1AC90D39505D69BULL,
		0x4DB6BDEE6FB8323FULL,
		0xA840331631721633ULL,
		0x397EFA3E5F842584ULL,
		0x6B3899DCE2ECEEF1ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23E6F9531C2ADEA4ULL,
		0x1AB432DAF07B2571ULL,
		0xB25D1900607ED392ULL,
		0x937119C237F3737FULL,
		0xB444C1A4DA234FF8ULL,
		0xA673AD1079B40461ULL,
		0xE99C551B06019872ULL,
		0x4073C20612003C9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE7C89EC5F54042ULL,
		0x884BE762B06B67B7ULL,
		0xB965F3DA0AFF3826ULL,
		0x5A42E7C55706338AULL,
		0x7B2568591CB9AEFAULL,
		0xBB8FAF747D579C7DULL,
		0xF9377A796DDE0B63ULL,
		0x9E0198C14FDF953DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC90131CDD9DF9EE6ULL,
		0x92FFD5B8401042C6ULL,
		0x0B38EADA6A81EBB4ULL,
		0xC933FE0760F540F5ULL,
		0xCF61A9FDC69AE102ULL,
		0x1DFC026404E3981CULL,
		0x10AB2F626BDF9311ULL,
		0xDE725AC75DDFA9A3ULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2FC16269B8632E7ULL,
		0x7AB248075F554456ULL,
		0xD9CEDFFCFFF15721ULL,
		0x3C14F90C26D7F2F8ULL,
		0x6F47BEFBDEDF0B24ULL,
		0x0652FF867289821CULL,
		0xBFB3DC88C4F77BADULL,
		0x15DE9606A696523AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C4178A4C9D008C1ULL,
		0xF71BF9BF231A99EBULL,
		0x7E7C58B42A78121AULL,
		0xC2DCA39570BAFF90ULL,
		0x6087FC7D3FCC6279ULL,
		0x1F4B74713AE9FE8BULL,
		0xE99224058417D98AULL,
		0x7ACFD0E26E265F7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEBD6E8252563A26ULL,
		0x8DA9B1B87C4FDDBDULL,
		0xA7B28748D589453BULL,
		0xFEC85A99566D0D68ULL,
		0x0FC04286E113695DULL,
		0x19198BF748607C97ULL,
		0x5621F88D40E0A227ULL,
		0x6F1146E4C8B00D41ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x986351A0A4B1C02EULL,
		0x6231C98A80AA1EEFULL,
		0x1807AEFC597C60C1ULL,
		0xA82EEF2017AB6D7CULL,
		0x507A64B9532D0B98ULL,
		0xB36D4C6FAF8A4BF7ULL,
		0xE4BCB65EF4210B3AULL,
		0x2AEA40666C7A0CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFF59D33621FF17ULL,
		0x5BF79E8AB656EE31ULL,
		0xFF84C43E08A35DC6ULL,
		0xC745BC48480A0A81ULL,
		0xA42390A218448ABBULL,
		0x4932644C3AFD14D2ULL,
		0x8CE5E34FCC37DB8CULL,
		0xCF0A66B5F84A9CA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE29C087392903F39ULL,
		0x39C6570036FCF0DEULL,
		0xE7836AC251DF3D07ULL,
		0x6F6B53685FA167FDULL,
		0xF459F41B4B698123ULL,
		0xFA5F282395775F25ULL,
		0x685955113816D0B6ULL,
		0xE5E026D39430907CULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4649FFEDAFC9CC8ULL,
		0xD28E0288E1E90781ULL,
		0x5BD173EAC2F311FAULL,
		0x98C6C9C9207C6F32ULL,
		0x2284D8E605A120A1ULL,
		0xFF7984638D0CA915ULL,
		0xF0A14CF910CC2F3FULL,
		0x1C5ED8E384C51A62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDC3CEB846CD8E68ULL,
		0x0A0F8D115EFD9C97ULL,
		0x83174258C809F31AULL,
		0x572BFB14FBDAD7FBULL,
		0x140A92DBD5310096ULL,
		0x66558C28A72F51C3ULL,
		0x35E3B4AE5D16B049ULL,
		0x145D31C14085B803ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19A751469C3112A0ULL,
		0xD8818F99BF149B16ULL,
		0xD8C631B20AFAE2E0ULL,
		0xCFED32DDDBA6B8C9ULL,
		0x368E4A3DD0902037ULL,
		0x992C084B2A23F8D6ULL,
		0xC542F8574DDA9F76ULL,
		0x0803E922C440A261ULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD3330F3472089C9ULL,
		0x572FB7DD034E7696ULL,
		0x95F2FFB816976406ULL,
		0xC9155181D14E3D57ULL,
		0xA5C326BCDB7DB5ADULL,
		0xEEBA4A9F2230D4DBULL,
		0x3F21073BA27E469FULL,
		0x34E82E39C11087E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA87B8A7F1E835CULL,
		0xE3DE93FF2A7E1396ULL,
		0xD0D4E483AF9F499DULL,
		0xC34D47B65BF6686DULL,
		0xB3D9B7E45B03F8D7ULL,
		0xA6D6623246C49680ULL,
		0x527AFF1022F0BDCBULL,
		0x06337FB2F1E33784ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD29B4B79383E0A95ULL,
		0xB4F1242229306500ULL,
		0x45261B3BB9082D9BULL,
		0x0A5816378AB8553AULL,
		0x161A9158807E4D7AULL,
		0x486C28AD64F4425BULL,
		0x6D5BF82B808EFB54ULL,
		0x32DB518B30F3B066ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE13DBDA491A933C1ULL,
		0x1ACBED93B3AC54BBULL,
		0x38F40E761770EC93ULL,
		0x0C5F607430B10194ULL,
		0x566DA279D80832E1ULL,
		0xDB66D56D2826B470ULL,
		0x78139F1174093842ULL,
		0xD297D74ADF8D09FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67EC7C1A9B8F0C85ULL,
		0xD59AFD666591DDE6ULL,
		0xFC11988931DEDAE4ULL,
		0x47719FA24779A321ULL,
		0x16ADEEEA94CD4432ULL,
		0x62E0DF45A1277B86ULL,
		0x0B49E3F868D0D861ULL,
		0x6B2F788323B64648ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86D1C1BE0A263F44ULL,
		0xCF5110F5D63D895DULL,
		0xC4E596FF26AE3677ULL,
		0x4B2EFFD677C8A2B5ULL,
		0x40C04C934CC576D3ULL,
		0xB9860A288901CFF6ULL,
		0x735A7CE91CD9E023ULL,
		0xB9B8AFC9FC3B4FB3ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FF8F9DD78D84E37ULL,
		0x8E31B71CE2C3D2A0ULL,
		0x7762CE1CEEE3D166ULL,
		0xC7BBA7AECEAF2F72ULL,
		0x0EEFA89DC2429CACULL,
		0x031274A66862A49EULL,
		0xB32F0DBB005E4DE5ULL,
		0x33EDB05025296A49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956FAE52832CEF7BULL,
		0x6D0F174F1E02F447ULL,
		0x402893FB29DEDD23ULL,
		0xA80D76998CD9E6FBULL,
		0x21F836D1DBC0063EULL,
		0xF80D3C7367CA9994ULL,
		0x3AA06E3EBFAD87E1ULL,
		0x3C63A58B60E11B4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A97578FFBF4A14CULL,
		0xE33EA053FCC126E7ULL,
		0x374A5DE7C73D0C45ULL,
		0x6FB6D1374276C989ULL,
		0x2F179E4C19829A92ULL,
		0xFB1F48D50FA83D0AULL,
		0x898F6385BFF3CA04ULL,
		0x0F8E15DB45C87105ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x291417C3C44BF2E7ULL,
		0x845AFBEAF978A8CBULL,
		0x149FD498A2565D95ULL,
		0xDCBA47835F8AD7A8ULL,
		0xBEE935BA4199E58FULL,
		0x30E85FF5D81EC696ULL,
		0x546E222FE683C2F8ULL,
		0xFBC67C94AC935045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E9B81EDA87FC36ULL,
		0x9CE09D045713E3D7ULL,
		0xBB9383B83D6C44F1ULL,
		0x276504EBA418AF73ULL,
		0xA78D133F651C6545ULL,
		0x0BD3CA9A6AE3A4A5ULL,
		0xAA8852443B505E02ULL,
		0x9FFCADFA15899943ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BFDAFDD1ECC0ED1ULL,
		0x18BA66EEAE6B4B1CULL,
		0xAF0C57209F3A1964ULL,
		0xFBDF4368FB9278DBULL,
		0x19642685248580CAULL,
		0x3B3B956FB2FD6233ULL,
		0xFEE6706BDDD39CFAULL,
		0x643AD16EB91AC906ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44E9021AAC97523EULL,
		0xEB1D4C3EF26E4833ULL,
		0x1B03E5DB0881BAFCULL,
		0x563CDED91EF48047ULL,
		0xE7F616C46B783005ULL,
		0x106DEE980E20DE21ULL,
		0xB187815E62DC76F4ULL,
		0x679CBD1DB179CB70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FF38955DEABFDCULL,
		0x9E7A54E9D9B5683AULL,
		0xB78304AE4D211EC7ULL,
		0x693DC74C159CA3B5ULL,
		0x2DAE12CCE97F50FBULL,
		0xA1775F550491FC96ULL,
		0xCD579DE073721DB5ULL,
		0x8631B34E35D0CDA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85163A8FF17DEDE2ULL,
		0x756718D72BDB2009ULL,
		0xAC80E17545A0A43BULL,
		0x3F0119950B6823F2ULL,
		0xCA580408820760FEULL,
		0xB11AB1CD0AB122B7ULL,
		0x7CD01CBE11AE6B41ULL,
		0xE1AD0E5384A906D4ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x822751B995577245ULL,
		0xFAF1F488BE54E04EULL,
		0xD45FF325137250E1ULL,
		0x543D6308E35D5A00ULL,
		0x78D8326AA575CF6BULL,
		0x9A90C96235821395ULL,
		0x8CA3199AD4DC221DULL,
		0xFE95FA79C7D41B78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F42B7EF952085EFULL,
		0x4508FCC89643E20AULL,
		0x884D61296D110E1DULL,
		0x89C714A3A44FA407ULL,
		0xA0D2D9DD4657524CULL,
		0xC9325FAAA740FD95ULL,
		0xD57E6C2A50C8C532ULL,
		0x1AB859B7A3F80E75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD65E6560077F7AAULL,
		0xBFF9084028170244ULL,
		0x5C12920C7E635EFCULL,
		0xDDFA77AB4712FE07ULL,
		0xD80AEBB7E3229D27ULL,
		0x53A296C892C2EE00ULL,
		0x59DD75B08414E72FULL,
		0xE42DA3CE642C150DULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D30B4B9B5184F6CULL,
		0x8B0862B1B0931131ULL,
		0x1740086D5A642A87ULL,
		0x5ED21F13980E8EEAULL,
		0x9DDAA2BFEFC93892ULL,
		0xD4164A13C7DCB2B7ULL,
		0xFE28EE866D71B7D6ULL,
		0x5B2D7F176D5B0941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88533FF47DD5A517ULL,
		0x33FF8D023FD604DEULL,
		0x410BA11BFA575425ULL,
		0x08FB0F774B0990DCULL,
		0xC882564F1EB1E5A1ULL,
		0x487D9AB9DE968913ULL,
		0x04BB6000A6D4E070ULL,
		0xA8F5B6DF52164CBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05638B4DC8CDEA7BULL,
		0xB8F7EFB38F4515EFULL,
		0x564BA976A0337EA2ULL,
		0x56291064D3071E36ULL,
		0x5558F4F0F178DD33ULL,
		0x9C6BD0AA194A3BA4ULL,
		0xFA938E86CBA557A6ULL,
		0xF3D8C9C83F4D45FEULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1529B45A7EB769EAULL,
		0xB038153862F21E3DULL,
		0xC0E2D273C1DB6980ULL,
		0xB2F9372ABC6D5345ULL,
		0xC49E0E00106FCFB0ULL,
		0x770C6ABAC69C9A41ULL,
		0xECCF210366FC7595ULL,
		0x7748A856F4BED4E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x584C8F4D19F4ABA4ULL,
		0xD34D8209BBB81D8EULL,
		0x78B8F888AD595AD6ULL,
		0x46253BF314F550BAULL,
		0x512EA55418B5E1B3ULL,
		0xB2244ADA3BCFD36FULL,
		0xCA3A63AD74B7496DULL,
		0x46CC8BCCD611AED0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D653B176743C24EULL,
		0x63759731D94A03B3ULL,
		0xB85A2AFB6C823356ULL,
		0xF4DC0CD9A89803FFULL,
		0x95B0AB5408DA2E03ULL,
		0xC5282060FD53492EULL,
		0x26F542AE124B3CF8ULL,
		0x3184239A22AF7A31ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE5E9B6E6C99CF1AULL,
		0x95B3FB91E9FD1E46ULL,
		0xFFA4F0FDC24165FFULL,
		0x26ADEBBB62D688B2ULL,
		0xEED61B5EF008618EULL,
		0x34BE751605710108ULL,
		0x07770D71313E2086ULL,
		0x2F3B6C9A157A6FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x978D0244A987153DULL,
		0xA02CF3608014B3BEULL,
		0xE6DC6AC0FB79BA9BULL,
		0xEF91BFF7E6001478ULL,
		0x170951338F5FF401ULL,
		0x9CC4F15A42DDC444ULL,
		0x63C83D2C81266DD7ULL,
		0x90824B38A7247716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D3992AC51EDA27ULL,
		0x359F08F169E9ADF8ULL,
		0x19789A3D3938DF64ULL,
		0xC93C544C84D69CCAULL,
		0xF9DF4A6D7F57958FULL,
		0xA87A844C47ACC54CULL,
		0x64BF305DB0184D51ULL,
		0xBFB927A2B25E18FCULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE4ABAEE0E431502ULL,
		0x79A279B4CAE22CF7ULL,
		0x2F7F9361E08168DEULL,
		0xEF4C4A1902E22477ULL,
		0xDB78C3BB10EEDC55ULL,
		0x57E134F6B293917DULL,
		0xCF433E50CD25C1E9ULL,
		0xD3DD4BBA7AFC4279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB830278BA63D462EULL,
		0x3AD998EA987B6720ULL,
		0xCEC97D17FA56DC60ULL,
		0xB8BD391645CA0031ULL,
		0xD2197AA032D4F12CULL,
		0x95B26535F1FC6B14ULL,
		0x1066855B56107A76ULL,
		0x5A2A3453B64DCBBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x667A9D65A87E532CULL,
		0x437BE15E52994BD7ULL,
		0xE1B6EE761AD7B4BEULL,
		0x57F1730F47282446ULL,
		0x0961B91B223A2D79ULL,
		0xC25351C3436FFA69ULL,
		0xDF25BB0B9B35BB9FULL,
		0x89F77FE9CCB189C2ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D2DE6A6C173373ULL,
		0x48FF1F4972558D68ULL,
		0xBDD89982A2FC03DCULL,
		0x49B656460BD81735ULL,
		0x6CF0154BC2A7B023ULL,
		0x897AA97F301B0D5BULL,
		0xDC151724D73D1984ULL,
		0x106619294C97B6D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFD1E66673D83842ULL,
		0x54902C3E88FDE43AULL,
		0x30D4534B8D6102AEULL,
		0xE82759EDC770625AULL,
		0xA9518584949EF1DBULL,
		0x6BB423785E54DAAEULL,
		0x56933F3A5990457CULL,
		0x686CBCE1DDEEE97DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D03380C1FCF0B31ULL,
		0x1C6F3377FAA86952ULL,
		0x8D0CCAC92F9D0172ULL,
		0xA1910FABCCA8756FULL,
		0xC5A190CF563941F8ULL,
		0xE2CE8A076E4FD7F5ULL,
		0x8A86281E8EAD5CF8ULL,
		0x780AA5C891795FABULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02F1E8860F211C67ULL,
		0xCF4B3F72C297B22BULL,
		0x04020F7B298065D1ULL,
		0x3E45217C60596E8AULL,
		0xB1A4E52E67D07D95ULL,
		0x0D783D7527848BB1ULL,
		0xF5AFCBE7954C1846ULL,
		0xA25BCBBDDF87DC78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5289018AD9C8FC8ULL,
		0xE28502A9FA48C37DULL,
		0x382DDFF7137A5166ULL,
		0x1D04D825430CBC95ULL,
		0xF87C28A29EEF9D65ULL,
		0x9388F3EB3B410EF0ULL,
		0xEA67AEB71A6889BCULL,
		0x32170CC297939516ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7D9789EA2BD93AFULL,
		0x2DCE3DDB38DF7156ULL,
		0x3C2FD08C3AFA34B7ULL,
		0x2341F9592355D21FULL,
		0x49D8CD8CF93FE0F0ULL,
		0x9EF0CE9E1CC58541ULL,
		0x1FC865508F2491FAULL,
		0x904CC77F4814496EULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0246E194D1FCCF9ULL,
		0xE4CF91D833C512D0ULL,
		0x40F16D4E60819354ULL,
		0x977AB4539CB42B4BULL,
		0xE35BD2C8D67DD529ULL,
		0x42403A012E07395DULL,
		0xBE62B9DE2CF3CB5EULL,
		0x944A94EBC54CD6C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC2919E7646A2279ULL,
		0xF9F8B3D3BE5C0F9AULL,
		0x0C9F563964FBF4AAULL,
		0xAA7BE65E0E4F9860ULL,
		0x42F17BB223F86422ULL,
		0xCB18E19399E61C2AULL,
		0xF46B1EB9CD97E3F5ULL,
		0x9F5E2EB14DFC785DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C0D77FE2975EE80ULL,
		0x1D37220B8D991D4AULL,
		0x4C6E3B77047A67FEULL,
		0x3D01520D92FBB32BULL,
		0xA1AAA97AF585B10BULL,
		0x8958DB92B7E12577ULL,
		0x4A09A767E16428ABULL,
		0x0B14BA5A88B0AE9EULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50F9EF2556D87761ULL,
		0xC87232E537EB0902ULL,
		0x5429CF7D323801D3ULL,
		0xB4282E3BC234C188ULL,
		0x324F31C1F23C97EFULL,
		0x98EE0DEEA8EE28B4ULL,
		0xAFB98733C9F6C989ULL,
		0xD310398DF8F2435CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x707DCBB95E720F2EULL,
		0x2B2651D582E32D61ULL,
		0xB2E299771D0E8074ULL,
		0xB68FDF3803DCBD4BULL,
		0xE55EA749E1DD8882ULL,
		0x92754EEC11E51B60ULL,
		0x83CD5E85C67710E5ULL,
		0x1A941C685FBD1626ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2084249C08AA784FULL,
		0xE3546330B5082463ULL,
		0xE6CB560A2F3681A7ULL,
		0x02A7F103C1E87CC3ULL,
		0xD711968813E11F6DULL,
		0x0A9B4302B90B33D4ULL,
		0x2C74D9B60F81D96CULL,
		0xC98425E5A74F557AULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A63914C4347A4AFULL,
		0x370B61F1530B088EULL,
		0xB687D86D4C693FC7ULL,
		0x4BF8CE1D4071D300ULL,
		0xA7CCC78C5608B298ULL,
		0x0EC1A9692E7387E2ULL,
		0x7872DAF6A7FFF713ULL,
		0x0B91E6DE27DF3A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4B08BE9A3FF701FULL,
		0x77BF47BEF2FBBC77ULL,
		0x33E4BFF58DB2542AULL,
		0x1A13B499C150A0B9ULL,
		0xD47CD35578BA8840ULL,
		0x43C9A089364012D5ULL,
		0x62786241B96A097DULL,
		0x5A3956D829357A63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED31AA5E0B8D4B0ULL,
		0x40B4264FA1F0B4F9ULL,
		0x85636798C1DB6BEDULL,
		0x51EB7A84812173B9ULL,
		0x73B014D92EB23AD8ULL,
		0x4D0809E018339537ULL,
		0x1A0AB8B71E95FE6EULL,
		0x51A8B0060EEA4028ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5BEB9CEB0E8FB8EULL,
		0xD82797020735D3D0ULL,
		0xB1F0D00DD163AFA1ULL,
		0x0966014A8A66AA0FULL,
		0x1CAAC55E7F2022DCULL,
		0x7B30E19EF1ABA646ULL,
		0x9B572F2E598DE2C0ULL,
		0x19E82FE43A5765D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD0361CA2A4C166AULL,
		0xEA2B21505FA3820EULL,
		0x041F2D3DDB591B33ULL,
		0x5B69A76E51DB1412ULL,
		0xA346DC66A4E90157ULL,
		0x77017A6FF9315919ULL,
		0xB90D3676AE47C097ULL,
		0x09999AA7C39EDE48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68BDD8049AA4EDE4ULL,
		0x320CB652589651DEULL,
		0xB5EFFD300A3AB492ULL,
		0x520FA624DBBDBE1DULL,
		0xBFEC1938DBC9238BULL,
		0x0C319BF1089AFF5FULL,
		0x225A1958F7CA2257ULL,
		0x1071B543F9C9BB90ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BA290A19F5AD2DBULL,
		0x00928FBA448415C8ULL,
		0xDF2EDF2870AA3F57ULL,
		0x1FC2F6E4B026463FULL,
		0x7076640FA15EFAE8ULL,
		0x8B1322E90746F510ULL,
		0x1BA448D5727646E2ULL,
		0x872FD8E83FD3811AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB977A0D51323C8ULL,
		0xCBFAFC712F7C5707ULL,
		0x962C3D1AAF0C1743ULL,
		0x5FD76F8944640948ULL,
		0xE8D9C9AAB9152FBCULL,
		0x3C9EA6BF76627128ULL,
		0xB5DFD75A3979E0CAULL,
		0xB9DF519F26E17C19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD71BE7014A49F113ULL,
		0xCB6873CB6BF842CFULL,
		0x4902E232DFA62814ULL,
		0x4015996DF4424F77ULL,
		0x98AFADA5184BD554ULL,
		0xB78D845671248438ULL,
		0xAE7B9F8F4B0FA628ULL,
		0x3EF089771932FD03ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEE63D0E56634A00ULL,
		0x8287F0DC049C28CBULL,
		0xDB526E3FA9AC83E0ULL,
		0x7CEFB754646EC035ULL,
		0x9A80E73B1F265613ULL,
		0x75E0B53C827440EEULL,
		0x7073D6F155AB2C6DULL,
		0x06804CA3C22CBD8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23FE7667AF88DC1FULL,
		0x41032A3B530FA0F0ULL,
		0x0ECF547D08CAC3D7ULL,
		0xCAA9E8358AF0C4BAULL,
		0xB6AFBE2EBC8F9487ULL,
		0x64CA5A57AEBCD511ULL,
		0xBE5E6C4571318864ULL,
		0x4BDDBD601CF9FB8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D184B69F9EB961FULL,
		0xC384DAE75793883BULL,
		0xD59D3A42A1664037ULL,
		0xB6465F61EE9E048FULL,
		0x2C2F5915A3A9C294ULL,
		0x112AEF6B2CC895FFULL,
		0xCE2DBAB4249AA409ULL,
		0x4D5DF1C3DED54607ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7144CA85BDE22A19ULL,
		0xE793F03C67F793B5ULL,
		0x8DEF783DE2FB2DE2ULL,
		0x186FD236CFEFBDD7ULL,
		0x9CA3308BEEC1819EULL,
		0x37C648D9404405FCULL,
		0x2BBA00EFC434D0B8ULL,
		0x54D29593ACA79730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F153B6119D6BC4AULL,
		0xC6B38169FF5B3A61ULL,
		0x827787A49902BD54ULL,
		0x248A9C3E21F7ECC0ULL,
		0x77723468C8916F72ULL,
		0x698AF43A4ABF5D55ULL,
		0xB3E210F880109A91ULL,
		0x1640119B9FB73757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E51F1E4A4349653ULL,
		0x2120715598ACA9D4ULL,
		0x0F98FF997BF990B6ULL,
		0x3CE54E08EE185117ULL,
		0xEBD104E32650EEECULL,
		0x5E4CBCE30AFB58A9ULL,
		0x9858101744244A29ULL,
		0x429284083310A067ULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DCF2E15409BDFA5ULL,
		0x5C276C3BC3CE93FDULL,
		0x5A14C82B0B12E8DAULL,
		0x05F2B12C8B9D48E3ULL,
		0x282E6F2035786F80ULL,
		0x505FE627BCC2EC6AULL,
		0xBAB015A866E28F84ULL,
		0x88598E344F1B96BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC562DCAACE83BAB0ULL,
		0x44D1D246723879FCULL,
		0xE0705D9317CCAA35ULL,
		0x0CBEA6CBC6C4A9B7ULL,
		0x8238E096085A74A7ULL,
		0xBC5574C91B354B9CULL,
		0x7BA0C3A13A982858ULL,
		0xDB417984EF3C99DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88ADF2BF8E186515ULL,
		0x18F6BE7DB1F6EA01ULL,
		0xBA6495B81CDE42EFULL,
		0x094C17E74D59E154ULL,
		0xAA168FB63D221B27ULL,
		0xEC0A92EEA7F7A7F6ULL,
		0xC110D6095C7AA7DCULL,
		0x5318F7B0A0270F67ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7C6E75E71AF1FF8ULL,
		0x13C3CB9AD11328A6ULL,
		0x7821D4F1ABDE9437ULL,
		0x0456DE834EDDD1BCULL,
		0xD06AEAC7FAAB6DD4ULL,
		0x5131985753B873DCULL,
		0x46373EB51F2EFB97ULL,
		0x364235713BBF42ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A5B268676F2F33ULL,
		0xCF3EFB5349405780ULL,
		0x6A85FDA47457FA56ULL,
		0xED6AA6DC88C1B05DULL,
		0x1071DADCBA84381FULL,
		0x79D16C2122B9E6EFULL,
		0xCFB262B00575EFC0ULL,
		0xB5E455FB59EFD43DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E63553616C030CBULL,
		0xDCFD30C998537F26ULL,
		0x12A42955DF896E61ULL,
		0xE93C785FC61C61E1ULL,
		0xC01B301B402F55CBULL,
		0x28E0F47671019533ULL,
		0x89855C051A5B1457ULL,
		0x83A6608A625096D1ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17AA13AB7F9CDE68ULL,
		0xF6EB33045974BDD9ULL,
		0xCB6D3F61496A0308ULL,
		0x2D07F75CC8D484B9ULL,
		0x3A1335BF4FFB63D2ULL,
		0xE845C961390A3956ULL,
		0xC78C46C6B187AF42ULL,
		0x9B93F04869CE118EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1908C4F68A7374EEULL,
		0xBCDE6271A20AF7B9ULL,
		0xF495F2890188A245ULL,
		0xF03C1057DCC2B641ULL,
		0x84251A6E8C700C03ULL,
		0xBCEC3665CB4AA27EULL,
		0xA403324DEE6F1169ULL,
		0x9AF20A43517D72B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EA2D75DF5EFAA86ULL,
		0x4A355175FB7E4A60ULL,
		0x3FF8CDE848E2A14DULL,
		0xDD3BE70B141632F8ULL,
		0xBE362FD1C38B6FD1ULL,
		0x54A9FF04F2409B28ULL,
		0x638F748B5FE8BE2BULL,
		0x0161FA0B38B3633FULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4ED693625EA0328ULL,
		0xF125001E15A21771ULL,
		0xC4DF85C5DFA6A2F0ULL,
		0xFBF28CE24B4F3915ULL,
		0x9BF52291EF67D13FULL,
		0x150B399A3A6490B2ULL,
		0x8349B30DB5002FB6ULL,
		0xBBAAB3BAEECF1568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA79CE90F9A658D1ULL,
		0x6E68A8AAF9D592DCULL,
		0x2F9EEEA4C791DE71ULL,
		0x58859970CFC7193DULL,
		0xB24050FCCE6192A2ULL,
		0x198152E804FB1DE4ULL,
		0x5EFAB51BCE6344FCULL,
		0xFF44E115C16B4F87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E94A7A6DC4C5BF9ULL,
		0x9F4DA8B4EC7785ADULL,
		0xEB416B6118377C81ULL,
		0xA377159284882028ULL,
		0x29B5726D2106439DULL,
		0x0C8A6B723E9F8D56ULL,
		0xDDB306167B636B4AULL,
		0x44EE52AF2FA45AEFULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE6CD7B46FFD2BD1ULL,
		0x0E116E959DCEEFACULL,
		0xE62A96500E5BE738ULL,
		0x20E1C08D236E4D5CULL,
		0x67775CECDFD77778ULL,
		0xA493E670D4D83995ULL,
		0xCAB0203D62596577ULL,
		0x99FBA44C6849AB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984CBAA9F54F67B6ULL,
		0x014CFFB1F69D63B8ULL,
		0x085A61B3D443159AULL,
		0x1ADE3B9A620C336EULL,
		0x99F1CDF0E6DE8FB3ULL,
		0x70AECF7A0DBB8E93ULL,
		0xBD302CA25DE55FBAULL,
		0xA4C06F3EA79B3BCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56206D1D9AB24C67ULL,
		0x0F5D91246B538C14ULL,
		0xEE70F7E3DA18F2A2ULL,
		0x3A3FFB1741627E32ULL,
		0xFE86911C3909F8CBULL,
		0xD43D290AD963B706ULL,
		0x77800C9F3FBC3ACDULL,
		0x3D3BCB72CFD290FEULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5674FAD7E24DAB02ULL,
		0xFA0F735556272E1AULL,
		0x25919228FB7B3C07ULL,
		0x3F2FEF5B467B4FA2ULL,
		0xC968792D01F9C8CFULL,
		0x5D073E6FB85BA8B4ULL,
		0x869015BF70A407A8ULL,
		0x800323C6123F8063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25896BB4EFC2DCAULL,
		0xA5BCD9CC7ECFBAAAULL,
		0xC943F781F4BA7966ULL,
		0xE99AD0518CC356C1ULL,
		0xB5090C3762AC4C4BULL,
		0x9A3E0B7762A2C454ULL,
		0x847DCBA76F00399CULL,
		0xA5E8E4C14B1A1304ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF42C6C6CACB186C8ULL,
		0x5FB3AA9928E894B0ULL,
		0xECD265A90FC14561ULL,
		0xD6B53F0ACAB81963ULL,
		0x7C61751A63558484ULL,
		0xC7393518DAF96CE0ULL,
		0x02EDDE181FA43E34ULL,
		0x25EBC70759259367ULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA01453FA0997E721ULL,
		0xD8E118FCC71B8814ULL,
		0xC17F399DE9A9D4EAULL,
		0x05F334C5A6844F90ULL,
		0x5266C1D792818A1BULL,
		0x180241E7DF15AC9BULL,
		0xA04FFB32640C8A13ULL,
		0x83E0F8D8489C1CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D71508F572F0970ULL,
		0xA9A38BD831854576ULL,
		0x9841BADAA49A4A1CULL,
		0xAC71BCF16E39A6D8ULL,
		0x07AE21BF5D8577B5ULL,
		0xC8E44CE30CC1396EULL,
		0x2ACFE98279571E67ULL,
		0xAA905580653336FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD6503755EB8EE51ULL,
		0x71429324F69ECD62ULL,
		0x593E83474D339EF6ULL,
		0xA9828834C8BDE948ULL,
		0x55C8E068CF04FDAEULL,
		0xD0E60D04D3D495F5ULL,
		0x8A8012B01D5B9474ULL,
		0x2970AD582DAF2A39ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0919AAE064EE0682ULL,
		0xDF89B4705BA54A15ULL,
		0xE3275F48746959D9ULL,
		0xA7FCC6EEDC5F6F88ULL,
		0xFE01275F570B15D2ULL,
		0x1E0150FC1B088E08ULL,
		0x3C8839AC53A288D4ULL,
		0xF4E7F4AF32E8DD32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00555326DA08910EULL,
		0x69169767C39D1897ULL,
		0x6F51D50924FBA529ULL,
		0xEE21395B8405DFF0ULL,
		0xD5D9810328EC19E7ULL,
		0x367E45BBB9AB193BULL,
		0x06A9499C60D95936ULL,
		0x9164000B6BE07AE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x094CF9C6BEE6978CULL,
		0xB69F231798385282ULL,
		0x8C768A415092FCF0ULL,
		0x49DDFFB5585AB078ULL,
		0x2BD8A65C7FE70C35ULL,
		0x287F1547A2A39733ULL,
		0x3A217030337BD1E2ULL,
		0x6583F4A45908A7D4ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14E8E69EACE1EF5EULL,
		0x1B23DD9BF4B39D95ULL,
		0x568F370B5D4C4A66ULL,
		0x3756F0130B08915CULL,
		0x9A22BA04C4DC13C8ULL,
		0x9B60CF86F09F3111ULL,
		0xEF0011113D20448DULL,
		0x7C57045791B70DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD555C70A0103B40DULL,
		0xAF06CE5E48930DB2ULL,
		0xEBDA16E5FEDF4875ULL,
		0x6C70B39905543CC1ULL,
		0xAAE3F8B6A591139DULL,
		0x0B2EC7182ABB8774ULL,
		0xC93C111DAAEE8E64ULL,
		0x4AA6E3D31AD99249ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1BD2194ADE25B53ULL,
		0xB42513C5BC209027ULL,
		0xBD5521EEA3930213ULL,
		0x5B26438A0E5CAD9DULL,
		0x30C142B2614D0055ULL,
		0x904E089EDA24B665ULL,
		0x263C000C97CECAE9ULL,
		0x36F1E7848B6E9F89ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BA9CDB13D15840AULL,
		0x981114E99A904B53ULL,
		0x1E4AC6EA0D894158ULL,
		0x7108937B3DC0324EULL,
		0x4E7186E08CDD98B5ULL,
		0xEC8F0840EB0D952BULL,
		0x5D78CFACAA8A76F6ULL,
		0x3652217E20055DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF3DB6F960E4918ULL,
		0x8FC93536FA787B95ULL,
		0x5C051ED471FFEA5DULL,
		0x060CD6133B100BE7ULL,
		0x8B92FC707B08D29CULL,
		0x5D753C5B1C122F12ULL,
		0x94C87F34BCA127C6ULL,
		0x2FDC0BDCCA9E3056ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC75A16DEAB1BCD12ULL,
		0x17D821DF60E830C6ULL,
		0x424FD83E7C76AB05ULL,
		0x7704456806D039A9ULL,
		0xC5E37A90F7D54A29ULL,
		0xB1FA341BF71FBA39ULL,
		0xC9B0B098162B5130ULL,
		0x198E2AA2EA9B6DE2ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4026FB8B3E7A7FEULL,
		0x37C3BED1A6240E11ULL,
		0x8F97499D36BAFBB1ULL,
		0xBBDA8163F3F0323EULL,
		0xD9F94ECDC617FEADULL,
		0xA10189DFD4384635ULL,
		0xD3ED848D94B1E428ULL,
		0x3D5B51526DBA229AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47777FF16DE5CC49ULL,
		0xE61DE707651A5F2DULL,
		0x2EC62870E088AE56ULL,
		0x4C8DC93AE6EC5517ULL,
		0x44C01B5BBE2E257AULL,
		0xA2AD2F745315630DULL,
		0x577C873C69CD0B06ULL,
		0x3DBA4750233C1EDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83751049DE026BB7ULL,
		0xD1DE59D6C33E513CULL,
		0xA15161EDD63255E7ULL,
		0xF7574859151C6729ULL,
		0x9D3955967839DBD7ULL,
		0x03ACA6AB872D2538ULL,
		0x849103B1FD7CEF2EULL,
		0x00E116024E863C45ULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC23C8D10E2CBC517ULL,
		0x8D30FE1903D55375ULL,
		0x8C17A399F951A844ULL,
		0x36066B18A7345967ULL,
		0xD7B5AF7EAB03F3BBULL,
		0xC20B1D83D3837096ULL,
		0x7ED47D9596C1D04EULL,
		0x2B35647256F9B517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27448D7903BEEAE3ULL,
		0xB226D8BDC173C977ULL,
		0x9994E634969B82E1ULL,
		0xA1A3029299455785ULL,
		0xBEE2517DE8EB4CFCULL,
		0x2CF813B97CAFC09AULL,
		0xB379C5E6D130D0CFULL,
		0x536A078E4863581CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5780069E1752FF4ULL,
		0x3F1626A4C2A69A02ULL,
		0x158345AD6FCA2AA5ULL,
		0x97A5698A3E710EE2ULL,
		0x6957FE0343E8BF47ULL,
		0xEEF30E3AAF2CB00CULL,
		0xCDADB87347F10081ULL,
		0x785F63FC1E9AED0BULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CE43E223655D31BULL,
		0x1A5CD3DAA4172746ULL,
		0x0959AF2758F0B9C1ULL,
		0x89441D2E3221A2A5ULL,
		0x37440EB4A31D60DCULL,
		0xFDA6F9CBFD540148ULL,
		0x1BD9B1E4562D4822ULL,
		0xF3ECA52577425054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA550DFA18C0BE958ULL,
		0x2D0C78C537AEC298ULL,
		0xC4495EF1257E554BULL,
		0x84C1B8A3F1171029ULL,
		0xB5EA21AC74192858ULL,
		0x00BA7936479CEAD8ULL,
		0xFD00F4744E4EBD0CULL,
		0x1478977A8F08DFCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89B4E183BA5E3A43ULL,
		0x3750AB1F93B9E5DEULL,
		0xCD10F1D67D8EEC8AULL,
		0x0D85A58DC336B28CULL,
		0x82AE2F18D7044884ULL,
		0xFD1C80FDBAC8EB90ULL,
		0xE6D945901863F52EULL,
		0xE794325FF84A8F9BULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E2D230FEF405B5EULL,
		0x7CF2BCFBB91FEC6AULL,
		0xECFA13D5148E91D3ULL,
		0xD2E50C1EA8C907DFULL,
		0x8036BA9C8C54DED0ULL,
		0x8B59956CE4CDC529ULL,
		0xD5B1D3237A2CC79DULL,
		0xA18A4A90AB6E300FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98D596AD1CCA9817ULL,
		0xE22C57DE90E2356DULL,
		0x9129A1D6EA02ADA8ULL,
		0xC7398A0D6B3403ECULL,
		0x8638491673A84A09ULL,
		0xB56E983C80A9F76DULL,
		0x152259A67AE2288BULL,
		0xAB07DF63C97E3A61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6F8B5A2F38AC349ULL,
		0x9EDEEB2529FDD907ULL,
		0x7DD3B203FE8C3C7BULL,
		0x15DC8613C3FD0433ULL,
		0x060EF38AFFFC94D9ULL,
		0x3E370D5064643244ULL,
		0xC0938A8500CEEF16ULL,
		0x0A8D95F362100A6EULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEE4CEA325B0680EULL,
		0x330BE869B40BEFE1ULL,
		0x4DCBA919C93E4487ULL,
		0x7F1D4B778E125D9BULL,
		0x9B2C40D146673C97ULL,
		0xBE2B366FD45F8637ULL,
		0x8AFE7AD17BB8A48AULL,
		0xDA7BB854F6FFA3ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD79B0B9F32CBEAFULL,
		0xF81B1AA434A45E66ULL,
		0xFA0F673487082C5EULL,
		0x6693A2BE13B8FF7DULL,
		0xCBD317BA4147413AULL,
		0x9A0736626F47D82EULL,
		0x06F9C231F228D20AULL,
		0xD113347D2AC2BC09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x639D7E1AD69CD6A1ULL,
		0xCB10F2CD80AFB187ULL,
		0xB7C4CE2D4E3668D9ULL,
		0x198EE9C99DAAA2E6ULL,
		0x50FF576B07207DADULL,
		0x242C000DBB185E19ULL,
		0x8C07B8E089907680ULL,
		0x0B688C29DC3D1FA5ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA78A4C914D65C204ULL,
		0x1CE9A97FB4359037ULL,
		0xE78D1D2589A40C02ULL,
		0xEAF8353C6508EB16ULL,
		0x55AC2D5E44568551ULL,
		0x60B84082C3CE29C8ULL,
		0x3C54B3B4FD698B79ULL,
		0x15594849AA21767DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78972E8FE7CA8A7AULL,
		0x8734043C42236EC6ULL,
		0x35E8A66EF01C5969ULL,
		0xD2DFCDB6586196CEULL,
		0xC1BD1CA4FF326FE5ULL,
		0x460FD9EB9E017165ULL,
		0x288C9656CAAE3898ULL,
		0xB2EE9A5851327599ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF1D621EAAAF487EULL,
		0x9BDDAD43F616FEF1ULL,
		0xD265BB4B79B8556BULL,
		0x3827F88A3D697DD8ULL,
		0x941131FABB64EAB4ULL,
		0x26B799695DCF58ADULL,
		0x14D825E237C7B3E1ULL,
		0xA7B7D211FB1303E4ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF346CE141B57A042ULL,
		0xF592799905450946ULL,
		0x106B259698FFAEB0ULL,
		0x75712759DDB0B05BULL,
		0x89CA0CEFAAAB4900ULL,
		0x770D1242E1F94D50ULL,
		0x3D860B57D2E8009CULL,
		0x8C8E64B10BDE38FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C676898A5864DBEULL,
		0x3751D8F880C42E94ULL,
		0x442BB9D3792947E1ULL,
		0xCB127530D20ACA85ULL,
		0x11B4BE27ACE01A64ULL,
		0x736315303E8BA42DULL,
		0xF3BF3F47ADC00AB3ULL,
		0xBB0E59226400A657ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F21A68CBED1EDFCULL,
		0xC2C3A161858127D2ULL,
		0x54409C45E1D6E951ULL,
		0xBE6352690FBA7ADEULL,
		0x987EB2C8064B5364ULL,
		0x046E0772DF72E97DULL,
		0xCE3934107F280A2FULL,
		0x37803D936FDE9EAAULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C99C2F28F6A3D52ULL,
		0xF8538B5358F27090ULL,
		0x269FC31EA7ADAA12ULL,
		0x521C3E24DFB725F2ULL,
		0xAFF0EA2F04FEF789ULL,
		0x393BC6655C0B885BULL,
		0x41EF4499722A6526ULL,
		0xF1B1E3ED74D3AE16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC763B3F1E45DDDULL,
		0xBCEE39475822483BULL,
		0x34D66E4972244610ULL,
		0x7D600008770EFBFDULL,
		0x229A68F384DA26FAULL,
		0xFD20C8FAA35EB7ECULL,
		0xAABE8EAE226AFEC7ULL,
		0xDB14010ED4A774B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE25EA1417E8E608FULL,
		0x44BDB21400D038ABULL,
		0x1249AD57D589EC02ULL,
		0x2F7C3E2CA8B9DE0FULL,
		0x8D6A82DC8024D173ULL,
		0xC41B0E9FFF553FB7ULL,
		0xEB51CA3750409BE1ULL,
		0x2AA5E2E3A074DAA1ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79D02BF427B2550AULL,
		0x24A818749FEDCE38ULL,
		0x744BE958BDBA4896ULL,
		0x9D8505A350ACF4B8ULL,
		0x7D253D3C26C101AEULL,
		0x12B31FC368E22453ULL,
		0xBE266C6FF576F2A7ULL,
		0xB2A8A3A44BA2ADE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A86BA71F733B96ULL,
		0xB7D1CD1F727AE2CDULL,
		0xB3271BF449606AD3ULL,
		0xB9985DB67CB8284CULL,
		0x6FD9ECDDE3253B89ULL,
		0x67EC52A7A64FBCB4ULL,
		0x63423D2DACA570ACULL,
		0x3CB34E39BACFAAEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0178405338C16E9CULL,
		0x9379D56BED972CF5ULL,
		0xC76CF2ACF4DA2245ULL,
		0x241D58152C14DCF4ULL,
		0x12FCD1E1C5E43A27ULL,
		0x755F4D64CEAD98E7ULL,
		0xDD64514259D3820BULL,
		0x8E1BED9DF16D070CULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFBC7BB9CEC067DAULL,
		0xE1EC3B36E6B2E3DAULL,
		0x96E601AD956BAF9DULL,
		0xFF70BE43ABBCF02CULL,
		0xB8985B7621C80990ULL,
		0x848DE47B13A88DF0ULL,
		0x1EE44830F53F202AULL,
		0xEF2D142AE5D6D512ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16D38D7E8FFD53DEULL,
		0xA9E245E49DB69AE3ULL,
		0x92E48A810D19B364ULL,
		0xAAA7725205C6EB96ULL,
		0xFA15F28D5201F47FULL,
		0xEE5A9D9FDFC58E33ULL,
		0xCFF556FF3D2E8A56ULL,
		0xF036C7539DF480F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB96FF6C7413D3404ULL,
		0x480E7ED27B047939ULL,
		0x04028B2C98721CF9ULL,
		0x55D7CC11AE7A1BBAULL,
		0x428DA9FB73C9FDEFULL,
		0x6AD779E4CC6D03C3ULL,
		0xD1111ECFC811AA7CULL,
		0x1F1BD379782255E6ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC440A32454E8013EULL,
		0xBC62BCBCA4F3D328ULL,
		0x881EADA9FDF3A9B6ULL,
		0xF2884A0331A35114ULL,
		0x9B5DD9D278DA52D1ULL,
		0xF8F2384FCB7F07DFULL,
		0x9E768F8D83CCA486ULL,
		0xF71721DA49E65769ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A1D8AA2901C7796ULL,
		0x772838C64699CC61ULL,
		0x75ECCDEB1644997CULL,
		0x6A8279B7AA5F9AC0ULL,
		0x7CB479156783E652ULL,
		0x951FCDC32DD7527BULL,
		0x0FB4526BF63A5BC3ULL,
		0xCBE5A7BEEBE58BAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E5D2986C4F476A8ULL,
		0xCB4A847AE26A1F49ULL,
		0xFDF26042EBB730CAULL,
		0x980A33B49BFCCBD4ULL,
		0xE7E9A0C71F59B483ULL,
		0x6DEDF58CE6A855A4ULL,
		0x91C2DDE675F6FF45ULL,
		0x3CF28664A203DCC7ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17FA5B288A5F4B70ULL,
		0x7A7BFC9D4917A6A9ULL,
		0x295238C1BC189597ULL,
		0xB896AB7B5AFA081FULL,
		0xCC648A66246EB959ULL,
		0x1FC2D8F083F8F824ULL,
		0x49C684BB05601AECULL,
		0x662782EA042CD166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCC94CAAF3248A8EULL,
		0xD7C23EF4196EF707ULL,
		0x5AD73FBC1526A1BAULL,
		0x91FB4DBD733FE323ULL,
		0xE1B89D778DD08B9EULL,
		0x00E32D4BCF12F82FULL,
		0x74078640ED8399B5ULL,
		0xC752BDA42CD80CCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB331782797BC1FEULL,
		0xADB9C269507951AEULL,
		0x7385077DA93E342DULL,
		0x296DE6C629C5EB3CULL,
		0x2DDC1711A9BE32C7ULL,
		0x1F21F5BB4CEA000BULL,
		0x3DC102FBE8E38359ULL,
		0xA1753F4E28F4DDACULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF21862C76E74725ULL,
		0x7F4F631425AF7E71ULL,
		0x26E0887ABECBC417ULL,
		0x0B548BB85F666EF9ULL,
		0xC73CA2CD45CCD1C6ULL,
		0xCB08DA364FC9455FULL,
		0xFB11AD082936CE9EULL,
		0x365AA81C6D26485AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF3830C61B6FCC3ULL,
		0x92326C81299CEC93ULL,
		0x3BE8419E5F24C19AULL,
		0xABFB562A9DB78B5AULL,
		0xAABE18E51884E34AULL,
		0xC358894DCAE461D4ULL,
		0x2C80DE6851C371DDULL,
		0x404ED0350AE30531ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50D205201751BBE6ULL,
		0xED7D0F950C3392E2ULL,
		0x1D08C9E4E1EF058DULL,
		0xA0AFDD92C2D1E5A3ULL,
		0x6D82BA285D48328CULL,
		0x0850537B852D248BULL,
		0xD791736078F5BF43ULL,
		0x7614782967C54D6BULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2D28775A656992EULL,
		0x6D17DA11876157EAULL,
		0x1D8A7E5AEDFE1E92ULL,
		0xBC34EED633E6FBECULL,
		0x6BACF2788D5025EEULL,
		0x139C50B644067409ULL,
		0x77FB827E94A986ECULL,
		0x41C060882C3B8FA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CEE4C9ED2D16B55ULL,
		0xBF6290D0F480A87AULL,
		0x1C15BFEA5FAC7B07ULL,
		0x7CEC32DFB63E11B9ULL,
		0x3D04FFD7D2145284ULL,
		0xAAF6FD519C7B0709ULL,
		0x0A51ED41E0C08F72ULL,
		0x8DDCB68653E505C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE3CCBEB7487F27BULL,
		0xD2754AC173E1FF90ULL,
		0x019FC1B0B2526595ULL,
		0xC0D8DC0985D8EA55ULL,
		0x56A80DAF5F44776AULL,
		0xB96AADE7D87D7300ULL,
		0x7DAA6F3F7469099EULL,
		0xCC1CD60E7FDE8A65ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC801079880509428ULL,
		0x68BBB463F3759904ULL,
		0xE640C6C3BA9A4EA9ULL,
		0x73FC104D34301AD4ULL,
		0x9D727BB428F3810AULL,
		0x727E5E882F78E9DCULL,
		0x88473D5EF08E50CEULL,
		0x1E9F26CAD0950BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99B9990C0BAF712CULL,
		0x7F623E19E05934FCULL,
		0x3F88F3CF9CB33AC1ULL,
		0x61C6AAF0106A1367ULL,
		0x2FF3061341B2FE22ULL,
		0x74358208C2BF27A1ULL,
		0x4847A3159619AE57ULL,
		0x2B940B8B3B47DC49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51B89E948BFFE504ULL,
		0x17D98A7A132CADF8ULL,
		0xD9C8350C26297468ULL,
		0x123ABABD245A09B3ULL,
		0xB2817DA769417F28ULL,
		0x064BDC80EDC7CE7DULL,
		0xC0009E4B6697FE99ULL,
		0x350B2D41EBD2D789ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5774E28FDF3630D3ULL,
		0x067F6F5DC69276FEULL,
		0x15AFDF59D972603DULL,
		0x3953AE954F8A5A67ULL,
		0x6F7AA8337645D168ULL,
		0x164409A1272441F7ULL,
		0xCD00A8039E8209C0ULL,
		0x00046C59B6111CF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FF9009DF3CCCA63ULL,
		0xE0ADD3212174F478ULL,
		0x82A314EA4C7247B9ULL,
		0xA2F95EE1201BEB38ULL,
		0xC0CA4A360A7ADBCDULL,
		0xB20722495B681F39ULL,
		0x9E328CD9DC5641EEULL,
		0xA84B2643E32E1787ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088DE2122CFAFAB0ULL,
		0xE6D2BC7CE7E68286ULL,
		0x970CCBB395002784ULL,
		0x9BAAF0746F91B15FULL,
		0xAFB0E2057C3F0AA5ULL,
		0xA4432BE87C4C5ECEULL,
		0x533224DA42D4482EULL,
		0xA84F4A1A553F0B71ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x104A4104091905DBULL,
		0x675930A16E61331CULL,
		0xCC56B701D3514F2EULL,
		0x821BFA6264425DA2ULL,
		0x3D935D0854BC3411ULL,
		0x323854BCF0F36307ULL,
		0x9CCE54728253C81CULL,
		0xA6E6774092494211ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47236ED1C33B8294ULL,
		0x952632808A227D69ULL,
		0xA4663D188EF858F4ULL,
		0x26183DAC68ADB336ULL,
		0xD210AA864B14F01BULL,
		0xC3E046501AB2A8E9ULL,
		0x77B1ACEA47B7326BULL,
		0x51AC76F95879E415ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57692FD5CA22874FULL,
		0xF27F0221E4434E75ULL,
		0x68308A195DA917DAULL,
		0xA403C7CE0CEFEE94ULL,
		0xEF83F78E1FA8C40AULL,
		0xF1D812ECEA41CBEEULL,
		0xEB7FF898C5E4FA77ULL,
		0xF74A01B9CA30A604ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80ABDAD2EC939B7FULL,
		0x65F52BFB58C03636ULL,
		0x9A70EAF96DF77B67ULL,
		0x07B8EBCA11160248ULL,
		0xB5754A80F6CF5567ULL,
		0xD0394D20292C51F8ULL,
		0x0B45D71775C19EA7ULL,
		0x2152A2DB9D9BF2F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA3BB3826C03ABC2ULL,
		0x642ADC08C768B4ACULL,
		0xCEDF1776177DC5E7ULL,
		0x0CD0462FE0DFC711ULL,
		0xCE489D972A6EB54DULL,
		0x6EB745F441455269ULL,
		0xE43068DD668DABFAULL,
		0x8F9D7B8511F631D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A906950809030BDULL,
		0x01DFF7F39FA8829AULL,
		0x54AFFD8F7A8ABE80ULL,
		0x0B68ADE5F1C9C559ULL,
		0x7B3DD717DCA1E02AULL,
		0xBE8E08D468690391ULL,
		0xEF75BFCA134C355DULL,
		0xAECFD95E8C6DC32DULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A534588E17BA537ULL,
		0x44D8B3B0F6BB9FE6ULL,
		0xD91D2C284156A903ULL,
		0x4261FE7CC1408751ULL,
		0xF3799012054D0E08ULL,
		0xCB4B107614D5B642ULL,
		0xF94EE47F89B6DE3BULL,
		0xB69182770865F924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16846BBEDFE9E314ULL,
		0xA6BC3275BF063494ULL,
		0x7DC9BD3152CF82DEULL,
		0x818DEC9849703284ULL,
		0x33A35CF0385565EBULL,
		0x799D58EEBEF37247ULL,
		0xFC2D137A6CD53B9CULL,
		0xD5E5706867AFCF24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CD72E363E924623ULL,
		0xE26481C549BDAB72ULL,
		0xA4D4911913992BDDULL,
		0xC3EC12E48830B5D5ULL,
		0xC0DACCE23D186BE3ULL,
		0xB2D64898AA26C405ULL,
		0x0563F705E563E5A7ULL,
		0x6374F21F6FCA3600ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72A45910849A7E8EULL,
		0xBB7F529B48872433ULL,
		0xE4E8F138E5938863ULL,
		0xA1A7652AE1DA9E30ULL,
		0xE03F85ED26A6C221ULL,
		0x81E75D3BDDA56A07ULL,
		0x352246DD0C0BBC83ULL,
		0x7AA9AB7308B6C20CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE97CE33DBBEA67FULL,
		0x9B9949CE5103001AULL,
		0xA7812DBC7331C449ULL,
		0x3102A0CEE6506313ULL,
		0x3078203D4E62EC65ULL,
		0xE6E57D504036F9D6ULL,
		0xCD8E01F46CBA3996ULL,
		0x3E9218D85C660080ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C3397235F24D8F1ULL,
		0x20E61B5519842429ULL,
		0x4369DC8496A24C2AULL,
		0x90A5C5E4078AFD23ULL,
		0xD047A5D068C42E44ULL,
		0x6702206B9D9393D1ULL,
		0xF8AC472960B18515ULL,
		0x443BB3AB54D0C28CULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B39EFFB00A06B76ULL,
		0xDA37D00C734213B6ULL,
		0xD7AB89C76E863089ULL,
		0x16D0EC2818770E05ULL,
		0xC6D3D80C9F2FB64FULL,
		0x40ABE36A110F13B7ULL,
		0x569C7FA775CD7118ULL,
		0x9E5F33C3E10990C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAF97BD4133D5509ULL,
		0x84C264903E7F648DULL,
		0x95E575BFB6E7561BULL,
		0x34CBF1A32EDD83B3ULL,
		0xC722B245191EA268ULL,
		0x6E39FAF0F673E6B8ULL,
		0xC4981C6C33E11037ULL,
		0x84333701C88C8A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C0942F139D3E7FULL,
		0x5EF5B49C4D3D773BULL,
		0x424EFC78D8616692ULL,
		0x221B1D8B36AA8DB6ULL,
		0x01F16A4986311427ULL,
		0x2E92199AE77CF50FULL,
		0x920463CB462C612FULL,
		0x1A6C04C229851ADCULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2529596E1BEB837BULL,
		0x5773D6CA8F7AC135ULL,
		0x0EFA6B8D6570ADE5ULL,
		0x1E06ED6DA89C2D97ULL,
		0x946E4412AE82FAD1ULL,
		0xCC3BCAB9A4E32809ULL,
		0x0ED245B46EF8FFCAULL,
		0xC27847FD1FD9CC02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A4CAA976261799AULL,
		0x47D0688DBF98156DULL,
		0x337AFE6294BCE5FCULL,
		0x58738B3CF600AB77ULL,
		0x8D40DB2A5B3B9211ULL,
		0xF709E051A6420589ULL,
		0x762A980FE6E47E16ULL,
		0xF27593A8D8034523ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF65F3F9798AFAE1ULL,
		0x10A3BE4730E2D458ULL,
		0x3D8095EFF1CC4819ULL,
		0x467566515E9C86E0ULL,
		0x192E9F38F5B968C0ULL,
		0x3B322AE802A12D80ULL,
		0x78F8DDBB881C81DCULL,
		0x300DD455C7DA8921ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A7EEF7EB2652EEEULL,
		0x0F1E2FD32AEC86DFULL,
		0x87053CE4C02A2869ULL,
		0x8033B9422151EE9FULL,
		0x55234C92783A229EULL,
		0x18AD985D3D070245ULL,
		0xBC8338585E5259AAULL,
		0xB44312B738C6877AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A82C4709B0F524ULL,
		0x5A884303E42B8038ULL,
		0x553326DFA966318FULL,
		0x3C4B7415C5B44FF4ULL,
		0x9D0B3EF1E8A1922BULL,
		0xFF841AF0CA09F380ULL,
		0x7AFFFA7F05EC6CD1ULL,
		0x9F1FA2A79EB1F1D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AD6C339BBD5DBCAULL,
		0x55966CD0CEC706E7ULL,
		0xD2361A3B694C19E6ULL,
		0xBC78CD57E4E5A16BULL,
		0xC8287263909BB0B5ULL,
		0xE72982ADF70EF1C5ULL,
		0xC67CC2275BBE357BULL,
		0x2B5CB010A67776AEULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7C267569E4C708AULL,
		0xD9B83267695254EFULL,
		0xFBE172ACD3540344ULL,
		0xE4F571760F1072DBULL,
		0xA6E82222436C8483ULL,
		0xF7112B232F55F242ULL,
		0x87837744BFE96A61ULL,
		0xA2DBA80F34E41213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00949F17D2C27DFCULL,
		0x5D937B1376B3B9C0ULL,
		0x95E4605749AB5DCFULL,
		0xD008984F111B409EULL,
		0x07B5EC29F1AC1FE7ULL,
		0x8B7C517A38393ADFULL,
		0x49A482AC18BCAD9AULL,
		0x73006774DA9862A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD756F8414C8E0D76ULL,
		0x842B49741FE1ED2FULL,
		0x6E0512FB9AFF5E8BULL,
		0x34FDE9391E0B3245ULL,
		0xA15DCE0BB2C09B64ULL,
		0x7C6D7A59176CC89DULL,
		0xCE27F5E8A755C7FBULL,
		0xD1DBCF7BEE7C70B1ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42F56F988A4607A4ULL,
		0x1F20C45DCBC63FFBULL,
		0x04D5CD73E3C4F65BULL,
		0xE194880AC4CD4FF1ULL,
		0x64F7764670C7C63AULL,
		0x80D91FA2175B7F43ULL,
		0x095EDBB13FC71D62ULL,
		0xBF5E31EEC3B330D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD270A65B10DB4AC0ULL,
		0xAF8BB4D58682B804ULL,
		0x63D9F1AAF01BD3A0ULL,
		0x50605A4BC8BB4524ULL,
		0x0E7149AE68160F9EULL,
		0x8AA26FAFFAAF7EE6ULL,
		0x61FD3C341860FE0DULL,
		0x38F885A3BACB66EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9085C9C39A9D4D64ULL,
		0xB0AB70884D4487FFULL,
		0x670C3CD913DF25FBULL,
		0xB1F4D2410C760AD5ULL,
		0x6A863FE818D1C9A4ULL,
		0x0A7B700DEDF401A5ULL,
		0x68A3E78527A7E36FULL,
		0x87A6B44D7978563AULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CAB6961FA140AC8ULL,
		0xED2CCD15B92B3890ULL,
		0x54D64296DD807CF6ULL,
		0xD5D8593DFF82D4EFULL,
		0x467914AD943E6C8CULL,
		0x22C42E33C243F709ULL,
		0x5EF1C161AB08F574ULL,
		0x7147E3C5EB638E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6607963EEDE35C3FULL,
		0x9055357C45E58194ULL,
		0x0F34E38A71008399ULL,
		0xD4E5AF48B9885CB3ULL,
		0xAC4A2D94F58B8D2FULL,
		0x35F7A05932B6D29FULL,
		0xE2D678CBACAD74A8ULL,
		0xB8E3293EE0A9ECA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAACFF5F17F756F7ULL,
		0x7D79F869FCCEB904ULL,
		0x5BE2A11CAC80FF6FULL,
		0x013DF675460A885CULL,
		0xEA33393961B5E1A3ULL,
		0x17338E6AF0F52596ULL,
		0xBC27B9AA07A581DCULL,
		0xC9A4CAFB0BCA6227ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65E6C1A482ACEB5AULL,
		0x64E377CC95EB16B4ULL,
		0x786976CB7EA84F76ULL,
		0xF87117FC48CCE5C4ULL,
		0xFAC3D9B811CF549DULL,
		0xAAB1744C0C3B67F0ULL,
		0x8AD255B157CF948CULL,
		0x759B58EA3BD81004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF6EF5AC4269C8E5ULL,
		0x366C00B7F07122A6ULL,
		0x04926CF850D1D9F7ULL,
		0xAC83A57ED46292E8ULL,
		0xA6EBC8D1B0B2C910ULL,
		0x9DD48D5EB97D4E04ULL,
		0x3820A38B4B67AC0BULL,
		0xEF6940B087B01FCCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA883408C0C523BFULL,
		0x528F777B659A3412ULL,
		0x7CFB1A332E799681ULL,
		0x54F2B2829CAE772CULL,
		0x5C281169A17D9D8DULL,
		0x3765F912B54629F4ULL,
		0xB2F2F63A1CA83887ULL,
		0x9AF2185ABC680FC8ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23B91CAE9FAA6AB5ULL,
		0x421B879D42F7C4B6ULL,
		0x123075751B587614ULL,
		0xC75A68185D81AA49ULL,
		0x42B9EEA2A8FC4631ULL,
		0xCDB7EC877C9334A8ULL,
		0xA72E2E39E2AB761BULL,
		0x2BF771655B41AEB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CA51B8F804C30D3ULL,
		0x90D3EF47674E50A8ULL,
		0x1F7518465FB3656AULL,
		0xF7C0C7DD25EF3873ULL,
		0xF0E1468090FD0DCAULL,
		0xE0F45226D1413CB6ULL,
		0x83D7319D89472CE6ULL,
		0xAE92B9CE6B9928D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F1C07211FE65A66ULL,
		0xD2C868DA25B9941EULL,
		0x0D456D3344EB137EULL,
		0x309AAFC5786E923AULL,
		0xB258A82238014BFBULL,
		0x2D43BEA1ADD2081EULL,
		0x24F91FA46BEC5AFDULL,
		0x8565C8AB30D88663ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8C014AA91F572B1ULL,
		0x6521A04CB21C0776ULL,
		0x1366A503E8B8499DULL,
		0xF9EA5B63D7046E76ULL,
		0x884286F35276EFFBULL,
		0xE07CD0A500EF9A79ULL,
		0xA539DF117AFDE541ULL,
		0xFA5F3D1F5A78FFAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E86C7C42596B3DULL,
		0x2317BD64489F15A2ULL,
		0x9C83B543602D524CULL,
		0xE82882A8E5BA9051ULL,
		0xE1257BFADD2AAB5EULL,
		0x8B3F51E2E609120EULL,
		0xA8DD9C94F300A33EULL,
		0x2A1ADD794A22D5E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC12878D6D3AC198CULL,
		0x46361D28FA8312D4ULL,
		0x8FE5104088951BD1ULL,
		0x11C2D9CB32BEFE27ULL,
		0x6967FD098F5C44A5ULL,
		0x6B438147E6E68877ULL,
		0x0DE4438589FD467FULL,
		0xD045E066105A2A48ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D0357248F0E87EAULL,
		0xBE89FD44A6B4011FULL,
		0x3ED4EF628E22B175ULL,
		0xE87FCFC3AF246229ULL,
		0x16769A7E15AA2B02ULL,
		0x788FD0346CA6F123ULL,
		0x2562C291A51657D7ULL,
		0x9EB8B7DBABD649E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23007981B611ABAFULL,
		0x78911289CAEB2DCFULL,
		0xFCFAA0FBF57C3F65ULL,
		0x08F8265B6DF47DCCULL,
		0xA31C59974A296A92ULL,
		0x3672DAE518EE42C5ULL,
		0x33F97E3DCC967A9EULL,
		0x6ADE1A9581D0AEAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E032EA5391F2C45ULL,
		0xC618EFCD6C5F2CD0ULL,
		0xC22E4F997B5E8E10ULL,
		0xE087E998C2D01FE5ULL,
		0xB56AC3E95F834190ULL,
		0x4EFD0AD17448B3E6ULL,
		0x169BBCAC69802D49ULL,
		0xF466AD4E2A06E74FULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE31879EBFC23462ULL,
		0x1C6507360F82D506ULL,
		0xEB8899B2BE303162ULL,
		0x4B53B61CACABAE21ULL,
		0x3E2093905DAF6423ULL,
		0xD167772EA0F9B537ULL,
		0x6BDA4E0A7CC488A3ULL,
		0x4E3DBB272992A7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A61278D690E8345ULL,
		0x6D5FDE5AD1066539ULL,
		0xDC6C9467E2076EF0ULL,
		0x74E3CF75EF354095ULL,
		0x7436D471BE369E95ULL,
		0xEABCACB078539DD9ULL,
		0x1A99B64869868C40ULL,
		0x18C8122D949DE3F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD450A013D6CCB727ULL,
		0x713AD96CDE84B03FULL,
		0x37E40DD55C375F92ULL,
		0x3FB07969439EEEB4ULL,
		0x4A1647E1E399FAB6ULL,
		0x3BDBDB9ED8AA28EEULL,
		0x7143F842154204E3ULL,
		0x56F5A90ABD0F4413ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A05BE626F71859CULL,
		0xD1115FC8A962156EULL,
		0x91DAAF8AE893648CULL,
		0x1DE1706EA02F0FBFULL,
		0x33019A7E63A2372BULL,
		0x148B1B036AAC95F4ULL,
		0x6A0A1EE9B04EFE88ULL,
		0x6F8C54773ADE6B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB8D5D82440A64DULL,
		0xF62DCFEFD002859AULL,
		0x85ABCC5E2D58A9F0ULL,
		0xBB7F792A6B856D69ULL,
		0x82F120E9E52FD916ULL,
		0x33516FE676E31A91ULL,
		0xC36FE896B2770B00ULL,
		0x18E570B27A5761D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1BD6BBA4B3123D1ULL,
		0x273C9027796090F4ULL,
		0x147163D4C5CBCD7CULL,
		0xA69E0944CBAA62D6ULL,
		0xB1F0BA97868DEE3DULL,
		0x27DA74E51C4F8F65ULL,
		0xA965F67F0239F588ULL,
		0x776924C540890ACCULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5397C789EE90F197ULL,
		0x767DA372E162B683ULL,
		0x3B0FE3C228443AE8ULL,
		0xDD35A3E715E9AD07ULL,
		0xB6F1964545494F54ULL,
		0xBDF148201A3272CAULL,
		0xDC0DE657EB090555ULL,
		0x48784C7CBD8DB53BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C10D188C81AEB7BULL,
		0x8122D9F03C794520ULL,
		0x75BB93492ACB20D8ULL,
		0xB2DC9CB3A0130D40ULL,
		0xE31338910C2B468DULL,
		0xB719E8A178B84F7EULL,
		0x8FECC25588B25E23ULL,
		0xB8F7860E0633A8D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F871601268A1AECULL,
		0xF75F7A82DD1BF3A3ULL,
		0x4EB4708B028F1A30ULL,
		0x6FE93F54B5FAA047ULL,
		0x55E2AED4496209D9ULL,
		0x0AE8A081628A3DB4ULL,
		0x53E1240263BB5B76ULL,
		0xF08FCA72BBBE1DEFULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x338DC64798120AE8ULL,
		0x2851CE9359F00EFEULL,
		0x78A4EB354030D82FULL,
		0xF435ABD8C039E441ULL,
		0x1E2C45B71131E41FULL,
		0x6D5095D2D18B0F74ULL,
		0x69526F7F08FC479DULL,
		0xB65D2EBFFFCCA2E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AF16BABA97976DEULL,
		0x3E72136DC7759237ULL,
		0xA9C29E6F17BF01B8ULL,
		0x75475889B773DF60ULL,
		0xF3393FF6EC1695E4ULL,
		0xB3D933B510718E89ULL,
		0x5F836440E78CF3A6ULL,
		0xEF496D238C9DB5B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA97CADEC316B7C36ULL,
		0x1623DDFE9E859CC9ULL,
		0xD166755A578FD997ULL,
		0x8172F351774A3B21ULL,
		0xED157A41FD2771FBULL,
		0xDE89A667C1FA81FDULL,
		0x36D10B3FEF70B43BULL,
		0x5914439C73511751ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x857974C26909E5B9ULL,
		0x93C76B510EE7ED3AULL,
		0xF35F9E22A2566B83ULL,
		0x11E5C75547E70AABULL,
		0x1817712B6B2AB404ULL,
		0xE46111F7DF73C0D0ULL,
		0x75BCFBAFA3A49A2EULL,
		0xEBFD3241F63CBB52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7D4FEBD1777F84FULL,
		0xE47D3AAF44B5381DULL,
		0x19A7FFD97C132772ULL,
		0x798796DBF265E283ULL,
		0xDDBDFAB135DEC713ULL,
		0xE2A9CB26E8E4CA0CULL,
		0x680DD6DCBD13689DULL,
		0xAFA57A168D7FBE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42AD8A7F7E7E1DF6ULL,
		0x77BA51FE4A52D527ULL,
		0xEAF861FBDE454CF1ULL,
		0x6862518EB582E828ULL,
		0xC5AA8B9A5EF47317ULL,
		0x06C8DAD137970ADCULL,
		0x1DB12D731EB7F2B3ULL,
		0x445848577B430573ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD97834E927BC687ULL,
		0x99E286EF1F21F5EEULL,
		0x99E4B1970F51AFEFULL,
		0x3CFCB1ACB7101A2FULL,
		0x53DA13707E90827CULL,
		0x903E2D9D7D53CD29ULL,
		0xE86C33B660EC9C32ULL,
		0x4B5C2FA713588B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAE4BF86F35E78CAULL,
		0x2700665F44332EB6ULL,
		0x2E5A02CA46F9EDFBULL,
		0xA43E3E57AD994AB5ULL,
		0x019ABF4D9FDB05A3ULL,
		0x7E16829C9AF56BCFULL,
		0x0BC24FB40ECA09E1ULL,
		0xD171660F47FA51EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17733CC86125BE4DULL,
		0xBEE2E0B05B12DB58ULL,
		0xB7BEB35D49A84214ULL,
		0x98C28FFB1A89509AULL,
		0x5240AC3DE14B87DFULL,
		0xEE28AF01E7A6A6E6ULL,
		0xE3AE7C026E2695D3ULL,
		0x9A2D49A854A2DAA2ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x181E639437CA609DULL,
		0x2828C3065E219BD3ULL,
		0x7BDD878B6CA07D0CULL,
		0x537A1785A2CDE8C0ULL,
		0xA7CE0671AE215197ULL,
		0x711F172594A7C3A1ULL,
		0x4DFA20B107C70711ULL,
		0xAA3C65B9A7A2277FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5609E82A5B123D9ULL,
		0xB0A9CBC52333207AULL,
		0xBC66C7631B84FD9BULL,
		0xA42B7F139CE982CCULL,
		0xE78BEB036EE2B79AULL,
		0x2013317E24200D33ULL,
		0x30FFE6C859F7FC4EULL,
		0xD6D841A52E10887AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD7EFD16927B4344ULL,
		0x988108C37D12BBA9ULL,
		0xC7BB40E877248097ULL,
		0xF75168963E246A0CULL,
		0x4045ED72C0C3E60DULL,
		0x510C265BB087CE92ULL,
		0x7D05C6795E30FB5FULL,
		0x7CE4241C89B2AF05ULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE69E7D0B38D02438ULL,
		0xC8D710F22A3B28ADULL,
		0x911644B0F069D761ULL,
		0x7347FD1DFD417932ULL,
		0x768AE0FCE9003A1BULL,
		0x164A4EFFE58E06C7ULL,
		0xBB3C351D2004E8B1ULL,
		0x8854D63AB66C0F14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x516778F9B66491EBULL,
		0x7D428F7DE608E1E9ULL,
		0x0B9E685F99BCBB8DULL,
		0xA760598D25F3D74AULL,
		0x162ADAA99D54B606ULL,
		0xD4853ADBD9F75C62ULL,
		0x2DD9CD2C4B2ABFA0ULL,
		0xDD3B72983C2DCF74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7F905F28EB4B5D3ULL,
		0xB5959F8FCC33C944ULL,
		0x9A882CEF69D56CECULL,
		0xD427A490D8B2AE78ULL,
		0x60A03A5574548C1DULL,
		0xC2CF74243C795AA5ULL,
		0x96E5F8316B2E5711ULL,
		0x556FA4A28A41C060ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2781B7DE8A948084ULL,
		0x18A76A1FF4E85048ULL,
		0xCEE628E3229145A6ULL,
		0xBF416C4EA0166C7DULL,
		0x01A0D5E1999F0197ULL,
		0xA5774BC3A31FFCD5ULL,
		0x15A270908F011F06ULL,
		0xD4A1A0679D7DFFB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5359EEF33364662EULL,
		0xC2E7F3EE72A8FC1CULL,
		0xCC911554DABEAD18ULL,
		0x1F89A080DA341288ULL,
		0x829B7550C7667A9CULL,
		0x603FB29BD9568F81ULL,
		0x1F879DD10148B5C4ULL,
		0x32AB92363D09E2DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74D8592DB9F0E6AAULL,
		0xDA4099F18640AC54ULL,
		0x02773DB7F82FE8BEULL,
		0xA0C8CCCE7A227EF5ULL,
		0x833BA0B15EF97B0BULL,
		0xC548F9587A497354ULL,
		0x0A25ED418E49AAC2ULL,
		0xE60A3251A0741D6AULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F1AE629AF76BB92ULL,
		0x6E84E9D9D3AC68BDULL,
		0xC5319314CF5A7794ULL,
		0x79EA0C3DB627E4A3ULL,
		0x6CB3463504F607A4ULL,
		0x123FB29C0AE8F96DULL,
		0xAE3AC50D8FD38486ULL,
		0xE399B217893513AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBEFEA90A6B67123ULL,
		0x2E445A31ACFB865CULL,
		0xA7CCE3C17D763E87ULL,
		0x6A5A4C774ADA2F89ULL,
		0xEBB63C1A94CBE680ULL,
		0x49180C7D22311128ULL,
		0x29E85BE0A8D8CA2AULL,
		0x12D274911D24884DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA4F50CB909C0CAB1ULL,
		0x40C0B3E87F57EEE1ULL,
		0x62FD70D5B22C4913ULL,
		0x13B0404AFCFDCB2AULL,
		0x87057A2F903DE124ULL,
		0x5B27BEE128D9E845ULL,
		0x87D29EED270B4EACULL,
		0xF14BC68694119BE2ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75DA45278ACA3D29ULL,
		0x011C2CB3C83ED0ECULL,
		0x1CBDDAAFE21E6BC0ULL,
		0x3AD9680B69AA24E5ULL,
		0x5EB36771AAB4DF37ULL,
		0xC6AA4E5EF05C07FDULL,
		0x4634AF4F20BDD97FULL,
		0x591E042C124FF51AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57363420EDD7EF4CULL,
		0xAA5AF543858E5309ULL,
		0xDE902EDF2CD58BB2ULL,
		0x84C5E4D7B2F27C3BULL,
		0x559E0B03097DE684ULL,
		0xA7C83D60841A008CULL,
		0x9E0DE0A5CE5FC6E6ULL,
		0xC47BDE13B4AD7119ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22EC7107671DD265ULL,
		0xAB46D9F04DB083E5ULL,
		0xC22DF470CECBE072ULL,
		0xBE1C8CDCDB5858DEULL,
		0x0B2D6C72A3C939B3ULL,
		0x6162733E74460771ULL,
		0xD8394FEAEEE21F99ULL,
		0x9D65DA3FA6E28403ULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1A462310C8E3581ULL,
		0x2A0381D2D438F64AULL,
		0xAFAA93D245411092ULL,
		0xD60EA13A8E54EAA5ULL,
		0x30CFF064F381FEA8ULL,
		0x50BE05BFB3A89086ULL,
		0xF12DCF5F558B61CEULL,
		0xE7C337CCDFF37080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B61C7374411CB74ULL,
		0xFCB8F64D5A6AD867ULL,
		0x7FDA002A2045208BULL,
		0x5FB815D0341846D8ULL,
		0xB6FAE16F9BD00729ULL,
		0x5E20F773C329BF82ULL,
		0xB7EA3CE3E870207EULL,
		0x4EFB7FC3556330C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AC5A506489FFEF5ULL,
		0xD6BB779F8E522E2DULL,
		0xD07093F865043019ULL,
		0x89B6B4EABA4CAC7DULL,
		0x8635110B6851F981ULL,
		0x0E9EF2CC70812F04ULL,
		0x46C7F3BCBDFB41B0ULL,
		0xA938480F8A904047ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC13E32A684AF9BBULL,
		0x54A05A13E0D90B59ULL,
		0x4E5A0FF55BEA7BD8ULL,
		0x727B44645493BCB9ULL,
		0x60648FF39C10A5BAULL,
		0x3B931820D6B528BFULL,
		0x29372F0CF925FBAFULL,
		0x4DCED8B636199EA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7307B8C753641DA7ULL,
		0x0947CC8D5E0FDDFEULL,
		0x846196A4680B2017ULL,
		0x87F456DDA2AF0698ULL,
		0xC664E9412787B438ULL,
		0x4FCC02E203D7851EULL,
		0x31CD0614FC65D729ULL,
		0xCF384C3B9668A1D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F145BED3B2EE41CULL,
		0x5DE7969EBED6D6A7ULL,
		0xCA3B995133E15BCFULL,
		0xF58F12B9F63CBA21ULL,
		0xA60066B2BB971182ULL,
		0x745F1AC2D562ADA1ULL,
		0x18FA291805402C86ULL,
		0x82F6948DA0713F72ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B0A95E513799FCAULL,
		0x0C3355B86E7FC237ULL,
		0xA19FE7198A2AF947ULL,
		0x10D8C79D461FBFEDULL,
		0x2CFD45649C04399FULL,
		0xE2E78F75D3629258ULL,
		0x29FAC7F4181D70A7ULL,
		0x7F7966E463B84356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x738354723E1C3FD3ULL,
		0x3D869F48C7B95A52ULL,
		0x2BA078F6EB716AA5ULL,
		0x5E92F452BA8D7DF2ULL,
		0x0CFB1EC25544E31FULL,
		0xCE72C77E75E764E3ULL,
		0xFAB2430327781B05ULL,
		0x70EAB9BB54BDDA40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0889C1972D65A019ULL,
		0x31B5CAF0A9C69865ULL,
		0x8A3F9FEF615B93E2ULL,
		0x4E4A33CFFC92C21FULL,
		0x20065BA6C940DA80ULL,
		0x2C95480BA685F6BBULL,
		0xD34884F73F656BA2ULL,
		0x0F93DF5F37059916ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8C2901CE9195D5BULL,
		0xE91E8E18E0E2EE70ULL,
		0x33B6D5CBF74DD8D1ULL,
		0xB4868857913EC028ULL,
		0xE4003B4D1770CCB0ULL,
		0xD288B8FA43DDB678ULL,
		0xCEBB48ACD0246BB2ULL,
		0x618006FFAA31616FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B924ACFEFABB7DDULL,
		0x3BC3F2C9E8B7A0ADULL,
		0x652AD566B06BF6E2ULL,
		0xCFC61F5B6F7B585FULL,
		0x4DD9BF855AFE925EULL,
		0x699F896FBB726D48ULL,
		0x037C70A71AD8F2F2ULL,
		0xD91A594FAA3E6AF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD350DAD306B2EA86ULL,
		0xD2DD7CD108554EDDULL,
		0x569C00AD47262E33ULL,
		0x7B40970CFE459877ULL,
		0xA9D984C84D8E5EEEULL,
		0xBB173195F8AFDB30ULL,
		0xCDC7380BCAFC9940ULL,
		0xB89A5FB0000F0B99ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2841CE10958ABC6EULL,
		0xF48551E5ED098E60ULL,
		0xEE187BDCCFE5196DULL,
		0xE77A48F3D2747C9AULL,
		0xD12CC6E31E3A3E17ULL,
		0x952438F15B11CAC8ULL,
		0x16533B8202893DDDULL,
		0x9ADEF680B3585902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2791C103ACE0265ULL,
		0xFD8A9DB2CDE8F906ULL,
		0xD90C25877E534599ULL,
		0x8CB8296E6772E332ULL,
		0xE15B46E5E6DF790AULL,
		0x567CE3A507F331EEULL,
		0x375B52B2AD7B246AULL,
		0x928C958347C4ADEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A38D200AF44BE0BULL,
		0x090FCC5720E17766ULL,
		0x37145E5BB1B65CF4ULL,
		0x6BC2619DB5069FA8ULL,
		0x30778006F8E5471DULL,
		0xC358DB545CE2FB26ULL,
		0x21086930AFF219B7ULL,
		0x08526303F49CF4E8ULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DD0847E76480210ULL,
		0x3E4C29FDDC9EE62DULL,
		0xD90945ECFBF49CFCULL,
		0x2ABE71730CB5F6B3ULL,
		0xAAD56772F3AC16C6ULL,
		0x5B042EF8D6ED8F60ULL,
		0xFEA50627377E938EULL,
		0xB8C1DA2D87D972D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAEE18CF7E6495AULL,
		0x7B724EB3DBFFC60AULL,
		0x6E01003651C3B4A7ULL,
		0x62530EC94B9DCB69ULL,
		0x4820DBF1A434C870ULL,
		0xD8B78BCE254BC8C6ULL,
		0xA0350192B9428297ULL,
		0xA5C6F10D9FD2354AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x177E65F281AE4B4AULL,
		0x453E674E07612027ULL,
		0xB70845DAAA37285BULL,
		0x48ED7FBA47283DDAULL,
		0xE2F5BC835798DEB6ULL,
		0x83B3A536F3A647A6ULL,
		0x5E9007B58E3C1119ULL,
		0x1D072B20180B479AULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFD23DC415C1FB39ULL,
		0x9565774809CA3E67ULL,
		0x9CD6C81B5B06859DULL,
		0x084798EC8C488EF9ULL,
		0x34E65B0CC474A888ULL,
		0x6AF065BDFF7A9DE7ULL,
		0x0D94AD97DD4F4273ULL,
		0x326647AF9C030941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43F87D86AD20A247ULL,
		0xB1FF8D5F7A3A442EULL,
		0x76ECDA837C591A96ULL,
		0xE1159CF1BB2BA7D3ULL,
		0x6E6F96BD66E69F3AULL,
		0xFFDB8E1B15224D3AULL,
		0xC6192996AAF82F7CULL,
		0x11090426BC5FDA41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC2A4042B8E1597EULL,
		0x249AFA1773F07A49ULL,
		0xEA3A1298275F9F0BULL,
		0xE952041D3763292AULL,
		0x5A89CDB1A29237B2ULL,
		0x952BEBA6EA58D0DDULL,
		0xCB8D840177B76D0FULL,
		0x236F4389205CD300ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x274B976295AAD4CFULL,
		0xA6DB8BF72C707681ULL,
		0xC81AC81D898A5882ULL,
		0x52EC8B3A0545FED2ULL,
		0xC76B0C2CFA4C6BB2ULL,
		0x7456ED22D38FA5C5ULL,
		0x6D419C091176FED2ULL,
		0x6023C3B96C6E3CB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54DF6A92A2A0B1C7ULL,
		0xDC85B96F0C590890ULL,
		0xA7D2BBF98DC94A7FULL,
		0xD485C7C63A0A480FULL,
		0x6526F25B9C2B2FE7ULL,
		0x81B51A79B318EC33ULL,
		0x47C13E7918D1FF41ULL,
		0x4E97375BA3DE683FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7394FDF0370A6508ULL,
		0x7A5E329820297E11ULL,
		0x6FC873E4044312FDULL,
		0x86694CFC3F4FB6DDULL,
		0xA24DFE7766674455ULL,
		0xF5E3F75B609749F6ULL,
		0x2A80A27009A70193ULL,
		0x2EB4F4E2CFB0548BULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3162EE9AAF5A60DULL,
		0xBE2F14F69E0F11A1ULL,
		0xB588F45C3FE5C975ULL,
		0x1A7706FA40CD747AULL,
		0xC60187E2A8C05AFBULL,
		0xE13A07A4C6E67EBFULL,
		0x6695A311537FFFDDULL,
		0x7DAD668DE1A3F374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC38E247BA9D600F4ULL,
		0xD4070A8895AD4779ULL,
		0x953D983EA6EF8815ULL,
		0xF24CEF22AD7607E5ULL,
		0xBC767AA365C03189ULL,
		0xBCB9BDBEC2829BFBULL,
		0xEE858988AE2CE42DULL,
		0x569625DFF5C8D037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70980A920323A6F9ULL,
		0x6A281E7E0BA256D8ULL,
		0x20B56C62990A4160ULL,
		0xE83BE9D8EDBB739FULL,
		0x7A77FD41CD006B72ULL,
		0x5D83BA1A0464E544ULL,
		0x88102A99FD531BF0ULL,
		0x2B3B4352146B2343ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0477F1EDED7D15BBULL,
		0x0369D9FF5F3EEBFCULL,
		0x1264E1D4198E54B3ULL,
		0xBD9DE8267DE391AAULL,
		0xED20D0CD58A435A0ULL,
		0x13E0AC7F5D6C6F76ULL,
		0x6EBEBE0CCC7749F8ULL,
		0x3487A4A1F9DEA674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C62B92E425EF7BULL,
		0x0AFFB5BFFFDA920AULL,
		0x9684658EAF668EFCULL,
		0x91D5E664E1B48306ULL,
		0x26AC68955FEA5672ULL,
		0x612056C2174D4175ULL,
		0x102926460AB9F0EEULL,
		0xBDF8CA025D9BA14EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CB1DA7F0958FAC0ULL,
		0x09966C40A0E479F6ULL,
		0x84E0845AB6E8DA4FULL,
		0x2C480E429C5712ACULL,
		0xCB8CB858074E63D2ULL,
		0x72C0FABD4A212E03ULL,
		0x7E97984AC6CEB916ULL,
		0x897F6EA3A445073AULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BF72896AC86B1DCULL,
		0x77E402371CC54282ULL,
		0x019FD8A29B3FEE30ULL,
		0x6FE8EEDF338B9B4EULL,
		0x1DDF08C428DB667AULL,
		0xDA71FC37FFE5B2DFULL,
		0xDC2C7EA5B28326C2ULL,
		0x720A0AE0BE1DCD13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD44E2D5D1FC9CC46ULL,
		0x473A4C8C99BDFEC6ULL,
		0x8AEB840DE8B7E4C6ULL,
		0x9794519E7F9ED442ULL,
		0x34B3650E9C546A85ULL,
		0x2A82810348BC0D62ULL,
		0x540D5AF2D8EA2763ULL,
		0x4272F526C6F99507ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFB905CBB34F7D9AULL,
		0x30DE4EBB8578BC44ULL,
		0x8B745CAF73880AF6ULL,
		0xF87CBF414C154F0CULL,
		0x296C6DCAB48F0CFFULL,
		0xF0F37D34B759BFBDULL,
		0x882124576A6901A1ULL,
		0x3078FFC678E45814ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x765DF571B4EAC24DULL,
		0x942531B037057214ULL,
		0x598160E0976F0F08ULL,
		0x2F09C2550A55E21AULL,
		0x903410A2AB930A9DULL,
		0x84A00776FE000097ULL,
		0x8039A9E7AA93C15BULL,
		0xD83B2407AF3E1BE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x664D95CF0F9EF1A3ULL,
		0x0DB4436A6438FFF3ULL,
		0x0A02C652B21E2387ULL,
		0xDA307D21DA9D4A5DULL,
		0xDAEFC117C00F0FD9ULL,
		0x13C90E1E41DCA9BDULL,
		0xF4B4F2BEF83A12E8ULL,
		0xD67261A143CDFA14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x101060BEBB7433EEULL,
		0x999172DA533D8DE7ULL,
		0x5383A6B225712C8FULL,
		0xF539BF74D0C8A847ULL,
		0x4ADBD1B56B9C0544ULL,
		0x97690968BFDCA92AULL,
		0x748D5B5952A9D3B3ULL,
		0x0E4945A6ECF3E1F3ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC62E24E567F3509AULL,
		0x8EDD5E97061BA29EULL,
		0x18AA037EF0CCD8F6ULL,
		0x65E221007A43EE12ULL,
		0xC38205744399AED4ULL,
		0xDA4948DDF09F6DD3ULL,
		0x7D219E90172B4C94ULL,
		0x1D3BEF6BCE0369C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C78B3B9CB34C48DULL,
		0xFF87FA00F917D0C1ULL,
		0x80CA09EE6A1BF8D2ULL,
		0x768DDB936B263779ULL,
		0xF10A8A039ED3CE15ULL,
		0xE2A791779200BF6AULL,
		0x8258B72C0F615C08ULL,
		0xB0A8CFED10A1C55DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A56975CACC79417ULL,
		0x715AA497FF0C725FULL,
		0x98600A909AD72024ULL,
		0x136FFA931165D96BULL,
		0x32888F77DD4A60C1ULL,
		0x38EED9AA629FD2B9ULL,
		0xFF7929BC184A109CULL,
		0xAD932086DEA2AC95ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F1104ABEAED2480ULL,
		0xD2909E1FB0CC1997ULL,
		0x318EDBFB5D8F858BULL,
		0x0952ED3A3C70B5D0ULL,
		0x3717F574DB4F4A92ULL,
		0xB5414369AE8DFCD1ULL,
		0x002A310CF3284C19ULL,
		0x9DDE871B575F9FE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFEAED2819308D22ULL,
		0x0861A483CACDF947ULL,
		0x50D20DA1635B47D9ULL,
		0x3F0F30AF65CFE3DAULL,
		0xCE2F6EEC7DF0BA07ULL,
		0xC4A0D5EF1DF4C380ULL,
		0x3CC8444DFF7AFF6EULL,
		0xD7DA377AEA73C9C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0FBE983F3DDA9A2ULL,
		0xDAF13A9C7A01E0D0ULL,
		0x615CD65A3ED4C252ULL,
		0x365DDD9559BF560AULL,
		0xF9389B98A6BFF095ULL,
		0x71E19686B3793F51ULL,
		0x3CE275410C52B377ULL,
		0x4A04B061BD2C5620ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4B03F27208BEC24ULL,
		0xCD62D8D61661A2BAULL,
		0x5EC88E0688E1ED26ULL,
		0x12F2DA36DE40CA7DULL,
		0x20610DA2E225F5C7ULL,
		0x5E60A619C859875BULL,
		0xB4FEB851EF117190ULL,
		0xD4C7558014AA68F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4908C70008B2F37CULL,
		0xCEE190C57893355AULL,
		0x9653F2EB101EEA1CULL,
		0x869ED065C8E4C91AULL,
		0x86466111E0580813ULL,
		0x5078A783FE5FC508ULL,
		0x49B1055B9CA55155ULL,
		0x61B9BC489C6BA25CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADB8F82728391F58ULL,
		0x038348136EF297E0ULL,
		0xC89B7CED98FF073AULL,
		0x946C0A5316A40367ULL,
		0xA6276CB3027DFDD4ULL,
		0x0E18019A36064253ULL,
		0xFD4FBD0A73B420C5ULL,
		0xB57EE9C888C1CAA8ULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BB0F3FF962D2D6FULL,
		0xEEDE4373339A822FULL,
		0xF22EA5D228DB60A7ULL,
		0x9376BCC045217030ULL,
		0x6D16849888DD0A39ULL,
		0xB64251CB1227119AULL,
		0x122CA2BB88A17CF1ULL,
		0x9314DBC1C4121027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F1A638ABE44E52ULL,
		0x491B64F3A6B805A2ULL,
		0x9BCA2A188AB01B0EULL,
		0x67AC59E11D2DB924ULL,
		0x2502532A62105B93ULL,
		0xC251917CEB7D60D1ULL,
		0x6D4A75C71F962B32ULL,
		0xA778A4C1F0F2FD7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D4155C73DC9633DULL,
		0xA7C527809522878DULL,
		0x69E48FCAA26B7BA9ULL,
		0xF4DAE521580CC914ULL,
		0x4814D7B2EACD51AAULL,
		0x7413C0B7F95A714BULL,
		0x7F66D77C973757C3ULL,
		0x346C7F0034E0ED5CULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18AEBF9B260BF0B2ULL,
		0x1BF91E6B3D865E4DULL,
		0xCA302C240A1EEB2BULL,
		0x6A58742F50D4C07AULL,
		0xE440F244AE93C9B8ULL,
		0x6344E0246EA12794ULL,
		0x2780797BC827FB68ULL,
		0xFC9AE9DA2F07A164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60FCEA054D86B114ULL,
		0x3AA8EB905A9CD1F5ULL,
		0xB74DBE13D6736512ULL,
		0x6A82853462326BC3ULL,
		0x67C74C13754477FAULL,
		0x8B11CCAFD98360BEULL,
		0x42E9A028F546CFDAULL,
		0x4774CB269E960701ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7852559E6B8D41A6ULL,
		0x2151F5FB671A8FB8ULL,
		0x7D7D9237DC6D8E39ULL,
		0x00DAF11B32E6ABB9ULL,
		0x8387BE57DBD7BE42ULL,
		0xE8552C8BB722472AULL,
		0x6569D9533D6134B2ULL,
		0xBBEE22FCB191A665ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x901D1ABDCC31105BULL,
		0x8F816C4F376E7CCCULL,
		0x0259A32EDDBB9E3DULL,
		0xAE9862F2184092EFULL,
		0xC1285B45D6A8EF5DULL,
		0x0222538F076804B5ULL,
		0x8D263D20AA2D3169ULL,
		0x3FC97C77D5BB158BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB30B20B472707C05ULL,
		0x0C232F5493745783ULL,
		0x0FC3A205F1F2E11EULL,
		0x16FF091127166C64ULL,
		0x49B5F1E3CC345F76ULL,
		0xD1C62391AFE87501ULL,
		0x87C90B8716E3CF52ULL,
		0x4C5A0F887ED79867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23163A09BE416C5EULL,
		0x83A2431BA41A2B4FULL,
		0x0D9A012B2C497F23ULL,
		0xB8676BE33F56FE8BULL,
		0x889DAAA61A9CB02BULL,
		0xD3E4701EA88071B4ULL,
		0x0AEF36A7BCCEFE3BULL,
		0x739373FFAB6C8DECULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA16602D1C112A540ULL,
		0x28AD8131A4788C74ULL,
		0x9428FCC9E7C5B88EULL,
		0x6BCEBD79C12FC28BULL,
		0x2A760FC075B77556ULL,
		0xC855B22B8FD3C9BEULL,
		0x6E26F755B3AC5409ULL,
		0x0918A2B44548265EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AF15B258BCD663BULL,
		0x79C7611F8A821BD3ULL,
		0x729931958C19219AULL,
		0x319FC863357A260EULL,
		0x7F56D313A4E640C5ULL,
		0xAF6DA8A9DCCA3E65ULL,
		0x8AFCF6B8ABAFB2A6ULL,
		0xCC7DD9A54B09FC92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB9759F44ADFC37BULL,
		0x516AE02E2EFA97A7ULL,
		0xE6B1CD5C6BDC9914ULL,
		0x5A51751AF455E485ULL,
		0x5520DCD3D1513593ULL,
		0x67381A825319F7DBULL,
		0xE4DA01ED1803E6AFULL,
		0xC5657B110E41DACCULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93DAEFA46D8E9D46ULL,
		0x4E4F4E3FF8C850A5ULL,
		0x33045313433875DDULL,
		0x9EB1F08DB3FECAACULL,
		0x3D215AC64271D6B3ULL,
		0x8512198E74720BADULL,
		0xC00816267DFD80F8ULL,
		0xB40B82C4E84007D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2E6D61267A6623ULL,
		0xC5EC375ADD4B9B17ULL,
		0x1A0BC09EBD9C0E95ULL,
		0x8AEB31CA040C82FEULL,
		0x4A4EAD5CA0DD1F49ULL,
		0xC1209FF653F16B4DULL,
		0x6AF3AAA136A90761ULL,
		0x8CC8589385C102B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DF482C54BF4FB65ULL,
		0x8BA379652583CBB2ULL,
		0x290F938DFEA47B48ULL,
		0x145AC147B7F24852ULL,
		0x776FF79AE2ACC9FAULL,
		0x44328678278360E0ULL,
		0xAAFBBC874B548799ULL,
		0x38C3DA576D810560ULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6303A38BC7B31361ULL,
		0x0F267876F396C353ULL,
		0x02A76562C0D480FDULL,
		0xCDDD3178FE0199A4ULL,
		0x8951DA75F76D986BULL,
		0xF235557DA31EAB14ULL,
		0xD54EE0671B7E92A2ULL,
		0xC00AAC0C2E2C3B85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906A4E539C4726C9ULL,
		0xDD17C23A07C0EAC1ULL,
		0x249C86148D8A1E08ULL,
		0x0299E63FD725D6E6ULL,
		0x944CC0FA8CB009CCULL,
		0x94BCCE6E82E870FDULL,
		0xA4906CC841B37AA2ULL,
		0xEB8FA36CD8D4E650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF369EDD85BF435A8ULL,
		0xD231BA4CF4562992ULL,
		0x263BE3764D5E9EF5ULL,
		0xCF44D74729244F42ULL,
		0x1D1D1A8F7BDD91A7ULL,
		0x66899B1321F6DBE9ULL,
		0x71DE8CAF5ACDE800ULL,
		0x2B850F60F6F8DDD5ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AD32D9F4CA28BD4ULL,
		0x1B195A8AF2613933ULL,
		0xC9E82E81899D92B2ULL,
		0xD43BA5F5191F4B10ULL,
		0x8FFC916E5A6B020BULL,
		0xD421005EC60083C2ULL,
		0xA6DB1A941A436A90ULL,
		0x958AE7BC22540EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8016E32C88B21FULL,
		0x5BA30E57EAEC0919ULL,
		0x64E928B858A7AC1DULL,
		0x4F6BD70E4D4A4C73ULL,
		0x69CD9210F3F4AD26ULL,
		0x99E15064D17C6F7BULL,
		0x6BA5A1AA5EEE8437ULL,
		0x84AE5A7D839A6366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0533B7C602A39CBULL,
		0x40BA54DD188D302AULL,
		0xAD010639D13A3EAFULL,
		0x9B5072FB54550763ULL,
		0xE631037EA99FAF2DULL,
		0x4DC0503A177CECB9ULL,
		0xCD7EBB3E44ADEEA7ULL,
		0x1124BDC1A1CE6D81ULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x919879FE73968B1BULL,
		0x689986BE4155016EULL,
		0x6B4F9CBB673DDC53ULL,
		0xBE97FADADBCD9705ULL,
		0x38AB6256A6739672ULL,
		0xEE92DB4E648FC3CFULL,
		0x051A8A22862B1C09ULL,
		0x7BB743B31A28BD18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x054C8E1D1B7B2FB1ULL,
		0x01A5038A9FF9625CULL,
		0x815192E2154E528DULL,
		0xEB333ED8F2BD4521ULL,
		0x4C15AAA4DA44DF54ULL,
		0x57EBE0B9BC51E87BULL,
		0xEB88489485125366ULL,
		0x2FB4CCE15C616936ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94D4F7E368EDA4AAULL,
		0x693C8534DEAC6332ULL,
		0xEA1E0E5972738EDEULL,
		0x55A4C4022970D224ULL,
		0x74BEC8F27C374926ULL,
		0xB9793BF7D8DE2BB4ULL,
		0xEE92C2B603394F6FULL,
		0x54038F524649D42EULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x163B29893A496CD2ULL,
		0x5827EB0C8EA8A9A0ULL,
		0xC2145560441712EAULL,
		0x147663C8497FE156ULL,
		0xFBC0AE756F9ACFF7ULL,
		0xD9596A21FA3FD9B2ULL,
		0xDFA5C2E0DF750DFCULL,
		0x1CD6169B7543B261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7EB154E090F4591ULL,
		0x9EDCE0C1C6F36022ULL,
		0xC97A25868EA4E53EULL,
		0x195FDB1CA69C9D4BULL,
		0x231E41C72F441C0CULL,
		0x905FADC3932ED983ULL,
		0x760A04B63521C221ULL,
		0x5A4902BB439BBB56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1D03CC733462943ULL,
		0xC6FB0BCD485BC982ULL,
		0x0B6E70E6CAB3F7D4ULL,
		0x0D29B8D4EFE37C1DULL,
		0xD8DEEFB240DED3FBULL,
		0x4906C7E269110031ULL,
		0xA9AFC656EA54CFDDULL,
		0x469F142036D80937ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x725D440D16A40CFCULL,
		0xCF0C499B17BA6F34ULL,
		0x6E8BFB0BFB3DADDEULL,
		0xC6F6E0B97C4890D4ULL,
		0xFDE2E2476B020AE1ULL,
		0x739A0C8B374DE653ULL,
		0x83638A33B11EB1FAULL,
		0x0EECA251E44C7A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B041A21C5A42205ULL,
		0xD2BA25774A31BEF7ULL,
		0x47FC28A7CE713AF4ULL,
		0x8137C179BEDB4B04ULL,
		0x8F2E8FC7E6D26F62ULL,
		0xF3AAFEB0F46301EAULL,
		0x74C276914D9C0DAEULL,
		0x0E7F2EADC48BF98CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39595E2CD3002EF9ULL,
		0x1DB66CEC5D8BD1C3ULL,
		0x2977D3AC354C972AULL,
		0x47C121C0C293DBD0ULL,
		0x72CC6D808DD06583ULL,
		0x8030F23BC32EE7B9ULL,
		0xF7A1FCA2FC82BC54ULL,
		0x00938CFC20C78308ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3822B9A94C752D3BULL,
		0x11A1818EBC222261ULL,
		0xA0F50010E519F395ULL,
		0xBF65761104193472ULL,
		0xA30F5FC962B92C98ULL,
		0xACD504ADC9C0C682ULL,
		0x47CFDF663B9C0FFCULL,
		0x81F942B19109D542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20ADD124FFD40B78ULL,
		0x0EEB5BDC06A62C13ULL,
		0x2CE43C7FAB614D56ULL,
		0x0E24089F766BB2CAULL,
		0x51734250EB6711B0ULL,
		0x5F4659F4D5727BD1ULL,
		0x93518AE3EDC29C4FULL,
		0x5D4CAA591681EEC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x188F688DB3A12643ULL,
		0x1F4ADA52BA840E72ULL,
		0x8C113C6F4E78BEC3ULL,
		0xB1417E8E727286B8ULL,
		0xF27C1D9989DE3D28ULL,
		0xF3935D591CB2BD53ULL,
		0xD49E5585D65E93B3ULL,
		0xDCB5E8E887883B8BULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 200 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35BEE66FCD1E8DFCULL,
		0xB59A4983D7BD928CULL,
		0xC1E3FE23300F3D84ULL,
		0x0F1CF01CDD4F40ECULL,
		0x9E262C2A74D8CDF7ULL,
		0x3D7DBB11BC4AACCCULL,
		0x7737711E67B41122ULL,
		0x1DB9A97B459FB09FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC24F76DDE8AC2A1EULL,
		0xA5154388B1D662D3ULL,
		0x65B30A28A4C51A16ULL,
		0xE7BA5ACC8C982A87ULL,
		0x8A2A2064E2D6C89BULL,
		0xB3BD6716FB257862ULL,
		0x77B8ED0183D228D7ULL,
		0x4F822C5CA830F163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7F190B225B2A7E2ULL,
		0x108F0A0B666BF05FULL,
		0xA450F40B94CA2792ULL,
		0xE8A6AAD051D76A6BULL,
		0x140C0C4E960E056CULL,
		0x8EC0DC07476FD4AEULL,
		0x008F9C1FE46639F5ULL,
		0x523B8527EDAF41FCULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 201 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A01344ABE276906ULL,
		0xD5CB177051766C12ULL,
		0xAD22F6F8E753EAD9ULL,
		0x6CF5E38AA435B201ULL,
		0xA998F17870559D9EULL,
		0xA6B5D8AEBB9F61ABULL,
		0xE851A9A3C6931E01ULL,
		0xF08D974F3F141C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAEB89254E4CCEB1ULL,
		0x17BCC6713E8A7352ULL,
		0xA5AE403EC446AF0EULL,
		0x3405CD874FFD5F73ULL,
		0x908DA10F03F44C7FULL,
		0xCFF5AC1C04FE80D3ULL,
		0x7A113B04FD112AF7ULL,
		0x99FA59B048093C30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30EABD6FF06BA7B7ULL,
		0xC277D1016FFC1F40ULL,
		0x088CB6C6231545D7ULL,
		0x58F02E0DEBC8ED72ULL,
		0x3915507773A1D1E1ULL,
		0x694074B2BF61E178ULL,
		0x924092A73B8234F6ULL,
		0x6977CEFF771D20B3ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 202 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF565639ED7C85B6ULL,
		0xB30C0D6844B1826EULL,
		0x57F3FF42F07BB5CDULL,
		0xBB5B963F2DB4A7F0ULL,
		0x5AA07A92213653E9ULL,
		0xA93E308D26E4A143ULL,
		0x615878BFCA11A408ULL,
		0xD65122AFB9A61F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912570E23764FA83ULL,
		0x157C744309829025ULL,
		0x25541C57439B2F43ULL,
		0x48D5F98540DA4E20ULL,
		0x12609BA641FDC036ULL,
		0x857C14B64FD082A3ULL,
		0xC3F6D251A35ABAA4ULL,
		0xB78049D53F30CD10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E7326DBDA187F35ULL,
		0xA670792B4D33124BULL,
		0x72A7E315B3E09A8EULL,
		0xF38E6FBA6D6EE9D0ULL,
		0x48C0E13460CB93DFULL,
		0x2C42243B693423E0ULL,
		0xA2AEAAEE694B1EACULL,
		0x61D16B7A8696D292ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 203 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x647FA4288D2CD419ULL,
		0x1F94ABC982E61526ULL,
		0x50FD2071720C9D85ULL,
		0x7B689B82675F4007ULL,
		0x450A3B67424CEBE4ULL,
		0x73174A0B4A6DC021ULL,
		0x41E21980F7BED1B5ULL,
		0x3570B5A82DCC116EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA1862ACE39131FULL,
		0x67A41C7055A1E318ULL,
		0x0B3230F1F78F9AC6ULL,
		0xC7B0C114DC70272DULL,
		0x3B2CF856AD5052FBULL,
		0x3658ACAB1451EC95ULL,
		0x14C5C35DC760C52EULL,
		0x03662F68E02EDEF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FDE22024315C706ULL,
		0x7830B7B9D747F63EULL,
		0x5BCF108085830743ULL,
		0xBCD85A96BB2F672AULL,
		0x7E26C331EF1CB91FULL,
		0x454FE6A05E3C2CB4ULL,
		0x5527DADD30DE149BULL,
		0x36169AC0CDE2CF97ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 204 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA93A653DDC6458C8ULL,
		0xBD576FE90F646FBDULL,
		0xAF6B580BA71C0E12ULL,
		0x028494CFBB36007CULL,
		0x44329CE3BD08237FULL,
		0xF87B96E3C8628C95ULL,
		0x68D8F65EC1678E2DULL,
		0xD870D30F41A45243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70698CC84E57FE26ULL,
		0x465ED7ECC0E0A78AULL,
		0x211F7D17EF944D58ULL,
		0x646EA6B91290B790ULL,
		0x34CBC395DD09330DULL,
		0x604572BA5842CDF4ULL,
		0x8E31CED0E59F399AULL,
		0xA3578F9EC74DC40AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD953E9F59233A6EEULL,
		0xFB09B805CF84C837ULL,
		0x8E74251C4888434AULL,
		0x66EA3276A9A6B7ECULL,
		0x70F95F7660011072ULL,
		0x983EE45990204161ULL,
		0xE6E9388E24F8B7B7ULL,
		0x7B275C9186E99649ULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 205 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x769AD8289C0BED18ULL,
		0x57B68E713345CC72ULL,
		0x3B92E6C3430FCBF9ULL,
		0xECCC434F3EB8CC29ULL,
		0xC36B4630397D7C20ULL,
		0xC6EC0E6939BEB654ULL,
		0x42F0178FDF711CA3ULL,
		0x293C6AC15B2E01F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEEDE5A08ABDDB73ULL,
		0x104CA11423905F9EULL,
		0x2DD87FCCEFD464BFULL,
		0x584C19AB76C50C54ULL,
		0x15A66168E41FAADCULL,
		0xEB07487192CF9E29ULL,
		0x77674946343DC0A6ULL,
		0x7F366A24A09C372FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8773D8816B6366BULL,
		0x47FA2F6510D593ECULL,
		0x164A990FACDBAF46ULL,
		0xB4805AE4487DC07DULL,
		0xD6CD2758DD62D6FCULL,
		0x2DEB4618AB71287DULL,
		0x35975EC9EB4CDC05ULL,
		0x560A00E5FBB236D7ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 206 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x748303CCE820DF73ULL,
		0xA9C5F07DDE2CA009ULL,
		0x71076BF0E2673B9FULL,
		0x91E2523B7DD3758AULL,
		0xB14B2C5322579E91ULL,
		0xE6B0033B7DE9E7DDULL,
		0xC3228C89C37F6088ULL,
		0xE52B4EC512D00B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA656AB47D81C0EE5ULL,
		0xF1142CF5CA68DC81ULL,
		0x201A9C93E0713B96ULL,
		0xB8DB1291ACB95D7FULL,
		0x5C590F7F836E32CCULL,
		0x508F13E362155D86ULL,
		0x2D328D5E79AF1164ULL,
		0xB5A64328FF9FEDBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2D5A88B303CD196ULL,
		0x58D1DC8814447C88ULL,
		0x511DF76302160009ULL,
		0x293940AAD16A28F5ULL,
		0xED12232CA139AC5DULL,
		0xB63F10D81FFCBA5BULL,
		0xEE1001D7BAD071ECULL,
		0x508D0DEDED4FE6B2ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 207 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3778A0795FD05E8ULL,
		0x66EFBC0E6CA7A4E7ULL,
		0x3AC05CC77878BC94ULL,
		0xFB8B211837097AD8ULL,
		0x3137D185DC3F2E27ULL,
		0x59E98AE32D159B3DULL,
		0x6DD61441949AA3B3ULL,
		0xED08C00ED521A140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE50DC347EA085F7ULL,
		0xCAA38092F95C514CULL,
		0x6EE572A932A3BE75ULL,
		0x963B74C7C039C04FULL,
		0x998D8424D0F7C924ULL,
		0x74D68878D81D98ECULL,
		0x159700A19023E098ULL,
		0x77373946BEFD0D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D275633EB5D801FULL,
		0xAC4C3C9C95FBF5ABULL,
		0x54252E6E4ADB02E1ULL,
		0x6DB055DFF730BA97ULL,
		0xA8BA55A10CC8E703ULL,
		0x2D3F029BF50803D1ULL,
		0x784114E004B9432BULL,
		0x9A3FF9486BDCAC57ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 208 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A29D493AB4CE01DULL,
		0xAFC63EB31DCF9431ULL,
		0xE3F180ABFAC5BA04ULL,
		0x4F66F99609DBFD5CULL,
		0x44CD72B0BFA1F218ULL,
		0x281A2DB3555B2426ULL,
		0xB1DC25511582ED6CULL,
		0xD1B6A6BADE081D12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CC919804E78AC7ULL,
		0xC39F5CCDE9DE4930ULL,
		0x69068A0DFC42A463ULL,
		0x1F6B0C42712763D0ULL,
		0x59AD61E7903D82BDULL,
		0x350D2FA4517D0B7DULL,
		0x32B02058D6B7EF99ULL,
		0x080CF86C82D3549EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48E5450BAFAB6ADAULL,
		0x6C59627EF411DD01ULL,
		0x8AF70AA606871E67ULL,
		0x500DF5D478FC9E8CULL,
		0x1D6013572F9C70A5ULL,
		0x1D17021704262F5BULL,
		0x836C0509C33502F5ULL,
		0xD9BA5ED65CDB498CULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 209 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BC1F68D9578B21CULL,
		0x155ECFEF75C2D4A4ULL,
		0x495467E0F0D6B265ULL,
		0x49A90ABB1682048EULL,
		0x1959064C233F028DULL,
		0xC68DBCE539631E45ULL,
		0x3274B504B1B2725CULL,
		0x1E35F4D0B462C1DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F46480D5996557ULL,
		0xDBE8DC76D88AA813ULL,
		0x2F81C242A00F5BFCULL,
		0xCF6FF8707E6E559BULL,
		0x031A1887FC431AB8ULL,
		0x9F446B686F689150ULL,
		0x384F961FC8DC9184ULL,
		0x7EB334ED8C2B95D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB835920D40E1D74BULL,
		0xCEB61399AD487CB7ULL,
		0x66D5A5A250D9E999ULL,
		0x86C6F2CB68EC5115ULL,
		0x1A431ECBDF7C1835ULL,
		0x59C9D78D560B8F15ULL,
		0x0A3B231B796EE3D8ULL,
		0x6086C03D38495408ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 210 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B0AEF37056B4322ULL,
		0x75F463E8D1A06E40ULL,
		0xFAA9961B96C92165ULL,
		0x13DCB8645B429036ULL,
		0x38E41C4F9AF6C082ULL,
		0x1CA05093288A408FULL,
		0x640827A3AA2AFC66ULL,
		0xCD6CEE238BF3058FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDB6703B909A9E03ULL,
		0x451291BC6A54993FULL,
		0xAC5B5F90F591007AULL,
		0x2B130813F3609DA2ULL,
		0x629573E3D5E55303ULL,
		0x06348D538EFF4E4DULL,
		0x6E2D7B387425DCE0ULL,
		0x9BF3334FEB1AB630ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6BC9F0C95F1DD21ULL,
		0x30E6F254BBF4F77FULL,
		0x56F2C98B6358211FULL,
		0x38CFB077A8220D94ULL,
		0x5A716FAC4F139381ULL,
		0x1A94DDC0A6750EC2ULL,
		0x0A255C9BDE0F2086ULL,
		0x569FDD6C60E9B3BFULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 211 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73564341B818A698ULL,
		0x896F7BBB3D67768FULL,
		0xB3573A21F0C92BB2ULL,
		0x5448383A09443873ULL,
		0xB4BC3023D9670086ULL,
		0x1224000843DFF769ULL,
		0x5CDD1ED3AE5EDB4BULL,
		0x434FA525E63E6FF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C6F9A4D0F460FB4ULL,
		0x01C050BC17DFB4A0ULL,
		0x9F68AC41A9B053D6ULL,
		0x4881FC409961D366ULL,
		0x518B42F34AB91010ULL,
		0x06BD01112AB6ADD9ULL,
		0xB9707A7700578DDCULL,
		0xFA59AC0FCC02E01BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F39D90CB75EA92CULL,
		0x88AF2B072AB8C22FULL,
		0x2C3F966059797864ULL,
		0x1CC9C47A9025EB15ULL,
		0xE53772D093DE1096ULL,
		0x1499011969695AB0ULL,
		0xE5AD64A4AE095697ULL,
		0xB916092A2A3C8FEFULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 212 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1DABDD63B7F0B0FULL,
		0xF1AD87767E675EE5ULL,
		0xD876B716248036F7ULL,
		0x9E4C601ED8C04EAEULL,
		0x979D4242A26D4216ULL,
		0xE111B75DBE811FACULL,
		0xB79BA3BC037C3DF6ULL,
		0xD698A1C2010B3304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3D3B3762EB2EA0ULL,
		0x2DFA71A2C72F43DAULL,
		0xBB833E73BB01A3B2ULL,
		0x498D87FE91ABD7F4ULL,
		0xF0C7FF85EEBE511BULL,
		0xFEAA2272CC371050ULL,
		0xBB422FE33DA3717BULL,
		0x59BFA15842D9C465ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBE786E1599425AFULL,
		0xDC57F6D4B9481D3FULL,
		0x63F589659F819545ULL,
		0xD7C1E7E0496B995AULL,
		0x675ABDC74CD3130DULL,
		0x1FBB952F72B60FFCULL,
		0x0CD98C5F3EDF4C8DULL,
		0x8F27009A43D2F761ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 213 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA71D04E43992570EULL,
		0x7B0D428888D07C8DULL,
		0x622F93B72833F2EEULL,
		0x78D30E442EA3D155ULL,
		0x6B1583A371E365EEULL,
		0x1DF6D195C9257E55ULL,
		0x5B390F895987EB2EULL,
		0x390FCE12DFEE78FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01DC1D9790593532ULL,
		0xFE666F1FF7D8EF2FULL,
		0x3B413AD903F5600AULL,
		0xF4DB806401A3B01FULL,
		0xC0FA5346D70FA04FULL,
		0x966C40F265EFED24ULL,
		0x794242D469D4F0CFULL,
		0xDD38CCAD4EFE8EB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6C11973A9CB623CULL,
		0x856B2D977F0893A2ULL,
		0x596EA96E2BC692E4ULL,
		0x8C088E202F00614AULL,
		0xABEFD0E5A6ECC5A1ULL,
		0x8B9A9167ACCA9371ULL,
		0x227B4D5D30531BE1ULL,
		0xE43702BF9110F64DULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 214 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBCE2438191A5079ULL,
		0x0B65B132975F19A0ULL,
		0x87CBD322474F9C50ULL,
		0x691A95BC6AB74814ULL,
		0x7A3470747E61B212ULL,
		0xB805B3CEC3FF2AE5ULL,
		0x8C5EE21DB6C17EC7ULL,
		0xE854CDFE6772DD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31EE872FE4FA1E16ULL,
		0xED6B6C2FC208A1A1ULL,
		0x0D14BF3566C2E4ADULL,
		0x67ADF077397268DBULL,
		0x2559B0B61888E773ULL,
		0x50445F08D86EA879ULL,
		0x2EEC6FA00ABFA4B0ULL,
		0x6A58EFD8C94126BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA20A317FDE04E6FULL,
		0xE60EDD1D5557B801ULL,
		0x8ADF6C17218D78FDULL,
		0x0EB765CB53C520CFULL,
		0x5F6DC0C266E95561ULL,
		0xE841ECC61B91829CULL,
		0xA2B28DBDBC7EDA77ULL,
		0x820C2226AE33FBB0ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 215 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60FB4BC7438D3BC6ULL,
		0x3727C25472966CF8ULL,
		0xA27F2944142D3B53ULL,
		0x95EC68AA94FEE717ULL,
		0x8776BA6575F28C93ULL,
		0x7047E927F014BD0DULL,
		0xCCA996D3D365FA3BULL,
		0xEC0B3038E605A356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F6ECF01B364527ULL,
		0x69EBC30333E47462ULL,
		0xA365F6E551548B03ULL,
		0x713FF4025CA63935ULL,
		0x48EBB9D51D5BE96DULL,
		0x905D89EDD17DA27BULL,
		0xE33F1EA4CC1C8D70ULL,
		0xD146D65BCB9E3E66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE80DA73758BB7EE1ULL,
		0x5ECC01574172189AULL,
		0x011ADFA14579B050ULL,
		0xE4D39CA8C858DE22ULL,
		0xCF9D03B068A965FEULL,
		0xE01A60CA21691F76ULL,
		0x2F9688771F79774BULL,
		0x3D4DE6632D9B9D30ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 216 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB94F90280F7D390CULL,
		0x6132D16137BE2EB1ULL,
		0x65F70DEEA13C30E9ULL,
		0xA9E7818B22424522ULL,
		0x23C393A9E9CB0E1EULL,
		0xF966058A86BCB31FULL,
		0x5F00B14A38C02A91ULL,
		0xD4111F5D2166A799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BCB5EFA76BA13F4ULL,
		0xCD7BBB58CC855FBEULL,
		0x149D02D255C72EBEULL,
		0xBFF9C700B8F137D3ULL,
		0x834B2145EAFF6F56ULL,
		0xF17479EC141B881FULL,
		0x92E8C0A1AC7F7CD3ULL,
		0x5B28B759B5DE0099ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3284CED279C72AF8ULL,
		0xAC496A39FB3B710FULL,
		0x716A0F3CF4FB1E57ULL,
		0x161E468B9AB372F1ULL,
		0xA088B2EC03346148ULL,
		0x08127C6692A73B00ULL,
		0xCDE871EB94BF5642ULL,
		0x8F39A80494B8A700ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 217 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1ABF7D3E149AF939ULL,
		0xC16C14A82437C93EULL,
		0xAA60C68F200B821BULL,
		0x97D9AAC6EA260F30ULL,
		0x19F07B77632B01B2ULL,
		0x7A4C6758C9FBEA4EULL,
		0x76D9EEC31CF9819BULL,
		0xCB6F95DD629CED48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C016AE30D76F10ULL,
		0xF4AFFF8FC76310C5ULL,
		0x81B440EDA76B9698ULL,
		0x7E1FD7803F4773E2ULL,
		0xE853DBE7CADA9026ULL,
		0xC272803123D8EE1EULL,
		0xB33BF07E21E6AE8AULL,
		0xFAF6AFE2E1129CEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA7F6B90244D9629ULL,
		0x35C3EB27E354D9FBULL,
		0x2BD4866287601483ULL,
		0xE9C67D46D5617CD2ULL,
		0xF1A3A090A9F19194ULL,
		0xB83EE769EA230450ULL,
		0xC5E21EBD3D1F2F11ULL,
		0x31993A3F838E71A7ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 218 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA7C5494D19568A6ULL,
		0x61224C62CD027A5FULL,
		0xBCE6C836E7AE2ED3ULL,
		0x9F4D2EB8B449C968ULL,
		0x8E146E1741FC84C4ULL,
		0x981CDAB53061549DULL,
		0x2559231F31676CC5ULL,
		0xD0275246EBD5E46DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6BD1D20384C1467ULL,
		0xCE031B05CF51E818ULL,
		0x35D67B982991FF2DULL,
		0x10A9EA0B1FCF5E92ULL,
		0x6FC5A836723F6C11ULL,
		0x49B4A1D74F4ADB37ULL,
		0x1A0A197662FBAC25ULL,
		0x0B0341466BAF6FBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CC149B4E9D97CC1ULL,
		0xAF21576702539247ULL,
		0x8930B3AECE3FD1FEULL,
		0x8FE4C4B3AB8697FAULL,
		0xE1D1C62133C3E8D5ULL,
		0xD1A87B627F2B8FAAULL,
		0x3F533A69539CC0E0ULL,
		0xDB241300807A8BD6ULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 219 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76A7B4EF1C4DDE7FULL,
		0x97A6F27E72FF3B95ULL,
		0xB0F4EEE93E7E0555ULL,
		0x9C3620676E6735C6ULL,
		0x22CA562A8DC9DD36ULL,
		0x2D795F8C0DF39FEAULL,
		0x07E3BC00FDDD7740ULL,
		0x82A29B5572D58DA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5327032ED6155CBULL,
		0x070DEEDA48ECAD6DULL,
		0xAFEA7ABDAEBD08B3ULL,
		0x67EA39E1882875FBULL,
		0xE253FF6578ED96F0ULL,
		0x7E98B5FCFDC5B402ULL,
		0xA6F37354F33D889BULL,
		0x7277929DFD41D0C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8395C4DDF12C8BB4ULL,
		0x90AB1CA43A1396F8ULL,
		0x1F1E945490C30DE6ULL,
		0xFBDC1986E64F403DULL,
		0xC099A94FF5244BC6ULL,
		0x53E1EA70F0362BE8ULL,
		0xA110CF540EE0FFDBULL,
		0xF0D509C88F945D6BULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 220 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x724613D82A2B6C57ULL,
		0x92A18D913499CB7EULL,
		0x0529C62AFB4DCB52ULL,
		0x6F3E47F33000295AULL,
		0x5541643840547697ULL,
		0x9D47A75F70AC20AEULL,
		0x6556413E1398FC37ULL,
		0x026D5F534080B416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A09852B33DE791CULL,
		0x045998F477B59974ULL,
		0xBC7EA40934C31208ULL,
		0xA1001DFB1643A48DULL,
		0x9968B5C22765C096ULL,
		0x7172820BE27EC8C5ULL,
		0x552CB937A8081828ULL,
		0x6880D68BF19E00F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x384F96F319F5154BULL,
		0x96F81565432C520AULL,
		0xB9576223CF8ED95AULL,
		0xCE3E5A0826438DD7ULL,
		0xCC29D1FA6731B601ULL,
		0xEC35255492D2E86BULL,
		0x307AF809BB90E41FULL,
		0x6AED89D8B11EB4E7ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 221 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9415BA737F65021BULL,
		0x1051EDAD483438E8ULL,
		0x991D483FC9966D44ULL,
		0xAC4875196AB9BDCFULL,
		0x00516B5BABAC53ADULL,
		0xB285473222E210F2ULL,
		0x922A704081936914ULL,
		0x4775059EFE8C3942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4A5624D954BCA9ULL,
		0x3109BB434DBABC90ULL,
		0x75420A34784F98D1ULL,
		0x52FAAD71B64CBED2ULL,
		0x51C9CF41C28D6307ULL,
		0x1006DA5FEBC0EE8DULL,
		0x3055D242FA527A09ULL,
		0x8BEE7E804C38BF4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB5FEC57A631BEB2ULL,
		0x215856EE058E8478ULL,
		0xEC5F420BB1D9F595ULL,
		0xFEB2D868DCF5031DULL,
		0x5198A41A692130AAULL,
		0xA2839D6DC922FE7FULL,
		0xA27FA2027BC1131DULL,
		0xCC9B7B1EB2B48608ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 222 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DAEA6ABE606FF0FULL,
		0xE7741123346C5092ULL,
		0x912C7E9D7F86D350ULL,
		0x7CF3F900D5DCB67BULL,
		0x8B63DD9B1D28048EULL,
		0x862C3094CFEDE9D7ULL,
		0x5A1E16A83C0CCCEDULL,
		0x268FE868491D2D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x710C0CD2BCFEECD4ULL,
		0x055943BFD675B4F8ULL,
		0x807255264A5E82B4ULL,
		0xEE8271C4D3EC2E67ULL,
		0xADD4C0B48C7BC170ULL,
		0x09ED5BA4F8CA99D1ULL,
		0xAE1340A77E3319D6ULL,
		0x332C26B4B7653410ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CA2AA795AF813DBULL,
		0xE22D529CE219E46AULL,
		0x115E2BBB35D851E4ULL,
		0x927188C40630981CULL,
		0x26B71D2F9153C5FEULL,
		0x8FC16B3037277006ULL,
		0xF40D560F423FD53BULL,
		0x15A3CEDCFE781972ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 223 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x337AE767C82831C9ULL,
		0xE39C6DAF90B080AAULL,
		0x0B9A05E0CDDC6C1BULL,
		0x0FE76E487F7947C6ULL,
		0x1170FD6EB27C4602ULL,
		0x1C36749ACDF6A551ULL,
		0x0FF00BFCD9078267ULL,
		0xE0C47F38147B6555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0CFA8C1745BE0E5ULL,
		0x90116CF49A178182ULL,
		0xF72F9F05145D41FEULL,
		0x0D5413C44450CAA5ULL,
		0x164B427B32D8C13DULL,
		0x1CE390EBC54B1092ULL,
		0x2299AC2A331D6364ULL,
		0x3382E13573284F32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93B54FA6BC73D12CULL,
		0x738D015B0AA70128ULL,
		0xFCB59AE5D9812DE5ULL,
		0x02B37D8C3B298D63ULL,
		0x073BBF1580A4873FULL,
		0x00D5E47108BDB5C3ULL,
		0x2D69A7D6EA1AE103ULL,
		0xD3469E0D67532A67ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 224 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77F2174BE48021D2ULL,
		0xAD6DE15AF6E3C3D6ULL,
		0x475AC57F7DA48A50ULL,
		0xBB49C2652316CE2EULL,
		0x011BF44465D61BF1ULL,
		0x0B498694BC891D87ULL,
		0x26D6AA6052401F7CULL,
		0x7895AC44DB1FEC69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F9DC8990C2014BULL,
		0x9A3131FD51239B80ULL,
		0xBE662E8746EA6AF7ULL,
		0x7F98245B47D6F26FULL,
		0xEA6E367573E1FF8DULL,
		0x6BA2854E81805647ULL,
		0x150C51BBBD7FA1F5ULL,
		0x43BF3FF2E61A4DA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250BCBC274422099ULL,
		0x375CD0A7A7C05856ULL,
		0xF93CEBF83B4EE0A7ULL,
		0xC4D1E63E64C03C41ULL,
		0xEB75C2311637E47CULL,
		0x60EB03DA3D094BC0ULL,
		0x33DAFBDBEF3FBE89ULL,
		0x3B2A93B63D05A1CCULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 225 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B86F177962936F7ULL,
		0x8D2D00ADCDA19174ULL,
		0x21DE459301FC70A9ULL,
		0x6B6D90CE10ADEE94ULL,
		0x0867CAE7512A344CULL,
		0x0067EF7F1FFD4E85ULL,
		0x7FBADDA65FCD20A7ULL,
		0x4A84A909033F9EC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B04225187A3BDD7ULL,
		0x46291EB403FE8AB6ULL,
		0x5FC89188C58AEE75ULL,
		0x958CCF6180320368ULL,
		0xFA689268FFE3E955ULL,
		0xD845DB64840902E1ULL,
		0x22448B698DEEFEDCULL,
		0x5C87874BD6D07C09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8082D326118A8B20ULL,
		0xCB041E19CE5F1BC2ULL,
		0x7E16D41BC4769EDCULL,
		0xFEE15FAF909FEDFCULL,
		0xF20F588FAEC9DD19ULL,
		0xD822341B9BF44C64ULL,
		0x5DFE56CFD223DE7BULL,
		0x16032E42D5EFE2C0ULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 226 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC6ACCCE42F57AA0ULL,
		0x490D2A6ADA2A841DULL,
		0x4C306E07B027CA45ULL,
		0xA8140C040028400EULL,
		0x90BA1D797E5DBC7EULL,
		0x12CD1CB071563D96ULL,
		0x28C86B0976B704BCULL,
		0xC0D938C363284B78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35503AED88C6C36ULL,
		0x9A0539D724C7F81FULL,
		0x2C3C4B54A21F7102ULL,
		0xD9B704AC863E3DEBULL,
		0x948EA6EE9CF3E89FULL,
		0xE225F6488918C851ULL,
		0x107D4568603F9564ULL,
		0xC41AFDBD42B8431BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F3FCF609A791696ULL,
		0xD30813BDFEED7C02ULL,
		0x600C25531238BB47ULL,
		0x71A308A886167DE5ULL,
		0x0434BB97E2AE54E1ULL,
		0xF0E8EAF8F84EF5C7ULL,
		0x38B52E61168891D8ULL,
		0x04C3C57E21900863ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 227 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x923E4D1940468060ULL,
		0xE2F7924E5CC24CADULL,
		0xFE32E4FDAB22D509ULL,
		0x040FBB071AA3A23CULL,
		0x77D322527401EFCAULL,
		0xF05E4994ABEC4D21ULL,
		0xA7E2AC291CA450EAULL,
		0xA7E250873E341D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4910FA1AEFF17192ULL,
		0x752E72F354D1C594ULL,
		0x1DA234E490118F0FULL,
		0x401D9DC75C961F69ULL,
		0x32FDBC535FFFB8A1ULL,
		0x8B884BE24BA079C9ULL,
		0x104CC50175C5C3FAULL,
		0x7D3340504464D3E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB2EB703AFB7F1F2ULL,
		0x97D9E0BD08138939ULL,
		0xE390D0193B335A06ULL,
		0x441226C04635BD55ULL,
		0x452E9E012BFE576BULL,
		0x7BD60276E04C34E8ULL,
		0xB7AE692869619310ULL,
		0xDAD110D77A50CEE3ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 228 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0B04CD9E23AB4A7ULL,
		0x042DF8F92E0AACF5ULL,
		0xA3862CC1EA37FCDDULL,
		0xE44B4CA381C5FD4DULL,
		0xB04D4C63677D7828ULL,
		0xACDF672227AFDF53ULL,
		0x50C46BA7CC367338ULL,
		0xC9D0B56C65E0361CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x417DD21DDD727DA1ULL,
		0xBB99F73264CB9164ULL,
		0xE13ADEA78E42DCB5ULL,
		0xDD85F14BB06CD67BULL,
		0xFB6800D5D63D732FULL,
		0x775DB8226140E3F5ULL,
		0x9AE560EFE1FDFBC0ULL,
		0x3A0D1B0FD1A6B390ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1CD9EC43F48C906ULL,
		0xBFB40FCB4AC13D91ULL,
		0x42BCF26664752068ULL,
		0x39CEBDE831A92B36ULL,
		0x4B254CB6B1400B07ULL,
		0xDB82DF0046EF3CA6ULL,
		0xCA210B482DCB88F8ULL,
		0xF3DDAE63B446858CULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 229 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25CBC66E57AADEC3ULL,
		0x96F4070C068EDCD7ULL,
		0x09C97AFBC92407D8ULL,
		0x6E1F2DE2B119A9ADULL,
		0x9EAD142BDD3B51F8ULL,
		0xE89DF1B36667D5B9ULL,
		0xA4B2C8A6C2EF02FEULL,
		0x4BB2B97798EFD2C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB48FDAA4F0E3456ULL,
		0xC168B153444ACAD3ULL,
		0xF505C6D729C917B2ULL,
		0x0FC0CD0C02F118DCULL,
		0x3985EDA2FDD28BBCULL,
		0x2C706E4D07A62C90ULL,
		0x49EF5AE1FA651701ULL,
		0x79C56C79C6655AFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE833BC418A4EA95ULL,
		0x579CB65F42C41604ULL,
		0xFCCCBC2CE0ED106AULL,
		0x61DFE0EEB3E8B171ULL,
		0xA728F98920E9DA44ULL,
		0xC4ED9FFE61C1F929ULL,
		0xED5D9247388A15FFULL,
		0x3277D50E5E8A883EULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 230 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x641F299B3F1512CDULL,
		0x6438148B36AE8EE1ULL,
		0xE2FB454CFDBE4F15ULL,
		0x99ED03E328F8CBDDULL,
		0x307F4B37B0141A69ULL,
		0xA67EFBB6D7AA2BB4ULL,
		0xA3A4C53EA91A6FEDULL,
		0x555CC0BE09BC62A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84B05D45F86BA999ULL,
		0xA8073C32E4467FA1ULL,
		0x82FF9229B2D91A3EULL,
		0x06941EAA063F17EBULL,
		0x197A4BA032E534B8ULL,
		0xB372AC39516E06CAULL,
		0x900FC7776E8974F0ULL,
		0xD0B2B1B41C91378CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0AF74DEC77EBB54ULL,
		0xCC3F28B9D2E8F140ULL,
		0x6004D7654F67552BULL,
		0x9F791D492EC7DC36ULL,
		0x2905009782F12ED1ULL,
		0x150C578F86C42D7EULL,
		0x33AB0249C7931B1DULL,
		0x85EE710A152D5524ULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 231 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF32CD5F96491A35ULL,
		0xDE367F22A843DEA3ULL,
		0x2FB197D4DC083CB8ULL,
		0xF512D1EBA080D858ULL,
		0x17E8CDAB692361E9ULL,
		0x0C7F973F54FD811EULL,
		0xD1F3DEDD98E3D0EFULL,
		0xE64BC4964BF68EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB62EDFD250AB952FULL,
		0x0972B845EB7C3070ULL,
		0x1BBB45A0CE32DBFEULL,
		0x48EFDD70DDB997D0ULL,
		0x539F6E7B5C99ECAAULL,
		0xB7DA6D1EE92EA23AULL,
		0xA1CC967787D22BFEULL,
		0xAD59EF388AC7EE25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x791C128DC6E28F1AULL,
		0xD744C767433FEED3ULL,
		0x340AD274123AE746ULL,
		0xBDFD0C9B7D394F88ULL,
		0x4477A3D035BA8D43ULL,
		0xBBA5FA21BDD32324ULL,
		0x703F48AA1F31FB11ULL,
		0x4B122BAEC13160DBULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 232 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20963407E8B94543ULL,
		0x1C505B19FD72CD66ULL,
		0x502EFF1182AB7FB5ULL,
		0xFC04578DDFE69B91ULL,
		0xEABCE1B76830DB32ULL,
		0x1635BE42AA86DA58ULL,
		0xDA52540E251AADE1ULL,
		0x4549877A7FD29380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD569884004663D00ULL,
		0x56704D522E402EDDULL,
		0x24AFA6152323758FULL,
		0x7A03CD955A5358DBULL,
		0x4D284669FCBEF92FULL,
		0x64C340FA83FF9989ULL,
		0x37AABD03BAAF7F3AULL,
		0xCD54FA29A3F1C4A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5FFBC47ECDF7843ULL,
		0x4A20164BD332E3BBULL,
		0x74815904A1880A3AULL,
		0x86079A1885B5C34AULL,
		0xA794A7DE948E221DULL,
		0x72F6FEB8297943D1ULL,
		0xEDF8E90D9FB5D2DBULL,
		0x881D7D53DC235728ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 233 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8BFD3F7320F2CC2ULL,
		0xA8E538D6B055B5BCULL,
		0x62919A81FEDA7626ULL,
		0x55A68DAA0486B321ULL,
		0xB43AA2E57546D8AFULL,
		0xED66142483224C3DULL,
		0x23C22634C527D215ULL,
		0x5560DFDFE194D01EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6C714B194CD5BADULL,
		0x59E9CA6E9FB47B64ULL,
		0x172851F8E23CCA9CULL,
		0x4BE22871D05E103CULL,
		0xB407B8E8AA8F948DULL,
		0xADDE30AF006178B7ULL,
		0x5AEB5E4FCEC64530ULL,
		0x955526E3D8C80E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E78C746A6C2776FULL,
		0xF10CF2B82FE1CED8ULL,
		0x75B9CB791CE6BCBAULL,
		0x1E44A5DBD4D8A31DULL,
		0x003D1A0DDFC94C22ULL,
		0x40B8248B8343348AULL,
		0x7929787B0BE19725ULL,
		0xC035F93C395CDE91ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 234 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F53A97974254CD4ULL,
		0xA51F77B15A220CC9ULL,
		0x621DA4D0E805C4E6ULL,
		0x2DD52515BC261434ULL,
		0x2C7EF83A7513B78CULL,
		0x833CF183B1BC02EEULL,
		0xB8B30E0A68E93351ULL,
		0x1571AE4DDA9CBD4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D6DC1F790B48109ULL,
		0x9C763316257907E6ULL,
		0x648975DFCA54DBAFULL,
		0x7DB6701883E63DE9ULL,
		0x40B418E58310E7DDULL,
		0x929081422954E5C7ULL,
		0xDE72515FE3A506B9ULL,
		0xAC2179BFA5DC5C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x123E688EE491CDDDULL,
		0x396944A77F5B0B2FULL,
		0x0694D10F22511F49ULL,
		0x5063550D3FC029DDULL,
		0x6CCAE0DFF6035051ULL,
		0x11AC70C198E8E729ULL,
		0x66C15F558B4C35E8ULL,
		0xB950D7F27F40E169ULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 235 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0E0CA49C9AC855FULL,
		0xB2F7BABF1BF71C54ULL,
		0x35416D6076358B66ULL,
		0x54E3DDFC2B113650ULL,
		0x04C5CB56E338B0D9ULL,
		0x4104134DB1A426ECULL,
		0x2E550E64FB9D202BULL,
		0x0DEECAE7B61BC55FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AFA4DF5A70A60E0ULL,
		0x1B9F69C9CBE2B836ULL,
		0x7E9B08E08CF5BABFULL,
		0xD3B99DB4F52398ACULL,
		0xD8B17C5D32F286F0ULL,
		0xBAE2A74141D89F75ULL,
		0xABF623F13327944AULL,
		0xE8F93F655F4B134BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A1A87BC6EA6E5BFULL,
		0xA968D376D015A462ULL,
		0x4BDA6580FAC031D9ULL,
		0x875A4048DE32AEFCULL,
		0xDC74B70BD1CA3629ULL,
		0xFBE6B40CF07CB999ULL,
		0x85A32D95C8BAB461ULL,
		0xE517F582E950D614ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 236 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4604F0BE579AEDB4ULL,
		0x5EA210A60F53D3DBULL,
		0xB69525E610A0158EULL,
		0xF8742C7165D82771ULL,
		0x9FAA00CD561E7D4CULL,
		0x37ADB1BB1D068AF5ULL,
		0x63EC6EE5DEB552E0ULL,
		0x16456C1B794DC1CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE58FD40C39CCC338ULL,
		0x9BB5E03412FF74D4ULL,
		0xCFF5BEA0EF887218ULL,
		0x8E453BA4BDA225F9ULL,
		0xA7B2D194ED204BD2ULL,
		0x4D30B8DF839C823EULL,
		0xD0B13A6226C46E88ULL,
		0x8D87D22BC8B11037ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA38B24B26E562E8CULL,
		0xC517F0921DACA70FULL,
		0x79609B46FF286796ULL,
		0x763117D5D87A0288ULL,
		0x3818D159BB3E369EULL,
		0x7A9D09649E9A08CBULL,
		0xB35D5487F8713C68ULL,
		0x9BC2BE30B1FCD1F9ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 237 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E49893F66FA67EBULL,
		0x9D4AB57BB8844132ULL,
		0x1D5CC38DD772C049ULL,
		0x904F2121C9D4FA33ULL,
		0x681490929C9923A4ULL,
		0x1BBCAA73CFC29237ULL,
		0xFCE37BF3A86CAF6BULL,
		0xF535130E63F0F7BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DFA26F6C8DACC24ULL,
		0x6F38CBD1701DEB7BULL,
		0xC7894CA6322A62A4ULL,
		0xA8F48F61A06C1714ULL,
		0x8934992BE793C93BULL,
		0x34F3A07382DC6D61ULL,
		0x8F1D2F53A3531507ULL,
		0xAAA055C0B137FB06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43B3AFC9AE20ABCFULL,
		0xF2727EAAC899AA49ULL,
		0xDAD58F2BE558A2EDULL,
		0x38BBAE4069B8ED27ULL,
		0xE12009B97B0AEA9FULL,
		0x2F4F0A004D1EFF56ULL,
		0x73FE54A00B3FBA6CULL,
		0x5F9546CED2C70CBCULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 238 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFAD46EC1AA5A513ULL,
		0x8F3E43C59487E0F2ULL,
		0x33B9F9E4BFF72611ULL,
		0xD56576654F40842FULL,
		0x1EBE8AE5C185F133ULL,
		0x6D056B24550B19F9ULL,
		0xD2B64E242352B27FULL,
		0x3DFE4C1E578894C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D69E6AF0D486FEULL,
		0xFEF95E178C4DF01CULL,
		0x350F704A3159AA65ULL,
		0xC9ED342B2DA1EA44ULL,
		0xE400A73C22E795F2ULL,
		0x5AA7B1B7843770AFULL,
		0x1AFEC6094C6F1E32ULL,
		0x6A1CA304FE93AABBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF7BD886EA7123EDULL,
		0x71C71DD218CA10EEULL,
		0x06B689AE8EAE8C74ULL,
		0x1C88424E62E16E6BULL,
		0xFABE2DD9E36264C1ULL,
		0x37A2DA93D13C6956ULL,
		0xC848882D6F3DAC4DULL,
		0x57E2EF1AA91B3E73ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 239 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9CDEE188D9152637ULL,
		0xD3E29F1BD3F9635CULL,
		0x555290D69FA242A9ULL,
		0xF197B7DF3679655EULL,
		0x63E5D8A1270C8828ULL,
		0xD68B3BB6B9B9D206ULL,
		0x91FF92865BF08DD9ULL,
		0x35BA0FE7FBA44226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAA5472A474E92AULL,
		0xBA477D41A02706FDULL,
		0xD10457216BCD1C59ULL,
		0xDA61581E8EE78D20ULL,
		0x80B1A428D188AEA1ULL,
		0xC8FB495F9AD6E16EULL,
		0xABDACC1B48DE86A8ULL,
		0xEB2FDC26A6487AF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2074B5FA7D61CF1DULL,
		0x69A5E25A73DE65A1ULL,
		0x8456C7F7F46F5EF0ULL,
		0x2BF6EFC1B89EE87EULL,
		0xE3547C89F6842689ULL,
		0x1E7072E9236F3368ULL,
		0x3A255E9D132E0B71ULL,
		0xDE95D3C15DEC38D3ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 240 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA2F18D365AE2A16ULL,
		0x1EE8E4675AB5BEE9ULL,
		0x44C13D57A26FC948ULL,
		0x7E94161B43015432ULL,
		0x8DDA28920D31ACA5ULL,
		0x6E0ACFE90A7F35FEULL,
		0x21125F7A67140859ULL,
		0x6E70D3E8A1E3BCD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD321A4CB93847F8ULL,
		0xC08C096D255E7B4CULL,
		0x30472E21E3C06385ULL,
		0x3D2E453231180ADEULL,
		0x9BED1E7549DC576BULL,
		0xED4FA88C06491F5BULL,
		0x22076B1ECA6568DCULL,
		0x91ECFFCDD5349474ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x671D029FDC966DEEULL,
		0xDE64ED0A7FEBC5A5ULL,
		0x7486137641AFAACDULL,
		0x43BA532972195EECULL,
		0x163736E744EDFBCEULL,
		0x834567650C362AA5ULL,
		0x03153464AD716085ULL,
		0xFF9C2C2574D728ADULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 241 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CC211F28A36EC4AULL,
		0x43D2B2C89F764AE2ULL,
		0xF8341DAC03EC21ADULL,
		0x50F5FF412CA958FBULL,
		0x46E37DFBD500DD07ULL,
		0xE51861C902B6812BULL,
		0x2A1CB66DC2A4CC2EULL,
		0xE1B48688B59A3B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7198F90F36FE0179ULL,
		0x917E3E2AD92B61EDULL,
		0x4321CBBFAF9CF9A0ULL,
		0x846E6D8A91251B15ULL,
		0xA323D1CE3C4539C4ULL,
		0xCFC039D7E66AEEE9ULL,
		0x63C101B017FDF1A9ULL,
		0xBB95FCC9E30F3D00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D5AE8FDBCC8ED33ULL,
		0xD2AC8CE2465D2B0FULL,
		0xBB15D613AC70D80DULL,
		0xD49B92CBBD8C43EEULL,
		0xE5C0AC35E945E4C3ULL,
		0x2AD8581EE4DC6FC2ULL,
		0x49DDB7DDD5593D87ULL,
		0x5A217A415695069EULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 242 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1D7E0D3B5D047BFULL,
		0xBB73F9394D2A2D80ULL,
		0xCFA1D446559A4C43ULL,
		0xCF6E98CEE4B24655ULL,
		0x8D2BC1A653B1517CULL,
		0x57E50A43EB620B33ULL,
		0x453CC76E280E1D35ULL,
		0xA1E167951FCD2C00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C8549720D7E3F32ULL,
		0xAEF714290430B234ULL,
		0x36482F50BDF60635ULL,
		0xCCF49AB1E4DAAC80ULL,
		0xF9EE0CC0195D2108ULL,
		0x93987D39B45FF846ULL,
		0xCC253CEF0E4B4DE3ULL,
		0x7CD4258F2A80C09DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD52A9A1B8AE788DULL,
		0x1584ED10491A9FB4ULL,
		0xF9E9FB16E86C4A76ULL,
		0x039A027F0068EAD5ULL,
		0x74C5CD664AEC7074ULL,
		0xC47D777A5F3DF375ULL,
		0x8919FB81264550D6ULL,
		0xDD35421A354DEC9DULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 243 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x852E42D8704DE9E6ULL,
		0x7B1B89E9E9DFA754ULL,
		0x1E65F60E15D5D1E4ULL,
		0x7F962846E7BBE7A1ULL,
		0xE1CDE694BA9F0819ULL,
		0x9D7D65CC645E411BULL,
		0x772110C9EF603AF0ULL,
		0xB3837954F76C7768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02CF399999FA58FBULL,
		0x5BB52833F84E4790ULL,
		0x89AC29B5EB2D60F9ULL,
		0xDCD25E8C1D463A13ULL,
		0x39C794F29388533EULL,
		0x50ACCD0EAB1F3418ULL,
		0x2DD86D78EDCB12E9ULL,
		0x1B790F9ACAD5AD1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87E17B41E9B7B11DULL,
		0x20AEA1DA1191E0C4ULL,
		0x97C9DFBBFEF8B11DULL,
		0xA34476CAFAFDDDB2ULL,
		0xD80A726629175B27ULL,
		0xCDD1A8C2CF417503ULL,
		0x5AF97DB102AB2819ULL,
		0xA8FA76CE3DB9DA77ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 244 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98B2B3D3403D02D3ULL,
		0x5B93F11E1414D6FEULL,
		0xE1A342364D281DA1ULL,
		0xCEA74AC6203E1FF1ULL,
		0x6FC2142CDF0719A5ULL,
		0x3D6B3144904D0772ULL,
		0xD898507950215DAAULL,
		0x74F2B9FB57F44BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE0D08CBA27AB557ULL,
		0x1F41F429B84D3D6AULL,
		0x0983D8CA4B29B9F9ULL,
		0x147E7AB2B026C915ULL,
		0x04CCC60120EA79C8ULL,
		0xC5EFDA474E3C18E0ULL,
		0x7D374951A951E016ULL,
		0xA675F791ECABA3B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56BFBB18E247B784ULL,
		0x44D20537AC59EB94ULL,
		0xE8209AFC0601A458ULL,
		0xDAD930749018D6E4ULL,
		0x6B0ED22DFFED606DULL,
		0xF884EB03DE711F92ULL,
		0xA5AF1928F970BDBCULL,
		0xD2874E6ABB5FE81EULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 245 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15ED721DAF34C658ULL,
		0xCB879B10D1645467ULL,
		0xB217A1E475B2EE9FULL,
		0x6F082571651DD985ULL,
		0x792C4085F34C7669ULL,
		0x35A9EB2B23FF1570ULL,
		0x0E5C66B2A7809956ULL,
		0xB3B8D3428FA68339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE050E5B59A0650E2ULL,
		0x3C7657F05662E2ADULL,
		0x1A40F49DE88CF639ULL,
		0x14E8FFF4D974B1FDULL,
		0x0E7D77DB1A8512C3ULL,
		0x3D227ACBEA464549ULL,
		0xEF50FA66DF28F5ABULL,
		0xB22E29E8B1E4125DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5BD97A8353296BAULL,
		0xF7F1CCE08706B6CAULL,
		0xA85755799D3E18A6ULL,
		0x7BE0DA85BC696878ULL,
		0x7751375EE9C964AAULL,
		0x088B91E0C9B95039ULL,
		0xE10C9CD478A86CFDULL,
		0x0196FAAA3E429164ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 246 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A96EFE4EE95CD27ULL,
		0xD63E1D3635C6BB90ULL,
		0x24FA9CE76C131C1FULL,
		0xA201E2D06C9139E7ULL,
		0xAB9A12ED65948C41ULL,
		0x3EE930247208B551ULL,
		0xBCD0B7C6849E3C04ULL,
		0xE06FD7460CC7B2F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5723D1D700FFBB1ULL,
		0xECE801E40407CA31ULL,
		0x497C1EA8B81D44A7ULL,
		0xEC1221024A744806ULL,
		0xEB7DD32B7D895F18ULL,
		0x70A2FDCA6129D984ULL,
		0x57ACDBB587536631ULL,
		0x357D2577C75ADE81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE4D2F99E9A3696ULL,
		0x3AD61CD231C171A1ULL,
		0x6D86824FD40E58B8ULL,
		0x4E13C3D226E571E1ULL,
		0x40E7C1C6181DD359ULL,
		0x4E4BCDEE13216CD5ULL,
		0xEB7C6C7303CD5A35ULL,
		0xD512F231CB9D6C70ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 247 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC28A43DA7B27BE7ULL,
		0x45DC974FBE1692B4ULL,
		0x83EA48D145D896A1ULL,
		0xBC7F4CE3C0FC6502ULL,
		0xD9DB2F545FAEDAFAULL,
		0xE089784E3EDDA7C0ULL,
		0xB448460D1E17FD21ULL,
		0x96B35A645A9BFD0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A847532177775D9ULL,
		0x139F9A7948285A07ULL,
		0x0683D0253F7934CEULL,
		0x19946562748A07BDULL,
		0x18DC12BAD5E26E39ULL,
		0x80DDBD381551192EULL,
		0x07BA5195317FBBD3ULL,
		0xB86B4C61C414701FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6ACD10FB0C50E3EULL,
		0x56430D36F63EC8B3ULL,
		0x856998F47AA1A26FULL,
		0xA5EB2981B47662BFULL,
		0xC1073DEE8A4CB4C3ULL,
		0x6054C5762B8CBEEEULL,
		0xB3F217982F6846F2ULL,
		0x2ED816059E8F8D15ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 248 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEB64F3FF75E7AA0ULL,
		0x5E2B1AD6A32F6A97ULL,
		0x817A285139C77787ULL,
		0x974D5A9CBB606771ULL,
		0xA51A4E05E744F1FEULL,
		0xAD3CBA5E32C1BD3FULL,
		0x16E19B823A5B0137ULL,
		0xD9DBC725F6B85BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30F5FC36984E3877ULL,
		0xAB40789E997550E9ULL,
		0x38EFC3A92D46523CULL,
		0xB17BB58B5B777B93ULL,
		0x20ACD9674FD0E40AULL,
		0xC8A3AC9F5027D852ULL,
		0xC057D590A22D1481ULL,
		0x4DDFB1AB2A48C4F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE43B3096F1042D7ULL,
		0xF56B62483A5A3A7EULL,
		0xB995EBF8148125BBULL,
		0x2636EF17E0171CE2ULL,
		0x85B69762A89415F4ULL,
		0x659F16C162E6656DULL,
		0xD6B64E12987615B6ULL,
		0x9404768EDCF09F5FULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 249 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CB0374F6C5B39EAULL,
		0xB6916CC6A811D8ECULL,
		0xD1509EAE67124D29ULL,
		0x28EB397B9E037F52ULL,
		0x06F71438F23B7A01ULL,
		0x7B2A7EDF7B5AF32BULL,
		0x908D0DF082A597C1ULL,
		0xEE19377D9F885415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A72204AD7118BE2ULL,
		0xE77D210F5A41CBB6ULL,
		0x96837BE0668140C3ULL,
		0xE1F513034E35DAD5ULL,
		0x7B5F4487F4702103ULL,
		0x68205742996BCE82ULL,
		0x77F0E90EF4F4F9E4ULL,
		0xE8212A31FDB9814CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56C21705BB4AB208ULL,
		0x51EC4DC9F250135AULL,
		0x47D3E54E01930DEAULL,
		0xC91E2A78D036A587ULL,
		0x7DA850BF064B5B02ULL,
		0x130A299DE2313DA9ULL,
		0xE77DE4FE76516E25ULL,
		0x06381D4C6231D559ULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 250 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D07D6245E7F1E0DULL,
		0x241147B5959C6D4DULL,
		0xE14937430F8C9CBBULL,
		0x2C22B690DB02CFA8ULL,
		0xF23F3A8112A87B0BULL,
		0x0212105A5231AF54ULL,
		0x89B91F7F9A7F54C2ULL,
		0x0B2FD5F03C2FBE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x470E78A027F1AA3DULL,
		0xC58026B8A5FC8415ULL,
		0xFB3A2371ADA60516ULL,
		0xCC9149CF5578815EULL,
		0xA008F710F1E1B287ULL,
		0xB5BB615037D27315ULL,
		0xA6898CF58EA4443AULL,
		0x5DB04A7C0A32642BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A09AE84798EB430ULL,
		0xE191610D3060E958ULL,
		0x1A731432A22A99ADULL,
		0xE0B3FF5F8E7A4EF6ULL,
		0x5237CD91E349C98CULL,
		0xB7A9710A65E3DC41ULL,
		0x2F30938A14DB10F8ULL,
		0x569F9F8C361DDA36ULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 251 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE00BCBD9AF4D896ULL,
		0xC8459D3D7DE1BA39ULL,
		0x5F0AECAF6AB67F75ULL,
		0xCB6FA0F6EE999E70ULL,
		0xD81F518143C3F2E0ULL,
		0x882409E888EA4321ULL,
		0x393E3B2D670F481DULL,
		0x12768BC9982136E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2EE98D3E86AA26ULL,
		0x91E873FC82465E59ULL,
		0x041C5C4AE57BE652ULL,
		0xCE4CB5BFEC60DDA7ULL,
		0xA3F9A9DE35742B32ULL,
		0xEEAE11CA96B0036FULL,
		0x2C725B497209CE7DULL,
		0x0C6B265D8EFCDEDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE22E5530A47272B0ULL,
		0x59ADEEC1FFA7E460ULL,
		0x5B16B0E58FCD9927ULL,
		0x0523154902F943D7ULL,
		0x7BE6F85F76B7D9D2ULL,
		0x668A18221E5A404EULL,
		0x154C606415068660ULL,
		0x1E1DAD9416DDE836ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 252 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A92F9D9EDEDF76AULL,
		0x896600AF29B91CCCULL,
		0x4A19311616C23D80ULL,
		0x5C5587E6F8B4CE5FULL,
		0xD00D75FA9C543D6CULL,
		0x89A7845B1D1430DAULL,
		0xF138C2EB317912A4ULL,
		0x4780D47FBA3CF170ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68609E530103884ULL,
		0x6A5AF974953C9F1DULL,
		0x9B8188D56DB6FBD7ULL,
		0x6AE2C9DD72F0CDB9ULL,
		0x67C56022820818F3ULL,
		0x0EA3B3646D5B5E2FULL,
		0xCFE204DDE0B0BF43ULL,
		0x34BE80C882C931B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC14F03CDDFDCFEEULL,
		0xE33CF9DBBC8583D1ULL,
		0xD198B9C37B74C657ULL,
		0x36B74E3B8A4403E6ULL,
		0xB7C815D81E5C259FULL,
		0x8704373F704F6EF5ULL,
		0x3EDAC636D1C9ADE7ULL,
		0x733E54B738F5C0C2ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 253 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0793C48DCF24F5B2ULL,
		0xFE78419CD9E5D810ULL,
		0x45399D7A615ECF8FULL,
		0x882826CFFD6D0AE6ULL,
		0xF4D2AA60027907F3ULL,
		0x23D07399E1CF5E86ULL,
		0x964B9D5F19588767ULL,
		0x12B1E421D53EE68AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E4C9733166F9236ULL,
		0xFEC1EBF83E077227ULL,
		0x358BB68C5603EA2AULL,
		0x16068A452800BFEEULL,
		0x7617855774E2011DULL,
		0x8330598A95BD06CFULL,
		0x8BFB2ACFFDE54F1EULL,
		0xE428657DBFB3AA8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69DF53BED94B6784ULL,
		0x00B9AA64E7E2AA37ULL,
		0x70B22BF6375D25A5ULL,
		0x9E2EAC8AD56DB508ULL,
		0x82C52F37769B06EEULL,
		0xA0E02A1374725849ULL,
		0x1DB0B790E4BDC879ULL,
		0xF699815C6A8D4C05ULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 254 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE94FAB116A8ECDE2ULL,
		0x2BEE60ED6D9E198AULL,
		0x0B6BF56312CCE9F3ULL,
		0x8DEB76288B80EE22ULL,
		0x908FB71EFE8A63EDULL,
		0xD0E5A749FDF9A2B8ULL,
		0xB1B93EFA9C85C8EBULL,
		0x17ECE9C574E4F9CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12C26A086D81E44EULL,
		0x702DBFBAA2BF49AFULL,
		0x8097D362C2AF3669ULL,
		0x4F92493FDEFAA90BULL,
		0x46E4DA6D7415C53AULL,
		0x711FF9609D1F04C6ULL,
		0xF055150ADC45286DULL,
		0xA9BF24BB093A4BC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB8DC119070F29ACULL,
		0x5BC3DF57CF215025ULL,
		0x8BFC2601D063DF9AULL,
		0xC2793F17557A4729ULL,
		0xD66B6D738A9FA6D7ULL,
		0xA1FA5E2960E6A67EULL,
		0x41EC2BF040C0E086ULL,
		0xBE53CD7E7DDEB208ULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 255 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7A1D55C969AE5F1ULL,
		0x29E9340576E8549FULL,
		0x95B81989A93A80FFULL,
		0xF81D13D7290E527BULL,
		0x92619F39B024BD7EULL,
		0x568AC445A6BA4E5DULL,
		0x265FEB5D456A339FULL,
		0xFCFF8D7E241C6E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76F8B279F3116AE8ULL,
		0x9AF88CC0D3438784ULL,
		0x485D8F29A7E56D13ULL,
		0xBB248648B5ECBA4AULL,
		0xA1636ECCA5744BD5ULL,
		0x6A1CFBD6521C9233ULL,
		0x5B9E7032259033EEULL,
		0xAB3ED5E9C074AFA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1596725658B8F19ULL,
		0xB311B8C5A5ABD31BULL,
		0xDDE596A00EDFEDECULL,
		0x4339959F9CE2E831ULL,
		0x3302F1F51550F6ABULL,
		0x3C963F93F4A6DC6EULL,
		0x7DC19B6F60FA0071ULL,
		0x57C15897E468C1DDULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 256 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F746EB477B7B2CULL,
		0xF5F947FF0A115774ULL,
		0xDBF110551EEA597EULL,
		0xE271A5F51D3B323FULL,
		0x4FC10E0E2EA81425ULL,
		0xC95D2B048FA2D4E9ULL,
		0xEEC1B6C9DC736177ULL,
		0x48C87A79CB19FAF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8C3FDD39AAE1AFULL,
		0x3AA25A4D770C706CULL,
		0xB6D88533F890521FULL,
		0x00222EE326090A02ULL,
		0x378A10D0CE59F814ULL,
		0xA5FDFE917534457DULL,
		0x49E8DC81A249152EULL,
		0xDF6F888BD6E8DF11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C7B79367ED19A83ULL,
		0xCF5B1DB27D1D2718ULL,
		0x6D299566E67A0B61ULL,
		0xE2538B163B32383DULL,
		0x784B1EDEE0F1EC31ULL,
		0x6CA0D595FA969194ULL,
		0xA7296A487E3A7459ULL,
		0x97A7F2F21DF125E7ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 257 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB58235FC96BDA199ULL,
		0xA12ECA077647952EULL,
		0x466EF2BF2547F6DFULL,
		0xF9904C93B8D9B260ULL,
		0x9C9C586DFB27E0A2ULL,
		0xA6E79C313C3FC0B9ULL,
		0xCAD5C7412586AC25ULL,
		0x95E63F3099C78452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B01153CE24D3DBULL,
		0x692E91355668F224ULL,
		0xD7865BFD63A2CB8EULL,
		0xB610B7D2B5B00363ULL,
		0x978CEE37E110E697ULL,
		0xAC82F04A918D0AB3ULL,
		0xF97648A93C7E3840ULL,
		0xF18C165546C4047FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC3224AF58997242ULL,
		0xC8005B32202F670AULL,
		0x91E8A94246E53D51ULL,
		0x4F80FB410D69B103ULL,
		0x0B10B65A1A370635ULL,
		0x0A656C7BADB2CA0AULL,
		0x33A38FE819F89465ULL,
		0x646A2965DF03802DULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 258 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA87DC4FFA21FF13FULL,
		0x582C17F961636895ULL,
		0xD40829D59D0D6ABAULL,
		0x7EA0115C8F28CE87ULL,
		0xB7F59D3391B24856ULL,
		0xEEF1E231C8D93614ULL,
		0x28C1112D42A53AF4ULL,
		0x00C9C555FBF7DC54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7BDE25E1B1B8872ULL,
		0x7B402CFE1C4D8576ULL,
		0xB0CF03D2125FD850ULL,
		0x0ABDC5961CF5F9E6ULL,
		0xDC19E2C445456D79ULL,
		0x9328F33E1A19D7E9ULL,
		0x968EF98E511D8712ULL,
		0xA15EB77327D32291ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FC026A1B904794DULL,
		0x236C3B077D2EEDE3ULL,
		0x64C72A078F52B2EAULL,
		0x741DD4CA93DD3761ULL,
		0x6BEC7FF7D4F7252FULL,
		0x7DD9110FD2C0E1FDULL,
		0xBE4FE8A313B8BDE6ULL,
		0xA1977226DC24FEC5ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 259 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A50558F7A26F239ULL,
		0x987341D82CE4F396ULL,
		0xA14CEDFD5508878FULL,
		0xDDDB87AE83AA4196ULL,
		0xF19C2E714A60F20AULL,
		0xC469B1A5253D8905ULL,
		0x60717FF02AE6F43FULL,
		0xD9A49924BCA1632CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DAC5E26B36B00DULL,
		0xAA646F79877E15A7ULL,
		0x064FF071792240B6ULL,
		0x23B3B2AB646F93A6ULL,
		0xC05702E00E48041CULL,
		0x3B288E3C7C904BFDULL,
		0xC7BD63CFC0992FEAULL,
		0x1343DAE430A4C5DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x238A906D11104234ULL,
		0x32172EA1AB9AE631ULL,
		0xA7031D8C2C2AC739ULL,
		0xFE683505E7C5D230ULL,
		0x31CB2C914428F616ULL,
		0xFF413F9959ADC2F8ULL,
		0xA7CC1C3FEA7FDBD5ULL,
		0xCAE743C08C05A6F3ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 260 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5AAA1A6733F36359ULL,
		0x2F54481D0F2C1642ULL,
		0xEAC226DC38A38310ULL,
		0xDF3A52D17B6179A6ULL,
		0xB66B8703FF23DB72ULL,
		0x93DF6AB12ADD4714ULL,
		0x19FE891F0F2C6090ULL,
		0xEA07185A61F6B602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09DD5FA41ADA879AULL,
		0xD84331DF50627DC2ULL,
		0x426790976D7ECE6FULL,
		0xADE89133378C7115ULL,
		0x661D58636DAFF32DULL,
		0x6574AFB25E666093ULL,
		0x6C53DA817443E337ULL,
		0x12FE96725976FC60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x537745C32929E4C3ULL,
		0xF71779C25F4E6B80ULL,
		0xA8A5B64B55DD4D7FULL,
		0x72D2C3E24CED08B3ULL,
		0xD076DF60928C285FULL,
		0xF6ABC50374BB2787ULL,
		0x75AD539E7B6F83A7ULL,
		0xF8F98E2838804A62ULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 261 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31DF6B07FC80E8ACULL,
		0xDEBE6D440A9FBBE3ULL,
		0xFE9C22ADB7B82CD7ULL,
		0xB75C9BF47D675747ULL,
		0x5451CEAF5F968816ULL,
		0xCC96558807C7AD39ULL,
		0x379E42001E654804ULL,
		0xD617FFEA9D165423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028BCBB0C106384FULL,
		0x74C7A7CDCC5BB8D3ULL,
		0xE6681B6664CC3895ULL,
		0x33CC19B051B2525EULL,
		0x343C06C63D1CE13FULL,
		0x85D7BF51BD8143AFULL,
		0x709FF69F49C54FBCULL,
		0xF3F6D1BE5FDC0C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3354A0B73D86D0E3ULL,
		0xAA79CA89C6C40330ULL,
		0x18F439CBD3741442ULL,
		0x849082442CD50519ULL,
		0x606DC869628A6929ULL,
		0x4941EAD9BA46EE96ULL,
		0x4701B49F57A007B8ULL,
		0x25E12E54C2CA5845ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 262 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x200654156059A2E0ULL,
		0x79EB9A8968EC3B6CULL,
		0xA050466A0EFDC2EAULL,
		0xD5C979AC1C17D9F5ULL,
		0x5C8DD1F3DB34CAFEULL,
		0xC610EEC2653198FAULL,
		0xA7DD065A8E086650ULL,
		0xB2CE7C859D011233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x989632418D34B48EULL,
		0x927049F15C1CD258ULL,
		0xB87D43ACFE00F805ULL,
		0x5AC039CC1CD3FE5BULL,
		0xC2588AA166E87237ULL,
		0xDB53C9811A79DEDFULL,
		0xFBD491D8FBE19EACULL,
		0xF0D638BDABEFD939ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8906654ED6D166EULL,
		0xEB9BD37834F0E934ULL,
		0x182D05C6F0FD3AEFULL,
		0x8F09406000C427AEULL,
		0x9ED55B52BDDCB8C9ULL,
		0x1D4327437F484625ULL,
		0x5C09978275E9F8FCULL,
		0x4218443836EECB0AULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 263 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44A9F290613BAA8EULL,
		0x582C0829579B402FULL,
		0x3678164F9C5619ECULL,
		0x4A94D7C699A9D17EULL,
		0xADC451E605D0EA5CULL,
		0xB4ABE2A8780C86B8ULL,
		0x710D995EA8EBD00AULL,
		0x98CF197FFFE2F309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF47D6DC1D5D9D11ULL,
		0x7DCB3A4B3A523CEBULL,
		0x2179C6C7E315659DULL,
		0x6F0F2C83AC32BA9EULL,
		0x5F3FFDBF55191A64ULL,
		0xC12B379984589572ULL,
		0x1290673DB41CE393ULL,
		0x1BF625E5E1DA7972ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBEE244C7C66379FULL,
		0x25E732626DC97CC4ULL,
		0x1701D0887F437C71ULL,
		0x259BFB45359B6BE0ULL,
		0xF2FBAC5950C9F038ULL,
		0x7580D531FC5413CAULL,
		0x639DFE631CF73399ULL,
		0x83393C9A1E388A7BULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 264 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6DA22E1757BCB48ULL,
		0x1C573A7A9944E9F4ULL,
		0xD0E18B093189D12BULL,
		0xC1DE8B8054AA81F0ULL,
		0xF69CDD865DEB0E0EULL,
		0xA6FD0275B4D8E75FULL,
		0x663BCBFC769ACCE2ULL,
		0x629C5B2032E65737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7B77B181DE5C5F7ULL,
		0x5629D0E17E345835ULL,
		0x9539C758EE09824DULL,
		0x37FD020DBD5362FAULL,
		0x81A4C161A2735867ULL,
		0x521A6AC78473AD63ULL,
		0x3B5591247DAB8F6CULL,
		0x5E2AF66D5F5DDA6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x316D59F9689E0EBFULL,
		0x4A7EEA9BE770B1C1ULL,
		0x45D84C51DF805366ULL,
		0xF623898DE9F9E30AULL,
		0x77381CE7FF985669ULL,
		0xF4E768B230AB4A3CULL,
		0x5D6E5AD80B31438EULL,
		0x3CB6AD4D6DBB8D5CULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 265 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x035803C23C4C5F77ULL,
		0xFDB05110B60C3283ULL,
		0xEEC160ADEA7C8C39ULL,
		0xD907E909788C867FULL,
		0xF13A4FA6A8B04890ULL,
		0xD899D6250EC17745ULL,
		0xCC2021387011A093ULL,
		0xC43815DBA4A15F9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A0B625298B5E099ULL,
		0xB45991A68EE72B8BULL,
		0x3E650C5D40D30860ULL,
		0x41BCCF3A4BE904B5ULL,
		0x2E202033A9D03950ULL,
		0x25D0130D0529E975ULL,
		0xBBEA577537B87D9CULL,
		0xB841F755B82FAE58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59536190A4F9BFEEULL,
		0x49E9C0B638EB1908ULL,
		0xD0A46CF0AAAF8459ULL,
		0x98BB2633336582CAULL,
		0xDF1A6F95016071C0ULL,
		0xFD49C5280BE89E30ULL,
		0x77CA764D47A9DD0FULL,
		0x7C79E28E1C8EF1C5ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 266 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF14C48DEA7D1E4ULL,
		0x6A026B60ABC24872ULL,
		0x9CA0F60A64815580ULL,
		0x349823561726BBC7ULL,
		0xA2E00DEA1C6A9E07ULL,
		0x8DE7EC10FDD55295ULL,
		0x99E87112B9A29B98ULL,
		0xD4681710C7D52D5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x491C6C9B108F92DDULL,
		0x9B004F6293F911E6ULL,
		0xC70D42659A722094ULL,
		0xA25B74A0C6FEB8A1ULL,
		0xD3E982F5DD6002ABULL,
		0x89C0F1ACCAEE31CAULL,
		0xF95EF65888A395DBULL,
		0xFE2C4C0CD2DB7BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26ED20D3CE284339ULL,
		0xF1022402383B5994ULL,
		0x5BADB46FFEF37514ULL,
		0x96C357F6D1D80366ULL,
		0x71098F1FC10A9CACULL,
		0x04271DBC373B635FULL,
		0x60B6874A31010E43ULL,
		0x2A445B1C150E56FAULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 267 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6B3FD1C221EFCE7ULL,
		0x974193FD095B36ADULL,
		0x9919EE09FB7A9B91ULL,
		0x034F05422440CFD2ULL,
		0xEB87CF221C12C527ULL,
		0x4F054DBD54B80A3FULL,
		0x3E8B260C12ED6F96ULL,
		0x1F4E3AF30C2EC0B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F4306C95D66395ULL,
		0xCA49A78C570A31FEULL,
		0xFBE03BB6E5249414ULL,
		0xE7287464C8312EEDULL,
		0xBB321E74D8BD2009ULL,
		0x9128039C66D55A7DULL,
		0x7F225BC27F039DB9ULL,
		0xE6E7D1ACAB75105BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E47CD70B7C89F72ULL,
		0x5D0834715E510753ULL,
		0x62F9D5BF1E5E0F85ULL,
		0xE4677126EC71E13FULL,
		0x50B5D156C4AFE52EULL,
		0xDE2D4E21326D5042ULL,
		0x41A97DCE6DEEF22FULL,
		0xF9A9EB5FA75BD0EBULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 268 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AE16EDF3A4917C2ULL,
		0x3D3F587CB6905287ULL,
		0x46FF4FDCE7F1098CULL,
		0x671D1E81A98CE922ULL,
		0x4A9A885516FB2112ULL,
		0xBD55FB6ABE558E64ULL,
		0xE51E1F377374A1ADULL,
		0x2BFDE91CEAE4B87AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36896AF92C9C6031ULL,
		0xFB3605F577072F9FULL,
		0xCABC218390EA539CULL,
		0x5E2094A9D02A6716ULL,
		0x1A806B2C3825323EULL,
		0x18666BD52843DF50ULL,
		0x96382D7AF68B230BULL,
		0x55B94B79122AD55AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C68042616D577F3ULL,
		0xC6095D89C1977D18ULL,
		0x8C436E5F771B5A10ULL,
		0x393D8A2879A68E34ULL,
		0x501AE3792EDE132CULL,
		0xA53390BF96165134ULL,
		0x7326324D85FF82A6ULL,
		0x7E44A265F8CE6D20ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 269 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD38788637ACE09A9ULL,
		0xEE5B5511F0E1BC5AULL,
		0x4E5F57254A4A24EFULL,
		0x9E0D1850FC5E73DBULL,
		0x3EBBC47BD769E28CULL,
		0x81C57F27A71CC675ULL,
		0x2E1888E831398C67ULL,
		0x3F567F074B83BCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C0AD3AD8068410CULL,
		0x5F434EF69B6708BEULL,
		0xBFB81B4CA7B30B09ULL,
		0x66F97CE2FCFF689EULL,
		0x81DD70F483A3CFDCULL,
		0xAD52CCB73CABC8F0ULL,
		0x2F834EAA6D9A5B99ULL,
		0xF28EC81E90BF896EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF8D5BCEFAA648A5ULL,
		0xB1181BE76B86B4E4ULL,
		0xF1E74C69EDF92FE6ULL,
		0xF8F464B200A11B45ULL,
		0xBF66B48F54CA2D50ULL,
		0x2C97B3909BB70E85ULL,
		0x019BC6425CA3D7FEULL,
		0xCDD8B719DB3C35DDULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 270 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C7BFEE9A891C978ULL,
		0xB237B4B291BD8A42ULL,
		0x1798CF66F74C483FULL,
		0xA8E1CE7E84894FFCULL,
		0x13F2D4D82F95EE74ULL,
		0x6DF6875C3809B5B7ULL,
		0x33ECAED3A46221ADULL,
		0x12647C3595F2553FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75227359B3A75863ULL,
		0x703515EEC3C6912BULL,
		0x07DC41AA7261E563ULL,
		0x76DF60AECAC5F7DEULL,
		0x4583D4BF1C00CE93ULL,
		0x72EC1BBFA3A08751ULL,
		0x2AEFDBE66468B15BULL,
		0xD69EE830F6BF28D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79598DB01B36911BULL,
		0xC202A15C527B1B69ULL,
		0x10448ECC852DAD5CULL,
		0xDE3EAED04E4CB822ULL,
		0x56710067339520E7ULL,
		0x1F1A9CE39BA932E6ULL,
		0x19037535C00A90F6ULL,
		0xC4FA9405634D7DE9ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 271 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDC4A858B044114BULL,
		0xA775514D676B7081ULL,
		0x0CBE675CC9DF72C6ULL,
		0x7D6AE8E411C7A641ULL,
		0x0B92959F8BAAC002ULL,
		0x69BAF7A5F61BAB01ULL,
		0x6F130214AC28D641ULL,
		0x3EDDC9F21211CC2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EDD3EA195DDF7FBULL,
		0x490AC0D423D26788ULL,
		0x511A3747A0184272ULL,
		0x45AA4C9089D0E6EFULL,
		0x8FBC304ED30B2A68ULL,
		0xC82E24443EC2DFDBULL,
		0xCEA558A00CBC417CULL,
		0x010C7F4C96877CEFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x831996F92599E6B0ULL,
		0xEE7F919944B91709ULL,
		0x5DA4501B69C730B4ULL,
		0x38C0A474981740AEULL,
		0x842EA5D158A1EA6AULL,
		0xA194D3E1C8D974DAULL,
		0xA1B65AB4A094973DULL,
		0x3FD1B6BE8496B0C2ULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 272 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE93A6B12259795B6ULL,
		0x78CCC7C31BC7EE67ULL,
		0xED552D97C7AFC8A5ULL,
		0x2E669D4724607796ULL,
		0x25AD4FCB6955A961ULL,
		0x090E8FC1B358CFB1ULL,
		0x453A7872AA522BAEULL,
		0xB1781A7D80920A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E651F18EDE7E3AULL,
		0x9696FCFDF25E27C3ULL,
		0x66E3135D81274ACAULL,
		0xB8F6CC9FAA6C8509ULL,
		0x522479B50636C9AAULL,
		0xD3480B2E8EC06D5AULL,
		0x022FD016A186CEFCULL,
		0xA4990E8B2199E319ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CDC3AE3AB49EB8CULL,
		0xEE5A3B3EE999C9A4ULL,
		0x8BB63ECA4688826FULL,
		0x969051D88E0CF29FULL,
		0x7789367E6F6360CBULL,
		0xDA4684EF3D98A2EBULL,
		0x4715A8640BD4E552ULL,
		0x15E114F6A10BE944ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 273 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFCF64F37649DF04ULL,
		0x1D647641768EEB8BULL,
		0x340C99BF43EFE338ULL,
		0x71FCA2C419924166ULL,
		0x9E57B502FF7D1614ULL,
		0xA3D93018FCC4A92BULL,
		0xF26B3E420E1C5BC4ULL,
		0xCBD249ADA2B4F43FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBB3FF3AA38308EULL,
		0x3BD3BEAA494000D1ULL,
		0x9F7B44274FA20FE1ULL,
		0xB9FC379009B640AFULL,
		0x2BCEE9C71568076BULL,
		0x7268AE0C0F921F23ULL,
		0x5B56AF56A797E6E9ULL,
		0x3C8FDB8E4941BA13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22745B00DC71EF8AULL,
		0x26B7C8EB3FCEEB5AULL,
		0xAB77DD980C4DECD9ULL,
		0xC8009554102401C9ULL,
		0xB5995CC5EA15117FULL,
		0xD1B19E14F356B608ULL,
		0xA93D9114A98BBD2DULL,
		0xF75D9223EBF54E2CULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 274 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC1490979206229BULL,
		0x262E9B43FD3ED150ULL,
		0x67A96F0B4F8E8279ULL,
		0x521F701742E14A71ULL,
		0xD56F22197EFB1252ULL,
		0x4D3703D07CB654A6ULL,
		0xB68F7676D26DE55EULL,
		0x7BDAF579836DCCCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8C66111E3C9194FULL,
		0xE052F2A5E57A73C8ULL,
		0x6C84CA484FDCDB5CULL,
		0xACD4665A06797668ULL,
		0x3D907CBC1BD2962AULL,
		0x0636C2C026B47530ULL,
		0x06CE2CC5FEDDCEEAULL,
		0x9792058B7EEFD10DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54D2F18671CF3BD4ULL,
		0xC67C69E61844A298ULL,
		0x0B2DA54300525925ULL,
		0xFECB164D44983C19ULL,
		0xE8FF5EA565298478ULL,
		0x4B01C1105A022196ULL,
		0xB0415AB32CB02BB4ULL,
		0xEC48F0F2FD821DC0ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 275 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8CEE405EA31D6AEEULL,
		0x37DB8E53F9FC9ED5ULL,
		0x1D5A5FAD5FA0E890ULL,
		0xE96B1B6E0238D6F4ULL,
		0xE9004212C0E3E811ULL,
		0x1E491EFB1DA8D18DULL,
		0x3929ACA666E8A563ULL,
		0xBDB8CEAE6CAE2C4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5F8EA5DD9D4695ULL,
		0xC0D590080C335DEFULL,
		0xE7993809EEC612B7ULL,
		0xC94ADEBA0CA35BADULL,
		0xD7CCA866F9B40B77ULL,
		0x1FD4A837FA479090ULL,
		0x2066E008AF4129E9ULL,
		0xB752C09684D79D55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3B1CEFB7E802C7BULL,
		0xF70E1E5BF5CFC33AULL,
		0xFAC367A4B166FA27ULL,
		0x2021C5D40E9B8D59ULL,
		0x3ECCEA743957E366ULL,
		0x019DB6CCE7EF411DULL,
		0x194F4CAEC9A98C8AULL,
		0x0AEA0E38E879B11BULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 276 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A40651EC814D267ULL,
		0xDEC03A7744597C33ULL,
		0xEF428F3B87E8C87AULL,
		0x64BB7F5B0637B5F6ULL,
		0x2A4DB30E4AC3C152ULL,
		0x94E5D4F8B2B28108ULL,
		0x1032962BC011806CULL,
		0xBD0260F258D4C2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16F4B976066B239ULL,
		0xD7971FFD7D780FAAULL,
		0x9C6CD2D74C133270ULL,
		0x43CAE5E2A1FE55E2ULL,
		0x0427DCF3BA33A042ULL,
		0x70C9F0A49B1AF95EULL,
		0xAFB015E713BAD397ULL,
		0xDDFC132986AC2E65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB2F2E89A872605EULL,
		0x0957258A39217399ULL,
		0x732E5DECCBFBFA0AULL,
		0x27719AB9A7C9E014ULL,
		0x2E6A6FFDF0F06110ULL,
		0xE42C245C29A87856ULL,
		0xBF8283CCD3AB53FBULL,
		0x60FE73DBDE78ECAEULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 277 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40CEA32D9899D87AULL,
		0x25B1DA0317693C11ULL,
		0xC736A927C6B82B1EULL,
		0xF005E70D5AC7036CULL,
		0x5C71DAAA7051C67EULL,
		0xC377BB23F8CD3A09ULL,
		0xF11AFC94F8E4E867ULL,
		0xD4E3BD5161E0498BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C651F354D4FAB42ULL,
		0xA888715DFF91EE78ULL,
		0x7271BAA0FEDE9F44ULL,
		0x9CF93111965A160FULL,
		0xC47EABA81A77AF27ULL,
		0x3E4D666E37BCDD70ULL,
		0x7E549C711F63FF80ULL,
		0x3A7A4C855AE18ACFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CABBC18D5D67338ULL,
		0x8D39AB5EE8F8D269ULL,
		0xB54713873866B45AULL,
		0x6CFCD61CCC9D1563ULL,
		0x980F71026A266959ULL,
		0xFD3ADD4DCF71E779ULL,
		0x8F4E60E5E78717E7ULL,
		0xEE99F1D43B01C344ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 278 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21A0E563A82D5ECEULL,
		0xA1B8EA9748E00A71ULL,
		0xB84FACE5F50169D9ULL,
		0x2667FF3C2A9828A3ULL,
		0x9D3DC14134652642ULL,
		0xB686A6EA266C3D96ULL,
		0xACFE8403137ED4F2ULL,
		0x5DB5B07E8FB6C8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9388B700B7F5442ULL,
		0x6658933C824D2434ULL,
		0xD19236A62A3A2CCFULL,
		0x1F643964A47B17E4ULL,
		0xD12E2075EA91152EULL,
		0x62248DA95A4453BDULL,
		0xCF1691E588ADFB7CULL,
		0x2DB52C5E81CF10DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8986E13A3520A8CULL,
		0xC7E079ABCAAD2E45ULL,
		0x69DD9A43DF3B4516ULL,
		0x3903C6588EE33F47ULL,
		0x4C13E134DEF4336CULL,
		0xD4A22B437C286E2BULL,
		0x63E815E69BD32F8EULL,
		0x70009C200E79D86EULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 279 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB2BB4F1D15088DEULL,
		0xD3E9BAD66B1E3F38ULL,
		0x6E773B159DD5F658ULL,
		0x27F292F5AEE61EAAULL,
		0xD7147567704C5BA2ULL,
		0x312A4198D3300AA0ULL,
		0x0345FACDD163D3E8ULL,
		0x8C10DCAC07186E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32C4C36C8539947ULL,
		0x08BE00775AFA7179ULL,
		0x902C0429D80C4DBDULL,
		0x8DED426C7E5144CAULL,
		0xCF78725D3558D6BFULL,
		0x4F7B4BDDBFC27BF1ULL,
		0x915BD50A66716B10ULL,
		0xE7DD03B5B4A79778ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4807F8C719031199ULL,
		0xDB57BAA131E44E41ULL,
		0xFE5B3F3C45D9BBE5ULL,
		0xAA1FD099D0B75A60ULL,
		0x186C073A45148D1DULL,
		0x7E510A456CF27151ULL,
		0x921E2FC7B712B8F8ULL,
		0x6BCDDF19B3BFF926ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 280 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41D96E2DFCB71599ULL,
		0xDFDD06B0DFCE1730ULL,
		0xAD2FDE98C48272EEULL,
		0x9D5CE47EE135F178ULL,
		0x62EEF1F594B4BD2AULL,
		0xB22806DBBD900621ULL,
		0x674F02DE2074EA49ULL,
		0xADCAACBED8B8A3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDCFAB0A378735C8ULL,
		0xAC6F888E55E88EDFULL,
		0x702CAF0509289D9BULL,
		0x6038C2773B0DCD4CULL,
		0x31507DBB870DE327ULL,
		0xED65DBE6550636B8ULL,
		0x30C870C6A66D61D5ULL,
		0x3C4810D0C6805FC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC16C527CB302051ULL,
		0x73B28E3E8A2699EFULL,
		0xDD03719DCDAAEF75ULL,
		0xFD642609DA383C34ULL,
		0x53BE8C4E13B95E0DULL,
		0x5F4DDD3DE8963099ULL,
		0x5787721886198B9CULL,
		0x9182BC6E1E38FC6EULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 281 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44EF2DDAD17AF99DULL,
		0x09117D0DFBECDF61ULL,
		0x8133E1CAC81DA1EBULL,
		0x7CA130C74698F90FULL,
		0xA6C50196BC0AD90EULL,
		0x2522FB0284578397ULL,
		0xB5762F5E62AED6B5ULL,
		0x9989C2152EB9C81BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024E89EE8C8486B7ULL,
		0xC99A8631B77CCDA0ULL,
		0xE5F7A093F8B94FB1ULL,
		0x7C288578284E8604ULL,
		0x3A2B016E7551CE1CULL,
		0x8A2531778A38848BULL,
		0x70FF539283558D9BULL,
		0x0307EABD24133A9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46A1A4345DFE7F2AULL,
		0xC08BFB3C4C9012C1ULL,
		0x64C4415930A4EE5AULL,
		0x0089B5BF6ED67F0BULL,
		0x9CEE00F8C95B1712ULL,
		0xAF07CA750E6F071CULL,
		0xC5897CCCE1FB5B2EULL,
		0x9A8E28A80AAAF280ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 282 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6133914C7040F85ULL,
		0x38046EAA823E9A5FULL,
		0x69E1EAEC2AA693D5ULL,
		0x56EF9E45EABCF3B4ULL,
		0x78B1C17FDB96CB8CULL,
		0x51A9DC201FF2796BULL,
		0x7D9F40E19546B69CULL,
		0x787A9EEE629A238BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAADBE7778AA6C851ULL,
		0x941857C8A97B1946ULL,
		0x3ADAEEDFCF45EB0BULL,
		0xC21424176060771DULL,
		0xDB74FB8C69042325ULL,
		0x207FCC1DB0DD479EULL,
		0x1820D23175E0F26AULL,
		0x3D84D1FBA23849EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CC8DE634DA2C7D4ULL,
		0xAC1C39622B458319ULL,
		0x533B0433E5E378DEULL,
		0x94FBBA528ADC84A9ULL,
		0xA3C53AF3B292E8A9ULL,
		0x71D6103DAF2F3EF5ULL,
		0x65BF92D0E0A644F6ULL,
		0x45FE4F15C0A26A61ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 283 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E238B17A6F18B22ULL,
		0x3E1FC000B62B3E14ULL,
		0x580B8227FAEAA638ULL,
		0xB2B9DF7608CFC454ULL,
		0xECA519292CFC83A5ULL,
		0x10CA959A38C2BF6CULL,
		0x1A511FFBC839FE1FULL,
		0x86CEAA19590D6747ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6265E2F5AA171780ULL,
		0xC48805E6BC6D5297ULL,
		0xF26E87CB9CBE2672ULL,
		0x5B69E61493B70ECEULL,
		0x0D2FF6EBC09548F0ULL,
		0x7DC7A81D4951D768ULL,
		0x8F1D65516FC633B2ULL,
		0xCD0924FC26FE852AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C4669E20CE69CA2ULL,
		0xFA97C5E60A466C83ULL,
		0xAA6505EC6654804AULL,
		0xE9D039629B78CA9AULL,
		0xE18AEFC2EC69CB55ULL,
		0x6D0D3D8771936804ULL,
		0x954C7AAAA7FFCDADULL,
		0x4BC78EE57FF3E26DULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 284 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x670D8C98BE4B7CEAULL,
		0x6141BE62351F662DULL,
		0x41B433B8D22F731EULL,
		0x3EEA64FEEEAEC6F4ULL,
		0x7A9E25CCBBD4869BULL,
		0x0E6510704882C64CULL,
		0x9EF37D112BD554FBULL,
		0x934C16F60CB3A1E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE07BF3247E244E98ULL,
		0xF320F60A00B37732ULL,
		0xB26F7160A19D39CCULL,
		0xD93C5FAB412E21D9ULL,
		0xB9906F8E57DB2777ULL,
		0x85A78611144A16B5ULL,
		0x6BD17C71E46AA6B5ULL,
		0xA8ABC9610C7C6DC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87767FBCC06F3272ULL,
		0x9261486835AC111FULL,
		0xF3DB42D873B24AD2ULL,
		0xE7D63B55AF80E72DULL,
		0xC30E4A42EC0FA1ECULL,
		0x8BC296615CC8D0F9ULL,
		0xF5220160CFBFF24EULL,
		0x3BE7DF9700CFCC29ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 285 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D5C17B96F6AC31FULL,
		0xD5CBD89D57D770FFULL,
		0xF04D9EBD17A31801ULL,
		0xEF77FA9FBF49F7C1ULL,
		0xB663D642E9AE34C9ULL,
		0xBFED201990063691ULL,
		0x091017E97C3B8407ULL,
		0xD213F386FF12FC24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BFDA37292B63ACULL,
		0xBE1DF74AB6831F0AULL,
		0x38AA8143A318B5E9ULL,
		0xAC27F1CF018554BAULL,
		0xD22C11C8083193AEULL,
		0x7E4BC3A9C8A24628ULL,
		0x7CCCDC8ACC5D81D4ULL,
		0xA2A8D24BE9C76B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FE3CD8E4641A0B3ULL,
		0x6BD62FD7E1546FF5ULL,
		0xC8E71FFEB4BBADE8ULL,
		0x43500B50BECCA37BULL,
		0x644FC78AE19FA767ULL,
		0xC1A6E3B058A470B9ULL,
		0x75DCCB63B06605D3ULL,
		0x70BB21CD16D597B9ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 286 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DA82806ECBF9361ULL,
		0xB776471ACB5749B7ULL,
		0xB9860A9109538D75ULL,
		0xEB9E78BAC31B1D71ULL,
		0xF40575EA9AF2FCF3ULL,
		0x02D1C03CDE1FB060ULL,
		0x1B8BDB8716CFD59FULL,
		0x17D48075234D3D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8CE025FA59A1922ULL,
		0x821FA8B31A890B5CULL,
		0xD492010265C3AC6AULL,
		0xFA7AD9B8562A0413ULL,
		0xF3130C5246379B8EULL,
		0xABBAF898CFE73599ULL,
		0x5B096FDE6CC6A7E5ULL,
		0x733A7532FE563106ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5662A5949258A43ULL,
		0x3569EFA9D1DE42EBULL,
		0x6D140B936C90211FULL,
		0x11E4A10295311962ULL,
		0x071679B8DCC5677DULL,
		0xA96B38A411F885F9ULL,
		0x4082B4597A09727AULL,
		0x64EEF547DD1B0C04ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 287 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94A7806663A00595ULL,
		0xAD1A221C8F0B43C6ULL,
		0x9C6B44A07BFFE6CAULL,
		0xEB95FBB84C226D18ULL,
		0x6E77034C559501A3ULL,
		0x1816B6375B2266C3ULL,
		0x18CE46FCCCAFF8E0ULL,
		0xC25E0A6BF16B1208ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEBAFD7E3DEB46CDULL,
		0x28EC636338069BDDULL,
		0xC4996E2AEEE5FD78ULL,
		0x4BE4367E30A87D9CULL,
		0x3FBC9591F2380B70ULL,
		0x8C91E37838F7139BULL,
		0x17A3A2F9405B6EC1ULL,
		0xB2E3C1B4F75CA110ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A1D7D185E4B4358ULL,
		0x85F6417FB70DD81BULL,
		0x58F22A8A951A1BB2ULL,
		0xA071CDC67C8A1084ULL,
		0x51CB96DDA7AD0AD3ULL,
		0x9487554F63D57558ULL,
		0x0F6DE4058CF49621ULL,
		0x70BDCBDF0637B318ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 288 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39C6ECBFA45747C5ULL,
		0x67E6866994C2BE27ULL,
		0xA464A40D43B86C99ULL,
		0xDE5817A17AAE9D7BULL,
		0x8296A7E520509E54ULL,
		0xAF7A8F8F3FAEB2ABULL,
		0x5D597C75B2EE3DE6ULL,
		0x139A50BC18B17EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB63EE3C2466FED59ULL,
		0xFC3CBCE7F1576EA1ULL,
		0xE86F184BB68D2A07ULL,
		0x87EF3B060A65A8AEULL,
		0x1186932FA9A2D665ULL,
		0x9262CACD549D757EULL,
		0x6C075EED004617C2ULL,
		0xD5AB386684623E0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FF80F7DE238AA9CULL,
		0x9BDA3A8E6595D086ULL,
		0x4C0BBC46F535469EULL,
		0x59B72CA770CB35D5ULL,
		0x931034CA89F24831ULL,
		0x3D1845426B33C7D5ULL,
		0x315E2298B2A82A24ULL,
		0xC63168DA9CD340A2ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 289 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81EC685E34BEF85CULL,
		0x0274B6EBC9753D32ULL,
		0x356681502920E140ULL,
		0xA85FDCB814F25770ULL,
		0x23BA83D1C2E0BDE4ULL,
		0xE6A6F97FCC014686ULL,
		0x3517D532D6A018DEULL,
		0x363B3AED2473B648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677FDCA48A75DE20ULL,
		0x0321A9C6E29E5988ULL,
		0xEB508B23661D9106ULL,
		0xF79B53B43A8E4A87ULL,
		0x3FFC25294D0D4771ULL,
		0x7A9A2ED85AC2B13BULL,
		0x3CE46C71E4357801ULL,
		0x1C44A78F8AF126A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE693B4FABECB267CULL,
		0x01551F2D2BEB64BAULL,
		0xDE360A734F3D7046ULL,
		0x5FC48F0C2E7C1DF7ULL,
		0x1C46A6F88FEDFA95ULL,
		0x9C3CD7A796C3F7BDULL,
		0x09F3B943329560DFULL,
		0x2A7F9D62AE8290E9ULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 290 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1077D483D37C83CULL,
		0x299F08C4C56BE6B8ULL,
		0x792096A101C08D81ULL,
		0x292B67885461D51AULL,
		0xDF8E3F51911F074DULL,
		0xF365056A82514487ULL,
		0x519E868E177FBA31ULL,
		0x21558E69A7C5461BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4E14918B716C437ULL,
		0xE3D37CA0F3CDFA58ULL,
		0xD3BD413289690386ULL,
		0x627485FD47F03367ULL,
		0xB87BCEBEA2CC71D7ULL,
		0x62E36E08F7F13E5EULL,
		0x38DCF25603100D8CULL,
		0xF529DD4FE9885F6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55E634508A210C0BULL,
		0xCA4C746436A61CE0ULL,
		0xAA9DD79388A98E07ULL,
		0x4B5FE2751391E67DULL,
		0x67F5F1EF33D3769AULL,
		0x91866B6275A07AD9ULL,
		0x694274D8146FB7BDULL,
		0xD47C53264E4D1977ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 291 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1388E2C914349090ULL,
		0xC3C79EFA15DE8B4BULL,
		0x183CDEA15B8F2731ULL,
		0x2950EA146F72EF93ULL,
		0xBC2F82A1B14A4E17ULL,
		0x5E517F5A28B38EC6ULL,
		0x028DFCA1E4C6D79EULL,
		0xDF4F663D33A04146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2508AF0DD5F3127FULL,
		0x56973CDA6DBBECFAULL,
		0xF67F810F59A966B1ULL,
		0xD0856459E8CE8E1EULL,
		0x38E337D99F062423ULL,
		0x89A189BDEF69747FULL,
		0xD09D0EFC5F0DFAFEULL,
		0x92B6D48443438479ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36804DC4C1C782EFULL,
		0x9550A220786567B1ULL,
		0xEE435FAE02264180ULL,
		0xF9D58E4D87BC618DULL,
		0x84CCB5782E4C6A34ULL,
		0xD7F0F6E7C7DAFAB9ULL,
		0xD210F25DBBCB2D60ULL,
		0x4DF9B2B970E3C53FULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 292 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCBDC048AF61F980FULL,
		0x5D9CAF6A64C1179EULL,
		0x9428A600B586A5BDULL,
		0xC65361AE5270A0A2ULL,
		0x1CD4159A9EDF2BCEULL,
		0x77F865529C7B51EBULL,
		0x32AD964435E11BACULL,
		0x13525B16D088E156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EE5B74D71F03718ULL,
		0xC39B25680E226D4FULL,
		0xCA9A630D76335503ULL,
		0x7BC447FB4FA598B9ULL,
		0x151CCB5848D3849FULL,
		0x977DA89C0D2FB933ULL,
		0xDDB609A4A2ADB884ULL,
		0xA6D4433FC1B370F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD539B3C787EFAF17ULL,
		0x9E078A026AE37AD1ULL,
		0x5EB2C50DC3B5F0BEULL,
		0xBD9726551DD5381BULL,
		0x09C8DEC2D60CAF51ULL,
		0xE085CDCE9154E8D8ULL,
		0xEF1B9FE0974CA328ULL,
		0xB5861829113B91A4ULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 293 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75D890D39FBC6358ULL,
		0x49FC9475903BC609ULL,
		0xF8FB81F4CF363054ULL,
		0x51FBB60744EB2ECAULL,
		0x25AEEE36FD4BF271ULL,
		0x061DA8079CFF19A9ULL,
		0x5552A31BF3646833ULL,
		0xDD08E0E3DE0F141DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80354713F9D7D859ULL,
		0x4E1EDAC7A6CC001EULL,
		0xA5C399AA892ABD16ULL,
		0xCC92AC819C2BEC3FULL,
		0x731CBD1239723412ULL,
		0xEC8FDDCB8C444939ULL,
		0x4226E562BC743268ULL,
		0xCC9887252C8CED52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5EDD7C0666BBB01ULL,
		0x07E24EB236F7C617ULL,
		0x5D38185E461C8D42ULL,
		0x9D691A86D8C0C2F5ULL,
		0x56B25324C439C663ULL,
		0xEA9275CC10BB5090ULL,
		0x177446794F105A5BULL,
		0x119067C6F283F94FULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 294 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x639BC3F7CFF02F70ULL,
		0x911C55AF96852545ULL,
		0x7C52B96B245A69E4ULL,
		0xFBCBBB282EAC88CFULL,
		0x2CD89B611910FD5BULL,
		0x48D68B1DEEB83F5CULL,
		0xCC055C981FD7541FULL,
		0xF7B6AA3B6A915628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1CD66F43B3006F1ULL,
		0x9E9A98E4C7AD56CCULL,
		0x2066EA786CE1E955ULL,
		0xB4A1FAF4DC43569BULL,
		0x34250E0C5BD8B41AULL,
		0x874A5C000445042BULL,
		0x53A6BEF408A6A568ULL,
		0xF16653BE0ADA1743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA256A503F4C02981ULL,
		0x0F86CD4B51287389ULL,
		0x5C34531348BB80B1ULL,
		0x4F6A41DCF2EFDE54ULL,
		0x18FD956D42C84941ULL,
		0xCF9CD71DEAFD3B77ULL,
		0x9FA3E26C1771F177ULL,
		0x06D0F985604B416BULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 295 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0220FEB7C97FDC3EULL,
		0x6BFF212C0EB413FFULL,
		0x2BBFE9B333633721ULL,
		0x932606B3E95E3EFAULL,
		0x25A8A8B3298D8CFDULL,
		0xE2E403A50F7FD1C0ULL,
		0x296F712BE2943AE4ULL,
		0xC19C498B5529973AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA901585AE08DDA0EULL,
		0x00063D4A9599261FULL,
		0x8E2F42CBFEC86603ULL,
		0xEB24AC1CE67BE145ULL,
		0x28AF9FCED24E8F4DULL,
		0xCC820F19441A7612ULL,
		0x26B23E0AE7F11B28ULL,
		0xAEDF6174ED0D9E4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB21A6ED29F20630ULL,
		0x6BF91C669B2D35E0ULL,
		0xA590AB78CDAB5122ULL,
		0x7802AAAF0F25DFBFULL,
		0x0D07377DFBC303B0ULL,
		0x2E660CBC4B65A7D2ULL,
		0x0FDD4F21056521CCULL,
		0x6F4328FFB8240975ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 296 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36EB27D78619A68CULL,
		0x363A35474F715A95ULL,
		0x62356C6CFBDB7D35ULL,
		0x68E207D777BA4059ULL,
		0xBBF9777E1CBB195AULL,
		0x8C066CE837E3FDD5ULL,
		0x34240EE87E38AB74ULL,
		0x324C1E8267820BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BA55198D5022471ULL,
		0x3C1FD2E227157B98ULL,
		0x19CF6DBB5D3EA6C1ULL,
		0x124779A5728FCC62ULL,
		0x2E3B147E4EB8FC4BULL,
		0x8395DF31C560323CULL,
		0xEAD13C4F3122A73EULL,
		0xA6BB45A330CE1570ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD4E764F531B82FDULL,
		0x0A25E7A56864210DULL,
		0x7BFA01D7A6E5DBF4ULL,
		0x7AA57E7205358C3BULL,
		0x95C263005203E511ULL,
		0x0F93B3D9F283CFE9ULL,
		0xDEF532A74F1A0C4AULL,
		0x94F75B21574C1EA4ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 297 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AAB563009DDEE29ULL,
		0xBF0B7143B04FDCF2ULL,
		0x5B7D49F8FF8D71BDULL,
		0x9FB2C70934BAAD5AULL,
		0x4DEABEF75FD8DF84ULL,
		0xDA18FDA041329430ULL,
		0x8EC161118BBD12AFULL,
		0x4658055AEF9C0799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23388E09B924AAE5ULL,
		0x0CA244D63A95F5A5ULL,
		0x56073621A713B11FULL,
		0x1E92125C53EE77F4ULL,
		0x8CDF3AEA8352A78EULL,
		0x6DD2034610C5AC34ULL,
		0xC38432AF55A3EF56ULL,
		0xEA8D4CAC5DDA03C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0993D839B0F944CCULL,
		0xB3A935958ADA2957ULL,
		0x0D7A7FD9589EC0A2ULL,
		0x8120D5556754DAAEULL,
		0xC135841DDC8A780AULL,
		0xB7CAFEE651F73804ULL,
		0x4D4553BEDE1EFDF9ULL,
		0xACD549F6B246045FULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 298 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93581F0286B81B99ULL,
		0x392E6DFFFCC067A9ULL,
		0xBD8AD7EA5D2615CAULL,
		0x56BDD3384752ADC1ULL,
		0x1EDE4D27F066E328ULL,
		0x4B73E9F2796AFC8AULL,
		0x186BC7ADD004C0BBULL,
		0xFCAB7A095F48550CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C21EA17DE60AA6ULL,
		0x7B30B8196298875EULL,
		0xC314B9185A8B00A9ULL,
		0x682CD0018D43F2A2ULL,
		0xBBCA49A0E00A590AULL,
		0xCF33AFF6E1F63A6CULL,
		0xC4CB2D5B3476CCF2ULL,
		0x764D848E23A3B4E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE39A01A3FB5E113FULL,
		0x421ED5E69E58E0F7ULL,
		0x7E9E6EF207AD1563ULL,
		0x3E910339CA115F63ULL,
		0xA5140487106CBA22ULL,
		0x84404604989CC6E6ULL,
		0xDCA0EAF6E4720C49ULL,
		0x8AE6FE877CEBE1E5ULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 299 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2501B57CB3E252AULL,
		0x737EE9085A65F39CULL,
		0x73BEEA6E8E820D4CULL,
		0x91389926F62F50CDULL,
		0xCB198CB8FF73099EULL,
		0xB6CEB98C1EBB0E1CULL,
		0x029E9F3AC953581CULL,
		0x530DBA4D945CD01AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x421010186E98DFEDULL,
		0x84C78F7B09EDB4DAULL,
		0xCA9FD5BA6BAE0436ULL,
		0xBA120BC8ED1D271DULL,
		0xF47ED3AD58166289ULL,
		0x25432E98A7C65193ULL,
		0xD17384A42DB7FCFDULL,
		0xB4F409466A09A527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0400B4FA5A6FAC7ULL,
		0xF7B9667353884746ULL,
		0xB9213FD4E52C097AULL,
		0x2B2A92EE1B3277D0ULL,
		0x3F675F15A7656B17ULL,
		0x938D9714B97D5F8FULL,
		0xD3ED1B9EE4E4A4E1ULL,
		0xE7F9B30BFE55753DULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 300 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x484C561FD9EDF6CEULL,
		0x9AB1ACFA67F932B7ULL,
		0xEFEC79FBE5A7ACCBULL,
		0x3F26016B61CECF05ULL,
		0xDECC45FFEFB53059ULL,
		0xA12650CD018B8ACDULL,
		0xECBD0AC9967214F2ULL,
		0xA00B4AC94BD4115DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BB5213E75872D1EULL,
		0x9957A5C62F8213A5ULL,
		0xB305AC311AF235A8ULL,
		0x4A9EF7FDFCBAED10ULL,
		0x13D03E001265DCD9ULL,
		0xA745A45949F3E47CULL,
		0xF905F8F3BC7FAF0BULL,
		0x7FFCE0880CB9FF74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13F97721AC6ADBD0ULL,
		0x03E6093C487B2112ULL,
		0x5CE9D5CAFF559963ULL,
		0x75B8F6969D742215ULL,
		0xCD1C7BFFFDD0EC80ULL,
		0x0663F49448786EB1ULL,
		0x15B8F23A2A0DBBF9ULL,
		0xDFF7AA41476DEE29ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 301 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3557A6DB022119D4ULL,
		0x1CD9E6B5D0373AACULL,
		0xA8CA9C5482249BA6ULL,
		0xCB553ECA58F1E324ULL,
		0x5B1632AA58FC4EB2ULL,
		0xE9D1464C3A33AA60ULL,
		0x855CF9AAE1144684ULL,
		0x04C189B16675BDC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39102BA030B2C1FDULL,
		0x7F53D31EA1C48732ULL,
		0x0395678F29388183ULL,
		0xF088C8BBE0A5EA5DULL,
		0xCA456991A150515CULL,
		0x81654F5A3890F814ULL,
		0xDB934708AA09E7C4ULL,
		0x487BFC2375E31CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C478D7B3293D829ULL,
		0x638A35AB71F3BD9EULL,
		0xAB5FFBDBAB1C1A25ULL,
		0x3BDDF671B8540979ULL,
		0x91535B3BF9AC1FEEULL,
		0x68B4091602A35274ULL,
		0x5ECFBEA24B1DA140ULL,
		0x4CBA75921396A110ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 302 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B7C0BEFFD5923EBULL,
		0x890CC186C494836CULL,
		0xAD10B89D5AE5A0F2ULL,
		0x1975AD5FA11EE814ULL,
		0x8802DB39D2B41050ULL,
		0xB8039B977A760B2FULL,
		0x2A7AB133400B22CEULL,
		0xBAB1D8227D606F89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x035EBBA124266EBFULL,
		0x22BD530A06DF0B11ULL,
		0x1817DF8FB92A6A4BULL,
		0x537FF8EA00C965DCULL,
		0x71281C76F57DCD1FULL,
		0x637C614940D9A637ULL,
		0x958DBBF5A7439C0BULL,
		0xDC69EA0C54A0D10DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5822B04ED97F4D54ULL,
		0xABB1928CC24B887DULL,
		0xB5076712E3CFCAB9ULL,
		0x4A0A55B5A1D78DC8ULL,
		0xF92AC74F27C9DD4FULL,
		0xDB7FFADE3AAFAD18ULL,
		0xBFF70AC6E748BEC5ULL,
		0x66D8322E29C0BE84ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 303 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3487A2A256B3C63CULL,
		0x5A4C313E263DBD67ULL,
		0x4870E6847D723C99ULL,
		0xA53916EE0AC7F39FULL,
		0x88B0054CB5BD1E17ULL,
		0x811DCF9B1C3F4D1FULL,
		0x6013AB23878D2BE1ULL,
		0xB616B98A256875A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x764037D893414C15ULL,
		0xDDA0C0D3241F11C6ULL,
		0x63AD61D9585221CFULL,
		0x17BFF9D6C0F1897BULL,
		0xCB7F912847521F69ULL,
		0x9801676207C27839ULL,
		0xD6B8F6ECF1F98798ULL,
		0x41A3229F952AEACCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C7957AC5F28A29ULL,
		0x87ECF1ED0222ACA1ULL,
		0x2BDD875D25201D56ULL,
		0xB286EF38CA367AE4ULL,
		0x43CF9464F2EF017EULL,
		0x191CA8F91BFD3526ULL,
		0xB6AB5DCF7674AC79ULL,
		0xF7B59B15B0429F69ULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 304 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC94AD51E3C1AA0E0ULL,
		0x2F73279712613D74ULL,
		0x91BB7D8F8E6A8D3DULL,
		0x26570B8233B61F9EULL,
		0xE2E10D969642F78BULL,
		0x8F26EDACB9CD412AULL,
		0x5773B30B5EACDD6DULL,
		0x21934506C332AFC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6302EBEC21641D3ULL,
		0xF0C0BB61D8668DE2ULL,
		0x1CC8E1B2934F5AC3ULL,
		0x873696C7E876188BULL,
		0x30C6973FC36F4F5FULL,
		0x59F53CE3D7890A22ULL,
		0xFF5B5B6AF97E6414ULL,
		0x24DD3E7AB42B9639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F7AFBA0FE0CE133ULL,
		0xDFB39CF6CA07B096ULL,
		0x8D739C3D1D25D7FEULL,
		0xA1619D45DBC00715ULL,
		0xD2279AA9552DB8D4ULL,
		0xD6D3D14F6E444B08ULL,
		0xA828E861A7D2B979ULL,
		0x054E7B7C771939FFULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 305 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5F449518955F957ULL,
		0x71470131460F4FE3ULL,
		0x3476EB29E7B73DCDULL,
		0x93F9536561F6A72AULL,
		0x3D93897109534DF4ULL,
		0x6D9FD8BE53E9C5F9ULL,
		0x71282F6CA83B984BULL,
		0x5B27F29D67A252BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E39B061622B48C2ULL,
		0xB462425E37EB6C7AULL,
		0x826DB1318322D968ULL,
		0x678E864668ED7DC9ULL,
		0xDB857D2048F3F21DULL,
		0x934B7185F844345FULL,
		0x6DEB028A8DA4D3C9ULL,
		0x623AD043E1C1868AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBCDF930EB7EB195ULL,
		0xC525436F71E42399ULL,
		0xB61B5A186495E4A5ULL,
		0xF477D523091BDAE3ULL,
		0xE616F45141A0BFE9ULL,
		0xFED4A93BABADF1A6ULL,
		0x1CC32DE6259F4B82ULL,
		0x391D22DE8663D435ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 306 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x949862586B2F0194ULL,
		0x7AAC420A4F729692ULL,
		0x02D4A93C04D03164ULL,
		0xE963F175D8252C84ULL,
		0xB0CB0F0D2C5D9514ULL,
		0xF310B4A55810DFD7ULL,
		0xE37632E6661D8B3EULL,
		0x129C1D1169FCC7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D48575D16A3EC1BULL,
		0x2557C90D53D13F1EULL,
		0xC8F56ADDB3C9F133ULL,
		0xE08A485535BFE382ULL,
		0x25D3D8A2F10A4377ULL,
		0x2F0C1F233DFD7EAAULL,
		0xCAB5C9661C7F0D43ULL,
		0x44B50FA63B4CDC2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9D035057D8CED8FULL,
		0x5FFB8B071CA3A98CULL,
		0xCA21C3E1B719C057ULL,
		0x09E9B920ED9ACF06ULL,
		0x9518D7AFDD57D663ULL,
		0xDC1CAB8665EDA17DULL,
		0x29C3FB807A62867DULL,
		0x562912B752B01B92ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 307 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x740048021C3537D4ULL,
		0x4D10F598819C64B0ULL,
		0x295FA10CA08C57E0ULL,
		0x935902428CB56FB1ULL,
		0x27D1EC9843C2D706ULL,
		0x586FB704A25BD31AULL,
		0xB66EF897C1362080ULL,
		0x28606D5794E4EA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ED5DD1FE0974924ULL,
		0x851C12C3C9F1AE36ULL,
		0xD5D6CD917BA02AB1ULL,
		0x6A65A7E4A8269441ULL,
		0xF95837815BEE85ABULL,
		0xF18799CFC997B157ULL,
		0xB006B348EEA10944ULL,
		0xB115B7F97154AF70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAD5951DFCA27EF0ULL,
		0xC80CE75B486DCA86ULL,
		0xFC896C9DDB2C7D51ULL,
		0xF93CA5A62493FBF0ULL,
		0xDE89DB19182C52ADULL,
		0xA9E82ECB6BCC624DULL,
		0x06684BDF2F9729C4ULL,
		0x9975DAAEE5B0454BULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 308 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BB772CDF9B9AEBAULL,
		0x12C1227783653313ULL,
		0x73E53FCA2E7BF071ULL,
		0x0C5EE77E9681541DULL,
		0xD82C92360AE8AEFBULL,
		0x8FACF1067B5485E9ULL,
		0x334A173C792B349AULL,
		0x7030B1FDDB185831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x830BAFA3BF3E2F29ULL,
		0xE28F15BF28091171ULL,
		0x5AB35480CC86A5C8ULL,
		0xF667A5FA0B32E9D8ULL,
		0x5653C9EAB4BF621AULL,
		0x95D0C20EF6894999ULL,
		0xDB064A5B8E29A971ULL,
		0x302C3253863F78B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8BCDD6E46878193ULL,
		0xF04E37C8AB6C2262ULL,
		0x29566B4AE2FD55B9ULL,
		0xFA3942849DB3BDC5ULL,
		0x8E7F5BDCBE57CCE1ULL,
		0x1A7C33088DDDCC70ULL,
		0xE84C5D67F7029DEBULL,
		0x401C83AE5D272085ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 309 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46F29C0846C8FE23ULL,
		0xA2C225449F1789B6ULL,
		0x884ABB49F60EF0C1ULL,
		0xED3F2B9D9980B345ULL,
		0x9F2821D5480E7478ULL,
		0x14B7C056A1F586C0ULL,
		0xEC1B89FA08FF4FEBULL,
		0x99AB5E177C7CDF47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x251DEAE794EE891BULL,
		0x8DC85E7C3F9670FAULL,
		0xD2080BEC9F5B15DDULL,
		0x1B6D93DF15C298B4ULL,
		0x0FA5F0CE6126E91AULL,
		0x278E8A9D80AB1C06ULL,
		0x9ECE8B8E876770D1ULL,
		0x9C0E9AA1D9645498ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63EF76EFD2267738ULL,
		0x2F0A7B38A081F94CULL,
		0x5A42B0A56955E51CULL,
		0xF652B8428C422BF1ULL,
		0x908DD11B29289D62ULL,
		0x33394ACB215E9AC6ULL,
		0x72D502748F983F3AULL,
		0x05A5C4B6A5188BDFULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 310 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC781CB19FB7ACF11ULL,
		0xF7320BB25D8AA817ULL,
		0x703E6823FF647FF4ULL,
		0x420746F6575424C8ULL,
		0x93473CAE8CCD0FFBULL,
		0x22A0B83D4EECBB43ULL,
		0x17AA3CFDA86B9E43ULL,
		0xB99A2BEADB3FDD18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB82018E9CE200E33ULL,
		0x73ED4D1EB4909BA7ULL,
		0x504F4735BD1D40D8ULL,
		0x027E372677A75F3BULL,
		0x31E79A824060D77FULL,
		0xEAEA4A90966B890DULL,
		0xFC79098068DC9208ULL,
		0xE3D870514D4F8346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FA1D3F0355AC122ULL,
		0x84DF46ACE91A33B0ULL,
		0x20712F1642793F2CULL,
		0x407971D020F37BF3ULL,
		0xA2A0A62CCCADD884ULL,
		0xC84AF2ADD887324EULL,
		0xEBD3357DC0B70C4BULL,
		0x5A425BBB96705E5EULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 311 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7EDB9FE79D26A98ULL,
		0x17BA06A5CF37E845ULL,
		0xF8BF7495C274F8D0ULL,
		0x408E12BC1D2D9F3CULL,
		0xF539C0AF68608749ULL,
		0x06EB487F6F1F4C33ULL,
		0xE37B40DA2756601FULL,
		0x65A4B422204A436AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DBEF7FBA288A80BULL,
		0xC34230E8C26E00BFULL,
		0x94AC1C06FF4425E6ULL,
		0xFD212E6D2AAAFC2FULL,
		0xC86963FF2C5C3849ULL,
		0x91AAE584187E710AULL,
		0x87F029868C4CB9E3ULL,
		0x368D1B5A1121A4FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA534E05DB5AC293ULL,
		0xD4F8364D0D59E8FAULL,
		0x6C1368933D30DD36ULL,
		0xBDAF3CD137876313ULL,
		0x3D50A350443CBF00ULL,
		0x9741ADFB77613D39ULL,
		0x648B695CAB1AD9FCULL,
		0x5329AF78316BE794ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 312 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x485E5ACEF33CBD09ULL,
		0xCC2898C6CA763BDEULL,
		0x716406D8A34138E9ULL,
		0x38891CDEAFF75A98ULL,
		0x1850AD366F9FBF1CULL,
		0xE0E3430618AA1299ULL,
		0xCA4AB317BA7D72E7ULL,
		0x249894F85D001415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC97D2F2ACF3607ULL,
		0x7714080157266751ULL,
		0x8ABF759EFC09E2C1ULL,
		0x26F2AB040F2B81F0ULL,
		0x56F21DCCDE8075ADULL,
		0x2929F89EDE9A1CC3ULL,
		0xD5211E0062D53993ULL,
		0xC569EEA55BDF6030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x879727E1D9F38B0EULL,
		0xBB3C90C79D505C8FULL,
		0xFBDB73465F48DA28ULL,
		0x1E7BB7DAA0DCDB68ULL,
		0x4EA2B0FAB11FCAB1ULL,
		0xC9CABB98C6300E5AULL,
		0x1F6BAD17D8A84B74ULL,
		0xE1F17A5D06DF7425ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 313 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF8CD48F17ACEA14ULL,
		0x7B8ACA5A85180862ULL,
		0x32C8012603ADAB78ULL,
		0x0AA23E5F53F99B84ULL,
		0xD11D13DE0A57AEB6ULL,
		0xF2E70409653BCC5EULL,
		0x67ED4A1931080D48ULL,
		0x7D4177E6E3B31F05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC710803EE515BAB6ULL,
		0x966AC0D086A5ADA2ULL,
		0x2DAE3833A69C0357ULL,
		0x0326C547F1664A6CULL,
		0xA2002DDD04EC2430ULL,
		0xC6099FC2314378B3ULL,
		0x8C9ED5B41270F38FULL,
		0x41F8337CD79DCA25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x189C54B1F2B950A2ULL,
		0xEDE00A8A03BDA5C0ULL,
		0x1F663915A531A82FULL,
		0x0984FB18A29FD1E8ULL,
		0x731D3E030EBB8A86ULL,
		0x34EE9BCB5478B4EDULL,
		0xEB739FAD2378FEC7ULL,
		0x3CB9449A342ED520ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 314 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B44CB3441BD946EULL,
		0xAF6CDB745485D1C2ULL,
		0xACDA4AADA7933596ULL,
		0x8C7134A984DA8C4DULL,
		0xC44466D96CCB85E2ULL,
		0xDCB606729D859ED5ULL,
		0x7504643E85BDB44DULL,
		0x1FB40D19D22FFBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFAD5156D199C95ULL,
		0x9F88975F7F71B1BAULL,
		0xC36072CD6FBF41EBULL,
		0xC1A437B688431C29ULL,
		0x2D7C79D8F206C0C9ULL,
		0x592B61332218ED75ULL,
		0xA92F74410971EA33ULL,
		0xB85111E73662EDC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41BE1E212CA408FBULL,
		0x30E44C2B2BF46078ULL,
		0x6FBA3860C82C747DULL,
		0x4DD5031F0C999064ULL,
		0xE9381F019ECD452BULL,
		0x859D6741BF9D73A0ULL,
		0xDC2B107F8CCC5E7EULL,
		0xA7E51CFEE44D1667ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 315 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA1BA116FDDA1DB2ULL,
		0x33EBFCB696C4D068ULL,
		0xAA8EC1C45F389F4EULL,
		0x5A14104CFA5E467AULL,
		0x4C1114339C3B978FULL,
		0x7F2517E26089CE17ULL,
		0x63F31046491B1161ULL,
		0x1D4FAE86C23157C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3555D7463B735FULL,
		0x46B43523811854DAULL,
		0x88B48F0CB729009BULL,
		0xF1CBEDE83E1575AEULL,
		0x99621C1A4CF24899ULL,
		0x2460F59925493BCCULL,
		0x07C571D077699814ULL,
		0xBCAB14401BEACCC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002EF4C1BBE16EEDULL,
		0x755FC99517DC84B2ULL,
		0x223A4EC8E8119FD5ULL,
		0xABDFFDA4C44B33D4ULL,
		0xD5730829D0C9DF16ULL,
		0x5B45E27B45C0F5DBULL,
		0x643661963E728975ULL,
		0xA1E4BAC6D9DB9B08ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 316 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B2F0ED7934748FAULL,
		0xEE1938193A2F5228ULL,
		0xEFC06DA303209DD1ULL,
		0xCED6050CC176CE33ULL,
		0xBFAE373566E97319ULL,
		0xCFEF88F208F29804ULL,
		0xBFD728601DBB4B85ULL,
		0x4966BC2219695467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x495CE7767FA027D9ULL,
		0xCCE8F8FCF90B3C76ULL,
		0x23663AFC547FE5A5ULL,
		0x3BC944400488151EULL,
		0xF8FEFCC51E762F75ULL,
		0xE5F0400FBD85433FULL,
		0x8CBDC9F560629766ULL,
		0x3373E3CBCD938B7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7273E9A1ECE76F23ULL,
		0x22F1C0E5C3246E5EULL,
		0xCCA6575F575F7874ULL,
		0xF51F414CC5FEDB2DULL,
		0x4750CBF0789F5C6CULL,
		0x2A1FC8FDB577DB3BULL,
		0x336AE1957DD9DCE3ULL,
		0x7A155FE9D4FADF1BULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 317 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x848B2B2A5513EBDAULL,
		0x0AAAFE81CD2505DDULL,
		0x9ABCC99D69A5CC09ULL,
		0xFFB6BDA4BD50BA9FULL,
		0x799A0F701DF6AAFFULL,
		0x027C0981E3286E24ULL,
		0x64B5978DFECC376BULL,
		0xA260AC1A3138F355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF161FF8387A6A55DULL,
		0x755B216C303F8010ULL,
		0x301114846E6F713EULL,
		0x1D1FBE49D9E68117ULL,
		0xDF96305FF519BA61ULL,
		0x58B952DD8B3CA161ULL,
		0xE0AA8052F590D3CDULL,
		0x405D124E1EE86888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75EAD4A9D2B54E87ULL,
		0x7FF1DFEDFD1A85CDULL,
		0xAAADDD1907CABD37ULL,
		0xE2A903ED64B63B88ULL,
		0xA60C3F2FE8EF109EULL,
		0x5AC55B5C6814CF45ULL,
		0x841F17DF0B5CE4A6ULL,
		0xE23DBE542FD09BDDULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 318 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x441DB2EEFC23D9D7ULL,
		0x2BD000940C4D0D9EULL,
		0x735A532753F7541FULL,
		0x0DE1BBB1CA418117ULL,
		0xBE4292AFBB11D61EULL,
		0xB21D5DA85F660292ULL,
		0xF57494E973518208ULL,
		0x39603520F465085BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE451E1AEC8A4DE45ULL,
		0xF77A93019559727FULL,
		0x313D0E01F9F1A1E8ULL,
		0xE8AA7EF59363F71DULL,
		0x16091B5ECBD81C2DULL,
		0x886FB461F6BB4B54ULL,
		0x7E71734F44369F2FULL,
		0x5EF70AE163772FF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA04C534034870792ULL,
		0xDCAA939599147FE1ULL,
		0x42675D26AA06F5F7ULL,
		0xE54BC5445922760AULL,
		0xA84B89F170C9CA33ULL,
		0x3A72E9C9A9DD49C6ULL,
		0x8B05E7A637671D27ULL,
		0x67973FC1971227AFULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 319 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6448BFFD4F52EBA9ULL,
		0x23DB4657210CD91FULL,
		0x892964EDEF233096ULL,
		0xBF7CF1E9B0A8C440ULL,
		0xF8CE6BE7AF0ABFD3ULL,
		0xEE5FD5ED0F98F2FEULL,
		0x283A5D66F7757283ULL,
		0xFB015AEB2EC55E72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22713B6416E27272ULL,
		0x935B6F7AD838AE32ULL,
		0x70AB8DC081B09AF8ULL,
		0xFFE40AE0FA7D048AULL,
		0xE5BAA28A1B57AC8BULL,
		0x9AEFF0C878C2A1CAULL,
		0x194844E32942361AULL,
		0xE05C6987FAD46DC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4639849959B099DBULL,
		0xB080292DF934772DULL,
		0xF982E92D6E93AA6EULL,
		0x4098FB094AD5C0CAULL,
		0x1D74C96DB45D1358ULL,
		0x74B02525775A5334ULL,
		0x31721985DE374499ULL,
		0x1B5D336CD41133B6ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 320 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x878D6A468D9FC706ULL,
		0x1CCF610F9491AA9BULL,
		0xEAB87715A58DE33EULL,
		0x80AD7798EA31C819ULL,
		0x872780FA8288D805ULL,
		0xFF5283B4828D6FD9ULL,
		0x4B86F815D64C089AULL,
		0xE280354DD7E1DA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27957455EE02096CULL,
		0x897C95FBF3EA3104ULL,
		0xB97EC991FF0319C0ULL,
		0x1FD90000DA08A54EULL,
		0x05714956B86BE3FCULL,
		0x08CBDD50B9D059E6ULL,
		0x940CB60F7DB96B0DULL,
		0x9F28373881634A18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0181E13639DCE6AULL,
		0x95B3F4F4677B9B9FULL,
		0x53C6BE845A8EFAFEULL,
		0x9F74779830396D57ULL,
		0x8256C9AC3AE33BF9ULL,
		0xF7995EE43B5D363FULL,
		0xDF8A4E1AABF56397ULL,
		0x7DA8027556829062ULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 321 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D9A2E8C1CB04F04ULL,
		0x51B55183180426AFULL,
		0xFFEA0F236CD62DE5ULL,
		0xD92956BC183C88ACULL,
		0x46AECBC86FE297E3ULL,
		0x7823E2B2DE162238ULL,
		0x008451C0B2B36FDBULL,
		0xFF3629F18CBB1D66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C2613168B421CAULL,
		0x121368B2B82B045CULL,
		0x488D3DE5317EC258ULL,
		0x96C0708AAB580F6AULL,
		0x16845DC179CF4CBAULL,
		0x7D2D9E2C6160808CULL,
		0xB203301292C242A1ULL,
		0x4C10707935A5759EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5584FBD74046ECEULL,
		0x43A63931A02F22F3ULL,
		0xB76732C65DA8EFBDULL,
		0x4FE92636B36487C6ULL,
		0x502A9609162DDB59ULL,
		0x050E7C9EBF76A2B4ULL,
		0xB28761D220712D7AULL,
		0xB3265988B91E68F8ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 322 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F699A1858674828ULL,
		0x4D58E69B35A30340ULL,
		0xE3C9065C41DA07A3ULL,
		0xDE218261AA6CD4C4ULL,
		0x020A832F5117F23CULL,
		0x90C1CFD5AF52A11FULL,
		0xE26F70B51088E9DEULL,
		0xBC5174B27266BFB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A05E19BFED6509ULL,
		0xA6BCDE9526DF2FBDULL,
		0x921D3445570124D6ULL,
		0xC9FBDA93EF1AE898ULL,
		0x1A0308EA2AE4EC28ULL,
		0x37E90697D04A6766ULL,
		0x238219C13B055199ULL,
		0x6BFA3A12C70573CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36C9C401E78A2D21ULL,
		0xEBE4380E137C2CFDULL,
		0x71D4321916DB2375ULL,
		0x17DA58F245763C5CULL,
		0x18098BC57BF31E14ULL,
		0xA728C9427F18C679ULL,
		0xC1ED69742B8DB847ULL,
		0xD7AB4EA0B563CC77ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 323 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BD899ADA8E75F3CULL,
		0x241DFF48392F023CULL,
		0x13B3206508302740ULL,
		0x60268F0E7868CFD9ULL,
		0xF02DAEC1D3253BE8ULL,
		0x43D10B6DBC86E1A9ULL,
		0xA5ACB5106A8A335DULL,
		0xF66D5F03F9D301C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEFD513D865CD1EDULL,
		0x31566AF7749AC0F1ULL,
		0x359BAF6250A4C0F1ULL,
		0x5AB2ABDB481E7D0AULL,
		0x43FF126651C82009ULL,
		0x7F6B63D126F11D7CULL,
		0x8461970A6B15CBDDULL,
		0xB0B4CE7870744E16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA525C8902EBB8ED1ULL,
		0x154B95BF4DB5C2CDULL,
		0x26288F075894E7B1ULL,
		0x3A9424D53076B2D3ULL,
		0xB3D2BCA782ED1BE1ULL,
		0x3CBA68BC9A77FCD5ULL,
		0x21CD221A019FF880ULL,
		0x46D9917B89A74FD0ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 324 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4266A9BCBA7C5015ULL,
		0x9222611EF52FE5B4ULL,
		0xB6EB2FE550E74D71ULL,
		0xCE2EEE60A3D9CFD8ULL,
		0xA3A652C2B534CE78ULL,
		0x561C70A9E6A4DE66ULL,
		0x50CBF3851D92892CULL,
		0xDC1C92DE6403FAF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x723A81EC20C962CDULL,
		0x37F50359A6417BA2ULL,
		0x0AA471949C784F96ULL,
		0xE3F348C0F94C282DULL,
		0x547A2A3116F22E3FULL,
		0x5B22ACC4C3443C73ULL,
		0x4722C20D094B55FBULL,
		0x9D1571C82697AA7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x305C28509AB532D8ULL,
		0xA5D76247536E9E16ULL,
		0xBC4F5E71CC9F02E7ULL,
		0x2DDDA6A05A95E7F5ULL,
		0xF7DC78F3A3C6E047ULL,
		0x0D3EDC6D25E0E215ULL,
		0x17E9318814D9DCD7ULL,
		0x4109E31642945084ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 325 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB5B01F3EF73DF2ULL,
		0xD430C703BFBF4B95ULL,
		0xCF57F221E7733A60ULL,
		0xB926B6FBD003EDBBULL,
		0x6B28BDEA483D7D17ULL,
		0x0A547F562E816C02ULL,
		0x1347272E9F9EBF69ULL,
		0xA9194CF5F704EC81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54AAE606806DF790ULL,
		0x24573C18B89BE607ULL,
		0x94FF2B594C31DF32ULL,
		0xC13A95525BFFE1BFULL,
		0x2EA23D0D528DEAB2ULL,
		0x2CD2E0F35E102F2BULL,
		0x7E5F57CDCCF3D174ULL,
		0x9826C57BF556CA74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B1F5619BE9ACA62ULL,
		0xF067FB1B0724AD92ULL,
		0x5BA8D978AB42E552ULL,
		0x781C23A98BFC0C04ULL,
		0x458A80E71AB097A5ULL,
		0x26869FA570914329ULL,
		0x6D1870E3536D6E1DULL,
		0x313F898E025226F5ULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 326 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x567A1A8B5B9479F1ULL,
		0x6FA45D34387F3226ULL,
		0x04D7EB16A68FCE75ULL,
		0x2A29530EB9C4B062ULL,
		0xA7F4F974A70DF20FULL,
		0xBCBA2B11095D3B58ULL,
		0xB0FC7CD1C4511CACULL,
		0xAD4BE820A5F89DC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23766AB5E4620471ULL,
		0x1C41CAB26013EF08ULL,
		0x994D3D2139B749B1ULL,
		0xD89C92C812CAF954ULL,
		0xAD4C58C97EE5F0ACULL,
		0x6565AA21EB2EBA9DULL,
		0x96CABD4924A36C03ULL,
		0x181E37C4AF96BFF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x750C703EBFF67D80ULL,
		0x73E59786586CDD2EULL,
		0x9D9AD6379F3887C4ULL,
		0xF2B5C1C6AB0E4936ULL,
		0x0AB8A1BDD9E802A3ULL,
		0xD9DF8130E27381C5ULL,
		0x2636C198E0F270AFULL,
		0xB555DFE40A6E2239ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 327 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x444E9CC7FDFF7F52ULL,
		0x4BCC0DB7E174C446ULL,
		0x79B70BBF0372DB42ULL,
		0x494110EC645D099CULL,
		0x6B1E654B3F73134CULL,
		0x5A7E9B07F82007A5ULL,
		0x471E6E6FB09EB2F0ULL,
		0x8A1A37AC50CF088DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x782B08EDDA58B53BULL,
		0x4BEC8420D1166E42ULL,
		0xD797CD85E733B925ULL,
		0x53D281DDCBFBCF2EULL,
		0xD48DA67165C254A9ULL,
		0x554079DE52166345ULL,
		0xEDB4B30D4CB0FA18ULL,
		0x014098897B4A1E41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C65942A27A7CA69ULL,
		0x002089973062AA04ULL,
		0xAE20C63AE4416267ULL,
		0x1A939131AFA6C6B2ULL,
		0xBF93C33A5AB147E5ULL,
		0x0F3EE2D9AA3664E0ULL,
		0xAAAADD62FC2E48E8ULL,
		0x8B5AAF252B8516CCULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 328 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC39B4377C3333F0ULL,
		0x227B138239771868ULL,
		0x58B5D340335AA92AULL,
		0xC00ECC09CCEB576CULL,
		0xC4ABFC1DDA34F5EBULL,
		0x082782E68C22B98AULL,
		0xE8CFEFD3A2C3E81EULL,
		0xE8C94ACD5DAC35B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43C6C540BCF5804FULL,
		0x53DECC787D77A7D2ULL,
		0x6A45C65C08869C04ULL,
		0xFD222BFB45E714EFULL,
		0xF2A5C30B38DBD276ULL,
		0x7F884B885AE008B6ULL,
		0xEDF502CCCB835BB7ULL,
		0xC0170804217F0846ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFFFF7177C0C6B3BFULL,
		0x71A5DFFA4400BFBAULL,
		0x32F0151C3BDC352EULL,
		0x3D2CE7F2890C4383ULL,
		0x360E3F16E2EF279DULL,
		0x77AFC96ED6C2B13CULL,
		0x053AED1F6940B3A9ULL,
		0x28DE42C97CD33DF2ULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 329 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57A93752371A5DCDULL,
		0x4E12F47066A705D3ULL,
		0x2A46EE123EB10510ULL,
		0x7A3AD07B0F58A8D0ULL,
		0x9A259A8967E5624DULL,
		0xCEA3E81C6303B116ULL,
		0x2C4F75B1E84D17A9ULL,
		0x627B090CE414E4B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF91CBF9DF9264212ULL,
		0xC65E7233840D7C1AULL,
		0x3568569EDB2E55ACULL,
		0x6CCA590926EDBD33ULL,
		0xF5ED5310BEF65BC9ULL,
		0x2D6D03A6C4AE84CCULL,
		0xA7950FF3FA0949A3ULL,
		0xD8E4EE356602A462ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEB588CFCE3C1FDFULL,
		0x884C8643E2AA79C9ULL,
		0x1F2EB88CE59F50BCULL,
		0x16F0897229B515E3ULL,
		0x6FC8C999D9133984ULL,
		0xE3CEEBBAA7AD35DAULL,
		0x8BDA7A4212445E0AULL,
		0xBA9FE739821640D3ULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 330 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4705084FEFB229FDULL,
		0x61814A23D7A231FFULL,
		0xB78F61349EB191ADULL,
		0x06613EA77719695CULL,
		0x3A920CECBB1308B9ULL,
		0x8AA3911FA41C5BDCULL,
		0xC99411A7C1641C5CULL,
		0x83CA0A7B63462EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9C29C0609637D61ULL,
		0x14DA756368F7DC89ULL,
		0xB27300B03544E60EULL,
		0x673D22B641F47250ULL,
		0xACA347961282D55DULL,
		0xC9169712E2747048ULL,
		0xDC4A5A6EBFD1906FULL,
		0xAF51B2D8E8CB605CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEC79449E6D1549CULL,
		0x755B3F40BF55ED76ULL,
		0x05FC6184ABF577A3ULL,
		0x615C1C1136ED1B0CULL,
		0x96314B7AA991DDE4ULL,
		0x43B5060D46682B94ULL,
		0x15DE4BC97EB58C33ULL,
		0x2C9BB8A38B8D4E87ULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 331 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x705D8A4795A41178ULL,
		0x2916815D3A063581ULL,
		0xECEB99C7E72BF539ULL,
		0x0A13C2AAF23C4D82ULL,
		0x446BA8FE96710338ULL,
		0x4193576051A505BCULL,
		0xC8F6FD603C186D90ULL,
		0xE5C253125576E74FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC375720DAD52FCCFULL,
		0xA67DE73C4C1B9239ULL,
		0x503B87CE0CA2934AULL,
		0x3D7BA96B48137D97ULL,
		0xA1FD389879E67055ULL,
		0x02D2990BFD5DBF74ULL,
		0xF94693502941E1B4ULL,
		0xEE040A3B33398DADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB328F84A38F6EDB7ULL,
		0x8F6B6661761DA7B8ULL,
		0xBCD01E09EB896673ULL,
		0x37686BC1BA2F3015ULL,
		0xE5969066EF97736DULL,
		0x4341CE6BACF8BAC8ULL,
		0x31B06E3015598C24ULL,
		0x0BC65929664F6AE2ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 332 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB3F4513F8F15FD7ULL,
		0x17365CEAA731D1EAULL,
		0xFFCE961431F9A11DULL,
		0x23ADDE58CAD5BDE6ULL,
		0x1EDDB2FEB9A8F7A6ULL,
		0xF8895D609128A5DBULL,
		0xA808324ADF258004ULL,
		0x8D80449814B7CAD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA21C711C4CB01865ULL,
		0x836AB311ABC7DF57ULL,
		0xAF0178DC526E5134ULL,
		0x6977FDFB8C76C0E2ULL,
		0x1FDE5E3F445DC8FDULL,
		0x2949B4460860C215ULL,
		0xD861C503A234CF59ULL,
		0xC7354EBC718ABB37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1923340FB44147B2ULL,
		0x945CEFFB0CF60EBDULL,
		0x50CFEEC86397F029ULL,
		0x4ADA23A346A37D04ULL,
		0x0103ECC1FDF53F5BULL,
		0xD1C0E926994867CEULL,
		0x7069F7497D114F5DULL,
		0x4AB50A24653D71E6ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 333 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7763C39141CBC69ULL,
		0xDEE471D5CE7C2781ULL,
		0xCF4119B3E6297B33ULL,
		0x5AA98339F061ACCBULL,
		0x0F02EA2B40555891ULL,
		0xC659F513F49076C9ULL,
		0x06D1B7DAEA679599ULL,
		0xD9282CFB58999651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44E25F3F214D6F0FULL,
		0x82F25A251A336120ULL,
		0xAA1722BD7270DFB0ULL,
		0xBEDB464B82CBFEC3ULL,
		0xE21774B9454751C7ULL,
		0xDB5B5BD22C8517E8ULL,
		0x4D15E8CC64892BC7ULL,
		0xAA6BD898368886A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF39463063551D366ULL,
		0x5C162BF0D44F46A1ULL,
		0x65563B0E9459A483ULL,
		0xE472C57272AA5208ULL,
		0xED159E9205120956ULL,
		0x1D02AEC1D8156121ULL,
		0x4BC45F168EEEBE5EULL,
		0x7343F4636E1110F1ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 334 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47454B7616F86919ULL,
		0xA424106F0EDF676AULL,
		0x455C8B5923F38162ULL,
		0x575C7524517B5D35ULL,
		0x17053B730CEFFB23ULL,
		0x073F05E1EECF2BBAULL,
		0x5E3A9F4690CC2173ULL,
		0xCCCA8D87E13876EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x912EC310458DC703ULL,
		0x62DEFF5AE8C91377ULL,
		0x7F8A60D39D8F3DF7ULL,
		0x71A644803EC68A4EULL,
		0x110DEA802B5DC9A5ULL,
		0xDF014703EF1A023AULL,
		0xC61FA4E11F15E903ULL,
		0x2B1946DA3B68E3FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD66B88665375AE1AULL,
		0xC6FAEF35E616741DULL,
		0x3AD6EB8ABE7CBC95ULL,
		0x26FA31A46FBDD77BULL,
		0x0608D1F327B23286ULL,
		0xD83E42E201D52980ULL,
		0x98253BA78FD9C870ULL,
		0xE7D3CB5DDA509511ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 335 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE7CF90B1567BB5DULL,
		0x46B9DFBA04F47F6AULL,
		0xBF3FAC2F5659B07FULL,
		0x2498C848E95AAD07ULL,
		0x1532DDD583C6E83DULL,
		0x0ED973B749249043ULL,
		0x8229D3914E494EF5ULL,
		0x9A3DADBD4A27821AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78DE4F3035DD5D99ULL,
		0x995BA3E8AEA09F58ULL,
		0x9837F8353C62C540ULL,
		0xA2800B14448E0BF9ULL,
		0xD7387144EE65DEBBULL,
		0xC46386A459F06A42ULL,
		0x9351BE843474E17CULL,
		0x3B4D57DCB45AC7C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6A2B63B20BAE6C4ULL,
		0xDFE27C52AA54E032ULL,
		0x2708541A6A3B753FULL,
		0x8618C35CADD4A6FEULL,
		0xC20AAC916DA33686ULL,
		0xCABAF51310D4FA01ULL,
		0x11786D157A3DAF89ULL,
		0xA170FA61FE7D45D2ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 336 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F778BDE267322FDULL,
		0x85E1A5AEA7BFD0C4ULL,
		0x65EE021FDB83240AULL,
		0x88A7D1A83A07B5E5ULL,
		0xF85AE3F6C8FD8B41ULL,
		0xEF3B5A45911B7F83ULL,
		0x37FBA96D9D355AA0ULL,
		0x4A0BE5F7466A8D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6124AEFE56173B6AULL,
		0x50C49B5AB9C46936ULL,
		0xCF72A1A970A373A2ULL,
		0x039880890FA2E461ULL,
		0x22877B972F681D15ULL,
		0xB631BCDD58BB151AULL,
		0x665CB73D55AD9450ULL,
		0x56D0D8863805643DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E53252070641997ULL,
		0xD5253EF41E7BB9F2ULL,
		0xAA9CA3B6AB2057A8ULL,
		0x8B3F512135A55184ULL,
		0xDADD9861E7959654ULL,
		0x590AE698C9A06A99ULL,
		0x51A71E50C898CEF0ULL,
		0x1CDB3D717E6FE911ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 337 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBE270D51AE640CBULL,
		0x4036BE0EFE877530ULL,
		0xF12FEF220837B7C3ULL,
		0x3AD3C7AFBC7A3513ULL,
		0xB841A794962FD348ULL,
		0xB156A075E041B996ULL,
		0x803E29CD34F69A00ULL,
		0x38A0C482B6912B7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224BB89EDB9A9C90ULL,
		0x7B70F9144D2824F3ULL,
		0x9D01ACBE7FD9D638ULL,
		0xEC8A18905020A879ULL,
		0x909F3C6F2D3AC174ULL,
		0x59A2E8B2FAE501DEULL,
		0x919173D9C099B00BULL,
		0x722F196FE3A8DC01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99A9C84BC17CDC5BULL,
		0x3B46471AB3AF51C3ULL,
		0x6C2E439C77EE61FBULL,
		0xD659DF3FEC5A9D6AULL,
		0x28DE9BFBBB15123CULL,
		0xE8F448C71AA4B848ULL,
		0x11AF5A14F46F2A0BULL,
		0x4A8FDDED5539F77EULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 338 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056798E346B36944ULL,
		0x76DC5625902BFFA9ULL,
		0x37B15B07E68A3F55ULL,
		0x82A9EFF490BE9898ULL,
		0xB6120E3D7DD807E5ULL,
		0x4C1FAF7BAC57E9CFULL,
		0xD88ED4222C251044ULL,
		0x2389FE4313679873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC5F04D450441E2ULL,
		0x8E93F159219DCD15ULL,
		0xFEA2076B8798C9A5ULL,
		0x630C33A079BCB257ULL,
		0xB4E37E2797F9E9D4ULL,
		0xAD03B74389A26FE0ULL,
		0x6BD0B5BFCE7850CDULL,
		0xD5D095F5DE8DE180ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAA268AE03B728A6ULL,
		0xF84FA77CB1B632BCULL,
		0xC9135C6C6112F6F0ULL,
		0xE1A5DC54E9022ACFULL,
		0x02F1701AEA21EE31ULL,
		0xE11C183825F5862FULL,
		0xB35E619DE25D4089ULL,
		0xF6596BB6CDEA79F3ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 339 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65950C510F424B2DULL,
		0x613601ECED9D1342ULL,
		0x3E879A84822D2E6BULL,
		0xEBB5572110D823DDULL,
		0x6AF563DAB280B1B5ULL,
		0xBFC3F899E33E3985ULL,
		0x0346D4B8FADA73AEULL,
		0x36DDA543FF8B1068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD027A4A335622CCBULL,
		0x8359FBF1B3ED2054ULL,
		0x92CA2D1E0FA1E527ULL,
		0xE6EEDCCE62406C42ULL,
		0x08F9CFB53FF935F2ULL,
		0xE8F6485A8374814BULL,
		0xA44DAB16FA9A2F14ULL,
		0xFE1B2D6D58BD22C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5B2A8F23A2067E6ULL,
		0xE26FFA1D5E703316ULL,
		0xAC4DB79A8D8CCB4CULL,
		0x0D5B8BEF72984F9FULL,
		0x620CAC6F8D798447ULL,
		0x5735B0C3604AB8CEULL,
		0xA70B7FAE00405CBAULL,
		0xC8C6882EA73632ACULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 340 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x981F2F64A58508A2ULL,
		0xE71D13A9EC927687ULL,
		0x64FEE08E590005C3ULL,
		0xF94836D17B75A6CAULL,
		0x50EDDBA18DABAD8CULL,
		0x125E1BAB713E3EEDULL,
		0x75BBF3A3A12DC926ULL,
		0x0CBA5573EF261EFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x747571F438E6C622ULL,
		0x52925C9021041CCEULL,
		0x3CF8F24A8224B7EBULL,
		0x29E07ED0D294168EULL,
		0x9F6DBE3497A27821ULL,
		0x5A445F35880C9923ULL,
		0x94C563958B6D1E57ULL,
		0x5E27B416E64D5289ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC6A5E909D63CE80ULL,
		0xB58F4F39CD966A49ULL,
		0x580612C4DB24B228ULL,
		0xD0A84801A9E1B044ULL,
		0xCF8065951A09D5ADULL,
		0x481A449EF932A7CEULL,
		0xE17E90362A40D771ULL,
		0x529DE165096B4C75ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 341 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91CDFA93C3FC92B6ULL,
		0x363BF2A3402A8CDAULL,
		0xF44E26101570B998ULL,
		0x7D3BFABD36878793ULL,
		0x164BE0DA2C9B7051ULL,
		0xCF02DC907E241340ULL,
		0x8CF547C69FF2B387ULL,
		0x00E653682EA59630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43FC04030A43E370ULL,
		0x315251D725E84920ULL,
		0xC00786E2942EA1CEULL,
		0x1F3F076E7CCE7A6AULL,
		0x65A5C933CF064466ULL,
		0x011EC8CB8EDDD7ECULL,
		0x1716F0E0A1E16B2CULL,
		0x2012AA72CADD536EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD231FE90C9BF71C6ULL,
		0x0769A37465C2C5FAULL,
		0x3449A0F2815E1856ULL,
		0x6204FDD34A49FDF9ULL,
		0x73EE29E9E39D3437ULL,
		0xCE1C145BF0F9C4ACULL,
		0x9BE3B7263E13D8ABULL,
		0x20F4F91AE478C55EULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 342 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C58B8FE3E545BC2ULL,
		0x52A277A740336B0DULL,
		0x8C846159A49D8E1BULL,
		0xE6A03E0076DF3E95ULL,
		0x5775237FC26BF986ULL,
		0x1DCDE15ABDE8C7ABULL,
		0xC078E79A9AFC4BBFULL,
		0xF5BBBBCBFE9D66D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98670D710EB1C5DAULL,
		0x50CC077B22C59C2DULL,
		0x105B5D8EE8AFF928ULL,
		0x37EA2872F02646BDULL,
		0x1B4F5B4D02EEF22FULL,
		0xD7504C80234EE2EBULL,
		0xF078663048982451ULL,
		0x0DB15EF967793B2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD43FB58F30E59E18ULL,
		0x026E70DC62F6F720ULL,
		0x9CDF3CD74C327733ULL,
		0xD14A167286F97828ULL,
		0x4C3A7832C0850BA9ULL,
		0xCA9DADDA9EA62540ULL,
		0x300081AAD2646FEEULL,
		0xF80AE53299E45DFEULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 343 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F5F236B2F470040ULL,
		0x3CBAAF6A38064CDFULL,
		0x783BB1E34B1B4EC7ULL,
		0x62332C9BCB4F957EULL,
		0x674718D5BE2A64ABULL,
		0x494B07A0C14F885EULL,
		0xEB6168D8D899E106ULL,
		0x23FEBF9EDADBC61EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBB58AAD54E45131ULL,
		0xD1FEE634DF6852ADULL,
		0xFBC616E8A78C2BBBULL,
		0x2983AC79629E74B0ULL,
		0x98A1E386C36BB77AULL,
		0x9794B147D4CFCE4BULL,
		0x75A946EB4EA00BCCULL,
		0xD3B61D6968338DF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54EAA9C67BA35171ULL,
		0xED44495EE76E1E72ULL,
		0x83FDA70BEC97657CULL,
		0x4BB080E2A9D1E1CEULL,
		0xFFE6FB537D41D3D1ULL,
		0xDEDFB6E715804615ULL,
		0x9EC82E339639EACAULL,
		0xF048A2F7B2E84BEFULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 344 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53E60E154E347E5FULL,
		0xF46FBA643186BA48ULL,
		0x20F3815B3A22D132ULL,
		0x6EACFB6444CDDF67ULL,
		0x2135E9D89F5657A2ULL,
		0x1BADC6F5637E588BULL,
		0x858E25493141BD76ULL,
		0xBD5C108DBDED095DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9AA680EDB291D7ULL,
		0x499E54CF734E5BF7ULL,
		0x3D684DB7FC6D12EDULL,
		0x1846E91AB135AB5CULL,
		0xD79F878E84BDB141ULL,
		0xB3268B34DBDA7B65ULL,
		0x3E5F0850874E20EDULL,
		0xCA60CCF983526197ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x687CA895A386EF88ULL,
		0xBDF1EEAB42C8E1BFULL,
		0x1D9BCCECC64FC3DFULL,
		0x76EA127EF5F8743BULL,
		0xF6AA6E561BEBE6E3ULL,
		0xA88B4DC1B8A423EEULL,
		0xBBD12D19B60F9D9BULL,
		0x773CDC743EBF68CAULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 345 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A47322AC47D5634ULL,
		0x8E4365AEDA9DC885ULL,
		0xE6F39CF6D7D332FDULL,
		0x95E2F8C7FFEC63E7ULL,
		0x1D4A7B3B38414AE9ULL,
		0x208624DFE51BD23BULL,
		0xBB54FFDFC0EBA32EULL,
		0x0567BDD7F1F8AD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE859C1A97CB34AAEULL,
		0x891921C79A66E616ULL,
		0x139E7F158DD3E450ULL,
		0xF9154AE0BEAC3094ULL,
		0x7ED69B83C5D7B4FBULL,
		0xE370DB634413C0F1ULL,
		0x930B1E9132FC4E57ULL,
		0x724CCC7DEBC5CE82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x821EF383B8CE1C9AULL,
		0x075A446940FB2E93ULL,
		0xF56DE3E35A00D6ADULL,
		0x6CF7B22741405373ULL,
		0x639CE0B8FD96FE12ULL,
		0xC3F6FFBCA10812CAULL,
		0x285FE14EF217ED79ULL,
		0x772B71AA1A3D63B9ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 346 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x513578E8866C72ADULL,
		0x47AB5AB0D62DCE12ULL,
		0x2DA4F176517DD052ULL,
		0xADEF62185931445AULL,
		0xE8A24868524DDCFBULL,
		0x65868B6855B42854ULL,
		0xF55073146D56328FULL,
		0xC0A4F467062C9EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8C88E3C33693E10ULL,
		0x3E83F335AF30DD9AULL,
		0x7F344EAE6F97A06FULL,
		0x2B31930226C47EC8ULL,
		0x1CECF336CAE665D3ULL,
		0x07EEB41590D836C6ULL,
		0xD073E31C80D4BA6AULL,
		0x0828CE670E3333FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9FDF6D4B5054CBDULL,
		0x7928A985791D1388ULL,
		0x5290BFD83EEA703DULL,
		0x86DEF11A7FF53A92ULL,
		0xF44EBB5E98ABB928ULL,
		0x62683F7DC56C1E92ULL,
		0x25239008ED8288E5ULL,
		0xC88C3A00081FAD3DULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 347 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66FD219702B1101AULL,
		0xC99CCB906B3682C2ULL,
		0xC476231F19F93E64ULL,
		0x5157757A7B44166BULL,
		0x4B49346C21D46CEDULL,
		0xEC5359213514C748ULL,
		0xB2E8DFD8D28A7241ULL,
		0x0B8B48F11EF040ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64089A6D4F915CF5ULL,
		0x02DEE752AB08B411ULL,
		0x393B68239C910572ULL,
		0x94478A4095F8C686ULL,
		0x435F5F3DAD425D7FULL,
		0x150A915C3332A1D3ULL,
		0x76B7A222D0823F3FULL,
		0x2179BFEB05CA3820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02F5BBFA4D204CEFULL,
		0xCB422CC2C03E36D3ULL,
		0xFD4D4B3C85683B16ULL,
		0xC510FF3AEEBCD0EDULL,
		0x08166B518C963192ULL,
		0xF959C87D0626669BULL,
		0xC45F7DFA02084D7EULL,
		0x2AF2F71A1B3A788CULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 348 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x933D9252B82D9B7EULL,
		0x030CC4D8E213F69CULL,
		0x812C5BD03BF42F3BULL,
		0x04A743CD1A46FF25ULL,
		0xCDBCB7DAA55EA505ULL,
		0xBA9594B959A7C12FULL,
		0xFE0F97060E9F3677ULL,
		0x2F20423F65934A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68AFC04682822C4EULL,
		0x012C49F5F9FDB69DULL,
		0x592F42127190AF50ULL,
		0x636C998DBD4FDDA3ULL,
		0xBE90EB9679A8A3C0ULL,
		0xAEC17303DBE1B683ULL,
		0xDED8C037D7F7A73FULL,
		0x88B46B9452D73070ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB9252143AAFB730ULL,
		0x02208D2D1BEE4001ULL,
		0xD80319C24A64806BULL,
		0x67CBDA40A7092286ULL,
		0x732C5C4CDCF606C5ULL,
		0x1454E7BA824677ACULL,
		0x20D75731D9689148ULL,
		0xA79429AB37447A04ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 349 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BDDA5E2A9533E55ULL,
		0x5C95DE48B69CC703ULL,
		0x5B5D979251583615ULL,
		0x46E444F6A70B4710ULL,
		0xE74919C3C9A72AADULL,
		0x3FF0C0797F31815AULL,
		0x7B33D06CCFF293D5ULL,
		0x532681C8F684B68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D06B0B494811FE3ULL,
		0xF546D52E65A4D364ULL,
		0xE8BAE53675C050FAULL,
		0x0A24BABD573C2191ULL,
		0xE0546F0C04924998ULL,
		0x84D031ABC87E838CULL,
		0x36B22958B06AC5ACULL,
		0xDC3007EE98174A55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56DB15563DD221B6ULL,
		0xA9D30B66D3381467ULL,
		0xB3E772A4249866EFULL,
		0x4CC0FE4BF0376681ULL,
		0x071D76CFCD356335ULL,
		0xBB20F1D2B74F02D6ULL,
		0x4D81F9347F985679ULL,
		0x8F1686266E93FCDBULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 350 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC28FDC0900EBCBE6ULL,
		0x6C15C5B2055151ABULL,
		0x92FD7E379CE5BC93ULL,
		0xA9C743CEAA3A6B36ULL,
		0xE042AE97A2851C93ULL,
		0xC98CE24F1BD2C0C1ULL,
		0xFBF93244EBF55047ULL,
		0xA5C0155168C88246ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C57C90F6FC65DEULL,
		0x12386F766E4C7837ULL,
		0x64E0F0C040D2B103ULL,
		0x2685B1AB070E3A1FULL,
		0xF3698D6744F7499FULL,
		0xEF957DC7B9DB6AEDULL,
		0x8D1770FDE9EA3873ULL,
		0x974AC7F266A7A0BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD14AA099F617AE38ULL,
		0x7E2DAAC46B1D299CULL,
		0xF61D8EF7DC370D90ULL,
		0x8F42F265AD345129ULL,
		0x132B23F0E672550CULL,
		0x26199F88A209AA2CULL,
		0x76EE42B9021F6834ULL,
		0x328AD2A30E6F22FCULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 351 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD354DB3E8F37ED24ULL,
		0x84851C42D4DAF323ULL,
		0xC0E6A0503DFC793AULL,
		0xCD42D2FC746F643EULL,
		0x2B1B2C4301FBCDE3ULL,
		0x826A09568D0AC292ULL,
		0x2C0D266FDFB335F0ULL,
		0xC0DEBC6D684C7B19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D99059A79BEDAABULL,
		0xBAABFF29060C7B0AULL,
		0xD6CD14B7A0B68D78ULL,
		0x08BA323E5D1CB676ULL,
		0xCDADB0F2023EE886ULL,
		0x19261C8152521ABEULL,
		0x780EC96E750E6647ULL,
		0xC904469BEA5507DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDECDDEA4F689378FULL,
		0x3E2EE36BD2D68829ULL,
		0x162BB4E79D4AF442ULL,
		0xC5F8E0C22973D248ULL,
		0xE6B69CB103C52565ULL,
		0x9B4C15D7DF58D82CULL,
		0x5403EF01AABD53B7ULL,
		0x09DAFAF682197CC4ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 352 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB78F8CE32B0B62FULL,
		0x272CD0BE588A242FULL,
		0x52E413ED08DAC603ULL,
		0x34284B3F4139CC23ULL,
		0x7EF502E76A21366FULL,
		0x70C98B689E61202DULL,
		0xC7FC29211816E721ULL,
		0x971166AE7512F242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1465064956B2ADULL,
		0xC893CABA5E9B4457ULL,
		0x1485CC4EA23CAB88ULL,
		0xC745A6FED201B908ULL,
		0xD04882D2CC52B19AULL,
		0x4C46011FB6BF6F41ULL,
		0x1CB5FE6A5248875AULL,
		0xF8D84F39205D3FF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x116C9DC87BE60482ULL,
		0xEFBF1A0406116078ULL,
		0x4661DFA3AAE66D8BULL,
		0xF36DEDC19338752BULL,
		0xAEBD8035A67387F5ULL,
		0x3C8F8A7728DE4F6CULL,
		0xDB49D74B4A5E607BULL,
		0x6FC92997554FCDBBULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 353 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33EAF716CA26DB50ULL,
		0x22FAA6576F83F202ULL,
		0xA071D5B4FB270F39ULL,
		0x203B49C8AE79897AULL,
		0x6ECE02C8B7AFA9A3ULL,
		0xF62075D2ABD99417ULL,
		0x5305F9B01BA51C64ULL,
		0xFF59299F82D49E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB61C7F7C689DB71ULL,
		0x3ED04978CC62672CULL,
		0xD5D8CA1C0F0DEF4AULL,
		0xE6567A133CC60A54ULL,
		0x0133DF712EC0E90AULL,
		0x831FF04428671840ULL,
		0x9BE1CE5169639A31ULL,
		0x792A7725E80CDDF7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988B30E10CAF0021ULL,
		0x1C2AEF2FA3E1952EULL,
		0x75A91FA8F42AE073ULL,
		0xC66D33DB92BF832EULL,
		0x6FFDDDB9996F40A9ULL,
		0x753F859683BE8C57ULL,
		0xC8E437E172C68655ULL,
		0x86735EBA6AD84383ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 354 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33D30C2D52971181ULL,
		0x1AC9BE4EB3491F40ULL,
		0xE20F6AFAE0BE53DFULL,
		0x19BC5605826A3810ULL,
		0xBC7E465BB03D0CE5ULL,
		0xAA1D88FCB8A7E7A7ULL,
		0x859BD4F907A7B464ULL,
		0x42928845D35720A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA65AB1243B4668B0ULL,
		0xBF223F24037F7D8FULL,
		0xE119997DB890C1F2ULL,
		0xBE6E8DE2A9EBF4A8ULL,
		0xB10A8E3F4DA3C840ULL,
		0xDFBA43FB5F2B20DBULL,
		0x03ED616D43B81700ULL,
		0x540D8FEB04EDC975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9589BD0969D17931ULL,
		0xA5EB816AB03662CFULL,
		0x0316F387582E922DULL,
		0xA7D2DBE72B81CCB8ULL,
		0x0D74C864FD9EC4A5ULL,
		0x75A7CB07E78CC77CULL,
		0x8676B594441FA364ULL,
		0x169F07AED7BAE9D2ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 355 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE19B5E52F11FD08ULL,
		0x68A2DE718A013A6AULL,
		0x5BA2E11D36078D49ULL,
		0xD92178D6D4EE58B3ULL,
		0x38E1C4135747B9C6ULL,
		0x83D1379FCD03C77AULL,
		0xADD269941D325AD1ULL,
		0xD4AB38433CEFAD29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DAED42E9FD1BCF9ULL,
		0x082C6A596785A7FDULL,
		0xFEC2E6A920D386EBULL,
		0xA4891B29EEE7CB87ULL,
		0x22E6D3A2E01FAFE7ULL,
		0xEC9EB4723F097E91ULL,
		0x479C270E973EE23DULL,
		0x5580DC5C01FE0B7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3B761CBB0C041F1ULL,
		0x608EB428ED849D97ULL,
		0xA56007B416D40BA2ULL,
		0x7DA863FF3A099334ULL,
		0x1A0717B1B7581621ULL,
		0x6F4F83EDF20AB9EBULL,
		0xEA4E4E9A8A0CB8ECULL,
		0x812BE41F3D11A656ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 356 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x237C7E79F50F9C59ULL,
		0xB9E8ED3EE53B9ACBULL,
		0x58D5CF15C2D1EFDBULL,
		0x3512E0E9EAB75F7EULL,
		0xEDD3993CF1CB492CULL,
		0x7B927F344B5F2E39ULL,
		0x00BBF3EF23A28265ULL,
		0xB1C266A975E6F8E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31EEF31598DE3B88ULL,
		0x98DC62DA7BC7FC31ULL,
		0xD195076715A6EA21ULL,
		0xBF0F89E8745EA06CULL,
		0xC74DA4CEEF169456ULL,
		0xE85C5475442DE72FULL,
		0x8C5A05281EB124D4ULL,
		0xA4DF5D73DEC26AFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12928D6C6DD1A7D1ULL,
		0x21348FE49EFC66FAULL,
		0x8940C872D77705FAULL,
		0x8A1D69019EE9FF12ULL,
		0x2A9E3DF21EDDDD7AULL,
		0x93CE2B410F72C916ULL,
		0x8CE1F6C73D13A6B1ULL,
		0x151D3BDAAB24921FULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 357 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A72A2540A93891ULL,
		0xBFDBA404D0800726ULL,
		0xEE77091A705848C3ULL,
		0xA2190FF81E33712BULL,
		0xD98C44E1EDA7288CULL,
		0xF96F367681D00226ULL,
		0x6B56B655CFBF43F6ULL,
		0xC80EDCCD77B5E37AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D90E748E40340AEULL,
		0x9F54610FD4579D34ULL,
		0x444BF4644165DB8DULL,
		0x7950B7EA518418FFULL,
		0x8FE9CDCB0245B4F5ULL,
		0xF9F69A393FBAA193ULL,
		0xCB2D45CCFA110B30ULL,
		0x8E18011EF0498920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A37CD6DA4AA783FULL,
		0x208FC50B04D79A12ULL,
		0xAA3CFD7E313D934EULL,
		0xDB49B8124FB769D4ULL,
		0x5665892AEFE29C79ULL,
		0x0099AC4FBE6AA3B5ULL,
		0xA07BF39935AE48C6ULL,
		0x4616DDD387FC6A5AULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 358 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD15346FF9653276ULL,
		0x5B999CEE5B9E00F9ULL,
		0x9DB56E2D0178365DULL,
		0x767A854E55514546ULL,
		0x101C3BE6FB5262F2ULL,
		0x868BA956DC393863ULL,
		0x0FB3F4A4D01EE0AEULL,
		0x40AD2B091A15AA00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD691E9FC39C2E486ULL,
		0x20927390BA70331FULL,
		0x159FE192C9FC4218ULL,
		0x18C188AF2A521CF1ULL,
		0x424BE186796B2F64ULL,
		0xDBCDBC76BAFB8D5AULL,
		0x9365DDB640AEC1C6ULL,
		0x3BC4F4B5FEC81949ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B84DD93C0A7D6F0ULL,
		0x7B0BEF7EE1EE33E6ULL,
		0x882A8FBFC8847445ULL,
		0x6EBB0DE17F0359B7ULL,
		0x5257DA6082394D96ULL,
		0x5D46152066C2B539ULL,
		0x9CD6291290B02168ULL,
		0x7B69DFBCE4DDB349ULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 359 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72C8AE6D7E52FD65ULL,
		0xB031742855543095ULL,
		0x3DCE3397FC315583ULL,
		0x0B255AFA37FEDB70ULL,
		0x2BDEE3D1A0C28961ULL,
		0x9D0FBAB4419256A2ULL,
		0x605F9D17BFE2D2E0ULL,
		0x7FB43EE8542C13E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3663D36721FD67ULL,
		0x13BEED161B4B1C46ULL,
		0x85C95E0130FD7724ULL,
		0x793A63BAB35DD0C8ULL,
		0x8DF9426E332293A3ULL,
		0x9272FAADBBEDFB4AULL,
		0x162EEDF6D291B10BULL,
		0x734A1A9E2B01D3E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACFECDBE19730002ULL,
		0xA38F993E4E1F2CD3ULL,
		0xB8076D96CCCC22A7ULL,
		0x721F394084A30BB8ULL,
		0xA627A1BF93E01AC2ULL,
		0x0F7D4019FA7FADE8ULL,
		0x767170E16D7363EBULL,
		0x0CFE24767F2DC00DULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 360 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66B625C4B1B57B1EULL,
		0xE654C37DBA91A3F8ULL,
		0x720E19FD0CA1DB7EULL,
		0xE4D3A329AF2A9777ULL,
		0x7AC27C8D848C49BCULL,
		0xC1BDDE28C1A5E934ULL,
		0x75A95286338D9FCAULL,
		0xAC6B50F367F6C5A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5FEBFE3F7EE097ULL,
		0x31BD5C97DEE7B726ULL,
		0x2D5043B0DB0B63E5ULL,
		0x288726D32691E151ULL,
		0xE461FF10C3D2B873ULL,
		0xBAC5BAF68CFE9658ULL,
		0xB4AC60B769AABEA3ULL,
		0x1ACA0E2B6EE096D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBE9CE3A8ECB9B89ULL,
		0xD7E99FEA647614DEULL,
		0x5F5E5A4DD7AAB89BULL,
		0xCC5485FA89BB7626ULL,
		0x9EA3839D475EF1CFULL,
		0x7B7864DE4D5B7F6CULL,
		0xC10532315A272169ULL,
		0xB6A15ED80916537BULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 361 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0933045C362AD25DULL,
		0xC70967C4167902F0ULL,
		0xA9AA5F140210C3ECULL,
		0xAAC4335200F630D1ULL,
		0xC768E7BDCCA19DFCULL,
		0xF44F3C1A1EB81282ULL,
		0xD76ACDB134CBA2EDULL,
		0xD1C89E14BAF1C07CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C4DB83393A036CULL,
		0x032DF8346C9D06C8ULL,
		0xBF475ED9BC0C8A8DULL,
		0x7912501C01DDAE06ULL,
		0xE209867883D3321EULL,
		0x2AC7A71978A86707ULL,
		0x5C22F162E13790F2ULL,
		0x9C9DDE7275EEA37CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41F7DFDF0F10D131ULL,
		0xC4249FF07AE40438ULL,
		0x16ED01CDBE1C4961ULL,
		0xD3D6634E012B9ED7ULL,
		0x256161C54F72AFE2ULL,
		0xDE889B0366107585ULL,
		0x8B483CD3D5FC321FULL,
		0x4D554066CF1F6300ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 362 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD59A1266BC5C8335ULL,
		0x5239B64ABEF439B8ULL,
		0xBCBD279FFA05A967ULL,
		0xA8F5F6BFD8EF80A6ULL,
		0xCEFF272B9F7DCE2CULL,
		0xCDC96CD7939603D1ULL,
		0x788347628286CE1DULL,
		0x2C3F971A5AA93F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x949E4693E0C0D58EULL,
		0x6FD60EB88C576F5EULL,
		0xD03CC5CC3FA79353ULL,
		0x4A44D19E8B77200DULL,
		0x6D64C368867FEC4DULL,
		0x7A632AE8ACD8EF44ULL,
		0x49E4B37E6FD9BCA4ULL,
		0x87C3114F0AD9AE13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410454F55C9C56BBULL,
		0x3DEFB8F232A356E6ULL,
		0x6C81E253C5A23A34ULL,
		0xE2B127215398A0ABULL,
		0xA39BE44319022261ULL,
		0xB7AA463F3F4EEC95ULL,
		0x3167F41CED5F72B9ULL,
		0xABFC865550709111ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 363 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC807767A5AF3393CULL,
		0x6AC5AE87B197BCBCULL,
		0x88B39262BB96BD46ULL,
		0x03FC74401802E741ULL,
		0x6166DC368D53A46AULL,
		0x2107BD64D51F6F72ULL,
		0xC4CB9B6208A298A9ULL,
		0x26D6C151EAF22EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0265415A6C0465ULL,
		0x670107223500F9E6ULL,
		0x5196048FA4FBBE6AULL,
		0xD9C8DCC1EDD31E3EULL,
		0x72E341A02E1A8D0EULL,
		0xB548C69BA2AC6B0FULL,
		0xB90597BF814ABFDAULL,
		0x0E39AC22EB1BEA80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5305133B009F3D59ULL,
		0x0DC4A9A58497455AULL,
		0xD92596ED1F6D032CULL,
		0xDA34A881F5D1F97FULL,
		0x13859D96A3492964ULL,
		0x944F7BFF77B3047DULL,
		0x7DCE0CDD89E82773ULL,
		0x28EF6D7301E9C42EULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 364 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x786BFC8BEEE3857CULL,
		0xA6773F147E2FB5D2ULL,
		0x91B165EB7AB5C81EULL,
		0xB86FAB79648550DFULL,
		0xC22824243D9709DFULL,
		0xE25AB325CF071A01ULL,
		0xACB1591F53D5611DULL,
		0x05C1AA3C63EA82EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE1EE3C8579321F9ULL,
		0x7E7A85F4346D9803ULL,
		0x28B689024196AF25ULL,
		0x7AEEBE1A677A7C1BULL,
		0x15A68109F6FB0BF5ULL,
		0xAA0AC725FCECBD7AULL,
		0xBB7FB9408AAC31D6ULL,
		0x583F3CB38A01AC4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86751F43B970A485ULL,
		0xD80DBAE04A422DD1ULL,
		0xB907ECE93B23673BULL,
		0xC281156303FF2CC4ULL,
		0xD78EA52DCB6C022AULL,
		0x4850740033EBA77BULL,
		0x17CEE05FD97950CBULL,
		0x5DFE968FE9EB2EA4ULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 365 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97342431035EC7CFULL,
		0xE7AA4A1EBCBCCC37ULL,
		0xA19F5C26E43C7F5CULL,
		0xC74AA4966E222292ULL,
		0x1DC5E2D90DA4D0FBULL,
		0x7A045BD3C0004186ULL,
		0xEEB7F2391A479099ULL,
		0x48EA77C1E1ECE178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648AD962D785A8F2ULL,
		0x57553C65A131370AULL,
		0x02B5B1A5192C82DCULL,
		0x29E0862B24307B80ULL,
		0xEF965F5CF356F100ULL,
		0x56A191B21625371BULL,
		0x2E58629FF5F9FB4AULL,
		0x9C6A5F12A7E6D0DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3BEFD53D4DB6F3DULL,
		0xB0FF767B1D8DFB3DULL,
		0xA32AED83FD10FD80ULL,
		0xEEAA22BD4A125912ULL,
		0xF253BD85FEF221FBULL,
		0x2CA5CA61D625769DULL,
		0xC0EF90A6EFBE6BD3ULL,
		0xD48028D3460A31A3ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 366 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x792D561BAEF7561CULL,
		0x764B42269785F1E6ULL,
		0x203A6A320A8D3544ULL,
		0xCB05FE329FFAC2BDULL,
		0x77AEFE1C7B917946ULL,
		0x87482D252A0371C4ULL,
		0x0047C26EDBC8A11DULL,
		0x5250991E8130E2CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA24443B98823331CULL,
		0x759B614441B2C51BULL,
		0x1D08E0429552ADC2ULL,
		0xBE3342DB11D434DBULL,
		0x3CFCB7662B18CB6AULL,
		0xD697917F439EF149ULL,
		0x6C1E7C77886AB772ULL,
		0x825766F282797F66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB6915A226D46500ULL,
		0x03D02362D63734FDULL,
		0x3D328A709FDF9886ULL,
		0x7536BCE98E2EF666ULL,
		0x4B52497A5089B22CULL,
		0x51DFBC5A699D808DULL,
		0x6C59BE1953A2166FULL,
		0xD007FFEC03499DABULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 367 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF5C601E33C409B2ULL,
		0x39B8DDB6F92BC7FDULL,
		0xC761B178553D7619ULL,
		0x93C1EE712456855CULL,
		0x9844A9E314DC0A75ULL,
		0xCA123A542DB3DEFEULL,
		0x708E8D57C4C51842ULL,
		0xB039CD94439BBD72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED6E5A5E63AA86CULL,
		0x47F59FD64716F9A8ULL,
		0xD7D471F96C2873E7ULL,
		0xD54A32DC82D83D75ULL,
		0xB1B37EBA5C8B10DCULL,
		0xC9B6814BC67D102AULL,
		0x4EA34B47FF7AF99DULL,
		0x721087BA7EB52798ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE18A85BBD5FEA1DEULL,
		0x7E4D4260BE3D3E55ULL,
		0x10B5C081391505FEULL,
		0x468BDCADA68EB829ULL,
		0x29F7D75948571AA9ULL,
		0x03A4BB1FEBCECED4ULL,
		0x3E2DC6103BBFE1DFULL,
		0xC2294A2E3D2E9AEAULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 368 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4D39DE79B50BF3EULL,
		0xA4C7E27CF9337F8AULL,
		0x9D52E542C1B77D58ULL,
		0x8496D41875458B35ULL,
		0xB072E00DE2962342ULL,
		0xA8827D152EDAB2CCULL,
		0x8CE5607E6A83220EULL,
		0x36FA08216BB4A631ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9BC98FD4C2C8EE3ULL,
		0x03CE2C3044A926BAULL,
		0xFEF6A1BB1A537EC4ULL,
		0x826C3877CA1E911FULL,
		0xAB1A6E7C14FFC07FULL,
		0xFB92545AD3F15C26ULL,
		0x60914D5E5C1A66ACULL,
		0x4282E0F71A7B54BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D6F051AD77C31DDULL,
		0xA709CE4CBD9A5930ULL,
		0x63A444F9DBE4039CULL,
		0x06FAEC6FBF5B1A2AULL,
		0x1B688E71F669E33DULL,
		0x5310294FFD2BEEEAULL,
		0xEC742D20369944A2ULL,
		0x7478E8D671CFF28EULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 369 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD217CEC4E4B102B5ULL,
		0xCC410C3E194E63B0ULL,
		0x532F0D616DE6C2BCULL,
		0xB8E3B080A39B0E71ULL,
		0xA98B55BF2C934C58ULL,
		0x42183567D56F311FULL,
		0x379C5DB27B84F046ULL,
		0x40EBBB21493EB852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39E347269006A396ULL,
		0x357790FFE2F5937AULL,
		0x0471D4C2F255072CULL,
		0x25A1034B02C2ECE2ULL,
		0x823B6C049C4B491BULL,
		0xD474B45BFCBB9D37ULL,
		0x459B842EEC719CB9ULL,
		0x203A6E654F06C4A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBF489E274B7A123ULL,
		0xF9369CC1FBBBF0CAULL,
		0x575ED9A39FB3C590ULL,
		0x9D42B3CBA159E293ULL,
		0x2BB039BBB0D80543ULL,
		0x966C813C29D4AC28ULL,
		0x7207D99C97F56CFFULL,
		0x60D1D54406387CFAULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 370 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00D6F4423E93FF9AULL,
		0x026F12402CF9727DULL,
		0x01AFF85C30EE95F5ULL,
		0xF790FFDF4872AFE6ULL,
		0xAB8CB866229DF83EULL,
		0x2A36ACF76366C7F7ULL,
		0xCABAD0D27BD6CA0FULL,
		0x3A34BE71D88D2F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043253549A3BA3EBULL,
		0x419308F8C0CE1EA6ULL,
		0x9B23D2F563C92B07ULL,
		0x549121FE3A2109BCULL,
		0xF54DC9B81ABA8446ULL,
		0x864E2315C4D16B28ULL,
		0x4245F679FF797839ULL,
		0xCC8B2A818CC19A54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E4A716A4A85C71ULL,
		0x43FC1AB8EC376CDBULL,
		0x9A8C2AA95327BEF2ULL,
		0xA301DE217253A65AULL,
		0x5EC171DE38277C78ULL,
		0xAC788FE2A7B7ACDFULL,
		0x88FF26AB84AFB236ULL,
		0xF6BF94F0544CB50BULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 371 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BB81EE55A63C451ULL,
		0xE392748333BC0B42ULL,
		0xC10A738A9693C3FEULL,
		0x20008AF768A610A8ULL,
		0xDB6E70B0836BE4D1ULL,
		0x85148E342B46B2D7ULL,
		0xCD2FD42FBA11FD95ULL,
		0x2B58F7F6B8237E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A1493385AEEB19ULL,
		0xD55B4E116E78A128ULL,
		0x4EDA51D892FE7B13ULL,
		0x5D7AF2E4C8F47344ULL,
		0x36F073AA6A8243A2ULL,
		0xC5493E8B4779FB1BULL,
		0xC501504BC7B0592AULL,
		0x2A9B75A75ED20326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x631957D6DFCD2F48ULL,
		0x36C93A925DC4AA6AULL,
		0x8FD02252046DB8EDULL,
		0x7D7A7813A05263ECULL,
		0xED9E031AE9E9A773ULL,
		0x405DB0BF6C3F49CCULL,
		0x082E84647DA1A4BFULL,
		0x01C38251E6F17D39ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 372 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDF0480EF89019F3ULL,
		0xCBAE00F970B1EF5FULL,
		0xE5AE7CB7261D950CULL,
		0x87CC07673471DCBFULL,
		0x4303646409A31D49ULL,
		0xCD90D9124D3F5BC5ULL,
		0xB25FBF66A5FC41B4ULL,
		0xE25D5B7AAB2936DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5EF7809BF5E37FCULL,
		0x633DB46D99150C8AULL,
		0xF214CBB1762F9E56ULL,
		0x8C5375A7D7361857ULL,
		0x32DEB90BF29B289AULL,
		0x1738915472397539ULL,
		0x154578E3B23AC2CFULL,
		0xED7CC98B301D3379ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x781F300747CE2E0FULL,
		0xA893B494E9A4E3D5ULL,
		0x17BAB70650320B5AULL,
		0x0B9F72C0E347C4E8ULL,
		0x71DDDD6FFB3835D3ULL,
		0xDAA848463F062EFCULL,
		0xA71AC78517C6837BULL,
		0x0F2192F19B3405A6ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 373 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDDD34066F1C38D0ULL,
		0x1CFC59D35E2B7DE4ULL,
		0x727FB36AF1B35309ULL,
		0x84A94B10F48122D7ULL,
		0x135D5CF89604C563ULL,
		0x9498BAF0CF5217A6ULL,
		0x879F8110E44426F2ULL,
		0xD502693DCF167245ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E03270EC9DB83DULL,
		0x1ADA5E5AE5BC80D2ULL,
		0xBEE203437558364BULL,
		0x63ABEDC0631D5450ULL,
		0x284CBFFA25A48BCBULL,
		0x164A5FB897DE7014ULL,
		0x0F6EA185D1E4332FULL,
		0x52418A8810C32193ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB3D0676838180EDULL,
		0x06260789BB97FD36ULL,
		0xCC9DB02984EB6542ULL,
		0xE702A6D0979C7687ULL,
		0x3B11E302B3A04EA8ULL,
		0x82D2E548588C67B2ULL,
		0x88F1209535A015DDULL,
		0x8743E3B5DFD553D6ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 374 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6550AC04C07AE2FEULL,
		0x08CB051ABAE88CE2ULL,
		0x088FF5343E3B3153ULL,
		0x3DC11CFB7033A2A8ULL,
		0x5BC0B03822C63126ULL,
		0x72EEBCC758061683ULL,
		0xA0BE081AA0DF728EULL,
		0xEED30DE8BF06D265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE12ED986F84D3BULL,
		0x1F36B30265537BEBULL,
		0xA85C41F7359AC1CCULL,
		0xA7EB67952D0A07A6ULL,
		0xFBA5D5B773514044ULL,
		0x083ABB37A9F2DE87ULL,
		0xFB791FAB7DF254DAULL,
		0x3C36B0C1CF717E0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBB182DD4682AFC5ULL,
		0x17FDB618DFBBF709ULL,
		0xA0D3B4C30BA1F09FULL,
		0x9A2A7B6E5D39A50EULL,
		0xA065658F51977162ULL,
		0x7AD407F0F1F4C804ULL,
		0x5BC717B1DD2D2654ULL,
		0xD2E5BD297077AC6BULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 375 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7ACF29C1694A8516ULL,
		0x41FE5B3A98CF48EDULL,
		0xFE2A5E9A05837836ULL,
		0x34B726A10544A690ULL,
		0x661A96C253500AC6ULL,
		0xB85AFFC11A6EC14CULL,
		0x98AFDAD18594EE40ULL,
		0xB8E882998CEA88D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67A835B4063A501AULL,
		0x7FB0C13A7EA8FFDEULL,
		0xD20EE53AE5EC2F79ULL,
		0x7FFC5DC9094BC44EULL,
		0x12D5D593A720A3A3ULL,
		0x6B3A4EC1639E91AAULL,
		0x138F7BF74FD7FEEFULL,
		0xF19A0ED33DCD54E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D671C756F70D50CULL,
		0x3E4E9A00E667B733ULL,
		0x2C24BBA0E06F574FULL,
		0x4B4B7B680C0F62DEULL,
		0x74CF4351F470A965ULL,
		0xD360B10079F050E6ULL,
		0x8B20A126CA4310AFULL,
		0x49728C4AB127DC39ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 376 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76108EC59B9555A8ULL,
		0x2547C025AC4A353AULL,
		0xEC00A9D7D59D1627ULL,
		0x5A3C090AA1A939D8ULL,
		0xDABCE22A82BC96CBULL,
		0xC6C7BB714C9FA22EULL,
		0x50DC6E56CEFC87B4ULL,
		0xFF219CBB6F794054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B37D0D3A7F4954EULL,
		0x0C886ED68E47E4BAULL,
		0xE51D20137BA61A7DULL,
		0xB927C542C3366350ULL,
		0xAEF1170EDB402F86ULL,
		0x5B8731EDF2124EB8ULL,
		0xF1A9B1B1C19DDFE4ULL,
		0xB29B5E5473B8DB4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD275E163C61C0E6ULL,
		0x29CFAEF3220DD180ULL,
		0x091D89C4AE3B0C5AULL,
		0xE31BCC48629F5A88ULL,
		0x744DF52459FCB94DULL,
		0x9D408A9CBE8DEC96ULL,
		0xA175DFE70F615850ULL,
		0x4DBAC2EF1CC19B1BULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 377 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4108EE323BFF33E8ULL,
		0x5EB9A23375F46CFBULL,
		0x53444E5D3E9181A1ULL,
		0x1A7289296C0FE5CEULL,
		0x5110C3C0B7E2DBDEULL,
		0x1B37D4C7A4557D45ULL,
		0x1DB19B12C9C4AFFEULL,
		0xEEA095CC4A9154DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7872A120A702BF5ULL,
		0x46D7AF112F45AB60ULL,
		0x10AD537E886551A8ULL,
		0x1FBB13888BA79754ULL,
		0x3C26F6CBDF985122ULL,
		0x3425EDF58843EFB0ULL,
		0xEF476386012C5F04ULL,
		0x08C0D86536C50F6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB68FC420318F181DULL,
		0x186E0D225AB1C79BULL,
		0x43E91D23B6F4D009ULL,
		0x05C99AA1E7A8729AULL,
		0x6D36350B687A8AFCULL,
		0x2F1239322C1692F5ULL,
		0xF2F6F894C8E8F0FAULL,
		0xE6604DA97C545BB4ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 378 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB693DAC1CFACFA66ULL,
		0xB9D4FD4FB36D65A2ULL,
		0x3E0C3A5C12E2D389ULL,
		0x6D74FD51EDB5B585ULL,
		0xD1429623F00D1708ULL,
		0xC9A5C7D40FE5450CULL,
		0xEDD959844920041DULL,
		0x2B3B61AE9EC5E4E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B93F1909917CE6ULL,
		0xC95299E858C49B4AULL,
		0xDFC9328A9A62A3B8ULL,
		0x3023774C068FFA3DULL,
		0xDA43B043F3C6438CULL,
		0x9DCD44FD55A5B6A1ULL,
		0x710EEC31CFE01A27ULL,
		0x3F719C8D2D1DA015ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x812AE5D8C63D8680ULL,
		0x708664A7EBA9FEE8ULL,
		0xE1C508D688807031ULL,
		0x5D578A1DEB3A4FB8ULL,
		0x0B01266003CB5484ULL,
		0x546883295A40F3ADULL,
		0x9CD7B5B586C01E3AULL,
		0x144AFD23B3D844F7ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 379 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E576204B2CF7217ULL,
		0x7537369EBE45AD65ULL,
		0x5CE7EACCD4CD5871ULL,
		0xD37E9F215694644DULL,
		0xE2049AF335D9696BULL,
		0x97AAB1DCB7C49D74ULL,
		0xAC9DE7799BB31B36ULL,
		0xBCF545C611232951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2D162460096B5A0ULL,
		0x9EEE1372FEE2CC68ULL,
		0x6C98B7BEA22D22C6ULL,
		0x478976F9FB7CAF7AULL,
		0x4ACBA6C646F0FAD6ULL,
		0xB3FA4C5FFAEEAEEBULL,
		0xB3FACB6A20216342ULL,
		0x0A37CB68B3BF5DC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC860042B259C7B7ULL,
		0xEBD925EC40A7610DULL,
		0x307F5D7276E07AB7ULL,
		0x94F7E9D8ADE8CB37ULL,
		0xA8CF3C35732993BDULL,
		0x2450FD834D2A339FULL,
		0x1F672C13BB927874ULL,
		0xB6C28EAEA29C7490ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 380 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x233C2777E5E57B96ULL,
		0xCEC706BC4711A225ULL,
		0xF6EB6BA7CEC9F0F8ULL,
		0x51993E805C41E305ULL,
		0x05073DC57BE08740ULL,
		0xF5519F9202BA9177ULL,
		0x38C7C17F282C11EAULL,
		0x6A11EA059D53B88EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F47E03858A069DULL,
		0x12A5BE0766D7EF4BULL,
		0xE17EA094D3E06C0FULL,
		0x441FD870A7D22529ULL,
		0xCF483CD313377AC5ULL,
		0x9B06264CEB1C2F29ULL,
		0x653B5E84FF8C1BB6ULL,
		0x162C9985EFCD2D6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0C85974606F7D0BULL,
		0xDC62B8BB21C64D6EULL,
		0x1795CB331D299CF7ULL,
		0x1586E6F0FB93C62CULL,
		0xCA4F011668D7FD85ULL,
		0x6E57B9DEE9A6BE5EULL,
		0x5DFC9FFBD7A00A5CULL,
		0x7C3D7380729E95E4ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 381 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7790E03E1DD4739ULL,
		0x5EBA2340EC1791EBULL,
		0x96A7B9C0EEFCA322ULL,
		0x322283A09043C55DULL,
		0xB26CC7E92DD51F9FULL,
		0xB50D18027DA7677FULL,
		0x049DAA2F2621C4F5ULL,
		0x629B1C8E8A870B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3765DA3FE4F34A89ULL,
		0xFC3434B22B4109A7ULL,
		0x793677B59689949BULL,
		0xC872568F6391B7A3ULL,
		0x0D44512F889EE68DULL,
		0x3B95082BB63C8572ULL,
		0x7C94170AC2A1F29EULL,
		0xCB42B7609C927557ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x901CD43C052E0DB0ULL,
		0xA28E17F2C756984CULL,
		0xEF91CE75787537B9ULL,
		0xFA50D52FF3D272FEULL,
		0xBF2896C6A54BF912ULL,
		0x8E981029CB9BE20DULL,
		0x7809BD25E480366BULL,
		0xA9D9ABEE16157E60ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 382 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A0710FF200CA0E5ULL,
		0xE14F45CA714CD879ULL,
		0x96C0FE06338913B1ULL,
		0x04E53F4F00B54B2FULL,
		0x23CB04C37029E80BULL,
		0xEE4F77E165956198ULL,
		0xD2092C47BF9991E1ULL,
		0xFFC0D25C8EC9B2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AD75E55EFFA0F1ULL,
		0x2E315B09AC70856DULL,
		0x389E3BFA2018EDFFULL,
		0xE837775958AC2A2BULL,
		0x334B4A946854905BULL,
		0xCE6421BB7C513BB9ULL,
		0x38B45CA0E11E2849ULL,
		0x6E94C2401845DA25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72AA651A7EF30014ULL,
		0xCF7E1EC3DD3C5D14ULL,
		0xAE5EC5FC1391FE4EULL,
		0xECD2481658196104ULL,
		0x10804E57187D7850ULL,
		0x202B565A19C45A21ULL,
		0xEABD70E75E87B9A8ULL,
		0x9154101C968C6896ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 383 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD593E86C3EBE113BULL,
		0xCDDA0BD89B60A39CULL,
		0x15FC0C3B78B468D0ULL,
		0xEB9FAFAA12F5B450ULL,
		0x6F4197F935E77522ULL,
		0x18144AEC32823681ULL,
		0xA5EB61D0316179A2ULL,
		0x04818E007DC02B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51D0AE920AE25898ULL,
		0xDDFA6C549425D837ULL,
		0x51620A0C639E0BFAULL,
		0x8B065CC197C0077CULL,
		0x940F927EADEFC4B1ULL,
		0xC28AEB00ABC4C8E3ULL,
		0x14483F241C7A7B3CULL,
		0x5D5E92D3A94C89F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x844346FE345C49A3ULL,
		0x1020678C0F457BABULL,
		0x449E06371B2A632AULL,
		0x6099F36B8535B32CULL,
		0xFB4E05879808B193ULL,
		0xDA9EA1EC9946FE62ULL,
		0xB1A35EF42D1B029EULL,
		0x59DF1CD3D48CA29FULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 384 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x253D952BD34DE6EFULL,
		0xC301D73ED74C1294ULL,
		0xCA67F5F4CD353023ULL,
		0x903C01EFD0D10CF0ULL,
		0x49499DFF56371531ULL,
		0x20365F9CD83353E3ULL,
		0xFD0F9CF694F5A9FFULL,
		0x92404BDA2C9F6173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FB79CD948911EBULL,
		0x1BB5ED2483471F06ULL,
		0xCA051F7448575ACFULL,
		0x5164BFE8E74C499CULL,
		0xFF590661E047F590ULL,
		0xFA84462819ED6434ULL,
		0x66400D38ADF25374ULL,
		0x0A98F7A0DD336CC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DC6ECE647C4F704ULL,
		0xD8B43A1A540B0D92ULL,
		0x0062EA8085626AECULL,
		0xC158BE07379D456CULL,
		0xB6109B9EB670E0A1ULL,
		0xDAB219B4C1DE37D7ULL,
		0x9B4F91CE3907FA8BULL,
		0x98D8BC7AF1AC0DB7ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 385 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF389355607B2299BULL,
		0xD27FBA9975CBEAB6ULL,
		0x90C3A04659E9799BULL,
		0x55D6F1EECCCD47A9ULL,
		0x8544C73981732B9FULL,
		0x32531CCC014820D3ULL,
		0x34E47FDDD6FB1640ULL,
		0xA6E9C97F0B02CB79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8F1F3E533C60B62ULL,
		0xFFB6835C9B2E5A38ULL,
		0xB5D1A26E783910E7ULL,
		0x775596ED1E1183C8ULL,
		0x1E82C5D507CB28B1ULL,
		0xCBFC8AFCB8E84EC5ULL,
		0x5125D68196857F8DULL,
		0xAB74CE882E289B08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B78C6B3347422F9ULL,
		0x2DC939C5EEE5B08EULL,
		0x2512022821D0697CULL,
		0x22836703D2DCC461ULL,
		0x9BC602EC86B8032EULL,
		0xF9AF9630B9A06E16ULL,
		0x65C1A95C407E69CDULL,
		0x0D9D07F7252A5071ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 386 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49BE7B0FCF36BE2BULL,
		0x012EEA6DE4F1C9B5ULL,
		0x3AD6BD969AEB7CABULL,
		0x1AD7B76819E1EEC0ULL,
		0x210DB5B5AF306B1CULL,
		0xB4D38ED4947EBD45ULL,
		0x3041BA20E397F52FULL,
		0xFB01717B99402895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEFE76F4059463D6ULL,
		0xDB55677B31B2AE32ULL,
		0x4BEC42060379B27CULL,
		0x160958EE0214D14CULL,
		0x77FED75A76735F34ULL,
		0xEE5BEDCC3D3E583CULL,
		0xA2BC0B355F29B604ULL,
		0xD37BBAAC3C3D2EAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7400DFBCAA2DDFDULL,
		0xDA7B8D16D5436787ULL,
		0x713AFF909992CED7ULL,
		0x0CDEEF861BF53F8CULL,
		0x56F362EFD9433428ULL,
		0x5A886318A940E579ULL,
		0x92FDB115BCBE432BULL,
		0x287ACBD7A57D063FULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 387 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03973CBDA62FBF17ULL,
		0xE95D80C7C028C373ULL,
		0x2F1FE6073650D463ULL,
		0xA5E6C105079356AEULL,
		0xEACDC675584009AFULL,
		0x8AB5E8F418AB3CDFULL,
		0x37F72D7E143A5974ULL,
		0x7741E70D14A972BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77BC861FB2FDF011ULL,
		0x11D6E850AF469AFFULL,
		0xBBCBDF77713FE373ULL,
		0xE4D7E0B854DC6D0EULL,
		0x80592CF604760ED7ULL,
		0xFE85F47E5C444DF5ULL,
		0x4FD96D766473C67EULL,
		0x66880B035F098509ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x742BBAA214D24F06ULL,
		0xF88B68976F6E598CULL,
		0x94D43970476F3710ULL,
		0x413121BD534F3BA0ULL,
		0x6A94EA835C360778ULL,
		0x74301C8A44EF712AULL,
		0x782E400870499F0AULL,
		0x11C9EC0E4BA0F7B3ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 388 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D3A1F569026CB43ULL,
		0xAD6AFC3C9521BFE7ULL,
		0x0B1B48AD8AE14BE6ULL,
		0x71A4E31DEA20EE59ULL,
		0xD54281B9FE517869ULL,
		0x12A7955FC304A736ULL,
		0x761AE4C03D701213ULL,
		0x96C8E40ABE3E826CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D4F85BD3B3468A5ULL,
		0xEC9B753138F0DC03ULL,
		0x26699C66290039F3ULL,
		0x7D5550D258442BBBULL,
		0x6838F32271DB4A69ULL,
		0xC1985F16995E0874ULL,
		0x9B1CFE74B710B799ULL,
		0x3D6FCB66198164AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0759AEBAB12A3E6ULL,
		0x41F1890DADD163E4ULL,
		0x2D72D4CBA3E17215ULL,
		0x0CF1B3CFB264C5E2ULL,
		0xBD7A729B8F8A3200ULL,
		0xD33FCA495A5AAF42ULL,
		0xED061AB48A60A58AULL,
		0xABA72F6CA7BFE6C6ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 389 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDA3E5380AB2FBACULL,
		0xB60854F84FB4E545ULL,
		0xF7DB9B754572804DULL,
		0xCDB96E30F4CDED7BULL,
		0x4DCB78755137493EULL,
		0xD68F8E796929E056ULL,
		0x4021AE486CAE8DBEULL,
		0x7B2555515105868FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x036088F111875B5FULL,
		0xD5C46A110A84A7E9ULL,
		0x54084C475495B330ULL,
		0xBB4A37273E0AC793ULL,
		0x4CEC092C785163CBULL,
		0xCB7BEE6D79C01C99ULL,
		0x478F31B981AB0A12ULL,
		0x3A2D703E7BF4BCE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEC36DC91B35A0F3ULL,
		0x63CC3EE9453042ACULL,
		0xA3D3D73211E7337DULL,
		0x76F35917CAC72AE8ULL,
		0x0127715929662AF5ULL,
		0x1DF4601410E9FCCFULL,
		0x07AE9FF1ED0587ACULL,
		0x4108256F2AF13A67ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 390 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB08DE21DA339476FULL,
		0x95E02A1F1EEA7711ULL,
		0x227543437D30C053ULL,
		0xD2E6EE7988796114ULL,
		0xB48235C3039D3E5FULL,
		0x0CB5540C6B49AF5CULL,
		0xC5C18EE35C635045ULL,
		0xF95767C277244078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4374B8D64656D76ULL,
		0xD25789186E838B73ULL,
		0xCE431EE724623753ULL,
		0xA1CBF9AA51BF13FEULL,
		0x1C80782FF01539A4ULL,
		0xFE5488DE6DB24E94ULL,
		0x1987BCF103291D05ULL,
		0x3AC4DE63FC14D237ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64BAA990C75C2A19ULL,
		0x47B7A3077069FC62ULL,
		0xEC365DA45952F700ULL,
		0x732D17D3D9C672EAULL,
		0xA8024DECF38807FBULL,
		0xF2E1DCD206FBE1C8ULL,
		0xDC4632125F4A4D40ULL,
		0xC393B9A18B30924FULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 391 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29B00C542BCB3AC0ULL,
		0x13064562E8AFA685ULL,
		0x9F325C77751E6CDDULL,
		0x3139B6689678DC3DULL,
		0xA076F4FB1C48FAF4ULL,
		0x708C197C5ABEE0E3ULL,
		0x37AE46CDAC16A1A4ULL,
		0xDAD0FC5D8CF1AB6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8340C69BCA9EDA6ULL,
		0x2C5A2413BC5B5DD5ULL,
		0x17B04F630816F351ULL,
		0x2914A54FD566E8DAULL,
		0x0639F50459BA7D80ULL,
		0xE1C3D154584C0050ULL,
		0xCF6EFADE7565641FULL,
		0x5F109E5041045537ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF184003D9762D766ULL,
		0x3F5C617154F4FB50ULL,
		0x888213147D089F8CULL,
		0x182D1327431E34E7ULL,
		0xA64F01FF45F28774ULL,
		0x914FC82802F2E0B3ULL,
		0xF8C0BC13D973C5BBULL,
		0x85C0620DCDF5FE5AULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 392 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA4D34F5ABFC1D27ULL,
		0xC4208DD123540302ULL,
		0xA5AEACE271B62343ULL,
		0x2521E1B7383DF2D9ULL,
		0x643941C6A5319AE4ULL,
		0x4BC45E52B78172FFULL,
		0x86961652CB17D3BDULL,
		0x32B78E51D3E868C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E5BB3D1CE836DF5ULL,
		0xFC94F644492331B2ULL,
		0x209E73A6E7416EB3ULL,
		0x4AE481E85923C62DULL,
		0x13E35B4445ABCEEEULL,
		0xDD834912064EB0C0ULL,
		0x0054F563CE883C6CULL,
		0xC4A7EE083BF2A581ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4168724657F70D2ULL,
		0x38B47B956A7732B0ULL,
		0x8530DF4496F74DF0ULL,
		0x6FC5605F611E34F4ULL,
		0x77DA1A82E09A540AULL,
		0x96471740B1CFC23FULL,
		0x86C2E331059FEFD1ULL,
		0xF6106059E81ACD49ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 393 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F6E538ED6F84DDBULL,
		0xB71A05A7822504E3ULL,
		0xEF97BDAE96294657ULL,
		0x25F6EFF48F037BF3ULL,
		0x57615A18766F7945ULL,
		0x4210D33653288082ULL,
		0x0C60941A48C03E20ULL,
		0x59228AF2CDD55B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF87B5410C526EC5ULL,
		0xF2B9017A707B4D78ULL,
		0xD4306100FFC33DB9ULL,
		0xFEFDD4165C4A5AF0ULL,
		0x4578351F67142A5CULL,
		0xB3AACF5E034CC5C8ULL,
		0x4A3E522E92A3061EULL,
		0x8366B615722091B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E9E6CFDAAA231EULL,
		0x45A304DDF25E499BULL,
		0x3BA7DCAE69EA7BEEULL,
		0xDB0B3BE2D3492103ULL,
		0x12196F07117B5319ULL,
		0xF1BA1C685064454AULL,
		0x465EC634DA63383EULL,
		0xDA443CE7BFF5CA2CULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 394 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9F6620E8E4921B1ULL,
		0xFC28E7438E29E65FULL,
		0x4F16DFCEDD0493A0ULL,
		0xA049AEE40CF4F213ULL,
		0xBA21CA369B2DBE6DULL,
		0xEBC5BC544D45CBF1ULL,
		0xBEEA126FA16C3967ULL,
		0xDD3475956735FD72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77B63DDB05C33383ULL,
		0x3F74EF11C7A24A9EULL,
		0xF27B5B597035F375ULL,
		0x49D1E6C17236046EULL,
		0xDEA9ACF159FA2410ULL,
		0x74971C3D7CB82EC1ULL,
		0x417CB283CDC8FD6FULL,
		0x7F5458342FBB9EA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE405FD58B8A1232ULL,
		0xC35C0852498BACC1ULL,
		0xBD6D8497AD3160D5ULL,
		0xE99848257EC2F67DULL,
		0x648866C7C2D79A7DULL,
		0x9F52A06931FDE530ULL,
		0xFF96A0EC6CA4C408ULL,
		0xA2602DA1488E63D2ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 395 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7268E36B02D5A8D3ULL,
		0x8D0712C390176C4FULL,
		0xAAAE8343C4A129ACULL,
		0x5703016B2B562461ULL,
		0x7454FC22DD9F0956ULL,
		0x7244E961EB6F1B21ULL,
		0x11138FB3188D9D09ULL,
		0xFC243FE976C7985DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE99955159B50382ULL,
		0x72F2BB74ACD45337ULL,
		0xE2C7DB9EE702F385ULL,
		0xAB7F5B5ECB39E712ULL,
		0x68244A2ECE2ECD75ULL,
		0x4AD53E6FE83355A2ULL,
		0xE0170E2AF8CB0727ULL,
		0xAAA4E26DA0EB3F7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CF1763A5B60AB51ULL,
		0xFFF5A9B73CC33F78ULL,
		0x486958DD23A3DA29ULL,
		0xFC7C5A35E06FC373ULL,
		0x1C70B60C13B1C423ULL,
		0x3891D70E035C4E83ULL,
		0xF1048199E0469A2EULL,
		0x5680DD84D62CA727ULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 396 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF842D78F467A35A2ULL,
		0x9A432D93180C89C4ULL,
		0xCA92A882AFB5F15EULL,
		0x1195CC5F1371E8E3ULL,
		0x5259F0C01542C443ULL,
		0x213C37748CFBACE6ULL,
		0x30EDDDB777C63192ULL,
		0xF51985D175B9F604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD096FFA80B0C0AF2ULL,
		0xCBF48B81AF74FFCBULL,
		0x47878FC6877670FBULL,
		0xFD0A3E8DF9726BA6ULL,
		0x5FABB49AE016BECBULL,
		0x7BF86C26E421C978ULL,
		0x3F5A4689B2C43050ULL,
		0x8816B1C0C59776ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28D428274D763F50ULL,
		0x51B7A612B778760FULL,
		0x8D15274428C381A5ULL,
		0xEC9FF2D2EA038345ULL,
		0x0DF2445AF5547A88ULL,
		0x5AC45B5268DA659EULL,
		0x0FB79B3EC50201C2ULL,
		0x7D0F3411B02E80A9ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 397 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BC5ADB587A0D68BULL,
		0x22A847DAAB4A777CULL,
		0x25B4EE587D49DACFULL,
		0x2E4203A490F4B8E9ULL,
		0x454D09C09AA46116ULL,
		0x3E406F4FB666EF6EULL,
		0x7A5E1FF6F571691DULL,
		0xA2399F1C3B6DD4D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F035FC414B6ED05ULL,
		0x8FB850597D5EB694ULL,
		0xC3435F777D542EFAULL,
		0x373EC6C1164B1F50ULL,
		0x75EF719936164D0BULL,
		0x260FE701EB045C87ULL,
		0x8DBCE3FE3808FCF4ULL,
		0xC883B02E24CC8681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24C6F27193163B8EULL,
		0xAD101783D614C1E8ULL,
		0xE6F7B12F001DF435ULL,
		0x197CC56586BFA7B9ULL,
		0x30A27859ACB22C1DULL,
		0x184F884E5D62B3E9ULL,
		0xF7E2FC08CD7995E9ULL,
		0x6ABA2F321FA15258ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 398 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x939726E3123E3AA4ULL,
		0x2AC5E55AC86D0F5EULL,
		0x442F15EA83CF2D3EULL,
		0x91EDC256861B59CEULL,
		0x362D8085C24849C9ULL,
		0x59D7AABC85B64B0CULL,
		0xD6C1979C4905AA1EULL,
		0x5D45CEEBD7008D77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEC6439A1E33BC22ULL,
		0x74953988EC32E585ULL,
		0x89A6C51704D098EAULL,
		0x1BF760E758A5C41AULL,
		0x3F125E0CE7D63EC3ULL,
		0xA49DA8A4622CF01AULL,
		0x7A43FA1FB39FFE8BULL,
		0x8AAF406FEAC77A28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D5165790C0D8686ULL,
		0x5E50DCD2245FEADBULL,
		0xCD89D0FD871FB5D4ULL,
		0x8A1AA2B1DEBE9DD4ULL,
		0x093FDE89259E770AULL,
		0xFD4A0218E79ABB16ULL,
		0xAC826D83FA9A5495ULL,
		0xD7EA8E843DC7F75FULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 399 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EF94B20DBFFBB4AULL,
		0xF1F9BFC06A504C6DULL,
		0xC374EFD1541F6D2DULL,
		0xB4B43F36203FB6D2ULL,
		0xA4715CAB6AF18D46ULL,
		0x7FE49C3DDAFB3318ULL,
		0x1087AA2941415E52ULL,
		0x9903AAC61EDB23EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0060DD9AEC3E7724ULL,
		0xF808043B2B4573EBULL,
		0x6B26E67936AB33A3ULL,
		0x86388378012365DAULL,
		0x67F2D535BCAEEBE8ULL,
		0xD1086B3FF0154FB7ULL,
		0x9AAEF9DCA27BC105ULL,
		0x3BA04F1962939ED6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E9996BA37C1CC6EULL,
		0x09F1BBFB41153F86ULL,
		0xA85209A862B45E8EULL,
		0x328CBC4E211CD308ULL,
		0xC383899ED65F66AEULL,
		0xAEECF7022AEE7CAFULL,
		0x8A2953F5E33A9F57ULL,
		0xA2A3E5DF7C48BD38ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 400 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E547A1706563B55ULL,
		0xA07F61C194A60EDFULL,
		0xDF63009CE6133174ULL,
		0xFEB7363DEFFA8AE4ULL,
		0xBA6BD09701BE34ADULL,
		0x322B9A77FCDCD8B8ULL,
		0xD87DF812B48364CCULL,
		0x5975D46A32FA55C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC05BF1A406694FCULL,
		0x382B2AD5DB195CC2ULL,
		0x5DFBC7FE6D6E738FULL,
		0x2559B9EAB39DCBEEULL,
		0xC4D110146B7867EBULL,
		0xCC2B9B6DFFFCEBFFULL,
		0xFCF00B6CD28B502EULL,
		0x24F80A5B47677879ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB251C50D4630AFA9ULL,
		0x98544B144FBF521DULL,
		0x8298C7628B7D42FBULL,
		0xDBEE8FD75C67410AULL,
		0x7EBAC0836AC65346ULL,
		0xFE00011A03203347ULL,
		0x248DF37E660834E2ULL,
		0x7D8DDE31759D2DBBULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 401 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BD577B3E8C5E8E3ULL,
		0xD2AE571DF284373BULL,
		0x5E9A741030C30CBFULL,
		0x231C33BA3C7A3497ULL,
		0xBA7A43C73D7E22A2ULL,
		0xEE084FBF9B65C781ULL,
		0x635F00C70730C8A5ULL,
		0x653165832AF0A2C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x217C533C74B16F0FULL,
		0x7359D54CD2258CDDULL,
		0x0D354873F506C865ULL,
		0x2E9EEBD66F4179A7ULL,
		0x395462C18A9F3A71ULL,
		0xCF4DFF7EF0207204ULL,
		0xCFE4AAD61019D736ULL,
		0x28C19B430FE3C87FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AA9248F9C7487ECULL,
		0xA1F7825120A1BBE6ULL,
		0x53AF3C63C5C5C4DAULL,
		0x0D82D86C533B4D30ULL,
		0x832E2106B7E118D3ULL,
		0x2145B0C16B45B585ULL,
		0xACBBAA1117291F93ULL,
		0x4DF0FEC025136ABEULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 402 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16222EF7DFDC8A05ULL,
		0xB5C5ABAB2A7DE47CULL,
		0xCADCB1B4DC8A877DULL,
		0x69E85659BD1C3826ULL,
		0xE0C858D90345CED3ULL,
		0xEDD10CC21BE6C68AULL,
		0xA17AEABEEA3FF3BEULL,
		0x5565A439938231EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C94D75F3F7CCC7ULL,
		0x63D22B256EADFBD5ULL,
		0x1F306BB14E64ECCCULL,
		0x82A8B74BD513FC23ULL,
		0xDFE2D77439CAD640ULL,
		0x21F230FFD6D0AF48ULL,
		0x3009A96E50A41D92ULL,
		0xF828220F5120624BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FEB63822C2B46C2ULL,
		0xD617808E44D01FA9ULL,
		0xD5ECDA0592EE6BB1ULL,
		0xEB40E112680FC405ULL,
		0x3F2A8FAD3A8F1893ULL,
		0xCC233C3DCD3669C2ULL,
		0x917343D0BA9BEE2CULL,
		0xAD4D8636C2A253A0ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 403 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B116BD2B73BAA5BULL,
		0x2BB797566683B471ULL,
		0x1AD5B9344974E1E8ULL,
		0x3017849AFBCDDFB9ULL,
		0x337840219ABFCF3EULL,
		0x54A5E2AB5712D8AFULL,
		0xB00D9A8E813AD483ULL,
		0xA4C23404EC0227F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA94EA35AD2C7E746ULL,
		0x83D7F0F3CB4BD173ULL,
		0xFAB09291DB0467BAULL,
		0xC64F18A2C84534D4ULL,
		0x3292B2694328007BULL,
		0xDCA9924CCCA55D6EULL,
		0x5C66920A1EA13842ULL,
		0x69A88CAF5282015DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC25FC88865FC4D1DULL,
		0xA86067A5ADC86502ULL,
		0xE0652BA592708652ULL,
		0xF6589C383388EB6DULL,
		0x01EAF248D997CF45ULL,
		0x880C70E79BB785C1ULL,
		0xEC6B08849F9BECC1ULL,
		0xCD6AB8ABBE8026A4ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 404 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0D3B5D72544707EULL,
		0xC2F2827B9E49C4BAULL,
		0xD8A562603077B9AAULL,
		0x39F06D61621C4E6FULL,
		0x5E4B0BA1337F3AF1ULL,
		0x46C76A0A62A5F9D0ULL,
		0x7E5510A637553712ULL,
		0x33777167C3756B01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5096DA270A5F492ULL,
		0x8D7824C699E55768ULL,
		0x8154175B51184EB0ULL,
		0x9007C08F4118C035ULL,
		0xA250F71FF94EEF89ULL,
		0xFE9E9356CD0CB128ULL,
		0x348496B2BEBC433FULL,
		0x3C986F909DFDFD96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15DAD87555E184ECULL,
		0x4F8AA6BD07AC93D2ULL,
		0x59F1753B616FF71AULL,
		0xA9F7ADEE23048E5AULL,
		0xFC1BFCBECA31D578ULL,
		0xB859F95CAFA948F8ULL,
		0x4AD1861489E9742DULL,
		0x0FEF1EF75E889697ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 405 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x573A6D8C2DDA714BULL,
		0x489F6671D741308FULL,
		0x0E44EDF27B199FCDULL,
		0x4D672FBCE0415E67ULL,
		0xB78DAD5D695C9785ULL,
		0x628E10A7D2FE7B1AULL,
		0xB86DF9F2AC20A22BULL,
		0x1445823DCB48C971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F785C7B81335D1ULL,
		0xAE57CC3ABFBE5F8FULL,
		0x425BC30AFE557AEFULL,
		0x23F3500363EC64B1ULL,
		0x8D74A9C3E9777E58ULL,
		0x3FDF9EA4E706F62BULL,
		0x67AFE7580789527BULL,
		0xBC29C0FF03FCBF28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17CDE84B95C9449AULL,
		0xE6C8AA4B68FF6F00ULL,
		0x4C1F2EF8854CE522ULL,
		0x6E947FBF83AD3AD6ULL,
		0x3AF9049E802BE9DDULL,
		0x5D518E0335F88D31ULL,
		0xDFC21EAAABA9F050ULL,
		0xA86C42C2C8B47659ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 406 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1F3384A906941B9ULL,
		0x10137860D364974AULL,
		0xC14A5E0F8DA58B80ULL,
		0x3C8EFE5DFA799FDFULL,
		0xF9FB02932810B91AULL,
		0xCCA3D0FCF2F20443ULL,
		0x39CCD247B7CCF840ULL,
		0xBE545A908DB77B10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17CD8B26E55EAF8ULL,
		0xCC494E021924A6CEULL,
		0x9754A7CAB565763BULL,
		0x3CEC732DEF4468D6ULL,
		0xE24608707494FB3FULL,
		0x14F2260B5C4C6489ULL,
		0xAAF2538F8B76ABDCULL,
		0x96D9DEB3BAB799FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408FE0F8FE3CAB41ULL,
		0xDC5A3662CA403184ULL,
		0x561EF9C538C0FDBBULL,
		0x00628D70153DF709ULL,
		0x1BBD0AE35C844225ULL,
		0xD851F6F7AEBE60CAULL,
		0x933E81C83CBA539CULL,
		0x288D84233700E2EEULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 407 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x374E4FFF596EF8D4ULL,
		0x7DE1426F477FDA35ULL,
		0x0959ECB505BF0026ULL,
		0x334DA60FE187DC39ULL,
		0xA36C58FAECEA6747ULL,
		0x5A7D956C543579FBULL,
		0x4A182CAC7A3AAA8AULL,
		0x33FDB77FD74FA23EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52BE5C0D6AF91BF6ULL,
		0x67497C185FA632A4ULL,
		0xE2152CA9F14225BEULL,
		0x15EC46588851F138ULL,
		0x6952EB66884D65EEULL,
		0xF50CEA582940DADEULL,
		0xAABE25D7B0B0F566ULL,
		0x9D0168F87443B9ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65F013F23397E322ULL,
		0x1AA83E7718D9E891ULL,
		0xEB4CC01CF4FD2598ULL,
		0x26A1E05769D62D01ULL,
		0xCA3EB39C64A702A9ULL,
		0xAF717F347D75A325ULL,
		0xE0A6097BCA8A5FECULL,
		0xAEFCDF87A30C1B95ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 408 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98720B63108EC284ULL,
		0x8621A643C77AB070ULL,
		0x8D4B8BD4E5F4FFC5ULL,
		0xCFE3BDB89C77A2A8ULL,
		0x9690F4B5682A9163ULL,
		0x6AC94F214E519618ULL,
		0x2C52BEE0CD35EBC4ULL,
		0xC34C10737212A7E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBBD008F5D3AF076ULL,
		0xA2B4764630F4C586ULL,
		0x1AEC93822AC6571AULL,
		0xA7530E89D145D3ADULL,
		0x3B7541EDFE8C7597ULL,
		0x2B455C0D7607549DULL,
		0xFC645CBB60F16EC1ULL,
		0x519AF00015F1081DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23CF0BEC4DB432F2ULL,
		0x2495D005F78E75F6ULL,
		0x97A71856CF32A8DFULL,
		0x68B0B3314D327105ULL,
		0xADE5B55896A6E4F4ULL,
		0x418C132C3856C285ULL,
		0xD036E25BADC48505ULL,
		0x92D6E07367E3AFFAULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 409 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E81D283E6F1198EULL,
		0x003C9EFEAA39CC4DULL,
		0x64DEB79CC52547D4ULL,
		0x90DD7F4741CFC713ULL,
		0x704BC70E806A5E9BULL,
		0x3F819D97998388DAULL,
		0x7D21AB71C3C3D4B6ULL,
		0x2C06E8E9826F707EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7990EEB310DCF901ULL,
		0xF900C435DA592CCCULL,
		0xB756F9E7ED037D61ULL,
		0x529458ACEEB48055ULL,
		0x0DE67159220CA506ULL,
		0xFC7E31C3CB6DB3A3ULL,
		0x31EB2157144C7E96ULL,
		0x62D792F92DAEDAE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17113C30F62DE08FULL,
		0xF93C5ACB7060E081ULL,
		0xD3884E7B28263AB5ULL,
		0xC24927EBAF7B4746ULL,
		0x7DADB657A266FB9DULL,
		0xC3FFAC5452EE3B79ULL,
		0x4CCA8A26D78FAA20ULL,
		0x4ED17A10AFC1AA9DULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 410 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EA5A50350B82E02ULL,
		0x49476F68BA88AD21ULL,
		0x3FF865A7C7787EFAULL,
		0x865E18B2C0D63162ULL,
		0x1C2765F62EDEEA71ULL,
		0x99D7C58A3D45ACABULL,
		0x2FF929C5A32D9D7CULL,
		0x328CB9BE948B8E49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F86F8CF65D9A0E7ULL,
		0xBC3375FF8AB15789ULL,
		0x7B25C97976BE30F2ULL,
		0x18F4857CEEBFEA73ULL,
		0xB5A3418BC8DF1CB0ULL,
		0x7D3697A568CB9125ULL,
		0x6F7C50B927090E55ULL,
		0x3D6325BD6FD3C3A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31235DCC35618EE5ULL,
		0xF5741A973039FAA8ULL,
		0x44DDACDEB1C64E08ULL,
		0x9EAA9DCE2E69DB11ULL,
		0xA984247DE601F6C1ULL,
		0xE4E1522F558E3D8EULL,
		0x4085797C84249329ULL,
		0x0FEF9C03FB584DEFULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 411 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26C860A70EE857D2ULL,
		0x54FA41BB3E813AEEULL,
		0xC628FCA311E77854ULL,
		0x3841F7D0C58D41E8ULL,
		0x976A48D3686E41DEULL,
		0xAB96F1E826AAD725ULL,
		0x7F72819E61C0D4C8ULL,
		0x049F540C5A584CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCB034DB5B38854EULL,
		0x5F2A7C2F3FFEED20ULL,
		0x83BC9A15D1566631ULL,
		0x84071F6AA1281324ULL,
		0xEA9F209BFF6294B2ULL,
		0xEC71467AE397F2FAULL,
		0xE1AE989996F6BC0DULL,
		0xC472C7E6C5C7B4B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA78547C55D0D29CULL,
		0x0BD03D94017FD7CEULL,
		0x459466B6C0B11E65ULL,
		0xBC46E8BA64A552CCULL,
		0x7DF56848970CD56CULL,
		0x47E7B792C53D25DFULL,
		0x9EDC1907F73668C5ULL,
		0xC0ED93EA9F9FF850ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 412 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF60FDF5EA3505AA4ULL,
		0x3632A4C038F87278ULL,
		0x59E6171D1158D4DDULL,
		0xF84F31DAD0D17D8AULL,
		0x909A6E38CF85CA15ULL,
		0xB46BD6AF8AEF68AEULL,
		0xC127825B2E4D795FULL,
		0x7EC046A8347F82CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81A4310B857E696ULL,
		0x9632DAF70E5AA8CAULL,
		0xABF1DA454553A202ULL,
		0xD58FF7F65EAB5648ULL,
		0x035826B8AE5EFAA2ULL,
		0x12115289182886E5ULL,
		0xAC58BCC3C3BB6438ULL,
		0x36163CB40598F2E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E159C4E1B07BC32ULL,
		0xA0007E3736A2DAB2ULL,
		0xF217CD58540B76DFULL,
		0x2DC0C62C8E7A2BC2ULL,
		0x93C2488061DB30B7ULL,
		0xA67A842692C7EE4BULL,
		0x6D7F3E98EDF61D67ULL,
		0x48D67A1C31E77023ULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 413 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB87A14CE4FE20DCULL,
		0xB618F941364A098DULL,
		0x3A3C26248CF20C0CULL,
		0x420BE5E79277E56DULL,
		0x9BBB81E275E65144ULL,
		0x432BCA46354135BDULL,
		0x2FD518D4995432A8ULL,
		0x24B8754C8781B852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22B6E77A1F66165DULL,
		0x93D79FA8D8621F79ULL,
		0x49B856B70715B3EDULL,
		0xEEA08519D630B667ULL,
		0x277B4BC0BD96A7ECULL,
		0x6EB06D6134906E69ULL,
		0xE38BB4E79E9C5CECULL,
		0xF5E4E4888EDBC0A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9314636FB983681ULL,
		0x25CF66E9EE2816F4ULL,
		0x738470938BE7BFE1ULL,
		0xACAB60FE4447530AULL,
		0xBCC0CA22C870F6A8ULL,
		0x2D9BA72701D15BD4ULL,
		0xCC5EAC3307C86E44ULL,
		0xD15C91C4095A78F6ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 414 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x902E262A18EC6293ULL,
		0x6ADD8ACDDD628D3BULL,
		0xDC113D16861554C3ULL,
		0x8414F5B2B9835124ULL,
		0x28B2AF43C8736592ULL,
		0x34BEC655AF8A45B2ULL,
		0x6E01EC5107C715BEULL,
		0x2D3B72F9A4700416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB801D801423A0D1CULL,
		0x9F928BEE74198B8EULL,
		0xB825E457367B69C8ULL,
		0xD3139E729D20C017ULL,
		0x9F12189535520423ULL,
		0x1DFE10DE1BC2432BULL,
		0x3CB26454E68385E0ULL,
		0xA00B227F6AB9208CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x282FFE2B5AD66F8FULL,
		0xF54F0123A97B06B5ULL,
		0x6434D941B06E3D0BULL,
		0x57076BC024A39133ULL,
		0xB7A0B7D6FD2161B1ULL,
		0x2940D68BB4480699ULL,
		0x52B38805E144905EULL,
		0x8D305086CEC9249AULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 415 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C7B832478220C82ULL,
		0xBEA4BD6C41E87C26ULL,
		0xB37CE7D607F8B4D6ULL,
		0xC72CB58C14B1AF2EULL,
		0x06855A43D68749BDULL,
		0x954F82B91760FC3CULL,
		0x9C3BAC6B90DD92B8ULL,
		0x0F12111A77981D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEC847BB2EA48F52ULL,
		0x7221CF60412800E2ULL,
		0x0FBCC4C2E58086DAULL,
		0x828379424597725AULL,
		0x413991170D2AA491ULL,
		0xAD229AC41A9352A4ULL,
		0xC23E01EFD302F236ULL,
		0xE769677F70194618ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92B3C49F568683D0ULL,
		0xCC85720C00C07CC4ULL,
		0xBCC02314E278320CULL,
		0x45AFCCCE5126DD74ULL,
		0x47BCCB54DBADED2CULL,
		0x386D187D0DF3AE98ULL,
		0x5E05AD8443DF608EULL,
		0xE87B766507815B0FULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 416 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79A1A9CB4F2381A5ULL,
		0xFA04AAE9034FE50BULL,
		0xE9648AE70DB92C9EULL,
		0x9368F5E94150DF82ULL,
		0x25E33A202DA7287AULL,
		0x91224CF93E0D599FULL,
		0x6D7FB34879B64157ULL,
		0x0EE431C744039BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBED51444E021A3ULL,
		0xE1FAB78FF8DB732FULL,
		0x60ABAC53E8F00178ULL,
		0x402C38357BA6ED86ULL,
		0x96C537BB939E785CULL,
		0x92B41348A45695FAULL,
		0x56A979534D591986ULL,
		0x3F3ADD1629A96EB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x261F7CDF0BC3A006ULL,
		0x1BFE1D66FB949624ULL,
		0x89CF26B4E5492DE6ULL,
		0xD344CDDC3AF63204ULL,
		0xB3260D9BBE395026ULL,
		0x03965FB19A5BCC65ULL,
		0x3BD6CA1B34EF58D1ULL,
		0x31DEECD16DAAF563ULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 417 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1CBF9DBB8F3AA13ULL,
		0x3CECB1494976EC0AULL,
		0x02C0EB9B60FF4C86ULL,
		0xA205B32B5BB49A9AULL,
		0x20052BF5AB7A1B3FULL,
		0x0C0873765B9BF802ULL,
		0x73EA41101BED000CULL,
		0x61E09A1ABC770C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A399F4EE7F39B44ULL,
		0x0B956CD214BC1F07ULL,
		0x23B904A634396C10ULL,
		0x4B43A2A9B8ECAE9EULL,
		0x7AEEC21739CF8B8DULL,
		0x6D22DC20739D5182ULL,
		0xA69B26637B757F61ULL,
		0xD4CB86F29E4DFA6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8BF266955F003157ULL,
		0x3779DD9B5DCAF30DULL,
		0x2179EF3D54C62096ULL,
		0xE9461182E3583404ULL,
		0x5AEBE9E292B590B2ULL,
		0x612AAF562806A980ULL,
		0xD571677360987F6DULL,
		0xB52B1CE8223AF60AULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 418 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1C74A6ECCD76A86ULL,
		0x5E48AFDC1D08B6B1ULL,
		0xFF281A14D6E67293ULL,
		0xED56DC2A6D4A2D13ULL,
		0x8212F54E489E52A3ULL,
		0xAF108037594F6F92ULL,
		0xFFEA9030090D4984ULL,
		0x6AB85D8CD3FFBAD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ADB9AB292F6EE79ULL,
		0x1472F7409B36DFB9ULL,
		0x02F9FD067E393AFFULL,
		0x8B7AC7C7BBB3BD8DULL,
		0xACACFB1615669DF1ULL,
		0x5E901B4F96EC2B32ULL,
		0x87E9B88015E11D09ULL,
		0xF123AB2D352B97EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B1CD0DC5E2184FFULL,
		0x4A3A589C863E6908ULL,
		0xFDD1E712A8DF486CULL,
		0x662C1BEDD6F9909EULL,
		0x2EBE0E585DF8CF52ULL,
		0xF1809B78CFA344A0ULL,
		0x780328B01CEC548DULL,
		0x9B9BF6A1E6D42D36ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 419 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F3B7A15AC4B50E8ULL,
		0x7497D011F468FABCULL,
		0xA81A5540091AB2C3ULL,
		0x40D7B21F9DE43787ULL,
		0x7D2856E4F28D4BE3ULL,
		0xA26E6162A8C47706ULL,
		0x734A897EE522612DULL,
		0x9543AFB5458F966EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD3E51B28F03B26ULL,
		0xD2E04443E98F675DULL,
		0xF8D45C2D2FBD6512ULL,
		0xEEEB77449BDF3944ULL,
		0xE40B9FAE04F0FA8AULL,
		0xDABC3A6CD51721EEULL,
		0xADC2DA2192D211D5ULL,
		0x929EFE0AFBCEA425ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35E89F0E84BB6BCEULL,
		0xA67794521DE79DE1ULL,
		0x50CE096D26A7D7D1ULL,
		0xAE3CC55B063B0EC3ULL,
		0x9923C94AF67DB169ULL,
		0x78D25B0E7DD356E8ULL,
		0xDE88535F77F070F8ULL,
		0x07DD51BFBE41324BULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 420 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8990B0A1A6B98DFFULL,
		0x7C71D2DCBBEE9865ULL,
		0xEF33795E55FA4693ULL,
		0xAEDE82146DA13AF1ULL,
		0x522E6A3298CB0340ULL,
		0xE99D305521E510EFULL,
		0xD6CF04C7CF504FB9ULL,
		0xF07AF50AA94E882DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BDEA90FFF110B7ULL,
		0xBC796A545C95E255ULL,
		0x2AFD7E5A1D8161A5ULL,
		0xFE05C617A34EF370ULL,
		0xC321C2C64E94C0D9ULL,
		0x04249574FE36432BULL,
		0x8B40FDAA0452CB02ULL,
		0x42132F57A0C42412ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC02D5A3159489D48ULL,
		0xC008B888E77B7A30ULL,
		0xC5CE0704487B2736ULL,
		0x50DB4403CEEFC981ULL,
		0x910FA8F4D65FC399ULL,
		0xEDB9A521DFD353C4ULL,
		0x5D8FF96DCB0284BBULL,
		0xB269DA5D098AAC3FULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 421 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D79F82F23E004C5ULL,
		0x9FD670CF8691AD51ULL,
		0xAE8F1D3B9D74182AULL,
		0x1DA5CBC490A12D63ULL,
		0x6B1F96CC2403C511ULL,
		0xB44BDF0432A9370BULL,
		0x19A8CC39C0AC655AULL,
		0xB6E8CEC51EAA78A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA11CEAFCC5C7AEDFULL,
		0x951D8073FD8DB139ULL,
		0x3F183FF76A17CDC5ULL,
		0x37AB8E3D90B353BEULL,
		0xD93F8DE923AE3F49ULL,
		0x36EB8C158F8E7F0EULL,
		0x4B4CE804572773E8ULL,
		0x6F138650F8FB7C66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC6512D3E627AA1AULL,
		0x0ACBF0BC7B1C1C68ULL,
		0x919722CCF763D5EFULL,
		0x2A0E45F900127EDDULL,
		0xB2201B2507ADFA58ULL,
		0x82A05311BD274805ULL,
		0x52E4243D978B16B2ULL,
		0xD9FB4895E65104CFULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 422 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B92D579C2179BBEULL,
		0x45A0DC414BD18068ULL,
		0x108AF50DF7ECAEBFULL,
		0x9EEBF20BC5F8B00BULL,
		0xCB513DE105049B0EULL,
		0x3524EC0118379ECBULL,
		0x5B2F21A77BA8CEBEULL,
		0xFBC50EF4A848A2BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DC85462D5E64317ULL,
		0x0B9467CD1790406EULL,
		0x64297CCEDDA0D0E1ULL,
		0x3ED6D5CE877AE6F0ULL,
		0xD0FC4975CC7FCF8DULL,
		0x8C2EEFF6BD0E38A9ULL,
		0xCCA3A05D01365B12ULL,
		0xBB23894C0CCCF125ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x065A811B17F1D8A9ULL,
		0x4E34BB8C5C41C006ULL,
		0x74A389C32A4C7E5EULL,
		0xA03D27C5428256FBULL,
		0x1BAD7494C97B5483ULL,
		0xB90A03F7A539A662ULL,
		0x978C81FA7A9E95ACULL,
		0x40E687B8A484539FULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 423 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97B3132BDBBCF602ULL,
		0x667A0AC79BE44496ULL,
		0x90DB8685C8C6FECCULL,
		0xF80915EA5D22AEB1ULL,
		0x734155E55C313CDDULL,
		0x1285C0C7DD5D6D57ULL,
		0x6CE11A9A3C2C1A1AULL,
		0x7CC0C014B9FF1CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1888E02A36DC3B91ULL,
		0x498960AB17CBAA66ULL,
		0x3D6A847E1373890AULL,
		0x111178DE160FDEBCULL,
		0x4447BBCB20C7CBD8ULL,
		0x8E57F38D5CB1CE0FULL,
		0x0654B0DD232E24D1ULL,
		0x86C206B4CA76026CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F3BF301ED60CD93ULL,
		0x2FF36A6C8C2FEEF0ULL,
		0xADB102FBDBB577C6ULL,
		0xE9186D344B2D700DULL,
		0x3706EE2E7CF6F705ULL,
		0x9CD2334A81ECA358ULL,
		0x6AB5AA471F023ECBULL,
		0xFA02C6A073891E80ULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 424 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C57BB019C9A0EE6ULL,
		0x5D188392D8B28338ULL,
		0x8F015C2731B7568AULL,
		0xE294707146B9A952ULL,
		0x8BDD023C65B2DD42ULL,
		0xB8020DA9B15B288DULL,
		0x4E7F084FB496D291ULL,
		0xBB10ED2466B6A14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C82CF37B73A89CCULL,
		0x8390F750927A0957ULL,
		0x24D99DE5C1EE3B03ULL,
		0x525E92A9E98DD366ULL,
		0xA520C77FD4B501F3ULL,
		0x0CA5AA86061061B6ULL,
		0xA963522C265FB3C6ULL,
		0xA04C444CAFB6B35AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60D574362BA0872AULL,
		0xDE8874C24AC88A6FULL,
		0xABD8C1C2F0596D89ULL,
		0xB0CAE2D8AF347A34ULL,
		0x2EFDC543B107DCB1ULL,
		0xB4A7A72FB74B493BULL,
		0xE71C5A6392C96157ULL,
		0x1B5CA968C9001211ULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 425 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9202D94CAC3C92B7ULL,
		0x25367B8A03AEDC75ULL,
		0x29AC953D736FF20AULL,
		0x27D4CD9DD54E3CA2ULL,
		0xF10B1576C05AA04EULL,
		0xE86E97138D457847ULL,
		0xFEF64C57C784C2FBULL,
		0x03D6646A6C84CF21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF967583E949CF4AULL,
		0x7DB9CCD709BD3736ULL,
		0x103A5D9A94664A3AULL,
		0xC35C09A93EC8D8D1ULL,
		0x442583D7FCA745A7ULL,
		0x814B4BAA7131A8F6ULL,
		0xCBB8AD19B47D9E38ULL,
		0x46E2883FAEBB7C87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D94ACCF45755DFDULL,
		0x588FB75D0A13EB43ULL,
		0x3996C8A7E709B830ULL,
		0xE488C434EB86E473ULL,
		0xB52E96A13CFDE5E9ULL,
		0x6925DCB9FC74D0B1ULL,
		0x354EE14E73F95CC3ULL,
		0x4534EC55C23FB3A6ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 426 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4F8F21873D133F1ULL,
		0xDAABB8613C1962EBULL,
		0xE08BB7C726E418ADULL,
		0xE92CFD4364B6EF92ULL,
		0x8DA66EDA260EA3BCULL,
		0x7913988D3673D3EDULL,
		0xAAF40DAAFD00F3FEULL,
		0x524E3A713EBE0FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE565F66812EB6C49ULL,
		0x7E280B3D306B98FDULL,
		0xCFF888EC9B252ED7ULL,
		0x6FD0B33E74CE58EFULL,
		0xF5AAA92222627AD0ULL,
		0x3144ACE5D206300FULL,
		0x2AAE59FF35D26904ULL,
		0xE2390802D1C7503BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x019D0470613A5FB8ULL,
		0xA483B35C0C72FA16ULL,
		0x2F733F2BBDC1367AULL,
		0x86FC4E7D1078B77DULL,
		0x780CC7F8046CD96CULL,
		0x48573468E475E3E2ULL,
		0x805A5455C8D29AFAULL,
		0xB0773273EF795FE6ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 427 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A133EFDC07FCD9FULL,
		0x4C7C1770965A3D5EULL,
		0xE068FB5B78930FF7ULL,
		0xD17E4C4553C79060ULL,
		0xEA4052CE8BF1813EULL,
		0x0476CD03DCA3448FULL,
		0xEC9728675660E5D4ULL,
		0x46CE074D033BC120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B2A91E3D0BEBB6DULL,
		0x190F66548E2279B9ULL,
		0x0DB4ACCEBA54F6E0ULL,
		0xC12E6B7A462283E2ULL,
		0x217F703A6B0EB7A7ULL,
		0x958BCF53438AD234ULL,
		0xE2C56166379DD813ULL,
		0x117BF1D4A8BA8603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2139AF1E10C176F2ULL,
		0x55737124187844E7ULL,
		0xEDDC5795C2C7F917ULL,
		0x1050273F15E51382ULL,
		0xCB3F22F4E0FF3699ULL,
		0x91FD02509F2996BBULL,
		0x0E52490161FD3DC7ULL,
		0x57B5F699AB814723ULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 428 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DE80744680B9F01ULL,
		0x87794BF6A0ACF504ULL,
		0xDE3635866033C1A1ULL,
		0x4EBAD18ABBEA9F2EULL,
		0xE6A204249723F8C8ULL,
		0xB9D99110942A77C9ULL,
		0x39D41E6D2E4DDEC9ULL,
		0x950739E00C779AB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09EE9ED9DD827162ULL,
		0xEF681A7A94674017ULL,
		0x4C4DFBB0DAB1AB82ULL,
		0x3398E4A6F56D69D7ULL,
		0xC4A4BD66218290DFULL,
		0xB8292F42DC819545ULL,
		0xAF9F1371920CBC30ULL,
		0x773E48F578F7432FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8406999DB589EE63ULL,
		0x6811518C34CBB513ULL,
		0x927BCE36BA826A23ULL,
		0x7D22352C4E87F6F9ULL,
		0x2206B942B6A16817ULL,
		0x01F0BE5248ABE28CULL,
		0x964B0D1CBC4162F9ULL,
		0xE23971157480D997ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 429 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B99D913B3D1BB88ULL,
		0x5889E30080B4FDC3ULL,
		0x8F9D9087295A6E1BULL,
		0xA67E78107DE8D417ULL,
		0xA0FDE0BF25761C2BULL,
		0xB719CB0B93FC1669ULL,
		0x50F75176D1A811C0ULL,
		0x236819D1DDEC0215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074C887A9B27EC70ULL,
		0x17411D2C4A77250DULL,
		0x082632E86CAD981EULL,
		0x3D0EE9A908B7C79EULL,
		0xF98C54302EC7C2CAULL,
		0x20A463A0FC7F9C12ULL,
		0x17B9BF711C54C782ULL,
		0x1CDCC4E0C5CA1708ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CD5516928F657F8ULL,
		0x4FC8FE2CCAC3D8CEULL,
		0x87BBA26F45F7F605ULL,
		0x9B7091B9755F1389ULL,
		0x5971B48F0BB1DEE1ULL,
		0x97BDA8AB6F838A7BULL,
		0x474EEE07CDFCD642ULL,
		0x3FB4DD311826151DULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 430 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F02F74D880C5028ULL,
		0xC17C935CD053F760ULL,
		0xFCA115E037BA69B8ULL,
		0x664243EE57383777ULL,
		0xE627F572776FC490ULL,
		0xBFD0C22E590041DCULL,
		0xE3429A796CA42E2FULL,
		0x8ED7D1D90B9F4AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01FEF9CBAC15AE24ULL,
		0x0D337775389B2F49ULL,
		0x3D75184C0BB6EA31ULL,
		0x5FF7E68998340D6DULL,
		0xBB1E4E3622C20019ULL,
		0x3AB65251F7794D82ULL,
		0x420C0D91A01CDD7CULL,
		0x4035C09E4047D715ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EFC0E862419FE0CULL,
		0xCC4FE429E8C8D829ULL,
		0xC1D40DAC3C0C8389ULL,
		0x39B5A567CF0C3A1AULL,
		0x5D39BB4455ADC489ULL,
		0x8566907FAE790C5EULL,
		0xA14E97E8CCB8F353ULL,
		0xCEE211474BD89DA6ULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 431 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFCBBEE57FF423C7ULL,
		0x433FDC74F27BA261ULL,
		0xD4F21156D8D7EFDCULL,
		0x38EC59E91AC13591ULL,
		0xE09D401485560BE5ULL,
		0xF2C00D0FB5FF8298ULL,
		0x3A69B922D649ACE9ULL,
		0x9DB528A8CDF75729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B9199A1F5E5C287ULL,
		0x54590CD8BA3D3D80ULL,
		0xF0E20DE7C16768B5ULL,
		0x8023AA8A901D2417ULL,
		0xD6E289BEC2D451A0ULL,
		0xD3BA885675F42BD9ULL,
		0x4E2714180C5F30A9ULL,
		0xEEAE657B93D3E5D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC45A27448A11E140ULL,
		0x1766D0AC48469FE1ULL,
		0x24101CB119B08769ULL,
		0xB8CFF3638ADC1186ULL,
		0x367FC9AA47825A45ULL,
		0x217A8559C00BA941ULL,
		0x744EAD3ADA169C40ULL,
		0x731B4DD35E24B2FEULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 432 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58348E14F7B33893ULL,
		0x40EFF0E15DBB784CULL,
		0xFA84EF07E671E505ULL,
		0xC5EDDA704E648554ULL,
		0x041B514003DE405FULL,
		0x15F5DF87434A8BB5ULL,
		0x9857B00D73B5FE3AULL,
		0x1F11A0EF626E1402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6674EA52C021123DULL,
		0xD6B69B2D908B3B1EULL,
		0x790AB7E3D57DB2E5ULL,
		0x958594559482A022ULL,
		0xE44B6B473246C783ULL,
		0x40BFA8D6624AEDAAULL,
		0xC5A7258AE6DF4AB9ULL,
		0x1C77DDF8BED2B7B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E40644637922AAEULL,
		0x96596BCCCD304352ULL,
		0x838E58E4330C57E0ULL,
		0x50684E25DAE62576ULL,
		0xE0503A07319887DCULL,
		0x554A77512100661FULL,
		0x5DF09587956AB483ULL,
		0x03667D17DCBCA3B6ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 433 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F8FCD7346AB793FULL,
		0xB87BD00F4021F428ULL,
		0xEC494FCA0910FF4EULL,
		0x533294950C620B82ULL,
		0x75687E4A8C74DD3EULL,
		0x980AC1585D4DFA7DULL,
		0xE37D86EEFBD89407ULL,
		0x6D5ECDBD7DF7A90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F6ABF10DDECEC75ULL,
		0xA2B8AB7E41DB3F60ULL,
		0x65AEB66736BC965EULL,
		0x48F5D0647B776DF1ULL,
		0x0C02B0BDC6C7749DULL,
		0x7B50D77B34EE4985ULL,
		0x7C7C4D94A2B6134DULL,
		0xA33126F5F0B9B8C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0E572639B47954AULL,
		0x1AC37B7101FACB48ULL,
		0x89E7F9AD3FAC6910ULL,
		0x1BC744F177156673ULL,
		0x796ACEF74AB3A9A3ULL,
		0xE35A162369A3B3F8ULL,
		0x9F01CB7A596E874AULL,
		0xCE6FEB488D4E11C4ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 434 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80447A56521149D9ULL,
		0x250886209F8594A1ULL,
		0x5530DEA237E90465ULL,
		0xA57294BDB82AD2BEULL,
		0x1B4521240A77AA34ULL,
		0xC58D89C802BEEE6CULL,
		0xD8220577FA18EA2DULL,
		0x431E1C075EEC63DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D0EA340E4CD04CULL,
		0x52FD5C2046955F79ULL,
		0x778F471A6F21406CULL,
		0x7217AAB74B77D460ULL,
		0x860E6352E2944277ULL,
		0x91B686C7AB59DA92ULL,
		0xA662F77646D9D521ULL,
		0x3C8B846BB1682FCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA39490625C5D9995ULL,
		0x77F5DA00D910CBD8ULL,
		0x22BF99B858C84409ULL,
		0xD7653E0AF35D06DEULL,
		0x9D4B4276E8E3E843ULL,
		0x543B0F0FA9E734FEULL,
		0x7E40F201BCC13F0CULL,
		0x7F95986CEF844C16ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 435 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21895152AF34BB17ULL,
		0xE09D8E797FF4AECAULL,
		0x403DC4368080DB81ULL,
		0x176ADB5AABDA94AFULL,
		0x643302D82D0168EEULL,
		0x48F8448C9D2509E2ULL,
		0x84EE0E3EA43D5433ULL,
		0x7AFAEEDB1D5E1E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5C301EB94CAD5AULL,
		0x6C60B6E2E425779CULL,
		0x311FAE6BF301D5BDULL,
		0xD9298B6406B02455ULL,
		0x3C76F59F51A7E42FULL,
		0x94180BED08200719ULL,
		0x5B90B1E2107BACD3ULL,
		0x478740965781C55EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CD5614C1678164DULL,
		0x8CFD389B9BD1D956ULL,
		0x71226A5D73810E3CULL,
		0xCE43503EAD6AB0FAULL,
		0x5845F7477CA68CC1ULL,
		0xDCE04F6195050EFBULL,
		0xDF7EBFDCB446F8E0ULL,
		0x3D7DAE4D4ADFDB7DULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 436 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A8B6C358A9C678CULL,
		0x30AAD7F42C4D4591ULL,
		0xF7193516C4EFD9FBULL,
		0x1BF495640D4F3AA7ULL,
		0xAA08A658E828D5A6ULL,
		0xF47B4C495A0D05BEULL,
		0x78927E957300AB35ULL,
		0x5E28D9F71D97698DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x872F8B07C11502D3ULL,
		0x4573A8B0AD7879ECULL,
		0xAFD2679F52D95503ULL,
		0xE12F2E87F719806FULL,
		0x20F103FD538E1DB1ULL,
		0x56CB973BEF17F815ULL,
		0xE85F81EF800CC96CULL,
		0x66392445F0A3DB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA4E7324B89655FULL,
		0x75D97F4481353C7DULL,
		0x58CB528996368CF8ULL,
		0xFADBBBE3FA56BAC8ULL,
		0x8AF9A5A5BBA6C817ULL,
		0xA2B0DB72B51AFDABULL,
		0x90CDFF7AF30C6259ULL,
		0x3811FDB2ED34B2D4ULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 437 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7601EBA74C22C43EULL,
		0x6B4D9DF781517958ULL,
		0xB7B372C3AA4B9D72ULL,
		0x8180FB49B7696AA5ULL,
		0x96FDD8F428C2B2E7ULL,
		0x76F8192B2F636A12ULL,
		0x15B61446305EC307ULL,
		0xB831FB1331254873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x355F413AFD64093FULL,
		0x9F211CB5F19883ADULL,
		0x5EA61DA6318047F2ULL,
		0x96C71966DF754D9BULL,
		0x4021D7C8692BC277ULL,
		0x76A8346943A63DEDULL,
		0x8A659C56D8A6A4F4ULL,
		0x8B7B568E3FB23801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x435EAA9DB146CD01ULL,
		0xF46C814270C9FAF5ULL,
		0xE9156F659BCBDA80ULL,
		0x1747E22F681C273EULL,
		0xD6DC0F3C41E97090ULL,
		0x00502D426CC557FFULL,
		0x9FD38810E8F867F3ULL,
		0x334AAD9D0E977072ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 438 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05F4328A9ECAE7A2ULL,
		0x98632193B12E45BFULL,
		0x3D85F5273C2EC989ULL,
		0xED6953AEAF2EF1BCULL,
		0x12953080A8169E78ULL,
		0x2E274408F751A1FAULL,
		0x467EAF231B07EECFULL,
		0xCA15BFCA9C7F711BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83824EE7C2006915ULL,
		0xA9E18C84EDDE4A61ULL,
		0x3EB2295C24D82519ULL,
		0xC9398102144D1001ULL,
		0x5CAF81292E1D770FULL,
		0xEDC64F16AEA2D996ULL,
		0x0B1543EECCDEACE7ULL,
		0xDFFC8D05D290542EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86767C6D5CCA8EB7ULL,
		0x3182AD175CF00FDEULL,
		0x0337DC7B18F6EC90ULL,
		0x2450D2ACBB63E1BDULL,
		0x4E3AB1A9860BE977ULL,
		0xC3E10B1E59F3786CULL,
		0x4D6BECCDD7D94228ULL,
		0x15E932CF4EEF2535ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 439 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA85CDD62CA005A4FULL,
		0x9DCD5D7BEE3594A9ULL,
		0xB0BA801590D55C69ULL,
		0xA5D130FF93E28A94ULL,
		0x74070959EF87C558ULL,
		0xFA271CD1084E2AF0ULL,
		0x4AED247EB65E7139ULL,
		0xDE42E66621B663C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x714C6E05069ECF9DULL,
		0x6FF29C3666BCFD2DULL,
		0x997FEDEFE996992AULL,
		0x554B8998ED1389D5ULL,
		0xBE98D626673C563BULL,
		0x6B7A03F35D92FA80ULL,
		0x9A9F4A69803E62A9ULL,
		0x13E245DA19359F3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD910B367CC9E95D2ULL,
		0xF23FC14D88896984ULL,
		0x29C56DFA7943C543ULL,
		0xF09AB9677EF10341ULL,
		0xCA9FDF7F88BB9363ULL,
		0x915D1F2255DCD070ULL,
		0xD0726E1736601390ULL,
		0xCDA0A3BC3883FCF6ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 440 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27A43751DEB917BBULL,
		0x0852C8A35384E968ULL,
		0x6754D8E4B35FB43CULL,
		0x5467DCADEB3E5D95ULL,
		0x7F9200AD92A8A8F5ULL,
		0xCDAAADC2E1821A0EULL,
		0x65EA0FCC1EBE5782ULL,
		0xC4A065CEF67AC4A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2FBF49F270D41CULL,
		0x1B9E6ADB7EFE7B01ULL,
		0x21D9D3050C06D9CEULL,
		0x3313557D11E6BDF6ULL,
		0x27967A1097DB6C3FULL,
		0xE502FFDDE2B2D337ULL,
		0x82713B635DB8F53AULL,
		0xDF197F384341D500ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A8B88182CC9C3A7ULL,
		0x13CCA2782D7A9269ULL,
		0x468D0BE1BF596DF2ULL,
		0x677489D0FAD8E063ULL,
		0x58047ABD0573C4CAULL,
		0x28A8521F0330C939ULL,
		0xE79B34AF4306A2B8ULL,
		0x1BB91AF6B53B11A4ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 441 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD86AD636EAE24BDULL,
		0x98A2C0D5C692A007ULL,
		0x45AFA82BAD439006ULL,
		0x2751A653C2102BCDULL,
		0x4EC90D79437C6F62ULL,
		0x44F3F78CA159C9E9ULL,
		0x4DC89DD428B44573ULL,
		0xB6ED404D83933385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1196AAFC7E22EEULL,
		0xB60433B5D3E436EDULL,
		0xDE5444B3EAEB1C64ULL,
		0xA6D00EF7178B3EACULL,
		0x5DBF2C3119A76303ULL,
		0x817D27A718BD90B9ULL,
		0x05F84827C918B221ULL,
		0x126C37F2B3453739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87973BC992D00653ULL,
		0x2EA6F360157696EAULL,
		0x9BFBEC9847A88C62ULL,
		0x8181A8A4D59B1561ULL,
		0x137621485ADB0C61ULL,
		0xC58ED02BB9E45950ULL,
		0x4830D5F3E1ACF752ULL,
		0xA48177BF30D604BCULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 442 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x615F8CCCB80D4A2CULL,
		0x68FCB9614759E00BULL,
		0xA32766A0CB2B7D51ULL,
		0x06EEF59A4A8F2049ULL,
		0x313214298919985AULL,
		0x50552FD4647569EAULL,
		0xAAA1ADC1D6484FF5ULL,
		0x81FA2474D36705E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E5143A99D683D3ULL,
		0x04B0F91B7253911DULL,
		0x82ADBBCBC16227C1ULL,
		0x14A8F8B62056481BULL,
		0x2C0483F897279B76ULL,
		0x12324F4B0F1A455BULL,
		0x61A455B8687E08CCULL,
		0x6ACB75A5CB433AA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77BA98F621DBC9FFULL,
		0x6C4C407A350A7116ULL,
		0x218ADD6B0A495A90ULL,
		0x12460D2C6AD96852ULL,
		0x1D3697D11E3E032CULL,
		0x4267609F6B6F2CB1ULL,
		0xCB05F879BE364739ULL,
		0xEB3151D118243F49ULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 443 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B6C95E6C8E4E63BULL,
		0x526D3792627BE0CDULL,
		0xD2ADFA76B19D6A62ULL,
		0xD083B01DF04C7D00ULL,
		0x1675B838A8731668ULL,
		0xCAEE1AD3E2FC9263ULL,
		0x860DE3CFE59D6850ULL,
		0xCEF7E0A83104FADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD963473A221EB13CULL,
		0x6FA24884D02E5055ULL,
		0x9E339440DB43AF66ULL,
		0xF3F916DC7E1EB701ULL,
		0x1CCFF97ED6C32C37ULL,
		0xA3423358468E5EFBULL,
		0x0C9FA50497E70299ULL,
		0x5179AFB01FDC49C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x520FD2DCEAFA5707ULL,
		0x3DCF7F16B255B098ULL,
		0x4C9E6E366ADEC504ULL,
		0x237AA6C18E52CA01ULL,
		0x0ABA41467EB03A5FULL,
		0x69AC298BA472CC98ULL,
		0x8A9246CB727A6AC9ULL,
		0x9F8E4F182ED8B31AULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 444 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B34B718F4641C63ULL,
		0xD353BA5E3F63E180ULL,
		0x0BB4CE2354B6E8EAULL,
		0x6EFBD6F8AE183774ULL,
		0x283D71E9FC443AE5ULL,
		0x93CCA005860EB2F4ULL,
		0x14E0F02085D37D05ULL,
		0x1F56F8199906F472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x733513387E3C0142ULL,
		0x144DD05DED5BC6EAULL,
		0x3599EA15F171BF53ULL,
		0x3096CED23C6C9B1BULL,
		0x79808C2DF3333A10ULL,
		0xF69DD897DD521D07ULL,
		0xA2DC6FB30BB28459ULL,
		0xB9A9D7729721EECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2801A4208A581D21ULL,
		0xC71E6A03D238276AULL,
		0x3E2D2436A5C757B9ULL,
		0x5E6D182A9274AC6FULL,
		0x51BDFDC40F7700F5ULL,
		0x655178925B5CAFF3ULL,
		0xB63C9F938E61F95CULL,
		0xA6FF2F6B0E271ABFULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 445 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63EF14B31DEA524FULL,
		0x04A44B21D4BBE4E2ULL,
		0x84225B8D6A4660ACULL,
		0x09965820CC827594ULL,
		0xF275C57E7955CDB5ULL,
		0x09590678E1FD4C3EULL,
		0xE91BB0F57499EE71ULL,
		0x2563C2DDAE956927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CD77BCED579A7F1ULL,
		0x1AE8C7ECC315BF66ULL,
		0x115803DFF0D319C8ULL,
		0xF8206AF86F479EA9ULL,
		0x7E450CB2A200B120ULL,
		0x10D23363E8385A66ULL,
		0xFE39D109B288CCEBULL,
		0x925513FCFA84B07EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F386F7DC893F5BEULL,
		0x1E4C8CCD17AE5B84ULL,
		0x957A58529A957964ULL,
		0xF1B632D8A3C5EB3DULL,
		0x8C30C9CCDB557C95ULL,
		0x198B351B09C51658ULL,
		0x172261FCC611229AULL,
		0xB736D1215411D959ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 446 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEFB59CE2316177FULL,
		0x3E4A339B348DB042ULL,
		0x28FFF2F530C6E24DULL,
		0x38E38A09D0E0FF9CULL,
		0x14875DC387C7D7EEULL,
		0x0F650611746679C8ULL,
		0xDAEA69B5DECD5F41ULL,
		0x507C0338689D5470ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBEB5A7EF72A765ULL,
		0x863B339DE025D208ULL,
		0x7644EA526B587960ULL,
		0x483E10218C939C63ULL,
		0xABB3686EAE00C19FULL,
		0xB5AADEF1908FDB66ULL,
		0x4F59B20C271B2967ULL,
		0x3C148FCB40E03FEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2245EC69CC64B01AULL,
		0xB8710006D4A8624AULL,
		0x5EBB18A75B9E9B2DULL,
		0x70DD9A285C7363FFULL,
		0xBF3435AD29C71671ULL,
		0xBACFD8E0E4E9A2AEULL,
		0x95B3DBB9F9D67626ULL,
		0x6C688CF3287D6B9AULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 447 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49A28A43CBB873F4ULL,
		0x3323A8EEFC373EADULL,
		0x7D75B36161A3EC88ULL,
		0x58EC542B9C43AC7FULL,
		0xBCA9C9D28BFFB3F5ULL,
		0xDAF4F851850431ADULL,
		0x396453617687FBC3ULL,
		0xF2D41B90FCDF3BDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9547DB3C86CCFDD3ULL,
		0x5C658F460B06EB33ULL,
		0x859E68338C736F92ULL,
		0x4EBAB2A8AC7A2F30ULL,
		0xD303B4EE2C3BAFBBULL,
		0x541E37AA1894D9AFULL,
		0xC00A5E0B95EF8FCBULL,
		0x63A9D93F01BC95ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCE5517F4D748E27ULL,
		0x6F4627A8F731D59EULL,
		0xF8EBDB52EDD0831AULL,
		0x1656E6833039834FULL,
		0x6FAA7D3CA7C41C4EULL,
		0x8EEACFFB9D90E802ULL,
		0xF96E0D6AE3687408ULL,
		0x917DC2AFFD63AE71ULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 448 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F3CF4517EC3B7D7ULL,
		0x5D0A7A0A4495210BULL,
		0xE80D20E687FA5F6DULL,
		0x15D22AF4E8CB6DA6ULL,
		0xD4FE134D2A86C406ULL,
		0x24A3E34550456B32ULL,
		0xB9FC25C9C3F997FEULL,
		0x34E60190CBB8B243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE8A2FB49F8CCCB6ULL,
		0x2B5A144160D9C7D1ULL,
		0xBBACE5409EFF3E21ULL,
		0xF9029AECAB5D88ADULL,
		0x150802C726B76B82ULL,
		0x3694C7D37A4DDBF6ULL,
		0xFA9D3E4F1D04EE7AULL,
		0x3F8AB3D0619977DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1B6DBE5E14F7B61ULL,
		0x76506E4B244CE6DAULL,
		0x53A1C5A61905614CULL,
		0xECD0B0184396E50BULL,
		0xC1F6118A0C31AF84ULL,
		0x123724962A08B0C4ULL,
		0x43611B86DEFD7984ULL,
		0x0B6CB240AA21C598ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 449 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FC2EBD0E35C7D1AULL,
		0xD7F92842E96C6D05ULL,
		0x62DE4773B0E4B892ULL,
		0x0B310063882C1FE9ULL,
		0x4E0991AE8BA76D69ULL,
		0xAAF12062811174A8ULL,
		0xAFCB81F1DA3E232CULL,
		0x3291B25F19F9DCDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x296C5291A2B1D4C3ULL,
		0xD2D6B6B8DA3C03C4ULL,
		0x82EBB02F388FBAC4ULL,
		0x2DA055DDBD4EE7DBULL,
		0x9364FF50C2FF842BULL,
		0x8E34C63183910A5CULL,
		0x2CD529CBA8B22E88ULL,
		0x23DB65BC2B7F7467ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16AEB94141EDA9D9ULL,
		0x052F9EFA33506EC1ULL,
		0xE035F75C886B0256ULL,
		0x269155BE3562F832ULL,
		0xDD6D6EFE4958E942ULL,
		0x24C5E65302807EF4ULL,
		0x831EA83A728C0DA4ULL,
		0x114AD7E33286A8BAULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 450 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C403757A74BA090ULL,
		0x0EB096C08D490F50ULL,
		0xF2F45C1724C251C5ULL,
		0xA256628464BC4AD5ULL,
		0x327235E8889EC0C2ULL,
		0xF68ED2E3C27FA7DCULL,
		0xDDF9EA69AFAA090FULL,
		0x852962E0AFA8EF0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FE251C091D6540ULL,
		0xB3E721F69629C94BULL,
		0x21569DDB5E4DB90DULL,
		0xEFC94E55CCB83F2BULL,
		0x802A06BFF2331F99ULL,
		0xFF0643721B63ACACULL,
		0x59772B666CE752A8ULL,
		0x64CD69656B2C02A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08BE124BAE56C5D0ULL,
		0xBD57B7361B60C61BULL,
		0xD3A2C1CC7A8FE8C8ULL,
		0x4D9F2CD1A80475FEULL,
		0xB25833577AADDF5BULL,
		0x09889191D91C0B70ULL,
		0x848EC10FC34D5BA7ULL,
		0xE1E40B85C484EDA3ULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 451 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C04543F41F9D9F6ULL,
		0x73EB7DBF6DB188ACULL,
		0x326166C8FC3F06BCULL,
		0x5ED1BFB902906BEFULL,
		0xD9DB18D63F269C84ULL,
		0xD29EC50C9BB899F4ULL,
		0xAD0F3065F882824EULL,
		0x6D486D152A359513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3496F54E7DC48225ULL,
		0x1D12F385EFED00DAULL,
		0xBEFF5D6C95A1FE87ULL,
		0xE43EB254A346BD93ULL,
		0x18A573136B4D4403ULL,
		0xCDBCD1189FB5E1AEULL,
		0x69CB322DDB98BEEEULL,
		0x5D20F8EE28FA8112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA892A1713C3D5BD3ULL,
		0x6EF98E3A825C8876ULL,
		0x8C9E3BA4699EF83BULL,
		0xBAEF0DEDA1D6D67CULL,
		0xC17E6BC5546BD887ULL,
		0x1F221414040D785AULL,
		0xC4C40248231A3CA0ULL,
		0x306895FB02CF1401ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 452 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x817CFC8D5D28AD20ULL,
		0x9508DF2A4A689CC2ULL,
		0xFE1AEC4B1C77C28CULL,
		0x51934F50E14BE7C0ULL,
		0xEE8C9EC2F88AD8CDULL,
		0x587CE8B146D85E86ULL,
		0xED36030CC94E5901ULL,
		0x64EC8E2F5BF1E6E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10BDBCBD6652406FULL,
		0x91145DA6C86FF79FULL,
		0xBD4D5574FDD7DDE2ULL,
		0x84148661825A40E5ULL,
		0x2892304BFD679811ULL,
		0x58E2C6A085D952ABULL,
		0x817FA74FA95A1F64ULL,
		0x7905D20F3CB56B8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C140303B7AED4FULL,
		0x041C828C82076B5DULL,
		0x4357B93FE1A01F6EULL,
		0xD587C9316311A725ULL,
		0xC61EAE8905ED40DCULL,
		0x009E2E11C3010C2DULL,
		0x6C49A44360144665ULL,
		0x1DE95C2067448D6FULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 453 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27AE553FE054BE77ULL,
		0x7ED1C4FF8182F7A8ULL,
		0x1F309F72DD1892F9ULL,
		0x8BA3F24B141CEC62ULL,
		0x187AC265157BE90AULL,
		0xA62EBA643318A5E0ULL,
		0xAEFC61D4845E8539ULL,
		0x0FC2B0EC1EE3A92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC07FF7E8AA14BC20ULL,
		0x90E9798C110DD91CULL,
		0x31BFB534186598E6ULL,
		0x65E1A6DAF10828E1ULL,
		0xF18131CF605CF427ULL,
		0xD45CBD9DCF2D3039ULL,
		0x467619A11AE0F50CULL,
		0xE4FFF0F80E97C65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7D1A2D74A400257ULL,
		0xEE38BD73908F2EB4ULL,
		0x2E8F2A46C57D0A1FULL,
		0xEE425491E514C483ULL,
		0xE9FBF3AA75271D2DULL,
		0x727207F9FC3595D9ULL,
		0xE88A78759EBE7035ULL,
		0xEB3D401410746F72ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 454 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC85969DCEB9D314ULL,
		0x990BA38A00152144ULL,
		0x77862716C144CC0FULL,
		0x948FD82A85C452CEULL,
		0x7349ABD673CE85E7ULL,
		0x8651825C3078E292ULL,
		0xC342B17E4DCC7635ULL,
		0x43D65F332A0B718AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC580EA0A2214061ULL,
		0x550129F980F7C9B7ULL,
		0x36CA5A659BE2CB80ULL,
		0xCF0572513CCD0D65ULL,
		0x83156E37CE308232ULL,
		0xFDADBD09FAAA9875ULL,
		0x2EB4859DD17017F9ULL,
		0xBF71A4A8ABC2492FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50DD983D6C989375ULL,
		0xCC0A8A7380E2E8F3ULL,
		0x414C7D735AA6078FULL,
		0x5B8AAA7BB9095FABULL,
		0xF05CC5E1BDFE07D5ULL,
		0x7BFC3F55CAD27AE7ULL,
		0xEDF634E39CBC61CCULL,
		0xFCA7FB9B81C938A5ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 455 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB06D046D921F2ECULL,
		0x336C2D420F503D35ULL,
		0x36E973280F12384CULL,
		0xFCD0A804E162174EULL,
		0xB058C803926BB6F7ULL,
		0x6438128F7523E834ULL,
		0x82574F20115F3026ULL,
		0x08683A06423AFAD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB563FF7DCBD94C82ULL,
		0xD1E6CE05027C1459ULL,
		0xB85EC5430C30B772ULL,
		0x82E827F27833D85EULL,
		0x5CD984DBF6FE84F9ULL,
		0xAD324FD9E5FA50B9ULL,
		0x772457D8E5FD02E2ULL,
		0x1E6C872287A7B1E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E652F3B12F8BE6EULL,
		0xE28AE3470D2C296CULL,
		0x8EB7B66B03228F3EULL,
		0x7E388FF69951CF10ULL,
		0xEC814CD86495320EULL,
		0xC90A5D5690D9B88DULL,
		0xF57318F8F4A232C4ULL,
		0x1604BD24C59D4B30ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 456 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x674973B66E99FF28ULL,
		0x42926DBAC337FC40ULL,
		0x127D101C5C763881ULL,
		0x4F720217854053C3ULL,
		0x2EBC76EC1B848C85ULL,
		0x7AC25C47DD4321B2ULL,
		0x337B0283612FEED2ULL,
		0x0ADA310E13181574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4A18F7F6359014ULL,
		0x510C4BDC0C81E200ULL,
		0x2AC5E18546768F00ULL,
		0x6929E706A634AE54ULL,
		0xDF1F3F2A1668CE23ULL,
		0xBE6EB887286E86EDULL,
		0x4F5797F0C3F85E6BULL,
		0x39D6DD2B19D6B9CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8036B4198AC6F3CULL,
		0x139E2666CFB61E40ULL,
		0x38B8F1991A00B781ULL,
		0x265BE5112374FD97ULL,
		0xF1A349C60DEC42A6ULL,
		0xC4ACE4C0F52DA75FULL,
		0x7C2C9573A2D7B0B9ULL,
		0x330CEC250ACEACBBULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 457 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5966B28D056E699AULL,
		0xD8E5FE320A548F21ULL,
		0xA0A8A88BA6C83932ULL,
		0x44F0889701341E8AULL,
		0x977BF4EFC473171FULL,
		0xBC4891D990F7FF44ULL,
		0xE80FEFF6F40BCAD1ULL,
		0x5EEC841FCF38A7EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD598B87D82F16CD9ULL,
		0xEA5DCB18166F507DULL,
		0x1951BA6E36D0107DULL,
		0x36641130E8E36B04ULL,
		0x2373C34E5F9AE473ULL,
		0x9CD424EEE2F77FD3ULL,
		0x6A5ACFA9541594A7ULL,
		0xD64FC0C1737FD70BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CFE0AF0879F0543ULL,
		0x32B8352A1C3BDF5CULL,
		0xB9F912E59018294FULL,
		0x729499A7E9D7758EULL,
		0xB40837A19BE9F36CULL,
		0x209CB53772008097ULL,
		0x8255205FA01E5E76ULL,
		0x88A344DEBC4770E4ULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 458 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC81830145753AA5ULL,
		0xF1591F4031289262ULL,
		0x6E4C9313AD7EA250ULL,
		0xE21B9F71F65ED474ULL,
		0xCE342C591DD6A6A4ULL,
		0xC9404FBCEDFB9080ULL,
		0xC1074AD7908E179FULL,
		0x67665559C6A974B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499BC62398043BDDULL,
		0xB0B918542AB4C1EEULL,
		0xF4BF4838663D9B39ULL,
		0xD36BC9602D9833A2ULL,
		0x278390138870CEE3ULL,
		0x9D1EAB09DFA9399DULL,
		0x1B4A694A426D3ACAULL,
		0xF5BE0BB35850E118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x851A4522DD710178ULL,
		0x41E007141B9C538CULL,
		0x9AF3DB2BCB433969ULL,
		0x31705611DBC6E7D6ULL,
		0xE9B7BC4A95A66847ULL,
		0x545EE4B53252A91DULL,
		0xDA4D239DD2E32D55ULL,
		0x92D85EEA9EF995ADULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 459 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA73263828AFDB96ULL,
		0xF78D72A7C701ED03ULL,
		0xE46D6A4BC5D2B137ULL,
		0xC1CEAF1849E8C3BEULL,
		0x2809DA62085CCD1AULL,
		0x47EB2A8F6C2AF0A1ULL,
		0x2434F644A0280A8CULL,
		0x54901E7589CA6184ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3B6333CA5D22269ULL,
		0x743790433512F2CBULL,
		0x0924A0E0823B94C4ULL,
		0x38FC9F47353F283FULL,
		0xF55255902C1E0EC4ULL,
		0x9A2E55DCF05BFC26ULL,
		0x921A67469E923B10ULL,
		0xF3F788C688443433ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09C515048D7DF9FFULL,
		0x83BAE2E4F2131FC8ULL,
		0xED49CAAB47E925F3ULL,
		0xF932305F7CD7EB81ULL,
		0xDD5B8FF22442C3DEULL,
		0xDDC57F539C710C87ULL,
		0xB62E91023EBA319CULL,
		0xA76796B3018E55B7ULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 460 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x592F6D36F995B0BDULL,
		0x53133B4891CA066BULL,
		0xE2BAF261E4B321C8ULL,
		0xE84F6B08BF79C140ULL,
		0xF5043060AB46D6D5ULL,
		0xEB9AB2987AB7A800ULL,
		0x68BC25E1332D188FULL,
		0x635933BAC7C53BE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x096AACDF75D7169FULL,
		0xCD5A2DD8860EFCA1ULL,
		0xDE1F973CF89DA039ULL,
		0x80ECCC5A6A0AD137ULL,
		0xE06E44EE1AB12052ULL,
		0xF5CE76251F1C673DULL,
		0x1CE3207328A9BC1FULL,
		0x4C71B21087D2B74CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5045C1E98C42A622ULL,
		0x9E49169017C4FACAULL,
		0x3CA5655D1C2E81F1ULL,
		0x68A3A752D5731077ULL,
		0x156A748EB1F7F687ULL,
		0x1E54C4BD65ABCF3DULL,
		0x745F05921B84A490ULL,
		0x2F2881AA40178CADULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 461 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAF72605E18A2080ULL,
		0xFA3178D983653E4DULL,
		0x558C2D4C10611CFEULL,
		0xBF4739BAFE33D925ULL,
		0x6458512B84010691ULL,
		0x21AC3DC53E0D0D76ULL,
		0x7E77D1ACE7240B68ULL,
		0xB314071D3D77CD61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42D32E40FBE9985ULL,
		0x9DDD79DA7D5A81F6ULL,
		0x4DDF8E417249B250ULL,
		0xEBD6DACA99DE489EULL,
		0x63156A6163C07A55ULL,
		0x18C066348505AD71ULL,
		0xE98D686047E231B7ULL,
		0x364A1564140F50ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EDA14E1EE34B905ULL,
		0x67EC0103FE3FBFBBULL,
		0x1853A30D6228AEAEULL,
		0x5491E37067ED91BBULL,
		0x074D3B4AE7C17CC4ULL,
		0x396C5BF1BB08A007ULL,
		0x97FAB9CCA0C63ADFULL,
		0x855E127929789DCCULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 462 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3661E8C33C399C76ULL,
		0x62AB46CB264ED33CULL,
		0xA535E362DEED95C5ULL,
		0xE1D1042A173F3F98ULL,
		0xE75A30CEC37AC339ULL,
		0x972F7F46A6A51FF3ULL,
		0xB68BB5EBD02377FCULL,
		0x4CC29889C6053D02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE7EC4607FD4469EULL,
		0x7A8937DDDB46FF09ULL,
		0x1F16574AEFBDCEADULL,
		0xCF8604A5868DE1C8ULL,
		0xB2CD5FC65F6F6B1DULL,
		0xCFE29AACF61D36FBULL,
		0x0FEAE13A05EE62B0ULL,
		0x77ABE3232BECE2A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF81F2CA343EDDAE8ULL,
		0x18227116FD082C35ULL,
		0xBA23B42831505B68ULL,
		0x2E57008F91B2DE50ULL,
		0x55976F089C15A824ULL,
		0x58CDE5EA50B82908ULL,
		0xB96154D1D5CD154CULL,
		0x3B697BAAEDE9DFA6ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 463 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B65B97E05D27E1DULL,
		0x5E708700D024C406ULL,
		0x22EBB1F4255E1E9CULL,
		0x94F4C7A2A624C906ULL,
		0xE106EC3723260765ULL,
		0x1D6093C582F689FBULL,
		0x90B319D6DB9C653CULL,
		0x95CE4A9E4AB22165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE17C11B69E4118EULL,
		0xC42A66F9193E077BULL,
		0x02F3D36533D36C36ULL,
		0x1169E53D4D82FBDCULL,
		0xB2594A7DDCB81869ULL,
		0xE198B4EEEB92B853ULL,
		0x4D9E0F0182C4C399ULL,
		0x9B52832E7CD95385ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF57278656C366F93ULL,
		0x9A5AE1F9C91AC37DULL,
		0x20186291168D72AAULL,
		0x859D229FEBA632DAULL,
		0x535FA64AFF9E1F0CULL,
		0xFCF8272B696431A8ULL,
		0xDD2D16D75958A6A5ULL,
		0x0E9CC9B0366B72E0ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 464 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x296BF377747D96C9ULL,
		0xC8AFFAADE11E8577ULL,
		0x3FDD1D0A0B51FC30ULL,
		0x7E7B6C39C97386ECULL,
		0x06DCEBD0EDC616FFULL,
		0xD52F5D5200822713ULL,
		0xAA44752ADF9B511CULL,
		0x1E7BB7976435CA03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x367BD510427A534FULL,
		0x86CAA8C0B7334E25ULL,
		0x4A1C9C7266AD7DFBULL,
		0x737290E5F415D0E8ULL,
		0x1D1DDC1B90393C05ULL,
		0x292CA0FCD91E7430ULL,
		0x8A4A31747EAFC8E9ULL,
		0x077F95A3BFF688A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F1026673607C586ULL,
		0x4E65526D562DCB52ULL,
		0x75C181786DFC81CBULL,
		0x0D09FCDC3D665604ULL,
		0x1BC137CB7DFF2AFAULL,
		0xFC03FDAED99C5323ULL,
		0x200E445EA13499F5ULL,
		0x19042234DBC342A7ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 465 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA20A70455C76AF3ULL,
		0xDCA9F32C09D11744ULL,
		0x00B0D5F1999A008AULL,
		0x496CBF84FDFADF59ULL,
		0xD352F503E03651DCULL,
		0x292D3EB71AAFCF37ULL,
		0xB161004080EC1C25ULL,
		0x76F34D5DF472A304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EDDEC5882792079ULL,
		0x45D866945E4EB01EULL,
		0x4F58010E36B1C045ULL,
		0x2D335735BC74F53FULL,
		0xFE88F407321EED61ULL,
		0x8FEF92B4F8E13166ULL,
		0xB7A8B176D4A237D5ULL,
		0xF75A559BC679DF83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4FD4B5CD7BE4A8AULL,
		0x997195B8579FA75AULL,
		0x4FE8D4FFAF2BC0CFULL,
		0x645FE8B1418E2A66ULL,
		0x2DDA0104D228BCBDULL,
		0xA6C2AC03E24EFE51ULL,
		0x06C9B136544E2BF0ULL,
		0x81A918C6320B7C87ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 466 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70683E561912DDD1ULL,
		0x2766843F0EE84DE6ULL,
		0x62B36A0C1C9EF5EBULL,
		0x88BDF2A397536207ULL,
		0xF10463670FC30428ULL,
		0x437147C134CFAF55ULL,
		0x15BB58E5AAF15EB1ULL,
		0x70A85AA17F278012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAFE50D08417BA99ULL,
		0x2B1416E147E0C13AULL,
		0xFB57A8648023E0C7ULL,
		0x4DBBFA68E7C244FFULL,
		0x151BC4092AE3B224ULL,
		0x80A5CE5B34121743ULL,
		0xB80AA04D0EF609E5ULL,
		0xD3C65E7518550F90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA966E869D056748ULL,
		0x0C7292DE49088CDCULL,
		0x99E4C2689CBD152CULL,
		0xC50608CB709126F8ULL,
		0xE41FA76E2520B60CULL,
		0xC3D4899A00DDB816ULL,
		0xADB1F8A8A4075754ULL,
		0xA36E04D467728F82ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 467 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9093419E78D691CULL,
		0xD1D8E820FA25A614ULL,
		0xE8A9C6ED9DE0F8E6ULL,
		0x282BCDF49AAF1824ULL,
		0x5071F5C74CDA106EULL,
		0xD1B8E47B9EE96EB7ULL,
		0xF9E7667F8F8B3987ULL,
		0x652035B6B6531040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DCE80F4D1F8CAB6ULL,
		0xEDD40B1681D1B8F5ULL,
		0x44C602D91DD8E888ULL,
		0x559A30A2509EA820ULL,
		0x14FDCC925D3B6D05ULL,
		0xBFF24FCBC4161112ULL,
		0x2BC9231EA470E8FBULL,
		0x5348A20DA81F6F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4C7B4ED3675A3AAULL,
		0x3C0CE3367BF41EE1ULL,
		0xAC6FC4348038106EULL,
		0x7DB1FD56CA31B004ULL,
		0x448C395511E17D6BULL,
		0x6E4AABB05AFF7FA5ULL,
		0xD22E45612BFBD17CULL,
		0x366897BB1E4C7F05ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 468 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88ED02B00F6B231AULL,
		0xF39518011E33AC0BULL,
		0xFA3838EE88ECCEDFULL,
		0x23645DA1A7BEC1A5ULL,
		0x6A3C67D4692160E5ULL,
		0xB3E5133546EDAA22ULL,
		0x9E690AB83FB92AEEULL,
		0x9624B1C74D10A13AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD035E1A55B17404ULL,
		0x691317F282483DDDULL,
		0x8F36DB1C73769499ULL,
		0x93304DCE8B2CF4F1ULL,
		0x6EE8336C6FFA4EDEULL,
		0xF93F1EFB4A4E970AULL,
		0x9EAB4E0BD5956749ULL,
		0x86D9C60EED594DA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55EE5CAA5ADA571EULL,
		0x9A860FF39C7B91D6ULL,
		0x750EE3F2FB9A5A46ULL,
		0xB054106F2C923554ULL,
		0x04D454B806DB2E3BULL,
		0x4ADA0DCE0CA33D28ULL,
		0x00C244B3EA2C4DA7ULL,
		0x10FD77C9A049EC9CULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 469 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7DEC3755ACE8D1CULL,
		0xF3BF6C24CB984A56ULL,
		0x51F45FDF4F0EEEDBULL,
		0xF0076135CDDB9A44ULL,
		0x8EC1A0BB1B9DE14CULL,
		0xBB0D233FB451DBDDULL,
		0xD42B4545754DB8B4ULL,
		0xFC6CE8CE6010A4ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BEB8CF8A6FA9A14ULL,
		0x360A65D3A6BBB1A1ULL,
		0x7BEB57166D64F473ULL,
		0xAA63B7E8D7B3C892ULL,
		0x5E426C9AB1A03D5DULL,
		0x9C1353F0BCE4EA94ULL,
		0xEDD94A3A45C93C05ULL,
		0x84BE45EE5681A0E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC354F8DFC341708ULL,
		0xC5B509F76D23FBF7ULL,
		0x2A1F08C9226A1AA8ULL,
		0x5A64D6DD1A6852D6ULL,
		0xD083CC21AA3DDC11ULL,
		0x271E70CF08B53149ULL,
		0x39F20F7F308484B1ULL,
		0x78D2AD2036910444ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 470 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD97DED691445DD00ULL,
		0x5D3C4FA0E514F582ULL,
		0xB163FB15C91FAEA7ULL,
		0x0C453559697AAC98ULL,
		0x7A323639F85B9942ULL,
		0xA3EBC7DE9B1E2388ULL,
		0x793283FB48FCE15DULL,
		0x77F51FAB56C4F9CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8ED715B24E440DCULL,
		0x518A1AC50ABAACA1ULL,
		0xAC346F5C503147BAULL,
		0x7866937409E67585ULL,
		0xD4A713D1993B9F8EULL,
		0x9E8D9A1A52F6C5CFULL,
		0x0BD72A0D78826991ULL,
		0xC009C8809775A3B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61909C3230A19DDCULL,
		0x0CB65565EFAE5923ULL,
		0x1D579449992EE91DULL,
		0x7423A62D609CD91DULL,
		0xAE9525E8616006CCULL,
		0x3D665DC4C9E8E647ULL,
		0x72E5A9F6307E88CCULL,
		0xB7FCD72BC1B15A78ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 471 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FAA6FC0C637691EULL,
		0x6861F0B09743EA0AULL,
		0xB1C25E28DF77B610ULL,
		0xDA4686541346FD3AULL,
		0x2556BB4D8DD3C794ULL,
		0xBCBF93EC315FE642ULL,
		0x245422B09C71B9DDULL,
		0x4DFAE57894F45377ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D2F9769CE2BE391ULL,
		0x854A1142BC522F60ULL,
		0x0ECF3E5AA0E7C811ULL,
		0x9B3928296703A561ULL,
		0xB06FAA6EA2FD59F3ULL,
		0x14407C32FA983101ULL,
		0x034C6AE3AD14DC79ULL,
		0x7778BAA192E055CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5285F8A9081C8A8FULL,
		0xED2BE1F22B11C56AULL,
		0xBF0D60727F907E01ULL,
		0x417FAE7D7445585BULL,
		0x953911232F2E9E67ULL,
		0xA8FFEFDECBC7D743ULL,
		0x27184853316565A4ULL,
		0x3A825FD9061406BBULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 472 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C482F89984ACD3DULL,
		0xCE666DD9D5181042ULL,
		0x4A380B47F052EC02ULL,
		0x69166A44FD82F1D4ULL,
		0xB2BCF56F5022E522ULL,
		0x76C0F731B499CCB5ULL,
		0x750A9B461CDE9421ULL,
		0x953997A8F24B2A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65AC49DEAC191C74ULL,
		0x97B03A145D6E0F96ULL,
		0xE4639367631A9AF6ULL,
		0xFDB311AF40D18747ULL,
		0x320C1EFB48895E07ULL,
		0x56477AA980E56C77ULL,
		0x429838FBDE2B3493ULL,
		0x50A154C7CF344B45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49E466573453D149ULL,
		0x59D657CD88761FD4ULL,
		0xAE5B9820934876F4ULL,
		0x94A57BEBBD537693ULL,
		0x80B0EB9418ABBB25ULL,
		0x20878D98347CA0C2ULL,
		0x3792A3BDC2F5A0B2ULL,
		0xC598C36F3D7F61C5ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 473 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5984814D6D5C25BULL,
		0x1A670FB334DE7368ULL,
		0xE40475CCCB49B8F3ULL,
		0xE686B1750253EF6AULL,
		0xB12643AAD2875C5FULL,
		0x78B60D2F5B5E77D7ULL,
		0xDF502B8F47B847D6ULL,
		0xBC7652840BDDE0C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A2825A78EEF06EULL,
		0xA1C2D843BD220E6EULL,
		0x05E870EEAD4D80CEULL,
		0x4B63DB9D5CF195DCULL,
		0x1B62F8D88045F96BULL,
		0x95C32B86AB836202ULL,
		0xA3121A4E936BCCC2ULL,
		0x274B7AF723326594ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x553ACA4EAE3B3235ULL,
		0xBBA5D7F089FC7D06ULL,
		0xE1EC05226604383DULL,
		0xADE56AE85EA27AB6ULL,
		0xAA44BB7252C2A534ULL,
		0xED7526A9F0DD15D5ULL,
		0x7C4231C1D4D38B14ULL,
		0x9B3D287328EF855DULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 474 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B7B4E572A5BF182ULL,
		0x4ACA68F19DF70AACULL,
		0x8391F99B360EB8BAULL,
		0x3F3A3046ABE9E72DULL,
		0xB63755ADA5454E6FULL,
		0x34DC83B45B9D08A8ULL,
		0x8662D9F3B99251EEULL,
		0x5F85139FF3277466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D906D251B53CE8ULL,
		0xACCBA83E2E25A6B2ULL,
		0x0EA7C923974BF0D5ULL,
		0xCF542C5DDF07D573ULL,
		0x9DB23CD510CF4091ULL,
		0x4008CC31AE3B9E83ULL,
		0x35E46D812969396DULL,
		0x048362FD61C9614BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBA248857BEECD6AULL,
		0xE601C0CFB3D2AC1EULL,
		0x8D3630B8A145486FULL,
		0xF06E1C1B74EE325EULL,
		0x2B856978B58A0EFEULL,
		0x74D44F85F5A6962BULL,
		0xB386B47290FB6883ULL,
		0x5B06716292EE152DULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 475 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x245877B731D1E5CAULL,
		0x4E1E74F83C04D9E0ULL,
		0x7CD6431BF0753C3CULL,
		0x0770E01B737EBED6ULL,
		0xE2B0B5C585C262EFULL,
		0xB4F88F1DBF404DA2ULL,
		0x079E727A87A05DFBULL,
		0x3D2B2CC4C4409789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD787B5D0E8D6BB25ULL,
		0x2AAACC45352D3743ULL,
		0x2603FC0F2BCA3C60ULL,
		0x8A0823BDDFD5B72FULL,
		0xED755E96EC2A8DBAULL,
		0x51F9BE528C33A3FCULL,
		0x492126C1D55D7AA6ULL,
		0x6B160F2C95E67011ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3DFC267D9075EEFULL,
		0x64B4B8BD0929EEA3ULL,
		0x5AD5BF14DBBF005CULL,
		0x8D78C3A6ACAB09F9ULL,
		0x0FC5EB5369E8EF55ULL,
		0xE501314F3373EE5EULL,
		0x4EBF54BB52FD275DULL,
		0x563D23E851A6E798ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 476 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD521FB28BB9F3594ULL,
		0x3872DFBD33BF5411ULL,
		0xA68E46BF9E8375B8ULL,
		0xB22CF80F4D8F3947ULL,
		0xEDA43CE91D4F048EULL,
		0xA35EFD7623028E33ULL,
		0x6DFB0BA3FEDB57EFULL,
		0xE540B897358CE9F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FBA5DD57F0D08E6ULL,
		0x31A697832BE3CCA1ULL,
		0x02D553501FBFD5FDULL,
		0x1785590A7438714AULL,
		0xCEF98A7514F2C808ULL,
		0xE9798442340DDFD6ULL,
		0x63DF6A4387D0ED44ULL,
		0x712D7B079474713BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA9BA6FDC4923D72ULL,
		0x09D4483E185C98B0ULL,
		0xA45B15EF813CA045ULL,
		0xA5A9A10539B7480DULL,
		0x235DB69C09BDCC86ULL,
		0x4A277934170F51E5ULL,
		0x0E2461E0790BBAABULL,
		0x946DC390A1F898C2ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 477 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x265F6FAC236B5BDBULL,
		0x61079EF4775E1558ULL,
		0x4867EE090BBB0B45ULL,
		0x4C4FB379432C4E30ULL,
		0xCC4FAAAB2D8B882FULL,
		0x5F9ECDAB92D49299ULL,
		0xA0B968C22EF22456ULL,
		0xB1EFE3ACD5A7A12DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E5739BA9D592DBULL,
		0xBB3797264D8B1076ULL,
		0x054F836DF34ED2BAULL,
		0x47C993A51242840CULL,
		0xE35B321C3711337FULL,
		0x175E1D8092723B4EULL,
		0x7A78DDEABCCB9101ULL,
		0x4DB71F3287034F70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10BA1C378ABEC900ULL,
		0xDA3009D23AD5052EULL,
		0x4D286D64F8F5D9FFULL,
		0x0B8620DC516ECA3CULL,
		0x2F1498B71A9ABB50ULL,
		0x48C0D02B00A6A9D7ULL,
		0xDAC1B5289239B557ULL,
		0xFC58FC9E52A4EE5DULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 478 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E459C9B092C2498ULL,
		0x58E377395911687BULL,
		0x10B4E69574A77B01ULL,
		0xCF10D9B6438DBD5FULL,
		0xB3C56FE1275A3EFEULL,
		0x826CB05AE5B50B46ULL,
		0x8CD126EE6AC22E2DULL,
		0xACB31073EE427C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B95C0CCC4162AEULL,
		0x3432ADF632B8D943ULL,
		0x64AF00BDBA9A8665ULL,
		0x797D2DF864C8CB1EULL,
		0x4753452940F3DDE5ULL,
		0x9607B147B7CC16A7ULL,
		0x809873FA515F9DC6ULL,
		0x33FD4E44551E1D8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38FCC097C56D4636ULL,
		0x6CD1DACF6BA9B138ULL,
		0x741BE628CE3DFD64ULL,
		0xB66DF44E27457641ULL,
		0xF4962AC867A9E31BULL,
		0x146B011D52791DE1ULL,
		0x0C4955143B9DB3EBULL,
		0x9F4E5E37BB5C61F9ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 479 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC25AD3390AEC2FAULL,
		0x18BF27A55E1FF296ULL,
		0xAC03C0BC72DA6139ULL,
		0xD9B5B45A54A38A9DULL,
		0xF984C984DBA5FF0BULL,
		0x4CD4C1456D53F277ULL,
		0x9F6410922F865688ULL,
		0xFB025EBA91C7382DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x273A2A90281A4CFCULL,
		0x87FBA3FEC0037420ULL,
		0x6002074B20B5F976ULL,
		0x380AF3300153D3E1ULL,
		0x21034D2578F3DA93ULL,
		0x9C16F002B80E8C36ULL,
		0x7101D106732160D7ULL,
		0xF5A5164C13E0A776ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB1F87A3B8B48E06ULL,
		0x9F44845B9E1C86B6ULL,
		0xCC01C7F7526F984FULL,
		0xE1BF476A55F0597CULL,
		0xD88784A1A3562598ULL,
		0xD0C23147D55D7E41ULL,
		0xEE65C1945CA7365FULL,
		0x0EA748F682279F5BULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 480 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8456AAC5CDA64D36ULL,
		0x1363ECF00C60B879ULL,
		0x18DB85BA805389FBULL,
		0xADFBDAE920AC9A38ULL,
		0x35263B03008C6FD4ULL,
		0x347946F3B4B6D5D2ULL,
		0x9B2B20968E8FAF25ULL,
		0xEC8759E859304181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74CF800E7C9FA520ULL,
		0x433A9E21E1F406C7ULL,
		0x4DA3C95A053F9EEAULL,
		0x1561794D66B95A68ULL,
		0x5CD209EE0F54AE56ULL,
		0x2AF7C2D7DF53588FULL,
		0x4F1A62735E68F78BULL,
		0x25C161947F7770C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0992ACBB139E816ULL,
		0x505972D1ED94BEBEULL,
		0x55784CE0856C1711ULL,
		0xB89AA3A44615C050ULL,
		0x69F432ED0FD8C182ULL,
		0x1E8E84246BE58D5DULL,
		0xD43142E5D0E758AEULL,
		0xC946387C26473146ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 481 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE092E765396DE4E6ULL,
		0xEABAF3123E96DA96ULL,
		0x84A223CDC973F9CEULL,
		0xE34860B0F3CC1B6FULL,
		0x97D2F77245AD8D0FULL,
		0x576D530205D4DAB6ULL,
		0x4DE41B28692E3EE3ULL,
		0xCAAAD89C18916C15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D321CCFA36408BULL,
		0x923115FFF152AF5AULL,
		0xA7652C093128FA79ULL,
		0xFAB01ED188642ABAULL,
		0xCC195E194D8C9965ULL,
		0xAEE466A8BFEF493CULL,
		0x67C4FF348E45C44CULL,
		0x415EA25CC2EFE514ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD741C6A9C35BA46DULL,
		0x788BE6EDCFC475CCULL,
		0x23C70FC4F85B03B7ULL,
		0x19F87E617BA831D5ULL,
		0x5BCBA96B0821146AULL,
		0xF98935AABA3B938AULL,
		0x2A20E41CE76BFAAFULL,
		0x8BF47AC0DA7E8901ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 482 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8D739FC09C99B4A8ULL,
		0x737F5F401B908C46ULL,
		0x59BDCD32E9226D6EULL,
		0x35B657E64E5C3E4AULL,
		0xD9E0998600BD98FBULL,
		0xCF52C427932EC4A6ULL,
		0x1146F285B7CDE1FAULL,
		0x5B5CF879B120B406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88AC083C4DFA27B9ULL,
		0x6C0E147F170E4B03ULL,
		0x6A6E511476191090ULL,
		0x49E24A3C4012772DULL,
		0x6A4D9F6A8975A069ULL,
		0x6F98D07B3F2294B0ULL,
		0xDECAFEE6D3D2B342ULL,
		0x0DC814B8EAADFE31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05DF97FCD1639311ULL,
		0x1F714B3F0C9EC745ULL,
		0x33D39C269F3B7DFEULL,
		0x7C541DDA0E4E4967ULL,
		0xB3AD06EC89C83892ULL,
		0xA0CA145CAC0C5016ULL,
		0xCF8C0C63641F52B8ULL,
		0x5694ECC15B8D4A37ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 483 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEFC274D18703B13ULL,
		0xB29EB73525F76BADULL,
		0x59F117DC135BA253ULL,
		0xD384009A94AF7DF9ULL,
		0xAC834D9F544D04F3ULL,
		0x4C82FC2054FAA7FEULL,
		0x8A180EECBF37EAB7ULL,
		0x922529F24B2BE916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3321787AD7A7B1CULL,
		0x51391050C7DC75F3ULL,
		0x41C62070D2E637F5ULL,
		0x7E306F900EF5BD0DULL,
		0xA632EFD8FB47F48EULL,
		0x064C9613E49CF580ULL,
		0xF06E46C9A8A5F0FFULL,
		0x60CE7462FBF478A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DCE30CAB50A400FULL,
		0xE3A7A765E22B1E5EULL,
		0x183737ACC1BD95A6ULL,
		0xADB46F0A9A5AC0F4ULL,
		0x0AB1A247AF0AF07DULL,
		0x4ACE6A33B066527EULL,
		0x7A76482517921A48ULL,
		0xF2EB5D90B0DF91B3ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 484 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA855978752BE7E95ULL,
		0x4529E46309A67D1CULL,
		0xD0D0464427C9E0BAULL,
		0x43F5B59376972405ULL,
		0x8AF9B5F743498125ULL,
		0xAB2C12A7780133B8ULL,
		0x3F939E242393E12FULL,
		0x806C05F9FE13E7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9DCB1E2402FAC68ULL,
		0x8E36641CC9C21E24ULL,
		0x3B9754225FA85666ULL,
		0x9F7C7C57BECE9577ULL,
		0xFA9A3FF468A47875ULL,
		0x68203F3CB9F5DE1DULL,
		0xF8ED6AE525ED91BDULL,
		0x0B09F00BCA084FACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x718926651291D2FDULL,
		0xCB1F807FC0646338ULL,
		0xEB4712667861B6DCULL,
		0xDC89C9C4C859B172ULL,
		0x70638A032BEDF950ULL,
		0xC30C2D9BC1F4EDA5ULL,
		0xC77EF4C1067E7092ULL,
		0x8B65F5F2341BA813ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 485 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C3AA671AFD895FCULL,
		0x86F96C909D3B6860ULL,
		0x43590B78D6D59BD3ULL,
		0x72FEA6AD14F4F640ULL,
		0x41B26FFFF07C277CULL,
		0x54A63E3F3C164C10ULL,
		0xB43918223E0E27DDULL,
		0xB94BE70CC5DD7199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61216D82D97BE6EBULL,
		0x7C10D3956B4CCBB6ULL,
		0x7D72E8D1C5DF28CCULL,
		0x12C75B9E4EFAAF4BULL,
		0xD5D1FAA296E98F76ULL,
		0x9A8A703DB9C0D319ULL,
		0xCB0647F193EB4B4BULL,
		0x62C339EF292BBD09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D1BCBF376A37317ULL,
		0xFAE9BF05F677A3D6ULL,
		0x3E2BE3A9130AB31FULL,
		0x6039FD335A0E590BULL,
		0x9463955D6695A80AULL,
		0xCE2C4E0285D69F09ULL,
		0x7F3F5FD3ADE56C96ULL,
		0xDB88DEE3ECF6CC90ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 486 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8A66A0220B3884EULL,
		0xD96E212D18EB96DAULL,
		0xFDAA5075DC95BF4EULL,
		0x55AB44E2BB0E6F03ULL,
		0x4171B30A67F0B66EULL,
		0x8350F81AB30E9004ULL,
		0x815A0CF76F729ADEULL,
		0x143DEDD9070312BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x074D01C841B69CCBULL,
		0xAC32B2F098993DF7ULL,
		0x2A280564A8AA339EULL,
		0x41CB61CCC6B4F89BULL,
		0xD2B3F796C1F95E51ULL,
		0xF4AD4DF63C646A28ULL,
		0x780782975B2BFE2CULL,
		0x3148EA60BAF9D246ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEFEB6BCA61051485ULL,
		0x755C93DD8072AB2DULL,
		0xD7825511743F8CD0ULL,
		0x1460252E7DBA9798ULL,
		0x93C2449CA609E83FULL,
		0x77FDB5EC8F6AFA2CULL,
		0xF95D8E60345964F2ULL,
		0x257507B9BDFAC0FDULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 487 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54027A8E232DC98EULL,
		0x0F9AA28F921F2F53ULL,
		0xACD4EF974E8DE987ULL,
		0x3A0C2A89718842E1ULL,
		0xF3E54E68E7B617F7ULL,
		0x527297117AC7F2FDULL,
		0x9B692C04BE66216CULL,
		0x8B820E062007D80AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x517502DA6FAA587AULL,
		0x927504A1FCE323CAULL,
		0x1B4E898545D39779ULL,
		0x470BEF38C20B1D98ULL,
		0xAEC1F1FA4BF382A3ULL,
		0x3E8870A1153742F7ULL,
		0x7ABE354B2EACCB60ULL,
		0x03A8084FEF8CA82EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x057778544C8791F4ULL,
		0x9DEFA62E6EFC0C99ULL,
		0xB79A66120B5E7EFEULL,
		0x7D07C5B1B3835F79ULL,
		0x5D24BF92AC459554ULL,
		0x6CFAE7B06FF0B00AULL,
		0xE1D7194F90CAEA0CULL,
		0x882A0649CF8B7024ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 488 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3897CB116DD25FA5ULL,
		0x9C7D9880E4BFBA90ULL,
		0x6F74A97359007460ULL,
		0xA68955E9E0E750CDULL,
		0xC8F8C6674836E44AULL,
		0xFB7602AF3EFD3FCEULL,
		0xA35C746C4BAAE9B5ULL,
		0xA38A085D2F05D2C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0735675FE5EB74EULL,
		0x9898B7E5BB857C72ULL,
		0x28510103D7DC81D7ULL,
		0x54B6580BA2322F2CULL,
		0xFFC3093E1175A0C8ULL,
		0xE8FCEE435C09CC81ULL,
		0x13FD146C0D5A32E7ULL,
		0xF2E0EA305158B2A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88E49D64938CE8EBULL,
		0x04E52F655F3AC6E2ULL,
		0x4725A8708EDCF5B7ULL,
		0xF23F0DE242D57FE1ULL,
		0x373BCF5959434482ULL,
		0x138AECEC62F4F34FULL,
		0xB0A1600046F0DB52ULL,
		0x516AE26D7E5D6060ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 489 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11413C385FDB3CB2ULL,
		0x4159BCCD4FDDA194ULL,
		0xBC29D3DEB2B2988FULL,
		0xE970DDE9D9E8E75DULL,
		0x98A8F528184EA04BULL,
		0xAF998D0003850859ULL,
		0xDF4E5D1AB48ABE33ULL,
		0x0756D0DD8ABDF77CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x356E37FF998F70ACULL,
		0x37E7CF4E402E1E5BULL,
		0xA36A0CF97BBCAE1EULL,
		0x40064EF446B340BDULL,
		0x99DBE77170479BCDULL,
		0x70EC6A7735ACEBBDULL,
		0x2FB80E205F84444AULL,
		0x7B9BE4E2B5B8A711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x242F0BC7C6544C1EULL,
		0x76BE73830FF3BFCFULL,
		0x1F43DF27C90E3691ULL,
		0xA976931D9F5BA7E0ULL,
		0x0173125968093B86ULL,
		0xDF75E7773629E3E4ULL,
		0xF0F6533AEB0EFA79ULL,
		0x7CCD343F3F05506DULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 490 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA50B9B1F6CAE25CFULL,
		0x2C9227390A71CE8CULL,
		0xD3A110C6CD75E88EULL,
		0xEE5C31F2CF8942CFULL,
		0x68BFA38DD9894DF7ULL,
		0x46B077D41B53757AULL,
		0x4538587B16491E18ULL,
		0x2645B12B25CC3AB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40D3ADCCAB88ED54ULL,
		0x90DF309A428015C6ULL,
		0xFBA55ED8F0D0E71AULL,
		0xC68FF89F050C9936ULL,
		0xE06283AB315EB413ULL,
		0x7E7D0AE08E324878ULL,
		0x922916C15E3B8D48ULL,
		0x26CBCAE056DF2DFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5D836D3C726C89BULL,
		0xBC4D17A348F1DB4AULL,
		0x28044E1E3DA50F94ULL,
		0x28D3C96DCA85DBF9ULL,
		0x88DD2026E8D7F9E4ULL,
		0x38CD7D3495613D02ULL,
		0xD7114EBA48729350ULL,
		0x008E7BCB7313174FULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 491 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47CF9FD85B19A485ULL,
		0x32E24BDF4670B48CULL,
		0x1D327B600C907802ULL,
		0xE839EFA92B41B403ULL,
		0x402FB2F1575299DEULL,
		0x6BFEBD962087D95EULL,
		0xA9FBB7350541AF01ULL,
		0xB9C20EA523E51EEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA9EB51E5E4C4597ULL,
		0xC66435386DCD01B1ULL,
		0x768C7BADFE7D31E7ULL,
		0xCE49420B9BAAAC72ULL,
		0x88D62CF8CACB7495ULL,
		0xEBB981F0390E20CBULL,
		0xAC83818006B642FDULL,
		0x97AD7A144E7A0310ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD512AC60555E112ULL,
		0xF4867EE72BBDB53DULL,
		0x6BBE00CDF2ED49E5ULL,
		0x2670ADA2B0EB1871ULL,
		0xC8F99E099D99ED4BULL,
		0x80473C661989F995ULL,
		0x057836B503F7EDFCULL,
		0x2E6F74B16D9F1DFAULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 492 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9145A4D0B067305ULL,
		0xD8F1C52E7EE79E8CULL,
		0x072FF99CE463ADD1ULL,
		0xE39A19D213551B13ULL,
		0x1DD543AFD2533A06ULL,
		0x04622AFEF4437C9EULL,
		0xD4AE6A7A64E947C7ULL,
		0xE12D9262B387BE40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E2B6F03AA95DBFULL,
		0xD77ADD7287B224A7ULL,
		0xE03DB65CA487BE84ULL,
		0x6D7B8B1AD1CC8988ULL,
		0xB65A34AABD8C6296ULL,
		0xA021A5D88D5C3579ULL,
		0x0CC4D78E1CB8275CULL,
		0xD5ACCDF9BD0F0350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FF6ECBD31AF2EBAULL,
		0x0F8B185CF955BA2BULL,
		0xE7124FC040E41355ULL,
		0x8EE192C8C299929BULL,
		0xAB8F77056FDF5890ULL,
		0xA4438F26791F49E7ULL,
		0xD86ABDF47851609BULL,
		0x34815F9B0E88BD10ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 493 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D7BF90EE02ED1CBULL,
		0x9F1A372AF8C64BB7ULL,
		0x788377B0147708FCULL,
		0xB3C114A6EBEB6D27ULL,
		0xA525F4787FA90FF5ULL,
		0x26FB56206C2A2530ULL,
		0xEE9E3085B59762BFULL,
		0xD5E80CF27A741681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F5EDA04DA5DBE32ULL,
		0x0C926C17CE0503FFULL,
		0x743AB5F43CEA9E5EULL,
		0x68C228D20F1DE5FFULL,
		0x66216E59D33E5A78ULL,
		0xB3D21D9EDDEF0144ULL,
		0x389B13C92BFF5879ULL,
		0x154DADFE572AFAA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7225230A3A736FF9ULL,
		0x93885B3D36C34848ULL,
		0x0CB9C244289D96A2ULL,
		0xDB033C74E4F688D8ULL,
		0xC3049A21AC97558DULL,
		0x95294BBEB1C52474ULL,
		0xD605234C9E683AC6ULL,
		0xC0A5A10C2D5EEC29ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 494 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC49D77823DCFE2DEULL,
		0x0869481CEA1B897BULL,
		0x4EC710F55293BEEFULL,
		0x57026535B5953681ULL,
		0xF1BB0C62EA3C6AF8ULL,
		0x0F5FD9968F6E4508ULL,
		0x9CB2CEF5F93340A1ULL,
		0xA05E6AF4338E6BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3159FFE567F2851ULL,
		0x4488FAE224D7BEE5ULL,
		0xDBEC5B4DEACD0BA3ULL,
		0x8E5814DD1B0BD294ULL,
		0xE760EC324424A0ABULL,
		0x516D9ECD0507866AULL,
		0x428CD55C07B3A728ULL,
		0x13FC15F5A17B7253ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3788E87C6BB0CA8FULL,
		0x4CE1B2FECECC379EULL,
		0x952B4BB8B85EB54CULL,
		0xD95A71E8AE9EE415ULL,
		0x16DBE050AE18CA53ULL,
		0x5E32475B8A69C362ULL,
		0xDE3E1BA9FE80E789ULL,
		0xB3A27F0192F51993ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 495 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x468FCA23EA5E2862ULL,
		0xB2CB57AA5B2C64D9ULL,
		0x41016712004F7E20ULL,
		0x8916E27404B306A5ULL,
		0x84FD60FA1721800AULL,
		0x9CAE2AD41656A5C8ULL,
		0xE201AF0C3740638DULL,
		0x3EBB058836556353ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3D7635EC614DDAULL,
		0xE4831CF5F1BCE909ULL,
		0x2B56111D643CC4A1ULL,
		0x4B41A717BA10214CULL,
		0x6F7743C41124B9D7ULL,
		0xD001C5B04C1EA9F8ULL,
		0x341C5500380470A8ULL,
		0x6F521DFECC8A2334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDB2BC16063F65B8ULL,
		0x56484B5FAA908DD0ULL,
		0x6A57760F6473BA81ULL,
		0xC2574563BEA327E9ULL,
		0xEB8A233E060539DDULL,
		0x4CAFEF645A480C30ULL,
		0xD61DFA0C0F441325ULL,
		0x51E91876FADF4067ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 496 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB05435FC17BF859ULL,
		0x47F8D73353E9F707ULL,
		0xD84D761B97853872ULL,
		0x1D7C98E6BD76E03AULL,
		0x0CF32E317B1F6E36ULL,
		0xB43F1446C7E30C43ULL,
		0xB671D3FE70E25B60ULL,
		0xC5BF6BBEE5167D05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72F1CCE806A5F4BDULL,
		0x56275A1AA2503786ULL,
		0x9259CC321DEBC7D6ULL,
		0xFC57EA4B3BBFD1A4ULL,
		0x6D67CD17DE4C6625ULL,
		0x3F5332344CE5E4A3ULL,
		0x94DE18C3BE39A2B6ULL,
		0x78A26D1DD4C4F156ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9F48FB7C7DE0CE4ULL,
		0x11DF8D29F1B9C081ULL,
		0x4A14BA298A6EFFA4ULL,
		0xE12B72AD86C9319EULL,
		0x6194E326A5530813ULL,
		0x8B6C26728B06E8E0ULL,
		0x22AFCB3DCEDBF9D6ULL,
		0xBD1D06A331D28C53ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 497 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7F073097890AC7BULL,
		0x2E34AF54A955812DULL,
		0xC4CD986D0BD6A97EULL,
		0x720C81845703CD36ULL,
		0xD1D1EB7916694118ULL,
		0x208D5526C1B3D6ABULL,
		0xD174DCAB85217119ULL,
		0x83B33CCFEFB4EE7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570BB4DC56ED00C2ULL,
		0xCB4B4E70E2BC50D5ULL,
		0xDC5989AEFA120B69ULL,
		0xE262656B9CBE8F72ULL,
		0x8519DDAFBBCC7E03ULL,
		0xB70D5FC0B426695CULL,
		0x87B210EA0D7E4E81ULL,
		0xCF7E6C460CF3FE2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0FBC7D52E7DACB9ULL,
		0xE57FE1244BE9D1F8ULL,
		0x189411C3F1C4A217ULL,
		0x906EE4EFCBBD4244ULL,
		0x54C836D6ADA53F1BULL,
		0x97800AE67595BFF7ULL,
		0x56C6CC41885F3F98ULL,
		0x4CCD5089E3471056ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 498 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA09223D8B617D99FULL,
		0xEF01186B17997F00ULL,
		0x49BA0221036767B9ULL,
		0x567FDC151FA245D5ULL,
		0x02A8F6D39FB939B5ULL,
		0x9B732A5E467CEA92ULL,
		0xD5F2D0E655D13E29ULL,
		0x4C8ADA5B5EEBC807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD946647E189619ULL,
		0x5FDA3AF5B1F229A5ULL,
		0x0A844FB084183261ULL,
		0x7DED8D72D5540866ULL,
		0xB876ED9D2B5F4E6BULL,
		0x248219F35980C788ULL,
		0xA86A9FBCB13449E5ULL,
		0xA7C0A01483E4B75AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF4B65BCC80F4F86ULL,
		0xB0DB229EA66B56A5ULL,
		0x433E4D91877F55D8ULL,
		0x2B925167CAF64DB3ULL,
		0xBADE1B4EB4E677DEULL,
		0xBFF133AD1FFC2D1AULL,
		0x7D984F5AE4E577CCULL,
		0xEB4A7A4FDD0F7F5DULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 499 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CE3B5A61ED3E93BULL,
		0xD5A71D89786755AFULL,
		0xF244CC77B7CF329EULL,
		0xB15C8640479D05A5ULL,
		0xFE78894B53B0E200ULL,
		0x378498BCA0E7D607ULL,
		0x94EA54F3E2B11E1CULL,
		0x93F570EF90ABF31EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1A6D9EC2848B51ULL,
		0x1843D832E6266FB4ULL,
		0x6E0FA648C91E0DC9ULL,
		0x382126DF05CD819DULL,
		0x72DF15BAFC6EBAEDULL,
		0xAC108132CB745E2FULL,
		0x8EFD4F37F24AB380ULL,
		0x6A0CC63212D22840ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02F9D838DC57626AULL,
		0xCDE4C5BB9E413A1BULL,
		0x9C4B6A3F7ED13F57ULL,
		0x897DA09F42508438ULL,
		0x8CA79CF1AFDE58EDULL,
		0x9B94198E6B938828ULL,
		0x1A171BC410FBAD9CULL,
		0xF9F9B6DD8279DB5EULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 500 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC1CE580398BAC4AULL,
		0xEEAD81B0526D67F7ULL,
		0x5B64667516C3DF30ULL,
		0x7B97050562324663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC1376FDE483BE14ULL,
		0xD8B1727BAD40EFB3ULL,
		0xFC47F2262A1DA22CULL,
		0x3236BB4919AF01CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC1376FDE483BE14ULL,
		0xD8B1727BAD40EFB3ULL,
		0xFC47F2262A1DA22CULL,
		0x3236BB4919AF01CEULL,
		0xBC1CE580398BAC4AULL,
		0xEEAD81B0526D67F7ULL,
		0x5B64667516C3DF30ULL,
		0x7B97050562324663ULL
	}};
	printf("Test Case 501\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 501 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C4CC01FE17D2C9DULL,
		0xB3B5F048063231DAULL,
		0x5FDE514777A6D408ULL,
		0xAA80B9BFB264771BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73ADC7F2AD12CB7DULL,
		0x418E91C9E1DF68F0ULL,
		0xC8A19D4FA05ABAE6ULL,
		0xF2A885E6F7EFA143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73ADC7F2AD12CB7DULL,
		0x418E91C9E1DF68F0ULL,
		0xC8A19D4FA05ABAE6ULL,
		0xF2A885E6F7EFA143ULL,
		0x6C4CC01FE17D2C9DULL,
		0xB3B5F048063231DAULL,
		0x5FDE514777A6D408ULL,
		0xAA80B9BFB264771BULL
	}};
	printf("Test Case 502\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 502 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2F50A91FBF4B90EULL,
		0x47A07ED5409689B8ULL,
		0xA84B957EB8139E49ULL,
		0x0CA938AB8AB3909DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43047CCF5084C42AULL,
		0xA59C0AF798E9C14EULL,
		0x62570818A9DFAD10ULL,
		0xBCB12CCFB3008F44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43047CCF5084C42AULL,
		0xA59C0AF798E9C14EULL,
		0x62570818A9DFAD10ULL,
		0xBCB12CCFB3008F44ULL,
		0xE2F50A91FBF4B90EULL,
		0x47A07ED5409689B8ULL,
		0xA84B957EB8139E49ULL,
		0x0CA938AB8AB3909DULL
	}};
	printf("Test Case 503\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 503 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED1C31B5A80BEDDCULL,
		0x963F7A52938B5747ULL,
		0xA6DEDDC960E423ECULL,
		0x748CD55963360BC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A256412DD499F5ULL,
		0xE67F9B30E1BAFD55ULL,
		0x6D6B149F3A469511ULL,
		0x1F307FE25F1F16CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78A256412DD499F5ULL,
		0xE67F9B30E1BAFD55ULL,
		0x6D6B149F3A469511ULL,
		0x1F307FE25F1F16CFULL,
		0xED1C31B5A80BEDDCULL,
		0x963F7A52938B5747ULL,
		0xA6DEDDC960E423ECULL,
		0x748CD55963360BC1ULL
	}};
	printf("Test Case 504\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 504 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x605E557A8E85D695ULL,
		0x8A8A261534EB93C7ULL,
		0xFE32C303C4438E97ULL,
		0x6F477CB199A16052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B13E1B8A4B4158AULL,
		0x5A1DBD1E205A3DE0ULL,
		0xD9DB85AF422F60E4ULL,
		0xFBBCFABC333A7A54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B13E1B8A4B4158AULL,
		0x5A1DBD1E205A3DE0ULL,
		0xD9DB85AF422F60E4ULL,
		0xFBBCFABC333A7A54ULL,
		0x605E557A8E85D695ULL,
		0x8A8A261534EB93C7ULL,
		0xFE32C303C4438E97ULL,
		0x6F477CB199A16052ULL
	}};
	printf("Test Case 505\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 505 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB30AC76CEF9E49DBULL,
		0x11D275FD112A2725ULL,
		0x350540CEF5FD9D55ULL,
		0x252224167182CA01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54FD7397B0EA896DULL,
		0xF24B3F31AA2D7D85ULL,
		0xCB0400D094AEA6CEULL,
		0x5CF6847CF04D37DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54FD7397B0EA896DULL,
		0xF24B3F31AA2D7D85ULL,
		0xCB0400D094AEA6CEULL,
		0x5CF6847CF04D37DEULL,
		0xB30AC76CEF9E49DBULL,
		0x11D275FD112A2725ULL,
		0x350540CEF5FD9D55ULL,
		0x252224167182CA01ULL
	}};
	printf("Test Case 506\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 506 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96EAC3E786C2CD9BULL,
		0xEA16776D468B9007ULL,
		0xE41AFCEA707E55C1ULL,
		0xDB5E2EE265F5E2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75FC68C2D1E1025AULL,
		0xE30290DA3B42BAA9ULL,
		0x4E9ACC785CB5E680ULL,
		0xFCFC94B33A41E0F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75FC68C2D1E1025AULL,
		0xE30290DA3B42BAA9ULL,
		0x4E9ACC785CB5E680ULL,
		0xFCFC94B33A41E0F8ULL,
		0x96EAC3E786C2CD9BULL,
		0xEA16776D468B9007ULL,
		0xE41AFCEA707E55C1ULL,
		0xDB5E2EE265F5E2BEULL
	}};
	printf("Test Case 507\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 507 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x574A1368B492BC46ULL,
		0xF77B6C6EE69424E9ULL,
		0xE5A1D2AAA21208A1ULL,
		0xEE9DBB797B2B0F27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB810B77AE1578C5ULL,
		0x11C824A8505D1136ULL,
		0x650A2E05B6A9964DULL,
		0x9CDC4CFEDA1D6116ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB810B77AE1578C5ULL,
		0x11C824A8505D1136ULL,
		0x650A2E05B6A9964DULL,
		0x9CDC4CFEDA1D6116ULL,
		0x574A1368B492BC46ULL,
		0xF77B6C6EE69424E9ULL,
		0xE5A1D2AAA21208A1ULL,
		0xEE9DBB797B2B0F27ULL
	}};
	printf("Test Case 508\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 508 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63AADFA767A2F7DFULL,
		0xCEFA156ED80522BCULL,
		0x8C36315EDA57118AULL,
		0xE991B5C16A3726D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF45ED098D144C926ULL,
		0x725B70BE2A11C819ULL,
		0xE0737C85F7C27D12ULL,
		0xCAA73D7DE0198C27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF45ED098D144C926ULL,
		0x725B70BE2A11C819ULL,
		0xE0737C85F7C27D12ULL,
		0xCAA73D7DE0198C27ULL,
		0x63AADFA767A2F7DFULL,
		0xCEFA156ED80522BCULL,
		0x8C36315EDA57118AULL,
		0xE991B5C16A3726D9ULL
	}};
	printf("Test Case 509\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 509 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB6DD412AD9EEAEEULL,
		0xEFE4E0336094EB11ULL,
		0x4EEB7F3EEE43AB90ULL,
		0x02E9956FE8DA1F1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA73A372FE11B00ULL,
		0x9F9BA3F05C69CFABULL,
		0x0EA1DE0AF404127EULL,
		0xCBC14F7DC757F2F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FA73A372FE11B00ULL,
		0x9F9BA3F05C69CFABULL,
		0x0EA1DE0AF404127EULL,
		0xCBC14F7DC757F2F9ULL,
		0xEB6DD412AD9EEAEEULL,
		0xEFE4E0336094EB11ULL,
		0x4EEB7F3EEE43AB90ULL,
		0x02E9956FE8DA1F1DULL
	}};
	printf("Test Case 510\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_xor(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 510 FAILED\n");
		printf("k1:\n");
		curve25519_key_printf(&k1, COMPLETE);
		printf("k2:\n");
		curve25519_key_printf(&k2, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}