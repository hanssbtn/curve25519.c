#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD36088E8451B8838ULL,
		0x75AC846C79FAA080ULL,
		0x78E854683A68BBB0ULL,
		0xBBE61FBFA00D2282ULL,
		0x9CA0DBCCCECF68F2ULL,
		0x32FDD4338EE2890CULL,
		0xE872B9E3C609BC5EULL,
		0x26A6146CEC7593CCULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xC374A97C4CA34BC3ULL,
		0xFC53BBA7425A4EE5ULL,
		0x0D2BB48DD434F067ULL,
		0x4EA7DF143B1F8275ULL,
		0x546CF16E2BBCCFDCULL,
		0x968593EC9C3C8D0DULL,
		0x26AB580374C25718ULL,
		0xE1D9EDEF6644E3B6ULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x483C297DAE4A7A4BULL,
		0xC2C19116A2CB83E2ULL,
		0x332F05599CE0BFC8ULL,
		0xF4E1AAD88547B551ULL,
		0xBFD8FF3DEB14E327ULL,
		0x34A5EC5D038FE5E0ULL,
		0x4BA9B39EC8CCFA9DULL,
		0x532D68F78192437CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFE3C83E2D3D5D8FULL,
		0x140EF5E02FF1A8E0ULL,
		0xD70528338028C448ULL,
		0xF4A272D07AB0517BULL,
		0xE9B89251059E4377ULL,
		0x35A9D74A60B1137CULL,
		0xEC2CF77B64FEA052ULL,
		0x060201462508B32CULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3B1A35A7F70DCA4ULL,
		0x22D222EF254CFF45ULL,
		0x74D60789AC3F4A48ULL,
		0x2FD858008757E93DULL,
		0x17F719902264B576ULL,
		0x94D65C5FF79FB9C1ULL,
		0x6480495C7833E7C6ULL,
		0x408E116942862AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E71AE88104D0D1ULL,
		0x6F56F4A085DEAFE3ULL,
		0x68D5DD222433A989ULL,
		0xB76DF330B7D06841ULL,
		0xDB456F05F5B6AFB8ULL,
		0xEC6CA69C5718CA97ULL,
		0xE6CB65FE8EECC455ULL,
		0x7CCDBF0608020816ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D405FB345AAB16EULL,
		0x03E72360E902F240ULL,
		0x280B696AFC53715FULL,
		0x95E75F5D232ECCECULL,
		0x7306420B0060FE8DULL,
		0xD09CA756C8691871ULL,
		0x6AF3AE5C56DA33DBULL,
		0x02C5CCCC623F56C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD85A347D400A4A8ULL,
		0xDBCE9A546365A3C5ULL,
		0x3BA226D33037D105ULL,
		0x986B6F711DF4432BULL,
		0xCBF160C12136D499ULL,
		0x33B33910F2C812DAULL,
		0x66DB29A1055256FEULL,
		0x46D3913DFBF1778CULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB38062B5F3D6532ULL,
		0x0545135B9E0F725FULL,
		0xE114F7B4B9B4F201ULL,
		0xEB57DE330C864EEAULL,
		0x329081E1738643B4ULL,
		0xCB664BF98284CD61ULL,
		0xE9C6C85231063EBBULL,
		0x92D9DFD8E3751716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB38062B5F3D6532ULL,
		0x0545135B9E0F725FULL,
		0xE114F7B4B9B4F201ULL,
		0xEB57DE330C864EEAULL,
		0x329081E1738643B4ULL,
		0xCB664BF98284CD61ULL,
		0xE9C6C85231063EBBULL,
		0x92D9DFD8E3751716ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CFB907350641652ULL,
		0xEFBAAA4AF156C536ULL,
		0xFDC3D1A1BE322EB6ULL,
		0x2D77421E0CD29B33ULL,
		0xCCB49F0622E44697ULL,
		0x13F5F389772D58D1ULL,
		0x4303F50979DC0BFEULL,
		0x44C932A4A771B4D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D91B38193D7DAD3ULL,
		0xA93C07C53451732EULL,
		0x9DA53D1AC482737EULL,
		0x8246C9F407357EFDULL,
		0xF1EE2470ACCC2767ULL,
		0xC66EE81F6FCC0800ULL,
		0x82B31866C79BA1ACULL,
		0xF4868B9CBBE93510ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0D3AC46E825E5A3ULL,
		0xEEF1B2683F2949F6ULL,
		0xCB2CD4730A630603ULL,
		0x74738B3CC790CB31ULL,
		0x25BB38DCA5A008B2ULL,
		0x95E5E0C048AF5BFDULL,
		0x894FB92D2652D151ULL,
		0x718E93AFB50E6206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8947441EC0CBC04CULL,
		0x03B476990426134CULL,
		0xB0B295B5C2F8886EULL,
		0x84AD5547BD63F8CCULL,
		0x4D048C092A67AC08ULL,
		0x89607F1394F6500CULL,
		0x2373E1DFDE0A7163ULL,
		0x3296CAB7948A6771ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EC0475EB12033ACULL,
		0x12FE50DD2ED57866ULL,
		0xC68AF90A735A6A8FULL,
		0x7E1D93988B52D8AEULL,
		0x8FCE704734B886EAULL,
		0xDCD9AED07C249C3FULL,
		0xA6F3F8CBD627BE01ULL,
		0x08241D00E0E11D09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF944A0E8464815ULL,
		0x7EDAA468AC7B7F72ULL,
		0x78956C92CAA7CF0FULL,
		0xBEA8BC1135DE3644ULL,
		0xB4DCACFFF76CC8B7ULL,
		0x41FCDAFAF272DB0BULL,
		0x7450CAF1B56D9C90ULL,
		0xAB308669FDF95434ULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6372ACE5E0020BCULL,
		0x287662874809E16FULL,
		0xAEDC97B03B80CE79ULL,
		0xDC377A130CED8A67ULL,
		0xF7060D91999FAD91ULL,
		0x6C99A1325EBB9110ULL,
		0xAC8249773503E286ULL,
		0x5228303AE9D7F291ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6372ACE5E0020BCULL,
		0x287662874809E16FULL,
		0xAEDC97B03B80CE79ULL,
		0xDC377A130CED8A67ULL,
		0xF7060D91999FAD91ULL,
		0x6C99A1325EBB9110ULL,
		0xAC8249773503E286ULL,
		0x5228303AE9D7F291ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97FC969C15CFC126ULL,
		0xC4FF9E7D45408895ULL,
		0xCAD0C9E0AF7D1AD8ULL,
		0xFC9023FAEF6DF6E5ULL,
		0x7075DB5B020A8F46ULL,
		0x998C8B74EAA0F2DFULL,
		0x6FC66E4321F8DDC7ULL,
		0x71234FD00CA32E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CC7CE9BEB37F47ULL,
		0x4BA1129EAA17C924ULL,
		0x266EC76BC5C5072FULL,
		0xCE3BC7D67A6FB7ACULL,
		0x217668DD5B074ED0ULL,
		0x39B85AB4686F5535ULL,
		0x89222E36DE405787ULL,
		0x73A62AE4F764FDA6ULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C912740337084C9ULL,
		0x1F44B2570C04BC2AULL,
		0x5EB79370903F162EULL,
		0xD914DA963603BB3BULL,
		0x4E9F2EDAE28A0F93ULL,
		0xC56228BC93194048ULL,
		0x39B2502C07829C3DULL,
		0x0DBA08E8DEA4F366ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A71F981B99E2A5ULL,
		0x6CE13D5B6797E5C5ULL,
		0x9DEC1251E2714C44ULL,
		0x1FFA0C33DA6DE8A6ULL,
		0x25E563DB59AD1ACBULL,
		0xE91F7875C817B595ULL,
		0x8E0759FD2F7A15D1ULL,
		0xF87127D12C51B7E4ULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCED8A5E86EB95F9ULL,
		0x36839FF764D3388BULL,
		0x492270196AEDED38ULL,
		0x50A83EDFF92CD6E5ULL,
		0x1D3973D4B06CB9E7ULL,
		0x459F8FCEF3A0443EULL,
		0x630F858C0E1F9E0EULL,
		0x42F0B8A59B7AB97CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DFF5E3C302DC57ULL,
		0xF87E3D489292D920ULL,
		0xB24DAB195DB4F64FULL,
		0x4260F3F41CF80193ULL,
		0x684CA02D3ECCCB02ULL,
		0x60A16C94253732B8ULL,
		0x2928896D56E9EFEBULL,
		0xF12F67DBEFE76FABULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB95663919637045DULL,
		0x16108E2BCAE25DFEULL,
		0x979ACC86E8CAA6BDULL,
		0xE53D409657B941A5ULL,
		0x429BC407A2AA355EULL,
		0x4D9905CB1A8134A8ULL,
		0x5ED763BC67EC4A44ULL,
		0x65051E5228E37EA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95663919637045DULL,
		0x16108E2BCAE25DFEULL,
		0x979ACC86E8CAA6BDULL,
		0xE53D409657B941A5ULL,
		0x429BC407A2AA355EULL,
		0x4D9905CB1A8134A8ULL,
		0x5ED763BC67EC4A44ULL,
		0x65051E5228E37EA8ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F9D8A47B74BD17BULL,
		0xAFBAF8AED7C2F26CULL,
		0x77738A6E0519E430ULL,
		0xBD58270F93515457ULL,
		0x4A1FBD4007BCCE7BULL,
		0x97A1D7709ED02E4FULL,
		0xA8206ABEF00899B7ULL,
		0xB02CBF95753BB7D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35E8D6A9823BFA5ULL,
		0xAF1D891460972DBCULL,
		0x0CB12982CF75C5A4ULL,
		0x7CC31F97F2048D8BULL,
		0x6AFC7B9772144561ULL,
		0x312C1B11984B3E59ULL,
		0xD7C0845D3706E26CULL,
		0x110EA48C9310F8EEULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D30E4F751C195F6ULL,
		0xDFFA3931AC8E61F1ULL,
		0x903A1C22391CC858ULL,
		0x12F1E5795DCE30B4ULL,
		0x9CB65A0467AF58FBULL,
		0xA6BE033EEAF73DECULL,
		0x45A39C23C08ED0FEULL,
		0x40D88303B68A9C0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87B7EECE7A93CC2ULL,
		0xF34BFEBF951045FBULL,
		0x2BEAC5FFDD6D2EDFULL,
		0x840C899EDD4A654EULL,
		0x01BAE9DAD5439723ULL,
		0x6F59D59D0D3C8FC7ULL,
		0x8E2A7899218401A9ULL,
		0xDC4D580DD08D6403ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01685B7E930E7FCAULL,
		0xA0AA2D3BABF8F62CULL,
		0xA2574034EFA0EF07ULL,
		0x34F40E24A7D93B91ULL,
		0xFDDFD23FE5307995ULL,
		0x50A1E951FE2046E8ULL,
		0x73237631B13FFBCFULL,
		0x72C81B246E7E9524ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x067A8B656F1BC274ULL,
		0x3CD022C566CFB888ULL,
		0x10C39C5DF7C39558ULL,
		0x9F71C325CF371F38ULL,
		0x31A2BF8745D3C39EULL,
		0x0C15E145A790E1FDULL,
		0x5088D4C15E4CCED3ULL,
		0x0C2B3401E4348F64ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCAC6522EE4703EAULL,
		0x48BE8C9A03EB35A5ULL,
		0xDCC2C941412DF4EEULL,
		0x5D199294F5A336B4ULL,
		0x34C8F65529275F5DULL,
		0xDD22D6B798117FE6ULL,
		0x59AD2CEF6A98949DULL,
		0xE32828363466CB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCAC6522EE4703EAULL,
		0x48BE8C9A03EB35A5ULL,
		0xDCC2C941412DF4EEULL,
		0x5D199294F5A336B4ULL,
		0x34C8F65529275F5DULL,
		0xDD22D6B798117FE6ULL,
		0x59AD2CEF6A98949DULL,
		0xE32828363466CB54ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD8F390B3AB00EFCULL,
		0x64C5892130C1AFE8ULL,
		0xB55847F4E199B1E1ULL,
		0xD81353BCE2EA5FEFULL,
		0xEE3175305136CFEEULL,
		0x29EA9348A6A1BE16ULL,
		0x2F2BFB983E2B9052ULL,
		0x695936804146FE24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B0263214BE5BAAULL,
		0xE778EB77482DF4D9ULL,
		0x90F0632B26386079ULL,
		0xA7D3D14F545D2864ULL,
		0xF996B1716CFF4839ULL,
		0x431AD1E30E9D82DDULL,
		0xFBF050420CA0B3A0ULL,
		0x04F5C2296F8E4F71ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E790AAF76A791D1ULL,
		0x7007BCECD5018957ULL,
		0xF14623C1A46E068CULL,
		0xA76371F00A8CBE7CULL,
		0x55EF34E3B6C06C72ULL,
		0x0D6DF74169463BE2ULL,
		0xDAAE6001DA9757D6ULL,
		0x4800B6483150FDA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6D97B31F44938FAULL,
		0xD71F1B8A6462E804ULL,
		0x97AA9EDE9CAE5A4FULL,
		0x42D2B7EAFE5BB454ULL,
		0x21C8B6632FFCB16DULL,
		0xDDB818D9DB96C6B5ULL,
		0x11B9192DE5CF3363ULL,
		0x1A42999BBD4512C3ULL
	}};
	t = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EAF80FAB3F75D52ULL,
		0xF80E17709DA71591ULL,
		0x70D92614F59A408CULL,
		0x09709D32A9E4B7F8ULL,
		0x8A9BA378B805D71CULL,
		0x8501FE98AEA52201ULL,
		0x34CBDE049A172943ULL,
		0xD95E5258BB567494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA202C3A3D97652ULL,
		0x4AFCF433815B8A91ULL,
		0x3651329B887C5E72ULL,
		0x59B8824802B51768ULL,
		0x23C0F1A89CC18922ULL,
		0x7DB1B17653D77523ULL,
		0x6EB5E98DE1F825A9ULL,
		0x73D82EB59AFEBAF9ULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51F83F4E52EFC07DULL,
		0x27D23568FB1D140AULL,
		0x8B0B08128A3F677BULL,
		0x12B5E6A57D750E7EULL,
		0xF2B4CAAF749A9A64ULL,
		0x3DA6CE13D7A498F4ULL,
		0x671674022D0DE7D1ULL,
		0x562FB40F3F3A7EC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51F83F4E52EFC07DULL,
		0x27D23568FB1D140AULL,
		0x8B0B08128A3F677BULL,
		0x12B5E6A57D750E7EULL,
		0xF2B4CAAF749A9A64ULL,
		0x3DA6CE13D7A498F4ULL,
		0x671674022D0DE7D1ULL,
		0x562FB40F3F3A7EC3ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01529DB93165E6DEULL,
		0x83ADC3CC98D9E648ULL,
		0x803ECDBF38C413F3ULL,
		0xEA47D986CD056672ULL,
		0xBC0F0C256A995B55ULL,
		0xD8F48792A588F8FEULL,
		0xC08FA68CCE09E1DAULL,
		0xAC95230D87D1EFCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C61E1D8F240CD9ULL,
		0x7CE80E38F9F059EDULL,
		0x73A6756B7F38BA2BULL,
		0x291414F6DCCAA124ULL,
		0xA76CB054C71D9CFDULL,
		0x0B902CF26FB5D745ULL,
		0x1A2747C3A8E7F6B3ULL,
		0x9295A46CA5DEB719ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA86ACD398B500FE6ULL,
		0xDD96BD6E75D6ADD8ULL,
		0xBAB248AD1667D8F6ULL,
		0xC8F6BAF8A046DAB5ULL,
		0xB77324534D4D7751ULL,
		0x52075E2F228104BAULL,
		0x0379AC7CC22162E6ULL,
		0x9D4BA1D0F5F23D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75DA22848AF176F4ULL,
		0xE767A2C7A3082F91ULL,
		0xDC2E08AAE3EF5BB4ULL,
		0xEEECE9193EB0964FULL,
		0x01CE543AA6AAAE22ULL,
		0x7F2FE75720940C6DULL,
		0x33CBA705844B708DULL,
		0xBBC3022D3EC7E3C6ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACA905CD3AB6D694ULL,
		0xF62FF3B42D0763D9ULL,
		0x2F985EF92C3C9D37ULL,
		0x2427FB5D50D605F5ULL,
		0x941A5A588438EA9BULL,
		0x9E0F4CA1E85F714DULL,
		0xA27097D58202B994ULL,
		0xD670746245052ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAC659AA15455A8EULL,
		0x4F3F2973F5097523ULL,
		0x7FC0C1CAA2178AD9ULL,
		0x83AEF5B70AEDEC3BULL,
		0xBDAE4B56D00C0F48ULL,
		0xBF40B42B854F69C2ULL,
		0x03D6609CF0FD217CULL,
		0x45333B49FEB88325ULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x279836ABBEEF6D0FULL,
		0x2E631900528ACCEFULL,
		0xE728679219C7DF47ULL,
		0xF4117A64E39EEB66ULL,
		0x5B97CD9B3DD836B4ULL,
		0x0AAECE60B783A6A8ULL,
		0x2F4704AE798F33D3ULL,
		0x0DB84575C903072EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279836ABBEEF6D0FULL,
		0x2E631900528ACCEFULL,
		0xE728679219C7DF47ULL,
		0xF4117A64E39EEB66ULL,
		0x5B97CD9B3DD836B4ULL,
		0x0AAECE60B783A6A8ULL,
		0x2F4704AE798F33D3ULL,
		0x0DB84575C903072EULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFF0D8F368AC6EEEULL,
		0x4F33AB1BAB119F95ULL,
		0x521A8E404EFDAB77ULL,
		0xEE07073C69186210ULL,
		0x2A91360BA2FCCEA3ULL,
		0x98E5BF5ECE48B331ULL,
		0x205F099802448DECULL,
		0x0FCFE5D5A9A3886CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD9709FE521BD5BULL,
		0x8803742CEEF0FB57ULL,
		0xFC2A737537DCC565ULL,
		0x079DCDA7431928D2ULL,
		0xF2EB66138314BAE1ULL,
		0xE34EFF6302A3DC23ULL,
		0x7F9AB9545888380CULL,
		0x7EC025561AE41FE8ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E58C32FD5D3AAD0ULL,
		0xAF02E74ECC858A10ULL,
		0x7393A0D654E74BADULL,
		0x95B25AC7A849A057ULL,
		0x8C13E85D47E6E136ULL,
		0x1FB8C5C359150207ULL,
		0x82B3E9A44C5FD3C1ULL,
		0xBFB456D94BB6AABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7DF5BD6A8C2E2F1ULL,
		0x59F847B6A56EAAACULL,
		0x820CEBF9FD6D5664ULL,
		0x293342C3B4852862ULL,
		0xDDCA2CAC801B5BD3ULL,
		0x82482B446218EC9AULL,
		0x9FBBB8E0DE5C5BB4ULL,
		0x64DDE9ABDEB9F670ULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDC5D54811A42006ULL,
		0xD6FFD27514F5CA58ULL,
		0xFDD187A78DA025D3ULL,
		0xAED1C2C88D39E0CFULL,
		0xCA923CF12CE51698ULL,
		0xDE01B2242FD15190ULL,
		0xD612E7D7911C33F7ULL,
		0x7C057D3BCB435A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86C70737703172A2ULL,
		0xCCEDEB4E59E9013DULL,
		0xF8321B90750B2F43ULL,
		0xE1DD4308D5D3D6BAULL,
		0x0376124413F3219AULL,
		0x30B372044610AA71ULL,
		0x86CE01AFF69E8868ULL,
		0xE908804E8B54A800ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A7AC1077801A9DEULL,
		0xE1C3EE23FC00B009ULL,
		0x6D39D7C0119936A0ULL,
		0x41A6836E5AD73C58ULL,
		0xB0F5E3D09C7A29F6ULL,
		0xDC6269F709A52F91ULL,
		0x8E330C4F6B6BD50CULL,
		0xFE4653AE683A2C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A7AC1077801A9DEULL,
		0xE1C3EE23FC00B009ULL,
		0x6D39D7C0119936A0ULL,
		0x41A6836E5AD73C58ULL,
		0xB0F5E3D09C7A29F6ULL,
		0xDC6269F709A52F91ULL,
		0x8E330C4F6B6BD50CULL,
		0xFE4653AE683A2C9DULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B45012FD025232EULL,
		0x4768670EFF0822B0ULL,
		0x4C81CF9F9F444EC3ULL,
		0x2B625FFF69377E6AULL,
		0x71A200DB77A96BABULL,
		0x2C287AC3A5D16A15ULL,
		0x115E55B2C1B2F715ULL,
		0x3639EBE3DBD29355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8221D6E93817DEULL,
		0xB3E11CA97DB8A2AFULL,
		0x27C5D93F040CE9DFULL,
		0x84A9E0F4F32C1035ULL,
		0x46CACEDFDEFEEBE0ULL,
		0x677350B31F7975C7ULL,
		0xC39F4708B8129024ULL,
		0x25784F694A018E5FULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F21D4E61529B24CULL,
		0x5AA240FD1FE380D4ULL,
		0x3B81716FE280911BULL,
		0xD4D80D5E53718E45ULL,
		0xBDD64C34999F3BE0ULL,
		0x39C93E69C3746F10ULL,
		0x87FE5D94BE1925AFULL,
		0x118F77960814B481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4161EDD44AADCD8ULL,
		0xA7FC1868BF5B478AULL,
		0x04D41483E6449AABULL,
		0x9634B02F4ADBF579ULL,
		0x365AEAFD44A78497ULL,
		0xD81656834C7CD41EULL,
		0xD1B78EE4E5DAE22CULL,
		0x2434B28CFA91005AULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C7A84577486D6C2ULL,
		0xBE2FF56504D15F5AULL,
		0xF897AD4AD02D5BA4ULL,
		0x696159907D504084ULL,
		0xD80C781308AE5200ULL,
		0x17E6449861378937ULL,
		0xD5824FA8C9D8AED9ULL,
		0x3682D8B5BFE7CD26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A9B63EF417F5BCULL,
		0xA538165790CFCD76ULL,
		0xF95199482D37A430ULL,
		0xB3D433CC5DD96EEFULL,
		0x55D4A1901B716282ULL,
		0x72025C779478B87FULL,
		0x830D77A52A14AFECULL,
		0xFBB722FC60C8F63BULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5CF89B996165393ULL,
		0x95D80E5E64AAC6ACULL,
		0xC7BF9CCC24BCF19FULL,
		0x900DEE5B3426BE00ULL,
		0xE41F592E11711B49ULL,
		0x851DA4F97FDEDBB2ULL,
		0xE0A015EF9C09A539ULL,
		0x9A855850B3921252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5CF89B996165393ULL,
		0x95D80E5E64AAC6ACULL,
		0xC7BF9CCC24BCF19FULL,
		0x900DEE5B3426BE00ULL,
		0xE41F592E11711B49ULL,
		0x851DA4F97FDEDBB2ULL,
		0xE0A015EF9C09A539ULL,
		0x9A855850B3921252ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5203D35DBE2F43EEULL,
		0xB44575C9B802D14FULL,
		0x1FEFA6CF927348F2ULL,
		0x01CE0B1569158A11ULL,
		0x8621C261506A05F5ULL,
		0x8D69384A6368385CULL,
		0xFE7098027065139FULL,
		0xC4EE50AE01FE83F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD11F9DFF82EA07E6ULL,
		0x1ABE5DE8DAAA5939ULL,
		0x92FF30225FDEB589ULL,
		0xBB26A37EDE0E12A0ULL,
		0x7A6AEC31F5D5A0DBULL,
		0xE0C126CBD85DBAD9ULL,
		0x78130E06D7E99841ULL,
		0x8C80859752193B8AULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x194CFA121F620C2FULL,
		0x21B61489D4D11DDEULL,
		0xC35A06F4750434F3ULL,
		0x77F5F6BFF7695E57ULL,
		0x58B5B3E8928385A9ULL,
		0x451578006D88F0B2ULL,
		0x148FFF57BE41688CULL,
		0xA9197032997851F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F66F8A275BDABAEULL,
		0xCEB82EB7B253FD2FULL,
		0x5454B2A18956B8C3ULL,
		0x08AF0406A4839499ULL,
		0xA5467B66A567AA61ULL,
		0xD47B4EF17FA3E66BULL,
		0xF6E9CDD2C4C65FDDULL,
		0xA0DD1DA1A9A2320BULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6CF073BCF3D4A6EULL,
		0xA53390F7524EE427ULL,
		0xAACE10C0B8C52ABCULL,
		0x8FF9C56C0B82B71EULL,
		0x21189D6B4A904343ULL,
		0x392DD3731DEE43E2ULL,
		0xA50E712A2B061CD5ULL,
		0xFF57BE614481F8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x081E5E0706F2C360ULL,
		0xD664CE11F1AB0826ULL,
		0x7E79656B24622DA4ULL,
		0xAB7EE4AB803146A0ULL,
		0xA8247F5C6F05D0E0ULL,
		0x3454B0488AFD3419ULL,
		0x539E5003C04C3B95ULL,
		0xF1098620EC9C7793ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4A639644511D395ULL,
		0x902859D0AFE0D4D4ULL,
		0x2848F139A7DBD618ULL,
		0x36D2153008DB39F2ULL,
		0xE9BE658790F27EACULL,
		0x3F75686E25BAC8A9ULL,
		0x01EAED5043A3232CULL,
		0x8C696671E83F05C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4A639644511D395ULL,
		0x902859D0AFE0D4D4ULL,
		0x2848F139A7DBD618ULL,
		0x36D2153008DB39F2ULL,
		0xE9BE658790F27EACULL,
		0x3F75686E25BAC8A9ULL,
		0x01EAED5043A3232CULL,
		0x8C696671E83F05C2ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51CC9A0CC917886CULL,
		0x9FDD2C837B4BECB8ULL,
		0x7F04AFDD051C8822ULL,
		0x4BB9861F539DB22FULL,
		0xFA5B38325F72BF90ULL,
		0x3E48BF18FF63DB2BULL,
		0x89C0A63DE2D69462ULL,
		0xF27339C02219495EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE346B78D4B62A8ULL,
		0xBA7AB1677B0DA400ULL,
		0xD3CDC249429499FCULL,
		0x414CE308B4D7B8B6ULL,
		0x690B74DD869FC0DDULL,
		0xE6BFB521A469977CULL,
		0x58162176237A3929ULL,
		0x32CE2D1D7D3E3DEDULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F8AD1DB4E3DDCCCULL,
		0x36D574AD4C200EEFULL,
		0xEAB104EA849747BFULL,
		0xF712FEEB56341C05ULL,
		0x452F22B38DDA1E18ULL,
		0xEEC7EA92C24DFC09ULL,
		0x6D74A5277D8AAF13ULL,
		0xD6458D6012AABFC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD91FA4AD27F61B94ULL,
		0xEC38B5C2E8538778ULL,
		0x263FEE4A24872B64ULL,
		0x881A14B599EB0F54ULL,
		0xBDB9BA23BF56E8EFULL,
		0x6A81889D59529281ULL,
		0x7DC64A3991DBE1C1ULL,
		0x1644F3E3D4646629ULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23AE2241911BCC1CULL,
		0xCC726CF744C05F67ULL,
		0x741F58E0D6454DD2ULL,
		0xAE16E6FAB6B7557CULL,
		0x7A025ED992CCF6E2ULL,
		0xAA5409682C36C6FBULL,
		0x8E7EC297013A100CULL,
		0x02E6CF17B25C523CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFD1639F47AF2E5ULL,
		0x5194AD728F714BB2ULL,
		0x0AA69B2D7C115C2CULL,
		0x4F1D625A2796F137ULL,
		0x9239D1BCBE1D1F08ULL,
		0x1D559E6096223E90ULL,
		0x29952A87C72A2D93ULL,
		0xACBF72F7820F625CULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C70B4605652A5BCULL,
		0x8E65AFED06C62D3EULL,
		0xF1F340FFFF8E8C83ULL,
		0xC4E66F7E8470EE10ULL,
		0xD158C9F2A131E4C2ULL,
		0x0DED63F9818A698BULL,
		0x254C9B09CCEC0307ULL,
		0x00EA2B404F1E5461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C70B4605652A5BCULL,
		0x8E65AFED06C62D3EULL,
		0xF1F340FFFF8E8C83ULL,
		0xC4E66F7E8470EE10ULL,
		0xD158C9F2A131E4C2ULL,
		0x0DED63F9818A698BULL,
		0x254C9B09CCEC0307ULL,
		0x00EA2B404F1E5461ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E42865D297B0E6AULL,
		0x94F72578382B35F5ULL,
		0x96C696990875AA1DULL,
		0xC37B56385DCDDD47ULL,
		0xC3B99D37B1AF174EULL,
		0x6BA5A06C03ED2C7BULL,
		0xE48C8444697E4FBFULL,
		0x86A73CACD0578D74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x118DF797285AEB33ULL,
		0xE9F2CE8342282F3BULL,
		0xFBF1BF154420307AULL,
		0xDE37CAD3E64871A9ULL,
		0x4912F839AB064872ULL,
		0xD92605C6A247A26BULL,
		0xD782E4B217377C62ULL,
		0x30310D8DD80EAE2DULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EE5B1FA13654281ULL,
		0x1C03BEC62681B439ULL,
		0x4ACB237E2CEDBF6AULL,
		0xE29FCAA70505F92BULL,
		0x93C88328E6A119BFULL,
		0xC5D758D47BE12124ULL,
		0xF8F56416DB3A2BD8ULL,
		0x61FB4E362663578EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA45EB95CAE14B8ULL,
		0xD4C8B0F2D3A77F82ULL,
		0x767851321608C384ULL,
		0x7DF6CE02D1C223D2ULL,
		0x5DC880F37C34DA9EULL,
		0x353C1AAD2634EFA1ULL,
		0xD304DC2031B9A396ULL,
		0xB399DD4F2209E8A0ULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB1AE2026A390327ULL,
		0x115C31B74B2918F6ULL,
		0x15EAFC1F678CA382ULL,
		0x0541DDFAC6C8E229ULL,
		0xBD369AB185AB06E1ULL,
		0x75AA3BC7CFACA44EULL,
		0xFDA7CCBD0F3EBBEDULL,
		0xD0D878786B99B338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA22C4E60BB0295ULL,
		0x795271C008F0A9BAULL,
		0x5ED6C8E1B5E8806DULL,
		0x2443DD172A6BE7B6ULL,
		0xA3CE53A3C12CB6FAULL,
		0xB5F80118847D9C99ULL,
		0x0048EB5EFD651975ULL,
		0xCB718D421CF54F99ULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD3211355B5980DCULL,
		0x91B05CBBBEBA3610ULL,
		0x66415FB1DF3D0663ULL,
		0x2148224C2C41D2BEULL,
		0xED2C3310A0719C78ULL,
		0x841D2ECA0FDA9097ULL,
		0xBC194162A5525385ULL,
		0x6D091935563EB6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD3211355B5980DCULL,
		0x91B05CBBBEBA3610ULL,
		0x66415FB1DF3D0663ULL,
		0x2148224C2C41D2BEULL,
		0xED2C3310A0719C78ULL,
		0x841D2ECA0FDA9097ULL,
		0xBC194162A5525385ULL,
		0x6D091935563EB6DBULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F8984BCFCC0FFF7ULL,
		0x7B024403A35EAB6FULL,
		0x983477A9FF58F210ULL,
		0x7FA9E82BD5B66F1CULL,
		0x6B20288C8576BA0FULL,
		0x5342E2607131D0BBULL,
		0xCDB652561EA19EC0ULL,
		0x4C67D0F32A4B2A0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD61D0021DB0759ULL,
		0x23B54587C107CF77ULL,
		0x9DDBBB31D5A7A053ULL,
		0x6F328567348C21B3ULL,
		0x7E21AC079E98518FULL,
		0x80BC32FE6878B1B2ULL,
		0x383FE2B272C5F831ULL,
		0x5820A79FB1DB1A98ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57818FA207A9CDF2ULL,
		0xFA7DDAD34398BE70ULL,
		0x49457B2E6349DE0CULL,
		0x4F68567A668F3686ULL,
		0x5C8610FECE9ADB67ULL,
		0x0F3F1A0638D26669ULL,
		0x90B0A9FCAFA330FFULL,
		0xF126D2B5063FFF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C9A3E362125ED54ULL,
		0x63C6D8979F596B1DULL,
		0xAFF5E213B05BD179ULL,
		0xCE41B62826CB191BULL,
		0x7D6D53BB6070B3F2ULL,
		0xBD30AD526C931422ULL,
		0xA57592E81F437A42ULL,
		0xB551AFDA7F0B3B6AULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92A29C14230F9AE2ULL,
		0xFBD826A0BC7172F7ULL,
		0x206C188A5A93DBFAULL,
		0xC79F4928413463ADULL,
		0xCBBF4EC04C60D443ULL,
		0x764BCC003C821232ULL,
		0xAC444C60C88D51FEULL,
		0xBB789E8ECC9A794FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65490180D44C728AULL,
		0x7A67CCC26D89F2ABULL,
		0x7F1521BA1F0F251EULL,
		0xF709CF277B905945ULL,
		0x9D85DF0E0756960DULL,
		0x13A9456F9A83FF2FULL,
		0x07531DABBD3477FAULL,
		0x3F2644D3C31B4B14ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x780A2013095B514EULL,
		0xC9AEA34733361FA2ULL,
		0x57ED64D08F0DE6E1ULL,
		0x916B5B01DC8A808EULL,
		0x9AA0B7636E594DAFULL,
		0x48ECBA3DE91BAFBCULL,
		0x9FB162CF84936FA2ULL,
		0xDE9D3CC0A98406D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780A2013095B514EULL,
		0xC9AEA34733361FA2ULL,
		0x57ED64D08F0DE6E1ULL,
		0x916B5B01DC8A808EULL,
		0x9AA0B7636E594DAFULL,
		0x48ECBA3DE91BAFBCULL,
		0x9FB162CF84936FA2ULL,
		0xDE9D3CC0A98406D1ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE94F7994D806A168ULL,
		0xD06C332DB9DD839EULL,
		0xC868A47C27466A75ULL,
		0xB6E2174F4985EB81ULL,
		0x81B5454BF99ACC15ULL,
		0x0D9DA129857ADB60ULL,
		0x78312F3690F661D0ULL,
		0xFDCFB866D5265233ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4AC28E2C7811095ULL,
		0x6F37D50AEAB8A7C5ULL,
		0x3E118DE3D08066BEULL,
		0x54B3C960A8AEABDFULL,
		0x4B4B7BD68D132E08ULL,
		0xA322400F3A4E6321ULL,
		0x83B869C9676A5DE7ULL,
		0x7C2AAA8B5C4EE44BULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD3B6E424F24418DULL,
		0x5FE8C607359D748CULL,
		0xA7025492EA0D8D1CULL,
		0x0D9DCB10D589F79AULL,
		0x47DEC1ACEF27C9D9ULL,
		0x59B808C89E343FADULL,
		0x60932D7EB4F8908FULL,
		0x21305816A725C7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A20601442AC33AULL,
		0x9F491637400C88BAULL,
		0x35E1285FF48763F9ULL,
		0x99E85EF130CAB242ULL,
		0xF01C451658593F03ULL,
		0xE78BF8C444389DF9ULL,
		0xB7C4A1914FAD65DFULL,
		0xF8672560608BEEC7ULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88AE3A244B1E8228ULL,
		0x4119397477FBD9ACULL,
		0xCE3E2324E4C3185CULL,
		0xF2A32E543368A17DULL,
		0x105C176ABA606309ULL,
		0xDE0A1D5575E1108EULL,
		0x7F72AACC64B60D3BULL,
		0xE3D0F7C5E44EC1CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30D985935B613CB3ULL,
		0xBBA68A18E2ED2726ULL,
		0x2FD01C53A0BBA720ULL,
		0x0BA26FE648DE16B0ULL,
		0xAD7EA564690AAD03ULL,
		0xDE931D3CDB7FB2ADULL,
		0x767FA28D4B9B5841ULL,
		0xF38C78B91BB1199CULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84A10FD68F22F45DULL,
		0x6E39BB16F1F4B2B2ULL,
		0x38A02C34541B5660ULL,
		0x2CE41A7D5B9907BFULL,
		0x4B490F817DDB2A85ULL,
		0x3C464A321A805183ULL,
		0x8A57A87CAA44AF51ULL,
		0xF8A2494F25E1BB6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A10FD68F22F45DULL,
		0x6E39BB16F1F4B2B2ULL,
		0x38A02C34541B5660ULL,
		0x2CE41A7D5B9907BFULL,
		0x4B490F817DDB2A85ULL,
		0x3C464A321A805183ULL,
		0x8A57A87CAA44AF51ULL,
		0xF8A2494F25E1BB6AULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFEFA355EF2E6FAAULL,
		0x043454E3ADBCC69BULL,
		0x3FD00E7AE2CCF8B6ULL,
		0xC26784592DBE3171ULL,
		0xFB6D3350953FE8ECULL,
		0xCB204014F16EEA46ULL,
		0x014A6BC0E647B6CFULL,
		0x49FD51535532521EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B2B323E6A32F51ULL,
		0x67D984B27946C7DFULL,
		0x254B60562960F990ULL,
		0x6E35836FF8465B56ULL,
		0x31011D01B6AE67E7ULL,
		0x26DA919F18C84668ULL,
		0x25C8A028DD024ED3ULL,
		0xB4959B97CA3CD5E2ULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF617E247E2AAB42ULL,
		0x99E409DAF01BD444ULL,
		0x2A2110B6D19DB201ULL,
		0x461B840D81814729ULL,
		0xABA83042750A0908ULL,
		0x43370CA9DB59AA2EULL,
		0xA1890181C9647B0BULL,
		0xBFBE6DEB4D583D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7830013F0393DCD1ULL,
		0x72900D72A9B8DF6AULL,
		0xE10223BFDA67DAFBULL,
		0x123E576161DF1DE5ULL,
		0x9B449235F237F46DULL,
		0x13509D06E03EBD3FULL,
		0x16C44DF01488E939ULL,
		0x65C815ABCD9FDF38ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A47EE65AD59CC60ULL,
		0x16F6507C158186F7ULL,
		0x894999DEBF27EF91ULL,
		0xDF35F017545116B0ULL,
		0xAB4D754F016B3D30ULL,
		0x89659ECD21EFB4E1ULL,
		0x05D85A7D36D8E345ULL,
		0x3B69B80C863B4D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37A2932CA9A1051ULL,
		0xFF1CE5F83FD83656ULL,
		0x858710BD80A1D8BEULL,
		0x813DF7A6771BEBA6ULL,
		0xAD9C718E3A316745ULL,
		0x31E9433203919471ULL,
		0xB05E59DB73D4647DULL,
		0xE80781AF2C33BEE2ULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15E456FFF137A2C1ULL,
		0x2D3417CA882E7DA4ULL,
		0x6BF1B1BA93037807ULL,
		0x6B9A0D5E52E70C46ULL,
		0xF95C8453078D29D6ULL,
		0xBABF6048C2CF943AULL,
		0x7CF1732B169A1FC4ULL,
		0x9E2BBFCA5B017CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E456FFF137A2C1ULL,
		0x2D3417CA882E7DA4ULL,
		0x6BF1B1BA93037807ULL,
		0x6B9A0D5E52E70C46ULL,
		0xF95C8453078D29D6ULL,
		0xBABF6048C2CF943AULL,
		0x7CF1732B169A1FC4ULL,
		0x9E2BBFCA5B017CE0ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B1DF977021D4B8EULL,
		0x815042FC8D918559ULL,
		0xB6A90B09C891A4F5ULL,
		0x9BB63D4F192ADADAULL,
		0xD4DE317CE5EF23EFULL,
		0xA0E84A586D1134F4ULL,
		0xC7CCC54BF6965FCEULL,
		0xE98410B1A82E4DFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C16CAE006DA754ULL,
		0xB612BD3093448C07ULL,
		0xDA24CAF46D265FCAULL,
		0x00A919C5E9BED694ULL,
		0xBE3D867B1D5D12C5ULL,
		0x58BF8E0BCF63CB02ULL,
		0xEFDE93F651C82EDEULL,
		0x44CE56734EAF12B5ULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4014853FB0C961FULL,
		0xA25BCD52D0605907ULL,
		0x03CD19B6F82884A7ULL,
		0xE503E27819F838D5ULL,
		0x6FDB343247446FD5ULL,
		0xFACF09703E412C7BULL,
		0x86509CB3BEB0933CULL,
		0x065A206428CB9215ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F6228377579510ULL,
		0x089671E6FD138740ULL,
		0x079F631BE32F4A5DULL,
		0x66F1CBDAD14A8BDCULL,
		0xB60A327EF3CAEA70ULL,
		0xA55F86B7C03AC4F7ULL,
		0xDD2B84AD7E6E746DULL,
		0x0F70724612BCF529ULL
	}};
	t = -1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A52A453D4F0614DULL,
		0xAD3E4E5A733961DFULL,
		0x08EA153076609D4DULL,
		0xE7CB917AEF2356D9ULL,
		0x01A5E20ADC0AEE2EULL,
		0x652F3F9E7A62984EULL,
		0x7C17267D58D5629EULL,
		0x8EEC8C7A8B6059F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB65ED8ADBE726755ULL,
		0x460FF80CDC42F2A8ULL,
		0xB0F8031F2F166F34ULL,
		0x9EEA84C6B00A17B4ULL,
		0x5D3DE97B210C1F12ULL,
		0x855BA9ED9D441E06ULL,
		0x534638FF56992BF8ULL,
		0x22520809FC2F66EAULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC35F62F33EE8738EULL,
		0xBEBBED571A17F4CBULL,
		0xD59F04F359EE55A9ULL,
		0x5F2C10D1128D1314ULL,
		0x0915040B8E061D60ULL,
		0xBDB137D0FF7BAE77ULL,
		0x3EC63E52253C3F7DULL,
		0xE58659200312772FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC35F62F33EE8738EULL,
		0xBEBBED571A17F4CBULL,
		0xD59F04F359EE55A9ULL,
		0x5F2C10D1128D1314ULL,
		0x0915040B8E061D60ULL,
		0xBDB137D0FF7BAE77ULL,
		0x3EC63E52253C3F7DULL,
		0xE58659200312772FULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C996A9A3694F54CULL,
		0x7876E6ECAD2E2F0FULL,
		0xFBEE0B2D870639C0ULL,
		0xC9E289877D9F4EA2ULL,
		0x23E343051A0754C1ULL,
		0x29F53E695469D896ULL,
		0x4E2A1FACBC9509A4ULL,
		0x345526226B0FC627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC89563EDE1E26CCULL,
		0x86D913EB8264CFFEULL,
		0x44DFD5CFFCECC9EEULL,
		0x59F59A9D1A67EE4FULL,
		0x068F3B9689BA1EFCULL,
		0x02FA561CCE6F9CE5ULL,
		0xF6D0120F18E3E240ULL,
		0x8B3B8BDC94AAD295ULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F8616CB38380EA7ULL,
		0x702499BCA5BC1756ULL,
		0x5D98F7A02FC7211AULL,
		0x6661FFC902E04006ULL,
		0xD9724FEEF93A5B0BULL,
		0xEBA1AC7E844C40F1ULL,
		0xE89B7E2DBE4AC977ULL,
		0x4B71EDF23FB103ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3F3767124BD3B2ULL,
		0x3B6E495C90F7F01BULL,
		0x1577C4B964BBCC79ULL,
		0xFD9414F6D769FC79ULL,
		0xE7CCCD01971EE6ACULL,
		0xCDD3DB652641C46FULL,
		0x420A25780C55005FULL,
		0x6DF0372057DE6D18ULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B8F5A076AF40B02ULL,
		0xC2F077B291961848ULL,
		0x4961ECC4119B24EAULL,
		0xDE0CFB40977F2A4BULL,
		0x26DB9C8111E5F993ULL,
		0x49319C810BB1B2FAULL,
		0x4C7D5BA39396C880ULL,
		0x10223A94A31D8819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3967FEF8115E895AULL,
		0x819CDF2FD11390ADULL,
		0xF2C9AA7FAD286DB9ULL,
		0x2424E7FB51B474C5ULL,
		0xFE300CF4ECE44A2DULL,
		0xEDA76315B92D60F0ULL,
		0xFB2EFF8C4A679F36ULL,
		0xD4C1319E2F62DB85ULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F156DE8C6F88260ULL,
		0x3A156BE02568CB62ULL,
		0x2719B0681165FCDCULL,
		0x93737976EDD60061ULL,
		0x22E6CAB0E9B5CE32ULL,
		0x40B84441F7847356ULL,
		0x2975B3C29ABD064FULL,
		0x0B61036A84442040ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F156DE8C6F88260ULL,
		0x3A156BE02568CB62ULL,
		0x2719B0681165FCDCULL,
		0x93737976EDD60061ULL,
		0x22E6CAB0E9B5CE32ULL,
		0x40B84441F7847356ULL,
		0x2975B3C29ABD064FULL,
		0x0B61036A84442040ULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A4C6CDF2612E91FULL,
		0xB73B030FD4D15908ULL,
		0x16105AD3C9806999ULL,
		0x52F3680CFB9F49FFULL,
		0x3B40D9E4439C91A5ULL,
		0x2326A48DFE79F98EULL,
		0xA55DA84B02CC0120ULL,
		0x57CD9E266A9A306EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD058DEFA9C6D92D4ULL,
		0xDBBE68C547CA066FULL,
		0xE6C77F674C843069ULL,
		0x7D67DCA61F0A3ED1ULL,
		0x753376E59731111FULL,
		0x41C42EB8E253E31FULL,
		0xB16CFE72014C2D47ULL,
		0xAA4603E05843F38EULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x076246FBA1EAC515ULL,
		0x90A922650FF5DE9DULL,
		0xD96B1E16CC7CC9E6ULL,
		0x1E947E4EEF0AF00BULL,
		0xC63E4FD414E95909ULL,
		0xD0DAE21A7A36F28AULL,
		0x26C8E079BD105DBDULL,
		0xB47D6DADFED6F9A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D228657EFD173D2ULL,
		0x575B3B79AC4F9D79ULL,
		0x276758D81FD32B8FULL,
		0xE2424B0C5EA486C8ULL,
		0x311AA8B08AEC9A4DULL,
		0xE577CAA293030BF5ULL,
		0x23832CC3EE138A48ULL,
		0x321C801CB0543DCFULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56663D95D403748EULL,
		0xDB6230A1538DC993ULL,
		0x3C47C8DC93B42387ULL,
		0x47D30037CADC8754ULL,
		0x071EE7CD141E0B82ULL,
		0xF4920AE3DDFAD13EULL,
		0x9D9ACA0ED8BFC37AULL,
		0x517AA1BE4301A970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4A3290974517CA2ULL,
		0x7A6F12637DB0C667ULL,
		0x76C235D0D5313985ULL,
		0xB4C28DAD06844F06ULL,
		0x8EC27D2628284EB3ULL,
		0xA3EA8583ADD9E6E6ULL,
		0x635497B5C9149886ULL,
		0x789A10D1099BC26EULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96E377E8BBE307B4ULL,
		0x361C441E95B19509ULL,
		0x86A44A3E1C43E1F6ULL,
		0xAA5A4CF31A473477ULL,
		0x102D9C423B5C313CULL,
		0xC5EFA316D95A7A11ULL,
		0x9428E54915DBEB5EULL,
		0xA1A9F4A1CDA8C302ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96E377E8BBE307B4ULL,
		0x361C441E95B19509ULL,
		0x86A44A3E1C43E1F6ULL,
		0xAA5A4CF31A473477ULL,
		0x102D9C423B5C313CULL,
		0xC5EFA316D95A7A11ULL,
		0x9428E54915DBEB5EULL,
		0xA1A9F4A1CDA8C302ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF84F22BDAAE49B4ULL,
		0x2F8AD2CD4AE49841ULL,
		0x30E9DAB07068008AULL,
		0x7F5A37D23E59A04CULL,
		0x5BB6D943D7AE20AFULL,
		0xC902585B4C94059EULL,
		0xB248B595ADED1F9AULL,
		0xC2C9EE75E934B65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF89A035AC59794E8ULL,
		0xDD007E6FA7073618ULL,
		0x4FA8CFF943FF9E37ULL,
		0x4A943AFAE7CFA78FULL,
		0xA6EE314178748314ULL,
		0x606CC9E8863B2CCEULL,
		0x1977F0D9F241064FULL,
		0xFEFC59ED841FF5BBULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD841DBAA5841541EULL,
		0x19118C97FAEA061DULL,
		0xD85549005B2EB97CULL,
		0x3A3F0A80D67E4E14ULL,
		0x14B3844A4F69B58EULL,
		0xAF2660395938739EULL,
		0xFD6D6D7F231BC3C1ULL,
		0x2CD0B6E67403B778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE83B89E09F96705ULL,
		0xAA21BB7AE57F0A93ULL,
		0x65ECA2810898F212ULL,
		0xC32E14B09DE7B906ULL,
		0xFCAC71B102FAE28DULL,
		0x5F7A694120513304ULL,
		0x621ACA1A87B2D955ULL,
		0x0F1AF6D547FE9712ULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD33259F42495C47ULL,
		0xE4D7271058965CB3ULL,
		0xB40A9F6AF9BDA24AULL,
		0x9497BB6C2EB0C674ULL,
		0x017F79882AB3421BULL,
		0xD7C05A6447E0201EULL,
		0x844D3FAFA5AE5F02ULL,
		0xBD58C32F036205C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55ABE98BEC0C2352ULL,
		0xA06037C8AE39A080ULL,
		0x075D553CFEB4FA13ULL,
		0x78CA31E2A4080405ULL,
		0x9D678F66BC2C23A5ULL,
		0x0B96AF2D00F928BEULL,
		0x7AD88021BE45CEC7ULL,
		0xFDB931048C6EF8F9ULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A4B27A0047B61D5ULL,
		0xEA22CE05C7213C23ULL,
		0xA44DF348EEC1B01BULL,
		0x98567E053D1DBB0DULL,
		0xE5184E1BBC1BAFD5ULL,
		0xDBFD9003E3452209ULL,
		0xB21E802572EFF312ULL,
		0xEDB981463BB40DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4B27A0047B61D5ULL,
		0xEA22CE05C7213C23ULL,
		0xA44DF348EEC1B01BULL,
		0x98567E053D1DBB0DULL,
		0xE5184E1BBC1BAFD5ULL,
		0xDBFD9003E3452209ULL,
		0xB21E802572EFF312ULL,
		0xEDB981463BB40DFBULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADBC16FFC65314B3ULL,
		0xC25AD41D2089BEF1ULL,
		0x9617BB867E5CAD36ULL,
		0xF627261F3BE1FC46ULL,
		0x14AD2F06556C10BEULL,
		0x2D01FA33E1D4F083ULL,
		0x559626DDA4B4575BULL,
		0xAD0AE696AB5BDE6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFBECC158A551CA0ULL,
		0xCA7EA00A56E50A1AULL,
		0xE7189901C0E2E8F1ULL,
		0x2C963DFB859685CFULL,
		0x81899636A0895C77ULL,
		0x8408E9DD35C53C96ULL,
		0x7189307BAE2B9604ULL,
		0xFC754D8B6D31C8B1ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCB11D74BCC5684BULL,
		0x7FCAB0CD8DB607D4ULL,
		0x42962B9CE69794DFULL,
		0xA42DF211C20BB3C5ULL,
		0x996F9D20F4FC9980ULL,
		0xC23C6CC71DB2FB8FULL,
		0x2ED22E1B7AE93999ULL,
		0x1EF999B90E50267FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8C0258373425DFULL,
		0x757E88C51B2E1CC2ULL,
		0xF1A90DB3F283450EULL,
		0xA746E32D852E6F97ULL,
		0xE33A59ED2ED43C52ULL,
		0x2012270442F09E22ULL,
		0x16ACB6CD16F3C326ULL,
		0x7AB4B8D57C035C92ULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43D271655758E140ULL,
		0xC44AE272167B4BB6ULL,
		0x4ECD91548426CB7BULL,
		0xAA92AAA0AEE4CAF5ULL,
		0x795F3788650E1AE5ULL,
		0x55A1F19603C06809ULL,
		0x2EA093EA66DF60A0ULL,
		0x6BA88AC0907544C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED8EE9D677D6A98ULL,
		0x13E03899E214FA1BULL,
		0x708E3E98EAC13241ULL,
		0x481EA5E1520B9EC0ULL,
		0xFFF78C884FA95995ULL,
		0xFC4B41A0E5F919BEULL,
		0xF8F337EF018EE9CBULL,
		0xBADB2ED8CD1BA07EULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C56A0147DC01FAFULL,
		0x79DB64D39D49E0C1ULL,
		0xEC1C6E96FFA69904ULL,
		0xCD28C081E4291574ULL,
		0x28716FB87F17F133ULL,
		0xAF686A6FE427EDAEULL,
		0xB1984E9EDD0C79E5ULL,
		0xC00EA8BB0690F13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C56A0147DC01FAFULL,
		0x79DB64D39D49E0C1ULL,
		0xEC1C6E96FFA69904ULL,
		0xCD28C081E4291574ULL,
		0x28716FB87F17F133ULL,
		0xAF686A6FE427EDAEULL,
		0xB1984E9EDD0C79E5ULL,
		0xC00EA8BB0690F13FULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x757D7D419640609BULL,
		0x2B2A6A45CDF7E53CULL,
		0x33748B8E627CB65BULL,
		0xB6F46C435DB99DC3ULL,
		0x1B9E60C8B55CFBB8ULL,
		0x57215283AA5C3EC3ULL,
		0xDEAA9775877101B3ULL,
		0x0B8AA88B1C4EEA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88EB0E4405BE4A6BULL,
		0x5179F07A4F742DEDULL,
		0x23E12CA129E1A1EDULL,
		0xE121F67E9489C005ULL,
		0xDF30B5CF8F2DAB9AULL,
		0x00B49856E136025EULL,
		0x99582DDCF8609298ULL,
		0x309221BF3AAB1C4CULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC843BCB66E2E8B28ULL,
		0x46A414FEECA1A71AULL,
		0x667FB807C2CE7357ULL,
		0x1490D2C02549328DULL,
		0x0B31A92893B8E478ULL,
		0x1DFCD2FA183DE2FFULL,
		0x9D68DAB61D2BFEAEULL,
		0x41D270652914399CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05F8DEA7953AA618ULL,
		0x27A691DBECDD55CDULL,
		0x6226414FDA81540DULL,
		0x1C9D32462788373FULL,
		0xD3EC6F17EE7073CFULL,
		0xF2A957D8DBF09F06ULL,
		0xAD1B76D3FE7D8255ULL,
		0xB9CEFB016AE2B0D0ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97CBF0CC339C7124ULL,
		0xED6D0603CFFA5DDAULL,
		0x3A045E6DEE0CC6ECULL,
		0xF814E6E67289DDFDULL,
		0xA4B5372560A87AE0ULL,
		0xE1E117E9AD75AB49ULL,
		0x452206504E68ED0DULL,
		0x8FB05D0717BD660AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0749D9C24B5C9EC4ULL,
		0xB1C1A725C94BDF19ULL,
		0x3F100944DFF57ABFULL,
		0xE398B787F44EEFB6ULL,
		0x08FD04352AB5148EULL,
		0x2D6965B7E39F4E44ULL,
		0xD4B53F0C931096DAULL,
		0xE48CE59057A8B8D0ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x364DEA0D52602FB7ULL,
		0xCB4420A403A7AD05ULL,
		0x019BE667B5BCB5FEULL,
		0xD6715475CC48A1B8ULL,
		0x673EEFEA4A5E4AEEULL,
		0x27EBEEAF9BFE5A62ULL,
		0x4EC1F52519C06AFEULL,
		0x136B147898E2C3F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x364DEA0D52602FB7ULL,
		0xCB4420A403A7AD05ULL,
		0x019BE667B5BCB5FEULL,
		0xD6715475CC48A1B8ULL,
		0x673EEFEA4A5E4AEEULL,
		0x27EBEEAF9BFE5A62ULL,
		0x4EC1F52519C06AFEULL,
		0x136B147898E2C3F5ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74FF15F8A2D8F121ULL,
		0x6B31E6D5E80CE4FBULL,
		0xA8D51A2EE452CD30ULL,
		0xFDBCA8DC27BD8DE9ULL,
		0x96DB2CCEC946B932ULL,
		0x43A68F2377B8C525ULL,
		0xBA3AE4728E69C3FCULL,
		0x73D533C250D80D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19022D309D177CEULL,
		0x2335AD6A53EE8566ULL,
		0x0B33151AAD9E8276ULL,
		0x8200CF85406A42E8ULL,
		0xF2603A35986192D1ULL,
		0x9FF7AF61FC54CE6BULL,
		0xA6B5F47A7E282925ULL,
		0x03F9B0BDE9D1A363ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B16778DDB1CA03CULL,
		0x657FA7EBAA653BABULL,
		0xCC95D11C72E0E4DBULL,
		0x09D6243B7E7948BEULL,
		0x41934A176867DE07ULL,
		0xE5F33EB6B942AB55ULL,
		0xFFD472BB17399F25ULL,
		0x8F5FCA96355EEA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x152552CBC659EFEFULL,
		0x8E9634ED111E2323ULL,
		0x778BE8FFCCF0C110ULL,
		0xADE670B4CC2BAC83ULL,
		0x5FBE4026131E8127ULL,
		0x50C9113F8E1A970FULL,
		0x5ABD06C9F079D37CULL,
		0x04051A2668ED5EC7ULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6126488874F0D59ULL,
		0xF1538BEDF1B0C6EFULL,
		0x87AAEAF69E296BD3ULL,
		0xEAEFD791B41F730BULL,
		0x3413186A306C52E0ULL,
		0xD294313AEE6AFA27ULL,
		0x0A7D1C0F13C0684DULL,
		0x533416DD44AF6F40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D8181C161F831AULL,
		0x19615BBE411C3329ULL,
		0x3DC68D789D8453B1ULL,
		0x78C8F7318C9F641EULL,
		0x473000D4DE91CC85ULL,
		0x672E84A59761A2CDULL,
		0xAFC28EBFCFFD521FULL,
		0xD9255480FC681DAFULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E31498BF30A6B72ULL,
		0xB1DFC3867D2AE74AULL,
		0x8C2FE2B77EAC69BEULL,
		0xA74792651D31A479ULL,
		0x5516C22326E3DE32ULL,
		0x95B03C7D4E8E4FFEULL,
		0xC6C12EC7C32CE20FULL,
		0x6C80E9CE43551804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E31498BF30A6B72ULL,
		0xB1DFC3867D2AE74AULL,
		0x8C2FE2B77EAC69BEULL,
		0xA74792651D31A479ULL,
		0x5516C22326E3DE32ULL,
		0x95B03C7D4E8E4FFEULL,
		0xC6C12EC7C32CE20FULL,
		0x6C80E9CE43551804ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8074A93C9BE8B44FULL,
		0x6C6CCA1C7408C245ULL,
		0x8CF2C747E0C5207CULL,
		0xD93AFB03FE5D53B6ULL,
		0x66B28F7608C38B75ULL,
		0xAB11B9D8B758F516ULL,
		0x8FD1504B11AFEEDBULL,
		0x57A2363286DE4983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06D484DC3C11B9B9ULL,
		0xA61ACBECFC4038AFULL,
		0x4B559CC27FCE450CULL,
		0xEF2C0EF67301358EULL,
		0x4670788292F77696ULL,
		0xF3CC519C4DD6914BULL,
		0x9DF03C4636DA727FULL,
		0x8EC633E8FBFBD955ULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90B298B81D757987ULL,
		0x563C17F8DA807D45ULL,
		0xF707B65CA7F83400ULL,
		0x11B24DB165E178EEULL,
		0x529F2F224ECBF9ECULL,
		0x5AAF08CE42E5B92CULL,
		0xDD2BCB33813351DCULL,
		0xFB1FD45E5336AC98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCDA2B22F79A3FF8ULL,
		0x68CECD153F954E72ULL,
		0x31F2364F5B64A926ULL,
		0xF9CEA07A465F97AAULL,
		0x62947C69E6674C9CULL,
		0x0BD046746B38DF8CULL,
		0x7909D839C815CFF2ULL,
		0x55557A10234C44CEULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B12A7BBD8EB4902ULL,
		0xE69AA332AC9298A2ULL,
		0x82DE9C7988ADC5AAULL,
		0x95711E53BC3BDF07ULL,
		0x94F5D13A74BBB264ULL,
		0x1483996C0EB69CC0ULL,
		0xEDBD61A3D6CB8D61ULL,
		0xD575079DD783E86EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBC7A6C9C0C8B292ULL,
		0xB27F970479E2C40FULL,
		0xF17BF7981FBC9015ULL,
		0xF1A1EEC07E683701ULL,
		0xF00C44973804B871ULL,
		0xDD8689635BF79D95ULL,
		0x5976E27AF6EA903CULL,
		0xF0B29504178A0FA9ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0223B5B5CB2F3D1BULL,
		0x084C88A892F30EDCULL,
		0xD20BD33B18A4DB5BULL,
		0xEBC0C843831B9063ULL,
		0xF44C687C012B19CBULL,
		0xB320CF787847E0D9ULL,
		0x30366BB160A8E68DULL,
		0xA0628D3123C87ECDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0223B5B5CB2F3D1BULL,
		0x084C88A892F30EDCULL,
		0xD20BD33B18A4DB5BULL,
		0xEBC0C843831B9063ULL,
		0xF44C687C012B19CBULL,
		0xB320CF787847E0D9ULL,
		0x30366BB160A8E68DULL,
		0xA0628D3123C87ECDULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD63B8AA80E06B18ULL,
		0x8BEE962DDB3ACBDAULL,
		0x802DE3073BAC316AULL,
		0x4777123347628E83ULL,
		0x6C794FD72C830CADULL,
		0x112848FBBE2BE8B4ULL,
		0xC557A64792A9A49BULL,
		0x00D7EF102546FC7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C8D2B195252713ULL,
		0x6F9E0ACC6606F420ULL,
		0x07D35B95AF9773E4ULL,
		0x81F6C1326FCF7A35ULL,
		0xFE0C33AB173B69E0ULL,
		0xF5783CFDD2DB3683ULL,
		0xCE229B74188E24B1ULL,
		0x13C925ED5D60ED75ULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EE3B3A28C11BF7DULL,
		0x1B365F5D11D67E62ULL,
		0xDE23EABD5B25BBF1ULL,
		0xD5B024ECAC87672CULL,
		0xDD39B0CA389AC6F7ULL,
		0xC7B4CA43DFADE04EULL,
		0x7B8B5020380C826AULL,
		0xEBD3E5639162EAC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A037420179D5797ULL,
		0x28FA6BF10B5B73DDULL,
		0x384A3F904A7D7F41ULL,
		0xB7B525EF5898B4A4ULL,
		0x8B16048F0B8E69C1ULL,
		0x2459240A16906B24ULL,
		0x2444E8CCFEB659A2ULL,
		0xF7E56471013B0215ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33887F197C1A8930ULL,
		0xCC99079E9EB4EBC5ULL,
		0xEDC5CA310AC62D83ULL,
		0x53CFEE6DA3AD2643ULL,
		0x993F34D52A40A8CDULL,
		0xA4679F6C08059087ULL,
		0x311C4B3FE6B8065AULL,
		0x39D575AC9FA4C6C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC6850DAF4F18BFBULL,
		0xFBD2C0E5BAEA8B45ULL,
		0x6D3EEF9368CA2AB9ULL,
		0x06D7F25BD87128A0ULL,
		0x1C91A721EC1FCA3BULL,
		0x2D1159CE7DD740D9ULL,
		0x5EC65E9A5132450BULL,
		0xA8768D352FDA5932ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44D6B6A8233101BBULL,
		0x76A82F4E13C080E6ULL,
		0xBEFDFCDF8B254861ULL,
		0xC2C6E4B569F6105CULL,
		0x613BBDB288101045ULL,
		0x6C6DBEC2355F695AULL,
		0x45F6441D6C90D2AFULL,
		0x13781C0408C67CB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D6B6A8233101BBULL,
		0x76A82F4E13C080E6ULL,
		0xBEFDFCDF8B254861ULL,
		0xC2C6E4B569F6105CULL,
		0x613BBDB288101045ULL,
		0x6C6DBEC2355F695AULL,
		0x45F6441D6C90D2AFULL,
		0x13781C0408C67CB4ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4EB0D80F074F513ULL,
		0xA7962B1BD6EBBCA0ULL,
		0x7804FA78B57FD068ULL,
		0x5B2651146E1DE256ULL,
		0x24FD7CD3F5EE78CCULL,
		0x21055D58217EE564ULL,
		0x9B683BF1A245A158ULL,
		0x899A7982BDF8ADD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0941A4190FEAABE6ULL,
		0xDBA06B82409A15A9ULL,
		0x0EFE2702F6074849ULL,
		0xD5C8005BB73986ACULL,
		0xF7C308353224428EULL,
		0xE343B6843B5D7BB3ULL,
		0xB5EF7745A483C3B2ULL,
		0xE75601E22F4074DAULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B416B89C13E7160ULL,
		0x0D41A93F09364345ULL,
		0x67A2B80054E278EBULL,
		0x803150F7D6292229ULL,
		0xA58B6EED75142C93ULL,
		0xA80E42845265AD5FULL,
		0x28CC855EFCC2CB04ULL,
		0x2322EFD06DF5C80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C247593087FF912ULL,
		0xE8B2047CE777EFE4ULL,
		0xF43613951F779E1FULL,
		0xA2550275239FF27EULL,
		0xEFBE3B48AC3B21E7ULL,
		0x5F33ADBE20ABC034ULL,
		0x84E82F38D6A1C4D4ULL,
		0xE0155DE02F32F55BULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE5AAC5BAEE71C82ULL,
		0x0BF5143152CF4EA2ULL,
		0xCFBC96600E3FCFE4ULL,
		0x9AD613CF5771F182ULL,
		0x0E59559DAC98F1D7ULL,
		0x40B4C08607C2F471ULL,
		0x02D3E2EDE9DBACF3ULL,
		0x53D4896CF52205C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C42117F277BD30ULL,
		0x4418E46279E2A6A2ULL,
		0x1DB0A11855D30963ULL,
		0xCF135EBB395BF3C1ULL,
		0x3246604B664FFAE8ULL,
		0xB014ED5B81050065ULL,
		0xD002A7F15766C747ULL,
		0x6FB225AD90FD565DULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x081D2C4D8923D59CULL,
		0x9C9F9656DEBBE90CULL,
		0x624EEC6DA106ED6BULL,
		0x55FFEA8048815E74ULL,
		0x1F73AC79E842AFEFULL,
		0x07D2C42D29B9ED0DULL,
		0x4BC5D741449C58A0ULL,
		0x925DB7CEB40741D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x081D2C4D8923D59CULL,
		0x9C9F9656DEBBE90CULL,
		0x624EEC6DA106ED6BULL,
		0x55FFEA8048815E74ULL,
		0x1F73AC79E842AFEFULL,
		0x07D2C42D29B9ED0DULL,
		0x4BC5D741449C58A0ULL,
		0x925DB7CEB40741D6ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64D4F0001C982465ULL,
		0x37E6010A8DD32C30ULL,
		0x9D6413543C0F0575ULL,
		0xD4856871C0465653ULL,
		0x50CA61F6CF5C5A6AULL,
		0x772F7613DA9C57DAULL,
		0xA6969BBA4D7024D4ULL,
		0x58DBDACE1F8C7B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDACBEFFD26EE7CE3ULL,
		0xCF533956994B5BE7ULL,
		0xFB9087C071A0D604ULL,
		0xB97BD302F0249A7DULL,
		0x6915A3F60EC19EC0ULL,
		0x6290F67432C5FA78ULL,
		0x763E3EA34936E6B8ULL,
		0xD8C644158E3C1ADBULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AA45A46D8A6EC58ULL,
		0x1E6329B8584FDA4BULL,
		0xE5C02A7FA8780486ULL,
		0x082FE8999B5825D7ULL,
		0xD49CC6BB418F609CULL,
		0xCEBBEADF675ADF38ULL,
		0x6FD6C447969A09FFULL,
		0x619B9CFA6FEB4EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5C2E248E19B0D48ULL,
		0x3094BD95BC6D9E6EULL,
		0x4054F5CC27D4AE0AULL,
		0xE561DD7F311553ACULL,
		0xA771272302F1AE2DULL,
		0x50749FAADD091724ULL,
		0x5738A2D01B8CE96AULL,
		0xDA7DD058D42C957DULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97022428DA5C97B4ULL,
		0x4C17F303B13EEEC4ULL,
		0xC1290CF9511FE1E3ULL,
		0x72A33EFC123C24DFULL,
		0x1AEE4C25C64F72BDULL,
		0x37092E9124836BF2ULL,
		0x8DFCCF18901E8953ULL,
		0x43319D3284A9A02BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4A1B504372B58FULL,
		0x7441FA2E9835CB00ULL,
		0x51CE756F71B466DDULL,
		0xFCEBAF896CB12DA4ULL,
		0x481FA00BC0A8483BULL,
		0xC173A8F72F14CBFFULL,
		0x43EA2713E93CCFDBULL,
		0x876C494EB42DDADEULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40F0C1EEEFFCB377ULL,
		0x4BE51CBEE42CB8A3ULL,
		0x942DE307017F1ADBULL,
		0xD6C9A842103A5E7DULL,
		0xBA202C067F1DE3C6ULL,
		0xCFFE41020FC909BEULL,
		0x2333312C205165AFULL,
		0x5F072B0ED861975EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F0C1EEEFFCB377ULL,
		0x4BE51CBEE42CB8A3ULL,
		0x942DE307017F1ADBULL,
		0xD6C9A842103A5E7DULL,
		0xBA202C067F1DE3C6ULL,
		0xCFFE41020FC909BEULL,
		0x2333312C205165AFULL,
		0x5F072B0ED861975EULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EADB0668B427E75ULL,
		0x3F4F7E344985B145ULL,
		0xF1EF688AE8BA7055ULL,
		0x21457AEFB16290F5ULL,
		0xF4E1DAED232C767CULL,
		0x91610719B6C2694CULL,
		0x2D65CE9DA41900EBULL,
		0xC90091C9798A9E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7114DE65DBD7D33CULL,
		0x0EFA690B279DC9ECULL,
		0x04C4E1D19CDD5DB8ULL,
		0x132EAFCF8207C93FULL,
		0x8F8FFAB84F31ACADULL,
		0xC7723BC9FD54E6D0ULL,
		0x4B88DD14390779C1ULL,
		0x4334E78480A9CBF1ULL
	}};
	t = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC63C85AAD38D24E9ULL,
		0xBB31BCA849D62C34ULL,
		0xFACF3E6F24ADD861ULL,
		0x00BF23FD22BD62C5ULL,
		0x8DFC9D254CDBCD1DULL,
		0x75D668B5C1A3E6D4ULL,
		0x6D91719B284ECDABULL,
		0x9B19D3CFA2ED1C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78378E4C71D646E3ULL,
		0xE16D2B9ABA66F1D5ULL,
		0x0CE9C0AF9039C6AFULL,
		0x90930B8EDC957C54ULL,
		0x076C049BAA785FDDULL,
		0xF390E48110342E7DULL,
		0xF0909BF58BD9302DULL,
		0x0CEC17AB5E82D3F6ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10323E590303688DULL,
		0x32D483E8A0F61446ULL,
		0x0D6808F4A9F44F46ULL,
		0xBE3343260023C016ULL,
		0x75A72650D36ADBB4ULL,
		0x3CE2DF16A20B1F86ULL,
		0xD6EF47D5D2B06B03ULL,
		0xD7CD67D86ACCB2C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329396C16F133590ULL,
		0x224130E9781CF57EULL,
		0xE9AF4C896F813746ULL,
		0x592FC0E3CD4615D8ULL,
		0x760D973E6351FE1CULL,
		0x70C13E5F4C724C88ULL,
		0xECA94D40A96B9CA1ULL,
		0x272AD2DCBFFB2D9FULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58E374B16A015106ULL,
		0x730801B5CB84F75AULL,
		0x14F833929D56B0E7ULL,
		0xF6ED977C596D0B3FULL,
		0x8C1D0C5AEB822960ULL,
		0x8C90670CC9DE43A5ULL,
		0xFF35F01EEB1FA222ULL,
		0x483330E7C42A6FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E374B16A015106ULL,
		0x730801B5CB84F75AULL,
		0x14F833929D56B0E7ULL,
		0xF6ED977C596D0B3FULL,
		0x8C1D0C5AEB822960ULL,
		0x8C90670CC9DE43A5ULL,
		0xFF35F01EEB1FA222ULL,
		0x483330E7C42A6FFEULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FE6B9FB0F6C1A03ULL,
		0x3EBEE5619E333C1DULL,
		0xFB1BE2F013EE6F96ULL,
		0xA1CB873F3B7F8268ULL,
		0x13C99E25E8AF582BULL,
		0xAE5034CF6E1D6B2BULL,
		0x19E8AEC8E82A888BULL,
		0xB3D15E099544C04CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD30FC83DBE108B7CULL,
		0xA48FBA3BFF4F52FDULL,
		0x70F878008759AB29ULL,
		0x84466641AC6D3E4CULL,
		0x7A68D0F96F27F7DBULL,
		0x1453A20486A573FCULL,
		0x70255505DD4AFBD1ULL,
		0xE184D3679AF2894EULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8937F5967477C8CULL,
		0x10A1A734F77C2C42ULL,
		0x80AC0CFEAEB2CED4ULL,
		0x09A52C0F9FD57DFEULL,
		0x5DD005058AD5C829ULL,
		0x3A8D3BFF276B29CEULL,
		0x0EBDB77A479951CCULL,
		0xD0F56AF5833F1037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A668A2DF172394ULL,
		0xA8343CDEE3EBDD4EULL,
		0xE117D84551698E76ULL,
		0x97940D393A35C0BDULL,
		0x065901E850DDAEE8ULL,
		0xE8038AB8829EBA7BULL,
		0x261646F8F7E21392ULL,
		0xCD48AF96ECF90AF5ULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79AC6C0C4E3A3732ULL,
		0x6F883AF9F59DCCFFULL,
		0x9E951B88876FB182ULL,
		0x8F3F4244857C610DULL,
		0xD758976101BEF1EAULL,
		0x049C804FBDF79DB7ULL,
		0x6D61EF8A990FB74FULL,
		0x6755B50077965301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2DBF20D6799C200ULL,
		0x16511A9ED56FC52BULL,
		0x73998BF285C23A2EULL,
		0xC37B24ECB78DCB25ULL,
		0x58E1FBA01D2ACB10ULL,
		0xDA13B8EDBD93E026ULL,
		0xB4F7F4E2BA496DA3ULL,
		0xBD70B10F452743A9ULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5375BE8590864FFULL,
		0x00BC6F2FCF2AFFA8ULL,
		0x46453FBE8333426AULL,
		0x3F35B7C483B0B22EULL,
		0xAAE76D1811578BD8ULL,
		0x3ACE88C3221B5CD3ULL,
		0x799020BD265F8A8CULL,
		0x79D1FC59D7257447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5375BE8590864FFULL,
		0x00BC6F2FCF2AFFA8ULL,
		0x46453FBE8333426AULL,
		0x3F35B7C483B0B22EULL,
		0xAAE76D1811578BD8ULL,
		0x3ACE88C3221B5CD3ULL,
		0x799020BD265F8A8CULL,
		0x79D1FC59D7257447ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3A728EBCE0CB594ULL,
		0x96C4B9FBE8B47878ULL,
		0x8DD8DC5476C0E9ACULL,
		0x8D7C98CB9B23B5CBULL,
		0x9D45E1613A54D514ULL,
		0x27F73756A4FC97B5ULL,
		0xDDAF60C83A7AD9BAULL,
		0xA4781CDA456F91D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5EEE6D880E9A71ULL,
		0xCFFD26BCB6249048ULL,
		0x7DA6476320811BBBULL,
		0xFF7D781F0712AF8CULL,
		0x5452FCF7EEF38FA2ULL,
		0x3B4C05E4DA0A0D7FULL,
		0x8E5A6B69F14BAEF3ULL,
		0x590BB1A1F3A64E87ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72E700AA683B2A8FULL,
		0x29C5741A91F78483ULL,
		0x287592EEA0E76A2DULL,
		0x2E7EC6FC57DBCB63ULL,
		0x0649D6CCCC233B03ULL,
		0x0A6F2A7B90189B22ULL,
		0xD1DD63D72F07C01FULL,
		0x285813220EADCA08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x803B23092E5F1CC4ULL,
		0xD6BE40E2962214B6ULL,
		0x78F05A119DD6C0F9ULL,
		0x2D9443AD2AF63F42ULL,
		0xA4823223CD5B3D30ULL,
		0xA532AD7EDCA107FAULL,
		0xFDD858F7949FD026ULL,
		0x6BC5B3E0191DCD84ULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FDCC7E0F8B509A7ULL,
		0x1B11513229F25F6BULL,
		0x28B445DBA3327775ULL,
		0xB0632824F5FE5548ULL,
		0x059A7B99A907689DULL,
		0xE2D9B2A233C9D14DULL,
		0x340F20F94AB0F69CULL,
		0xAEF30ED0C950181FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBAFF079F62D8448ULL,
		0x2951C250E6562DD7ULL,
		0xEB18B773C2602060ULL,
		0x8B182AD3AC096907ULL,
		0xFA51DEA985C1C397ULL,
		0x0940105CE75E9C38ULL,
		0xC5527966C338C136ULL,
		0x93D84568BBC86FA2ULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8ED746A5C8692675ULL,
		0xF6D7DF5F8278BBD5ULL,
		0xD0C024FFC1BE57A4ULL,
		0xF4CC0D9EE7A1DC5EULL,
		0x6DABC12914AFA2E3ULL,
		0x97075D779A577A40ULL,
		0x1D083DC0BF1952B9ULL,
		0x02109D093B35FD2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ED746A5C8692675ULL,
		0xF6D7DF5F8278BBD5ULL,
		0xD0C024FFC1BE57A4ULL,
		0xF4CC0D9EE7A1DC5EULL,
		0x6DABC12914AFA2E3ULL,
		0x97075D779A577A40ULL,
		0x1D083DC0BF1952B9ULL,
		0x02109D093B35FD2FULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D56FFA0E5BD9307ULL,
		0x44736BEC0E914BDEULL,
		0xF71D74225BDE99DDULL,
		0x27E3EA43855DF09FULL,
		0xDBF55A0D237B3AE0ULL,
		0x535A2F8327ABF5A6ULL,
		0x1A9159B502F0B252ULL,
		0xAD50F760696ECB95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37345DB1F8114E3DULL,
		0xC29046DCFEB958D8ULL,
		0xBA970800AC70BAAAULL,
		0x24092B0CAB5898B8ULL,
		0x8FCB95E81023060FULL,
		0x5E960F2973F7D4EBULL,
		0x21CFF25E9593CEA5ULL,
		0x20E96FDF022E87BFULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59E6E0EEDAF7B144ULL,
		0x95C468E546085327ULL,
		0x1553D88918094729ULL,
		0xF74FE5F7420749A3ULL,
		0x3F417B443CAB3A94ULL,
		0x59DB424D5DD7620EULL,
		0x5D260A410266A5AFULL,
		0x34A86B7B57A77F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E82B5FEACFD2C7ULL,
		0xBD642A4AEC962D96ULL,
		0x833DE2592B44C76DULL,
		0x600FA72C176989A4ULL,
		0xF063351735F511ACULL,
		0x17D1D6E5E7714D7BULL,
		0xA33F2EC01E2C2F7FULL,
		0xDF6C283592FFA05AULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x079FEEA35BC34855ULL,
		0xB2A9095FAD4D96B2ULL,
		0xFB15F09CCC675155ULL,
		0x8DFFB653D4B74587ULL,
		0xA1E7605CA6D38C26ULL,
		0x1AF64DF4056567C4ULL,
		0xDBFFF828B6D99E8EULL,
		0x270FD2BF52FFE6B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83BD886E8FF61B68ULL,
		0x0D52D1D4976324AEULL,
		0x6C62100A3A144951ULL,
		0x8D5E781E5B238ABCULL,
		0xCB24C59CD8371646ULL,
		0x8843D6E3A7C5C0D7ULL,
		0xDAFB389496AD265AULL,
		0x3CD4D78D5204BB82ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE0D69AEFD7DA46FULL,
		0x2659FC16336D23A6ULL,
		0x2948417B4CFDD103ULL,
		0x3C186503A736136FULL,
		0xE2C60E4EA1623BB0ULL,
		0x6373D706A544AF7DULL,
		0xD6AE08A331734C39ULL,
		0xBA3F07CBF33838CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0D69AEFD7DA46FULL,
		0x2659FC16336D23A6ULL,
		0x2948417B4CFDD103ULL,
		0x3C186503A736136FULL,
		0xE2C60E4EA1623BB0ULL,
		0x6373D706A544AF7DULL,
		0xD6AE08A331734C39ULL,
		0xBA3F07CBF33838CCULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06B48059F1433C81ULL,
		0x704F85ED81C7F71AULL,
		0xECC8D5F6DC93EBECULL,
		0x98A1F68497C7F034ULL,
		0xE236D875D82EEBA8ULL,
		0x2F2564F818308807ULL,
		0x0F962022D1DFBBBFULL,
		0x99FABCD8D502F8FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F343042EF6B8E84ULL,
		0x08C2F366FCEBB91EULL,
		0x2D965B9B018A6B22ULL,
		0xBDE46D4A5A67B21DULL,
		0x40927F2C022C8D21ULL,
		0x02802CAA7367C4E9ULL,
		0xCFDDC8E7DF30FADFULL,
		0x4F9335F2BAFD988AULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF61E53BEA5876D7CULL,
		0xB58DC19FF60C7503ULL,
		0x26D57E5F57753E2FULL,
		0xE944B6E023C084D5ULL,
		0x5B3BF74AF363E991ULL,
		0x714CBC423C1E0320ULL,
		0xDABAA6AA816344A8ULL,
		0xDEEEEBDAE2298574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17174E0BBEA9AFEDULL,
		0x8BB4DDB5D509E1ADULL,
		0x2A4C1AF9CCCAB670ULL,
		0xFF091264D28D788DULL,
		0xC2332229C91F6A74ULL,
		0x93F610F9CE570BA0ULL,
		0x3DA5DF0F46536B13ULL,
		0x1475D28CD0879D52ULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EF9F528FC0747F2ULL,
		0xBBB833A27A12144CULL,
		0xCC368AD01FD56B04ULL,
		0x1E6DD928C5FAA422ULL,
		0x250D315BAA631116ULL,
		0x278065E20F125015ULL,
		0xB06D7E19D393BDE8ULL,
		0x3F816FD05BABB4ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75C784972CF584A3ULL,
		0x5A019D76D120ED60ULL,
		0x2FAA6FE08C5C76E9ULL,
		0x07B88F141C397965ULL,
		0x9077CCF08A2C13A2ULL,
		0x03D105AB6A8D05D2ULL,
		0xFA7768AC459C33CEULL,
		0xF562F12A34E4156EULL
	}};
	t = -1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE68D70FFC3C6ED46ULL,
		0x56827C64BB99C6A8ULL,
		0x6A832AC0E8E80937ULL,
		0xCB0644A50C5FE1B0ULL,
		0xA99487754865475FULL,
		0x0C9B19DE18A9C5C4ULL,
		0x03D39151A0780DE6ULL,
		0xF27FA0B3031E09CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE68D70FFC3C6ED46ULL,
		0x56827C64BB99C6A8ULL,
		0x6A832AC0E8E80937ULL,
		0xCB0644A50C5FE1B0ULL,
		0xA99487754865475FULL,
		0x0C9B19DE18A9C5C4ULL,
		0x03D39151A0780DE6ULL,
		0xF27FA0B3031E09CFULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D179DFD0E7590A0ULL,
		0x49EA2904BC2370F7ULL,
		0xAAC4F14B4C8CADC4ULL,
		0x5EA3F173C86FBE44ULL,
		0xCAB6460D2D7A4EEEULL,
		0xF11F0770F9F6135AULL,
		0x834A21CDB1CA429DULL,
		0xEFE81649F0F6B6ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B49B6214B9EA9F4ULL,
		0xC0E9606B2511BF27ULL,
		0xD6055BCE5732B247ULL,
		0xF55CE277B65818A5ULL,
		0x4AA28DC156AD9C90ULL,
		0x175616D8694CEF9CULL,
		0xB23BFE55FC434BE9ULL,
		0x8CBFD65999EABAE6ULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA47F935CAA0301A6ULL,
		0x1BCFA146786D0D1CULL,
		0xBF014BD94F698D5DULL,
		0xFD1B176B8012FAA4ULL,
		0x6634B5567D3456FDULL,
		0xD2C4D9C7E914FA1BULL,
		0x30D11D022BA34565ULL,
		0x67D32FAA9FB442ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC53E48D671D321ULL,
		0x37406B187BC5222AULL,
		0x8487C5D8DBE52766ULL,
		0x775A74359CA16B7DULL,
		0x26A74F5FFD27C587ULL,
		0xAF83B8F52C41E487ULL,
		0x41C5B1EA981DA4ACULL,
		0x1834529F65E56C5FULL
	}};
	t = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D2CB1B44A09E8DAULL,
		0xE8F8E9D8457DBCD2ULL,
		0xFC296ADBF212EC63ULL,
		0xA6EDAD223CFFB520ULL,
		0x64E5B8CFBBE21799ULL,
		0xC20441C5FC8AA1BFULL,
		0x8CF3C23D640C778DULL,
		0x9BD37AC85A0B800BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464A43ACCA1EA8E9ULL,
		0x2C4D20726FE51CD5ULL,
		0x0D51C0995E1F3248ULL,
		0x6B3BD66D156909CAULL,
		0x3727C9A71407ECF7ULL,
		0x00BA073D29FB37B0ULL,
		0x97F89028F0FCD263ULL,
		0x25108D62ACB4A35AULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1122D5329F1A80C9ULL,
		0xF98812830166DE18ULL,
		0xE39B7559BDD12229ULL,
		0xEE45E1D1140B87FBULL,
		0xDDD7D7EE6F359398ULL,
		0xAAB9FE046C0DF714ULL,
		0x13E8CB04FDAFFDF3ULL,
		0x6BB36CCAF2C261CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1122D5329F1A80C9ULL,
		0xF98812830166DE18ULL,
		0xE39B7559BDD12229ULL,
		0xEE45E1D1140B87FBULL,
		0xDDD7D7EE6F359398ULL,
		0xAAB9FE046C0DF714ULL,
		0x13E8CB04FDAFFDF3ULL,
		0x6BB36CCAF2C261CDULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8816302E395000AULL,
		0xEC64A7BBFB789544ULL,
		0xDB6F81307FA89B05ULL,
		0x048F0D1122AD46B6ULL,
		0xC308F5C4A814D757ULL,
		0x8E14904D635ED6A7ULL,
		0x6E26E99E28A5DB62ULL,
		0xD04D970D436A5181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012D2572EDE1A1CBULL,
		0x5844B8EA7D93578BULL,
		0xE736B5AEF9F9A3D3ULL,
		0x6C389B4B37BAA94CULL,
		0xE72235A51AB023BEULL,
		0x3F83FF460042E218ULL,
		0x65E350781660D817ULL,
		0x1AD317129A3158A5ULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFFF0156A934ECEEULL,
		0x0290BC41DD03FF78ULL,
		0xCDA907F367CA3F64ULL,
		0xB4F48963A74515F3ULL,
		0x5F22FAFA2AC0FB9BULL,
		0x435024EF0F6FFC7DULL,
		0xE299761B0F896104ULL,
		0x51AC7770F2A8FA83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5FEC6BCE16DBFE3ULL,
		0x31FE7F8D1F8EC6D7ULL,
		0x605520DDB39E0257ULL,
		0xA11244383766762AULL,
		0xC412A68AB0D4C1EDULL,
		0xE202802F6DDE8D39ULL,
		0x5FE516FA32832AA4ULL,
		0x5D1BA19CF67CFBEAULL
	}};
	t = -1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2578207837CCB85FULL,
		0x3B1A70028C082075ULL,
		0x673EF042584D96E6ULL,
		0xB98D877410C88481ULL,
		0x253A7667B7AB33ECULL,
		0xFECB4E019BC988ECULL,
		0x7F9A4913BB16D204ULL,
		0xBF1DF7BCF27C5A1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D942ED9978508AULL,
		0x87CAC42D74190050ULL,
		0x8DC6CE64F79CC020ULL,
		0x36CE89B4DB74CF09ULL,
		0x38144D3CF5B97E4EULL,
		0x525367732373694EULL,
		0x40F69A599A610A59ULL,
		0x41C1019646AB942CULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA53662F89751A44AULL,
		0x47540081BFE85CECULL,
		0xF4E7F75272DFBB55ULL,
		0xFC02B50BD6D78867ULL,
		0xD3EBAB45A70C7DDDULL,
		0x97BE5B0F2B4D4266ULL,
		0xB3A5CDE843856C99ULL,
		0x823DC186255371BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53662F89751A44AULL,
		0x47540081BFE85CECULL,
		0xF4E7F75272DFBB55ULL,
		0xFC02B50BD6D78867ULL,
		0xD3EBAB45A70C7DDDULL,
		0x97BE5B0F2B4D4266ULL,
		0xB3A5CDE843856C99ULL,
		0x823DC186255371BBULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E6544EC3DE2FD9EULL,
		0x8F2FC5E092112B93ULL,
		0x01D1811EF7E97E75ULL,
		0xDF6AA39B1B597283ULL,
		0xA327679E26FA4196ULL,
		0x3D8652882C759E22ULL,
		0x041EE1EEBFEEBA9FULL,
		0xC716E648CE8155E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD79ABD1827E3674EULL,
		0x3B00993E08EC66D9ULL,
		0x43BFC63EF5B9E86EULL,
		0x7D26AA13320AA172ULL,
		0x05118ECAD241BB0FULL,
		0x056B6BFB8C4833C8ULL,
		0x35DA9BB9BD61AA7EULL,
		0x34E670FB4EA8C125ULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x813900779D9EB3F6ULL,
		0xBC6BC784BD75E560ULL,
		0xCC740CE62655A43CULL,
		0x4D745D09F318FB44ULL,
		0xF84CFDAC49B22AFCULL,
		0x76926B4CB498E726ULL,
		0x24C1F7C55EA61096ULL,
		0x58B156AEB7473914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA3FE34D0BE57F7AULL,
		0x83A60C52C2A16FA6ULL,
		0xA542E2EE7E7717D8ULL,
		0xFEAE5B431F6E76EDULL,
		0xFCD290BBF5F40B46ULL,
		0x2D639CB64F781F77ULL,
		0xE796F4875ADE38A4ULL,
		0xC5378679DAD52F59ULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEC0682F0974A70BULL,
		0x73F471C4F4835C04ULL,
		0x50761B298ABAD662ULL,
		0x69DF942FD8AF30E9ULL,
		0xE083BB03E77FE458ULL,
		0xB5D6F0EA484BAF1CULL,
		0x46964AFCA7BB98DBULL,
		0x7BC09B62B93CA6D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3443A12EFA291DULL,
		0xA55D71E5E53B7865ULL,
		0xFA359E87EE447B2FULL,
		0xC3976EB8EE8658ABULL,
		0xF7A93C0EBB11B0C3ULL,
		0x0DF38977A5F1EB9AULL,
		0x25DE01DF084DB916ULL,
		0xC6CA40DD10DD7ADEULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26E32517D81AAF2BULL,
		0x35EC98DD9B4DD1FCULL,
		0x0335D0C6EC0F36C1ULL,
		0xCF16EFBE8CF6E592ULL,
		0xCE4BAD5F2075DB4FULL,
		0x1E914241089D3FC1ULL,
		0x083CF9609B6CE17EULL,
		0xCFFBAF646E1C883BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26E32517D81AAF2BULL,
		0x35EC98DD9B4DD1FCULL,
		0x0335D0C6EC0F36C1ULL,
		0xCF16EFBE8CF6E592ULL,
		0xCE4BAD5F2075DB4FULL,
		0x1E914241089D3FC1ULL,
		0x083CF9609B6CE17EULL,
		0xCFFBAF646E1C883BULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x533084DE606C6425ULL,
		0x1959E5AE2C873DBBULL,
		0x6559449099158AFEULL,
		0x95957679DFD51B97ULL,
		0x1841DBB9EB3F0492ULL,
		0x3B0C8F01080C8B1BULL,
		0x69DDEB4BBEF9C393ULL,
		0x74E93529998A2DA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59DDB5CA920CF37ULL,
		0x26BE930B93F6D165ULL,
		0xB4C8DD5E03C8509FULL,
		0xEEA1370EC8E2A4D8ULL,
		0x3F41B25EE7D89E74ULL,
		0x36952A2F883BC8AFULL,
		0x05E316DB379401A6ULL,
		0x8553EE6A92C54E3FULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97D3E418982FE273ULL,
		0x69FE7144B4F5FDAEULL,
		0x19DBDEBE9F3C1F6BULL,
		0x8A913879A0EEE0A8ULL,
		0x019EE60ED14BEDD1ULL,
		0xEE820CDC5649314DULL,
		0x21A0A80DCCEB3B9DULL,
		0xC74C6B008099F2ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D0F087B0790900ULL,
		0x414513EA106413D8ULL,
		0x683542C7427D9928ULL,
		0x4E295804C9038140ULL,
		0x396494CA6521AC46ULL,
		0xE96639ACECA03F82ULL,
		0xC2A5897D0934B3DFULL,
		0x513D218446FC07AFULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F488E2661BD9342ULL,
		0x51DC6D2A95E87DDCULL,
		0x6A0D2215C611D27DULL,
		0x2DAD87E12A205C82ULL,
		0xA4DB531FB71C0533ULL,
		0x46EA292109CE09E2ULL,
		0x638F4308C4CF78DAULL,
		0xCBFED629F95A4BBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E0A9564E025A286ULL,
		0xF0D9965FE3F33310ULL,
		0x779E99C272569DF2ULL,
		0xDE8ECD99EF4DA932ULL,
		0xC9969FCF2609C9B4ULL,
		0x6F7BD3B4298BE54CULL,
		0xBE46D747778DAB21ULL,
		0x091DFFA7964C7EBCULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE282CD92C0CE3869ULL,
		0x0328B0182C71B8A7ULL,
		0xC6093B8B4C6208CDULL,
		0x45E337204CC690D0ULL,
		0xBA68E4AF88BF6DCBULL,
		0x2FABE6D856BA7B2CULL,
		0x7880F1AEF73BF263ULL,
		0x47AECEABB0D2F70FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE282CD92C0CE3869ULL,
		0x0328B0182C71B8A7ULL,
		0xC6093B8B4C6208CDULL,
		0x45E337204CC690D0ULL,
		0xBA68E4AF88BF6DCBULL,
		0x2FABE6D856BA7B2CULL,
		0x7880F1AEF73BF263ULL,
		0x47AECEABB0D2F70FULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1AEBCB6EA7BC366EULL,
		0xD45E116FAAE5AF19ULL,
		0x99DF1F082780E96FULL,
		0x5619967AE7DDDCB0ULL,
		0x8815059F2A3097BAULL,
		0x554C2F8AFEE1B220ULL,
		0x74DB216C359C7750ULL,
		0x20775D251F9EE784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E63031DC040D5B9ULL,
		0x3EBE4E1C41709BA0ULL,
		0xBAE5CBACC93528FAULL,
		0xAC66B9B833026A63ULL,
		0x85B27F899CC1A805ULL,
		0xE5E1813BDB3C266FULL,
		0xCA339D5A5526F3C4ULL,
		0xF56437E03629195DULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB08D49945FE087AULL,
		0xAF6E49E50B4C4B02ULL,
		0xF2092778CB31B0AFULL,
		0x7AF36AA9F503AF2AULL,
		0x9B844430A1C6A757ULL,
		0x1FAD66EF853A615DULL,
		0xC4F6244A27287B5AULL,
		0xA5D9EDB3F4679A47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C879AD2D7A7A07BULL,
		0x312684D23480025DULL,
		0xC6FCBA73063FA404ULL,
		0xEB115374FE3D84A4ULL,
		0xC5B32FCE1922EB07ULL,
		0xCCECFDF3779AA073ULL,
		0x0ACD00F61058793AULL,
		0x87FFEDFC8A27149AULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2E8B38EC9715ACEULL,
		0x3FCBB4B29295EDB1ULL,
		0xDE460FB77D1E9893ULL,
		0xA4860970FC381F39ULL,
		0xFFEC94FEC1DA3CC8ULL,
		0x0ABE71B1034D05FEULL,
		0xBD515E1F8D8E510CULL,
		0x040CF271709858B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FF43029CD9293D3ULL,
		0x7FC01D640F260EC7ULL,
		0xCB9CBB285AB45603ULL,
		0x06933FDA7E9E2F7DULL,
		0x9DCF0CF31C1A5933ULL,
		0x4F3C849D5CE20792ULL,
		0x2C37CAF672925FFAULL,
		0x8C58C7A87C7D6D04ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F3084A1B5DC7FEULL,
		0x67BA6F6B20DB601AULL,
		0x90A1F716812E0A44ULL,
		0x67D90743CE3B4E87ULL,
		0xB45511EFE2AC0FDEULL,
		0x6FCE92C6BAF1D241ULL,
		0x4C004C23CB39EA0FULL,
		0x3CAD3A212E0F7610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93F3084A1B5DC7FEULL,
		0x67BA6F6B20DB601AULL,
		0x90A1F716812E0A44ULL,
		0x67D90743CE3B4E87ULL,
		0xB45511EFE2AC0FDEULL,
		0x6FCE92C6BAF1D241ULL,
		0x4C004C23CB39EA0FULL,
		0x3CAD3A212E0F7610ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAA2629E7A9408F6ULL,
		0x0E76D4E0AB2B799CULL,
		0x978D832929924D6FULL,
		0x131C943EB56261F3ULL,
		0x5A86205CD430DA30ULL,
		0x4249BA6433AB7EF1ULL,
		0x26BC9377175F1E13ULL,
		0xCCBE32D21D20970FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F628B359FA8EB3ULL,
		0x1286EF3C1BB117ECULL,
		0xD5EF67EAFCC39C06ULL,
		0x18C1C75F7353A239ULL,
		0x63F4DE52F2FEF391ULL,
		0xEADCBC76873C417AULL,
		0x24E58A1A6DD691B4ULL,
		0x458E8BA671DD4464ULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E7883236BFCB8FEULL,
		0xD2BDA7C45BB52042ULL,
		0x80BFEBE34D9F70AFULL,
		0xBB4901CC1B83138CULL,
		0x4357F4D4CA2C41AFULL,
		0xEB5ADBB76046ED18ULL,
		0xACFA06F554EA2E57ULL,
		0xCD6246D4710BFF59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EFDE555F5C0283ULL,
		0x15FDEE4301C3F4D5ULL,
		0x58E43053AE224FC6ULL,
		0xA0A218F65D3CAE63ULL,
		0xBD1822E0E4B91070ULL,
		0x1F64D128CC95A0BDULL,
		0x950E0169234F35B9ULL,
		0x67FE2EC364057275ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED207FB8E229318AULL,
		0xFDDB4A4F95B6E034ULL,
		0xD8043AC9704B3EA5ULL,
		0xAA907C3769EEEA12ULL,
		0x00B9C8699C1AE677ULL,
		0xF5810DD294F6A546ULL,
		0x34A7A6B708ECC65AULL,
		0x80096C33642B83C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD023AC9CC32D97BAULL,
		0x2966B352DBCD447BULL,
		0x1EDC3AAB7E0C2BD4ULL,
		0x19C4933114923596ULL,
		0x8AA3A55CDDEBCDECULL,
		0x0C19ABAEEA3F863BULL,
		0x21DD34B76E1FA3CAULL,
		0x29D022D75F5ED293ULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70E3185FE95E3F55ULL,
		0x26DDB7A92C80ED80ULL,
		0xC12139FA7F835919ULL,
		0x97DEC020C0A02E4BULL,
		0xCC1B2E9D6910DC52ULL,
		0x086CC002A3EB46F6ULL,
		0x9745611C95DBF211ULL,
		0x24902E30CB3DCBCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70E3185FE95E3F55ULL,
		0x26DDB7A92C80ED80ULL,
		0xC12139FA7F835919ULL,
		0x97DEC020C0A02E4BULL,
		0xCC1B2E9D6910DC52ULL,
		0x086CC002A3EB46F6ULL,
		0x9745611C95DBF211ULL,
		0x24902E30CB3DCBCAULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8845208DA2EB2C8ULL,
		0x5B09885158005704ULL,
		0x36D6EBFC42698430ULL,
		0xA82DFE61E9DCFC62ULL,
		0x820D16A4CF0B174EULL,
		0x1CADA70A576C6554ULL,
		0x9428F24D08E78468ULL,
		0xF4E22439B635ADDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4CFB7389B3675E7ULL,
		0xA8B78974CB05647FULL,
		0x3B68973665773AA2ULL,
		0xBE379A5383AE3A96ULL,
		0x7DDEE746AA044E1DULL,
		0xE01088F195E57A14ULL,
		0xA5790AD6CC5F52E2ULL,
		0xC6FAE34E22E14674ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x365D161EA2E80FDEULL,
		0x0A0851486AEC93C1ULL,
		0xFFD897DB7B67E8C0ULL,
		0x2CE55B4801424567ULL,
		0xACA184F1F501FA68ULL,
		0xD41AABBAF3D39C7BULL,
		0xB35E7780214E4317ULL,
		0x38714FA5CD707AE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2256E53312A628F1ULL,
		0xD0269CCD5C22EA18ULL,
		0xBB99BA385D6FC840ULL,
		0xFE3524E98B799101ULL,
		0xEB15D890E383E6FBULL,
		0x3D9CEA3BFB9D21C9ULL,
		0x8033D66EEABF2715ULL,
		0x280B473689DC65D8ULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3A14891462D69DDULL,
		0xD9F8139C40F706E5ULL,
		0xA23B2D558DE746A8ULL,
		0x283DF3BDA5974E5EULL,
		0x061E14045B779508ULL,
		0x6930066B0BA6B542ULL,
		0xE07DAC75FE8F02CDULL,
		0x42D80C7290AE85F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467A8431B0F95993ULL,
		0x6FD66FCF4B7FE9F6ULL,
		0xD719A7BE969FD033ULL,
		0x7E95FAB271764EA8ULL,
		0x9A3110191DBF7F26ULL,
		0x8A48D1C50590F2EFULL,
		0xDA3EC3827E86578FULL,
		0xA3C4557FE4FEA7FCULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3775ED1C8837602ULL,
		0xAFE88679ED5E3436ULL,
		0xD018AA6C8CE1548AULL,
		0xAB2CA5E9E583A89DULL,
		0x131C1D75FAB3BE56ULL,
		0x2C3F02DAD52757DBULL,
		0xCAAA05B5E16B96C1ULL,
		0x9D5FE204EFCE97B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3775ED1C8837602ULL,
		0xAFE88679ED5E3436ULL,
		0xD018AA6C8CE1548AULL,
		0xAB2CA5E9E583A89DULL,
		0x131C1D75FAB3BE56ULL,
		0x2C3F02DAD52757DBULL,
		0xCAAA05B5E16B96C1ULL,
		0x9D5FE204EFCE97B4ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0C36AD2D5F7CFA1ULL,
		0xE11030C51DC47E82ULL,
		0xF126201ED03B579BULL,
		0x86F8C07988CABF74ULL,
		0x12DB2D37F2645112ULL,
		0x5C6A3A64204E9A1DULL,
		0x46438C1E2EEC6054ULL,
		0x09A1770D395C741EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1401FB0C5DED53A5ULL,
		0x2774821D31077D4BULL,
		0xE0901A8935B3AC3FULL,
		0x574D49D57950C742ULL,
		0xEEDD32D22808D53EULL,
		0x15A09720E0D4DED6ULL,
		0x2200D573B867C185ULL,
		0x18CFC558CDCBB00BULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D99535CCCDB8B7DULL,
		0xBB1647EE015CF8BFULL,
		0x894B475975D18492ULL,
		0xD0E52153FCBB952AULL,
		0x4E78EDE30AAE1864ULL,
		0x9334033C11F0E098ULL,
		0x6A38BA4A771F3EF8ULL,
		0xC1AC26687CBFB907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64FB7A65622D0053ULL,
		0x796E27056E62D83CULL,
		0x16F5119D0C9FD129ULL,
		0x3968950E442F7B2CULL,
		0xCC549CA072F25DB8ULL,
		0xD814AC00F6F083F3ULL,
		0x9C790F68D466EB01ULL,
		0xCF15475053AD9A0AULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x229CD0FFDBC3BACFULL,
		0xECA2ED4495875852ULL,
		0x5F4C62EFB52EACDCULL,
		0x6DBD062E0190A32CULL,
		0xA1FF29D4C21E44A0ULL,
		0xD1F5454D76B93CC7ULL,
		0x25C63A25A476E68CULL,
		0xFB928D97AE58E7D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4957B0FF1324CC2ULL,
		0xD1DB57DB35917AC8ULL,
		0xCC7E31C8205A1CB5ULL,
		0x0FF17080E2C63A47ULL,
		0xC8DFBAE0BA436530ULL,
		0x11B0AFD931358A85ULL,
		0x9D6C1C148CAF36DDULL,
		0x9B6DD46A5874FD1FULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x461DFB547DD484BBULL,
		0xF46561E7CF42A72DULL,
		0xF2A5E4A641978044ULL,
		0x577F9C4E12684B4DULL,
		0x1C11C8BCC7520EACULL,
		0xC7C45F72E27E6869ULL,
		0x669A332B1B9A9E00ULL,
		0x5335AF0E79A5CB1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x461DFB547DD484BBULL,
		0xF46561E7CF42A72DULL,
		0xF2A5E4A641978044ULL,
		0x577F9C4E12684B4DULL,
		0x1C11C8BCC7520EACULL,
		0xC7C45F72E27E6869ULL,
		0x669A332B1B9A9E00ULL,
		0x5335AF0E79A5CB1CULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x979E75E714D1FD61ULL,
		0xE8050C130336B66FULL,
		0x4605EB8B5597BA93ULL,
		0x22D3CDECAA2BD693ULL,
		0x725A71F8B4B4EF0EULL,
		0xE291C96DB1405A2DULL,
		0x5D4DF652702FA58AULL,
		0x77E5A88132443832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CC17F4A0736C36CULL,
		0x430309CA59DFDBDAULL,
		0x988BBBBB48AEF6A0ULL,
		0x8418521C73DEF954ULL,
		0xDBAFD7D255611FBBULL,
		0x8015738DEEF96664ULL,
		0x3AC0F998836B7EB4ULL,
		0x355912AA8044FCE4ULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD051FD52693FB0F4ULL,
		0x455CE01AD25A61F6ULL,
		0xCEDEBCEFA8D1CAA8ULL,
		0x941EDBD1DC8FD686ULL,
		0xFE28A72DFAC772E3ULL,
		0xD8265CDC8FBC53AEULL,
		0x854B4CB81753B9BDULL,
		0x2B629B60F5CEEB71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A64CA1B659574FULL,
		0x72E5C4A873A69C8AULL,
		0x4937C2E16D0B3726ULL,
		0x9F26FB27EE5AA969ULL,
		0xD13F2732B161FE3DULL,
		0x826AA467170EF859ULL,
		0x0A9DB3D87E9B094FULL,
		0x63404930FA728A20ULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x812B97365EE09646ULL,
		0x4261CB1B350D48F0ULL,
		0x9AAC9F3B65D873BCULL,
		0xB4D594246A0D0375ULL,
		0xA62CF06D85183365ULL,
		0x4ABE08D2D30EA0F2ULL,
		0x489314B3C38049F3ULL,
		0x1A94AB5EFAF72004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C5FDE739CCFB3AULL,
		0xCF30B553F0F19BDAULL,
		0x85FDBA23C023BBAEULL,
		0x7BA065145FC09F8EULL,
		0xB2F4387BCFCC189CULL,
		0xC5417767C026564FULL,
		0xC1A861B057027F64ULL,
		0x1CC2B906F4A07FBFULL
	}};
	t = -1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F36D3548C26F824ULL,
		0x47742484CB959CF5ULL,
		0xA588DB0B97AEEFD1ULL,
		0x395B795789F2C00BULL,
		0x9EA98939A07128B5ULL,
		0xAA81E5477EC54A9BULL,
		0x04647A42C276B355ULL,
		0xDDC037319D9886FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F36D3548C26F824ULL,
		0x47742484CB959CF5ULL,
		0xA588DB0B97AEEFD1ULL,
		0x395B795789F2C00BULL,
		0x9EA98939A07128B5ULL,
		0xAA81E5477EC54A9BULL,
		0x04647A42C276B355ULL,
		0xDDC037319D9886FBULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFF3513279079FF9ULL,
		0x80B1CDB56064B76BULL,
		0xD625F6F0BBC6E901ULL,
		0xB419CB739632D8FEULL,
		0xFC8A603FFCBEB95FULL,
		0xECAC53E24BF03E3EULL,
		0x94895E6D1CB65B3BULL,
		0xDBE4AD4DA8A804C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x812FF6CB87D2C0DDULL,
		0x335A38B6E651C641ULL,
		0xD9032451A581BB46ULL,
		0xEA9FE6BA4C9AB532ULL,
		0x68E1A19FD80B070AULL,
		0x51D59D700DA769BFULL,
		0x80B9CD0755F2CDB2ULL,
		0xF0F699252A76B6F3ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21F2FC631E6B789CULL,
		0x221416BFBAD7CFE4ULL,
		0x05E3C91ED06E0DECULL,
		0x495494A5740413B5ULL,
		0xBF45425A6867C8F4ULL,
		0xE0213BB96A5685F9ULL,
		0x00E94BD3BF889E2BULL,
		0x213F825EEE7F5927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BB2A26BEB95032BULL,
		0x88BFB102D1D50AA6ULL,
		0x3F4F90ED03754364ULL,
		0x78D7F400BE93BD28ULL,
		0x1379EDFE3724EE95ULL,
		0x14DA9B28F073336FULL,
		0xB7CB7939F53F7DFDULL,
		0xF2A374C566CA973EULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0B34960D836B2E1ULL,
		0x1F730018E6B8EF55ULL,
		0xCE1BCE65C8E89906ULL,
		0x4E6370676DCA3EA6ULL,
		0x0CEDEF806CF7C56EULL,
		0xDBEC7ABBC94AD1B1ULL,
		0x3D26BD5C61268512ULL,
		0xE51CD19A905AA09EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE130C21C44169534ULL,
		0x247BC70820A9D6D1ULL,
		0x262F0D13BC64986AULL,
		0x52F1E85E308A50BDULL,
		0xEAF8C9104E80FB48ULL,
		0x36F8FFB6DAD81F37ULL,
		0x7C048CD4D46236C3ULL,
		0xB61C3DB5BCCD7909ULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x990CEECBC95C2584ULL,
		0x9CA873875A73B51AULL,
		0x5194F75DDFC07126ULL,
		0xE01E335B96896894ULL,
		0x8B588FF1E365A37EULL,
		0x08EA217218FC4897ULL,
		0xD087C55113E79CACULL,
		0xE7153A8D9CE7290FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x990CEECBC95C2584ULL,
		0x9CA873875A73B51AULL,
		0x5194F75DDFC07126ULL,
		0xE01E335B96896894ULL,
		0x8B588FF1E365A37EULL,
		0x08EA217218FC4897ULL,
		0xD087C55113E79CACULL,
		0xE7153A8D9CE7290FULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F9C0F92A75F2751ULL,
		0x9524C6A06D1AE17DULL,
		0xEF78A888978594E6ULL,
		0xB45DE39CE25550AFULL,
		0x902CF8B493EA147CULL,
		0x40A6095B10EF7C84ULL,
		0x0B832F21DF22063EULL,
		0xB995E34C1CF5E483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407554883A78206AULL,
		0xC8A15C5C16D3F030ULL,
		0x57EE462E9872C3B2ULL,
		0x3704513793062EDFULL,
		0xB4D1A50FE1343AA1ULL,
		0x1318671CCE23E796ULL,
		0x28F0B7A2A1A07D30ULL,
		0x14A799231F72D8E7ULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C95B5C28C8CAFA2ULL,
		0x5C20B5518681C8DEULL,
		0x0E2786E5858648E1ULL,
		0x095C7CFBB9520D71ULL,
		0x82C441C2F153EA97ULL,
		0x677DCDC91EEC1CDBULL,
		0xAB848323E063FB6BULL,
		0xEF01531AFF53A67EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3017D1190CB0CE8AULL,
		0xB19390FF0DFD7858ULL,
		0x06A6E63B18FDE7CDULL,
		0x8E1D6190DA0C9F95ULL,
		0xC94FC6D05EC2590FULL,
		0x029271BBE583230CULL,
		0xD02E5A20D3789057ULL,
		0xEF3F2BDA564BD9FDULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x016EDB88B82E969BULL,
		0x03D3FB504D1C447DULL,
		0xDE2AAAE99C4C908EULL,
		0x8E70D9B893344952ULL,
		0x4372B962ADE3F5C1ULL,
		0xE31654E762D15987ULL,
		0x6ACD72CF063EF021ULL,
		0xB378B2014C7719D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0563689399B3D936ULL,
		0xAE49E9FE1126A07CULL,
		0x5484839DFF343353ULL,
		0xFBF3745B3543E9BBULL,
		0x381BBE4145FC0C19ULL,
		0x6EE2C647E6C4B1A0ULL,
		0x1F89066D973AE70AULL,
		0x3F861B61716D03D1ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74B9524111C96969ULL,
		0xA1B62B911BB18398ULL,
		0xD39A8D795EE4825DULL,
		0x2322FCE1F93CF89AULL,
		0x81C26AAAADC35EFBULL,
		0xC7CCF793536EE5DFULL,
		0xE35F72A3E4034D8DULL,
		0x6CB9A2F562A92826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74B9524111C96969ULL,
		0xA1B62B911BB18398ULL,
		0xD39A8D795EE4825DULL,
		0x2322FCE1F93CF89AULL,
		0x81C26AAAADC35EFBULL,
		0xC7CCF793536EE5DFULL,
		0xE35F72A3E4034D8DULL,
		0x6CB9A2F562A92826ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x330EE33BB5BBF8CBULL,
		0xB2A24AD8BC8EFA9EULL,
		0x329FDD88A8CA3E92ULL,
		0xB1D6D785F74D59CFULL,
		0xE96A375149355F3AULL,
		0xC762DBC6AB59E91CULL,
		0x599ACA25C6C1ADFFULL,
		0xA462072A9FD8713FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x646F639EBEEDA9D6ULL,
		0x5A82F02277C41BCCULL,
		0x35B17CE4B2FA3C26ULL,
		0x8ACDCA9E91C92327ULL,
		0xF024AA4B218EC1B8ULL,
		0x0D1094BA8245A8FAULL,
		0x5832846B5A8E72A1ULL,
		0xC175A78A87498619ULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8BFA43B322B4967CULL,
		0x2FF8D1168A2B0F85ULL,
		0x7AD69128F8BD6DC5ULL,
		0x2DC76B80F6F53B82ULL,
		0x09D034FE162BE94AULL,
		0xA856161B24984D77ULL,
		0x07425D6D1C04080BULL,
		0xAAF0CB05C2E1422BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89515C146F021D5ULL,
		0xCFCE8423299088C8ULL,
		0xF039E8E10DC12F0DULL,
		0xC4CDC7A31C2B5945ULL,
		0xC9917DEED4C07BA9ULL,
		0xE89BC0B02732D2FDULL,
		0x9DC4FFD0FA31CADEULL,
		0x0DB026686438012DULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x084F14B4C2677512ULL,
		0x46561F09F1BCCF89ULL,
		0xF5C05DC283FB9DA1ULL,
		0xF7EE4580212586D9ULL,
		0x735691D84994E409ULL,
		0x33C179901802162EULL,
		0x67A97F808A6DF333ULL,
		0xDF5205DAF2B35DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735864E728A6AD3CULL,
		0xE975F202FEC62FC8ULL,
		0x82BAA33DABDCBC8DULL,
		0xC73EF033CF34276BULL,
		0x662E0A706CEA93D3ULL,
		0x5B1EBC93AC0E0972ULL,
		0xE3F1A860E6A11659ULL,
		0x21763A999A0110DAULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20618B9FE70285F0ULL,
		0x7ED0C5CA22A014C8ULL,
		0xAF5DC170B4395270ULL,
		0x9C32B4A7431B8AD8ULL,
		0x695F8D8771219B1DULL,
		0xC3395E15EBF62D34ULL,
		0x691816750FBCF1DAULL,
		0x9733E77B995E5336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20618B9FE70285F0ULL,
		0x7ED0C5CA22A014C8ULL,
		0xAF5DC170B4395270ULL,
		0x9C32B4A7431B8AD8ULL,
		0x695F8D8771219B1DULL,
		0xC3395E15EBF62D34ULL,
		0x691816750FBCF1DAULL,
		0x9733E77B995E5336ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD290874C65CA746ULL,
		0x8E36DE2C159079C7ULL,
		0x5F56D7A073F4960CULL,
		0x1F2A999DB3DD212DULL,
		0xA4FFB4E2BFC58226ULL,
		0xEC70AA5808AC25A3ULL,
		0xC3B59671060D8780ULL,
		0xA863D0C7C7FA7C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12680C0DBC14225AULL,
		0x659CB4FB8D4017DFULL,
		0x82945AC91B720985ULL,
		0x7ED637A9DF3E8C28ULL,
		0xC4FDD35B1F2A776FULL,
		0x35076AE8B6A32007ULL,
		0xD774F4A550DD549FULL,
		0x795802B31D8388F7ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97FBE143439FBBA1ULL,
		0xAA987AB1A047712BULL,
		0x77C8D61BA58BA5E8ULL,
		0xBF3B2C98A048CB1CULL,
		0x84A0F719D007B3F8ULL,
		0xC666842C60498E74ULL,
		0xA992612EDA011685ULL,
		0x85B7EE5549A9C142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x387AD6825A2AD393ULL,
		0xB2E1D6E91898EACFULL,
		0x30C6A9A0784FD50FULL,
		0x3B6DC4DF708520ADULL,
		0x1198DD301A048D61ULL,
		0x255137BA02826BD6ULL,
		0x7ADBE185A1EA01DEULL,
		0x5ADD18FD8B400F1FULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC133711D59B977CULL,
		0x4E9604D594451C4EULL,
		0xE957DC602E02E5E6ULL,
		0x3A09908C51081B31ULL,
		0x7E012656E5C67059ULL,
		0x7D64E15692734834ULL,
		0xB44BBB2AC82EC051ULL,
		0xBF17AF9A368F39F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF306B2581E2F051ULL,
		0x39974FA5FFE0A09EULL,
		0xA17CD29C2CE98FB8ULL,
		0x1894637F65285453ULL,
		0x803F507F74B4B8C8ULL,
		0x59E4BB935C587B54ULL,
		0x1F7AA501DD09AC5DULL,
		0xCF2DAE6897491D9CULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD0CDF1247CDE5B0ULL,
		0x20F92428192CB7F0ULL,
		0xBC77F36C26885BEBULL,
		0x41579C551AC083D7ULL,
		0x8E6422B2284714AEULL,
		0x1F8487F3589D56AEULL,
		0x68985595B5AA2BE8ULL,
		0x5A8D1BB1BE59EB9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0CDF1247CDE5B0ULL,
		0x20F92428192CB7F0ULL,
		0xBC77F36C26885BEBULL,
		0x41579C551AC083D7ULL,
		0x8E6422B2284714AEULL,
		0x1F8487F3589D56AEULL,
		0x68985595B5AA2BE8ULL,
		0x5A8D1BB1BE59EB9DULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A3D0ED2BF99CC75ULL,
		0x4C3BFF5A78A990B1ULL,
		0xB483EF774BAE2C63ULL,
		0x9967E80216A8A24FULL,
		0x457818459332E2C4ULL,
		0x1D455D26B5725120ULL,
		0x7EA528C2C317E092ULL,
		0x09C201AE205A13AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC3EA9AC211D91AULL,
		0x8D9DC6402877E242ULL,
		0x2E4630AF665C31DFULL,
		0xFE7CA14B470EECF8ULL,
		0x746A9E7C62F15C89ULL,
		0xF14C41F714F606CEULL,
		0xE2B25D55054155E6ULL,
		0x372B50B4DABEE8E5ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8848FBAD48F8526ULL,
		0x8BF63D0D0E7B3B9BULL,
		0xB5C35F6096C22708ULL,
		0x536279F54406486AULL,
		0x816CB4860B5543D0ULL,
		0xE9795F0603C1F2FCULL,
		0x2EAE6CDBA8FAD705ULL,
		0xC848DEC5FE411A00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F418C8DC699D172ULL,
		0xF6B74A140D309C43ULL,
		0xF3BFDDEDC01870FFULL,
		0x559F778575B6B8B3ULL,
		0x999881D1FBE7A819ULL,
		0xB06CFCBB2FF6FA7FULL,
		0x56D3B4D99082B150ULL,
		0x5E67328C9D8D5243ULL
	}};
	t = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8028BC23C6562F42ULL,
		0xEAF00AD095AB5121ULL,
		0xAC2467FFD1940844ULL,
		0xDB4F196444BC880EULL,
		0xAB8D31F1B65D79F1ULL,
		0xF2A2D3F52B721CB4ULL,
		0xD85FD8F4489AB3B8ULL,
		0x2379BE647A1FAF17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2600716B23141019ULL,
		0xBAA100CBB9031B63ULL,
		0x70E1C1631E559E17ULL,
		0xF649534E28DBA272ULL,
		0x097ADACB1924286DULL,
		0x2FA53796F452E5DCULL,
		0xF3670D1BA5334C58ULL,
		0x7804E8E26703C608ULL
	}};
	t = -1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47AE57B11638F0BCULL,
		0x1C7315BBF8BAA334ULL,
		0x8B38E1313FC14FD2ULL,
		0x2E815BC1D72A8365ULL,
		0x012348074A5E2235ULL,
		0x3B3980A9F52DE43AULL,
		0x4C43C5C03EF221BFULL,
		0x78944659847DB325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47AE57B11638F0BCULL,
		0x1C7315BBF8BAA334ULL,
		0x8B38E1313FC14FD2ULL,
		0x2E815BC1D72A8365ULL,
		0x012348074A5E2235ULL,
		0x3B3980A9F52DE43AULL,
		0x4C43C5C03EF221BFULL,
		0x78944659847DB325ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BBC03D228F4D54CULL,
		0x91364F9808EAC9A6ULL,
		0x4EA71C99C5798DE2ULL,
		0x640E4D0D8878B947ULL,
		0xA4744AF8EEF36446ULL,
		0x5EAA18FDD9754580ULL,
		0x6099C9F73CDE47D2ULL,
		0xBCEFF13D3A2678F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x776E4A1B348E19A6ULL,
		0x16F2819E2D6C12B7ULL,
		0x36ADCB1831702973ULL,
		0xEE7AD5FD1B5F83FEULL,
		0x380D243952164711ULL,
		0xF0C0BF743F59084AULL,
		0x6B11ECEE6DDE3F95ULL,
		0xE75BFD15F578E2F8ULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27CCAF952E567C6CULL,
		0x9E82BD6FC2AC4B7EULL,
		0xE60A3DD29653BF9EULL,
		0x03A5CA2184CD3B50ULL,
		0xEA701BDF49D948D3ULL,
		0xA2223830A68BFD23ULL,
		0x591AC9E14283469AULL,
		0x803B7C6BDEBE54D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088741CE5C16B9D2ULL,
		0x5BB9DE59DC1745B8ULL,
		0x29B8F2E2B17007CDULL,
		0xA8EBA01851C46CC7ULL,
		0x4FCAA29338540E4BULL,
		0x6DD184FC3F705CA6ULL,
		0x57E51BFF6986C312ULL,
		0x4421310610EA1DB7ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1D422CF804B3EACULL,
		0x13DE5D1A1CE77811ULL,
		0x9756247E892EE3B5ULL,
		0xFC7D515468FAE93AULL,
		0x3BD5BC8D46F8A67FULL,
		0xE7D3E3635536EE1CULL,
		0xEAE3841D9C904A69ULL,
		0xBB40B01245612D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x609EEFB859C5CEB0ULL,
		0x72E6E27CBC9D6D82ULL,
		0x10703AEAFA94B60EULL,
		0x6B27B696DC547128ULL,
		0x99B73A6604116E6FULL,
		0xF29C1AC73FECF397ULL,
		0x656DBD3406F8414BULL,
		0x84F7ADDFEDC82FF9ULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E3169E83AE9DBE2ULL,
		0x1835839965483338ULL,
		0xD40365C20C8D1F2BULL,
		0xA358395D40E91298ULL,
		0x168E4907DD90BA8CULL,
		0x4102E447CE7E283BULL,
		0xA6C1B61C7A9E8E28ULL,
		0x25DDA2F25AA4E5D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E3169E83AE9DBE2ULL,
		0x1835839965483338ULL,
		0xD40365C20C8D1F2BULL,
		0xA358395D40E91298ULL,
		0x168E4907DD90BA8CULL,
		0x4102E447CE7E283BULL,
		0xA6C1B61C7A9E8E28ULL,
		0x25DDA2F25AA4E5D9ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF566E5D6F2A0C70ULL,
		0x6377B38FFCFB1D33ULL,
		0x7EA0F26BC2592CEEULL,
		0xC6FEDE385A1B1A8DULL,
		0x32E2BA5C054A4ED6ULL,
		0xA291170D0515FC4CULL,
		0x1409211A47D46B2EULL,
		0xC6215FFA1A577801ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E1451EB9AD99A8ULL,
		0x2CF0BF285BF34A0EULL,
		0x6F00FC1D26F31D57ULL,
		0x1CF6692C53A5A04FULL,
		0x84C2D15E1791A89FULL,
		0x633A13571BC35ED0ULL,
		0x8A1AA2183C008CD6ULL,
		0xF199A645418A402FULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFA747D301F8DFD4ULL,
		0xB96CBCF5E0F712ECULL,
		0x6E55AB9C92287AA3ULL,
		0xEE0A2D3C422C7165ULL,
		0xC469E9446BC479CFULL,
		0x6A7EC9B49D5C80E6ULL,
		0xF223205E9A582251ULL,
		0x8A1BFB50B83FB951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACCDFDBE6636CE47ULL,
		0xB9A8FD712584FE40ULL,
		0xE179AB3BE2EF7621ULL,
		0x1E327D12F0A26659ULL,
		0xBDF74B6043102189ULL,
		0x0E6DE9A1E78FBCE7ULL,
		0x9ACA6A587B036F6BULL,
		0x238B1392BC5E49C7ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CBA62F5412CC5ACULL,
		0xC6F2724C988EFDBFULL,
		0x377B9E798EE5E38EULL,
		0x5EE7F389CEE0B52EULL,
		0xA1D8BB16F3EF3009ULL,
		0x8850618A97D5C166ULL,
		0x38F5C11C6ADDE136ULL,
		0xBA7E6732848A4218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90BC8CA530EA1DB7ULL,
		0x947B16A7E01C2C9AULL,
		0xDB412DBEC7D33B2FULL,
		0x9B5D70E24F897871ULL,
		0xDE00E9BA2385B3A4ULL,
		0x78C0BBE2FA93914DULL,
		0xB0948FFC4FBE1669ULL,
		0x64C7303698026D71ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0F461D39E90FD89ULL,
		0x62532E417122ED76ULL,
		0x644862B9625F1B49ULL,
		0x6DA5E53D46004113ULL,
		0xB1BB38228E5D5628ULL,
		0x15927C5E433C8E23ULL,
		0xD31ADD37492A6691ULL,
		0xEA91E430BF3FB712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0F461D39E90FD89ULL,
		0x62532E417122ED76ULL,
		0x644862B9625F1B49ULL,
		0x6DA5E53D46004113ULL,
		0xB1BB38228E5D5628ULL,
		0x15927C5E433C8E23ULL,
		0xD31ADD37492A6691ULL,
		0xEA91E430BF3FB712ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E87E659019D4A4FULL,
		0x349F5692F84D7C58ULL,
		0xB655A0AAA8AB81C1ULL,
		0x95DD5A19685888C6ULL,
		0xA40A1ADD55784AAFULL,
		0xBF4647F5C0E719C7ULL,
		0x7CF89DD3740F99FAULL,
		0xF548E50911425F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB170B862BB66B098ULL,
		0xF4B797C6F752E18CULL,
		0x7730C1AE566B54FBULL,
		0x3DE7E2886279A958ULL,
		0x251BB2D1A628EAC3ULL,
		0x2983987223039D65ULL,
		0x78EB25801ADC94C8ULL,
		0x9BEEDFFC7B226895ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69ACBEF9BF94C511ULL,
		0x282B6A8384522EF2ULL,
		0x8E39C241C699DCABULL,
		0x7570FFAEEEBCBD0AULL,
		0x48CDE0EF53FCD211ULL,
		0x6F94428DC3FF867FULL,
		0x6078C79E2125DE21ULL,
		0xB7CC77F2C902BB55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2461E03F93BACD91ULL,
		0x945083F361437195ULL,
		0x7A11BF69021AEBC0ULL,
		0x8A67C804F24817E3ULL,
		0x919C63CDA6FFE5C6ULL,
		0xF727D276E848A1B4ULL,
		0xB2243147FB338972ULL,
		0x0781A296BC63C4B6ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x883702FA6F587AA8ULL,
		0xD001BD0385BDA92BULL,
		0x5F94CF7B0A2073C9ULL,
		0xB03445F83D9932A9ULL,
		0x8428B08835DEE883ULL,
		0x0E2235340DE82C82ULL,
		0xDC41E20B058691D7ULL,
		0x06E5CFC5EBEBF8B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8158A7BAF3EDBE6ULL,
		0xB9C0E565BBAE3419ULL,
		0x42CDEA4164A125CEULL,
		0x843BF00812A394ECULL,
		0xB86A518C91ABCC75ULL,
		0xA63953FAB16F79DCULL,
		0x566178388B84FB46ULL,
		0x782609D76F4C6DFCULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2372959061D8E271ULL,
		0x0C51EDEFD73FB864ULL,
		0x95FC5EA9D5E731E5ULL,
		0xDB5EA1176C9AD5D9ULL,
		0x175417FE96F859CDULL,
		0xA970B1AF2A70A866ULL,
		0x2B6BD9C2859AF20FULL,
		0x4D55E3EC67D4FAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2372959061D8E271ULL,
		0x0C51EDEFD73FB864ULL,
		0x95FC5EA9D5E731E5ULL,
		0xDB5EA1176C9AD5D9ULL,
		0x175417FE96F859CDULL,
		0xA970B1AF2A70A866ULL,
		0x2B6BD9C2859AF20FULL,
		0x4D55E3EC67D4FAC3ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2D4A2368641A085ULL,
		0x4C486A1DBE40867DULL,
		0xC734CA6665619C1DULL,
		0x170C6AF8598095C0ULL,
		0xD1094FF2338D8191ULL,
		0x1382EF8A9A31CBA6ULL,
		0x9AC5D642F9780FF5ULL,
		0xA3E37D551DF9C367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FCA74B110DC22B6ULL,
		0x26213887378D0CB7ULL,
		0x64460B7E2B3BE1F7ULL,
		0xB668FCBC0AF8058EULL,
		0x647844958B9A2392ULL,
		0x989E7361AC1B934BULL,
		0xB0630888AB73EEADULL,
		0x5925B467C797A50AULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA9FEF0A2EEFDB56ULL,
		0x58B46344014A0703ULL,
		0xBFFF4B2595CA9368ULL,
		0x39FDF3B8997781AFULL,
		0x80E11BDC3E5F7052ULL,
		0x3036A864B2ABBB24ULL,
		0x721EBF338BC4F781ULL,
		0x8DF40D71BA74FAA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85687E4623636EB3ULL,
		0xCA8F98D476B903BBULL,
		0x67CE76172DB27DBCULL,
		0x12A262E7B3830497ULL,
		0x6285382FD136C648ULL,
		0xD56EE3B31013D9BFULL,
		0x221829C62B1EC6A8ULL,
		0x8AEF6769572190BCULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A915BE6A1A16ACCULL,
		0x9A70CCFA6B333662ULL,
		0x28FFB93865647978ULL,
		0xBB7ACC1710898E8CULL,
		0x0AE6C8D0A8E233B6ULL,
		0xA6C44A6A27C0613CULL,
		0xAFA05C38C606D7F5ULL,
		0x8F2BE25FF80889A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07AA0066804E7A7CULL,
		0x264DBA286B342CE4ULL,
		0xB4F0C637CFCBD457ULL,
		0xFBFE59D1842B2C18ULL,
		0x1316DB67E876A085ULL,
		0x507C43CBBD836C76ULL,
		0x514B4E058F0C5E3AULL,
		0x2BA4B4D3433FB0C3ULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03C74DEF38F13DBFULL,
		0x470BB0C7F875D025ULL,
		0x0C07D5EB4F43864CULL,
		0x8A4A00F7497DBE10ULL,
		0xBA57BC6D9F454EB7ULL,
		0xA4D9E2DD0395A8A6ULL,
		0x9788F1DBC48EBC88ULL,
		0x559316540697E7D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C74DEF38F13DBFULL,
		0x470BB0C7F875D025ULL,
		0x0C07D5EB4F43864CULL,
		0x8A4A00F7497DBE10ULL,
		0xBA57BC6D9F454EB7ULL,
		0xA4D9E2DD0395A8A6ULL,
		0x9788F1DBC48EBC88ULL,
		0x559316540697E7D8ULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6695761106558DFULL,
		0x1FB0E93C5AD6A1A8ULL,
		0x5E330A37C548C5DFULL,
		0x77EC7FAC679DD64DULL,
		0xF3BC323A72723029ULL,
		0x473950FB89624231ULL,
		0x8DCD3F1F9820BA68ULL,
		0xBC4CD570B249538CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA933CB52E87EFB92ULL,
		0x9967E27AA61ED537ULL,
		0xBE821210488B9344ULL,
		0x26B123282DFD2707ULL,
		0x020E06BDCE351807ULL,
		0x24F30251A558F02EULL,
		0xBD54423B31572447ULL,
		0x62EDBF26C25CBC83ULL
	}};
	t = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C80E2C9F52C4722ULL,
		0x44684C58966E7171ULL,
		0xF72447AB8E18B370ULL,
		0xFE4BBDA385B9F4D5ULL,
		0x11AA21E4291DCCC2ULL,
		0x5733E680BB0A0767ULL,
		0xBC36F2655CF02F48ULL,
		0x6A42908D1A8CC7D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A699F7F5E6FA4D4ULL,
		0x0BEEC482D8032C03ULL,
		0xBFC211D2A260971DULL,
		0x4A41488CFA882FACULL,
		0x60054E380FD2E546ULL,
		0x72AC14B2CBCDE11BULL,
		0x096B3E5CC09FA000ULL,
		0xC731D105FED1B21DULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE18269573F8C93BFULL,
		0xBBC89D1C2624B1A6ULL,
		0x13041AD992E85B97ULL,
		0x18AD746BAE6A5C71ULL,
		0x829A03CCF62C6B4AULL,
		0x899F87C6FEE6E39DULL,
		0x808826A5259463E2ULL,
		0x9469F1B15874BB3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E50BE651345A24ULL,
		0x3C05CC47421C0136ULL,
		0xB635DE1F0DB4920DULL,
		0x02043F4E52E57894ULL,
		0x857F293F492C8017ULL,
		0xB25E0C58EE041BD1ULL,
		0x4D15A82DCF3C6C2EULL,
		0xF6F2D8CCDF753665ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x979C347987917B80ULL,
		0xC4E031AE3750ED9AULL,
		0xB318C13736806432ULL,
		0x1C33EA0184F73BB5ULL,
		0x68E824ED3BDAA162ULL,
		0xCD4E0F15F0EA9F77ULL,
		0x629C87D23A28EFA9ULL,
		0x649DD6544212AB41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979C347987917B80ULL,
		0xC4E031AE3750ED9AULL,
		0xB318C13736806432ULL,
		0x1C33EA0184F73BB5ULL,
		0x68E824ED3BDAA162ULL,
		0xCD4E0F15F0EA9F77ULL,
		0x629C87D23A28EFA9ULL,
		0x649DD6544212AB41ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC48D0573367C72EFULL,
		0x4D06B8FB3E23327EULL,
		0xFC5D9292969D1793ULL,
		0xA3F3076554F4FAECULL,
		0x67EE58C756283D84ULL,
		0x49404764432328E4ULL,
		0x05CB45E6EC19F377ULL,
		0xD4C452B427DC8A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x078A683A0E0E3FCDULL,
		0x7AA8B544A2E98F58ULL,
		0xD0124AA93EE9468EULL,
		0x9A65F45B425F6F84ULL,
		0x2056CA62E6A6362CULL,
		0x23AB5D72AE98BCFCULL,
		0xF35F79D95344C705ULL,
		0x6D4540DC4EF85224ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x339F3D8D0CA2DA5FULL,
		0xD23727A15EF36EBCULL,
		0x2329E0F6C24E3097ULL,
		0x1994A6A25BE7310EULL,
		0x5EF23D667DAA8C9DULL,
		0x66CF1044951FBD03ULL,
		0x0F16268FF15770BFULL,
		0xF84BAFF04D9DE13BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBE176C8AEABAAEEULL,
		0x108396797977AA7EULL,
		0xC967E9BBD07EA8CFULL,
		0x722825C665AEF87CULL,
		0x5E1E137DC1A1CB16ULL,
		0xD635E8F35DC898D7ULL,
		0x79BB337F6FE41249ULL,
		0xBDF4AEA4F819C37AULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC483F0CCFD157ACULL,
		0x34B8E4220444D109ULL,
		0xC98D71223E3574FFULL,
		0x44CF288F43227522ULL,
		0x9C5BDD954455C6E8ULL,
		0xE4E934230321228CULL,
		0x5460F13360E9C119ULL,
		0x5ED5174851F496BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE2E46EDF06F7D04ULL,
		0x21AB2400B2AD3BE7ULL,
		0xDB0275A8EAD5BF8FULL,
		0x3C26EABA07E67971ULL,
		0xC1101CD09887E77EULL,
		0xD25F16A920CF22CAULL,
		0x6830236602F225BEULL,
		0x4851F45ACC2D2907ULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
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