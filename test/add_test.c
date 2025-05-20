#include "tests.h"

int32_t curve25519_key_add_test(void) {
	printf("Add Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x9FE20A6BEC28B086,
		0xF09C5677ED85B71A,
		0x3BCAF5EB3F857EBB,
		0x1C3253647FE42A80
	}};
	curve25519_key_t k2 = {.key64 = {
		0xDB831E7B448F2158,
		0x3FE4EAA8CD929E97,
		0x7D9D8C2CBB89A774,
		0x4EEFC4FEBD23BD6C
	}};
	curve25519_key_t k3 = {.key64 = {
		0x7B6528E730B7D1DE,
		0x30814120BB1855B2,
		0xB9688217FB0F2630,
		0x6B2218633D07E7EC
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x263041550BB5CCA1,
		0xEE35971D9DF06ED7,
		0x59C6776F48CAA382,
		0x3B65F89B56E3628B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28294EB0BC94CBD2,
		0x86E90D6CEF6C959E,
		0x41B24E31E2256029,
		0x3020CCD344C221E3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E599005C84A9873,
		0x751EA48A8D5D0475,
		0x9B78C5A12AF003AC,
		0x6B86C56E9BA5846E
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A8C8004A740B557,
		0xAA23CFFB79D2272F,
		0x64CD2A4115EE2ACF,
		0x06F02A020D69FA04
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x790D55DD66202B52,
		0x75F4E60937A28F58,
		0xDA1E45F4652520E1,
		0x3FB4ADC9F2A9616D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD399D5E20D60E0A9,
		0x2018B604B174B687,
		0x3EEB70357B134BB1,
		0x46A4D7CC00135B72
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7AB38AC0EF43F6C,
		0x1FB61E9369C20886,
		0x10579F1F14BD63A3,
		0x1BD85C73A768D8B1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x270942C7020BE13F,
		0x82FE1BE56A545E6B,
		0x28A7EDC09579EA8E,
		0x38A7BA6BEF4B7508
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEB47B73110020AB,
		0xA2B43A78D41666F1,
		0x38FF8CDFAA374E31,
		0x548016DF96B44DB9
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01F9FE56F8450288,
		0x0F43CC2912EBA0C0,
		0x8ADE7D6FC158DEEA,
		0x525B6913C10AEC2B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC204BC469513E03D,
		0xC9D7BBD468A5D870,
		0xADE05E4CC286854F,
		0x1FE9F2232399D170
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3FEBA9D8D58E2C5,
		0xD91B87FD7B917930,
		0x38BEDBBC83DF6439,
		0x72455B36E4A4BD9C
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3017E5D7A3E7A358,
		0x7604A9239944454D,
		0x374B45CFA068E1C2,
		0x669E584D4A5A01E9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFF4FBDEF517D62B,
		0x8432128DC1DE81A9,
		0x8651490039E1DE4B,
		0x69FB6EDD2D203760
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF00CE1B698FF7996,
		0xFA36BBB15B22C6F6,
		0xBD9C8ECFDA4AC00D,
		0x5099C72A777A3949
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01ACD05B6437657C,
		0x90B04047D35B59D2,
		0xAA378E0EE46CB1DC,
		0x4418B5FCC874BCCC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21D707F6A2117FD5,
		0x2B30CAE2B67E52B0,
		0x53CAEB17C4FF4FF8,
		0x4C37836E23E86810
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2383D8520648E564,
		0xBBE10B2A89D9AC82,
		0xFE027926A96C01D4,
		0x1050396AEC5D24DC
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x436933EF5D835E1F,
		0x52CDC0A51A6C0A94,
		0x492C1E38343E26F2,
		0x2A90DE32D8C7F469
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B49E299FA54466A,
		0x684BE3F13E97C0AF,
		0x87DD66774EB06DD5,
		0x17F3D8A7EBB40754
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8EB3168957D7A489,
		0xBB19A4965903CB43,
		0xD10984AF82EE94C7,
		0x4284B6DAC47BFBBD
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAAA674173135065,
		0x8E2672D640BB20DA,
		0xF1706A77D4F93E54,
		0x65BAEA19C11F669A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE697946A7746BB3,
		0x00CB267783D6A313,
		0xF172F40548A36B75,
		0x57DD7816170316EB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5913E0881A87BC2B,
		0x8EF1994DC491C3EE,
		0xE2E35E7D1D9CA9C9,
		0x3D98622FD8227D86
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EF65255E8ACBDA2,
		0xB44285B0D6203C52,
		0x72262FDC1DA9A0B2,
		0x1BAF6E4A9B3BA134
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB43FD4C19954962,
		0x18D9CA3136156A1F,
		0x4C3F7CB70EF8BB53,
		0x3BBC35F2144FD5F4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA3A4FA202420704,
		0xCD1C4FE20C35A671,
		0xBE65AC932CA25C05,
		0x576BA43CAF8B7728
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7BCB9EE6C823C15,
		0x46CF87EEE7378FCE,
		0xE397D12C8EE7BA17,
		0x202AD48350F32C3C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC602D3D524FD7319,
		0xDFCDD4A108A1350E,
		0x3B2DBA631263C091,
		0x6F9173FD90A379DA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDBF8DC3917FAF41,
		0x269D5C8FEFD8C4DD,
		0x1EC58B8FA14B7AA9,
		0x0FBC4880E196A617
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA699A3ABB02CDE71,
		0xE2B64EBB80C2D83C,
		0xC833878E97CE5111,
		0x7E74F08C81420BB9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25F43D52843E2DE0,
		0xBC18C0946A9A963B,
		0x81461E219DEB27F1,
		0x05299A997AA8C51C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC8DE0FE346B0C64,
		0x9ECF0F4FEB5D6E77,
		0x4979A5B035B97903,
		0x039E8B25FBEAD0D6
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD31465CAC5DA287,
		0x4F310D5A2A242025,
		0x917F1BDC521C7446,
		0x09EF6708E767C752
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x556D01063D4C9333,
		0xCC04D759AA624FA1,
		0x7302C241B693F16B,
		0x020E3F1D8FEB3199
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x329E4762E9AA35BA,
		0x1B35E4B3D4866FC7,
		0x0481DE1E08B065B2,
		0x0BFDA6267752F8EC
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x464872C5959FBB1A,
		0x0CBAD9ACD42C723E,
		0x824EBC2C1E696126,
		0x0B54D17E849E407F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97F93D3E3D6E11E,
		0xD11310BF96B5CD5D,
		0x1785C2845B1129A6,
		0x4CAAED6F22CA4326
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FC8069979769C38,
		0xDDCDEA6C6AE23F9C,
		0x99D47EB0797A8ACC,
		0x57FFBEEDA76883A5
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA88481B06E91EF7A,
		0xED527FB555C4B6E0,
		0x1DC8049DAC8F335F,
		0x6186F56D12CE0032
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA76DCC3EBD164C0,
		0x242D8A4E5458D32C,
		0x07A79348362D19D2,
		0x26A996837BC76D34
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72FB5E745A63544D,
		0x11800A03AA1D8A0D,
		0x256F97E5E2BC4D32,
		0x08308BF08E956D66
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ADE04F872164715,
		0xDAA220D89395A98B,
		0x9FC74A4E585D6FE7,
		0x2AB2C13AE3CA3AB7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32AD917507A9949B,
		0xA7A55B992145906D,
		0x7707FE75897966BC,
		0x634F8E50661E966E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D8B966D79BFDBC3,
		0x82477C71B4DB39F8,
		0x16CF48C3E1D6D6A4,
		0x0E024F8B49E8D126
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8BA0F4DC33301B9,
		0xD36D487E4305109B,
		0xD0176CA6660F37F5,
		0x3EEC6F70FD7B0B1B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFBCE5C3DCD77A98,
		0x697392E59AACA67A,
		0x76E04B442CB3CD8B,
		0x43BC0E4D8B82ABB6
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8876F511A00A7C64,
		0x3CE0DB63DDB1B716,
		0x46F7B7EA92C30581,
		0x02A87DBE88FDB6D2
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98A03086CBD3250D,
		0xB7692FC1E6400F3D,
		0x5F4F4F02D0A60ED0,
		0x6734BA1453DFF995
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80461E6805A854D4,
		0x16BC5F51C147F31A,
		0x71CEC805B9CFA1A0,
		0x77042B6829C00FB5
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18E64EEED17B79F4,
		0xCE258F13A7880258,
		0xD11E17088A75B070,
		0x5E38E57C7DA0094A
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17CA78C4D695E189,
		0xC66AE82982847D0B,
		0x98913D5FD59325DD,
		0x00C84C4D82AF73CC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5703A4C65404D1D0,
		0xFD81D34A0BC9443A,
		0x989D2E9F0C7E0C8B,
		0x14C110EA8BC07467
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ECE1D8B2A9AB359,
		0xC3ECBB738E4DC145,
		0x312E6BFEE2113269,
		0x15895D380E6FE834
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6349040FA0529D0A,
		0x873421AB62729413,
		0x007FD5132AC7C6FC,
		0x018EA9D3CBF6FD2D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C61C87506CB73B,
		0xD39EA0E99974BA44,
		0x71CEF8C22BD0A5EA,
		0x29F3A40253BAB5AB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B0F2096F0BF5445,
		0x5AD2C294FBE74E57,
		0x724ECDD556986CE7,
		0x2B824DD61FB1B2D8
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80A666C41815C648,
		0xD39CC0146B45286C,
		0xD30D3F1F53ABB77E,
		0x63BF55EFFD0855D2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F6252E9A4168ED,
		0x572BAE31FE7EA8F3,
		0xBDB96ECCF280C5F9,
		0x767340A70B204FBC
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD89C8BF2B2572F48,
		0x2AC86E4669C3D15F,
		0x90C6ADEC462C7D78,
		0x5A3296970828A58F
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F9D25C402F6D473,
		0xCED5B36C422984AF,
		0xFC912019730AAFB8,
		0x4671A55435B20600
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x718F10950160DB6C,
		0x35D54690A475BE20,
		0x39E464155E592445,
		0x64CFB961D3B9B389
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA12C36590457AFF2,
		0x04AAF9FCE69F42CF,
		0x3675842ED163D3FE,
		0x2B415EB6096BB98A
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B74A51185F4BA27,
		0x83D61BCF20A4A53D,
		0xC50B503E707BAB8A,
		0x06393CB7A921C48B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x402EDB11555840FF,
		0x6C3AAECDBC4AD11A,
		0x5BDB49D936377299,
		0x682B1A4714E853BB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BA38022DB4CFB26,
		0xF010CA9CDCEF7657,
		0x20E69A17A6B31E23,
		0x6E6456FEBE0A1847
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC76867E79FBF9FE,
		0x38C03196CF516BFC,
		0xA4C359E1CFEC7993,
		0x271208E7AF0BB082
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB61C3695D705E0C0,
		0xFE6EB33DC97C380C,
		0x1385BA7FE13FF60D,
		0x35E67A49F89E02D1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6292BD145101DABE,
		0x372EE4D498CDA409,
		0xB8491461B12C6FA1,
		0x5CF88331A7A9B353
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC2D0A8D4DD840CF,
		0x077D3A704B019365,
		0x35D7C7511D5317DC,
		0x119071FB46D6AF7B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DDA5B9FB18BB58E,
		0x3A331220F808E443,
		0x55FA3605D85848D6,
		0x0C7A90A5C8CCC9FE
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA07662CFF63F65D,
		0x41B04C91430A77A8,
		0x8BD1FD56F5AB60B2,
		0x1E0B02A10FA37979
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC930931D9D309AA8,
		0xDB618575C0CFD44E,
		0x750B359AF1CB1793,
		0x062AD8F3A18799E6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28DF2C275FA7D71E,
		0xBA59318C59FC6501,
		0x21AFA0678DCEE82F,
		0x5F498B411D8BE2FD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF20FBF44FCD871C6,
		0x95BAB7021ACC394F,
		0x96BAD6027F99FFC3,
		0x65746434BF137CE3
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF5D25591BCF1E9,
		0x500AB03A16EC7B0A,
		0x88581101ED508D04,
		0x274AF1B9F03F6AC1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4FC8BBCB6ABB181,
		0x174F4CDD1F4A49D8,
		0xF58332F61AB0D15B,
		0x27C1FABF91EEA57C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43F25E124868A36A,
		0x6759FD173636C4E3,
		0x7DDB43F808015E5F,
		0x4F0CEC79822E103E
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x787EEA8702AD91B4,
		0x4558E1479615AA4D,
		0x67BF64F1EAB40A07,
		0x067086049F2D36E5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55C52E2EC5CF6812,
		0x1DEE31394493E0FB,
		0x1D6074A8C66BAD4E,
		0x3A81977F32ACF66B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE4418B5C87CF9C6,
		0x63471280DAA98B48,
		0x851FD99AB11FB755,
		0x40F21D83D1DA2D50
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC145FC6F4256DF24,
		0x5C4F35B39453E3CC,
		0x9B7133E66A4A7699,
		0x7F5E18088A66E414
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9CC6FCDDE657559,
		0x9D372CF6F7C55B8F,
		0xE64CD6D59BB44567,
		0x03D69052FE73021C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B126C3D20BC5490,
		0xF98662AA8C193F5C,
		0x81BE0ABC05FEBC00,
		0x0334A85B88D9E631
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87EF46EED90271DB,
		0x8BE1125FA03E7AC2,
		0x79C4AC698AB9A3CD,
		0x1148668138C0756A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ACC558C35E764DC,
		0x0BBDAEED8E2BD11F,
		0xF45C52665CE06D92,
		0x54B2B29D58F79E64
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2BB9C7B0EE9D6B7,
		0x979EC14D2E6A4BE1,
		0x6E20FECFE79A115F,
		0x65FB191E91B813CF
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F6187D2A3933EDB,
		0x930E262814616FF1,
		0xD0706E11058C145A,
		0x37D358C24C0BB278
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDBFDC89359D3BC2,
		0xBF27DF57BA52EDA1,
		0x7F6E388A32D9F3DC,
		0x39926DD60D5C234E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D21645BD9307A9D,
		0x5236057FCEB45D93,
		0x4FDEA69B38660837,
		0x7165C6985967D5C7
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF8EC901786A3F86,
		0xC3F4CC6E489A3A42,
		0xA4A82E06A313A91E,
		0x1733BB2DFB44A073
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20994A85E1A753CD,
		0x7AAFE865814C2D10,
		0x8760D0FF404922E3,
		0x59C2556CAC3B398E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE02813875A119353,
		0x3EA4B4D3C9E66752,
		0x2C08FF05E35CCC02,
		0x70F6109AA77FDA02
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x097BDB2B956C48F0,
		0x40EA55A638970538,
		0x7B37411766E3FB00,
		0x227E32849F1E8B07
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA50D0631718F0FF,
		0x820AF81C268511DD,
		0xFC470421067FA910,
		0x0781F39437213A18
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3CCAB8EAC8539EF,
		0xC2F54DC25F1C1715,
		0x777E45386D63A410,
		0x2A002618D63FC520
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCC7B7A6666E7932,
		0x99F806DDF80C4581,
		0xC290629C557F200A,
		0x0A9C7FDA2B350B31
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3622AA804C563887,
		0x2C6ADD0DBF36190B,
		0x85CB3757DB49630E,
		0x1941874C56F0427C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12EA6226B2C4B1B9,
		0xC662E3EBB7425E8D,
		0x485B99F430C88318,
		0x23DE072682254DAE
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81833EB3D3574483,
		0x77711518F8D930CF,
		0x41F0DCEB1C148BC4,
		0x16BCD0A24B647BE7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA0C6054A8ED3DD,
		0x892A0BB578A3AA04,
		0x95E99ADE3D2E3BEF,
		0x5A177BC08DD3B1B0
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D2404B91DE61860,
		0x009B20CE717CDAD4,
		0xD7DA77C95942C7B4,
		0x70D44C62D9382D97
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8BE882CA65E7B70,
		0x25CF58F2F12FEB76,
		0xCB0587216EED85B8,
		0x407ED0C5D444BA43
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3108529B253680DC,
		0x164B5205E88E9EB3,
		0xA9FE5A0D56A59271,
		0x4CA1987D03D8A348
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29C6DAC7CB94FC5F,
		0x3C1AAAF8D9BE8A2A,
		0x7503E12EC5931829,
		0x0D206942D81D5D8C
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x960C5FB8113D19FB,
		0x6269C473E62A2E46,
		0x374CE44F785C0C1A,
		0x58055F3C2EA23FA7
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657FBFD2C0A89721,
		0x24BD83C2E7FFD2D6,
		0x2C5C36F05CA782C7,
		0x4525105074319D8A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB8C1F8AD1E5B12F,
		0x87274836CE2A011C,
		0x63A91B3FD5038EE1,
		0x1D2A6F8CA2D3DD31
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EF6CED61493D545,
		0x35EFD5C9088287F3,
		0xA245484C3A3A3977,
		0x69472BE8FF81F589
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3658313AAC6784A3,
		0xF7FE4382184CFEED,
		0x0E2F9F20FAC3770A,
		0x5238AB55E562009F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x754F0010C0FB59FB,
		0x2DEE194B20CF86E0,
		0xB074E76D34FDB082,
		0x3B7FD73EE4E3F628
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF66783FC43865202,
		0x26FCE987CA9C982B,
		0xFD1709AD3014F4F9,
		0x5623AC3F4A56BE07
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A62C659C7D95C8,
		0x71116E38F3498523,
		0xA283E9EF0E9C57E0,
		0x1C5F5D1190843073
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B0DB061E003E7CA,
		0x980E57C0BDE61D4F,
		0x9F9AF39C3EB14CD9,
		0x72830950DADAEE7B
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73781DEEB1E55D1E,
		0x72AE4D5F9EB54077,
		0x8921A0C904E46CED,
		0x2DCF712688E8A3A3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x481F7CF0FCB35243,
		0x773C7C66FAF4C12C,
		0x47C4A29D84FE6B03,
		0x2FB0C3DFF48FB8DB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB979ADFAE98AF61,
		0xE9EAC9C699AA01A3,
		0xD0E6436689E2D7F0,
		0x5D8035067D785C7E
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x250180CA46165CFF,
		0x1D4DE60DB24D6248,
		0x93518D3CC65C5C39,
		0x324FF578B057B6C5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF2DDE2EA1B740EE,
		0x079319701FDE893E,
		0x4758863C7CA2BFC5,
		0x7298755240032DA3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x142F5EF8E7CD9E00,
		0x24E0FF7DD22BEB87,
		0xDAAA137942FF1BFE,
		0x24E86ACAF05AE468
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34E04F00B8C4FF9,
		0x1C7A3992BCA3A757,
		0x76D63B52C1C3D498,
		0x03C104C1DCC07A37
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AF7B382BA5E93D9,
		0xCE6F91C3DAB5918F,
		0x2A23D13DB7998689,
		0x3FB54102411D6E17
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E45B872C5EAE3D2,
		0xEAE9CB56975938E7,
		0xA0FA0C90795D5B21,
		0x437645C41DDDE84E
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CB0DD176BE16962,
		0xBCB6A7A6E00205A9,
		0x6487DF8C7A8C5F98,
		0x7C193F1348980C84
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2721D0BABFFEFE07,
		0x974021B18DEF4D89,
		0xA611095EAF0FD9C9,
		0x2AB0F32A8A84F3BB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73D2ADD22BE0677C,
		0x53F6C9586DF15332,
		0x0A98E8EB299C3962,
		0x26CA323DD31D0040
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9A7500E92C821372,
		0x1936CEC1F8E11523,
		0xDE19333FC3B9D95E,
		0x3FC135A49B77E9F8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA82151777A1A2E74,
		0xDAE2A923D321DA8B,
		0xBCA054F6ECB6D6C1,
		0x6B91EDDEC1CAF795
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42965260A69C41F9,
		0xF41977E5CC02EFAF,
		0x9AB98836B070B01F,
		0x2B5323835D42E18E
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00DF29A94A91FDBC,
		0x713ECFD58C7F2336,
		0x88913CB21EDCCBBA,
		0x08A097FF3236835A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E399F9BCAEA2A66,
		0x2B01F8BC8B6A2E6C,
		0x9E5F27FF4F27B02C,
		0x2EC686A067B59EAB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F18C945157C2822,
		0x9C40C89217E951A2,
		0x26F064B16E047BE6,
		0x37671E9F99EC2206
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F6AD4412A8C49EA,
		0x8417553A1815BA0B,
		0xA2AE53E7775529B6,
		0x748896598433762B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x312711F590A9E407,
		0x172BC0CD15DAD200,
		0x01D805C07AEF7AAA,
		0x124FEF1D2BDBD980
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4091E636BB362E04,
		0x9B4316072DF08C0B,
		0xA48659A7F244A460,
		0x06D88576B00F4FAB
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8C1D23ED8C93BCF,
		0x4243E0E1094E7B8D,
		0x64DF324FE3BBDB62,
		0x773426DD2F78D4C0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B38FC42DBF3A1C3,
		0x2246FED42589B748,
		0xD2E6AB108E961E92,
		0x02DBD360978AA258
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53FACE81B4BCDD92,
		0x648ADFB52ED832D6,
		0x37C5DD607251F9F4,
		0x7A0FFA3DC7037719
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB95E69B4FF7FAF93,
		0x7050A1A506C07BE2,
		0x563ED023213F8B0D,
		0x4AC03B9B615FE9C6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810719CE8E81EDF6,
		0x1C80E5AF1C68F805,
		0x6BF818243AAA2C87,
		0x1917501D7FBE3748
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A6583838E019D89,
		0x8CD18754232973E8,
		0xC236E8475BE9B794,
		0x63D78BB8E11E210E
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87960648BA186857,
		0xD6003773B665259C,
		0xB40749CCA79A8E96,
		0x591BA0DB888B43BF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4955A1FAC49B002,
		0x4FF197B4A724EE4E,
		0x93C2B426A2111FB5,
		0x5D6D886CF3EB7DCB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C2B60686662186C,
		0x25F1CF285D8A13EB,
		0x47C9FDF349ABAE4C,
		0x368929487C76C18B
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F2F9F8717980D5E,
		0xBA690C6367CD8AD8,
		0x02DC4B8A5678D270,
		0x72C81622CFD7D939
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8557354C03614CE,
		0xEDA770A9347BBDA4,
		0x8B3154258C115AC0,
		0x2701173BBF85E83A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x478512DBD7CE223F,
		0xA8107D0C9C49487D,
		0x8E0D9FAFE28A2D31,
		0x19C92D5E8F5DC173
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D0ADDFABC89BB16,
		0x893A3D0BA02FBDD5,
		0x04295B72765A08A5,
		0x1D3FDFBC81E22A10
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5FF9F377DE7C545,
		0xF32ACE22EF4761A5,
		0xFFECD4897352B961,
		0x1000C46FA7F0EF71
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030A7D323A71805B,
		0x7C650B2E8F771F7B,
		0x04162FFBE9ACC207,
		0x2D40A42C29D31982
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A10B2547ED0DEEE,
		0xBEA5DFE833CA8720,
		0xA0EB526C5AAB08C0,
		0x7ABE5F6616D4137E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0334947892E6FB0A,
		0x476294BFD97161C9,
		0x0169495576D49B50,
		0x79B3A5A88D062773
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D4546CD11B7DA0B,
		0x060874A80D3BE8E9,
		0xA2549BC1D17FA411,
		0x7472050EA3DA3AF1
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02EEA2EF0D46DB91,
		0x9797FAB511AFD671,
		0x3C47C131B287D15B,
		0x40AF2CE169910E00
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC10A54A8D0AC604C,
		0x2E20AB27AB463DDB,
		0xA91406371ADA7041,
		0x7F84A1078AEF0EA5
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3F8F797DDF33BF0,
		0xC5B8A5DCBCF6144C,
		0xE55BC768CD62419C,
		0x4033CDE8F4801CA5
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FFDCF6C3650082D,
		0x50BA212BCED986C9,
		0xAAE59A2A2A6286D6,
		0x079D02164941B16B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF2F0C86AFE5CBEA,
		0x132602F0EA7F0561,
		0xCE31F1F65A44B976,
		0x2191DB124A52C4E9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F2CDBF2E635D417,
		0x63E0241CB9588C2B,
		0x79178C2084A7404C,
		0x292EDD2893947655
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8B9E5A8D5EF6DB9,
		0xA08170F8086DFD10,
		0x593968F7171D7752,
		0x572B1BD5E7D3C8E1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73DA473871500ED3,
		0x7D63ED2A32897071,
		0x2BCC4EC787B48D9B,
		0x4139801009630404
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C942CE1473F7C9F,
		0x1DE55E223AF76D82,
		0x8505B7BE9ED204EE,
		0x18649BE5F136CCE5
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABC583FF88D7D1AE,
		0x80D332C38515FFA3,
		0x128727BCF52870B1,
		0x181B0D782BEBC19A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C9A0A090AAC9F26,
		0x2EDE5C7533FEE0D2,
		0x8A0441C1CEA28CE9,
		0x074B8848F9C3BBF9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF85F8E08938470D4,
		0xAFB18F38B914E075,
		0x9C8B697EC3CAFD9A,
		0x1F6695C125AF7D93
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4183A96F8D950F61,
		0x2E83AC4F315DC775,
		0x6D1788DD79A1687B,
		0x5B2015E67928936D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DBBFF1CDAD03F3,
		0xCFD771243E283F60,
		0x0BB1EAF52CA470A9,
		0x10741501BCEA284F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x025F69615B421354,
		0xFE5B1D736F8606D6,
		0x78C973D2A645D924,
		0x6B942AE83612BBBC
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEA4ACE6C02B63CB,
		0xD1EFA835785BC789,
		0xB8E00019FC63E811,
		0x26A79631A9822C5A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BB6C2F1F719A79,
		0x62059FF061EC09F3,
		0xB8233B89B751FEF7,
		0x7BE519533DFE6E89
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0601915DF9CFE57,
		0x33F54825DA47D17D,
		0x71033BA3B3B5E709,
		0x228CAF84E7809AE4
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB438AD6E0723E138,
		0xA8C6C7066342F659,
		0xA99DECEF5EC640E0,
		0x0D9EF233CF67D89B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1525359B9220BA6C,
		0x6165128A218ED633,
		0xFA91C6B9D3DD13B3,
		0x659BBEACA7170106
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC95DE30999449BA4,
		0x0A2BD99084D1CC8C,
		0xA42FB3A932A35494,
		0x733AB0E0767ED9A2
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2ADFEBA10BD3E71,
		0x015B229C0254EB3D,
		0x6FBFB6A91FDB2083,
		0x0CED786FF9CD7985
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B3A8E16762EBF3A,
		0x1DCFCFB2D544EA5E,
		0x17C27C75F50C3DE7,
		0x1D96E9133443DF03
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DE88CD086EBFDAB,
		0x1F2AF24ED799D59C,
		0x8782331F14E75E6A,
		0x2A8461832E115888
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7661F8F55E44ADF6,
		0xC0A838EA01B6EA86,
		0xC383C0C1D49637F5,
		0x4034D31B2A6B008F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B776B1DC6E7A14D,
		0xE824B55693EDE359,
		0x5EB3C6BC14D9F78C,
		0x3102085A7B52F971
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1D96413252C4F43,
		0xA8CCEE4095A4CDDF,
		0x2237877DE9702F82,
		0x7136DB75A5BDFA01
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x136045A150D07A32,
		0x2DDF25F178F69CF6,
		0x699552DFE84E904E,
		0x023434121B5A49BB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73C892677D402EB8,
		0x579AF4730C15200F,
		0x38BB0F7830B626BC,
		0x38D7BFD8DD93B1C4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8728D808CE10A8EA,
		0x857A1A64850BBD05,
		0xA25062581904B70A,
		0x3B0BF3EAF8EDFB7F
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x980CAAB0B5AED489,
		0x14F47ED89293D1E6,
		0x76D55D59FBDC603B,
		0x05A7F99059C6A99A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EFC9682B7D0D58C,
		0x78B3A7D4DC683B1D,
		0x0B9CE69B500085F5,
		0x79955031C409179B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE70941336D7FAA15,
		0x8DA826AD6EFC0D03,
		0x827243F54BDCE630,
		0x7F3D49C21DCFC135
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE06AF0B9843295D0,
		0xDE89974B75B0564C,
		0xF9EA16FF93777483,
		0x702E6E13D3D47903
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAF18D10568B68BE,
		0xC7AFCF01BF6AA21C,
		0xE106A45D217C3863,
		0x4C109525F4C1A6A4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB5C7DC9DABDFEA1,
		0xA639664D351AF869,
		0xDAF0BB5CB4F3ACE7,
		0x3C3F0339C8961FA8
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x594F1EF673029B9B,
		0x21C651F59D277C6D,
		0x8B252E14A7315718,
		0x6CD623BEFA89211B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D696EBF75D2601,
		0x12B7EE4832551F6B,
		0x085FEF6C141CA700,
		0x645A42A993C80C93
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1125B5E26A5FC1AF,
		0x347E403DCF7C9BD9,
		0x93851D80BB4DFE18,
		0x513066688E512DAE
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0B8C9BB0103A08F,
		0x66C342BEF7A98399,
		0x7DA3DB14C461F183,
		0x186DE713117565A0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FAB16A48ADF0573,
		0x31EBE5F256C2917E,
		0xE2774E4BCA02447E,
		0x2F68D5393BEB13FA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9063E05F8BE2A602,
		0x98AF28B14E6C1518,
		0x601B29608E643601,
		0x47D6BC4C4D60799B
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF1E9C1123D21FB7,
		0x1AF33BE01133E3C0,
		0x78780D13F071B00E,
		0x04C9768EB3B3D470
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E0DB2C8196DF570,
		0x02917AE0E107DA63,
		0x361257EEF9961F77,
		0x35E58805FDB8C3A7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED2C4ED93D401527,
		0x1D84B6C0F23BBE23,
		0xAE8A6502EA07CF85,
		0x3AAEFE94B16C9817
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB42CDA288C9E5F2,
		0x3728CBC8981321B2,
		0x61E41A49AB96ED22,
		0x1C703A32B5678B3A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0869DAD78DF307F9,
		0xB4C04912C2770F38,
		0x806B346D0E721EF2,
		0x1139CCA4299B9885
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3ACA87A16BCEDEB,
		0xEBE914DB5A8A30EA,
		0xE24F4EB6BA090C14,
		0x2DAA06D6DF0323BF
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52FCFAE4A44B3DA2,
		0xC254056F169FB20B,
		0x305B9A3072E05B7B,
		0x735593D202C6A889
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E53068B358FECCC,
		0xB9D5FC6EA2002557,
		0x3BD357025565D026,
		0x2F3FD42F6BB6F707
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8150016FD9DB2A81,
		0x7C2A01DDB89FD762,
		0x6C2EF132C8462BA2,
		0x229568016E7D9F90
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5569BE32C61EB949,
		0xD49A7528545E9CFC,
		0x00F452E6BF695FDB,
		0x30CFF3DA0378207B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9267E3233F0673F9,
		0x31B236E135DA0E8E,
		0x6D4CC332C6B94F69,
		0x1F22ED47206CD7C9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7D1A15605252D42,
		0x064CAC098A38AB8A,
		0x6E4116198622AF45,
		0x4FF2E12123E4F844
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26925456EE9CC65F,
		0x195F4B58BEEFFCA8,
		0xB63A543472DEEF2E,
		0x27D9A3374A0FA715
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D4B215D392B3456,
		0x5732752558292A8A,
		0x421A5C65EB0AA456,
		0x66E6C0333E34FC9B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63DD75B427C7FAC8,
		0x7091C07E17192732,
		0xF854B09A5DE99384,
		0x0EC0636A8844A3B0
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC336D776D8349AA7,
		0xAADEA42A81A476BB,
		0xE14687AE7ED15396,
		0x745409896D917BAE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F58519B7297503F,
		0x97856DDCA16DFE0C,
		0xF0DF171E451E9C9E,
		0x1FCFC59273F07FB7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128F29124ACBEAF9,
		0x42641207231274C8,
		0xD2259ECCC3EFF035,
		0x1423CF1BE181FB66
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x299236D32B120F87,
		0xDE01389A05E6EB0B,
		0xF072FA220264A5E5,
		0x30E0E3D05487ABE8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x399A1A8E1B24D3D8,
		0x00A94120D94E89CC,
		0x34DE8887C151A2D4,
		0x41346FEB2C774109
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x632C51614636E35F,
		0xDEAA79BADF3574D7,
		0x255182A9C3B648B9,
		0x721553BB80FEECF2
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x155DB6A81D21B1C8,
		0x3C2AB63DA987ED80,
		0x0AB99019D10291DA,
		0x40612A5240BBEC6B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x483586ED06EB1696,
		0x0D9F47D08408C620,
		0xDD341020A042DB53,
		0x434DD58D44471E32
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D933D95240CC871,
		0x49C9FE0E2D90B3A0,
		0xE7EDA03A71456D2D,
		0x03AEFFDF85030A9D
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42EE913FD8FAE146,
		0x83DFA018845ED2A8,
		0xD5FACCBCDC64A5CD,
		0x369E0AB57C5B433B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF927975DEBAE24AF,
		0x6936E86BC773C988,
		0xFD5CC4AA20CB8002,
		0x6C780A7E694335E5
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C16289DC4A90608,
		0xED1688844BD29C31,
		0xD3579166FD3025CF,
		0x23161533E59E7921
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F616BD28CF3E404,
		0xB8E76879DA2CE4A5,
		0x9AE94AFFCF5EB629,
		0x603B88C1F4DADA6E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB9839162F344438,
		0x1155538373FE211F,
		0x5CC300B0038DC945,
		0x5CC03898E58BF972
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AF9A4E8BC28284F,
		0xCA3CBBFD4E2B05C5,
		0xF7AC4BAFD2EC7F6E,
		0x3CFBC15ADA66D3E0
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA316B84C0D281A7C,
		0x5917A81B4871B661,
		0x377925E8218CF4B7,
		0x406DF95334647729
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E3834D3195DA4B7,
		0x40C0F5A985400E9E,
		0xCD32726824B69FCC,
		0x451AC1B4957E52C3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x214EED1F2685BF46,
		0x99D89DC4CDB1C500,
		0x04AB985046439483,
		0x0588BB07C9E2C9ED
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA5C7C48DA83E1FA,
		0x1F3FF26DDE48F093,
		0x64D2F59434CEB3AD,
		0x20936198B8C0DA8B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B76CF930EA5B3D6,
		0x321BBF25DBB3E0CA,
		0x3A649DF6B8CEDDB1,
		0x244D285FCD5B613F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D34BDBE92995D0,
		0x515BB193B9FCD15D,
		0x9F37938AED9D915E,
		0x44E089F8861C3BCA
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27608068D02931DA,
		0xB9C03F9BE27D1E0D,
		0x42C89A5349D7DBD0,
		0x1D607F4BC7392569
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFED1BCA97425712,
		0xB6BD1D887F787FC1,
		0xC8114A4F5A827841,
		0x0C9DDFD4DC09853E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x274D9C33676B88EC,
		0x707D5D2461F59DCF,
		0x0AD9E4A2A45A5412,
		0x29FE5F20A342AAA8
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD790AE282E8542B2,
		0x25D923A7B41626DC,
		0x9D8BB530E595B54D,
		0x26DF88E4043EEE34
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9110129DAF2C4405,
		0xA30746208E1B6BC4,
		0xF5BEBAF9935726EE,
		0x39CF3F4F2B80AA92
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A0C0C5DDB186B7,
		0xC8E069C8423192A1,
		0x934A702A78ECDC3B,
		0x60AEC8332FBF98C7
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D45EFAEB795B8BE,
		0x10B3D91BD3712130,
		0xA48F5CA57903726C,
		0x657F4AEC430793C5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1814FED4A636D83,
		0x62D247C5C9CD55AA,
		0xE908A6016614D51D,
		0x750AE11D64A71893
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEC73F9C01F92654,
		0x738620E19D3E76DA,
		0x8D9802A6DF184789,
		0x5A8A2C09A7AEAC59
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B8C6DF7C42C20CF,
		0xFD5C61AEC4EB058A,
		0x2F252BAE2F901A80,
		0x0CE5F0027BA6B8E8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE1FF2B379D6AA7,
		0xC684ECA1CDC8142C,
		0x73490F7A7282B5C9,
		0x2F62DB56CAD34BD5
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B6E6D22FBC98B76,
		0xC3E14E5092B319B6,
		0xA26E3B28A212D04A,
		0x3C48CB59467A04BD
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x952A93ADE2C377C7,
		0x2A9986CE5C219AA4,
		0x8310CCF36EDC7BF0,
		0x218E9E108CBB9EFE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A3C7156960C73ED,
		0xE45FD74EFAEABAB0,
		0x80A3C285D06C716B,
		0x308C8F99B36149DE
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F67050478CFEBB4,
		0x0EF95E1D570C5555,
		0x03B48F793F48ED5C,
		0x521B2DAA401CE8DD
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9197BF8A8DC57DA,
		0xF4C4278F0BF30518,
		0x8D1D6DCE445E10B4,
		0x2E3CB7A9A88F7506
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFADE1DCA2D79937,
		0xEB14CE50F272074B,
		0xAB69BB017F5F9510,
		0x5768CFB06EF8D6B2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8C75DD54BB3F124,
		0xDFD8F5DFFE650C64,
		0x388728CFC3BDA5C5,
		0x05A5875A17884BB9
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD92E27867BA3BCB,
		0x806E7F12BD73A745,
		0xB2A8E8A378C9FA2F,
		0x113CEBC94D6D6729
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x128052441D169D34,
		0xCDD09F35A03AD4C5,
		0x5BAE4B191BD247A0,
		0x2D416E7A1F412637
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF01334BC84D0D8FF,
		0x4E3F1E485DAE7C0A,
		0x0E5733BC949C41D0,
		0x3E7E5A436CAE8D61
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7EB42CA11946C48,
		0xFCF7D618C5630CAA,
		0x746F61C602DF2EB0,
		0x24DDE34A83D522A9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA070FE64D9E88F,
		0x1B03390126DE5749,
		0xA7E305BB83A96533,
		0x589F97916C2DCF5D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x038BB3C8766E54D7,
		0x17FB0F19EC4163F4,
		0x1C526781868893E4,
		0x7D7D7ADBF002F207
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5C677936B1F9F96,
		0xD06DA079CCE1E3C1,
		0x344A8EA1D89BD40E,
		0x20C48AAFFFA499EF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA43435F7185D224,
		0x7177244EB7F9B291,
		0x80E5577CC11A1143,
		0x546990B210BEFA09
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC009BAF2DCA571BA,
		0x41E4C4C884DB9653,
		0xB52FE61E99B5E552,
		0x752E1B62106393F8
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9C10C6F0DB4DC5E,
		0xA840935532584E89,
		0xC47F0370CFE72320,
		0x74001112CF2254F1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB670F3DAEB3A842D,
		0x83601570402E0D2C,
		0xDB791D248D09CA49,
		0x413A3B52A9C919D7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90320049F8EF609E,
		0x2BA0A8C572865BB6,
		0x9FF820955CF0ED6A,
		0x353A4C6578EB6EC9
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1D19E026197257A,
		0x0A8FCFD9A7C294DB,
		0x8CA9C1BA9A103A97,
		0x6D97AB10CD1257AA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABBA821EDD45C53A,
		0x4E8DC0056CE7E9CB,
		0xB2E563C0FD8F3543,
		0x3AAA4180DE4F8341
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D8C20213EDCEAC7,
		0x591D8FDF14AA7EA7,
		0x3F8F257B979F6FDA,
		0x2841EC91AB61DAEC
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x391E4BD4BF5F9789,
		0x430AB656C57E5EDD,
		0x445FDE0D6BFC3680,
		0x00D0AD66803143BC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E6451B88215A20,
		0xC08FB50520B12CDE,
		0x4B88984D2210264D,
		0x178CD53270ABD742
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x830490F04780F1A9,
		0x039A6B5BE62F8BBB,
		0x8FE8765A8E0C5CCE,
		0x185D8298F0DD1AFE
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F272FF914DD78F2,
		0x14205ED72A253808,
		0xF7EC576AB0BC140D,
		0x1A21F94502F8DE44
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9276656EE5EE5657,
		0x17A928629D2DD570,
		0xC60710D6665022C7,
		0x02081F4A4F825A9B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC19D9567FACBCF49,
		0x2BC98739C7530D78,
		0xBDF36841170C36D4,
		0x1C2A188F527B38E0
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B5598C4A777F9AD,
		0x640E4C39CCF8AD2D,
		0xE6816D93A2CD957C,
		0x7D4E47772A9A51E1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53C43B8BB201DD4,
		0xA9A269F0ACC23B1B,
		0x870B646B212D1AF5,
		0x429780609D8AF232
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB091DC7D62981794,
		0x0DB0B62A79BAE848,
		0x6D8CD1FEC3FAB072,
		0x3FE5C7D7C8254414
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B42F3C6E45191CE,
		0xDDFB65149E168842,
		0xBFA9B42505C98102,
		0x6ECBDEC9092ADE19
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6638C88CC44536,
		0x58236B14AEF089BA,
		0x15F4331C0189D9EE,
		0x120823CB1008901E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88A92C8F7115D717,
		0x361ED0294D0711FC,
		0xD59DE74107535AF1,
		0x00D4029419336E37
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFC2CBC0BF0ED1DE,
		0x6E36EEB9D4FB51A1,
		0x2F529DC7CDADCEF2,
		0x61CB69900E9B8BB8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA49BB9FDA61A330D,
		0xD206C5BDE40DA8A0,
		0xABB021C9B97CE2D5,
		0x557F5F2008FEB171
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x745E85BE652904FE,
		0x403DB477B908FA42,
		0xDB02BF91872AB1C8,
		0x374AC8B0179A3D29
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61416ED1993734DC,
		0x99E81C40C9D442BB,
		0xAB368291300CC97B,
		0x49435CA08CEEF37A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADCC2268A41139E8,
		0xCA80625B0FF82B2C,
		0x6A3B2A9A41931249,
		0x2B8C58AEF73E07BA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F0D913A3D486EC4,
		0x64687E9BD9CC6DE8,
		0x1571AD2B719FDBC5,
		0x74CFB54F842CFB35
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C73ABB7E73A18DD,
		0xDA2F6DBC518A620A,
		0xDD0C2CA0370C0A52,
		0x29E55218FF85390F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x495541E8A48B9F79,
		0x4BE528790A25B1D3,
		0x6D2842EE841F0998,
		0x7E2F6F42842464CE
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65C8EDA08BC5B869,
		0x261496355BB013DD,
		0x4A346F8EBB2B13EB,
		0x2814C15B83A99DDE
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC429E16414F5F9CE,
		0xFB5AFA169E7628B4,
		0x4D249178E8D766CB,
		0x3DAD3838CC5414B1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9875F309FA4F4CC4,
		0x69C4CD794727CD0B,
		0x93F8ED8F1085A178,
		0x6DEE473AF3DD29FB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C9FD46E0F4546A5,
		0x651FC78FE59DF5C0,
		0xE11D7F07F95D0844,
		0x2B9B7F73C0313EAC
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A5A0494D69F8F4D,
		0x6A333894B697400D,
		0x48B2B0E9D14067E3,
		0x105D53C681B61779
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5861E75C6C6C2C32,
		0xC6A797D394E828B5,
		0x0B8C68DCDACA31CB,
		0x4ED1C4955496979C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2BBEBF1430BBB7F,
		0x30DAD0684B7F68C2,
		0x543F19C6AC0A99AF,
		0x5F2F185BD64CAF15
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E4F1E02758C9EB9,
		0x1AC2CA6F50354F82,
		0xFAF868DC32398BF8,
		0x61D051762407BEA2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3B81F22E3E66B6,
		0x0C366572C1412BF6,
		0x3AFF3FBDE2DA13D0,
		0x1A14D66BE17B3BED
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288A9FF4A3CB056F,
		0x26F92FE211767B79,
		0x35F7A89A15139FC8,
		0x7BE527E20582FA90
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62DF81AC87B7F7FC,
		0x1EFC8FB3D62744C3,
		0xFF567724701D762E,
		0x18F315F36F98D6C8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB6BA7D79DE94221,
		0x77F139983FB0D7FE,
		0xDB7987FB144DCB8D,
		0x66924AFE0C462A5D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E4B298425A13A1D,
		0x96EDC94C15D81CC2,
		0xDACFFF1F846B41BB,
		0x7F8560F17BDF0126
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}