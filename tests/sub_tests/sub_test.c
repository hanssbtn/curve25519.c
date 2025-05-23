#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0xA9B95C43FABB046AULL,
		0x5BC0A6FF4C89C820ULL,
		0x75525A441702B48BULL,
		0x577D3E828473DEE0ULL,
		0xBBF81AC3B092B20EULL,
		0x62E39B571E4CA186ULL,
		0x7E1F5BF20118C862ULL,
		0xB2B473FAFEC238BCULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x70EBE9DBA7D862ABULL,
		0xACEA89E7B28E68A1ULL,
		0x973136EE5E99DECAULL,
		0xC7028D6D1B2D4D1CULL,
		0xCA3BABEE7343DE0EULL,
		0x493958A1FBF5733AULL,
		0xF3C79B96F6131D62ULL,
		0x9C159E5AC3F75272ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x38CD726852E2A1BFULL,
		0xAED61D1799FB5F7FULL,
		0xDE212355B868D5C0ULL,
		0x907AB115694691C3ULL,
		0xF1BC6ED53D4ED3FFULL,
		0x19AA42B522572E4BULL,
		0x8A57C05B0B05AB00ULL,
		0x169ED5A03ACAE649ULL
	}};
	int sign = 0;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	int borrow = curve25519_key_sub(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF2E7716F8C9BF1DULL,
		0x2F95FC393C73A251ULL,
		0x083F117061DF8337ULL,
		0xBBBE8F79818BB437ULL,
		0x899C186C64D37FDCULL,
		0x5E6D15F32246DA24ULL,
		0x21C1DF230630311FULL,
		0x9F09C22FC4929013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E6830CD43DB466ULL,
		0xF890EFF12EDC43B4ULL,
		0x8F0BBE7B6BDF67CAULL,
		0xD3A3C3402110FDA8ULL,
		0x5987E6A112C3BD4DULL,
		0xDDD376797A3D963FULL,
		0x708D03FA97B73E23ULL,
		0xDF296F0A3AD71388ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB47F40A248C0AB7ULL,
		0x37050C480D975E9DULL,
		0x793352F4F6001B6CULL,
		0xE81ACC39607AB68EULL,
		0x301431CB520FC28EULL,
		0x80999F79A80943E5ULL,
		0xB134DB286E78F2FBULL,
		0xBFE0532589BB7C8AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BE487E16BB6EC1FULL,
		0xFD8222DC4A95F4BCULL,
		0xD32CBBF8B956EB15ULL,
		0xB378B60214522182ULL,
		0x565D1D81432550ABULL,
		0x85BA10832BADFEAEULL,
		0x3B3841C89428CA2EULL,
		0xCA8C79B51152C1A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85D55885670606FBULL,
		0x826E4580E194A123ULL,
		0xC15ACF9532889CB4ULL,
		0xE0612A10E05A4AC8ULL,
		0x08D8A1576E0D3732ULL,
		0x8FED2FD41676B119ULL,
		0x97B1E4808DC165BFULL,
		0x42870F9AA00B1126ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD60F2F5C04B0E524ULL,
		0x7B13DD5B69015398ULL,
		0x11D1EC6386CE4E61ULL,
		0xD3178BF133F7D6BAULL,
		0x4D847C29D5181978ULL,
		0xF5CCE0AF15374D95ULL,
		0xA3865D480667646EULL,
		0x88056A1A7147B07EULL
	}};
	sign = 0;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0726E90EFA93FDCBULL,
		0x02A8CFA4ADF7907FULL,
		0xF779857EF01E5E18ULL,
		0x1C12407D5C1D11C0ULL,
		0xF4BE3A7605214E06ULL,
		0x8426E297B53A5A80ULL,
		0x134E2F13D4F69940ULL,
		0x9C6F6EE0AFF27D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86A5E47EE2507B49ULL,
		0x98EE16A84E818DEFULL,
		0xE1045FF490565FD3ULL,
		0x08ECA7A5527C7926ULL,
		0x87FACCB4B4E759BFULL,
		0x49BFC7B961D34879ULL,
		0x917D3D6BFCECF873ULL,
		0x61142D88DEE0B4CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8081049018438282ULL,
		0x69BAB8FC5F76028FULL,
		0x1675258A5FC7FE44ULL,
		0x132598D809A0989AULL,
		0x6CC36DC15039F447ULL,
		0x3A671ADE53671207ULL,
		0x81D0F1A7D809A0CDULL,
		0x3B5B4157D111C855ULL
	}};
	sign = 0;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86B88B251DF0C0CEULL,
		0xBDCEC58A448162D1ULL,
		0xD42F25191D48E885ULL,
		0x43085D66E007CEB0ULL,
		0x9C8036AB863D7B29ULL,
		0xA9693E08584FDA36ULL,
		0xB9FCADF4B1A04EB4ULL,
		0x47A2F7981F51FEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6F74B666D1C47CULL,
		0x9C558F609ACAD9DAULL,
		0x68A97514CB139A9FULL,
		0x1E91286D2EF4098BULL,
		0x7F6E243E7FE7CE92ULL,
		0x50C95A5A68C17F50ULL,
		0x56F9935EED350037ULL,
		0x5146A270235C8EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B49166EB71EFC52ULL,
		0x21793629A9B688F7ULL,
		0x6B85B00452354DE6ULL,
		0x247734F9B113C525ULL,
		0x1D12126D0655AC97ULL,
		0x589FE3ADEF8E5AE6ULL,
		0x63031A95C46B4E7DULL,
		0xF65C5527FBF57027ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54995C903C065E4DULL,
		0xB6878C5778203AB8ULL,
		0xB13D41DEE994E3A3ULL,
		0xC7A5BFEC130A8CAFULL,
		0x7F0FEDD34A1EBCF7ULL,
		0x138CF32F529B4C4BULL,
		0x1F2634FD1D950B08ULL,
		0x2F1F4958BEB0575BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10E682152DD361D5ULL,
		0xC2958DBDCFC2280BULL,
		0xB8338FE5838079B7ULL,
		0xA366C7779B9D5DE0ULL,
		0x2288BE34D64B79EFULL,
		0xD2BE076DBB43E69EULL,
		0x132863629BF77ED1ULL,
		0xE9257602E6E60D95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43B2DA7B0E32FC78ULL,
		0xF3F1FE99A85E12ADULL,
		0xF909B1F9661469EBULL,
		0x243EF874776D2ECEULL,
		0x5C872F9E73D34308ULL,
		0x40CEEBC1975765ADULL,
		0x0BFDD19A819D8C36ULL,
		0x45F9D355D7CA49C6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x304C5720F1F03714ULL,
		0x68AE8A119351B7EDULL,
		0x84DD5C818EBBC28FULL,
		0x76FA7EE4370604EDULL,
		0x5D98136CC40B209EULL,
		0x01B5D9034D0694A3ULL,
		0x0BC926056CDB4569ULL,
		0x919BB76A32F2369CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52527FB265446CB7ULL,
		0xE90642E57B3CE95AULL,
		0xEAFDBA9B14831185ULL,
		0x9A7781FE02312848ULL,
		0x21634F712A8B1082ULL,
		0x9F13515FF19BBB9DULL,
		0xC8DD6FEE4FE7F99AULL,
		0x23DCE5F240AE2DFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDF9D76E8CABCA5DULL,
		0x7FA8472C1814CE92ULL,
		0x99DFA1E67A38B109ULL,
		0xDC82FCE634D4DCA4ULL,
		0x3C34C3FB9980101BULL,
		0x62A287A35B6AD906ULL,
		0x42EBB6171CF34BCEULL,
		0x6DBED177F244089CULL
	}};
	sign = 0;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x564E04E0E5E2F00BULL,
		0xDEB0B63A05F1901CULL,
		0x7816138FEBD4040EULL,
		0x20119826BACBBF09ULL,
		0x7BBEC875B3216C45ULL,
		0xC8ACDB00E0674D1AULL,
		0x9CAD89B9223DD75CULL,
		0x0CE021D199F50183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6373FC76418BDFD8ULL,
		0x8447E384839B21A3ULL,
		0xBA6FE7CA1FCF24D6ULL,
		0xCEC6A36D88673D37ULL,
		0x6EC2BE38B23EC38BULL,
		0x9E1A045136155325ULL,
		0x25AF960D059AB078ULL,
		0x1AF58B161FB4D150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2DA086AA4571033ULL,
		0x5A68D2B582566E78ULL,
		0xBDA62BC5CC04DF38ULL,
		0x514AF4B9326481D1ULL,
		0x0CFC0A3D00E2A8B9ULL,
		0x2A92D6AFAA51F9F5ULL,
		0x76FDF3AC1CA326E4ULL,
		0xF1EA96BB7A403033ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD8C346655DE8CF4ULL,
		0xE7560C83B301422CULL,
		0xDAC5CF8885862AD1ULL,
		0x1538DDC83EAB61F9ULL,
		0xC6CEDCB3561676F8ULL,
		0xD82DCF932BCF612FULL,
		0x53B92BFF35D0F9B2ULL,
		0x6FFC8F3ABA8826AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9484A9900FBEEC7BULL,
		0xD3D75D47D5D8650CULL,
		0x522E2C675B94C10EULL,
		0x2F5E31F162929B39ULL,
		0x97339381FACA2BB4ULL,
		0x745B2B8E3DFE0339ULL,
		0x6039D8975C1E13EAULL,
		0x7CCCDBF52C47BD82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39078AD6461FA079ULL,
		0x137EAF3BDD28DD20ULL,
		0x8897A32129F169C3ULL,
		0xE5DAABD6DC18C6C0ULL,
		0x2F9B49315B4C4B43ULL,
		0x63D2A404EDD15DF6ULL,
		0xF37F5367D9B2E5C8ULL,
		0xF32FB3458E40692CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AB88F882B3B8D4EULL,
		0x868702A5CE733ACAULL,
		0x0B652D99A8C5B680ULL,
		0x9D2FF4AC004E70F6ULL,
		0x327D7F1335A6E277ULL,
		0xDA2D950D1BA0245BULL,
		0x121819536D287ACBULL,
		0x436E46BD745793E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A41B7421A2377D3ULL,
		0x8014C52095CEB596ULL,
		0xFF10A0D0CF14224CULL,
		0x7C663594626EF7A8ULL,
		0xD8007FA1D4A65353ULL,
		0xEEB96E1F2DA293B9ULL,
		0x8D885A7D46FFDBBBULL,
		0x487B071844EA40A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6076D8461118157BULL,
		0x06723D8538A48534ULL,
		0x0C548CC8D9B19434ULL,
		0x20C9BF179DDF794DULL,
		0x5A7CFF7161008F24ULL,
		0xEB7426EDEDFD90A1ULL,
		0x848FBED626289F0FULL,
		0xFAF33FA52F6D533EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76B9B54B73ED06ADULL,
		0xEE788D69E8647055ULL,
		0xCE95C128B77C1CB0ULL,
		0x6C537103C83F94BEULL,
		0x3FDA564BACA74064ULL,
		0x1AE0324E27DE6A26ULL,
		0xB85586802CA2EC1EULL,
		0x67B56524F31FD0CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA3A161CD4BDE31EULL,
		0x428DC00D9CB0A0D8ULL,
		0x717582488AC8324FULL,
		0x545A361512D0CD9BULL,
		0x20C1EFDE82D4483DULL,
		0x357CB5D3AC920E38ULL,
		0xEB1EE0CDAD6E04BFULL,
		0x26787739B1DC98EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC7F9F2E9F2F238FULL,
		0xABEACD5C4BB3CF7CULL,
		0x5D203EE02CB3EA61ULL,
		0x17F93AEEB56EC723ULL,
		0x1F18666D29D2F827ULL,
		0xE5637C7A7B4C5BEEULL,
		0xCD36A5B27F34E75EULL,
		0x413CEDEB414337E2ULL
	}};
	sign = 0;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA4B5FE8CAC1DA09ULL,
		0xA553F2D33A4F1CFCULL,
		0x822322FE0296FC5CULL,
		0x80E1D60DAAB43395ULL,
		0x57F59416F6529C2EULL,
		0xDED986DDC69BCCC4ULL,
		0xD75F4CA05FD6B2E7ULL,
		0xE49F0AC18484A85DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x475D76CC1E301036ULL,
		0x4826AAE9EE3E0CBCULL,
		0x43A4C4D8AD1EFD1EULL,
		0x042F1E2571B94BF6ULL,
		0xB7E93AE97FAB8C58ULL,
		0x934DB4D8BFD0EDC8ULL,
		0x745EA5CAEB46874EULL,
		0x9F7D5BFF96F19BFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62EDE91CAC91C9D3ULL,
		0x5D2D47E94C111040ULL,
		0x3E7E5E255577FF3EULL,
		0x7CB2B7E838FAE79FULL,
		0xA00C592D76A70FD6ULL,
		0x4B8BD20506CADEFBULL,
		0x6300A6D574902B99ULL,
		0x4521AEC1ED930C5EULL
	}};
	sign = 0;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7A3E6D4F5A214AAULL,
		0xA8AF61527F93331EULL,
		0x7E2502AC51FE5256ULL,
		0xD5CD5E708EF3E57AULL,
		0xE43969E9C87E4518ULL,
		0x05827F612E6D5406ULL,
		0x372C1EA7121303CFULL,
		0x2742762FFC66D8C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0A378F03DD01C23ULL,
		0xADB257204B24D9CFULL,
		0x658D25EF7F18C8B1ULL,
		0xCF1E67CDEAC60730ULL,
		0xB7607863ECD0B3E4ULL,
		0xE329F5C7BC331ABFULL,
		0xCFEB4ABCA3D68B6DULL,
		0x74C21BBA2D3F5349ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7006DE4B7D1F887ULL,
		0xFAFD0A32346E594EULL,
		0x1897DCBCD2E589A4ULL,
		0x06AEF6A2A42DDE4AULL,
		0x2CD8F185DBAD9134ULL,
		0x22588999723A3947ULL,
		0x6740D3EA6E3C7861ULL,
		0xB2805A75CF278577ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF52CD95C07A0929CULL,
		0x8309B9F3E3CC6B9CULL,
		0xF2C70BD5096472CDULL,
		0x6EDB6D0324DF6094ULL,
		0xE5FF49C9A8B3E060ULL,
		0xCCD450F37D8981C4ULL,
		0xA63CCC247C02548FULL,
		0x4C8853A261323B5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x570800ECCFB77900ULL,
		0x4266B109358B96CAULL,
		0x4D01F0D8DB7B1148ULL,
		0xF44ACD536D31FFB2ULL,
		0x6919CE1E1E07F3C0ULL,
		0xC4E776A1C44B6535ULL,
		0x4703A4842DDAAA52ULL,
		0x9CF47A33EBEDEF84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E24D86F37E9199CULL,
		0x40A308EAAE40D4D2ULL,
		0xA5C51AFC2DE96185ULL,
		0x7A909FAFB7AD60E2ULL,
		0x7CE57BAB8AABEC9FULL,
		0x07ECDA51B93E1C8FULL,
		0x5F3927A04E27AA3DULL,
		0xAF93D96E75444BDBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80924155CA47C16EULL,
		0x850354B3BC2CBC43ULL,
		0x935241881295D1D5ULL,
		0x0E56A1BFAEAD2EAEULL,
		0x837061959A169B7CULL,
		0xE014C9F665F479F7ULL,
		0xA491F052311FEB19ULL,
		0x996CA83AB7366F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3194106FBEF8B0BDULL,
		0x675BA996FCC687DAULL,
		0x528F2707CB7CA68CULL,
		0x955BEDC5C4D1EDCEULL,
		0xFF859674311E237EULL,
		0x5E7E6D1C6D5020B1ULL,
		0x87957D15C7DC722FULL,
		0x07AACE8EC90E3348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4EFE30E60B4F10B1ULL,
		0x1DA7AB1CBF663469ULL,
		0x40C31A8047192B49ULL,
		0x78FAB3F9E9DB40E0ULL,
		0x83EACB2168F877FDULL,
		0x81965CD9F8A45945ULL,
		0x1CFC733C694378EAULL,
		0x91C1D9ABEE283C1EULL
	}};
	sign = 0;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E4377F9DB643AE6ULL,
		0xA837453502B3939DULL,
		0x2075AADECF372589ULL,
		0x3FAB3D563B5E50D2ULL,
		0x444A8A78FE1C6FD2ULL,
		0x46F59D09119B6E6AULL,
		0xBED1E67DC45006AAULL,
		0x4C4A286568DF85FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59986C41F12CA5B4ULL,
		0xC00C59D49D73541FULL,
		0x73976B4519C87794ULL,
		0x2E6AC0636DA82F56ULL,
		0xA0191CA42F9E428CULL,
		0x044BE3ED0A77C643ULL,
		0xC6747D0703E52598ULL,
		0xC52951C2337277A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4AB0BB7EA379532ULL,
		0xE82AEB6065403F7DULL,
		0xACDE3F99B56EADF4ULL,
		0x11407CF2CDB6217BULL,
		0xA4316DD4CE7E2D46ULL,
		0x42A9B91C0723A826ULL,
		0xF85D6976C06AE112ULL,
		0x8720D6A3356D0E55ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x437C96ACE76F40AFULL,
		0x6CD57819BBF87638ULL,
		0x9A763869DF7A2A68ULL,
		0x53406B23A31C623CULL,
		0x870960141DEC9962ULL,
		0xAE481AF46018520AULL,
		0x14409932B134E0FAULL,
		0x27EDD5409C158AC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4275AE2E4CD7BABCULL,
		0x9F71EF6C258937A9ULL,
		0xE79B199AAF15AB1BULL,
		0x990C300907736482ULL,
		0x4B8688B39F242E61ULL,
		0x0F22318D319114AAULL,
		0x24C03A7F55AABC1DULL,
		0x93455C9F736CA633ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0106E87E9A9785F3ULL,
		0xCD6388AD966F3E8FULL,
		0xB2DB1ECF30647F4CULL,
		0xBA343B1A9BA8FDB9ULL,
		0x3B82D7607EC86B00ULL,
		0x9F25E9672E873D60ULL,
		0xEF805EB35B8A24DDULL,
		0x94A878A128A8E494ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD422D64B0CE282E0ULL,
		0x35411B7230C80B00ULL,
		0xF90C564C3B81EAB8ULL,
		0x85B592CCCF074D3BULL,
		0xD325543CE85B0153ULL,
		0x88C0B8F706074677ULL,
		0x83C8DE75FABA34EFULL,
		0xC1889B4AE8CBE08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCACFC7A6BBD430D7ULL,
		0x6DD93965C7FE681CULL,
		0xF388487118EA87D0ULL,
		0x9E51D07F32A0C1C5ULL,
		0x724B790DC91EEED2ULL,
		0x9BF7CAACD5C76CCCULL,
		0xDF396B53F536FCD6ULL,
		0x3051F5B4DD8EF865ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09530EA4510E5209ULL,
		0xC767E20C68C9A2E4ULL,
		0x05840DDB229762E7ULL,
		0xE763C24D9C668B76ULL,
		0x60D9DB2F1F3C1280ULL,
		0xECC8EE4A303FD9ABULL,
		0xA48F732205833818ULL,
		0x9136A5960B3CE825ULL
	}};
	sign = 0;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE494173A873A9C28ULL,
		0x0F877EBDB14CCD49ULL,
		0x553C94DB2F8A0A6AULL,
		0xDFE2F86B103C81E1ULL,
		0x89F19581C0B26A68ULL,
		0xA2B097FC435E5609ULL,
		0x2438E70CAD6CCEA4ULL,
		0x4B039EEFD2309708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CBE417DC8EAD7DCULL,
		0xC7C476053C4C7D55ULL,
		0x08D95890AD23483BULL,
		0x521AE38F16C6AAD3ULL,
		0xEB1E437C0CEF1424ULL,
		0xEE26E2120AF70D9CULL,
		0xBABAE05FFE851D9AULL,
		0x920290DA29B44102ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77D5D5BCBE4FC44CULL,
		0x47C308B875004FF4ULL,
		0x4C633C4A8266C22EULL,
		0x8DC814DBF975D70EULL,
		0x9ED35205B3C35644ULL,
		0xB489B5EA3867486CULL,
		0x697E06ACAEE7B109ULL,
		0xB9010E15A87C5605ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2433FD44B6AEE50ULL,
		0xA7C2C7FEEEE7D131ULL,
		0x98195981CA51798DULL,
		0xC995F19D0E4F04C0ULL,
		0x7E9C08D2D8199C43ULL,
		0x8371E7B3E2BD53E1ULL,
		0xBB22391D66E5FDEEULL,
		0xBEF58494FB1B1B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11CF9BE3C26E64E8ULL,
		0xEB3ED4B411DB024EULL,
		0x01059CF03201F299ULL,
		0x992C63E04D8C5A88ULL,
		0x38D545FEA56C2289ULL,
		0x87F81175EF3922BAULL,
		0x084CA06F2D7514D5ULL,
		0x22A22E97463C86E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD073A3F088FC8968ULL,
		0xBC83F34ADD0CCEE3ULL,
		0x9713BC91984F86F3ULL,
		0x30698DBCC0C2AA38ULL,
		0x45C6C2D432AD79BAULL,
		0xFB79D63DF3843127ULL,
		0xB2D598AE3970E918ULL,
		0x9C5355FDB4DE9488ULL
	}};
	sign = 0;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7A8536D7F91115BULL,
		0xAA48D1199DADB086ULL,
		0x78BA68231AF423BBULL,
		0xEF089FB942940BCBULL,
		0xA55EB7D706EF7726ULL,
		0xBBD4980378A30163ULL,
		0x7A1CE5EFABE5F03CULL,
		0xF517DF9D27A9C343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x752F4CF722830B6CULL,
		0x07FAD6B301D01B53ULL,
		0x0564B0D2C155044DULL,
		0xBAB2824E5CFB56ACULL,
		0x551040E90095DE78ULL,
		0x8573C994BDE39344ULL,
		0x7468A12F95956E54ULL,
		0x9563E9C16A72F6B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x327906765D0E05EFULL,
		0xA24DFA669BDD9533ULL,
		0x7355B750599F1F6EULL,
		0x34561D6AE598B51FULL,
		0x504E76EE065998AEULL,
		0x3660CE6EBABF6E1FULL,
		0x05B444C0165081E8ULL,
		0x5FB3F5DBBD36CC91ULL
	}};
	sign = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x805624E237E2794FULL,
		0x6CB0EE4408A9628EULL,
		0x773A58398D0615E5ULL,
		0xBD7B7B90BBC51D9FULL,
		0x05A5EC34C28E48D6ULL,
		0x2E364A13013E63A3ULL,
		0xF5976B78BE87600DULL,
		0x3D9F7A8946A27C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72CF5C1D87D02147ULL,
		0x717C64B5111AE9F9ULL,
		0x381A81267E7428CEULL,
		0x35BE218D8A673FFEULL,
		0xFAB1FC7D29E6B856ULL,
		0xFCAEFBC9E427B02CULL,
		0xE3F2E8E8EFDD2128ULL,
		0xED0EEECFB1F0E3BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D86C8C4B0125808ULL,
		0xFB34898EF78E7895ULL,
		0x3F1FD7130E91ED16ULL,
		0x87BD5A03315DDDA1ULL,
		0x0AF3EFB798A79080ULL,
		0x31874E491D16B376ULL,
		0x11A4828FCEAA3EE4ULL,
		0x50908BB994B1987EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED30F22D4DC65A30ULL,
		0xC44D70A7EA59A3BFULL,
		0x217397825B3C4D87ULL,
		0x18885F3731983F13ULL,
		0x7FF43ABA50219F3BULL,
		0x5B12217F13994CC4ULL,
		0x90824EF774AB3FF6ULL,
		0xB86F549B84684EF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4CE33FB830E59E0ULL,
		0x2F7953A745F2D945ULL,
		0xA81CCBE757A14ED6ULL,
		0x9D9C75EF491EF125ULL,
		0x684BB1009BC3F3F5ULL,
		0x6AC5EDEDB42337F7ULL,
		0xC022EBBA3593896FULL,
		0xB76FA95DF18226A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2862BE31CAB80050ULL,
		0x94D41D00A466CA7AULL,
		0x7956CB9B039AFEB1ULL,
		0x7AEBE947E8794DEDULL,
		0x17A889B9B45DAB45ULL,
		0xF04C33915F7614CDULL,
		0xD05F633D3F17B686ULL,
		0x00FFAB3D92E62850ULL
	}};
	sign = 0;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E41A2036E73E02DULL,
		0x2338E890F82D9743ULL,
		0xADF809245EC3EF59ULL,
		0x5AE890CF44F6455EULL,
		0x947CE6A23F79370FULL,
		0x773D653B62CD2D62ULL,
		0x8992A11A7BB09EA0ULL,
		0x0B88C10CE8E340F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8697E6F73C1001EULL,
		0x7724966BAE949E22ULL,
		0x1E1ECE54EBA608D3ULL,
		0xEA683E971BD68197ULL,
		0x51606B1DDEB35FD5ULL,
		0xBE46F71EE96B67F0ULL,
		0xEAC56A718FA76DF7ULL,
		0xA257CA4FF84F636EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5D82393FAB2E00FULL,
		0xAC1452254998F920ULL,
		0x8FD93ACF731DE685ULL,
		0x70805238291FC3C7ULL,
		0x431C7B8460C5D739ULL,
		0xB8F66E1C7961C572ULL,
		0x9ECD36A8EC0930A8ULL,
		0x6930F6BCF093DD89ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98B3BB70AFFE98C6ULL,
		0x2F9D6AD2F7C7798CULL,
		0x8868FCFA64B6D538ULL,
		0x6C9A6F0BB4B429E2ULL,
		0xE7E078FB241825BBULL,
		0x47183EF725CB05E7ULL,
		0x0AD93EB1B449B697ULL,
		0x9A20556FB9D3C7E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6701C344EE32464ULL,
		0x21550B14D181E77AULL,
		0x02C8242784F8F3EAULL,
		0x01D41FEECE38F7DFULL,
		0x2FC1A6E297B3AC77ULL,
		0xC8C751D289090A06ULL,
		0x3377A192965D1492ULL,
		0x786D629048855AFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2439F3C611B7462ULL,
		0x0E485FBE26459211ULL,
		0x85A0D8D2DFBDE14EULL,
		0x6AC64F1CE67B3203ULL,
		0xB81ED2188C647944ULL,
		0x7E50ED249CC1FBE1ULL,
		0xD7619D1F1DECA204ULL,
		0x21B2F2DF714E6CE3ULL
	}};
	sign = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9081BA1BBB74ED1FULL,
		0xBBB5CA6086A297CDULL,
		0x84C91C6B4F05B56AULL,
		0xF0B773929F689198ULL,
		0xC166401020B2223AULL,
		0x48DAED6479D26DCFULL,
		0x963BA50F17D23C94ULL,
		0xEB9682AE0F602A6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68A41C71A6CF53A1ULL,
		0x0D88AB1DFFB8F75CULL,
		0x3EDBE52FAC28774AULL,
		0x02045B7567FAEE6EULL,
		0xB1026D1AA15D7074ULL,
		0x4ADA4A0F1124933EULL,
		0x4A0C08B2D20817CBULL,
		0xF94E5F1B874A70CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27DD9DAA14A5997EULL,
		0xAE2D1F4286E9A071ULL,
		0x45ED373BA2DD3E20ULL,
		0xEEB3181D376DA32AULL,
		0x1063D2F57F54B1C6ULL,
		0xFE00A35568ADDA91ULL,
		0x4C2F9C5C45CA24C8ULL,
		0xF24823928815B99EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF374A283840BCF2ULL,
		0x91825BF8EE229A80ULL,
		0xFACC71593C8B143DULL,
		0x620903C25D01523FULL,
		0x4D4E8B3DAB209E9BULL,
		0x039FB21A4FE06F8DULL,
		0x70551CB1A1C4C5A8ULL,
		0x036D29BCC623346CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F5C6F99EDD158D8ULL,
		0xF4E26AF65D6F4C70ULL,
		0xD7ED62975C36EED8ULL,
		0x2EA854B5FF56113FULL,
		0x5677863744811715ULL,
		0x64BB7C9CC01069FAULL,
		0xC7BEC6E4EAD582B7ULL,
		0x2F7E9F0A3837E2FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFDADA8E4A6F641AULL,
		0x9C9FF10290B34E10ULL,
		0x22DF0EC1E0542564ULL,
		0x3360AF0C5DAB4100ULL,
		0xF6D70506669F8786ULL,
		0x9EE4357D8FD00592ULL,
		0xA89655CCB6EF42F0ULL,
		0xD3EE8AB28DEB5170ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13F7B730E2354024ULL,
		0xCDEFC516CD83241CULL,
		0x2C5D5AED6CAE240DULL,
		0x83CFE63E45BE978AULL,
		0x59B48A53E24B7C5BULL,
		0x2BC7616350E8F46AULL,
		0xB16C550EE7FDE405ULL,
		0x65C0CFB491EC1C98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC0A7BDD815C6CB4ULL,
		0x94F64F294DEE6BC1ULL,
		0xCB43AA1E49F40654ULL,
		0xA44C84BCC82DA885ULL,
		0x422C44BEC8B1B527ULL,
		0x083497B3B9A21A46ULL,
		0xE6BCA0D513DAAA93ULL,
		0xBAC5774AC51B57E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17ED3B5360D8D370ULL,
		0x38F975ED7F94B85AULL,
		0x6119B0CF22BA1DB9ULL,
		0xDF8361817D90EF04ULL,
		0x178845951999C733ULL,
		0x2392C9AF9746DA24ULL,
		0xCAAFB439D4233972ULL,
		0xAAFB5869CCD0C4B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF755300F10B32748ULL,
		0x36784A1C3EF1CE35ULL,
		0x8E6D47B13EFA2E3FULL,
		0x7A3DB661A1DCC98CULL,
		0x3BF12A3185855BB9ULL,
		0x34286E498CEAC8B8ULL,
		0xE046513D70A51578ULL,
		0xE31501E04B1100B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE548B2D62A24DA6ULL,
		0x11BCC6C4D35D91BBULL,
		0xBC1B36C2037F87D1ULL,
		0x21CFD866103ACCD7ULL,
		0x5FD3170A5D0540A7ULL,
		0x3142CEFF9D666EB1ULL,
		0x2C0DAC17F60D71B1ULL,
		0x6D97189E6857390DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1900A4E1AE10D9A2ULL,
		0x24BB83576B943C7AULL,
		0xD25210EF3B7AA66EULL,
		0x586DDDFB91A1FCB4ULL,
		0xDC1E132728801B12ULL,
		0x02E59F49EF845A06ULL,
		0xB438A5257A97A3C7ULL,
		0x757DE941E2B9C7ACULL
	}};
	sign = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E09483882865EDCULL,
		0xD86C37DE2CBA1039ULL,
		0x8B1775FC8D0835E0ULL,
		0x25B37D99F7DD6845ULL,
		0x0450BF0094D60332ULL,
		0xB1ED434A4BE0AD75ULL,
		0x4641147CC7774DD5ULL,
		0x5312AEB3757134ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D41549F004272BCULL,
		0xEEE923EEB589C410ULL,
		0x3E6118B9ED95C1ABULL,
		0x347192C4AC0836F9ULL,
		0xD5DA66F5434690AFULL,
		0x716FF745569160D7ULL,
		0xECC90201FE6E4583ULL,
		0x30769A07E4B2B51DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0C7F3998243EC20ULL,
		0xE98313EF77304C28ULL,
		0x4CB65D429F727434ULL,
		0xF141EAD54BD5314CULL,
		0x2E76580B518F7282ULL,
		0x407D4C04F54F4C9DULL,
		0x5978127AC9090852ULL,
		0x229C14AB90BE7F8FULL
	}};
	sign = 0;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3950FF2582C9C3C9ULL,
		0x98A51DEF6AF78AA5ULL,
		0x2DB97A38085BB886ULL,
		0x3C1C36E3F7C5ACEEULL,
		0xB9322DA18AD18A99ULL,
		0x77EA9E9073D2328EULL,
		0x8AB19D3A0A9E79D6ULL,
		0x82CE58E3BF7261BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1DD1F083F490F7ULL,
		0x0F8BA8796AF27551ULL,
		0xA25F08C555BDC1A1ULL,
		0xFD5331337D7142A4ULL,
		0x35FEF96525338DE3ULL,
		0xB42386317674B9E5ULL,
		0xFC91AE79649F7250ULL,
		0x095CFE5D016FEDEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA332D34FED532D2ULL,
		0x8919757600051553ULL,
		0x8B5A7172B29DF6E5ULL,
		0x3EC905B07A546A49ULL,
		0x8333343C659DFCB5ULL,
		0xC3C7185EFD5D78A9ULL,
		0x8E1FEEC0A5FF0785ULL,
		0x79715A86BE0273CCULL
	}};
	sign = 0;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC1BC86BE127BFC4ULL,
		0x194A3F4E52DE921DULL,
		0x92A87A5254DA1B7BULL,
		0xD120884D70D66E5EULL,
		0x50FEA9A7E1C809DBULL,
		0x7C7C28ADB144B0B9ULL,
		0x875617E8DE403FBDULL,
		0x7F62E03C46BC888EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56EC56D11AB59C34ULL,
		0x6694252D35F9A765ULL,
		0x8A3123752979DC24ULL,
		0x090E8AD4DB663590ULL,
		0x6A393451FAADAB8DULL,
		0xC9FD9DC8589F16FCULL,
		0xC5B61EC55A56EB31ULL,
		0x34E84054A9912BB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x852F719AC6722390ULL,
		0xB2B61A211CE4EAB8ULL,
		0x087756DD2B603F56ULL,
		0xC811FD78957038CEULL,
		0xE6C57555E71A5E4EULL,
		0xB27E8AE558A599BCULL,
		0xC19FF92383E9548BULL,
		0x4A7A9FE79D2B5CD5ULL
	}};
	sign = 0;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3F3816811803B43ULL,
		0xC202307046B09748ULL,
		0x5D63FFBDBB7C0FA2ULL,
		0xCCEC30B108E2CC30ULL,
		0xFB955EBE12928AA9ULL,
		0x1BC5192B7708D5BBULL,
		0x85012A3103409DBAULL,
		0x3E2F2251734BC045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54CF6CF10B5700D6ULL,
		0x7F58788E0B2C1A58ULL,
		0x552521EADED12617ULL,
		0x1A5D7BB898CFED1FULL,
		0x4A6503DA11C97B30ULL,
		0x0138E923910F3FD4ULL,
		0x35F63A0ACE4448DEULL,
		0xC4F77B0BD421B8B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F24147706293A6DULL,
		0x42A9B7E23B847CF0ULL,
		0x083EDDD2DCAAE98BULL,
		0xB28EB4F87012DF11ULL,
		0xB1305AE400C90F79ULL,
		0x1A8C3007E5F995E7ULL,
		0x4F0AF02634FC54DCULL,
		0x7937A7459F2A078DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B1DEE0EC6C96894ULL,
		0x39084AEBF7E9687AULL,
		0x2360B36648242769ULL,
		0x1EB7039B6F072C39ULL,
		0xB9E5E8D51574B49BULL,
		0x7BFB667632DED03BULL,
		0x9673CE96486E01D7ULL,
		0x88A5BE862EB6D657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01520457E0F8696ULL,
		0x9FA7F2FD6710D69AULL,
		0x53B7794DAFF7F954ULL,
		0x1824282957BECEFDULL,
		0xD1CC0A5C7F55185DULL,
		0xECF39B2679FE6559ULL,
		0x9973563705DFF6AFULL,
		0x7E445D9B0EA0CC23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B08CDC948B9E1FEULL,
		0x996057EE90D891DFULL,
		0xCFA93A18982C2E14ULL,
		0x0692DB7217485D3BULL,
		0xE819DE78961F9C3EULL,
		0x8F07CB4FB8E06AE1ULL,
		0xFD00785F428E0B27ULL,
		0x0A6160EB20160A33ULL
	}};
	sign = 0;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC79699A6A6A9056DULL,
		0x98F7207DB6E4A405ULL,
		0xCF3A23063B9E98B1ULL,
		0x5FB7531716941341ULL,
		0xD235F6DAD30F21FAULL,
		0x7D890E47F002C74CULL,
		0x68284F5654581B50ULL,
		0xA5870A0DAF3EABA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C9E4B5537CDF6D2ULL,
		0xED46ED90B6DAD5A7ULL,
		0xAE55882453EF44CCULL,
		0xD760E9D2AC012003ULL,
		0x60E4E3F85784981AULL,
		0xC1ECC12FF9BEADD3ULL,
		0xE047939BE15ED8C6ULL,
		0x289C6034A55909DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF84E516EDB0E9BULL,
		0xABB032ED0009CE5EULL,
		0x20E49AE1E7AF53E4ULL,
		0x885669446A92F33EULL,
		0x715112E27B8A89DFULL,
		0xBB9C4D17F6441979ULL,
		0x87E0BBBA72F94289ULL,
		0x7CEAA9D909E5A1CBULL
	}};
	sign = 0;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x696AB598153B88E7ULL,
		0xAA3E48988023CD91ULL,
		0x0528D7DDDDA13C2BULL,
		0x14F778C91FDB79C8ULL,
		0xFA2A089EBE8E2C11ULL,
		0xF36FACF3955AB44EULL,
		0x76C49689F132CF05ULL,
		0xE78DD108A70B0F8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB511F7939A843074ULL,
		0xD277D78185F13586ULL,
		0xB73A6456234F5358ULL,
		0x602821014B6AB348ULL,
		0x4CB22ABA296D13BDULL,
		0xBB57C7E1FE357BE2ULL,
		0x18F81D3984996749ULL,
		0x39ECD6CD33EA2CC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB458BE047AB75873ULL,
		0xD7C67116FA32980AULL,
		0x4DEE7387BA51E8D2ULL,
		0xB4CF57C7D470C67FULL,
		0xAD77DDE495211853ULL,
		0x3817E5119725386CULL,
		0x5DCC79506C9967BCULL,
		0xADA0FA3B7320E2C4ULL
	}};
	sign = 0;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50666DED43796453ULL,
		0x75C643AA09BE1C85ULL,
		0xF64114E1FE41F914ULL,
		0x71A0661E58A20C48ULL,
		0x7566F50C5CADCCF2ULL,
		0x9DF428011A248F57ULL,
		0x0BDB0D46E161EE2BULL,
		0x6E9A5342FB14FC53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C6AAD0622FC94FULL,
		0x0AB6962D2365E476ULL,
		0x15E46FF69E8469A9ULL,
		0x52BCD7CAD533BC88ULL,
		0x3C7919D716C6BFAAULL,
		0x3589B87CBF5AECADULL,
		0xB662B9F7096D2F5BULL,
		0xB7C65078871E0204ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA9FC31CE1499B04ULL,
		0x6B0FAD7CE658380EULL,
		0xE05CA4EB5FBD8F6BULL,
		0x1EE38E53836E4FC0ULL,
		0x38EDDB3545E70D48ULL,
		0x686A6F845AC9A2AAULL,
		0x5578534FD7F4BED0ULL,
		0xB6D402CA73F6FA4EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDB7C76DE60B9F7BULL,
		0x636CC3D51EC62462ULL,
		0xC98CBD8D4EE0DC40ULL,
		0x14DC01E45C425AAAULL,
		0xEA914A2597FE76EFULL,
		0x1696898549D63CB0ULL,
		0x1579D86EEE06462BULL,
		0x7AD042B6AC5FE9E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3537A26EB7ACA0B2ULL,
		0x591613C20A054436ULL,
		0xA422A8DB0A013834ULL,
		0x90E0199DD7A4BD7BULL,
		0x00334B1B3B357D68ULL,
		0xFF47410833B2DC6AULL,
		0xD9E2778B020F5651ULL,
		0xF02B5C0E93596038ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC88024FF2E5EFEC9ULL,
		0x0A56B01314C0E02CULL,
		0x256A14B244DFA40CULL,
		0x83FBE846849D9D2FULL,
		0xEA5DFF0A5CC8F986ULL,
		0x174F487D16236046ULL,
		0x3B9760E3EBF6EFD9ULL,
		0x8AA4E6A8190689ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6087087EEA87471CULL,
		0xF9E5A1C4979B8716ULL,
		0xAB5FA34CB1838297ULL,
		0xA078C81C7778EA4FULL,
		0x3DA847987046E7BDULL,
		0xE849632F7D7A5E1FULL,
		0x5ADDD6287CA20CC1ULL,
		0x9DA8A4CBB0995539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DABD9A34693CCCULL,
		0x630C96DF6070917FULL,
		0xCF026EB289044A61ULL,
		0xC64E038B94C5510CULL,
		0x67F42BDAE6FD9BF5ULL,
		0x4EBA4163E3DF2A17ULL,
		0x5BFFC93F4B0562B4ULL,
		0xB2ADC7F6972AE2E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDAC4AE4B61E0A50ULL,
		0x96D90AE5372AF596ULL,
		0xDC5D349A287F3836ULL,
		0xDA2AC490E2B39942ULL,
		0xD5B41BBD89494BC7ULL,
		0x998F21CB999B3407ULL,
		0xFEDE0CE9319CAA0DULL,
		0xEAFADCD5196E7258ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x086F59925150457DULL,
		0x50AEF04496992335ULL,
		0xB79B027ECBE09C3DULL,
		0x7B239B952EEC615EULL,
		0xACEEE1C07C7302DCULL,
		0x1D85B3E1B8EFE07DULL,
		0xFB77E497D301CDECULL,
		0x5270D620FDD6CB39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07944FC46139FAF5ULL,
		0x45FB9537D7592509ULL,
		0xBDBAB6834F8CA52EULL,
		0x798C6487B137F0A1ULL,
		0xCA4406D8B98FA0C9ULL,
		0x5A2095E8C4E22AECULL,
		0xF85E1DDD7EC6FE0FULL,
		0x9C2B79EA47A8E8A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00DB09CDF0164A88ULL,
		0x0AB35B0CBF3FFE2CULL,
		0xF9E04BFB7C53F70FULL,
		0x0197370D7DB470BCULL,
		0xE2AADAE7C2E36213ULL,
		0xC3651DF8F40DB590ULL,
		0x0319C6BA543ACFDCULL,
		0xB6455C36B62DE297ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B051A6B955302B4ULL,
		0xC4F0235FAAA37A78ULL,
		0x6D788A97FD7006D9ULL,
		0x1541EA5EB38B06BAULL,
		0xAB51CE3268D1C21CULL,
		0x6BB862F0761B089DULL,
		0x4D14B05E647179A3ULL,
		0xB7FDDCE123DC9273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5486F4A52A08B2ULL,
		0x1FAA79E40BC5BCEAULL,
		0xB02CF62BA57D4A24ULL,
		0x5A3FC55C18FB48CDULL,
		0xC91774E8624AF6DCULL,
		0x03BDC9B1534DAAF5ULL,
		0x0BCEDE95811D456FULL,
		0x7CC43139AE4A9DB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EB09376F028FA02ULL,
		0xA545A97B9EDDBD8EULL,
		0xBD4B946C57F2BCB5ULL,
		0xBB0225029A8FBDECULL,
		0xE23A594A0686CB3FULL,
		0x67FA993F22CD5DA7ULL,
		0x4145D1C8E3543434ULL,
		0x3B39ABA77591F4BDULL
	}};
	sign = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1665244470FDE583ULL,
		0xE8CF799DEF07A877ULL,
		0x3193A7E244A663B3ULL,
		0x3394EA6496D20D05ULL,
		0x063CBAB93C7EEAFFULL,
		0xAB8EA77592B7EFEFULL,
		0x55E0D994D9E64C6DULL,
		0x24AE86C45110DBEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B7D559619251C8ULL,
		0x19DE55BB748CF395ULL,
		0xB49C64850E6F24CFULL,
		0x5A81EFCE12059B8AULL,
		0x8E08515920F6C8EFULL,
		0x86F3DD60410D9B54ULL,
		0x4FB0EFE495CD2B50ULL,
		0xDA1B8246FBE687A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83AD4EEB0F6B93BBULL,
		0xCEF123E27A7AB4E1ULL,
		0x7CF7435D36373EE4ULL,
		0xD912FA9684CC717AULL,
		0x783469601B88220FULL,
		0x249ACA1551AA549AULL,
		0x062FE9B04419211DULL,
		0x4A93047D552A544AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB99993FF089098CAULL,
		0xB62B95750DB12C4AULL,
		0x5154D0FDA2F35AC7ULL,
		0xF2E1BC391A47B88BULL,
		0xE5BA02A688E365A6ULL,
		0x5B2022F67F3F19DCULL,
		0x7261B0613DFD3832ULL,
		0xF9957CB4AF01582BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A0760BA13FF037ULL,
		0xE17FCABEE76CB49FULL,
		0xEA4A3C99483E183CULL,
		0xFFDDEC54253E9429ULL,
		0xA7B7939EF18E8C2CULL,
		0x599C5EA75F99AF97ULL,
		0xA371349A61963DCCULL,
		0xCF9D1736694D3E59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2F91DF36750A893ULL,
		0xD4ABCAB6264477ABULL,
		0x670A94645AB5428AULL,
		0xF303CFE4F5092461ULL,
		0x3E026F079754D979ULL,
		0x0183C44F1FA56A45ULL,
		0xCEF07BC6DC66FA66ULL,
		0x29F8657E45B419D1ULL
	}};
	sign = 0;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBE10DC9455C4663ULL,
		0x78667F09B42CD8ECULL,
		0x0522D1DA8D20BFDCULL,
		0x819E6E9F97EB5867ULL,
		0xA06A2166436DA201ULL,
		0xB2368092F95829A7ULL,
		0x3513822D9B2456FCULL,
		0xCA22D127DE13FD15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x887A7FF611B2453BULL,
		0x86DBB338B8CE6E44ULL,
		0x215EF75F00673181ULL,
		0x68389A515DE545E6ULL,
		0x06710B52C25C1A59ULL,
		0xEDE10DE15E2EAF36ULL,
		0xDC6445691ED97BF5ULL,
		0x0BA9C1045CE0C215ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53668DD333AA0128ULL,
		0xF18ACBD0FB5E6AA8ULL,
		0xE3C3DA7B8CB98E5AULL,
		0x1965D44E3A061280ULL,
		0x99F91613811187A8ULL,
		0xC45572B19B297A71ULL,
		0x58AF3CC47C4ADB06ULL,
		0xBE79102381333AFFULL
	}};
	sign = 0;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AA2A866046AE5A1ULL,
		0x3E72F50FDA74BAF4ULL,
		0x9F698728CA6908D9ULL,
		0xC968A8E686E8B1B9ULL,
		0x655A0487A50234A7ULL,
		0xE1C192A239D036DFULL,
		0xA6F39696384E0CBCULL,
		0x0AFC6E74F7D20F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x112871829B4F183EULL,
		0xCA6E6457AF1384C0ULL,
		0xEF46E38E7FD28F72ULL,
		0xAF00D4B63A2D345AULL,
		0xEA26124F46199831ULL,
		0x05563640D37B2252ULL,
		0x5D259E555DA69C7EULL,
		0x1FBEE8B4CD7E2163ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x897A36E3691BCD63ULL,
		0x740490B82B613634ULL,
		0xB022A39A4A967966ULL,
		0x1A67D4304CBB7D5EULL,
		0x7B33F2385EE89C76ULL,
		0xDC6B5C616655148CULL,
		0x49CDF840DAA7703EULL,
		0xEB3D85C02A53EDEEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FCB17C563BC4E30ULL,
		0x9F1EB113709015DFULL,
		0x5EEAAA826774F88EULL,
		0x1DF0F81392C8EBF5ULL,
		0xEE082F21480AEFB4ULL,
		0x40C55F30D1A3F476ULL,
		0x99522ADB98B04F86ULL,
		0x24DA7B2E8CE9CFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA28531140FF3312ULL,
		0x48FBCBA7BDC7F71CULL,
		0xC92AB11F6C490802ULL,
		0x627FCB1F01958690ULL,
		0x8EA581A7F24E3456ULL,
		0x010980A41704F3E7ULL,
		0x40E82C6198EFBD4EULL,
		0xC2C49812C1C85A85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85A2C4B422BD1B1EULL,
		0x5622E56BB2C81EC2ULL,
		0x95BFF962FB2BF08CULL,
		0xBB712CF491336564ULL,
		0x5F62AD7955BCBB5DULL,
		0x3FBBDE8CBA9F008FULL,
		0x5869FE79FFC09238ULL,
		0x6215E31BCB217565ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0C8FF04FC97140BULL,
		0xA143859A333DBDF5ULL,
		0x9457D93A371771B3ULL,
		0x572AC01CF5BD934FULL,
		0xE48B02B8B870A0D1ULL,
		0x9373E59DD905B80CULL,
		0x64331CB1C94E36A4ULL,
		0x95BEBD1EBF281129ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x709A3ED4EA9ABD03ULL,
		0x033A612FB22E2C41ULL,
		0x2C0F41EE2DDE912BULL,
		0x5F86C641E01A9B20ULL,
		0x67E874772C98041DULL,
		0x0DA8CAF4E81644E1ULL,
		0x8E763CF8CE6A9B70ULL,
		0xA612F68B76C9C4B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302EC03011FC5708ULL,
		0x9E09246A810F91B4ULL,
		0x6848974C0938E088ULL,
		0xF7A3F9DB15A2F82FULL,
		0x7CA28E418BD89CB3ULL,
		0x85CB1AA8F0EF732BULL,
		0xD5BCDFB8FAE39B34ULL,
		0xEFABC693485E4C78ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x462E2D574BA6068CULL,
		0x21B10DD89CCF49D9ULL,
		0x1BEEBAECCAE026BCULL,
		0xC2C77F38FB9D3393ULL,
		0x669B206967FC5A25ULL,
		0xCE185095DD912A7CULL,
		0x586EB891CFF6126FULL,
		0x0AA1AAA5CDA4BB4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7323F381E757BDEAULL,
		0x2E68AFABDEA185F7ULL,
		0xD3E07397ADA5D554ULL,
		0xE691D3B377EF8E02ULL,
		0x1BD3880F9662A9D7ULL,
		0x700E02A5CCF474C6ULL,
		0x834FFFC296AF1E90ULL,
		0x839D2EC85E2C2B07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD30A39D5644E48A2ULL,
		0xF3485E2CBE2DC3E1ULL,
		0x480E47551D3A5167ULL,
		0xDC35AB8583ADA590ULL,
		0x4AC79859D199B04DULL,
		0x5E0A4DF0109CB5B6ULL,
		0xD51EB8CF3946F3DFULL,
		0x87047BDD6F789042ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC952DA8FD1654F2AULL,
		0xF93C90BD704A5B8FULL,
		0x9513139735D3D14BULL,
		0xF9D24BD4FF85B105ULL,
		0xDD5C965BD38F229AULL,
		0xAFB9B1DE867B7AC1ULL,
		0xE287F3267D1F32FBULL,
		0xCF2A4BA025A959C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6092BFC5B4822891ULL,
		0x0BF9BDCA19260D4DULL,
		0x7A06366EDF2FD4AAULL,
		0x9DDD32E089B2D69AULL,
		0x99F6A7F0AF9B384EULL,
		0xC8D74CE316E6F246ULL,
		0x1E9B4409421999ABULL,
		0x8C4D3D6628859606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68C01ACA1CE32699ULL,
		0xED42D2F357244E42ULL,
		0x1B0CDD2856A3FCA1ULL,
		0x5BF518F475D2DA6BULL,
		0x4365EE6B23F3EA4CULL,
		0xE6E264FB6F94887BULL,
		0xC3ECAF1D3B05994FULL,
		0x42DD0E39FD23C3BBULL
	}};
	sign = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC3DF1DEF6B3BF5ULL,
		0xBD11794DF6681070ULL,
		0x5D4CBF0196B17BE5ULL,
		0xE52AC3C7FE9AE9FCULL,
		0xBDDC825D71D66495ULL,
		0xFC4A4180E3A90864ULL,
		0x48D07E7F141F1BDFULL,
		0xDFFD8DCFAD6885A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x704176BE08E5AA38ULL,
		0x9413D17D07BCAF5DULL,
		0xE8F31A37A221B200ULL,
		0xADFA09524D428443ULL,
		0xC819A4DD89727CE1ULL,
		0x8447D0A6475F0E08ULL,
		0xB57C5E945BB016D4ULL,
		0x0493A9411E6D6773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC82685FE68591BDULL,
		0x28FDA7D0EEAB6112ULL,
		0x7459A4C9F48FC9E5ULL,
		0x3730BA75B15865B8ULL,
		0xF5C2DD7FE863E7B4ULL,
		0x780270DA9C49FA5BULL,
		0x93541FEAB86F050BULL,
		0xDB69E48E8EFB1E2CULL
	}};
	sign = 0;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E87511DC298E43BULL,
		0xDD5C6ECD0A096217ULL,
		0xCE2DC1D9259563B4ULL,
		0x4878451D678B1348ULL,
		0x466AF772EBB641BBULL,
		0x07ED7B5A7731EAE8ULL,
		0x4378BCB58D8842B9ULL,
		0x1F3EF57C3BEADC60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37A4ACADE9BD33F0ULL,
		0x1FDBA58EF8008421ULL,
		0x046D4099C9007CD4ULL,
		0xA5349D08A178C592ULL,
		0x72CAED10D8202685ULL,
		0x41F0C2ADFF72C8DAULL,
		0x9F4ABBBF1F4F3B43ULL,
		0x3C126F02194CE371ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36E2A46FD8DBB04BULL,
		0xBD80C93E1208DDF6ULL,
		0xC9C0813F5C94E6E0ULL,
		0xA343A814C6124DB6ULL,
		0xD3A00A6213961B35ULL,
		0xC5FCB8AC77BF220DULL,
		0xA42E00F66E390775ULL,
		0xE32C867A229DF8EEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0F5D994A1DDF67BULL,
		0x273DCF8067D1E45EULL,
		0xCF57CE5826965BD7ULL,
		0x505EAD47D0AD5A7AULL,
		0x364B093CC48DC637ULL,
		0x0E3DDCF387D12153ULL,
		0x28BA1222783B7C0BULL,
		0xD9DC4389D3EEE11EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF004A19F840AF2ABULL,
		0xB4E47E2AC9DEB78DULL,
		0xABD0E2F42C0A93F8ULL,
		0x7220EA48CE680413ULL,
		0xDF8F554EBE57A66EULL,
		0x3BDB91747503CC12ULL,
		0xB909D345C1B8E150ULL,
		0x09DD28A1EBBFEF97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0F137F51DD303D0ULL,
		0x725951559DF32CD0ULL,
		0x2386EB63FA8BC7DEULL,
		0xDE3DC2FF02455667ULL,
		0x56BBB3EE06361FC8ULL,
		0xD2624B7F12CD5540ULL,
		0x6FB03EDCB6829ABAULL,
		0xCFFF1AE7E82EF186ULL
	}};
	sign = 0;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA011E7F8793F8E7BULL,
		0x5623560FBB91735AULL,
		0x1D4CA23E9831B8AAULL,
		0x8AC22CC2C7E4A533ULL,
		0x5237C688C088757BULL,
		0xB6FC4927A947D8C8ULL,
		0x0EA5696F07267311ULL,
		0x9C87AB982261EF02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33516DDA8CCCC98ULL,
		0x85ED40E6FD6E6757ULL,
		0xC667DB412F58875BULL,
		0x81A21A1B066D5799ULL,
		0xB3E6300387D168F7ULL,
		0xBEC85F91FDB7A5E0ULL,
		0xAB91CEBFA96E3D50ULL,
		0x055F33E8EE8FA99BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDCDCD11AD072C1E3ULL,
		0xD0361528BE230C02ULL,
		0x56E4C6FD68D9314EULL,
		0x092012A7C1774D99ULL,
		0x9E51968538B70C84ULL,
		0xF833E995AB9032E7ULL,
		0x63139AAF5DB835C0ULL,
		0x972877AF33D24566ULL
	}};
	sign = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2A8A13B087F752DULL,
		0x016B1F29FCA23801ULL,
		0x9483685A27B90008ULL,
		0x288D95919DCC40E0ULL,
		0xE799E3D5197519ECULL,
		0x8C1B22274020C41AULL,
		0x04987D272DFAB011ULL,
		0xB7E67BE492961128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BD2CC800702609CULL,
		0xFCB0E6223ED2D1ACULL,
		0x9ECAC043B428E2D5ULL,
		0x5A52BF5D1A9A2CF3ULL,
		0x14375FC4A0E76376ULL,
		0x59FF0FE77DCCFA48ULL,
		0x4DAEC0B26CE1091BULL,
		0xC139D83D3DEA0E52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76D5D4BB017D1491ULL,
		0x04BA3907BDCF6655ULL,
		0xF5B8A81673901D32ULL,
		0xCE3AD634833213ECULL,
		0xD3628410788DB675ULL,
		0x321C123FC253C9D2ULL,
		0xB6E9BC74C119A6F6ULL,
		0xF6ACA3A754AC02D5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC956326A878D88BULL,
		0xA794B85B75B66C0BULL,
		0xAB9DA14C469765A8ULL,
		0x26FBD2CE4C7B782FULL,
		0x4D40EFB3598687D6ULL,
		0x7058FE8DFF9B888CULL,
		0x0404AD5F05FD58BCULL,
		0x0F7E7990C610435EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19BCE989F19660C7ULL,
		0xA0D5596B3CEC66B4ULL,
		0xDD9337A477EA9C38ULL,
		0x3B8148CD6C2BA988ULL,
		0x34794722A0707179ULL,
		0xE3C468133319F38CULL,
		0xD8B0F370919FA300ULL,
		0x42C835A37C0D3859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2D8799CB6E277C4ULL,
		0x06BF5EF038CA0557ULL,
		0xCE0A69A7CEACC970ULL,
		0xEB7A8A00E04FCEA6ULL,
		0x18C7A890B916165CULL,
		0x8C94967ACC819500ULL,
		0x2B53B9EE745DB5BBULL,
		0xCCB643ED4A030B04ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3A0BE99EE07C972ULL,
		0xF538AB38FE8C504BULL,
		0x392B7D9EF661958FULL,
		0x3589F167E172EAEBULL,
		0xE441F94ACEBD7C37ULL,
		0x361D544048C6DE0BULL,
		0x7FD58D7A9EE43FBFULL,
		0x7F055C32D99F38C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A8C69FD46844E95ULL,
		0x1FABC019AC3F68C8ULL,
		0x4662DAE5503B8E5EULL,
		0x20F087B85EE95D7CULL,
		0xFFF7FA64B88592EDULL,
		0x514FD002EA2875A3ULL,
		0xD6BE53D2853A9E52ULL,
		0x6010DD8272397F2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9914549CA7837ADDULL,
		0xD58CEB1F524CE783ULL,
		0xF2C8A2B9A6260731ULL,
		0x149969AF82898D6EULL,
		0xE449FEE61637E94AULL,
		0xE4CD843D5E9E6867ULL,
		0xA91739A819A9A16CULL,
		0x1EF47EB06765B99AULL
	}};
	sign = 0;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA66C4A2B3F6788AFULL,
		0x4BA4E08BA4118878ULL,
		0xE562A150FB42CE7AULL,
		0x7ABBEC6313F19F4EULL,
		0xCED3F89374C7FB0EULL,
		0xCB629CB8908B41A0ULL,
		0x97C6545EBF14F118ULL,
		0xB49EFCC3581B1610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7021465226518BULL,
		0xAD044DF5CB30A4FBULL,
		0xE7E4085F2DDC5FAEULL,
		0x74DD3F7EAD861CF8ULL,
		0xE902AB7117839DEBULL,
		0x57931D0CDA8C8FD6ULL,
		0x70332B2327933DA7ULL,
		0x69502880BA7DF1A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26FC28E4ED413724ULL,
		0x9EA09295D8E0E37DULL,
		0xFD7E98F1CD666ECBULL,
		0x05DEACE4666B8255ULL,
		0xE5D14D225D445D23ULL,
		0x73CF7FABB5FEB1C9ULL,
		0x2793293B9781B371ULL,
		0x4B4ED4429D9D2467ULL
	}};
	sign = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA12F8F7C11DFCDDULL,
		0xD8A752EED9F9DD18ULL,
		0xB38D2CBF825A7E03ULL,
		0x55368F0EF8073009ULL,
		0x060C97A3BDF31D65ULL,
		0x9FC21606E665C5B6ULL,
		0xE7F4552E68F855A6ULL,
		0x29E34D746561D2FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD82CDCA0C171F491ULL,
		0x9E2C31E604CB711FULL,
		0x0737512D43CD31BAULL,
		0x723F9384FF003870ULL,
		0x714DA17F55DF4C0CULL,
		0x1FD946CF8F888330ULL,
		0x19792817F166FD3DULL,
		0xA30EF9383B24D588ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01E61C56FFAC084CULL,
		0x3A7B2108D52E6BF9ULL,
		0xAC55DB923E8D4C49ULL,
		0xE2F6FB89F906F799ULL,
		0x94BEF6246813D158ULL,
		0x7FE8CF3756DD4285ULL,
		0xCE7B2D1677915869ULL,
		0x86D4543C2A3CFD73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC99273C248C90D8ULL,
		0x01DA3723762CEACAULL,
		0x63BE721BC23D6656ULL,
		0x791758DBA001260AULL,
		0xEEF2E49DA1F4E523ULL,
		0x0895A502BEB2AEDAULL,
		0x39B425DF59A9586DULL,
		0x719B3EB766444603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8C6605D9D3FD2C7ULL,
		0x20F19DB7DFFDDCBFULL,
		0x8E9B8A6E177F6B8DULL,
		0x871692961C5736A1ULL,
		0x58ECD7112679B823ULL,
		0x157BEC7A1D65DE90ULL,
		0x73CE73CEADCEB47BULL,
		0xBA70023F07E6D225ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3D2C6DE874CBE11ULL,
		0xE0E8996B962F0E0AULL,
		0xD522E7ADAABDFAC8ULL,
		0xF200C64583A9EF68ULL,
		0x96060D8C7B7B2CFFULL,
		0xF319B888A14CD04AULL,
		0xC5E5B210ABDAA3F1ULL,
		0xB72B3C785E5D73DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E180E6E8C9C865ULL,
		0x8EF0F9AE7498C594ULL,
		0x6A8190683AD001B7ULL,
		0x9124553AACCE6CC6ULL,
		0x76BD24C66A769594ULL,
		0x072E59CD0DFA14BCULL,
		0x843E2A7BC8E8815AULL,
		0x6F3F82E7B343DF38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1039EFB1E5DDB84ULL,
		0x3957B57CE6A784E1ULL,
		0x1AB20AC5621EF37AULL,
		0x5B0A7E5BA33EFF55ULL,
		0x2023650E418E3148ULL,
		0x9603045550B6C298ULL,
		0x16D526334187EC9FULL,
		0xF6D8930875D40510ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4DDE1EBCA6BECE1ULL,
		0x559944318DF140B2ULL,
		0x4FCF85A2D8B10E3DULL,
		0x3619D6DF098F6D71ULL,
		0x5699BFB828E8644CULL,
		0x712B5577BD435224ULL,
		0x6D690448876094BAULL,
		0x7866EFDF3D6FDA28ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x488CAE9F1224252BULL,
		0x7C8DA56CA8CEF342ULL,
		0xAB219658421B2D4EULL,
		0x54677A5807A0A3B2ULL,
		0x6A01AB8032B1EBC0ULL,
		0xA5E3CC5DAABBD17AULL,
		0xF3336F85AC8D86A3ULL,
		0x5214EB7D2F7B1DFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC576F8A93104822ULL,
		0x1722AC10F368A290ULL,
		0x7C1DD9075EC86185ULL,
		0x9B97E3CAEC629116ULL,
		0x95A46F540B24206AULL,
		0x808353657F429552ULL,
		0xF306D6AF9A5BF660ULL,
		0x3A8B51570CF4D1DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C353F147F13DD09ULL,
		0x656AF95BB56650B1ULL,
		0x2F03BD50E352CBC9ULL,
		0xB8CF968D1B3E129CULL,
		0xD45D3C2C278DCB55ULL,
		0x256078F82B793C27ULL,
		0x002C98D612319043ULL,
		0x17899A2622864C20ULL
	}};
	sign = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09E3598B19E78513ULL,
		0x2055E963F5778DC8ULL,
		0x5BCEC8D0E6B121FEULL,
		0xC92012AC0038E1CEULL,
		0x8C8AE8586BEDBCFDULL,
		0x79A5F5468B9AE7B1ULL,
		0xC948799F8A3D7521ULL,
		0xD9EE1B4F7752C066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x151C7CC71859E58DULL,
		0xA723F0973E336135ULL,
		0xA821980AA31E8D75ULL,
		0x84766690E33A5CD9ULL,
		0x6CF7DB3F1BFC6BDBULL,
		0xCE978026995C77E5ULL,
		0x85E93F054D4F9353ULL,
		0xA2218A9A943AC0C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4C6DCC4018D9F86ULL,
		0x7931F8CCB7442C92ULL,
		0xB3AD30C643929488ULL,
		0x44A9AC1B1CFE84F4ULL,
		0x1F930D194FF15122ULL,
		0xAB0E751FF23E6FCCULL,
		0x435F3A9A3CEDE1CDULL,
		0x37CC90B4E317FFA2ULL
	}};
	sign = 0;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5981D9EF3908AA9ULL,
		0x08C6D91B1B7817B6ULL,
		0xFC67928B715DB5E3ULL,
		0x30C8188B8719C3E8ULL,
		0x4F88212D6806882CULL,
		0x84D63439176DEDBEULL,
		0x58BF9DD92EBA5457ULL,
		0x27C8A22744F7CED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D014A517A4B3F7ULL,
		0x1103303E1235E6BFULL,
		0xD97D8E160246FE4FULL,
		0xB7D95A4B54CAC9BDULL,
		0x70F6D40A28D098F7ULL,
		0x148D79FC7214E0CEULL,
		0x78206560CFC4499CULL,
		0x4DB92C50DB87CAA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0C808F9DBEBD6B2ULL,
		0xF7C3A8DD094230F6ULL,
		0x22EA04756F16B793ULL,
		0x78EEBE40324EFA2BULL,
		0xDE914D233F35EF34ULL,
		0x7048BA3CA5590CEFULL,
		0xE09F38785EF60ABBULL,
		0xDA0F75D66970042AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6593673B56BEF06FULL,
		0x93E05F42E2AC15EAULL,
		0xE009E0B89B717AE8ULL,
		0x678018E40C5251D0ULL,
		0x1BF6191810BEFD89ULL,
		0xC07E8D887BF0A674ULL,
		0x9FD241A05D622C0EULL,
		0x586263111968E504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x908C8F08C64C36DBULL,
		0x5CD72A9FF67195F1ULL,
		0x1834F8FBF698EFC5ULL,
		0x7C29C9A9B738FE6DULL,
		0xB90C0D4FFEEF54B5ULL,
		0xF5DA78A3BDFC3996ULL,
		0x975359FA42991682ULL,
		0x6D9FA912059F2F2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD506D8329072B994ULL,
		0x370934A2EC3A7FF8ULL,
		0xC7D4E7BCA4D88B23ULL,
		0xEB564F3A55195363ULL,
		0x62EA0BC811CFA8D3ULL,
		0xCAA414E4BDF46CDDULL,
		0x087EE7A61AC9158BULL,
		0xEAC2B9FF13C9B5DAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC0834D2310A046ULL,
		0x782DBB5254C63D83ULL,
		0xE8568D12DEC97567ULL,
		0x288608E686CFB206ULL,
		0xD403914E126D2124ULL,
		0xB1D73E27EE00DF09ULL,
		0x6AC837CA3126CEAEULL,
		0x935355E361F32AE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD861213D591D17ULL,
		0x11A7C4CDC766DDF6ULL,
		0x185BB5110BF7FACAULL,
		0x8E0F11910A28C7D9ULL,
		0xC424D336225B5AE7ULL,
		0x73E519D708C09FB2ULL,
		0xA6659E6AB90F94E8ULL,
		0xAD8012D278BFB753ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDEE8222BE5B7832FULL,
		0x6685F6848D5F5F8CULL,
		0xCFFAD801D2D17A9DULL,
		0x9A76F7557CA6EA2DULL,
		0x0FDEBE17F011C63CULL,
		0x3DF22450E5403F57ULL,
		0xC462995F781739C6ULL,
		0xE5D34310E9337393ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6F3EEC27E8C94AEULL,
		0x9E3BA6B431ED750CULL,
		0x6FEB32815A26FB30ULL,
		0x31B94F95456DAFCEULL,
		0x32F27025688DA050ULL,
		0x6FA3B3051B556CF1ULL,
		0x0929AB87E6471914ULL,
		0xB6BE6AF6A3B5D35BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7BEFE60B332F42CULL,
		0x2EFC88C5FF776E20ULL,
		0xD79ED4FEF1916C96ULL,
		0x434428A5DB3E6966ULL,
		0x7DEED8A90228500FULL,
		0x73AC67A4A2070B32ULL,
		0xAB0C21F29B582862ULL,
		0xE80AAF98D312AD98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF34F061CB59A082ULL,
		0x6F3F1DEE327606EBULL,
		0x984C5D8268958E9AULL,
		0xEE7526EF6A2F4667ULL,
		0xB503977C66655040ULL,
		0xFBF74B60794E61BEULL,
		0x5E1D89954AEEF0B1ULL,
		0xCEB3BB5DD0A325C2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA9608D523E89F77ULL,
		0xE58193199F5563C6ULL,
		0x687CDABED0C2C0D1ULL,
		0x8EC247EE7A241102ULL,
		0x1C6E469CA746D49FULL,
		0xB70E1B7637B77DD1ULL,
		0xD3E48F3AB382B632ULL,
		0x1A3553D662CC4EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1659ACC2F09E1C3DULL,
		0x13B306B4F14D9FE8ULL,
		0x8FF190472C940B1CULL,
		0xE98484F1E98666CCULL,
		0xD367FC86238B1CE5ULL,
		0x498147027ED5F72CULL,
		0x7016A661BD51E0DEULL,
		0x22D11B95DB68E249ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE43C5C12334A833AULL,
		0xD1CE8C64AE07C3DEULL,
		0xD88B4A77A42EB5B5ULL,
		0xA53DC2FC909DAA35ULL,
		0x49064A1683BBB7B9ULL,
		0x6D8CD473B8E186A4ULL,
		0x63CDE8D8F630D554ULL,
		0xF764384087636CA9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE56E18989BE6829BULL,
		0x5FD1E408FFD0EF12ULL,
		0x012A99CE8A35C446ULL,
		0xAB46B5B714AA6FAEULL,
		0x633910E02E066CACULL,
		0x1030123DFE9B7634ULL,
		0x5C96D3B7739FF366ULL,
		0x58EEAF8B217E43ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x187CA3FD414C23B7ULL,
		0xF5814710B8D4BA34ULL,
		0x52B97496F23AF7B8ULL,
		0x050C15415763EED0ULL,
		0xBB0F89EB560D174CULL,
		0xCA14EBF8F3F2ED82ULL,
		0x6EEE31ACBEAB14DDULL,
		0xF0B6A2434B53906DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCF1749B5A9A5EE4ULL,
		0x6A509CF846FC34DEULL,
		0xAE71253797FACC8DULL,
		0xA63AA075BD4680DDULL,
		0xA82986F4D7F95560ULL,
		0x461B26450AA888B1ULL,
		0xEDA8A20AB4F4DE88ULL,
		0x68380D47D62AB33FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE7374B1F5C7DCAFULL,
		0xB947F182C258FDF9ULL,
		0x89F4005A19948568ULL,
		0x7C5333DBB349D7E6ULL,
		0xC7092374CD2B39A6ULL,
		0x6ADA116683335F8AULL,
		0xDBAB146E66363AE0ULL,
		0x6C51E56DDD03BB5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD68B532C78889EB9ULL,
		0x4D0B6FBDAEF95887ULL,
		0xDA8A27B66BD423DCULL,
		0xB5C059FB23BA78FEULL,
		0x750015D90BA5AEFEULL,
		0x0A45D4D95B229FC5ULL,
		0xF329D3CC724A0F3CULL,
		0xEB989BEF794F7CC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07E821857D3F3DF6ULL,
		0x6C3C81C5135FA572ULL,
		0xAF69D8A3ADC0618CULL,
		0xC692D9E08F8F5EE7ULL,
		0x52090D9BC1858AA7ULL,
		0x60943C8D2810BFC5ULL,
		0xE88140A1F3EC2BA4ULL,
		0x80B9497E63B43E93ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDB2AD7FDD3560ACULL,
		0x7092472D051BB061ULL,
		0x4D2D2D6A18398633ULL,
		0xA353A37EBD25393CULL,
		0x8F511BD5432F62F4ULL,
		0xC4D2AF05F7A94901ULL,
		0x8C73430DDBD9B855ULL,
		0xC8EB02CD8124D837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09CE6896AA5B293EULL,
		0xBDCFED0CC49707F4ULL,
		0x310A43A550BAD416ULL,
		0x39D54DC991775B62ULL,
		0x936B4AC72BC8F9CFULL,
		0x4B60E4366E1DD92AULL,
		0x3C25BE8FBFAF5C60ULL,
		0xB0E2421356CE1CF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3E444E932DA376EULL,
		0xB2C25A204084A86DULL,
		0x1C22E9C4C77EB21CULL,
		0x697E55B52BADDDDAULL,
		0xFBE5D10E17666925ULL,
		0x7971CACF898B6FD6ULL,
		0x504D847E1C2A5BF5ULL,
		0x1808C0BA2A56BB42ULL
	}};
	sign = 0;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEABDB3B942DB6A7CULL,
		0x7119FBCCEB6F1D90ULL,
		0x7E8CE04D10CDBA2DULL,
		0x60484D203CD4CAA4ULL,
		0xA785946FE3ACF000ULL,
		0x2F389D69E5F39019ULL,
		0x20B15FFCB07F91C5ULL,
		0x08B7D77D82A6ACBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA85D8A55492F11C2ULL,
		0xCAD300456F0A6965ULL,
		0x4E29388FC8B42680ULL,
		0xEBEB561386561497ULL,
		0x482E9D7242E8459BULL,
		0x22E426BC7C9FAE73ULL,
		0x550DE5515345EF92ULL,
		0xA70C0E73E95138FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42602963F9AC58BAULL,
		0xA646FB877C64B42BULL,
		0x3063A7BD481993ACULL,
		0x745CF70CB67EB60DULL,
		0x5F56F6FDA0C4AA64ULL,
		0x0C5476AD6953E1A6ULL,
		0xCBA37AAB5D39A233ULL,
		0x61ABC909995573BEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0BAC12DBDA0E61E2ULL,
		0xADCBF30D12A1FB94ULL,
		0xA44D8F6CAE12D379ULL,
		0xEC24E1E1B9AA151AULL,
		0x40B23FB04F201CD9ULL,
		0x83CC20536E266346ULL,
		0x276B5BEFF5E40674ULL,
		0x481C15FA8BD14504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A5CD75316C7B237ULL,
		0x6412ED9658B38718ULL,
		0xEEC4AD7BA5474470ULL,
		0x2C20709A8D08F85FULL,
		0x3C88E234587EB813ULL,
		0x9FF3ADA8CD5D1709ULL,
		0x26B40362C31D561BULL,
		0x8BAE369CD2BF2ED4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x714F3B88C346AFABULL,
		0x49B90576B9EE747BULL,
		0xB588E1F108CB8F09ULL,
		0xC00471472CA11CBAULL,
		0x04295D7BF6A164C6ULL,
		0xE3D872AAA0C94C3DULL,
		0x00B7588D32C6B058ULL,
		0xBC6DDF5DB9121630ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x479B959CCCF313C7ULL,
		0xEB23F6C3A9DC3302ULL,
		0x8D1C24F858D9D96DULL,
		0x4213EC351934A68EULL,
		0x92AA83704779DF11ULL,
		0x08E2D30EA49D7A0DULL,
		0x2CBEA4178EC94C8FULL,
		0x31330E99DB7EDFE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E344139FEC59F7ULL,
		0xD99513F671427D39ULL,
		0xF67ACE231FBEE314ULL,
		0x1F0594AB8AE4029AULL,
		0x6B5A2BF6753C3D8FULL,
		0x98B187975B46133CULL,
		0x95ED5D4EE6A8E038ULL,
		0x6B4471CB28DA7F37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42B851892D06B9D0ULL,
		0x118EE2CD3899B5C9ULL,
		0x96A156D5391AF659ULL,
		0x230E57898E50A3F3ULL,
		0x27505779D23DA182ULL,
		0x70314B77495766D1ULL,
		0x96D146C8A8206C56ULL,
		0xC5EE9CCEB2A460ACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CCDE16380CF8271ULL,
		0xEB344A269AB64B79ULL,
		0x53877098FDF8F3FFULL,
		0x17E5F036A82284D5ULL,
		0xAAAE3B7D1742AD1CULL,
		0x816E7CC4FF1C661CULL,
		0x265DE47694255922ULL,
		0x8334135CC4F4CF71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C62D039471C157ULL,
		0x37CB63E7813D8502ULL,
		0xC2619FB24C4AE21AULL,
		0x779218C62D78B8BEULL,
		0x71A3C3F07C0BCA08ULL,
		0x1D0FEF65766303CCULL,
		0x662E29B62895549CULL,
		0x8570E80731628094ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE307B45FEC5DC11AULL,
		0xB368E63F1978C676ULL,
		0x9125D0E6B1AE11E5ULL,
		0xA053D7707AA9CC16ULL,
		0x390A778C9B36E313ULL,
		0x645E8D5F88B96250ULL,
		0xC02FBAC06B900486ULL,
		0xFDC32B5593924EDCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E65AE0D1883B237ULL,
		0xCECBA7B16C71305BULL,
		0xEB82C68EED807F8AULL,
		0xC99954162F8FA700ULL,
		0xC3CB201AD90907D8ULL,
		0x35AF057C43CC9F64ULL,
		0x20D1868B74542295ULL,
		0x03400AE8094862ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F1A1BC0FC7882F4ULL,
		0xDB9C21816E17F48EULL,
		0x202F2DD8D8D38A75ULL,
		0xF44235EAF66E98A9ULL,
		0x72FE8D2A91726580ULL,
		0x4B3C1D83CCEE0F53ULL,
		0x8FC75D5E3833B4EAULL,
		0x9161A8FC58E2327CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF4B924C1C0B2F43ULL,
		0xF32F862FFE593BCCULL,
		0xCB5398B614ACF514ULL,
		0xD5571E2B39210E57ULL,
		0x50CC92F04796A257ULL,
		0xEA72E7F876DE9011ULL,
		0x910A292D3C206DAAULL,
		0x71DE61EBB066302EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32B57E37C3F57CC5ULL,
		0xECE3D68755BF3438ULL,
		0x08D88EF3EF72B546ULL,
		0x52C578DA32B320F4ULL,
		0xB25F9877FE046E63ULL,
		0xDB8EF3C81958FCF1ULL,
		0x2C9979FB4044D990ULL,
		0xBAF746A2C404ECDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E2E0A2933B973B2ULL,
		0x5CE9C77498F3B9F4ULL,
		0xFEC038993698272CULL,
		0x9D5AC0A0F5C7A9A8ULL,
		0xFF8048F8E09F7029ULL,
		0x63AF1B9B43D32B4FULL,
		0x33E2007E3C8DA3E4ULL,
		0xAA895B0D811C32B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0487740E903C0913ULL,
		0x8FFA0F12BCCB7A44ULL,
		0x0A18565AB8DA8E1AULL,
		0xB56AB8393CEB774BULL,
		0xB2DF4F7F1D64FE39ULL,
		0x77DFD82CD585D1A1ULL,
		0xF8B7797D03B735ACULL,
		0x106DEB9542E8BA26ULL
	}};
	sign = 0;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2435D8047E701E1EULL,
		0xAB7096580EA069B2ULL,
		0x6F7CF5749339CB8EULL,
		0x550279B818E4FC54ULL,
		0xF0540B9A618FD7D3ULL,
		0x2CA906BDD2200356ULL,
		0x0EE0D548E00E271CULL,
		0x7A1152EA744FAF48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08A356657C9C24CFULL,
		0xB8C1079261498B06ULL,
		0x4781757C580DE9C8ULL,
		0xD7DF488319AEB9F5ULL,
		0xD1B949CF752C11BCULL,
		0x550D70FBD4C113F7ULL,
		0x2FF76441F6E7710DULL,
		0x7C994AC20097C104ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B92819F01D3F94FULL,
		0xF2AF8EC5AD56DEACULL,
		0x27FB7FF83B2BE1C5ULL,
		0x7D233134FF36425FULL,
		0x1E9AC1CAEC63C616ULL,
		0xD79B95C1FD5EEF5FULL,
		0xDEE97106E926B60EULL,
		0xFD78082873B7EE43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F2A9FDAE3FE21A5ULL,
		0xD52DAF658F72AAC8ULL,
		0x5E4C8A495E19DBA9ULL,
		0x6973A176EBF47A32ULL,
		0x11D3704579017638ULL,
		0x0A39269E88A0BBC6ULL,
		0x064BB51783BCEF4CULL,
		0x25E071D61663A702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72074E3C082C021FULL,
		0x260DB526FECF8409ULL,
		0x45D7311E5B25BEF1ULL,
		0xB3390B4C8A2A43FDULL,
		0x75EA35436265E105ULL,
		0x7977CDBF3E4F0C60ULL,
		0x85440E05688AEC02ULL,
		0xCBC5863F8E8D888EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD23519EDBD21F86ULL,
		0xAF1FFA3E90A326BEULL,
		0x1875592B02F41CB8ULL,
		0xB63A962A61CA3635ULL,
		0x9BE93B02169B9532ULL,
		0x90C158DF4A51AF65ULL,
		0x8107A7121B320349ULL,
		0x5A1AEB9687D61E73ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2495AE2F836835B7ULL,
		0x5567E191AEAB5356ULL,
		0x3337062B7A73AA48ULL,
		0x2EB4B38735232D17ULL,
		0xCC0AB4D652DC4F94ULL,
		0x68651A8C8B2245B2ULL,
		0xD5505175A84D8A18ULL,
		0x47E5E61F95963B54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0D31B1D87530DE7ULL,
		0xC0623596CE125DF0ULL,
		0x0FF6393A33060861ULL,
		0xDF59A87AA55B4CF4ULL,
		0xE30598BD36887F9CULL,
		0xF0BD46DA01F38324ULL,
		0xA57C8CF5EE875B44ULL,
		0x30C2756C7159C7DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33C29311FC1527D0ULL,
		0x9505ABFAE098F565ULL,
		0x2340CCF1476DA1E6ULL,
		0x4F5B0B0C8FC7E023ULL,
		0xE9051C191C53CFF7ULL,
		0x77A7D3B2892EC28DULL,
		0x2FD3C47FB9C62ED3ULL,
		0x172370B3243C7375ULL
	}};
	sign = 0;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCD16EA2E46C3D00ULL,
		0xA0FCF533D02040E2ULL,
		0xA018EB7784509B1AULL,
		0x2A5168D3308F256DULL,
		0xF6FAFB679E490267ULL,
		0xA075252DFFB706F6ULL,
		0xB8FB9D2FF4B16AB5ULL,
		0x823CE2AA474E6F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9201AC211EFD81DULL,
		0x0A53927CCA06DCB3ULL,
		0xB5F609B94C65AC7AULL,
		0xB1DF623A69B32D56ULL,
		0x3C36A7C469527169ULL,
		0xDD68A15AA35D206FULL,
		0x5A6AB125D3DC097AULL,
		0x284BDC73D6B597EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3B153E0D27C64E3ULL,
		0x96A962B70619642EULL,
		0xEA22E1BE37EAEEA0ULL,
		0x78720698C6DBF816ULL,
		0xBAC453A334F690FDULL,
		0xC30C83D35C59E687ULL,
		0x5E90EC0A20D5613AULL,
		0x59F106367098D789ULL
	}};
	sign = 0;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D0429E5EBAC3018ULL,
		0x23E6BC6016434E66ULL,
		0xB46C1448A1F3392CULL,
		0x230ADDD26A813455ULL,
		0x6CCE0566CC525F33ULL,
		0x82A25D9FDBBADE8AULL,
		0x202F0123FE4997BAULL,
		0x98A1167F0F0B78AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5DE558DD5A2B8EULL,
		0x90F88D95CCFC78DCULL,
		0x19B67689385CABFDULL,
		0x184AF0D07FFD8DD1ULL,
		0xAACF5B71804D634DULL,
		0x61E3DA6CB42BB47FULL,
		0x049BC862EF3490F3ULL,
		0xA37216218F779061ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFA6448D0E52048AULL,
		0x92EE2ECA4946D589ULL,
		0x9AB59DBF69968D2EULL,
		0x0ABFED01EA83A684ULL,
		0xC1FEA9F54C04FBE6ULL,
		0x20BE8333278F2A0AULL,
		0x1B9338C10F1506C7ULL,
		0xF52F005D7F93E84DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C52F58D40827CDDULL,
		0x08475D162E065BB5ULL,
		0xFFBED62A201D7012ULL,
		0x4C65286182D60379ULL,
		0x1645ED2BE29EF101ULL,
		0xD6911177951ADA37ULL,
		0xD0866C9A23FF7FA1ULL,
		0x743A9DA1EADBE728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x416BF55ED1B64BE7ULL,
		0xD056E56CE6D9169BULL,
		0x70E20BA49560465EULL,
		0x12FE0DE1FC43FB23ULL,
		0x0764BCD0568238D4ULL,
		0x9006C328FA3FA8BAULL,
		0x13468E8E207621F3ULL,
		0xFB8CDA8A7DDF1091ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AE7002E6ECC30F6ULL,
		0x37F077A9472D451AULL,
		0x8EDCCA858ABD29B3ULL,
		0x39671A7F86920856ULL,
		0x0EE1305B8C1CB82DULL,
		0x468A4E4E9ADB317DULL,
		0xBD3FDE0C03895DAEULL,
		0x78ADC3176CFCD697ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC88CEBFE56813987ULL,
		0x2986D9FF5E2D1C90ULL,
		0xAB016410F1A677DEULL,
		0x4FCD1181F0ADF243ULL,
		0x18D364898EDB33E1ULL,
		0x227A8843E56B2BD7ULL,
		0xD8F7F67040CA142FULL,
		0x320C12AB2B82C89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97489EE88E9FDB95ULL,
		0xBD1EF301B3FEC0F4ULL,
		0x8073A7B65A6CD7E4ULL,
		0x100C3BDA0B209304ULL,
		0xB8BA13FADF98667DULL,
		0xBBE92EDF57AAE917ULL,
		0x508DDEFE086B8661ULL,
		0x9F340DE7241650B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31444D15C7E15DF2ULL,
		0x6C67E6FDAA2E5B9CULL,
		0x2A8DBC5A97399FF9ULL,
		0x3FC0D5A7E58D5F3FULL,
		0x6019508EAF42CD64ULL,
		0x669159648DC042BFULL,
		0x886A1772385E8DCDULL,
		0x92D804C4076C77ECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16802F6C16DE3464ULL,
		0x25CB8C4853874652ULL,
		0xB76466D22E60986AULL,
		0x439D0BA0173C5ADAULL,
		0x72A520B99DFB9953ULL,
		0x80CA65906DC5D56AULL,
		0x53748565F726BDD1ULL,
		0x28DC61E9E14C04F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C4544DAFF87BA2FULL,
		0xB15276DF18AC39E0ULL,
		0x7D34DDCA87714FD2ULL,
		0x05C9F4EFF5630459ULL,
		0x23BEC575AC698C21ULL,
		0x26667DDDA8671F8DULL,
		0xD3435AD3D2D303A9ULL,
		0xF05BC9C2B6619D7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA3AEA9117567A35ULL,
		0x747915693ADB0C71ULL,
		0x3A2F8907A6EF4897ULL,
		0x3DD316B021D95681ULL,
		0x4EE65B43F1920D32ULL,
		0x5A63E7B2C55EB5DDULL,
		0x80312A922453BA28ULL,
		0x388098272AEA677BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD2587F2902F18CE2ULL,
		0xD67D2857CD5C7AA8ULL,
		0x4C9559116BFE3AACULL,
		0x07B858B999E621DEULL,
		0xF65986515EA403E5ULL,
		0x04DB69925C5FB263ULL,
		0x6DC7DE68DB3A108FULL,
		0x9FC9CC97678F4DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x544DA3BBC7CD3549ULL,
		0x3636E24C0D19F7F5ULL,
		0xD27E552F8DBB4CE7ULL,
		0x6F15520455AD54F3ULL,
		0x8D93FE01C0182A61ULL,
		0x6678A449ACF414C0ULL,
		0x01DA93DE79EA66ACULL,
		0x3C91AD74643B4849ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E0ADB6D3B245799ULL,
		0xA046460BC04282B3ULL,
		0x7A1703E1DE42EDC5ULL,
		0x98A306B54438CCEAULL,
		0x68C5884F9E8BD983ULL,
		0x9E62C548AF6B9DA3ULL,
		0x6BED4A8A614FA9E2ULL,
		0x63381F2303540561ULL
	}};
	sign = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF114B79FB3DFF2EDULL,
		0x4B534609DC484BA8ULL,
		0x9E19EDA7896144D7ULL,
		0x7F5E820162CAED40ULL,
		0x1DC4FA377404008EULL,
		0x62D8BC862221FCC5ULL,
		0xB09387B97B92F0E8ULL,
		0xE227474D9123DFD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9978BEA62F9768FCULL,
		0x453D8A05751303DEULL,
		0x38FDF2072F6A91AAULL,
		0x47563A527A49E9FAULL,
		0x601DC8BBCCA7BDA4ULL,
		0x72971772DD7BBEE8ULL,
		0x7995865D6CB5B670ULL,
		0x1A0C72EB3B747F0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x579BF8F9844889F1ULL,
		0x0615BC04673547CAULL,
		0x651BFBA059F6B32DULL,
		0x380847AEE8810346ULL,
		0xBDA7317BA75C42EAULL,
		0xF041A51344A63DDCULL,
		0x36FE015C0EDD3A77ULL,
		0xC81AD46255AF60CDULL
	}};
	sign = 0;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD924A594DF7F13DFULL,
		0x08A5FF27729FF0D7ULL,
		0x9FC7A144AAF22B7EULL,
		0x6FDBDF720828A44EULL,
		0x94FBFC7CB8D3E9E3ULL,
		0x8E345474B6C9BDC4ULL,
		0x7AC89C6930C55B93ULL,
		0x9435ED6C450DFDA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24E7266A973303B5ULL,
		0x50A52BEA9ED1616FULL,
		0x8BF8D88EA8262B41ULL,
		0xDB78062263139E1FULL,
		0x7718EAB57EBE63B5ULL,
		0x009809D281449C0DULL,
		0xB393A86CEB260180ULL,
		0x1443586FE3164B54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB43D7F2A484C102AULL,
		0xB800D33CD3CE8F68ULL,
		0x13CEC8B602CC003CULL,
		0x9463D94FA515062FULL,
		0x1DE311C73A15862DULL,
		0x8D9C4AA2358521B7ULL,
		0xC734F3FC459F5A13ULL,
		0x7FF294FC61F7B24EULL
	}};
	sign = 0;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DE7DF7EB704A00FULL,
		0x9BD1D155FF0A9DD2ULL,
		0x1340F2A2FF4CA96BULL,
		0x9094A5D2A4289712ULL,
		0x4612DF070543A397ULL,
		0x32D080E83927CAA7ULL,
		0x0108F0737DF1E4ABULL,
		0xB26F01DCC98DCCAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DBBF64A897EBDBULL,
		0xCF36DA9AF8DCB549ULL,
		0xBC6FD46292F6EA61ULL,
		0x067218002E3A2582ULL,
		0xB720848C94D82440ULL,
		0xEF50C535FA066CE2ULL,
		0xA292A796E73C2D06ULL,
		0xC234DF3E2B7ADEFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250C201A0E6CB434ULL,
		0xCC9AF6BB062DE889ULL,
		0x56D11E406C55BF09ULL,
		0x8A228DD275EE718FULL,
		0x8EF25A7A706B7F57ULL,
		0x437FBBB23F215DC4ULL,
		0x5E7648DC96B5B7A4ULL,
		0xF03A229E9E12EDAAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35076B219EA8A960ULL,
		0x32EDC1DBFB9776EEULL,
		0x614F746F93928BF7ULL,
		0xEBB8B1307748AD19ULL,
		0x4FF415F7698F26E3ULL,
		0x7842B7E1B9E83B6FULL,
		0xCBDEAD426A3D917FULL,
		0xE055BCFBB6F2ECE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7838A78AF7A90E98ULL,
		0xE4087E9FFEF1F2D7ULL,
		0x09C94E6CADEF792FULL,
		0xD6AD173B19BAAF0BULL,
		0xC0EF56BD12C77A24ULL,
		0x7A24FC6C99B69922ULL,
		0xD3451612CFD91AB7ULL,
		0x50EBD4004A01A55BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCCEC396A6FF9AC8ULL,
		0x4EE5433BFCA58416ULL,
		0x57862602E5A312C7ULL,
		0x150B99F55D8DFE0EULL,
		0x8F04BF3A56C7ACBFULL,
		0xFE1DBB752031A24CULL,
		0xF899972F9A6476C7ULL,
		0x8F69E8FB6CF14786ULL
	}};
	sign = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E388340031AA6ABULL,
		0xED607B63AB8E1275ULL,
		0x47CE1DFEC765437EULL,
		0xCD676C30C1492F12ULL,
		0x87BA079050A41DFEULL,
		0xB9F4C72FBF346F48ULL,
		0x74CF5A9D47071F76ULL,
		0x8FDA7F47CE5E79D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACED0A23335998D9ULL,
		0x9D9605D85F5F4FF3ULL,
		0xE01727CF4B4DAF9EULL,
		0x187F6E9CD7F95AE8ULL,
		0xB4FDC44868EA22D7ULL,
		0x1AEE2804D1D1493EULL,
		0xAEC1410EFA5909E3ULL,
		0xDE5C7268820E9E0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x614B791CCFC10DD2ULL,
		0x4FCA758B4C2EC281ULL,
		0x67B6F62F7C1793E0ULL,
		0xB4E7FD93E94FD429ULL,
		0xD2BC4347E7B9FB27ULL,
		0x9F069F2AED632609ULL,
		0xC60E198E4CAE1593ULL,
		0xB17E0CDF4C4FDBC7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D6A4E7DE95CE562ULL,
		0x26A53B6C02667AC2ULL,
		0x51FBC9855E87C9AFULL,
		0x2914DB67C4841A2FULL,
		0x4ED6C10ABCC55FC6ULL,
		0xACACCD2E706BE456ULL,
		0x1E1D60494757D14CULL,
		0xDB36306C56EFFA88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8B4715E93A6B149ULL,
		0xD0860598CC495C7AULL,
		0x5F60BCE26C16AA31ULL,
		0x83F72D3B8A422D6FULL,
		0xFB14FF2AE3DA88BFULL,
		0xD3173A71811FFD8AULL,
		0x9DABDD06F08675E1ULL,
		0xB269A1C43C4D25E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4B5DD1F55B63419ULL,
		0x561F35D3361D1E47ULL,
		0xF29B0CA2F2711F7DULL,
		0xA51DAE2C3A41ECBFULL,
		0x53C1C1DFD8EAD706ULL,
		0xD99592BCEF4BE6CBULL,
		0x8071834256D15B6AULL,
		0x28CC8EA81AA2D49EULL
	}};
	sign = 0;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8950B5CEF645C38ULL,
		0xC447B6D674096356ULL,
		0x79FF5F4EEF6A0B80ULL,
		0x9C6A514FED0B7FC3ULL,
		0x559A4027D5399938ULL,
		0x4598560DD3E6BD84ULL,
		0x38D61ABC46FF6B96ULL,
		0xC2304F39F24EB685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E1EC82C1EE2BDFULL,
		0xFD507DCA3EB2220CULL,
		0x14C3B12264A6E19EULL,
		0x7454843B623ED01FULL,
		0x71B3BCE19068B78EULL,
		0xD7E42009F70E8450ULL,
		0x543AE7E74AF5010DULL,
		0xBB0F6813644430ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86B31EDA2D763059ULL,
		0xC6F7390C3557414AULL,
		0x653BAE2C8AC329E1ULL,
		0x2815CD148ACCAFA4ULL,
		0xE3E6834644D0E1AAULL,
		0x6DB43603DCD83933ULL,
		0xE49B32D4FC0A6A88ULL,
		0x0720E7268E0A8598ULL
	}};
	sign = 0;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB122777646B40E7ULL,
		0x7ED4AF12EF3F4F96ULL,
		0x426A54F189234845ULL,
		0x1E509432E8B1FFC4ULL,
		0x9B575DD82FA34410ULL,
		0xE01E2DC14A42135BULL,
		0x1ACCA83E61A2A13DULL,
		0x568AEF46B82CFB36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBADF96CC2B5E992BULL,
		0x8279258717CD5A82ULL,
		0x49129BB99EA8E467ULL,
		0x1AC72CEE4609F4A6ULL,
		0x542E4F0728C85E28ULL,
		0x1BFF1EA7D416350DULL,
		0xBC3AC89E03217EC4ULL,
		0xE3ED57438A2174D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x403290AB390CA7BCULL,
		0xFC5B898BD771F514ULL,
		0xF957B937EA7A63DDULL,
		0x03896744A2A80B1DULL,
		0x47290ED106DAE5E8ULL,
		0xC41F0F19762BDE4EULL,
		0x5E91DFA05E812279ULL,
		0x729D98032E0B865EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE34C3FAD80252A41ULL,
		0xEE75F250B2F91FD5ULL,
		0x0633CC0CC67E3D57ULL,
		0xE507928695AC9274ULL,
		0x6A9E26C9C7903C9DULL,
		0x953894CCC330DC92ULL,
		0xDC740544D5E60C2CULL,
		0x0EE67E991C75B5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F1C3F64AEF25AAULL,
		0x940CCCC623A02A48ULL,
		0xA74374F3FB4AA37FULL,
		0x0541291CE67DA964ULL,
		0xE6BABD7EA1A5626DULL,
		0x1431D39FC570A06BULL,
		0x2C4B4E3B63372521ULL,
		0x89DFEA02D13634A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A5A7BB735360497ULL,
		0x5A69258A8F58F58DULL,
		0x5EF05718CB3399D8ULL,
		0xDFC66969AF2EE90FULL,
		0x83E3694B25EADA30ULL,
		0x8106C12CFDC03C26ULL,
		0xB028B70972AEE70BULL,
		0x850694964B3F811BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6DF7FFA9CEDFB4BCULL,
		0x3248BA75D2C43BFDULL,
		0x854648117814102BULL,
		0xCC50F042D3912EF1ULL,
		0x95D59D59772D337AULL,
		0x08894416E4963B3DULL,
		0x7B480C571C0A7F16ULL,
		0x1D15568E83E496BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C18D1ED6AA1A21DULL,
		0xE36F4FA178C18868ULL,
		0x9994FA7E33BCEA9FULL,
		0xBE0364645B81A40BULL,
		0xFDCD65EC22D811BFULL,
		0xC0E015CE21C2CEF0ULL,
		0x3142445E66591CFCULL,
		0xF26817B4837B9AB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1DF2DBC643E129FULL,
		0x4ED96AD45A02B394ULL,
		0xEBB14D934457258BULL,
		0x0E4D8BDE780F8AE5ULL,
		0x9808376D545521BBULL,
		0x47A92E48C2D36C4CULL,
		0x4A05C7F8B5B16219ULL,
		0x2AAD3EDA0068FC05ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF70E834F7AEA2C90ULL,
		0x1B96BDEADBA6F5B4ULL,
		0x77675EB7797F13EBULL,
		0x4A91CD798E85E0BAULL,
		0x7C477EC7639B0B56ULL,
		0xDB1518AFB5EB7B1CULL,
		0xE40239ACAD69DFDAULL,
		0xB17DC7EE427F4879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x956B00C0517BD666ULL,
		0x37904C7FC0611EFDULL,
		0x893F7E1B52DCD2A6ULL,
		0xFBAEE767CA277F68ULL,
		0x3F401D93E115FB15ULL,
		0x8117349F0B013612ULL,
		0x316D5EF9DD93069AULL,
		0xC2A57C1C23E080E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61A3828F296E562AULL,
		0xE406716B1B45D6B7ULL,
		0xEE27E09C26A24144ULL,
		0x4EE2E611C45E6151ULL,
		0x3D07613382851040ULL,
		0x59FDE410AAEA450AULL,
		0xB294DAB2CFD6D940ULL,
		0xEED84BD21E9EC796ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A1FF0BFB202406CULL,
		0x30D1D035DD66DE7BULL,
		0x588E14FA1C4AC5DBULL,
		0x590BAA17A6188A07ULL,
		0x11DF4CDD7AB73179ULL,
		0xC1E767BDF75A692AULL,
		0xF240218C17712C35ULL,
		0x493644D7170EEA2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A40555BC263EA77ULL,
		0x8C3E78D798B06B43ULL,
		0x884B9ED8560ADBBEULL,
		0xDD44F76911CDB3DBULL,
		0x2BF2509DA27AA10CULL,
		0xF3F1FE495167EAD2ULL,
		0xD13CBCC841C6F74DULL,
		0x7B422CAF2EEAE59BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFDF9B63EF9E55F5ULL,
		0xA493575E44B67337ULL,
		0xD0427621C63FEA1CULL,
		0x7BC6B2AE944AD62BULL,
		0xE5ECFC3FD83C906CULL,
		0xCDF56974A5F27E57ULL,
		0x210364C3D5AA34E7ULL,
		0xCDF41827E824048FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E20D111157FCBFFULL,
		0xF777EFBDEDC67CD5ULL,
		0x0F29E1A36D51DA86ULL,
		0xE82DA882FFDE2B3AULL,
		0x4ED830C80B07322FULL,
		0x96382669AC676B4AULL,
		0x1A16421F7E7B8F8BULL,
		0xFDFA8C114B171F27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85154F08A037DCC6ULL,
		0xAE02514AA705E504ULL,
		0x2F9A14282FDCEC77ULL,
		0x19A52745B4219D6DULL,
		0x3A0F6E417B6F5642ULL,
		0xAD846BED8A777F18ULL,
		0x8D42DDC55FB4CC52ULL,
		0xD066124905AC8DACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA90B82087547EF39ULL,
		0x49759E7346C097D0ULL,
		0xDF8FCD7B3D74EE0FULL,
		0xCE88813D4BBC8DCCULL,
		0x14C8C2868F97DBEDULL,
		0xE8B3BA7C21EFEC32ULL,
		0x8CD3645A1EC6C338ULL,
		0x2D9479C8456A917AULL
	}};
	sign = 0;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF04CE99ADA5A372EULL,
		0xDBC8AE0A37A1E3F1ULL,
		0x1A4CA2967D8526BBULL,
		0xAD7B2F9BF767C981ULL,
		0xE8C13E540C508F1BULL,
		0x25C30C349E9C2481ULL,
		0x9F50032DEB7C55CBULL,
		0xE09564C1396E209EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A165C294DBF4F4ULL,
		0x5DA5504AB7757DEEULL,
		0xBFA11226E556011EULL,
		0x3338EE8AE831F871ULL,
		0x70332CD108BD1458ULL,
		0x4F0C6FDB906877ACULL,
		0xB09C57ADD37A299BULL,
		0xC8F9D63D7D4C97B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EAB83D8457E423AULL,
		0x7E235DBF802C6603ULL,
		0x5AAB906F982F259DULL,
		0x7A4241110F35D10FULL,
		0x788E118303937AC3ULL,
		0xD6B69C590E33ACD5ULL,
		0xEEB3AB8018022C2FULL,
		0x179B8E83BC2188E5ULL
	}};
	sign = 0;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27268EE4E0D0FC18ULL,
		0x48B439E8B7BE9B4BULL,
		0xB42A8E4E605022C5ULL,
		0x6F92FC7E532FE743ULL,
		0x80BE98D23764D8DFULL,
		0xEF662BA71E530A7BULL,
		0x9AFE12DE2738B995ULL,
		0x74856884BE93E912ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF475E512C275A242ULL,
		0x3DB4957031627DF9ULL,
		0x4935124F68281F51ULL,
		0xCDD53A22654032C1ULL,
		0x44F04C635B757003ULL,
		0x8FCEABFD20517110ULL,
		0xDF9706125F2C541AULL,
		0x99ADB74269657AA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32B0A9D21E5B59D6ULL,
		0x0AFFA478865C1D51ULL,
		0x6AF57BFEF8280374ULL,
		0xA1BDC25BEDEFB482ULL,
		0x3BCE4C6EDBEF68DBULL,
		0x5F977FA9FE01996BULL,
		0xBB670CCBC80C657BULL,
		0xDAD7B142552E6E6EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x902D0F6596F518EAULL,
		0x7C5B3F2BC3D34359ULL,
		0x61F93ECB10A1D76DULL,
		0xD09A1988F298BE8AULL,
		0xA6062F6466B41C4CULL,
		0x67FAD9D16DDC81F3ULL,
		0x6E1E4307E9FF66FAULL,
		0xCB87F5C386269235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CE3B0FF9756B7C9ULL,
		0x80EE8E601691638EULL,
		0x827262DA1B222BE9ULL,
		0x6ACE8A4DC5301935ULL,
		0x9D56B456CFB86359ULL,
		0x28187B647C65B1FCULL,
		0x7C4DD022F3904DE0ULL,
		0x60067AA83BED91FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3495E65FF9E6121ULL,
		0xFB6CB0CBAD41DFCAULL,
		0xDF86DBF0F57FAB83ULL,
		0x65CB8F3B2D68A554ULL,
		0x08AF7B0D96FBB8F3ULL,
		0x3FE25E6CF176CFF7ULL,
		0xF1D072E4F66F191AULL,
		0x6B817B1B4A390035ULL
	}};
	sign = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0D6134218D025D6ULL,
		0x92A106E90F50DF5DULL,
		0xE801FB95F03BB614ULL,
		0x884DB2CEC6F8D676ULL,
		0x15AC2C6D47519319ULL,
		0xFA72A813446C1CD0ULL,
		0xCC151A27F91623CFULL,
		0xF811F9C39BF8FFF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DA444630A8EFCC1ULL,
		0x8C1A26E1D784BD2CULL,
		0x673AA5EB66B6442EULL,
		0xAA0C7118A55A16DCULL,
		0xD602DA2436D7B8F9ULL,
		0x93281A8DD82CFD88ULL,
		0x57315A7B9917ADBCULL,
		0x837F0065247BFEB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9331CEDF0E412915ULL,
		0x0686E00737CC2231ULL,
		0x80C755AA898571E6ULL,
		0xDE4141B6219EBF9AULL,
		0x3FA952491079DA1FULL,
		0x674A8D856C3F1F47ULL,
		0x74E3BFAC5FFE7613ULL,
		0x7492F95E777D0142ULL
	}};
	sign = 0;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAFF91215C68868B1ULL,
		0x7DB13039CE8BB266ULL,
		0x1BB0291ED4EF20E2ULL,
		0xB1CF4DCA5A213362ULL,
		0x1F5872BADC8D1FA7ULL,
		0x385AE35B477C6750ULL,
		0xC54F26EF67895D53ULL,
		0x3B7D633FA15ACEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C48F66DBB710A16ULL,
		0xA81FDD462EE3BB5DULL,
		0x39F86A51910C91D5ULL,
		0x7C0DFA0D3A05B379ULL,
		0x81347B2802FC13AAULL,
		0xDC2AB0568B23B115ULL,
		0x8B0BF40BF0EE0AA4ULL,
		0x601E4FD79E89A65EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83B01BA80B175E9BULL,
		0xD59152F39FA7F709ULL,
		0xE1B7BECD43E28F0CULL,
		0x35C153BD201B7FE8ULL,
		0x9E23F792D9910BFDULL,
		0x5C303304BC58B63AULL,
		0x3A4332E3769B52AEULL,
		0xDB5F136802D12882ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64430B67B835838AULL,
		0x7DE9C5110CF6620DULL,
		0xA6D2E91FC5D4AFCEULL,
		0xB50250D4B3B79A2BULL,
		0x5B964AAEAC9F2BB3ULL,
		0x2E4BDA88B7366FF3ULL,
		0x92BD65AB4F2319EAULL,
		0xCC6EC95D0B47DAFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED7A563E9134F47ULL,
		0xE640C796B1A5515EULL,
		0x8D35F17872822A38ULL,
		0xF751E8CEF0AD3E98ULL,
		0x32D0E1EF96241560ULL,
		0xB7E052433C158726ULL,
		0x04B7B08B7BBDC242ULL,
		0x645450F427A992E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x956B6603CF223443ULL,
		0x97A8FD7A5B5110AEULL,
		0x199CF7A753528595ULL,
		0xBDB06805C30A5B93ULL,
		0x28C568BF167B1652ULL,
		0x766B88457B20E8CDULL,
		0x8E05B51FD36557A7ULL,
		0x681A7868E39E481BULL
	}};
	sign = 0;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE43A21B6710A6791ULL,
		0x8387CC8C3E54CF03ULL,
		0x59A340497CBB996FULL,
		0xC606C4A0D658C61FULL,
		0x8E8B75D1B443588BULL,
		0x9A8ACAEE385E97B5ULL,
		0x582C5A72A9A528C3ULL,
		0xA06A53828E54E55AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47CADB8459CA6385ULL,
		0x076192DD3B79D7D6ULL,
		0x62ACD2171F3BA4D3ULL,
		0x982A5BC405ED9593ULL,
		0x888F8C69470B212FULL,
		0xA08AC3F4C8729861ULL,
		0xD5EF043FA2560D90ULL,
		0x886CF921BE3CA1E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C6F46321740040CULL,
		0x7C2639AF02DAF72DULL,
		0xF6F66E325D7FF49CULL,
		0x2DDC68DCD06B308BULL,
		0x05FBE9686D38375CULL,
		0xFA0006F96FEBFF54ULL,
		0x823D5633074F1B32ULL,
		0x17FD5A60D0184378ULL
	}};
	sign = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FD33CFE737F477FULL,
		0x904974926105767DULL,
		0xD722AD2C610C3FD6ULL,
		0x70CA36A75088D8D9ULL,
		0x4492996E54D8A124ULL,
		0x593539ACD44834B5ULL,
		0xC88588E66DBA0A5FULL,
		0xE1DC102A7AD539C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28081BB60BC73AA6ULL,
		0xA9528BF7612B2EE0ULL,
		0xB1483E43555053ADULL,
		0xF975657438C98A53ULL,
		0x11A7C6E61C2E86E4ULL,
		0xE5BFEC495616907DULL,
		0x32EC917D3E8CBF9AULL,
		0xE7E05E881B34A6A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47CB214867B80CD9ULL,
		0xE6F6E89AFFDA479DULL,
		0x25DA6EE90BBBEC28ULL,
		0x7754D13317BF4E86ULL,
		0x32EAD28838AA1A3FULL,
		0x73754D637E31A438ULL,
		0x9598F7692F2D4AC4ULL,
		0xF9FBB1A25FA09320ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97C7CFFE6EA65603ULL,
		0x5C438398A85ED47CULL,
		0x19FB6777A3ECCEEEULL,
		0x7A46CB84643D17B4ULL,
		0x46AAA90C01557121ULL,
		0x6565A1BB90E9BA5AULL,
		0x066471FEB670A26CULL,
		0xC5E9B646F11F2A0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BAB1D04E713777ULL,
		0xFDCFCAF0FBE22D84ULL,
		0x57CFEA1741367AB2ULL,
		0xD0DF248688BBA508ULL,
		0x4985374E5171A696ULL,
		0xD0DAFAC34A9248DDULL,
		0x7F125CADA2C7F4FFULL,
		0xD9353DAA1AB5BC89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E0D1E2E20351E8CULL,
		0x5E73B8A7AC7CA6F8ULL,
		0xC22B7D6062B6543BULL,
		0xA967A6FDDB8172ABULL,
		0xFD2571BDAFE3CA8AULL,
		0x948AA6F84657717CULL,
		0x8752155113A8AD6CULL,
		0xECB4789CD6696D85ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE64435CCF815B77ULL,
		0x7A9EA4D748D18276ULL,
		0x24DAB9D495235A93ULL,
		0x5A1F4DB0654A85E8ULL,
		0x6CCC5DA7A1DDDE29ULL,
		0x09021D85B2286614ULL,
		0xBAC9F666E836E2B8ULL,
		0xFCF9145E94290B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2F0DF22305FB71ULL,
		0x7169BD0FBACB5720ULL,
		0x56E2EE7E63DB342FULL,
		0x73578FB4C96DAC6FULL,
		0xEFD97C450F57975FULL,
		0x40B8F961B361B49EULL,
		0x727E521C9836B794ULL,
		0x6800AE3D16638F0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0435356AAC7B6006ULL,
		0x0934E7C78E062B56ULL,
		0xCDF7CB5631482664ULL,
		0xE6C7BDFB9BDCD978ULL,
		0x7CF2E162928646C9ULL,
		0xC8492423FEC6B175ULL,
		0x484BA44A50002B23ULL,
		0x94F866217DC57C68ULL
	}};
	sign = 0;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD068E022FD42CDA3ULL,
		0xFF2D754A773F19E8ULL,
		0x6636E8F6A06DA0E3ULL,
		0xE5EF096BDE5C75D7ULL,
		0x29D8C3D9179756B3ULL,
		0x6938A92AF64EC57CULL,
		0x102086EE47F96C10ULL,
		0x03B5A258EB649582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C8F4F02AC7873DULL,
		0x8EDAB80ECBE5F9E3ULL,
		0x4A2A45E7C34795D4ULL,
		0x4A14CB643DB40837ULL,
		0xFBF12074232ABA50ULL,
		0xBB2CC455D0804F92ULL,
		0x0F1E086D5C8C32D0ULL,
		0x11CA644C41730C03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F9FEB32D27B4666ULL,
		0x7052BD3BAB592005ULL,
		0x1C0CA30EDD260B0FULL,
		0x9BDA3E07A0A86DA0ULL,
		0x2DE7A364F46C9C63ULL,
		0xAE0BE4D525CE75E9ULL,
		0x01027E80EB6D393FULL,
		0xF1EB3E0CA9F1897FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD4761E883D46E87ULL,
		0xAC82089C951119E0ULL,
		0x082071C7A008EE8CULL,
		0xE6312963EF7CA00BULL,
		0xD093FFEB1D3E748FULL,
		0x51B4DA13F35747F3ULL,
		0xA167D599AAC0124AULL,
		0x8997B147579652DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F302DDE18A6998FULL,
		0x7D5E00537F0EFA01ULL,
		0x1B7D37747C6B5058ULL,
		0xE684FCC5C9E5E529ULL,
		0x028B507C36D1D84DULL,
		0xCD541105CFE551FCULL,
		0xF02DE1C6D2C478FAULL,
		0xB632EC8A221984CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E17340A6B2DD4F8ULL,
		0x2F24084916021FDFULL,
		0xECA33A53239D9E34ULL,
		0xFFAC2C9E2596BAE1ULL,
		0xCE08AF6EE66C9C41ULL,
		0x8460C90E2371F5F7ULL,
		0xB139F3D2D7FB994FULL,
		0xD364C4BD357CCE13ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58BF7867E51FBEF7ULL,
		0xA1939079B2F92FF2ULL,
		0x25303243F79D368DULL,
		0xA581DFBFEE7EC3DEULL,
		0xE43CE526F509C4DEULL,
		0x3C7E5B6B8C36F4C3ULL,
		0x10F93AB4FD6F526FULL,
		0xF13E8894CB1070F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C3817DF2744E2CULL,
		0x73FDB018B91B936AULL,
		0x8198FF5155AC4F65ULL,
		0xE1E610136AF8EAD2ULL,
		0x9A7EC89B61EF45E7ULL,
		0x004E70E7964A7EB4ULL,
		0xD1DDFCDF928C16B5ULL,
		0xC36E5DEDC358E8BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFFBF6E9F2AB70CBULL,
		0x2D95E060F9DD9C87ULL,
		0xA39732F2A1F0E728ULL,
		0xC39BCFAC8385D90BULL,
		0x49BE1C8B931A7EF6ULL,
		0x3C2FEA83F5EC760FULL,
		0x3F1B3DD56AE33BBAULL,
		0x2DD02AA707B78832ULL
	}};
	sign = 0;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8342C50E2F037E9BULL,
		0xB311F3C58D916E4AULL,
		0x0BC5822F48200170ULL,
		0x969A8F2D4CCEFA49ULL,
		0x2D8E35AA7CFB9819ULL,
		0x760D8DC086C8A26BULL,
		0xAB5BFACA230E3F84ULL,
		0xA727DADDF03E9262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D8A99CECD4E21CULL,
		0x41D8F1C768D6E577ULL,
		0x5ABE801AEF37EB4EULL,
		0xE44C41F22C18B850ULL,
		0xF3B32D687A1BDDB5ULL,
		0x16651C9EAF43F834ULL,
		0x1ED67F5F4AEAEAF6ULL,
		0x5F640622084CADB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB16A1B71422E9C7FULL,
		0x713901FE24BA88D2ULL,
		0xB107021458E81622ULL,
		0xB24E4D3B20B641F8ULL,
		0x39DB084202DFBA63ULL,
		0x5FA87121D784AA36ULL,
		0x8C857B6AD823548EULL,
		0x47C3D4BBE7F1E4ABULL
	}};
	sign = 0;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x674B910D67E11D08ULL,
		0x53327FCABC4C12E5ULL,
		0xFA30EB22C94AD9AFULL,
		0x08ABDE7BB062093EULL,
		0xBE0BE37D16396425ULL,
		0x35CCD22E22BBBA17ULL,
		0xB28266A1889C68ECULL,
		0xDE3566D1E97A1B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90F9E23BFDF90ECFULL,
		0x19D5DD0FEFF5A606ULL,
		0xBF17F269CA93A5D0ULL,
		0x5A8E2AA6158DF5AAULL,
		0x71B12EEB7D5BDFB9ULL,
		0xF8D50379712EAA6AULL,
		0x62BE84302F81E403ULL,
		0xA06767E80E56A023ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD651AED169E80E39ULL,
		0x395CA2BACC566CDEULL,
		0x3B18F8B8FEB733DFULL,
		0xAE1DB3D59AD41394ULL,
		0x4C5AB49198DD846BULL,
		0x3CF7CEB4B18D0FADULL,
		0x4FC3E271591A84E8ULL,
		0x3DCDFEE9DB237B07ULL
	}};
	sign = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E4347E14A41C47AULL,
		0x7580575CB16ABBC1ULL,
		0xA9B3D5F39F33DEDBULL,
		0xDDBAA0308AE03316ULL,
		0xF4F816DE08ADC003ULL,
		0x457587DFF402079CULL,
		0xDC5D444A350F7F31ULL,
		0x27E7254C91BA90BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x657659B3E3128FC9ULL,
		0x8BAFDDDEE01B28C0ULL,
		0xD33D8FF92F8BFCFCULL,
		0x9A190228CF052720ULL,
		0x3C7C8D35C4061BF3ULL,
		0xFE746114C28E8E08ULL,
		0x9C11179E8E9FDBC3ULL,
		0x360FD59EB4201BD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8CCEE2D672F34B1ULL,
		0xE9D0797DD14F9300ULL,
		0xD67645FA6FA7E1DEULL,
		0x43A19E07BBDB0BF5ULL,
		0xB87B89A844A7A410ULL,
		0x470126CB31737994ULL,
		0x404C2CABA66FA36DULL,
		0xF1D74FADDD9A74E7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x456EA11A37D3E461ULL,
		0x856B26F5F6C10423ULL,
		0xB4517CE373C82EFAULL,
		0x8EC2E5E6CA3C540DULL,
		0x252BD6B0CD432B3DULL,
		0x152EFC691A1A32CAULL,
		0xDEF14C9834BE6E3CULL,
		0x7014006C087541CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDC8C0AA9CDD81A5ULL,
		0x079ACCC51EC11097ULL,
		0xF17A15C8C5D22B73ULL,
		0x9C3D3B4702A1CE1AULL,
		0xA7D6D03B1F243964ULL,
		0xC5E37FB2E700F05DULL,
		0xF22AE47674FEA693ULL,
		0x89A88BA662104853ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87A5E06F9AF662BCULL,
		0x7DD05A30D7FFF38BULL,
		0xC2D7671AADF60387ULL,
		0xF285AA9FC79A85F2ULL,
		0x7D550675AE1EF1D8ULL,
		0x4F4B7CB63319426CULL,
		0xECC66821BFBFC7A8ULL,
		0xE66B74C5A664F97BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x717818F91137BC83ULL,
		0x950890F9D4B4E51DULL,
		0x02092F5CB0F79666ULL,
		0xEBD307A427714E9BULL,
		0x753724ADE3C6F06BULL,
		0xB43C4E6F43074B75ULL,
		0xCB5F7FBC260E41FDULL,
		0x1853748C32CAC185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B2D99816E06BF32ULL,
		0x05ED289A6668A026ULL,
		0x62E1C222E42BCCE4ULL,
		0x8CA364C761E068AAULL,
		0x5FB407C96DB8159FULL,
		0xCEB84D8091462752ULL,
		0x8402A04F72D649B3ULL,
		0xE16EE91F21C4386BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x464A7F77A330FD51ULL,
		0x8F1B685F6E4C44F7ULL,
		0x9F276D39CCCBC982ULL,
		0x5F2FA2DCC590E5F0ULL,
		0x15831CE4760EDACCULL,
		0xE58400EEB1C12423ULL,
		0x475CDF6CB337F849ULL,
		0x36E48B6D1106891AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37604EF0CA4C4C1CULL,
		0x00F1F119B87B17CCULL,
		0x33EF838B372F64DEULL,
		0x6E7428133C8B95CBULL,
		0xD81D5256EAC48947ULL,
		0x2BFF92E8714335ECULL,
		0xD317C5FA90D17F31ULL,
		0x0A6A2079FBC8D473ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96D4285CCCFE72BAULL,
		0x10420FDF410BA719ULL,
		0xF2DF171A77133BEBULL,
		0x178E3E1F1D40D150ULL,
		0x101A47BFF5CB95AFULL,
		0x9B591E6591F9B929ULL,
		0x549C895333F38FA6ULL,
		0xC00796EF84502333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA08C2693FD4DD962ULL,
		0xF0AFE13A776F70B2ULL,
		0x41106C70C01C28F2ULL,
		0x56E5E9F41F4AC47AULL,
		0xC8030A96F4F8F398ULL,
		0x90A67482DF497CC3ULL,
		0x7E7B3CA75CDDEF8AULL,
		0x4A62898A7778B140ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4317BEE2E3AC6340ULL,
		0x8DF1B70CA7D1E517ULL,
		0x964F12E477810DCFULL,
		0xDB9C9D8103486159ULL,
		0x99F631BEC1405EF7ULL,
		0x43131C0EC9FD10AFULL,
		0x2E3C5EAB3B02A8E3ULL,
		0xB3FE2D17FD5EB942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAEEA3C26250D9D3ULL,
		0xBDC8B5AEEA532B7AULL,
		0xF88BB86B0AD4D6BAULL,
		0xFD60D7D8557EFFD3ULL,
		0x00F7B842556E8417ULL,
		0xFC4E1005B11902C7ULL,
		0x08565F116E6D2EEAULL,
		0x2021A27F782FF98DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78291B20815B896DULL,
		0xD029015DBD7EB99CULL,
		0x9DC35A796CAC3714ULL,
		0xDE3BC5A8ADC96185ULL,
		0x98FE797C6BD1DADFULL,
		0x46C50C0918E40DE8ULL,
		0x25E5FF99CC9579F8ULL,
		0x93DC8A98852EBFB5ULL
	}};
	sign = 0;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FA64B58456F1FA6ULL,
		0x30E580CEA46B5A34ULL,
		0x9A3B62972AE10001ULL,
		0xBFBC5F25BCBC900CULL,
		0xB09F81062271056CULL,
		0xD64A181E149540EBULL,
		0xB124F3251CAA64A6ULL,
		0xEAC0B3A8DC117586ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE70ACF60EE37B8ULL,
		0xD9DAE67789C9408DULL,
		0xD75E8618AD6CB613ULL,
		0xED6B159327422A65ULL,
		0x0DD26F15B5F12FBEULL,
		0x10647E8EF7A585FEULL,
		0x0E50CBE22D5C38A3ULL,
		0xDD02C6EA0516EBD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50BF4088E480E7EEULL,
		0x570A9A571AA219A7ULL,
		0xC2DCDC7E7D7449EDULL,
		0xD2514992957A65A6ULL,
		0xA2CD11F06C7FD5ADULL,
		0xC5E5998F1CEFBAEDULL,
		0xA2D42742EF4E2C03ULL,
		0x0DBDECBED6FA89B6ULL
	}};
	sign = 0;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16DA0FCB1D106720ULL,
		0x403EB7DBC4814895ULL,
		0xA5C2450E029108FAULL,
		0x369D60B571185362ULL,
		0x0F59DB720A90592CULL,
		0x909B30259CAFBEFDULL,
		0x066D3FDF6225114DULL,
		0xCD2E47A2A5B583ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBBD3644E5406A2FULL,
		0xB11F505DBB8DC2E1ULL,
		0xD790E00954B7987BULL,
		0x82E1ED7CCD639775ULL,
		0x59EF5FB9B3B5EB73ULL,
		0xD91759A8AC925EF6ULL,
		0x763F4A39061C3F40ULL,
		0x0A1874222EEE9DE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B1CD98637CFFCF1ULL,
		0x8F1F677E08F385B3ULL,
		0xCE316504ADD9707EULL,
		0xB3BB7338A3B4BBECULL,
		0xB56A7BB856DA6DB8ULL,
		0xB783D67CF01D6006ULL,
		0x902DF5A65C08D20CULL,
		0xC315D38076C6E5C6ULL
	}};
	sign = 0;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E4E1FB03899DDD3ULL,
		0xAC42832A4B71EB89ULL,
		0x97EC9A1C593CBFD4ULL,
		0xB892F2A8CC320CCFULL,
		0xF6D1E22850E0C2E6ULL,
		0x0F74B877BBE6D996ULL,
		0x19D7B26B966750E8ULL,
		0x1B171DC6FBCE9165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8008FAD76276D6F2ULL,
		0xA1768B9450384C92ULL,
		0xB4673E3BB76BC8BEULL,
		0xFFBDCD9EBF13D896ULL,
		0x465153508D371831ULL,
		0xCF77776A5A76ADFDULL,
		0x91C74357CEA3B8DAULL,
		0xE3B57271AA2DC621ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E4524D8D62306E1ULL,
		0x0ACBF795FB399EF6ULL,
		0xE3855BE0A1D0F716ULL,
		0xB8D5250A0D1E3438ULL,
		0xB0808ED7C3A9AAB4ULL,
		0x3FFD410D61702B99ULL,
		0x88106F13C7C3980DULL,
		0x3761AB5551A0CB43ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C7EA9A0089359BBULL,
		0x18ED54E6CCE3B016ULL,
		0x76098E1D3948C941ULL,
		0xE09554C2CD8C8888ULL,
		0x3AEF9871F4D37211ULL,
		0xC6D1652C060DE936ULL,
		0x8D607148515BF4FEULL,
		0xA0B403771E654266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F3E3CB66F67A4C8ULL,
		0x2691A4D32DD3F5F7ULL,
		0xBE360796C166B4F8ULL,
		0x35A7A22C5B5EF221ULL,
		0x43F93182E350A7BDULL,
		0x6AD48A009824E8EEULL,
		0x6D688C1C61C40761ULL,
		0x2C36124416E850C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D406CE9992BB4F3ULL,
		0xF25BB0139F0FBA1FULL,
		0xB7D3868677E21448ULL,
		0xAAEDB296722D9666ULL,
		0xF6F666EF1182CA54ULL,
		0x5BFCDB2B6DE90047ULL,
		0x1FF7E52BEF97ED9DULL,
		0x747DF133077CF19DULL
	}};
	sign = 0;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F7F47737EF61177ULL,
		0xD87364D05690E2C1ULL,
		0xBAA05C6424C51641ULL,
		0x829CF636957F23E3ULL,
		0xDB65ED30BE905488ULL,
		0xAFCB28AE6C6330E6ULL,
		0x8DC11073BD2AED8EULL,
		0xB8C024041508EC83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B27C0AE3A3C178ULL,
		0x8BAAC5C4D65247B0ULL,
		0xD2FDB2A9950B0BD4ULL,
		0x5D4692BCB6C35F9BULL,
		0xEAA666E4D4E8F145ULL,
		0xF37C6AF642ED2E10ULL,
		0x151EE3D321F3F9DAULL,
		0xC2006A8EE8742890ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABCCCB689B524FFFULL,
		0x4CC89F0B803E9B10ULL,
		0xE7A2A9BA8FBA0A6DULL,
		0x25566379DEBBC447ULL,
		0xF0BF864BE9A76343ULL,
		0xBC4EBDB8297602D5ULL,
		0x78A22CA09B36F3B3ULL,
		0xF6BFB9752C94C3F3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0351E395EEB44409ULL,
		0xD02EA0815D3DB888ULL,
		0x974991991C40552BULL,
		0xE8155324E4BAB34FULL,
		0x60FB6E06B27674C9ULL,
		0xAE9EAA0E0BFA426DULL,
		0xB86B5EE819080609ULL,
		0xF135DB2827E7ED5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3AF93A131B4DD0EULL,
		0x0684660D1C02EA95ULL,
		0x2DA850FC541A4EF6ULL,
		0xEE5136FF707ED049ULL,
		0x5D22305093C14DEDULL,
		0x0DF6D73CB6E7A42AULL,
		0xF41D07BEA30A7107ULL,
		0x157C34778F5597E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FA24FF4BCFF66FBULL,
		0xC9AA3A74413ACDF2ULL,
		0x69A1409CC8260635ULL,
		0xF9C41C25743BE306ULL,
		0x03D93DB61EB526DBULL,
		0xA0A7D2D155129E43ULL,
		0xC44E572975FD9502ULL,
		0xDBB9A6B09892557AULL
	}};
	sign = 0;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79DEB0D4BC86CBEEULL,
		0xFF1305E8B186224DULL,
		0x6B37245A314EEA2AULL,
		0xC7A5A0F02507D256ULL,
		0xCD59EFEA2F752E46ULL,
		0xEDFA261BEA169188ULL,
		0xE517906B7C1F142FULL,
		0x8A889418265B2441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E54F2D71E8A54CAULL,
		0x6FF38C31EBFAB356ULL,
		0xB2D692AF38E4EA32ULL,
		0x004B5FDD880AA8D4ULL,
		0x61A46EBFA8BF2D8AULL,
		0x7DB83FB3DD4FC52AULL,
		0x07E8358A0869A38FULL,
		0x01CE49A0A720F2F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B89BDFD9DFC7724ULL,
		0x8F1F79B6C58B6EF7ULL,
		0xB86091AAF869FFF8ULL,
		0xC75A41129CFD2981ULL,
		0x6BB5812A86B600BCULL,
		0x7041E6680CC6CC5EULL,
		0xDD2F5AE173B570A0ULL,
		0x88BA4A777F3A3148ULL
	}};
	sign = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADDDAA6D52F8F929ULL,
		0x486CF69360DF7F18ULL,
		0x243F8051511E65BEULL,
		0x18371583D3C2A89AULL,
		0x95B471FBD6319112ULL,
		0x0B94AE003A92DD7DULL,
		0xDF273A33FB2579C2ULL,
		0xCC1B1EDF7F3188B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x354BDD6CC9B3EC8EULL,
		0xF83547C4C3795382ULL,
		0xD62E09A0ED9AE2D4ULL,
		0xB04481AAC55CEE9CULL,
		0xF41CC9822FD8CDEAULL,
		0x7D48F321211C1736ULL,
		0xC7AA12D90FA16E7AULL,
		0xF39B50EEFB221F88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7891CD0089450C9BULL,
		0x5037AECE9D662B96ULL,
		0x4E1176B0638382E9ULL,
		0x67F293D90E65B9FDULL,
		0xA197A879A658C327ULL,
		0x8E4BBADF1976C646ULL,
		0x177D275AEB840B47ULL,
		0xD87FCDF0840F6929ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39F5651F81CF1913ULL,
		0xC6E3AC2A20A296CAULL,
		0x643DEAA9B129758CULL,
		0x2971EBE71362F25DULL,
		0x0EDF5DEF51CE5613ULL,
		0x5000B02F81673771ULL,
		0x6349805FF5CF696AULL,
		0xB4054007FCF52244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2122AF6023641BBFULL,
		0x75B070774E50F30CULL,
		0x3761564E1F086398ULL,
		0xFCBB899E68D7A674ULL,
		0xD01890E4B4DBFE91ULL,
		0x7BA66D24875C67F8ULL,
		0xA4D1F619A11B6DA7ULL,
		0x46056FD7966987C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18D2B5BF5E6AFD54ULL,
		0x51333BB2D251A3BEULL,
		0x2CDC945B922111F4ULL,
		0x2CB66248AA8B4BE9ULL,
		0x3EC6CD0A9CF25781ULL,
		0xD45A430AFA0ACF78ULL,
		0xBE778A4654B3FBC2ULL,
		0x6DFFD030668B9A7CULL
	}};
	sign = 0;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2FAB7E31D2B6249ULL,
		0x89DA73AF8291F3EAULL,
		0x7BE025B73863CF11ULL,
		0x984F654DAC5132DEULL,
		0x8EE1C1D86CEB9E8DULL,
		0xA877F04F2EADD240ULL,
		0x73502BB15D1CEF5AULL,
		0x8485E4A0CED62A08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1FDECB4E4814D9ULL,
		0xC3C1D3AA18246D43ULL,
		0x4E99AF537F601439ULL,
		0x417D0910B69AC72EULL,
		0x17E7971C50D02A01ULL,
		0xE63710CF2D08F981ULL,
		0xA62564CD6A8FF5DDULL,
		0x40CCE9CED7A8AD47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73DAD917CEE34D70ULL,
		0xC618A0056A6D86A7ULL,
		0x2D467663B903BAD7ULL,
		0x56D25C3CF5B66BB0ULL,
		0x76FA2ABC1C1B748CULL,
		0xC240DF8001A4D8BFULL,
		0xCD2AC6E3F28CF97CULL,
		0x43B8FAD1F72D7CC0ULL
	}};
	sign = 0;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CA9568DEFE31C3FULL,
		0x1089EC7F3AD1B0BDULL,
		0x3C75DB1ED87D071FULL,
		0xC99E5DF06F62A8FCULL,
		0xCAA2D81AB35CC545ULL,
		0x6DF91A62F44C013BULL,
		0x44FC972C0C9AF8B9ULL,
		0x1CE7DC283B76B293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDEF1DAC3E012BDULL,
		0x86BD093075DF9FBAULL,
		0xCEED209B8C5F6C49ULL,
		0xD0C62C394CE02FF8ULL,
		0xCA26226C403B597BULL,
		0xCED9596BFA953E16ULL,
		0xFDB46B9E9B5F5C02ULL,
		0x99441F12CBFF235BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ECA64B32C030982ULL,
		0x89CCE34EC4F21103ULL,
		0x6D88BA834C1D9AD5ULL,
		0xF8D831B722827903ULL,
		0x007CB5AE73216BC9ULL,
		0x9F1FC0F6F9B6C325ULL,
		0x47482B8D713B9CB6ULL,
		0x83A3BD156F778F37ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74309F57712147CEULL,
		0x2F19F22DA21A7F4DULL,
		0x65C184F45636547DULL,
		0xBA26520C54007C7EULL,
		0xBB84B81FCE9709CFULL,
		0x2027B08909AD049BULL,
		0x0DD32AE534F7BC3BULL,
		0x46A6A9FC002B2255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDEADF544C93524AULL,
		0x8FB0D200E4BECA55ULL,
		0x5B58FDDBDF792F7FULL,
		0x0188B73ADC3F3E8EULL,
		0xA086952473C9DCB0ULL,
		0x00C83FD7307B6B80ULL,
		0x8DF7C4C5903F12CEULL,
		0x3D6A1EADDD272FCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA645C003248DF584ULL,
		0x9F69202CBD5BB4F7ULL,
		0x0A68871876BD24FDULL,
		0xB89D9AD177C13DF0ULL,
		0x1AFE22FB5ACD2D1FULL,
		0x1F5F70B1D931991BULL,
		0x7FDB661FA4B8A96DULL,
		0x093C8B4E2303F287ULL
	}};
	sign = 0;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA4C57963ECCE7F41ULL,
		0xEBA6BC837FB58A50ULL,
		0x95E73EC172F2FDA6ULL,
		0x658F55DF371795FAULL,
		0x484CFC6190CDE67AULL,
		0xB47569C2FD9F533CULL,
		0xE06C0CBCA38047C5ULL,
		0x05DA1A19A1F6D2CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EBF483CE0F441EULL,
		0x3EA88B759B9F4E42ULL,
		0xDD9BF2CEFC1865A3ULL,
		0xDA9EC704A994CD05ULL,
		0x60811493D05AB5EDULL,
		0x1900D077E6B8196DULL,
		0x4F4BF43771A50336ULL,
		0x4ADD9AEFE7D8513DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFAD984E01EBF3B23ULL,
		0xACFE310DE4163C0DULL,
		0xB84B4BF276DA9803ULL,
		0x8AF08EDA8D82C8F4ULL,
		0xE7CBE7CDC073308CULL,
		0x9B74994B16E739CEULL,
		0x9120188531DB448FULL,
		0xBAFC7F29BA1E8192ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99C4BD66C83CEB8AULL,
		0x8CC52F7FF113E4BDULL,
		0x41EF127C450CF9FAULL,
		0xC4308F65DF0729DDULL,
		0x8A2F696E1EC805AEULL,
		0x8ABB6A134053B907ULL,
		0x78B45EBB2D470651ULL,
		0x47D3A4A496B3B9BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE295A3401E757F1CULL,
		0x08B879F8E45D2EE7ULL,
		0xB79D2A154C922C78ULL,
		0xDA882ABC740850A7ULL,
		0xC0D36FFE599B868AULL,
		0x1D1CE00E8F1DB3AFULL,
		0x65E073F26D6F68CDULL,
		0xE42E994F2EBFD6DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB72F1A26A9C76C6EULL,
		0x840CB5870CB6B5D5ULL,
		0x8A51E866F87ACD82ULL,
		0xE9A864A96AFED935ULL,
		0xC95BF96FC52C7F23ULL,
		0x6D9E8A04B1360557ULL,
		0x12D3EAC8BFD79D84ULL,
		0x63A50B5567F3E2E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB9477E909BDF45DULL,
		0x59146D682252F07AULL,
		0x6E09948997D52339ULL,
		0xCCF56E3A6DB0C0A6ULL,
		0x1E723DEFC68E207EULL,
		0x183CD8E91756D9FDULL,
		0x946CCA990DB3C93CULL,
		0x8345B42F23195F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD7638CFB177C0EULL,
		0x7FC558589853F69AULL,
		0xE3783AD573D2A38CULL,
		0xF9F40EDB790579A7ULL,
		0xE7E2DE7D37FF896DULL,
		0xA48B4A8755A65313ULL,
		0x3F455E88383F3664ULL,
		0xEF0EB9DE661C6EEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40BD145C0EA6784FULL,
		0xD94F150F89FEF9E0ULL,
		0x8A9159B424027FACULL,
		0xD3015F5EF4AB46FEULL,
		0x368F5F728E8E9710ULL,
		0x73B18E61C1B086E9ULL,
		0x55276C10D57492D7ULL,
		0x9436FA50BCFCF0ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x294147BAABF01038ULL,
		0xE9FFBD108AE3DC6AULL,
		0x1A000A52C2931E94ULL,
		0x47D461CAA801D90CULL,
		0x13787087D0F45B47ULL,
		0x7EAD6DB04171DEE3ULL,
		0xF5DCD07EA73C1E13ULL,
		0x51B1F1FF9CA84A4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EFBCECED046C4FCULL,
		0x7D1FC06CADC65929ULL,
		0xDAB910BE3FE088A2ULL,
		0x9FA5238C86B3EF55ULL,
		0x6453AE730D3ACBA5ULL,
		0xE9DF69D0B6417A78ULL,
		0xF802AD46927B74EEULL,
		0x6221AAA0CEBE7616ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFA4578EBDBA94B3CULL,
		0x6CDFFCA3DD1D8340ULL,
		0x3F46F99482B295F2ULL,
		0xA82F3E3E214DE9B6ULL,
		0xAF24C214C3B98FA1ULL,
		0x94CE03DF8B30646AULL,
		0xFDDA233814C0A924ULL,
		0xEF90475ECDE9D434ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D584B58B4AC24A3ULL,
		0xD68EA92AB4225D0FULL,
		0xC687293619273916ULL,
		0x50451647B05136A0ULL,
		0x4759FCDB615FFB36ULL,
		0xC79855CE5CCB16C0ULL,
		0x57D0F1B47B73ADC2ULL,
		0x4254056F5EB8E81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7B04049B11AC5F9ULL,
		0x795A25B97745CE4DULL,
		0xA7D590DCCA6C01F8ULL,
		0xA7DAB79307A6281BULL,
		0x31BE263DC0B8682BULL,
		0x2297DA662A737A63ULL,
		0xED1D1796211D919EULL,
		0x804091F737BAB9E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35A80B0F03915EAAULL,
		0x5D3483713CDC8EC1ULL,
		0x1EB198594EBB371EULL,
		0xA86A5EB4A8AB0E85ULL,
		0x159BD69DA0A7930AULL,
		0xA5007B6832579C5DULL,
		0x6AB3DA1E5A561C24ULL,
		0xC213737826FE2E39ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x761461BF1BD3D295ULL,
		0xC4A840D362182DCBULL,
		0x1E45B57173084DE1ULL,
		0xCB18CDB7B9293C20ULL,
		0xD611E7E116AED0BAULL,
		0x137953068A06AEC8ULL,
		0x4275E5711BCD086FULL,
		0xB4CFE82BCE60DE6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E2A8EE442C32A7EULL,
		0x20F8FBB1B4BE67ECULL,
		0x4F879151EA8F53B6ULL,
		0x9A684DBFDFF66725ULL,
		0xE66929CD8970625DULL,
		0x55C7458FE9591EDCULL,
		0x1C6B72A9E7DF6904ULL,
		0x740ED31D759BAB43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37E9D2DAD910A817ULL,
		0xA3AF4521AD59C5DFULL,
		0xCEBE241F8878FA2BULL,
		0x30B07FF7D932D4FAULL,
		0xEFA8BE138D3E6E5DULL,
		0xBDB20D76A0AD8FEBULL,
		0x260A72C733ED9F6AULL,
		0x40C1150E58C5332CULL
	}};
	sign = 0;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3219670699FC2C38ULL,
		0xBBE61AE1BD8E4207ULL,
		0x9415CC87E0F466F0ULL,
		0x28548ACB9161BD4DULL,
		0xD91C311B8E70D384ULL,
		0x16157F8B7EECF3A7ULL,
		0xDDD4195667720951ULL,
		0x1CC4066B686A9D24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C91DFCA22A3DFEAULL,
		0x8C9516D520EDB31FULL,
		0xE0F56E0BF3103691ULL,
		0xE0A21E1A3C8A27B4ULL,
		0xB9FD829682D445D0ULL,
		0x5E277953FCFB3E83ULL,
		0xDF61360C4089CEB5ULL,
		0xC97615FF75875A70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2587873C77584C4EULL,
		0x2F51040C9CA08EE8ULL,
		0xB3205E7BEDE4305FULL,
		0x47B26CB154D79598ULL,
		0x1F1EAE850B9C8DB3ULL,
		0xB7EE063781F1B524ULL,
		0xFE72E34A26E83A9BULL,
		0x534DF06BF2E342B3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05FFE88CD03CE74BULL,
		0x6FCD1446570EA913ULL,
		0xB01638B769AF6C14ULL,
		0x9A7B0B6B328B0BC1ULL,
		0x4E2EC9FD7CF43033ULL,
		0xD6EF110AE367266EULL,
		0xD4D61E64AAFCAB4FULL,
		0x0E90F6BF6512B560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2685D64DF396FF13ULL,
		0x1F59F95715E7C5ADULL,
		0x6FB344188FEDAE07ULL,
		0x7A896BB65F894E91ULL,
		0x7120FD06E96E4123ULL,
		0x4B3116B8219F5B4BULL,
		0x724F68D8FFBFD0A3ULL,
		0x2F304392DE46E12AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF7A123EDCA5E838ULL,
		0x50731AEF4126E365ULL,
		0x4062F49ED9C1BE0DULL,
		0x1FF19FB4D301BD30ULL,
		0xDD0DCCF69385EF10ULL,
		0x8BBDFA52C1C7CB22ULL,
		0x6286B58BAB3CDAACULL,
		0xDF60B32C86CBD436ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AD63388B0F712E3ULL,
		0x23A0CFC9A690E9BCULL,
		0xF4806C0AE83D7C76ULL,
		0x538C4DBBFCD2B45EULL,
		0xACAACCFDBE1BF6B8ULL,
		0xA9534CB2547D93FDULL,
		0xF2D830E6C0700242ULL,
		0xF1DE1845F36DB17AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55B819417D1A855ULL,
		0xEFE5079E68C65CC2ULL,
		0x135DA8FC74ABAD70ULL,
		0xABF85866D53F69D9ULL,
		0x4480E5EE59A50180ULL,
		0x54B27022688A79B4ULL,
		0x89D5577D17E6D411ULL,
		0xB4820AC9393BCB33ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA57AB1F499256A8EULL,
		0x33BBC82B3DCA8CF9ULL,
		0xE122C30E7391CF05ULL,
		0xA793F55527934A85ULL,
		0x6829E70F6476F537ULL,
		0x54A0DC8FEBF31A49ULL,
		0x6902D969A8892E31ULL,
		0x3D5C0D7CBA31E647ULL
	}};
	sign = 0;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD794CB5E1056E40AULL,
		0x339EBCB71DE0C8F8ULL,
		0x9B5A256E3D4D75E9ULL,
		0xD2DD617D1FF03E7AULL,
		0xE18A7888068B8F81ULL,
		0xAB7CE0E8F95258ACULL,
		0x1E9CA5E1BE1F06E6ULL,
		0xF9E240922986139CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9193DB8330E12D9ULL,
		0x145882994D82DF03ULL,
		0x773F572953625FD2ULL,
		0x06EFE02CA10F20ACULL,
		0x44177494D680682CULL,
		0xDF4875B8E98BEAD8ULL,
		0xBA018FF8897BCF1DULL,
		0xFC788CCB8FDAAD12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE7B8DA5DD48D131ULL,
		0x1F463A1DD05DE9F4ULL,
		0x241ACE44E9EB1617ULL,
		0xCBED81507EE11DCEULL,
		0x9D7303F3300B2755ULL,
		0xCC346B300FC66DD4ULL,
		0x649B15E934A337C8ULL,
		0xFD69B3C699AB6689ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C275D2E0AC1FE8AULL,
		0x2E634FA7E5A26F98ULL,
		0x619E499C7C2D46B9ULL,
		0x5D102C83B992B93AULL,
		0xF598CBDA650185F0ULL,
		0x20DC2B3DCF05392CULL,
		0x192D16210AD559B6ULL,
		0x791D14DD0858F043ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73AF2CD4BDB141B3ULL,
		0x288EFD87396582ADULL,
		0x02DDA29362B251D3ULL,
		0x5C9D8BE6B5B988BFULL,
		0x7135FEE74F1ECE32ULL,
		0xFC172FBAEDE9B153ULL,
		0xFF994278DC60783EULL,
		0xA3E11609245CCED4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x187830594D10BCD7ULL,
		0x05D45220AC3CECEBULL,
		0x5EC0A709197AF4E6ULL,
		0x0072A09D03D9307BULL,
		0x8462CCF315E2B7BEULL,
		0x24C4FB82E11B87D9ULL,
		0x1993D3A82E74E177ULL,
		0xD53BFED3E3FC216EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7858BD9939E0D14ULL,
		0x69008C9194163C56ULL,
		0x8A481D6E7D956FA6ULL,
		0xAA2AF7686CE62152ULL,
		0x0C87B26F2EE10BD8ULL,
		0xA5B38185DCBDA52AULL,
		0x3FF35877B3130EA3ULL,
		0x77654C6B7E19074AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4E27DC04CE6E25ULL,
		0x19763C5A31C481EDULL,
		0xFF4742131356A45FULL,
		0x13A096547B004A27ULL,
		0xABFF3E3B337D0042ULL,
		0x2E33D6A2B72DB249ULL,
		0xF972BF4A090ED150ULL,
		0x3D4A0E43EBF0E025ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x883763FD8ECF9EEFULL,
		0x4F8A50376251BA69ULL,
		0x8B00DB5B6A3ECB47ULL,
		0x968A6113F1E5D72AULL,
		0x60887433FB640B96ULL,
		0x777FAAE3258FF2E0ULL,
		0x4680992DAA043D53ULL,
		0x3A1B3E2792282724ULL
	}};
	sign = 0;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A955BF020B2FA47ULL,
		0x8CA14582BC64A4E9ULL,
		0x34B1A9B4709873DEULL,
		0x12110A58BE159083ULL,
		0x933DA130349DA0A1ULL,
		0x3E964BE7F0AEC00EULL,
		0xC68260A6AB847B87ULL,
		0xC0BC68619EBD89B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x282AB497E3F54CF1ULL,
		0x4FAF2CF8729F6633ULL,
		0x4B51256724F662B6ULL,
		0x7F2B4FF52EF024E3ULL,
		0x7060BD008CF1C3D9ULL,
		0x743BB8A3B9A74DD8ULL,
		0x1FEC0DAB6EB08F02ULL,
		0x7CF28AF7E0EB377FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x026AA7583CBDAD56ULL,
		0x3CF2188A49C53EB6ULL,
		0xE960844D4BA21128ULL,
		0x92E5BA638F256B9FULL,
		0x22DCE42FA7ABDCC7ULL,
		0xCA5A934437077236ULL,
		0xA69652FB3CD3EC84ULL,
		0x43C9DD69BDD2523AULL
	}};
	sign = 0;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A9A4A4078C139EFULL,
		0x1E575C2A27F2487DULL,
		0x494E0C9C83A20323ULL,
		0x7D8C45290C0B1C26ULL,
		0xA8D4332995009B4EULL,
		0xC8D16AC76107C2FFULL,
		0x1CB4E9E344A35221ULL,
		0xB9E85D50D83CC9DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BD4E0EADF15ACEULL,
		0x38A0961655595553ULL,
		0x028933CDDF72A4F0ULL,
		0x34590407F1E4700CULL,
		0xA03A345E6CC95B13ULL,
		0xA3C65549975BA15FULL,
		0xCE39F1185A0AF235ULL,
		0x705CB334FCA0F366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20DCFC31CACFDF21ULL,
		0xE5B6C613D298F32AULL,
		0x46C4D8CEA42F5E32ULL,
		0x493341211A26AC1AULL,
		0x0899FECB2837403BULL,
		0x250B157DC9AC21A0ULL,
		0x4E7AF8CAEA985FECULL,
		0x498BAA1BDB9BD675ULL
	}};
	sign = 0;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E779911483137F9ULL,
		0x002E818A2B9962ABULL,
		0x0ED4CF8E81729222ULL,
		0x8C599FFB971BD454ULL,
		0x9880E43F3F3EC0DFULL,
		0x6E5A745B718234BBULL,
		0x07D11E9BA34921D5ULL,
		0x3ED7BD4E2AF65E25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDBC491C0CCB7927ULL,
		0x7FA5B8A3B0AE8B74ULL,
		0xE0E4AE58A7E2B272ULL,
		0x85378E37DB2CF544ULL,
		0x2F5C6F08DA9BB3D0ULL,
		0x5A2B7BFE17DFEA98ULL,
		0x0FA53372A34533E2ULL,
		0xD6A40D14E70D2A52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0BB4FF53B65BED2ULL,
		0x8088C8E67AEAD736ULL,
		0x2DF02135D98FDFAFULL,
		0x072211C3BBEEDF0FULL,
		0x6924753664A30D0FULL,
		0x142EF85D59A24A23ULL,
		0xF82BEB290003EDF3ULL,
		0x6833B03943E933D2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6478FE429780617DULL,
		0x27F4377ACA8F4310ULL,
		0x3964F1646A133D6CULL,
		0xC073C522D6CCE88FULL,
		0x404AE880839F0ACFULL,
		0x96AD2EDC10D9C2DEULL,
		0x4D6CD5195F34580AULL,
		0x361DFB69F09B398DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAE6D4E98C70C27DULL,
		0xA22E5849C9E6694BULL,
		0xC171D9E4C293CD7CULL,
		0x2B4356F378964B16ULL,
		0x1F9B4DAD9FA430EEULL,
		0x65CE80D63216D083ULL,
		0x137940FD312F3583ULL,
		0x858275F2CC747459ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA99229590B0F9F00ULL,
		0x85C5DF3100A8D9C4ULL,
		0x77F3177FA77F6FEFULL,
		0x95306E2F5E369D78ULL,
		0x20AF9AD2E3FAD9E1ULL,
		0x30DEAE05DEC2F25BULL,
		0x39F3941C2E052287ULL,
		0xB09B85772426C534ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC117A174F6EC5327ULL,
		0x4E8ED511301C79A3ULL,
		0x85A6D5C007DCE24EULL,
		0xAB6E253BAFC8B9B3ULL,
		0xDC17045499999A66ULL,
		0x7AB66A3E4DB72E01ULL,
		0xA35BAA4069560920ULL,
		0x74D5335CA2BE9D7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53BFB53507C94E13ULL,
		0x8A97BC7BBC24F806ULL,
		0x8B47C79E2C2DB9DBULL,
		0x3D451E098A358464ULL,
		0xE79C507408E074A7ULL,
		0x63211C0A9E2A3FB4ULL,
		0x29479B75CDAE3408ULL,
		0x9107BA677812FEEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D57EC3FEF230514ULL,
		0xC3F7189573F7819DULL,
		0xFA5F0E21DBAF2872ULL,
		0x6E2907322593354EULL,
		0xF47AB3E090B925BFULL,
		0x17954E33AF8CEE4CULL,
		0x7A140ECA9BA7D518ULL,
		0xE3CD78F52AAB9E8CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x480D2C8B11370CB3ULL,
		0x9A53871E847BE2AFULL,
		0xF06D3FAF80F34868ULL,
		0xF1C582D049197E57ULL,
		0xEB46C42E5D7343DCULL,
		0x9D26C48FF45E17B8ULL,
		0x4C4589A3E406ED56ULL,
		0xE75275BDF5A53FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19DF43FB49D0717ULL,
		0x16106692A176E3A9ULL,
		0x08E24B17AAFDD041ULL,
		0x79CD920C5E21476EULL,
		0x5095A7E02E4AF06FULL,
		0xDD1B07F525F3857AULL,
		0xA3B9ED60823FA5ECULL,
		0xA9814524AC55672BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x966F384B5C9A059CULL,
		0x8443208BE304FF05ULL,
		0xE78AF497D5F57827ULL,
		0x77F7F0C3EAF836E9ULL,
		0x9AB11C4E2F28536DULL,
		0xC00BBC9ACE6A923EULL,
		0xA88B9C4361C74769ULL,
		0x3DD13099494FD8B1ULL
	}};
	sign = 0;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEADE9071978DE9FULL,
		0x3C66D4C547476BE6ULL,
		0x8BC3C08AA96484B8ULL,
		0x2607A0B8D2E1AE6DULL,
		0xC0C086C272FA3270ULL,
		0xF1F19436DD794A92ULL,
		0x1AFB7569BD29A8BDULL,
		0x68E0F41C21D419B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86E44250F400CA2FULL,
		0xF8EED89C3C2C2FC5ULL,
		0x110C35A9D02A668EULL,
		0xCB48C2A4B049FC5EULL,
		0x5A7D28498247FEE5ULL,
		0xA8706ACB9D2149B4ULL,
		0x4C7AFD3A06B8C5E2ULL,
		0x549E3F038DDF9733ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27C9A6B625781470ULL,
		0x4377FC290B1B3C21ULL,
		0x7AB78AE0D93A1E29ULL,
		0x5ABEDE142297B20FULL,
		0x66435E78F0B2338AULL,
		0x4981296B405800DEULL,
		0xCE80782FB670E2DBULL,
		0x1442B51893F48280ULL
	}};
	sign = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x695BE5B21774FB5CULL,
		0x882C5470A10CFDEDULL,
		0xDE4EADAA9385B43BULL,
		0x7D9B55766B4173D6ULL,
		0x1BCD6FBA8A41B9CAULL,
		0x6D2A3DEC355E4539ULL,
		0xCC8E6244ED422173ULL,
		0x28A8B0BCB251E8A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x536A3D526323202EULL,
		0x0BEF97B33F870C1AULL,
		0xEAEBA1F17BF894F6ULL,
		0x62B8A241BACF9AFEULL,
		0x05F9ACCCA9097648ULL,
		0x6632A7BBC5FB03A7ULL,
		0xC905D560B1A84BA8ULL,
		0x270263E0B6922937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15F1A85FB451DB2EULL,
		0x7C3CBCBD6185F1D3ULL,
		0xF3630BB9178D1F45ULL,
		0x1AE2B334B071D8D7ULL,
		0x15D3C2EDE1384382ULL,
		0x06F796306F634192ULL,
		0x03888CE43B99D5CBULL,
		0x01A64CDBFBBFBF6DULL
	}};
	sign = 0;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F0840DC178FFC8FULL,
		0x7F69C95EBAE3ECDCULL,
		0x80084A339B4829A9ULL,
		0xFADCD40858C87D9CULL,
		0xED3F24CA56F754A2ULL,
		0x808D6442D9FEFFA7ULL,
		0x8499DF3D017766BAULL,
		0x7A31A54E309184FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B4EE8B5EB60461ULL,
		0x3EFED358E2C1DC3DULL,
		0x81C23F327A9BE204ULL,
		0x3F844D8A9E82D8EAULL,
		0x90AC0D5E11B21EF8ULL,
		0x0EE085190924770FULL,
		0x1DB469ACA192E4B6ULL,
		0xCF0A6B75CE1415DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE535250B8D9F82EULL,
		0x406AF605D822109EULL,
		0xFE460B0120AC47A5ULL,
		0xBB58867DBA45A4B1ULL,
		0x5C93176C454535AAULL,
		0x71ACDF29D0DA8898ULL,
		0x66E575905FE48204ULL,
		0xAB2739D8627D6F1FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27B2325A39EF8D16ULL,
		0x3468B7089367C391ULL,
		0xCE31E11A405284A8ULL,
		0x0CB9956F15B25A2BULL,
		0x5ABD3709AAC8ECA5ULL,
		0x766C0EC08A6048D8ULL,
		0x9A3B9C2C088500B2ULL,
		0x3AEBF0245BEC3814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x158BC144B59F82C7ULL,
		0x8F10EBB7AB5ECCFAULL,
		0xAC349137ECC2EA06ULL,
		0x7E00D9A4C1038D00ULL,
		0x5535B0D6429C7276ULL,
		0xF9639F4F876AD853ULL,
		0x03C1E43861B7BEBAULL,
		0xD2369E1B95DCBFFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1226711584500A4FULL,
		0xA557CB50E808F697ULL,
		0x21FD4FE2538F9AA1ULL,
		0x8EB8BBCA54AECD2BULL,
		0x05878633682C7A2EULL,
		0x7D086F7102F57085ULL,
		0x9679B7F3A6CD41F7ULL,
		0x68B55208C60F7818ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCEDE56D49DF3D79ULL,
		0x58C7511065E91F1AULL,
		0x2BFB64778694E73CULL,
		0xF038FD2F927F2BCBULL,
		0xA0CBCAB38C9B3BD0ULL,
		0x1C5289C9FE8F320FULL,
		0xEF406B85B7EC0985ULL,
		0xF3688A369F089DB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAB32DA75939DB30ULL,
		0x9E2088B8FE13731DULL,
		0x26DFEA03AC90E39DULL,
		0x4FB785088F8946FFULL,
		0x4871ADB0CFC9D426ULL,
		0xC0909C8430CE1894ULL,
		0x8D40B1A670C895F4ULL,
		0xF70AB075E342177CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x223AB7C5F0A56249ULL,
		0xBAA6C85767D5ABFDULL,
		0x051B7A73DA04039EULL,
		0xA081782702F5E4CCULL,
		0x585A1D02BCD167AAULL,
		0x5BC1ED45CDC1197BULL,
		0x61FFB9DF47237390ULL,
		0xFC5DD9C0BBC68636ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA49C9606502F3BD9ULL,
		0x2CEFA7C3CCEFE0FCULL,
		0x454C4A82A04F2E2AULL,
		0x7304568470DAB4BFULL,
		0xCDC072C543764607ULL,
		0x26AFD4DA52EF2E01ULL,
		0xCC5C60E78EFF08CDULL,
		0x443A66BF868E8424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F96F618C395556ULL,
		0xEE8D9E2D748FA807ULL,
		0x9DAC85771A84FBB9ULL,
		0xBD221468836FFFE7ULL,
		0x0EAC593BB85F89D7ULL,
		0x362B325303912BA8ULL,
		0x58711CF872DBC24CULL,
		0x056BEA6F6C7F69A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BA326A4C3F5E683ULL,
		0x3E620996586038F5ULL,
		0xA79FC50B85CA3270ULL,
		0xB5E2421BED6AB4D7ULL,
		0xBF1419898B16BC2FULL,
		0xF084A2874F5E0259ULL,
		0x73EB43EF1C234680ULL,
		0x3ECE7C501A0F1A84ULL
	}};
	sign = 0;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77BD71CB453B22B1ULL,
		0x835949598B41F8C1ULL,
		0xF75E961F5C424805ULL,
		0x75A4787F6C921995ULL,
		0x354A11B592E3F3ECULL,
		0x8C643A7CEB5E7DD7ULL,
		0xA66A58B2F7799440ULL,
		0x21470E7683D01748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F2F9BD0D28E49C5ULL,
		0x85CE9E5BA03A00DBULL,
		0xF2A266E93FAF36C3ULL,
		0xAC990A5902BA6040ULL,
		0xD2901226C5547D41ULL,
		0x58049AFB0F5D5044ULL,
		0xB79C8ADA85A6115AULL,
		0xDB3ACA035D575423ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD88DD5FA72ACD8ECULL,
		0xFD8AAAFDEB07F7E5ULL,
		0x04BC2F361C931141ULL,
		0xC90B6E2669D7B955ULL,
		0x62B9FF8ECD8F76AAULL,
		0x345F9F81DC012D92ULL,
		0xEECDCDD871D382E6ULL,
		0x460C44732678C324ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6679D4F114DD8EAULL,
		0xD4B03C27BA3BAC84ULL,
		0x74107B5F226DF226ULL,
		0xE9D494D4A2CE7AF4ULL,
		0x6D35335DE6AA663BULL,
		0xE27677A316093944ULL,
		0xD3926E334C9E8685ULL,
		0x911B421BE49626A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x751FB67DE8DD9C20ULL,
		0x9F49EEDB170020A1ULL,
		0x3B3C5282A0ACDF83ULL,
		0xE0B9C3EF62998BEEULL,
		0x0208A3C0518F7327ULL,
		0x8CC82109258E90DBULL,
		0xA0669DB3545AC158ULL,
		0xE911452926C9C801ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5147E6D128703CCAULL,
		0x35664D4CA33B8BE3ULL,
		0x38D428DC81C112A3ULL,
		0x091AD0E54034EF06ULL,
		0x6B2C8F9D951AF314ULL,
		0x55AE5699F07AA869ULL,
		0x332BD07FF843C52DULL,
		0xA809FCF2BDCC5EA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x678A39344279294DULL,
		0x25EBC7911F771E48ULL,
		0xA6B6CDC8E0E3B40EULL,
		0x71EEC753B0B945CCULL,
		0x880653D003B254E1ULL,
		0x57C5B169956EECA6ULL,
		0x828E7A4C1A409A33ULL,
		0x78653C986669446DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F40BD8878AFE775ULL,
		0x79A67539F9694E56ULL,
		0x308D21E0E60AE39AULL,
		0x7CC9C33D257557AFULL,
		0x899314B2AB94145CULL,
		0x5363742A7CFCEE81ULL,
		0xC64E8911239B11F5ULL,
		0xDF39993EE2894D91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18497BABC9C941D8ULL,
		0xAC455257260DCFF2ULL,
		0x7629ABE7FAD8D073ULL,
		0xF52504168B43EE1DULL,
		0xFE733F1D581E4084ULL,
		0x04623D3F1871FE24ULL,
		0xBC3FF13AF6A5883EULL,
		0x992BA35983DFF6DBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3ECF90277446C06ULL,
		0x45F186A775BC884FULL,
		0x2C691907C37E853BULL,
		0x0A616C5FB8300702ULL,
		0x3A9E859F09E1496EULL,
		0xA00C1AF353416155ULL,
		0x9A965DA914D09054ULL,
		0x226C11DA37DDAD70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0EDD0E87767861CULL,
		0x4E334A75E75E5C8CULL,
		0x224AF12A9FA49D5AULL,
		0x2BFE820B12B975ACULL,
		0x79EC1AC0374A34BBULL,
		0x5A58D5E4FDC4F7E9ULL,
		0x1490FEF2F0C6076CULL,
		0x8178721C975468A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2FF2819FFDCE5EAULL,
		0xF7BE3C318E5E2BC2ULL,
		0x0A1E27DD23D9E7E0ULL,
		0xDE62EA54A5769156ULL,
		0xC0B26ADED29714B2ULL,
		0x45B3450E557C696BULL,
		0x86055EB6240A88E8ULL,
		0xA0F39FBDA08944CCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1914CAEC1054537CULL,
		0xC0567FD5D2341E80ULL,
		0x7F1773468DF13356ULL,
		0xD0A07320FAB899F0ULL,
		0xB78DF3A651AF5853ULL,
		0x9DBBF18DDB31D38AULL,
		0xD3C714064ED01DDFULL,
		0x4E4B44CE5F8D4F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E81EBC644300D7AULL,
		0x0CC8E8062088BA94ULL,
		0x714A52757B9AB71CULL,
		0x2E7D3578DE1E2591ULL,
		0xAC0E993FAF865C67ULL,
		0x3D018161934E7F65ULL,
		0x569168DA1D1AE27EULL,
		0x016978496BE76952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA92DF25CC244602ULL,
		0xB38D97CFB1AB63EBULL,
		0x0DCD20D112567C3AULL,
		0xA2233DA81C9A745FULL,
		0x0B7F5A66A228FBECULL,
		0x60BA702C47E35425ULL,
		0x7D35AB2C31B53B61ULL,
		0x4CE1CC84F3A5E5BAULL
	}};
	sign = 0;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8F7FE47913A38F9ULL,
		0x44B45B2605CC7CABULL,
		0x961A6B184B915441ULL,
		0x4BFF9BA01CFA205DULL,
		0x9DE939BA624C8092ULL,
		0x51535F8AA85307C9ULL,
		0x0E6EA50C58E77804ULL,
		0xBCF2F9DF3EF45883ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19E27E397598DBE0ULL,
		0x43491DF5A5941056ULL,
		0x4F37417B02806F96ULL,
		0x0D0E29A2BD54190FULL,
		0x0DB72F0FEF895B41ULL,
		0x927EDB43DB062468ULL,
		0xB6CF757E0AA72DB0ULL,
		0x92F8DA9EA9602735ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF15800E1BA15D19ULL,
		0x016B3D3060386C55ULL,
		0x46E3299D4910E4ABULL,
		0x3EF171FD5FA6074EULL,
		0x90320AAA72C32551ULL,
		0xBED48446CD4CE361ULL,
		0x579F2F8E4E404A53ULL,
		0x29FA1F409594314DULL
	}};
	sign = 0;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x497813C1C2D5C2D5ULL,
		0x99B950C3F25376B8ULL,
		0x663F4CE00244B2EBULL,
		0x15C0E5BA6434BE9CULL,
		0xA883BAB48D09740FULL,
		0x4E1D2B4E1BEAC920ULL,
		0x010EDC915C6B8DE0ULL,
		0x4B41A4D234795357ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2453D4FA9A2F712EULL,
		0xF18BE29BE8BE12B6ULL,
		0x6DB95EF6037DCE37ULL,
		0x296BBA3B545AA6E9ULL,
		0xD69FD790B906057AULL,
		0x9998FC1C87E603A4ULL,
		0x64AE8F011C3263D0ULL,
		0xDC6B9BEBFAFDC53FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25243EC728A651A7ULL,
		0xA82D6E2809956402ULL,
		0xF885EDE9FEC6E4B3ULL,
		0xEC552B7F0FDA17B2ULL,
		0xD1E3E323D4036E94ULL,
		0xB4842F319404C57BULL,
		0x9C604D9040392A0FULL,
		0x6ED608E6397B8E17ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED15BF7D629AF2CCULL,
		0x44485228ED9C39D8ULL,
		0x3AB0E70E44636614ULL,
		0xC4DBED2D6703C158ULL,
		0x435EBD27EB102A6EULL,
		0x9B172991ECD12C7CULL,
		0x42B82E828189ECC7ULL,
		0x8C5F1E35665D643AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F63C8D534B274A7ULL,
		0x0CEC35A112E04C03ULL,
		0xEFC4586EE0FCA721ULL,
		0x1BB2888752F919F8ULL,
		0xA04E1FAF0579C420ULL,
		0xADC716566A02095EULL,
		0x72F348ED03004F41ULL,
		0x80D27E481F9E63F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB1F6A82DE87E25ULL,
		0x375C1C87DABBEDD5ULL,
		0x4AEC8E9F6366BEF3ULL,
		0xA92964A6140AA75FULL,
		0xA3109D78E596664EULL,
		0xED50133B82CF231DULL,
		0xCFC4E5957E899D85ULL,
		0x0B8C9FED46BF0046ULL
	}};
	sign = 0;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEABFE193C399189CULL,
		0xBACC870F16330208ULL,
		0xA5831C4C773CB349ULL,
		0x0893C4E2C0776980ULL,
		0x57A9BA35CD9394FAULL,
		0xFA34D7826E402EA7ULL,
		0x277016B1BECD168BULL,
		0xAD04AD8549589204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3948A417D2A1AAC5ULL,
		0xD8E4D10B69C79C33ULL,
		0x081134BED85B838BULL,
		0x5ED06BD2464A3077ULL,
		0x11D557E29E513257ULL,
		0x78C16DF9DFAF7C93ULL,
		0x5559728E4911F7E1ULL,
		0x7CCE1F2445FBB719ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1773D7BF0F76DD7ULL,
		0xE1E7B603AC6B65D5ULL,
		0x9D71E78D9EE12FBDULL,
		0xA9C359107A2D3909ULL,
		0x45D462532F4262A2ULL,
		0x817369888E90B214ULL,
		0xD216A42375BB1EAAULL,
		0x30368E61035CDAEAULL
	}};
	sign = 0;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6C726A1EB22476ULL,
		0x66F6F5B1CDB1D8D7ULL,
		0x9515F2E3BF003A28ULL,
		0xD28730C7F046C77BULL,
		0x86035F2F07B22AE8ULL,
		0x6462328E253C55F2ULL,
		0x4DDA786511C86421ULL,
		0x0E7D5086290E44C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61AEC0FA3CB17ECCULL,
		0xD16C5CF38BF200FDULL,
		0x66BF20A3F7D30C38ULL,
		0xF7B411343D89A304ULL,
		0x35C58667113FB80AULL,
		0x73FC124C7D57A5FCULL,
		0xFD2BC0B888BF37C7ULL,
		0xD4EE612BB4535D12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68BDB16FE200A5AAULL,
		0x958A98BE41BFD7DAULL,
		0x2E56D23FC72D2DEFULL,
		0xDAD31F93B2BD2477ULL,
		0x503DD8C7F67272DDULL,
		0xF0662041A7E4AFF6ULL,
		0x50AEB7AC89092C59ULL,
		0x398EEF5A74BAE7B0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE0BCBE3A97434FE2ULL,
		0xFCF8B6E5848B0CF7ULL,
		0x7A7BABB90EAEA122ULL,
		0xC4DE1BE8D81BFFA9ULL,
		0x2CAB791A552DF5B0ULL,
		0x548A6A24EE7C6BABULL,
		0x93E39CF5E5202EFDULL,
		0x982D94656AE6EC1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6E4A4533088429ULL,
		0x0B41A7A8FBFD393DULL,
		0x2D074D847DE7343DULL,
		0x297EF8B17F602477ULL,
		0x83DD8A8127367DF5ULL,
		0x4A3C888C4EFF6330ULL,
		0xB4612F956EB5B9FEULL,
		0x90D617983988DAAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x654E73F5643ACBB9ULL,
		0xF1B70F3C888DD3BAULL,
		0x4D745E3490C76CE5ULL,
		0x9B5F233758BBDB32ULL,
		0xA8CDEE992DF777BBULL,
		0x0A4DE1989F7D087AULL,
		0xDF826D60766A74FFULL,
		0x07577CCD315E116FULL
	}};
	sign = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51793836495D80A9ULL,
		0xD59BE8E36F10942EULL,
		0x672CA0D6FB35BFF1ULL,
		0x9BED89DBAEA237F0ULL,
		0x0FD71E612A18F3E0ULL,
		0xF8829EFCC0CC72A9ULL,
		0x2E85490CBE797B0AULL,
		0x521EDDEB21090521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9235FAF9AE677AFFULL,
		0x0755F5765457D8D9ULL,
		0xEF5CF00154C29B42ULL,
		0x44E3B38B0F524259ULL,
		0xE3D9381F04427796ULL,
		0xE0B03B509ED227DAULL,
		0xB59479797D7649AAULL,
		0x67C403796AEEEEA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF433D3C9AF605AAULL,
		0xCE45F36D1AB8BB54ULL,
		0x77CFB0D5A67324AFULL,
		0x5709D6509F4FF596ULL,
		0x2BFDE64225D67C4AULL,
		0x17D263AC21FA4ACEULL,
		0x78F0CF9341033160ULL,
		0xEA5ADA71B61A1679ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF90392E5B105201BULL,
		0x6EAF3F3D1DF58581ULL,
		0x16DEB35B89B56570ULL,
		0xA80B8761988D65CDULL,
		0x6DB7E8D8F33DD711ULL,
		0x97DC13CE9880C8D7ULL,
		0xE90D8A22027C4A84ULL,
		0x0D8BD4A027AC51EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34CA22DDF3522507ULL,
		0x72767B31DC0B51A4ULL,
		0x5816BD7EC6E1A523ULL,
		0x7A91FBD2B7A1F7DFULL,
		0xCE98196B2D4B3B5BULL,
		0xFAF8D4BFD8CBC9F9ULL,
		0xCE7E5825D75C2D25ULL,
		0xE0705B5491C21091ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4397007BDB2FB14ULL,
		0xFC38C40B41EA33DDULL,
		0xBEC7F5DCC2D3C04CULL,
		0x2D798B8EE0EB6DEDULL,
		0x9F1FCF6DC5F29BB6ULL,
		0x9CE33F0EBFB4FEDDULL,
		0x1A8F31FC2B201D5EULL,
		0x2D1B794B95EA415EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BCBCE2C4BA06740ULL,
		0x7C73F8CAE7A5B3C2ULL,
		0x6FB5157B955DBCD6ULL,
		0xE1FEAABB00B75836ULL,
		0xE32658DBFD7CE292ULL,
		0x9B791EABE7A14DBBULL,
		0x4C9F7762E081FEBAULL,
		0x09C5E4AB95512E76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238A1339E8C6FBFCULL,
		0x48970AB0D2624F3DULL,
		0xCCC1C383DAD9D3ACULL,
		0xC2640DDF8F3645E8ULL,
		0xF45A94468F8D0182ULL,
		0x99D7937545F165B8ULL,
		0x46B3BE189380FFB5ULL,
		0xE1C49BB3E6DB9DDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1841BAF262D96B44ULL,
		0x33DCEE1A15436485ULL,
		0xA2F351F7BA83E92AULL,
		0x1F9A9CDB7181124DULL,
		0xEECBC4956DEFE110ULL,
		0x01A18B36A1AFE802ULL,
		0x05EBB94A4D00FF05ULL,
		0x280148F7AE759098ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0D2C2D6B7B3009ULL,
		0xB4B91A4FC75A32FDULL,
		0x821E0E5729743B59ULL,
		0x4BF797CBDB06C509ULL,
		0x6DBC49896B668CD9ULL,
		0x77757E51F00900FBULL,
		0x85002863A8D8F9D4ULL,
		0xD42186AD0344C6DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE0D90307B017357ULL,
		0x1FBB57C1A69AC630ULL,
		0x0E1BBE3ECB655DC1ULL,
		0x19B2005F59285491ULL,
		0x418D2092BBB75CDFULL,
		0x589D23C10B416321ULL,
		0x8D810BEF4357A353ULL,
		0xE76AD3A822CC4D5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DFF9BFCF079BCB2ULL,
		0x94FDC28E20BF6CCCULL,
		0x740250185E0EDD98ULL,
		0x3245976C81DE7078ULL,
		0x2C2F28F6AFAF2FFAULL,
		0x1ED85A90E4C79DDAULL,
		0xF77F1C7465815681ULL,
		0xECB6B304E078797EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CB9A6078F6BD606ULL,
		0x284F676D871A3057ULL,
		0x5BEDFA1959AFA57BULL,
		0x4975C717634C2091ULL,
		0xDBB93716F2BE6693ULL,
		0xC9B803D87475A900ULL,
		0xE7ED0A45369CECE1ULL,
		0xF82E77CC0CB0027AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6007B52891A94D08ULL,
		0x1BCC36AA06B94D28ULL,
		0x075F0E8B624AAB8FULL,
		0x51E564ABFEDDA01AULL,
		0x29ACEE2B74B2305DULL,
		0xB38C46DA39093D1DULL,
		0xA73F665189F7AA27ULL,
		0x26644193B683F308ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CB1F0DEFDC288FEULL,
		0x0C8330C38060E32FULL,
		0x548EEB8DF764F9ECULL,
		0xF790626B646E8077ULL,
		0xB20C48EB7E0C3635ULL,
		0x162BBCFE3B6C6BE3ULL,
		0x40ADA3F3ACA542BAULL,
		0xD1CA3638562C0F72ULL
	}};
	sign = 0;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x131584EDB9400D5BULL,
		0xEC35CE06396A79FEULL,
		0x8A953372F14F2383ULL,
		0xA66E14395DEB37CAULL,
		0xC78DA1AA3B5CB08BULL,
		0x5CBD6EC229689065ULL,
		0xFEBD9137B27CA059ULL,
		0x7586C5C43887D165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A9A36CBA5F43235ULL,
		0xDF05217F4F271959ULL,
		0x3AE872D8F864FF0AULL,
		0x66DA6EB1E1977EE4ULL,
		0xB9A3A72E8C073617ULL,
		0x0211394872DE4D03ULL,
		0xD1C2806E67026707ULL,
		0xEAE290808ED92283ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD87B4E22134BDB26ULL,
		0x0D30AC86EA4360A4ULL,
		0x4FACC099F8EA2479ULL,
		0x3F93A5877C53B8E6ULL,
		0x0DE9FA7BAF557A74ULL,
		0x5AAC3579B68A4362ULL,
		0x2CFB10C94B7A3952ULL,
		0x8AA43543A9AEAEE2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA95D000767170DA4ULL,
		0x7D4885320A080E6BULL,
		0x3937787143571214ULL,
		0xAAD4AD1455C9F6BBULL,
		0xE73CCCE4EEA51883ULL,
		0xF63B1BDEC292AF30ULL,
		0xE1D825C7384BBE46ULL,
		0x3E0CCE31A346271CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E8DA77D23EA485CULL,
		0x765EF27093CE5D4DULL,
		0x8E4DF6FBB429CE90ULL,
		0x6255822AB9EA569BULL,
		0x3594D91C196D64D7ULL,
		0x141AABC8A9D88AB6ULL,
		0x7AC2FA4EFC788802ULL,
		0xC6C1FD95B099D453ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ACF588A432CC548ULL,
		0x06E992C17639B11EULL,
		0xAAE981758F2D4384ULL,
		0x487F2AE99BDFA01FULL,
		0xB1A7F3C8D537B3ACULL,
		0xE220701618BA247AULL,
		0x67152B783BD33644ULL,
		0x774AD09BF2AC52C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3EA8AC23BFE2C030ULL,
		0xA19C07CC0877FF61ULL,
		0x6F4E96BEF9938ED6ULL,
		0x6CDC1CE1ABC92545ULL,
		0x8BBBE86C9198FEE4ULL,
		0x07B818A220B7D95DULL,
		0x2549E057C32A59A5ULL,
		0xE2988F5B4E5F6D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84304105D6F940C3ULL,
		0xE8D4C40FB968D803ULL,
		0xE2B8A1668AA58575ULL,
		0xAD9DBAF866D4F974ULL,
		0xD54C104AC31E43C2ULL,
		0x75F3A2C3EF1A0B8DULL,
		0xA2543BF8F8D36B25ULL,
		0xAC7ED2C4AA195E62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA786B1DE8E97F6DULL,
		0xB8C743BC4F0F275DULL,
		0x8C95F5586EEE0960ULL,
		0xBF3E61E944F42BD0ULL,
		0xB66FD821CE7ABB21ULL,
		0x91C475DE319DCDCFULL,
		0x82F5A45ECA56EE7FULL,
		0x3619BC96A4460EB6ULL
	}};
	sign = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB08494CC1387874ULL,
		0x3FE6EC66144C7995ULL,
		0x79F53E1F7FF8E755ULL,
		0xF602D97D2323AC87ULL,
		0x43D142F597A69A4DULL,
		0xA801C76ABB2F9D4DULL,
		0x48DD9D16302B9684ULL,
		0x150C8B6700597BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B55268B05FF62DULL,
		0x866BA7CA765C3F52ULL,
		0x7EE674079660FADAULL,
		0x5DBAE81673F90C59ULL,
		0x9B014A3E8D509F9CULL,
		0x803F74003E274A44ULL,
		0x761E94920CA28C38ULL,
		0x7657B71D39824EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6152F6E410D88247ULL,
		0xB97B449B9DF03A43ULL,
		0xFB0ECA17E997EC7AULL,
		0x9847F166AF2AA02DULL,
		0xA8CFF8B70A55FAB1ULL,
		0x27C2536A7D085308ULL,
		0xD2BF088423890A4CULL,
		0x9EB4D449C6D72D09ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AEFFA394E1F82F0ULL,
		0xC162442D99355291ULL,
		0xD98E60F65918CBF8ULL,
		0xF5E087F377FDC21FULL,
		0x0EF263E7E41AD118ULL,
		0x8AEC1EE614A2ED11ULL,
		0x5E404AB1EC4AB097ULL,
		0x3D312BCA0CE08122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBACF84CD3E4661EULL,
		0xE4EF08E807C7836EULL,
		0x0ECC60F53459C469ULL,
		0xF4AD66F0F67F7A1AULL,
		0x5549DC940ACAB740ULL,
		0x648DCC5AD68862FBULL,
		0x80013A02EAF37E0EULL,
		0xFE93123ABE40C9B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F4301EC7A3B1CD2ULL,
		0xDC733B45916DCF22ULL,
		0xCAC2000124BF078EULL,
		0x01332102817E4805ULL,
		0xB9A88753D95019D8ULL,
		0x265E528B3E1A8A15ULL,
		0xDE3F10AF01573289ULL,
		0x3E9E198F4E9FB76AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31DC17A66D45F8B1ULL,
		0x6FBAF7A4B2D5DEFAULL,
		0x1F369D420890126CULL,
		0xB22AFF2C1F604850ULL,
		0x385FDD03617237ADULL,
		0x362D35655AC7BE5AULL,
		0xEFA67E40515774E6ULL,
		0x2A8A116977F6B887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA850259198AFDFAAULL,
		0x9E9781A99A066A91ULL,
		0x9FA4040E10603190ULL,
		0x67AAA8FD84F65486ULL,
		0x6C086067EFACEAFBULL,
		0xB3D51856784CEE6CULL,
		0xC502A38A31AEDD64ULL,
		0xF660F278D310456BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x898BF214D4961907ULL,
		0xD12375FB18CF7468ULL,
		0x7F929933F82FE0DBULL,
		0x4A80562E9A69F3C9ULL,
		0xCC577C9B71C54CB2ULL,
		0x82581D0EE27ACFEDULL,
		0x2AA3DAB61FA89781ULL,
		0x34291EF0A4E6731CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29F623DEFC0754A2ULL,
		0x104F4D8A93B87A7DULL,
		0xF5516A752802A041ULL,
		0xA9D45F30ECD74CC5ULL,
		0xE577144035469A11ULL,
		0xC0A5825C742844B9ULL,
		0xC7EA86F74ADBBAC6ULL,
		0xC2D46991B13AF680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95462697B498FF6DULL,
		0xD3877E718D0520E2ULL,
		0x0875CED5A12E292CULL,
		0xC1E5636FCB8FA419ULL,
		0xD7DB8490C321E341ULL,
		0x3C6DE593EE40BB73ULL,
		0x9331135961EB55F5ULL,
		0x5CCF03CBA037EB9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94AFFD47476E5535ULL,
		0x3CC7CF1906B3599AULL,
		0xECDB9B9F86D47714ULL,
		0xE7EEFBC12147A8ACULL,
		0x0D9B8FAF7224B6CFULL,
		0x84379CC885E78946ULL,
		0x34B9739DE8F064D1ULL,
		0x660565C611030AE3ULL
	}};
	sign = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21E890BF0B1FAFF0ULL,
		0xD243934BD55458AAULL,
		0x886EADBE802965B7ULL,
		0x66EFB7D6C9CA6B4AULL,
		0xCA908711CA98F8A5ULL,
		0x883F21F4DFA9E238ULL,
		0xF053299A6C8A8300ULL,
		0x5656CAA7AECEBEB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5886FD23CBB22729ULL,
		0x48DB5CA2D3986EEAULL,
		0x9316287A737C477AULL,
		0x7DBAA128024D75A9ULL,
		0x787EFBBDB90D8C43ULL,
		0x0BAAFD4022DF8C01ULL,
		0xACFC1A75EB3AEB7AULL,
		0xB0C29405F43E2F24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC961939B3F6D88C7ULL,
		0x896836A901BBE9BFULL,
		0xF55885440CAD1E3DULL,
		0xE93516AEC77CF5A0ULL,
		0x52118B54118B6C61ULL,
		0x7C9424B4BCCA5637ULL,
		0x43570F24814F9786ULL,
		0xA59436A1BA908F92ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC579FB29166A2BDULL,
		0x6C04271D43B9824CULL,
		0xA6C229D2EAACCB61ULL,
		0xC1EABDB1A81536D6ULL,
		0x1216725E67953BC7ULL,
		0x9B9C3B5133666428ULL,
		0x750EA68BC4BCF272ULL,
		0x5BA6706F43567B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC19BB6E63C82EB7ULL,
		0x841BCBB24D14D732ULL,
		0xA96B38957567A748ULL,
		0xEBAA607954C19EF1ULL,
		0x4F6CA894B71C9286ULL,
		0x420E3D18CA84AD38ULL,
		0xAA68390CC1F167C7ULL,
		0x7A623E0EEC2C333DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x503DE4442D9E7406ULL,
		0xE7E85B6AF6A4AB1AULL,
		0xFD56F13D75452418ULL,
		0xD6405D38535397E4ULL,
		0xC2A9C9C9B078A940ULL,
		0x598DFE3868E1B6EFULL,
		0xCAA66D7F02CB8AABULL,
		0xE1443260572A47C7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0DAB2F4F262E1EULL,
		0xB9626EC2E8A9CC15ULL,
		0x380629992449FB09ULL,
		0x422F18A88D26D49BULL,
		0xD6E23B1B91C8F2E7ULL,
		0x7B5D3799A8FBF24FULL,
		0xF08B47ED0D6774FDULL,
		0xDDE76A6F45F67F21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5EDFFE31A0F7FC0ULL,
		0xFF20DA41E17D3DB4ULL,
		0x707EFDCE77797BE9ULL,
		0x4BB7BA9EB37C9200ULL,
		0x29782CBB1CF3A6F7ULL,
		0x9F6A706BE52EF1B9ULL,
		0xC3B34A8A9B055931ULL,
		0xD275831EF0A48D5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD61FAB4C3516AE5EULL,
		0xBA419481072C8E60ULL,
		0xC7872BCAACD07F1FULL,
		0xF6775E09D9AA429AULL,
		0xAD6A0E6074D54BEFULL,
		0xDBF2C72DC3CD0096ULL,
		0x2CD7FD6272621BCBULL,
		0x0B71E7505551F1C3ULL
	}};
	sign = 0;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD779EFCF2296DD9ULL,
		0x23134AC322B2D702ULL,
		0xE13395BCD66F4190ULL,
		0x8AADA35DBDEB2C95ULL,
		0xF24DBCB277C83402ULL,
		0xA08D45A0582F5602ULL,
		0x84C4DA3E77660C4DULL,
		0xAF0309B281BA073CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4FA4E0BBE7B6EA3ULL,
		0xC368C52FEAE30CC8ULL,
		0x0153EADDEBA762BDULL,
		0x8C0709DF58778FC9ULL,
		0x440E0F49074095DFULL,
		0x36108B178029D891ULL,
		0xF2328ED7CAC19D11ULL,
		0x029626F9FCD2BD2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD87D50F133ADFF36ULL,
		0x5FAA859337CFCA39ULL,
		0xDFDFAADEEAC7DED2ULL,
		0xFEA6997E65739CCCULL,
		0xAE3FAD6970879E22ULL,
		0x6A7CBA88D8057D71ULL,
		0x92924B66ACA46F3CULL,
		0xAC6CE2B884E74A11ULL
	}};
	sign = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE08C506C0D9BD3FCULL,
		0x0D069839FE55AAD0ULL,
		0x4B0AB13DDDEF76BFULL,
		0x8A46955946411A10ULL,
		0x019676A3211C280CULL,
		0x7E37455AA14FB0C2ULL,
		0x06F8DE8DFF0FC1F0ULL,
		0xF157EA24401A1E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDD786E4203F20F9ULL,
		0x762939AEF1DFF466ULL,
		0x12436F8174E40408ULL,
		0x17DAAF8FD6F003C5ULL,
		0x7B0A2E1C2BC03ED0ULL,
		0xE8A25F46B4D463A9ULL,
		0x54D7C38C007D6A66ULL,
		0x0F90B120D1814632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12B4C987ED5CB303ULL,
		0x96DD5E8B0C75B66AULL,
		0x38C741BC690B72B6ULL,
		0x726BE5C96F51164BULL,
		0x868C4886F55BE93CULL,
		0x9594E613EC7B4D18ULL,
		0xB2211B01FE925789ULL,
		0xE1C739036E98D832ULL
	}};
	sign = 0;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69DCFAB8F5019669ULL,
		0x5472BC3B810AE78CULL,
		0xCBCE5C47143F7C4AULL,
		0xD7472AF1C181FB99ULL,
		0xB5BE4E12183EA5C2ULL,
		0x2FEB9F9947EDFEB0ULL,
		0xECC37928A3DF3C0FULL,
		0x9365F44E5D970A40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87EFE8D5AF3B8716ULL,
		0x44884F1E104A68DFULL,
		0x47DF78D23D0457DEULL,
		0x44A5A56ABC1D12B8ULL,
		0x29C0899C2AC14A89ULL,
		0xA704FC3884FB352BULL,
		0x2E69FCA55DBCE80AULL,
		0xB141E8E612E7FDD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1ED11E345C60F53ULL,
		0x0FEA6D1D70C07EACULL,
		0x83EEE374D73B246CULL,
		0x92A185870564E8E1ULL,
		0x8BFDC475ED7D5B39ULL,
		0x88E6A360C2F2C985ULL,
		0xBE597C8346225404ULL,
		0xE2240B684AAF0C6AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE717373CDDC1CFCULL,
		0x205F8A523D6B09A7ULL,
		0x768059C94DB53201ULL,
		0xE0267D2A8224BE75ULL,
		0x1FF6A5191DD4D05FULL,
		0xB5369DB0964C5B4FULL,
		0x9E4712E8FE2C91EFULL,
		0x08AC13C217D14CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF84FF23E4816160BULL,
		0xED4FB81CD0E67D30ULL,
		0x7F44642CD28A8437ULL,
		0xCDE4DEA3F007763EULL,
		0x433B7667C6B4487DULL,
		0x839CB5F4A8E4D265ULL,
		0x787D3926FE0EA6EAULL,
		0x1EB2C3DFB21A06B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD621813585C606F1ULL,
		0x330FD2356C848C76ULL,
		0xF73BF59C7B2AADC9ULL,
		0x12419E86921D4836ULL,
		0xDCBB2EB1572087E2ULL,
		0x3199E7BBED6788E9ULL,
		0x25C9D9C2001DEB05ULL,
		0xE9F94FE265B74607ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2B11C5DFC630742ULL,
		0x416F79CED2D47BB8ULL,
		0x868F184BBEDA0551ULL,
		0x0D2E70EA943DC223ULL,
		0x88DB17C0DBE771E7ULL,
		0x8421DBAB8383E34CULL,
		0x34FB56C3EF16DB3FULL,
		0x84714DC1526A92BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71483B50CE59883ULL,
		0xD605ADDA6797BC1CULL,
		0xB2D8B9DF402FC2C7ULL,
		0xAB94813A3907DF45ULL,
		0x324F7C644ED52189ULL,
		0x3414204FA8F9245FULL,
		0x9B015C07690D57F7ULL,
		0xEF4FCE1D61810F35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B9C98A8EF7D6EBFULL,
		0x6B69CBF46B3CBF9CULL,
		0xD3B65E6C7EAA4289ULL,
		0x6199EFB05B35E2DDULL,
		0x568B9B5C8D12505DULL,
		0x500DBB5BDA8ABEEDULL,
		0x99F9FABC86098348ULL,
		0x95217FA3F0E98388ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD0967C685463768ULL,
		0xA6E1F4E554AF8AC6ULL,
		0x0F3E25A20D2966CFULL,
		0x3264E7903C2E3BC7ULL,
		0x862AF1A7E4997439ULL,
		0x7C44DEC11CB7D658ULL,
		0xB633EF3A1CC15EE5ULL,
		0xEDE7BFC0D5DBD0CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5B1A6C22893BBB7ULL,
		0xAB800F22CF9337E0ULL,
		0x17ACCCA2E1EFCA65ULL,
		0x6DB62113F1EC78BEULL,
		0xE3490CE1B02D8A5EULL,
		0x89F349B9BC5842D9ULL,
		0x73DE7B258245AEE7ULL,
		0xD5B63AFFD29C5714ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1757C1045CB27BB1ULL,
		0xFB61E5C2851C52E6ULL,
		0xF79158FF2B399C69ULL,
		0xC4AEC67C4A41C308ULL,
		0xA2E1E4C6346BE9DAULL,
		0xF2519507605F937EULL,
		0x425574149A7BAFFDULL,
		0x183184C1033F79B9ULL
	}};
	sign = 0;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0576BB954E64898ULL,
		0x978D03F03DF0753CULL,
		0xA0161EE105F8A02FULL,
		0xEF7C7180345FE2B6ULL,
		0x95917D93B3F6DA0AULL,
		0xC88701040AEE8A91ULL,
		0x1A25098134AC8F9CULL,
		0xFF00CFF9D0E2A99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB156AFDC70A3B208ULL,
		0x74ABE8E91113DF39ULL,
		0x30E0811E14487541ULL,
		0x30D455A4C246AD7AULL,
		0x6E77FEE21A31D3D4ULL,
		0x1568B615A98BF622ULL,
		0xDCCC32D062296844ULL,
		0x296091474DCC832FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF00BBDCE4429690ULL,
		0x22E11B072CDC9602ULL,
		0x6F359DC2F1B02AEEULL,
		0xBEA81BDB7219353CULL,
		0x27197EB199C50636ULL,
		0xB31E4AEE6162946FULL,
		0x3D58D6B0D2832758ULL,
		0xD5A03EB28316266BULL
	}};
	sign = 0;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2026CDEC5607E383ULL,
		0x0CA6313E5C06FCC1ULL,
		0xC03F20BA3BDC9E86ULL,
		0xEA2632BBF462303CULL,
		0xC932BAC16AB0B7F4ULL,
		0x472F20D14771DFE3ULL,
		0x44754E69AC8B11D9ULL,
		0xC334A1F2F13770AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97C76BF65D1EF716ULL,
		0xAB57E723A9D83EBDULL,
		0x5F77FD007143480DULL,
		0xB72BEBD76DE1B4DFULL,
		0x0EC2CD11067B2EADULL,
		0x2D6C8E25CF94C9FDULL,
		0x05E2BB2461DC6A6CULL,
		0xE6A1B04BA4013F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x885F61F5F8E8EC6DULL,
		0x614E4A1AB22EBE03ULL,
		0x60C723B9CA995678ULL,
		0x32FA46E486807B5DULL,
		0xBA6FEDB064358947ULL,
		0x19C292AB77DD15E6ULL,
		0x3E9293454AAEA76DULL,
		0xDC92F1A74D3631AEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8258B0C385EDDF70ULL,
		0x433733DB241D7BC5ULL,
		0xDBB596051B1FDC54ULL,
		0xDFE8C3A7FF945E0DULL,
		0x494A20237AE8397DULL,
		0xEF66A3D12FE68A0BULL,
		0x0800C16765A22F60ULL,
		0x8F3F52120E7430F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31334EA7169E6E40ULL,
		0xA34C9DAD42AF2DE5ULL,
		0x543BD1BE4AFCBC96ULL,
		0x26BBE5C8027C4BD7ULL,
		0xF0FFF5083A344C29ULL,
		0x43F705FE75E41712ULL,
		0x58C90D856481DDA1ULL,
		0xC36463D840D1D530ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5125621C6F4F7130ULL,
		0x9FEA962DE16E4DE0ULL,
		0x8779C446D0231FBDULL,
		0xB92CDDDFFD181236ULL,
		0x584A2B1B40B3ED54ULL,
		0xAB6F9DD2BA0272F8ULL,
		0xAF37B3E2012051BFULL,
		0xCBDAEE39CDA25BC2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11BEF1FE4F667BB4ULL,
		0x3F9998019462BBB0ULL,
		0x1D6F460353F4269CULL,
		0x0FF010412DEC2EB5ULL,
		0x84C7D3EE0C200F9CULL,
		0x832B53AA5587131DULL,
		0x982E0E14C7C690C3ULL,
		0x822F4536BD8B9F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8B7015676193D4ULL,
		0x07B58394A180B7FBULL,
		0xB003FC95BBC03AF5ULL,
		0xB78D3F5243DAEDD2ULL,
		0x8249A8BB12BE40A7ULL,
		0x473BF35D375F896BULL,
		0xD89449DB4B886242ULL,
		0x3444AFD063CB7D50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x123381E8E804E7E0ULL,
		0x37E4146CF2E203B4ULL,
		0x6D6B496D9833EBA7ULL,
		0x5862D0EEEA1140E2ULL,
		0x027E2B32F961CEF4ULL,
		0x3BEF604D1E2789B2ULL,
		0xBF99C4397C3E2E81ULL,
		0x4DEA956659C02233ULL
	}};
	sign = 0;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67C241D7F1B7EE24ULL,
		0x928A0F60B2299BAAULL,
		0x4818B7FB9057424BULL,
		0xEE7BD5F97BFBC6F8ULL,
		0x4AE6C99FF92D3A48ULL,
		0xD339180E93158C00ULL,
		0xE33DABC9506D3C39ULL,
		0xBEA0E6F5DCE9DEDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF060BE519EEF93EAULL,
		0xDE8A77C5292A4E93ULL,
		0x378D30073E4175A3ULL,
		0x0F986A6665BA44F8ULL,
		0xE0D958C3C82D8EEAULL,
		0x72A37D1B3675676FULL,
		0x94EC8BC192F9008FULL,
		0x7F128F7E81416C53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7761838652C85A3AULL,
		0xB3FF979B88FF4D16ULL,
		0x108B87F45215CCA7ULL,
		0xDEE36B9316418200ULL,
		0x6A0D70DC30FFAB5EULL,
		0x60959AF35CA02490ULL,
		0x4E512007BD743BAAULL,
		0x3F8E57775BA87288ULL
	}};
	sign = 0;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8859008506CDACDULL,
		0x31AC7435154EEF13ULL,
		0x5D937C5961384F42ULL,
		0x2C4DB1B27702B4CAULL,
		0xC6C1B6FCF8FE84E2ULL,
		0x606194C191F0313AULL,
		0x4AE8106CE47F4316ULL,
		0xFAF20CEBDEF5D705ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1EE19E194AF6F52ULL,
		0x546FAF319742C351ULL,
		0xD5145AA7579F5528ULL,
		0x4DA98C678D16CD75ULL,
		0x92E04104B4C77D99ULL,
		0xDB8B49A97EDC3C87ULL,
		0x6CA25EC7315F3C2BULL,
		0xE77CB395B45D06E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06977626BBBD6B7BULL,
		0xDD3CC5037E0C2BC2ULL,
		0x887F21B20998FA19ULL,
		0xDEA4254AE9EBE754ULL,
		0x33E175F844370748ULL,
		0x84D64B181313F4B3ULL,
		0xDE45B1A5B32006EAULL,
		0x137559562A98D021ULL
	}};
	sign = 0;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE1977BF3E86B06BULL,
		0x8C9E46B910538247ULL,
		0x4C423994504F7873ULL,
		0x6FB0F3E2426A40C8ULL,
		0xF0E4F559D98C66C2ULL,
		0xF874BDCAA6525082ULL,
		0x71059B0FEB119A1FULL,
		0xD49C91269DADCE96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D092073FE497A2AULL,
		0x8D3DE649F256596AULL,
		0x616C2AF1149CCF71ULL,
		0x96A7E16591146EB9ULL,
		0xAF3D0200B4446D18ULL,
		0xF8EB74A8715B5D54ULL,
		0x3C8962F1CD827DCAULL,
		0x1B94690E7DC9EFECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8110574B403D3641ULL,
		0xFF60606F1DFD28DDULL,
		0xEAD60EA33BB2A901ULL,
		0xD909127CB155D20EULL,
		0x41A7F3592547F9A9ULL,
		0xFF89492234F6F32EULL,
		0x347C381E1D8F1C54ULL,
		0xB90828181FE3DEAAULL
	}};
	sign = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5004A2D9F49A0CFFULL,
		0x74A47FA9F0B031DFULL,
		0xFCFA11A4C854F8AFULL,
		0x3BD514893379DC38ULL,
		0x47F50DFA69F9A765ULL,
		0x68963A13853D359EULL,
		0x625C511D0E297AB7ULL,
		0x40C1F2B540A90302ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62C2DF343092D3EDULL,
		0x7868B365593CE10CULL,
		0xEA78A35A1A2CAB08ULL,
		0x802DF49E0411A942ULL,
		0x14B9C099745594DEULL,
		0x0F97D23F1C22A0BEULL,
		0x46005D049AC25056ULL,
		0xEC35AE39ED1EEE82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED41C3A5C4073912ULL,
		0xFC3BCC44977350D2ULL,
		0x12816E4AAE284DA6ULL,
		0xBBA71FEB2F6832F6ULL,
		0x333B4D60F5A41286ULL,
		0x58FE67D4691A94E0ULL,
		0x1C5BF41873672A61ULL,
		0x548C447B538A1480ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76759C0703DEBCCEULL,
		0x18D3BC00466C93E4ULL,
		0xEE17E78EFA8E4E2CULL,
		0xDA658091E31126B7ULL,
		0x5EBD902EAF4F7B4CULL,
		0xCB2D114ADEDB7C31ULL,
		0x9638B16234E7DD7CULL,
		0xE92989414691D3F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA34AE8832B50A71ULL,
		0x5256ECE0988404F2ULL,
		0x68DD9C71F508EA8BULL,
		0x605C07F2EA142269ULL,
		0x074862C09A72B582ULL,
		0x09B3448FFB465D3BULL,
		0xFA1C1FEBDFA193DDULL,
		0x7F8E0431FE5C3285ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC40ED7ED129B25DULL,
		0xC67CCF1FADE88EF1ULL,
		0x853A4B1D058563A0ULL,
		0x7A09789EF8FD044EULL,
		0x57752D6E14DCC5CAULL,
		0xC179CCBAE3951EF6ULL,
		0x9C1C91765546499FULL,
		0x699B850F4835A16BULL
	}};
	sign = 0;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x810BC10270E9E0E4ULL,
		0x62ED9C74A54B72B7ULL,
		0xE60DE815BAE3F6DEULL,
		0xDBF5C0E62080C334ULL,
		0x43D734E25ABAF2B4ULL,
		0xEC49C0DB35FDBEFAULL,
		0x2F1FFB224A848C7CULL,
		0x4BCC0CA351CB46C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE41F23EB211B3F2ULL,
		0x83252E4E32A69DF8ULL,
		0x0368FA6CEF9BBADDULL,
		0xD568559A90A7DAB5ULL,
		0xA781D7F82388EAD5ULL,
		0x48F798A13F43D285ULL,
		0x25BA5FE2EEBBC85FULL,
		0x993A6E6302867030ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82C9CEC3BED82CF2ULL,
		0xDFC86E2672A4D4BEULL,
		0xE2A4EDA8CB483C00ULL,
		0x068D6B4B8FD8E87FULL,
		0x9C555CEA373207DFULL,
		0xA3522839F6B9EC74ULL,
		0x09659B3F5BC8C41DULL,
		0xB2919E404F44D693ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x753B115B7F937430ULL,
		0xC8BFF678AC09F94BULL,
		0xD3E688E53619FB3AULL,
		0xD57CAEBA40A9BE8FULL,
		0x2A1BA2B03AF41B9FULL,
		0xCE26D81AF0532FA4ULL,
		0x1C8751DC717A300BULL,
		0xACB63144E1F8FD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA656F24C01D9754BULL,
		0x04486480F25D0B4EULL,
		0x25FBF6791B3747A8ULL,
		0x0DEE52BFDBE68FBFULL,
		0xFCD589312B46CDDEULL,
		0x5986C3B1097ECDD3ULL,
		0x1581AA1E1D996408ULL,
		0x54F03E3E8EEEE231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCEE41F0F7DB9FEE5ULL,
		0xC47791F7B9ACEDFCULL,
		0xADEA926C1AE2B392ULL,
		0xC78E5BFA64C32ED0ULL,
		0x2D46197F0FAD4DC1ULL,
		0x74A01469E6D461D0ULL,
		0x0705A7BE53E0CC03ULL,
		0x57C5F306530A1B31ULL
	}};
	sign = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA483B5CDB2BAB318ULL,
		0xFA3288573F19FA04ULL,
		0x25CC9D07C131B6BDULL,
		0xC7F986A0972395E0ULL,
		0x6D412C8D4DE7ACD5ULL,
		0xD2AAE03A0564F86BULL,
		0x914D780A964F63D9ULL,
		0x974F77836A70924FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1FAE907284095CCULL,
		0xB56644243F3A08D4ULL,
		0x1BD10DCD475E5E66ULL,
		0x82C3C312D0B5626FULL,
		0x68B76F83FA722CD5ULL,
		0xECC14676B2292651ULL,
		0x9BE7D8AA2BC447E0ULL,
		0x370C0390EC069D38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD288CCC68A7A1D4CULL,
		0x44CC4432FFDFF12FULL,
		0x09FB8F3A79D35857ULL,
		0x4535C38DC66E3371ULL,
		0x0489BD0953758000ULL,
		0xE5E999C3533BD21AULL,
		0xF5659F606A8B1BF8ULL,
		0x604373F27E69F516ULL
	}};
	sign = 0;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4439D7BF89C85CBCULL,
		0x08FEE0E836984546ULL,
		0x562C6A6B5B46F516ULL,
		0x5E846F4DF918BAD8ULL,
		0xD9D941B9F5C9AF61ULL,
		0x95EDADF24E3B2E6BULL,
		0x9B3EEF5BF588D665ULL,
		0x099CE60CD7AD8CF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D53E07A375A175FULL,
		0x89EFB5CF71AF2AF1ULL,
		0x4E8A2F0329C68D6EULL,
		0xB3F9D77231AA1A91ULL,
		0xEA5AD1977D8F7F10ULL,
		0x0FDD818D434C4AF9ULL,
		0x9BB027F274C941E0ULL,
		0x089AFE3B11A79029ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36E5F745526E455DULL,
		0x7F0F2B18C4E91A55ULL,
		0x07A23B68318067A7ULL,
		0xAA8A97DBC76EA047ULL,
		0xEF7E7022783A3050ULL,
		0x86102C650AEEE371ULL,
		0xFF8EC76980BF9485ULL,
		0x0101E7D1C605FCCFULL
	}};
	sign = 0;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x921C000F245081B7ULL,
		0xCB7713CCB5FC95B1ULL,
		0xCEAAFF56CD259A91ULL,
		0x05613854E9B3B70BULL,
		0xBE3B2725A648DC6DULL,
		0xB220BFD16E2E4154ULL,
		0xC7EAB8DEFA718606ULL,
		0x92DE8D4C4099DDB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC3FC4A57CA1DDBFULL,
		0x5DB6C810AB43DB5BULL,
		0x7FD577743C068AC8ULL,
		0x36D17A530DA1AE5CULL,
		0x91143BB4C972E8A6ULL,
		0x2A4A2751920CC307ULL,
		0x1542037BB8A3CEE9ULL,
		0x71329F38AFAEECC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5DC3B69A7AEA3F8ULL,
		0x6DC04BBC0AB8BA55ULL,
		0x4ED587E2911F0FC9ULL,
		0xCE8FBE01DC1208AFULL,
		0x2D26EB70DCD5F3C6ULL,
		0x87D6987FDC217E4DULL,
		0xB2A8B56341CDB71DULL,
		0x21ABEE1390EAF0F9ULL
	}};
	sign = 0;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60A3BAC7A2791397ULL,
		0xA749746874A28030ULL,
		0x4E8372F0CC3F70D3ULL,
		0x1C8DA65E6158DA39ULL,
		0x87A4DCCB29A8EE1CULL,
		0x63933A6F36915051ULL,
		0x122E819CC18794C2ULL,
		0x75B77DD46F583DCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BA88E485596D3BULL,
		0x25C4075A577333ACULL,
		0x65B9DEA4B482E69BULL,
		0xB66D75B4DBDBB06DULL,
		0xD63055C2D3C5729FULL,
		0x93347EDF89569B22ULL,
		0x75F5853A8C3430AAULL,
		0x9C22F8157C901986ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDFE931E31D1FA65CULL,
		0x81856D0E1D2F4C83ULL,
		0xE8C9944C17BC8A38ULL,
		0x662030A9857D29CBULL,
		0xB174870855E37B7CULL,
		0xD05EBB8FAD3AB52EULL,
		0x9C38FC6235536417ULL,
		0xD99485BEF2C82447ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBC0FA34B3F82BBBULL,
		0xF12D35E31B2808ECULL,
		0x3E00AA83EE45BE8AULL,
		0x4DF1A4AAFF1F39C6ULL,
		0x54CBDC46FEF81B13ULL,
		0x52E0181219EDDB44ULL,
		0xE24FDEBDD8DD83E3ULL,
		0x24556484246397B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174A00A9CE181384ULL,
		0x4C29D83446744A8CULL,
		0x6ECD55952FEB40ECULL,
		0x8B9EF588897F1DBAULL,
		0x141F4FC7FA182177ULL,
		0x032125AAE959D742ULL,
		0x311E887F0C2A105DULL,
		0x18A24071AFC355D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD476F98AE5E01837ULL,
		0xA5035DAED4B3BE60ULL,
		0xCF3354EEBE5A7D9EULL,
		0xC252AF2275A01C0BULL,
		0x40AC8C7F04DFF99BULL,
		0x4FBEF26730940402ULL,
		0xB131563ECCB37386ULL,
		0x0BB3241274A041E1ULL
	}};
	sign = 0;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x20CA220618108A7FULL,
		0x118B047AB74AC157ULL,
		0x3CB5529EB0F8C5E5ULL,
		0x2A875E9B3D50B433ULL,
		0xB46049461DFCEE1FULL,
		0x4647F379E663F93FULL,
		0x67F2FA47F98E8C2BULL,
		0xC308F91AE4A40D3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E4C1655E9C1A66BULL,
		0x76CA4B72445AFF24ULL,
		0xA8ABC905609E1AB4ULL,
		0xBB9659823E699E05ULL,
		0xF2311D378B0AB006ULL,
		0x622A61C69D7602A3ULL,
		0x11BC30A01E3E1F6BULL,
		0x4A71E2EA3689D78AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE27E0BB02E4EE414ULL,
		0x9AC0B90872EFC232ULL,
		0x94098999505AAB30ULL,
		0x6EF10518FEE7162DULL,
		0xC22F2C0E92F23E18ULL,
		0xE41D91B348EDF69BULL,
		0x5636C9A7DB506CBFULL,
		0x78971630AE1A35B1ULL
	}};
	sign = 0;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E0FC6422A94439ULL,
		0xC85304CAD56CCD11ULL,
		0x81CD7AE53DA663C2ULL,
		0xB165920DE79C2A94ULL,
		0xD5E4F2F27BCB19FAULL,
		0x2A412B46095162B1ULL,
		0x6781328FE8396DE4ULL,
		0xDF859319A70449E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930E725097FBF73BULL,
		0x9B5F5F59B0B6C7CEULL,
		0xC072BD53D6A30A85ULL,
		0xEE8E4980A96F3E59ULL,
		0xC331D415C56B2926ULL,
		0xA696771EB83B5F12ULL,
		0xCE75634ADE17713FULL,
		0xC62226F24981649EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2D28A138AAD4CFEULL,
		0x2CF3A57124B60542ULL,
		0xC15ABD916703593DULL,
		0xC2D7488D3E2CEC3AULL,
		0x12B31EDCB65FF0D3ULL,
		0x83AAB4275116039FULL,
		0x990BCF450A21FCA4ULL,
		0x19636C275D82E543ULL
	}};
	sign = 0;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09A94D5C78BA2D21ULL,
		0x24BB9BB7F28CEF4CULL,
		0x1423594886D78FACULL,
		0x42C9D71422206B35ULL,
		0xE0DAE2275781F166ULL,
		0x1B4E72A5C62615BBULL,
		0xE72EEB5A9D2D697CULL,
		0xC670508A91CC7B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4133DB60817F200DULL,
		0x04ED6D6596873956ULL,
		0x4F03EAF56863385EULL,
		0x45559DABFFE19608ULL,
		0x1FDC110631F2935AULL,
		0x0D25E8AAC3EDC7B1ULL,
		0x5D8776EE4DF47F41ULL,
		0xC741E0C860217E1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC87571FBF73B0D14ULL,
		0x1FCE2E525C05B5F5ULL,
		0xC51F6E531E74574EULL,
		0xFD743968223ED52CULL,
		0xC0FED121258F5E0BULL,
		0x0E2889FB02384E0AULL,
		0x89A7746C4F38EA3BULL,
		0xFF2E6FC231AAFD69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB4E17E836F184F1ULL,
		0x0D55545DA82B9371ULL,
		0xABC88479F0C5EE64ULL,
		0xFCFAEFDA837517FCULL,
		0x9147C7E83FDCC6CEULL,
		0x288C428B2BC696BFULL,
		0x8C0163FC55D225D2ULL,
		0xEF41B6478DC0C8B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E47B7A335B40E2FULL,
		0x01923E05B591AB8FULL,
		0x13128DCE327E188AULL,
		0xDD7F03B20D895170ULL,
		0x2537532331AA5439ULL,
		0xB49401CD44B4CF3AULL,
		0x4EFF4F8478DDE7FBULL,
		0xF9AD68E051E61716ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D066045013D76C2ULL,
		0x0BC31657F299E7E2ULL,
		0x98B5F6ABBE47D5DAULL,
		0x1F7BEC2875EBC68CULL,
		0x6C1074C50E327295ULL,
		0x73F840BDE711C785ULL,
		0x3D021477DCF43DD6ULL,
		0xF5944D673BDAB19AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63811C5E9904F392ULL,
		0x2C388F44161F53BBULL,
		0x7D15B1BEB90705DAULL,
		0xBD013834E32B7153ULL,
		0x1E5BA198DD7C74DCULL,
		0x6CAAB27BBAA43FC2ULL,
		0x6872C8A4C7A2B63BULL,
		0x4A8A51B9EC785541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE10FBFB3C60BD8EULL,
		0xBC7B99F167CF598AULL,
		0x22F9B6A79D8D4DD3ULL,
		0xD5E76755D6FC3712ULL,
		0x14E9B798B558D598ULL,
		0xB146A25F7B82B50AULL,
		0xA07D516AD931DB07ULL,
		0xBD1F5EA7D73AE81BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x957020635CA43604ULL,
		0x6FBCF552AE4FFA30ULL,
		0x5A1BFB171B79B806ULL,
		0xE719D0DF0C2F3A41ULL,
		0x0971EA0028239F43ULL,
		0xBB64101C3F218AB8ULL,
		0xC7F57739EE70DB33ULL,
		0x8D6AF312153D6D25ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCB53BEAA0F57D9CULL,
		0x1755A1B2E2C1F5F6ULL,
		0x6911194F988F64E2ULL,
		0xCA435F5C13EE4A46ULL,
		0x253367669A7828DEULL,
		0x130AFD798EC148BBULL,
		0x1C1E24FB95FA9072ULL,
		0xF48C930C151E6EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A94A1A0937FA30ULL,
		0x709F6C8ABBE99A48ULL,
		0x740EA6CE81E7B58EULL,
		0x910078918D156200ULL,
		0xA5F4939FD188D6D0ULL,
		0xAA9C77CD967431B6ULL,
		0x44B23D25D6CE98C7ULL,
		0x9D178D98721EAB3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A0BF1D097BD836CULL,
		0xA6B6352826D85BAEULL,
		0xF502728116A7AF53ULL,
		0x3942E6CA86D8E845ULL,
		0x7F3ED3C6C8EF520EULL,
		0x686E85ABF84D1704ULL,
		0xD76BE7D5BF2BF7AAULL,
		0x57750573A2FFC378ULL
	}};
	sign = 0;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6932D68E6941857ULL,
		0x352BA012877E2CB4ULL,
		0xB50C56C13DC6D4A4ULL,
		0x4EE14BB8091C3115ULL,
		0x2428E7B79E0FDE92ULL,
		0x4CA8D5879BD27B63ULL,
		0xE32B933EDDC83E1DULL,
		0xC6725C77D45A707CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05F18A08504F9E7ULL,
		0x72FA1DCC81D0DFD6ULL,
		0x36F335CA0BF62663ULL,
		0x7ACC76EF966B7F73ULL,
		0x2F39AA1582E45779ULL,
		0x5A80C001BC9319FBULL,
		0x1FD2DE5A51D76F7AULL,
		0x6FB9CCBF2883D0DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF63414C8618F1E70ULL,
		0xC231824605AD4CDDULL,
		0x7E1920F731D0AE40ULL,
		0xD414D4C872B0B1A2ULL,
		0xF4EF3DA21B2B8718ULL,
		0xF2281585DF3F6167ULL,
		0xC358B4E48BF0CEA2ULL,
		0x56B88FB8ABD69FA0ULL
	}};
	sign = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5DA9D139FBB8CA4ULL,
		0xD7E192C169DB741AULL,
		0xBD14F4523C56C82BULL,
		0x2F3FC0109B61A3D8ULL,
		0x606A4C23533C7061ULL,
		0x4C8F3F5A41C6B1C2ULL,
		0x6B6E002DFF4519F0ULL,
		0xA562973DE3FA4E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD39893646F4728F0ULL,
		0x9DA0C895B9B782D4ULL,
		0xFC5C3CA66D4D0D2BULL,
		0x21CF7D68FE8372DAULL,
		0xDD77B6A9692BDD76ULL,
		0xBF762188C538E049ULL,
		0x8210A9CAE2CE910BULL,
		0xC6FDC733475D7975ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x224209AF307463B4ULL,
		0x3A40CA2BB023F146ULL,
		0xC0B8B7ABCF09BB00ULL,
		0x0D7042A79CDE30FDULL,
		0x82F29579EA1092EBULL,
		0x8D191DD17C8DD178ULL,
		0xE95D56631C7688E4ULL,
		0xDE64D00A9C9CD509ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BA8E6EE74B45886ULL,
		0x48581A15036A3C16ULL,
		0x0456B2149C1521EBULL,
		0x7525629B24B56B33ULL,
		0x92576B569D0305A5ULL,
		0x2CABB27AE4C87B7FULL,
		0x322C3FE6A65B50A9ULL,
		0x26DFD9FFB883BE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F191EC590F1F007ULL,
		0x927E9CDCEE9363BAULL,
		0x19422CFF8148AE1FULL,
		0xE9534D57C3739C42ULL,
		0x6149823AE4A4F389ULL,
		0x8441716154B8B521ULL,
		0x4B4DBF93EE30EBBEULL,
		0x0BC6DD370B32709CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC8FC828E3C2687FULL,
		0xB5D97D3814D6D85BULL,
		0xEB1485151ACC73CBULL,
		0x8BD215436141CEF0ULL,
		0x310DE91BB85E121BULL,
		0xA86A4119900FC65EULL,
		0xE6DE8052B82A64EAULL,
		0x1B18FCC8AD514DC5ULL
	}};
	sign = 0;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6027C8BEDA761007ULL,
		0xDD8CB5CB37F7CF12ULL,
		0x5226693781412017ULL,
		0x4C1C3D4A625C24C8ULL,
		0x58DDFD5BE4763A83ULL,
		0xA13C9CBEDFC63F32ULL,
		0xC4A028A9797ABF78ULL,
		0x75BC7C3DB79A0C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC71999D82C2459C4ULL,
		0xA9CA8410D645D681ULL,
		0x03F1F5EB94360F2AULL,
		0x439512B391D1E8E4ULL,
		0x0517D1BE5D4BD2D7ULL,
		0x97367E466CBD56B3ULL,
		0xD4B3BE910B37861BULL,
		0x41FCB29F56CC5959ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x990E2EE6AE51B643ULL,
		0x33C231BA61B1F890ULL,
		0x4E34734BED0B10EDULL,
		0x08872A96D08A3BE4ULL,
		0x53C62B9D872A67ACULL,
		0x0A061E787308E87FULL,
		0xEFEC6A186E43395DULL,
		0x33BFC99E60CDB2DBULL
	}};
	sign = 0;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD360E8BDA815B052ULL,
		0x5A5F3A38F6A64FB2ULL,
		0x2D86AA64F580298EULL,
		0xEEEFE9AAB0107D23ULL,
		0xA3972A8C75A2A38DULL,
		0x1FFFC113ABF6AE99ULL,
		0x8E6F621A94E2F1E1ULL,
		0xDC334B06B8A3DCFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB669492ACE80C979ULL,
		0xBE47B04762AC5135ULL,
		0xB26C7B83425B6220ULL,
		0x026B7B8B0777AF82ULL,
		0x9433E9361824F589ULL,
		0x4AB19B21A0F1014AULL,
		0x03E01F7B59ECDD19ULL,
		0xF0992F07B672243FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CF79F92D994E6D9ULL,
		0x9C1789F193F9FE7DULL,
		0x7B1A2EE1B324C76DULL,
		0xEC846E1FA898CDA0ULL,
		0x0F6341565D7DAE04ULL,
		0xD54E25F20B05AD4FULL,
		0x8A8F429F3AF614C7ULL,
		0xEB9A1BFF0231B8BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x768FC0E44B174C3CULL,
		0x14C713AA0979AAE3ULL,
		0x2BEB4C2C8139CC5BULL,
		0xAA6F95256B33718CULL,
		0xAB788855551414A5ULL,
		0x80FC614F6C994576ULL,
		0x61B232A5B8708F50ULL,
		0xE16C189D399D20ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x953337ECB5145BB0ULL,
		0x8DD6A864194C9552ULL,
		0x5D19E4C66AF91C04ULL,
		0xE6482BE431FEB4DDULL,
		0x0E6AE5343AAF3332ULL,
		0xE082198C4F519078ULL,
		0xF87094D53A7B1A03ULL,
		0xE0C1B65C5635F78FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE15C88F79602F08CULL,
		0x86F06B45F02D1590ULL,
		0xCED167661640B056ULL,
		0xC42769413934BCAEULL,
		0x9D0DA3211A64E172ULL,
		0xA07A47C31D47B4FEULL,
		0x69419DD07DF5754CULL,
		0x00AA6240E367291CULL
	}};
	sign = 0;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC814EA798EC9ECCCULL,
		0x376963DFEC0CDED0ULL,
		0x8EF0DB8C1D2D0866ULL,
		0xDAC4AD360958F083ULL,
		0x18A501E13C7EAC54ULL,
		0x87020593806AF667ULL,
		0x85A1086A3C342891ULL,
		0x455EBAFD563B955CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78088143EE23B8D4ULL,
		0xD9B53BA3F12C948AULL,
		0xA20169F1687538AFULL,
		0x314EEF291509AA22ULL,
		0x80752C934A301E8AULL,
		0xD7525801D336C5B8ULL,
		0x94B2415675E246A8ULL,
		0xDE36DD8B957C631DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500C6935A0A633F8ULL,
		0x5DB4283BFAE04A46ULL,
		0xECEF719AB4B7CFB6ULL,
		0xA975BE0CF44F4660ULL,
		0x982FD54DF24E8DCAULL,
		0xAFAFAD91AD3430AEULL,
		0xF0EEC713C651E1E8ULL,
		0x6727DD71C0BF323EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC6E6106774E6BC4ULL,
		0x0C325BEAF271C58BULL,
		0x06A2D68D20F79163ULL,
		0xC8F0607B49BFBF57ULL,
		0x818D5D92446D44DCULL,
		0xCDCE6FDAD79A58E1ULL,
		0x9725445649C323C2ULL,
		0x05A6C8EC10BECFD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61E1513F5C291FB4ULL,
		0xA99AF1D781574F1CULL,
		0x0610F57DA40B5EBBULL,
		0xDD5B8490B24F3953ULL,
		0x0CFEBC0E168E3107ULL,
		0x9551A4B78D9EAF7BULL,
		0x57C5D1E9ABC73D14ULL,
		0x7C36B3DC8149C387ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A8D0FC71B254C10ULL,
		0x62976A13711A766FULL,
		0x0091E10F7CEC32A7ULL,
		0xEB94DBEA97708604ULL,
		0x748EA1842DDF13D4ULL,
		0x387CCB2349FBA966ULL,
		0x3F5F726C9DFBE6AEULL,
		0x8970150F8F750C4DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD16F35C756FFD59ULL,
		0x9336833C91F9A566ULL,
		0xB2CB4FFDF453D67BULL,
		0x4D1CD63EECBFC5F4ULL,
		0xD2CA623D26C0DDECULL,
		0xA8A9A6B3D4EF3545ULL,
		0x7471BCEAF052375BULL,
		0x97C7218B5BB56F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A931035B3B0E47ULL,
		0xD7D3D9ED0DBFF2A7ULL,
		0xFF8E434E22CC2D42ULL,
		0x18B273CBB7AE9970ULL,
		0xD64748F2114E1C05ULL,
		0x564BB4423081E23AULL,
		0x3F4E8E7DE448F7C3ULL,
		0x64665F0605DA6742ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A6DC2591A34EF12ULL,
		0xBB62A94F8439B2BFULL,
		0xB33D0CAFD187A938ULL,
		0x346A627335112C83ULL,
		0xFC83194B1572C1E7ULL,
		0x525DF271A46D530AULL,
		0x35232E6D0C093F98ULL,
		0x3360C28555DB0853ULL
	}};
	sign = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB90401EE7CD451CEULL,
		0xE5A5175A435E7AECULL,
		0xB060AB756CC1CBA1ULL,
		0xBEB4102773F98DACULL,
		0x5B50302E6273AD83ULL,
		0x1470B078601E88F6ULL,
		0x60E0F060E1DD6914ULL,
		0x4C43B1817B739465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EED8789D624E9FCULL,
		0xB6140CD4C9E253D2ULL,
		0x7DDDF5EF662D5B78ULL,
		0xADD048F0F8178330ULL,
		0x2D52B531BE483A53ULL,
		0x2103D6A3E0A78B2EULL,
		0x6F9FF6A8CC51A8B6ULL,
		0xB53FF079AA70E551ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A167A64A6AF67D2ULL,
		0x2F910A85797C271AULL,
		0x3282B58606947029ULL,
		0x10E3C7367BE20A7CULL,
		0x2DFD7AFCA42B7330ULL,
		0xF36CD9D47F76FDC8ULL,
		0xF140F9B8158BC05DULL,
		0x9703C107D102AF13ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3862C359C8AE73CULL,
		0x7C601FCDEAA443B5ULL,
		0x72C6C9E322571B7BULL,
		0xD6DD6C4002ECCB9CULL,
		0x80A039E2F23681BAULL,
		0xBBE362C66F093D7BULL,
		0xDCB5E5CE3640A3F3ULL,
		0x6C10F6B37BD6F14AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A8BDD72D09F5CEULL,
		0x7DA0ED496F938E7EULL,
		0x4D6F4F38AECBD8D2ULL,
		0x88D0FA65117177B8ULL,
		0x93A6059FB291806FULL,
		0x56BAFDAF492EF8B8ULL,
		0xD2310F569341F9B9ULL,
		0xF33A5C93B9977DD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40DD6E5E6F80F16EULL,
		0xFEBF32847B10B537ULL,
		0x25577AAA738B42A8ULL,
		0x4E0C71DAF17B53E4ULL,
		0xECFA34433FA5014BULL,
		0x6528651725DA44C2ULL,
		0x0A84D677A2FEAA3AULL,
		0x78D69A1FC23F7377ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC622102EEB6E2E33ULL,
		0x8A9EAA54D080843EULL,
		0x67C6253970B8744BULL,
		0xF560AD020BD91923ULL,
		0xAC88BD8E61B53F99ULL,
		0xE96B649F18209238ULL,
		0xB25E76EFFEE61605ULL,
		0x875BDD820BC3D8A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58CB3B23ADFFA249ULL,
		0x3EADF4D505666A47ULL,
		0xDB6927B3A7BCA9F7ULL,
		0x40F20D31ECA3DC49ULL,
		0x0D9F8BCB7353A894ULL,
		0x672F30DA6A4AF006ULL,
		0x70C6F70242462EA9ULL,
		0xADDCAA2AB8DE1BA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D56D50B3D6E8BEAULL,
		0x4BF0B57FCB1A19F7ULL,
		0x8C5CFD85C8FBCA54ULL,
		0xB46E9FD01F353CD9ULL,
		0x9EE931C2EE619705ULL,
		0x823C33C4ADD5A232ULL,
		0x41977FEDBC9FE75CULL,
		0xD97F335752E5BD00ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7D07E2691675F3FULL,
		0x0F1FA16A8BBECB52ULL,
		0x5BC7AC8811849F0AULL,
		0xD81DB5ECF6257B8CULL,
		0xA7F0B68E55A27219ULL,
		0xA66F6868C93C7131ULL,
		0x7A36BE45F566B778ULL,
		0x1B9DD5497A42552EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FDDF6E6485B69BDULL,
		0xB44AFDAAECC8F720ULL,
		0x1FCCE2FB5CDCE29FULL,
		0x263BC16B8F7B06A4ULL,
		0xE6F8D70A1CC34D0AULL,
		0x71D48E0673D5F51FULL,
		0xA72598F9CD23FA38ULL,
		0xD73F31D34896C101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7F28740490BF582ULL,
		0x5AD4A3BF9EF5D432ULL,
		0x3BFAC98CB4A7BC6AULL,
		0xB1E1F48166AA74E8ULL,
		0xC0F7DF8438DF250FULL,
		0x349ADA6255667C11ULL,
		0xD311254C2842BD40ULL,
		0x445EA37631AB942CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F9675660809D6B6ULL,
		0x38EB214F8E35D0B7ULL,
		0x4A1031E57B216827ULL,
		0xA798A03AF6D8948DULL,
		0x10C3456F4A557FC5ULL,
		0xEA2130E1BD1C7EF1ULL,
		0xA09EBC4342865975ULL,
		0xBC4A72732A48ECE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x120DF3538E431288ULL,
		0x860182F188170DA3ULL,
		0xE46860E13EB3A7BDULL,
		0x46B91FAC5E2ABCD9ULL,
		0x0E7E902501F3B3EBULL,
		0xB25769B740ED3A35ULL,
		0x2828E5F674CFF9E9ULL,
		0x6BEB7EAE1AD87B8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D88821279C6C42EULL,
		0xB2E99E5E061EC314ULL,
		0x65A7D1043C6DC069ULL,
		0x60DF808E98ADD7B3ULL,
		0x0244B54A4861CBDAULL,
		0x37C9C72A7C2F44BCULL,
		0x7875D64CCDB65F8CULL,
		0x505EF3C50F707155ULL
	}};
	sign = 0;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCA702F21D70CB0CULL,
		0xD6E546277DF3EE1AULL,
		0x349FAC766F4D08D0ULL,
		0x037434A8DEAFF877ULL,
		0xE3F9FAB986DE2A8FULL,
		0xD5C155C5B7E9C752ULL,
		0xE47B6444993A5018ULL,
		0xE37E7EAD501C785CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B72A982BC77AE45ULL,
		0xF79FDE85E47A5E74ULL,
		0xA15AE72F49FF06BAULL,
		0xD0F15548A10739DAULL,
		0xDE495E29662D1B3EULL,
		0x376D3F43EE0E6D2EULL,
		0xFFC37E741D6D541DULL,
		0xC2340A031410BFD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC134596F60F91CC7ULL,
		0xDF4567A199798FA6ULL,
		0x9344C547254E0215ULL,
		0x3282DF603DA8BE9CULL,
		0x05B09C9020B10F50ULL,
		0x9E541681C9DB5A24ULL,
		0xE4B7E5D07BCCFBFBULL,
		0x214A74AA3C0BB889ULL
	}};
	sign = 0;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5572AF8DDB6DCFCULL,
		0x72A50A7D36E5A966ULL,
		0x6E11C554EB4B18E5ULL,
		0xCA6148C941267320ULL,
		0xCF373098904FA170ULL,
		0x77B09324233E3B62ULL,
		0x0DDD50BF561A2BEBULL,
		0x5B41B0912074D3B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48AA5B65BD6DB1FFULL,
		0x397130D0161ECCF1ULL,
		0x31928132CDBD71AFULL,
		0x7FD23C8F06FE67F5ULL,
		0x5D79BD5CF2D2DC18ULL,
		0x099F90EAEA57BD80ULL,
		0x04109D25A24C38F8ULL,
		0xC3A4BFD8A1B929FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CACCF9320492AFDULL,
		0x3933D9AD20C6DC75ULL,
		0x3C7F44221D8DA736ULL,
		0x4A8F0C3A3A280B2BULL,
		0x71BD733B9D7CC558ULL,
		0x6E11023938E67DE2ULL,
		0x09CCB399B3CDF2F3ULL,
		0x979CF0B87EBBA9BDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAE11A7E93FBDC8FULL,
		0xE6BB22BF274FEC63ULL,
		0x632F0F41612AA63FULL,
		0x85D3F7F634CF0DB6ULL,
		0xCCE0DC064C3D5613ULL,
		0x0D9E8D6624E34ECAULL,
		0x74D5CF441D6AD0A7ULL,
		0x38093FCE2C7BC7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB981822FF93A9E1ULL,
		0x636B18C5166E99C7ULL,
		0xF148AE28354BD6E5ULL,
		0x6072877A92E0549BULL,
		0xB617CF1737758F90ULL,
		0x9C500306F8BC51FFULL,
		0x69DA79D858E0E06AULL,
		0xFFCBF571B1EC7193ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F49025B946832AEULL,
		0x835009FA10E1529CULL,
		0x71E661192BDECF5AULL,
		0x2561707BA1EEB91AULL,
		0x16C90CEF14C7C683ULL,
		0x714E8A5F2C26FCCBULL,
		0x0AFB556BC489F03CULL,
		0x383D4A5C7A8F562CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BF01E8445C7EFEEULL,
		0xD228DBDEB464D75FULL,
		0xBA3CFA1A047AC886ULL,
		0xE54C32542AE15C12ULL,
		0x74D99CDAC7118568ULL,
		0x85CCC4EB5FA5606AULL,
		0x792B40849C8E697DULL,
		0x9396B4AF4745F66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x604451B0C29F98D2ULL,
		0x30FBF6F6F16C8349ULL,
		0x842F8154C7FBB677ULL,
		0x0D92444C092D26D0ULL,
		0x5AECC063A3347360ULL,
		0x6F8CA0015F3BEF77ULL,
		0x85C21C25301B682CULL,
		0x052CA0E9F8A4462CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBABCCD38328571CULL,
		0xA12CE4E7C2F85415ULL,
		0x360D78C53C7F120FULL,
		0xD7B9EE0821B43542ULL,
		0x19ECDC7723DD1208ULL,
		0x164024EA006970F3ULL,
		0xF369245F6C730151ULL,
		0x8E6A13C54EA1B03DULL
	}};
	sign = 0;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0FCFFF5E95E5872ULL,
		0xEF8EB653945952B5ULL,
		0x05406C1173F7135EULL,
		0x00C0F0FB5E63EA34ULL,
		0x04CA379267E2D4E1ULL,
		0xFD479EC03C20D9D5ULL,
		0xA2B5527EE62EBB94ULL,
		0xE53B272BEEDB70CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D04981B6F8372CULL,
		0x2E0033961B881145ULL,
		0x5F2E56CBF78C24FEULL,
		0xB182BB5895B0CCBDULL,
		0xF916D92869BD61DAULL,
		0x3E90752BDF36CF94ULL,
		0x78AC48CFCFB202F7ULL,
		0x557AEA18101253C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D2CB67432662146ULL,
		0xC18E82BD78D14170ULL,
		0xA61215457C6AEE60ULL,
		0x4F3E35A2C8B31D76ULL,
		0x0BB35E69FE257306ULL,
		0xBEB729945CEA0A40ULL,
		0x2A0909AF167CB89DULL,
		0x8FC03D13DEC91D08ULL
	}};
	sign = 0;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA976E91598B45C46ULL,
		0xC0C609259B2A1681ULL,
		0xCEAADEBC02CB8A8FULL,
		0xCD93209F703E51C3ULL,
		0xA94F4E83F3F0363DULL,
		0x086A6ED14C9633B2ULL,
		0x7239BC67CD339A7AULL,
		0x89CF116241F444E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB0EF2E47C40E5FULL,
		0x2A274988DF31B387ULL,
		0x8F02A2FB3939A61EULL,
		0x6975773D542069B0ULL,
		0xB36562A8B9586409ULL,
		0x74EBFF3E057EA3ACULL,
		0x8ABF643964FA5F70ULL,
		0x4FEA9F59E417C543ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6AC5F9E750F04DE7ULL,
		0x969EBF9CBBF862FAULL,
		0x3FA83BC0C991E471ULL,
		0x641DA9621C1DE813ULL,
		0xF5E9EBDB3A97D234ULL,
		0x937E6F9347179005ULL,
		0xE77A582E68393B09ULL,
		0x39E472085DDC7FA5ULL
	}};
	sign = 0;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FAB12D605ED2BD0ULL,
		0x470FF2B86E1196E8ULL,
		0x9FBA61E0A320D7F0ULL,
		0x0D733E53009A0E7DULL,
		0x3D7428C9ACC08C7CULL,
		0xB7E249A6CEC8D97EULL,
		0xA3D2A93C157E941EULL,
		0x91263DF15D465799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE367FCDCAC2CFA6ULL,
		0xCE02F9CEAE8EC91EULL,
		0x0F187BA9F8E8C1A1ULL,
		0x21DB6EF9C6DEF7A0ULL,
		0x699A7865D5D16AD3ULL,
		0x614910952760ADA6ULL,
		0x173FC18849A96462ULL,
		0x7AFC0BB5CFC2C5E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x317493083B2A5C2AULL,
		0x790CF8E9BF82CDC9ULL,
		0x90A1E636AA38164EULL,
		0xEB97CF5939BB16DDULL,
		0xD3D9B063D6EF21A8ULL,
		0x56993911A7682BD7ULL,
		0x8C92E7B3CBD52FBCULL,
		0x162A323B8D8391B0ULL
	}};
	sign = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1124A28C12339BCULL,
		0x0D4D8D76BFB3B44FULL,
		0x44FBCF2C5F32B2C6ULL,
		0xEC6D8686ECCE96E0ULL,
		0xF2C52F6737B11147ULL,
		0x22B8EE03B8CFFD65ULL,
		0xB6BA8E9E34050F28ULL,
		0x05101D072EB6B15EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB8DBC979403DA11ULL,
		0x129BEA406E9FAC5DULL,
		0x2875D9F882E1BE26ULL,
		0x55DF89806D633353ULL,
		0x1C6A06E750832C78ULL,
		0x67581F759F951B70ULL,
		0x3CA781251FD1DBF0ULL,
		0xD271A107D62D2A7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35848D912D1F5FABULL,
		0xFAB1A336511407F2ULL,
		0x1C85F533DC50F49FULL,
		0x968DFD067F6B638DULL,
		0xD65B287FE72DE4CFULL,
		0xBB60CE8E193AE1F5ULL,
		0x7A130D7914333337ULL,
		0x329E7BFF588986E0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D19C556548863AEULL,
		0x39B646D325668A7FULL,
		0xA71CAB9EC71D36FDULL,
		0x9B1349A36CC4D6A4ULL,
		0x5E94D042049F0AC3ULL,
		0x352BECB0C24DDEBAULL,
		0x32331209DCB3B2D9ULL,
		0xF5D534D5F20F7961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC9E0A83A1BB8D5ULL,
		0x21942722DF002D9CULL,
		0x4EF0246C4E560985ULL,
		0xDD7311D3586C0EF1ULL,
		0x61FF6A94FCCF1ED3ULL,
		0x08192EF0BE484AD1ULL,
		0x8176E361F29C0F6CULL,
		0x7A6736D4421DE623ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB14FE4AE1A6CAAD9ULL,
		0x18221FB046665CE2ULL,
		0x582C873278C72D78ULL,
		0xBDA037D01458C7B3ULL,
		0xFC9565AD07CFEBEFULL,
		0x2D12BDC0040593E8ULL,
		0xB0BC2EA7EA17A36DULL,
		0x7B6DFE01AFF1933DULL
	}};
	sign = 0;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B38479D9164BCBEULL,
		0x973BE16C86A3E128ULL,
		0x4236E23C077CBE52ULL,
		0x4389D85CC83CBDB5ULL,
		0x27BECAA4AB78C9E9ULL,
		0xECE45C87532D7A05ULL,
		0xA878A65068A1A8C1ULL,
		0xC1171F532878ED6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB17328792AD95AFCULL,
		0x66B5691618CDA868ULL,
		0x00B808684A75DCD2ULL,
		0x648651ED17B8C8B9ULL,
		0x2225F6D1548CEB64ULL,
		0x9E0F0EAB370448D1ULL,
		0x1AF7704E380FD958ULL,
		0x45215B7F56045A5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE9C51F24668B61C2ULL,
		0x308678566DD638BFULL,
		0x417ED9D3BD06E180ULL,
		0xDF03866FB083F4FCULL,
		0x0598D3D356EBDE84ULL,
		0x4ED54DDC1C293134ULL,
		0x8D8136023091CF69ULL,
		0x7BF5C3D3D2749310ULL
	}};
	sign = 0;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5D535D22CC2F6C6ULL,
		0xFC0F554736A8A80BULL,
		0x1EBFCA4FEE45952CULL,
		0x9DF7226C0604E254ULL,
		0x8FD6BC645A44FDD0ULL,
		0xC795B8780A88596AULL,
		0x637E234D564BDB7FULL,
		0xCC2C1B20210FD942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF60DD83E87CE0CULL,
		0xDF244CF66786D36FULL,
		0x0FF08C07295CD51DULL,
		0x6CD63105B28CB17DULL,
		0x5EE85D40A44C0D80ULL,
		0xB4BAA26CD867D8C0ULL,
		0x2E08A1D7000006B5ULL,
		0x69A458799C43BD11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7DF27F9EE3B28BAULL,
		0x1CEB0850CF21D49BULL,
		0x0ECF3E48C4E8C00FULL,
		0x3120F166537830D7ULL,
		0x30EE5F23B5F8F050ULL,
		0x12DB160B322080AAULL,
		0x35758176564BD4CAULL,
		0x6287C2A684CC1C31ULL
	}};
	sign = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x813A718BA1746111ULL,
		0x9B56EB2D4FE646DAULL,
		0xB8E3F8037CE79C7AULL,
		0x2F910B823A7042DEULL,
		0x5AD243CE1BB4317BULL,
		0x87EDB6A5F5A7613DULL,
		0xCE4214CC7CF06CB8ULL,
		0x0F3D3BEF93045B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D897237E71FE763ULL,
		0xDD7DC31B8F1B7EA8ULL,
		0x33AEA22F1F9E1A8AULL,
		0x1F433FA861212C5DULL,
		0x1820B9A755DB72DBULL,
		0xF705E5F3CA405608ULL,
		0x1660DC616813FC21ULL,
		0x5306B1744B7A804DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03B0FF53BA5479AEULL,
		0xBDD92811C0CAC832ULL,
		0x853555D45D4981EFULL,
		0x104DCBD9D94F1681ULL,
		0x42B18A26C5D8BEA0ULL,
		0x90E7D0B22B670B35ULL,
		0xB7E1386B14DC7096ULL,
		0xBC368A7B4789DB19ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8011E6ABAD9A4262ULL,
		0xE1F2FFCE00D30815ULL,
		0x8E1B4934BAE5E440ULL,
		0x18075EF6C00AF162ULL,
		0x5497885A317493C5ULL,
		0x8A38A4EED5854530ULL,
		0x37E7CB86F2C276DDULL,
		0xFD5988AB0515CC44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB3C2259311E73A9ULL,
		0x2A508C15C63D176DULL,
		0x2AD7C12BB7D71AECULL,
		0xD8E1B002C41E6AE5ULL,
		0x002E2BF091659293ULL,
		0x3345B2D75C285C7EULL,
		0x5C60599F96829EDEULL,
		0xD891D9B5AC3439C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94D5C4527C7BCEB9ULL,
		0xB7A273B83A95F0A7ULL,
		0x63438809030EC954ULL,
		0x3F25AEF3FBEC867DULL,
		0x54695C69A00F0131ULL,
		0x56F2F217795CE8B2ULL,
		0xDB8771E75C3FD7FFULL,
		0x24C7AEF558E19281ULL
	}};
	sign = 0;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BA1E003A9936CD8ULL,
		0x7A54C3A2442E6979ULL,
		0x9A8E512F0BBF75EFULL,
		0x49490B714D735844ULL,
		0x796586455BECB664ULL,
		0x6E1DBB30930454B6ULL,
		0xC4EEAA14AA353E5CULL,
		0x5AA6A22025E0FA47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A09378FA96A3A97ULL,
		0x6C9FBF0F69390C4EULL,
		0x6190C43D649A9101ULL,
		0xDC2A62F6AC372AF6ULL,
		0x4CFB9DDF8D13A4E5ULL,
		0x2BBCF4661B1E770DULL,
		0x03339147B7FFE287ULL,
		0xCE091CC748F9510DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA198A87400293241ULL,
		0x0DB50492DAF55D2AULL,
		0x38FD8CF1A724E4EEULL,
		0x6D1EA87AA13C2D4EULL,
		0x2C69E865CED9117EULL,
		0x4260C6CA77E5DDA9ULL,
		0xC1BB18CCF2355BD5ULL,
		0x8C9D8558DCE7A93AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97028E7464D6D4AFULL,
		0x09FE907A21241A46ULL,
		0x3AA0CB862FF99BCDULL,
		0x495AAEF7E1E5D56FULL,
		0x946FAE0C3585C04BULL,
		0x9C8348A3A7D43080ULL,
		0x8E201B8D4DBB29EFULL,
		0xD7190C529646C5F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA4848F52FCC239DULL,
		0x08E8C46ABF94887FULL,
		0x1798FB7CCC8C9FA1ULL,
		0xCE2D125A36BB9C0DULL,
		0xC4E04D0B44A9ED32ULL,
		0x4F2DFBE2D5597F5AULL,
		0xE6AACC236A2C7B5AULL,
		0xEEECB4C5716A1AB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CBA457F350AB112ULL,
		0x0115CC0F618F91C6ULL,
		0x2307D009636CFC2CULL,
		0x7B2D9C9DAB2A3962ULL,
		0xCF8F6100F0DBD318ULL,
		0x4D554CC0D27AB125ULL,
		0xA7754F69E38EAE95ULL,
		0xE82C578D24DCAB3AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0D3444ED79BF5AFAULL,
		0xECE2F00DD4F01106ULL,
		0xB3DA1C0A9066E60CULL,
		0x0A868A7297773DA1ULL,
		0xCDF193E39E9116C6ULL,
		0xBD7A54A27CDF52A8ULL,
		0x6B6EC2545EB8572EULL,
		0x8303C0BA65D48EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D5E910C74F163CULL,
		0x83C966D6BB5FE714ULL,
		0x408AD36431C1114AULL,
		0x19B22F277285C2DDULL,
		0x70C49BC734D24681ULL,
		0x4E0288D8C455BC05ULL,
		0xFA7461C142F593E7ULL,
		0xE81BD78BE9D1F8D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C5E5BDCB27044BEULL,
		0x69198937199029F2ULL,
		0x734F48A65EA5D4C2ULL,
		0xF0D45B4B24F17AC4ULL,
		0x5D2CF81C69BED044ULL,
		0x6F77CBC9B88996A3ULL,
		0x70FA60931BC2C347ULL,
		0x9AE7E92E7C02960CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E9F9207A415DBC7ULL,
		0x1E2EEB95E20094D4ULL,
		0x3E3A0FFC09D2209FULL,
		0xF4E1915960EA51B9ULL,
		0x90EA1770EE288400ULL,
		0x706DBC91337E9021ULL,
		0x929C5B7BBED80590ULL,
		0xD7AEB576BA639901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5D89A98B070295ULL,
		0x83867DD92409ABE4ULL,
		0x76066B70BBB5D1E5ULL,
		0xF105C9BDBBF6D7A2ULL,
		0xD984BD2EFB728185ULL,
		0x3CDF5DE78980D48EULL,
		0xBB12937F769CD2C3ULL,
		0x181758459E1DE585ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB142085E190ED932ULL,
		0x9AA86DBCBDF6E8EFULL,
		0xC833A48B4E1C4EB9ULL,
		0x03DBC79BA4F37A16ULL,
		0xB7655A41F2B6027BULL,
		0x338E5EA9A9FDBB92ULL,
		0xD789C7FC483B32CDULL,
		0xBF975D311C45B37BULL
	}};
	sign = 0;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F68200BF5936C16ULL,
		0xFB308736D5970A24ULL,
		0xCCCEC82B7379F08DULL,
		0xFFDB8E229072F4D7ULL,
		0x503172DA09EB22CCULL,
		0xA0E1D06586FED466ULL,
		0xC3DCE0FEE5CC6AF2ULL,
		0x7E2B35546D46A722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D031A2C4FA57C5ULL,
		0x5F3FE3171322F4F5ULL,
		0x73028145493C18DFULL,
		0x8996679E8B62C0D2ULL,
		0x6C4FFAF2636E8419ULL,
		0xB2D2B03EFA8A3DE2ULL,
		0xEF36480289F4DDAAULL,
		0xDEDFC41765AAC336ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D97EE6930991451ULL,
		0x9BF0A41FC274152FULL,
		0x59CC46E62A3DD7AEULL,
		0x7645268405103405ULL,
		0xE3E177E7A67C9EB3ULL,
		0xEE0F20268C749683ULL,
		0xD4A698FC5BD78D47ULL,
		0x9F4B713D079BE3EBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F59F35E06C2352DULL,
		0x311257DCA20D2ECFULL,
		0x05084F155E7BA196ULL,
		0xF650174ABF47CA52ULL,
		0x4E4F06EDAA0773A9ULL,
		0x3E0455E6080F779CULL,
		0xA45D55D1A264E97BULL,
		0x866E400CACF73B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A62C022A9ECE7EFULL,
		0x1FF67BEE5E481001ULL,
		0xB49E9D5D0406D0EDULL,
		0x18AAF9EFB6A6E803ULL,
		0x645DBD10100A7FA9ULL,
		0x9A3710CAA441AC1CULL,
		0xE386E78B83C6CC6CULL,
		0xEC21D4E838355586ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04F7333B5CD54D3EULL,
		0x111BDBEE43C51ECEULL,
		0x5069B1B85A74D0A9ULL,
		0xDDA51D5B08A0E24EULL,
		0xE9F149DD99FCF400ULL,
		0xA3CD451B63CDCB7FULL,
		0xC0D66E461E9E1D0EULL,
		0x9A4C6B2474C1E5E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB58241A0C6F5B2E5ULL,
		0xBD75B6110AADDFAFULL,
		0x4A303BC48A5B9404ULL,
		0x284E89A87F7B8AA4ULL,
		0x3F3F5A28E9F87591ULL,
		0x1FD75E80586B71B5ULL,
		0x0A70F558668C8E22ULL,
		0x7344249401C7F472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE58A8019C6CDE8A8ULL,
		0xF3E0AA57AE464023ULL,
		0x84E59535AA5043A3ULL,
		0x87365F48F8FF9FC4ULL,
		0xB97F7DA0114A1F2FULL,
		0x0B2D9AAAD0ABDA43ULL,
		0xA16061C118C5D7E7ULL,
		0x8882D8BB73B94818ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFF7C1870027CA3DULL,
		0xC9950BB95C679F8BULL,
		0xC54AA68EE00B5060ULL,
		0xA1182A5F867BEADFULL,
		0x85BFDC88D8AE5661ULL,
		0x14A9C3D587BF9771ULL,
		0x691093974DC6B63BULL,
		0xEAC14BD88E0EAC59ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x414EBCE0C8ABAFCBULL,
		0xFE523743D6A67309ULL,
		0xA4499D6DFB3D1E91ULL,
		0x2F8CF0F94CAEF6EFULL,
		0x7CC5763F0FDC8C66ULL,
		0x06948C509CCB835DULL,
		0x4C5B0B8AB22D7555ULL,
		0x94EFD52B5074886DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0248E14B83E67F40ULL,
		0x061AAD90405ECFBDULL,
		0x05BD8BD2E407F364ULL,
		0x514D26053636F584ULL,
		0x030151AD1701F83AULL,
		0xA48D88F4FFE01D60ULL,
		0x05B8A13F72354B88ULL,
		0x51CDE810522C0962ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F05DB9544C5308BULL,
		0xF83789B39647A34CULL,
		0x9E8C119B17352B2DULL,
		0xDE3FCAF41678016BULL,
		0x79C42491F8DA942BULL,
		0x6207035B9CEB65FDULL,
		0x46A26A4B3FF829CCULL,
		0x4321ED1AFE487F0BULL
	}};
	sign = 0;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0396AFA459ADD287ULL,
		0xF7BFB45C661D5DCDULL,
		0x1A1CE264DEB35A7AULL,
		0xC919FB2307C3FE88ULL,
		0xE77B72020F761372ULL,
		0xFAF3C3635D1463E2ULL,
		0x3DE3270D575DF890ULL,
		0xBB77016DD9677202ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6D7021FF21A62EULL,
		0x9AE66CADC3DAE0AAULL,
		0x1CCDF4E2C5B87905ULL,
		0xDE8F7CAF18C10BA1ULL,
		0x182E48D1199FC2E2ULL,
		0x4D160CAA8A506405ULL,
		0x96F681A1B1AE8520ULL,
		0xE9C364AA5C87C3A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9293F825A8C2C59ULL,
		0x5CD947AEA2427D22ULL,
		0xFD4EED8218FAE175ULL,
		0xEA8A7E73EF02F2E6ULL,
		0xCF4D2930F5D6508FULL,
		0xADDDB6B8D2C3FFDDULL,
		0xA6ECA56BA5AF7370ULL,
		0xD1B39CC37CDFAE5AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61FA45B2D05DE5FCULL,
		0x12C5E03F0E8C2912ULL,
		0x11C830999663E2CCULL,
		0x97E5178A2138D548ULL,
		0x0B0759551D8A371EULL,
		0x8C0AA880647D520CULL,
		0x259CC74580FDD8F7ULL,
		0xE584836ED545AB2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9DD46CDF052C3BULL,
		0xCB63C0B2A5BF3EF6ULL,
		0xFB4F74C5DAD6B09AULL,
		0x31C73754FDABC844ULL,
		0x322729F497F75F4DULL,
		0x5DD5BB26E7500653ULL,
		0x253CEE0B80BA393FULL,
		0xE10D52630D29C0B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA45C7145F158B9C1ULL,
		0x47621F8C68CCEA1BULL,
		0x1678BBD3BB8D3231ULL,
		0x661DE035238D0D03ULL,
		0xD8E02F608592D7D1ULL,
		0x2E34ED597D2D4BB8ULL,
		0x005FD93A00439FB8ULL,
		0x0477310BC81BEA75ULL
	}};
	sign = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F01C26DFC640CD5ULL,
		0xDAFF92B09E7BD23EULL,
		0x3EFA356786EA9CBCULL,
		0x87E4B2CD2B7F8D55ULL,
		0xBD7E43890D405C4EULL,
		0xABFD2FE03175854DULL,
		0x9527A4F5DD03BAA9ULL,
		0xC7FE038BB53C60DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A8BCEBB33F913FULL,
		0x1016EB4016FFAFFAULL,
		0xC924D23094680C4DULL,
		0xD4751D902A21EA5CULL,
		0xACF3AC4D7ADB5B17ULL,
		0xB607235EDABD8292ULL,
		0x107A0A4EF23FCB20ULL,
		0x100137E485D9C5D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA59058249247B96ULL,
		0xCAE8A770877C2243ULL,
		0x75D56336F282906FULL,
		0xB36F953D015DA2F8ULL,
		0x108A973B92650136ULL,
		0xF5F60C8156B802BBULL,
		0x84AD9AA6EAC3EF88ULL,
		0xB7FCCBA72F629B09ULL
	}};
	sign = 0;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65B8997FED6A1852ULL,
		0xAD4213ECB8CFBCB1ULL,
		0x02C6CA1127675688ULL,
		0x550FDCC3C4558F73ULL,
		0xEE47A336BC730BBBULL,
		0xFD71B6EE50774C07ULL,
		0xDE894D51D9D9979BULL,
		0xFCDC69436FAFCD95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B94673A814014B4ULL,
		0xA9B7718126C77AE5ULL,
		0xC49696FED5E5EEEDULL,
		0xB9E631C9821A0163ULL,
		0xB6C4DA307201076DULL,
		0x968FF5339B51458AULL,
		0x8F5D2FDDC05B19C3ULL,
		0xB1F260B549A1732AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA2432456C2A039EULL,
		0x038AA26B920841CBULL,
		0x3E3033125181679BULL,
		0x9B29AAFA423B8E0FULL,
		0x3782C9064A72044DULL,
		0x66E1C1BAB526067DULL,
		0x4F2C1D74197E7DD8ULL,
		0x4AEA088E260E5A6BULL
	}};
	sign = 0;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9DDC387C2B9C6E9ULL,
		0xE1EF198704DBE61FULL,
		0x423B049EF7B33C70ULL,
		0x34077EAFE3B28DC4ULL,
		0xC0AB4D59AE2B2BECULL,
		0xE934848B3C030095ULL,
		0x52605BEDB4626BE4ULL,
		0xE9F0660B9C3333FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B4B787D0205B9D9ULL,
		0x7CDD34762D9232C7ULL,
		0x12DB30C8766EF5A6ULL,
		0xD9D030771D03515DULL,
		0x3D5E5BD2C119F6F6ULL,
		0xA3056B8ABA1923A5ULL,
		0x564A80FA582C82E8ULL,
		0xCF58E440211A5EDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E924B0AC0B40D10ULL,
		0x6511E510D749B358ULL,
		0x2F5FD3D6814446CAULL,
		0x5A374E38C6AF3C67ULL,
		0x834CF186ED1134F5ULL,
		0x462F190081E9DCF0ULL,
		0xFC15DAF35C35E8FCULL,
		0x1A9781CB7B18D51CULL
	}};
	sign = 0;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1EF0FEE6E9025A7ULL,
		0x40DFA862AD44655FULL,
		0x282791C6A4454026ULL,
		0x95C075F18CFEDDBDULL,
		0x43391F425AA2FB68ULL,
		0x5434E1E6D78123F8ULL,
		0xF626056AD5DE663AULL,
		0x3FA26193EC7EFD26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54B91096F60CC2AULL,
		0x40BCDB319B4E258DULL,
		0xFCE756A2800972F0ULL,
		0x5F752D36AAD12795ULL,
		0x75F2D5E5D4F27D5BULL,
		0xB3CF4B935F7B134DULL,
		0x6BA1607188866C46ULL,
		0x2F6241C686FF873FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCA37EE4FF2F597DULL,
		0x0022CD3111F63FD1ULL,
		0x2B403B24243BCD36ULL,
		0x364B48BAE22DB627ULL,
		0xCD46495C85B07E0DULL,
		0xA0659653780610AAULL,
		0x8A84A4F94D57F9F3ULL,
		0x10401FCD657F75E7ULL
	}};
	sign = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EBD256D7D8B80C1ULL,
		0xF71B9FA1800C146BULL,
		0x865A06BA52FADDF6ULL,
		0xED6546625C72CC70ULL,
		0x65DCB2F07B4E225BULL,
		0xC70F5150E6D71C77ULL,
		0xB56D8EC719AA7C2BULL,
		0x6FD78D24B07FFAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFB972C49EEBD82EULL,
		0x8224B02D89DBDBB9ULL,
		0x042BFD2A636D5927ULL,
		0x9AFB102938506C71ULL,
		0xA0A5DA3D85A691E7ULL,
		0x81D5423512836FC2ULL,
		0xD19819C6B72C27EDULL,
		0x1353697146C289FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F03B2A8DE9FA893ULL,
		0x74F6EF73F63038B1ULL,
		0x822E098FEF8D84CFULL,
		0x526A363924225FFFULL,
		0xC536D8B2F5A79074ULL,
		0x453A0F1BD453ACB4ULL,
		0xE3D57500627E543EULL,
		0x5C8423B369BD70AFULL
	}};
	sign = 0;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF34E343D5B7AFD8ULL,
		0x2A08C76665548355ULL,
		0xFFC69A0700DAC09FULL,
		0x0164857FEE78F5E3ULL,
		0x3EA7B2B0468481BEULL,
		0x8650781EDE625506ULL,
		0x0D8470DD39EABC71ULL,
		0x93AC9C1FA8CCA7C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602949583AACB7FEULL,
		0x519C9307CEB50385ULL,
		0x5092EF2550E21F9AULL,
		0xBA617AA8F96DBD90ULL,
		0xB634A6FBCF6D0426ULL,
		0x3CCF0A82D0982175ULL,
		0x3C48467B16711CE1ULL,
		0x970DE1643DCD17DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F0B99EB9B0AF7DAULL,
		0xD86C345E969F7FD0ULL,
		0xAF33AAE1AFF8A104ULL,
		0x47030AD6F50B3853ULL,
		0x88730BB477177D97ULL,
		0x49816D9C0DCA3390ULL,
		0xD13C2A6223799F90ULL,
		0xFC9EBABB6AFF8FE4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B00ECE218DE0979ULL,
		0x8293F2E110EDEE7CULL,
		0xF83F07D55472883AULL,
		0xAC4EA2A42925FBA1ULL,
		0x0DA6B8E7AF732152ULL,
		0xC5FE4B274BFF2951ULL,
		0xA01031786F1732A1ULL,
		0xDFC4190B7BDD1DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF219B86B73155574ULL,
		0x6120D9AC7387D785ULL,
		0x85A0125B5E40726BULL,
		0xAD417DD6B60C3921ULL,
		0x54C5BFFB182A4794ULL,
		0xE041BC96DB955907ULL,
		0xB8E04C36D3F9BD83ULL,
		0x3968BEDD36999D20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48E73476A5C8B405ULL,
		0x217319349D6616F6ULL,
		0x729EF579F63215CFULL,
		0xFF0D24CD7319C280ULL,
		0xB8E0F8EC9748D9BDULL,
		0xE5BC8E907069D049ULL,
		0xE72FE5419B1D751DULL,
		0xA65B5A2E4543808DULL
	}};
	sign = 0;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB21B9F2CF6CC28DULL,
		0x41B81C87F1D0060BULL,
		0x3C6AC1D544BFD3BFULL,
		0xE73F4709701AA111ULL,
		0x10DA6090317FFA32ULL,
		0x5D6D465F4CC4426DULL,
		0x1271B585AB45266DULL,
		0x60A2E0678C3B0319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x370F0200F903C65EULL,
		0x34BC01BE8D4CDE92ULL,
		0x02959C41AB357CD1ULL,
		0x9E58A5C34D976593ULL,
		0x76F2930BF50E7E4EULL,
		0xBA8233C393714737ULL,
		0x81D3371346C80524ULL,
		0x8733103181046FC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC412B7F1D668FC2FULL,
		0x0CFC1AC964832779ULL,
		0x39D52593998A56EEULL,
		0x48E6A14622833B7EULL,
		0x99E7CD843C717BE4ULL,
		0xA2EB129BB952FB35ULL,
		0x909E7E72647D2148ULL,
		0xD96FD0360B369351ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4210D6585BB9DB54ULL,
		0xC93E66B1C5193CC9ULL,
		0x3ADDF6362AFCECCCULL,
		0x4EA46327B46D959BULL,
		0xFE5197BE88022BFEULL,
		0xEC4C10AF066CFDCBULL,
		0x8D91E3BE5B61BEC3ULL,
		0x4E1012A2A97FBC77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46C3BED799D0B610ULL,
		0x452CDC93F8E16715ULL,
		0xBA726578977FFDD9ULL,
		0xD6D610A411DC3B69ULL,
		0x47436914052215ECULL,
		0x3B74DC0FF4D279B4ULL,
		0x2DF1EEE2E5DA1008ULL,
		0x3B37616F37B18E8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB4D1780C1E92544ULL,
		0x84118A1DCC37D5B3ULL,
		0x806B90BD937CEEF3ULL,
		0x77CE5283A2915A31ULL,
		0xB70E2EAA82E01611ULL,
		0xB0D7349F119A8417ULL,
		0x5F9FF4DB7587AEBBULL,
		0x12D8B13371CE2DECULL
	}};
	sign = 0;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81503FAEACBC0EEEULL,
		0x61CE11F81A4DDC13ULL,
		0x8C3E9157A5EE818DULL,
		0x7951F42DA66C12B3ULL,
		0x8C263BD20B558AB1ULL,
		0xFD12EA54F7CE90DEULL,
		0xB4703A2EFFE8640AULL,
		0xDF912A0F90F5FC3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x946DC41DF3754954ULL,
		0xBA4A6C4ACC2AB96FULL,
		0xE9BDE2405032C12CULL,
		0xAD4243ABD1BC2E36ULL,
		0xBD5BA9F9FB46C3A1ULL,
		0x8D277BD1F59BE6FEULL,
		0x038C199FD64D9008ULL,
		0xFFA7676554DE0C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECE27B90B946C59AULL,
		0xA783A5AD4E2322A3ULL,
		0xA280AF1755BBC060ULL,
		0xCC0FB081D4AFE47CULL,
		0xCECA91D8100EC70FULL,
		0x6FEB6E830232A9DFULL,
		0xB0E4208F299AD402ULL,
		0xDFE9C2AA3C17EFC2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9586F8FAC0C099D7ULL,
		0x592E459BF1B731EFULL,
		0x07BB93DD0D097EBBULL,
		0x944CC7B47DF8259CULL,
		0x1B06656F03D84409ULL,
		0xAAE37CC47793E728ULL,
		0xD1B1EF2D71609BD1ULL,
		0x2EEC8FF2902B3603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC02A0BBD00380037ULL,
		0xACE818116EE41D80ULL,
		0x85CB91277B629194ULL,
		0x932E0D656B9B87E8ULL,
		0x39BBA7FC7CB803B7ULL,
		0xD512356A82513837ULL,
		0xAD37922679F9EBA5ULL,
		0x8A2B615AE37CA675ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD55CED3DC08899A0ULL,
		0xAC462D8A82D3146EULL,
		0x81F002B591A6ED26ULL,
		0x011EBA4F125C9DB3ULL,
		0xE14ABD7287204052ULL,
		0xD5D14759F542AEF0ULL,
		0x247A5D06F766B02BULL,
		0xA4C12E97ACAE8F8EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DFE43FBD4C44D5BULL,
		0x8197C9071DB5EF12ULL,
		0xED918F1D4B376FC2ULL,
		0x500FF20E21216E87ULL,
		0xF4CD425995F3C5C0ULL,
		0xEF6463F953D1B59BULL,
		0xD69A2B95FF11AEC7ULL,
		0xA0C8F5790F1E796BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD42210EA400795ULL,
		0x957D9E81C69E7AE5ULL,
		0x59EF7E8A53E970AEULL,
		0xCC65B2D423361D89ULL,
		0xF3C0BD9A1709F924ULL,
		0x924541160E7EA0BFULL,
		0xC07178AA00C99FA1ULL,
		0x0EF516E5D5A8BB97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x202A21EAEA8445C6ULL,
		0xEC1A2A855717742CULL,
		0x93A21092F74DFF13ULL,
		0x83AA3F39FDEB50FEULL,
		0x010C84BF7EE9CC9BULL,
		0x5D1F22E3455314DCULL,
		0x1628B2EBFE480F26ULL,
		0x91D3DE933975BDD4ULL
	}};
	sign = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21BF2400C14E5568ULL,
		0x7F19476E2C3919F0ULL,
		0x3DB6B21AD188D4CFULL,
		0x2B0CA2F0C2039901ULL,
		0x3E744368AEF9B033ULL,
		0x630DC8B8F05475D6ULL,
		0x7C8BB5EEAE82EC17ULL,
		0x92378A2EE25903D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE474228E8251FDF8ULL,
		0x433275657BD300C6ULL,
		0x0D32576531F04197ULL,
		0x5FAC230C0649BDCBULL,
		0x5392319913B06381ULL,
		0x8D4A083C880F86F6ULL,
		0x9EBA78385C55D68DULL,
		0xD477A94A879D6158ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D4B01723EFC5770ULL,
		0x3BE6D208B0661929ULL,
		0x30845AB59F989338ULL,
		0xCB607FE4BBB9DB36ULL,
		0xEAE211CF9B494CB1ULL,
		0xD5C3C07C6844EEDFULL,
		0xDDD13DB6522D1589ULL,
		0xBDBFE0E45ABBA27AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45073456612E6494ULL,
		0xC4A154AB9FCF5481ULL,
		0x526E22FA87BFE4F5ULL,
		0x27E26A7B228B8850ULL,
		0xD63B53D87D8E12DEULL,
		0x9291C5D16D8D0FBCULL,
		0xD781EFCF547E69C5ULL,
		0xEF02E69D2DF01B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3784E158BC8A7DF6ULL,
		0xF5506345100A0A85ULL,
		0x5AF170347BC8A393ULL,
		0x5040CC30B8584218ULL,
		0xBD70C01B154A65C3ULL,
		0xA56BD40D87816B41ULL,
		0x055FD905B103CECEULL,
		0x1CE774B00FAB2783ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D8252FDA4A3E69EULL,
		0xCF50F1668FC549FCULL,
		0xF77CB2C60BF74161ULL,
		0xD7A19E4A6A334637ULL,
		0x18CA93BD6843AD1AULL,
		0xED25F1C3E60BA47BULL,
		0xD22216C9A37A9AF6ULL,
		0xD21B71ED1E44F3CAULL
	}};
	sign = 0;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A3A061F3BE8D2D6ULL,
		0xBFCCFFED6AECB119ULL,
		0x47068F720BBC5F1EULL,
		0x474578E96D8F69B7ULL,
		0x63D7F4420142B366ULL,
		0x05DADD30C61BF4CCULL,
		0xDE39CBB581B02CEDULL,
		0x5F1ED13C0D8AC3B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573CA7FE2340B0C4ULL,
		0xB101DA13DC8586A2ULL,
		0xD1A8AEE36CCC061BULL,
		0x75337A8DF774C4EAULL,
		0xE36DB122E7E0A76AULL,
		0x5F744CA1D911A0E2ULL,
		0xE219120C8A20F695ULL,
		0xDCAEF53EBEDF9296ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02FD5E2118A82212ULL,
		0x0ECB25D98E672A77ULL,
		0x755DE08E9EF05903ULL,
		0xD211FE5B761AA4CCULL,
		0x806A431F19620BFBULL,
		0xA666908EED0A53E9ULL,
		0xFC20B9A8F78F3657ULL,
		0x826FDBFD4EAB311FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74DBC0F03ABB855DULL,
		0x8BAC2BEEBA99D0DBULL,
		0x861DF314DCB3B54DULL,
		0x369C4B889E6F888EULL,
		0x2DF3E533538A1FA0ULL,
		0xD6764F6DBEF12098ULL,
		0x8793E5F88CF7696BULL,
		0x3CA8E7D4395EAA1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE685D542D6FAF304ULL,
		0x56217A25AB89B662ULL,
		0xC0272A503D4631DBULL,
		0x9FF081CD4D5006D8ULL,
		0x3E871FE1CA1C8A50ULL,
		0x036C1FFFC92D13E9ULL,
		0xBBD1B0B5B47A5F38ULL,
		0xDB4D42A9AA52006DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E55EBAD63C09259ULL,
		0x358AB1C90F101A78ULL,
		0xC5F6C8C49F6D8372ULL,
		0x96ABC9BB511F81B5ULL,
		0xEF6CC551896D954FULL,
		0xD30A2F6DF5C40CAEULL,
		0xCBC23542D87D0A33ULL,
		0x615BA52A8F0CA9ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2EB27CDBFC2EA13ULL,
		0x6A4CB3403D19F73AULL,
		0x7E699C6E23941950ULL,
		0x2B430791D679D75EULL,
		0xDA93C2F812E39796ULL,
		0xFE722A93B2F532B4ULL,
		0xF8E8D1A5AEA053FFULL,
		0x1AA81EA3CF1A4A12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69937B8DE117A2FULL,
		0xCAAEC28D2B5F0697ULL,
		0xF36B6014D73C3336ULL,
		0x77DACB5EE8659485ULL,
		0x0A20F3263E842289ULL,
		0xC9371652E8909C2CULL,
		0x078F88436756E37DULL,
		0x2400CF07B6735C45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC51F014E1B16FE4ULL,
		0x9F9DF0B311BAF0A2ULL,
		0x8AFE3C594C57E619ULL,
		0xB3683C32EE1442D8ULL,
		0xD072CFD1D45F750CULL,
		0x353B1440CA649688ULL,
		0xF159496247497082ULL,
		0xF6A74F9C18A6EDCDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDA4E43A4D23FBD1ULL,
		0xA8685F8F0BD2DCBAULL,
		0xF50E6C85FAC0FE7CULL,
		0x60C7E7B5185A0C24ULL,
		0x89342DE381A5B6E5ULL,
		0x775446A137476A5DULL,
		0xDB384FFFA771FB53ULL,
		0xEB28B37CBAF86B7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9758EF130C0F091ULL,
		0x4C8ED071D96AEF43ULL,
		0x8BBB876BC87C6319ULL,
		0x02A75B3B7547B388ULL,
		0x4868BC87F44E88E1ULL,
		0x4FE25D4BDE88B523ULL,
		0xE426B747C84AE7B3ULL,
		0x7F325F64DE88191DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x042F55491C630B40ULL,
		0x5BD98F1D3267ED77ULL,
		0x6952E51A32449B63ULL,
		0x5E208C79A312589CULL,
		0x40CB715B8D572E04ULL,
		0x2771E95558BEB53AULL,
		0xF71198B7DF2713A0ULL,
		0x6BF65417DC70525CULL
	}};
	sign = 0;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7B31B2113F8FB01ULL,
		0xEA5A5E0905CF62A9ULL,
		0xF6FB17499E131BE1ULL,
		0xC061AE15E3D4E058ULL,
		0xC8AAA6A4E8609D8CULL,
		0x2AD6CE6C35F0680FULL,
		0x00C4BFD45B8CEBCEULL,
		0x13F0F0833DF419F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28E1BCC5A45BBD8AULL,
		0x715B42B035EB03F6ULL,
		0x5DEEA673CCCFF9AAULL,
		0x5CA9764049D30C53ULL,
		0xCBD133B0FCCB9F09ULL,
		0xFCE2DAF37DBABBE2ULL,
		0x8174A44A8BEB1948ULL,
		0xD03D5AE16FF402BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ED15E5B6F9D3D77ULL,
		0x78FF1B58CFE45EB3ULL,
		0x990C70D5D1432237ULL,
		0x63B837D59A01D405ULL,
		0xFCD972F3EB94FE83ULL,
		0x2DF3F378B835AC2CULL,
		0x7F501B89CFA1D285ULL,
		0x43B395A1CE00173BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1DB6D07A7D5FC06ULL,
		0xBEDC205BD02B15AEULL,
		0xED159BACDCCFBBD7ULL,
		0x3A4AAA2EE1FE414CULL,
		0x1EC8F030FEAFB86BULL,
		0x0D32F009290F95D0ULL,
		0x5DDDE20A1BDB68A1ULL,
		0x3681A2F1F1068463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53ECBD6E918FFE70ULL,
		0xBCC7ED5EA1B9750AULL,
		0x8CBC9E58BDAF3DD4ULL,
		0x130F232789729626ULL,
		0x6CD527E439FD8CF4ULL,
		0xBD2403D9BA07FD29ULL,
		0x76FFFB03D70B6828ULL,
		0xF55C5E37C1A7CA74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DEEAF991645FD96ULL,
		0x021432FD2E71A0A4ULL,
		0x6058FD541F207E03ULL,
		0x273B8707588BAB26ULL,
		0xB1F3C84CC4B22B77ULL,
		0x500EEC2F6F0798A6ULL,
		0xE6DDE70644D00078ULL,
		0x412544BA2F5EB9EEULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4C648A5B8E6690FULL,
		0x60DAD0CB68DF8082ULL,
		0x36456EC08B2E9EE9ULL,
		0xF4FDC7FC23B8F86BULL,
		0x3977ACB838A387B1ULL,
		0x6A48A538D9911201ULL,
		0xB721E3C68388559CULL,
		0x63DCE0E0D03FE0C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB44FD4E31FF66CD3ULL,
		0xB928723F098B3B28ULL,
		0x664BD1A6DEF2431CULL,
		0x1187F7DA395DD486ULL,
		0x51B5D0EEA911895FULL,
		0x663025E2F131997CULL,
		0xACA39736ADD5B0C2ULL,
		0xF59AFC9A28871405ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x307673C298EFFC3CULL,
		0xA7B25E8C5F54455AULL,
		0xCFF99D19AC3C5BCCULL,
		0xE375D021EA5B23E4ULL,
		0xE7C1DBC98F91FE52ULL,
		0x04187F55E85F7884ULL,
		0x0A7E4C8FD5B2A4DAULL,
		0x6E41E446A7B8CCBCULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47CA0C7862E0B5C5ULL,
		0x1B82874F659FBE18ULL,
		0x9F48C5C20ABD1513ULL,
		0xB400710E3F16694AULL,
		0xF9E57DCBDDE34702ULL,
		0x04C873AEB1115C7DULL,
		0xD69B10CD333366FEULL,
		0xCA1A21AD0199EA04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x224F5393EC46909BULL,
		0x55BB9DFD49543950ULL,
		0x44FCB228F0AD0012ULL,
		0xB718A95D7D74EC10ULL,
		0xA04DC6E7803B78FEULL,
		0x607498F153F21DDEULL,
		0xF76AC9CE99CD2039ULL,
		0xD49BBCDE9E54BA5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x257AB8E4769A252AULL,
		0xC5C6E9521C4B84C8ULL,
		0x5A4C13991A101500ULL,
		0xFCE7C7B0C1A17D3AULL,
		0x5997B6E45DA7CE03ULL,
		0xA453DABD5D1F3E9FULL,
		0xDF3046FE996646C4ULL,
		0xF57E64CE63452FA8ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB6B06A37547934CULL,
		0x70B41BC96E4DE92FULL,
		0xDB0A93B8D2E4BB89ULL,
		0x80A4B85977143701ULL,
		0xA23969CAF39C103FULL,
		0xE0DC61C421C94A71ULL,
		0xED881BCB43E93948ULL,
		0xB4ED58AC0797755EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAF8960C456F6CAULL,
		0x9600EF28B4E7F9E4ULL,
		0x4FA305E033CAA97FULL,
		0xB595150FF46EAFFFULL,
		0x279493655780E97FULL,
		0xCC7AD32F31B2C8E8ULL,
		0xFDBE5191ABE1EB40ULL,
		0xF9865B3EC87326C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCBB7D42B0F09C82ULL,
		0xDAB32CA0B965EF4BULL,
		0x8B678DD89F1A1209ULL,
		0xCB0FA34982A58702ULL,
		0x7AA4D6659C1B26BFULL,
		0x14618E94F0168189ULL,
		0xEFC9CA3998074E08ULL,
		0xBB66FD6D3F244E98ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5AF92F4C088488EULL,
		0x093D871CF0FBBD02ULL,
		0xE5FCFA9A2766F6A3ULL,
		0xB8B9F72184940D43ULL,
		0xC3BF81EF920EC77BULL,
		0xCC6BBEC769AB29D2ULL,
		0x3E1AE2CFDDE2AF61ULL,
		0x19302C436B142F45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D1C68A752598DA1ULL,
		0xD9D64F7A5F433263ULL,
		0x2DDD338142A29969ULL,
		0xD9BEDB9BADC5DC43ULL,
		0x7AF652406FC6533CULL,
		0xA7D309BC59A9744BULL,
		0x1FA493B0B88B6B42ULL,
		0xE9338F67C9CF1C0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98932A4D6E2EBAEDULL,
		0x2F6737A291B88A9FULL,
		0xB81FC718E4C45D39ULL,
		0xDEFB1B85D6CE3100ULL,
		0x48C92FAF2248743EULL,
		0x2498B50B1001B587ULL,
		0x1E764F1F2557441FULL,
		0x2FFC9CDBA1451338ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8245FC6F950344F5ULL,
		0x06B834C98A9C50BBULL,
		0x91F3F2405A94FEAFULL,
		0x58557A5715673B0EULL,
		0x9C5E155D3C61A2D4ULL,
		0x60E7576F9BAAAD07ULL,
		0x8EC5199A1CC2764EULL,
		0x25BACEB20146A4B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE783F5A047CE4A0ULL,
		0x1BAA47165727838DULL,
		0x9AEE7095E743B607ULL,
		0x11D4EDF5C1C22D78ULL,
		0xC19B8A70395E111EULL,
		0x3143C0674972D0C2ULL,
		0xDA6F5BAB5E10388EULL,
		0xB723D183122B2B43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3CDBD1590866055ULL,
		0xEB0DEDB33374CD2DULL,
		0xF70581AA735148A7ULL,
		0x46808C6153A50D95ULL,
		0xDAC28AED030391B6ULL,
		0x2FA397085237DC44ULL,
		0xB455BDEEBEB23DC0ULL,
		0x6E96FD2EEF1B7973ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71D2A2DFEE6649FEULL,
		0x62EC5F5CFADC65AFULL,
		0xADAE0CDD24502219ULL,
		0xA71706574FE90434ULL,
		0xDF5B445B7F11F841ULL,
		0x63D89BD5033D8513ULL,
		0xE83DDA6A041B1C35ULL,
		0xE8289100A0090748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D760473C734F7B9ULL,
		0x7F898C6D768FE4F7ULL,
		0xFFEE64CAE3086652ULL,
		0xA11A935145B34691ULL,
		0x7948216B60E69576ULL,
		0xD35C8C17B9C06636ULL,
		0xBC487E728B49A761ULL,
		0xECC83D5168E90145ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x645C9E6C27315245ULL,
		0xE362D2EF844C80B8ULL,
		0xADBFA8124147BBC6ULL,
		0x05FC73060A35BDA2ULL,
		0x661322F01E2B62CBULL,
		0x907C0FBD497D1EDDULL,
		0x2BF55BF778D174D3ULL,
		0xFB6053AF37200603ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1613753F6171477DULL,
		0x431E7E40F4339F59ULL,
		0x62CACE8E67C8F893ULL,
		0x4BA00E0ABA1DABA8ULL,
		0xAA5E9CD578BA8E6BULL,
		0x13FBEF894E3354F3ULL,
		0xD88D953A717E0E13ULL,
		0xE58FAF5667586659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12665DD41216A28ULL,
		0xCCC3F92270E07814ULL,
		0x76437BBF970AFAF0ULL,
		0x67B1C925CFB37F60ULL,
		0xFD9A23FB5C30B1A8ULL,
		0x53F7E861623F03A0ULL,
		0x4E58A0BC98D9A62BULL,
		0x49EA63569F9E4690ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74ED0F62204FDD55ULL,
		0x765A851E83532744ULL,
		0xEC8752CED0BDFDA2ULL,
		0xE3EE44E4EA6A2C47ULL,
		0xACC478DA1C89DCC2ULL,
		0xC0040727EBF45152ULL,
		0x8A34F47DD8A467E7ULL,
		0x9BA54BFFC7BA1FC9ULL
	}};
	sign = 0;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x771BC97B2D05EF95ULL,
		0x7961F76081B3944DULL,
		0x7366D5DE7D979983ULL,
		0x3DBF26C237C3B167ULL,
		0x67E7D50048FB3BF4ULL,
		0x9DBA813C446E9DA9ULL,
		0xF9705C7A814770C7ULL,
		0x8C1ADC259A745C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E47D911E3BB75C7ULL,
		0x09EC26AC353137EDULL,
		0xE138280D313B09BEULL,
		0xA604245E6E8C8B58ULL,
		0x3855BEECC3012461ULL,
		0xE440BF8F720142ACULL,
		0x0DB9B003E6A6FC8EULL,
		0x838B3F2E27797CA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8D3F069494A79CEULL,
		0x6F75D0B44C825C5FULL,
		0x922EADD14C5C8FC5ULL,
		0x97BB0263C937260EULL,
		0x2F92161385FA1792ULL,
		0xB979C1ACD26D5AFDULL,
		0xEBB6AC769AA07438ULL,
		0x088F9CF772FADFE6ULL
	}};
	sign = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A6B0C2142A6D78DULL,
		0xE9AC7A953E0ADC92ULL,
		0x5236E9FD5FCF83C2ULL,
		0x6602F827CF7DC4B8ULL,
		0x15DF61B8D5DD8F4CULL,
		0xD9C10F3530FE0DD8ULL,
		0x7E27028A9058F0EBULL,
		0x924D0C01F7B99023ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6622EBE3C6D2B2EBULL,
		0x06F91686591F4169ULL,
		0xA16056C9A2F43E91ULL,
		0xEB24DBC2D7A2A14EULL,
		0x85BF38BD61967696ULL,
		0xBC7EF35EBD2D8558ULL,
		0x63740975B6AE510FULL,
		0x64D830B18D49A0C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA448203D7BD424A2ULL,
		0xE2B3640EE4EB9B28ULL,
		0xB0D69333BCDB4531ULL,
		0x7ADE1C64F7DB2369ULL,
		0x902028FB744718B5ULL,
		0x1D421BD673D0887FULL,
		0x1AB2F914D9AA9FDCULL,
		0x2D74DB506A6FEF61ULL
	}};
	sign = 0;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1FADDC2A8B2BA72ULL,
		0x29EEA6F6D412A990ULL,
		0x498DD9B34CDEEA99ULL,
		0x09F9AFF6B2EB03E3ULL,
		0xAB5789DDBAF9941AULL,
		0x4E617C04039910DAULL,
		0xCCE2D915706FD9A8ULL,
		0x80CA04B318A4D29CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BB690173C02D0EDULL,
		0x9C73D736C941CF66ULL,
		0x73F638989711979FULL,
		0x17CC4A88FBE0598AULL,
		0x09245CCB125E9F81ULL,
		0x74AF377951E64F64ULL,
		0x06A0B921746E1A7BULL,
		0x527E2C32C13CA21AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6444DAB6CAFE985ULL,
		0x8D7ACFC00AD0DA2AULL,
		0xD597A11AB5CD52F9ULL,
		0xF22D656DB70AAA58ULL,
		0xA2332D12A89AF498ULL,
		0xD9B2448AB1B2C176ULL,
		0xC6421FF3FC01BF2CULL,
		0x2E4BD88057683082ULL
	}};
	sign = 0;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF1D00421ED3EC18ULL,
		0xC59A5F6C94A23122ULL,
		0x1F4ADCA0B1FF6A8AULL,
		0x758B3D5DBD51D750ULL,
		0x04D6A9C204F77291ULL,
		0xA339B05295F1F5E4ULL,
		0xA5D8A85230DE1942ULL,
		0xF6D281181B458BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0A1C057E344D6DAULL,
		0x0C094572559E4610ULL,
		0x4AA295BC46775948ULL,
		0x11DE50E8D5EF4B7BULL,
		0xB3547290B0E1F3FBULL,
		0x48A127ED2E16C261ULL,
		0x95855316946D4A3FULL,
		0x8C2FCCE0E54AD236ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE7B3FEA3B8F153EULL,
		0xB99119FA3F03EB11ULL,
		0xD4A846E46B881142ULL,
		0x63ACEC74E7628BD4ULL,
		0x5182373154157E96ULL,
		0x5A98886567DB3382ULL,
		0x1053553B9C70CF03ULL,
		0x6AA2B43735FAB977ULL
	}};
	sign = 0;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EC595A7E7C20F12ULL,
		0xC27D2349BE45E79CULL,
		0xF086159F380C7AC5ULL,
		0xD65B1A6F761C6C0FULL,
		0xD167C6D7ADEC303BULL,
		0x9B4B001752915EACULL,
		0x15E601E3939E4A3FULL,
		0x52A93B89E5067DF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30B0C97C1FC9922EULL,
		0xA5A9B5C3981C658FULL,
		0xB13BFBC3265C2228ULL,
		0xD434365CC0520931ULL,
		0x819A494F1DEB6A6EULL,
		0x0ACA33E046A9F99EULL,
		0xF7D2C6C1AD457521ULL,
		0xB703B57C1805C0EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E14CC2BC7F87CE4ULL,
		0x1CD36D862629820DULL,
		0x3F4A19DC11B0589DULL,
		0x0226E412B5CA62DEULL,
		0x4FCD7D889000C5CDULL,
		0x9080CC370BE7650EULL,
		0x1E133B21E658D51EULL,
		0x9BA5860DCD00BD03ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF80492518C3B0737ULL,
		0x4CE41F6B3902889FULL,
		0x5159706BD8545FA3ULL,
		0x601EACB59E5B63C2ULL,
		0xD86BEEEE1F6D9ADAULL,
		0x633F7B86917147F9ULL,
		0x468639E2B7E9143CULL,
		0x4DECF0AE6F83B661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30AD13119BFCE498ULL,
		0x341F6D7E66084089ULL,
		0xC789E106B3D908A8ULL,
		0xD4FFF578AE1F1C40ULL,
		0x6910D216C42ECC91ULL,
		0xE7A06B0362E8FB1EULL,
		0xF92C525546EBEA54ULL,
		0x613E54DF98728532ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7577F3FF03E229FULL,
		0x18C4B1ECD2FA4816ULL,
		0x89CF8F65247B56FBULL,
		0x8B1EB73CF03C4781ULL,
		0x6F5B1CD75B3ECE48ULL,
		0x7B9F10832E884CDBULL,
		0x4D59E78D70FD29E7ULL,
		0xECAE9BCED711312EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D98DBD3500BEA37ULL,
		0xD53899D6E9F1E21EULL,
		0xE244AD43264BEA6DULL,
		0x0B4602F16E0C1114ULL,
		0x8078DD68A38E2DF5ULL,
		0x936DB110406552D9ULL,
		0x32E934F8660F5768ULL,
		0xAEB15EF659A7D1D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40E387AFE33C97DEULL,
		0xD65EE806468B3F51ULL,
		0xBB1D13C8AAF4F1F9ULL,
		0x57D10B9446772313ULL,
		0x1346FA781B779B69ULL,
		0x77556838ACAF8441ULL,
		0x96E0BEB48EE8EDFAULL,
		0xD45EEC00B2ACAF8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CB554236CCF5259ULL,
		0xFED9B1D0A366A2CDULL,
		0x2727997A7B56F873ULL,
		0xB374F75D2794EE01ULL,
		0x6D31E2F08816928BULL,
		0x1C1848D793B5CE98ULL,
		0x9C087643D726696EULL,
		0xDA5272F5A6FB2248ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA94CBD3166D16A0ULL,
		0xAC6189587F917468ULL,
		0x2AF17A8FB55261A4ULL,
		0xB5AE150D6748134AULL,
		0xF18DB76EEDD66ACEULL,
		0x6651AA597D124657ULL,
		0x1B2CE9E088995B1AULL,
		0x19431AB618D73164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171FBDAD8449091EULL,
		0xB9CD4F63AFD7B114ULL,
		0xFC2E6229BA15058CULL,
		0xC9A3B7F03C7CF456ULL,
		0xC2FF6ED689BD2182ULL,
		0xCFAD97E1610EC1ADULL,
		0x4290D8E728295DFDULL,
		0x1A1F8C7D3C5BC076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3750E2592240D82ULL,
		0xF29439F4CFB9C354ULL,
		0x2EC31865FB3D5C17ULL,
		0xEC0A5D1D2ACB1EF3ULL,
		0x2E8E48986419494BULL,
		0x96A412781C0384AAULL,
		0xD89C10F9606FFD1CULL,
		0xFF238E38DC7B70EDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67A782D4C23EB81AULL,
		0xE96817F2F8370A1EULL,
		0x3B93B632A7E69E2EULL,
		0xD2113C57FE60003EULL,
		0x6C0CC17C06F564EDULL,
		0x7BA6410891B78358ULL,
		0x25710187AD926582ULL,
		0x8FFE187A0EAC491AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x839DB95DAE1219B5ULL,
		0xE03DFECA432D3870ULL,
		0xE02BAE44330B4253ULL,
		0xE4FB7A4C545D2186ULL,
		0x6755F77EDD94A6DAULL,
		0x23816FF8A7CCA3BFULL,
		0x7D07FCB8859C0ABAULL,
		0x014347A83138FC4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE409C977142C9E65ULL,
		0x092A1928B509D1ADULL,
		0x5B6807EE74DB5BDBULL,
		0xED15C20BAA02DEB7ULL,
		0x04B6C9FD2960BE12ULL,
		0x5824D10FE9EADF99ULL,
		0xA86904CF27F65AC8ULL,
		0x8EBAD0D1DD734CCEULL
	}};
	sign = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x466C042B817DB778ULL,
		0xDD08B8209E767F89ULL,
		0x11A0BFFB2E3BA09CULL,
		0xC60943F1818BCFBBULL,
		0x4B836EBD9B4B291CULL,
		0x2A4F302A1D20C846ULL,
		0xD78B1C3B9C0228D8ULL,
		0x66FFF949F69FC5B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B6BEFFA856D151ULL,
		0x1863889350549A57ULL,
		0x52AAE005E6472741ULL,
		0x3F4D8287A80C91A2ULL,
		0x9CE2928C04174B37ULL,
		0xEC209DD042712F5DULL,
		0xF6BB3551DDBE3935ULL,
		0xB51C5C3772641F90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2B5452BD926E627ULL,
		0xC4A52F8D4E21E531ULL,
		0xBEF5DFF547F4795BULL,
		0x86BBC169D97F3E18ULL,
		0xAEA0DC319733DDE5ULL,
		0x3E2E9259DAAF98E8ULL,
		0xE0CFE6E9BE43EFA2ULL,
		0xB1E39D12843BA620ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5B062BCD40374DFULL,
		0x652B4EAC89C52FF5ULL,
		0xA987FD4794418D17ULL,
		0xEA0C5A0FA0278F4AULL,
		0x0015B901337185A0ULL,
		0xACDDAF42C3843B47ULL,
		0xDE4528DF41B13B75ULL,
		0x89751517219F4DE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE94E7242A9A0216AULL,
		0xEDDE720E209D564DULL,
		0x31673A38083B76CAULL,
		0x5C52690BC4954C5AULL,
		0x2B5B3AAF41B129F6ULL,
		0x6604D19420B6FFD7ULL,
		0x37D5EE53973D7D38ULL,
		0x45D5911F823C52B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC61F07A2A635375ULL,
		0x774CDC9E6927D9A7ULL,
		0x7820C30F8C06164CULL,
		0x8DB9F103DB9242F0ULL,
		0xD4BA7E51F1C05BAAULL,
		0x46D8DDAEA2CD3B6FULL,
		0xA66F3A8BAA73BE3DULL,
		0x439F83F79F62FB31ULL
	}};
	sign = 0;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x839BB88D3C676A19ULL,
		0x543BC2E0D5F6992CULL,
		0xB5E096EF060D4258ULL,
		0x9995AE7ED971CDBFULL,
		0x29C7DDF617F028A9ULL,
		0x3F78308E636DC04EULL,
		0x9F69317282A8B5EFULL,
		0x05BF0CC7B23684BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3D7BE7A787F183ULL,
		0x47A2AE0F1A6B8206ULL,
		0xBABAE836543A186AULL,
		0x1C0C4A15F319DF31ULL,
		0x1C8C6046821FEC4BULL,
		0xAB5610631E93D95EULL,
		0x4C577AF98B59CC01ULL,
		0x736C8B6236BC9F15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x345E3CA594DF7896ULL,
		0x0C9914D1BB8B1726ULL,
		0xFB25AEB8B1D329EEULL,
		0x7D896468E657EE8DULL,
		0x0D3B7DAF95D03C5EULL,
		0x9422202B44D9E6F0ULL,
		0x5311B678F74EE9EDULL,
		0x925281657B79E5AAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x895DC643B223C637ULL,
		0x82018026E38978A9ULL,
		0xD0C82119DA25B9A2ULL,
		0x387D73658E4D107AULL,
		0x5D470798E71DD7D2ULL,
		0xDA0A7DF6E4B2BFD6ULL,
		0xE80D81E8BD9929CCULL,
		0xB4D0AFA08616FE35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B637B43494067D9ULL,
		0xEA1E7B386316822EULL,
		0x7FCD3FFA8C8BF9F0ULL,
		0xE791487F5A339B54ULL,
		0x7E5156686624D416ULL,
		0x30B79688351E2F1CULL,
		0x38A9E3201C64FC85ULL,
		0xE6CBBE4B22B6D6C4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DFA4B0068E35E5EULL,
		0x97E304EE8072F67BULL,
		0x50FAE11F4D99BFB1ULL,
		0x50EC2AE634197526ULL,
		0xDEF5B13080F903BBULL,
		0xA952E76EAF9490B9ULL,
		0xAF639EC8A1342D47ULL,
		0xCE04F15563602771ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2EA8AF8ED1A02E9ULL,
		0xA7D2C59120AD57C1ULL,
		0xEF491A98BD020EEFULL,
		0xA728AA31772F044EULL,
		0xBEB0BBA30BCE75A0ULL,
		0x132381C50282D27EULL,
		0x6E320A17E459CAA6ULL,
		0x19DFB62B78B24350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770AA14E0B618196ULL,
		0xACC0B7B654B16961ULL,
		0x15F1190879EC29ADULL,
		0xBD4E85E3209A2F79ULL,
		0xFB6C4D40F28BCCF4ULL,
		0xA1A7D90D8A90208AULL,
		0x478E8671274CC846ULL,
		0xAF8605ADCB1FF336ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4BDFE9AAE1B88153ULL,
		0xFB120DDACBFBEE60ULL,
		0xD95801904315E541ULL,
		0xE9DA244E5694D4D5ULL,
		0xC3446E621942A8ABULL,
		0x717BA8B777F2B1F3ULL,
		0x26A383A6BD0D025FULL,
		0x6A59B07DAD92501AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x908A0688A7555F59ULL,
		0xA72D88AC91D2E8A3ULL,
		0xE70A5AA85197D958ULL,
		0x7CE1C3B0E2A1DC65ULL,
		0x797358D5D6475A91ULL,
		0x81EF372C0F8D42F3ULL,
		0x27FCBAC23E122ECAULL,
		0xDF1A79FDB6822691ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F4FEF240988838ULL,
		0x991D05D3A4B79A70ULL,
		0xC4668F9A997E9008ULL,
		0xD6ED3CDE092EE62AULL,
		0x2ED8713E932B884AULL,
		0xFDA8119785BBD4CFULL,
		0xA831457FE9137C39ULL,
		0x0A48B60310318A44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1895079666BCD721ULL,
		0x0E1082D8ED1B4E33ULL,
		0x22A3CB0DB8194950ULL,
		0xA5F486D2D972F63BULL,
		0x4A9AE797431BD246ULL,
		0x8447259489D16E24ULL,
		0x7FCB754254FEB290ULL,
		0xD4D1C3FAA6509C4CULL
	}};
	sign = 0;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4422F40F0B0F1B25ULL,
		0x0ACD4CE9971DE269ULL,
		0xCD917705C7FE21C6ULL,
		0xBEE636A84C776F49ULL,
		0x9CA78E84BA4BFB04ULL,
		0xE209D10E3E885B29ULL,
		0x42BDFCFF953CF5CFULL,
		0x03FD5B4F4F37DE0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFE33D9E90FE69A2ULL,
		0x1E5716999C837F85ULL,
		0xB9BBDC2FB6ED59FAULL,
		0xA217BEA1080A4980ULL,
		0x63A30CECEC5435DBULL,
		0x994C0AE92A49DA4EULL,
		0x17E9203F8AF2CAF3ULL,
		0x63584719E7426A0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x843FB6707A10B183ULL,
		0xEC76364FFA9A62E3ULL,
		0x13D59AD61110C7CBULL,
		0x1CCE7807446D25C9ULL,
		0x39048197CDF7C529ULL,
		0x48BDC625143E80DBULL,
		0x2AD4DCC00A4A2ADCULL,
		0xA0A5143567F573FBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08EAF96F7DA3B961ULL,
		0x63314E02BCFCE0C9ULL,
		0xDD770D192A6A6B98ULL,
		0x8463BF2C5758914EULL,
		0x0BC8A13275649DF4ULL,
		0xFF96CA9B3EF728A3ULL,
		0xAA006F31F2F2EBC4ULL,
		0xFE36CDCF8DB97ECBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CCEE6BB77902B1ULL,
		0xA6F973367D6D4997ULL,
		0x70A7EDC9626D81DEULL,
		0x22F364C3B413052EULL,
		0xA7CD5BAD36D225F7ULL,
		0xD33CCE8BA1E15707ULL,
		0x850B7570BC45FA39ULL,
		0x1B42E2DCEDE75E06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F1E0B03C62AB6B0ULL,
		0xBC37DACC3F8F9731ULL,
		0x6CCF1F4FC7FCE9B9ULL,
		0x61705A68A3458C20ULL,
		0x63FB45853E9277FDULL,
		0x2C59FC0F9D15D19BULL,
		0x24F4F9C136ACF18BULL,
		0xE2F3EAF29FD220C5ULL
	}};
	sign = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x165EDCBC682BF2DEULL,
		0xC86DE1EFA9FBD3B9ULL,
		0x9FAE64EB4081A82EULL,
		0x0FEB0150EB5CACB8ULL,
		0x975BC65A783AC4EAULL,
		0xCEAC389BC9DD4C69ULL,
		0x86AC38E083BC6373ULL,
		0xF34B173821AE42FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBEF12F6EE6E7340ULL,
		0xFD0495CCFBE5A6C9ULL,
		0xAA108E89BAFBCDBDULL,
		0x9BA2E0AE00A3BA18ULL,
		0xC7812E3819E41DD7ULL,
		0x266AD2599DC6703FULL,
		0x6C6FFE8D30F3207EULL,
		0x29922CA9C2E538E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A6FC9C579BD7F9EULL,
		0xCB694C22AE162CEFULL,
		0xF59DD6618585DA70ULL,
		0x744820A2EAB8F29FULL,
		0xCFDA98225E56A712ULL,
		0xA84166422C16DC29ULL,
		0x1A3C3A5352C942F5ULL,
		0xC9B8EA8E5EC90A1BULL
	}};
	sign = 0;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB15B228F793862B6ULL,
		0x0ACD6CFB4F581BBBULL,
		0x1C925DCB22750467ULL,
		0x3512ACB12F49E477ULL,
		0x48CADC72CBCD2FF1ULL,
		0x8E8F55A68ABE139DULL,
		0x15D9F8D5A7645BA7ULL,
		0xAD8DACBFD14430F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x300D95129F9485D0ULL,
		0x3443DD829454CB77ULL,
		0x5D83EDE2C57AEA21ULL,
		0xDA4997DD3F0086D6ULL,
		0x135AEC17C4E26948ULL,
		0x18BE078C08811204ULL,
		0xD54495ACA2692F7AULL,
		0x044C9FBDE6BB300BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x814D8D7CD9A3DCE6ULL,
		0xD6898F78BB035044ULL,
		0xBF0E6FE85CFA1A45ULL,
		0x5AC914D3F0495DA0ULL,
		0x356FF05B06EAC6A8ULL,
		0x75D14E1A823D0199ULL,
		0x4095632904FB2C2DULL,
		0xA9410D01EA8900E4ULL
	}};
	sign = 0;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB4A4237BA6B04BCULL,
		0xF2C7205ED2F3428CULL,
		0x80FBE733FDB541AEULL,
		0x14B3251C3EC15732ULL,
		0x5881C19E8235EBE1ULL,
		0x3E4C04C8B69E5EDAULL,
		0xE62F27437B94CA70ULL,
		0x568101292BF9E555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E0F591D21D6872ULL,
		0x52C54E82E45E031FULL,
		0x75305C2C7CA4A2B8ULL,
		0xB49BC6D877FD549FULL,
		0xC045025995A0FF5DULL,
		0x336A4C8EADA81D58ULL,
		0x3433175D762FB9ADULL,
		0x9D33120449509FA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6694CA5E84D9C4AULL,
		0xA001D1DBEE953F6DULL,
		0x0BCB8B0781109EF6ULL,
		0x60175E43C6C40293ULL,
		0x983CBF44EC94EC83ULL,
		0x0AE1B83A08F64181ULL,
		0xB1FC0FE6056510C3ULL,
		0xB94DEF24E2A945B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB93A8D4D2021ACAULL,
		0x71AC0E7559CF4368ULL,
		0x8BAF29BC40B947C4ULL,
		0xCCAA9095F120564BULL,
		0x24AB63F00BF832C1ULL,
		0xB1EB853328DA1A0BULL,
		0xF03B292EE5CAD8C2ULL,
		0xF6B3E48E2E5D707CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110B74B6EDE1A17EULL,
		0xB132495A59F36E96ULL,
		0xD466CB2756385EF3ULL,
		0xF0EB2F787510B8D1ULL,
		0xEB9391C133706646ULL,
		0x192554689C22B513ULL,
		0xBDD07FB526AD9471ULL,
		0xBFD0DA0E9E68B37EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA88341DE420794CULL,
		0xC079C51AFFDBD4D2ULL,
		0xB7485E94EA80E8D0ULL,
		0xDBBF611D7C0F9D79ULL,
		0x3917D22ED887CC7AULL,
		0x98C630CA8CB764F7ULL,
		0x326AA979BF1D4451ULL,
		0x36E30A7F8FF4BCFEULL
	}};
	sign = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x154926B49FE024D6ULL,
		0xD8B197FF63612441ULL,
		0x144D7F5E59040FE3ULL,
		0x9F3D1402D440517BULL,
		0xB44938165B2B8DC9ULL,
		0xC7B349BE94EB729BULL,
		0x2D35EF95ACF90D63ULL,
		0x63AE640A1CE0456CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0914623E6484B7C2ULL,
		0xE3A360E800661924ULL,
		0xF7C3B8083F3C7D28ULL,
		0x358E9A2F896C6242ULL,
		0x0DE7620653FAEEB0ULL,
		0x6657CE45B56523BBULL,
		0x8AF4B006F895CDB2ULL,
		0xA11E8DC54DFAFACAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C34C4763B5B6D14ULL,
		0xF50E371762FB0B1DULL,
		0x1C89C75619C792BAULL,
		0x69AE79D34AD3EF38ULL,
		0xA661D61007309F19ULL,
		0x615B7B78DF864EE0ULL,
		0xA2413F8EB4633FB1ULL,
		0xC28FD644CEE54AA1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FE63AAA0DA9CCADULL,
		0x7B643F9B33169D88ULL,
		0x302671D76E48D5E7ULL,
		0x783E063D94F2E552ULL,
		0xBB94CF360F69487AULL,
		0x07635AB7BEE06249ULL,
		0x6BB4E745FB6A1E3AULL,
		0x9A49BF8D449DEDBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02AEC7E9F787D87AULL,
		0xA9230CA6C57D8823ULL,
		0x0D18A6E199B80531ULL,
		0xC83F969895D85CECULL,
		0x57FE9231BF1F943DULL,
		0x49AE6B5FA594560FULL,
		0x9ACC6DD13FF1C723ULL,
		0x0CAD69E810298AAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D3772C01621F433ULL,
		0xD24132F46D991565ULL,
		0x230DCAF5D490D0B5ULL,
		0xAFFE6FA4FF1A8866ULL,
		0x63963D045049B43CULL,
		0xBDB4EF58194C0C3AULL,
		0xD0E87974BB785716ULL,
		0x8D9C55A53474630DULL
	}};
	sign = 0;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AD7C05839D6E84FULL,
		0x8027372ABB48CE25ULL,
		0x9E9157524F1EEE18ULL,
		0x8948FC7147BCBDE7ULL,
		0xEED0A2DEF441CC7FULL,
		0x13497AEDD21A6110ULL,
		0x69E911D6ACD8DB44ULL,
		0x45EBE5F326C486B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D2F56E14B0D95F9ULL,
		0x5089E5E7F0753234ULL,
		0x54D4CE74EC70865BULL,
		0x4891D6C16B7A8BEAULL,
		0xB3DE749046D53892ULL,
		0xBEB3048393681FCEULL,
		0x929E7541AFCA7F61ULL,
		0x5CBC7DE9D33A31DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDDA86976EEC95256ULL,
		0x2F9D5142CAD39BF0ULL,
		0x49BC88DD62AE67BDULL,
		0x40B725AFDC4231FDULL,
		0x3AF22E4EAD6C93EDULL,
		0x5496766A3EB24142ULL,
		0xD74A9C94FD0E5BE2ULL,
		0xE92F6809538A54D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D5EFEA5636F7A41ULL,
		0x1062B4D3250BFE13ULL,
		0x4ED64AE9EF524879ULL,
		0xA7EB627E73FC6FAAULL,
		0x2DA8B15627E1162CULL,
		0xE48650FDC2DDAB7DULL,
		0xCB8EB64AF982187FULL,
		0x74AA35A343BAFA80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E224878617AFAFULL,
		0x80BCE4E64F7F2A9CULL,
		0x06C2FBE398469542ULL,
		0x7FE087722A48038FULL,
		0x0CBD94C42535A973ULL,
		0x9DFC04FB622ACA61ULL,
		0xED1A2FC1E010033DULL,
		0x746469A80F1629E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A7CDA1DDD57CA92ULL,
		0x8FA5CFECD58CD376ULL,
		0x48134F06570BB336ULL,
		0x280ADB0C49B46C1BULL,
		0x20EB1C9202AB6CB9ULL,
		0x468A4C0260B2E11CULL,
		0xDE74868919721542ULL,
		0x0045CBFB34A4D09AULL
	}};
	sign = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x41A354746FE8E838ULL,
		0x4F0E3DDD1B867919ULL,
		0x2DB6C92322090260ULL,
		0x2BAC1C5C2F5BB47DULL,
		0x663CEEF8C9F3CD73ULL,
		0xA4EC65078FBAB3AEULL,
		0x03F1FC90979C0D61ULL,
		0x52CEB497BEB65BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC6DB214A955355ULL,
		0x85FBFA3D5B07E351ULL,
		0x09AA39CA2C73AC64ULL,
		0xF578A12AD8F73BF6ULL,
		0x461209F278C0C789ULL,
		0x848013AC4120FE6BULL,
		0xFA0974B29B6442B9ULL,
		0xBFC11BD87EBAF020ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94DC7953255394E3ULL,
		0xC912439FC07E95C7ULL,
		0x240C8F58F59555FBULL,
		0x36337B3156647887ULL,
		0x202AE506513305E9ULL,
		0x206C515B4E99B543ULL,
		0x09E887DDFC37CAA8ULL,
		0x930D98BF3FFB6BBFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE88F6D76AF6FD064ULL,
		0x812A36CED9FD8259ULL,
		0x3B31C03B4B979147ULL,
		0x2C0603518025ABD6ULL,
		0xF7E33F0610CAB42BULL,
		0xCA7B8ED221BF1EA0ULL,
		0xB067A3FD65DAC24EULL,
		0xC0FE01F7CC1BE45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1A246B0B8DE859ULL,
		0x6B858925EA063A61ULL,
		0xED53F559AFD44785ULL,
		0x06240D4CB04EA6DAULL,
		0xBCBA2E07EEC5DE17ULL,
		0xD364CA3B1E25B198ULL,
		0xD457ECCFB4B10031ULL,
		0xAA081BA248A730C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C75490BA3E1E80BULL,
		0x15A4ADA8EFF747F8ULL,
		0x4DDDCAE19BC349C2ULL,
		0x25E1F604CFD704FBULL,
		0x3B2910FE2204D614ULL,
		0xF716C49703996D08ULL,
		0xDC0FB72DB129C21CULL,
		0x16F5E6558374B397ULL
	}};
	sign = 0;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52394C4AC6C13A1DULL,
		0x6612C20A565E011EULL,
		0x9C44AAA769C9371AULL,
		0xBC4EA04F9C764686ULL,
		0xEA6C45EFDFCD7E99ULL,
		0x3399CAE2E114497FULL,
		0x5F4DB85ED8890819ULL,
		0xEAC54F42A3327878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE50D2928645FACE9ULL,
		0x25404834D4A24797ULL,
		0x3127D7B99915BF5AULL,
		0xCCC14BACF9C31E86ULL,
		0x6EE1D5BE3B0FA002ULL,
		0xEA5A4EFF9B15977EULL,
		0xE7DD57BDF7450659ULL,
		0x81AF5DA0F671333FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D2C232262618D34ULL,
		0x40D279D581BBB986ULL,
		0x6B1CD2EDD0B377C0ULL,
		0xEF8D54A2A2B32800ULL,
		0x7B8A7031A4BDDE96ULL,
		0x493F7BE345FEB201ULL,
		0x777060A0E14401BFULL,
		0x6915F1A1ACC14538ULL
	}};
	sign = 0;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA0FEFB30948F2CEULL,
		0xB9445B3EC4DF36EFULL,
		0x3CF478E5E8B5C36CULL,
		0xC5832DDDBE87A602ULL,
		0x988D166E38BD8BF7ULL,
		0x52551A71F1E9F83BULL,
		0xEAC9E1186E56A32DULL,
		0xDF3EB3C1BAB68903ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97444E8F6F3F99CFULL,
		0xA4E0C39B5EDFA12EULL,
		0x9AA2497082158CBEULL,
		0xE2F56974AA7C222FULL,
		0x4D10A013828D2E35ULL,
		0x274D80712D070D11ULL,
		0xAA4208B0EC134F9EULL,
		0x8A0DFDB686ED3B90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42CBA1239A0958FFULL,
		0x146397A365FF95C1ULL,
		0xA2522F7566A036AEULL,
		0xE28DC469140B83D2ULL,
		0x4B7C765AB6305DC1ULL,
		0x2B079A00C4E2EB2AULL,
		0x4087D8678243538FULL,
		0x5530B60B33C94D73ULL
	}};
	sign = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDB29179535E02ACULL,
		0x4CA3B2CEADED497CULL,
		0xE78D6877396A409EULL,
		0x0602B32598ED94D3ULL,
		0x92E82B74D0CA7E36ULL,
		0xD6E7B8FD23A5A2FEULL,
		0x33CA20C7A0B9850BULL,
		0xBA9EFB686CF924E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AD3E8A5DE4299D0ULL,
		0x9A4BE383BCA2B10DULL,
		0x4A01DDD4A7944CB4ULL,
		0xF82F84EA689BF8C7ULL,
		0x826935535DA6FA05ULL,
		0xB5D96740856C7AB6ULL,
		0xD2E3A952C797680CULL,
		0xF0FC64A805C36628ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22DEA8D3751B68DCULL,
		0xB257CF4AF14A986FULL,
		0x9D8B8AA291D5F3E9ULL,
		0x0DD32E3B30519C0CULL,
		0x107EF62173238430ULL,
		0x210E51BC9E392848ULL,
		0x60E67774D9221CFFULL,
		0xC9A296C06735BEC0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65AAF533907ABA7DULL,
		0x43F5A8EC6F5BFCA0ULL,
		0xEA45191943F46160ULL,
		0x53B0117E9856FEB0ULL,
		0xCBB44CD1DAA8E220ULL,
		0x093797D0AC65B470ULL,
		0x4F5873DD8A7323A5ULL,
		0x25E4DEC291545796ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE41E012426D6F6ECULL,
		0xA07F5A083AA8BD1DULL,
		0xA997817DDE906205ULL,
		0xEE0830661B3D17C7ULL,
		0x48DB6A084979B655ULL,
		0x1127C3C5202B8747ULL,
		0x780AA8C6FB5AC5E5ULL,
		0x5A6463F2CDD6F68EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x818CF40F69A3C391ULL,
		0xA3764EE434B33F82ULL,
		0x40AD979B6563FF5AULL,
		0x65A7E1187D19E6E9ULL,
		0x82D8E2C9912F2BCAULL,
		0xF80FD40B8C3A2D29ULL,
		0xD74DCB168F185DBFULL,
		0xCB807ACFC37D6107ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B92C4BF968D1D18ULL,
		0x1A66EEF8F03985B2ULL,
		0x3ADA55DC5B187531ULL,
		0xE1D69CBE90A422A0ULL,
		0xB67B8D368B0EE424ULL,
		0xB312D1BB82288E9CULL,
		0xF340178EC2BF922CULL,
		0xD6D33E7D43ABABE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A1BB2A3C82A9CAULL,
		0x8C7702629564214AULL,
		0x10E629873DD6711FULL,
		0x33E76DE039DC2883ULL,
		0xBB528D7D5C56A02BULL,
		0x101EDAA557ED2082ULL,
		0x87A7F0DAB56EEACCULL,
		0xC11FA4B3458156AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x47F109955A0A734EULL,
		0x8DEFEC965AD56468ULL,
		0x29F42C551D420411ULL,
		0xADEF2EDE56C7FA1DULL,
		0xFB28FFB92EB843F9ULL,
		0xA2F3F7162A3B6E19ULL,
		0x6B9826B40D50A760ULL,
		0x15B399C9FE2A5535ULL
	}};
	sign = 0;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DC88DAE7A55F81FULL,
		0xE66313B3A79E3049ULL,
		0xCC09FE16A45DDD4FULL,
		0x0CDBFF9291B2F67FULL,
		0x4F975CEAD426FBF0ULL,
		0x8059129EDDEB3096ULL,
		0x474BD6E67A8D8A98ULL,
		0x616DB083869A276FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058AA25A3766BC14ULL,
		0x6BFD0218B81B1419ULL,
		0x2AACE7F092B5C1D1ULL,
		0xCA58DA872D23CD36ULL,
		0xAAECAED62F1C8EE9ULL,
		0x32E840DB27C7E30AULL,
		0x7971568800EF5440ULL,
		0x19222746245523FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x983DEB5442EF3C0BULL,
		0x7A66119AEF831C30ULL,
		0xA15D162611A81B7EULL,
		0x4283250B648F2949ULL,
		0xA4AAAE14A50A6D06ULL,
		0x4D70D1C3B6234D8BULL,
		0xCDDA805E799E3658ULL,
		0x484B893D62450370ULL
	}};
	sign = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42E17050DD1F0231ULL,
		0xB4ECB8EF54659BBBULL,
		0xD6FA32BEFD70FB33ULL,
		0xA02F4602AB8C9076ULL,
		0xC22CB3C34664772AULL,
		0x88E662E3096CABB9ULL,
		0x2FACA19C9D6FDFA5ULL,
		0xEC597A6826AC6688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B2DA2399B4D45ABULL,
		0xD6E154DC48865FD3ULL,
		0x1E47E4577A474CC9ULL,
		0x286591E939608691ULL,
		0x469C7FE67ECDA7F3ULL,
		0x5005B080FD06CDEFULL,
		0x60F2C7F59771102BULL,
		0xEC058ADA2E27FEB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27B3CE1741D1BC86ULL,
		0xDE0B64130BDF3BE8ULL,
		0xB8B24E678329AE69ULL,
		0x77C9B419722C09E5ULL,
		0x7B9033DCC796CF37ULL,
		0x38E0B2620C65DDCAULL,
		0xCEB9D9A705FECF7AULL,
		0x0053EF8DF88467D1ULL
	}};
	sign = 0;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84D67A7C87C4E86CULL,
		0x19836326E12C28E8ULL,
		0xFDFEB4CF3AC009F5ULL,
		0xFFCEE4DBCBE8C1CFULL,
		0xB43BFE05E99D7FDCULL,
		0xC85630486A224AA3ULL,
		0x9BB155BB0F32B7C1ULL,
		0x23FDC3B7C2267DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB66222323B22674FULL,
		0x573C846DE2FDFEE1ULL,
		0x7206C514A3527786ULL,
		0xF6F52BE9B03AD0EBULL,
		0xE7F7338EBE68BCB5ULL,
		0x8A0E114B93C6C9ABULL,
		0x6EC2C861E51EC020ULL,
		0x0E8D5BA5E51D59BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE74584A4CA2811DULL,
		0xC246DEB8FE2E2A06ULL,
		0x8BF7EFBA976D926EULL,
		0x08D9B8F21BADF0E4ULL,
		0xCC44CA772B34C327ULL,
		0x3E481EFCD65B80F7ULL,
		0x2CEE8D592A13F7A1ULL,
		0x15706811DD09240DULL
	}};
	sign = 0;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43146E3D9E720C2CULL,
		0x173E7F33869A40A2ULL,
		0x27304B55ECE5FE20ULL,
		0x697B00B1E9E68D04ULL,
		0xF0A668E40BACFE31ULL,
		0x47B0049AB8CCDD1AULL,
		0xC52A5C6DCFC71557ULL,
		0xA3A0B65D9B8A5621ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2418619A378C0BEAULL,
		0xAA4D0DDB9F58EC76ULL,
		0x706FCCCEAF7CCCA3ULL,
		0x8439116A317624E4ULL,
		0x315D07A13D5E416FULL,
		0xEEDFD7D4EBC34C06ULL,
		0xF67709163C24D2C6ULL,
		0xBD6360FC0FA6E3EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EFC0CA366E60042ULL,
		0x6CF17157E741542CULL,
		0xB6C07E873D69317CULL,
		0xE541EF47B870681FULL,
		0xBF496142CE4EBCC1ULL,
		0x58D02CC5CD099114ULL,
		0xCEB3535793A24290ULL,
		0xE63D55618BE37236ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE07AB853840FB066ULL,
		0xA0C456E1B3CCABCBULL,
		0x83B10B379EFECC13ULL,
		0x8D4E9C3FA782D6B0ULL,
		0x50C5B1EF08A12A5AULL,
		0xD44F08CA85382A80ULL,
		0xF593580CC4B99879ULL,
		0x952349076C683011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49DF8083A190D54DULL,
		0xCAFE943127A548DCULL,
		0x177DE90DA6948634ULL,
		0x90021523D84E5AD7ULL,
		0x032258A6FE2D6019ULL,
		0x82CA5C59C3E016C8ULL,
		0x551D4FE22C6562B5ULL,
		0xAD5E42135611678EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x969B37CFE27EDB19ULL,
		0xD5C5C2B08C2762EFULL,
		0x6C332229F86A45DEULL,
		0xFD4C871BCF347BD9ULL,
		0x4DA359480A73CA40ULL,
		0x5184AC70C15813B8ULL,
		0xA076082A985435C4ULL,
		0xE7C506F41656C883ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE178CC54E10EC61ULL,
		0xE7EF36D9EDEAE2A2ULL,
		0x5A3BF5A9070C4B95ULL,
		0x54E2D5BB16D5CF07ULL,
		0xC6FB4675F5BBE50AULL,
		0x931B76ED3D5F37E4ULL,
		0xEC9EC16B0046E966ULL,
		0x36C90EF78C57B4AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10749FE15F53E4F3ULL,
		0x8005B0EC63986879ULL,
		0x941F28225833CFD1ULL,
		0xCB34A96D8A735D31ULL,
		0x33AE49FAC248ECAAULL,
		0xE6096C7F4A595679ULL,
		0x713E4C5BBD6DE174ULL,
		0x433242EC856B8571ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DA2ECE3EEBD076EULL,
		0x67E985ED8A527A29ULL,
		0xC61CCD86AED87BC4ULL,
		0x89AE2C4D8C6271D5ULL,
		0x934CFC7B3372F85FULL,
		0xAD120A6DF305E16BULL,
		0x7B60750F42D907F1ULL,
		0xF396CC0B06EC2F3DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x058EAB2906321F80ULL,
		0x6248E51F90819D82ULL,
		0x3249616C3A91313EULL,
		0xB2F77F724033590AULL,
		0x50E593A220ED3771ULL,
		0xB60A10955C61FBC2ULL,
		0xFE49895FA643114FULL,
		0x06493F8248F05CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD9CFEE9D562B39ULL,
		0x3EB5D3AFA253B4EAULL,
		0xE7F16467B4750019ULL,
		0xBD6838CF0EAABECDULL,
		0x2C81BC63A17C56F7ULL,
		0xA481F1146F08DEFFULL,
		0x3A4384FC51F708B0ULL,
		0xEEC09A54287E5EB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAB4DB3A68DBF447ULL,
		0x2393116FEE2DE897ULL,
		0x4A57FD04861C3125ULL,
		0xF58F46A331889A3CULL,
		0x2463D73E7F70E079ULL,
		0x11881F80ED591CC3ULL,
		0xC4060463544C089FULL,
		0x1788A52E2071FE24ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA2C6041C5C59456ULL,
		0x029E29EC94A4E54DULL,
		0x347AE8009D48F53EULL,
		0x7DA2AB6A9EE985EEULL,
		0x4B2AD74044BC8056ULL,
		0xE2D82DDC236C141CULL,
		0x6ECBF2EDDC18C161ULL,
		0x29D94CA1ED48C37EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B9EAAA13B3D589ULL,
		0x42C5A7409BFE82A8ULL,
		0x9DC908ACE88A6971ULL,
		0x8A14F226366D0963ULL,
		0x68D3F914FC1F53B1ULL,
		0xA77DB029DE80AE1CULL,
		0x839B2F28B4716BE1ULL,
		0xA57CB1A786DC1C8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61727597B211BECDULL,
		0xBFD882ABF8A662A5ULL,
		0x96B1DF53B4BE8BCCULL,
		0xF38DB944687C7C8AULL,
		0xE256DE2B489D2CA4ULL,
		0x3B5A7DB244EB65FFULL,
		0xEB30C3C527A75580ULL,
		0x845C9AFA666CA6EFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26D972E18FC63B16ULL,
		0xC8045F89FF6E69DEULL,
		0x54E08C10E72D2BBCULL,
		0x803120E78ACEBB0FULL,
		0xDEF635AC0C88B8F0ULL,
		0x6E64C747472A2BDAULL,
		0x8849F8827C6B713BULL,
		0x5B497372A0426EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F32E2E3C1717258ULL,
		0x87B526C4B24DE9C4ULL,
		0xA5EE6E7C6E97E678ULL,
		0x7228E393E9569397ULL,
		0xFF3A81DE8EFDDEB2ULL,
		0x39AC1045A4F5CF2DULL,
		0x87F432306C9D6643ULL,
		0xC9E69D7619FF5187ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7A68FFDCE54C8BEULL,
		0x404F38C54D208019ULL,
		0xAEF21D9478954544ULL,
		0x0E083D53A1782777ULL,
		0xDFBBB3CD7D8ADA3EULL,
		0x34B8B701A2345CACULL,
		0x0055C6520FCE0AF8ULL,
		0x9162D5FC86431D30ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA31C696FCEA335D5ULL,
		0x9B2BCFE470D1D4A6ULL,
		0xE59E2D8816ABE01FULL,
		0x93C64F13ABE55519ULL,
		0xE1BFA1E29FC0613FULL,
		0x7882E7903169489AULL,
		0x89CFBECBC99271BBULL,
		0xD82AE16D5D96F230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B83830ADA0BFAF5ULL,
		0x39BEE8DB11905A44ULL,
		0x1DEA6DDA0F9E4722ULL,
		0xEF537C1F5172502EULL,
		0x9674A3C08898DF9AULL,
		0xC7658A86A7103EAEULL,
		0x3AC63926BF27336EULL,
		0x700953684BCA5D3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1798E664F4973AE0ULL,
		0x616CE7095F417A62ULL,
		0xC7B3BFAE070D98FDULL,
		0xA472D2F45A7304EBULL,
		0x4B4AFE22172781A4ULL,
		0xB11D5D098A5909ECULL,
		0x4F0985A50A6B3E4CULL,
		0x68218E0511CC94F4ULL
	}};
	sign = 0;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x328CEDE5D465D5E9ULL,
		0xCD64A9CF33722B64ULL,
		0x488FFE2379D17B9FULL,
		0x82BC44CBEAEC97CCULL,
		0xB4E9283B6216687BULL,
		0x0E030EF5CFA48DD5ULL,
		0x1F44EFA3159A2C9AULL,
		0x254F8521B9034BDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AECD28A864F69CBULL,
		0xC943CA3F7CFCB792ULL,
		0x093B4AA3D3AA0CC4ULL,
		0x30356A06971C9017ULL,
		0x840993B9BB65EA39ULL,
		0xD5D1CABCFB4D4921ULL,
		0xCCCB42C55B0524A8ULL,
		0x3FC65D232B25C9E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7A01B5B4E166C1EULL,
		0x0420DF8FB67573D1ULL,
		0x3F54B37FA6276EDBULL,
		0x5286DAC553D007B5ULL,
		0x30DF9481A6B07E42ULL,
		0x38314438D45744B4ULL,
		0x5279ACDDBA9507F1ULL,
		0xE58927FE8DDD81F6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E198D98E502C39EULL,
		0x7FDB74B93136EA4BULL,
		0x8C4374FB1AAD4E4FULL,
		0x3D58CCE08E95A647ULL,
		0x95398294EA0AD1E3ULL,
		0x3327DF7B78C45D0AULL,
		0x36AFB4E648FC33DBULL,
		0xADE217E2787A2724ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D64D1F5EF076ADULL,
		0x95177DB3E445C8B2ULL,
		0x395E0388832BCB90ULL,
		0xA2C4A88390379308ULL,
		0xAEE52F5177197443ULL,
		0xF7A681FDC1EE40B6ULL,
		0xCC59ACD8F2652EE3ULL,
		0x521367F4D8AA8B8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6B43407986124CF1ULL,
		0xEAC3F7054CF12198ULL,
		0x52E57172978182BEULL,
		0x9A94245CFE5E133FULL,
		0xE654534372F15D9FULL,
		0x3B815D7DB6D61C53ULL,
		0x6A56080D569704F7ULL,
		0x5BCEAFED9FCF9B97ULL
	}};
	sign = 0;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFE364DA88248E3AULL,
		0xB3CFFE7F671002A4ULL,
		0x324661CE16073E61ULL,
		0x99FBB1B7E4DA8F98ULL,
		0x2810B103E62D4999ULL,
		0xEBAD9353F1258C08ULL,
		0xCEC1C35A6097646DULL,
		0x87FAC1E88C8A9258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2232DCCB1FDA5AB4ULL,
		0x93256A1FA21EEC04ULL,
		0x9AFFC1351E5EECCCULL,
		0x2CBE99FC04BE9759ULL,
		0x810607CCECFBE529ULL,
		0xD7F5DC069A5D9629ULL,
		0xF91CA487B66D8FBCULL,
		0x8F9CE479E858E3B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB0880F684A3386ULL,
		0x20AA945FC4F116A0ULL,
		0x9746A098F7A85195ULL,
		0x6D3D17BBE01BF83EULL,
		0xA70AA936F9316470ULL,
		0x13B7B74D56C7F5DEULL,
		0xD5A51ED2AA29D4B1ULL,
		0xF85DDD6EA431AEA7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBFBC154547EEC4AULL,
		0xDB30723516BA1FA6ULL,
		0x95184AC1FEE1E022ULL,
		0x74EF023D05D3AFC3ULL,
		0xFFC929256010B108ULL,
		0x90D8E405D1118A84ULL,
		0x09F7F8E04068EBD0ULL,
		0x08238AC84A7568D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81F86845CB148FABULL,
		0x75D26D006CF2DA27ULL,
		0xA791F0FC7481EB8AULL,
		0x67AC48A358AF0F48ULL,
		0xC29C176755FDF41BULL,
		0x332F53FF8CF6FB8EULL,
		0x883EAD9764B6C5D5ULL,
		0x9F77E2CD2446B9C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A03590E896A5C9FULL,
		0x655E0534A9C7457FULL,
		0xED8659C58A5FF498ULL,
		0x0D42B999AD24A07AULL,
		0x3D2D11BE0A12BCEDULL,
		0x5DA99006441A8EF6ULL,
		0x81B94B48DBB225FBULL,
		0x68ABA7FB262EAF15ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB852978B62D5F62FULL,
		0xD631BA935E84DBEEULL,
		0x03099582E2B17169ULL,
		0x15634C672738E2EEULL,
		0x265081C1352855C9ULL,
		0x74FB7F89BAC5080BULL,
		0xEB595BAF2650813AULL,
		0xDD530DA55DDC528DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5808770EF47780ULL,
		0x97553A04F8137494ULL,
		0xD1AE31785C5B2180ULL,
		0x2E36A4EBE5459C0EULL,
		0x7CB36FC94CE05E5CULL,
		0x180DD96841E922DBULL,
		0xB72B6465E8764FBBULL,
		0x668BF8201BF4AC7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFBFA8F1453E17EAFULL,
		0x3EDC808E66716759ULL,
		0x315B640A86564FE9ULL,
		0xE72CA77B41F346DFULL,
		0xA99D11F7E847F76CULL,
		0x5CEDA62178DBE52FULL,
		0x342DF7493DDA317FULL,
		0x76C7158541E7A612ULL
	}};
	sign = 0;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE778307841DA7A04ULL,
		0x623BA926E75A0DD5ULL,
		0x837ADB20D0CCDE9CULL,
		0x92BF24B188DC03B8ULL,
		0x390803E3A6EB5611ULL,
		0x22879BFE769C1F38ULL,
		0x3F78BA5FAE428E24ULL,
		0xE3C20B9FB5D6CAC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE919AEF2B67A598ULL,
		0xC309FE2667AA3F3DULL,
		0x655B8559F56C8798ULL,
		0x344A936ACD44622FULL,
		0x5B826D42D7260EE1ULL,
		0x08DF5A2F2BA69ECBULL,
		0x3DE80674828BCEAEULL,
		0x18A2BA4C14D2589DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38E695891672D46CULL,
		0x9F31AB007FAFCE98ULL,
		0x1E1F55C6DB605703ULL,
		0x5E749146BB97A189ULL,
		0xDD8596A0CFC54730ULL,
		0x19A841CF4AF5806CULL,
		0x0190B3EB2BB6BF76ULL,
		0xCB1F5153A104722AULL
	}};
	sign = 0;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06835C1DAF095820ULL,
		0x82D7DC1580C4F2AFULL,
		0x5D4E22D008EB007EULL,
		0xC79A7698EAFEFE7CULL,
		0xB2EAC47299F4CBB0ULL,
		0x1ABA0BE59AA53453ULL,
		0x5BDA22AA548140F4ULL,
		0x78E16A1ACDAB4800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC029459C5EA9F158ULL,
		0xE78236BC3635A6D0ULL,
		0x5FF6A8A925F7B014ULL,
		0x606078DFE6368F2BULL,
		0x4ED7A70C4472D892ULL,
		0xF1F77E13BC83FF49ULL,
		0xB203F1C12E9963E8ULL,
		0x41AC4BECB2FBACC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x465A1681505F66C8ULL,
		0x9B55A5594A8F4BDEULL,
		0xFD577A26E2F35069ULL,
		0x6739FDB904C86F50ULL,
		0x64131D665581F31EULL,
		0x28C28DD1DE21350AULL,
		0xA9D630E925E7DD0BULL,
		0x37351E2E1AAF9B39ULL
	}};
	sign = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0281D964E963233ULL,
		0x4E3C60DE9980EFC2ULL,
		0x83A7EE611624832CULL,
		0x1A26999D9D66ADB6ULL,
		0x5769CC1B9A04C56CULL,
		0x96F074BF5B0FDA3CULL,
		0x144689C88BD544C8ULL,
		0xF8CAB576A40A0DFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12CC1A5F7937B453ULL,
		0x611FF8D86614B8F6ULL,
		0x2444C4AEB3FE150AULL,
		0x4129B7E86C785071ULL,
		0x8683F6CD0961ADE2ULL,
		0xCFC01BCC8023C98DULL,
		0x7E08D41868EDB845ULL,
		0x1757E919CBE83F66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD5C0336D55E7DE0ULL,
		0xED1C6806336C36CCULL,
		0x5F6329B262266E21ULL,
		0xD8FCE1B530EE5D45ULL,
		0xD0E5D54E90A31789ULL,
		0xC73058F2DAEC10AEULL,
		0x963DB5B022E78C82ULL,
		0xE172CC5CD821CE95ULL
	}};
	sign = 0;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A3CD5BA701E5921ULL,
		0xAE7AB3D0603CD616ULL,
		0x98A008AA1FEBD921ULL,
		0xA161927971E40BC4ULL,
		0x303B3F0AE0F9DE4AULL,
		0x40D63F442FD59FCCULL,
		0xDC6C9F54C33A283FULL,
		0x60437C207E558E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB871A6F8D61D1C6EULL,
		0x1501086A18ECA398ULL,
		0x7C37EDAA856125C7ULL,
		0xCB7DA3365FABD8F0ULL,
		0xA6DB19712FFBFE75ULL,
		0x0D8EBB67C9AAB127ULL,
		0x8881EF29A50A6D85ULL,
		0x056BAD9CB46D44ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51CB2EC19A013CB3ULL,
		0x9979AB664750327DULL,
		0x1C681AFF9A8AB35AULL,
		0xD5E3EF43123832D4ULL,
		0x89602599B0FDDFD4ULL,
		0x334783DC662AEEA4ULL,
		0x53EAB02B1E2FBABAULL,
		0x5AD7CE83C9E849A7ULL
	}};
	sign = 0;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05449A3E90DB1C99ULL,
		0x971DAE4120F59632ULL,
		0x78CB2B28A0F0CD08ULL,
		0x3856F6A380B0266CULL,
		0xBB307E9EBAF88F3CULL,
		0xB7D0AEA49736F5D5ULL,
		0x4413A66BE6B8D3B9ULL,
		0x41FDBFF2EC28B081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B6DE00BEAD6A66ULL,
		0x315F6A7014868DABULL,
		0x80BC7C2C8F9E8163ULL,
		0x874C64FDB05C60DAULL,
		0x83F24C7C8CF702F0ULL,
		0x2B5EE75461A233FFULL,
		0x42B0B3367A8142FEULL,
		0xF5C843BA1CC2DBEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC8DBC3DD22DB233ULL,
		0x65BE43D10C6F0886ULL,
		0xF80EAEFC11524BA5ULL,
		0xB10A91A5D053C591ULL,
		0x373E32222E018C4BULL,
		0x8C71C7503594C1D6ULL,
		0x0162F3356C3790BBULL,
		0x4C357C38CF65D493ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE8A5ECB14758241ULL,
		0xE9196CADB4017F2DULL,
		0xD9D6D2C2DBCBDB35ULL,
		0x0906D6CCC9A5F391ULL,
		0x43EE57F11C5F13E6ULL,
		0x2CA334D99E0EF3BCULL,
		0xC0590363E2C96A46ULL,
		0xCB2A0E3BB188BD56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C8A47F0BFAF5D02ULL,
		0xFEC5D9283940B97AULL,
		0xD9A47A31A692F756ULL,
		0xB050306E3E4FE8A3ULL,
		0x82DCC0EC68AFD297ULL,
		0xF41AC8D4BD336AE9ULL,
		0xE3EABF1893356BF6ULL,
		0x3593E96954C16272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE20016DA54C6253FULL,
		0xEA5393857AC0C5B3ULL,
		0x003258913538E3DEULL,
		0x58B6A65E8B560AEEULL,
		0xC1119704B3AF414EULL,
		0x38886C04E0DB88D2ULL,
		0xDC6E444B4F93FE4FULL,
		0x959624D25CC75AE3ULL
	}};
	sign = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28EBE0932C63BF30ULL,
		0xA9F5AC826C89E2C9ULL,
		0x4E3E8BE402B03950ULL,
		0x09F58798168AEE0CULL,
		0xABE54447724D8EB3ULL,
		0x62625269A469B225ULL,
		0x29A46EC52CBBBCDFULL,
		0x12ADAD8B76BDF335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E224AE3FC27D6DDULL,
		0xAB852C3E214BD180ULL,
		0xF1CA6238DAA6ED59ULL,
		0x8AE9FA318F001985ULL,
		0x3F0B7F0180CC792CULL,
		0xBA5FCDFC54808E28ULL,
		0x1879635DBFB1462BULL,
		0xE28BED4EA2C1427FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAC995AF303BE853ULL,
		0xFE7080444B3E1148ULL,
		0x5C7429AB28094BF6ULL,
		0x7F0B8D66878AD486ULL,
		0x6CD9C545F1811586ULL,
		0xA802846D4FE923FDULL,
		0x112B0B676D0A76B3ULL,
		0x3021C03CD3FCB0B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x58609F78B47FDEACULL,
		0xBDAD3E3000DA14ACULL,
		0x8243A6E8807BD57BULL,
		0xFC81F5D83ADBF47DULL,
		0x62C11B1252C083FEULL,
		0xE68743791997BAD6ULL,
		0xF8A16582C86AD75AULL,
		0x765A14B3CF0DD856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x080A94325DD4A188ULL,
		0xFF31164129FA396FULL,
		0xE1EC38523E3D9BC8ULL,
		0xB3F4DCD3F9576406ULL,
		0xBB026E6A97B982C7ULL,
		0xBF3CAE34B9D7E736ULL,
		0x2293B427C4DC15C6ULL,
		0x65CA01733497C26EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50560B4656AB3D24ULL,
		0xBE7C27EED6DFDB3DULL,
		0xA0576E96423E39B2ULL,
		0x488D190441849076ULL,
		0xA7BEACA7BB070137ULL,
		0x274A95445FBFD39FULL,
		0xD60DB15B038EC194ULL,
		0x109013409A7615E8ULL
	}};
	sign = 0;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10EB810AA3C330B0ULL,
		0xA415A110C11B9ACFULL,
		0x51D9DEF49FBE5231ULL,
		0x51D23D2C42CA6D20ULL,
		0x89F2604411081CF3ULL,
		0x1222032BCE806F66ULL,
		0x3E0198F2FDAE986FULL,
		0xC7A000870D3F159FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CFEB680745E582DULL,
		0x12CA2BDF4232BA8FULL,
		0x6ADD4F0BCD0852B0ULL,
		0xDA7ED20652861D4BULL,
		0x5ED9D57751C10C4BULL,
		0xC75159312DE1A113ULL,
		0x4A7262F9478E4FEEULL,
		0xC6734F066BADDF62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3ECCA8A2F64D883ULL,
		0x914B75317EE8E03FULL,
		0xE6FC8FE8D2B5FF81ULL,
		0x77536B25F0444FD4ULL,
		0x2B188ACCBF4710A7ULL,
		0x4AD0A9FAA09ECE53ULL,
		0xF38F35F9B6204880ULL,
		0x012CB180A191363CULL
	}};
	sign = 0;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ABB8245DF711EE7ULL,
		0x9945C1062A0223C0ULL,
		0xDD932CED754F236FULL,
		0x4F5C5E3B507AC257ULL,
		0x1E0D473DA072066AULL,
		0x8D8AC810C9B18BCDULL,
		0xAB5F5FAD4543B9CAULL,
		0xF751A812A2C41C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E6DDE2E2E537C0ULL,
		0xDC7178E07FFF5BAAULL,
		0x47AFAC0879A74D9FULL,
		0x6807038F21215D1FULL,
		0xBA31F57A4C5EE0C4ULL,
		0x97325644A1F3DB42ULL,
		0x1E5BBC475FE079FAULL,
		0xEBAD08C6AABDF271ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97D4A462FC8BE727ULL,
		0xBCD44825AA02C815ULL,
		0x95E380E4FBA7D5CFULL,
		0xE7555AAC2F596538ULL,
		0x63DB51C3541325A5ULL,
		0xF65871CC27BDB08AULL,
		0x8D03A365E5633FCFULL,
		0x0BA49F4BF806299FULL
	}};
	sign = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1590C4563BA36C3ULL,
		0x8A070B40CF5C0E2DULL,
		0x1DB63FE2A0A810CDULL,
		0x7AF9A2797FF2A262ULL,
		0x772E64888A6C9F98ULL,
		0x05BBFC847B585349ULL,
		0x349063C85B3108C2ULL,
		0x7C37DCB371D71214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F473647E3D60056ULL,
		0xF723EF6CED7460EBULL,
		0xB3B9B907A9ADBCB9ULL,
		0x2055C3AF481C3243ULL,
		0x594ACEEC4896B2C6ULL,
		0xB83D522BBBA7C44BULL,
		0x76E8A1C7A6610630ULL,
		0x342256F911AC2767ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA211D5FD7FE4366DULL,
		0x92E31BD3E1E7AD42ULL,
		0x69FC86DAF6FA5413ULL,
		0x5AA3DECA37D6701EULL,
		0x1DE3959C41D5ECD2ULL,
		0x4D7EAA58BFB08EFEULL,
		0xBDA7C200B4D00291ULL,
		0x481585BA602AEAACULL
	}};
	sign = 0;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFAB95E54BD36751ULL,
		0xB2EAC397B2DCBBB9ULL,
		0x4453A86806CA70D0ULL,
		0xD5FB1257551B0503ULL,
		0xFE86E376366C46A9ULL,
		0x1DA839CE07BECD0AULL,
		0x14E8D6F178B29248ULL,
		0xBB237F8CA6A98308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x794BECEBF8679493ULL,
		0x85A7C1DB6760D230ULL,
		0xB548B4BB65E12F13ULL,
		0x7F635CE905663DFFULL,
		0x2989590CF87EB510ULL,
		0x0A05B4F673FFDEADULL,
		0x993D78CEEAEF021DULL,
		0x716E04BEDD58B937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x465FA8F9536BD2BEULL,
		0x2D4301BC4B7BE989ULL,
		0x8F0AF3ACA0E941BDULL,
		0x5697B56E4FB4C703ULL,
		0xD4FD8A693DED9199ULL,
		0x13A284D793BEEE5DULL,
		0x7BAB5E228DC3902BULL,
		0x49B57ACDC950C9D0ULL
	}};
	sign = 0;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44C8AA0781E746A1ULL,
		0x606B17664D313F75ULL,
		0xA103C4112E865DEEULL,
		0x6F236DD429433C2AULL,
		0x94FAC518F998B608ULL,
		0xA5C556F7887892A1ULL,
		0x5AE1651238D0BF59ULL,
		0x69C95D358994B8A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFBEA8994AE53CEEULL,
		0x7FFB0CA506026BB5ULL,
		0x632F5B7646D055F2ULL,
		0x9780D27BE5B54741ULL,
		0xA8C30141A54B4042ULL,
		0xA587ABC4A0B2BAF0ULL,
		0x817C9A206B69E680ULL,
		0x89031830A5960667ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x750A016E370209B3ULL,
		0xE0700AC1472ED3BFULL,
		0x3DD4689AE7B607FBULL,
		0xD7A29B58438DF4E9ULL,
		0xEC37C3D7544D75C5ULL,
		0x003DAB32E7C5D7B0ULL,
		0xD964CAF1CD66D8D9ULL,
		0xE0C64504E3FEB239ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE482D9094F0D523FULL,
		0x8028EAC5EAC6E021ULL,
		0x466F1958D9DD9E9DULL,
		0x527267EFEACFA780ULL,
		0x3553C4BB4092060EULL,
		0x888782FAACF77D06ULL,
		0xD43279CF7CA9FC7BULL,
		0xF8E8E2FC05F5A882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70CC2D92695F094ULL,
		0xD9EF60355D54D62BULL,
		0xBE04E4EAD604635DULL,
		0xB2A010B66A1B8461ULL,
		0x099CAA424A091407ULL,
		0xCFF01ECC1D2ECF18ULL,
		0x33794575C4E576EFULL,
		0xCD538168923400DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD761630287761ABULL,
		0xA6398A908D7209F5ULL,
		0x886A346E03D93B3FULL,
		0x9FD2573980B4231EULL,
		0x2BB71A78F688F206ULL,
		0xB897642E8FC8ADEEULL,
		0xA0B93459B7C4858BULL,
		0x2B95619373C1A7A6ULL
	}};
	sign = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC18CA8F594F73D42ULL,
		0xBC09EF938F4E7D2CULL,
		0x9E28D8E075A85C13ULL,
		0xEC30DDB7896B156DULL,
		0x4413B8FA1744F5C7ULL,
		0xA727EC5D10DBB3E8ULL,
		0xBC0E109EE8D8B2D6ULL,
		0xB75404EDDC4667B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B089A8BD6964F2CULL,
		0x68D393B56A20AE2FULL,
		0x5464D83A88609761ULL,
		0x774C59226B761862ULL,
		0xAF3DF6CB0988E08BULL,
		0xEBCBF425DD6A3C8EULL,
		0xF02CF74E70DE3424ULL,
		0xCE6DA746B37D779DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86840E69BE60EE16ULL,
		0x53365BDE252DCEFDULL,
		0x49C400A5ED47C4B2ULL,
		0x74E484951DF4FD0BULL,
		0x94D5C22F0DBC153CULL,
		0xBB5BF83733717759ULL,
		0xCBE1195077FA7EB1ULL,
		0xE8E65DA728C8F017ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83EAB2A72B5C2B45ULL,
		0xBE42F70EBB17267AULL,
		0x071E50EFA652C4DBULL,
		0xD90499EF9AD0E82DULL,
		0x4E08A9694E910CBBULL,
		0x020D6C0F77A76E1CULL,
		0xAD63DF8961F56A37ULL,
		0x8FE0CC13102D1E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8555646EDFDB1CBULL,
		0x7123C400E0191847ULL,
		0xC4BFF414D9B8B1ADULL,
		0x8DA74F6BBE2B0CBCULL,
		0x4EA8571D2B822D78ULL,
		0xD48E44EA1EB6B324ULL,
		0xED12C132E435562AULL,
		0x86F22B7967C99E93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB955C603D5E797AULL,
		0x4D1F330DDAFE0E32ULL,
		0x425E5CDACC9A132EULL,
		0x4B5D4A83DCA5DB70ULL,
		0xFF60524C230EDF43ULL,
		0x2D7F272558F0BAF7ULL,
		0xC0511E567DC0140CULL,
		0x08EEA099A8637FADULL
	}};
	sign = 0;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA4096414FF133CCULL,
		0x108D597C8617CEE4ULL,
		0x77375B069FF3EC38ULL,
		0x9B6F382CA3D45672ULL,
		0x9EA30D8EC0D991CBULL,
		0xBD9B41E482B7E302ULL,
		0x5E37997FEAED112BULL,
		0x8D2FF108921F2A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86D195EC937CBCB4ULL,
		0x9954CCDC3E37520DULL,
		0xC24B061052956BD8ULL,
		0xD5E5DA06439311F5ULL,
		0xA014407BF8DCBF97ULL,
		0x9510ADFAE2CF99E1ULL,
		0x025AF79548190905ULL,
		0xF9DF2E54E2A5EBE3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x536F0054BC747718ULL,
		0x77388CA047E07CD7ULL,
		0xB4EC54F64D5E805FULL,
		0xC5895E266041447CULL,
		0xFE8ECD12C7FCD233ULL,
		0x288A93E99FE84920ULL,
		0x5BDCA1EAA2D40826ULL,
		0x9350C2B3AF793E6AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3862B447EB340FB6ULL,
		0xF7E4C7F02C50ABD2ULL,
		0x44EE7A7A06EEA2EDULL,
		0xAFAD0C8E4394648DULL,
		0x7E8157E1E59C536EULL,
		0x882B67DAE45D2DEDULL,
		0x42A88D2F57BA11CDULL,
		0xAD36E9E05CA739C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC097E6092F382F3EULL,
		0x567F73385C9BEAA4ULL,
		0x265A88BBD42FB3D7ULL,
		0xCB1164D9799F02C0ULL,
		0xF786F2C5F8AFE020ULL,
		0xE67F41502A558DF6ULL,
		0x19CF4174442E31BBULL,
		0xDC1FCAD165BE912BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77CACE3EBBFBE078ULL,
		0xA16554B7CFB4C12DULL,
		0x1E93F1BE32BEEF16ULL,
		0xE49BA7B4C9F561CDULL,
		0x86FA651BECEC734DULL,
		0xA1AC268ABA079FF6ULL,
		0x28D94BBB138BE011ULL,
		0xD1171F0EF6E8A89AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8039074FCACD535AULL,
		0x064472A8B6C18632ULL,
		0x34516E6BA6CAEE78ULL,
		0x779A107F3D2498C0ULL,
		0xC5B641B1ECBA34FBULL,
		0x4BB10BA242640063ULL,
		0xD401958D8B0FDDD8ULL,
		0xEC01B1E04B385FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5088E9672406C3C5ULL,
		0x5A939CC53644FE9AULL,
		0x37512EE554E77D20ULL,
		0x8498EE851546F9F5ULL,
		0x1478866503C03D3AULL,
		0x179A3677A17C02BCULL,
		0xA375B4F2BB29B158ULL,
		0x2398271EA3021F8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB01DE8A6C68F95ULL,
		0xABB0D5E3807C8798ULL,
		0xFD003F8651E37157ULL,
		0xF30121FA27DD9ECAULL,
		0xB13DBB4CE8F9F7C0ULL,
		0x3416D52AA0E7FDA7ULL,
		0x308BE09ACFE62C80ULL,
		0xC8698AC1A836401CULL
	}};
	sign = 0;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22F70794770128B1ULL,
		0x6537C15E12E2C7F5ULL,
		0x49E6992FB75425E0ULL,
		0x67E53004AB04FEC7ULL,
		0xF9084C619BE36B9BULL,
		0x7442C62DD84FD77AULL,
		0x334E1DE6D50BED3AULL,
		0x9BEBBE2E46D72B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62E1B8BDF2B9F71EULL,
		0xFBD06C349DD305AEULL,
		0x129AEADDC45B7F56ULL,
		0xAB5F9984B661BB4CULL,
		0x8A9658063016D461ULL,
		0x9AFF707590A1BA95ULL,
		0xC39DBD6221E0ECC0ULL,
		0x34FF83CC25B7EBBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0154ED684473193ULL,
		0x69675529750FC246ULL,
		0x374BAE51F2F8A689ULL,
		0xBC85967FF4A3437BULL,
		0x6E71F45B6BCC9739ULL,
		0xD94355B847AE1CE5ULL,
		0x6FB06084B32B0079ULL,
		0x66EC3A62211F3F7BULL
	}};
	sign = 0;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86AE08028BDBE5A5ULL,
		0x35F10121618CFC61ULL,
		0x98AE5CCDBC43F5B7ULL,
		0x21532063C2A3A95BULL,
		0x3EF4D01F424C4D01ULL,
		0xE1F30D19958BFE1DULL,
		0x96241526DDECBB93ULL,
		0x73D2EB9DBBE21C58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D2D0444B5B68C2ULL,
		0xC2FE8CE59B9EF938ULL,
		0x0D6C65CD1ED473E7ULL,
		0xABE55B83C1FF180EULL,
		0x43A2EEBB0F64599FULL,
		0xB2F3209A552F5F30ULL,
		0x73B6E4C2CD63411AULL,
		0x176258BE814F6ABBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0DB37BE40807CE3ULL,
		0x72F2743BC5EE0328ULL,
		0x8B41F7009D6F81CFULL,
		0x756DC4E000A4914DULL,
		0xFB51E16432E7F361ULL,
		0x2EFFEC7F405C9EECULL,
		0x226D306410897A79ULL,
		0x5C7092DF3A92B19DULL
	}};
	sign = 0;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA11AE3B839F634EULL,
		0xCD215A8A6A822F7BULL,
		0x5F1BEEA39AD0B488ULL,
		0xDDCDA604E6DF0DCCULL,
		0xB0151E0F8958DE69ULL,
		0xACC4ABC920858364ULL,
		0xE895848EA2B81FB0ULL,
		0xCEF11B5E99155A9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C461042C25455AULL,
		0x0E8D3338D9D987EFULL,
		0x2B50E2C4FF516CD9ULL,
		0xE37BA511FBF068BEULL,
		0xF7B111A5C2CA4131ULL,
		0x806F5CACDA7C3A2FULL,
		0xE605C8E3EE98B48EULL,
		0xFD351298A805F074ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB24D4D37577A1DF4ULL,
		0xBE94275190A8A78BULL,
		0x33CB0BDE9B7F47AFULL,
		0xFA5200F2EAEEA50EULL,
		0xB8640C69C68E9D37ULL,
		0x2C554F1C46094934ULL,
		0x028FBBAAB41F6B22ULL,
		0xD1BC08C5F10F6A27ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB9C9495CCE61B43ULL,
		0x960C45ABB63F4CDDULL,
		0x9BF7A77CA0979167ULL,
		0xF02BBF5198119082ULL,
		0x49C5BC23C769274DULL,
		0x121D026EE6E38F08ULL,
		0x4CF3D64E914A9FF4ULL,
		0xEC2B2253E2B2460FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB51D7441E3CF1FB1ULL,
		0x7CD66E2C403EA243ULL,
		0x0451B2825D7F44CDULL,
		0x516EA8EB8636D9DCULL,
		0xFFF5FA97B42B30B3ULL,
		0xED26D9A067C5CB42ULL,
		0xB44AD5F1497AE647ULL,
		0xC48647FB56A40F31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x267F2053E916FB92ULL,
		0x1935D77F7600AA9AULL,
		0x97A5F4FA43184C9AULL,
		0x9EBD166611DAB6A6ULL,
		0x49CFC18C133DF69AULL,
		0x24F628CE7F1DC3C5ULL,
		0x98A9005D47CFB9ACULL,
		0x27A4DA588C0E36DDULL
	}};
	sign = 0;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C685723C4A6E364ULL,
		0xF0B34EDA94A734B0ULL,
		0xA7A3B0CDA9827A22ULL,
		0xCF41975821AC10C9ULL,
		0x562F8EA31E2C1DAAULL,
		0x1CA595772B949C59ULL,
		0x1838C8306AC1B652ULL,
		0xAC6B951D82627CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F812EA41B796912ULL,
		0x15A677D1B4F25B3CULL,
		0xB66F633B3FEFB0E7ULL,
		0xE1B9775265277752ULL,
		0x5CB47A30038F0AC8ULL,
		0x92EFF5D0CABE1D31ULL,
		0x180E771DDD7B281EULL,
		0xB976C6F8DEE52981ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CE7287FA92D7A52ULL,
		0xDB0CD708DFB4D974ULL,
		0xF1344D926992C93BULL,
		0xED882005BC849976ULL,
		0xF97B14731A9D12E1ULL,
		0x89B59FA660D67F27ULL,
		0x002A51128D468E33ULL,
		0xF2F4CE24A37D532FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D3CA8C0383F6F13ULL,
		0xC9F5A20D6CB991DEULL,
		0x6B458D31E87E8E81ULL,
		0xDAA38111AA8C6EF4ULL,
		0xF235CDA72622A1C0ULL,
		0xFE1C3B6800D81152ULL,
		0xC864A8451E1AAFC3ULL,
		0x99326188D87AA9E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D3160BFF2FA3C86ULL,
		0x750E9E9056CA64AAULL,
		0xEED28F83CB3E4E31ULL,
		0x2D3BCEE3906D29BAULL,
		0xDCEAB90B5FE22099ULL,
		0xD1E67E08147945F2ULL,
		0x92BCA65623B72333ULL,
		0x5D4196D4E8D3958AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100B48004545328DULL,
		0x54E7037D15EF2D34ULL,
		0x7C72FDAE1D404050ULL,
		0xAD67B22E1A1F4539ULL,
		0x154B149BC6408127ULL,
		0x2C35BD5FEC5ECB60ULL,
		0x35A801EEFA638C90ULL,
		0x3BF0CAB3EFA71459ULL
	}};
	sign = 0;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EE951A221F98ED9ULL,
		0x1642378043FECF6CULL,
		0xBCC5EE628D62E37CULL,
		0x951A2BD2C02A518EULL,
		0x850C5D58F5531AC6ULL,
		0x9066E091D5C4E3C8ULL,
		0x74CB33A058935D89ULL,
		0x3E01F7C6764602D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B1157518E65BA0ULL,
		0x5361BFE20A29839CULL,
		0xD1CADB2E386587A9ULL,
		0x007E7C5F8FFFE765ULL,
		0x499A9BD405536DF3ULL,
		0x6519A334A81FDC9CULL,
		0xD36CCDF5B41C6063ULL,
		0xA3BD369708797856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9383C2D09133339ULL,
		0xC2E0779E39D54BCFULL,
		0xEAFB133454FD5BD2ULL,
		0x949BAF73302A6A28ULL,
		0x3B71C184EFFFACD3ULL,
		0x2B4D3D5D2DA5072CULL,
		0xA15E65AAA476FD26ULL,
		0x9A44C12F6DCC8A79ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6F647D2F93B2D5DULL,
		0x34D429BCAC3F9258ULL,
		0x1679EAB156C8253EULL,
		0xEAE2AE8BB0111892ULL,
		0x1DF10BB712932753ULL,
		0x1BD77BFC5A2AB602ULL,
		0xDD5C72991374B49FULL,
		0xCC7F8B37D411A886ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41460412205C0592ULL,
		0x50255C4B51FEA58FULL,
		0xD46CFA6440F3BA4CULL,
		0xECC5BA1FC996B9D9ULL,
		0x1EFB96BAC58A3648ULL,
		0xC80C1D8E9DBA1D51ULL,
		0x61AFE315D6AC8A5DULL,
		0xF3984B29AEDEC5E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5B043C0D8DF27CBULL,
		0xE4AECD715A40ECC9ULL,
		0x420CF04D15D46AF1ULL,
		0xFE1CF46BE67A5EB8ULL,
		0xFEF574FC4D08F10AULL,
		0x53CB5E6DBC7098B0ULL,
		0x7BAC8F833CC82A41ULL,
		0xD8E7400E2532E2A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FDEBCED8734EB50ULL,
		0xA323C131C9D3BC48ULL,
		0x6F7EB37DA248296FULL,
		0x6038AC349EE58F3AULL,
		0x8C35FBD67850B96EULL,
		0x1D91818780891428ULL,
		0xF22A70904EE8C7D0ULL,
		0x978F352BF81BF26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7A1C3316626EE6ULL,
		0xDCF6D70FE3EF2ED8ULL,
		0xBF827F3F54E3E080ULL,
		0xF9E99F791C91FBD2ULL,
		0x6DDC2CE5369E9364ULL,
		0x9E126F4014143F6EULL,
		0xF6931DFE76CE74D9ULL,
		0x6F0FD2D54EE5ABA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD464A0BA70D27C6AULL,
		0xC62CEA21E5E48D6FULL,
		0xAFFC343E4D6448EEULL,
		0x664F0CBB82539367ULL,
		0x1E59CEF141B22609ULL,
		0x7F7F12476C74D4BAULL,
		0xFB975291D81A52F6ULL,
		0x287F6256A93646C8ULL
	}};
	sign = 0;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9AC1542C99B021FULL,
		0x39E8D4E3D003D2D9ULL,
		0x783B57A06B5A59B7ULL,
		0x1AF1E114C21DFA00ULL,
		0x5CCA1BF554F0C830ULL,
		0xBB1CDCBEED560710ULL,
		0x7743341111A53711ULL,
		0x8BC138FAA984E41DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5701F8F73995B132ULL,
		0x8B0DFE8EE13E96C6ULL,
		0xBC4CC5EE95386176ULL,
		0x7AA7471F6A97A081ULL,
		0x58BD01B49CA497AFULL,
		0xD02A600DE8DF5B88ULL,
		0x3CA9C4C3BC5D302AULL,
		0x5863B785159EC2B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52AA1C4B900550EDULL,
		0xAEDAD654EEC53C13ULL,
		0xBBEE91B1D621F840ULL,
		0xA04A99F55786597EULL,
		0x040D1A40B84C3080ULL,
		0xEAF27CB10476AB88ULL,
		0x3A996F4D554806E6ULL,
		0x335D817593E6216AULL
	}};
	sign = 0;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE7F7A80560731C7ULL,
		0x654F301B51BD360DULL,
		0x607D736FB016DD0FULL,
		0x8FFB62DC91FCA910ULL,
		0x1982D1B0E9A82B90ULL,
		0xE1C319662E8D0475ULL,
		0xF8FA5161216E2FA1ULL,
		0xE804BFF1D7455627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AFDDF282A0B7339ULL,
		0xDE6FC023631D1077ULL,
		0xE98F66295AB28764ULL,
		0x9AAC9E31C4E98F80ULL,
		0x0BED99A54B04ED36ULL,
		0xE16F7E2C31713699ULL,
		0xFF2B8740E396F3F9ULL,
		0x7073FC94496FA9A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83819B582BFBBE8EULL,
		0x86DF6FF7EEA02596ULL,
		0x76EE0D46556455AAULL,
		0xF54EC4AACD13198FULL,
		0x0D95380B9EA33E59ULL,
		0x00539B39FD1BCDDCULL,
		0xF9CECA203DD73BA8ULL,
		0x7790C35D8DD5AC82ULL
	}};
	sign = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28EE85B1BC1C20AFULL,
		0xF5B3C581C5015281ULL,
		0x73A00C531EBCDD22ULL,
		0x1E091F712F402532ULL,
		0x32B5C9DE215605E6ULL,
		0xDDB107D033D3CA27ULL,
		0xC94BF46847F33CE3ULL,
		0xCD06B978139D3248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1F2B71ACF16013CULL,
		0xC45BEBA2232A7D52ULL,
		0x6C7101377B07AA3BULL,
		0xC28FE6A646CB98DEULL,
		0xD4FCF15F3F6CEF99ULL,
		0x0AEA82EAB056557BULL,
		0x44B0C363950FA432ULL,
		0x920D1B4F35EF25B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56FBCE96ED061F73ULL,
		0x3157D9DFA1D6D52EULL,
		0x072F0B1BA3B532E7ULL,
		0x5B7938CAE8748C54ULL,
		0x5DB8D87EE1E9164CULL,
		0xD2C684E5837D74ABULL,
		0x849B3104B2E398B1ULL,
		0x3AF99E28DDAE0C96ULL
	}};
	sign = 0;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADC0FDF507A050A3ULL,
		0xDB9FF40E88FEC30AULL,
		0x186E6E710D92A05FULL,
		0x192543D9D6C8681AULL,
		0x24106DB380D047E3ULL,
		0x6731D11EE243BC9BULL,
		0x49D9A92BC00EBB60ULL,
		0x0C452C38880833DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32FC291EEDA044A7ULL,
		0x05E7CEEF5780889AULL,
		0xEB3019206A16A31EULL,
		0xC506C5411F0A3A1FULL,
		0xA383A59756C10D5DULL,
		0xB6B33B3BBF2DE16CULL,
		0x8AA01E2648FA4D5AULL,
		0x2E0557FD8F43BBC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AC4D4D61A000BFCULL,
		0xD5B8251F317E3A70ULL,
		0x2D3E5550A37BFD41ULL,
		0x541E7E98B7BE2DFAULL,
		0x808CC81C2A0F3A85ULL,
		0xB07E95E32315DB2EULL,
		0xBF398B0577146E05ULL,
		0xDE3FD43AF8C4781CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x365DBA73A7136E4FULL,
		0x705F7C5A5D606BB1ULL,
		0x92A89866E9CB98F4ULL,
		0x32513C3874DE102AULL,
		0x3771C57FA3ADD509ULL,
		0x8299ED99D058F290ULL,
		0x115250A5EE5AF23BULL,
		0xAFA768F3A9F6BA84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA93CA90F63BDBB60ULL,
		0xCFC557D40AD15B1CULL,
		0x3127FA4F886C8AA3ULL,
		0x1DEC8D5E189CE864ULL,
		0xDF407497B5B07F07ULL,
		0xF1B4006BD2F98C53ULL,
		0x4BA26D4C94E64F63ULL,
		0x5D70CAE0FAB10E74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D2111644355B2EFULL,
		0xA09A2486528F1094ULL,
		0x61809E17615F0E50ULL,
		0x1464AEDA5C4127C6ULL,
		0x583150E7EDFD5602ULL,
		0x90E5ED2DFD5F663CULL,
		0xC5AFE3595974A2D7ULL,
		0x52369E12AF45AC0FULL
	}};
	sign = 0;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30399E30E5032C2AULL,
		0xA083F014B90C5FD5ULL,
		0x3866B4B4129E63BDULL,
		0xA5E59BF75B5CFC98ULL,
		0x26606DE7DA84A4DCULL,
		0x4B84E77DF014F2AEULL,
		0xAAB37905F03FDCD1ULL,
		0xB84FFAE7D84C4A4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E418CAD6BC536F4ULL,
		0xDF13B3F4D66769B9ULL,
		0xA9966DCEC2B7D692ULL,
		0xBCBB2D9CEB610D07ULL,
		0x662E3C5886B247ACULL,
		0x4263BE8B664CCA3EULL,
		0xA23013E101CC1EB0ULL,
		0x0CC2548B2AA07DB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F81183793DF536ULL,
		0xC1703C1FE2A4F61BULL,
		0x8ED046E54FE68D2AULL,
		0xE92A6E5A6FFBEF90ULL,
		0xC032318F53D25D2FULL,
		0x092128F289C8286FULL,
		0x08836524EE73BE21ULL,
		0xAB8DA65CADABCC94ULL
	}};
	sign = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4787AC23CB8C66B0ULL,
		0x3030E06D627BEBD1ULL,
		0x861A766CB9116A46ULL,
		0xE79C512E7D2E1DC3ULL,
		0x637815FE7644CFF8ULL,
		0x227E4A6548025491ULL,
		0x356DC4704E00DFB9ULL,
		0xB23A8CAD0A3D8E0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EE0B302286A3A6EULL,
		0x9B379F9DA6FEA5F1ULL,
		0xFC914A0BCA6D60E2ULL,
		0x97F43A0ACF2FEDAEULL,
		0x80FF3873B05BEC35ULL,
		0xBEA3CD8777CC2BB6ULL,
		0xABD75872916E28A8ULL,
		0x38B05A55ABB04D1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8A6F921A3222C42ULL,
		0x94F940CFBB7D45DFULL,
		0x89892C60EEA40963ULL,
		0x4FA81723ADFE3014ULL,
		0xE278DD8AC5E8E3C3ULL,
		0x63DA7CDDD03628DAULL,
		0x89966BFDBC92B710ULL,
		0x798A32575E8D40EDULL
	}};
	sign = 0;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC266FDA855FDB3CCULL,
		0x1F07249977B3FD97ULL,
		0x61DB22B4438074DDULL,
		0x3FB8EE0ADD7E8E0EULL,
		0x17CE9570991A4073ULL,
		0x18A10577D406BA0DULL,
		0xE282BF15872398FDULL,
		0x14C67F1875CEFB28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182D478722F0B01CULL,
		0x3178F2A2F8C0FF55ULL,
		0x6AAF8AA1A46A7788ULL,
		0xA8C636FECA5D7C61ULL,
		0xCD1D2174C24193B7ULL,
		0xFF7BABD96F80D597ULL,
		0x7E2AC9D0EB70D6BEULL,
		0x900E9A82F5C265DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA39B621330D03B0ULL,
		0xED8E31F67EF2FE42ULL,
		0xF72B98129F15FD54ULL,
		0x96F2B70C132111ACULL,
		0x4AB173FBD6D8ACBBULL,
		0x1925599E6485E475ULL,
		0x6457F5449BB2C23EULL,
		0x84B7E495800C9549ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE827331D907AF492ULL,
		0xC842D4A849DBC6EFULL,
		0xE87F29FC73AAEA34ULL,
		0xE968E3809445536FULL,
		0x2BE8D6F55FB7806BULL,
		0xE8FEC68451243CB4ULL,
		0xE1A78E9AB047E080ULL,
		0xCC3FA7C14EF4927AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013402580EABD153ULL,
		0x2606A158E64B346FULL,
		0x52C73E35609F4119ULL,
		0x337688519237EC8EULL,
		0x7EBB17E94FCDDBD9ULL,
		0x5E9617CA0C82B81BULL,
		0x8C91B797612559DCULL,
		0x5CA12705F56D133AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6F330C581CF233FULL,
		0xA23C334F63909280ULL,
		0x95B7EBC7130BA91BULL,
		0xB5F25B2F020D66E1ULL,
		0xAD2DBF0C0FE9A492ULL,
		0x8A68AEBA44A18498ULL,
		0x5515D7034F2286A4ULL,
		0x6F9E80BB59877F40ULL
	}};
	sign = 0;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AE037064BD14868ULL,
		0xB401018FF822B15AULL,
		0xD1BA0575CA7A94C2ULL,
		0x37011888FBA19D02ULL,
		0x011295D7844FCA73ULL,
		0x6662FD3AFCCD8A67ULL,
		0xB5386BF69D932054ULL,
		0x683A0AEC5579AE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F30416BD1D0C4E7ULL,
		0x27B328702028D7EFULL,
		0xCBB04CF06E9754BCULL,
		0x0A6A3183B1A76118ULL,
		0xE98D87F2B090EE28ULL,
		0x81055B4E778BC389ULL,
		0x6CC13DAC67F50C9BULL,
		0xCF8FE6F067F064DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEBAFF59A7A008381ULL,
		0x8C4DD91FD7F9D96AULL,
		0x0609B8855BE34006ULL,
		0x2C96E70549FA3BEAULL,
		0x17850DE4D3BEDC4BULL,
		0xE55DA1EC8541C6DDULL,
		0x48772E4A359E13B8ULL,
		0x98AA23FBED8949ADULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4A500A51DDFDADAULL,
		0x5CC2037EB0F6EE81ULL,
		0xA0414B3E4E7C38C2ULL,
		0xD4972D32C61E0936ULL,
		0x821C709E6D264E5EULL,
		0xAA1AE61868440209ULL,
		0x2A8431841E4E51BAULL,
		0x6305A01304CBA21CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D81B0D55AF94ABULL,
		0x5C8A94FEAE38CC6EULL,
		0xD57BC3A768E02FB2ULL,
		0x32BABE0D133A02E6ULL,
		0x978590C83363EBACULL,
		0x1A6D3B0367173852ULL,
		0xED229C610BB9EA43ULL,
		0xD6A0E3148A4E1827ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BCCE597C830462FULL,
		0x00376E8002BE2213ULL,
		0xCAC58796E59C0910ULL,
		0xA1DC6F25B2E4064FULL,
		0xEA96DFD639C262B2ULL,
		0x8FADAB15012CC9B6ULL,
		0x3D61952312946777ULL,
		0x8C64BCFE7A7D89F4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x465E2C68A7E1E434ULL,
		0x8AA4D202C9CD776FULL,
		0x8E45A112A9FED666ULL,
		0x57EC17061204C9A5ULL,
		0x90163E4F61864475ULL,
		0x2A59A928E7CE92BAULL,
		0xFFD8E9D05E238DE0ULL,
		0x43534E10D228220CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0640E3E89530F860ULL,
		0x684F5D0F51DF314AULL,
		0xAED9376EE788BE51ULL,
		0x65BB2ED6382C06BCULL,
		0x2AB67491E0801C3EULL,
		0xACCBD264DD845EB6ULL,
		0xC3B0B951C83B60DEULL,
		0x3AD4DCE569FD258DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401D488012B0EBD4ULL,
		0x225574F377EE4625ULL,
		0xDF6C69A3C2761815ULL,
		0xF230E82FD9D8C2E8ULL,
		0x655FC9BD81062836ULL,
		0x7D8DD6C40A4A3404ULL,
		0x3C28307E95E82D01ULL,
		0x087E712B682AFC7FULL
	}};
	sign = 0;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x623EC731F360A8ADULL,
		0x15A2EBE2ABE9BDEBULL,
		0xF5F231DB2BEA8E0FULL,
		0x5F7F4C66A9B2C32CULL,
		0xEA054933C859C352ULL,
		0xC472DF89EB5F07CAULL,
		0x9386A277C250013CULL,
		0xD5403C1A2DE689D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CE1354B2AFE9689ULL,
		0xCF1F8E95BFB53F78ULL,
		0x35DCF7AA126F2E54ULL,
		0x30EB6C9348882369ULL,
		0x531097F9BBD4F0DBULL,
		0x7CA32727E6CD477DULL,
		0x6FA143AA31B92B61ULL,
		0xCD98BE4C5CF6C096ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x455D91E6C8621224ULL,
		0x46835D4CEC347E73ULL,
		0xC0153A31197B5FBAULL,
		0x2E93DFD3612A9FC3ULL,
		0x96F4B13A0C84D277ULL,
		0x47CFB8620491C04DULL,
		0x23E55ECD9096D5DBULL,
		0x07A77DCDD0EFC940ULL
	}};
	sign = 0;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3D70A2103ED08ACULL,
		0xD725A95C91E8EF4CULL,
		0xEB4427769911EB8EULL,
		0x1A13EFCE294E7915ULL,
		0xE8B1C7B5F9D0CFFAULL,
		0x9BBD2E5B7F5CC485ULL,
		0x8227B662A5028451ULL,
		0xFDBDFBEB905C700EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20FE60929BC7A263ULL,
		0x645C700B6524817EULL,
		0x0E38A04A5804D372ULL,
		0xD1233DF3B441F464ULL,
		0x76CA348F4A1DA401ULL,
		0x6DBA3A57C2DAB475ULL,
		0x31F0D8E170ED6F07ULL,
		0xEDD621EE2220124BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2D8A98E68256649ULL,
		0x72C939512CC46DCEULL,
		0xDD0B872C410D181CULL,
		0x48F0B1DA750C84B1ULL,
		0x71E79326AFB32BF8ULL,
		0x2E02F403BC821010ULL,
		0x5036DD813415154AULL,
		0x0FE7D9FD6E3C5DC3ULL
	}};
	sign = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F0E0C14FB957428ULL,
		0xCCAE58D1EE573320ULL,
		0x200EA0102C1B7A7CULL,
		0xD7AC4603C5B9B527ULL,
		0x875FA8568EC6760FULL,
		0xB60B15FBCBBBBA3EULL,
		0x6A6ABCDA9A31D2BEULL,
		0x054E35498499F8DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B31081B242753A9ULL,
		0xECE1BB39D4E51EA2ULL,
		0xBE64CA2DAE4FCFCDULL,
		0x6D6E60991FC00B48ULL,
		0xF715C024988DE6F4ULL,
		0x0EEC9B242EF1CBDCULL,
		0xEA23D2EB6DE9B69FULL,
		0xAE78D453CA2A8D07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03DD03F9D76E207FULL,
		0xDFCC9D981972147EULL,
		0x61A9D5E27DCBAAAEULL,
		0x6A3DE56AA5F9A9DEULL,
		0x9049E831F6388F1BULL,
		0xA71E7AD79CC9EE61ULL,
		0x8046E9EF2C481C1FULL,
		0x56D560F5BA6F6BD5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BB4A00BAFEB3602ULL,
		0xB422670AAAE6542DULL,
		0x20864F759D2D7446ULL,
		0x73B747E67416C46AULL,
		0xCCED370AF9227E65ULL,
		0x48885A048AF76B12ULL,
		0x2D58A0B7593AB74EULL,
		0xD0CD0D2CAED6AA1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63B66052A7708528ULL,
		0xF04991244D7E86E0ULL,
		0xD0D7FB6A1986B784ULL,
		0x89BBEA3DF4DB0273ULL,
		0xD6C57949D3ADAE7AULL,
		0xC37B9D96D411AA3FULL,
		0xC8309B89C7A66180ULL,
		0xF543A590003187C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7FE3FB9087AB0DAULL,
		0xC3D8D5E65D67CD4CULL,
		0x4FAE540B83A6BCC1ULL,
		0xE9FB5DA87F3BC1F6ULL,
		0xF627BDC12574CFEAULL,
		0x850CBC6DB6E5C0D2ULL,
		0x6528052D919455CDULL,
		0xDB89679CAEA52253ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B03956427E8A939ULL,
		0x2FA952899FE202FCULL,
		0x503E55CD677C4BBAULL,
		0x551BD0EA470D96DAULL,
		0x68B420B156EE9AB1ULL,
		0x626313976DE3C201ULL,
		0xDEE4EDFBD240FC3FULL,
		0x73B10406E8D37F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC258A048CA5AD722ULL,
		0x2F474719C108E8E1ULL,
		0xD00B6F6C2A36C843ULL,
		0x7EC2A7E0FC893CF4ULL,
		0xF7CEC2D71670614DULL,
		0x04FDFAEC56D164E9ULL,
		0x4CA567EB6089C333ULL,
		0x5E38686433E94F1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88AAF51B5D8DD217ULL,
		0x00620B6FDED91A1AULL,
		0x8032E6613D458377ULL,
		0xD65929094A8459E5ULL,
		0x70E55DDA407E3963ULL,
		0x5D6518AB17125D17ULL,
		0x923F861071B7390CULL,
		0x15789BA2B4EA3035ULL
	}};
	sign = 0;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4689E989F607A151ULL,
		0xDB6C96E71E594B98ULL,
		0x23C50C800CFF101DULL,
		0xD726A107586F2C75ULL,
		0x98CDE10F335A47A1ULL,
		0xF1A4C38559EA1A9DULL,
		0x686AAF2680D94538ULL,
		0x3A98608F085588FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x702B164F2EABE131ULL,
		0x73FAA4780FD07C6BULL,
		0x50DA995431184663ULL,
		0x9544DCE0BB07CBC4ULL,
		0xDF2894EF13E164A4ULL,
		0x17267F556A4CA3BDULL,
		0xFA45B147C34AD69CULL,
		0x79B4B142E7F0D070ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD65ED33AC75BC020ULL,
		0x6771F26F0E88CF2CULL,
		0xD2EA732BDBE6C9BAULL,
		0x41E1C4269D6760B0ULL,
		0xB9A54C201F78E2FDULL,
		0xDA7E442FEF9D76DFULL,
		0x6E24FDDEBD8E6E9CULL,
		0xC0E3AF4C2064B88DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x072D1F879259B95EULL,
		0x123600795C7FA04BULL,
		0x98914BE6FD98CDAFULL,
		0xEAF38DB0F43091F9ULL,
		0x5006E9FA8B06FC89ULL,
		0xBE8F51CCF656BCA7ULL,
		0xCE980ECE6BA975D6ULL,
		0xA0390721F6E4F420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2266D4014BD1CFDFULL,
		0x55A640B2C8CB1103ULL,
		0x96E7D405C3B27B0CULL,
		0x945378D3D53F24CEULL,
		0xF120AE7A5B0A27FEULL,
		0x721B9F64B13BC047ULL,
		0xC3AD73437DE29680ULL,
		0x63DD2218012B9431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4C64B864687E97FULL,
		0xBC8FBFC693B48F47ULL,
		0x01A977E139E652A2ULL,
		0x56A014DD1EF16D2BULL,
		0x5EE63B802FFCD48BULL,
		0x4C73B268451AFC5FULL,
		0x0AEA9B8AEDC6DF56ULL,
		0x3C5BE509F5B95FEFULL
	}};
	sign = 0;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCFDAAFD5E733650EULL,
		0xA69D2B0E23CC7373ULL,
		0xE2EE6C51F40ADF13ULL,
		0x12F80AA357264B02ULL,
		0xA2EAE40F686069F6ULL,
		0x96E4B8C899D568AEULL,
		0x5503F051D280C3BFULL,
		0xDD9677F8B99DB4B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0273651F2C42FA52ULL,
		0x37DBC830DBA256AEULL,
		0x667738C2041FFE23ULL,
		0x1E2C02C2BD6F09DDULL,
		0x122FCFEBD452D86AULL,
		0x950A3ED043D6E069ULL,
		0x55A7C4D0491B55DBULL,
		0x4D0C9E27AB019F4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD674AB6BAF06ABCULL,
		0x6EC162DD482A1CC5ULL,
		0x7C77338FEFEAE0F0ULL,
		0xF4CC07E099B74125ULL,
		0x90BB1423940D918BULL,
		0x01DA79F855FE8845ULL,
		0xFF5C2B8189656DE4ULL,
		0x9089D9D10E9C1565ULL
	}};
	sign = 0;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD7C66B9BD46EC48ULL,
		0x9E6501D2113D5603ULL,
		0xD297FEC85EE64153ULL,
		0xB6854CE108995FE8ULL,
		0x9D4B7C42357EDFF5ULL,
		0x2876CC04585821D6ULL,
		0x2281105164608C7CULL,
		0x8FC80D40269E41D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9C2E3D876409D7DULL,
		0x7D3CA3D87C901F04ULL,
		0xAA36588476DE9CA2ULL,
		0xAF334F8BBDEE7B3FULL,
		0x1B702DC3D0E25D5DULL,
		0x3C56D6EE2598009FULL,
		0x981D6EBF50E7AA22ULL,
		0xB3897A8A5A3BDC06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD3B982E147064ECBULL,
		0x21285DF994AD36FEULL,
		0x2861A643E807A4B1ULL,
		0x0751FD554AAAE4A9ULL,
		0x81DB4E7E649C8298ULL,
		0xEC1FF51632C02137ULL,
		0x8A63A1921378E259ULL,
		0xDC3E92B5CC6265CDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC59883FD6CD96EA0ULL,
		0x17C3A2903E6D82DCULL,
		0xFAE210995884521AULL,
		0x1151825C1AA6159EULL,
		0x1E2A0FE11A973699ULL,
		0xF6259DF028DEE724ULL,
		0x8ECB2B5DA4185C42ULL,
		0x310D97A513B2ECD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC62109D3A3587C9AULL,
		0x90F5C7D281932401ULL,
		0x7EA0CE8B218D2629ULL,
		0xDE0A99C5C41CF4F6ULL,
		0x666237C020C5A6B5ULL,
		0x3F3CE91E621C0352ULL,
		0xBD5E7DA06EDBDC83ULL,
		0x5CCEBFEAADD9DAB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF777A29C980F206ULL,
		0x86CDDABDBCDA5EDAULL,
		0x7C41420E36F72BF0ULL,
		0x3346E896568920A8ULL,
		0xB7C7D820F9D18FE3ULL,
		0xB6E8B4D1C6C2E3D1ULL,
		0xD16CADBD353C7FBFULL,
		0xD43ED7BA65D9121BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA8C06AB06A424B0ULL,
		0xFA2310C4234DE20DULL,
		0x7128FF688341E6AAULL,
		0xBF74C9387A534B9DULL,
		0x09E6BE21395FE67AULL,
		0xA68E003FD0F1EE56ULL,
		0x57A2D8638B43AB4FULL,
		0x1B352AE1F4BD9BEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x810CBC3093363067ULL,
		0xB2D26854F192FC4FULL,
		0xEEAF3D89AA5B7E9CULL,
		0xD10C36C4A56097EFULL,
		0x540AC8828EA2D36CULL,
		0x5B50B134356D15E1ULL,
		0x6B30D859BA891FFDULL,
		0x2D9AE061C4D4B6E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x497F4A7A736DF449ULL,
		0x4750A86F31BAE5BEULL,
		0x8279C1DED8E6680EULL,
		0xEE689273D4F2B3ADULL,
		0xB5DBF59EAABD130DULL,
		0x4B3D4F0B9B84D874ULL,
		0xEC720009D0BA8B52ULL,
		0xED9A4A802FE8E50EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF087F7202F126E0ULL,
		0x95BA48E9BBE0E13AULL,
		0x5857ADF6F33D06D4ULL,
		0x4437D65E569236C7ULL,
		0x225FB4542800F0B9ULL,
		0x9D00DEF85EA75C8EULL,
		0x3BA41F19B39729BEULL,
		0x243122A654E17840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125967C262D36004ULL,
		0xF06E296C49178BC9ULL,
		0xB467433D5B17E97DULL,
		0x59A252D77B56E34BULL,
		0xC2EC71AE58E9A1C5ULL,
		0xD5CE7C34C9E90175ULL,
		0x3631FDA45B4C0A86ULL,
		0x6F1650D321FA16A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECAF17AFA01DC6DCULL,
		0xA54C1F7D72C95571ULL,
		0xA3F06AB998251D56ULL,
		0xEA958386DB3B537BULL,
		0x5F7342A5CF174EF3ULL,
		0xC73262C394BE5B18ULL,
		0x05722175584B1F37ULL,
		0xB51AD1D332E761A0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C344D75771378A6ULL,
		0x07B03029F2DBD80EULL,
		0xC07D3BF0C5E333D0ULL,
		0xB5F0FAE2FF3E26E8ULL,
		0x3310F39C602C4C19ULL,
		0xFAF754675B2048CCULL,
		0x4B196704D4BFA4C1ULL,
		0xDF9880DD178C2C98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012902A3B11B5DE5ULL,
		0x9F38BA58C7F16B86ULL,
		0x9F82C9D1659B4735ULL,
		0xACF8C02CEB517A95ULL,
		0xBEC0706986A7A334ULL,
		0x95A45593E61C0AB1ULL,
		0x453583CCAFC16941ULL,
		0xD42CB14ED6849847ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7B0B4AD1C5F81AC1ULL,
		0x687775D12AEA6C88ULL,
		0x20FA721F6047EC9AULL,
		0x08F83AB613ECAC53ULL,
		0x74508332D984A8E5ULL,
		0x6552FED375043E1AULL,
		0x05E3E33824FE3B80ULL,
		0x0B6BCF8E41079451ULL
	}};
	sign = 0;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C594C8ABBC5CEB0ULL,
		0x15709302D6915493ULL,
		0x723DB0BD711E691EULL,
		0x6251D95D60006464ULL,
		0x4B984BCC5A6A3D71ULL,
		0x478AD00BEAA3AB24ULL,
		0x659D12D4610D814EULL,
		0xABBC8E733585C15AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x623859701B8995EBULL,
		0x83015F6A2F0B6A9DULL,
		0xDA7BE1A2301C56A3ULL,
		0x70B806BA5FCDB345ULL,
		0xB7821B69D2598BBAULL,
		0x682C616B9B8866D8ULL,
		0x663612C67063D736ULL,
		0x83CD797899690820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA20F31AA03C38C5ULL,
		0x926F3398A785E9F5ULL,
		0x97C1CF1B4102127AULL,
		0xF199D2A30032B11EULL,
		0x941630628810B1B6ULL,
		0xDF5E6EA04F1B444BULL,
		0xFF67000DF0A9AA17ULL,
		0x27EF14FA9C1CB939ULL
	}};
	sign = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49B7D1B147813695ULL,
		0x0A09CB3CB4774A13ULL,
		0x1EF0AA4E324C96AEULL,
		0x2CCF21F303005052ULL,
		0xF9D14ADDFF1AF60AULL,
		0x2E3162DB6CD718B6ULL,
		0xAC390A6DD66794E6ULL,
		0xCDADCEA4AF27758DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D37882E6A092002ULL,
		0x6E1820D3F491B815ULL,
		0xBD3CB2A80DF31E57ULL,
		0x6C802F17B69134D9ULL,
		0xC858C75FD6CF8924ULL,
		0x787C42BB03B62482ULL,
		0x7DD5A80453E3D102ULL,
		0x2BEEEC7FA87CF190ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C804982DD781693ULL,
		0x9BF1AA68BFE591FEULL,
		0x61B3F7A624597856ULL,
		0xC04EF2DB4C6F1B78ULL,
		0x3178837E284B6CE5ULL,
		0xB5B520206920F434ULL,
		0x2E6362698283C3E3ULL,
		0xA1BEE22506AA83FDULL
	}};
	sign = 0;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3940A2284507D477ULL,
		0x02021D19BB20349BULL,
		0x14E318C6FCC3A253ULL,
		0x45B7FFD405ED3897ULL,
		0xA6362EB84FDAA90BULL,
		0x43B4ACF699C9ACF1ULL,
		0x764A0FC539AA2AD7ULL,
		0x3DDCD355C2647CC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB7859E8CE8A3F90ULL,
		0xF6C726FAF6654C77ULL,
		0xCE784048DC8AEEF2ULL,
		0xD04BCA0D8D5952E5ULL,
		0xFEC4B782853EC9C8ULL,
		0x9E5FACFA8692377EULL,
		0x9534E8DE3C6FE3BDULL,
		0x1E2E4CAC7807E954ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DC8483F767D94E7ULL,
		0x0B3AF61EC4BAE823ULL,
		0x466AD87E2038B360ULL,
		0x756C35C67893E5B1ULL,
		0xA7717735CA9BDF42ULL,
		0xA554FFFC13377572ULL,
		0xE11526E6FD3A4719ULL,
		0x1FAE86A94A5C9374ULL
	}};
	sign = 0;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43B101DAA50590FAULL,
		0x97D66435499BD16BULL,
		0x639C51619EDFF427ULL,
		0xFE1897284EE9D79CULL,
		0xF6111FEE0A64995BULL,
		0xCD38E6F84E5C7921ULL,
		0x38E599138A2EEC79ULL,
		0x2F402393EBFBFE98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAD200E902CE7703ULL,
		0x2D57CC7ECDF1EA54ULL,
		0xF1844438BFBFBEB0ULL,
		0xC710B23EE0750156ULL,
		0x73C883E04EEDCC91ULL,
		0x0A8863BE33F3F86AULL,
		0xEFE7A807454DE51EULL,
		0xE4F057C96F4E18BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88DF00F1A23719F7ULL,
		0x6A7E97B67BA9E716ULL,
		0x72180D28DF203577ULL,
		0x3707E4E96E74D645ULL,
		0x82489C0DBB76CCCAULL,
		0xC2B0833A1A6880B7ULL,
		0x48FDF10C44E1075BULL,
		0x4A4FCBCA7CADE5DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2841182812BF74CBULL,
		0xC661D74D4A3D9AD1ULL,
		0x471821E0CDD4E83AULL,
		0x0E30A5F0C48A62A2ULL,
		0xDB7CB4230177ACBEULL,
		0x4973FC0B40B52A8FULL,
		0x8E138F7E34BB0738ULL,
		0x723F3286C8324090ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4BC58C7556FC51ULL,
		0x7B80BFED5002F6C2ULL,
		0x30A4095380E29115ULL,
		0xD792FBECD84EDB38ULL,
		0xC44C87A8C332EFEBULL,
		0x430DE353C0CE717BULL,
		0xB47678F96D53B206ULL,
		0x915170A2BA8C61AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BF5529B9D68787AULL,
		0x4AE1175FFA3AA40EULL,
		0x1674188D4CF25725ULL,
		0x369DAA03EC3B876AULL,
		0x17302C7A3E44BCD2ULL,
		0x066618B77FE6B914ULL,
		0xD99D1684C7675532ULL,
		0xE0EDC1E40DA5DEE5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09575B392C00A5C8ULL,
		0xD9F16A65C0D53A95ULL,
		0x77FDD9297AB66C68ULL,
		0x74AE5CC3D627099FULL,
		0xDAFCC0D7813AFC30ULL,
		0xDF50E532D8A0DEFEULL,
		0x29A8A45E81E97224ULL,
		0xE2FB7F4ACBCA585DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE85641E3D645D96ULL,
		0xC315C770A9337173ULL,
		0x48B1717B6AAC6D37ULL,
		0x45D4108E6B2AC6CAULL,
		0xC1943D5689398486ULL,
		0x85CD96F127DBF116ULL,
		0x8A13EE01C1EEC6B4ULL,
		0xDB70D85611530638ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AD1F71AEE9C4832ULL,
		0x16DBA2F517A1C921ULL,
		0x2F4C67AE1009FF31ULL,
		0x2EDA4C356AFC42D5ULL,
		0x19688380F80177AAULL,
		0x59834E41B0C4EDE8ULL,
		0x9F94B65CBFFAAB70ULL,
		0x078AA6F4BA775224ULL
	}};
	sign = 0;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB380CDE00EBA4BF3ULL,
		0x769B77DD4533699DULL,
		0x823518E79BF11BA1ULL,
		0xFEEE2A9CF24E2FC3ULL,
		0xCD149E003026E0B1ULL,
		0x7002003384625FADULL,
		0x35376579DC50149BULL,
		0x333AEA5AD03EF6B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34448BA21FC1706DULL,
		0x14FCFEEFD98BD69CULL,
		0x980D8D90F83B3374ULL,
		0x5B11347C81395C44ULL,
		0x1BF6683BFB7BD0FFULL,
		0x0EBFF1E651568D4DULL,
		0x4CB1BDC41A41EACBULL,
		0xAE592ABC8746050EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F3C423DEEF8DB86ULL,
		0x619E78ED6BA79301ULL,
		0xEA278B56A3B5E82DULL,
		0xA3DCF6207114D37EULL,
		0xB11E35C434AB0FB2ULL,
		0x61420E4D330BD260ULL,
		0xE885A7B5C20E29D0ULL,
		0x84E1BF9E48F8F1A5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x987B06F21D19303EULL,
		0x711978A0EFDAE0D3ULL,
		0x6912C65F81A007DAULL,
		0xE98729AF2E2AF089ULL,
		0x389229EE841F74A2ULL,
		0x9370283912D378BAULL,
		0x0E9F6477598D26A1ULL,
		0xC233CD233BB31459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A06C2A1B6565905ULL,
		0xFB4B3BBEAEBE9170ULL,
		0xA0EAF40FB3F92A13ULL,
		0xB3B56F0E00650EDFULL,
		0xCA15AF1ABCA297D1ULL,
		0xEF6EB63F2B51B91AULL,
		0x15AA4B1C2E59EEAAULL,
		0xBE540272AF6C46B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE74445066C2D739ULL,
		0x75CE3CE2411C4F62ULL,
		0xC827D24FCDA6DDC6ULL,
		0x35D1BAA12DC5E1A9ULL,
		0x6E7C7AD3C77CDCD1ULL,
		0xA40171F9E781BF9FULL,
		0xF8F5195B2B3337F6ULL,
		0x03DFCAB08C46CDA8ULL
	}};
	sign = 0;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D8C44C26BF22CA1ULL,
		0x6C78F75B1CF42F38ULL,
		0x4568C7EE822516FEULL,
		0x3484B8966CE1CFD2ULL,
		0x563AC2F421950900ULL,
		0xD1EEDC604B199193ULL,
		0x1C3ACC654AA3DC46ULL,
		0x5801D610DD345797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A3D17625C6BF70ULL,
		0xCDD0EDC9481CA6B5ULL,
		0xA3EA8AE6B1C6DFDBULL,
		0x7C7545695D71B8B4ULL,
		0xCADADBA398193F61ULL,
		0xC1A37A663713998FULL,
		0x933B65D591524774ULL,
		0x815A60FC9E80B0C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E8734C462B6D31ULL,
		0x9EA80991D4D78883ULL,
		0xA17E3D07D05E3722ULL,
		0xB80F732D0F70171DULL,
		0x8B5FE750897BC99EULL,
		0x104B61FA1405F803ULL,
		0x88FF668FB95194D2ULL,
		0xD6A775143EB3A6D6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA96020DA95B5C7FEULL,
		0xEC4ACCC209A604ADULL,
		0x4A69F7DC9B7F957DULL,
		0x79D076BC3AC88B03ULL,
		0x62320C19F5E4537EULL,
		0x5C2522460186A757ULL,
		0x3EC84EFE84CDEAF7ULL,
		0x78761D15E09BAA9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75279E1A3456A8F8ULL,
		0x8E8A321F4C803FCAULL,
		0xB58549F840AE15B7ULL,
		0x090D078CBCDEF939ULL,
		0x7FD183503F1AD248ULL,
		0x4703E9C79BC32035ULL,
		0x49EED97CCD62B6DBULL,
		0x145F5782B7F98A95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x343882C0615F1F06ULL,
		0x5DC09AA2BD25C4E3ULL,
		0x94E4ADE45AD17FC6ULL,
		0x70C36F2F7DE991C9ULL,
		0xE26088C9B6C98136ULL,
		0x1521387E65C38721ULL,
		0xF4D97581B76B341CULL,
		0x6416C59328A22005ULL
	}};
	sign = 0;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44EA343995870C24ULL,
		0xDC4F8F1A1965D665ULL,
		0x3CFAF7983EAA59BAULL,
		0x9B98E9370EE59290ULL,
		0x869F46DCEB4F3C60ULL,
		0xCFA86D156907344BULL,
		0xCCCA3E2FD19DD6C6ULL,
		0xE10D63598694DD3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661C5B2AD562DDE9ULL,
		0x3A79695CC7D6CDC7ULL,
		0x30D4A79887BA8A9BULL,
		0x272A9F9058C48F85ULL,
		0xC2BD4C515CE1572FULL,
		0x719EAEDABC6D9DEFULL,
		0x9395FF8AD6C8D701ULL,
		0x5AE5FD2EAB2AFF23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDECDD90EC0242E3BULL,
		0xA1D625BD518F089DULL,
		0x0C264FFFB6EFCF1FULL,
		0x746E49A6B621030BULL,
		0xC3E1FA8B8E6DE531ULL,
		0x5E09BE3AAC99965BULL,
		0x39343EA4FAD4FFC5ULL,
		0x8627662ADB69DE17ULL
	}};
	sign = 0;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB60F9F328196CE74ULL,
		0x31F2F9B6D06E19C3ULL,
		0x3693A4D8C0000346ULL,
		0x6E4F33BDECA695D4ULL,
		0xCAE7ACD7564C1327ULL,
		0x421535AE7E1010D1ULL,
		0x9FEF30A2C4D9EC62ULL,
		0x972ED5B5440DB821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4145C54A333D74E0ULL,
		0x3A7EFBC3BB3B8890ULL,
		0x2BFE6C8AB4B579CBULL,
		0xC81F0E18B45522B6ULL,
		0x7D50EDCCA46057B5ULL,
		0x5298EDCF8E43EB6EULL,
		0x8BA6BE14F74B49BEULL,
		0x8C4FAE854643FD54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74C9D9E84E595994ULL,
		0xF773FDF315329133ULL,
		0x0A95384E0B4A897AULL,
		0xA63025A53851731EULL,
		0x4D96BF0AB1EBBB71ULL,
		0xEF7C47DEEFCC2563ULL,
		0x1448728DCD8EA2A3ULL,
		0x0ADF272FFDC9BACDULL
	}};
	sign = 0;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0113354283F8C178ULL,
		0xE18F9AF99FE0DB84ULL,
		0x1A684AB15CD8506BULL,
		0xCAC43013A94546D0ULL,
		0xD8621F19CECF1AFEULL,
		0x59F97DEEB29A7500ULL,
		0x29CC222AB716BC8FULL,
		0x5A482F618CF1CF8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8CF0B7F1DAAE231ULL,
		0x06B83A4508C2AFF7ULL,
		0x78B3DB6047AF8835ULL,
		0x4E02CE71775AA5ACULL,
		0xDF7A328EBDF3BB5FULL,
		0xF86DB70409508558ULL,
		0xEFBFE3833A4D905DULL,
		0x7EF3BA6FBD8266B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184429C3664DDF47ULL,
		0xDAD760B4971E2B8CULL,
		0xA1B46F511528C836ULL,
		0x7CC161A231EAA123ULL,
		0xF8E7EC8B10DB5F9FULL,
		0x618BC6EAA949EFA7ULL,
		0x3A0C3EA77CC92C31ULL,
		0xDB5474F1CF6F68D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FA2DC5CF0396F8EULL,
		0x00C1159DD957A6F2ULL,
		0x9E0C97D2467E6541ULL,
		0x1FF16F3F8741B488ULL,
		0xF471F808FCC142C3ULL,
		0x18DE073A41AC6974ULL,
		0x339C51E6F6758C45ULL,
		0x242BB464428F8827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36D7AE97FB7C441ULL,
		0x03FFF763F05C5397ULL,
		0x83752ACFDFDBA3B0ULL,
		0x7962535537080115ULL,
		0x12ADCB0C9AE7E630ULL,
		0xD5C1105794CAE03BULL,
		0x29489EA8F54C1014ULL,
		0x5407043266C9CEF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC3561737081AB4DULL,
		0xFCC11E39E8FB535AULL,
		0x1A976D0266A2C190ULL,
		0xA68F1BEA5039B373ULL,
		0xE1C42CFC61D95C92ULL,
		0x431CF6E2ACE18939ULL,
		0x0A53B33E01297C30ULL,
		0xD024B031DBC5B932ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A4E0BEF0FEF8A5BULL,
		0x1F3A536DCF75A194ULL,
		0x7E9C76415D95D2E6ULL,
		0x0B7E0E52AA88E9E9ULL,
		0xD74C939EA2209C6AULL,
		0x452FA26014FC7FB8ULL,
		0xC29C23A5B4D5AE63ULL,
		0xE58A0C6C234ACECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF34895E13483071ULL,
		0x41CD77169951781EULL,
		0x8699441E68E6226FULL,
		0x3B8E49DB1111E188ULL,
		0xCC71563A0DD936CBULL,
		0x482C6C09E1223CE7ULL,
		0x66D8B281BAE4F657ULL,
		0xA4EF40785963752CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B198290FCA759EAULL,
		0xDD6CDC5736242975ULL,
		0xF8033222F4AFB076ULL,
		0xCFEFC47799770860ULL,
		0x0ADB3D649447659EULL,
		0xFD03365633DA42D1ULL,
		0x5BC37123F9F0B80BULL,
		0x409ACBF3C9E759A0ULL
	}};
	sign = 0;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD32C51B0A35EB53CULL,
		0xE1282BDD6412BA21ULL,
		0x310DCA2DD880B58CULL,
		0x3348A21ED1B78E82ULL,
		0xFE9C66B8CC1840B4ULL,
		0xEE8F1442D579B0D4ULL,
		0x208E4E32591A4960ULL,
		0x06A2100DD3326FE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82EE224B21B29E8AULL,
		0x635775405BDF881EULL,
		0x5C0D12A340D72D72ULL,
		0x32006A34AACFE243ULL,
		0xDF675F31E02DA6E2ULL,
		0xBA0C5C4639C46D30ULL,
		0xA66DE48E015C74F5ULL,
		0xF370B193637EE6A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x503E2F6581AC16B2ULL,
		0x7DD0B69D08333203ULL,
		0xD500B78A97A9881AULL,
		0x014837EA26E7AC3EULL,
		0x1F350786EBEA99D2ULL,
		0x3482B7FC9BB543A4ULL,
		0x7A2069A457BDD46BULL,
		0x13315E7A6FB38940ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA47D3CA347DE4E9ULL,
		0xBCA69F56C5E60CADULL,
		0x80B4185198CFF9A9ULL,
		0x39999ECF84BCB01CULL,
		0xCF763B8FAFDECD9DULL,
		0xA42CC9D667521634ULL,
		0xD9A5EC379BF7D39AULL,
		0x171C6D86B3CC5990ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AED81A0178E5EABULL,
		0xC21DBF9EFF736FBBULL,
		0x9229C2A471CBA630ULL,
		0xEF3D364CF8BE90E9ULL,
		0xDCDC148CA0D80683ULL,
		0x987C7A9EE3F54CFCULL,
		0x881A12EA4E4D7C7BULL,
		0xEE9E49B83B05BC99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F5A522A1CEF863EULL,
		0xFA88DFB7C6729CF2ULL,
		0xEE8A55AD27045378ULL,
		0x4A5C68828BFE1F32ULL,
		0xF29A27030F06C719ULL,
		0x0BB04F37835CC937ULL,
		0x518BD94D4DAA571FULL,
		0x287E23CE78C69CF7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE24F0264811699BBULL,
		0xBBE57870D79E7D02ULL,
		0x049A8381F275920FULL,
		0x41EDDA4067A8A160ULL,
		0xEBBADE53777DEBB9ULL,
		0x6FC925679028C02BULL,
		0xDEFFDA56F1123F35ULL,
		0xF9778F9BA686631DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58B92899CFF5E7F1ULL,
		0x27A25894FAB4C7FDULL,
		0x70D85C3CAAF5ED21ULL,
		0x233307EC991903A4ULL,
		0x815475B2A5394C42ULL,
		0x5169776907A4876FULL,
		0x320354C89AC4FBFEULL,
		0x4698B60459F45995ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8995D9CAB120B1CAULL,
		0x94431FDBDCE9B505ULL,
		0x93C22745477FA4EEULL,
		0x1EBAD253CE8F9DBBULL,
		0x6A6668A0D2449F77ULL,
		0x1E5FADFE888438BCULL,
		0xACFC858E564D4337ULL,
		0xB2DED9974C920988ULL
	}};
	sign = 0;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB83A5621003BEA82ULL,
		0x079B7C2BDB0FAA2FULL,
		0x6A9DF97966AF1508ULL,
		0x37AE6DDBD8D6EC60ULL,
		0x35035BFA72E8F00CULL,
		0x1F6AEF4DD4F49D39ULL,
		0x5E85F75208CF6C49ULL,
		0x0D80340539DE9E1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2EC4FC5FFE11D9DULL,
		0xD274E5E6E2D78169ULL,
		0x2277CB90C8103B28ULL,
		0x17F77F9211C3FF63ULL,
		0xF049C8FAFCDFA7A7ULL,
		0x0E79190D1C156FBEULL,
		0x26D3A937C623DC38ULL,
		0x45369530EEBF20D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD54E065B005ACCE5ULL,
		0x35269644F83828C5ULL,
		0x48262DE89E9ED9DFULL,
		0x1FB6EE49C712ECFDULL,
		0x44B992FF76094865ULL,
		0x10F1D640B8DF2D7AULL,
		0x37B24E1A42AB9011ULL,
		0xC8499ED44B1F7D4CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFE56680D21A314FULL,
		0xAEFB51D1348CABFEULL,
		0x6640758C937C4A81ULL,
		0x8906A1129A85B532ULL,
		0xB30E1459793629CAULL,
		0xF38C6DFF7CE5CC2FULL,
		0x6B8B6C37ADF0CB7DULL,
		0x6FD44ADF8649EC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6563FDFBE150078AULL,
		0xAD3655B3F7028FD5ULL,
		0x934E7B6F652027D4ULL,
		0x0A78D67570174203ULL,
		0x0B05C63411B2707CULL,
		0x684E23F64057F550ULL,
		0x82FC6D6E25451051ULL,
		0x682EF8488F3108D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A816884F0CA29C5ULL,
		0x01C4FC1D3D8A1C29ULL,
		0xD2F1FA1D2E5C22ADULL,
		0x7E8DCA9D2A6E732EULL,
		0xA8084E256783B94EULL,
		0x8B3E4A093C8DD6DFULL,
		0xE88EFEC988ABBB2CULL,
		0x07A55296F718E354ULL
	}};
	sign = 0;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE15561A64F51438EULL,
		0x6E144C5713197640ULL,
		0x79EC71073DB5830EULL,
		0x9179C616EFA2060FULL,
		0x1DD1BEB11E65ACCCULL,
		0xE60BE866E762E1E2ULL,
		0x9B56D477EEB88BDFULL,
		0x8B37A8A6EC42D618ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFABC74875D3D71ULL,
		0x8D314DF7036034E9ULL,
		0x8B2794C917DCB0F5ULL,
		0x0EDD821769B59DD8ULL,
		0x5E140F1A983A4B41ULL,
		0x45297CBC593D9A29ULL,
		0x275DA7B59E7ED500ULL,
		0x1972965B6CDB447FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD25AA531C7F4061DULL,
		0xE0E2FE600FB94157ULL,
		0xEEC4DC3E25D8D218ULL,
		0x829C43FF85EC6836ULL,
		0xBFBDAF96862B618BULL,
		0xA0E26BAA8E2547B8ULL,
		0x73F92CC25039B6DFULL,
		0x71C5124B7F679199ULL
	}};
	sign = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4622BD5E2EB4F36FULL,
		0x875B9B6A401469DCULL,
		0xFA2A5D3DA404EE07ULL,
		0x7835000599B0905DULL,
		0x131D3932FF905CE6ULL,
		0x3615271A9FF4F96BULL,
		0xF1916AE45E9A1613ULL,
		0x63A334A50F59E2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF78CC2144E1A4AB8ULL,
		0xEE4C6C08EABA9065ULL,
		0xC20B5E77F525B9ECULL,
		0xCB844A8994176C35ULL,
		0x5EB737E04E80CD8BULL,
		0xCEA1190B1722383DULL,
		0x8A0614062D8152ADULL,
		0xA0F82F0090B03CBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E95FB49E09AA8B7ULL,
		0x990F2F615559D976ULL,
		0x381EFEC5AEDF341AULL,
		0xACB0B57C05992428ULL,
		0xB4660152B10F8F5AULL,
		0x67740E0F88D2C12DULL,
		0x678B56DE3118C365ULL,
		0xC2AB05A47EA9A600ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1230A68FA1AE220EULL,
		0x269D8CA45EC156DFULL,
		0xA055AA60C275198DULL,
		0x6A5B39F0BD75334CULL,
		0xF59D6D2C608663DFULL,
		0xB07355347F43D8A3ULL,
		0xE640E7B9ECCF956CULL,
		0x8A4138E2515377E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC9001227138ACEULL,
		0x19511D7A74E95C7FULL,
		0x464DB1A0914363E3ULL,
		0x1528D02540000042ULL,
		0x29110F26E04DB406ULL,
		0x2BFCCFEFCA468637ULL,
		0xBA57632E8DEA1DCEULL,
		0xF99F1D1D8261A3F5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD767A67D7A9A9740ULL,
		0x0D4C6F29E9D7FA5FULL,
		0x5A07F8C03131B5AAULL,
		0x553269CB7D75330AULL,
		0xCC8C5E058038AFD9ULL,
		0x84768544B4FD526CULL,
		0x2BE9848B5EE5779EULL,
		0x90A21BC4CEF1D3F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25BC5386570C2FF1ULL,
		0x3BC88F22C73337D6ULL,
		0x78111AFCC783C0D7ULL,
		0x9CC35FBFD8E56E72ULL,
		0xC5887F9A8A3611F8ULL,
		0x8D510E5801C8E555ULL,
		0x686D6C0F5258A8BBULL,
		0x05315519C36BFA3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212279CD201E820CULL,
		0x64908B4218A65D0BULL,
		0x8709ED2C37289B42ULL,
		0x33B2781F0420C02FULL,
		0x849E3A30F58AA732ULL,
		0x41DD6B00F2F4269CULL,
		0x74DEA0310B03CB86ULL,
		0xE3C8B3D16EF1F079ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0499D9B936EDADE5ULL,
		0xD73803E0AE8CDACBULL,
		0xF1072DD0905B2594ULL,
		0x6910E7A0D4C4AE42ULL,
		0x40EA456994AB6AC6ULL,
		0x4B73A3570ED4BEB9ULL,
		0xF38ECBDE4754DD35ULL,
		0x2168A148547A09C3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29532CA470672973ULL,
		0xB8D6A61D04F097ACULL,
		0x28C489C81251605EULL,
		0xE2079040FE09DB46ULL,
		0x13C81995106F0468ULL,
		0xF23A4AC171F89EC4ULL,
		0xFA649D7C0C20B447ULL,
		0x730078D53904A72FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A413C35F3CF24ACULL,
		0x3117F06BAB1EC404ULL,
		0x23F7BF6FFA02D7DCULL,
		0x8C00426A4BCACE33ULL,
		0x36066988A509DF35ULL,
		0x940729EB10DA5BE5ULL,
		0xFEBA85BF2438D3BAULL,
		0xA09018855EB1AA65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF11F06E7C9804C7ULL,
		0x87BEB5B159D1D3A7ULL,
		0x04CCCA58184E8882ULL,
		0x56074DD6B23F0D13ULL,
		0xDDC1B00C6B652533ULL,
		0x5E3320D6611E42DEULL,
		0xFBAA17BCE7E7E08DULL,
		0xD270604FDA52FCC9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BAA815D58A97934ULL,
		0x25DF687C8C073239ULL,
		0xC5B716C894B04C21ULL,
		0x0BB43863F38AC85BULL,
		0x662ED2E7EE01B207ULL,
		0x38595D4E9818FD77ULL,
		0x7943FB2BCB065630ULL,
		0xD31D4BD3940F4F18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2066E511FF7DEFACULL,
		0xB89932E42003B698ULL,
		0x1AEB3787D82B1088ULL,
		0x9D8D74139AD2949CULL,
		0xC845FB1864C6FDDEULL,
		0xC5092C9C2C2853BCULL,
		0xB6D628930CD29B8FULL,
		0xCE69F5EDA5F6B0EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B439C4B592B8988ULL,
		0x6D4635986C037BA1ULL,
		0xAACBDF40BC853B98ULL,
		0x6E26C45058B833BFULL,
		0x9DE8D7CF893AB428ULL,
		0x735030B26BF0A9BAULL,
		0xC26DD298BE33BAA0ULL,
		0x04B355E5EE189E2AULL
	}};
	sign = 0;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B200D03432A2A99ULL,
		0x3E560528C3D16828ULL,
		0x52DDD9A6253A1077ULL,
		0xDDFC5338E0D82A4CULL,
		0x03889BFDC1CF8FC5ULL,
		0x88EF0218246E9665ULL,
		0x833C213F0744D63FULL,
		0x42783723EF77779DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC9827066607C622ULL,
		0xE36BAD14ADA624F9ULL,
		0xD9FD992B0504AF2FULL,
		0x809EFD291D9354B4ULL,
		0x37ADEC6A4068F98AULL,
		0xD6933C1CCCE3F8E1ULL,
		0x34BEBD391779D38AULL,
		0xA7C22EB89F137C7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E87E5FCDD226477ULL,
		0x5AEA5814162B432EULL,
		0x78E0407B20356147ULL,
		0x5D5D560FC344D597ULL,
		0xCBDAAF938166963BULL,
		0xB25BC5FB578A9D83ULL,
		0x4E7D6405EFCB02B4ULL,
		0x9AB6086B5063FB1EULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5368BB3104733D0ULL,
		0x251B1663D295D819ULL,
		0xE5CF285FCA10FD64ULL,
		0x4BFD0BE9DCB699CEULL,
		0xDD5BA2D6573E24F5ULL,
		0x18E3C7BA74CA15C1ULL,
		0x2B0949C476444BA6ULL,
		0xCADCACA85F4A8905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80BC2D2CD7357DB6ULL,
		0xFB8D51F700B7186DULL,
		0xA850CCD03C43F680ULL,
		0x56908C1DE83E43AFULL,
		0xDA9BD0B059C6974CULL,
		0xB7A09E50555B1172ULL,
		0x8B5C7F15ECEB3ED0ULL,
		0xD725BC163F15863BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x747A5E863911B61AULL,
		0x298DC46CD1DEBFACULL,
		0x3D7E5B8F8DCD06E3ULL,
		0xF56C7FCBF478561FULL,
		0x02BFD225FD778DA8ULL,
		0x6143296A1F6F044FULL,
		0x9FACCAAE89590CD5ULL,
		0xF3B6F092203502C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B1EF61E96F135F1ULL,
		0x8A9FCB30298DF87AULL,
		0x36210EEC34E520A8ULL,
		0x075B33A33776075BULL,
		0xF75EA44AC87F952BULL,
		0xA736E616B2A8436CULL,
		0xBC94E20395D30985ULL,
		0x5B14E2F9A7500B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28A40C6B1ECCA1BBULL,
		0x6C7DF37063023B65ULL,
		0x2F4D7AC98A5EAB0AULL,
		0x7D03586F381188B2ULL,
		0x39395965E3B75912ULL,
		0x48728D9C79585810ULL,
		0x32EAF551905DA0B5ULL,
		0x6FB49CDFF885804FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x027AE9B378249436ULL,
		0x1E21D7BFC68BBD15ULL,
		0x06D39422AA86759EULL,
		0x8A57DB33FF647EA9ULL,
		0xBE254AE4E4C83C18ULL,
		0x5EC4587A394FEB5CULL,
		0x89A9ECB2057568D0ULL,
		0xEB604619AECA8B4FULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208A3E44A5F67FDAULL,
		0x8BD39A1616104724ULL,
		0x7AC0E011C6C625BEULL,
		0xBD3B09195C724138ULL,
		0x42AA4BD0E4398960ULL,
		0x9C688BAC9231DA29ULL,
		0x11C7687749169304ULL,
		0x829F6B1A177E05B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25435AB5BEED83D3ULL,
		0xEEDA97B4C34B03ADULL,
		0x83A3C179C5E8BF40ULL,
		0xDD972A06831CDD08ULL,
		0xC3DE62790951B853ULL,
		0x859B5463401C229EULL,
		0xFACC24D3457CA2BAULL,
		0x3ECD491F96BBDCFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB46E38EE708FC07ULL,
		0x9CF9026152C54376ULL,
		0xF71D1E9800DD667DULL,
		0xDFA3DF12D955642FULL,
		0x7ECBE957DAE7D10CULL,
		0x16CD37495215B78AULL,
		0x16FB43A40399F04AULL,
		0x43D221FA80C228B9ULL
	}};
	sign = 0;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B7CFB2BC96057F5ULL,
		0xF7662F11D2C3D4ABULL,
		0xB7D9DF7FD6D573CAULL,
		0x6FBE6F13E3B9E693ULL,
		0x47C6ADC09828A10DULL,
		0xC199ABC3B88102B1ULL,
		0xFBCDE960B529F7C5ULL,
		0x0C35EC689A7CBB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3475705F2EE6A8B5ULL,
		0xA65FEBBF2E0055B0ULL,
		0x01E5C42C60533566ULL,
		0xDF338F1E8A742D6CULL,
		0xD43786C0FB9124BDULL,
		0xFCD11ECE867F7A70ULL,
		0x020F53FA31FDE884ULL,
		0x49DE4EE69ABF3867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7078ACC9A79AF40ULL,
		0x51064352A4C37EFAULL,
		0xB5F41B5376823E64ULL,
		0x908ADFF55945B927ULL,
		0x738F26FF9C977C4FULL,
		0xC4C88CF532018840ULL,
		0xF9BE9566832C0F40ULL,
		0xC2579D81FFBD8331ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x328121CAF0100F4FULL,
		0xDDC344A022DD7973ULL,
		0xFCB066AD7F293740ULL,
		0x185254C8130E3724ULL,
		0xDB78DEAC4B68CC6FULL,
		0x96CC53BF7D61B36DULL,
		0xF9CDAEE2B303B7D0ULL,
		0x339DAAEBAE552BD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C3E760542C6DEDULL,
		0xB0AE629A258C4DF2ULL,
		0x638E4020CDA0DA51ULL,
		0xD069EDE9D70DE03CULL,
		0xF16CA5C948CB0429ULL,
		0xD462DB4A67457C3AULL,
		0x8FB486268D69B276ULL,
		0xE59630F51C4D4BC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DBD3A6A9BE3A162ULL,
		0x2D14E205FD512B80ULL,
		0x9922268CB1885CEFULL,
		0x47E866DE3C0056E8ULL,
		0xEA0C38E3029DC845ULL,
		0xC2697875161C3732ULL,
		0x6A1928BC259A0559ULL,
		0x4E0779F69207E018ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB1B842C44C3B7CEULL,
		0xC4A1E759EF399B13ULL,
		0xE74C6856FA4A0283ULL,
		0x9AB1AD7057D7930FULL,
		0x78943D53A8118E40ULL,
		0x84E3831178625090ULL,
		0x17F17A6E30D5E726ULL,
		0x69A562111B7B06E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43F26E3D111DF3E6ULL,
		0xCEAFEC370CC36AFBULL,
		0xE410CC7956C34199ULL,
		0x1135C0F62213B0E7ULL,
		0x4543FA37B8796DE0ULL,
		0xBFE067FBA3731A6AULL,
		0x9DFC928BE581BEA9ULL,
		0x968A39CF8F606C78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB72915EF33A5C3E8ULL,
		0xF5F1FB22E2763018ULL,
		0x033B9BDDA386C0E9ULL,
		0x897BEC7A35C3E228ULL,
		0x3350431BEF982060ULL,
		0xC5031B15D4EF3626ULL,
		0x79F4E7E24B54287CULL,
		0xD31B28418C1A9A6DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9652D40153EA9F0ULL,
		0x8AB11615B11374FDULL,
		0xBFA5B1D7ACD4A977ULL,
		0xC64E1DE758FB8E0CULL,
		0x8D1533FB014FB618ULL,
		0x33AD01778945BD45ULL,
		0xBF6B2AC7DA78DB7CULL,
		0x9EBE89D8FFA72EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12FDB19B1A018D87ULL,
		0xA99D57C5CB1537E9ULL,
		0xB91DE5FBF3B56DBEULL,
		0xBEDB3660E17FAA97ULL,
		0x8F964CB6246AC428ULL,
		0x5FF0BF0EB266958BULL,
		0x22247096B7A38568ULL,
		0xEA2A2B064D9F41D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6677BA4FB3D1C69ULL,
		0xE113BE4FE5FE3D14ULL,
		0x0687CBDBB91F3BB8ULL,
		0x0772E786777BE375ULL,
		0xFD7EE744DCE4F1F0ULL,
		0xD3BC4268D6DF27B9ULL,
		0x9D46BA3122D55613ULL,
		0xB4945ED2B207ED02ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1DE1E366F868DB85ULL,
		0x34FB3354E22DF531ULL,
		0x418BAA7167C1A49BULL,
		0x1F46CAE6CE48432BULL,
		0x3FCEAA8713393BB8ULL,
		0xED908AE00D2EF095ULL,
		0xC679009E2FDF7365ULL,
		0x8829620856C9C518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9655D158E4CFBA1ULL,
		0xB6FB985A0C25D11DULL,
		0x833029728043D7A4ULL,
		0x8CBC5AAF9AADFA90ULL,
		0x25DAD293A459869DULL,
		0x3C0F3D642FE288B8ULL,
		0xCC09737125CF3D64ULL,
		0x9E7485CD4458E33CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x647C86516A1BDFE4ULL,
		0x7DFF9AFAD6082413ULL,
		0xBE5B80FEE77DCCF6ULL,
		0x928A7037339A489AULL,
		0x19F3D7F36EDFB51AULL,
		0xB1814D7BDD4C67DDULL,
		0xFA6F8D2D0A103601ULL,
		0xE9B4DC3B1270E1DBULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99707896819740DFULL,
		0xBEDE05D09C315D59ULL,
		0xDCFBC8164EBFD0EFULL,
		0x216E27B7A52D0BCFULL,
		0x0A9C49C1F4A76770ULL,
		0x17B9B00B1F6C1D8CULL,
		0x3C27F7F8BAD8E1A8ULL,
		0xC33D400CDC621AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F83BB0932C69CB3ULL,
		0xDBF2CEF0B9256AC3ULL,
		0xBEB7FD185166C66CULL,
		0xE7DE0E9663B93095ULL,
		0x1A9D2AA81638643DULL,
		0x8FADC167AB0008C1ULL,
		0x03FE04C8720B664FULL,
		0x1C9F2B68D5FEAE9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9ECBD8D4ED0A42CULL,
		0xE2EB36DFE30BF295ULL,
		0x1E43CAFDFD590A82ULL,
		0x399019214173DB3AULL,
		0xEFFF1F19DE6F0332ULL,
		0x880BEEA3746C14CAULL,
		0x3829F33048CD7B58ULL,
		0xA69E14A406636C4EULL
	}};
	sign = 0;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FF52C600BE05C5EULL,
		0x08F1993A6F8C3F1DULL,
		0xB8940A66F4E7F1C8ULL,
		0x9985287434B0A686ULL,
		0x2288C4C6C05D46E2ULL,
		0x0CAAA9F96137101AULL,
		0x0F9F306EAB8185A5ULL,
		0x7E42BFAE8B7547EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9DEAB7E007D4BCULL,
		0x3716872D33CA3902ULL,
		0x28C5458B73CF0785ULL,
		0x83B0992C37DDBD61ULL,
		0xEDBF49B9B9E3B0F7ULL,
		0x63DB0A4065549E3CULL,
		0x92F01E7B1D33FB76ULL,
		0x1A288B20DEF1EBDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x055741A82BD887A2ULL,
		0xD1DB120D3BC2061BULL,
		0x8FCEC4DB8118EA42ULL,
		0x15D48F47FCD2E925ULL,
		0x34C97B0D067995EBULL,
		0xA8CF9FB8FBE271DDULL,
		0x7CAF11F38E4D8A2EULL,
		0x641A348DAC835C12ULL
	}};
	sign = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5482DE7716041EAULL,
		0x6A17F9E6D28907B0ULL,
		0xD0A8EB09EED73F8DULL,
		0xBF509A2DBBE226E9ULL,
		0xCFAD5A1C709D48D4ULL,
		0x84B66C046946B3F4ULL,
		0xD5CE935FFAC2EBECULL,
		0xBBB7202424127CB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA868406BFD13FD00ULL,
		0x37C4F525D5DCE0FDULL,
		0xB053FF079BE90A9EULL,
		0x3CF7ACDDA214D6B5ULL,
		0x382554FAE61FAF46ULL,
		0xF8288FEE4D51DA0DULL,
		0x40283B917E2940FEULL,
		0x18144A8C24979F64ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCDFED7B744C44EAULL,
		0x325304C0FCAC26B2ULL,
		0x2054EC0252EE34EFULL,
		0x8258ED5019CD5034ULL,
		0x978805218A7D998EULL,
		0x8C8DDC161BF4D9E7ULL,
		0x95A657CE7C99AAEDULL,
		0xA3A2D597FF7ADD55ULL
	}};
	sign = 0;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0D45E5A29B3EA63ULL,
		0xC88499B5CA887A4EULL,
		0x3D453295C31B9D6AULL,
		0x3D471ADAE96C1835ULL,
		0xAAE5748A57948E10ULL,
		0x81FF64129800FD55ULL,
		0xA3A174233A46E32BULL,
		0x65A6D0DD8675FDA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0167E665BA681CDULL,
		0x98C57C7818B4F19FULL,
		0x998AEFFA09F4FB23ULL,
		0x4AD2A18EA54687C0ULL,
		0xB69D811A65FF7971ULL,
		0x121342DF9BBA9293ULL,
		0x563FDA79821C173FULL,
		0x272127C2BD47745FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10BDDFF3CE0D6896ULL,
		0x2FBF1D3DB1D388AFULL,
		0xA3BA429BB926A247ULL,
		0xF274794C44259074ULL,
		0xF447F36FF195149EULL,
		0x6FEC2132FC466AC1ULL,
		0x4D6199A9B82ACBECULL,
		0x3E85A91AC92E8947ULL
	}};
	sign = 0;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11E6E1A919428C43ULL,
		0x2E6C972B34E20657ULL,
		0xBF7EF4C8798C331EULL,
		0xEA0F389A205A799BULL,
		0xD655308D2BD3A44BULL,
		0xC8B15AE8CC35FD63ULL,
		0x2F6B419745D440ABULL,
		0x20BE8AD8DD8B01E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE00175B25D2598E2ULL,
		0x85BD283F8D54D10DULL,
		0xB466D6A85C13037BULL,
		0xD15115DE7BBCF51EULL,
		0x5754CD2B49F36AA3ULL,
		0xF186CEAE762E9D8BULL,
		0xBDE82B481128BEFCULL,
		0x9AC3D3E3F1818996ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31E56BF6BC1CF361ULL,
		0xA8AF6EEBA78D3549ULL,
		0x0B181E201D792FA2ULL,
		0x18BE22BBA49D847DULL,
		0x7F006361E1E039A8ULL,
		0xD72A8C3A56075FD8ULL,
		0x7183164F34AB81AEULL,
		0x85FAB6F4EC09784CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94C45CC9C4CC7EEBULL,
		0xDD2754BEE6F34B05ULL,
		0xB4C4FB12575ED5CEULL,
		0x5202D1A56CC78758ULL,
		0x8691B36C3F5F4D2FULL,
		0x2E321401C3B5D7E2ULL,
		0x693D8FF6CED9ECB9ULL,
		0x0B60A3DB6DE57F26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0004ACD78FA5451FULL,
		0x3D7AA65AAF1BA0A6ULL,
		0xB36E8BE6C51DF878ULL,
		0x702D3C59EC1A1CE9ULL,
		0xC45D3C5DFA2BE3C5ULL,
		0xF98ABECA04215D18ULL,
		0x50E225DE8BE913A0ULL,
		0xDAEE2A6D2EBA043AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94BFAFF2352739CCULL,
		0x9FACAE6437D7AA5FULL,
		0x01566F2B9240DD56ULL,
		0xE1D5954B80AD6A6FULL,
		0xC234770E45336969ULL,
		0x34A75537BF947AC9ULL,
		0x185B6A1842F0D918ULL,
		0x3072796E3F2B7AECULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9097E676432A9FA7ULL,
		0x95FB0BF355E7BEB1ULL,
		0xA227D8E281C4BB1CULL,
		0x50EBEE843EBCC0B8ULL,
		0x4CE1F57210DECA0BULL,
		0x515D03CE59EB9395ULL,
		0xEE8F15BD652CA6BCULL,
		0x739B5806743E37DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E01D65F98EABEBULL,
		0x11700CE6028837A8ULL,
		0x3816A310747A9228ULL,
		0x93E79332CD809BFEULL,
		0x0DE0403A5F2953D8ULL,
		0xFD56A7787C179211ULL,
		0xFBA760F0A84763E9ULL,
		0x13AEB1F9E2619B46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DB7C910499BF3BCULL,
		0x848AFF0D535F8709ULL,
		0x6A1135D20D4A28F4ULL,
		0xBD045B51713C24BAULL,
		0x3F01B537B1B57632ULL,
		0x54065C55DDD40184ULL,
		0xF2E7B4CCBCE542D2ULL,
		0x5FECA60C91DC9C96ULL
	}};
	sign = 0;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x942D06C36AC820D8ULL,
		0x075D5B3D669F7FE0ULL,
		0xF2795E6A252AAB59ULL,
		0xD431C04F75BCF136ULL,
		0x89DF7320623B3D97ULL,
		0xC17A8D14AB33F6E1ULL,
		0x2565ABF8A24189EBULL,
		0xA78F222DC9B24AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3837A475DF5C2F5BULL,
		0x517DC44F36CD4998ULL,
		0x648A1404C028C7D6ULL,
		0x0D7760DB8F686651ULL,
		0x0B3C31E7165DCC5EULL,
		0x5BB0D540997DC6B8ULL,
		0x136EDA69DB217184ULL,
		0xA5FE36772FAFA344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BF5624D8B6BF17DULL,
		0xB5DF96EE2FD23648ULL,
		0x8DEF4A656501E382ULL,
		0xC6BA5F73E6548AE5ULL,
		0x7EA341394BDD7139ULL,
		0x65C9B7D411B63029ULL,
		0x11F6D18EC7201867ULL,
		0x0190EBB69A02A770ULL
	}};
	sign = 0;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7E01E403DDE72C2ULL,
		0xFFF3DF57A2B65451ULL,
		0x2162F0BCC032C066ULL,
		0xBB136E54D3DC8948ULL,
		0x674F4260980C6A0BULL,
		0xC2B82631A3B333CBULL,
		0x235CA422A00CFB64ULL,
		0x5DE5AF4036AB5F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D11093C5F8A8B13ULL,
		0xBC4F414BB183C04AULL,
		0x70503FCF8C6C03FEULL,
		0xE0249F86E808A183ULL,
		0x0875DF5660E5F5B9ULL,
		0x621D792655F37312ULL,
		0x6422461F0D1BAC6BULL,
		0x059C91FB3EC1DF05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCACF1503DE53E7AFULL,
		0x43A49E0BF1329407ULL,
		0xB112B0ED33C6BC68ULL,
		0xDAEECECDEBD3E7C4ULL,
		0x5ED9630A37267451ULL,
		0x609AAD0B4DBFC0B9ULL,
		0xBF3A5E0392F14EF9ULL,
		0x58491D44F7E9805BULL
	}};
	sign = 0;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF33B52407D6E60C7ULL,
		0x0441A84521CFA707ULL,
		0x6EFE568D1967BDA5ULL,
		0x16A912205F479C87ULL,
		0xCC714024EDB42343ULL,
		0xA38E3C4AEEA930A6ULL,
		0x8A83D0E8FF462F6EULL,
		0x105EF60DC8D66F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC09D81064543682EULL,
		0x0B4895500390DE68ULL,
		0x658DBAF5751AADA5ULL,
		0x633D64E16965DE4AULL,
		0xD736DA0580601AF4ULL,
		0x4228A873B558A653ULL,
		0xDA906E302168DCD4ULL,
		0xCCF3B8B1D126AA6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x329DD13A382AF899ULL,
		0xF8F912F51E3EC89FULL,
		0x09709B97A44D0FFFULL,
		0xB36BAD3EF5E1BE3DULL,
		0xF53A661F6D54084EULL,
		0x616593D739508A52ULL,
		0xAFF362B8DDDD529AULL,
		0x436B3D5BF7AFC49DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C08660F39A11377ULL,
		0xA1C9AEF59922D420ULL,
		0x64DED586043496BCULL,
		0x9936351FFF5E61FBULL,
		0x7E173C3086D24DFDULL,
		0xD333EFA421BCE68BULL,
		0x94FA03EA38D8CE5FULL,
		0x1C05C3522CA691BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x012D905743591D38ULL,
		0xA9A5DD91FB22FF62ULL,
		0x8F03148653C10512ULL,
		0x7F538198B17A75F4ULL,
		0x4A96AE0BBE31CE5BULL,
		0x9A1C54FED37D3F34ULL,
		0x64931B79B2A829A6ULL,
		0xAF526E346295D529ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ADAD5B7F647F63FULL,
		0xF823D1639DFFD4BEULL,
		0xD5DBC0FFB07391A9ULL,
		0x19E2B3874DE3EC06ULL,
		0x33808E24C8A07FA2ULL,
		0x39179AA54E3FA757ULL,
		0x3066E8708630A4B9ULL,
		0x6CB3551DCA10BC96ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD2A0F8C59E60AD6ULL,
		0xA23C39627B4D8BBEULL,
		0x681019CA0D376437ULL,
		0xDA29DE76654F7FADULL,
		0xFCBDFF0E4FB0787BULL,
		0x50C591EDB1F8C6BBULL,
		0x5FD5EDCFC7E7696AULL,
		0xD4C07A07D84FD83AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79CEF3AC3DBAF695ULL,
		0x1327949295A0414DULL,
		0x0B526A745EF84ED3ULL,
		0x1F4847B09204E4DAULL,
		0xCA37C1C5FA5B6FE7ULL,
		0xF594436169E8BBB1ULL,
		0x524CCE38308134DDULL,
		0xA7F40BB6BD006209ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x635B1BE01C2B1441ULL,
		0x8F14A4CFE5AD4A71ULL,
		0x5CBDAF55AE3F1564ULL,
		0xBAE196C5D34A9AD3ULL,
		0x32863D4855550894ULL,
		0x5B314E8C48100B0AULL,
		0x0D891F979766348CULL,
		0x2CCC6E511B4F7631ULL
	}};
	sign = 0;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81C7DCEE5FE4758AULL,
		0x99FC2426A585FBF1ULL,
		0x384E287A94ED1EA1ULL,
		0x4B00FF07BEFE999DULL,
		0x2874C82F817400F5ULL,
		0x24DAB1BB0C5126A4ULL,
		0xA560772801C21990ULL,
		0x9AB840C7C4786AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9905A3E45B33BB0ULL,
		0x7BF1AA825C6FD25AULL,
		0x8ECC595935157921ULL,
		0xA018AAEAEE4236EEULL,
		0x522D75076F4EB560ULL,
		0xB56C7A2C72FFDA89ULL,
		0x7C5E97EB12F3F3ACULL,
		0x6438AE190E35F43BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA83782B01A3139DAULL,
		0x1E0A79A449162996ULL,
		0xA981CF215FD7A580ULL,
		0xAAE8541CD0BC62AEULL,
		0xD647532812254B94ULL,
		0x6F6E378E99514C1AULL,
		0x2901DF3CEECE25E3ULL,
		0x367F92AEB64276BAULL
	}};
	sign = 0;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE59A6E608DF0013BULL,
		0xE38AB601D72C31A3ULL,
		0xE725A993D7F2DEEBULL,
		0x14E2736AE22C0918ULL,
		0xB6D60548F76CDBACULL,
		0xDDA01385EDDF3B40ULL,
		0x9A5DB0866746DBAEULL,
		0x18B94E0343E30878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4781E72B380322ADULL,
		0xCC348D4289375715ULL,
		0x16B7C5FC329A726BULL,
		0x85076FC075AF6673ULL,
		0xF714B6009F0A2EA3ULL,
		0x2C85AA9A6C1B025FULL,
		0x6B78AF3FCDD8C7B7ULL,
		0xA613AE48E1319DB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E18873555ECDE8EULL,
		0x175628BF4DF4DA8EULL,
		0xD06DE397A5586C80ULL,
		0x8FDB03AA6C7CA2A5ULL,
		0xBFC14F485862AD08ULL,
		0xB11A68EB81C438E0ULL,
		0x2EE50146996E13F7ULL,
		0x72A59FBA62B16AC2ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72115B256F286028ULL,
		0xDA524763BF29CC59ULL,
		0x3CD5931CBB68B99AULL,
		0x046E8A82014CACC8ULL,
		0x0F9EF2B2477F7BECULL,
		0x591BE6A490E2DFF0ULL,
		0xAD468B9F6EB35FCBULL,
		0x075F0E730E353491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3787D841DEB72CULL,
		0x3873886FD284060BULL,
		0xDF3EA19A04548720ULL,
		0x50DA14E0DC983501ULL,
		0xB6912F6E6348B2E5ULL,
		0x720DEC8420273A54ULL,
		0xDAA72C44FF1176ACULL,
		0xCA6CB0182F8946BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2D9D34D2D49A8FCULL,
		0xA1DEBEF3ECA5C64DULL,
		0x5D96F182B714327AULL,
		0xB39475A124B477C6ULL,
		0x590DC343E436C906ULL,
		0xE70DFA2070BBA59BULL,
		0xD29F5F5A6FA1E91EULL,
		0x3CF25E5ADEABEDD4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x912E7AB5AB0E1A50ULL,
		0x7839A98248FE316AULL,
		0xCFA214AC983FDADDULL,
		0x35EC447D81B4282FULL,
		0x6F10524C7DF86F3CULL,
		0xA8395DF2A40F85EEULL,
		0x3356A896E0536312ULL,
		0x45CB7E39F4E101AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12E49F90A6C99E3BULL,
		0xFE6C17AF87A05439ULL,
		0x4BE5BEE0EAE48908ULL,
		0x7CCF5DCCADCB5944ULL,
		0x7118A9D49E9A6CC4ULL,
		0xA65598D4DDCC7FB3ULL,
		0x5AC8C1BAC900F64AULL,
		0xA56E8385F5F28EDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7E49DB2504447C15ULL,
		0x79CD91D2C15DDD31ULL,
		0x83BC55CBAD5B51D4ULL,
		0xB91CE6B0D3E8CEEBULL,
		0xFDF7A877DF5E0277ULL,
		0x01E3C51DC643063AULL,
		0xD88DE6DC17526CC8ULL,
		0xA05CFAB3FEEE72D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA93BDCF3F1FD9240ULL,
		0x23986FA6A5EA47B7ULL,
		0xE61C21CC34998A40ULL,
		0x6ADE0E8651230D24ULL,
		0xE40A8D28CE818392ULL,
		0xA6BE655E3B6E7AF8ULL,
		0x3CF1B699FBE34FE5ULL,
		0x5CF2E97C63F36C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4FA284E5DC2ECAULL,
		0x5967802616B5F586ULL,
		0xA0A70958389503CFULL,
		0x25337A8D7C07386DULL,
		0xBB6138C6B882C18DULL,
		0x0CF37DD0BEF4AAC7ULL,
		0x51F6C62D5F3FF607ULL,
		0xC2F657A39B7BEB52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEEC3A6F0C216376ULL,
		0xCA30EF808F345230ULL,
		0x45751873FC048670ULL,
		0x45AA93F8D51BD4B7ULL,
		0x28A9546215FEC205ULL,
		0x99CAE78D7C79D031ULL,
		0xEAFAF06C9CA359DEULL,
		0x99FC91D8C877814AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63B562EF28D37D80ULL,
		0x9348BB998C2B2249ULL,
		0xCDD125EDD7BA8A54ULL,
		0xE76D72156D07735BULL,
		0x6412F3F3DB0BA349ULL,
		0x4D12ECA9F913FC9EULL,
		0xAFB95F9351FC1030ULL,
		0x131F4A7896E5C9A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C0EECC073C106A1ULL,
		0xB2C4A5B7467143D3ULL,
		0x46B1109F23078F0BULL,
		0x4796EBE29805DAC3ULL,
		0xC1F7E35DA16B6F8AULL,
		0x18D03CDBD7B2486EULL,
		0x31E5368264B6424DULL,
		0xDAD397FB93BC3C6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57A6762EB51276DFULL,
		0xE08415E245B9DE76ULL,
		0x8720154EB4B2FB48ULL,
		0x9FD68632D5019898ULL,
		0xA21B109639A033BFULL,
		0x3442AFCE2161B42FULL,
		0x7DD42910ED45CDE3ULL,
		0x384BB27D03298D3AULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA11E2E5D285B4E90ULL,
		0x27EF1C7451FE87CEULL,
		0xC3625CD166A3A9B0ULL,
		0x3CFC425CEC3906C1ULL,
		0x44926FD3991D66E0ULL,
		0x49F38DAB8A1077C8ULL,
		0x93C26AAAF0E8E5D4ULL,
		0x7811A4D16AF623EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA1756F1E0C7E0CDULL,
		0xC0BFBAE89C7FEF9DULL,
		0xD527B03992F530ABULL,
		0x08B44C3286F46FF4ULL,
		0x0CC11A4DD9878432ULL,
		0x09CD1E826906B6A8ULL,
		0x91C4456FAB9CD466ULL,
		0xB7D97592E7D8E773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD706D76B47936DC3ULL,
		0x672F618BB57E9830ULL,
		0xEE3AAC97D3AE7904ULL,
		0x3447F62A654496CCULL,
		0x37D15585BF95E2AEULL,
		0x40266F292109C120ULL,
		0x01FE253B454C116EULL,
		0xC0382F3E831D3C7BULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A27ABCA1270E3D8ULL,
		0xA540DDF99E18A63FULL,
		0xB9BD3E22F428A8CAULL,
		0x2C8BA7BDB3807279ULL,
		0x6B30680751380695ULL,
		0x484E8D70A841B26DULL,
		0xDB9AB78AAEA3A02AULL,
		0x33725CA802532878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F67C458C925A695ULL,
		0x1D549C29EF9BA435ULL,
		0x6F5FBB9DDD5FEC99ULL,
		0xD6C0D8B8746212D9ULL,
		0x013CE0934946C1C1ULL,
		0x9255A8291DCD062DULL,
		0xFD69B2D6303F58F2ULL,
		0xA6E74361158AFAB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCABFE771494B3D43ULL,
		0x87EC41CFAE7D0209ULL,
		0x4A5D828516C8BC31ULL,
		0x55CACF053F1E5FA0ULL,
		0x69F3877407F144D3ULL,
		0xB5F8E5478A74AC40ULL,
		0xDE3104B47E644737ULL,
		0x8C8B1946ECC82DC3ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2858AA2C15828EE1ULL,
		0xA2E64EA48772EBCDULL,
		0x64A6B5BC395CBD4BULL,
		0x72928BAA67FDF4ECULL,
		0x852BF4D021302FD1ULL,
		0xB44DB20BE7AA4AB7ULL,
		0xD32DD445A4F42E1BULL,
		0x494203B5143C8605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CCFE5053280483FULL,
		0x1EE6D12CEBAAFEC4ULL,
		0xED35734064041862ULL,
		0xFD1632FBC2E12CBDULL,
		0x4BEBD809605F723DULL,
		0x6FF9B47DEC0BE163ULL,
		0xFE220D00CC7B615FULL,
		0xCED3E92234D62458ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B88C526E30246A2ULL,
		0x83FF7D779BC7ED09ULL,
		0x7771427BD558A4E9ULL,
		0x757C58AEA51CC82EULL,
		0x39401CC6C0D0BD93ULL,
		0x4453FD8DFB9E6954ULL,
		0xD50BC744D878CCBCULL,
		0x7A6E1A92DF6661ACULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1860C51A4C978385ULL,
		0xEA08915BA602D338ULL,
		0xEB9224BC298A53D7ULL,
		0x655A40912C985631ULL,
		0x8DD6B41AB770E857ULL,
		0xA98F6784F57E121DULL,
		0x32E900C1458DEC95ULL,
		0x1BFAD5892455D7A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3DC95A07507B49ULL,
		0x1CA6FB27FB2B6D56ULL,
		0x267CCE347409B646ULL,
		0xF5660DD5BA487B14ULL,
		0xC2B82F1B2408A325ULL,
		0x8D036390210B4640ULL,
		0xD99B73A5BE48A207ULL,
		0xDD218E024CEBA150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B22FBC04547083CULL,
		0xCD619633AAD765E1ULL,
		0xC5155687B5809D91ULL,
		0x6FF432BB724FDB1DULL,
		0xCB1E84FF93684531ULL,
		0x1C8C03F4D472CBDCULL,
		0x594D8D1B87454A8EULL,
		0x3ED94786D76A3651ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5276A52370ACB1EULL,
		0x73F1A35D3F161165ULL,
		0xB95DAB5369E3C9CFULL,
		0x36B82A5C85D23F08ULL,
		0x33AD410C63515B60ULL,
		0x456446E84176ADE0ULL,
		0x4363921CC9FDFFB3ULL,
		0x53F44B759F9EA356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998E0782897D8EEBULL,
		0xBBDF26A8DF9E6866ULL,
		0x9DC08F5FD0EA95B8ULL,
		0x41BE662D78B02954ULL,
		0x58EC7CE7A646D318ULL,
		0x80E0A44EF0B1E5A5ULL,
		0x230F5797942DFB75ULL,
		0x857AE7C6B4099599ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B9962CFAD8D3C33ULL,
		0xB8127CB45F77A8FFULL,
		0x1B9D1BF398F93416ULL,
		0xF4F9C42F0D2215B4ULL,
		0xDAC0C424BD0A8847ULL,
		0xC483A29950C4C83AULL,
		0x20543A8535D0043DULL,
		0xCE7963AEEB950DBDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8734BAB8F9C3A57ULL,
		0x1070830C5C99F5D5ULL,
		0xF9CF03B60170F62DULL,
		0xB228CF22C78A96F6ULL,
		0xE3DC93ACD8C2202CULL,
		0x492C00EC428C4636ULL,
		0x461E89A3A1D20625ULL,
		0xDA23F31507FB0FC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDCEF22C4386AFACULL,
		0xFE0543C2F54D7402ULL,
		0x85BE7D8BAD886E77ULL,
		0x65BBCE1BD263D2E2ULL,
		0xFBF9326C43162271ULL,
		0x6605AB43C448C7B1ULL,
		0x88993C5C9CC87003ULL,
		0x3878B58A4369328DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AA4597F4C158AABULL,
		0x126B3F49674C81D3ULL,
		0x7410862A53E887B5ULL,
		0x4C6D0106F526C414ULL,
		0xE7E3614095ABFDBBULL,
		0xE32655A87E437E84ULL,
		0xBD854D4705099621ULL,
		0xA1AB3D8AC491DD35ULL
	}};
	sign = 0;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67726C35C098282FULL,
		0x779808E416B96751ULL,
		0xAD74D6EF87186A5CULL,
		0xE7B42FF8D6905AAAULL,
		0x51B83C7407AB93C5ULL,
		0x0EC0E6E09D770434ULL,
		0x4919A2AE563D24A8ULL,
		0x70239EE2A49758A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40BF9C64686AFBD2ULL,
		0x58CA482F5871B498ULL,
		0xD33745BF930C88D1ULL,
		0x620C023553F34361ULL,
		0xFF21840464763403ULL,
		0xDCFB2BE0DCBB56E6ULL,
		0xA705D3AC016D55E7ULL,
		0x189E06F5E51833E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26B2CFD1582D2C5DULL,
		0x1ECDC0B4BE47B2B9ULL,
		0xDA3D912FF40BE18BULL,
		0x85A82DC3829D1748ULL,
		0x5296B86FA3355FC2ULL,
		0x31C5BAFFC0BBAD4DULL,
		0xA213CF0254CFCEC0ULL,
		0x578597ECBF7F24B8ULL
	}};
	sign = 0;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x570445BA63B841FEULL,
		0xB9BAE3B7BFC59B3CULL,
		0x9612FC02821C1843ULL,
		0x675D36A85ABD8789ULL,
		0xC5A073E61A0EBCAFULL,
		0xD1326D8F2B3EFAB1ULL,
		0xA8F21DBA0C121C80ULL,
		0xB9C6C969D0E4454CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F085E3CBEFA6144ULL,
		0xA38111A3B84702C2ULL,
		0x774ED71A75736C94ULL,
		0x192578414A929DF5ULL,
		0xB9572E6288B091B0ULL,
		0x61C97D5338A15AF2ULL,
		0x87EFACFBCCDE6D8CULL,
		0x195C075B063F5247ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7FBE77DA4BDE0BAULL,
		0x1639D214077E9879ULL,
		0x1EC424E80CA8ABAFULL,
		0x4E37BE67102AE994ULL,
		0x0C494583915E2AFFULL,
		0x6F68F03BF29D9FBFULL,
		0x210270BE3F33AEF4ULL,
		0xA06AC20ECAA4F305ULL
	}};
	sign = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FD4A675D2930414ULL,
		0xDFAADAB50580A490ULL,
		0x268FF9D5D89BA4AFULL,
		0xCFE000B1F0EC96FEULL,
		0x95B32D36698AAE47ULL,
		0x42220FE6BD0C33C3ULL,
		0xBE24139BC765C85EULL,
		0x09858C56EA75BBF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD84A49541D23B289ULL,
		0xEDDB0F2A15211580ULL,
		0x4063CDA7747E42E4ULL,
		0xFB49C6997FBBDBBAULL,
		0x7558D5C1047D7C3EULL,
		0xE91245A98697C288ULL,
		0xF9BA375CA619C503ULL,
		0xE43D95FD3E697741ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB78A5D21B56F518BULL,
		0xF1CFCB8AF05F8F0FULL,
		0xE62C2C2E641D61CAULL,
		0xD4963A187130BB43ULL,
		0x205A5775650D3208ULL,
		0x590FCA3D3674713BULL,
		0xC469DC3F214C035AULL,
		0x2547F659AC0C44B5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AAC77A89A4BB76BULL,
		0xEC046B2777F24E65ULL,
		0x4D216E1505413B30ULL,
		0x896025E0D9BC8031ULL,
		0x408DC1CA8B38DFCFULL,
		0xB5B1F85782D46A24ULL,
		0x97295E49A6CD6AB9ULL,
		0x02AC74179730F550ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C890C6EA747686ULL,
		0x876105F293FC18C6ULL,
		0x2F0BDCF3E36A4AD7ULL,
		0x018FF24DFB54B941ULL,
		0x36EBF5ECEE6C928FULL,
		0x71AFB37B4B2711F8ULL,
		0xBAA64D6D9842A7D9ULL,
		0x80AFF51BA4AAA3BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7E3E6E1AFD740E5ULL,
		0x64A36534E3F6359EULL,
		0x1E15912121D6F059ULL,
		0x87D03392DE67C6F0ULL,
		0x09A1CBDD9CCC4D40ULL,
		0x440244DC37AD582CULL,
		0xDC8310DC0E8AC2E0ULL,
		0x81FC7EFBF2865193ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC87230AD4E336D71ULL,
		0x311F409C916A5DE0ULL,
		0x199B2417F9BB6D08ULL,
		0x5F650DE5E65B8048ULL,
		0x7F2F3D22BA5D7BE3ULL,
		0x1D467C0CF96C9F0CULL,
		0x06941EB44E00CEA4ULL,
		0x3E027DF1C7C3C410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6156588419F8ADBULL,
		0x96E32A92507AB3CAULL,
		0x6E6FD82C5C949729ULL,
		0x3D0F74D9DC1DF505ULL,
		0x55805129D1CFD30DULL,
		0x27D1730576092F1AULL,
		0xDC71EE8B9441D381ULL,
		0xFA365227F147D445ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x025CCB250C93E296ULL,
		0x9A3C160A40EFAA16ULL,
		0xAB2B4BEB9D26D5DEULL,
		0x2255990C0A3D8B42ULL,
		0x29AEEBF8E88DA8D6ULL,
		0xF575090783636FF2ULL,
		0x2A223028B9BEFB22ULL,
		0x43CC2BC9D67BEFCAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB28CEE6687A3A44ULL,
		0x9B4FA0BEBCDDBD3CULL,
		0xC8C0EA59802B0613ULL,
		0x537F365767ABC495ULL,
		0xD2DADB4177449F31ULL,
		0x62A410DA7D35ADCAULL,
		0xE91EE1291FC2435DULL,
		0xF57A1BDD439EC3D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BFF52A2F6CDED9ULL,
		0x7C63B434FBCE76B1ULL,
		0xA7A2507FFD7774A4ULL,
		0xAD9E59C85A8843D4ULL,
		0x686D63115F66636CULL,
		0xF3029E3DAA023C3FULL,
		0xF23D8DCDD22C783DULL,
		0xE765CD99EB11BD12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8868D9BC390D5B6BULL,
		0x1EEBEC89C10F468BULL,
		0x211E99D982B3916FULL,
		0xA5E0DC8F0D2380C1ULL,
		0x6A6D783017DE3BC4ULL,
		0x6FA1729CD333718BULL,
		0xF6E1535B4D95CB1FULL,
		0x0E144E43588D06BDULL
	}};
	sign = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10CF61B4A1BCBA35ULL,
		0x4A0CFB42CD3BA763ULL,
		0x085971F98D3B98DAULL,
		0x3C355C57357A5468ULL,
		0x03567AF485576B47ULL,
		0x62974D3FD5BD06F2ULL,
		0x92C5F5E26497D359ULL,
		0x48C23BF6E42D715CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0648DD23D78BA99ULL,
		0x31C15C00B114B86EULL,
		0x150FC2EDCE204BF9ULL,
		0x1FB8E7B9D51E807AULL,
		0x59849439545F54EAULL,
		0x3013963927CC6968ULL,
		0x1F5AFB681F65FAD6ULL,
		0x9C54855093BD093FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x506AD3E26443FF9CULL,
		0x184B9F421C26EEF4ULL,
		0xF349AF0BBF1B4CE1ULL,
		0x1C7C749D605BD3EDULL,
		0xA9D1E6BB30F8165DULL,
		0x3283B706ADF09D89ULL,
		0x736AFA7A4531D883ULL,
		0xAC6DB6A65070681DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE927D60501A93D3FULL,
		0x7F70876AC788A3D2ULL,
		0x7F40FC8BC7EE8D0BULL,
		0x96B1BACE4AFBEA44ULL,
		0x3BB3B48EBEDF7BA1ULL,
		0x3753CB8C7DFAE220ULL,
		0x7FFD6A72EBC4777EULL,
		0xB88B12FC896AE6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DCE7AF6942D6E6CULL,
		0xB7F5E03160C1AFB6ULL,
		0x22792CC20C08A43DULL,
		0x9D8EB325668EB5D4ULL,
		0xF9E7973C38E6C79BULL,
		0x37B2814B3CE24888ULL,
		0x84FD35C2668F9157ULL,
		0x7503E8923A38CC6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B595B0E6D7BCED3ULL,
		0xC77AA73966C6F41CULL,
		0x5CC7CFC9BBE5E8CDULL,
		0xF92307A8E46D3470ULL,
		0x41CC1D5285F8B405ULL,
		0xFFA14A4141189997ULL,
		0xFB0034B08534E626ULL,
		0x43872A6A4F321A81ULL
	}};
	sign = 0;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA08FB06DA30C254AULL,
		0x6C2BE12808941001ULL,
		0xB02BC3F87D979FA2ULL,
		0x7B757D808A30426AULL,
		0xDAA09C5C6FB2C6E5ULL,
		0x0154D0B850AE6D2FULL,
		0x39F6BD114E87FD18ULL,
		0x9AB319CB73CCAE32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB37A479F2EE6563CULL,
		0xC473BAE4EB565735ULL,
		0x723D6C55E4FEAC6CULL,
		0xC9A80D5913B3C74FULL,
		0x6BA83860ED82F897ULL,
		0x73FEF39C60DC6D09ULL,
		0xE47514CEE345D7AEULL,
		0xF4EB29DEFD9ED710ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED1568CE7425CF0EULL,
		0xA7B826431D3DB8CBULL,
		0x3DEE57A29898F335ULL,
		0xB1CD7027767C7B1BULL,
		0x6EF863FB822FCE4DULL,
		0x8D55DD1BEFD20026ULL,
		0x5581A8426B422569ULL,
		0xA5C7EFEC762DD721ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3630B0E8A7774F78ULL,
		0x75F2D6A3383561E6ULL,
		0x3A5E87A265B49DCCULL,
		0xBA8CC0DA670486D7ULL,
		0x2C7759349F99167BULL,
		0x65E11234A1E6872DULL,
		0xC65F56237C98C085ULL,
		0x1393B812962D5D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DBD330CE11CEFC5ULL,
		0x86205AA068CE2476ULL,
		0xDCC97577AD85673AULL,
		0xE7982A8D0A623748ULL,
		0x7BD7020C0E9E06BBULL,
		0xD3720747AF9BC615ULL,
		0x6D8826C1272AA0BAULL,
		0xF60AF66A30994850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18737DDBC65A5FB3ULL,
		0xEFD27C02CF673D70ULL,
		0x5D95122AB82F3691ULL,
		0xD2F4964D5CA24F8EULL,
		0xB0A0572890FB0FBFULL,
		0x926F0AECF24AC117ULL,
		0x58D72F62556E1FCAULL,
		0x1D88C1A8659414FAULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31CC9034E49EC35FULL,
		0xC95CCDF4A0F87B35ULL,
		0x6378B6DDD419EB26ULL,
		0xD105A3B3889447E8ULL,
		0x33ADC392318E1592ULL,
		0xB03DF8F317980ED4ULL,
		0xD3D058030EEA932CULL,
		0xACAE74A8A9586BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2D284C252597DEAULL,
		0xE4A5BFDBF93E257CULL,
		0x21FBF5AF0590C3B2ULL,
		0x275186313FC44ED8ULL,
		0x8647BC7AF8A1ADDDULL,
		0xB99E6B708E29C213ULL,
		0x3C3097B6FAB0A41BULL,
		0x18B1C9288B1F9FFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EFA0B7292454575ULL,
		0xE4B70E18A7BA55B8ULL,
		0x417CC12ECE892773ULL,
		0xA9B41D8248CFF910ULL,
		0xAD66071738EC67B5ULL,
		0xF69F8D82896E4CC0ULL,
		0x979FC04C1439EF10ULL,
		0x93FCAB801E38CBAAULL
	}};
	sign = 0;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC34ED4EDB871BD45ULL,
		0x2ADAB49AA196E44FULL,
		0x35C51519482937BEULL,
		0x31BBF770AF1A0EEBULL,
		0x680062F725DCC006ULL,
		0x0FAD341ABF779D01ULL,
		0x51CB707F89E4FE5DULL,
		0x9716D777B0B9E2D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4385C3279B9CCFE8ULL,
		0x33BA0C6159DE07A6ULL,
		0xAEF78C963C4967FAULL,
		0xF1B068F9321025F6ULL,
		0x4E62C34B538285C2ULL,
		0x01BB3ADE5E718377ULL,
		0x87709134E2FBE965ULL,
		0x7C1D7A414E1A0657ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FC911C61CD4ED5DULL,
		0xF720A83947B8DCA9ULL,
		0x86CD88830BDFCFC3ULL,
		0x400B8E777D09E8F4ULL,
		0x199D9FABD25A3A43ULL,
		0x0DF1F93C6106198AULL,
		0xCA5ADF4AA6E914F8ULL,
		0x1AF95D36629FDC7DULL
	}};
	sign = 0;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCEADAB2C536D458ULL,
		0xCB42ECFF48708849ULL,
		0x205F50AA8070E581ULL,
		0xCC66FEDF6B6E7516ULL,
		0xFA222883FEAABC05ULL,
		0xC0CCE77E3B327F7BULL,
		0xBC9CCF2FCD0274D6ULL,
		0xF506AF36D39D9FD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11CCF26CF8018DA6ULL,
		0xFC67D9467A3BD221ULL,
		0xEC0C16855BE4A939ULL,
		0x653AD8B28A21888AULL,
		0x135251066AEBDEDFULL,
		0x6DC95C209513A414ULL,
		0x6E07FEB1542B3E37ULL,
		0x8C4D038403EDDDD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB1DE845CD3546B2ULL,
		0xCEDB13B8CE34B628ULL,
		0x34533A25248C3C47ULL,
		0x672C262CE14CEC8BULL,
		0xE6CFD77D93BEDD26ULL,
		0x53038B5DA61EDB67ULL,
		0x4E94D07E78D7369FULL,
		0x68B9ABB2CFAFC202ULL
	}};
	sign = 0;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x87603EE96C7F5835ULL,
		0xB678D9E88A6CD3D8ULL,
		0x477B4B122D5C57C0ULL,
		0xE1225434F32C89C9ULL,
		0xF5493A2573851BD7ULL,
		0xF509D7A9F03E6BE2ULL,
		0x08191D5A58C2EDACULL,
		0xA653602BBE07DB7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C9BC74C686E77FULL,
		0x4785782A814B17DAULL,
		0x49F49C3893C05A36ULL,
		0x07DFD0153962D510ULL,
		0x2F0FC5584A2622D5ULL,
		0x68F79BFED68E4FDFULL,
		0xD8F6EB86DAB38759ULL,
		0xCA1ECBBF63839FBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3968274A5F870B6ULL,
		0x6EF361BE0921BBFDULL,
		0xFD86AED9999BFD8AULL,
		0xD942841FB9C9B4B8ULL,
		0xC63974CD295EF902ULL,
		0x8C123BAB19B01C03ULL,
		0x2F2231D37E0F6653ULL,
		0xDC34946C5A843BBDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5DF112F6FCC4877ULL,
		0x67017E57585FB5B8ULL,
		0x33675CC4EA184872ULL,
		0xD04EB043686D8062ULL,
		0x9765465E3DA8C886ULL,
		0x5994E83A5E711AC6ULL,
		0x9B0DB59F279B13C2ULL,
		0xBC52957063AC6B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x356AC573F5813DC5ULL,
		0xECB69FE38DACB8E8ULL,
		0x83A86929239E0D4DULL,
		0x7BF8A46CC7E8FAF0ULL,
		0x56069DC1949928DFULL,
		0x5E657B7A3DC4790FULL,
		0x01EF3FF4798BAE91ULL,
		0xA0978AF61E096B56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80744BBB7A4B0AB2ULL,
		0x7A4ADE73CAB2FCD0ULL,
		0xAFBEF39BC67A3B24ULL,
		0x54560BD6A0848571ULL,
		0x415EA89CA90F9FA7ULL,
		0xFB2F6CC020ACA1B7ULL,
		0x991E75AAAE0F6530ULL,
		0x1BBB0A7A45A3002BULL
	}};
	sign = 0;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0CAC8FA8264961A6ULL,
		0x4EFF5718848EC44FULL,
		0x5F0F52473F578277ULL,
		0xA8B0A7236B79D678ULL,
		0x860C41038A275D5CULL,
		0xFB1854F109DF5F3DULL,
		0xF9A44D063C98D75DULL,
		0x0F5B3DA6BF1EAB0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D440591882918B2ULL,
		0x72FA88FC814D097AULL,
		0x4E513974A139C54CULL,
		0x8F4BE00FDAD3B74BULL,
		0x69744059A9F301A2ULL,
		0x762E412660A8AC95ULL,
		0x4CAA6711B2E80ABEULL,
		0x3970C6ACC5695AC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F688A169E2048F4ULL,
		0xDC04CE1C0341BAD4ULL,
		0x10BE18D29E1DBD2AULL,
		0x1964C71390A61F2DULL,
		0x1C9800A9E0345BBAULL,
		0x84EA13CAA936B2A8ULL,
		0xACF9E5F489B0CC9FULL,
		0xD5EA76F9F9B5504DULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDDBAB48E1F7003DDULL,
		0x00BACBB31092AB83ULL,
		0x30C919D2D1A90C48ULL,
		0x9C491E26BA868E21ULL,
		0x8EA369CE04757191ULL,
		0x352CA5B6E23241F4ULL,
		0x36891A49F24182B4ULL,
		0x35DCE7CD69D00CBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA21B75108097DCULL,
		0x2AF169ED2C066312ULL,
		0x49CD677D1A6DFC9DULL,
		0x3DF2B46BCD7E3554ULL,
		0x461F637662DB6884ULL,
		0x08178462E533005DULL,
		0xABE62591826253D5ULL,
		0x38B59F5336622A78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x121899190EEF6C01ULL,
		0xD5C961C5E48C4871ULL,
		0xE6FBB255B73B0FAAULL,
		0x5E5669BAED0858CCULL,
		0x48840657A19A090DULL,
		0x2D152153FCFF4197ULL,
		0x8AA2F4B86FDF2EDFULL,
		0xFD27487A336DE241ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x543648FCF339D127ULL,
		0xC72E9A589D35466BULL,
		0x49B50A25A8354816ULL,
		0x4B66B02AF956F8B0ULL,
		0x715C0B520D9C3AB7ULL,
		0x8FAD3990E3B7EE3EULL,
		0x1C9A18E87590203CULL,
		0xA6753A2C42509D04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62617E3B41186EB5ULL,
		0xAEEA3394B85CE604ULL,
		0x6158115B17C2E74DULL,
		0x04150F0977122106ULL,
		0xF0F06E8B2EC1DC1BULL,
		0x59CBC72808483F26ULL,
		0x5662BA196B6F7752ULL,
		0x4E86A70519D9D9ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1D4CAC1B2216272ULL,
		0x184466C3E4D86066ULL,
		0xE85CF8CA907260C9ULL,
		0x4751A1218244D7A9ULL,
		0x806B9CC6DEDA5E9CULL,
		0x35E17268DB6FAF17ULL,
		0xC6375ECF0A20A8EAULL,
		0x57EE93272876C317ULL
	}};
	sign = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEFD284A8157F05FULL,
		0x7ED4BCAD2616A227ULL,
		0x7AC29526A94A66F2ULL,
		0x009058945BDD837AULL,
		0x0BC75E113203C1CFULL,
		0x8C2ACD8DD3394522ULL,
		0x45A2AE70F98F6977ULL,
		0x3A1CB27B1C947798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A91568E5987D39ULL,
		0x5900B837D7951596ULL,
		0x12B603F69BC13A94ULL,
		0x7F3AAC613D39C35CULL,
		0xD46B3262D4F86631ULL,
		0xEA6A5D99464F4595ULL,
		0xF184D79D155945DEULL,
		0xE083C71D0B379FF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE65412E19BBF7326ULL,
		0x25D404754E818C90ULL,
		0x680C91300D892C5EULL,
		0x8155AC331EA3C01EULL,
		0x375C2BAE5D0B5B9DULL,
		0xA1C06FF48CE9FF8CULL,
		0x541DD6D3E4362398ULL,
		0x5998EB5E115CD7A4ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE62529F9CCE74DF7ULL,
		0x196871CC555DFEF0ULL,
		0x5A2AB62B149EFFDDULL,
		0x84D905B8FFA5A275ULL,
		0x6D8DD276A64A06AFULL,
		0x54CAD145D2ABC5C4ULL,
		0x0ED3D6E8C8B762D2ULL,
		0xE954518789781890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BB42167800277F5ULL,
		0x1BEBF411AE8AF3D4ULL,
		0x13B76B0C03A731E6ULL,
		0x655F9309F4372051ULL,
		0x32024F767209F4C0ULL,
		0xD03BD471FAF90CA3ULL,
		0x126689429E51477BULL,
		0x93960F3C709777CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A7108924CE4D602ULL,
		0xFD7C7DBAA6D30B1CULL,
		0x46734B1F10F7CDF6ULL,
		0x1F7972AF0B6E8224ULL,
		0x3B8B8300344011EFULL,
		0x848EFCD3D7B2B921ULL,
		0xFC6D4DA62A661B56ULL,
		0x55BE424B18E0A0C4ULL
	}};
	sign = 0;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3C4159841A203BDULL,
		0xD708F1289C38D89EULL,
		0x28BFC0ABD927CD41ULL,
		0xA4A826B2D701E16DULL,
		0x804E80BC0EF8F594ULL,
		0x031EC02FBF372D17ULL,
		0x12C97F88F3E0FFF9ULL,
		0x649F5F7A9A2D2DC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD973DCCE0348DE3AULL,
		0x93BBDF526887B47BULL,
		0x8F7C95443F0B9A07ULL,
		0xEBF3C5657DE34985ULL,
		0xBC0891F550DA4FFDULL,
		0xBF9C71793A237602ULL,
		0x59F129FAD58781B9ULL,
		0xA1B7572CA03F4B09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A5038CA3E592583ULL,
		0x434D11D633B12423ULL,
		0x99432B679A1C333AULL,
		0xB8B4614D591E97E7ULL,
		0xC445EEC6BE1EA596ULL,
		0x43824EB68513B714ULL,
		0xB8D8558E1E597E3FULL,
		0xC2E8084DF9EDE2B6ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39460BA69D1DA383ULL,
		0xE6DDA2D778840B78ULL,
		0x92A8B4EDD5EA7C06ULL,
		0xE9CAA1014A161F5FULL,
		0x03CED12E3A19F340ULL,
		0x0A39E6FF48AA4CAAULL,
		0xCF5132232238ED89ULL,
		0xAAF151895DA47DF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FEF8320F9FF8FE3ULL,
		0x084CCBB2E76080D3ULL,
		0x77D1C255F7D81064ULL,
		0x2775AA6C385EC33DULL,
		0x495CF71DF928326DULL,
		0x897892A48CB51AC1ULL,
		0x4C012802BBC56971ULL,
		0x019A3A351ED0818CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09568885A31E13A0ULL,
		0xDE90D72491238AA5ULL,
		0x1AD6F297DE126BA2ULL,
		0xC254F69511B75C22ULL,
		0xBA71DA1040F1C0D3ULL,
		0x80C1545ABBF531E8ULL,
		0x83500A2066738417ULL,
		0xA95717543ED3FC6DULL
	}};
	sign = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB13E2DB6C81963AAULL,
		0x6588026BBF68D76EULL,
		0xA7EE3BBDDE42180CULL,
		0x6DF4954649AE4F60ULL,
		0x6C049A38B0FC0830ULL,
		0xECA766B786151F75ULL,
		0x8495D4C2A380D530ULL,
		0xA6A6B0275B50961AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FCC2FFE7F25E3AEULL,
		0xDB8B896AE80025E3ULL,
		0xEBF65D7B9BDBCBD8ULL,
		0xD987C5A3D776CE43ULL,
		0x0D87A396040F9B57ULL,
		0xE65226069868B6D3ULL,
		0x90AA089231057E0DULL,
		0x3A03FF0045C28FCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6171FDB848F37FFCULL,
		0x89FC7900D768B18BULL,
		0xBBF7DE4242664C33ULL,
		0x946CCFA27237811CULL,
		0x5E7CF6A2ACEC6CD8ULL,
		0x065540B0EDAC68A2ULL,
		0xF3EBCC30727B5723ULL,
		0x6CA2B127158E064FULL
	}};
	sign = 0;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B169648CD7CCF17ULL,
		0xE74C25949F17A0E9ULL,
		0x8E2DAAE68404F070ULL,
		0x9AB80F065A8C2DA9ULL,
		0x401E8816EC4BC759ULL,
		0x5F43A2B132A7735CULL,
		0xE1B021DFCCCEECFEULL,
		0x2978C30D44C71F54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631C8B1D6C8BD498ULL,
		0x1684666EDA32BBD2ULL,
		0x036314EDFF646E75ULL,
		0x10C9DCC75244F7DEULL,
		0x44BD324F66FAE584ULL,
		0x0A778074A8410CA0ULL,
		0x7652A67525431069ULL,
		0xF332AFDFFF0D6995ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07FA0B2B60F0FA7FULL,
		0xD0C7BF25C4E4E517ULL,
		0x8ACA95F884A081FBULL,
		0x89EE323F084735CBULL,
		0xFB6155C78550E1D5ULL,
		0x54CC223C8A6666BBULL,
		0x6B5D7B6AA78BDC95ULL,
		0x3646132D45B9B5BFULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFEC23EBAE47A6879ULL,
		0x595ABAB9810E7E28ULL,
		0xE443B9B72E4B2F31ULL,
		0x98B83F43764F6F4DULL,
		0xA3F1861C00EADF5FULL,
		0x61370BDC8BB82125ULL,
		0xD1AB13B3EE338582ULL,
		0x2AFEE60379541AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4E774619A2BBF9ULL,
		0xF6062177B36BC51DULL,
		0xB36677B5B0BCCBB1ULL,
		0xA370B311CDED9A11ULL,
		0x92C1C0F17FEA3CCCULL,
		0xCC0E1AF7B91118B1ULL,
		0x26FDE599451BA28FULL,
		0xA736BB0C97093250ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB273C774CAD7AC80ULL,
		0x63549941CDA2B90BULL,
		0x30DD42017D8E637FULL,
		0xF5478C31A861D53CULL,
		0x112FC52A8100A292ULL,
		0x9528F0E4D2A70874ULL,
		0xAAAD2E1AA917E2F2ULL,
		0x83C82AF6E24AE8ABULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6EECF0805CA40B2AULL,
		0x465238224A143AB7ULL,
		0xB30FF05ABE4C8424ULL,
		0x27D3A70726E29A37ULL,
		0x1D31945E67AE6E78ULL,
		0xD97AF0CAA8943EABULL,
		0xE67B2B50D3B1E02DULL,
		0xA33522744237C163ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x432F566908AB9B78ULL,
		0x989ADAB3079F4CF2ULL,
		0xA8FF6B57D1632264ULL,
		0x5FB4AA007B464D8BULL,
		0xADCA3BEEA100EF02ULL,
		0x45936F1C140AADA9ULL,
		0xA816EFE8346D960AULL,
		0xD53BABAC556FC272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2BBD9A1753F86FB2ULL,
		0xADB75D6F4274EDC5ULL,
		0x0A108502ECE961BFULL,
		0xC81EFD06AB9C4CACULL,
		0x6F67586FC6AD7F75ULL,
		0x93E781AE94899101ULL,
		0x3E643B689F444A23ULL,
		0xCDF976C7ECC7FEF1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D5221F676F4F864ULL,
		0x78F1608A48E08C74ULL,
		0x69F0134CB6F462D3ULL,
		0xBA9BFCABF84ED927ULL,
		0x8EA05FF038C4FBBCULL,
		0xB80C4B309E6FE34BULL,
		0xEB4B2954C0787F9DULL,
		0xEB7C81CA8BD986E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E986470556CF268ULL,
		0xDDF4D7B96B24C589ULL,
		0x21AEC5A94370123BULL,
		0xE58272AD874E9140ULL,
		0x6C3D2D7CB513525DULL,
		0xF290B3E10FDDABCCULL,
		0xD246BCDF4B527FEDULL,
		0x6804A69D1E814C30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEB9BD86218805FCULL,
		0x9AFC88D0DDBBC6EAULL,
		0x48414DA373845097ULL,
		0xD51989FE710047E7ULL,
		0x2263327383B1A95EULL,
		0xC57B974F8E92377FULL,
		0x19046C757525FFAFULL,
		0x8377DB2D6D583AB3ULL
	}};
	sign = 0;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AAECB060A32FAD5ULL,
		0x964CDD50CBF05B8AULL,
		0xA980BE0BDD624856ULL,
		0x89090052502E8B42ULL,
		0xB9DCB502DA608CB7ULL,
		0xA328279A522D81C9ULL,
		0x6E7B60F57082FEF8ULL,
		0x6BDB4A3AE7C4A239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B660D80B5FA5EAAULL,
		0x204A075977EF7B7EULL,
		0x956157B8A6A84841ULL,
		0xBA70B59DCC0C0C51ULL,
		0xD7B0CBDAB33BF22FULL,
		0x409865B889DF7991ULL,
		0x7C5AFBF52EC560B9ULL,
		0xB44FF649D3168C28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F48BD8554389C2BULL,
		0x7602D5F75400E00CULL,
		0x141F665336BA0015ULL,
		0xCE984AB484227EF1ULL,
		0xE22BE92827249A87ULL,
		0x628FC1E1C84E0837ULL,
		0xF220650041BD9E3FULL,
		0xB78B53F114AE1610ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9A1CED79D51887BULL,
		0x94969F88D5872695ULL,
		0x5385A8A938AB5279ULL,
		0x8FFE56B86B5FF2EEULL,
		0xACBA84A2869B556DULL,
		0x5043B6E0CA4873D9ULL,
		0x608A0F5997923610ULL,
		0x90ADAE77FEFD68BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5B57FA8BFDF1F3ULL,
		0x582DED87AADF61ADULL,
		0x8E1A45CF3EE87BF2ULL,
		0x8339D0D2462C9356ULL,
		0xDA02F900A16276ADULL,
		0x9AA9D8D5A98E5D74ULL,
		0xFD067FC455DE2EE7ULL,
		0xD094ADADD76E66DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD4676DD11539688ULL,
		0x3C68B2012AA7C4E8ULL,
		0xC56B62D9F9C2D687ULL,
		0x0CC485E625335F97ULL,
		0xD2B78BA1E538DEC0ULL,
		0xB599DE0B20BA1664ULL,
		0x63838F9541B40728ULL,
		0xC01900CA278F01E1ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40B36D3F3F18437CULL,
		0x0195C324040F9B8DULL,
		0x1EED91E7115395CFULL,
		0xBD8047724783AED5ULL,
		0x032222B351AB9410ULL,
		0x7A50E76A933622B2ULL,
		0x8404A04A1F3505ACULL,
		0xBAE6671CFF287FA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6CD3103E9F50EAULL,
		0x3C8CC11D385AA089ULL,
		0xCC734F59DF95A960ULL,
		0xC12D5894F2CAE10AULL,
		0xC1635796890EDE39ULL,
		0xC5A7C6F67703EC35ULL,
		0x082F3BB2B518A60AULL,
		0x3A3E957D2A68AF40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6469A2F0078F292ULL,
		0xC5090206CBB4FB03ULL,
		0x527A428D31BDEC6EULL,
		0xFC52EEDD54B8CDCAULL,
		0x41BECB1CC89CB5D6ULL,
		0xB4A920741C32367CULL,
		0x7BD564976A1C5FA1ULL,
		0x80A7D19FD4BFD060ULL
	}};
	sign = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9983D9835DB1A926ULL,
		0xFB6643332F9AD0D6ULL,
		0x66F5D64548753438ULL,
		0x4651545F5FEF950EULL,
		0xF08CB3A564C40669ULL,
		0x3CCB66ABC92589E3ULL,
		0xA01811240C58FBDAULL,
		0xE9C258519CBFE185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9619BE17475AE78ULL,
		0x8C3DC62662BE87EAULL,
		0x1EB1246D24FC0ED1ULL,
		0x7D3B83538E392D07ULL,
		0xC96A3D7B0E8BE365ULL,
		0x263B92A6663B06C3ULL,
		0x84D42971E3D988D0ULL,
		0x17EE0985B4AF2F52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0223DA1E93BFAAEULL,
		0x6F287D0CCCDC48EBULL,
		0x4844B1D823792567ULL,
		0xC915D10BD1B66807ULL,
		0x2722762A56382303ULL,
		0x168FD40562EA8320ULL,
		0x1B43E7B2287F730AULL,
		0xD1D44ECBE810B233ULL
	}};
	sign = 0;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86D1FE03864ED758ULL,
		0x10E30C627D068DD5ULL,
		0xC3DFF3EC5349AE8DULL,
		0x67623D6A65BF9A8AULL,
		0xAAA05F8A21392109ULL,
		0xB0DC9A3601D3A841ULL,
		0x121959E56159D6C2ULL,
		0x89925EE96868EAA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ACCA73E3BC3EAA4ULL,
		0x90106B52F123436AULL,
		0xF16FB33A0DDEC63CULL,
		0x7E20F0019269FA46ULL,
		0x3E89D3D3F738982EULL,
		0x4519A172EB37BBE6ULL,
		0xBEE0A197D6B7A1E8ULL,
		0x3FDDD92447EF99BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C0556C54A8AECB4ULL,
		0x80D2A10F8BE34A6BULL,
		0xD27040B2456AE850ULL,
		0xE9414D68D355A043ULL,
		0x6C168BB62A0088DAULL,
		0x6BC2F8C3169BEC5BULL,
		0x5338B84D8AA234DAULL,
		0x49B485C5207950EAULL
	}};
	sign = 0;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50503958207EBAF6ULL,
		0xE9D3DCDE1BE852D4ULL,
		0x7CF137C6629184DCULL,
		0x87985123E5DDD876ULL,
		0xC6CF3694464A9362ULL,
		0x672C968603FC8C6CULL,
		0x30974BB7D78E1869ULL,
		0xBFC9C76FECAEBD7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA669F0156C4ABF4DULL,
		0x0C72B1C586EB99F1ULL,
		0x536943CE42AE1F26ULL,
		0x0DE4DB5EC2033262ULL,
		0xA9E00B94E8068512ULL,
		0x4F711919DFFDB2EEULL,
		0x099C4DF27D56002EULL,
		0xE17C28E8A24DBFF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9E64942B433FBA9ULL,
		0xDD612B1894FCB8E2ULL,
		0x2987F3F81FE365B6ULL,
		0x79B375C523DAA614ULL,
		0x1CEF2AFF5E440E50ULL,
		0x17BB7D6C23FED97EULL,
		0x26FAFDC55A38183BULL,
		0xDE4D9E874A60FD89ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x387A22F31E36FAEAULL,
		0x12E83AC9AD1C84C9ULL,
		0xBEE38C50EB04B348ULL,
		0x5762579844DEFFF0ULL,
		0xB8013C4341362FB9ULL,
		0xE31048F399B7B108ULL,
		0xC04362EF950D7B06ULL,
		0xC2B737EC1A22866EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A8E421E622A022ULL,
		0x9ED211B4328141BEULL,
		0xFCB3C459F3A6CE71ULL,
		0x8A3AEFD612E0671DULL,
		0x92304632EDF2D3F4ULL,
		0xDFCA19B09827272BULL,
		0xCC5BFA184B9EB83AULL,
		0xA7B3CDC7F912F533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02D13ED138145AC8ULL,
		0x741629157A9B430BULL,
		0xC22FC7F6F75DE4D6ULL,
		0xCD2767C231FE98D2ULL,
		0x25D0F61053435BC4ULL,
		0x03462F43019089DDULL,
		0xF3E768D7496EC2CCULL,
		0x1B036A24210F913AULL
	}};
	sign = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD28AA77AB2C63DE2ULL,
		0x1592422170111636ULL,
		0x4E7E5FEC3E9F7F62ULL,
		0xD79F451C9A7172DFULL,
		0xF606513E70BE092DULL,
		0x7269620CB041A0B1ULL,
		0xD80E202B10C04142ULL,
		0x2CB950EC60AFD2D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5532A53204F8E99DULL,
		0xF2143449A7C207E6ULL,
		0x6D8F677CEDDF26A5ULL,
		0x399B506E50693C16ULL,
		0xE131F93BA3D89F1FULL,
		0xB111A258DCBBB4F4ULL,
		0xF65FC15CA1BC4367ULL,
		0x72E7C6EDD6B3C30AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D580248ADCD5445ULL,
		0x237E0DD7C84F0E50ULL,
		0xE0EEF86F50C058BCULL,
		0x9E03F4AE4A0836C8ULL,
		0x14D45802CCE56A0EULL,
		0xC157BFB3D385EBBDULL,
		0xE1AE5ECE6F03FDDAULL,
		0xB9D189FE89FC0FC7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x103D957FBBC0E973ULL,
		0xC820FE6FAB457E63ULL,
		0xEBBC616D832CA04DULL,
		0xB03A457B9431FE46ULL,
		0x0646BE37E124A803ULL,
		0xFF798C5E09C58569ULL,
		0x2A4D4F5D29B46675ULL,
		0xC83A03BAAB620519ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3E0B0A14858E9D4ULL,
		0x52F486690EF07C27ULL,
		0x149BEB35AA0F889FULL,
		0xA2F3C5B2AF0E01D5ULL,
		0xFB3409E5AC0724B2ULL,
		0x456999BDF0375066ULL,
		0x921F6977BE26333CULL,
		0x1C1CDD2025967B8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C5CE4DE7367FF9FULL,
		0x752C78069C55023BULL,
		0xD7207637D91D17AEULL,
		0x0D467FC8E523FC71ULL,
		0x0B12B452351D8351ULL,
		0xBA0FF2A0198E3502ULL,
		0x982DE5E56B8E3339ULL,
		0xAC1D269A85CB898AULL
	}};
	sign = 0;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FAB54229CEFE379ULL,
		0x7E5DAFAE63E8449AULL,
		0x7468A451B29B7FFBULL,
		0x9275D4D6D8041842ULL,
		0xD88C71DE7C562C71ULL,
		0xF313F45888ED6593ULL,
		0x2EBF6620A953579BULL,
		0xB82C5797886F4EDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AE3ABC13E3E2935ULL,
		0x8A563D5C5F289A2FULL,
		0x61FF199BBF2BAF2CULL,
		0xAB65DCB4A2647E57ULL,
		0x4AC530A085CC37F4ULL,
		0xE95759CA4FA5CACBULL,
		0xCFA2359C37DD145EULL,
		0xAA755721CB26D587ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14C7A8615EB1BA44ULL,
		0xF407725204BFAA6BULL,
		0x12698AB5F36FD0CEULL,
		0xE70FF822359F99EBULL,
		0x8DC7413DF689F47CULL,
		0x09BC9A8E39479AC8ULL,
		0x5F1D30847176433DULL,
		0x0DB70075BD487952ULL
	}};
	sign = 0;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCBF037599F0711DULL,
		0x71520B49FB88A087ULL,
		0x87E9D42BE5AB7606ULL,
		0x90DA744F42F03E19ULL,
		0x26C4D8DE326732B3ULL,
		0xEAC9D36E3FD7235AULL,
		0xCD10D6EA363F9589ULL,
		0x3094C925BC8EE0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB16ED7A0AED41964ULL,
		0xCBE55A85961B8762ULL,
		0x11C6C5FB994066EBULL,
		0x411680CCCF5BD6A7ULL,
		0x7A1304B279677EA1ULL,
		0xC1D93E3B0E623C4FULL,
		0xA64C03C0398ACF86ULL,
		0x76C76F31EE2AC3DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B502BD4EB1C57B9ULL,
		0xA56CB0C4656D1925ULL,
		0x76230E304C6B0F1AULL,
		0x4FC3F38273946772ULL,
		0xACB1D42BB8FFB412ULL,
		0x28F095333174E70AULL,
		0x26C4D329FCB4C603ULL,
		0xB9CD59F3CE641CC5ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4AE42E28AC8EBD7ULL,
		0x12A565507E117901ULL,
		0x4C7BB64ADBC94B61ULL,
		0xDC7CC50790B73C60ULL,
		0xFDD6C25A2CF1C2D2ULL,
		0x3CBDA62CB89F59D4ULL,
		0x9D38D92D376D7007ULL,
		0x2A569FAF7A3A3A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE9D6306AA07E3DAULL,
		0xF04A99BBBB430C16ULL,
		0x7BEECA170F59F24BULL,
		0x9AFB4C62DD0DCBD2ULL,
		0x08CD7DD83386024AULL,
		0x9D96373ADAA086DAULL,
		0xD56F4DDEAACA9C24ULL,
		0x3C0BEDFDB9420A44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2610DFDBE0C107FDULL,
		0x225ACB94C2CE6CEBULL,
		0xD08CEC33CC6F5915ULL,
		0x418178A4B3A9708DULL,
		0xF5094481F96BC088ULL,
		0x9F276EF1DDFED2FAULL,
		0xC7C98B4E8CA2D3E2ULL,
		0xEE4AB1B1C0F8300CULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73CA304679D52656ULL,
		0x35E3939FDF6FD5F4ULL,
		0x36E3577141A607DCULL,
		0x3678A00E869317A1ULL,
		0xC7B46CA27782BC28ULL,
		0xE484C72F06FF69CCULL,
		0x185446F1243A1C04ULL,
		0xCFFA42DEA3DE335FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BC8FF1C8F8CE11ULL,
		0x41FCDCED679A7EC7ULL,
		0x687A4143B4BD30E2ULL,
		0xB035855CAE10FA91ULL,
		0x39FB6C38E110E38EULL,
		0x75DEA3A4BA747B87ULL,
		0x3DB17F1808D2D2C5ULL,
		0x9C67BA5F1F244E2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A0DA054B0DC5845ULL,
		0xF3E6B6B277D5572DULL,
		0xCE69162D8CE8D6F9ULL,
		0x86431AB1D8821D0FULL,
		0x8DB900699671D899ULL,
		0x6EA6238A4C8AEE45ULL,
		0xDAA2C7D91B67493FULL,
		0x3392887F84B9E533ULL
	}};
	sign = 0;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B779B5E04744A08ULL,
		0x7932788940269060ULL,
		0xF2CFF04ACF1795ECULL,
		0x3F93FB489F8FA21CULL,
		0x572D67C94F3727D7ULL,
		0xC5FE35AECBCB7A7DULL,
		0xF6795AF80115390CULL,
		0x7A0D66EDC1418F87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34EB26798B9AFA6BULL,
		0xA648C9860BF3900DULL,
		0xA874156ECA1A7767ULL,
		0x0FE17E03AD5EF967ULL,
		0x731F7022BD5E3CC5ULL,
		0xF81010862395DE8CULL,
		0xBCDB3F5C63627214ULL,
		0x19F4116E5B2A3D1BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x368C74E478D94F9DULL,
		0xD2E9AF0334330053ULL,
		0x4A5BDADC04FD1E84ULL,
		0x2FB27D44F230A8B5ULL,
		0xE40DF7A691D8EB12ULL,
		0xCDEE2528A8359BF0ULL,
		0x399E1B9B9DB2C6F7ULL,
		0x6019557F6617526CULL
	}};
	sign = 0;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA4710EAD26A2D39ULL,
		0x5EC3A1E39787ED5AULL,
		0x09CC265498781256ULL,
		0x47584EC055B31AF8ULL,
		0x2910BBF1763FA690ULL,
		0x1C7CD1DD9277309BULL,
		0x509202D045DB7581ULL,
		0x6D7A4AB3B17A7B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC8379CA3E354519ULL,
		0xFFF170D87A67289FULL,
		0xF6DF5DE4259B74F2ULL,
		0xEFF815EBAF0F9D9BULL,
		0x01558B21812EA5C1ULL,
		0x931699C4AA27BFCEULL,
		0xBC4ADD2F822A42CEULL,
		0x0A45AE6A1599A63DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDC397209434E820ULL,
		0x5ED2310B1D20C4BAULL,
		0x12ECC87072DC9D63ULL,
		0x576038D4A6A37D5CULL,
		0x27BB30CFF51100CEULL,
		0x89663818E84F70CDULL,
		0x944725A0C3B132B2ULL,
		0x63349C499BE0D4E3ULL
	}};
	sign = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1465C8FF23D2A4BULL,
		0x9AD65E21A3B04D7CULL,
		0x87A6B85D5C2FD438ULL,
		0x711391A1B9BCBE20ULL,
		0x6B9A4CC1B8B2B815ULL,
		0x6FB723819C72F069ULL,
		0xD76D045710AD81D1ULL,
		0x8E3021B0326FF292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864084C7F4DAEAB7ULL,
		0xCBE908899950FD4AULL,
		0x346BFACD99C507DEULL,
		0x6257A125A392C6E4ULL,
		0x6A7D077AF622BBD3ULL,
		0x77FB2CEB7DE25086ULL,
		0xF2503BC4021DA2FFULL,
		0xAEA5BC41822C6D4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B05D7C7FD623F94ULL,
		0xCEED55980A5F5032ULL,
		0x533ABD8FC26ACC59ULL,
		0x0EBBF07C1629F73CULL,
		0x011D4546C28FFC42ULL,
		0xF7BBF6961E909FE3ULL,
		0xE51CC8930E8FDED1ULL,
		0xDF8A656EB0438545ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD8F782B0A35A8D02ULL,
		0x9374A149732FA6CBULL,
		0x6AA346AF4C87F7B3ULL,
		0x09102384AB2E6BC8ULL,
		0x0410901F77366D36ULL,
		0x26F60F4C6759E5E0ULL,
		0x6836E30E822762C4ULL,
		0xB1A700D550E124A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x972A5EFE9A81DE63ULL,
		0x5F6C7EB91442333BULL,
		0xB6E22CB2C0949586ULL,
		0xEA6279C528196039ULL,
		0x18D001DF8D8218BDULL,
		0x02A11DE12E523071ULL,
		0x3176FEA853BCF152ULL,
		0xFC15E96D1D30EAC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41CD23B208D8AE9FULL,
		0x340822905EED7390ULL,
		0xB3C119FC8BF3622DULL,
		0x1EADA9BF83150B8EULL,
		0xEB408E3FE9B45478ULL,
		0x2454F16B3907B56EULL,
		0x36BFE4662E6A7172ULL,
		0xB591176833B039E0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25404B3D68081B1CULL,
		0x177491BACF817DA7ULL,
		0xE8142855389F4ACBULL,
		0x9A04E0BF0EE10803ULL,
		0x0C5DAB88CEA10419ULL,
		0xA56A9ED4C062099BULL,
		0xB8B03883F9C1108CULL,
		0x9A3F9048E2D28848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF552987AF97025FULL,
		0x9BB50C2740D57927ULL,
		0xDC3448A7D1E0F0C6ULL,
		0x05633EEA59CAB5B7ULL,
		0x73FF07003F3A434DULL,
		0x5AAF8C73F926E88AULL,
		0x7D2F64A2C0DF92E6ULL,
		0x28AE86AFBFFA7DE6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75EB21B5B87118BDULL,
		0x7BBF85938EAC047FULL,
		0x0BDFDFAD66BE5A04ULL,
		0x94A1A1D4B516524CULL,
		0x985EA4888F66C0CCULL,
		0x4ABB1260C73B2110ULL,
		0x3B80D3E138E17DA6ULL,
		0x7191099922D80A62ULL
	}};
	sign = 0;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D621CC4BCAC5BE0ULL,
		0xCF63A9EA0B8ADE21ULL,
		0xD5F1FB9DE6DE6F83ULL,
		0x7731537E32EBBFBCULL,
		0xFCE7AEA81D238F52ULL,
		0xBA669BF612B480C0ULL,
		0xB080D8074344D648ULL,
		0x8494AF1C4DFA4D8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00617AE1FEF42946ULL,
		0x5E2EA0E7B3DEFE5FULL,
		0x9246ED84FF633BE1ULL,
		0x97B53ABFC6398928ULL,
		0x4BBE3816D2371F04ULL,
		0xE4C0509A8726C005ULL,
		0x077146E4DD99A0CEULL,
		0x2F10A20B6C80E6FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D00A1E2BDB8329AULL,
		0x7135090257ABDFC2ULL,
		0x43AB0E18E77B33A2ULL,
		0xDF7C18BE6CB23694ULL,
		0xB12976914AEC704DULL,
		0xD5A64B5B8B8DC0BBULL,
		0xA90F912265AB3579ULL,
		0x55840D10E1796690ULL
	}};
	sign = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4875DCE0414C22BDULL,
		0xE89BCFFF87F08261ULL,
		0x2D9B60890DD739A0ULL,
		0x63A1D49191061B49ULL,
		0xA09433B47F3E37B6ULL,
		0x443A3F53A20BB3F0ULL,
		0xAE91821F737C1437ULL,
		0x718D4105CD91B624ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7715B4FCF9A5294ULL,
		0x0C92810C148618A0ULL,
		0x663F414A6A932086ULL,
		0x7F69A3890D745AC7ULL,
		0xEA6E71AF723CA261ULL,
		0xE04273FF3630223CULL,
		0x9C139AB3929356DEULL,
		0x248A9539DD9A10D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA104819071B1D029ULL,
		0xDC094EF3736A69C0ULL,
		0xC75C1F3EA344191AULL,
		0xE43831088391C081ULL,
		0xB625C2050D019554ULL,
		0x63F7CB546BDB91B3ULL,
		0x127DE76BE0E8BD58ULL,
		0x4D02ABCBEFF7A551ULL
	}};
	sign = 0;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1FD1ED6B503F991ULL,
		0xB6500EB40C0F3C69ULL,
		0x3AF910B771E71C8AULL,
		0xE387BCB129AF9427ULL,
		0x1B148200FCF75416ULL,
		0xF547FCCFCE2D4D21ULL,
		0xCD54EBA58747EC2BULL,
		0x8B597081342FB0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AA084CCAE69682AULL,
		0xCC097166935ADDE7ULL,
		0x8B6DBD3FA094180BULL,
		0x0CA7EC6DC4769A6AULL,
		0x27328B9940BA199BULL,
		0xB6B59F8CA35CB854ULL,
		0x79A30340D411FBD5ULL,
		0xFC32280F83FE0B1AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x575C9A0A069A9167ULL,
		0xEA469D4D78B45E82ULL,
		0xAF8B5377D153047EULL,
		0xD6DFD0436538F9BCULL,
		0xF3E1F667BC3D3A7BULL,
		0x3E925D432AD094CCULL,
		0x53B1E864B335F056ULL,
		0x8F274871B031A5DDULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B9BD03AAD57AA49ULL,
		0x7699FB68D8E1BDEDULL,
		0xE89CA6B2A45DDD41ULL,
		0x137602AF04624A45ULL,
		0x442E959DC54F12B4ULL,
		0x0CF114A2DA6BAB73ULL,
		0x98407BD6522A843DULL,
		0x1C316926032CFACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2AE83134D0DDFFEULL,
		0x69CF09A3EE0F2EC7ULL,
		0x7619995AB747685CULL,
		0xC6A2908140F0BAD8ULL,
		0x14D658DB4C058BE6ULL,
		0xFF33D67F5A08ECA1ULL,
		0x4CEBBEC895B04B34ULL,
		0xA0EE94993CDEDFA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x88ED4D276049CA4BULL,
		0x0CCAF1C4EAD28F25ULL,
		0x72830D57ED1674E5ULL,
		0x4CD3722DC3718F6DULL,
		0x2F583CC2794986CDULL,
		0x0DBD3E238062BED2ULL,
		0x4B54BD0DBC7A3908ULL,
		0x7B42D48CC64E1B29ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8573D0883A2ED8B3ULL,
		0xF56B30D5B9EB3D57ULL,
		0xD0C48634FE6B116FULL,
		0xB7C9593585A82D18ULL,
		0x64A02CDD12F65F6EULL,
		0xF68A6A74BB1D1D2DULL,
		0xA81ADB1E6CB448DFULL,
		0x06809EB64E7E1A8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE83217800E143CCULL,
		0xCFF95E2DB8FEBF3FULL,
		0x83BDF28272A3F74AULL,
		0x52A16EAB2F2616D6ULL,
		0xBE5274C17E7ECE0BULL,
		0x9A9A38D2848C681FULL,
		0x8DE2721AEBACA656ULL,
		0xC91630CFCD921B21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6F0AF10394D94E7ULL,
		0x2571D2A800EC7E17ULL,
		0x4D0693B28BC71A25ULL,
		0x6527EA8A56821642ULL,
		0xA64DB81B94779163ULL,
		0x5BF031A23690B50DULL,
		0x1A3869038107A289ULL,
		0x3D6A6DE680EBFF69ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDBC045D5BF7B6B5BULL,
		0x9D55F8F6EE0CE3F6ULL,
		0xDC8EDF6E27877CCCULL,
		0x8D1326752B56640FULL,
		0xF0A083CDC11BD6D8ULL,
		0xA22C5CAA86305091ULL,
		0x4D0D87409E79A3A7ULL,
		0xAF4FD77236CE10FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8160A9C7D8016D18ULL,
		0x1FCDC2966310A4D5ULL,
		0x1B1CA85ED229CAF3ULL,
		0x375B4D16A4297EB1ULL,
		0xCFD075D8DFEA44E1ULL,
		0x12BE28716B3422D0ULL,
		0x42227FB46A96CB3FULL,
		0xF277EB437244EB97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A5F9C0DE779FE43ULL,
		0x7D8836608AFC3F21ULL,
		0xC172370F555DB1D9ULL,
		0x55B7D95E872CE55EULL,
		0x20D00DF4E13191F7ULL,
		0x8F6E34391AFC2DC1ULL,
		0x0AEB078C33E2D868ULL,
		0xBCD7EC2EC4892566ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6ECF66B0313E7B7ULL,
		0x000F137871DD6D7DULL,
		0xA62D68EB9BDA0E22ULL,
		0x8D849834FAE14812ULL,
		0xE7154F62AE7EEBB7ULL,
		0x14D41CAF70AD0F0FULL,
		0x7D7EF37F7FC10CF1ULL,
		0xD5E98FFB1B4F9BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E87298A49B782FULL,
		0x6E6E3554F5165057ULL,
		0x5913EF966BC46517ULL,
		0xB85997D0D84035F8ULL,
		0x1872E7508E8AB65BULL,
		0xEF070107DDC63E25ULL,
		0x029C80CFB6C7244EULL,
		0x6707DCFF1D546C83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x140483D25E786F88ULL,
		0x91A0DE237CC71D26ULL,
		0x4D1979553015A90AULL,
		0xD52B006422A1121AULL,
		0xCEA268121FF4355BULL,
		0x25CD1BA792E6D0EAULL,
		0x7AE272AFC8F9E8A2ULL,
		0x6EE1B2FBFDFB2F3AULL
	}};
	sign = 0;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52E27F0C1A40D07EULL,
		0x54C7F23515841180ULL,
		0x8AEC92C0EC5C3B48ULL,
		0xFE2B52F7B3652671ULL,
		0x2C211EC62638AE99ULL,
		0xE6C1179E5DA2CDF8ULL,
		0xB8EB182466893FF0ULL,
		0x3CBCCEC5F52258F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602F70BE2816F114ULL,
		0xC0EBF70C62216001ULL,
		0x0762B5D37888CD2FULL,
		0x2D4F6D90C39863E3ULL,
		0x9DCCF86E3E89AA1FULL,
		0xC0B285C742EFCF7BULL,
		0xAE7966E88AFD69B0ULL,
		0xDA5A856BD29C7BA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2B30E4DF229DF6AULL,
		0x93DBFB28B362B17EULL,
		0x8389DCED73D36E18ULL,
		0xD0DBE566EFCCC28EULL,
		0x8E542657E7AF047AULL,
		0x260E91D71AB2FE7CULL,
		0x0A71B13BDB8BD640ULL,
		0x6262495A2285DD51ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D08C4D82BC749ACULL,
		0xCA8C8848406E779DULL,
		0x0A260CCF058B4F65ULL,
		0x593BAD96ABA738D5ULL,
		0x3AD5F9AC977987A7ULL,
		0x35E9B0649B86ED39ULL,
		0xA76DAAD2E44A8784ULL,
		0x53CB607332942D64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A40DB0046DF50A9ULL,
		0x1564CD093D52D599ULL,
		0x17F6829DB01F9124ULL,
		0x77046DE263A13E7DULL,
		0x965EB21DEE548D86ULL,
		0x6C970EBB67ADEA3AULL,
		0x77661E1CC4E17918ULL,
		0x8DB52D86DB74A053ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32C7E9D7E4E7F903ULL,
		0xB527BB3F031BA204ULL,
		0xF22F8A31556BBE41ULL,
		0xE2373FB44805FA57ULL,
		0xA477478EA924FA20ULL,
		0xC952A1A933D902FEULL,
		0x30078CB61F690E6BULL,
		0xC61632EC571F8D11ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95B41053B56FD553ULL,
		0x178DFE1240BBB953ULL,
		0xFE3095E02CF5BE5BULL,
		0xBD9CF9690498584BULL,
		0x00B1FE444C9B451DULL,
		0x69A4D18F43B783FAULL,
		0x172A7CFAB1E14618ULL,
		0x50682FA8408B2996ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36E9369FE86E7653ULL,
		0x4631E6B6F42230ACULL,
		0x5DA78634BF1CFCE2ULL,
		0xDE6E5F10A39B2378ULL,
		0x8C27DABB5E0A6B7CULL,
		0x35E1E3889F0B7146ULL,
		0x1747D2F28C7D722DULL,
		0x7FE00901548A0790ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5ECAD9B3CD015F00ULL,
		0xD15C175B4C9988A7ULL,
		0xA0890FAB6DD8C178ULL,
		0xDF2E9A5860FD34D3ULL,
		0x748A2388EE90D9A0ULL,
		0x33C2EE06A4AC12B3ULL,
		0xFFE2AA082563D3EBULL,
		0xD08826A6EC012205ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8F07ED4C2FA82B3ULL,
		0x74F5482F98554D7CULL,
		0xF93E70587838071BULL,
		0x382FE40D4B13430DULL,
		0x2BB3CF44FD06F040ULL,
		0x726CE92FBC81F4E1ULL,
		0x0C58BF4AE387668FULL,
		0xED328C13D0946768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39C2C24666AA40C1ULL,
		0x1152C14EBF23B5BEULL,
		0x42572230527F560BULL,
		0x467AC1E8A29DF392ULL,
		0xF0A65D19346AF778ULL,
		0xEA574D557DAC7F0CULL,
		0x4C854F22D6E54A19ULL,
		0xEAC4BE7D0C02B37DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F2DBC8E5C5041F2ULL,
		0x63A286E0D93197BEULL,
		0xB6E74E2825B8B110ULL,
		0xF1B52224A8754F7BULL,
		0x3B0D722BC89BF8C7ULL,
		0x88159BDA3ED575D4ULL,
		0xBFD370280CA21C75ULL,
		0x026DCD96C491B3EAULL
	}};
	sign = 0;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50DE0E5FE1B3E02BULL,
		0x47FDEB7D0A6FE19DULL,
		0x36B004669C352F2BULL,
		0x4773E0E364F0D6C5ULL,
		0xA89F570D2EBA0CE3ULL,
		0xEE3AA4C907085443ULL,
		0xEE772A504BFC3930ULL,
		0x8C4C2311A20879C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB88151470C897E97ULL,
		0x303064078FBCD237ULL,
		0x52A59BBB25F47844ULL,
		0xB25250E34A106B2BULL,
		0x3B2E8C43FCBEFC35ULL,
		0x1B15CF9BED5515F1ULL,
		0xF809707F0904970AULL,
		0x837D640377E8210EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x985CBD18D52A6194ULL,
		0x17CD87757AB30F65ULL,
		0xE40A68AB7640B6E7ULL,
		0x952190001AE06B99ULL,
		0x6D70CAC931FB10ADULL,
		0xD324D52D19B33E52ULL,
		0xF66DB9D142F7A226ULL,
		0x08CEBF0E2A2058B4ULL
	}};
	sign = 0;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8992F58208B787DULL,
		0x5838AB5FEDF390C8ULL,
		0x2F0D5D4E63E36B98ULL,
		0xCB90CBB52F5E9C70ULL,
		0x098026919CDF9AA8ULL,
		0x4FC839D7497B7440ULL,
		0xD845FBEEC9477914ULL,
		0x0CA14FAA82E7CDD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81FF8F33247F25F1ULL,
		0xCE9B92B702211095ULL,
		0x64D01843E967E125ULL,
		0xC4858766C5585C76ULL,
		0xDD9A87E4768B7125ULL,
		0x89E44FC54777E55CULL,
		0x03CC3F4116260454ULL,
		0x447350EB4BEEED71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6699A024FC0C528CULL,
		0x899D18A8EBD28033ULL,
		0xCA3D450A7A7B8A72ULL,
		0x070B444E6A063FF9ULL,
		0x2BE59EAD26542983ULL,
		0xC5E3EA1202038EE3ULL,
		0xD479BCADB32174BFULL,
		0xC82DFEBF36F8E067ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF1C7C22A3C13C95ULL,
		0x853DAEFB194D1E50ULL,
		0x2BD254BF859ABDC0ULL,
		0xAB6CD8D3634A5E8EULL,
		0x55D527661139A21BULL,
		0xB1C6929231055FB2ULL,
		0x4C1EC2609111EFE1ULL,
		0xE1E64AE04D0CE666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC196ABFB1BB2E5DULL,
		0x77E50A6A06D36D86ULL,
		0x0251028D9723DECEULL,
		0x9F0AAD89E6D3F0FAULL,
		0x276E5783C58297D5ULL,
		0xFD57E0A96BFF08F7ULL,
		0x5104AD88CB79CAE0ULL,
		0x264F82F21CFD9820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3031162F2060E38ULL,
		0x0D58A4911279B0C9ULL,
		0x29815231EE76DEF2ULL,
		0x0C622B497C766D94ULL,
		0x2E66CFE24BB70A46ULL,
		0xB46EB1E8C50656BBULL,
		0xFB1A14D7C5982500ULL,
		0xBB96C7EE300F4E45ULL
	}};
	sign = 0;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x688EFF6C1515AE62ULL,
		0xC7AAEDEB692848F4ULL,
		0x8836EE6FF2CFDAA0ULL,
		0xF29E219D2EE34C54ULL,
		0x309CBDCB6A5FDF06ULL,
		0x025206F2860A0756ULL,
		0xBC52A9F5A4E499CDULL,
		0x3823BDD95619A48BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE516F1C5160F66D5ULL,
		0x3BBADBE2C494D2EDULL,
		0x5323F37EC6DEA33EULL,
		0x93D769752834CB24ULL,
		0x748EEBA1B5AC20E1ULL,
		0x19114F1DB8838B82ULL,
		0x07085429BC3ECF68ULL,
		0xF134CF0D1070C109ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83780DA6FF06478DULL,
		0x8BF01208A4937606ULL,
		0x3512FAF12BF13762ULL,
		0x5EC6B82806AE8130ULL,
		0xBC0DD229B4B3BE25ULL,
		0xE940B7D4CD867BD3ULL,
		0xB54A55CBE8A5CA64ULL,
		0x46EEEECC45A8E382ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x237E47ADBD49520CULL,
		0xA27A11733FD41C4BULL,
		0x2DE2DCAF61FB65D4ULL,
		0xB8D00D7ABB027616ULL,
		0x1CD213358985565CULL,
		0xC8F4416BB841A209ULL,
		0x392A517301E7B29CULL,
		0xEA9DC020CC4FE144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82163C90D6921B50ULL,
		0x657C872CA85EB17FULL,
		0xE034000A57F7F7BEULL,
		0x24F70C51D59F973CULL,
		0xC7CC49ACBD73BDA6ULL,
		0xA0DBE4D7E47212DEULL,
		0x92D5811BDA3D4236ULL,
		0xD9DCFE1DDB0C87A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1680B1CE6B736BCULL,
		0x3CFD8A4697756ACBULL,
		0x4DAEDCA50A036E16ULL,
		0x93D90128E562DED9ULL,
		0x5505C988CC1198B6ULL,
		0x28185C93D3CF8F2AULL,
		0xA654D05727AA7066ULL,
		0x10C0C202F14359A1ULL
	}};
	sign = 0;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4319C98253CD88C3ULL,
		0x080521C35156F42CULL,
		0xD5905335EB1F8B10ULL,
		0xE42D7B6103F11C0EULL,
		0x84ED167C46B5237BULL,
		0x9B1F50DE1AA5EE67ULL,
		0xD298D7951339AEF8ULL,
		0xEB513F9F69C81B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E89B4F97645306ULL,
		0x8F0A379A3F33F87DULL,
		0x9A12878EC7A52B16ULL,
		0x5E6E76AB3BA4B328ULL,
		0x03071DA5C43477CAULL,
		0x5297036FD2A90C5EULL,
		0xB50971CB8BA0229CULL,
		0x3817A1FE77FCFF11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD312E32BC6935BDULL,
		0x78FAEA291222FBAEULL,
		0x3B7DCBA7237A5FF9ULL,
		0x85BF04B5C84C68E6ULL,
		0x81E5F8D68280ABB1ULL,
		0x48884D6E47FCE209ULL,
		0x1D8F65C987998C5CULL,
		0xB3399DA0F1CB1C18ULL
	}};
	sign = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF85504A8E212C8CCULL,
		0xDEE689EA71DD7E3EULL,
		0xEEB1F28CAE8F0029ULL,
		0x3242B721D5D705F6ULL,
		0x3792D31B662B802FULL,
		0x3A240CB4F94F299FULL,
		0xE97343F7D60872CBULL,
		0x96BF5C2BE3B1ABE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F3E4CCB143DB71CULL,
		0xB1BA768543958070ULL,
		0x27E306865B585523ULL,
		0x2B106CED9B75566EULL,
		0x58463EBF9FBCEC4EULL,
		0x1767BA94623A0289ULL,
		0xD8E9EB133E5772E4ULL,
		0xA2606ED02B33C652ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9916B7DDCDD511B0ULL,
		0x2D2C13652E47FDCEULL,
		0xC6CEEC065336AB06ULL,
		0x07324A343A61AF88ULL,
		0xDF4C945BC66E93E1ULL,
		0x22BC522097152715ULL,
		0x108958E497B0FFE7ULL,
		0xF45EED5BB87DE593ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FF394540010F9D4ULL,
		0x3EB1CDFA6520F1B5ULL,
		0xC4244AD0C0F0BF18ULL,
		0x50C481F09D41893CULL,
		0x9672AED72B2F8D7DULL,
		0xED71038F6C3114D7ULL,
		0xA5926A21592EDA12ULL,
		0x9EBD496F4C007F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C8BC08033D6054EULL,
		0x26F83A345E8F6452ULL,
		0x6CAA23EFC187522EULL,
		0x3C88A983AD4F2DC7ULL,
		0xC1CB15DCD9CC68EEULL,
		0x3AF6B2900D36457DULL,
		0x1BA14D3272179C9AULL,
		0x273964D807C3020DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4367D3D3CC3AF486ULL,
		0x17B993C606918D63ULL,
		0x577A26E0FF696CEAULL,
		0x143BD86CEFF25B75ULL,
		0xD4A798FA5163248FULL,
		0xB27A50FF5EFACF59ULL,
		0x89F11CEEE7173D78ULL,
		0x7783E497443D7D66ULL
	}};
	sign = 0;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39D4C288CA703C01ULL,
		0x193639CD1BD5E7CCULL,
		0x1D08791D2FE149D3ULL,
		0x011B80EECBE0A9B9ULL,
		0x5C15FB03FF1DB975ULL,
		0xC7A39C16B9592E6BULL,
		0xAB85B4BA2E3A1F82ULL,
		0x53617538C90C7F24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46F6B9240DC704FULL,
		0xA81AF5BB78FE9324ULL,
		0x1D2A5A1D74154D79ULL,
		0x9B87E859B46D07D3ULL,
		0xFCA4FC3605B059DAULL,
		0xFFA2E12AAD4FBE63ULL,
		0x86F3138D27243FD1ULL,
		0xD9AFF5424A901444ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x856556F68993CBB2ULL,
		0x711B4411A2D754A7ULL,
		0xFFDE1EFFBBCBFC59ULL,
		0x659398951773A1E5ULL,
		0x5F70FECDF96D5F9AULL,
		0xC800BAEC0C097007ULL,
		0x2492A12D0715DFB0ULL,
		0x79B17FF67E7C6AE0ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4481AFFE55C28BFEULL,
		0x0DECB94249C55130ULL,
		0x250AE492FE07BCE7ULL,
		0x2BBC96845C3E96DBULL,
		0x7ACF8C40E33CBAF1ULL,
		0x727ACC565DF96C6AULL,
		0x674A41CFC9E63ABFULL,
		0x33C6E7A32C9A65ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF66033B75333615ULL,
		0xB7FFA7E6B23FF0BAULL,
		0x9F45C12E70B860E9ULL,
		0xAF22F8B21A13CB6BULL,
		0x64A79417DCAAA9F2ULL,
		0xCF997C6E3980A645ULL,
		0xA11FA8EF76F70EB1ULL,
		0x9A68B29D0555FCD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x651BACC2E08F55E9ULL,
		0x55ED115B97856075ULL,
		0x85C523648D4F5BFDULL,
		0x7C999DD2422ACB6FULL,
		0x1627F829069210FEULL,
		0xA2E14FE82478C625ULL,
		0xC62A98E052EF2C0DULL,
		0x995E3506274468D7ULL
	}};
	printf("Underflow\n");
	sign = 1;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDE833376205FD91EULL,
		0x9709CE3DE3AEFA9EULL,
		0xE063F7A22DB58649ULL,
		0x5C8A97C611FFE7DEULL,
		0x0CCD3F071B96A21DULL,
		0x34CA6D1EB8444F1CULL,
		0x12627CD63FCDF84DULL,
		0xB2F9626252E17813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4B902351860D94ULL,
		0x19872CC7279C36EFULL,
		0xE37FD07812E7B634ULL,
		0xE9F8A0EB85D52251ULL,
		0x444047ECC7A8857EULL,
		0xF1567EEB9BB1EE23ULL,
		0x5303129CB2B55F1EULL,
		0x1D2E2AF416F8D00CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1137A352CED9CB8AULL,
		0x7D82A176BC12C3AFULL,
		0xFCE4272A1ACDD015ULL,
		0x7291F6DA8C2AC58CULL,
		0xC88CF71A53EE1C9EULL,
		0x4373EE331C9260F8ULL,
		0xBF5F6A398D18992EULL,
		0x95CB376E3BE8A806ULL
	}};
	sign = 0;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCEEC333F05E4D7E9ULL,
		0x214A649B4F2958B8ULL,
		0x938FCA6F32442058ULL,
		0x8896C35CAA056087ULL,
		0xD57BF0404A596462ULL,
		0xD60C67DF942D225CULL,
		0x5D15D7EEFA163959ULL,
		0xDB7ED4FD6AAAD7F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3051318460AE4FULL,
		0x39561A43E807D728ULL,
		0x7A7700521EC085E6ULL,
		0xAA26D5B04F944766ULL,
		0x12203067AD61A1DDULL,
		0x44ABC64B03FAEBDDULL,
		0x070083C80E18F1F3ULL,
		0x41335AA2CA0694BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7FBBE20D8184299AULL,
		0xE7F44A5767218190ULL,
		0x1918CA1D13839A71ULL,
		0xDE6FEDAC5A711921ULL,
		0xC35BBFD89CF7C284ULL,
		0x9160A1949032367FULL,
		0x56155426EBFD4766ULL,
		0x9A4B7A5AA0A44338ULL
	}};
	sign = 0;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1825AA3DE1CA3F5ULL,
		0xC2409A6F068F3421ULL,
		0x08A25B6A1B9FFD84ULL,
		0xEFC98ADFFA7BF0C1ULL,
		0xB59764469C8FC34CULL,
		0x24ECCD880CF52C07ULL,
		0x6D814A6E7FD95781ULL,
		0x9A9AEB8C3F2DDA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46A4F024A4A447F0ULL,
		0xAFFED71A370FCF8FULL,
		0x083E3A4E76B3DFDBULL,
		0xF6285E5CBA004432ULL,
		0x6ACD934E9A67C029ULL,
		0x2795CF12B159C644ULL,
		0xBB96A292E8BE1BC7ULL,
		0x73FDC0710E27CB01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7ADD6A7F39785C05ULL,
		0x1241C354CF7F6492ULL,
		0x0064211BA4EC1DA9ULL,
		0xF9A12C83407BAC8FULL,
		0x4AC9D0F802280322ULL,
		0xFD56FE755B9B65C3ULL,
		0xB1EAA7DB971B3BB9ULL,
		0x269D2B1B31060F48ULL
	}};
	sign = 0;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	borrow = curve25519_key_sub(&k1, &k2, &r);
	res = curve25519_key_cmp(&r.key, &k3);
	printf("Result:\n");
	curve25519_key_printf(&r.key, COMPLETE);
	if (res && ((sign && borrow) || (!sign && !borrow))) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}