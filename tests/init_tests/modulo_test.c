#include "../tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA3CE2B56818E57DBULL,
		0x1D1C17401E74F326ULL,
		0xD850FEA48E82C905ULL,
		0x334CC3BA527F7AFAULL,
		0xD846FFB19B0303D2ULL,
		0xADB1D21799B3887DULL,
		0x7C8EC2A888183BE3ULL,
		0x73A7236C278A736CULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBE581FB38400EB8DULL,
		0xE58146C0EF1B35D4ULL,
		0x5581E3A8C21BACD0ULL,
		0x5E1C05C8310C9D15ULL,
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
	compute_modulo_25519(&k1);
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
		0x318F8C59584D5BFCULL,
		0x09315B893ABA3D2CULL,
		0xA35FDFDEA0458437ULL,
		0xBFDF07609F68A4CFULL,
		0x80BCA4EA4ECC4AD8ULL,
		0x1C42B47B19230D8DULL,
		0xA32338C05013E118ULL,
		0xF0B1259E94F8A9B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9007210AA07D64ULL,
		0x3B1825CEF5EE402DULL,
		0xDA9A4C6A8338EDCBULL,
		0x7A2A9CEABC51D507ULL,
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
	compute_modulo_25519(&k1);
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
		0x68A2F52877CCB817ULL,
		0x2EBEA81785429F8FULL,
		0x6F380C1A42C4436CULL,
		0xA9E718C14AAE2498ULL,
		0xB62D91AFBCFDFB0CULL,
		0x4262140F0E7483F5ULL,
		0xC6DC626E3BF8A15CULL,
		0xF5E77C737F682733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7366953E8580015DULL,
		0x094DA253AA8E3608ULL,
		0xF3EEA87729AC371EULL,
		0x2A4391E63423F647ULL,
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
	compute_modulo_25519(&k1);
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
		0xB1A680FC83637A83ULL,
		0x5CECF507EFA43926ULL,
		0x5C508746614D8054ULL,
		0xAC4BC4D0E42650F6ULL,
		0x1B7C6F549F080351ULL,
		0xDC370F6D53CB81E5ULL,
		0x8FDEE4B80B2E193CULL,
		0x647964FCC8C4F52CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC61F078C1E93FAD6ULL,
		0x0D193F425FD98128ULL,
		0xB7667A980A253F5DULL,
		0x1650C256B162B593ULL,
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
	compute_modulo_25519(&k1);
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
		0xF7024D4E34B725EBULL,
		0x3A00E969C1F85E6BULL,
		0x23CBD69AEDF8116BULL,
		0xBA110F738A8022EEULL,
		0x968DD713417E3725ULL,
		0xBEFBF1668340D30EULL,
		0xDFF9BEA7A24C6736ULL,
		0x9B4D2DB19E077B6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50103A29ED7358E6ULL,
		0x9366BEA13D97B296ULL,
		0x62DE237D054F638BULL,
		0x4785D7D0FF9C7517ULL,
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
	compute_modulo_25519(&k1);
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
		0x183423B7223D282DULL,
		0x303441F0EE78EA9BULL,
		0xBB7536BF5E4FD348ULL,
		0x2FE7044CA5B8EA62ULL,
		0x8D29F579AB1C4451ULL,
		0x332FD614EE5E2544ULL,
		0x2B2AFD0FE631D5A8ULL,
		0xF1D7D2FC302C1EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C6E93C6886F518BULL,
		0xC94E090C507272C8ULL,
		0x23D6C71B89B58A3FULL,
		0x15F055BBCC457C19ULL,
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
	compute_modulo_25519(&k1);
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
		0xB84C5444653222D0ULL,
		0x4A53EFD2614E28C6ULL,
		0x7FFBEABD73741EF5ULL,
		0x84D47CABB6D3C76FULL,
		0xAA9ED30EDA43425CULL,
		0xABB31AF2CF728702ULL,
		0xE59059D022CE7717ULL,
		0xD84A2181EF7F78F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BDFA878CB2E014BULL,
		0xC6E9EFDD2C4E332CULL,
		0x93693FA29E19CC78ULL,
		0x1FD575F543BFBC3BULL,
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
	compute_modulo_25519(&k1);
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
		0x12D538AE29B7E28FULL,
		0x3663F1E39F2C54F7ULL,
		0x0E762F9368073506ULL,
		0xA497E48D07A03AF6ULL,
		0xD2E197C0EBD80F39ULL,
		0x70D2509E2E1FB5BCULL,
		0xE78FE047B9A0BB9DULL,
		0x37C5E3396DEE8CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6051BF512BCA2648ULL,
		0xF59BE95E77E14EFEULL,
		0x6DD17A38F5E30E64ULL,
		0x6BF79F135909221EULL,
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
	compute_modulo_25519(&k1);
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
		0x6315A7F389605D06ULL,
		0x9B28EEF01AACB778ULL,
		0x7662D79095552DD6ULL,
		0x3E5037135A32D8EDULL,
		0xF04CA79CE865DA65ULL,
		0xFD697C29A30BCFD1ULL,
		0xB40B5210712DDB77ULL,
		0x3D549420F00A38E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E76893E087EC95AULL,
		0x38D15D1E4E6D90A2ULL,
		0x301106016223C1A6ULL,
		0x58DE33F6FBB74ABAULL,
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
	compute_modulo_25519(&k1);
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
		0xCBC4F05DB854A124ULL,
		0x6713B61F262D9391ULL,
		0xBDDA84BA37220ACEULL,
		0xCACCE7D02449B46AULL,
		0xAA0EB26F0BA43742ULL,
		0x7462E6EE0EF3B9D2ULL,
		0xD2B101AF651615A8ULL,
		0x516E5E63892D79ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09F36CD972B4D6CBULL,
		0xADC1FD755E5B28D7ULL,
		0x0420C4C3386941CFULL,
		0x612EEA968109C438ULL,
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
	compute_modulo_25519(&k1);
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
		0x3D9E5BA7B894DFD1ULL,
		0x5D8A9D3D4C8D005BULL,
		0x24177CA56AD5ADFDULL,
		0x71EE37045560FC91ULL,
		0xE6AA5F0472E38D97ULL,
		0x0B90BE83E08A3DA1ULL,
		0x1F89E68BA3C04B92ULL,
		0x79381EA902BD005DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AE87650C65BE6E7ULL,
		0x1506E4D0A1122663ULL,
		0xD28FB55FB960E5ABULL,
		0x7042C41ABD6F0A63ULL,
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
	compute_modulo_25519(&k1);
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
		0x77430C3EBB062677ULL,
		0x247F4B7755F7FF6BULL,
		0x778FF96129849BB8ULL,
		0x0096C7A12CEBEA10ULL,
		0x30B51CE2717B4B73ULL,
		0x2B89E854073ABA11ULL,
		0x06DA9A1A98E1B484ULL,
		0x79AD9739E75EFB77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB22555DB93535C35ULL,
		0x9AF7C7F068AF9DF8ULL,
		0x7C02D953DB056756ULL,
		0x105B3A3985053DBBULL,
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
	compute_modulo_25519(&k1);
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
		0x8F9BBE6C26F06D0FULL,
		0xE0882966A92D78EDULL,
		0x8A31ED285ED8CD2CULL,
		0xA26D415801A8488FULL,
		0x584BB09B21914997ULL,
		0xF358CB6192231579ULL,
		0xE0FA6E7CE0BEE465ULL,
		0x5F1636E1E290CBCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAD7F57322815BA0ULL,
		0xFFB659E25A62A8F0ULL,
		0xEF5E53B1BB2EB44EULL,
		0x3FB966DFA326896AULL,
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
	compute_modulo_25519(&k1);
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
		0x86E5DC48C606C5E0ULL,
		0x6019A55551D44D08ULL,
		0x8911949DA2CCE1CDULL,
		0x5BEAD13771F61670ULL,
		0xDE2F3D21F720F2AAULL,
		0xD8B6FF789E687FDEULL,
		0x3CD5EBBF42D0E195ULL,
		0xEA51904B2DBAB474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E8EF5374EAD04EULL,
		0x8B43913CD557481DULL,
		0x90D293018DCE5E0BULL,
		0x24063C603BACDFB1ULL,
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
	compute_modulo_25519(&k1);
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
		0xD1E67D98BF009294ULL,
		0xEF40D387796A13FCULL,
		0xC85ACC4806E080FEULL,
		0xDBA50110A7E39C5FULL,
		0xF3156FDE4A14F9FFULL,
		0x5A1AC6F3D24FBEA4ULL,
		0xA5FE5DE07192BDC6ULL,
		0x02A6052F74A2BDC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7151897BE1DAE94ULL,
		0x4F3A5BB8B1406078ULL,
		0x6C1CBB98E2A8AC70ULL,
		0x4049C61BF80BC802ULL,
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
	compute_modulo_25519(&k1);
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
		0x1093DBC867CF592CULL,
		0x8BAEA31C40351144ULL,
		0xB280F4395D4FF403ULL,
		0xF247E70AEEC8239CULL,
		0x1EEEAA001DB4BC65ULL,
		0x8CA234FEB07E9085ULL,
		0x91A8CE1EE765A50CULL,
		0xB0A45ABE39A2B66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA80117CCD0A3542CULL,
		0x6BC280EA72FE8506ULL,
		0x518F8CCFB66673E0ULL,
		0x2AAD5F477CEF3806ULL,
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
	compute_modulo_25519(&k1);
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
		0x1CE771D16485C0B6ULL,
		0x8C1042B9047F8144ULL,
		0xB02B823AE0BBA41BULL,
		0xFD20A39F9283B80EULL,
		0x8F6B581CF0ED9C3CULL,
		0x0D261235A6F2272BULL,
		0xCCBBD43E8C440CACULL,
		0x605DC3A277425EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66D6861D27CAF3D8ULL,
		0x7FB6F6AFCC7151BBULL,
		0x140D0383B2D585A5ULL,
		0x4B0BADBD465DCFCDULL,
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
	compute_modulo_25519(&k1);
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
		0xDE150B6BE675A2C8ULL,
		0x9C651D5D01479751ULL,
		0x7B7A55723031944FULL,
		0x85FFE59D7F27ECCCULL,
		0x13D263759A5EB30EULL,
		0x00FDF7AA4680FCDAULL,
		0xDF4568A1696DC05EULL,
		0x4BE8E3F12A9D916BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4FCEE0D0843891ULL,
		0xC217E0A3786D1FB0ULL,
		0x9FC7DD67D67C2243ULL,
		0x4A91BB69D28B82CFULL,
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
	compute_modulo_25519(&k1);
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
		0x0CCBE406BFF44594ULL,
		0x7387C18A5BF1FAFFULL,
		0x70B35FA8913A1B72ULL,
		0x023682B2909EB33BULL,
		0x46FB4523CC29FAA5ULL,
		0x58C021DE19B4F076ULL,
		0x1FE8AE19EF3E7332ULL,
		0x02B79F64B1136133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x961827570E2F7A12ULL,
		0xA00CC8822CCDAC8DULL,
		0x2D3D3782147F34EBULL,
		0x69782BA4D97F20D2ULL,
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
	compute_modulo_25519(&k1);
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
		0x572E64ABD2912350ULL,
		0xB1DEF2CFA3826814ULL,
		0x56E93E866ED86697ULL,
		0x240FFE2B6A4A9900ULL,
		0x69C2F236045B2157ULL,
		0xC4CFF84EA7E1AF5BULL,
		0x36B8C358538A49F2ULL,
		0xF5593C2BF1D1ACD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A1E58B078181BA5ULL,
		0xE8BDCE7C8F026FA6ULL,
		0x76563DA2D55F60A0ULL,
		0x0F4EECB14F6A405AULL,
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
	compute_modulo_25519(&k1);
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
		0xBAEE85A64B3AA64CULL,
		0x1017F05A39C35BB5ULL,
		0x58EF9E0012E994F4ULL,
		0xBB6E8CCE516216D8ULL,
		0xFDD6A802E7136461ULL,
		0xC4214BDDBF1A316CULL,
		0x817B58E091ECD7A4ULL,
		0x5641D5BA33892BACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CB7614981B8EB3ULL,
		0x2D09334497A6B1E3ULL,
		0x913ECF55BC119769ULL,
		0x09344671F7BE9273ULL,
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
	compute_modulo_25519(&k1);
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
		0x774D31CE509CC6DBULL,
		0xAD0AEB60ADC0EA7EULL,
		0xC631AC759DDDEBF8ULL,
		0x4BCA5C3E4FDADB5DULL,
		0x1B6B3D80E3B710B3ULL,
		0xD28CEB69B67AE6EDULL,
		0xBBAD5FE163ACC6B3ULL,
		0x47CB90920A4436EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x893852F01DC942FCULL,
		0xEDF5DD11C3FF31B0ULL,
		0xA1EDE7EA69836AA9ULL,
		0x7401D1EBD5FB02CDULL,
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
	compute_modulo_25519(&k1);
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
		0xDE6263025429383BULL,
		0x9DFC7489C384A702ULL,
		0xECC5A69E665D4D93ULL,
		0xA0C01F2979001049ULL,
		0x56D8391696F6BA70ULL,
		0x9AE978FECA526BFBULL,
		0x043C8EC06E29E3AFULL,
		0x691F0DEA44B956D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC27ADC5CBCC8E73BULL,
		0x9CA46A5BCBC0AE51ULL,
		0x8DC2D72EC09519A4ULL,
		0x3B5C2FEFAC82F32AULL,
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
	compute_modulo_25519(&k1);
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
		0xEEBD788C3E74471DULL,
		0x55CABE063F4639F1ULL,
		0x7B287D2AAF8EACC9ULL,
		0x0351CAC0C3E392E4ULL,
		0x374AB7BD367BAFF0ULL,
		0xECE569311A362A11ULL,
		0x2B494FADD5DC452CULL,
		0x0EED0C16CFE32B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23D4BEA254D06509ULL,
		0x7FD85B5023507880ULL,
		0xE80A50F86E40F174ULL,
		0x3A8196239F9BF9AAULL,
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
	compute_modulo_25519(&k1);
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
		0x8B4B77D5B680FDF2ULL,
		0xC7C776D8BBB50047ULL,
		0x30A1188DF4E3DA83ULL,
		0x7AA313780556B61FULL,
		0xEFBB2EF583DDBA6BULL,
		0xBB05A97B44DD87E5ULL,
		0x9E6E0A21F627662AULL,
		0x7D641F8AE9E39C5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21147047496AACA6ULL,
		0x8A9E9F24F4972C69ULL,
		0xB4F699987EBD04DBULL,
		0x177FC216BD1FEBB8ULL,
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
	compute_modulo_25519(&k1);
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
		0x88C0D6130EB542AEULL,
		0xC4C4F863B4F7DCDEULL,
		0x54DD394085E7718AULL,
		0x449A09BCD6C497DDULL,
		0xBC12054342F2FCEAULL,
		0x9BEACF95B87BCFF7ULL,
		0x951C5C86F10BCA9CULL,
		0x78E465B9F6FB4634ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736D9E0EFEC6D016ULL,
		0xE99FC89D1758BBA4ULL,
		0x7712F5484DA784C9ULL,
		0x36812357801103ABULL,
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
	compute_modulo_25519(&k1);
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
		0x5A7091B29BD39C27ULL,
		0x0F88978020A41E40ULL,
		0x04311F4957F4AA0BULL,
		0x03259AFA32DC4F69ULL,
		0x346CD08FD0A160E4ULL,
		0x533B784EF145AEF6ULL,
		0xFA91419356121F15ULL,
		0x5EDC2C1CD842A29DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2297870B93C80013ULL,
		0x6A5C7337F0FC16CCULL,
		0x35C0DB281EA54735ULL,
		0x17D427424CC072DCULL,
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
	compute_modulo_25519(&k1);
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
		0xF228DEFF68211262ULL,
		0x235571759CE63528ULL,
		0x64E5FE4058EFB29AULL,
		0x4D9CFFA7244F3ED9ULL,
		0xD44A176A4740AC0CULL,
		0x843A68EBE2A31DD0ULL,
		0xCFA55BA8A87A8DF2ULL,
		0xBAB54601B02245B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x752858C5FBBAA052ULL,
		0xC4010479411CA228ULL,
		0x377199495B20C499ULL,
		0x048563E749659848ULL,
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
	compute_modulo_25519(&k1);
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
		0xA1E7CDCFB915723CULL,
		0xB4C3A7FCABD708F2ULL,
		0xA17DB1CB237F4889ULL,
		0x2FB473409DE464C2ULL,
		0x6345000A8E062607ULL,
		0xCC0EA176C54BC76EULL,
		0xF52DC4D4A7285213ULL,
		0xE9715D8D8AA5BFB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E25CF60CDFF1C65ULL,
		0xFEEF9F9DF516A355ULL,
		0x0648E95BF37B7779ULL,
		0x56885643327ED953ULL,
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
	compute_modulo_25519(&k1);
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
		0x56AA3AA87E27107AULL,
		0x3383C5EE9267780EULL,
		0x7162CA4DDB0BD8FFULL,
		0xB516A0456C44A061ULL,
		0x354AD490AD23DA4AULL,
		0x267CFCDAC17CDCF8ULL,
		0x87ED97E2419E522BULL,
		0x6C265A07B765CEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FC5C822317979E9ULL,
		0xEA114E674AF044E6ULL,
		0x9EA755E3988C0B66ULL,
		0x42C7FD6AA5614EE1ULL,
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
	compute_modulo_25519(&k1);
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
		0x95F84C46F58F4D0EULL,
		0x4C65808E6311800DULL,
		0x4DCA76DB7C68EB47ULL,
		0x35B62DE730259265ULL,
		0x39EBA67A391C7352ULL,
		0x2F0ED901D9028C7BULL,
		0xB3CBCA6A99587CC2ULL,
		0x85C57FBACBCD4552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EF3026B6FC86E32ULL,
		0x4899B6D499725A58ULL,
		0xFE0A82AE3F8B701AULL,
		0x110723A1709DDCABULL,
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
	compute_modulo_25519(&k1);
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
		0x79C768FA703B9F2BULL,
		0x4E93EEACAF94D7E9ULL,
		0xA0ACF637003A0919ULL,
		0x5A642C3F666FD584ULL,
		0x7AED82FA0B250A32ULL,
		0x7C9E483245996424ULL,
		0x6A716F4FADFB5E1DULL,
		0xD87A0F3B2DD7A4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB908DA1817BB2757ULL,
		0xCE12A6230459B553ULL,
		0x6D837C0AD38A0179ULL,
		0x7C826F0834724C4EULL,
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
	compute_modulo_25519(&k1);
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
		0x0ADEA3982F063197ULL,
		0xBE1BBCF17911099FULL,
		0xCD2B88B962CA1C7DULL,
		0xC5A7EA1ED2588E70ULL,
		0xB4885A110968EF3BULL,
		0xB678AC262BAA9953ULL,
		0xE1FC0AF307D8DA04ULL,
		0xCBD7BE26480ADD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71C021F9499B8F3ULL,
		0xD4054A9BF463CC0BULL,
		0x589528CC8CFA7930ULL,
		0x07AE23CD83F56FB8ULL,
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
	compute_modulo_25519(&k1);
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
		0x60A42B9E3F632BB7ULL,
		0x40D51D69463E9CB2ULL,
		0xF188675D5B1EF369ULL,
		0xAF51607D1C270C20ULL,
		0x8A91637B1697E7BCULL,
		0x092F682B460909D1ULL,
		0x256D791132DCE359ULL,
		0x89482061471FCB9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF238EFE399EF94BDULL,
		0x9DDE93D5AB9611CCULL,
		0x7FC85FEAE7E8B2A0ULL,
		0x10062EEDAADF459AULL,
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
	compute_modulo_25519(&k1);
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
		0xFAD67BB2244B35B8ULL,
		0x6410E060A6B99353ULL,
		0x163B33E7A2E9CD2BULL,
		0x5FCF59070D0B415BULL,
		0x717246EAF35566DFULL,
		0xF2D7BEBF0AB9641FULL,
		0x2FA446E2E882FB56ULL,
		0xAD6D2E14BF88D821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1CD029242F87EAEULL,
		0x701730BC3E3E6FFEULL,
		0x289DB996265B1C13ULL,
		0x1E04301B7B5B5648ULL,
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
	compute_modulo_25519(&k1);
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
		0xA5460037507F77E1ULL,
		0x86EFAC2311E742F1ULL,
		0xB5E7298283927E19ULL,
		0x72EBA362AAA452CFULL,
		0x4AF69EC8431EDB53ULL,
		0xB647E3D09E1BEE2BULL,
		0x4F9F0F10988AE4F5ULL,
		0xA81F351B8D987FFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E191F1471409E9ULL,
		0x959B7D1A8A0C9D5EULL,
		0x878365F928307A92ULL,
		0x678D8579AF475269ULL,
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
	compute_modulo_25519(&k1);
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
		0x92B98A8DF09FF306ULL,
		0xC7D5D948BABCC413ULL,
		0x0F150129E62B6E26ULL,
		0x32E026BD44B04123ULL,
		0x2BEAC8324A53A8D2ULL,
		0xEC377BB1D211A20AULL,
		0x25DF40AD53D91953ULL,
		0xA979D659BA4C41DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17934204F90B05E8ULL,
		0xD81235ADE95AD196ULL,
		0xAE389AE45865309BULL,
		0x5AF5F80EEC020784ULL,
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
	compute_modulo_25519(&k1);
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
		0x1F33E13D50EC14BEULL,
		0xBA5A42F611888F09ULL,
		0x82331E8141A81FE1ULL,
		0x6AC8C58ED559DEA1ULL,
		0x1655CF0073C086E6ULL,
		0xB0338E9B095F9FA0ULL,
		0x2CF4ADD8D2233E28ULL,
		0xE8B88A5DD39B3777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF09B4E7F802001ULL,
		0xE2016DF975BA40CCULL,
		0x2E84ECB072E359EBULL,
		0x762D4F7C3E641A52ULL,
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
	compute_modulo_25519(&k1);
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
		0x674F8F2B37DDB31FULL,
		0x620DE6914733BE7EULL,
		0xA72720E31A077D8AULL,
		0xBD13430EE0E74E4EULL,
		0x82ECA526F6811172ULL,
		0xE1F34C48296D924FULL,
		0x91D5EF2612D0BA2EULL,
		0x24DBD0003C53729AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67012F3CF064AEFULL,
		0xEC2B39476D77764BULL,
		0x4CE8A089E503207FULL,
		0x35B42317D54A5140ULL,
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
	compute_modulo_25519(&k1);
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
		0x421A1571D0B7844CULL,
		0x78F8F6660C2CFF52ULL,
		0x63DCB22F4B717BEEULL,
		0x62AA9E500ED7005AULL,
		0x95AB744E30EBF9D4ULL,
		0x43427C7D642C81ECULL,
		0x675DE4F95918C74DULL,
		0xE45630FC220DEA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x798D590D13BE9ED0ULL,
		0x74D77102EAC84870ULL,
		0xBBCCAF32851F1166ULL,
		0x4775E3BD1CE7C233ULL,
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
	compute_modulo_25519(&k1);
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
		0x69C1CDF24F37A691ULL,
		0x959A40266DD0481FULL,
		0x5B2D2468E3772437ULL,
		0x654F2799DC8032C9ULL,
		0xBD716D691F6E4ABCULL,
		0x051DEA05FCF4847BULL,
		0x07FD21D622755D0DULL,
		0xC8ED13581C158BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88980B8CF996C2EDULL,
		0x580AFD09FA1BF27DULL,
		0x8AC02A3200E2F426ULL,
		0x388006AE07B2F572ULL,
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
	compute_modulo_25519(&k1);
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
		0x5E24C9AB09ED9F85ULL,
		0x8FE18275CD80E05EULL,
		0x8EF2D33D851E6891ULL,
		0xC7FD5387FD12F3B8ULL,
		0x07CABB454B47F7F3ULL,
		0x8971759890DF1A35ULL,
		0x5F353681B387A67CULL,
		0x1B92EDACE4864588ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863C95F4369C6E42ULL,
		0xF6B8F71B4E9EC43DULL,
		0xB0D8EA7E2B411F0DULL,
		0x5FCC9B31E90145F6ULL,
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
	compute_modulo_25519(&k1);
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
		0x9F915EF3F766D3DBULL,
		0xA35F4C24E469F8E1ULL,
		0x46A48FD82D34671BULL,
		0x34975BFA6BB3C208ULL,
		0x82FCCC4F13B1E97DULL,
		0x8DE9A38E3FBA263AULL,
		0x830CD0314A43182CULL,
		0xAD88F558B7CFACBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1117B2B0E3CF8032ULL,
		0xB40D93425A0BA591ULL,
		0xBA8B77293329FDB8ULL,
		0x76EBC725B487664FULL,
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
	compute_modulo_25519(&k1);
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
		0x5DC14D68FFDA0AE7ULL,
		0x6B5BF026D76179BDULL,
		0x9E666AA989FDFA49ULL,
		0x73EF68B25EEE138EULL,
		0x18A1B13709BFD46BULL,
		0x0C3E9C9F8E7AA0BBULL,
		0x3953808C5C17AB62ULL,
		0x7767320DD7981D92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C19B9472539575ULL,
		0x3CA72FD5FD955583ULL,
		0x20CB7F7F35816AD7ULL,
		0x2D40D6C05F827743ULL,
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
	compute_modulo_25519(&k1);
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
		0xA078C2B78D143E48ULL,
		0xB8E37DB1A394C71CULL,
		0x86F499F25008E98BULL,
		0xA581CFF63B3957C3ULL,
		0x89E4A7BC61AD6F52ULL,
		0x6BA84DA459611B34ULL,
		0xDC7C948548EF9099ULL,
		0xD77617870E7F2659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1869A8AE0CD2C947ULL,
		0xB3DF0416E7FED0E9ULL,
		0x4172A5BB23986051ULL,
		0x21094E026219091AULL,
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
	compute_modulo_25519(&k1);
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
		0x4E50AC76D73D0EF5ULL,
		0x651E463F8317D12DULL,
		0xA22B352BA2DAD45CULL,
		0x7EB29DDD830943CCULL,
		0x400BB3F264EE26FAULL,
		0x9A7EADFF827887B7ULL,
		0xA82163977A9F4AF5ULL,
		0x3FEAB668CCC8FE67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD00D6271D296D97AULL,
		0x53EC1A2CE0FBF660ULL,
		0x971FFDA7D67FF4D1ULL,
		0x7B89B16BE8DF072FULL,
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
	compute_modulo_25519(&k1);
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
		0x5A54CDB184D23B63ULL,
		0xF3DEF0E2FB32105DULL,
		0xA811B099142EB3A3ULL,
		0x48D888978BD23F57ULL,
		0x48A95B11AFE0C8FEULL,
		0x6BBDE03455BB1585ULL,
		0x7B8DAE0F21CCFA92ULL,
		0x673FA81242078314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23785251A0301364ULL,
		0xF20E38A7B4F74226ULL,
		0xFF1986D8189BE55FULL,
		0x1C4B7B4D58EFB461ULL,
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
	compute_modulo_25519(&k1);
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
		0xF610FE2EC08E45FDULL,
		0x71A3BC86AEA21AAFULL,
		0xF485EF6C1F2F5178ULL,
		0x1586D8B8509E04F8ULL,
		0x4BD95BDF28ED5D03ULL,
		0x58345A8ABBA9B83AULL,
		0x62AC1AC815DD6AE8ULL,
		0x205F1968532D9B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3854A14ED3CA151AULL,
		0x89692D1E89D37357ULL,
		0x9A11E91F5E0D2FF5ULL,
		0x63A49E34A9630A97ULL,
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
	compute_modulo_25519(&k1);
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
		0x69F8DCE3168E3DBFULL,
		0x1F1B796FB69879F1ULL,
		0x00B3386D3C3FBBA7ULL,
		0xDB5381502E16E090ULL,
		0x9A91A00ADCAF7434ULL,
		0xE0EAA84FA8AEB1EDULL,
		0xE4448BD388ED5785ULL,
		0xE95A2B931DF6AC6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B969E7FD89982A9ULL,
		0x81F07542C086E336ULL,
		0xE2DFF9D38F7AB986ULL,
		0x7EB5F926A0B47893ULL,
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
	compute_modulo_25519(&k1);
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
		0xF5CA1F0DC65CB3B5ULL,
		0xE9AA07798B5F5777ULL,
		0x0F4561FD247227E3ULL,
		0x4B1AED6C33583C78ULL,
		0xA801106731C4C714ULL,
		0x0E397462F258E4BDULL,
		0xBAAE8EB60A85D369ULL,
		0x11FEEF7352B2C35EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F28E5F2992410CULL,
		0x06314E2984914B9EULL,
		0xC52E9102B44F897CULL,
		0x76F2788A79E13C87ULL,
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
	compute_modulo_25519(&k1);
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
		0xE994967599CFCBF3ULL,
		0x9C59F49BC8274168ULL,
		0xFBAEB90BDC219EA3ULL,
		0x79178B3F9C801816ULL,
		0x0B758FB48926B902ULL,
		0x81367E5597FE0668ULL,
		0xB036F3D3748B2E75ULL,
		0xA24ACEE746101458ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D07EB41F58F45E2ULL,
		0xCA70B55057DC34DAULL,
		0x23D6EA6F28CA8414ULL,
		0x1032419402E31D41ULL,
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
	compute_modulo_25519(&k1);
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
		0x93241E1AD2C0D32FULL,
		0x175999D77534B8E8ULL,
		0x62F87BAEB920466BULL,
		0x3D14FCF759169E04ULL,
		0xEAE415F61F013F80ULL,
		0xA4FA18C455A62907ULL,
		0x37E04433D4671164ULL,
		0xDE17AA1C3439F60BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FF60A36CF04515ULL,
		0x947946FC2BDED015ULL,
		0xAE429B60406CDB5BULL,
		0x34983D2719B123AEULL,
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
	compute_modulo_25519(&k1);
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
		0xAAE1AD9E5998123BULL,
		0x4DC494A63FC215EAULL,
		0x90CC7A8EB2CB7566ULL,
		0xE47AA86D8AFE3B42ULL,
		0xE6C072E599CA828DULL,
		0x3FC933F0AFE75659ULL,
		0xABC97CA240C64769ULL,
		0x56E075C1D29C803CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB72BBB32DA7752AULL,
		0xC5A24A605C18E742ULL,
		0x10B4FAA4503A0F05ULL,
		0x49CC2332CE394444ULL,
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
	compute_modulo_25519(&k1);
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
		0x1B82C1744794A606ULL,
		0x55316147AE836634ULL,
		0x898B9861A0C04768ULL,
		0x219A9D20670E3627ULL,
		0x0B983C9B108DB6FFULL,
		0x486D0AED699D1CAEULL,
		0x49B4C33DE33E832DULL,
		0x4C9DA2CA8D77F9FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41BC078BC9DD195ULL,
		0x156100855BD5A809ULL,
		0x7A6093915C07C021ULL,
		0x0100C73166DD514EULL,
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
	compute_modulo_25519(&k1);
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
		0x9098E32F83974B3DULL,
		0x7EBBDA131A4C1241ULL,
		0x08FF54C30A086845ULL,
		0x3810DA23DD6FFB16ULL,
		0x75FEB712FF9C1759ULL,
		0xE4DBAF7B257C9CB7ULL,
		0x115137D8DC0DC845ULL,
		0x4AFF3B6D5432C0C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1468100174C2C415ULL,
		0x7757E65AAACB557DULL,
		0x9B0D9EF3B41422A5ULL,
		0x59F3AC5E5CF89856ULL,
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
	compute_modulo_25519(&k1);
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
		0x82D65881592EB516ULL,
		0xFC0741A563D8440BULL,
		0x901210EDF708EDB1ULL,
		0x2611B19152A93BC5ULL,
		0xED8CF514C233D927ULL,
		0x204AB7AEEBE30D3EULL,
		0x77719F071D230A77ULL,
		0x4215F7BB0D48F40CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C2B9962CE0F249ULL,
		0xC71E859C678C3B62ULL,
		0x4AEFABFC4A3C7B60ULL,
		0x755477554B7D759FULL,
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
	compute_modulo_25519(&k1);
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
		0x2D1A2926A14CAEE8ULL,
		0xA0043AE2C7AB5680ULL,
		0xDACCBAC3AC10CB8CULL,
		0x7C08A891B8689018ULL,
		0xC61216140D6A3BE2ULL,
		0x5DBBE3F4B56B1046ULL,
		0x57EF80C9C3482F9AULL,
		0x6C24C988417588ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C970209F1194E7ULL,
		0x89E81135B58FC101ULL,
		0xE859D8B6A8C7DC76ULL,
		0x097E92CB6FDAE32DULL,
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
	compute_modulo_25519(&k1);
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
		0x2DCA89B7D14BAF73ULL,
		0xE55F8B916DA15327ULL,
		0x7D8B5D89BFA6607AULL,
		0xF52D9D23142A566CULL,
		0x70C7928050392379ULL,
		0x4F0029B37AF60883ULL,
		0x2B345293B61796ABULL,
		0x31F593A94870C761ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB6A48C3B9C6F499ULL,
		0x9F65BC35AE2696A9ULL,
		0xE74F9F76C726BDE8ULL,
		0x5FA18843D4E7EED8ULL,
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
	compute_modulo_25519(&k1);
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
		0xB46BCD5D255CE73FULL,
		0x6BE5846D849998E7ULL,
		0xF26DF62BF10B0E75ULL,
		0xC4B56CC4D054D408ULL,
		0xD41672D0B7E6F015ULL,
		0x0569C9A216D6AF94ULL,
		0x5B5F0F611DFFD841ULL,
		0x0B3D2FE5AE118134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC0D85871A48AA9ULL,
		0x3999727CE877A8FFULL,
		0x828A3E966505281CULL,
		0x6FCA88DCA6EE01CEULL,
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
	compute_modulo_25519(&k1);
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
		0x16B80E8386236795ULL,
		0x3DB738B9F50F05BFULL,
		0x2F1EDB6F4B4690A7ULL,
		0x4A77DCACA1140377ULL,
		0x4E7E574463353317ULL,
		0x20D2CE93630AE7D0ULL,
		0x3CFD6A31E6C6DED7ULL,
		0x644BCC778CB19590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD7902AA4008FF39ULL,
		0x1D01E29AA8AD6EAAULL,
		0x3CBC9ED78CCBA496ULL,
		0x2DB8366B837036E0ULL,
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
	compute_modulo_25519(&k1);
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
		0xC5CE0868B0070399ULL,
		0x9D67DA89FD9FEE64ULL,
		0xC80D7007F9DDA2A6ULL,
		0x1CA5E567320F03B9ULL,
		0x4596C0F693627768ULL,
		0x7B9753860CD486F1ULL,
		0x86C406A5A92F9B75ULL,
		0xA4C621088A6F95B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A2EAD0290A4C0ACULL,
		0xF5DE406FE52BF635ULL,
		0xC9266C9F16EEB616ULL,
		0x120ECCABBE9F3D43ULL,
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
	compute_modulo_25519(&k1);
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
		0x5A8D960781509E75ULL,
		0xCC26389C90ACC18DULL,
		0x563803CDA1396CF3ULL,
		0x3FD747E0D8DFE915ULL,
		0x23EB981B2C443245ULL,
		0x40D2925E95E94681ULL,
		0x0C0F9EE58C13A943ULL,
		0x205AB680DA1AB897ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF862A1013701571ULL,
		0x6B67F2A6D14D38B8ULL,
		0x208999E06C248CEFULL,
		0x0D4E5F0138D74F81ULL,
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
	compute_modulo_25519(&k1);
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
		0x6F91526E5A2D08F0ULL,
		0xA5A91A63791D0782ULL,
		0xB25379840ED35990ULL,
		0x0C7CAA495D8489C2ULL,
		0x38B2D677737A9521ULL,
		0xB00563F355AEDEA2ULL,
		0x7D76E9BE647840CFULL,
		0x4BD91BE106B75F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA1D28297E5F2D78ULL,
		0xC675F08231121396ULL,
		0x51FA2BC6F8ACF864ULL,
		0x4EB6CDB05CBCAF69ULL,
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
	compute_modulo_25519(&k1);
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
		0x1B5E1214C12049C9ULL,
		0x3B6EE6AD2831D01DULL,
		0x4183BBACB9BB8F03ULL,
		0x9C1434FD6B45D52AULL,
		0xDA62F9DF61D3415CULL,
		0x90B2DF11DC5BB2A8ULL,
		0x9C5904ECF65FA8E4ULL,
		0x4208D44285789752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x860F293D467BFEEDULL,
		0xB5FC0353DDCE552DULL,
		0x76BA76D94BEEA0F0ULL,
		0x6963B6DD3B2C4B6DULL,
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
	compute_modulo_25519(&k1);
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
		0x0386A26B72A6EE65ULL,
		0xFE57B3E559EACD5FULL,
		0x0FF3EDE26B32C86EULL,
		0xBAAFE4AB6CE2E078ULL,
		0x8FBA6125E47C9A1CULL,
		0x8CF9A3D36A9657E1ULL,
		0x2AFE2124DF560355ULL,
		0x78ACE4D57DF1C9EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59310E0B5D25D14CULL,
		0xEB6605472C3BD8DAULL,
		0x71ACD95B91F74721ULL,
		0x2459DC5C1EC6D9ACULL,
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
	compute_modulo_25519(&k1);
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
		0x20CDEBD290F024BCULL,
		0xE1F228D1EBEE8E3FULL,
		0x1037F5C79A2FA23AULL,
		0x64C63F3DD4B548F5ULL,
		0x1A629B03F45E8084ULL,
		0x9D31CB4D9F23423AULL,
		0x0099A20728E3F72CULL,
		0x10A269A964FE7DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B70EE68D6F738B3ULL,
		0x375656578B2A62DFULL,
		0x270602D7AC0652DAULL,
		0x5CE1EE62D27BF5D5ULL,
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
	compute_modulo_25519(&k1);
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
		0xEBDEECBAA64EF96BULL,
		0xC6F03AB88908BE42ULL,
		0x4915E33A7CBF17F5ULL,
		0x8BEB8589A900EBF7ULL,
		0x1E23D0C9D7FAB336ULL,
		0x6C669510754324D8ULL,
		0x5E5032EC1510CA71ULL,
		0xC34AF5F669B0BB38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x652FEAB0B58597D0ULL,
		0xDE2A5B29F1003657ULL,
		0x48FD72459D3D24CBULL,
		0x090C081D593CB655ULL,
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
	compute_modulo_25519(&k1);
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
		0x5AA612F106F7C8B6ULL,
		0x2561DE59FE8D7EF5ULL,
		0x6E9AEE6617BCBEF8ULL,
		0x6CADC279F54FA907ULL,
		0x7681111335472FFFULL,
		0x5BB818D7F4BF095AULL,
		0x0DB9AFEA60CE4A08ULL,
		0xDA548307707E3608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1CE9BCAEF88ED63ULL,
		0xC2B58E6852E8E262ULL,
		0x782B0B30765BBC35ULL,
		0x55393594A80BAE39ULL,
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
	compute_modulo_25519(&k1);
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
		0xD4B3440073B44FF5ULL,
		0xF0BD8DA95B38D76DULL,
		0x1E4812F8288C8360ULL,
		0xA269FA5CFA0528F5ULL,
		0xE5828ABE550F8A97ULL,
		0x81CA38EACA07ED44ULL,
		0xD8A62AB42C345E2CULL,
		0x4ADCB9CEE219CFCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE613DC411402E414ULL,
		0x34C2008358660FA7ULL,
		0x46F269B6B8527DFCULL,
		0x3F2D8F1289DA015DULL,
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
	compute_modulo_25519(&k1);
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
		0x412FCCEF71BB577EULL,
		0x2437E53E77176D55ULL,
		0xCC766C9F2314DF2CULL,
		0xD189BFDBC4BBAA06ULL,
		0xB4DE73855345F438ULL,
		0xE7270D61C2C9040FULL,
		0x0BA213F729ED1340ULL,
		0xBF185F62F9DA3E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A34F2B9CE1D9C1CULL,
		0x7403E1C160EE07AAULL,
		0x8685634F5C45BACEULL,
		0x2F27E88CDB20EE82ULL,
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
	compute_modulo_25519(&k1);
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
		0x7B2643D8EFFDD7E8ULL,
		0x8086C7D1257985ADULL,
		0x0BEC7317D4E4A81EULL,
		0x8A738FE03BD2FD8DULL,
		0x2EF45F9E4517B61CULL,
		0x3957F49C0B5D2EC7ULL,
		0x74C14E3879C90282ULL,
		0xEE9BF90CB4827921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736C75573182E555ULL,
		0x039516FAD54E773EULL,
		0x609E0F79E8BB0773ULL,
		0x759A87C30730F884ULL,
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
	compute_modulo_25519(&k1);
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
		0x809167B8EE7997FBULL,
		0x5150499B214BBBE1ULL,
		0xFD41C6A5040ED7B6ULL,
		0xE4A7AD03FD631DE5ULL,
		0x30735AE6611CD8BCULL,
		0x540CE64409058EF5ULL,
		0x83B6C49BC80084F7ULL,
		0xFE7F2F46A02DC0D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B0E5EB58C1C99AULL,
		0xCB3A77B4781EF446ULL,
		0x8A62F5C4B422946CULL,
		0x2B88B17FC42DBCFFULL,
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
	compute_modulo_25519(&k1);
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
		0x4CD8ED95A40B2547ULL,
		0xDE8517D76A9856DCULL,
		0x69104E517CE0BF20ULL,
		0x5A7324AECE77409DULL,
		0x780646F5DC50088BULL,
		0xE5543F87AE270E19ULL,
		0x6EFF68F2786F2422ULL,
		0xFBBF824D1391E1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DC7761457EC6F7AULL,
		0xE90685FB44646EA4ULL,
		0xE2F9E24F5D601C4EULL,
		0x38E07C1FB61EC3EBULL,
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
	compute_modulo_25519(&k1);
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
		0x53DDAB3043FD4A0AULL,
		0x55D430A97691C075ULL,
		0x98914EDD20A27538ULL,
		0xF5B6129EB668557DULL,
		0xEA74AEB7FED73A8FULL,
		0x6F890D03DD6BEDA7ULL,
		0x1C96D31628EE08A5ULL,
		0xB814051C083D37CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212F9A8017EFFF6CULL,
		0xE42C1F3C54970762ULL,
		0xD6F4A42733F7BDC6ULL,
		0x48AED4C7EF7E9E3BULL,
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
	compute_modulo_25519(&k1);
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
		0xD4E200C018952E18ULL,
		0x01EEC8947C35BDEDULL,
		0x02012179294678BEULL,
		0x3CDD932CBC13AC71ULL,
		0x27067E240F56EFE2ULL,
		0x97F202E731B3EC0BULL,
		0x76F967BEC029A76BULL,
		0xA1CA169C76804F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD8BA1A5F7CCD34ULL,
		0x8FDB36E5DCEAC795ULL,
		0xAB0687C9AF7552B6ULL,
		0x40DCEE66531F671AULL,
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
	compute_modulo_25519(&k1);
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
		0xD83ED973C6EAE97FULL,
		0x2F7BA2609E3BD6A9ULL,
		0xDB2A0FE2B9A9C3F1ULL,
		0x57FB9DE076D2F72AULL,
		0x9819C6AA5C455036ULL,
		0xE483CFE6B3FE3CFDULL,
		0x115AF50076758858ULL,
		0xDDDB697AE392B004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C1256BD7934D669ULL,
		0x1B0C7E9F55F8E44EULL,
		0x6EAA6DF44F1C0123ULL,
		0x468D461E3E9917C5ULL,
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
	compute_modulo_25519(&k1);
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
		0xFEAC8CCF8302521EULL,
		0x360C81B4B8EDBE9DULL,
		0xE4EE88C5201BFFCAULL,
		0x225C1A3870F20DABULL,
		0xF1E431E1AB6E9FC1ULL,
		0x49D136DB4AA06F75ULL,
		0x08CF0C72D75672F5ULL,
		0x861B4A6A3EB2F1EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE68BF44EF56E0BBCULL,
		0x2B1AA641CCBE4A1FULL,
		0x33AA61D116F11033ULL,
		0x0A6925FDBF81F701ULL,
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
	compute_modulo_25519(&k1);
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
		0xD8F0D386C64D300CULL,
		0xB3E1883CDE36105AULL,
		0xDB876A0BD59038FBULL,
		0xD18537E5CFA2A872ULL,
		0xA9DC2C861E677E92ULL,
		0xDE72C030DCE74692ULL,
		0xC206BF3102718BFBULL,
		0xA52B8900A72873ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F9F6F6F49A9FD6EULL,
		0xB8EA0F7DA88A8A20ULL,
		0xA887CB52326B005EULL,
		0x55FB8DFE9FA3DD97ULL,
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
	compute_modulo_25519(&k1);
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
		0x1040F870C7B94D2FULL,
		0xBA4024457E4ABB7EULL,
		0x4EF7C5E64DE105D7ULL,
		0x808671F4AE410D54ULL,
		0x7E20643233B70361ULL,
		0x47076FCEC5B5C47BULL,
		0x880E625C136FF107ULL,
		0x98609D365578C907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC90FD7E474E3D0FFULL,
		0x455ABCF6D745E5D2ULL,
		0x811A5F91307ECCECULL,
		0x1EDDC8055E2EE472ULL,
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
	compute_modulo_25519(&k1);
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
		0x22518F70E8569ACFULL,
		0xD62656B544F18962ULL,
		0x3A8EE0D3D63B47FEULL,
		0x43C41E7A2830600DULL,
		0x18A477D28A8A5F32ULL,
		0xD440464BAAA57CCDULL,
		0xB0B04EBB818C05ACULL,
		0xBBDDB5D588172675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCABB58B178E0C063ULL,
		0x57B0C5F099820FD3ULL,
		0x74BA90A911041FA6ULL,
		0x26AD1C2C5BA01585ULL,
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
	compute_modulo_25519(&k1);
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
		0xB1436CA0856E31A2ULL,
		0x8C26A29A80CC097DULL,
		0x3B06C9BF08A8792EULL,
		0x4C7B749CDD854410ULL,
		0xF9A5605F83378129ULL,
		0xA721BA47F17A41CFULL,
		0xF025E6DC55B80389ULL,
		0xE2518020AB8A5406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFCFBACDFFAB62B1ULL,
		0x5B28494858F1CE5CULL,
		0xE0A70E73C1F8FF9DULL,
		0x64947976540DBD17ULL,
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
	compute_modulo_25519(&k1);
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
		0xDA47FEB128D7F606ULL,
		0xFCA500C0FB8E8037ULL,
		0x42DF849373CA6BD2ULL,
		0x8BEDFE2DF7DF5459ULL,
		0x1B2DF37583754A2CULL,
		0x2A465528E0441C39ULL,
		0x11E181EB0CDC9E34ULL,
		0xA5BF059C679DA10AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE31A2222AC40FC44ULL,
		0x4315A4D245AAB0B1ULL,
		0xEA58CD775C89E791ULL,
		0x2648D36559453BD7ULL,
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
	compute_modulo_25519(&k1);
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
		0x2E526BB8234F0D5BULL,
		0xB33D9E4C46E0B81BULL,
		0x63DAF60F7F160471ULL,
		0xBDE24C390DCA3890ULL,
		0x0D813DC6C5F24F10ULL,
		0xBBF756DA96E0DCB6ULL,
		0x1C5B04A0092297B3ULL,
		0x49AD288C665136AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F8197398546CB70ULL,
		0x99F482BEAC417B21ULL,
		0x995DA5D0DA38891FULL,
		0x2D9651103DD8568EULL,
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
	compute_modulo_25519(&k1);
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
		0x2C5202AB908845ABULL,
		0x0F32A3111F829054ULL,
		0x1E80BAF6AFB94FE4ULL,
		0x5159C12AC22DDF3AULL,
		0xD608711C5F128EADULL,
		0xF2E235801D0CF6DDULL,
		0xA207FF5FF6B45652ULL,
		0x11AA190564CFFD7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF192CCE1AD4973B8ULL,
		0x1CC694156F6F3541ULL,
		0x2BB0A3354E7E2034ULL,
		0x709977F7B90D802CULL,
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
	compute_modulo_25519(&k1);
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
		0x26465C35F34FDFF4ULL,
		0xD2C54B1A4A9EC4F6ULL,
		0x1FA47B1D670E570BULL,
		0xC639E30909F44DBCULL,
		0x43DED85A27EA00A7ULL,
		0xE7842011BFE69F35ULL,
		0xBE81C513220C68E6ULL,
		0x9CE0D66AF3EB2B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395A7997E00BFC4EULL,
		0x30620DBCC6DA66DEULL,
		0x66E7BBF474E5E952ULL,
		0x0F99B6E93EDCB76AULL,
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
	compute_modulo_25519(&k1);
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
		0xEC22A9487DD868ECULL,
		0x04610B6029445EF8ULL,
		0x8548D4F0BA097459ULL,
		0x811813B9323E1450ULL,
		0x4A5EA89FAB5B1B7EULL,
		0xDC7D439DACB083E2ULL,
		0x9D8B275CA1334A89ULL,
		0xB03500DC951E5BAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF62FB0FBED5E818FULL,
		0xBEF914C7CB77F28FULL,
		0xE7F0ACB0A7A684CFULL,
		0x28F6347754BFB03BULL,
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
	compute_modulo_25519(&k1);
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
		0xE73A7D1EA5611132ULL,
		0x6E68B0462BE8269DULL,
		0x583247D9522CE707ULL,
		0x72158E480347CF42ULL,
		0x772044E956695812ULL,
		0xEBC9F7628C85E3D9ULL,
		0x416073A83E9FBBEBULL,
		0x4238E6F0C9AEC1C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9604B7C17904255AULL,
		0x6E6368E707C7F8E5ULL,
		0x0C8372D29DE2CC0CULL,
		0x4687D605F33892B0ULL,
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
	compute_modulo_25519(&k1);
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
		0x28072582B189EC68ULL,
		0xFDED4293C41FEFF8ULL,
		0xDF3DFAD4901E37A0ULL,
		0x84AF4D3D56EC8AA5ULL,
		0x9AEC623FF8176962ULL,
		0xC6CCE3D6DD7E6DD6ULL,
		0xE97FF0A99F06DA0AULL,
		0x6037864B8D12B94EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271DBB018503931BULL,
		0x80571478A4E43DD3ULL,
		0x883BB4022B22953AULL,
		0x4CED3C7447B40C5CULL,
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
	compute_modulo_25519(&k1);
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
		0xB632CA9C35A6F5A5ULL,
		0xCE431112A3177995ULL,
		0x6AE0898F27C65156ULL,
		0x2110B3108EA1FC12ULL,
		0xF9C22C999752A0DEULL,
		0x5E83B63A627F933BULL,
		0x0CB1217B0C7BD4FCULL,
		0x48D3C6DCB4B63EB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9056968ABEAD828ULL,
		0xD5D01DBD4207547CULL,
		0x4D2B81D30227EECCULL,
		0x708037D361AF4A34ULL,
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
	compute_modulo_25519(&k1);
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
		0x598C507E368AF0E3ULL,
		0x68278B90A0606B39ULL,
		0x45AB671FA6EE287EULL,
		0x52C0C44E3D1430C6ULL,
		0x2E5F604B5F354558ULL,
		0xFA4A4097FC694941ULL,
		0xD15C86F229C5F0B2ULL,
		0x1ED77136B703957CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB49BAE58733C9EULL,
		0x8F2D222018014AE6ULL,
		0x59676F11DA4FE30FULL,
		0x66BB926D679C614DULL,
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
	compute_modulo_25519(&k1);
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
		0xA209BBF03631203AULL,
		0x80D84E3979D27B71ULL,
		0x58DCF2F19D5334F1ULL,
		0x1206AA24F95D7270ULL,
		0x617DDB369A582446ULL,
		0x55C00F14D1D542A7ULL,
		0xE997DB7A566E6C26ULL,
		0x4810B70329CB7118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB8460B1F46842DULL,
		0x3B5A8B509F7A604AULL,
		0x0567871A71B742A2ULL,
		0x4481D49D2D903C23ULL,
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
	compute_modulo_25519(&k1);
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
		0x359DFAA815495449ULL,
		0x9E102AB8352BA5C4ULL,
		0x36EE7BD2C1A9F7CEULL,
		0xA02FBF6279208EF5ULL,
		0x9E64BF9A397FD716ULL,
		0xE807E9EF972BB8CFULL,
		0xEBED15DD08BB6EBEULL,
		0x14F38D6A3406F6D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8926B8C9E434212ULL,
		0x0F3CE448A5A91495ULL,
		0x3C1FBAA20D7C6825ULL,
		0x3C56BD263229321EULL,
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
	compute_modulo_25519(&k1);
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
		0xD3CEAD1F13D558C6ULL,
		0x75C7021CAA6CC55DULL,
		0x3D7EC541D97737FCULL,
		0x292D25C30664106FULL,
		0x00AFB5CB8F24D7ECULL,
		0x34F227C1D25801F1ULL,
		0xD3D5257067C65EE3ULL,
		0x750229709740DA69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE3A956534D6867ULL,
		0x51B8E8E1E37D0F23ULL,
		0xAF2253F140E94DB6ULL,
		0x077F4C797A047C24ULL,
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
	compute_modulo_25519(&k1);
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
		0x532AF67A89FDB4ADULL,
		0x54B6441DC4A02598ULL,
		0x5B7A8CAFFA8B2F38ULL,
		0xB68A660D60D8ED90ULL,
		0x90967CD0AF557C9AULL,
		0x6E681D60E818CEEBULL,
		0xAF244709FB35B7F0ULL,
		0x7331C8A42B5E4CACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9817D7490AE3622ULL,
		0xB82AA080384EDC8FULL,
		0x5ADD182B44847CE8ULL,
		0x4FEE2E6BD0D84F32ULL,
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
	compute_modulo_25519(&k1);
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
		0x61C42F3F3B4C5D5EULL,
		0x9811B74D4D7D1E2FULL,
		0x49CBD54BACE269FCULL,
		0xBDF43D2592195C5FULL,
		0x8A8DBBB157AF886EULL,
		0x2D7941E50A5E8282ULL,
		0x6A349C7AF3C66223ULL,
		0x7DCD93403A562305ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CE0B923F5AA084ULL,
		0x58117F4CD7847D8FULL,
		0x0D9B0F8BDC54FB35ULL,
		0x6A7818AE3AE28F2DULL,
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
	compute_modulo_25519(&k1);
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
		0x3D879AB02220DB6DULL,
		0xCD484A6CAB3B83CBULL,
		0x3AD8EFE3A907B859ULL,
		0x435E82E27CE53FD9ULL,
		0x57E5A7D921F53ED8ULL,
		0xDAD303E1506BC348ULL,
		0xC2F0D48C7BA9B804ULL,
		0x6D5CF6CD1B4C306AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x499E84EB2C8831DDULL,
		0x489ADDDE9B3A8088ULL,
		0x2A987CBE04390912ULL,
		0x7F2B25548A346FB2ULL,
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
	compute_modulo_25519(&k1);
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
		0x8D060E4BB71A2D3EULL,
		0x60FDABF792C1E0A0ULL,
		0x762CC41BDD67EEC0ULL,
		0x8DC00BF68D8359D7ULL,
		0x98E3CE0C5F3F322EULL,
		0xC98D0D51593454F5ULL,
		0x99F5C88DBBD3FCB4ULL,
		0x9EB6DD6271850BE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED6A421DA7BA3A2ULL,
		0x4BEDA60AD0867D15ULL,
		0x50A88925BEDF7196ULL,
		0x1CE4E89367431DECULL,
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
	compute_modulo_25519(&k1);
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
		0xEB804C324487D374ULL,
		0x1A47068A42DF1553ULL,
		0xF98DFC9939FD1BD1ULL,
		0x775EBB623ECD8C93ULL,
		0x296B4DF29F3EEC33ULL,
		0xB0121772F37CE496ULL,
		0xD3123C02A5CF59FFULL,
		0x5CBF2FD720A90A4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x116DDE35E7DEE51AULL,
		0x3CF6819A6769039EULL,
		0x4E42E4FDD6C477C5ULL,
		0x3BBFD55117E51447ULL,
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
	compute_modulo_25519(&k1);
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
		0x0FFF46CDC9408958ULL,
		0xF19656B0405B36DAULL,
		0x8CC57930C9DEF2CEULL,
		0xE5EA96DF8DCF42C9ULL,
		0x3D18AEC71EF898AEULL,
		0x89EFD45CFE1652D8ULL,
		0x183495D6C96EDCB8ULL,
		0x05B992C73F0885C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A9385C62273365ULL,
		0x6B2FDC7DF7AB82F3ULL,
		0x2493B712B053B633ULL,
		0x3F766072E9131D4DULL,
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
	compute_modulo_25519(&k1);
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
		0x865B6B57DD2770FEULL,
		0x8F388E7C1C4AA9E1ULL,
		0x2D1A41BB5F3D258DULL,
		0xC1142F469A4ACC4DULL,
		0x194D2D6E0657D83EULL,
		0x9321807F0211ED0AULL,
		0xECF0D5AA4CA62AE2ULL,
		0xC63EF153A51FA0D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47D029ACCE318EA6ULL,
		0x6631A1566AF3D961ULL,
		0x58D9F902BFE7832FULL,
		0x2E6C01B11CFCAB50ULL,
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
	compute_modulo_25519(&k1);
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
		0x4E96A3565F432BF5ULL,
		0xF2C8ABC65A16AF97ULL,
		0x257D82293EE9A5C2ULL,
		0xF00986244D93ECBBULL,
		0xC450C6F3B9D07AD8ULL,
		0x1D9BBE0D330B12F3ULL,
		0x603EBBBFCFF4DDAFULL,
		0x1AD70104CEAC51B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72942B83F43568B0ULL,
		0x57E6E1BBEDBB7FC6ULL,
		0x6ECD60A21D428DC1ULL,
		0x6BF3ACDAFB280E3FULL,
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
	compute_modulo_25519(&k1);
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
		0xF79CC6A196CA8207ULL,
		0x737378C4836BFA29ULL,
		0xC4007D272B251E8BULL,
		0x47641B414FB46F2EULL,
		0x693E65BC1B829316ULL,
		0xB515028A30CBBB5DULL,
		0xAC4013614B10E0B8ULL,
		0x2E335F8E2CE0ED5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96DFE08DAC2C5855ULL,
		0x5491D947C1A9CA07ULL,
		0x55835D984FA679F6ULL,
		0x23044A5BF917AB62ULL,
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
	compute_modulo_25519(&k1);
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
		0xC82C614993A721F7ULL,
		0xF255B8E6FF77C820ULL,
		0xABE3C095A6686A6CULL,
		0xF7B581DE44E2930FULL,
		0x47596133D4AD6536ULL,
		0x5581261317E6AE73ULL,
		0xC3753436D092CBB0ULL,
		0x4D3E59828B100477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F70CEFB256429C3ULL,
		0xA3815FBC8BB5AD3DULL,
		0xAF4980B89C32A699ULL,
		0x6EF6CB3EE9433CD6ULL,
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
	compute_modulo_25519(&k1);
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
		0x057FC359AB3DAC14ULL,
		0xB9444788AF562505ULL,
		0x71A372E9548AA1B0ULL,
		0xAFA81B6ED9559785ULL,
		0xCE5BAEFE498655B1ULL,
		0xBB26461C6322C449ULL,
		0xE81A761C56C62F60ULL,
		0x2585D3E2075B3F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71BBD18952E653EULL,
		0x80F2AFBF667F47F9ULL,
		0xE590FB1E35F5AA0CULL,
		0x41858EFBF0E0F82FULL,
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
	compute_modulo_25519(&k1);
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
		0x836DF3050EBDCDF3ULL,
		0xE8AAD984D518979AULL,
		0xB2A68340F245F2CFULL,
		0xC9BA3BC2D0AD9D6BULL,
		0xA8BF7D38F123D283ULL,
		0x2796B0BFC1BC488AULL,
		0x89C4AA5D9796CA95ULL,
		0x1DC52AB08EB49A00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FDA8978DA0F0E23ULL,
		0xC90915FB970B5C2FULL,
		0x25D7CD2572A804F3ULL,
		0x34FE91F7FF7C7980ULL,
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
	compute_modulo_25519(&k1);
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
		0x16F2E59FD0D18F4DULL,
		0xB6E8CC4C5E63F61DULL,
		0xC5FEB4EA1DE5A080ULL,
		0x25CCBDB32D19A903ULL,
		0x17ACBCDB39C036B0ULL,
		0x02D8D3253D312A28ULL,
		0x01DE98D83EDF0C41ULL,
		0x94B518B1138429D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A96EE2A6359B0B1ULL,
		0x231823D373B03810ULL,
		0x0D09650373017227ULL,
		0x38AE67FC12B7DE7CULL,
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
	compute_modulo_25519(&k1);
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
		0x3215027E48322B06ULL,
		0x727478E5A4632A8EULL,
		0xF5F9D8DBFA9C78E2ULL,
		0xCD2D8A3D877053D1ULL,
		0x4339730BEDCFAEBDULL,
		0x3B87FF1902E7046DULL,
		0x4C2FC3EE596054FAULL,
		0xAA00001E70840895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C9C164395061EF0ULL,
		0x48A4569C12ADD2C6ULL,
		0x4510EE3D3EE91607ULL,
		0x092D8EC23B0999FBULL,
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
	compute_modulo_25519(&k1);
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
		0x1A84D1098415C116ULL,
		0xF3C19E430A925A9EULL,
		0x36A78F239DD942BAULL,
		0x2E93A0D41DC38EA3ULL,
		0x91DFBA3AE6F15AEBULL,
		0xB6D0ED628A4E9439ULL,
		0xE86C65D3D7FDB34DULL,
		0x88E19FC442AFEAE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BA75C7CBE94303ULL,
		0x16C4DAE3923C5B29ULL,
		0xB6BEAC95AD81E044ULL,
		0x001157F603E06C9DULL,
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
	compute_modulo_25519(&k1);
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
		0xA3E627834930B9DEULL,
		0x06D6618C79CC10C2ULL,
		0x331D516A8F828EA6ULL,
		0xADCF54CA3844C38DULL,
		0xC0C70ABFBDDD3EDEULL,
		0xC8989AB7E8404F55ULL,
		0xE7279D90D4161411ULL,
		0xB6C875E2824BAE32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4171BFF9780812E7ULL,
		0xCD7D58D8F357D77DULL,
		0x82FEB4EA0AC98949ULL,
		0x4F90D4698F809F1BULL,
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
	compute_modulo_25519(&k1);
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
		0xE7ACCEC2E721F5F7ULL,
		0x86BE0050A29D7E25ULL,
		0x957689A40E58D7B1ULL,
		0x17A7E554F8D6CCB5ULL,
		0x2145BAB928E2E9BCULL,
		0x2EB05A388C6F5C0AULL,
		0xA63D21D4F002B2EDULL,
		0x6331841956C93C7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD806863EF8D0AA06ULL,
		0x74EB64B57B2527A6ULL,
		0x42898F3FAEBF66E6ULL,
		0x51018117DAB5C710ULL,
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
	compute_modulo_25519(&k1);
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
		0x19B270851B02F177ULL,
		0x34806BC27F878D5CULL,
		0x1F4A8A9500B18C9CULL,
		0xA3BD8DCB124675CCULL,
		0x9D16B6A871F15211ULL,
		0x697A7904AC30DEA0ULL,
		0x086C804EC8CDB5BCULL,
		0x264D6CB1468967F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B118D8604D520E1ULL,
		0xDCAE62740EC89933ULL,
		0x5F659646CF3A8693ULL,
		0x533BB01B8AABE42BULL,
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
	compute_modulo_25519(&k1);
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
		0xE000C07024CB9053ULL,
		0xDB4475C1F0B14B58ULL,
		0xF0EB1517319AA0B7ULL,
		0x7FBA504F932D6400ULL,
		0x28FDAA9E8F21F048ULL,
		0xC0009FE98E80B2FCULL,
		0x7A0B8952BA95A1EBULL,
		0xD806F6B75317D962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A813F963D53FD6ULL,
		0x5B5C326D17CBDCC6ULL,
		0x0EA1775EE3D0A9B6ULL,
		0x10C2EF85E8B7A89FULL,
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
	compute_modulo_25519(&k1);
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
		0x88684F9F1AB78048ULL,
		0x1A10124D10605B0EULL,
		0x4C14107AFD160702ULL,
		0xF8EEE5D60134F4E8ULL,
		0xBBE5BF7D1308C91FULL,
		0x4A7AA94188061E94ULL,
		0xB5A77F9D9A201499ULL,
		0x083B55B3FAF3B957ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C82BC2FEE055B2EULL,
		0x284532074148E522ULL,
		0x42F101DFDDD915C3ULL,
		0x31BD9E8D416277EDULL,
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
	compute_modulo_25519(&k1);
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
		0xA89D9C1C15F9F059ULL,
		0x67E2ABB11C95E93BULL,
		0xD061F358767F9BE2ULL,
		0xEAEE866BFCB7AD1BULL,
		0x2AEDFCDE5F283F85ULL,
		0x32ECB3A971317402ULL,
		0xC3E7086CAF23BDF5ULL,
		0xB6406979FFA068E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F1251E35F3622CULL,
		0xF70556D7E9ED218EULL,
		0xE4AD337A75CDCE47ULL,
		0x787E2E87EE873E9EULL,
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
	compute_modulo_25519(&k1);
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
		0xAA7CE712CDCF2212ULL,
		0x51564F34C1CB9CB8ULL,
		0x45272DDDF31E0DE9ULL,
		0x73827CCB4DDA458DULL,
		0xFB3B1CD95AEF91D2ULL,
		0xD3742E9ABE168A09ULL,
		0x5D507515149F0AA2ULL,
		0xB5071AB5B7ED3A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5432F564D5ECB40ULL,
		0xB4953A2CF9241A33ULL,
		0x1F188EFF02B9A214ULL,
		0x529073C49B10F7DFULL,
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
	compute_modulo_25519(&k1);
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
		0x558B96A33841AD12ULL,
		0xDDD1CF6EC7A65D83ULL,
		0x21684AEBE53EE776ULL,
		0x7EE1C0BE9AAB976CULL,
		0x3044CE35E55BC2F4ULL,
		0x2D262066927260DAULL,
		0x06F70C3ACD542E8FULL,
		0xB6C4CF8B56BBF697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC232A343E0A15FULL,
		0x917A9EA884A0BDE6ULL,
		0x2A141BA65FBDD0B7ULL,
		0x20188F6D7A9231D7ULL,
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
	compute_modulo_25519(&k1);
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
		0x741EBD4B7D743971ULL,
		0x71978F3DF7DA8A96ULL,
		0xE870E4AC6C05DEB6ULL,
		0x780E54F9D13985B6ULL,
		0x28FEAD54CAB612B1ULL,
		0x50792D39A10D86A6ULL,
		0xA9BE703F92CC7F8EULL,
		0x48EB96C784FCD2E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EC77E1947B0159ULL,
		0x639445CBDFDC8740ULL,
		0x1AB58E1C3660CDD6ULL,
		0x4B06B6978EC0D466ULL,
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
	compute_modulo_25519(&k1);
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
		0xB1AC61AE0A676042ULL,
		0x7233CD895F314D2BULL,
		0x3C47A3A3EEE82651ULL,
		0x7CE24D6C94BA315DULL,
		0xC6FA2F65A0DD17EBULL,
		0x76B4D593D3E89AB9ULL,
		0x7D2F4CEF280657CFULL,
		0xA43977324B7D6E1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ACF6AC3EB38F0C7ULL,
		0x110B817AD3B844BFULL,
		0xD14D0F23DFD92F1DULL,
		0x5D69FEE3C95889BDULL,
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
	compute_modulo_25519(&k1);
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
		0xB94CC906132BF222ULL,
		0x713C772BB20B8A9FULL,
		0xDC02809CF603502FULL,
		0x5CAE83BD8C22C723ULL,
		0x18EE1D499888EDF6ULL,
		0xC7849C0DC2D67474ULL,
		0xC833D4D17A9A7D3AULL,
		0xE31A16C388121E4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CA521F2B77F49B2ULL,
		0x0EEBA1369DE0D3DBULL,
		0x93B417B528F1E6E9ULL,
		0x128DE4C3BED346FBULL,
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
	compute_modulo_25519(&k1);
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
		0x3D99F3EC09C91626ULL,
		0x93093670A81203CCULL,
		0xF93ACF7A3784D3FDULL,
		0x5570CE1EEE35093AULL,
		0x6E1AC34B11ECF63CULL,
		0x4D7D392C051D3D80ULL,
		0x2B5729C35D36831EULL,
		0xDEC533D7C278C71EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9592F110B2F5A7F4ULL,
		0x139FB2F96A6924DCULL,
		0x682B027A0D9C4A7DULL,
		0x66B68025CC2297B5ULL,
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
	compute_modulo_25519(&k1);
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
		0x7CDC58686E476F2EULL,
		0x61D887A5E15A1737ULL,
		0xDCF03CB4FA4C2633ULL,
		0x2F18E4BB175A6F0CULL,
		0x97CD98A3EEBD9C1CULL,
		0xA54447972BB0D006ULL,
		0x9CBD3384571A2543ULL,
		0xAE7F8BF9C5299F42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x056100BDDE6C9F32ULL,
		0xE9FB28165D98F832ULL,
		0x2105E259E82DAE3DULL,
		0x1607ABCE5B8812F0ULL,
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
	compute_modulo_25519(&k1);
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
		0xFCBE378A6E00273AULL,
		0x0D2983836AD6E9AAULL,
		0x151AED44B9FF92EBULL,
		0x3FB34C1609B0E13FULL,
		0x3CC8BBE629143E1CULL,
		0x99AC5301053CEAA5ULL,
		0x3BAF9655F9074C57ULL,
		0xF089CA14BAFABF92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028A1BB4870164A7ULL,
		0xDCBDD5AA31E1BE32ULL,
		0xF12B3E07B114E7EBULL,
		0x74274B29CAE950F3ULL,
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
	compute_modulo_25519(&k1);
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
		0x856C28879EAA317DULL,
		0x45B4087A18FDFEEDULL,
		0x88534274B35EFDCFULL,
		0xC8B1AB9EFDD83DB8ULL,
		0x62181D1C67EB96D1ULL,
		0x5967BA86A0381F2BULL,
		0xA6096AA80796704DULL,
		0x4450A8532E9ED441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15007ABF0BA29612ULL,
		0x8B19B875E1529F5EULL,
		0x2DB91765D3B3A94AULL,
		0x6CAAA7F7E96BBF77ULL,
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
	compute_modulo_25519(&k1);
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
		0xC237340CC1A5D7E2ULL,
		0x1F04DC9AE6D896F3ULL,
		0x1E5526B72A59FEC5ULL,
		0x5FA56769E5F3F000ULL,
		0x21B4938B610AD9ADULL,
		0xD6720A239A53B6D1ULL,
		0xE2AD49574DCC8D4BULL,
		0x318ADDC2BE2B877EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3051ABD294228ADULL,
		0xF3F25DE3CF45B9FEULL,
		0xC40E09ACB6B6F806ULL,
		0x3A425252206A0CD5ULL,
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
	compute_modulo_25519(&k1);
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
		0x68CCC4A71E8456DAULL,
		0x36EF96E8790F1BAAULL,
		0x03E85EA1E1565CEDULL,
		0x7AA462CD81610285ULL,
		0x944531AB23CFD8B0ULL,
		0x21D1E63B54EB2ADFULL,
		0x1B9A0137D01E2875ULL,
		0x8A3F21B55DD9234DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B12240E6F5E8418ULL,
		0x3C17C3B713F778DAULL,
		0x1CC48CEAC5D05E50ULL,
		0x000363B96F9C3FF7ULL,
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
	compute_modulo_25519(&k1);
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
		0x7CB993C30DC24204ULL,
		0xDB43623ECFF1A379ULL,
		0x03C4D48CE4ACBCF1ULL,
		0xD61B8ADABC47B427ULL,
		0x63F451033E796263ULL,
		0x90C73C97C1C72851ULL,
		0x80C681FB7869F343ULL,
		0xF52952813069C54CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52FD9A3E53C6E234ULL,
		0x58D660C593819F8EULL,
		0x213C1FE0C466D8F9ULL,
		0x3A3DCA07EBFAFD82ULL,
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
	compute_modulo_25519(&k1);
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
		0x0258EAC7A875BF85ULL,
		0x6151DEA2AF4DF8D8ULL,
		0xCC796607D298DB6EULL,
		0xC6430EED3E0F7D88ULL,
		0xBE39F62F964B25AFULL,
		0x01C636C0D0A1BFB7ULL,
		0xF2FA98E76B0286F6ULL,
		0x87705EAB4E15A3B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EF375D7F79D5A8AULL,
		0xA4BDFF41A7506E1EULL,
		0xDDAC1861B4F8E3F2ULL,
		0x60F11C5AD545C9CCULL,
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
	compute_modulo_25519(&k1);
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
		0xD6E44EFA5402707CULL,
		0x96E1F50C67E2FF84ULL,
		0x798B7321EF90A984ULL,
		0x72A14D9968D2759EULL,
		0xD78CDE4EDBBF35D2ULL,
		0x23DDB3C940E4CDEDULL,
		0x1FC72331507F93D8ULL,
		0x01C498AC4B057FA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5CD4EAEF2646DBBULL,
		0xE9CAA4EC09D990D2ULL,
		0x311AAC73E2809B99ULL,
		0x35CFF72C8BA3686DULL,
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
	compute_modulo_25519(&k1);
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
		0x8D983DBF41B3FBFEULL,
		0x8F86B66B72D7D4D0ULL,
		0xDFB4116FE2B3A612ULL,
		0xD9B9AB4A637B1640ULL,
		0xB4AAF43C5D303E7FULL,
		0x185F6CDFFDB3944CULL,
		0x7F004B12E6039ECCULL,
		0xB6F0D962B9705AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF87EB516DD4700ULL,
		0x2DB0DFAB1B7FD833ULL,
		0xB9BF363E073D385EULL,
		0x0179EFF1EA2891A5ULL,
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
	compute_modulo_25519(&k1);
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
		0x638D5C4CA438DE76ULL,
		0xE8D68CEC01B7F417ULL,
		0x05D437856EA4DB8BULL,
		0x242EE25A30C67F70ULL,
		0x272537E679FEC53AULL,
		0x37DB87CACD0AF876ULL,
		0x2445A86284FDA31DULL,
		0xE0BCE9B8DBC8FBD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3313A882C00A2A0BULL,
		0x336CB5067158D5A1ULL,
		0x682B36252C4B11E2ULL,
		0x003993CAD09BE15FULL,
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
	compute_modulo_25519(&k1);
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
		0x16F513437C60B8B8ULL,
		0xC33E4978E35C443AULL,
		0x5C4FE56DADE98842ULL,
		0x638794FBF1A7C98CULL,
		0xFB1F20FDCBA755D1ULL,
		0xC34D82879E5B2852ULL,
		0x5F88B0EFE54B402AULL,
		0x67FF155205EFE9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D93F8EFB737780BULL,
		0xC0BFA99A64E4408BULL,
		0x8A9A2909B7150E9BULL,
		0x5364BF28D3448444ULL,
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
	compute_modulo_25519(&k1);
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
		0xD91E16BBD15D8EB8ULL,
		0x7BE361FA310CAB01ULL,
		0x777E3243AEE406F3ULL,
		0xCAC4A941DD9F11A6ULL,
		0x0BCF75F3F117E74EULL,
		0x8E7DAE03663C43E5ULL,
		0xE25EA54836AE0FBBULL,
		0xE7AC9BCC06B1DF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E998F19AE9E97EULL,
		0xA28B367B5DFEBF01ULL,
		0x118ABAFBCCBA5CCAULL,
		0x2E63C98ADC064044ULL,
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
	compute_modulo_25519(&k1);
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
		0x418E9FB0A0A9F39FULL,
		0xE30DF72F79F624D9ULL,
		0xFC2E8A4537D04E90ULL,
		0x0FE0B4307415CF3FULL,
		0xFB3FB9D264694AF5ULL,
		0x842D430160E6B352ULL,
		0x5DB54C510F561EC7ULL,
		0xAD92F537E7246611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D0434EB884B17C6ULL,
		0x81C5E963DC34C32AULL,
		0xE517DE4D7E98E02EULL,
		0x53B11A7CC37CF5D3ULL,
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
	compute_modulo_25519(&k1);
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
		0x14A2E3DB740F64B0ULL,
		0x071905F07AB55D05ULL,
		0x9DB773C07ED86CE0ULL,
		0xD64FB1446F68C10DULL,
		0x7AAF4956E08D9457ULL,
		0x0A763E7A11B276B3ULL,
		0x48178943C645B7E7ULL,
		0x6037BCEC1F72123FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AA7C6C0C9136BD4ULL,
		0x94A64C0F1B32FBA9ULL,
		0x5135D3CFED31B92BULL,
		0x1E95BC511A577672ULL,
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
	compute_modulo_25519(&k1);
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
		0x7C5E5D554818AFB8ULL,
		0xFA60872B143E7076ULL,
		0xD810B115019D42D2ULL,
		0x590849B991CADFFBULL,
		0xEB0C3A79D0B53BFCULL,
		0xF8A7A62436E40D2EULL,
		0x90A53C9640160604ULL,
		0xEDB4E2DDD03B9DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x602F0B6A42FF9C65ULL,
		0xE343308B3A18656DULL,
		0x5097AF6284E2278FULL,
		0x21E1F6A67AA44C59ULL,
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
	compute_modulo_25519(&k1);
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
		0x34E290710D6394BFULL,
		0xB125B87FFE193604ULL,
		0xDD7FA19265AE1906ULL,
		0x23C87ED6782D7E48ULL,
		0xDF990CA010DC152FULL,
		0x84D2390409AC47C1ULL,
		0xB058F8775EA3BD4DULL,
		0x7E766CA8EBBBF66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659A70338E0EBC78ULL,
		0x685A2F196DABDCCBULL,
		0x0AB4834A71FC3288ULL,
		0x695C9FE97614121FULL,
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
	compute_modulo_25519(&k1);
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
		0xB6244757F49C7F39ULL,
		0xE02DCD8BEB766826ULL,
		0x0C2CA7004D711234ULL,
		0x174ECC358F01B184ULL,
		0xB3D3A717AD4E80E7ULL,
		0x29AD1C0609E00EB8ULL,
		0x7865B10E966A15E3ULL,
		0x1D146B69E68E3500ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678F14DBAE43A21BULL,
		0x0FDFF67162B89791ULL,
		0xEB44EF2AA13051EDULL,
		0x6856BDEDC81D8F95ULL,
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
	compute_modulo_25519(&k1);
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
		0x89025FC0F8B54657ULL,
		0xCD496D8C84BB6D0AULL,
		0x5ADB65AE38C052B8ULL,
		0x5603EA5B8472E4D5ULL,
		0xA977A0CF7AD12F16ULL,
		0x5167BA07D0B3967FULL,
		0xBC2A2F8711E282B3ULL,
		0xC2A2408BA7A697C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C43E8D33C247E9ULL,
		0xE2AF0AB57F63C3FDULL,
		0x491E73BAE05FB956ULL,
		0x3A197F16672D6BBDULL,
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
	compute_modulo_25519(&k1);
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
		0xB7C0CEBDBA32EA50ULL,
		0xF45AE5CC0948E9ABULL,
		0xE4F55C7BCA690179ULL,
		0xD3A7F444B03FD81DULL,
		0x6822AF920EC6707DULL,
		0x4CE95A15AF798821ULL,
		0x883449AA07E592C1ULL,
		0x18BB784734DC635FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CE6DE6BEBA79D76ULL,
		0x5EFE450415531EA1ULL,
		0x1CB84BB8F67CCA2BULL,
		0x7F7BCED688F6984CULL,
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
	compute_modulo_25519(&k1);
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
		0xE6ABC0D12F1548ADULL,
		0x8090A86CB1E9ECB3ULL,
		0xF378D33D906030CEULL,
		0xE96DBCD796B37098ULL,
		0x245C3179AB2209CFULL,
		0x5BFD18AB3A2415A0ULL,
		0x7FCD325A56E8B4D5ULL,
		0xE71E1F4D829722D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5B18E09622C299ULL,
		0x282251D753452279ULL,
		0xEBEE4CA676EB087AULL,
		0x37E66258F9229BD7ULL,
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
	compute_modulo_25519(&k1);
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
		0x680222EF75E445D9ULL,
		0xB2AF2392B99B22E8ULL,
		0x707234FF371BE844ULL,
		0x1B130B3E7B4A2C21ULL,
		0x959BF51A628FFBCAULL,
		0xE4FE5D3C573D39DCULL,
		0x84B0E04001902CF4ULL,
		0x041C5A3EC40FAD33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D2884DA1743A5E8ULL,
		0xB070FA87ACB1B9A6ULL,
		0x22B37E7F7282949EULL,
		0x3748708F959DE1C7ULL,
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
	compute_modulo_25519(&k1);
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
		0xF9A4FDABABB4F795ULL,
		0x7D5B2651E32EB945ULL,
		0x556E9FFCBF214DB4ULL,
		0xA954E032A3450ABCULL,
		0xF46CB2BDB289359AULL,
		0x1E711E6B80AA412BULL,
		0x1900C40D42C9B4E3ULL,
		0x1DA55703B46E774AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41C785D42C12ED2FULL,
		0x0225AA46FC7465CCULL,
		0x0B8BB9F4A912276BULL,
		0x0FDFCABF6BAABFBCULL,
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
	compute_modulo_25519(&k1);
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
		0x6C879066A416380FULL,
		0x8BB562FF2E58F3E7ULL,
		0x396962D7466C6D0BULL,
		0x534308CF3EFC763EULL,
		0x6BE7AF2E463BA1B8ULL,
		0x76FD3DA4B8024747ULL,
		0xC477EC896EE6356BULL,
		0x86FDA194B2507E94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70EB914510F03C57ULL,
		0x354C89727EAF8881ULL,
		0x63367F3DBC985AFFULL,
		0x5CE904E1B6EF4053ULL,
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
	compute_modulo_25519(&k1);
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
		0xB87EEBB744F3D981ULL,
		0x566D104C51FB2DBEULL,
		0xF15499C637CB93A0ULL,
		0xEC70C9D2F8B8E521ULL,
		0x28B489175CD93AC4ULL,
		0x381C2BB3AC941D10ULL,
		0x4DC4189AB0EC5F02ULL,
		0x2034FE9AD9137AD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC34B452F0D32936AULL,
		0xAA9B8CF7EFF77E24ULL,
		0x7C7040BC7AE1ADF4ULL,
		0x344E94CF319D213DULL,
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
	compute_modulo_25519(&k1);
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
		0xB2F7855361D4E1D7ULL,
		0x6C01E655898DFE8FULL,
		0xC97E7B992F10CFF9ULL,
		0x0CA4593854C806E5ULL,
		0xC9360C1A452026E7ULL,
		0x7F35848E6E286FD0ULL,
		0x7F8E6BFDF83B65A3ULL,
		0xD50FC577B4206492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90FD5139A49AACCEULL,
		0x4DF39379E38E978DULL,
		0xB8A2834C07E1E63EULL,
		0x2CFBA8FD1196F4A4ULL,
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
	compute_modulo_25519(&k1);
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
		0x7123108FA17BC1A7ULL,
		0x8D8D5EA7E046CFC9ULL,
		0x39BDB16B2564477EULL,
		0x74DA8B1B478D3A93ULL,
		0x9351B57F70D3D30AULL,
		0x8FCFF1290F1CC982ULL,
		0xF7DC958E66419FA2ULL,
		0xD55736C5C1028D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F44017A60ED19E3ULL,
		0xE66B2AC01E8CB92BULL,
		0x047BE48E5321F99FULL,
		0x1FCCAC75EDEE2B8AULL,
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
	compute_modulo_25519(&k1);
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
		0xABB9011C31834722ULL,
		0xDD6C2F08A89F80D0ULL,
		0xDCD19DB9F092877BULL,
		0x22ED8FB42F7D98C2ULL,
		0xFBE29F17D3E5AA98ULL,
		0x08C3BE064AC5F092ULL,
		0x905A439A88BC2F9FULL,
		0x5498397D1CDD138AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5C9EA5A59A9B8DULL,
		0x2A7A63F7C20136A2ULL,
		0x4A37A6AA3C819917ULL,
		0x31861846784E7F54ULL,
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
	compute_modulo_25519(&k1);
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
		0x5DE443B9F1803C61ULL,
		0xE8BA91F7A67DEB90ULL,
		0xEB07AFEE1080D00CULL,
		0xB88148AB2C40FCBAULL,
		0x3D499E6748B82F0DULL,
		0xA10BD1BC119205F2ULL,
		0x2B924222311F689FULL,
		0x65BA54C79E0C234CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76D1C70EBCD73A9CULL,
		0xD07BB3E2422ACD85ULL,
		0x62BD81015B2A57BEULL,
		0x5229DE4CA20E3A09ULL,
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
	compute_modulo_25519(&k1);
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
		0xF1CB7719BF767206ULL,
		0x8955DC389585CCBFULL,
		0xF3DD10CE336B04A4ULL,
		0x296D582C79265AE4ULL,
		0x47ECE4F3CCAA554FULL,
		0xCCA8B78494EAE242ULL,
		0xFBA2FADB3144BC06ULL,
		0x274229CAAEAFBDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EF5734A20BF1C91ULL,
		0xEA6119E6B0636296ULL,
		0x4E0E4D57839EEDA6ULL,
		0x7D3F8C42673C8648ULL,
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
	compute_modulo_25519(&k1);
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
		0x797D73839DCC1CF8ULL,
		0x982D5BB4CF0B34CAULL,
		0x13BF4083BE2350EBULL,
		0xEDC270224DD21CD0ULL,
		0xBDAB89B6EF75BCA6ULL,
		0xEC647D4F4C36D54DULL,
		0x023A1E86429A5F8AULL,
		0x09EBC926443B2666ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0F3E4AB29461DE8ULL,
		0xAF17F57A1F2EDE54ULL,
		0x685FC871A10D7F8AULL,
		0x66C24BD06E99CFF4ULL,
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
	compute_modulo_25519(&k1);
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
		0xE1F612436DF97A6EULL,
		0x4740C4AF0A5FC163ULL,
		0x2C98E9780C5D4156ULL,
		0x127E597EC4D57E6CULL,
		0xE56CB6B1AFC582A3ULL,
		0xA7F0C1267FD30CEFULL,
		0xFC2749938EDDC2F5ULL,
		0x80B8CA65FAF4B042ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01930A3854AE172ULL,
		0x34FD706603B3ACFFULL,
		0x9A6DD55F414831CDULL,
		0x2DEC64A20527A85DULL,
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
	compute_modulo_25519(&k1);
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
		0xCFE95552476AC94FULL,
		0xC4E564A00B3C74C7ULL,
		0x89381D78FDCAEBC4ULL,
		0x67C4A39ECEAD59C3ULL,
		0xE241331A2438D3D4ULL,
		0x4542C8F391F1D388ULL,
		0xFC9DD3080296CB04ULL,
		0x717F09C7B0CF64F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6596EB33A7DA3D4DULL,
		0x0CCF38C7B521DB19ULL,
		0x08A570A9602D0E67ULL,
		0x40A017430D7655FBULL,
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
	compute_modulo_25519(&k1);
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
		0x4C048AECDA8F14BAULL,
		0x9BB01C4EA2EB31FDULL,
		0x30F6235F8D5FA6F3ULL,
		0xE7A62FEDF92C59B0ULL,
		0xE66BBD6632A2AB9CULL,
		0xE47D79C4B0BFF78BULL,
		0x1D3E3A3D85760DCDULL,
		0x9A9A456EF66E9BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8002A8185EB4915FULL,
		0x86502F80DF69F0C1ULL,
		0x8832C8815CE5B383ULL,
		0x5A8C7E668D97798AULL,
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
	compute_modulo_25519(&k1);
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
		0xA87477D92E1947A7ULL,
		0xFC5B2D69660DE753ULL,
		0x706F3E261C874510ULL,
		0x45AFBE491C0642D5ULL,
		0x4BBEA154BCA7A148ULL,
		0xAD591B9A601B7720ULL,
		0xDBCBDF2D0AFC3BB1ULL,
		0xCC37D62A0C5C3EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C06A6D2EFB3CDEULL,
		0xB7954653AA21961EULL,
		0x10B25ED5BDF82170ULL,
		0x15F98886F1B79A96ULL,
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
	compute_modulo_25519(&k1);
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
		0xCC01CA8BAF8897EBULL,
		0x16D51E49C188EE65ULL,
		0xBA805E049015E4BBULL,
		0x44EBB4A06AA4BB93ULL,
		0x803DF41655FE80C7ULL,
		0x13C448BC66536839ULL,
		0xBD5B4BD0F20B2BFDULL,
		0xDBBCD520C97FFE88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53405DC734FBA48ULL,
		0x05F7EA40F1EA66EEULL,
		0xD60D9F087DBE6C4CULL,
		0x62F3577E53A483DFULL,
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
	compute_modulo_25519(&k1);
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
		0xB7DD673EF81EBE4DULL,
		0xF8E34C5BD473F389ULL,
		0x4431E137A40D7CD0ULL,
		0x14FF724D8AB20256ULL,
		0x1D573E4331E1ADAAULL,
		0x647795B2C4ACDB56ULL,
		0x3591600EC0BA53E9ULL,
		0xAB91FE514B160145ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12D0A5385F9E8952ULL,
		0xE2A384E5061C8252ULL,
		0x37C623683FB5F175ULL,
		0x0CAB325EAFF6329CULL,
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
	compute_modulo_25519(&k1);
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
		0x6C1A20AD957245FAULL,
		0xFD00787F2C8207C1ULL,
		0xD6462E5084E585EEULL,
		0x8FA260DF47CEB882ULL,
		0xBAE5E59094FA521EULL,
		0xBDD3C025C3F99037ULL,
		0x77492F3DC84E925FULL,
		0x5E6C2F74CE6164D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A3A3423B29A7895ULL,
		0x2A6EFE1A438D7007ULL,
		0x8B23317C408F4025ULL,
		0x13B16C35EA43B00CULL,
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
	compute_modulo_25519(&k1);
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
		0x1877771AF9FCE501ULL,
		0xAB96C806B4EF14EBULL,
		0xB6959BF9D1751A72ULL,
		0x9680AB181578BA0BULL,
		0xBEF413DB05EDF5D1ULL,
		0x76AEB1DE7CA1C210ULL,
		0xEE4F23438F3046D8ULL,
		0x509A2D7C06021276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70B2699DDB4F63E2ULL,
		0x49852F0D34F1E367ULL,
		0x1654D801129F9E94ULL,
		0x0D636B80F9C777B3ULL,
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
	compute_modulo_25519(&k1);
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
		0x7DA03710DF4AE2FCULL,
		0x11BE428A035386D3ULL,
		0xE1FA7009F6DFA1C3ULL,
		0xA287A47F6DCBDB06ULL,
		0xFCB27611CC7FD2B6ULL,
		0xD8D0AA3BC2D31615ULL,
		0x3314635FDDCF0866ULL,
		0x2F7232A77589C8DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x001DBDB53A442B1DULL,
		0x40B78768EEA8CE17ULL,
		0x77013044E39AE107ULL,
		0x2D7B295AE03FAB90ULL,
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
	compute_modulo_25519(&k1);
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
		0x4F80E0C32DAD291AULL,
		0xE0F020DC4EA5F8B4ULL,
		0x019A231AC5F68D37ULL,
		0x2D76DA636C2E6C31ULL,
		0x9A1F5802007535B1ULL,
		0xC7FFE7C3888467A6ULL,
		0x1935CE450F6710E7ULL,
		0x4F3FA720B38EE2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3027F10F3F132315ULL,
		0x90EC87E2924D5B6FULL,
		0xBF96C15B0F430F9FULL,
		0x70E9A93E13641526ULL,
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
	compute_modulo_25519(&k1);
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
		0x1C84A63D27BF79CDULL,
		0x1D7C621ECCCBE086ULL,
		0x60BC62F88051AA2EULL,
		0x9E9B67DC51C60416ULL,
		0x4CA18D4080A8E5CDULL,
		0xB6BB0F449863C322ULL,
		0x1A86305D33E24CC8ULL,
		0x9D0C345828F24091ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C7F9DD040D199B8ULL,
		0x3D40A64D6B9AD79DULL,
		0x50A790CE33E90FF9ULL,
		0x6E6B2CF265BB99A0ULL,
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
	compute_modulo_25519(&k1);
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
		0xFC7A3603C144F37AULL,
		0x3004F5C5921D6197ULL,
		0x57E8E71221C221C9ULL,
		0x2910A474BBB4256DULL,
		0xE8DA6A0715E82351ULL,
		0x994C9EED13F5A1D9ULL,
		0x681E0DE2DF154FE5ULL,
		0xBD9DF8BA8ECF2267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CE5F31101BA35A8ULL,
		0xF1648CF6889367F0ULL,
		0xCC5EF6BF3EEBFDDDULL,
		0x4E839025EE7340C6ULL,
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
	compute_modulo_25519(&k1);
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
		0xA0CCDF57DF21FD0EULL,
		0xEC3EA83D97567111ULL,
		0x8BCB7292BF3E69FCULL,
		0x2A373BC4D73086A8ULL,
		0xEAB687621F541F9FULL,
		0x7F6A3AA32CBB0B46ULL,
		0x18682818E808DFBDULL,
		0x7ED52ED68C7A7229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77E4F7E8859EB167ULL,
		0xD6035C763B1A1D98ULL,
		0x2B416645308FA01DULL,
		0x7DDC2F9DB15D78C2ULL,
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
	compute_modulo_25519(&k1);
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
		0xEA80767A235453E5ULL,
		0xF1CB19A5F854722FULL,
		0xF6096BEDC850916CULL,
		0xA6248E0B8FF3AC38ULL,
		0x800CE9159BE1C449ULL,
		0x352B4DC143D64809ULL,
		0xFB8E4E7E0CCAF246ULL,
		0x9271C3438FBFA8A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC6B0FAF46D779FFULL,
		0xD638A4560A232398ULL,
		0x4D2912A3AE7087D8ULL,
		0x63078A12E666B4B6ULL,
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
	compute_modulo_25519(&k1);
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
		0xDF551CF6DAFA22C9ULL,
		0x596C946F7DA347C3ULL,
		0x66935A4B2A3977CEULL,
		0xA15681AAB075A685ULL,
		0x30B4C764DE9259CCULL,
		0x8940DCA7A0790565ULL,
		0x8E90819401DFAFF8ULL,
		0x7AF351328189FAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A2AB5EFE4B379D0ULL,
		0xB90D55514F9A14C9ULL,
		0x90069643716D96B2ULL,
		0x61748F29EAF0E212ULL,
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
	compute_modulo_25519(&k1);
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
		0x493A15F486BAC315ULL,
		0x4C2CCC7AEC550FA5ULL,
		0xB66C171F0AD1AAD0ULL,
		0x657260B42FCC69DDULL,
		0xEA2D05A58FA16D07ULL,
		0xA8C9663A92145CBBULL,
		0x0751D6330E886E44ULL,
		0x9D0A835D1F224959ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE8EC87D8B0F59CULL,
		0x5A11F92C9B5AD38AULL,
		0xCC91E2B333120901ULL,
		0x3501E086CEE34D14ULL,
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
	compute_modulo_25519(&k1);
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
		0x7814EDB28B3256CBULL,
		0x21677B702802DAC2ULL,
		0x12F797E6430B4F4EULL,
		0xFC8A8311AE7B00ADULL,
		0x1BC6AFA9C8BCF492ULL,
		0x0FCBE3ACCF2FB5D0ULL,
		0xDDF1D6A22C382D92ULL,
		0x4E61AE4129901391ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979300E6573EA652ULL,
		0x79AB4716E917D7A6ULL,
		0x04DD73F8D36212FCULL,
		0x1F0A60BDD9DDE854ULL,
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
	compute_modulo_25519(&k1);
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
		0xBF3181A57B4BEDC5ULL,
		0x0997AC9B911EB883ULL,
		0xA9D0A3222041B35CULL,
		0x1B493CBA0D3B43EAULL,
		0x73E211F5E75AE7A9ULL,
		0xAE0F274424BDF620ULL,
		0xD94DB7BBC2CD48A8ULL,
		0xADDC35C5636467FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C02C25D2CA54A4ULL,
		0xDFD780B905514154ULL,
		0xEB59E9010ABA7C65ULL,
		0x69F93806CE22B326ULL,
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
	compute_modulo_25519(&k1);
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
		0x1A7BDDC42A7448D5ULL,
		0x4BA2C67046476ED3ULL,
		0x7A63897F49D7CC86ULL,
		0x7ADE17A2B46C370FULL,
		0x81097CAB6449DF61ULL,
		0xBC77A67DC9A15FECULL,
		0x5003BF36A76351B8ULL,
		0x662B3525C4C75077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E45F350D6B7388ULL,
		0x45657D1C343BABEEULL,
		0x5AF1EB9C2295EDF2ULL,
		0x2547FB3DEA0228C5ULL,
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
	compute_modulo_25519(&k1);
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
		0x2FEAE01B3854DC6CULL,
		0x6F51D34BEC437C8DULL,
		0x0D31666B239073DBULL,
		0x3D42A51FB45148B3ULL,
		0x50BB177F02EFA654ULL,
		0xA3D2699AD8E35829ULL,
		0x274FE3A16335C654ULL,
		0x2B57ADA5122B0733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BB05CF5A7E78DDBULL,
		0xC08D80481E0292AFULL,
		0xE30D305FDD8BE46BULL,
		0x2C466BA066B45A4AULL,
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
	compute_modulo_25519(&k1);
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
		0xF0F82C9FB53CB812ULL,
		0xB7420B537DBA34DAULL,
		0x55ED9ABAC485AD0DULL,
		0x4B843B73CCEB90B4ULL,
		0x111D4DCA80A61521ULL,
		0xCA2140A0D71C0077ULL,
		0xAB45B9C2A405F907ULL,
		0xC39AE57939E34CB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B51B8AECDE3DF46ULL,
		0xB831A3336BE24687ULL,
		0xC2472D9F1D68A435ULL,
		0x54824B7264A8F35FULL,
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
	compute_modulo_25519(&k1);
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
		0x44BEA77895D7D1FAULL,
		0x72926A2186E187A1ULL,
		0x9C99FB6BC6894B82ULL,
		0xE6AF32FA8F7EEAD8ULL,
		0x6C665C705120D193ULL,
		0xF6888301CAC60D8CULL,
		0x621D9E5399AE2FDAULL,
		0xA75E69933D89F8FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF06024A0B6F195ULL,
		0x0AD5DC65A0478A79ULL,
		0x2CFF7BD496646603ULL,
		0x3EB2DED5B1F9E09BULL,
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
	compute_modulo_25519(&k1);
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
		0x23EF0790E0C24F59ULL,
		0x78E47275915B9297ULL,
		0x6FB0E540B3C2A79EULL,
		0x7A299C8DC9C37677ULL,
		0x64EFF5E0F41083CDULL,
		0xCCAFD970A357A3B8ULL,
		0x9F1D861E4CCD1364ULL,
		0xC1943C2FBF4379EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F8D86F51B35E415ULL,
		0xDAFEB92DD05DDFF6ULL,
		0x0E12CDC01A338894ULL,
		0x362A8BA42DC79009ULL,
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
	compute_modulo_25519(&k1);
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
		0xB1856A6D3C74846FULL,
		0xAE5EA5FCFD0C1621ULL,
		0xFEDAE92F3F2B0E68ULL,
		0xED1581EE9E959931ULL,
		0x8EA6845118F7DCD5ULL,
		0xDD79FCFB169E39DFULL,
		0x1343E536BFB505BEULL,
		0x1F8853A6932BF22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3D0E76F13F4CDEULL,
		0x8E7A33425888AD50ULL,
		0xDAEEEF4FB409E8BDULL,
		0x1B51ECA8771B8C08ULL,
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
	compute_modulo_25519(&k1);
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
		0x3BF8249F8761027DULL,
		0xE366A4C410C87746ULL,
		0x590A905E4025BE7AULL,
		0x00A413D63C168D1FULL,
		0x4FE79C82D4A45694ULL,
		0x86E5FD254F7C53BDULL,
		0xAE3D09F7DEA5FBB1ULL,
		0xD9F952C1660D6FB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1859600B17C5E135ULL,
		0xE98A384DDD3CE560ULL,
		0x361A0B294CC91AD4ULL,
		0x5BA65C8B621521CBULL,
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
	compute_modulo_25519(&k1);
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
		0xB922841142FB26ADULL,
		0x666BD74CBA857233ULL,
		0xDBB4ABDF8E838D31ULL,
		0xA76DEDF139F73F83ULL,
		0x88E1CA9161C377A9ULL,
		0x0B410087C948FB5DULL,
		0x0ECF7D4F54082231ULL,
		0x4A861F75764A4F73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA695A5C5FEEB78ULL,
		0x1211EB749B5AC216ULL,
		0x0E8145A607B8A079ULL,
		0x37569960C8FF0A98ULL,
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
	compute_modulo_25519(&k1);
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
		0xE39E4368433D59EAULL,
		0xEBFC2B343BC1968BULL,
		0x1660B6B11CA2D889ULL,
		0x2E2EBDE9DD7EDA09ULL,
		0x870AA206E3315C2CULL,
		0xA0F2B69AD563C6BEULL,
		0xF69A4A1BA7029509ULL,
		0x040B669ABC64CFF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF32506DFC910885ULL,
		0xD003462FE89116D3ULL,
		0xB147B6CBE704F7F7ULL,
		0x47DFF8E1D475B8FDULL,
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
	compute_modulo_25519(&k1);
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
		0xBEC0573B66A9374EULL,
		0x1A9749ED20A9B4EDULL,
		0xFBB78C5E07347B7DULL,
		0x3D9AE4F85E89DB63ULL,
		0x4195C6D74553AC3FULL,
		0x94A8974EDE8C883FULL,
		0x9CA250E094FA4572ULL,
		0xA55021942FFCCC00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AFBDB2FB114CC4BULL,
		0x2B9DBFA22985EE51ULL,
		0x3BCF8DB4245ACA7FULL,
		0x477FE0F77E10237BULL,
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
	compute_modulo_25519(&k1);
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
		0x72CCB295FC35CFEDULL,
		0x9EB70C31248C6F91ULL,
		0x4467AE28D7BB31FCULL,
		0x29E6D2332BC36A82ULL,
		0x4875FD51A3F66EA5ULL,
		0xC497763A10A73FFCULL,
		0x9678615726701C41ULL,
		0xD5904BF29AA83ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34504CB452CA4118ULL,
		0xCD3298CF9D5FEF04ULL,
		0x9A4621188C5F63BFULL,
		0x5D52183620BCBD9EULL,
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
	compute_modulo_25519(&k1);
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
		0x4BBF6F9E14E577F7ULL,
		0x8D6086EBC03A945CULL,
		0x6B8BFEA2B6E926B1ULL,
		0xF1A9C8B3FD531A58ULL,
		0x0804D2E6A114E7FFULL,
		0x105F78B05CC57C18ULL,
		0x0E2A6CE5134C024BULL,
		0x9EFBADADDFC13A24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C76BDD9FDFFEB74ULL,
		0xFB8C7119858AFFEDULL,
		0x85D828A394317DD5ULL,
		0x0B0590833401BBB2ULL,
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
	compute_modulo_25519(&k1);
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
		0x26FBB321E85C29D8ULL,
		0xC5B7E95424EB852FULL,
		0x6BB162581268BBBEULL,
		0x40DE5A6E0131FADFULL,
		0xAE398534F60D55C2ULL,
		0xBDEC0FAE9CD54A3DULL,
		0xE109727830F0204BULL,
		0x9CF349A5194156BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x038578FE6E56E821ULL,
		0xF6C23D3F6C948A57ULL,
		0xD318602F560D86FCULL,
		0x0CFB48EFC0E4DAC2ULL,
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
	compute_modulo_25519(&k1);
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
		0x45059D858341756DULL,
		0xF8CC02259CE73E69ULL,
		0x7252FCD0FDB62602ULL,
		0xCBB95C398E76F3E5ULL,
		0x24F90CF94771C2E8ULL,
		0xE84812CDB86BA0BFULL,
		0x411213025FC9447CULL,
		0xB02BBD0F7901FA52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FD8A861E2467CCULL,
		0x737ECCAEFCE11AC8ULL,
		0x1B01CF2B3596508DULL,
		0x72376C8584C21C1BULL,
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
	compute_modulo_25519(&k1);
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
		0x50BC52A5B5FAA642ULL,
		0xEA77A37CD5102994ULL,
		0xCE704099770A05D8ULL,
		0x3E52EE57AED3B7CBULL,
		0x13ACFDEC0A5D986DULL,
		0x143B96A1E77A9A58ULL,
		0x2387E62B888923FEULL,
		0x515CAD2FE138CFA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C6A03AF3FDF4838ULL,
		0xEB4FFF85314312A7ULL,
		0x149C6B0FBB655D8FULL,
		0x5214A3731D428A4FULL,
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
	compute_modulo_25519(&k1);
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
		0x8F0295F0143CD607ULL,
		0x446E59752104AF04ULL,
		0x92D5EA4ACF215803ULL,
		0x7C6936327D0DDE94ULL,
		0xD4117E0EE9757591ULL,
		0xE6D6AE85ECA22C06ULL,
		0xA095067935A131B6ULL,
		0xC11E466294E8914EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x099B4C26BBAC4DDBULL,
		0x884C415641173808ULL,
		0x68F4E048C50EB929ULL,
		0x26E7A8D497937040ULL,
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
	compute_modulo_25519(&k1);
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
		0x168C09F638AAA6B2ULL,
		0x5B52581309B26AFEULL,
		0x42ED27FE3E9254CEULL,
		0x5C1321375A9E5272ULL,
		0x9146D3BD439ACA7BULL,
		0x5D7D388756A7E1D6ULL,
		0xD26B2B43435AE46EULL,
		0xFF89CF8C433E872FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70F780E41A4BA98ULL,
		0x3BE8BC29E69DF0D7ULL,
		0x7ED593FA3E103D30ULL,
		0x4A87F00955E6638BULL,
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
	compute_modulo_25519(&k1);
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
		0x81FC7F4649E76813ULL,
		0x8D61FFB84DE52B46ULL,
		0xE36A320DA2DD4AE6ULL,
		0x09D65A6C959DF1A5ULL,
		0x6574098BF8363E3EULL,
		0xA34887D13929D680ULL,
		0x7E1A72EC9BEA3355ULL,
		0x5FE9EB425C9A8B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9135EA0D21F4A75BULL,
		0xCA2628C6CA1B0255ULL,
		0x9B57412CC7A0E99CULL,
		0x468F4646548EA328ULL,
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
	compute_modulo_25519(&k1);
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
		0x28DE3D6CD3C7A845ULL,
		0xBDB33B13D912A2E5ULL,
		0x7A33BB18CC0A4A77ULL,
		0x7CCCE20CEDDCE4BEULL,
		0x4D68E75F81297B3CULL,
		0x12A4E9454E6310E0ULL,
		0x72388444B8C5D709ULL,
		0xEE8841D824575893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6709599FFEFF872ULL,
		0x822DDB5D7BC72430ULL,
		0x6E975D4C396835D0ULL,
		0x6506A82252D40AA1ULL,
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
	compute_modulo_25519(&k1);
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
		0x12C6D3E1F5AD948EULL,
		0xBF0E3D0E7A8A01D7ULL,
		0x072E03BF2DEA2263ULL,
		0x7360C24133A51679ULL,
		0x05C355110F8B3AB6ULL,
		0x91289349648F1D16ULL,
		0x0F28ED05DD0C0B2BULL,
		0x9C31505A6F8B1183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDC5746A44584F0FULL,
		0x4B1419F367C8531BULL,
		0x4741329DFDB3CADBULL,
		0x22B2AFADC249AFEDULL,
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
	compute_modulo_25519(&k1);
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
		0x172E10ABE045CF50ULL,
		0x29B2EEB8C076420FULL,
		0x6F05D32E6EB68AFAULL,
		0x0BEB13F47E51F2A0ULL,
		0x03BDF1D568D5AF0EULL,
		0x7FEDC799C75CC1CAULL,
		0x0EE1806E74E7480FULL,
		0x3ADAE36FAAA7469BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA55FF6596FFDCCA7ULL,
		0x26FE8F8C583B060BULL,
		0xA47EE393C90B3D47ULL,
		0x4868D687D3266DA4ULL,
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
	compute_modulo_25519(&k1);
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
		0xD8AFDCE187011B27ULL,
		0x0FD5A486553C668FULL,
		0x8976786A3E13C172ULL,
		0x2B0F247B91E69C1FULL,
		0x33C2D043FAC749BFULL,
		0x7B420461D84C679DULL,
		0x7D7D8CEF0089A20FULL,
		0xE02266315D7F50EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x879AC6F8C0961267ULL,
		0x5BA24B0C7093C7E5ULL,
		0x2A1963E45281CFBEULL,
		0x702A4FCF72CC9F60ULL,
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
	compute_modulo_25519(&k1);
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
		0x6BCC7316301BE9AEULL,
		0xE91D34B966572F84ULL,
		0x3312ECC234DAF1EBULL,
		0x44F8977273F2BC89ULL,
		0xE38B534E79A59D4CULL,
		0x3A7F92A6FD55AD26ULL,
		0xA9319883E027641AULL,
		0x7846C2DDBAF95ED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x327AD0BC3EB145A2ULL,
		0x980CF983010EE34AULL,
		0x506F90557AB3CDD0ULL,
		0x1F79845C34F6D01AULL,
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
	compute_modulo_25519(&k1);
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
		0xEE5DF35C97049283ULL,
		0xC597B45390A17661ULL,
		0xBE4BFC68D47902A4ULL,
		0x72C878986AC55FFBULL,
		0x245D4104C31F7D0AULL,
		0xB7C97798ED4FB129ULL,
		0x8EC80ECED15B7594ULL,
		0x96F4CBA104DA27FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54359A118DB12556ULL,
		0x0D7F7506CA75C27DULL,
		0xEFFE2F1BE80C76B8ULL,
		0x5B1EB27F23274FEAULL,
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
	compute_modulo_25519(&k1);
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
		0x5EF41B2A0824FF6AULL,
		0x99658EA8C2A08C97ULL,
		0x7FBDFBFE506E0663ULL,
		0x875ADAB42E1D6A43ULL,
		0x5C8A5C0A597CBC73ULL,
		0x9BCB3DADFE734EB0ULL,
		0x70E260DED54F7B30ULL,
		0x398E65FAA7FA20FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7DC4B350A8F9D2ULL,
		0xB990B67C87BE3AC5ULL,
		0x41585D11FA3A4F9AULL,
		0x127DFDE91D3E4F96ULL,
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
	compute_modulo_25519(&k1);
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
		0xAB0F7C7B24B524A8ULL,
		0x663D73D74B5249F5ULL,
		0x5904AE0EE0498178ULL,
		0xB88203F7C6C9224CULL,
		0xC95C33844726EE8CULL,
		0x0F5BEF5ACBD70403ULL,
		0xE0ADA0A98C406034ULL,
		0xA5A37F555BD04A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EBF221DB47C9126ULL,
		0xADE2FB518D3CE285ULL,
		0xB2CA8739B1D7C932ULL,
		0x4EC6EAA367B42FA5ULL,
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
	compute_modulo_25519(&k1);
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
		0xDDF209EBCEF6E9F6ULL,
		0x112EE9AD224A0370ULL,
		0x8ED15615A110934FULL,
		0x2CCC107E508BFE6BULL,
		0xB0409EFD1DD5A6CAULL,
		0xB0A1244AF526B887ULL,
		0x7071CD9DBC3CBAC9ULL,
		0x24A03C8C2A39CD41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0789A37E3CADACC3ULL,
		0x491A4CCD86096795ULL,
		0x3FB5DB7F92144D3FULL,
		0x1C950D4C95207622ULL,
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
	compute_modulo_25519(&k1);
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
		0xEA3DA11D9779EFB8ULL,
		0x38E149672DA9FEE5ULL,
		0x3321E8290484D045ULL,
		0x67C4A647B1478955ULL,
		0xD215F1903695B57CULL,
		0xCF68748108693A6CULL,
		0x8ADD83FDE2AB6893ULL,
		0x8A484123C41D1C6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x197F7C85B1B2E32BULL,
		0x0262948E6D48AB0DULL,
		0xD0037FD8A9F65636ULL,
		0x6E7E5196CD99C1E3ULL,
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
	compute_modulo_25519(&k1);
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
		0x3F5FD66422E8D2BFULL,
		0x3884EE83E630C138ULL,
		0x160CE6F0CFD3BB50ULL,
		0xABB4E022B129DEF7ULL,
		0x9C2ACCA0454165E6ULL,
		0xB3D0C18447B29B55ULL,
		0xE4193BB2D0AAA00CULL,
		0x3A42F912202F06C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DBA362E6A9DF439ULL,
		0xE981A8268AB3CFEDULL,
		0xF1CBC37BC9277D32ULL,
		0x51A5D8D37824DF98ULL,
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
	compute_modulo_25519(&k1);
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
		0xF0602930E3C60B4EULL,
		0x73F41CCF903AA744ULL,
		0xA7C3A6C64EAF6929ULL,
		0xEF193DD00EFAB83FULL,
		0x2853859AD80BB123ULL,
		0xC39A50A9BCE5BC9FULL,
		0x3372BD6EE6F521FAULL,
		0x9EF4635239262C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC5FE2CF5825A23ULL,
		0x7CDC16019A54A6E4ULL,
		0x4ACBC53C97127462ULL,
		0x075FFC048AA54BB5ULL,
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
	compute_modulo_25519(&k1);
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
		0xCC9D179D81A2CA2CULL,
		0x49BBF45342C387ACULL,
		0x03791F5175C45D9AULL,
		0x1699AD1A91839AF1ULL,
		0x3BA5293FFDC6637FULL,
		0x4873D9D7C5CE3417ULL,
		0x254547777671DB3DULL,
		0x0B5546FC2C2BE765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA721371D2D158F3FULL,
		0x0AEE4A5A9F5F431FULL,
		0x8BC1BB0D0AAAE8B3ULL,
		0x454236892007F3F4ULL,
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
	compute_modulo_25519(&k1);
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
		0x51DE074D360407D6ULL,
		0x5DA9A49D123FB601ULL,
		0x7CDF16FB8942808BULL,
		0xCAD06BD69DF84723ULL,
		0x0ECFBC25F78F3549ULL,
		0x1BC4FF93FDEC1BDEULL,
		0x7BE3EA248415C2E4ULL,
		0xDD282BB0310D1B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84B3F4EFF545F5A5ULL,
		0x7CE79494C34BD8F7ULL,
		0xE0B3D867247D6E67ULL,
		0x1EC6E7FDE5EA534DULL,
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
	compute_modulo_25519(&k1);
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