#include "../tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Key Subtraction Test\n");
	curve25519_key_signed_t r = {};
	curve25519_key_t k1 = {.key64 = {
		0x0D6B627AE746F078ULL,
		0x38A979832C676D43ULL,
		0x46ED6D9910E59F97ULL,
		0xD0AAAD0D960991E8ULL,
		0xEF2A792145D8E1F2ULL,
		0x8DF7BB4E9561508CULL,
		0x85E39C4224E479B4ULL,
		0x68B89A572DAA63D0ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x7D68BAF9A33315DBULL,
		0xFDD02A717DE2B55EULL,
		0x647332897D6964C6ULL,
		0x8577A82D3E16D858ULL,
		0x7D1C876A8D5935F1ULL,
		0x857661BF1F9FEBB5ULL,
		0xE226DEB4D4D4814BULL,
		0x460C94B712205C95ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x9002A7814413DA9DULL,
		0x3AD94F11AE84B7E4ULL,
		0xE27A3B0F937C3AD0ULL,
		0x4B3304E057F2B98FULL,
		0x720DF1B6B87FAC01ULL,
		0x0881598F75C164D7ULL,
		0xA3BCBD8D500FF869ULL,
		0x22AC05A01B8A073AULL
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
		0x6B61A1CEBA8ABEAFULL,
		0x800AA46F11A7919EULL,
		0x482622B5DEA4AB24ULL,
		0xE5C9E56036EC0BB4ULL,
		0x56F5B4425F820841ULL,
		0x69A5C3C99D8A59C2ULL,
		0x9F020961F7AE0A76ULL,
		0xF672BF0E74C74480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58B981FE2841C69ULL,
		0x8DF965A7B320126AULL,
		0xA0828BDD55E0038DULL,
		0x66DA8F31DCC42B97ULL,
		0x920871B34BE2F42CULL,
		0x9B8556B018A464EAULL,
		0x946203027DD617F5ULL,
		0x4C5BB5EA07EA6059ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5D609AED806A246ULL,
		0xF2113EC75E877F33ULL,
		0xA7A396D888C4A796ULL,
		0x7EEF562E5A27E01CULL,
		0xC4ED428F139F1415ULL,
		0xCE206D1984E5F4D7ULL,
		0x0AA0065F79D7F280ULL,
		0xAA1709246CDCE427ULL
	}};
	sign = 0;
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
		0xF1C2183A5A7521A4ULL,
		0x5DF32026C54DF420ULL,
		0x099EF385123A553EULL,
		0x66695147F755A09BULL,
		0xA89A5A861D0B74EDULL,
		0xD010E57BD0D22C20ULL,
		0x4A7BCC5381AF62B3ULL,
		0x67AA60D08DE4103FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FB112E4C725ED4EULL,
		0xC31A5410A5234556ULL,
		0x85E9E093AD241731ULL,
		0x270ADD8CAB66D3E1ULL,
		0x16205942452C1A78ULL,
		0x19261784B184CB8AULL,
		0x5378523E6FF2388BULL,
		0x88A6349A2186B6FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92110555934F3456ULL,
		0x9AD8CC16202AAECAULL,
		0x83B512F165163E0CULL,
		0x3F5E73BB4BEECCB9ULL,
		0x927A0143D7DF5A75ULL,
		0xB6EACDF71F4D6096ULL,
		0xF7037A1511BD2A28ULL,
		0xDF042C366C5D5942ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6105BA78948992F3ULL,
		0x5E5E76CC114D8A4BULL,
		0x4678187985961B72ULL,
		0x8CB528D08DFBFEBFULL,
		0x592159C11441CB9CULL,
		0x4FC1588EEB9F1754ULL,
		0x45366AD0B2BF3B07ULL,
		0x86679DF82F2E2136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB5BA1DFC7DD222ULL,
		0x03CEFA8E6244B6FBULL,
		0x3DEF6D7315C594BAULL,
		0x6E33EAD1C2AF2244ULL,
		0xAFA7FD3E772677D9ULL,
		0xB537B059952AD617ULL,
		0x02B12A973DF0E64DULL,
		0x28C2C7E149F8B998ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0650005A980BC0D1ULL,
		0x5A8F7C3DAF08D350ULL,
		0x0888AB066FD086B8ULL,
		0x1E813DFECB4CDC7BULL,
		0xA9795C829D1B53C3ULL,
		0x9A89A8355674413CULL,
		0x4285403974CE54B9ULL,
		0x5DA4D616E535679EULL
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
		0x672B939EEE79CE76ULL,
		0x441B550379F31C10ULL,
		0x6CB0C2C9C04102CCULL,
		0x9D80A0703E790CF9ULL,
		0x9CB912F8C5BC78AEULL,
		0xB9821F91C45B5995ULL,
		0x16A970CAD58D3BA5ULL,
		0xECF1304D58B60917ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB4FA0CE99D4E3FULL,
		0xAC4DFF8F79837AD9ULL,
		0x6D1859CA33237832ULL,
		0xB2493E02D8DD237DULL,
		0x80BB120CDEC1347FULL,
		0xDC24AECB71B2361EULL,
		0x35EE939DDF3D4DD9ULL,
		0xB624DDCBD415A429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B76999204DC8037ULL,
		0x97CD5574006FA137ULL,
		0xFF9868FF8D1D8A99ULL,
		0xEB37626D659BE97BULL,
		0x1BFE00EBE6FB442EULL,
		0xDD5D70C652A92377ULL,
		0xE0BADD2CF64FEDCBULL,
		0x36CC528184A064EDULL
	}};
	sign = 0;
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
		0xF95691C3AD1B33ABULL,
		0xAC6B27E02E13B6ABULL,
		0x9A10D19C20106A02ULL,
		0x9F944880A00DFAC5ULL,
		0xEDE23709BA64CBB1ULL,
		0x146DC0D2EEF7BA03ULL,
		0x45F7BB1D0C49FB80ULL,
		0xB022DDA936C426B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C4AA838D45D7DD2ULL,
		0x169CF26690DEDBADULL,
		0x2914DD30D0E68917ULL,
		0x1257BD20EA5C5B44ULL,
		0x1C560C11E585C985ULL,
		0x5F2DF10D020D990BULL,
		0x2F3C87F9FBAF70FEULL,
		0x80C99C7D88689203ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D0BE98AD8BDB5D9ULL,
		0x95CE35799D34DAFEULL,
		0x70FBF46B4F29E0EBULL,
		0x8D3C8B5FB5B19F81ULL,
		0xD18C2AF7D4DF022CULL,
		0xB53FCFC5ECEA20F8ULL,
		0x16BB3323109A8A81ULL,
		0x2F59412BAE5B94B3ULL
	}};
	sign = 0;
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
		0xC73A76B9705E6A07ULL,
		0xB8BD082F501113DBULL,
		0x975FD505970DE878ULL,
		0xDBC59267DC26240CULL,
		0xF9DA45117CCF462CULL,
		0x7385C15494416203ULL,
		0x9EF93F3B7E523C4DULL,
		0x433E537050A39A28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA1BA23D566AA6AULL,
		0x42C52306A4762C90ULL,
		0xB28650E29F374176ULL,
		0xCA22F65874580C4BULL,
		0x1C9099D653A97425ULL,
		0xFF46C119C143D398ULL,
		0x02577CFD5F47EAC4ULL,
		0xCC991C7811258BCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B98BC959AF7BF9DULL,
		0x75F7E528AB9AE74BULL,
		0xE4D98422F7D6A702ULL,
		0x11A29C0F67CE17C0ULL,
		0xDD49AB3B2925D207ULL,
		0x743F003AD2FD8E6BULL,
		0x9CA1C23E1F0A5188ULL,
		0x76A536F83F7E0E5EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9BF66582FC099DB0ULL,
		0x0A4E07603393DE4BULL,
		0x1AA942EB93E659BEULL,
		0x3182EDE826A2970BULL,
		0xF53DA80E0CAAF756ULL,
		0x375377F0727EC314ULL,
		0x021FDE3BBE4E6E37ULL,
		0x6B31F489EBDE7884ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x379E6A907FE67DB6ULL,
		0x6735864FFAD20CDDULL,
		0x094DBBD876DA248EULL,
		0x7B9A21725D19527FULL,
		0x3FC2D853B87240E2ULL,
		0x948052C85BF41CC5ULL,
		0xB432E8BF0C7463AFULL,
		0x868626BED6F34562ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6457FAF27C231FFAULL,
		0xA318811038C1D16EULL,
		0x115B87131D0C352FULL,
		0xB5E8CC75C989448CULL,
		0xB57ACFBA5438B673ULL,
		0xA2D32528168AA64FULL,
		0x4DECF57CB1DA0A87ULL,
		0xE4ABCDCB14EB3321ULL
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
		0xE2F87F212E050554ULL,
		0xA0FA9110DB1B2FDBULL,
		0x92A87653A5909E50ULL,
		0xB71AFDA4590E4058ULL,
		0xCE9A74B82E0BF2B9ULL,
		0x317539EA001638F8ULL,
		0xC84B18EE7E794ABAULL,
		0x1C416B1FE3AC307EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52088DA0F1C65197ULL,
		0xD84666008D33D910ULL,
		0xA8499E61896370E3ULL,
		0xB636FA1FC73AEF7DULL,
		0x5FE9842A6ED3AA00ULL,
		0xECD17BD5CB23B74FULL,
		0x1E3FFE72D7143DF8ULL,
		0x1AD2C347AC3E4E72ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90EFF1803C3EB3BDULL,
		0xC8B42B104DE756CBULL,
		0xEA5ED7F21C2D2D6CULL,
		0x00E4038491D350DAULL,
		0x6EB0F08DBF3848B9ULL,
		0x44A3BE1434F281A9ULL,
		0xAA0B1A7BA7650CC1ULL,
		0x016EA7D8376DE20CULL
	}};
	sign = 0;
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
		0x820E9D38624DE801ULL,
		0x949957286B0F3A30ULL,
		0xB1C4C56A83896884ULL,
		0x6882740FDD1976F8ULL,
		0xACA96EF27B070A9DULL,
		0x13BAAB6EB0F94DEFULL,
		0x2F55E531D907328AULL,
		0x9225486E090C0FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41612FA3091E6C61ULL,
		0xC9B2B2F346B888E6ULL,
		0xC59DFC82C0F90A40ULL,
		0x9476E0BC14A7D401ULL,
		0xBC07AF89B6A46AB0ULL,
		0x5258AD1A615C4B45ULL,
		0x85A34EC2412C07D7ULL,
		0x5BE9FE18D67B96CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40AD6D95592F7BA0ULL,
		0xCAE6A4352456B14AULL,
		0xEC26C8E7C2905E43ULL,
		0xD40B9353C871A2F6ULL,
		0xF0A1BF68C4629FECULL,
		0xC161FE544F9D02A9ULL,
		0xA9B2966F97DB2AB2ULL,
		0x363B4A55329078F9ULL
	}};
	sign = 0;
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
		0xE9F80D331F431F32ULL,
		0x615161B860381DBEULL,
		0x54E9B01B09E207C5ULL,
		0xFAC93370F6580D58ULL,
		0x64754704B01303E1ULL,
		0x837575431325785DULL,
		0xA264035D10860BBDULL,
		0xCB36B5532C7D1C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DD44287123F7F5CULL,
		0x2CF43FE6B843ED45ULL,
		0x2E875E1029DD7ADCULL,
		0xD010A06581E76056ULL,
		0x1097D58FE2E63C46ULL,
		0x49438DD9DCA28BBEULL,
		0x5502E2478BCD5C44ULL,
		0xD923444366CD9F40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C23CAAC0D039FD6ULL,
		0x345D21D1A7F43079ULL,
		0x2662520AE0048CE9ULL,
		0x2AB8930B7470AD02ULL,
		0x53DD7174CD2CC79BULL,
		0x3A31E7693682EC9FULL,
		0x4D61211584B8AF79ULL,
		0xF213710FC5AF7D3DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6702C141AC00B479ULL,
		0xC2EB2442E1D1C98EULL,
		0xE31CA54B60B572C4ULL,
		0x12466E16BF7C050DULL,
		0xFB83C32CE02ABF44ULL,
		0xFC09680F7EF62664ULL,
		0x0EBB8041F12F6FC4ULL,
		0x6F88579F48554CEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD5A16A0E934F665ULL,
		0xADB7899D115361A2ULL,
		0x8C32F38823E9E590ULL,
		0x9707447FF11211A5ULL,
		0xAC6039A70D34AE4CULL,
		0x310E602E8E2144C8ULL,
		0x28DB07888D0B9267ULL,
		0x1DB47B8FCB27E604ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89A8AAA0C2CBBE14ULL,
		0x15339AA5D07E67EBULL,
		0x56E9B1C33CCB8D34ULL,
		0x7B3F2996CE69F368ULL,
		0x4F238985D2F610F7ULL,
		0xCAFB07E0F0D4E19CULL,
		0xE5E078B96423DD5DULL,
		0x51D3DC0F7D2D66E8ULL
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
		0x295DF1C866229AAEULL,
		0xA8194C5CD8EB24BCULL,
		0x0A0B98B0D90402A5ULL,
		0x8356A5A55DBD7ED2ULL,
		0x1A949301F2C30B9FULL,
		0x563F5AD9B84D772AULL,
		0x4C04D2EAD7D9FFE3ULL,
		0xB54E9D6DD973C720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1FC416980596EE8ULL,
		0x0A5BE247C5F7A59EULL,
		0x71F8746CB3A89AD9ULL,
		0x4BDE6FA5C27656A5ULL,
		0x1B1E747AA7E82C8FULL,
		0x58801E1974557BCCULL,
		0x1108FBCA18A562B0ULL,
		0x25936CC9F8275E7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8761B05EE5C92BC6ULL,
		0x9DBD6A1512F37F1DULL,
		0x98132444255B67CCULL,
		0x377835FF9B47282CULL,
		0xFF761E874ADADF10ULL,
		0xFDBF3CC043F7FB5DULL,
		0x3AFBD720BF349D32ULL,
		0x8FBB30A3E14C68A1ULL
	}};
	sign = 0;
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
		0x24A52ACA817159F8ULL,
		0x2E7D6D704808AF84ULL,
		0x5BF618FDCAF172F7ULL,
		0x0141199F914031ABULL,
		0xD4809B64A44080F4ULL,
		0xEEE01D26A480491FULL,
		0x650202E3AC203571ULL,
		0xE03D04D1C0DF6606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3D52E16B96CC15ULL,
		0x6105E014D35545DAULL,
		0xCDF83C59C26A0CD0ULL,
		0xA3B389E8FB218289ULL,
		0x04096BA6C4DA1D1CULL,
		0xF1A91E47F47B60D6ULL,
		0xAFBC021A7FB4670EULL,
		0xFFEBAD4CDDF950AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3767D7E915DA8DE3ULL,
		0xCD778D5B74B369A9ULL,
		0x8DFDDCA408876626ULL,
		0x5D8D8FB6961EAF21ULL,
		0xD0772FBDDF6663D7ULL,
		0xFD36FEDEB004E849ULL,
		0xB54600C92C6BCE62ULL,
		0xE0515784E2E61556ULL
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
		0x276340E98E7DADF8ULL,
		0x86BBCA800DDCB148ULL,
		0xB9D33FF25C88E794ULL,
		0x9D9763BBB3C050FEULL,
		0xE94D81DD3809A085ULL,
		0x8965208F89599261ULL,
		0xCEE1BCCF2B123868ULL,
		0xA2BD6DC99821E33DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x621CC285C8E940D2ULL,
		0x4752A23086C87933ULL,
		0x198918334F52E730ULL,
		0x86790E0B43D15592ULL,
		0x9CDC2A1DE77AB288ULL,
		0x2D7F5B0200870D71ULL,
		0x9D05E34F7A166824ULL,
		0x97196BB4917E3905ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC5467E63C5946D26ULL,
		0x3F69284F87143814ULL,
		0xA04A27BF0D360064ULL,
		0x171E55B06FEEFB6CULL,
		0x4C7157BF508EEDFDULL,
		0x5BE5C58D88D284F0ULL,
		0x31DBD97FB0FBD044ULL,
		0x0BA4021506A3AA38ULL
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
		0x3D8C632D99BB36F6ULL,
		0x287177FBA088AB84ULL,
		0xC9D9A16A20BB472FULL,
		0xAB061D650ACDC4B2ULL,
		0x0F03CC780992E121ULL,
		0xFAE7AD966C31F84FULL,
		0x305C6E0E9DDCA143ULL,
		0x09FF46D6FFA83D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C50081388E3AA3ULL,
		0xEB0C0EAAD916C906ULL,
		0x662A6F1BBD41BFC6ULL,
		0xB57ABF681B89CD96ULL,
		0xB616B8F164FD2142ULL,
		0x957046949F059A54ULL,
		0xC5021CB92BA3D8D9ULL,
		0xF10DE0AB7835C684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABC762AC612CFC53ULL,
		0x3D656950C771E27DULL,
		0x63AF324E63798768ULL,
		0xF58B5DFCEF43F71CULL,
		0x58ED1386A495BFDEULL,
		0x65776701CD2C5DFAULL,
		0x6B5A51557238C86AULL,
		0x18F1662B877276CCULL
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
		0xB7156F3EA4ED9C83ULL,
		0x4657FD910B4B3290ULL,
		0xA0362199EA75FC0CULL,
		0xBE0470B08F88DA8CULL,
		0x3804BFF5E041F10BULL,
		0xC2455332F52DB69EULL,
		0xFCA908BD0ADAC860ULL,
		0x334C210386209802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45D8CD2D6C1E8660ULL,
		0xD5373EC0AE24869FULL,
		0x2AC82134F26D172FULL,
		0xADD6E49389F33C14ULL,
		0x301C9E020B88231AULL,
		0xF1D440D1780B81D6ULL,
		0xF1AC0FF469815134ULL,
		0xAE1D2777F9E9DDD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x713CA21138CF1623ULL,
		0x7120BED05D26ABF1ULL,
		0x756E0064F808E4DCULL,
		0x102D8C1D05959E78ULL,
		0x07E821F3D4B9CDF1ULL,
		0xD07112617D2234C8ULL,
		0x0AFCF8C8A159772BULL,
		0x852EF98B8C36BA2FULL
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
		0xA871A7A1A258C231ULL,
		0xFFDA6ABCCF01B8D7ULL,
		0xDD538873D029D474ULL,
		0xE3D955B98CC10AEEULL,
		0x30B71F54EEBEADE2ULL,
		0x678C8D33F9A7426BULL,
		0x2146AA8D552AE671ULL,
		0x43400683BEA513B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC77C27E7AD009BEBULL,
		0x7FFF953E9F0B97ACULL,
		0x55CBC493AE6B1232ULL,
		0x147CB9842C236F93ULL,
		0x70C8358D53EA4BFDULL,
		0x4FCF3970350D9656ULL,
		0xE102B900E83FF710ULL,
		0x7C0F477870CF7457ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0F57FB9F5582646ULL,
		0x7FDAD57E2FF6212AULL,
		0x8787C3E021BEC242ULL,
		0xCF5C9C35609D9B5BULL,
		0xBFEEE9C79AD461E5ULL,
		0x17BD53C3C499AC14ULL,
		0x4043F18C6CEAEF61ULL,
		0xC730BF0B4DD59F60ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x476B19BB38C5A827ULL,
		0x4929E250363DB292ULL,
		0x2570174E0A1086C1ULL,
		0x1AD155A8C69B5CEEULL,
		0x9F6BDD5EE0EA9143ULL,
		0xFE250167047FF3F4ULL,
		0x784660097E40B7DAULL,
		0xEF62A366973A8D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4384FEE74B345D7ULL,
		0x1AEF463EBA45C0A6ULL,
		0xFE7384DE560EF070ULL,
		0xCDCB1F4A16D57080ULL,
		0x82352408FB1EF372ULL,
		0xB6824BFE1FC5ACCDULL,
		0xF46FCB5D63C906D2ULL,
		0xE3CBB2585E86C728ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7332C9CCC4126250ULL,
		0x2E3A9C117BF7F1EBULL,
		0x26FC926FB4019651ULL,
		0x4D06365EAFC5EC6DULL,
		0x1D36B955E5CB9DD0ULL,
		0x47A2B568E4BA4727ULL,
		0x83D694AC1A77B108ULL,
		0x0B96F10E38B3C671ULL
	}};
	sign = 0;
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
		0x2F1439EFF7D5C426ULL,
		0x184BDDF19F9A0A9AULL,
		0x219B736BA4A79DD0ULL,
		0x5C56CCC919B9F16FULL,
		0xC35C997E4A152C45ULL,
		0x88A22D0AC4F6C953ULL,
		0xD84D617779F67275ULL,
		0xD7E0D37957856EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330B8F5A18BEEA1DULL,
		0x97E71A19022A4320ULL,
		0xCD9365328CD0FCB3ULL,
		0x4D45FC2001F5C5FFULL,
		0xB8EB87E84B9D4340ULL,
		0xD53CDC7565445193ULL,
		0xEC6E451F2309E862ULL,
		0x64EB86E89D7F8653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC08AA95DF16DA09ULL,
		0x8064C3D89D6FC779ULL,
		0x54080E3917D6A11CULL,
		0x0F10D0A917C42B6FULL,
		0x0A711195FE77E905ULL,
		0xB36550955FB277C0ULL,
		0xEBDF1C5856EC8A12ULL,
		0x72F54C90BA05E85EULL
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
		0x9D351BA83D633F88ULL,
		0xFF754BFE2D620537ULL,
		0x7B9E9DCF7D33EC25ULL,
		0x70A30BB99468DB4DULL,
		0xB4EE0F20A64342C6ULL,
		0x22D833A4DC1A3638ULL,
		0xB99F471607A924B9ULL,
		0x8E4381E62AC323B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C9CCF86DD598DDULL,
		0x6D5857E99716B724ULL,
		0x5A724554290483F8ULL,
		0xE69E9734949F37FBULL,
		0xFA4E958238505945ULL,
		0xC1A842CEF363190CULL,
		0x38AEB37B2EBDAB52ULL,
		0xE059B7D8CC4C74F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x656B4EAFCF8DA6ABULL,
		0x921CF414964B4E13ULL,
		0x212C587B542F682DULL,
		0x8A047484FFC9A352ULL,
		0xBA9F799E6DF2E980ULL,
		0x612FF0D5E8B71D2BULL,
		0x80F0939AD8EB7966ULL,
		0xADE9CA0D5E76AEBDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x99137644EE5360D6ULL,
		0x503759199ABCD67CULL,
		0xD95A76F346A75426ULL,
		0x2FFCBD234F886706ULL,
		0xFEEA62157E4C9D84ULL,
		0x3CCF50BDFFCE220CULL,
		0x0CCB1E5D022F79C1ULL,
		0x7834DB7D68D5F69DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E35E341D575FCEULL,
		0x1FCFE48A47174EC7ULL,
		0x4601D6267B8411DBULL,
		0x2A260E7A2C5109DEULL,
		0x7E3753E139F3D534ULL,
		0xD596FE16AB8BC541ULL,
		0x4BAB82D0A57ADA52ULL,
		0x6540553BDCE3C231ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83301810D0FC0108ULL,
		0x3067748F53A587B5ULL,
		0x9358A0CCCB23424BULL,
		0x05D6AEA923375D28ULL,
		0x80B30E344458C850ULL,
		0x673852A754425CCBULL,
		0xC11F9B8C5CB49F6EULL,
		0x12F486418BF2346BULL
	}};
	sign = 0;
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
		0xA3AF5377D3DD327DULL,
		0xF6B0FA410CE69FE9ULL,
		0xDA85859BB8F72F8EULL,
		0x60733E4462051EC1ULL,
		0xB05FC123C8ABBFD3ULL,
		0xCEBEBC91DD34594FULL,
		0x1BEA6AFE3A9FDA6FULL,
		0x259400F9ED58AFE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6628D83DF2757691ULL,
		0x729A10ED461C1143ULL,
		0xE271797FDF9A4E25ULL,
		0x1DFD84E6EEE60227ULL,
		0x6A37DEA9141F415BULL,
		0x75851381FECD55BAULL,
		0xE1AA588843A5285AULL,
		0xC425ADAFB8667EE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D867B39E167BBECULL,
		0x8416E953C6CA8EA6ULL,
		0xF8140C1BD95CE169ULL,
		0x4275B95D731F1C99ULL,
		0x4627E27AB48C7E78ULL,
		0x5939A90FDE670395ULL,
		0x3A401275F6FAB215ULL,
		0x616E534A34F230F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1E7D90A3F446EAB0ULL,
		0x3AD8F662CFDA7A29ULL,
		0xF0F59CC89DED01CDULL,
		0x75EF3FAB3E74BB3EULL,
		0x4C2F33C2BA38D9B1ULL,
		0x6D001FCAFAAF3F59ULL,
		0x8E15516AB10A246BULL,
		0x0EE64B9BADB27A67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BCFE206FC040DF5ULL,
		0xC90B034B7D57648EULL,
		0x8D497637240C35A3ULL,
		0x401E9A5A39D30271ULL,
		0x3024A6E0AC763AB9ULL,
		0x3B3D99D447BB9AB0ULL,
		0xC9093BC20D5073E1ULL,
		0xCF53D6AC4025401CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2ADAE9CF842DCBBULL,
		0x71CDF3175283159AULL,
		0x63AC269179E0CC29ULL,
		0x35D0A55104A1B8CDULL,
		0x1C0A8CE20DC29EF8ULL,
		0x31C285F6B2F3A4A9ULL,
		0xC50C15A8A3B9B08AULL,
		0x3F9274EF6D8D3A4AULL
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
		0xC8946F90ECFBB1D8ULL,
		0xC2B289BFAA3EE931ULL,
		0xA1B0AC17A34B7060ULL,
		0x2CB7EE3D20C2F032ULL,
		0xCB49C7FC13C62A47ULL,
		0x25E8F2F5B7997CC8ULL,
		0x3384F1751E0CB740ULL,
		0xA3939BA0AFE6D788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8557AA1309A547B7ULL,
		0x6159987EA51450A2ULL,
		0xB8DB93F2F3481566ULL,
		0x67FECF8AC63EF5BCULL,
		0xBB85E725C03B0EDEULL,
		0xB0177E821EC5DCC7ULL,
		0xE8A30037C091D4ABULL,
		0x1C2A7F37FB4624C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x433CC57DE3566A21ULL,
		0x6158F141052A988FULL,
		0xE8D51824B0035AFAULL,
		0xC4B91EB25A83FA75ULL,
		0x0FC3E0D6538B1B68ULL,
		0x75D1747398D3A001ULL,
		0x4AE1F13D5D7AE294ULL,
		0x87691C68B4A0B2C5ULL
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
		0xB9F1881CB5C5BB24ULL,
		0xED5D8A561659764DULL,
		0x0CF80D43D253FF46ULL,
		0x474481AFEE8D5A23ULL,
		0x768FDC2F1FD05D64ULL,
		0x8DBA085D4C915792ULL,
		0x1F7F8978F0055857ULL,
		0xF76C7FD010AD006BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84575F6E9F81D2CAULL,
		0xA6F40E12783415B3ULL,
		0x495041E8C853841DULL,
		0xF131C5B9FC50885AULL,
		0xBEB19DD05BC23C88ULL,
		0x5D044A11AC8971C9ULL,
		0xC8A18B5DC862BB9FULL,
		0x811BC87675E01739ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x359A28AE1643E85AULL,
		0x46697C439E25609AULL,
		0xC3A7CB5B0A007B29ULL,
		0x5612BBF5F23CD1C8ULL,
		0xB7DE3E5EC40E20DBULL,
		0x30B5BE4BA007E5C8ULL,
		0x56DDFE1B27A29CB8ULL,
		0x7650B7599ACCE931ULL
	}};
	sign = 0;
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
		0x168343E610F732DEULL,
		0x74B25B6213538F2CULL,
		0x1AAB5638E09504EEULL,
		0xCA0227DE0D415B92ULL,
		0x889054C1F08534D5ULL,
		0xF38E4CA04AE05349ULL,
		0xC6B99B8807ED0E66ULL,
		0xE3317C54743E054BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB9DA92339730547ULL,
		0x8919545EC3B45D1CULL,
		0x3E26DEFB9EC0E301ULL,
		0x1F38BF77D839CC63ULL,
		0xCD10D9C3E4A200D7ULL,
		0xA11B30339F7F7CBCULL,
		0x5F6F42E0B86B4596ULL,
		0x9C33C74B318F233BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AE59AC2D7842D97ULL,
		0xEB9907034F9F320FULL,
		0xDC84773D41D421ECULL,
		0xAAC9686635078F2EULL,
		0xBB7F7AFE0BE333FEULL,
		0x52731C6CAB60D68CULL,
		0x674A58A74F81C8D0ULL,
		0x46FDB50942AEE210ULL
	}};
	sign = 0;
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
		0xB186AC193EFBEA88ULL,
		0x7A807EEC652329DBULL,
		0x0A7D1765B4D18DD4ULL,
		0x0B722E03F90730A8ULL,
		0x689CED6C2A307FFCULL,
		0xBD1558CA215C897BULL,
		0x268E85728A232E8AULL,
		0x30136E34FDD9B762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D9E9BC8701FBF7ULL,
		0x1538907CE0D58F54ULL,
		0x53CA5C97B3A9D8DCULL,
		0x06E7185D28253607ULL,
		0x7DACD9C04CEA26FDULL,
		0x5BE277726BD6B634ULL,
		0x6C05EA96624BCEB4ULL,
		0x5E222D4F3D5C3F7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BACC25CB7F9EE91ULL,
		0x6547EE6F844D9A87ULL,
		0xB6B2BACE0127B4F8ULL,
		0x048B15A6D0E1FAA0ULL,
		0xEAF013ABDD4658FFULL,
		0x6132E157B585D346ULL,
		0xBA889ADC27D75FD6ULL,
		0xD1F140E5C07D77E4ULL
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
		0x64FD63BC485F7E1FULL,
		0xC7891A744DFE90F9ULL,
		0xC260769B1D43B1A9ULL,
		0xDF53C78110779309ULL,
		0x5AD8E1515CBAEA63ULL,
		0x54D9BE7FFD3BE4EBULL,
		0xE1CBBF3AAAFD03E7ULL,
		0xA8458F9233E5B807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB663BC0A9DD89CULL,
		0xBF571FB4EF29463DULL,
		0x70695B0ED8F8A876ULL,
		0x4A8A82B6B14DD1FDULL,
		0xBA861D8A47E6D5FAULL,
		0x09984B8B9C691429ULL,
		0x63F9651741014717ULL,
		0x87B1393AE0608991ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x564700003DC1A583ULL,
		0x0831FABF5ED54ABCULL,
		0x51F71B8C444B0933ULL,
		0x94C944CA5F29C10CULL,
		0xA052C3C714D41469ULL,
		0x4B4172F460D2D0C1ULL,
		0x7DD25A2369FBBCD0ULL,
		0x2094565753852E76ULL
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
		0xED0207A4897D7158ULL,
		0x27EE8FCE525C1D73ULL,
		0xF20500C513E5159EULL,
		0x6F3688FB358C3557ULL,
		0xCB608CD8EE89BD95ULL,
		0x649F2F599BDBE821ULL,
		0xB83311ED9C641578ULL,
		0x825395E48C9FB5A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95E70A5E5A071063ULL,
		0xEDB6EBB61B881FC1ULL,
		0x38412733F064477EULL,
		0xCAA75091DA1B19E5ULL,
		0x2B53A800ABD23512ULL,
		0xABE30C6AA82A66DCULL,
		0xAD2C473AE5A94CE5ULL,
		0x96D321679854DBF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x571AFD462F7660F5ULL,
		0x3A37A41836D3FDB2ULL,
		0xB9C3D9912380CE1FULL,
		0xA48F38695B711B72ULL,
		0xA00CE4D842B78882ULL,
		0xB8BC22EEF3B18145ULL,
		0x0B06CAB2B6BAC892ULL,
		0xEB80747CF44AD9AEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8EE2E7A3DFB1D03EULL,
		0x4047A26CE8AC7D69ULL,
		0x8DE0E370EE8A4A06ULL,
		0x1EECEBFB207757F0ULL,
		0x8DF2EC14A6E1DC51ULL,
		0x67A95C4E77C4B0A5ULL,
		0x781A150466D8F675ULL,
		0x4D34289860C65037ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1EEEF14091DB82ULL,
		0x31FB46F7A227D6D7ULL,
		0x5C00987BDF5AECE5ULL,
		0xFBF0107B18D303BEULL,
		0x67065D68D60BEF01ULL,
		0xF410C4A7B584B8B3ULL,
		0x4220DDE3CAB80070ULL,
		0x506FDFF392FEA8DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0C3F8B29F1FF4BCULL,
		0x0E4C5B754684A691ULL,
		0x31E04AF50F2F5D21ULL,
		0x22FCDB8007A45432ULL,
		0x26EC8EABD0D5ED4FULL,
		0x739897A6C23FF7F2ULL,
		0x35F937209C20F604ULL,
		0xFCC448A4CDC7A75DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBC61B076C15954ADULL,
		0xDD7D138CF68BE0EBULL,
		0x1B8A5EA53693CC1AULL,
		0x4DEB7D089B4B97D7ULL,
		0x17CA1E508E727631ULL,
		0xC56D7B76E1BBD208ULL,
		0x989B8C2E8744EAE9ULL,
		0xCBFC8A2FEF58C6A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76A6568987D6384ULL,
		0x8E89904726C31D59ULL,
		0xDA6263A87B23815EULL,
		0xF7F0E61F63C15329ULL,
		0x0581D0C6BE1764DAULL,
		0x506F3FC8CAA1C3BFULL,
		0xAF5E8056F7DFCC06ULL,
		0x604DB32A0CC2D161ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4F74B0E28DBF129ULL,
		0x4EF38345CFC8C391ULL,
		0x4127FAFCBB704ABCULL,
		0x55FA96E9378A44ADULL,
		0x12484D89D05B1156ULL,
		0x74FE3BAE171A0E49ULL,
		0xE93D0BD78F651EE3ULL,
		0x6BAED705E295F546ULL
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
		0x2EE21653540A5E16ULL,
		0x5AF22279B70C649FULL,
		0x056998D4C853A4FDULL,
		0x7BBAAAC62E64D0B1ULL,
		0xF80C2DE6C9C20813ULL,
		0xDDB6DBF16F12A3E6ULL,
		0x255FE05A9209FACAULL,
		0xF301580D70CACC97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09FA397D7A455907ULL,
		0x37B168238ABC1F5AULL,
		0x656F91913D267632ULL,
		0xC7F77F4F483FE887ULL,
		0xC9C24DA898A4E6FEULL,
		0x87CC38F74934DD77ULL,
		0x8D6AFEE9C34D12F7ULL,
		0xCCBA38983A6DF824ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24E7DCD5D9C5050FULL,
		0x2340BA562C504545ULL,
		0x9FFA07438B2D2ECBULL,
		0xB3C32B76E624E829ULL,
		0x2E49E03E311D2114ULL,
		0x55EAA2FA25DDC66FULL,
		0x97F4E170CEBCE7D3ULL,
		0x26471F75365CD472ULL
	}};
	sign = 0;
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
		0x3603DE86575C71F5ULL,
		0xE500010665BE3835ULL,
		0x69F17FE4FBBBC3B2ULL,
		0x9A3A04D0CDC2E4BCULL,
		0xF1496F3DD18CF8A3ULL,
		0xF5B2C46081585817ULL,
		0x2EBF78BF17F6EFEBULL,
		0x22372CAA08AE96B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEAD47304A11A533ULL,
		0x25ED82F2A2000546ULL,
		0x100F5675F5854FE6ULL,
		0x6718DEBDF3A00856ULL,
		0x44E01E8E5D4CAF2FULL,
		0xD60DE963D4F7396FULL,
		0x1DD50685E980BFD5ULL,
		0x8B37C8350D14E003ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x875697560D4ACCC2ULL,
		0xBF127E13C3BE32EEULL,
		0x59E2296F063673CCULL,
		0x33212612DA22DC66ULL,
		0xAC6950AF74404974ULL,
		0x1FA4DAFCAC611EA8ULL,
		0x10EA72392E763016ULL,
		0x96FF6474FB99B6B0ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE3D93BAE4084FDD2ULL,
		0x09D3A4305F0BD777ULL,
		0x140D1BEA36543685ULL,
		0x3A83BE6BD49B87E0ULL,
		0x295D035FF15167BBULL,
		0x9A8360C05748A463ULL,
		0x162DDE8A366F1957ULL,
		0xABDD5FF053500DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3535DDAD5844B5EULL,
		0xE0D625C215588055ULL,
		0xE29B4C87CC87AA2CULL,
		0x3D562EC8C79D034EULL,
		0x90C24C16B0CDEF8AULL,
		0xEFBE957BCB6D8B68ULL,
		0x836681856986C986ULL,
		0xD9230F67B53A3399ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4085DDD36B00B274ULL,
		0x28FD7E6E49B35722ULL,
		0x3171CF6269CC8C58ULL,
		0xFD2D8FA30CFE8491ULL,
		0x989AB74940837830ULL,
		0xAAC4CB448BDB18FAULL,
		0x92C75D04CCE84FD0ULL,
		0xD2BA50889E15DA11ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x67352686E1DB6799ULL,
		0x96AAA469932BE930ULL,
		0xC19ADE13DD5472DEULL,
		0x40BDD2E1334EB697ULL,
		0x5D65CE8EF2C66D08ULL,
		0xA550C408E0CB8983ULL,
		0x3CA4EDC1B6684588ULL,
		0x109F9BA3E35D45EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C17CE1336353778ULL,
		0xD224DCF383D57274ULL,
		0x600195896C1A1ADDULL,
		0x7429D646D25B472FULL,
		0xCD4B8B1F21E9BFDDULL,
		0x65DB58D72A47B6DDULL,
		0x212B073CBAB7C38DULL,
		0x9DF547598E97DDE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB1D5873ABA63021ULL,
		0xC485C7760F5676BBULL,
		0x6199488A713A5800ULL,
		0xCC93FC9A60F36F68ULL,
		0x901A436FD0DCAD2AULL,
		0x3F756B31B683D2A5ULL,
		0x1B79E684FBB081FBULL,
		0x72AA544A54C56801ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE7824E2B31ECFE36ULL,
		0x20E376AC221E019EULL,
		0x0E2F9D5B2D8A968CULL,
		0x1F8AAF303151415BULL,
		0xF21EBE59D1A5B526ULL,
		0x9BC18524B1687D77ULL,
		0x24A0AB2249DBF079ULL,
		0x941B6BF42DA7876FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886814D7880C967CULL,
		0xE56ED206AAF930A2ULL,
		0x05082C47FC2A7337ULL,
		0x311DD80F848EE3D6ULL,
		0x068D450834110492ULL,
		0x823CFF7D18EACF23ULL,
		0xFF66C9477D65D9E3ULL,
		0xEE611E8292173DFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F1A3953A9E067BAULL,
		0x3B74A4A57724D0FCULL,
		0x0927711331602354ULL,
		0xEE6CD720ACC25D85ULL,
		0xEB9179519D94B093ULL,
		0x198485A7987DAE54ULL,
		0x2539E1DACC761696ULL,
		0xA5BA4D719B904970ULL
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
		0x1038385F6009A626ULL,
		0x5CA1D167A7A6F81AULL,
		0xF149CD9DE40098E2ULL,
		0x182BECA4C137D8BDULL,
		0x9CCED0141FE39EEFULL,
		0x63196E6073E16539ULL,
		0x4B3812A811DBDBBEULL,
		0xDB48DAD3C060E541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0E7C6F1B8AA4C11ULL,
		0x3737604076D4DAEDULL,
		0x896FEFE829E8D485ULL,
		0xE30E1E45E3114B8AULL,
		0x36AB3CDC74A99B5AULL,
		0x7941807655919D14ULL,
		0xC12131F952BB6B0BULL,
		0xC080670ABBE163CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F50716DA75F5A15ULL,
		0x256A712730D21D2CULL,
		0x67D9DDB5BA17C45DULL,
		0x351DCE5EDE268D33ULL,
		0x66239337AB3A0394ULL,
		0xE9D7EDEA1E4FC825ULL,
		0x8A16E0AEBF2070B2ULL,
		0x1AC873C9047F8173ULL
	}};
	sign = 0;
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
		0xBD24ACBE6F16D3DEULL,
		0x0D8249A27436A2AEULL,
		0x12EC0E28B4BA3F61ULL,
		0xD31C0BAAA516978AULL,
		0xAD8E02F8CFB9E8ABULL,
		0xEC9CE99A45775980ULL,
		0x8C68A178529330ECULL,
		0x0CF0602D0ECD7102ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388D6DAA4751AA49ULL,
		0x9CA2A48F3C0302E1ULL,
		0x6CA04148EF2CB3BFULL,
		0x481B22F027B277AEULL,
		0x40493E7C56C65C15ULL,
		0xCF7E4E846AF45B06ULL,
		0x15253D37B821D855ULL,
		0x5BE948DBDD10BADEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84973F1427C52995ULL,
		0x70DFA51338339FCDULL,
		0xA64BCCDFC58D8BA1ULL,
		0x8B00E8BA7D641FDBULL,
		0x6D44C47C78F38C96ULL,
		0x1D1E9B15DA82FE7AULL,
		0x774364409A715897ULL,
		0xB107175131BCB624ULL
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
		0xD6A07BE57DD0C470ULL,
		0x21316D5B759B84E6ULL,
		0x46B6DAB094F6867DULL,
		0xCAEC454162E172CCULL,
		0xBA33340C4655FD3BULL,
		0xEAD90DCCD4C56C4DULL,
		0xE19BC48B46A03C4FULL,
		0x0C0471213A828C1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x063F3A94C5718A2AULL,
		0x0BEB11D185FBD762ULL,
		0x3D70AD0B149D37B0ULL,
		0x8DD8BA263F44A596ULL,
		0x01F7B7EAA7C494F6ULL,
		0x41B3E39B2DD51CCEULL,
		0xA1D632CD2383BFC0ULL,
		0xD3B7BF1DEA973A53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0614150B85F3A46ULL,
		0x15465B89EF9FAD84ULL,
		0x09462DA580594ECDULL,
		0x3D138B1B239CCD36ULL,
		0xB83B7C219E916845ULL,
		0xA9252A31A6F04F7FULL,
		0x3FC591BE231C7C8FULL,
		0x384CB2034FEB51C9ULL
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
		0x2C66AC96CF619B27ULL,
		0x8C479AE6EC611B31ULL,
		0xCFDB7B8B649293C6ULL,
		0x0F97A151F0168283ULL,
		0xD6CE0595D2FFB5A6ULL,
		0x90DF25C98E58C4D3ULL,
		0xDA5F1424352F81C5ULL,
		0x4B0D05F415529F76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82A4D898F0A6E739ULL,
		0x49B346DC462C036FULL,
		0xFD7AC4A32C2E9BCBULL,
		0x9FDE31BBB406C8E6ULL,
		0xA5A84EEB1D813201ULL,
		0xD316B5D5760BC1F7ULL,
		0x8100270F46C93C3AULL,
		0x32D5218D132BE692ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9C1D3FDDEBAB3EEULL,
		0x4294540AA63517C1ULL,
		0xD260B6E83863F7FBULL,
		0x6FB96F963C0FB99CULL,
		0x3125B6AAB57E83A4ULL,
		0xBDC86FF4184D02DCULL,
		0x595EED14EE66458AULL,
		0x1837E4670226B8E4ULL
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
		0x66D2C0BA3DB7F23BULL,
		0xA6975A02E27C5F9BULL,
		0x445B6046DC076B43ULL,
		0x8417A7B1852C99B6ULL,
		0x9213FC1A8E1A5710ULL,
		0x30CABA12E8A6939BULL,
		0x52913FD1096CCFCEULL,
		0x19F9B17798F6ABE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA72A9F94EC5538DAULL,
		0x928C43CC7F945054ULL,
		0x29521C77207DE80CULL,
		0x28C3DCC879FC51EDULL,
		0x8BC2F2915003DBBBULL,
		0x9B95EA718771DF17ULL,
		0xB994F00D92A47B8DULL,
		0x11AF738A0A4BCDC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFA821255162B961ULL,
		0x140B163662E80F46ULL,
		0x1B0943CFBB898337ULL,
		0x5B53CAE90B3047C9ULL,
		0x065109893E167B55ULL,
		0x9534CFA16134B484ULL,
		0x98FC4FC376C85440ULL,
		0x084A3DED8EAADE18ULL
	}};
	sign = 0;
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
		0x3392F618922FA8CCULL,
		0x517BF2D92ABC0565ULL,
		0xF7385C3212E2168BULL,
		0x4FCEE15646C7C0B7ULL,
		0x79B5E424E3303DABULL,
		0xB7E53990E44D44ADULL,
		0xD9D366B413C7009EULL,
		0x074C9F18D7193F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x384F02017928AF75ULL,
		0x37BE89C1E4633ABFULL,
		0x2B38DF97DFF7C698ULL,
		0x36F4CF70296F4749ULL,
		0x6A674010D0B63980ULL,
		0xFDFEA48C6D4E2793ULL,
		0x75C13C30CA302A76ULL,
		0xAD1F3754247A642EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB43F4171906F957ULL,
		0x19BD69174658CAA5ULL,
		0xCBFF7C9A32EA4FF3ULL,
		0x18DA11E61D58796EULL,
		0x0F4EA414127A042BULL,
		0xB9E6950476FF1D1AULL,
		0x64122A834996D627ULL,
		0x5A2D67C4B29EDB1BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x41C20711E3CE05F6ULL,
		0xBDD0EB69AE7F6636ULL,
		0x11F37F6E8F2787F0ULL,
		0x5E00EBBC0D530DAEULL,
		0x44FC1956BFA02945ULL,
		0xF3AF5DF7DEF7E56BULL,
		0xFAE03796A1A04E76ULL,
		0xC8EAF98FA743F1F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60EA4D2A9C4233C9ULL,
		0x32D8ED599CBC5194ULL,
		0x356A6BC7EB53A7ADULL,
		0x07A1A247CC816EF5ULL,
		0xE81319E63142470BULL,
		0xEE577AA29FBACFA1ULL,
		0x732842E2B74072B1ULL,
		0xE94DFECF35545A05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0D7B9E7478BD22DULL,
		0x8AF7FE1011C314A1ULL,
		0xDC8913A6A3D3E043ULL,
		0x565F497440D19EB8ULL,
		0x5CE8FF708E5DE23AULL,
		0x0557E3553F3D15C9ULL,
		0x87B7F4B3EA5FDBC5ULL,
		0xDF9CFAC071EF97ECULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDE799E9FC12652F4ULL,
		0x8C0D31B43172341BULL,
		0xEDCA71115751532EULL,
		0x97A32F6262FB888BULL,
		0xA42A71C18488450FULL,
		0x36F2672C03D142D9ULL,
		0xE40BBC43A04067F8ULL,
		0x5604342371837B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A7DC943B7710C2ULL,
		0x50DA322D90D670F4ULL,
		0x542DD7DA361B1079ULL,
		0x49B11092F467D062ULL,
		0x3BA32734AA36B3B1ULL,
		0x1BFE27244A0D4D5CULL,
		0xD6C72FE13DD7F090ULL,
		0x6003D5B080B7BFCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17D1C20B85AF4232ULL,
		0x3B32FF86A09BC327ULL,
		0x999C9937213642B5ULL,
		0x4DF21ECF6E93B829ULL,
		0x68874A8CDA51915EULL,
		0x1AF44007B9C3F57DULL,
		0x0D448C6262687768ULL,
		0xF6005E72F0CBBBCAULL
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
		0x328C29C93E5B5893ULL,
		0x548F267C870CF9B7ULL,
		0xC7E051352AA1CD81ULL,
		0x89DD3904689A2417ULL,
		0x07BFDFDC0E91CD09ULL,
		0x8A4BFCD4FB1FAE4BULL,
		0xDC0A9FF62EE183D9ULL,
		0xE59F4BD7CD38CCA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95653B5D9BF0163DULL,
		0x1EEEE7CAAB707B6AULL,
		0x9F56639C89AB1863ULL,
		0x4B5923D8946EF993ULL,
		0x0469D6A92CD17366ULL,
		0xF01FB72D9A8BCBFCULL,
		0xA6FFA06FD0E9138EULL,
		0xECD1F96D475D3F89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D26EE6BA26B4256ULL,
		0x35A03EB1DB9C7E4CULL,
		0x2889ED98A0F6B51EULL,
		0x3E84152BD42B2A84ULL,
		0x03560932E1C059A3ULL,
		0x9A2C45A76093E24FULL,
		0x350AFF865DF8704AULL,
		0xF8CD526A85DB8D19ULL
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
		0x626B2AF14CF097A0ULL,
		0x9C3B475B8479C033ULL,
		0xCBA46F1FB64757E5ULL,
		0x2EDF3C81483CF24DULL,
		0xF903540C53FA7E29ULL,
		0x9E5CCAB6D7F6F37DULL,
		0x17134A5D3140D08DULL,
		0xCDBF74DA4ABE317FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90FF3A0A35FCADAEULL,
		0xDD096444605D4B11ULL,
		0x584DAA726B7DD7B9ULL,
		0x739148CB4CBD03ABULL,
		0x21547ECD43C96C89ULL,
		0xDD80D9AFFD235C1FULL,
		0x8616F73434A13DDEULL,
		0x37647A22812E6EA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD16BF0E716F3E9F2ULL,
		0xBF31E317241C7521ULL,
		0x7356C4AD4AC9802BULL,
		0xBB4DF3B5FB7FEEA2ULL,
		0xD7AED53F1031119FULL,
		0xC0DBF106DAD3975EULL,
		0x90FC5328FC9F92AEULL,
		0x965AFAB7C98FC2DAULL
	}};
	sign = 0;
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
		0x6FC5B8F7A87AE043ULL,
		0x4EC04CD43D4F82BAULL,
		0x09A7688E729F7313ULL,
		0x589102AC9918BF0AULL,
		0x4577E9FB755D3EBFULL,
		0x5BBCA02C1B8EF412ULL,
		0x74213F9109918F49ULL,
		0x1E923D2E92B2FCB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x107CBE7EB05BB324ULL,
		0x0314C9A015BEE213ULL,
		0x4125596EA3D4D305ULL,
		0xF6D0A292A2BFB175ULL,
		0x139F90DB98D82AB1ULL,
		0xF9F1CBB1391F68A6ULL,
		0xE9A401E314722470ULL,
		0x96E1C9ED94E3E360ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5F48FA78F81F2D1FULL,
		0x4BAB83342790A0A7ULL,
		0xC8820F1FCECAA00EULL,
		0x61C06019F6590D94ULL,
		0x31D8591FDC85140DULL,
		0x61CAD47AE26F8B6CULL,
		0x8A7D3DADF51F6AD8ULL,
		0x87B07340FDCF1957ULL
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
		0x7B5FCAFD6748DF9CULL,
		0x89E9800878E69371ULL,
		0x3F0E2AD9C46CDBD6ULL,
		0x7E14010601773EF0ULL,
		0xB74460758F5FF69BULL,
		0x284875A696770BD6ULL,
		0x0901663FD5D50B5FULL,
		0xE89B3FF02E6D0450ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67743CBAB5A3216FULL,
		0x9CFED58359B3CF3FULL,
		0x53C29F12E2B4D498ULL,
		0x2FDBD07702F263C8ULL,
		0x69CEA74A13C04DD3ULL,
		0x4B29FC01DE4167D7ULL,
		0xAA70EBDD1CE6C5A1ULL,
		0xDEC0062CD287ABC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13EB8E42B1A5BE2DULL,
		0xECEAAA851F32C432ULL,
		0xEB4B8BC6E1B8073DULL,
		0x4E38308EFE84DB27ULL,
		0x4D75B92B7B9FA8C8ULL,
		0xDD1E79A4B835A3FFULL,
		0x5E907A62B8EE45BDULL,
		0x09DB39C35BE5588BULL
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
		0xA4D5823EF723C8BAULL,
		0xB0C1314DEFA030A4ULL,
		0xA663C923EE7FE87BULL,
		0xD067851028B451B6ULL,
		0x9B35E420600C9D95ULL,
		0xFC95C145D0C3715CULL,
		0x22BBA72AF92DCE7AULL,
		0xE4CC6F7C8CF774B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x581F6FA95D46015CULL,
		0x1A5B333271D266C1ULL,
		0x09EBF76B8510981BULL,
		0x4708975A3AF2ECB2ULL,
		0xA0A266900373EA31ULL,
		0x90800EAC1B9EDAB1ULL,
		0x5DFE0E3C4F37D90CULL,
		0x4D3B87E791D42265ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CB6129599DDC75EULL,
		0x9665FE1B7DCDC9E3ULL,
		0x9C77D1B8696F5060ULL,
		0x895EEDB5EDC16504ULL,
		0xFA937D905C98B364ULL,
		0x6C15B299B52496AAULL,
		0xC4BD98EEA9F5F56EULL,
		0x9790E794FB23524EULL
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
		0xDA0164563F3B19B5ULL,
		0x1712ECD12358B1C1ULL,
		0x87EE8E17C7BC1DF3ULL,
		0x1B679A280943D0CEULL,
		0x5052F1CEA4C07836ULL,
		0x3716F2CEB3CD3197ULL,
		0x31A474841F8611FDULL,
		0xE8E727D3988D0F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60AC5EEEDCBBA837ULL,
		0xDC597BD999AFBE3EULL,
		0x29A0C511B4EC65C8ULL,
		0x2344237717FB4FA8ULL,
		0x133860E1A7EAFF7FULL,
		0xD7D657321A8BFC12ULL,
		0x0861C968946B06B5ULL,
		0xB59D4142F328C0DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79550567627F717EULL,
		0x3AB970F789A8F383ULL,
		0x5E4DC90612CFB82AULL,
		0xF82376B0F1488126ULL,
		0x3D1A90ECFCD578B6ULL,
		0x5F409B9C99413585ULL,
		0x2942AB1B8B1B0B47ULL,
		0x3349E690A5644EA6ULL
	}};
	sign = 0;
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
		0x510A046FC07168EDULL,
		0x8968EAAC9800622EULL,
		0xFEACF640EF432100ULL,
		0xF39DAA724AA7352FULL,
		0x8151F863B5DC330EULL,
		0x706409C51F7ACC7DULL,
		0x8D143C00990F6B08ULL,
		0x414DEA78877D27DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED85F87E1F98D492ULL,
		0xAC493370C34BCF1BULL,
		0x62D669E0DEDFA284ULL,
		0x79B7F32AA6A75DA6ULL,
		0x749B7185D302A6A3ULL,
		0x019FB336ECE56A89ULL,
		0x9A6ECD1FF838575DULL,
		0xF7980448E347BA2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63840BF1A0D8945BULL,
		0xDD1FB73BD4B49312ULL,
		0x9BD68C6010637E7BULL,
		0x79E5B747A3FFD789ULL,
		0x0CB686DDE2D98C6BULL,
		0x6EC4568E329561F4ULL,
		0xF2A56EE0A0D713ABULL,
		0x49B5E62FA4356DADULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8B592BC6D5778705ULL,
		0xD30E23BB9EAA093DULL,
		0x2A990F963176089BULL,
		0xE9AE88E91D056A8EULL,
		0x07E1C19D2D38F526ULL,
		0xCCA9B0DCBE30797DULL,
		0x84E3926274DCE11DULL,
		0xF2885B1BDFE981E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F2BAC0B71F21C8BULL,
		0x6A0554A7AECB81E8ULL,
		0x321847D61EB9CF66ULL,
		0x2B6F66B2D636D153ULL,
		0x2F570E744CBB8710ULL,
		0xADD523ACB5ACF4AAULL,
		0x32DF5AEC6CA23113ULL,
		0x4BACA344104AE1A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C2D7FBB63856A7AULL,
		0x6908CF13EFDE8755ULL,
		0xF880C7C012BC3935ULL,
		0xBE3F223646CE993AULL,
		0xD88AB328E07D6E16ULL,
		0x1ED48D30088384D2ULL,
		0x52043776083AB00AULL,
		0xA6DBB7D7CF9EA045ULL
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
		0xE72670F44248FE86ULL,
		0xFD4B034D992D6196ULL,
		0xD84B35A973B19A3CULL,
		0x0DCE38392A4CA0F2ULL,
		0x3C897DC93234EE69ULL,
		0x573770800FD3E2B2ULL,
		0x640DFFA0DED5A101ULL,
		0x0FC3205D9E4903CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3AEE621216C4727ULL,
		0xD6D8CCEFE3606806ULL,
		0xE05656B9FF446399ULL,
		0xABAE13BAD788AE41ULL,
		0x318ADD377BE9661FULL,
		0x1447C20CE448D60DULL,
		0x144BC2739E68DCC2ULL,
		0x012C226221273DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x43778AD320DCB75FULL,
		0x2672365DB5CCF990ULL,
		0xF7F4DEEF746D36A3ULL,
		0x6220247E52C3F2B0ULL,
		0x0AFEA091B64B8849ULL,
		0x42EFAE732B8B0CA5ULL,
		0x4FC23D2D406CC43FULL,
		0x0E96FDFB7D21C60AULL
	}};
	sign = 0;
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
		0x79F272D206F9F941ULL,
		0xA9824DFBE9E81EBAULL,
		0x84A13DD57A9FFAB8ULL,
		0xA27A3FFF8059FFB5ULL,
		0x10E00D6D4E1D44F3ULL,
		0x284719CA37D16B36ULL,
		0x606B250908FE2A7EULL,
		0x83875BFB5BF65569ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31E94E1320E9C5C6ULL,
		0xD0161C7B2F07216AULL,
		0xD8BA9D70A316D8DEULL,
		0x169C4F821394C82EULL,
		0xC0C1E83B93C8D4FEULL,
		0x4AB22EA286479D19ULL,
		0x5F2177BEB5522555ULL,
		0xA3D85CE9012D5B44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x480924BEE610337BULL,
		0xD96C3180BAE0FD50ULL,
		0xABE6A064D78921D9ULL,
		0x8BDDF07D6CC53786ULL,
		0x501E2531BA546FF5ULL,
		0xDD94EB27B189CE1CULL,
		0x0149AD4A53AC0528ULL,
		0xDFAEFF125AC8FA25ULL
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
		0xB8AE943A27CF563BULL,
		0xA8A1B84BD01265A5ULL,
		0x96E8882705CA8695ULL,
		0x004EAD84B351EF49ULL,
		0x07FFF074B38F31D6ULL,
		0xD2298A1F06DE22EDULL,
		0x7C100A20F6817F76ULL,
		0x4902640C53340722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AFC69B8DD303816ULL,
		0x19BD3D1F9BDA6C23ULL,
		0x9FCFECAEFAF5E0B2ULL,
		0xDC80BF3BC6EDA3EEULL,
		0xB94F0CF10C8F2967ULL,
		0x3CC496D500267F62ULL,
		0xB2EE6E3632F6E001ULL,
		0xE20A48AC0EC27682ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DB22A814A9F1E25ULL,
		0x8EE47B2C3437F982ULL,
		0xF7189B780AD4A5E3ULL,
		0x23CDEE48EC644B5AULL,
		0x4EB0E383A700086EULL,
		0x9564F34A06B7A38AULL,
		0xC9219BEAC38A9F75ULL,
		0x66F81B604471909FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD1F4231655F20B52ULL,
		0x1FB1F9C03747E9EAULL,
		0xE2724FEAC942EE99ULL,
		0x0700336F707FFB46ULL,
		0x3AF080A2E55D7379ULL,
		0x8EF269F7B9378C3DULL,
		0xF61E8896FC4BA330ULL,
		0x7C9DEC4D0A76FFB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4F84E8EEDB1BE80ULL,
		0xE789D2D72D6A5ABBULL,
		0x95C797BC2B7D0F1FULL,
		0x8581E43D5A85FFD2ULL,
		0xF03832A0A865CD5BULL,
		0x8D8B8322467AD09CULL,
		0x9682E71A897F7554ULL,
		0x36310FD90C91AAA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CFBD48768404CD2ULL,
		0x382826E909DD8F2FULL,
		0x4CAAB82E9DC5DF79ULL,
		0x817E4F3215F9FB74ULL,
		0x4AB84E023CF7A61DULL,
		0x0166E6D572BCBBA0ULL,
		0x5F9BA17C72CC2DDCULL,
		0x466CDC73FDE55518ULL
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
		0x7A15FA70E30DE8E4ULL,
		0x3390682085849707ULL,
		0x65814850EC68C3D5ULL,
		0x77C4EED583FB2E61ULL,
		0xD432EAE37C7E75C8ULL,
		0x1CB175F172A446CBULL,
		0xF1A53F9E00EE2979ULL,
		0x3BEB582BA206B49FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60CBF3CB9273404AULL,
		0x75A86FDD63CC10F8ULL,
		0xA6782A25EDB47C21ULL,
		0xEE1BEF9716C42F88ULL,
		0x2AFFF1C7381E443AULL,
		0x0B23566995176AFDULL,
		0x3E469570F7FBD529ULL,
		0x9BC49DD0FFAA08E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x194A06A5509AA89AULL,
		0xBDE7F84321B8860FULL,
		0xBF091E2AFEB447B3ULL,
		0x89A8FF3E6D36FED8ULL,
		0xA932F91C4460318DULL,
		0x118E1F87DD8CDBCEULL,
		0xB35EAA2D08F25450ULL,
		0xA026BA5AA25CABBAULL
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
		0x6C1CECE87E1F2573ULL,
		0x035FD4558D0D4775ULL,
		0xA6949763C4DFC163ULL,
		0xC81CB04C470FA987ULL,
		0x7136829F8ECB64EEULL,
		0x427E15C18D732AEDULL,
		0xC7ACD805B613A145ULL,
		0x44D470FCE00D7FC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C22A9CD7E4716B2ULL,
		0x1ADC012A950FDD6AULL,
		0xF7246A3A3D79CC8FULL,
		0xDC29A8A7F95B6149ULL,
		0x67DA9C472C7DD70AULL,
		0xF9AE36728700DEF3ULL,
		0xDAA6DE0E3C5A51CAULL,
		0x6DEFF2135A8594E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FFA431AFFD80EC1ULL,
		0xE883D32AF7FD6A0BULL,
		0xAF702D298765F4D3ULL,
		0xEBF307A44DB4483DULL,
		0x095BE658624D8DE3ULL,
		0x48CFDF4F06724BFAULL,
		0xED05F9F779B94F7AULL,
		0xD6E47EE98587EAE5ULL
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
		0x90988D9CB2AF3E62ULL,
		0x005C2EC485BDF994ULL,
		0x2FE494C4479C7C1CULL,
		0x6270F650AACC2563ULL,
		0x531C6B5C7D38513CULL,
		0x945948EEEFAA2D53ULL,
		0xA81914456E2B2FFAULL,
		0x532B215F9DEC1D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2C932FBC0864435ULL,
		0xDC694A1C9264C21BULL,
		0x4813C69D4CDEE4C1ULL,
		0x07726DD84ACC7586ULL,
		0x3333EAF038218182ULL,
		0x85FF528609FD9369ULL,
		0x2EEF97EBB30361B1ULL,
		0x1ED8D14CD7990E2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DCF5AA0F228FA2DULL,
		0x23F2E4A7F3593778ULL,
		0xE7D0CE26FABD975AULL,
		0x5AFE88785FFFAFDCULL,
		0x1FE8806C4516CFBAULL,
		0x0E59F668E5AC99EAULL,
		0x79297C59BB27CE49ULL,
		0x34525012C6530F48ULL
	}};
	sign = 0;
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
		0x96F22537EDA33D6BULL,
		0x73585FEBD34ED66DULL,
		0x64F775D3AD0442C2ULL,
		0x23F6B99454B2E65CULL,
		0x0CEE7A2064AF6910ULL,
		0xC5FDF01647E12E3AULL,
		0x57FA1194AFC7FE34ULL,
		0x8A6ECA4D375BB207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEF1BC2AF597F6C1ULL,
		0xEB2A1E5EB171FFE2ULL,
		0x8E66E730D980C14BULL,
		0x4C3385C6BFD1EDBEULL,
		0x5F05B43B6D90BC07ULL,
		0x4F4848BD53F4ABF5ULL,
		0xFD3336F479D527DAULL,
		0xFABCC099A18354B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9800690CF80B46AAULL,
		0x882E418D21DCD68AULL,
		0xD6908EA2D3838176ULL,
		0xD7C333CD94E0F89DULL,
		0xADE8C5E4F71EAD08ULL,
		0x76B5A758F3EC8244ULL,
		0x5AC6DAA035F2D65AULL,
		0x8FB209B395D85D4DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8044AB4C003B89C0ULL,
		0x1FAB2BDC46BCACB8ULL,
		0xDFEF853B398B411DULL,
		0x88DFB87CE66F897CULL,
		0x95B3156ACDE07FF5ULL,
		0x09C3E6DF6DB7CF46ULL,
		0x9A02F36F2F8FA0CBULL,
		0x4B1ACD640320F0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D22885FF2D42A6ULL,
		0x7B44F6F4CF746F0DULL,
		0x510242A1D7C7EF2FULL,
		0xC6406FB1D2F7B998ULL,
		0xE24AF24FF74A5BE8ULL,
		0x80F26BC7117EFC0EULL,
		0x0537EC0B36884DC9ULL,
		0xDA2CDE9C045E62BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E7282C6010E471AULL,
		0xA46634E777483DABULL,
		0x8EED429961C351EDULL,
		0xC29F48CB1377CFE4ULL,
		0xB368231AD696240CULL,
		0x88D17B185C38D337ULL,
		0x94CB0763F9075301ULL,
		0x70EDEEC7FEC28DE7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAF626D8D13C0E60FULL,
		0xAD9DF55DFCE600B1ULL,
		0xE4738AB428817B94ULL,
		0x60AD051311553359ULL,
		0x3FD33740B0692C83ULL,
		0x0CE92EF292779833ULL,
		0x3F75561FF788D980ULL,
		0x016AE807C27824C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1B9C11564697FCEULL,
		0xAC800F6F14CF3431ULL,
		0x2F122FA5FBDBA8F8ULL,
		0x360CD99A521D89A0ULL,
		0x345B43A85E3435EDULL,
		0x430A0C095DCA6AE7ULL,
		0xA8B2445EB27C432AULL,
		0xCBE415202F26BAB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBDA8AC77AF576641ULL,
		0x011DE5EEE816CC7FULL,
		0xB5615B0E2CA5D29CULL,
		0x2AA02B78BF37A9B9ULL,
		0x0B77F3985234F696ULL,
		0xC9DF22E934AD2D4CULL,
		0x96C311C1450C9655ULL,
		0x3586D2E793516A0AULL
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
		0xC8E870955A90EFE8ULL,
		0x2472708734A08178ULL,
		0x82AFEA73AC6BDF36ULL,
		0x81BA788327206FF3ULL,
		0xED4999EC9A1C6DC9ULL,
		0x2960C2CFD5EECA8FULL,
		0xF41E3596AFE957B9ULL,
		0xD46D9527EA51B791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB8B3B6C9887F2B9ULL,
		0x9F753DCCEBF64D0CULL,
		0xCCAA8791B5408658ULL,
		0x8EAFE874FCAA71DAULL,
		0x1C6C663EF1B7674CULL,
		0xF8F053C37BC11FACULL,
		0xA188F3D552127D83ULL,
		0x3F8C276EE7663481ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCD5D3528C208FD2FULL,
		0x84FD32BA48AA346BULL,
		0xB60562E1F72B58DDULL,
		0xF30A900E2A75FE18ULL,
		0xD0DD33ADA865067CULL,
		0x30706F0C5A2DAAE3ULL,
		0x529541C15DD6DA35ULL,
		0x94E16DB902EB8310ULL
	}};
	sign = 0;
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
		0xE1DD7E9B8C767A79ULL,
		0x7E78C9CF07803478ULL,
		0x20C6E1635D1F069AULL,
		0xA44B050A70A2115AULL,
		0xB7150C3CCEE78367ULL,
		0x9206E8E4E0485A52ULL,
		0xF0AA2430E3DF7E30ULL,
		0x7F42FC504936EA48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x472829A7CCAB7AE8ULL,
		0x0E9439EEC9EE5D8CULL,
		0x1E173CD6A89D35B1ULL,
		0xD670498FF3876A66ULL,
		0x014516673549CD30ULL,
		0x4ECB70B6E2CD1201ULL,
		0xD1887D2C536586DBULL,
		0xC2B405130EDF1707ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AB554F3BFCAFF91ULL,
		0x6FE48FE03D91D6ECULL,
		0x02AFA48CB481D0E9ULL,
		0xCDDABB7A7D1AA6F4ULL,
		0xB5CFF5D5999DB636ULL,
		0x433B782DFD7B4851ULL,
		0x1F21A7049079F755ULL,
		0xBC8EF73D3A57D341ULL
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
		0x9C77554962FF0C5CULL,
		0xF250BB24D31FC39EULL,
		0x2C27F432AB37CF46ULL,
		0xD3E96C07A525F185ULL,
		0xC422FF2AEA6BF60CULL,
		0xC8828BA6EB66E0CEULL,
		0x3B9A85F8F040C763ULL,
		0xD37EDF503B3ADEFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F18CDD5E141704BULL,
		0xA7F380E5A0DB19DCULL,
		0xE661A110C797C85BULL,
		0x857BC2248EE92775ULL,
		0x43200C9765A93FF6ULL,
		0x68C2BD0B05B25558ULL,
		0x6D7454CF7072AF68ULL,
		0xDD37F8F038C4E8B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D5E877381BD9C11ULL,
		0x4A5D3A3F3244A9C2ULL,
		0x45C65321E3A006EBULL,
		0x4E6DA9E3163CCA0FULL,
		0x8102F29384C2B616ULL,
		0x5FBFCE9BE5B48B76ULL,
		0xCE2631297FCE17FBULL,
		0xF646E6600275F649ULL
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
		0x356DB250B8D9B182ULL,
		0x2B62A722F33A3DA5ULL,
		0xC84D96E3D413AF87ULL,
		0x98A91C65164A7DDFULL,
		0x180718F3A762A9A9ULL,
		0x4F822D20B27C71BDULL,
		0xDC59CA51D38B2C61ULL,
		0x8C26925E0308DF4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC19E0A18057D08ULL,
		0x97668B179D506473ULL,
		0x885C0C7A4A7E652CULL,
		0x52480A909D86256AULL,
		0x469F13AA8CFCF73CULL,
		0x5ED237E87FEC385EULL,
		0x6B8C37B6160776B1ULL,
		0xDEC8F9DAD4447B2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AAC1446A0D4347AULL,
		0x93FC1C0B55E9D931ULL,
		0x3FF18A6989954A5AULL,
		0x466111D478C45875ULL,
		0xD16805491A65B26DULL,
		0xF0AFF5383290395EULL,
		0x70CD929BBD83B5AFULL,
		0xAD5D98832EC46421ULL
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
		0x2FF31E89CA741EF4ULL,
		0xB0D8FE842171C354ULL,
		0xF9C764A20023CDD0ULL,
		0xE6035780BD536A7AULL,
		0x0D855B21299DA197ULL,
		0xA788C5269280EB26ULL,
		0xBCBB3289074E058DULL,
		0xA985584AF73DEA85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728AB5D71232373AULL,
		0x40B2BFAE6269E8BCULL,
		0x78695BB20DB2D6F7ULL,
		0x08099BC678D5E069ULL,
		0xDFAF870D9D70796EULL,
		0x9A30167A9BAF37B2ULL,
		0x6BA872C7F457C459ULL,
		0xA6DFB7DB7D676614ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBD6868B2B841E7BAULL,
		0x70263ED5BF07DA97ULL,
		0x815E08EFF270F6D9ULL,
		0xDDF9BBBA447D8A11ULL,
		0x2DD5D4138C2D2829ULL,
		0x0D58AEABF6D1B373ULL,
		0x5112BFC112F64134ULL,
		0x02A5A06F79D68471ULL
	}};
	sign = 0;
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
		0x70B4F89D3DD86DBDULL,
		0xAD4EF9C7AC468179ULL,
		0x5DCF13977CE87C5FULL,
		0x6DB6CD0A3DDC8EC1ULL,
		0x870608C56C294E5FULL,
		0x151F0C865186BCC6ULL,
		0x684778C82CA32BCEULL,
		0xE2E235A94B968B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA66C581F0B8DB700ULL,
		0x7793F07BD7F2CCE9ULL,
		0x44CFF1A781A83D4FULL,
		0x680332DCE9CF6A92ULL,
		0xAF98883C5289BA75ULL,
		0x28676D32D6AF59F3ULL,
		0x9B22E054CC844F3EULL,
		0xCEB25981BEDD7EABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA48A07E324AB6BDULL,
		0x35BB094BD453B48FULL,
		0x18FF21EFFB403F10ULL,
		0x05B39A2D540D242FULL,
		0xD76D8089199F93EAULL,
		0xECB79F537AD762D2ULL,
		0xCD249873601EDC8FULL,
		0x142FDC278CB90CD8ULL
	}};
	sign = 0;
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
		0x67004A7142DB28A7ULL,
		0xF137F7DDBDB034A9ULL,
		0xD6F1AFFA813BF8D3ULL,
		0xFBABA3682592655BULL,
		0xB8FAB7D0B08494D5ULL,
		0x65FF398FB0D6054BULL,
		0xF306522E57698446ULL,
		0x9F5EA1013DF4E0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x163CFDD1A4873941ULL,
		0x702FBC98B544D4C6ULL,
		0x01ABFDA769421C94ULL,
		0xF17516192FB5FD9AULL,
		0xF1F076E930FF2E33ULL,
		0x157A29309265EFC5ULL,
		0xD33140805725AB08ULL,
		0xBA9FEADEE01407F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50C34C9F9E53EF66ULL,
		0x81083B45086B5FE3ULL,
		0xD545B25317F9DC3FULL,
		0x0A368D4EF5DC67C1ULL,
		0xC70A40E77F8566A2ULL,
		0x5085105F1E701585ULL,
		0x1FD511AE0043D93EULL,
		0xE4BEB6225DE0D8AFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6D4E534793D578A5ULL,
		0x1E90C651FFBBAF90ULL,
		0xF282005B24165056ULL,
		0x11984F01A53CF9CEULL,
		0x63E3AF9BACE52F7FULL,
		0x435756C5853F8C48ULL,
		0x8D9A7250C0472B17ULL,
		0xD0E7F8422BAD5D2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5088BD02195F4EBULL,
		0x5807AEB8B50101CEULL,
		0x0DC3538BD718D934ULL,
		0x8C2F6E3671B6C876ULL,
		0xC2CD5352B1FA8C57ULL,
		0xC2FABDFADEA8839BULL,
		0xAF6688C730F513FAULL,
		0x21EB55C729AB6709ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB845C777723F83BAULL,
		0xC68917994ABAADC1ULL,
		0xE4BEACCF4CFD7721ULL,
		0x8568E0CB33863158ULL,
		0xA1165C48FAEAA327ULL,
		0x805C98CAA69708ACULL,
		0xDE33E9898F52171CULL,
		0xAEFCA27B0201F624ULL
	}};
	sign = 0;
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
		0x7659BF6ADBB8BC5FULL,
		0x52E5EB8432E2B084ULL,
		0xB08D57353533064AULL,
		0x86F994DBB2487DA0ULL,
		0x31F4C5D7A9E6A8F3ULL,
		0xC7BDC158B9AF7AD2ULL,
		0xE3F953C9BA36CEFFULL,
		0xA75F777593B99DDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51306834400C992ULL,
		0x59E96C5BFA418AACULL,
		0x18805BB97460EBEDULL,
		0xD6AC984019049082ULL,
		0xA6A3481757CEF7D2ULL,
		0x805D96E0F0E62918ULL,
		0x120CD07F0C4F4D41ULL,
		0x9DE67D891CBB1BB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9146B8E797B7F2CDULL,
		0xF8FC7F2838A125D7ULL,
		0x980CFB7BC0D21A5CULL,
		0xB04CFC9B9943ED1EULL,
		0x8B517DC05217B120ULL,
		0x47602A77C8C951B9ULL,
		0xD1EC834AADE781BEULL,
		0x0978F9EC76FE8226ULL
	}};
	sign = 0;
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
		0x4954C74835081CE5ULL,
		0xE7A1F96FDB7A78BAULL,
		0x445E74E882FAF60BULL,
		0x088F20379CFAFBB3ULL,
		0x2D7E3A7A62BBF84CULL,
		0x14ECF0708A2DEA5AULL,
		0x9DCFE3BC1381552FULL,
		0x585B9F6F97158D54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B913078BD8EEDA3ULL,
		0x3C1A653C8993A76DULL,
		0xDB58BF053E46C9D6ULL,
		0x631B7C4350DEF00BULL,
		0x976E557EBF5D16EAULL,
		0x8DD6E3B320FEFDEAULL,
		0xDF83C4BABC7EC8D1ULL,
		0x0FD3CA3E3E1DA563ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDC396CF77792F42ULL,
		0xAB87943351E6D14CULL,
		0x6905B5E344B42C35ULL,
		0xA573A3F44C1C0BA7ULL,
		0x960FE4FBA35EE161ULL,
		0x87160CBD692EEC6FULL,
		0xBE4C1F0157028C5DULL,
		0x4887D53158F7E7F0ULL
	}};
	sign = 0;
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
		0x1419FE6AB36934ADULL,
		0xC8619388EAE228A0ULL,
		0x9523F47B647A6D0AULL,
		0xFEDC00065C2BD218ULL,
		0xB29693EE54BA797DULL,
		0x0A68AB473427B188ULL,
		0xE2C94B1F7A8A9BA0ULL,
		0x84A8D816BD9BFDBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1CCC19F84D416ECULL,
		0x87385841B31BEA9CULL,
		0x2A2EEEBD0821E0C5ULL,
		0xD065B51078CBC30CULL,
		0x9606A46B85ACABA5ULL,
		0xA48E0C0910181260ULL,
		0xE1B25B03B7EB00F7ULL,
		0xC2EB0D3DDC503B0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x224D3CCB2E951DC1ULL,
		0x41293B4737C63E03ULL,
		0x6AF505BE5C588C45ULL,
		0x2E764AF5E3600F0CULL,
		0x1C8FEF82CF0DCDD8ULL,
		0x65DA9F3E240F9F28ULL,
		0x0116F01BC29F9AA8ULL,
		0xC1BDCAD8E14BC2AFULL
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
		0x26B20F4C3A70BABDULL,
		0x7D84BA8C099310FAULL,
		0xDB765E3999DEE664ULL,
		0xFA615F0FEB9DE407ULL,
		0x8F754DFE215A4B09ULL,
		0x58394CF7730EB80DULL,
		0x275D0A163648F869ULL,
		0x57941B163921FD43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F8CB8392E5A6F79ULL,
		0x0689FD6E0B3A545DULL,
		0xF24BBD73D1F18E87ULL,
		0x74EA2B7BAC52979DULL,
		0xF1E95242BDD90792ULL,
		0x12C21B20048597A6ULL,
		0xCE5472FBC1AEC31FULL,
		0x8A165DAD69200098ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE72557130C164B44ULL,
		0x76FABD1DFE58BC9CULL,
		0xE92AA0C5C7ED57DDULL,
		0x857733943F4B4C69ULL,
		0x9D8BFBBB63814377ULL,
		0x457731D76E892066ULL,
		0x5908971A749A354AULL,
		0xCD7DBD68D001FCAAULL
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
		0xED35722A7602F6A7ULL,
		0x795E6712709896BBULL,
		0xD40563036863BB0FULL,
		0x82BB12A085709305ULL,
		0x4C0DD5C088989F13ULL,
		0xD242EFD225583F8AULL,
		0x02A40B5EF257E0DEULL,
		0xD69113D5FBC306A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD9708AF8E52F95ULL,
		0x31B6C7AA8B9E0CA9ULL,
		0x8B695C230B17C033ULL,
		0x3655BC27297AF756ULL,
		0x34F090E58FD881EDULL,
		0x7B4E7695D92FDE3BULL,
		0xFF2F640185B46936ULL,
		0x7BDA0C566051DE0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x105C019F7D1DC712ULL,
		0x47A79F67E4FA8A12ULL,
		0x489C06E05D4BFADCULL,
		0x4C6556795BF59BAFULL,
		0x171D44DAF8C01D26ULL,
		0x56F4793C4C28614FULL,
		0x0374A75D6CA377A8ULL,
		0x5AB7077F9B71289BULL
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
		0xE84FCEF6BF72B498ULL,
		0x785DD4E68651D363ULL,
		0x60948B99D1FD7AA1ULL,
		0x8EEE8D4E324D85A4ULL,
		0x9AC8BFC5BA9E9A36ULL,
		0xD0F3478D7BCE4351ULL,
		0xF50A54F708E80340ULL,
		0x8B11A7C2CE6D7248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A5FA3F80B118311ULL,
		0x02E87D7DF8286EF7ULL,
		0xF45E460F52E8087CULL,
		0x0782278F9C6B6252ULL,
		0x702A0A853DFE11CCULL,
		0xC24256BD7E1099EEULL,
		0x3C165A9F74478BBFULL,
		0x0CF13A1668A45C26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xADF02AFEB4613187ULL,
		0x757557688E29646CULL,
		0x6C36458A7F157225ULL,
		0x876C65BE95E22351ULL,
		0x2A9EB5407CA0886AULL,
		0x0EB0F0CFFDBDA963ULL,
		0xB8F3FA5794A07781ULL,
		0x7E206DAC65C91622ULL
	}};
	sign = 0;
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
		0xFC37F17611C2D980ULL,
		0xD91618B34C36E3EFULL,
		0x935858BD2781D9A0ULL,
		0x6F9E4AEA45AECB9FULL,
		0x8A1139D9C243ADD7ULL,
		0x06C7E45C90B9CD59ULL,
		0x69AC1862344AEF41ULL,
		0x6FFFA0834C18B58FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7276F4C39DCD5472ULL,
		0xFAD8FA5B0480079AULL,
		0xECB20FC93011C475ULL,
		0x4377DFC888EE3E2EULL,
		0xD6A1292B6D8E3071ULL,
		0x89EE813B6B42D58BULL,
		0xC19776F684504F82ULL,
		0x8793073B2E3F3326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x89C0FCB273F5850EULL,
		0xDE3D1E5847B6DC55ULL,
		0xA6A648F3F770152AULL,
		0x2C266B21BCC08D70ULL,
		0xB37010AE54B57D66ULL,
		0x7CD963212576F7CDULL,
		0xA814A16BAFFA9FBEULL,
		0xE86C99481DD98268ULL
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
		0xB88E9714426322EDULL,
		0x478FFBB37237D2F7ULL,
		0x5617B6BF22BFDD6AULL,
		0x9FBD32EAF46591FBULL,
		0x8AAE60C0DB73961BULL,
		0x93FB69537BB88BC7ULL,
		0xE74249402CEB6A4AULL,
		0xBFC956A410F8583DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62A6846FD1E36712ULL,
		0xFE27586F671F44CCULL,
		0x7D8E0DFEFB41F680ULL,
		0x2B3D12CA064DE89DULL,
		0xBB75BF02E4E7CAE4ULL,
		0xA4574D0CD4398750ULL,
		0x2353017277FDD3A1ULL,
		0xB1995D3ED3655DA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55E812A4707FBBDBULL,
		0x4968A3440B188E2BULL,
		0xD889A8C0277DE6E9ULL,
		0x74802020EE17A95DULL,
		0xCF38A1BDF68BCB37ULL,
		0xEFA41C46A77F0476ULL,
		0xC3EF47CDB4ED96A8ULL,
		0x0E2FF9653D92FA99ULL
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
		0x48C95D6BCFED852AULL,
		0xE6AA2E76DE819253ULL,
		0x511104FA68C12121ULL,
		0x2AB07B5CE98BCDE7ULL,
		0xD5F6B1B204729AFDULL,
		0xC2B40AB7405B02F7ULL,
		0xAF1CFB7AE0AFD326ULL,
		0xDB17118202CCA205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2477FD532DC91A71ULL,
		0x39E96DF206F2C41BULL,
		0x517EB4EE449E6D05ULL,
		0x2E4A8C4119594C98ULL,
		0xAEC3F5A48C7E27C8ULL,
		0x6DB84CB86DC5E700ULL,
		0xD8DD484A9BCC99AAULL,
		0xA43E4213E2B16CC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24516018A2246AB9ULL,
		0xACC0C084D78ECE38ULL,
		0xFF92500C2422B41CULL,
		0xFC65EF1BD032814EULL,
		0x2732BC0D77F47334ULL,
		0x54FBBDFED2951BF7ULL,
		0xD63FB33044E3397CULL,
		0x36D8CF6E201B353CULL
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
		0xD5E81BC182AE77BAULL,
		0xD85EE87C98640DD0ULL,
		0xC2ED064F3F254BF8ULL,
		0x4E5599B94F379CF1ULL,
		0x0AF3D82AB462841FULL,
		0xC53B880A0DA4BDE6ULL,
		0x9ACFE5573CB158BBULL,
		0x4044207451D61A7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74BAF4B8E74BAFD8ULL,
		0x62DEF5117E2DA865ULL,
		0xFD7AEDFEDFA32364ULL,
		0x3AEACB71A432782FULL,
		0xA467E3BB2A3E773AULL,
		0x0156C246B1C283A7ULL,
		0x3A778D47B2DE9E6AULL,
		0x3B7EE42466C13BCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x612D27089B62C7E2ULL,
		0x757FF36B1A36656BULL,
		0xC57218505F822894ULL,
		0x136ACE47AB0524C1ULL,
		0x668BF46F8A240CE5ULL,
		0xC3E4C5C35BE23A3EULL,
		0x6058580F89D2BA51ULL,
		0x04C53C4FEB14DEAFULL
	}};
	sign = 0;
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
		0x1D5BC46F2160B846ULL,
		0x36C3B4370FF5B661ULL,
		0xECC45334068B3472ULL,
		0xD3301E0BA5315EB8ULL,
		0x9F1B640772C4047BULL,
		0x1DC1899342E60813ULL,
		0x334E044183823CA9ULL,
		0xD06A78176D401062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x927F7D197A690B31ULL,
		0x2AA06ED42EB3338BULL,
		0x870E789FE02D3E05ULL,
		0x327EE7212946E148ULL,
		0x16259B9EDC8AD2D0ULL,
		0xD66D77CE6A3B1F62ULL,
		0x402B4CEAEAA65DB9ULL,
		0xE3B74DF3E847B1A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8ADC4755A6F7AD15ULL,
		0x0C234562E14282D5ULL,
		0x65B5DA94265DF66DULL,
		0xA0B136EA7BEA7D70ULL,
		0x88F5C868963931ABULL,
		0x475411C4D8AAE8B1ULL,
		0xF322B75698DBDEEFULL,
		0xECB32A2384F85EBBULL
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
		0x20101F9C42E6D3AAULL,
		0xE499CDCF63989160ULL,
		0xBFE5023782B396F2ULL,
		0xC47999398EEBC1FAULL,
		0x1422CCDBA2502100ULL,
		0x2B91CD4B8143D9B2ULL,
		0xD42606EAF31D04F4ULL,
		0x53B330486B0B5365ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD02A8B3D0D36F564ULL,
		0x9BF6110E785E406BULL,
		0x7BD5FA2F9408B3D2ULL,
		0xC7D5526DC14F1BEBULL,
		0x099528DE32908E82ULL,
		0x23F9F14DF5BAED57ULL,
		0xE7ABA31124C641A9ULL,
		0x77E44EA731C26C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FE5945F35AFDE46ULL,
		0x48A3BCC0EB3A50F4ULL,
		0x440F0807EEAAE320ULL,
		0xFCA446CBCD9CA60FULL,
		0x0A8DA3FD6FBF927DULL,
		0x0797DBFD8B88EC5BULL,
		0xEC7A63D9CE56C34BULL,
		0xDBCEE1A13948E703ULL
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
		0x588962CD0F8C6E27ULL,
		0x99F0A8BC5AE17819ULL,
		0xB3AAC56597DE878FULL,
		0x5DA49C67284AA585ULL,
		0xCA3FBB5F83ABEA84ULL,
		0x2A5CEB45C2E1F572ULL,
		0xF7F332F2D1CC5856ULL,
		0x26487D5A6E81A85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A06F8D7D9C5C5B2ULL,
		0x1B335AB7FE09E5ECULL,
		0x5328CB478CCAAE74ULL,
		0xF14ECD7A0843EDDBULL,
		0x14C8B4131FF0B058ULL,
		0xED7F4206142A7C17ULL,
		0x4428CA22342EC640ULL,
		0xF9F07CB3856B56B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E8269F535C6A875ULL,
		0x7EBD4E045CD7922DULL,
		0x6081FA1E0B13D91BULL,
		0x6C55CEED2006B7AAULL,
		0xB577074C63BB3A2BULL,
		0x3CDDA93FAEB7795BULL,
		0xB3CA68D09D9D9215ULL,
		0x2C5800A6E91651A7ULL
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
		0xFEA4139D5D916788ULL,
		0x33F33B47C8E126F7ULL,
		0x720C46E297EA02E8ULL,
		0xCBCACF4A01FFE109ULL,
		0x4029A66E3A282133ULL,
		0xC20EB10C18FD72F9ULL,
		0x166A4AB5A61192B7ULL,
		0x3442A8BB67775E26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29ACF647DC954C4FULL,
		0x608ED92736CB9916ULL,
		0x9919FD9A1F837CE3ULL,
		0xAA74F46E8F1B5615ULL,
		0x832DA15C23CE86CEULL,
		0xC85FCD351CEDF56DULL,
		0x622BB348951CEC82ULL,
		0x4821291A1F8290A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4F71D5580FC1B39ULL,
		0xD364622092158DE1ULL,
		0xD8F2494878668604ULL,
		0x2155DADB72E48AF3ULL,
		0xBCFC051216599A65ULL,
		0xF9AEE3D6FC0F7D8BULL,
		0xB43E976D10F4A634ULL,
		0xEC217FA147F4CD7EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDDA2EFB4B1752107ULL,
		0x8A6F81B1544B5648ULL,
		0x44BD99BBF333BCF6ULL,
		0xF3C98A301C599532ULL,
		0x642192F0FFD0A721ULL,
		0x2F787AEAD2281ED2ULL,
		0x041D32E6B4EDF950ULL,
		0xAB073C22E2680AE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA22DFB7FE112518ULL,
		0xD6BF7E0DB439AB6CULL,
		0x122681AD819C52D9ULL,
		0xF04C883B3228C78BULL,
		0x792191576F7BBABAULL,
		0x265FA382DF4600B4ULL,
		0x35BEB1F70EADC85EULL,
		0x44FD02A53D2E9370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23800FFCB363FBEFULL,
		0xB3B003A3A011AADCULL,
		0x3297180E71976A1CULL,
		0x037D01F4EA30CDA7ULL,
		0xEB0001999054EC67ULL,
		0x0918D767F2E21E1DULL,
		0xCE5E80EFA64030F2ULL,
		0x660A397DA539776FULL
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
		0x7B8C3FCD5B6FE1A0ULL,
		0xEDB12FED416ED2ADULL,
		0xEA0D6BFCA3639CBEULL,
		0xAFDF5A27DAC42EECULL,
		0x81CB582C0A506725ULL,
		0x74E573402CCBAAA5ULL,
		0x6B6622260427E62CULL,
		0x28101A34A5EA6C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x764E1AA1827807D9ULL,
		0x475E923893374653ULL,
		0x411DEBBEC46A7CFDULL,
		0x2246DD4B69ED1BBAULL,
		0xB55261D9B731E414ULL,
		0x298BCC53FE85FF10ULL,
		0x2E2B4CDEFDE2F336ULL,
		0xD6B72BE6DBA525A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x053E252BD8F7D9C7ULL,
		0xA6529DB4AE378C5AULL,
		0xA8EF803DDEF91FC1ULL,
		0x8D987CDC70D71332ULL,
		0xCC78F652531E8311ULL,
		0x4B59A6EC2E45AB94ULL,
		0x3D3AD5470644F2F6ULL,
		0x5158EE4DCA4546B1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x636B6864022F570CULL,
		0xA5A35074BDBD7332ULL,
		0xA531E8AB18F4E252ULL,
		0xB2C34B1861417BD9ULL,
		0x92EB822384742353ULL,
		0xEDF23FDDABA75077ULL,
		0xAE0B8DA2232CCF0BULL,
		0x8BBA81958DFF4C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD457762ED10E7CB6ULL,
		0x393ED0B705667D76ULL,
		0xC796AB5097EC771FULL,
		0x6D250566377367C0ULL,
		0x68A5C3D0A8E57852ULL,
		0xD401340F7450D936ULL,
		0xFCB3A40BFC6F85DCULL,
		0xC05000F87D266ADBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F13F2353120DA56ULL,
		0x6C647FBDB856F5BBULL,
		0xDD9B3D5A81086B33ULL,
		0x459E45B229CE1418ULL,
		0x2A45BE52DB8EAB01ULL,
		0x19F10BCE37567741ULL,
		0xB157E99626BD492FULL,
		0xCB6A809D10D8E131ULL
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
		0x1A00E8781068DE02ULL,
		0x02AFD76794FFA982ULL,
		0x5E3DC76A26B11FDFULL,
		0x4017323754750DF4ULL,
		0xE16F38CAF4C3A511ULL,
		0x09C10175E9CBCBE0ULL,
		0x810A002F6B90CA22ULL,
		0x07E670B1E01BAAB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x362C8F52A6FA44B4ULL,
		0x86F408510E7FCE5AULL,
		0xA4BD0AD7A66CACBEULL,
		0x6E707CE8A2AFE296ULL,
		0x44E2B31E4F3FAAADULL,
		0xD42B7D36873D6609ULL,
		0xF959EC1D96CA405BULL,
		0x7565EA79901710BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3D45925696E994EULL,
		0x7BBBCF16867FDB27ULL,
		0xB980BC9280447320ULL,
		0xD1A6B54EB1C52B5DULL,
		0x9C8C85ACA583FA63ULL,
		0x3595843F628E65D7ULL,
		0x87B01411D4C689C6ULL,
		0x92808638500499F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0ABAB012E6DDD9B1ULL,
		0xFEF6CECC4664B00EULL,
		0x5DB88D5A3EC962C5ULL,
		0x7ADAEDA7082072C3ULL,
		0xECEE69D5142A08CEULL,
		0x655F0AAA5E07B011ULL,
		0x7DB971FEAAAB485FULL,
		0xF2E1BEA356EDD921ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD933AA54A2163A6CULL,
		0xE7FB97BE30EE1525ULL,
		0x6BD02C88C51A5985ULL,
		0x65ACC9512A71611CULL,
		0x2D2397B3FAD4791EULL,
		0x6478573B9F753604ULL,
		0x095D28CC7F855041ULL,
		0x3F47988EBCF3D93BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x318705BE44C79F45ULL,
		0x16FB370E15769AE8ULL,
		0xF1E860D179AF0940ULL,
		0x152E2455DDAF11A6ULL,
		0xBFCAD22119558FB0ULL,
		0x00E6B36EBE927A0DULL,
		0x745C49322B25F81EULL,
		0xB39A261499F9FFE6ULL
	}};
	sign = 0;
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
		0x3731DA1ADBE40E82ULL,
		0x234E2FEE7AFE48B4ULL,
		0xC841C7357B030BDBULL,
		0x1693DF8868605F06ULL,
		0xB5B521EBD963E32EULL,
		0xB1B23821077A9D72ULL,
		0xE3FE3344D9F67EEBULL,
		0x9189D4168A1620C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D57EBB5CBC2D180ULL,
		0x1C08E58B1A8A35FDULL,
		0xB9E645471280C3B4ULL,
		0x5CE1FBBBAE76D414ULL,
		0x14284CDD860F2712ULL,
		0x1717DED89FCD2341ULL,
		0x4E0F2FCEB0E4900AULL,
		0x5360975A96A50E68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09D9EE6510213D02ULL,
		0x07454A63607412B7ULL,
		0x0E5B81EE68824827ULL,
		0xB9B1E3CCB9E98AF2ULL,
		0xA18CD50E5354BC1BULL,
		0x9A9A594867AD7A31ULL,
		0x95EF03762911EEE1ULL,
		0x3E293CBBF3711261ULL
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
		0x9DF952C47BDDDEB5ULL,
		0xCB23F15724990BF0ULL,
		0x5F2358A6AC45B8E0ULL,
		0xF1A5422BD770D91BULL,
		0x0C1C80A1C8A89554ULL,
		0x70D18024703EF245ULL,
		0x001EDE8D7BBD2ABCULL,
		0x0AF4F89DACCC6E8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4351691D12E54458ULL,
		0x37EAC5C303CB44DAULL,
		0xAC2DD0A943E956A0ULL,
		0x9481439B694C4F5DULL,
		0xF8846E93B4378703ULL,
		0x45776647006AD48CULL,
		0x73FEEBE8E98C9D1AULL,
		0xFECC725FA05BBA81ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5AA7E9A768F89A5DULL,
		0x93392B9420CDC716ULL,
		0xB2F587FD685C6240ULL,
		0x5D23FE906E2489BDULL,
		0x1398120E14710E51ULL,
		0x2B5A19DD6FD41DB8ULL,
		0x8C1FF2A492308DA2ULL,
		0x0C28863E0C70B40BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x846CC1D16A49D257ULL,
		0xA3BF77563665DA5FULL,
		0x0C0EEA0E1D40CFA5ULL,
		0x6F15BF68F15B2C7EULL,
		0x412C788C2E246746ULL,
		0x53268E7BECE3DC19ULL,
		0xD93DF0653E142950ULL,
		0x4A91A27DEEC40BA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780AF43D02B542B3ULL,
		0xB826DED6A1238A63ULL,
		0xEAD81ADDB8C08E1FULL,
		0xBE075FD6C5FF2945ULL,
		0xC82EF243E8979064ULL,
		0xB0DE8F52D17F81D9ULL,
		0x8A1EE9CC8DE389B8ULL,
		0x527C458F66A3576AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C61CD9467948FA4ULL,
		0xEB98987F95424FFCULL,
		0x2136CF3064804185ULL,
		0xB10E5F922B5C0338ULL,
		0x78FD8648458CD6E1ULL,
		0xA247FF291B645A3FULL,
		0x4F1F0698B0309F97ULL,
		0xF8155CEE8820B43FULL
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
		0xBD5744C3C0CC5E14ULL,
		0xDE6620C4D18D8FB7ULL,
		0x9DF44694356E53EEULL,
		0x3AE6CE38F1BB882BULL,
		0xDC893DCC2149B411ULL,
		0x91A1635691500F91ULL,
		0xD0E597A2384CEB73ULL,
		0x0527943C7873AF66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A493E3A1818D0C0ULL,
		0x0B7B615064D302B2ULL,
		0xE8FB8FD077C1C2F9ULL,
		0xB90A37CAFA8C9D0EULL,
		0xB82C9964F67A8CFFULL,
		0x67DE235BF8F38F93ULL,
		0x27EA8547B74365B4ULL,
		0x01A132D8A4B821EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB30E0689A8B38D54ULL,
		0xD2EABF746CBA8D05ULL,
		0xB4F8B6C3BDAC90F5ULL,
		0x81DC966DF72EEB1CULL,
		0x245CA4672ACF2711ULL,
		0x29C33FFA985C7FFEULL,
		0xA8FB125A810985BFULL,
		0x03866163D3BB8D77ULL
	}};
	sign = 0;
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
		0x58C42AF2FD268239ULL,
		0x6C998D1C51F0C551ULL,
		0xE5163B1CCC510E53ULL,
		0x3DB493398F4E71AFULL,
		0x344AA41853DB6E0DULL,
		0x951603B1A08BF10BULL,
		0x86016276210F02A4ULL,
		0xE7C6E262AFFC8D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB23CCFD22DA73E5ULL,
		0xDFC2CA4E6D012090ULL,
		0x56E204FB6D05F3FBULL,
		0xFA975F9BB1AA6A15ULL,
		0x22EA4CC82AC063A4ULL,
		0xE4BB60E92FF628F3ULL,
		0x9C766A94EF0F6F48ULL,
		0x642C421A05C27A4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7DA05DF5DA4C0E54ULL,
		0x8CD6C2CDE4EFA4C0ULL,
		0x8E3436215F4B1A57ULL,
		0x431D339DDDA4079AULL,
		0x11605750291B0A68ULL,
		0xB05AA2C87095C818ULL,
		0xE98AF7E131FF935BULL,
		0x839AA048AA3A1334ULL
	}};
	sign = 0;
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
		0x81BD8613E1F26D85ULL,
		0x22B9DB044AC7C337ULL,
		0xA8F898070F824E24ULL,
		0xF8215DB6F2D15F21ULL,
		0x50CB31AAA84BE05BULL,
		0xA957A299FB633949ULL,
		0x2401CB54B312F130ULL,
		0x8F8AEF86729C3EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BF9B1B9D82B201CULL,
		0x2DFC21D365DE9107ULL,
		0x9FB996390AEC71F5ULL,
		0x20AFD306870C4215ULL,
		0xD73D6CEA6A39DD44ULL,
		0x8A9812B04622562DULL,
		0xA7E84F5CAF4F2526ULL,
		0xED4FCB1031C2C74FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35C3D45A09C74D69ULL,
		0xF4BDB930E4E93230ULL,
		0x093F01CE0495DC2EULL,
		0xD7718AB06BC51D0CULL,
		0x798DC4C03E120317ULL,
		0x1EBF8FE9B540E31BULL,
		0x7C197BF803C3CC0AULL,
		0xA23B247640D977A2ULL
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
		0x653E18CF2F1AA3B3ULL,
		0xF84D34BFC162A85BULL,
		0x9D56A12FDB0BFDF2ULL,
		0x20D866D840711ED3ULL,
		0x7848356CB44CBDA0ULL,
		0xEAD8D5A5107AED59ULL,
		0xC08B403C289EC3CDULL,
		0x2753AC901B65C131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FA15ACA1E44B2FCULL,
		0x2FEEE1320A95AA45ULL,
		0x1EBE4ECB284245B4ULL,
		0x25570BBC9A2A1445ULL,
		0xD14AD6A906CFCF21ULL,
		0x24150B47AEC18575ULL,
		0x26794B43E57251AAULL,
		0x5C638178E628F711ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x559CBE0510D5F0B7ULL,
		0xC85E538DB6CCFE16ULL,
		0x7E985264B2C9B83EULL,
		0xFB815B1BA6470A8EULL,
		0xA6FD5EC3AD7CEE7EULL,
		0xC6C3CA5D61B967E3ULL,
		0x9A11F4F8432C7223ULL,
		0xCAF02B17353CCA20ULL
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
		0xD15838C5B39967D2ULL,
		0x9AC2C6B325A53049ULL,
		0x5289BCAAD5C1E194ULL,
		0x5B9D87BCDEC5470FULL,
		0x0DB880540AECAC56ULL,
		0x3ABB1C5A1B530811ULL,
		0xF550E0A5968A8EADULL,
		0x2E5AE77AE196AA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD06C18A3D74E0F33ULL,
		0xB7047513586FD20EULL,
		0x5C7D1FF82AB07751ULL,
		0x056FD2A50C50DF16ULL,
		0x0A0D0A971EE6A03BULL,
		0xCC790C7E61AF1B7EULL,
		0xAC6CF4213B2D5B54ULL,
		0x8F5ABB996BAC28DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00EC2021DC4B589FULL,
		0xE3BE519FCD355E3BULL,
		0xF60C9CB2AB116A42ULL,
		0x562DB517D27467F8ULL,
		0x03AB75BCEC060C1BULL,
		0x6E420FDBB9A3EC93ULL,
		0x48E3EC845B5D3358ULL,
		0x9F002BE175EA81AAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x50E0F1BC21874BCFULL,
		0xCD4B0338B50DB1FBULL,
		0x4CC4A4E0F59344D0ULL,
		0x503CFE199AA64874ULL,
		0x3E012FE890432318ULL,
		0x7E294A5BAD0AC34CULL,
		0xC214C27804D1BA88ULL,
		0xA5D807441F09777EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C0F67732EBD495ULL,
		0xA10C4423FC836EA7ULL,
		0x9B9FD84D463318D3ULL,
		0xEC5268FE7A09470AULL,
		0x7D5E0E20F080416CULL,
		0xFBC30038860A8BFDULL,
		0x4A59BADBAB1F1F6BULL,
		0x8F386CF6F7B27DDCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x591FFB44EE9B773AULL,
		0x2C3EBF14B88A4353ULL,
		0xB124CC93AF602BFDULL,
		0x63EA951B209D0169ULL,
		0xC0A321C79FC2E1ABULL,
		0x82664A232700374EULL,
		0x77BB079C59B29B1CULL,
		0x169F9A4D2756F9A2ULL
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
		0x2F6C671659A3DF91ULL,
		0xE84B110F9D18BB6EULL,
		0x1E3D91E799C04FEBULL,
		0x68051016E2C9A56BULL,
		0xBB0829DB1AD805B1ULL,
		0xAE6BB9F089330DC3ULL,
		0x05A2557B92D21B44ULL,
		0x7658A1C2C2390FFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D454493DA7D2DEULL,
		0xF2BC25A093C31695ULL,
		0x1980FB9C9C416B55ULL,
		0x259D4942882F1EC2ULL,
		0x22F99B4A84F91CD7ULL,
		0xD6BA71E443A63855ULL,
		0xD2D872BE78C84688ULL,
		0xD131804001ED826CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA79812CD1BFC0CB3ULL,
		0xF58EEB6F0955A4D8ULL,
		0x04BC964AFD7EE495ULL,
		0x4267C6D45A9A86A9ULL,
		0x980E8E9095DEE8DAULL,
		0xD7B1480C458CD56EULL,
		0x32C9E2BD1A09D4BBULL,
		0xA5272182C04B8D8EULL
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
		0x55732CA0DD84ED61ULL,
		0x463301A4E547A25BULL,
		0x89C30CBC51623E9EULL,
		0xB651D5F2825CD0A6ULL,
		0x4E9DA5C9A7925095ULL,
		0x00342529F9A9BB22ULL,
		0x33648AE1AF6E9458ULL,
		0x0B0E6F659FC80971ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x939C2A5339EC203CULL,
		0x537EF9B8B58D2515ULL,
		0xEAF9328B4AB7EE0EULL,
		0x3B46387489179021ULL,
		0x609A4A1789CE663DULL,
		0x3D29804F38A8C813ULL,
		0xFB15C6731BE24417ULL,
		0x53804BD837F7E55EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1D7024DA398CD25ULL,
		0xF2B407EC2FBA7D45ULL,
		0x9EC9DA3106AA508FULL,
		0x7B0B9D7DF9454084ULL,
		0xEE035BB21DC3EA58ULL,
		0xC30AA4DAC100F30EULL,
		0x384EC46E938C5040ULL,
		0xB78E238D67D02412ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7A32A39E64A98D9DULL,
		0xCB790D29C1EC2DF5ULL,
		0x146210B01E4397B4ULL,
		0x7E47F9E674FE4613ULL,
		0x7975629E2A7BE20CULL,
		0xD91C3B341B8F0EDDULL,
		0xF4676C2B1FF53887ULL,
		0x6790164A9C10FEFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE96BB965DDA2CE1BULL,
		0x6666AC6512923D03ULL,
		0xD65B3A2F9F35EFD6ULL,
		0xE5856558DA1AE3A2ULL,
		0xFE5E28D00DBAF74DULL,
		0xDB18EF0B080EC92AULL,
		0x451F0A13FD113A07ULL,
		0x0FA3D17E6D4C2C8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90C6EA388706BF82ULL,
		0x651260C4AF59F0F1ULL,
		0x3E06D6807F0DA7DEULL,
		0x98C2948D9AE36270ULL,
		0x7B1739CE1CC0EABEULL,
		0xFE034C29138045B2ULL,
		0xAF48621722E3FE7FULL,
		0x57EC44CC2EC4D270ULL
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
		0xB072651C5D9468B7ULL,
		0x8F75DC0574A4D448ULL,
		0x7F41E2C3EE1B5B17ULL,
		0x10AB017DBF7729BBULL,
		0xE33FCA4F0BC3FC1DULL,
		0xD3112B88508BC785ULL,
		0x2D061898814F013FULL,
		0x52F78EAB406F31B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D69D704F3C722CULL,
		0x7FF7919EF0FF5272ULL,
		0xDC3CAD7406604291ULL,
		0x6D5541E51CDAFCD4ULL,
		0x9B34D77EC63830B1ULL,
		0xB44B20C384CDFE77ULL,
		0xFCA009BBD80FA921ULL,
		0x0E627105CC9C0955ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF9BC7AC0E57F68BULL,
		0x0F7E4A6683A581D6ULL,
		0xA305354FE7BB1886ULL,
		0xA355BF98A29C2CE6ULL,
		0x480AF2D0458BCB6BULL,
		0x1EC60AC4CBBDC90EULL,
		0x30660EDCA93F581EULL,
		0x44951DA573D3285BULL
	}};
	sign = 0;
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
		0xEA2AD04BEA8BE9E6ULL,
		0xD29C8BF13A186C38ULL,
		0xF5990240522EEEC4ULL,
		0x38EAF7D82E4211E8ULL,
		0x70EB4B3BED028DEAULL,
		0x15B980B80B7E7194ULL,
		0x5FE9C94296F1FE1FULL,
		0x39E093ADB1C6268CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EEBAABCC9498C1FULL,
		0x53EA23D76BD9BDE6ULL,
		0xD708E550ACAD6779ULL,
		0xB5EFEC0A4C1A3E5AULL,
		0x833599E138838576ULL,
		0xBAB95165B2992F48ULL,
		0xDB11B275402B69EFULL,
		0x00F558B7EB63F7C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B3F258F21425DC7ULL,
		0x7EB26819CE3EAE52ULL,
		0x1E901CEFA581874BULL,
		0x82FB0BCDE227D38EULL,
		0xEDB5B15AB47F0873ULL,
		0x5B002F5258E5424BULL,
		0x84D816CD56C6942FULL,
		0x38EB3AF5C6622EC5ULL
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
		0xBFD4023C970BC540ULL,
		0xC792A7911B9DB105ULL,
		0x84DCF63E33DB988BULL,
		0x2D0660B291AEB7D1ULL,
		0xE9517308225A2595ULL,
		0x50EE5A3D5540331AULL,
		0x84FCC0D00F772586ULL,
		0x717E657D89723CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8F884B8970EA15CULL,
		0xAB33DCB1ED1A9BF6ULL,
		0x7AFDCFF12225C57BULL,
		0x185722C28AB0919FULL,
		0x5BDD1E905673A487ULL,
		0xCAF047CBC059433BULL,
		0x3B40DD317F2BD66EULL,
		0x101AF9D70012ACD5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6DB7D83FFFD23E4ULL,
		0x1C5ECADF2E83150EULL,
		0x09DF264D11B5D310ULL,
		0x14AF3DF006FE2632ULL,
		0x8D745477CBE6810EULL,
		0x85FE127194E6EFDFULL,
		0x49BBE39E904B4F17ULL,
		0x61636BA6895F9013ULL
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
		0xFDD0D6F3F40F222FULL,
		0x53B396D484EF7425ULL,
		0x1B339FB47E52F182ULL,
		0x8C180649D5D28243ULL,
		0x84942D0A12231116ULL,
		0x039D6A1C2133C759ULL,
		0xB66BA7497B4844F6ULL,
		0xCD8A0FA33E23B714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x207B2459D39B9F0CULL,
		0xC924FC9C4528B578ULL,
		0x7269A13A0014CBB4ULL,
		0x81B082E2C54F91DBULL,
		0xBA363747DDAD606EULL,
		0xF3AD0E3CA9B127B3ULL,
		0x8BB136CDCB0A220AULL,
		0x1C7250D3E9CF00A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD55B29A20738323ULL,
		0x8A8E9A383FC6BEADULL,
		0xA8C9FE7A7E3E25CDULL,
		0x0A6783671082F067ULL,
		0xCA5DF5C23475B0A8ULL,
		0x0FF05BDF77829FA5ULL,
		0x2ABA707BB03E22EBULL,
		0xB117BECF5454B671ULL
	}};
	sign = 0;
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
		0xCA5333227C252D14ULL,
		0xC26D8651FEC1BDF6ULL,
		0x785187D5D46B2D22ULL,
		0x285EF36045A42419ULL,
		0x189F77E6D02F8565ULL,
		0xACDA5F96D4F3253AULL,
		0x4EA1E502D488C491ULL,
		0xF234E97E4EE23E37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E085E3E9FAFBB2ULL,
		0x77B48BADE689A931ULL,
		0x20C41E993F15C34AULL,
		0xFCA5B682507DD6C4ULL,
		0x5413B10263E6E740ULL,
		0x04F0FA7CEF5BA4AAULL,
		0x278FCA66F95476B1ULL,
		0xA06F9CD24E04AFFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4272AD3E922A3162ULL,
		0x4AB8FAA4183814C5ULL,
		0x578D693C955569D8ULL,
		0x2BB93CDDF5264D55ULL,
		0xC48BC6E46C489E24ULL,
		0xA7E96519E597808FULL,
		0x27121A9BDB344DE0ULL,
		0x51C54CAC00DD8E38ULL
	}};
	sign = 0;
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
		0x740A5D8B1C378C58ULL,
		0x8D5BE9248028C77AULL,
		0x7461361C1AA0AA07ULL,
		0x0D58B86571FAAA81ULL,
		0x849B6ECF6C10503DULL,
		0x996E9389879FED8FULL,
		0x54491B5A55370770ULL,
		0xA164FED6A5252D1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1638E0137A6AD3DEULL,
		0x9A776A6A9C4F051AULL,
		0xD69DA9E5F393C362ULL,
		0x1BF3CB46FEB94F50ULL,
		0x473E3FE2A1757129ULL,
		0x48D0DAD0CFB7E58AULL,
		0x582814299B1188CAULL,
		0xA2451C7BA6DD1B5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DD17D77A1CCB87AULL,
		0xF2E47EB9E3D9C260ULL,
		0x9DC38C36270CE6A4ULL,
		0xF164ED1E73415B30ULL,
		0x3D5D2EECCA9ADF13ULL,
		0x509DB8B8B7E80805ULL,
		0xFC210730BA257EA6ULL,
		0xFF1FE25AFE4811BBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0A5B5D977C0FB299ULL,
		0xC2AE8FCECD5ED4D0ULL,
		0x471CC417E4CFBC94ULL,
		0xA5A9E836E2C3BCB4ULL,
		0x229654A3966DBDE9ULL,
		0x6A314DE3B85AB436ULL,
		0x33EE66530CB9A608ULL,
		0xD9752DEDF40956A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AF81307D230C4A9ULL,
		0xDB1ED1863B4F0585ULL,
		0x51F2057EB80F386FULL,
		0x2E93B45D71A7B45DULL,
		0xF41A8AA3FECD20FDULL,
		0x9E527F8D05185C88ULL,
		0xCCA9EF8749AC9664ULL,
		0xB0BA3859711C2047ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF634A8FA9DEEDF0ULL,
		0xE78FBE48920FCF4AULL,
		0xF52ABE992CC08424ULL,
		0x771633D9711C0856ULL,
		0x2E7BC9FF97A09CECULL,
		0xCBDECE56B34257ADULL,
		0x674476CBC30D0FA3ULL,
		0x28BAF59482ED3660ULL
	}};
	sign = 0;
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
		0x46FC6F6C93BF20FEULL,
		0x42749EA7EBFC2F49ULL,
		0x2229C162AC00B177ULL,
		0x5F9EC92AADDFB032ULL,
		0xE67E361CCD89C985ULL,
		0x562B24B79D0BF90EULL,
		0xC41B3862EEFF58B2ULL,
		0x817CF487F4479C32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD0151B204C50E8ULL,
		0x69F6409A7DCDFBBBULL,
		0x590DCA4808DF0CA0ULL,
		0x3EBB2ED51A92B998ULL,
		0xE36B7127D29D091FULL,
		0x06B3D4114482A5BFULL,
		0x0947CD338D2D9BE5ULL,
		0x27C56E2268B2F2C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x492C5A517372D016ULL,
		0xD87E5E0D6E2E338DULL,
		0xC91BF71AA321A4D6ULL,
		0x20E39A55934CF699ULL,
		0x0312C4F4FAECC066ULL,
		0x4F7750A65889534FULL,
		0xBAD36B2F61D1BCCDULL,
		0x59B786658B94A96BULL
	}};
	sign = 0;
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
		0xDC93B470398BF081ULL,
		0x15F6F0B34B7E1146ULL,
		0xD6B96894DF0EA51DULL,
		0xC4854C6665B650BAULL,
		0x26D0BD15AC65B05DULL,
		0xD599245C82C6519DULL,
		0x4E9170065677EDFAULL,
		0x9EF8D9F5D8519283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5685A05A87122F9ULL,
		0x4AF0EC00BBAC1731ULL,
		0x913AE4FD613EBA37ULL,
		0xAB9C688A03FD4D3AULL,
		0x9968B9EADEC81A3AULL,
		0xFC9ECFD158A91D53ULL,
		0x929A681782F8D657ULL,
		0x28FE1EA337F10727ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x172B5A6A911ACD88ULL,
		0xCB0604B28FD1FA15ULL,
		0x457E83977DCFEAE5ULL,
		0x18E8E3DC61B90380ULL,
		0x8D68032ACD9D9623ULL,
		0xD8FA548B2A1D3449ULL,
		0xBBF707EED37F17A2ULL,
		0x75FABB52A0608B5BULL
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
		0xD58987214C8B7B37ULL,
		0x0534832BA739EC51ULL,
		0xB5F524D18788997AULL,
		0xDEBCA21C04A628C1ULL,
		0x4756CDA4016D06C2ULL,
		0x4A3FC53999F667CAULL,
		0xFD3700C5BF4B78C5ULL,
		0x6140CB296834DEB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29018E97908A8528ULL,
		0x40B1ED893B804117ULL,
		0xFCA0CAC5E5549E15ULL,
		0x0ADB3DAA46B83CC5ULL,
		0xD2691C79628F3907ULL,
		0x9E5C90A6231A4DC8ULL,
		0x95A89F02A333CB3EULL,
		0x6C2476227EB4A6F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC87F889BC00F60FULL,
		0xC48295A26BB9AB3AULL,
		0xB9545A0BA233FB64ULL,
		0xD3E16471BDEDEBFBULL,
		0x74EDB12A9EDDCDBBULL,
		0xABE3349376DC1A01ULL,
		0x678E61C31C17AD86ULL,
		0xF51C5506E98037BEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x61EC983659AA9D54ULL,
		0x331E6A3C4CD4834BULL,
		0x37DED87459ECD709ULL,
		0x8AA329DE63EAC260ULL,
		0x10BC085BA594C039ULL,
		0x2FD72E42E5C634CCULL,
		0x9B807E14FA7927D4ULL,
		0xADFABAC03328DFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0F2284A68B095FDULL,
		0x5D9B9E969E2465A6ULL,
		0x47D38BEDE62EA831ULL,
		0x7B55EECC7B506548ULL,
		0x6CCCFF19805E2140ULL,
		0xDE2C9F77F83D729EULL,
		0xD8FB6A950297592BULL,
		0x31D09316E01C6863ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80FA6FEBF0FA0757ULL,
		0xD582CBA5AEB01DA4ULL,
		0xF00B4C8673BE2ED7ULL,
		0x0F4D3B11E89A5D17ULL,
		0xA3EF094225369EF9ULL,
		0x51AA8ECAED88C22DULL,
		0xC285137FF7E1CEA8ULL,
		0x7C2A27A9530C778CULL
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
		0x02CA03683A3079B0ULL,
		0x9B704E4CE62EBE03ULL,
		0xFB86A4315DFFB5BEULL,
		0x9DE61FB12E5AD198ULL,
		0xAE8B5A8CB8A140D7ULL,
		0x00150C596A9D02CFULL,
		0x631AC9A94DED29A4ULL,
		0x72223ACA4CA10799ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC33B1C97A4A1D123ULL,
		0x4616EA63011C1229ULL,
		0x9724542D85606566ULL,
		0x42067DB3DBD62ED6ULL,
		0xF69A7BA9840323ADULL,
		0x91159206DD0445D9ULL,
		0x901F200C81E98D4EULL,
		0x3560D99C07C5D3B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F8EE6D0958EA88DULL,
		0x555963E9E512ABD9ULL,
		0x64625003D89F5058ULL,
		0x5BDFA1FD5284A2C2ULL,
		0xB7F0DEE3349E1D2AULL,
		0x6EFF7A528D98BCF5ULL,
		0xD2FBA99CCC039C55ULL,
		0x3CC1612E44DB33E0ULL
	}};
	sign = 0;
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
		0x0DB256FAD5B126B3ULL,
		0x67FB4A760BDE7028ULL,
		0xB9AF02AD61A32080ULL,
		0x20D7D51008C5355CULL,
		0x64572AA45557D5A1ULL,
		0x9B67C765A861B941ULL,
		0xABA1969FBB1207A9ULL,
		0xE4ED88F39D76DB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x338781F052BAD4D8ULL,
		0x50008EA6EDE7B9EAULL,
		0x218D0BA95B70861DULL,
		0xD383CB4BB59D6886ULL,
		0xDB3354F397444F5FULL,
		0xD3737E52F85CD382ULL,
		0x4D7B341A8B03F8C7ULL,
		0x71C93CF7AC314993ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA2AD50A82F651DBULL,
		0x17FABBCF1DF6B63DULL,
		0x9821F70406329A63ULL,
		0x4D5409C45327CCD6ULL,
		0x8923D5B0BE138641ULL,
		0xC7F44912B004E5BEULL,
		0x5E266285300E0EE1ULL,
		0x73244BFBF14591B4ULL
	}};
	sign = 0;
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
		0x0A9468754BA5B0A9ULL,
		0xE3BF281BC31FED32ULL,
		0x112272ED77CACFD8ULL,
		0x4404D28AA55A12E5ULL,
		0xE36BD64C1A8116A2ULL,
		0xCF6D3193EEA0E77FULL,
		0x7ACB5984AD0B6D97ULL,
		0x9883EA7C9D7EB8D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDD5FD57085EDD36ULL,
		0x729C90539AFF4410ULL,
		0x571C88368228B3C7ULL,
		0x5DF290C06586259EULL,
		0xA4E651279F917ED9ULL,
		0x434813E9CC064AF8ULL,
		0x72A2DA92CB8A38C8ULL,
		0xF6BF9A5647CD1F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CBE6B1E4346D373ULL,
		0x712297C82820A921ULL,
		0xBA05EAB6F5A21C11ULL,
		0xE61241CA3FD3ED46ULL,
		0x3E8585247AEF97C8ULL,
		0x8C251DAA229A9C87ULL,
		0x08287EF1E18134CFULL,
		0xA1C4502655B199D0ULL
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
		0xA644F9E184B4CCD8ULL,
		0x8EAABC20F4D74C66ULL,
		0x770000D14FAFC5C3ULL,
		0x853EADB860E8DA7DULL,
		0x7BB4438A27CF78EFULL,
		0x1448234704D44E59ULL,
		0x14D66DBD56E87B5EULL,
		0x3EB35172DE2500CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7408BDF829D9019BULL,
		0x56AD9E2284F5A524ULL,
		0x4CC26227E421122AULL,
		0x88A2628914D336F7ULL,
		0x5A903FBA78B5CF3BULL,
		0x7323153745CC513BULL,
		0x170E15E466D562F0ULL,
		0x5EA75F3EFB827162ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x323C3BE95ADBCB3DULL,
		0x37FD1DFE6FE1A742ULL,
		0x2A3D9EA96B8EB399ULL,
		0xFC9C4B2F4C15A386ULL,
		0x212403CFAF19A9B3ULL,
		0xA1250E0FBF07FD1EULL,
		0xFDC857D8F013186DULL,
		0xE00BF233E2A28F6AULL
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
		0xC5201EE954D03543ULL,
		0x70735408F0294330ULL,
		0xCE245E917AC60056ULL,
		0x3DADAEF46F8C7A52ULL,
		0xCE6B4BCE6D2F1232ULL,
		0x138670AA55B3AF9BULL,
		0xBE554A22D198A3DAULL,
		0xDACAD3CBF0588582ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57C1533B1EE877DAULL,
		0xF91FE778D50A9EF5ULL,
		0x0FDFCD4AFC918E9AULL,
		0xE6088D3704065A7FULL,
		0xB51CC04C4D3A5BC9ULL,
		0x8C286B15FAB48268ULL,
		0xA497624BFE7FC411ULL,
		0xE3F9DE89313CE720ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D5ECBAE35E7BD69ULL,
		0x77536C901B1EA43BULL,
		0xBE4491467E3471BBULL,
		0x57A521BD6B861FD3ULL,
		0x194E8B821FF4B668ULL,
		0x875E05945AFF2D33ULL,
		0x19BDE7D6D318DFC8ULL,
		0xF6D0F542BF1B9E62ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6B41F908DC215FBAULL,
		0x814DB92952F5FB58ULL,
		0x3A1F07DC578C7075ULL,
		0x374C0FA4CEFDE0ACULL,
		0xC5547042B2875076ULL,
		0xD4CC1535DB78D940ULL,
		0xB2B341038ADECEE9ULL,
		0xC19B0A84C522582BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0D50673DB217C2ULL,
		0xE21CE980D765C327ULL,
		0x60E2CD63683F4DECULL,
		0x9E61E09BB2EC71D5ULL,
		0x00552E303AAF49C3ULL,
		0x36C79AA4BC9914C6ULL,
		0xE7199E327AE3EDDBULL,
		0xE1A8ADCA3257F08EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D34A8A19E6F47F8ULL,
		0x9F30CFA87B903831ULL,
		0xD93C3A78EF4D2288ULL,
		0x98EA2F091C116ED6ULL,
		0xC4FF421277D806B2ULL,
		0x9E047A911EDFC47AULL,
		0xCB99A2D10FFAE10EULL,
		0xDFF25CBA92CA679CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xE7C420D82C67E6AFULL,
		0xE416F01074291D66ULL,
		0xE3F6F3EE0F2B8079ULL,
		0xF9B239AA4A462871ULL,
		0x9F86C4254EBF72D6ULL,
		0x730120087E26265AULL,
		0x3445E467C457CB2CULL,
		0x3C16AE064C66EDA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66163A76D197705ULL,
		0xBF6D51A08F6B3270ULL,
		0x162E13FCDA3F55D6ULL,
		0x8269F1D843C87CB1ULL,
		0xECA4D211E6F46113ULL,
		0x7B2B009C1446AE9AULL,
		0xF8BB653E9FCD598CULL,
		0xB2AD868FB740DA7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF162BD30BF4E6FAAULL,
		0x24A99E6FE4BDEAF5ULL,
		0xCDC8DFF134EC2AA3ULL,
		0x774847D2067DABC0ULL,
		0xB2E1F21367CB11C3ULL,
		0xF7D61F6C69DF77BFULL,
		0x3B8A7F29248A719FULL,
		0x8969277695261328ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCA0A2E14030A7633ULL,
		0x692E4EAFC61B74DEULL,
		0xE3047F7B9A3E5946ULL,
		0x2D5E4F7875EDB2B0ULL,
		0x5FB557F6A1D862B7ULL,
		0xD436B60CA449B718ULL,
		0x2BB4EE14DD4E97A6ULL,
		0x2BFCF7BBA55C93DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B392530D721D73ULL,
		0xC1B6DC3DF2F1D8C5ULL,
		0x5CF061C4ACBA65A3ULL,
		0x37044C7F78D02B29ULL,
		0xEF417F2579E4C13CULL,
		0xF8BFFFBFC0DE277CULL,
		0x43CD871F95EA5225ULL,
		0x58D6BB7854AECD3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6569BC0F59858C0ULL,
		0xA7777271D3299C18ULL,
		0x86141DB6ED83F3A2ULL,
		0xF65A02F8FD1D8787ULL,
		0x7073D8D127F3A17AULL,
		0xDB76B64CE36B8F9BULL,
		0xE7E766F547644580ULL,
		0xD3263C4350ADC69EULL
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
		0x4DF0416F97578D81ULL,
		0x0D45D04320CEFB09ULL,
		0x146A54578431BF06ULL,
		0xC3098FB2C23FE15BULL,
		0xB96014E1BF517971ULL,
		0x3D18E89ADFD7023FULL,
		0xFCFAC28992C81AE0ULL,
		0x71BE7E6BE2E4C087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9906C6AB120ADC75ULL,
		0x29037E3E6CCEF45EULL,
		0x530AD9ABDFD6F5E4ULL,
		0x4A0A64754A1FAA03ULL,
		0xBF01CA32E70D3600ULL,
		0x5DFD610EEA97CEE1ULL,
		0x709B09E6351432D6ULL,
		0x0DEDB14D2AEF88BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4E97AC4854CB10CULL,
		0xE4425204B40006AAULL,
		0xC15F7AABA45AC921ULL,
		0x78FF2B3D78203757ULL,
		0xFA5E4AAED8444371ULL,
		0xDF1B878BF53F335DULL,
		0x8C5FB8A35DB3E809ULL,
		0x63D0CD1EB7F537C9ULL
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
		0xAD5A1AE64D3CDEA0ULL,
		0xED9DD8E32A5F00AAULL,
		0x842F2CC66DF40050ULL,
		0xC91C587B79AC5A8EULL,
		0xCF0FB6D2B3E46E45ULL,
		0xEAFB78E4338F1DC0ULL,
		0x323704AA4557E04AULL,
		0x20FFF648AB7EC1D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35805B78F2D3CBEBULL,
		0xF0A2AFEEE93D2971ULL,
		0xD750464756C5C4C9ULL,
		0x13EE312A23BC5523ULL,
		0x00F175A60BE154C9ULL,
		0x21BBF44291ECC1E5ULL,
		0x994247976183766BULL,
		0x458A206732B7143CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77D9BF6D5A6912B5ULL,
		0xFCFB28F44121D739ULL,
		0xACDEE67F172E3B86ULL,
		0xB52E275155F0056AULL,
		0xCE1E412CA803197CULL,
		0xC93F84A1A1A25BDBULL,
		0x98F4BD12E3D469DFULL,
		0xDB75D5E178C7AD93ULL
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
		0xF0927017C23C73B6ULL,
		0xB423A71DA4DBFC19ULL,
		0x8CC2C484F11375B4ULL,
		0xC69EA2ED7BF91D8CULL,
		0xFA42D1E9E5266487ULL,
		0xDEF6765A0287B63AULL,
		0x1392E887423883F1ULL,
		0xAD3A4022F9C741A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E2C56F72A1624A9ULL,
		0x2989F6F1AD58D6BBULL,
		0xC6614595D6469EAFULL,
		0xF041B43A1E4F306AULL,
		0x51ACF144D675B524ULL,
		0xE9DA4C8D260E6FA1ULL,
		0x3C5DB84C1220D1E8ULL,
		0x7D9723AFA14E55BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9266192098264F0DULL,
		0x8A99B02BF783255EULL,
		0xC6617EEF1ACCD705ULL,
		0xD65CEEB35DA9ED21ULL,
		0xA895E0A50EB0AF62ULL,
		0xF51C29CCDC794699ULL,
		0xD735303B3017B208ULL,
		0x2FA31C735878EBEAULL
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
		0xED04DDD2B723452CULL,
		0x2D8CB16DA60C7223ULL,
		0xA59AB64C2AB04963ULL,
		0x6C0BB9A8452A0BBCULL,
		0xE4A1884F450614E3ULL,
		0xB739A965BE98C942ULL,
		0xBCAB02BC914CB8FEULL,
		0xB28BA8C18682AA0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA65A94B79E64ECDULL,
		0x2E360966B6B705C8ULL,
		0x011E9DAB8A6921A4ULL,
		0x7EEA940266D576A4ULL,
		0xE330E1784ECEF2D9ULL,
		0x378D61769E2FEFCAULL,
		0x39324BC7A3E7145BULL,
		0xE3686E2105D09202ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x429F34873D3CF65FULL,
		0xFF56A806EF556C5BULL,
		0xA47C18A0A04727BEULL,
		0xED2125A5DE549518ULL,
		0x0170A6D6F6372209ULL,
		0x7FAC47EF2068D978ULL,
		0x8378B6F4ED65A4A3ULL,
		0xCF233AA080B21808ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDDC48287D9E60FBDULL,
		0x02A294CB77E35CECULL,
		0xFEC2201183F8A0BFULL,
		0xF2C446ACE65B0562ULL,
		0x5ED5C2C058FE6301ULL,
		0x30259DF359FF98A3ULL,
		0x93B6B7523A0B388CULL,
		0xC246B5C8DF93B88CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB47BA437678D2DULL,
		0x8301B872A4FDF838ULL,
		0x12BBB4E80927C90DULL,
		0x26C1DF6468431F25ULL,
		0x34C30C948D151EBEULL,
		0x38BF7D5E96A4F0FAULL,
		0xB3034027D0D21C8DULL,
		0x3197EEE02481A80CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x811006E3A27E8290ULL,
		0x7FA0DC58D2E564B4ULL,
		0xEC066B297AD0D7B1ULL,
		0xCC0267487E17E63DULL,
		0x2A12B62BCBE94443ULL,
		0xF7662094C35AA7A9ULL,
		0xE0B3772A69391BFEULL,
		0x90AEC6E8BB12107FULL
	}};
	sign = 0;
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
		0xD3570447FF95EEDCULL,
		0x0821DD70D152FAD4ULL,
		0xBEDC0F3F33963698ULL,
		0x854E917C539184ADULL,
		0x4544B90F411608D5ULL,
		0x52A1BDEADCF81D58ULL,
		0x60DCB7122FD048B2ULL,
		0xE4F373EF9D2904EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE46FE9889F8EB0CULL,
		0x4095F6B8F14564EBULL,
		0x88C4A06D755A97EBULL,
		0xDC391D8B7A2884E1ULL,
		0x63225FF6C24E0C19ULL,
		0x346D24A2A90AD569ULL,
		0xC9980F44588A683EULL,
		0x894B6B8FC357914DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x151005AF759D03D0ULL,
		0xC78BE6B7E00D95E9ULL,
		0x36176ED1BE3B9EACULL,
		0xA91573F0D968FFCCULL,
		0xE22259187EC7FCBBULL,
		0x1E34994833ED47EEULL,
		0x9744A7CDD745E074ULL,
		0x5BA8085FD9D173A1ULL
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
		0x27F74F165EB27B32ULL,
		0x5108FCF0E3612947ULL,
		0x46B5044357B10292ULL,
		0x209B86552E860051ULL,
		0xF1409421CD004AACULL,
		0xDAAC7FA46CAAD73EULL,
		0x311F3339C9668EDAULL,
		0x9A97341DC56410ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86BD7C6C3584F311ULL,
		0x244349656818C1B0ULL,
		0x29AEF85901A66577ULL,
		0x7BEA80CE2A57536BULL,
		0xF7574DD8A1FFA44DULL,
		0x57D951A041CA56F2ULL,
		0xD6B0FFB211838888ULL,
		0x5E4CE4D708ACF72AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA139D2AA292D8821ULL,
		0x2CC5B38B7B486796ULL,
		0x1D060BEA560A9D1BULL,
		0xA4B10587042EACE6ULL,
		0xF9E946492B00A65EULL,
		0x82D32E042AE0804BULL,
		0x5A6E3387B7E30652ULL,
		0x3C4A4F46BCB71982ULL
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
		0xB5C6254EF297EBD5ULL,
		0x41D92A147C6E64FFULL,
		0xAA25D5E06D56D40EULL,
		0x061C41AA161D8060ULL,
		0xE8D0B48790EE67E4ULL,
		0x6761F9F332316EF9ULL,
		0xD1C4CAF223B80008ULL,
		0xE01C7554170700AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x326F93FEC9F2E462ULL,
		0xCB7D9AD305E228E1ULL,
		0xB80DA8C52410751AULL,
		0xC4D6C2DEF1C8E363ULL,
		0x26B69A4682D7AADDULL,
		0x7AFBC1BB761D4BE7ULL,
		0x2B4446C44A10FF8DULL,
		0x3844013F834F08CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8356915028A50773ULL,
		0x765B8F41768C3C1EULL,
		0xF2182D1B49465EF3ULL,
		0x41457ECB24549CFCULL,
		0xC21A1A410E16BD06ULL,
		0xEC663837BC142312ULL,
		0xA680842DD9A7007AULL,
		0xA7D8741493B7F7E1ULL
	}};
	sign = 0;
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
		0xC60171E126BFE5D1ULL,
		0x89B46D0925E58FFCULL,
		0xF326F12350BEEB5AULL,
		0x3984E7902F83D150ULL,
		0x86283AE04F25E7BAULL,
		0x2E21BCE3A9D8E7D4ULL,
		0x7B93B63BA55E1377ULL,
		0xA4D7EAD234F27D06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F27FF672D38039ULL,
		0xF91660BCD8CDC323ULL,
		0x0B8EB5BFD0155549ULL,
		0xFEDC726DE0AB648FULL,
		0x74D9E42536A7F963ULL,
		0x5AA650221C66F6D5ULL,
		0x0D16E419734E6551ULL,
		0xBE90DC9D9432438CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB50EF1EAB3EC6598ULL,
		0x909E0C4C4D17CCD9ULL,
		0xE7983B6380A99610ULL,
		0x3AA875224ED86CC1ULL,
		0x114E56BB187DEE56ULL,
		0xD37B6CC18D71F0FFULL,
		0x6E7CD222320FAE25ULL,
		0xE6470E34A0C0397AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9C1F57FBA126DCA8ULL,
		0x70071204006AB608ULL,
		0x1F1625483EDB2F1CULL,
		0x0ED2E9C9077346F6ULL,
		0x7DB3E5E29BF737D8ULL,
		0x49DDF9C407830218ULL,
		0xD71112F28A2E32A3ULL,
		0x39FA0C4B0C346DA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B0EDA15C3B1E027ULL,
		0xF7C46B9124C93AEDULL,
		0x1CB996375D726EBFULL,
		0xA843D36B7393E66EULL,
		0xD9D6B9DED1F3C740ULL,
		0xAB1564374E0CC8BBULL,
		0xD2083CBC10851ECAULL,
		0xB18DE906F65E5E90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91107DE5DD74FC81ULL,
		0x7842A672DBA17B1BULL,
		0x025C8F10E168C05CULL,
		0x668F165D93DF6088ULL,
		0xA3DD2C03CA037097ULL,
		0x9EC8958CB976395CULL,
		0x0508D63679A913D8ULL,
		0x886C234415D60F14ULL
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
		0xAF6EF94776907D54ULL,
		0xCE3E8D828A4B7C83ULL,
		0xA10A1D97B245E9B4ULL,
		0x1CD16860526E741BULL,
		0x637E612E0DCC10E8ULL,
		0xCACC6F211A1193F6ULL,
		0x64B4D7A456C834A8ULL,
		0x65E958813E61D566ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4123A58166C596BULL,
		0xC4F388F86DF8B0A0ULL,
		0x6F1BAF27BAC5522BULL,
		0x950BD29B78371194ULL,
		0xB59909E9B9D07DEBULL,
		0x8BB01FA3FA7BBF74ULL,
		0x76C7F0EDE5DFF1B9ULL,
		0xD626CFCA04A548E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB5CBEEF602423E9ULL,
		0x094B048A1C52CBE2ULL,
		0x31EE6E6FF7809789ULL,
		0x87C595C4DA376287ULL,
		0xADE5574453FB92FCULL,
		0x3F1C4F7D1F95D481ULL,
		0xEDECE6B670E842EFULL,
		0x8FC288B739BC8C82ULL
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
		0xA214666DA919AF3FULL,
		0x64BAD1FE7233F28FULL,
		0x88FBEEAD500C9DF0ULL,
		0xBE0ADAA8B32C64E4ULL,
		0xE4E4728CFE438FEDULL,
		0xBE5E97EECACD21D0ULL,
		0xB2E89354645A6AF6ULL,
		0x980E669395AFA3A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA48B50C7BB27C81BULL,
		0x24879DBCEE4F7BCBULL,
		0x372BB04A79E10B99ULL,
		0xEB978E57B0DF4DA8ULL,
		0x68905E6CFA277FD8ULL,
		0x688CAF77D753A567ULL,
		0x26D05AFF4030D596ULL,
		0x98E8D246C56E418BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD8915A5EDF1E724ULL,
		0x4033344183E476C3ULL,
		0x51D03E62D62B9257ULL,
		0xD2734C51024D173CULL,
		0x7C541420041C1014ULL,
		0x55D1E876F3797C69ULL,
		0x8C18385524299560ULL,
		0xFF25944CD0416215ULL
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
		0xAE469A0A5200DA0BULL,
		0x46E73A56F657DB63ULL,
		0x56FC2AA7437BB4F7ULL,
		0x2636BBE62B6B7AF2ULL,
		0x8FA07BA42CCFFC35ULL,
		0x3ECD8CB9F423B38FULL,
		0x553AE64CF504E293ULL,
		0xF865A1701618F7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0A4F66A78772B3AULL,
		0x699B7760A6AEAABCULL,
		0xC13E8A03306A7AF0ULL,
		0x467C46580ACAB6B4ULL,
		0x572C324CAFDCA97AULL,
		0x3D545E296D07AC1AULL,
		0xAA47AF37B18D88A6ULL,
		0xEF22386F220B89DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDA1A39FD989AED1ULL,
		0xDD4BC2F64FA930A6ULL,
		0x95BDA0A413113A06ULL,
		0xDFBA758E20A0C43DULL,
		0x387449577CF352BAULL,
		0x01792E90871C0775ULL,
		0xAAF33715437759EDULL,
		0x09436900F40D6DC6ULL
	}};
	sign = 0;
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
		0x88F7936536E59253ULL,
		0x0395E1127010310AULL,
		0x549FFE08F3D65E32ULL,
		0xFFE7E9092A84804FULL,
		0x2AB732D748764E65ULL,
		0x1B62B3F72756D628ULL,
		0xF5C745EADFEB8860ULL,
		0x6D9C66C4D2FE39FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36EB4ABDF67B0388ULL,
		0xB706676DC86A4091ULL,
		0xD75BBF79469D7E76ULL,
		0x8EA6CE36221969F6ULL,
		0x6AC7EDADFB4BCB62ULL,
		0x7FCF25EB78CBC46BULL,
		0x1439B88052705FC3ULL,
		0xCD996D173BB06CDDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x520C48A7406A8ECBULL,
		0x4C8F79A4A7A5F079ULL,
		0x7D443E8FAD38DFBBULL,
		0x71411AD3086B1658ULL,
		0xBFEF45294D2A8303ULL,
		0x9B938E0BAE8B11BCULL,
		0xE18D8D6A8D7B289CULL,
		0xA002F9AD974DCD1EULL
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
		0x23B5903273BDE229ULL,
		0x642523D6B915A67BULL,
		0x67D5B4E71CD9C8F8ULL,
		0x14990BA38EBD3713ULL,
		0x2D3F3B5DB581EB86ULL,
		0x4F7E88DC90EC094BULL,
		0xA53E258A4475F033ULL,
		0xFB6AC8CFEEBA5439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA0EA2FB74D7221ULL,
		0x7C9D2A2D179B67F0ULL,
		0xFBFF47852CF1FE91ULL,
		0x23FD5C26A9B20C92ULL,
		0xDCB1968B3994DFD0ULL,
		0xC21F61D4DEEFE23AULL,
		0xFE0EA3414FE8411CULL,
		0xB2DF1D082D454EBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9714A602BC707008ULL,
		0xE787F9A9A17A3E8AULL,
		0x6BD66D61EFE7CA66ULL,
		0xF09BAF7CE50B2A80ULL,
		0x508DA4D27BED0BB5ULL,
		0x8D5F2707B1FC2710ULL,
		0xA72F8248F48DAF16ULL,
		0x488BABC7C175057DULL
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
		0x5301DA91F88BCB83ULL,
		0x817AC4781E875842ULL,
		0x37FB97138CA53E03ULL,
		0x9D91751A4F5D74A3ULL,
		0xB9E211A50EBE4A03ULL,
		0xE4DBD4EE466DF41CULL,
		0x71F3969FB4E9C2CAULL,
		0x5B6B0101391ACDEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E2F45E558BE3429ULL,
		0x03538AEA9F794533ULL,
		0x00378985B269F095ULL,
		0x49148BF55F8DDC15ULL,
		0x6722509FAB2C34BDULL,
		0xD5E93227DF48A5A4ULL,
		0x35CA103D6C11C845ULL,
		0x04B58DD6D06F7C6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04D294AC9FCD975AULL,
		0x7E27398D7F0E130FULL,
		0x37C40D8DDA3B4D6EULL,
		0x547CE924EFCF988EULL,
		0x52BFC10563921546ULL,
		0x0EF2A2C667254E78ULL,
		0x3C29866248D7FA85ULL,
		0x56B5732A68AB5183ULL
	}};
	sign = 0;
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
		0x3FEFA4298519A0F6ULL,
		0xDEA4A35EB7F85F98ULL,
		0x832933AE8C67B9FBULL,
		0xE12AE82A9B067FDEULL,
		0x56B5C8ECFAFA0A76ULL,
		0xA79C71CC9881CD92ULL,
		0xEA763512AEBCF85FULL,
		0xAD58A3A7FE4C1ADBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9355E4CE15B5A7B7ULL,
		0xFB856C28043A9306ULL,
		0xE4DB87A07FD7374EULL,
		0xBE512895B3374656ULL,
		0x5CFF2AB3995EF205ULL,
		0xD16BA4C9E7FB044FULL,
		0xDF5FA09E14EBA0CFULL,
		0x5AAF29971C22EC0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC99BF5B6F63F93FULL,
		0xE31F3736B3BDCC91ULL,
		0x9E4DAC0E0C9082ACULL,
		0x22D9BF94E7CF3987ULL,
		0xF9B69E39619B1871ULL,
		0xD630CD02B086C942ULL,
		0x0B16947499D1578FULL,
		0x52A97A10E2292ED0ULL
	}};
	sign = 0;
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
		0x4BA1B7108CB82CABULL,
		0x2977999C0B7D1BB0ULL,
		0x7866373FF6FBF14FULL,
		0x13823A71A5661415ULL,
		0x7B189BB641AC4EA5ULL,
		0x505D86FD320FCD1DULL,
		0x704B86E41878045CULL,
		0x46AB7EA2B29F86ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC974719558DB6922ULL,
		0x2335D924614D5862ULL,
		0xB2F6775A2998D53AULL,
		0x5189714DBA44307FULL,
		0xC95DA0AE3BCE6FB9ULL,
		0xAAC27D3ABAB97713ULL,
		0xC2D6C2474BC49F45ULL,
		0x44115F2BC6DCE9F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x822D457B33DCC389ULL,
		0x0641C077AA2FC34DULL,
		0xC56FBFE5CD631C15ULL,
		0xC1F8C923EB21E395ULL,
		0xB1BAFB0805DDDEEBULL,
		0xA59B09C277565609ULL,
		0xAD74C49CCCB36516ULL,
		0x029A1F76EBC29CBBULL
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
		0x64E0B0A77527A783ULL,
		0x0A1D975B7249B065ULL,
		0xEE0A06295E49BAC8ULL,
		0x88827B4D3761A860ULL,
		0x54CD481979083F04ULL,
		0x8A7DC55432C7B679ULL,
		0x92A3D09591B05318ULL,
		0xE56B6D8215B4B44FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3673AAC41AA523ULL,
		0xA915767A9DAFA1C0ULL,
		0x77F3DA810FFAE00FULL,
		0x323F2C4EF6E9A2F0ULL,
		0x7691B3BE702AF00EULL,
		0x6992C346DEAB7791ULL,
		0x8CF7EE8A7D5E3523ULL,
		0x2CCD3D379941BCA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55AA3CFCB10D0260ULL,
		0x610820E0D49A0EA5ULL,
		0x76162BA84E4EDAB8ULL,
		0x56434EFE40780570ULL,
		0xDE3B945B08DD4EF6ULL,
		0x20EB020D541C3EE7ULL,
		0x05ABE20B14521DF5ULL,
		0xB89E304A7C72F7A9ULL
	}};
	sign = 0;
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
		0xB93A90E2BD5173C9ULL,
		0x7C7122D850125719ULL,
		0xB322B5F0131AB221ULL,
		0xAF35444FC39F831EULL,
		0x37DC06BA07F65496ULL,
		0xC5F78814457AF2B4ULL,
		0x32543E51045FEBADULL,
		0x280814FA5D8A66C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54140771378EF328ULL,
		0x069A2E4D652CFE62ULL,
		0x92A3EF1CD718B663ULL,
		0x016C01EAD3A60F1EULL,
		0x83D17E9793A08FB8ULL,
		0xF1FEB55B8362A4B8ULL,
		0x1702C304D08620BDULL,
		0xCBC832C51E1266FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6526897185C280A1ULL,
		0x75D6F48AEAE558B7ULL,
		0x207EC6D33C01FBBEULL,
		0xADC94264EFF97400ULL,
		0xB40A88227455C4DEULL,
		0xD3F8D2B8C2184DFBULL,
		0x1B517B4C33D9CAEFULL,
		0x5C3FE2353F77FFCDULL
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
		0x0F505936DA932EBEULL,
		0x1AAADC086876BE05ULL,
		0x898CF22F1DD0A8D8ULL,
		0x00AD6084626DDFD7ULL,
		0x087E63D3D5CC856CULL,
		0x500DC63B101D558FULL,
		0xE19007DB94DD32E4ULL,
		0x2AB15F483E6EBB66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAD95AE54BDE1EB4ULL,
		0xCB05BD484AC42A99ULL,
		0xF98D77DA75C05898ULL,
		0x4B4A715DF2009B7BULL,
		0xA6917DCCEFFFC2D1ULL,
		0xB10D44BC48909F5FULL,
		0x78080555B107768EULL,
		0x0EFCC68F11C029DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6476FE518EB5100AULL,
		0x4FA51EC01DB2936BULL,
		0x8FFF7A54A810503FULL,
		0xB562EF26706D445BULL,
		0x61ECE606E5CCC29AULL,
		0x9F00817EC78CB62FULL,
		0x69880285E3D5BC55ULL,
		0x1BB498B92CAE918CULL
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
		0xEF639DF6DBE5A47BULL,
		0x4C748C2E7586AE3AULL,
		0x45E0C6A00EF63322ULL,
		0x5B255E5F30E9AD04ULL,
		0xFE063C72DEC144EFULL,
		0xDD8A6641606034C2ULL,
		0x278679D0EFF0BF84ULL,
		0x69F063C7BFBD1867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B36EA0D88B12430ULL,
		0x266A8E90A6C43FEEULL,
		0x2EBC61C9364CDA4EULL,
		0xF18996A8373221E3ULL,
		0x303DF57C98EF81F4ULL,
		0x8F62135B0DE0FBDBULL,
		0x97BA1BC34292FFF2ULL,
		0xEBFFA3465E8EFF0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD42CB3E95334804BULL,
		0x2609FD9DCEC26E4CULL,
		0x172464D6D8A958D4ULL,
		0x699BC7B6F9B78B21ULL,
		0xCDC846F645D1C2FAULL,
		0x4E2852E6527F38E7ULL,
		0x8FCC5E0DAD5DBF92ULL,
		0x7DF0C081612E1957ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4DF27120AF0DCABFULL,
		0x6E47F62FD7DA2B89ULL,
		0x4B9B5FF0BF307ADBULL,
		0x9D0C233CAB30027FULL,
		0xC1826C85DDD36387ULL,
		0x3B9E75FB4217B00FULL,
		0x1FB6705455B085DCULL,
		0x28D368B68DE26045ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC836B4748C2DDE61ULL,
		0x209F5A063E599183ULL,
		0xA01B7A108497A517ULL,
		0x1D8564761211A226ULL,
		0x7A5F4A5A2C81F692ULL,
		0xE489604247C842D7ULL,
		0xEED38497C4808B3CULL,
		0x0747D7CABECB0757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85BBBCAC22DFEC5EULL,
		0x4DA89C2999809A05ULL,
		0xAB7FE5E03A98D5C4ULL,
		0x7F86BEC6991E6058ULL,
		0x4723222BB1516CF5ULL,
		0x571515B8FA4F6D38ULL,
		0x30E2EBBC912FFA9FULL,
		0x218B90EBCF1758EDULL
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
		0x49A7F76C8BAC8ACDULL,
		0x09FF9A990D4E961DULL,
		0x540361E784FBBD1AULL,
		0x75677AC739D06616ULL,
		0x8EB3AED3D5B627D3ULL,
		0x9D6C700B8C449532ULL,
		0xDE931D646BDCA5B3ULL,
		0x1A6B6DC135CBB7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB732E6E7C11104ULL,
		0xCA71E026DA6619D0ULL,
		0xC837D6360D9E84ECULL,
		0x45EA9B9731779393ULL,
		0xACC0668C24942049ULL,
		0x899A6CB366807F95ULL,
		0x9807514DE7E90069ULL,
		0xC2CD683C0EF4A5C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABF0C485A3EB79C9ULL,
		0x3F8DBA7232E87C4CULL,
		0x8BCB8BB1775D382DULL,
		0x2F7CDF300858D282ULL,
		0xE1F34847B122078AULL,
		0x13D2035825C4159CULL,
		0x468BCC1683F3A54AULL,
		0x579E058526D711EBULL
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
		0xEB35588D86A855AEULL,
		0x4E0F7DEDCC79ECFBULL,
		0x8BC9D447C2155CDEULL,
		0xB988F5E7A212652FULL,
		0x29C7FC1D44B6D1D9ULL,
		0xA1636E8A44C63F11ULL,
		0x8B6E7AD3DFFDC875ULL,
		0x6F014817050763A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7523254A5414333AULL,
		0xC68F6EC9421A197BULL,
		0x392A6356582A6586ULL,
		0x99A5D17D3F6BAFE4ULL,
		0x057B1303033B1A86ULL,
		0xBAE0EA9827243D8EULL,
		0x4C0C922C7F976687ULL,
		0x604EAD9E0745E7F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7612334332942274ULL,
		0x87800F248A5FD380ULL,
		0x529F70F169EAF757ULL,
		0x1FE3246A62A6B54BULL,
		0x244CE91A417BB753ULL,
		0xE68283F21DA20183ULL,
		0x3F61E8A7606661EDULL,
		0x0EB29A78FDC17BB7ULL
	}};
	sign = 0;
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
		0x53879932FF55C5E3ULL,
		0x0D05F1956E46A3B0ULL,
		0x812FF949003828F6ULL,
		0x080344D645B5C5FAULL,
		0x1D0EB5AEEA4E6927ULL,
		0x7145D250F992BF95ULL,
		0x79F0107865D4C707ULL,
		0xF00E58B8F2672AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBF68799A13FB28EULL,
		0x448F5339C6A93DABULL,
		0xB65AD2C52E8A5DFBULL,
		0xCD519553F2A69B6FULL,
		0xAF9C02EEE0F24270ULL,
		0x5A5BA4132C2A6E8CULL,
		0x19242B883546B43DULL,
		0x0F359FC888F28B0BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x979111995E161355ULL,
		0xC8769E5BA79D6604ULL,
		0xCAD52683D1ADCAFAULL,
		0x3AB1AF82530F2A8AULL,
		0x6D72B2C0095C26B6ULL,
		0x16EA2E3DCD685108ULL,
		0x60CBE4F0308E12CAULL,
		0xE0D8B8F069749FF1ULL
	}};
	sign = 0;
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
		0x080A98AF194CE08CULL,
		0x475F3A457661B6E6ULL,
		0x044946397011D731ULL,
		0x5503693E102B7BD4ULL,
		0xB1DA9CCF460811FCULL,
		0x11A5AF76F21B31E6ULL,
		0x429B3CC5B0649292ULL,
		0xC2A06DAA357F49DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF89CBFCC3F7FEAFULL,
		0x94541DFA1FAE9CA2ULL,
		0xD76B49C0742C888BULL,
		0x5D053582EB0AC936ULL,
		0x642C7BCF238D88CEULL,
		0x9F0FB160B9BCF70BULL,
		0xA22877DD35612CBAULL,
		0xCB1D9D9D7DBEC422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5880CCB25554E1DDULL,
		0xB30B1C4B56B31A43ULL,
		0x2CDDFC78FBE54EA5ULL,
		0xF7FE33BB2520B29DULL,
		0x4DAE2100227A892DULL,
		0x7295FE16385E3ADBULL,
		0xA072C4E87B0365D7ULL,
		0xF782D00CB7C085BAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB64D1C61CA1997F9ULL,
		0x2A5BFC4AB55DF866ULL,
		0x092B78D3F29841EEULL,
		0x0711735C328E227DULL,
		0x067375E0A617E8FCULL,
		0xC8EE94E0A2E4139DULL,
		0x32BA3921614CAF9CULL,
		0x2AE2239D3F6493F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930A8774A60F5B05ULL,
		0xD3263A70EEEFC5A4ULL,
		0x5E8BEED27C887104ULL,
		0xBFA179B009467029ULL,
		0xAD3957ADAA4CE356ULL,
		0x63DAF4C8C7B5245EULL,
		0x27AA6545B7006D4EULL,
		0x8AEDB77262201D0DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x234294ED240A3CF4ULL,
		0x5735C1D9C66E32C2ULL,
		0xAA9F8A01760FD0E9ULL,
		0x476FF9AC2947B253ULL,
		0x593A1E32FBCB05A5ULL,
		0x6513A017DB2EEF3EULL,
		0x0B0FD3DBAA4C424EULL,
		0x9FF46C2ADD4476E9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x280D4C6878049D7AULL,
		0x07FE72DBC3561390ULL,
		0x7CF7DE3D8C018B80ULL,
		0x6DF2344FB0E3342FULL,
		0x485BBACEEE7DA147ULL,
		0x211BF211F68656B2ULL,
		0x984ECCC04A3037D1ULL,
		0xFEF3D9F4C771A06AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF3ABB4D7BB15E8ULL,
		0xDA2488409160FBA1ULL,
		0xBC3A070D8C14DFC3ULL,
		0x8E2615865F330DF1ULL,
		0xF3D8386C1AAEB00AULL,
		0xDF709007AF31381FULL,
		0x3A571C6BF3F01B94ULL,
		0xAC123CF7C1022C99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC19A0B3A0498792ULL,
		0x2DD9EA9B31F517EEULL,
		0xC0BDD72FFFECABBCULL,
		0xDFCC1EC951B0263DULL,
		0x54838262D3CEF13CULL,
		0x41AB620A47551E92ULL,
		0x5DF7B05456401C3CULL,
		0x52E19CFD066F73D1ULL
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
		0x1110F58E58FA71F8ULL,
		0x7046995C639A6726ULL,
		0xE0D1FB8EDA052D58ULL,
		0x42EB247A6617A10FULL,
		0xC39FEC8140B2522FULL,
		0x7664099680E8BFBCULL,
		0xD2F1C47510568426ULL,
		0x14434C91A0EE1D9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DE214B9E8C1C54ULL,
		0x76266B3106771D59ULL,
		0x08CE8C662E16C256ULL,
		0x1A8A1AD40DE8B3F1ULL,
		0x75752DC6A51A1BE8ULL,
		0x04367DFBB412D113ULL,
		0xB82878993388EA62ULL,
		0x2D07766C139674F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F32D442BA6E55A4ULL,
		0xFA202E2B5D2349CCULL,
		0xD8036F28ABEE6B01ULL,
		0x286109A6582EED1EULL,
		0x4E2ABEBA9B983647ULL,
		0x722D8B9ACCD5EEA9ULL,
		0x1AC94BDBDCCD99C4ULL,
		0xE73BD6258D57A8ABULL
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
		0xD2F7E97E18CA3CF6ULL,
		0x3137EBEFFC3A91BEULL,
		0xFC64BC92ACAA0C1FULL,
		0x93F9019C20E63F73ULL,
		0x6D35CB5A15A6E209ULL,
		0x020D129392E42C40ULL,
		0xA7744B9B966F0B4AULL,
		0x2EF3DF4DE4952394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD130595284B31498ULL,
		0x4B1EF743E1B0035FULL,
		0x96B30732CC14C407ULL,
		0xE5025BB52E84EB0EULL,
		0xAB41446F4A7A9E3FULL,
		0xA0114098F5E402A1ULL,
		0x7697A835E97084DEULL,
		0xC3291BF9BEA6B07DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01C7902B9417285EULL,
		0xE618F4AC1A8A8E5FULL,
		0x65B1B55FE0954817ULL,
		0xAEF6A5E6F2615465ULL,
		0xC1F486EACB2C43C9ULL,
		0x61FBD1FA9D00299EULL,
		0x30DCA365ACFE866BULL,
		0x6BCAC35425EE7317ULL
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
		0x8BD8E5EC5766526EULL,
		0xECE748C4400B8783ULL,
		0x1674FA3E0D32DFCCULL,
		0x7E1D727D5A8F5B5DULL,
		0x31E850016299DC37ULL,
		0x7D750CADAAEBFE95ULL,
		0xB5DD0F3F95E78A70ULL,
		0x0C304E4A12B5F008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FE9B7E90E1E92CBULL,
		0xAC19F76DEF91A404ULL,
		0xA6A0450825536ADAULL,
		0x59230A8E6BF3F12AULL,
		0x6A2EA97FDE76B2EEULL,
		0x95F7245CCE3C90D7ULL,
		0xF21079D3D71E1E9BULL,
		0xFE75B5ACC57797C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1BEF2E034947BFA3ULL,
		0x40CD51565079E37FULL,
		0x6FD4B535E7DF74F2ULL,
		0x24FA67EEEE9B6A32ULL,
		0xC7B9A68184232949ULL,
		0xE77DE850DCAF6DBDULL,
		0xC3CC956BBEC96BD4ULL,
		0x0DBA989D4D3E5847ULL
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
		0x4B7005FD0A34DE43ULL,
		0xF088C5E151CF83B4ULL,
		0xC95504BE882C36B7ULL,
		0xEB40876769DD47C9ULL,
		0xA95584E615D88E77ULL,
		0xA181B8F6462BF7ABULL,
		0xFBBDDFB96FFC0241ULL,
		0xA96B9614B035AA1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CB3830777B84A0FULL,
		0xB7BA42C5D499FCA6ULL,
		0xCCB843D8A85A1F25ULL,
		0x4527752CA0F0BD5EULL,
		0xDE9AA2DE5E50BD33ULL,
		0x9B4E329BF911AB14ULL,
		0x3BDE3CD3088993A6ULL,
		0x15B4268A7C780EC3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEEBC82F5927C9434ULL,
		0x38CE831B7D35870DULL,
		0xFC9CC0E5DFD21792ULL,
		0xA619123AC8EC8A6AULL,
		0xCABAE207B787D144ULL,
		0x0633865A4D1A4C96ULL,
		0xBFDFA2E667726E9BULL,
		0x93B76F8A33BD9B5CULL
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
		0xCFA076132498E6A4ULL,
		0xE0A3E816D315A496ULL,
		0x95796298E7646FE3ULL,
		0xF53060A1D544F885ULL,
		0x1C7774E6A700052CULL,
		0xBBE0ABA07562F82AULL,
		0x8D58E627C39D3F19ULL,
		0x49F16214EA6F02FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x560D4DD7F0991CA3ULL,
		0x094F8F2FDB423634ULL,
		0x365AE4C8A2055A96ULL,
		0x9E3ABDB473AC774FULL,
		0x1572BC104A38F21DULL,
		0x5551F927F4DFE7FCULL,
		0x598968441287A40EULL,
		0xE83E1DDDAC1FE3EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7993283B33FFCA01ULL,
		0xD75458E6F7D36E62ULL,
		0x5F1E7DD0455F154DULL,
		0x56F5A2ED61988136ULL,
		0x0704B8D65CC7130FULL,
		0x668EB2788083102EULL,
		0x33CF7DE3B1159B0BULL,
		0x61B344373E4F1F0EULL
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
		0xAAA6456F151B5F52ULL,
		0x1BE7C5595D1B6219ULL,
		0xCEE61D3EEE6CEA54ULL,
		0x49474A83DB0EAB7AULL,
		0x52FE45A8DD32D4C6ULL,
		0xDF82E66AE34D436BULL,
		0x4A26F3D8E5AE33F6ULL,
		0x379908B9C3FB9673ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6242A6C7001CE6E0ULL,
		0xBB884F381C3980F1ULL,
		0x94C3E0DC427C671FULL,
		0x9A7C056F06B3BBAAULL,
		0x6BB60EDFE6DD8A69ULL,
		0xF9A1A91C07DD000AULL,
		0x7AA0228F1E0AA6D0ULL,
		0x949E752A1F14E19FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48639EA814FE7872ULL,
		0x605F762140E1E128ULL,
		0x3A223C62ABF08334ULL,
		0xAECB4514D45AEFD0ULL,
		0xE74836C8F6554A5CULL,
		0xE5E13D4EDB704360ULL,
		0xCF86D149C7A38D25ULL,
		0xA2FA938FA4E6B4D3ULL
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
		0xC23A48741A64D881ULL,
		0x1FC49E041FA35ABEULL,
		0x82D79B8B9D8CC5CCULL,
		0xAF4F44A1116A57A6ULL,
		0x39BD978AF0A9AC41ULL,
		0x18CAD0433A1BD75BULL,
		0x2AE92D1B10F206CAULL,
		0x803F7CC30498F485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24436D5C5DF8898DULL,
		0xE3CD384D4EE4A24AULL,
		0x692C8CFD306E61E1ULL,
		0x74D9CB947009D2FBULL,
		0x7E3D9CEBE94A8CB1ULL,
		0x5E6361884EA22172ULL,
		0x5880921EE7007B5DULL,
		0x51E903B682D2DF57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9DF6DB17BC6C4EF4ULL,
		0x3BF765B6D0BEB874ULL,
		0x19AB0E8E6D1E63EAULL,
		0x3A75790CA16084ABULL,
		0xBB7FFA9F075F1F90ULL,
		0xBA676EBAEB79B5E8ULL,
		0xD2689AFC29F18B6CULL,
		0x2E56790C81C6152DULL
	}};
	sign = 0;
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
		0x06B75470B199FA55ULL,
		0x2EF7F4E65BE0B82FULL,
		0x8F6838DE5635CBC5ULL,
		0x63C9A8CB5F7E7152ULL,
		0xFC4C55019982CF55ULL,
		0x56D50D45560D3883ULL,
		0x731B9601548072A2ULL,
		0xDFB62415C82B21D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x209C1DBE38A28554ULL,
		0x7E6FDE5451E71111ULL,
		0xA74F7AB1B72E6DE4ULL,
		0x47A3C6DC1CD6BFCCULL,
		0x4ABDF2225B668634ULL,
		0x49F9E43838FCE3BCULL,
		0xE6A7307BBA183BAFULL,
		0xB0723016276657E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE61B36B278F77501ULL,
		0xB088169209F9A71DULL,
		0xE818BE2C9F075DE0ULL,
		0x1C25E1EF42A7B185ULL,
		0xB18E62DF3E1C4921ULL,
		0x0CDB290D1D1054C7ULL,
		0x8C7465859A6836F3ULL,
		0x2F43F3FFA0C4C9EFULL
	}};
	sign = 0;
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
		0x203CF443A0BA2F59ULL,
		0xCCAEE608D08DF9BAULL,
		0x96F468B33377A52DULL,
		0x290A981BDA2DDF37ULL,
		0xA3122B596A599968ULL,
		0x2ECC124075787379ULL,
		0x0376808E5F9A8208ULL,
		0x3B2ECDFF724E8054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF6C6B73B437D99ULL,
		0xDFF180652F7FB589ULL,
		0x971CA028E240D6D2ULL,
		0x16D1B39577D4AD87ULL,
		0xCAEAEA385F8FD368ULL,
		0x30B7E6362CF31FA5ULL,
		0xD65E1A5E032A6C62ULL,
		0xB753254D8D08D5B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1462D8C6576B1C0ULL,
		0xECBD65A3A10E4430ULL,
		0xFFD7C88A5136CE5AULL,
		0x1238E486625931AFULL,
		0xD82741210AC9C600ULL,
		0xFE142C0A488553D3ULL,
		0x2D1866305C7015A5ULL,
		0x83DBA8B1E545AAA1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA4B17D6D5A5277BEULL,
		0x9C989860C4EC99D7ULL,
		0x431D18639D847E85ULL,
		0x500B6AC9E258CB4BULL,
		0xD881224A99C5DF16ULL,
		0x4AB9DE0545B98DCCULL,
		0x9383D57DC344C7B1ULL,
		0x9F7023DB8C8D7F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7AE48C933D358EAULL,
		0x115AD7A9EBAC4D06ULL,
		0xFAD224E8AA415356ULL,
		0x8A68136197E12ED2ULL,
		0xBC86CD827CC2D23FULL,
		0xF908B7A534FD6044ULL,
		0xCA48E0583435969BULL,
		0xF394AD555DC5252CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED0334A4267F1ED4ULL,
		0x8B3DC0B6D9404CD0ULL,
		0x484AF37AF3432B2FULL,
		0xC5A357684A779C78ULL,
		0x1BFA54C81D030CD6ULL,
		0x51B1266010BC2D88ULL,
		0xC93AF5258F0F3115ULL,
		0xABDB76862EC85A6BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB55E4557131755A8ULL,
		0x15B9D132B7453D9CULL,
		0x70641EACA3AEB710ULL,
		0x9C45E74C698D7A71ULL,
		0x0C53D1D33F607B8BULL,
		0x57B164EAA31498E0ULL,
		0xFCFFB42110CA2DAAULL,
		0xBCE46B43963898C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x643D1C58DBE81714ULL,
		0xADD4970BE7F4C062ULL,
		0xB109822D8044CD1CULL,
		0x1CC94FCE3F9DD95BULL,
		0x3241847FBE261E99ULL,
		0x45C5B1B67D1D9E3EULL,
		0x1C3C00286AA20886ULL,
		0x492360649CA035DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x512128FE372F3E94ULL,
		0x67E53A26CF507D3AULL,
		0xBF5A9C7F2369E9F3ULL,
		0x7F7C977E29EFA115ULL,
		0xDA124D53813A5CF2ULL,
		0x11EBB33425F6FAA1ULL,
		0xE0C3B3F8A6282524ULL,
		0x73C10ADEF99862E8ULL
	}};
	sign = 0;
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
		0xC41034CDECFE85F2ULL,
		0xA5509C22BFA35EC2ULL,
		0x9B51B9BA2AC7729FULL,
		0x3B68EDF78068556AULL,
		0x5D7AE0F79F29D238ULL,
		0x0AE747BBD45E140CULL,
		0x296744378B242959ULL,
		0x2D3FED70213576C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ACFE2F01B97CC4AULL,
		0xC590D927672A9FB2ULL,
		0xC2CC7801CDF974C6ULL,
		0xA820947062B2141BULL,
		0x7B7D82DF30B5B84AULL,
		0xDA7B5D78FCA0300AULL,
		0x6DAEEF2DE7AA41B7ULL,
		0x11D222D55BDF8A99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x394051DDD166B9A8ULL,
		0xDFBFC2FB5878BF10ULL,
		0xD88541B85CCDFDD8ULL,
		0x934859871DB6414EULL,
		0xE1FD5E186E7419EDULL,
		0x306BEA42D7BDE401ULL,
		0xBBB85509A379E7A1ULL,
		0x1B6DCA9AC555EC2AULL
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
		0x2320FECED4980D60ULL,
		0x4ABFA35CF274CD03ULL,
		0x4C51599C573483F1ULL,
		0xFA4DB83235712B19ULL,
		0x80A4C901E296965BULL,
		0x711308ACFA89ABB8ULL,
		0x0589278C17B862AFULL,
		0x841586268FFB72E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E5E42AC91D53443ULL,
		0x115678B0C3E27BB1ULL,
		0x6A5850B98CC7AB24ULL,
		0x88FE364F41C49B1DULL,
		0x81F7BFF7C726165EULL,
		0x208E0AECC2BBBE99ULL,
		0x64A954098AD1411AULL,
		0x55F9C75075201BFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14C2BC2242C2D91DULL,
		0x39692AAC2E925152ULL,
		0xE1F908E2CA6CD8CDULL,
		0x714F81E2F3AC8FFBULL,
		0xFEAD090A1B707FFDULL,
		0x5084FDC037CDED1EULL,
		0xA0DFD3828CE72195ULL,
		0x2E1BBED61ADB56EAULL
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
		0x6D98C23FA890BC36ULL,
		0x1DCB17F3EDC63F65ULL,
		0xF26C4F55C0E2E449ULL,
		0x608A68D414DC9DC0ULL,
		0x548F060D59DEC326ULL,
		0xA059353A588658AAULL,
		0xE0D56CDA49B1E991ULL,
		0xE3D0B2D8DB8D2F5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40412BDD4D0C7269ULL,
		0x88267BE8708C6055ULL,
		0x15569817CEB3F453ULL,
		0xB2D7B0D96393CE15ULL,
		0xEB5387FC468A3C6BULL,
		0x2C8FB3622BE476BAULL,
		0x1280FED544C63735ULL,
		0x2B40347E8D0F4177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D5796625B8449CDULL,
		0x95A49C0B7D39DF10ULL,
		0xDD15B73DF22EEFF5ULL,
		0xADB2B7FAB148CFABULL,
		0x693B7E11135486BAULL,
		0x73C981D82CA1E1EFULL,
		0xCE546E0504EBB25CULL,
		0xB8907E5A4E7DEDE8ULL
	}};
	sign = 0;
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
		0xE4E4747724BB4715ULL,
		0xC596E453E395EAF4ULL,
		0x161FC07EC0D76E7CULL,
		0x19EB40CD4489B24FULL,
		0x0EA4AE3717B0807FULL,
		0x0118317A142C5251ULL,
		0x810263BF42D69001ULL,
		0x8BC57E7122C8BDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9104812B97990E01ULL,
		0x4AE61B2853FD7CF9ULL,
		0x5C83A91403FA3634ULL,
		0x6667D1853D2F374FULL,
		0x6437BEE48D8A477FULL,
		0xB74DF73209FE42A2ULL,
		0x4648A02C4A90DE2DULL,
		0x62D8E609160C0FEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53DFF34B8D223914ULL,
		0x7AB0C92B8F986DFBULL,
		0xB99C176ABCDD3848ULL,
		0xB3836F48075A7AFFULL,
		0xAA6CEF528A2638FFULL,
		0x49CA3A480A2E0FAEULL,
		0x3AB9C392F845B1D3ULL,
		0x28EC98680CBCADD7ULL
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
		0x0253D258ED637B42ULL,
		0x5F999D1E92701AEAULL,
		0xAA4AEFDD3AA15423ULL,
		0xC0F7D1A0BD4944FBULL,
		0xF0792B08CBD4C395ULL,
		0x9FDF9571C8D51F35ULL,
		0x79B2AB9A9FF2D87FULL,
		0x2A476FE40CFDD403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE740040E6EE4DC8AULL,
		0x2D61506D463ECB98ULL,
		0x48F843E35004BC43ULL,
		0x62C2B228AB8ADED9ULL,
		0xF391902E8F12E61DULL,
		0xA71B9EF450C6B019ULL,
		0x0851A4FFE319E646ULL,
		0x31A868AB4244C417ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B13CE4A7E7E9EB8ULL,
		0x32384CB14C314F51ULL,
		0x6152ABF9EA9C97E0ULL,
		0x5E351F7811BE6622ULL,
		0xFCE79ADA3CC1DD78ULL,
		0xF8C3F67D780E6F1BULL,
		0x7161069ABCD8F238ULL,
		0xF89F0738CAB90FECULL
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
		0xED4E6BE339062C3AULL,
		0x6C0CB00C41C8BD66ULL,
		0x76F94278E6EDB3DAULL,
		0xEB6E4F19E6417415ULL,
		0xA0335DDBFFC94392ULL,
		0xB2C5D0604B38614EULL,
		0xC2A8401ADAAEB128ULL,
		0x61285CCCCF10102DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83D2F4703F926F26ULL,
		0xFAF4E2796EBE3BA8ULL,
		0x0156BDD714C2AB47ULL,
		0x820844FB1393A1EDULL,
		0xFDF93FADD124AF40ULL,
		0xEFBAA9642DCD8AC7ULL,
		0x79AAF1D058115A56ULL,
		0x9F384FF1559D27C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x697B7772F973BD14ULL,
		0x7117CD92D30A81BEULL,
		0x75A284A1D22B0892ULL,
		0x69660A1ED2ADD228ULL,
		0xA23A1E2E2EA49452ULL,
		0xC30B26FC1D6AD686ULL,
		0x48FD4E4A829D56D1ULL,
		0xC1F00CDB7972E865ULL
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
		0x7FA81053C0F9177BULL,
		0x6686B74538DD9A30ULL,
		0xDCD2F6CA5435C780ULL,
		0x48CEB1D72A535F69ULL,
		0x31FF8C967BC4C96FULL,
		0x07A09DCA040202CCULL,
		0xE06094DBA208A02EULL,
		0x282459A7EDC61C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DBA20FB46AD7ECCULL,
		0x2821900BBE4CA587ULL,
		0xEB44E1A110896D30ULL,
		0x517CB0E7D9E7C202ULL,
		0x52E496974B3ACED6ULL,
		0x105EEA6986E5FBA1ULL,
		0x094B31B556FDC657ULL,
		0x4AD34D1011B80C32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11EDEF587A4B98AFULL,
		0x3E6527397A90F4A9ULL,
		0xF18E152943AC5A50ULL,
		0xF75200EF506B9D66ULL,
		0xDF1AF5FF3089FA98ULL,
		0xF741B3607D1C072AULL,
		0xD71563264B0AD9D6ULL,
		0xDD510C97DC0E0FE1ULL
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
		0x5EAF0ADE15F3EB49ULL,
		0x3176594A4F89BF9BULL,
		0xC703B09F607C6827ULL,
		0x05F24CF0A79C23BDULL,
		0x94D6965CB028C09CULL,
		0x3B5F2FAB447A89ACULL,
		0x156F67C2FCC32247ULL,
		0x61CDFBD7DD0E3DACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB50F33285BBE163DULL,
		0x448D2FCC3BC64D15ULL,
		0xD01BCEFCAB939F6EULL,
		0x8F46484C34284B59ULL,
		0x673744339CE05AAFULL,
		0x082704C9AB425C43ULL,
		0xFD459528A784D448ULL,
		0x02B6E973DA2D6B00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA99FD7B5BA35D50CULL,
		0xECE9297E13C37285ULL,
		0xF6E7E1A2B4E8C8B8ULL,
		0x76AC04A47373D863ULL,
		0x2D9F5229134865ECULL,
		0x33382AE199382D69ULL,
		0x1829D29A553E4DFFULL,
		0x5F17126402E0D2ABULL
	}};
	sign = 0;
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
		0xAD79848CF2FD465DULL,
		0xD0D9439395559999ULL,
		0x1F72561CB6E7EF7EULL,
		0xC5EBF456FDEA6107ULL,
		0xDA8DCDCF74C97177ULL,
		0x52F124BF0C2657CCULL,
		0x383154731772580BULL,
		0xC92C176919FE45AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F9C091190DEDFF5ULL,
		0xBF6E3308408F84E6ULL,
		0xEF3B8C420B72CEBAULL,
		0xC2C96C2FF09BEAA3ULL,
		0xDE7447FBEFFB532BULL,
		0x1AF94DF0619D27D0ULL,
		0x87BA2983C10892A5ULL,
		0x4B67E4059F15C18AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DDD7B7B621E6668ULL,
		0x116B108B54C614B3ULL,
		0x3036C9DAAB7520C4ULL,
		0x032288270D4E7663ULL,
		0xFC1985D384CE1E4CULL,
		0x37F7D6CEAA892FFBULL,
		0xB0772AEF5669C566ULL,
		0x7DC433637AE88423ULL
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
		0xC6375D13ADC925CFULL,
		0x6FD268865AD9068DULL,
		0x5CED9EE34FDF6D8DULL,
		0x37093C2DA7D6FF86ULL,
		0x9332E7F03A253483ULL,
		0xB4857E79A0765B10ULL,
		0xCCD840B7CAEF0E1CULL,
		0xBEF02D6A0F59C92CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA0E4C67737CF611ULL,
		0x0B53C86D2E1CCFB3ULL,
		0xACA0C932A0A4C7A8ULL,
		0xB3D8C0B90F0D455AULL,
		0xA7C7E73C4C3E96CFULL,
		0x8D138DA534DD1C53ULL,
		0xB51705570727490BULL,
		0x46B5153A5FFD8CCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C2910AC3A4C2FBEULL,
		0x647EA0192CBC36DAULL,
		0xB04CD5B0AF3AA5E5ULL,
		0x83307B7498C9BA2BULL,
		0xEB6B00B3EDE69DB3ULL,
		0x2771F0D46B993EBCULL,
		0x17C13B60C3C7C511ULL,
		0x783B182FAF5C3C5DULL
	}};
	sign = 0;
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
		0xD28927CFFAD86285ULL,
		0xFDC14A4A9BD1DED1ULL,
		0xBA8E8525CEDF1F7FULL,
		0x20681843B3AAD5E6ULL,
		0x61D205BC9FC05896ULL,
		0x16C52AAA83CCF70AULL,
		0x33E8614A76ECDBA4ULL,
		0xA2071367CFD2FB91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x324D32645F05A67AULL,
		0xD68A5005759C7010ULL,
		0x515DA72EA26CBAE0ULL,
		0x32A2DC6A5286D74DULL,
		0x2BB3F13F76A66429ULL,
		0x4054168533E1311CULL,
		0xCDBD80A0964ED617ULL,
		0xA136FD627299642DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA03BF56B9BD2BC0BULL,
		0x2736FA4526356EC1ULL,
		0x6930DDF72C72649FULL,
		0xEDC53BD96123FE99ULL,
		0x361E147D2919F46CULL,
		0xD67114254FEBC5EEULL,
		0x662AE0A9E09E058CULL,
		0x00D016055D399763ULL
	}};
	sign = 0;
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
		0x5CD6AAA8D655A3ABULL,
		0x822BB0D7AAB602E7ULL,
		0xEAD151E05E29DB16ULL,
		0xA86E4EE9ECF30E27ULL,
		0x7E737199D05F00EBULL,
		0xBB4B4A553D9C062AULL,
		0xDE7419DAC9ABA75EULL,
		0x51ABB40E8E4CAD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x374495872C12DD22ULL,
		0xC45804328DCEBF6EULL,
		0xFD28F34BF9155567ULL,
		0xD3456C1AF78E75CDULL,
		0xAEA8D188901CAE43ULL,
		0x630C690C18C89428ULL,
		0x8FB0404DBF32262DULL,
		0xB2FD818F23457044ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25921521AA42C689ULL,
		0xBDD3ACA51CE74379ULL,
		0xEDA85E94651485AEULL,
		0xD528E2CEF5649859ULL,
		0xCFCAA011404252A7ULL,
		0x583EE14924D37201ULL,
		0x4EC3D98D0A798131ULL,
		0x9EAE327F6B073CC0ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0B0A52849D6FB62CULL,
		0x11F7505F96BF1E3BULL,
		0x174F6FBFB1E8AC78ULL,
		0xC68EE7512389FDD6ULL,
		0x36E5DE94F410747EULL,
		0xB1032CABC0DE8A98ULL,
		0x24BEF248DCC287BCULL,
		0x23A898284F76A73FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5713F158C042D8CULL,
		0xF0EBAE2C4284B1B8ULL,
		0xC08CD687B30F2A24ULL,
		0xD179B55F52C86A89ULL,
		0xB74173A947069C37ULL,
		0x0B9563935A4BB10EULL,
		0x30B6FD2311791A75ULL,
		0xBE7CF2CF70CDFBC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3599136F116B88A0ULL,
		0x210BA233543A6C82ULL,
		0x56C29937FED98253ULL,
		0xF51531F1D0C1934CULL,
		0x7FA46AEBAD09D846ULL,
		0xA56DC9186692D989ULL,
		0xF407F525CB496D47ULL,
		0x652BA558DEA8AB7AULL
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
		0xF68D367EB224AF50ULL,
		0x7621734F6438EA8FULL,
		0x2928C29FC47A1F88ULL,
		0xBD7D895BD3EA0ECAULL,
		0x8DE68B21E0C8F46AULL,
		0xA8462418599FAA33ULL,
		0x250023F1F8FFDD0CULL,
		0x4585E48EBCD40137ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE110EC091D0CED4ULL,
		0xB75DAEDE5257CEEBULL,
		0xDCD26AF542223D9EULL,
		0x2D47A64F6AF3CD1FULL,
		0xEBF8CA1061FE8E44ULL,
		0xD6DD3CE8A7E2504CULL,
		0x560EC8D4FACC6D3CULL,
		0x17A2BCB31858CA4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x287C27BE2053E07CULL,
		0xBEC3C47111E11BA4ULL,
		0x4C5657AA8257E1E9ULL,
		0x9035E30C68F641AAULL,
		0xA1EDC1117ECA6626ULL,
		0xD168E72FB1BD59E6ULL,
		0xCEF15B1CFE336FCFULL,
		0x2DE327DBA47B36E8ULL
	}};
	sign = 0;
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
		0x20E19E5BD30AB887ULL,
		0x09EDB78E4CE4DDB9ULL,
		0x79ACBBD8EF47BD52ULL,
		0x314FD0049B741E32ULL,
		0x30C80E9F751C9A81ULL,
		0xDFC1DF4F1707DEF7ULL,
		0x1D84F87E64DD9D8DULL,
		0xB0C75A4ADB0ECBB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x559F31EA74947F41ULL,
		0xD9214E0D4028E214ULL,
		0x4ADE05AD4F839D94ULL,
		0x662889BCB1FCF9A9ULL,
		0x7D2535FDC8598817ULL,
		0x9C646675CB8F0E06ULL,
		0x07564557A4F47A1AULL,
		0x043EAF1FC19BA9C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB426C715E763946ULL,
		0x30CC69810CBBFBA4ULL,
		0x2ECEB62B9FC41FBDULL,
		0xCB274647E9772489ULL,
		0xB3A2D8A1ACC31269ULL,
		0x435D78D94B78D0F0ULL,
		0x162EB326BFE92373ULL,
		0xAC88AB2B197321F0ULL
	}};
	sign = 0;
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
		0xE08CB4D8D462E90EULL,
		0x27BBEC3875255948ULL,
		0xD9D8A4CF322D10CBULL,
		0x7A1D4AB83CF5BB49ULL,
		0x71D8BAAF4945DB23ULL,
		0x00744856D8D9995BULL,
		0xF8954DD1F7A0891BULL,
		0x254D4614573CDF2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7413CAA57D7B024ULL,
		0x5A69C735812E5B4DULL,
		0x8B1E514D692B483EULL,
		0x3A1CDB3B53B6FC62ULL,
		0x4B08C78ED943B055ULL,
		0xD344DA0C99021FECULL,
		0x04A3163A82AD5127ULL,
		0x0B616DC8F501D6BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE94B782E7C8B38EAULL,
		0xCD522502F3F6FDFAULL,
		0x4EBA5381C901C88CULL,
		0x40006F7CE93EBEE7ULL,
		0x26CFF32070022ACEULL,
		0x2D2F6E4A3FD7796FULL,
		0xF3F2379774F337F3ULL,
		0x19EBD84B623B086FULL
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
		0x33F9E54C61D85E97ULL,
		0x9800F42330169EB7ULL,
		0x933C74C840DF58D1ULL,
		0x507AEE1B7AB6CB45ULL,
		0x01F2E00E77A26536ULL,
		0xFAA6B33EAD1B2543ULL,
		0x8A94873C9A9715F0ULL,
		0x8AF0B529FA766340ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C96A21A3762C436ULL,
		0xF4C6AA4E51D0C1BAULL,
		0x680D47E9542F10E8ULL,
		0xBADD7D492AF56821ULL,
		0x866DAC984E8CB537ULL,
		0xA6BD4A514CD0AF42ULL,
		0x05394F89F9808444ULL,
		0x790E9F6527318BB7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB76343322A759A61ULL,
		0xA33A49D4DE45DCFCULL,
		0x2B2F2CDEECB047E8ULL,
		0x959D70D24FC16324ULL,
		0x7B8533762915AFFEULL,
		0x53E968ED604A7600ULL,
		0x855B37B2A11691ACULL,
		0x11E215C4D344D789ULL
	}};
	sign = 0;
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
		0x5AAD47304203C5DEULL,
		0xCA820932BADE60E5ULL,
		0x89C04BA5614E1009ULL,
		0x27C0C7BDEE99BDCCULL,
		0x1AE0A4F134A63F27ULL,
		0x56F7748FE7D5F861ULL,
		0xBFD36A3CED5F613BULL,
		0x8E8248E30BC2ADE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962855D0412F32D2ULL,
		0xBDE4CB3077BFFD63ULL,
		0xC93AA6DE07F09259ULL,
		0xF07AFE5F00E21F73ULL,
		0xA7080CFFB05D0DDBULL,
		0xCCABBC53A933C152ULL,
		0x4A4E58A38BEF64A6ULL,
		0x74ED9479DBB513BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC484F16000D4930CULL,
		0x0C9D3E02431E6381ULL,
		0xC085A4C7595D7DB0ULL,
		0x3745C95EEDB79E58ULL,
		0x73D897F18449314BULL,
		0x8A4BB83C3EA2370EULL,
		0x75851199616FFC94ULL,
		0x1994B469300D9A29ULL
	}};
	sign = 0;
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
		0xA57E33626FBAD230ULL,
		0x4A819CB46AD92EEFULL,
		0x5704F09EBD308AFFULL,
		0x7A34001FD8EC3712ULL,
		0xAF5401FA7F420D15ULL,
		0x7A128233973E8947ULL,
		0xC36395FB861F1667ULL,
		0xC236A106CB02A7D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF7150C4A4908D5ULL,
		0x3A9C1EF5044A5E58ULL,
		0xE054108174C45C34ULL,
		0xA6E94C710457E15FULL,
		0x11A2E85D1B4FE738ULL,
		0x8E500C55C2C49179ULL,
		0xF7E78005A1305261ULL,
		0xF7BF5D790BB598D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19871E562571C95BULL,
		0x0FE57DBF668ED097ULL,
		0x76B0E01D486C2ECBULL,
		0xD34AB3AED49455B2ULL,
		0x9DB1199D63F225DCULL,
		0xEBC275DDD479F7CEULL,
		0xCB7C15F5E4EEC405ULL,
		0xCA77438DBF4D0EFFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2DE84AE06E645A1AULL,
		0x0EF95046F378D251ULL,
		0xF7EB157953FDAA4EULL,
		0x8777FD573F2317DDULL,
		0x8DA4BFE8402CA7D0ULL,
		0x048048CDDFBAF5F6ULL,
		0xD0EA9B2CA73545FAULL,
		0x2F3EF565CC0383FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69775EAABB9E8724ULL,
		0x14BCBE35FDF27DCCULL,
		0x583B04E664BA8550ULL,
		0x66404C478076AADDULL,
		0x84332B7A6F3E1BB6ULL,
		0xF4AAD114CB4D849AULL,
		0x3F7CC20E2C21EBC6ULL,
		0x65F63E887D7075BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC470EC35B2C5D2F6ULL,
		0xFA3C9210F5865484ULL,
		0x9FB01092EF4324FDULL,
		0x2137B10FBEAC6D00ULL,
		0x0971946DD0EE8C1AULL,
		0x0FD577B9146D715CULL,
		0x916DD91E7B135A33ULL,
		0xC948B6DD4E930E41ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8CFC9BF43E312E63ULL,
		0x63FC54FAC9D6ABC4ULL,
		0xFA1913D5BB12F889ULL,
		0x67CE01DF1A88FE10ULL,
		0xB46F8D7344B417F8ULL,
		0x059AC4509F3498F3ULL,
		0x6F9B70052EC0C84BULL,
		0xE96701805498D576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9AB0D27AAE17A8AULL,
		0x3867A2A715167493ULL,
		0x18F67E2102846DE8ULL,
		0x22BE4F4635E49029ULL,
		0x70DB45981925B255ULL,
		0xE2B5383FB2E1E69BULL,
		0xB8556FE342D29FE4ULL,
		0x9FFC24A285384609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93518ECC934FB3D9ULL,
		0x2B94B253B4C03730ULL,
		0xE12295B4B88E8AA1ULL,
		0x450FB298E4A46DE7ULL,
		0x439447DB2B8E65A3ULL,
		0x22E58C10EC52B258ULL,
		0xB7460021EBEE2866ULL,
		0x496ADCDDCF608F6CULL
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
		0xABB4661873ED8DF1ULL,
		0x3D41B7168FBABD87ULL,
		0xD72DE7FDEF19743BULL,
		0xF331EC44AA895C26ULL,
		0xBDDEFD43A412F6BBULL,
		0x4B154D547BE9D20AULL,
		0x79B2CB40F3D6F009ULL,
		0xF0F1F70F88D3FF55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4F71E0D1566E2AAULL,
		0x1E49338E841D0A35ULL,
		0x8601822558C87AD8ULL,
		0x48C882AE5716BD32ULL,
		0x62DA3FAC0658D69BULL,
		0xB001E3F6040F56A3ULL,
		0xD776E8E6EBA176A2ULL,
		0xBA2205BABBAF2391ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6BD480B5E86AB47ULL,
		0x1EF883880B9DB351ULL,
		0x512C65D89650F963ULL,
		0xAA69699653729EF4ULL,
		0x5B04BD979DBA2020ULL,
		0x9B13695E77DA7B67ULL,
		0xA23BE25A08357966ULL,
		0x36CFF154CD24DBC3ULL
	}};
	sign = 0;
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
		0x53157B91855DA973ULL,
		0x9AE6449016000A69ULL,
		0x8A7891A794CDB7E9ULL,
		0x595D99FA63732A3CULL,
		0xD1D25BA854D31119ULL,
		0x08300C35E8E88265ULL,
		0x81C333072BBFEC4CULL,
		0xF33B03E06330B319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4945C0B5A7BC2D3CULL,
		0xC2A9DF56B0734440ULL,
		0xBCCC298A12DABB70ULL,
		0x10B750503EFEA5C2ULL,
		0xA3F4BF5F77135D01ULL,
		0x7DBDF430D395B4C7ULL,
		0x7C1B01D16274B1EEULL,
		0x429D78513A13BB50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09CFBADBDDA17C37ULL,
		0xD83C6539658CC629ULL,
		0xCDAC681D81F2FC78ULL,
		0x48A649AA24748479ULL,
		0x2DDD9C48DDBFB418ULL,
		0x8A7218051552CD9EULL,
		0x05A83135C94B3A5DULL,
		0xB09D8B8F291CF7C9ULL
	}};
	sign = 0;
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
		0x92AC7AD3EE4126B7ULL,
		0xA1DD45734CB43CB5ULL,
		0x989DFCDE6888F4C3ULL,
		0x650893A36C8C280EULL,
		0xD86B0395D3A7EF5AULL,
		0xAC6FE088D1C63B44ULL,
		0xEF0609B20B83D7CDULL,
		0x916566C85795EAEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60094764503C69F0ULL,
		0x52DFA5953B2A6023ULL,
		0x7746358B465ABFCEULL,
		0x2A6AFA8050B7E395ULL,
		0xF69589B9DCE37190ULL,
		0xFAAFA73E7CEBB407ULL,
		0x900CEBA2F6F6428CULL,
		0xAB969F9896138980ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32A3336F9E04BCC7ULL,
		0x4EFD9FDE1189DC92ULL,
		0x2157C753222E34F5ULL,
		0x3A9D99231BD44479ULL,
		0xE1D579DBF6C47DCAULL,
		0xB1C0394A54DA873CULL,
		0x5EF91E0F148D9540ULL,
		0xE5CEC72FC182616DULL
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
		0xD6C9FF022871FAFDULL,
		0x94FC61893226983CULL,
		0x8C60EEDE3F7BF6A2ULL,
		0xC95B0CA04BE28D6FULL,
		0x66C51086A052A724ULL,
		0x0020FD4698A17F7CULL,
		0x51BE9E382717B570ULL,
		0xCB97903D8C1B6014ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5601A91D5CD056A4ULL,
		0x54F41F9D13FF5BFBULL,
		0xF5AC3A65EAA041D8ULL,
		0x3F0E3A5679BBB046ULL,
		0x73C18F327DD664CEULL,
		0x2AC2287DB9060628ULL,
		0x7993BCCEB4E7C915ULL,
		0x6A59896344C148C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C855E4CBA1A459ULL,
		0x400841EC1E273C41ULL,
		0x96B4B47854DBB4CAULL,
		0x8A4CD249D226DD28ULL,
		0xF3038154227C4256ULL,
		0xD55ED4C8DF9B7953ULL,
		0xD82AE169722FEC5AULL,
		0x613E06DA475A1750ULL
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
		0x99A4E7B05926173BULL,
		0x0ABB74C22D030829ULL,
		0x70374FD93590FC51ULL,
		0xF690B5D3E21E6DA6ULL,
		0x691FB6B49F0B837DULL,
		0x72836985E6A69BB7ULL,
		0x279135FBFD4F0E21ULL,
		0x9072F11E6FC99E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x861D5F52340636F7ULL,
		0xE242CAD1E3E6C700ULL,
		0xD04149ADD85B1C98ULL,
		0xB96361127B622678ULL,
		0x817065B98ABC0746ULL,
		0x5A509A291ECCF1A0ULL,
		0x797021ECA4D083A0ULL,
		0x7225A8D7C0B48AF2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1387885E251FE044ULL,
		0x2878A9F0491C4129ULL,
		0x9FF6062B5D35DFB8ULL,
		0x3D2D54C166BC472DULL,
		0xE7AF50FB144F7C37ULL,
		0x1832CF5CC7D9AA16ULL,
		0xAE21140F587E8A81ULL,
		0x1E4D4846AF1513A7ULL
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
		0x00BCDA1E400A203DULL,
		0xE5E15DBBE4D5B462ULL,
		0xDD6F1F29F67C4DBDULL,
		0x5E491666AC5306B0ULL,
		0xF96FCF42366FB8C6ULL,
		0xD15A127948A7A41CULL,
		0xE5FE3F0015778CA6ULL,
		0x9AFC459BAADD70C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9F160FDD32A6826ULL,
		0x3D2347DE92489573ULL,
		0xD9EDB02F5B9C3236ULL,
		0x31E9C3CF18712F89ULL,
		0x990A1912E2E00BA4ULL,
		0x501F324C37FD40DFULL,
		0x02B67F1AA8AF4018ULL,
		0xE69D38C97D4D6BBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16CB79206CDFB817ULL,
		0xA8BE15DD528D1EEEULL,
		0x03816EFA9AE01B87ULL,
		0x2C5F529793E1D727ULL,
		0x6065B62F538FAD22ULL,
		0x813AE02D10AA633DULL,
		0xE347BFE56CC84C8EULL,
		0xB45F0CD22D900502ULL
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
		0x9B3A14DC6E2161ACULL,
		0x6ABF544CEA444E9AULL,
		0xB1197757603F6139ULL,
		0xC8159F439FE01B73ULL,
		0x69420822A665D7B5ULL,
		0xC0F3D534C0F24E39ULL,
		0x2DC78F0321649404ULL,
		0x3B4B9D91A70EED9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3BEC29022E6157AULL,
		0x92DC516F41A50C6BULL,
		0x5DFBA19F88BA4983ULL,
		0xC1740F3F41B4C20CULL,
		0xB8468863BC1C26E4ULL,
		0x6B6BD5EDD596CA4DULL,
		0xB93D448DF284F5F0ULL,
		0x00E857422F63515BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB77B524C4B3B4C32ULL,
		0xD7E302DDA89F422EULL,
		0x531DD5B7D78517B5ULL,
		0x06A190045E2B5967ULL,
		0xB0FB7FBEEA49B0D1ULL,
		0x5587FF46EB5B83EBULL,
		0x748A4A752EDF9E14ULL,
		0x3A63464F77AB9C3EULL
	}};
	sign = 0;
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
		0x3CFEB35A4BEC61F6ULL,
		0x39A7E0D04AAD0B5FULL,
		0x736E68B05F2F34B1ULL,
		0x495BFC818E1230CCULL,
		0x18BF77F947D13738ULL,
		0x54D78239901600AAULL,
		0x5E95CCFB3290E3E6ULL,
		0xE3157E277E2B8E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E36484554E53B0ULL,
		0xB35F68995F536C97ULL,
		0x5C1A6BCD790854D7ULL,
		0x340F292576ACE880ULL,
		0x29ACFA5A3E2580B2ULL,
		0x29CC4AED2E966695ULL,
		0x277A52CA8219AB55ULL,
		0x7FC3C214E50CC25EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC81B4ED5F69E0E46ULL,
		0x86487836EB599EC7ULL,
		0x1753FCE2E626DFD9ULL,
		0x154CD35C1765484CULL,
		0xEF127D9F09ABB686ULL,
		0x2B0B374C617F9A14ULL,
		0x371B7A30B0773891ULL,
		0x6351BC12991ECC17ULL
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
		0x3F9C6D87F5473D51ULL,
		0xC3825A0DAF15E9EBULL,
		0x55BABD8B5E390D57ULL,
		0x37D57886BFF6DF7AULL,
		0x788B28398400641FULL,
		0x5FA28724F2C1A964ULL,
		0x37383409BB0804DEULL,
		0xE90A0B71BC07A6B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD649C977D09298AULL,
		0xFDFE4881D8182A7CULL,
		0xEF8ABB71AAD1CC13ULL,
		0xB861F7EDC989E1F2ULL,
		0xF99376EC5800BB14ULL,
		0xCC00350ADA1444FCULL,
		0xC14038497FB107DFULL,
		0xF7B200829C4D283FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6237D0F0783E13C7ULL,
		0xC584118BD6FDBF6EULL,
		0x66300219B3674143ULL,
		0x7F738098F66CFD87ULL,
		0x7EF7B14D2BFFA90AULL,
		0x93A2521A18AD6467ULL,
		0x75F7FBC03B56FCFEULL,
		0xF1580AEF1FBA7E73ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x729AE209A55AB53AULL,
		0x270B6118412903AFULL,
		0x75E1FF5FCA36C909ULL,
		0x3971BC7D0CDBE39AULL,
		0x6AD81B205605B318ULL,
		0x2501CA3186168C2CULL,
		0x9E6741600AF4BF15ULL,
		0x085BC4EDB28A312FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD93018068E233C5ULL,
		0xBF2F917AA55243E2ULL,
		0x70878C85367EB253ULL,
		0xAAC82394150CBA98ULL,
		0xE56ABB04FF635489ULL,
		0x5C93D61697A9B33AULL,
		0xBB8AC754F7637A6EULL,
		0x700601A3D2DB6411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB507E0893C788175ULL,
		0x67DBCF9D9BD6BFCCULL,
		0x055A72DA93B816B5ULL,
		0x8EA998E8F7CF2902ULL,
		0x856D601B56A25E8EULL,
		0xC86DF41AEE6CD8F1ULL,
		0xE2DC7A0B139144A6ULL,
		0x9855C349DFAECD1DULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFDD42D76D7C1A3FAULL,
		0x9436FDB4492421EFULL,
		0x62A574C27B7F922FULL,
		0x03C178E76224E09AULL,
		0xAE7D2CCCBED142AAULL,
		0x7AF618749CAC70FAULL,
		0x913CC4118F25536EULL,
		0x505D1DD923786F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DFBB4A68CEA90CEULL,
		0xECDBEF6E382BDB0AULL,
		0xBE06C71F9C3537A6ULL,
		0x5269C29E44E09928ULL,
		0x1217FE3ACAFFB567ULL,
		0x5C2615F4F86F933BULL,
		0x5F6D5D431775926CULL,
		0x1D51303759D99913ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFD878D04AD7132CULL,
		0xA75B0E4610F846E5ULL,
		0xA49EADA2DF4A5A88ULL,
		0xB157B6491D444771ULL,
		0x9C652E91F3D18D42ULL,
		0x1ED0027FA43CDDBFULL,
		0x31CF66CE77AFC102ULL,
		0x330BEDA1C99ED5F5ULL
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
		0x3128B43CB1A6EEEEULL,
		0x59488D93FA56B4A2ULL,
		0xB6BEE8524E745D5FULL,
		0x6AC4D0FF1037D2A1ULL,
		0xA6A6CA469F0E3222ULL,
		0xFF72E9FF820F45CFULL,
		0x5302CDAC0FB59619ULL,
		0x1A51224A078B4E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C5A0999B671F21ULL,
		0x255BD522D48E93CBULL,
		0xD79DDB06E509E3F4ULL,
		0x200950A05D4AE258ULL,
		0x2F9D2D24051C3CD6ULL,
		0x1D27BFF9464DACD4ULL,
		0x98ECC7A9704995A6ULL,
		0x0DA521E418C329BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF6313A3163FCFCDULL,
		0x33ECB87125C820D6ULL,
		0xDF210D4B696A796BULL,
		0x4ABB805EB2ECF048ULL,
		0x77099D2299F1F54CULL,
		0xE24B2A063BC198FBULL,
		0xBA1606029F6C0073ULL,
		0x0CAC0065EEC824B4ULL
	}};
	sign = 0;
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
		0x626052F803E425A2ULL,
		0xB4439B6D9BBB3374ULL,
		0xDFE3CCF71567A1C8ULL,
		0xD67F22604CA5E4E5ULL,
		0xBA928793BFDA4673ULL,
		0x85EF2968F6EF1869ULL,
		0xCCBDF736AC87C153ULL,
		0x3741F349FA7530DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE632F1F329FEFFF1ULL,
		0x9BDE6CD3459020B3ULL,
		0xDA9982F02A6B4E02ULL,
		0xA0DCEBCC55FC534BULL,
		0x1F9A5B21FE376486ULL,
		0x12D2D975065E37BDULL,
		0xEE9474FCEEA71EB6ULL,
		0x05FC437E4AB8B318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7C2D6104D9E525B1ULL,
		0x18652E9A562B12C0ULL,
		0x054A4A06EAFC53C6ULL,
		0x35A23693F6A9919AULL,
		0x9AF82C71C1A2E1EDULL,
		0x731C4FF3F090E0ACULL,
		0xDE298239BDE0A29DULL,
		0x3145AFCBAFBC7DC6ULL
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
		0xC62439EAF2D0D005ULL,
		0xFED84AE119068A4DULL,
		0xCDF7581DB60E85D5ULL,
		0xA3BE79D01DCE0C0BULL,
		0x16136B7417BCE6A4ULL,
		0x1556BB2AD2A93513ULL,
		0x93E4FFAFBF013F73ULL,
		0x8EAAD47C70DD7F7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF603AED03C500492ULL,
		0x896D74F1B6CCECD2ULL,
		0xB26D22EA74C1771AULL,
		0xC06EE38F8500060EULL,
		0xE77490031A8C2227ULL,
		0x91806B3A369BF368ULL,
		0x088454729DB690ACULL,
		0xC07CAAAFA911E659ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0208B1AB680CB73ULL,
		0x756AD5EF62399D7AULL,
		0x1B8A3533414D0EBBULL,
		0xE34F964098CE05FDULL,
		0x2E9EDB70FD30C47CULL,
		0x83D64FF09C0D41AAULL,
		0x8B60AB3D214AAEC6ULL,
		0xCE2E29CCC7CB9925ULL
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
		0xA9B8D9A7C14E53E5ULL,
		0x27E4CECEE0121B22ULL,
		0x1032BD36AB061AA8ULL,
		0xE737F8F53E3B33A0ULL,
		0xBE284914EFDB743BULL,
		0xD4311F4FF3E6B000ULL,
		0x745745CE3A2AB055ULL,
		0x24D3080F3E716B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F6322B746B087E2ULL,
		0xD35D3A8E05E2D302ULL,
		0x701FA0F9D2AB919CULL,
		0x823663F72C5EC652ULL,
		0xA3B27B856280DD9BULL,
		0x6C64AD81C104C225ULL,
		0x6A1A0C1856EAF307ULL,
		0x99FC6592322697D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A55B6F07A9DCC03ULL,
		0x54879440DA2F4820ULL,
		0xA0131C3CD85A890BULL,
		0x650194FE11DC6D4DULL,
		0x1A75CD8F8D5A96A0ULL,
		0x67CC71CE32E1EDDBULL,
		0x0A3D39B5E33FBD4EULL,
		0x8AD6A27D0C4AD344ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF6A5DDD3F2C654FAULL,
		0xA2B0F29DFB55D54EULL,
		0xA0427E70E0F08C29ULL,
		0x1EF5BE67E6818732ULL,
		0x8AF99182DA69ED77ULL,
		0xCB7CF69BF879525BULL,
		0xD6B288CCCFF3660DULL,
		0xA3FCBDCC06C4986EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BEA074B81AFBCCULL,
		0x9060027DB5B56517ULL,
		0xE234FF426EB3D1C8ULL,
		0xFA4BC0B2D8AAC2FBULL,
		0xCD6E650133C2ED07ULL,
		0x213C116D0051F0B1ULL,
		0x1A9D93DC1FDA9D9AULL,
		0xC382BDDFFE837CCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CE73D5F3AAB592EULL,
		0x1250F02045A07037ULL,
		0xBE0D7F2E723CBA61ULL,
		0x24A9FDB50DD6C436ULL,
		0xBD8B2C81A6A7006FULL,
		0xAA40E52EF82761A9ULL,
		0xBC14F4F0B018C873ULL,
		0xE079FFEC08411BA3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD7843EC25D0033F4ULL,
		0x783C57B869686550ULL,
		0xC115898CFA047B2FULL,
		0x7021066A919E1DDDULL,
		0xD822B3E277EF554BULL,
		0x1B77362A719215B9ULL,
		0x320F920A49693AD4ULL,
		0xD5EE99BC25155E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94FA96DF27D89A18ULL,
		0x8E3E146B50ABC592ULL,
		0xB93C2C2DDAEBCA78ULL,
		0x39E17CDFD243A1E8ULL,
		0x8101E9DF86E15882ULL,
		0xF54360B83A999152ULL,
		0x92CDBD683A233687ULL,
		0x718B327E4F48DAE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4289A7E3352799DCULL,
		0xE9FE434D18BC9FBEULL,
		0x07D95D5F1F18B0B6ULL,
		0x363F898ABF5A7BF5ULL,
		0x5720CA02F10DFCC9ULL,
		0x2633D57236F88467ULL,
		0x9F41D4A20F46044CULL,
		0x6463673DD5CC832FULL
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
		0xBC24008BE74AC295ULL,
		0x48AAC5E2E60C3888ULL,
		0x75601B12FD5EC957ULL,
		0xF89FCFAB0AADED7EULL,
		0xA35EF020B7DB1AC7ULL,
		0x324275D861CB27C5ULL,
		0x1E00B18C088E73C7ULL,
		0xB3F8E91136534BDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4972074B2A488BAULL,
		0xED125BA8AA05F6B3ULL,
		0xE62D45C109EC2D22ULL,
		0x0A671D1FC235FF59ULL,
		0x7A89F3BE904957C5ULL,
		0x41220C4B04857FDAULL,
		0x89E34A66838DC857ULL,
		0x86E76760C07B6536ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF78CE01734A639DBULL,
		0x5B986A3A3C0641D4ULL,
		0x8F32D551F3729C34ULL,
		0xEE38B28B4877EE24ULL,
		0x28D4FC622791C302ULL,
		0xF120698D5D45A7EBULL,
		0x941D67258500AB6FULL,
		0x2D1181B075D7E6A8ULL
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
		0xF384BEDC0CBC2345ULL,
		0xB5836911C6FECA98ULL,
		0xCC681904381AD24DULL,
		0xCDE0948F6C8A2A81ULL,
		0x21A135A003FF88F0ULL,
		0xF2C83DFD34F169A4ULL,
		0x1102B9358506F006ULL,
		0x67C4453296B3687CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5E67E6C503E81C6ULL,
		0x67D0AF231333F219ULL,
		0x5484E310699F44E6ULL,
		0x987EEA838537F82FULL,
		0x47202394E39DCB7BULL,
		0x11BFD18A903953B7ULL,
		0x7435D462C7352F76ULL,
		0x19F2FE18CC324210ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D9E406FBC7DA17FULL,
		0x4DB2B9EEB3CAD87FULL,
		0x77E335F3CE7B8D67ULL,
		0x3561AA0BE7523252ULL,
		0xDA81120B2061BD75ULL,
		0xE1086C72A4B815ECULL,
		0x9CCCE4D2BDD1C090ULL,
		0x4DD14719CA81266BULL
	}};
	sign = 0;
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
		0xC93A85E63B37D2F0ULL,
		0x77A47E5662DE14ACULL,
		0x3D67006B67846A8FULL,
		0x55D06EEB4DA4DEA0ULL,
		0x2C20E45C2FFAE0EFULL,
		0x251573688ECE45CCULL,
		0x7CA5ADD15FD563B9ULL,
		0x9B8691DFB204507CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x371274F2AFCF0199ULL,
		0x4ED2C9CDFE820C9AULL,
		0x22627644D8D11AD0ULL,
		0x242ABAC49BD971DFULL,
		0x8D916A613B5C0BD2ULL,
		0x60C4CD0D1FFFFAC5ULL,
		0xD10241D392FA5BEFULL,
		0x6F5FC4B8F15BBD87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x922810F38B68D157ULL,
		0x28D1B488645C0812ULL,
		0x1B048A268EB34FBFULL,
		0x31A5B426B1CB6CC1ULL,
		0x9E8F79FAF49ED51DULL,
		0xC450A65B6ECE4B06ULL,
		0xABA36BFDCCDB07C9ULL,
		0x2C26CD26C0A892F4ULL
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
		0xDC679AFFF469A9DBULL,
		0xB4491A1F6B4A1294ULL,
		0x5CDD07C9BB2DBE3AULL,
		0x500BB69219A91E73ULL,
		0x82F63D5CBBC1C7D4ULL,
		0x80A1A08F92F1EFF8ULL,
		0x9A27284424D9B0D2ULL,
		0x2D84D6C0DF1605EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF60C66CB6E6C10CULL,
		0x3C62F973CD51DDD6ULL,
		0xC3CD50E20A0BA40EULL,
		0x8D31E230C0C0E80CULL,
		0x9994BD8D96BCBC79ULL,
		0x8683FEB54468E9D2ULL,
		0xCE93188999407BF5ULL,
		0x970C84AB7C495316ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D06D4933D82E8CFULL,
		0x77E620AB9DF834BEULL,
		0x990FB6E7B1221A2CULL,
		0xC2D9D46158E83666ULL,
		0xE9617FCF25050B5AULL,
		0xFA1DA1DA4E890625ULL,
		0xCB940FBA8B9934DCULL,
		0x9678521562CCB2D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF3B751DEF127BA68ULL,
		0x13679C4507271187ULL,
		0x924DBA828B650B45ULL,
		0x1C3686464FAD96EBULL,
		0x9091D09B2090924FULL,
		0x940897FF6C8E5A74ULL,
		0x64EDEF61A5550029ULL,
		0x02C68C74F7189E7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA71D3E8FDA88880CULL,
		0x0D712F6B1A2EF032ULL,
		0x27227E2DF0AC3931ULL,
		0x6731C8AA024C86B3ULL,
		0x4AB5607B0F5CB167ULL,
		0xEC77A8B920DFEA44ULL,
		0x6B6B82736D7AB887ULL,
		0xA114788E8D7DE586ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C9A134F169F325CULL,
		0x05F66CD9ECF82155ULL,
		0x6B2B3C549AB8D214ULL,
		0xB504BD9C4D611038ULL,
		0x45DC70201133E0E7ULL,
		0xA790EF464BAE7030ULL,
		0xF9826CEE37DA47A1ULL,
		0x61B213E6699AB8F7ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x159E64479BDA1312ULL,
		0x41453B3675E41BCCULL,
		0x471DB8C9DEC8D765ULL,
		0xDD29080B02EE734EULL,
		0x1CD4D430572D9CA5ULL,
		0xB503703C2FB2EEF5ULL,
		0x444C7F1D9C726EF9ULL,
		0x754C7DDB069D3754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C5ACDD394478460ULL,
		0x431864B2BEE7B551ULL,
		0xB1836E11A85A5227ULL,
		0x4F34D2318FA5723EULL,
		0xD772EDEE1F9EFC3AULL,
		0xC459D6B276B719E3ULL,
		0xF688280EED461DE0ULL,
		0x479ECF43ACF4023AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC943967407928EB2ULL,
		0xFE2CD683B6FC667AULL,
		0x959A4AB8366E853DULL,
		0x8DF435D97349010FULL,
		0x4561E642378EA06BULL,
		0xF0A99989B8FBD511ULL,
		0x4DC4570EAF2C5118ULL,
		0x2DADAE9759A93519ULL
	}};
	sign = 0;
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
		0x93E7891017059EFDULL,
		0x65D18931515D6171ULL,
		0xE7884CB5CF137AE0ULL,
		0x3B113A77581E003AULL,
		0x4A87076F52A51401ULL,
		0x19BA60815A7ED992ULL,
		0x288CF3C7C5A4981FULL,
		0x8C3657BAFCC94E36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2293734914C9AF17ULL,
		0x7DAA4C17872A2F3BULL,
		0x28B34C0D3BD3B4B6ULL,
		0x8EAB00F7B801601FULL,
		0x2FF5CA0A65EA04E8ULL,
		0xF715558F86B65591ULL,
		0xCAC2E2B95E9E65F7ULL,
		0x12D75CC1211DAAE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x715415C7023BEFE6ULL,
		0xE8273D19CA333236ULL,
		0xBED500A8933FC629ULL,
		0xAC66397FA01CA01BULL,
		0x1A913D64ECBB0F18ULL,
		0x22A50AF1D3C88401ULL,
		0x5DCA110E67063227ULL,
		0x795EFAF9DBABA34EULL
	}};
	sign = 0;
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
		0xC925D8C2E963DCE0ULL,
		0x3F0B950B460A76FEULL,
		0x6C98FB34AA3BF692ULL,
		0x8C289FBE38C12EDDULL,
		0x4EA7A3B5F57E95EEULL,
		0x903BB63C11B0BEFEULL,
		0x2A41A8C18A475CF7ULL,
		0xDBC1A7828F35952AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0D9105F0E70F4C8ULL,
		0xB8556FDEEFE789FEULL,
		0xAD00DDE978E687D1ULL,
		0x646E99ACAC03B616ULL,
		0xD74CD914743EFD89ULL,
		0x3734E627BB1B0B97ULL,
		0x19B4C82D96A3F64BULL,
		0xE0B3C7EE9BDA972EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x084CC863DAF2E818ULL,
		0x86B6252C5622ED00ULL,
		0xBF981D4B31556EC0ULL,
		0x27BA06118CBD78C6ULL,
		0x775ACAA1813F9865ULL,
		0x5906D0145695B366ULL,
		0x108CE093F3A366ACULL,
		0xFB0DDF93F35AFDFCULL
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
		0x95C8A5A3EE29FE94ULL,
		0x34562B579F99E0F4ULL,
		0x65E133D538C08F6EULL,
		0xCAF86732DA60D873ULL,
		0x1366DBEA59FCA280ULL,
		0x8D6E328D5DA8C631ULL,
		0x1C7EE0F1F49AA7BCULL,
		0x519AA47AEDC7E309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADD17C61525BB46AULL,
		0xA269990120FE3E04ULL,
		0x16A9EDFAEA64BC44ULL,
		0xF39E9470D92ED2F6ULL,
		0x945A377F047E37DEULL,
		0x5087499A2B20A199ULL,
		0xA58DDDFFF6B80402ULL,
		0x78AC5EB130E260BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE7F729429BCE4A2AULL,
		0x91EC92567E9BA2EFULL,
		0x4F3745DA4E5BD329ULL,
		0xD759D2C20132057DULL,
		0x7F0CA46B557E6AA1ULL,
		0x3CE6E8F332882497ULL,
		0x76F102F1FDE2A3BAULL,
		0xD8EE45C9BCE5824CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x943D0FDB9005AD91ULL,
		0xA94E5FB126B8BF26ULL,
		0xA1B3A04E5FD8B627ULL,
		0xFB7FC4C9E75C1D59ULL,
		0xE04A17068A3FB74DULL,
		0xEC9EC0DEFD1D1BCAULL,
		0xCA8DF95D36DC6702ULL,
		0x122A280072EAC462ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB65B7DE4EFE137CULL,
		0xE694DEF2345C947CULL,
		0xD6035F1E886D59D8ULL,
		0x7E089100FBA0063AULL,
		0x4D3B5FF0B74F4B2DULL,
		0xE9F1CD11467FFD9EULL,
		0x9D2F4F4E653B3D2DULL,
		0x5F328665A4B1B2A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8D757FD41079A15ULL,
		0xC2B980BEF25C2AA9ULL,
		0xCBB0412FD76B5C4EULL,
		0x7D7733C8EBBC171EULL,
		0x930EB715D2F06C20ULL,
		0x02ACF3CDB69D1E2CULL,
		0x2D5EAA0ED1A129D5ULL,
		0xB2F7A19ACE3911BAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x07A798102B4B7BD6ULL,
		0xF74D5C51C6BE882EULL,
		0xD4EBFA604C07450BULL,
		0x85411AFC678FB57DULL,
		0x0CEBB4F2AFB8BA01ULL,
		0xB91483019080837FULL,
		0x1B58D55C76D468DEULL,
		0x316DE0F63C54CD09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AE5FC0110F123C1ULL,
		0xF9439E80346929C4ULL,
		0xF3EC7EB37AA96F65ULL,
		0xC5D905FC40C42023ULL,
		0x51B573BB4ECB1927ULL,
		0x39A852FB87E64CAAULL,
		0xAAB57A3C4DF410FFULL,
		0xC86B1192A04D5616ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CC19C0F1A5A5815ULL,
		0xFE09BDD192555E69ULL,
		0xE0FF7BACD15DD5A5ULL,
		0xBF68150026CB9559ULL,
		0xBB36413760EDA0D9ULL,
		0x7F6C3006089A36D4ULL,
		0x70A35B2028E057DFULL,
		0x6902CF639C0776F2ULL
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
		0x269C8257FBE5E4FAULL,
		0x808989D95D1EF050ULL,
		0xFB787611D0BE1D95ULL,
		0x32DDE3E8F4481434ULL,
		0x0A3C57BA2A2E10DEULL,
		0xD81E0CB5BB76AC13ULL,
		0x17AB8A2B5CB01696ULL,
		0x295B741C758D3DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA56863A9E47FFDULL,
		0x1110A62855A51941ULL,
		0x45C23E9F5384DB7AULL,
		0xC5AAE37C0DF1DE1BULL,
		0x04524CE936331F22ULL,
		0x9DA37645F30AA515ULL,
		0xF3A644556FAD1348ULL,
		0x39ACE40C0919BB16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8F719F4520164FDULL,
		0x6F78E3B10779D70EULL,
		0xB5B637727D39421BULL,
		0x6D33006CE6563619ULL,
		0x05EA0AD0F3FAF1BBULL,
		0x3A7A966FC86C06FEULL,
		0x240545D5ED03034EULL,
		0xEFAE90106C7382C9ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x78A41562A2191E5DULL,
		0x1FE9C9B1DC9A61BCULL,
		0x76B3C57DC6DB648DULL,
		0x7868EA6C61627E2CULL,
		0xE9B163B8D2DA1C5EULL,
		0x1879412B079492BDULL,
		0x2EB99A6DAEDEE1E9ULL,
		0x5E6D40B2BDFA1453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E19B916DFE5CB0ULL,
		0x9DF1A93C425EC54AULL,
		0x5393D6C56A424AA0ULL,
		0x1D6D8C65F12804BCULL,
		0x6ECF35CC9FE992E2ULL,
		0x55755F130478068FULL,
		0x976667FC4B99AF7BULL,
		0xCFAE31A0BD9BE8ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56C279D1341AC1ADULL,
		0x81F820759A3B9C72ULL,
		0x231FEEB85C9919ECULL,
		0x5AFB5E06703A7970ULL,
		0x7AE22DEC32F0897CULL,
		0xC303E218031C8C2EULL,
		0x975332716345326DULL,
		0x8EBF0F12005E2B66ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC051B393F47C5416ULL,
		0x097719F4C0D8C5F7ULL,
		0x24033C2E0323FCEEULL,
		0x46F0EF74764BB29CULL,
		0x1C8B8F8FDFCB6773ULL,
		0x808C725A49A73AE4ULL,
		0xB13E88F90A80436BULL,
		0x9CA6EEDCE742BC4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB82E6760FE86EECULL,
		0xD10E5CCE89904B73ULL,
		0xF12F25A557595185ULL,
		0x8FFCCB0D41BB37B4ULL,
		0xCB9F9F5ED931585AULL,
		0x67BA66CF35F26DF0ULL,
		0x595751A60450201CULL,
		0xCA0475647D48D0F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14CECD1DE493E52AULL,
		0x3868BD2637487A84ULL,
		0x32D41688ABCAAB68ULL,
		0xB6F4246734907AE7ULL,
		0x50EBF031069A0F18ULL,
		0x18D20B8B13B4CCF3ULL,
		0x57E737530630234FULL,
		0xD2A2797869F9EB57ULL
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
		0xE55D25CAC9ADD15FULL,
		0x1AA820C989C5893FULL,
		0xBFC0A7C01C6ED7E9ULL,
		0xAC0C78DE6C650501ULL,
		0x51034E87683E79BCULL,
		0x90D2F016582D5AE7ULL,
		0xCBBCAA717F95BBB0ULL,
		0xBDE137730AC80086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB83BF03D463AA79ULL,
		0xF1D8C86312557399ULL,
		0x5123F9E0BF5C46B0ULL,
		0x98B8CA44411852FBULL,
		0x368876DD19BEC99DULL,
		0x4814CE730CD0F603ULL,
		0xDA6B846ADFA1C82AULL,
		0x7A95D601348A1DC4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19D966C6F54A26E6ULL,
		0x28CF5866777015A6ULL,
		0x6E9CADDF5D129138ULL,
		0x1353AE9A2B4CB206ULL,
		0x1A7AD7AA4E7FB01FULL,
		0x48BE21A34B5C64E4ULL,
		0xF15126069FF3F386ULL,
		0x434B6171D63DE2C1ULL
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
		0x4D77EFAEF64AAA2DULL,
		0x6EB058FE6DC7C8A1ULL,
		0x0CE53F787EE150C2ULL,
		0x7419511DA0F3E60AULL,
		0xFD1817719940E617ULL,
		0xBEEDB9427C0B742EULL,
		0xBC3616441F2A8B15ULL,
		0xD4E4D5BBC89822B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE707DABF13EE750ULL,
		0x332C38D588B3DD5BULL,
		0xD19F5BE02DB0B1C9ULL,
		0xAD4579A0BDEC0EF6ULL,
		0x435638F4DC065429ULL,
		0xC992803C905D3B36ULL,
		0x714676E4F1D71637ULL,
		0xB774A57B8B88A47BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F077203050BC2DDULL,
		0x3B842028E513EB45ULL,
		0x3B45E39851309EF9ULL,
		0xC6D3D77CE307D713ULL,
		0xB9C1DE7CBD3A91EDULL,
		0xF55B3905EBAE38F8ULL,
		0x4AEF9F5F2D5374DDULL,
		0x1D7030403D0F7E35ULL
	}};
	sign = 0;
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
		0x82AC54DFF62854BEULL,
		0xE43F0D0AEE72F8D3ULL,
		0x4179E4F129824E85ULL,
		0x33384B14BAFC5797ULL,
		0xF8D2D45D0FC17FF4ULL,
		0xF364A2BBB37670AFULL,
		0xFFBAD82D87D3C440ULL,
		0x2D9E3D8936214260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28228AC3BF49CD88ULL,
		0xE172CDA2A0B50AFCULL,
		0xDB1DED72F3057492ULL,
		0xC533BC29E5B372A7ULL,
		0x0FD5611BBAE587A1ULL,
		0x0602F898554A3E31ULL,
		0x816E5F18EAEECEA8ULL,
		0xCD024D840E4C18A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A89CA1C36DE8736ULL,
		0x02CC3F684DBDEDD7ULL,
		0x665BF77E367CD9F3ULL,
		0x6E048EEAD548E4EFULL,
		0xE8FD734154DBF852ULL,
		0xED61AA235E2C327EULL,
		0x7E4C79149CE4F598ULL,
		0x609BF00527D529BDULL
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
		0xD32B0FBA6D479A23ULL,
		0x6CF3F5239515D2C9ULL,
		0xC0AD4B01EE7F4199ULL,
		0xF2BCB1B1CE8A2F1DULL,
		0xD234F82106254A6EULL,
		0x25C733C93F674B39ULL,
		0x602487B89484696FULL,
		0xB0EA88FDB3442C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAA04DB9F476022AULL,
		0x38B4569AB7138031ULL,
		0x1E77D88A7CCB23F3ULL,
		0x6D86DE18A9F0F788ULL,
		0xC56C5362752A1ED5ULL,
		0x2D192222D5C1A791ULL,
		0xA9CB5E0E21D1BC5BULL,
		0x86AEED05592A6C82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD88AC20078D197F9ULL,
		0x343F9E88DE025297ULL,
		0xA235727771B41DA6ULL,
		0x8535D39924993795ULL,
		0x0CC8A4BE90FB2B99ULL,
		0xF8AE11A669A5A3A8ULL,
		0xB65929AA72B2AD13ULL,
		0x2A3B9BF85A19BFE7ULL
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
		0x595605A4119C2D3BULL,
		0xA990D91C96422C6AULL,
		0x37DF84C8BBDF9720ULL,
		0x871DF00F7216426EULL,
		0xD6EE38C66D84B94AULL,
		0xFF6871B9FE9E41A0ULL,
		0x41689EA891991267ULL,
		0x909ACF8FDD2826A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD6B74DC9E33C51CULL,
		0x8818E99C49ADD073ULL,
		0xA0945450C4BA1BC9ULL,
		0xC44AA398DEDDD523ULL,
		0xF50064C0EC9CFBF4ULL,
		0x22637AB8B563AFBCULL,
		0x5894705A72404B20ULL,
		0x57182D1271970AEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABEA90C77368681FULL,
		0x2177EF804C945BF6ULL,
		0x974B3077F7257B57ULL,
		0xC2D34C7693386D4AULL,
		0xE1EDD40580E7BD55ULL,
		0xDD04F701493A91E3ULL,
		0xE8D42E4E1F58C747ULL,
		0x3982A27D6B911BBBULL
	}};
	sign = 0;
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
		0x7E57F750E1C49434ULL,
		0xA439047DF79D603BULL,
		0xB488384D297A18A4ULL,
		0x2BF5AFDB65FFB2EEULL,
		0x8531F5C26AF3B62BULL,
		0x0118956984F4D6F6ULL,
		0xF9C0713A4F99D21FULL,
		0x820733F512AC04D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD633BBADCCD9D5B4ULL,
		0xA47EC099E927A3CDULL,
		0x5D88B55C7C864A24ULL,
		0x893B85A673A8DE25ULL,
		0x282AE0E79AE39522ULL,
		0x0698200566D6FE2FULL,
		0xD299A0D2EAE64EC0ULL,
		0xE72027D54F4FB7E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8243BA314EABE80ULL,
		0xFFBA43E40E75BC6DULL,
		0x56FF82F0ACF3CE7FULL,
		0xA2BA2A34F256D4C9ULL,
		0x5D0714DAD0102108ULL,
		0xFA8075641E1DD8C7ULL,
		0x2726D06764B3835EULL,
		0x9AE70C1FC35C4CF6ULL
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
		0x4470E146E22E530FULL,
		0xBF03F06C0019DE72ULL,
		0x0BC565DA5C8AEF49ULL,
		0x07EDC4BF902004ABULL,
		0x4DE0CA821FEF5412ULL,
		0x9002ADDB65B3C965ULL,
		0xB09D337756AD2C89ULL,
		0x08964B5BE3D408E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94416194725E0136ULL,
		0x0F0F303024748BD9ULL,
		0x413D294955F9C967ULL,
		0x7BC26A2D692CA9B4ULL,
		0x84E790AF13C5F3FBULL,
		0x1EC4A58DC9C1ABE5ULL,
		0x950D972760A99669ULL,
		0x54CF2E9F0E2A420AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB02F7FB26FD051D9ULL,
		0xAFF4C03BDBA55298ULL,
		0xCA883C91069125E2ULL,
		0x8C2B5A9226F35AF6ULL,
		0xC8F939D30C296016ULL,
		0x713E084D9BF21D7FULL,
		0x1B8F9C4FF6039620ULL,
		0xB3C71CBCD5A9C6DFULL
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
		0x744C3C9C67B4C99DULL,
		0x074F98AEC736EDCAULL,
		0xCD33F97AAAACB427ULL,
		0xF93AA73B7D8FAF07ULL,
		0xC945DBD5DD5DB349ULL,
		0xE2550DF20F4AE3BDULL,
		0x43A1218A947AE2AEULL,
		0x71A17B63D9908774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50EEE18B2E2E7588ULL,
		0x93F8DBA8EA4E5E87ULL,
		0x670A8D23E5FE7F85ULL,
		0x3F98A200234F84C9ULL,
		0x40B25C6ECE9329EFULL,
		0x0ED2B22957396DF2ULL,
		0x6C7A185EE459725CULL,
		0xDD8C45146F32D1A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235D5B1139865415ULL,
		0x7356BD05DCE88F43ULL,
		0x66296C56C4AE34A1ULL,
		0xB9A2053B5A402A3EULL,
		0x88937F670ECA895AULL,
		0xD3825BC8B81175CBULL,
		0xD727092BB0217052ULL,
		0x9415364F6A5DB5CEULL
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
		0x64075CFAC0AA2688ULL,
		0x6786F465E9C576E0ULL,
		0x432300CCF27E1F4BULL,
		0x945609ADB7E39384ULL,
		0x46FA6D95FB2EC748ULL,
		0x8D247DAFDCD989FAULL,
		0x16BD2F62BD657967ULL,
		0x578196561C3ED2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62F61D888A4961E1ULL,
		0x35A4024EF3D126B0ULL,
		0xC67166A77863E1D0ULL,
		0x1B6301EF392A1A55ULL,
		0xDDA7A2467C462626ULL,
		0x93EE37687F5C84B5ULL,
		0x8D98D9D9ED795010ULL,
		0xB63B7CD6C5D570F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01113F723660C4A7ULL,
		0x31E2F216F5F45030ULL,
		0x7CB19A257A1A3D7BULL,
		0x78F307BE7EB9792EULL,
		0x6952CB4F7EE8A122ULL,
		0xF93646475D7D0544ULL,
		0x89245588CFEC2956ULL,
		0xA146197F566961D3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCEF5B7ACED6E9D7DULL,
		0x56235BB3ACADE078ULL,
		0x0C2DA15A6E4EFBAFULL,
		0x188B7BAC1F928E5FULL,
		0x325DEC9274A9DC71ULL,
		0x7652060245D6DC65ULL,
		0x8A49D9E271000AFFULL,
		0x026FDB365CCA81E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF73E9937EA72233ULL,
		0x2F53CD091B2D0C22ULL,
		0xA04B884389AD9CA1ULL,
		0xAF3F1669BD063F93ULL,
		0x50AEDFC2DC081B28ULL,
		0x194866F45E32DED7ULL,
		0x2B45C92701485858ULL,
		0x5DF995BA4BEABCC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCF81CE196EC77B4AULL,
		0x26CF8EAA9180D455ULL,
		0x6BE21916E4A15F0EULL,
		0x694C6542628C4ECBULL,
		0xE1AF0CCF98A1C148ULL,
		0x5D099F0DE7A3FD8DULL,
		0x5F0410BB6FB7B2A7ULL,
		0xA476457C10DFC524ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8FC74FDDBEE88B5DULL,
		0xB555EA2A6C7A0B48ULL,
		0x7B8C7736A00B71C0ULL,
		0x20C5076F631A47EAULL,
		0x5909C7045E053509ULL,
		0x2F8390E2E1161589ULL,
		0x5B527051E10330F8ULL,
		0xBFD000483F3D0DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x760CC66BD773D2FDULL,
		0x35D882A3DC8CAADEULL,
		0xBD4E335548DA2169ULL,
		0xC0A14497B3329B9BULL,
		0xFB1220B5F734EA18ULL,
		0x04A07F05730FFF4DULL,
		0x83E335A0A8197EB8ULL,
		0x9E4E3F44099F3B47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19BA8971E774B860ULL,
		0x7F7D67868FED606AULL,
		0xBE3E43E157315057ULL,
		0x6023C2D7AFE7AC4EULL,
		0x5DF7A64E66D04AF0ULL,
		0x2AE311DD6E06163BULL,
		0xD76F3AB138E9B240ULL,
		0x2181C104359DD28AULL
	}};
	sign = 0;
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
		0xB15476A056751FC3ULL,
		0x76A8F1E7333FE75BULL,
		0xBCEDDBEA678C4223ULL,
		0xE9187E765C982CE9ULL,
		0x418CDD2F1F98EE40ULL,
		0xA81C427D9D306C56ULL,
		0xAE28F587A40C92E1ULL,
		0x03AB633CDA243EB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60402FA7AF112B82ULL,
		0xF0BEE66438431CDBULL,
		0x5FA026E79275E139ULL,
		0xC14767AB8FF47EFEULL,
		0x6ED62AAE41B14237ULL,
		0x90BE388E0966BA64ULL,
		0xDD89994D074D5DA1ULL,
		0x1B887849EB857F5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x511446F8A763F441ULL,
		0x85EA0B82FAFCCA80ULL,
		0x5D4DB502D51660E9ULL,
		0x27D116CACCA3ADEBULL,
		0xD2B6B280DDE7AC09ULL,
		0x175E09EF93C9B1F1ULL,
		0xD09F5C3A9CBF3540ULL,
		0xE822EAF2EE9EBF5DULL
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
		0x1333DC3317F9527EULL,
		0xAFC74A15AADF93D4ULL,
		0xFDD2E067C6118758ULL,
		0x82E68D43B86E32CFULL,
		0x3839928124B87433ULL,
		0x122885357FB2CB26ULL,
		0x33FDD72DA3F0B436ULL,
		0x66A4070C86E405ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x023C6E432E976423ULL,
		0x75E4C5BC7F9F04FEULL,
		0xCCF9F6C5F803C4A8ULL,
		0xCCBF3E32BF75B501ULL,
		0x2626B28FF27643ADULL,
		0xDF1322ED45C27301ULL,
		0xB00D092AAB3E254AULL,
		0xF77CB2456B8B7A31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10F76DEFE961EE5BULL,
		0x39E284592B408ED6ULL,
		0x30D8E9A1CE0DC2B0ULL,
		0xB6274F10F8F87DCEULL,
		0x1212DFF132423085ULL,
		0x3315624839F05825ULL,
		0x83F0CE02F8B28EEBULL,
		0x6F2754C71B588B7AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA3457422A7ED15FBULL,
		0x8950A86D7DED240AULL,
		0x4D60936E9FE8A4B4ULL,
		0x93CB581374665A67ULL,
		0xD7AE26E9B6302D04ULL,
		0x786EFCC3BB3DE6FEULL,
		0x4FCAEF17279F7274ULL,
		0x94C4BB1C8799275CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C6CB00E08E29C09ULL,
		0x2FC4D636FDE2A0EEULL,
		0x1F1EEAB62C92D3B6ULL,
		0x83DD6E189B525EE1ULL,
		0xC20B4A5914F7EA2BULL,
		0xBF56B11212880D14ULL,
		0x749C748E7E11A465ULL,
		0xCE1950BB39ACF159ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06D8C4149F0A79F2ULL,
		0x598BD236800A831CULL,
		0x2E41A8B87355D0FEULL,
		0x0FEDE9FAD913FB86ULL,
		0x15A2DC90A13842D9ULL,
		0xB9184BB1A8B5D9EAULL,
		0xDB2E7A88A98DCE0EULL,
		0xC6AB6A614DEC3602ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x468167FDA3E05456ULL,
		0x221C5B90502066E0ULL,
		0x2134AB5410B110C2ULL,
		0x57AC550E58D80B89ULL,
		0x8F29B2465C86EC63ULL,
		0xD83AC7C64818BC27ULL,
		0x70073E656F19F845ULL,
		0xEE6E5CE320F0ECDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x294B154F9980B768ULL,
		0x1F59A83412EE21C1ULL,
		0x579142373D4AE33AULL,
		0xE3AE113920B00FF1ULL,
		0x47E80EE6AAA8ECC1ULL,
		0x8FCA01A356D64CA6ULL,
		0x8E55D68C0AB3D691ULL,
		0x76519336DD3DB017ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D3652AE0A5F9CEEULL,
		0x02C2B35C3D32451FULL,
		0xC9A3691CD3662D88ULL,
		0x73FE43D53827FB97ULL,
		0x4741A35FB1DDFFA1ULL,
		0x4870C622F1426F81ULL,
		0xE1B167D9646621B4ULL,
		0x781CC9AC43B33CC7ULL
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
		0xB4F9066B13247583ULL,
		0xF4E6C6BAA7348898ULL,
		0x01636420C5E9E44EULL,
		0xFB3C93E44FD899B3ULL,
		0xA0E1954DA359B30DULL,
		0x33FC8AC4C18F9E2DULL,
		0x799A0C6852E6FDD0ULL,
		0xBECE5546973D7BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD74335390774B25ULL,
		0xBE9AC75093477726ULL,
		0x99C9CFF9647DAF07ULL,
		0x10FEEAC021A026D0ULL,
		0xAC80CC19E19CC4B8ULL,
		0x276C72999955F389ULL,
		0x1DD42D50614B8438ULL,
		0x3EBB7F17D24BD817ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF784D31782AD2A5EULL,
		0x364BFF6A13ED1171ULL,
		0x67999427616C3547ULL,
		0xEA3DA9242E3872E2ULL,
		0xF460C933C1BCEE55ULL,
		0x0C90182B2839AAA3ULL,
		0x5BC5DF17F19B7998ULL,
		0x8012D62EC4F1A3A6ULL
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
		0xDA94D0CBE97BD4F4ULL,
		0xB14363514806A731ULL,
		0x2F1C0954878C419FULL,
		0xCC845317B9BFDA91ULL,
		0x44300F97B90D9F30ULL,
		0x372BADD039FE8CB0ULL,
		0xE36CBEC0E6337581ULL,
		0x70071236B9DFC425ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x713749992319CA4EULL,
		0xE9067F868AF2A465ULL,
		0xD84A61E8DCB4D4C5ULL,
		0x562D932B2DCD9A88ULL,
		0x686C7A2EAEC71973ULL,
		0x7DBB8A505FCE1B8CULL,
		0x3F9C563D5E6E9E9BULL,
		0x22931B6C4D3FDC4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x695D8732C6620AA6ULL,
		0xC83CE3CABD1402CCULL,
		0x56D1A76BAAD76CD9ULL,
		0x7656BFEC8BF24008ULL,
		0xDBC395690A4685BDULL,
		0xB970237FDA307123ULL,
		0xA3D0688387C4D6E5ULL,
		0x4D73F6CA6C9FE7D9ULL
	}};
	sign = 0;
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
		0x1CA5F24E27CF3300ULL,
		0x0EE3511BD650FF66ULL,
		0xFD7E6D330BCD20E8ULL,
		0xD47C1943C5759AA9ULL,
		0x1FCF94BDC512232FULL,
		0x072E7A9BA10A3383ULL,
		0x78236E25EF75FBC5ULL,
		0xE363BFCDA336FF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC03F3990E521074ULL,
		0x51DA350A44D13C24ULL,
		0x96374303BE5CD91EULL,
		0xDF92FD86F70E00E4ULL,
		0x18DCACCC60B1DDC0ULL,
		0x2DA4AC13AE9091C1ULL,
		0xEDFE796E10068251ULL,
		0xDA80C570099EBF9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70A1FEB5197D228CULL,
		0xBD091C11917FC341ULL,
		0x67472A2F4D7047C9ULL,
		0xF4E91BBCCE6799C5ULL,
		0x06F2E7F16460456EULL,
		0xD989CE87F279A1C2ULL,
		0x8A24F4B7DF6F7973ULL,
		0x08E2FA5D99983F9DULL
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
		0xA8BAF9E9048C5086ULL,
		0x9F5FDCD84994DD92ULL,
		0x9ADCECD874A25BC4ULL,
		0xE9CB2A77CB71568EULL,
		0x041FA80966CA92D5ULL,
		0x3AC4A9D04EF9E329ULL,
		0x5EAA0ABC8DBEE671ULL,
		0x4FA729863F848337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0CFDBEBD4DEBE70ULL,
		0x0DEC21E7A6BA8FECULL,
		0x3D858BAD9B80C240ULL,
		0x57BFAD023B534EB2ULL,
		0x48130F48FFF916AEULL,
		0xED81191E23929F2BULL,
		0x1912993617039E49ULL,
		0xEDEE140248E5E26BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7EB1DFD2FAD9216ULL,
		0x9173BAF0A2DA4DA5ULL,
		0x5D57612AD9219984ULL,
		0x920B7D75901E07DCULL,
		0xBC0C98C066D17C27ULL,
		0x4D4390B22B6743FDULL,
		0x4597718676BB4827ULL,
		0x61B91583F69EA0CCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x500A00F2CB8FDF07ULL,
		0x7411DC6D822BBE6EULL,
		0x41619B1F505F399FULL,
		0x4B49C3CCC0E0CC6CULL,
		0xBF36225F9D0CB785ULL,
		0xA507D1914EB1E986ULL,
		0x700DE65B97F19303ULL,
		0x381B2E56D81BCD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7765BDEB067C5143ULL,
		0xFD640426D13FD452ULL,
		0x98ABB63FCCF215E8ULL,
		0x27E88E4BCDDF971CULL,
		0x9A4823385514B954ULL,
		0xF41E70143EB1B569ULL,
		0xEC3C802D50AFC6E2ULL,
		0x46227CB4692E76EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD8A44307C5138DC4ULL,
		0x76ADD846B0EBEA1BULL,
		0xA8B5E4DF836D23B6ULL,
		0x23613580F301354FULL,
		0x24EDFF2747F7FE31ULL,
		0xB0E9617D1000341DULL,
		0x83D1662E4741CC20ULL,
		0xF1F8B1A26EED561CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7227539594994B77ULL,
		0x229FAC9D85BDF1BFULL,
		0x9A5431FAA55EEB70ULL,
		0xFDF1A74BAFE11A3DULL,
		0x586B463F2663C9D1ULL,
		0xBEA2A0411721DFDBULL,
		0x411E3CCCBE07D9FBULL,
		0xC7E8993F03272F43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CF6986F3BA710B5ULL,
		0x1FCC62FF1DC0EC74ULL,
		0x686C6F16B29BC09AULL,
		0xE853B365858E7E69ULL,
		0x6353493EEECDEF19ULL,
		0xBD3246BC2A304616ULL,
		0x5A26E7BD3B8218DFULL,
		0x3569BEF48864EC1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6530BB2658F23AC2ULL,
		0x02D3499E67FD054BULL,
		0x31E7C2E3F2C32AD6ULL,
		0x159DF3E62A529BD4ULL,
		0xF517FD003795DAB8ULL,
		0x01705984ECF199C4ULL,
		0xE6F7550F8285C11CULL,
		0x927EDA4A7AC24323ULL
	}};
	sign = 0;
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
		0x8A1A5FCFE0748C26ULL,
		0xD2ACC95E19CA7AC0ULL,
		0x1E60F1BF3E2A5A9DULL,
		0x84224C72D1150723ULL,
		0x5C7B3838A49A6326ULL,
		0xB0AF52C8B6C12079ULL,
		0x58D0FF19EF3D9259ULL,
		0xD18D7B337B445783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE28DB0EE44C3C4DULL,
		0x07F8ABC4EB7F33ACULL,
		0xE08A69CCE83903CDULL,
		0xF5B96E04953E0889ULL,
		0xF7DD089353C5DB1FULL,
		0x95CC7CC2867E5FFCULL,
		0x23E48E1E9EE51B84ULL,
		0x2AFCEE66F16BE9B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF184C0FC284FD9ULL,
		0xCAB41D992E4B4713ULL,
		0x3DD687F255F156D0ULL,
		0x8E68DE6E3BD6FE99ULL,
		0x649E2FA550D48806ULL,
		0x1AE2D6063042C07CULL,
		0x34EC70FB505876D5ULL,
		0xA6908CCC89D86DCEULL
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
		0xDE4B35E2078CA45FULL,
		0xF4E8DC99B52DA496ULL,
		0xC388B1DB43F74E7BULL,
		0x67BD5C5779CC5A02ULL,
		0x2A3838F350E0F8B7ULL,
		0x59CAD3607E145F6BULL,
		0x76A7F27F7E0B38DFULL,
		0x2736A9D4D6D6BDECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x492903B78B16243AULL,
		0x6B9BC95DF8C74342ULL,
		0x1E7282BD5CEF2B69ULL,
		0xF383A3829C3C19BFULL,
		0xE5BB8DA673D8BA2BULL,
		0x0C1A1D37773C9725ULL,
		0xBE0C238BD00B05EAULL,
		0x5F302CB4474FFC7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9522322A7C768025ULL,
		0x894D133BBC666154ULL,
		0xA5162F1DE7082312ULL,
		0x7439B8D4DD904043ULL,
		0x447CAB4CDD083E8BULL,
		0x4DB0B62906D7C845ULL,
		0xB89BCEF3AE0032F5ULL,
		0xC8067D208F86C170ULL
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
		0x46D2A3C2661FBB23ULL,
		0xD2BC54251A0182EBULL,
		0x996655DA4BDFAB9BULL,
		0x8CFC074C01BB84DAULL,
		0x65C0E9F707AE1E24ULL,
		0xB49C6F83C59C49AAULL,
		0xD5C1BADB2BDF661BULL,
		0xF56DE5B171BFF3A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24974E439AFC2055ULL,
		0x9C396CAD57FB3E75ULL,
		0xC09C540227B0202EULL,
		0x5E9158D0F817366FULL,
		0x4E419CA83635F4C0ULL,
		0xD48C69E89E446B89ULL,
		0xCA736F553919C0C3ULL,
		0xA164A15867FB641DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x223B557ECB239ACEULL,
		0x3682E777C2064476ULL,
		0xD8CA01D8242F8B6DULL,
		0x2E6AAE7B09A44E6AULL,
		0x177F4D4ED1782964ULL,
		0xE010059B2757DE21ULL,
		0x0B4E4B85F2C5A557ULL,
		0x5409445909C48F85ULL
	}};
	sign = 0;
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
		0x3DD5257A265D4B47ULL,
		0xEEEED8B242D10231ULL,
		0xA03336B41AE0F0A5ULL,
		0x74D74B87A91E1121ULL,
		0x915577D3A0D43699ULL,
		0x8A167736734A54D7ULL,
		0xB1AF48249D576FADULL,
		0x35337F7F7B954CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D701EAD793A0EBULL,
		0x931302D9162168E4ULL,
		0x9EA09B3023897645ULL,
		0x80EA053841D67F53ULL,
		0xB9BBED256D71635CULL,
		0xA869534A06F83DC2ULL,
		0x6C8ABDFE8866FFC7ULL,
		0xAC227E99C72A420AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05FE238F4EC9AA5CULL,
		0x5BDBD5D92CAF994DULL,
		0x01929B83F7577A60ULL,
		0xF3ED464F674791CEULL,
		0xD7998AAE3362D33CULL,
		0xE1AD23EC6C521714ULL,
		0x45248A2614F06FE5ULL,
		0x891100E5B46B0AD5ULL
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
		0x4B9602DE455DBC16ULL,
		0x33D1C3DA4CE320E2ULL,
		0x3B11B1940D1B8C1EULL,
		0x5407EEA050CD9181ULL,
		0x06DE72A870CD6F23ULL,
		0xD535B85656EF5DAFULL,
		0x0865F9DFE57E476BULL,
		0x1602945CCD4BBE7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98208DAD8379842CULL,
		0x6879D5AC70ADA092ULL,
		0xF0C282E39B650A54ULL,
		0x5058D44B5BBC5298ULL,
		0x64BD4444DFAC7613ULL,
		0xC07A18165FE76A70ULL,
		0xB4E272B004CC129EULL,
		0x8C86FE386E8295A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB3757530C1E437EAULL,
		0xCB57EE2DDC35804FULL,
		0x4A4F2EB071B681C9ULL,
		0x03AF1A54F5113EE8ULL,
		0xA2212E639120F910ULL,
		0x14BBA03FF707F33EULL,
		0x5383872FE0B234CDULL,
		0x897B96245EC928D4ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x97C6A5C103131CF4ULL,
		0xDDC2C5919F85CDA1ULL,
		0x42F08A676240042AULL,
		0x8D526090E6DA02B8ULL,
		0x0507749F6EC72DBDULL,
		0x662A7EADA69171EDULL,
		0xD5935AC77691D004ULL,
		0x3F17CD025A44CFDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD6B9F945ED569A3ULL,
		0x86311F16389C4AC0ULL,
		0xA8510B3BBE94B245ULL,
		0x4CAE2739EC4E3196ULL,
		0x4B9BFF7ABA95FE3BULL,
		0x29ADA9A2A39B4C24ULL,
		0x3A55A8D81BD8C36DULL,
		0x9B7AEBD6CF1978D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEA5B062CA43DB351ULL,
		0x5791A67B66E982E0ULL,
		0x9A9F7F2BA3AB51E5ULL,
		0x40A43956FA8BD121ULL,
		0xB96B7524B4312F82ULL,
		0x3C7CD50B02F625C8ULL,
		0x9B3DB1EF5AB90C97ULL,
		0xA39CE12B8B2B5705ULL
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
		0xEB03B426FDCF9289ULL,
		0xB8825F8CA8A96D3DULL,
		0x41F40220DF222AE4ULL,
		0xC8C54DF3CC00B849ULL,
		0x66F54C2F5940E2D7ULL,
		0x7A152BE9E98A6A92ULL,
		0x3A1289E36E49CF5EULL,
		0x723D1C6DBFB671B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FBB5FC5BE1C44EULL,
		0xE72D437D9CA0982FULL,
		0x509E3D1DEFE629A9ULL,
		0x5D491226E6CEB3AAULL,
		0x5166707C7B4CA842ULL,
		0x4CB5B451E2A2A72AULL,
		0xC9F645C485B121E9ULL,
		0xD4EAFE7C1C3017EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0907FE2AA1EDCE3BULL,
		0xD1551C0F0C08D50EULL,
		0xF155C502EF3C013AULL,
		0x6B7C3BCCE532049EULL,
		0x158EDBB2DDF43A95ULL,
		0x2D5F779806E7C368ULL,
		0x701C441EE898AD75ULL,
		0x9D521DF1A38659C7ULL
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
		0xEE8769851AC0985EULL,
		0x1058EA8049E8CF87ULL,
		0x381D88338E66998DULL,
		0x8449D017EBC8295CULL,
		0x14D123632EDD8B8EULL,
		0x7475B33A50A6E113ULL,
		0x1F843FE16C7791EDULL,
		0xFAF418F19026A646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x117CDC6468961540ULL,
		0xE74994DB6E5ADF1BULL,
		0x2EE7DF9E0795C540ULL,
		0x159E7D80E75E4CAAULL,
		0x95632A16F685BD0DULL,
		0x3C20C67995F8CB16ULL,
		0x62CE183B57C7812DULL,
		0x5848D0622760F4FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0A8D20B22A831EULL,
		0x290F55A4DB8DF06CULL,
		0x0935A89586D0D44CULL,
		0x6EAB52970469DCB2ULL,
		0x7F6DF94C3857CE81ULL,
		0x3854ECC0BAAE15FCULL,
		0xBCB627A614B010C0ULL,
		0xA2AB488F68C5B146ULL
	}};
	sign = 0;
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
		0xDB40AB4257BC49EFULL,
		0x96086FDBD857F1ABULL,
		0x8CCD434E1ADAE0AEULL,
		0x5F2E8291DD8C2193ULL,
		0x683B4E12FCD256F0ULL,
		0x541ED50DB37870B5ULL,
		0xC1072B3206D7AFB3ULL,
		0x1BA1BF4FF92F0B3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40B150973AD75E75ULL,
		0x32F1D62255F12B1AULL,
		0x014ECEFFEE4F9E8DULL,
		0x114A5C0D04B600B9ULL,
		0x59044F17CE8F0FA1ULL,
		0x97EF2B7A7937D967ULL,
		0xD620CE652E3C580CULL,
		0x1112AE7C415AA1F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A8F5AAB1CE4EB7AULL,
		0x631699B98266C691ULL,
		0x8B7E744E2C8B4221ULL,
		0x4DE42684D8D620DAULL,
		0x0F36FEFB2E43474FULL,
		0xBC2FA9933A40974EULL,
		0xEAE65CCCD89B57A6ULL,
		0x0A8F10D3B7D4694AULL
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
		0xEE9110FB6A08037EULL,
		0x31AFC2A068D333E6ULL,
		0xD9FA49378CBE9EDAULL,
		0x9D58A090FD91E871ULL,
		0x286ACBA02B794A25ULL,
		0xAC58664FD6AF078EULL,
		0xD5464C45272AF2A8ULL,
		0x1BA2FAAB715C4758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84A75E2E1754BA44ULL,
		0x45104A4E1C129888ULL,
		0x374BBF37176A79DDULL,
		0x053735DC3EA16A13ULL,
		0x3E46B3BF25FE8FB5ULL,
		0x5661C9A4E3568A55ULL,
		0x77407990CD7EF221ULL,
		0x22D857908B236F21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69E9B2CD52B3493AULL,
		0xEC9F78524CC09B5EULL,
		0xA2AE8A00755424FCULL,
		0x98216AB4BEF07E5EULL,
		0xEA2417E1057ABA70ULL,
		0x55F69CAAF3587D38ULL,
		0x5E05D2B459AC0087ULL,
		0xF8CAA31AE638D837ULL
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
		0x4AA523A62AA9D431ULL,
		0x9866EF1B40D9C4D2ULL,
		0x99FEAFF283C3A6F1ULL,
		0xDDEB89C3B4A1195CULL,
		0x0C859C50EF845914ULL,
		0xEF2497DCD0B5B1C6ULL,
		0x62FCBEA7F7E290A9ULL,
		0xE283BB983337BBA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE29F1BA5CC7E73A6ULL,
		0x9F1989EE95799E9FULL,
		0x7A3E9DC0D64FE78CULL,
		0x0FD2269D8D21FA61ULL,
		0x0B58E25C6860BC4EULL,
		0xCC44E0BDBAB306B1ULL,
		0xDA9F3D91A09CA74CULL,
		0xF7C6366CF18F9668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x680608005E2B608BULL,
		0xF94D652CAB602632ULL,
		0x1FC01231AD73BF64ULL,
		0xCE196326277F1EFBULL,
		0x012CB9F487239CC6ULL,
		0x22DFB71F1602AB15ULL,
		0x885D81165745E95DULL,
		0xEABD852B41A82539ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9B73BCD0EEBF9B15ULL,
		0xB5D655600CC32B83ULL,
		0xE0D126C96C296045ULL,
		0x9EB6DB6DB01100E4ULL,
		0xB6A0A5623C7E7905ULL,
		0xAD6ECB802481C51CULL,
		0x27DEE54A485F4E95ULL,
		0xEE82DB94714A674DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3934B7D307B14893ULL,
		0x0D7362C0B80B03CBULL,
		0x1CD410FAD462066FULL,
		0xEBD2E374F22E5509ULL,
		0x940CA92CBEDDD865ULL,
		0x580A7BBAB8EBAB0BULL,
		0xB1C02B6D50CB2E6BULL,
		0xAD948ED925B4927AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x623F04FDE70E5282ULL,
		0xA862F29F54B827B8ULL,
		0xC3FD15CE97C759D6ULL,
		0xB2E3F7F8BDE2ABDBULL,
		0x2293FC357DA0A09FULL,
		0x55644FC56B961A11ULL,
		0x761EB9DCF794202AULL,
		0x40EE4CBB4B95D4D2ULL
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
		0x4F3362C68DE95238ULL,
		0x909470DC653FFB75ULL,
		0xE334169E6AEF9073ULL,
		0xC6CC9F0205574D03ULL,
		0xDCE1656DDF9CD1D8ULL,
		0x1E5A6163D83A2B69ULL,
		0xF8AE8032ECE4E73AULL,
		0x01950F5BC0BC5E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9EB3F08994912D6ULL,
		0xF56B25F2A7C37235ULL,
		0x349F0ADF695A4E1DULL,
		0xDCBA52A6E4DE3E9FULL,
		0x41706589204355B0ULL,
		0x6349794D7BA4F756ULL,
		0xDB2CEDF1701979A8ULL,
		0x7030D1134299099AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x854823BDF4A03F62ULL,
		0x9B294AE9BD7C893FULL,
		0xAE950BBF01954255ULL,
		0xEA124C5B20790E64ULL,
		0x9B70FFE4BF597C27ULL,
		0xBB10E8165C953413ULL,
		0x1D8192417CCB6D91ULL,
		0x91643E487E235505ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCE35E3E626F89074ULL,
		0xA3D8EB384F1BA4F6ULL,
		0xC7DC204EACB75AE2ULL,
		0x6D8988F2BDA33EADULL,
		0x793A0807D40F6DD0ULL,
		0xF123DAD89BB47C47ULL,
		0x2F30CC904DFBD820ULL,
		0xD18B888BF8F831CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x758EB39B6BEEA83FULL,
		0xA7BF898AB2941146ULL,
		0x1EE819965E49E165ULL,
		0x140C8E7EB3C16813ULL,
		0xBF7DB628CD4E6CDAULL,
		0x8F0A4CEE52C37E19ULL,
		0x4BFDEB8D286266BAULL,
		0xE014C31CC76DB69DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58A7304ABB09E835ULL,
		0xFC1961AD9C8793B0ULL,
		0xA8F406B84E6D797CULL,
		0x597CFA7409E1D69AULL,
		0xB9BC51DF06C100F6ULL,
		0x62198DEA48F0FE2DULL,
		0xE332E10325997166ULL,
		0xF176C56F318A7B2CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x50F925AEC007483FULL,
		0x484D86B8486090A5ULL,
		0x810EC6E29C31C12DULL,
		0x0360042A8BF0A6D5ULL,
		0x9F67AB9929EE46DAULL,
		0x449247A837A591CDULL,
		0x66101BBC3AB7C1E1ULL,
		0xFE9FBFCB2694139EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB89A235E4B76B9AULL,
		0x3D4D2D083D403B95ULL,
		0x4CD7C50ED39EE955ULL,
		0x84F094A9185E9685ULL,
		0x4BFFE26C220E0260ULL,
		0xD11733AF43EFBC91ULL,
		0x09E90DBBB0A944A9ULL,
		0x7FD49F2484FC4295ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x756F8378DB4FDCA5ULL,
		0x0B0059B00B20550FULL,
		0x343701D3C892D7D8ULL,
		0x7E6F6F8173921050ULL,
		0x5367C92D07E04479ULL,
		0x737B13F8F3B5D53CULL,
		0x5C270E008A0E7D37ULL,
		0x7ECB20A6A197D109ULL
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
		0x53026B82096F0870ULL,
		0xA179A8E38132951FULL,
		0x186A80D0CE89F94DULL,
		0x4E415C69169971E6ULL,
		0x532BEC8C33FE71D8ULL,
		0xE54F5417C01E2242ULL,
		0xA30DF3E99C932B55ULL,
		0x15D62ACAC478DDB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D695B544AB5C63ULL,
		0xA76DCCD6B2BFE1D0ULL,
		0x2DC348A5CE089646ULL,
		0xBF816E424DC8CAC2ULL,
		0x170E8CBE0CD780F7ULL,
		0x85962C22DADCD209ULL,
		0x8330D05E860B3CCBULL,
		0x05A5231AD4EB9D71ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA12BD5CCC4C3AC0DULL,
		0xFA0BDC0CCE72B34EULL,
		0xEAA7382B00816306ULL,
		0x8EBFEE26C8D0A723ULL,
		0x3C1D5FCE2726F0E0ULL,
		0x5FB927F4E5415039ULL,
		0x1FDD238B1687EE8AULL,
		0x103107AFEF8D4048ULL
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
		0xD83C5521FA28F822ULL,
		0xD7A18259B0E51EF6ULL,
		0x398750E057FC792EULL,
		0x2D70F816FF0359F3ULL,
		0xAFE2989FD6D20340ULL,
		0x28DE1DE46BEE9200ULL,
		0x1979E38E9F11E336ULL,
		0x8655BB65DF83A218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835E94AAADC26A47ULL,
		0x583B66A04779A493ULL,
		0xC561DD343A3DF836ULL,
		0x276B9CE76164EA11ULL,
		0xF91F733EE038CAA5ULL,
		0xD7DC94322B6515B8ULL,
		0x66C3D8DBCC43117CULL,
		0x677D398BB06154D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54DDC0774C668DDBULL,
		0x7F661BB9696B7A63ULL,
		0x742573AC1DBE80F8ULL,
		0x06055B2F9D9E6FE1ULL,
		0xB6C32560F699389BULL,
		0x510189B240897C47ULL,
		0xB2B60AB2D2CED1B9ULL,
		0x1ED881DA2F224D44ULL
	}};
	sign = 0;
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
		0x1E9E09EF1DABECC6ULL,
		0x93FE757DEC13506CULL,
		0x293EB251F6E92A9AULL,
		0x493954E79AA5FFD4ULL,
		0xDAA118FBE9E3B91AULL,
		0x2C18313E2A6E389DULL,
		0x0B2CBEC0D5756C5CULL,
		0xB2A60E0A54D20794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DB14A71E8DA7F1FULL,
		0x35746E69193CC8CAULL,
		0xB436FDE6C5CB735AULL,
		0xFF0F41762357DEBBULL,
		0xCC9CCAD29753C4D2ULL,
		0x5E4AA232DDDFDA76ULL,
		0xEA1D8E5CDAFFEA50ULL,
		0xBD8FBD6654CD42B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0ECBF7D34D16DA7ULL,
		0x5E8A0714D2D687A1ULL,
		0x7507B46B311DB740ULL,
		0x4A2A1371774E2118ULL,
		0x0E044E29528FF447ULL,
		0xCDCD8F0B4C8E5E27ULL,
		0x210F3063FA75820BULL,
		0xF51650A40004C4DCULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7B22B4C486DE2351ULL,
		0x4A7B944EC4B48F86ULL,
		0x7ED4DDF32B04A8CEULL,
		0xC8953B227EB1BD68ULL,
		0x42D5253E88855689ULL,
		0xD8B1B912D0778A94ULL,
		0x66323FEB144B4D80ULL,
		0x9715FA2F087F4C13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20F42BDD7C5EE8BULL,
		0x14F70491752923E3ULL,
		0x774D2CF1C84FF9FAULL,
		0x8EF3C0AF1A6B5394ULL,
		0x68D8BA7D72688A07ULL,
		0x332A1CA5F4962E58ULL,
		0x4082625451FE5B9CULL,
		0xBA085BBC7CFD37A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9137206AF1834C6ULL,
		0x35848FBD4F8B6BA2ULL,
		0x0787B10162B4AED4ULL,
		0x39A17A73644669D4ULL,
		0xD9FC6AC1161CCC82ULL,
		0xA5879C6CDBE15C3BULL,
		0x25AFDD96C24CF1E4ULL,
		0xDD0D9E728B82146EULL
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
		0x86678E0C4B550CE1ULL,
		0x348C5236B2F42FCEULL,
		0xECB5635B57043F0DULL,
		0x4FC15BEDA39411ADULL,
		0x56215B13AB75D4FBULL,
		0x7F170A6C79F3F835ULL,
		0xD8734DF84E4F745CULL,
		0x46AABB74AFBFFD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F20A2E80921F2B5ULL,
		0x4A0EBC05724BE55FULL,
		0x6E0880744AB24D0DULL,
		0x121AA084793BB992ULL,
		0x979CF4EBA361F133ULL,
		0x6F82F70B7C800850ULL,
		0xAC50B28239ACB321ULL,
		0x84EDC6F30906453FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5746EB2442331A2CULL,
		0xEA7D963140A84A6FULL,
		0x7EACE2E70C51F1FFULL,
		0x3DA6BB692A58581BULL,
		0xBE8466280813E3C8ULL,
		0x0F941360FD73EFE4ULL,
		0x2C229B7614A2C13BULL,
		0xC1BCF481A6B9B80EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF76709D5B2A67998ULL,
		0x9D19A7E4EDA2AFEAULL,
		0xB377FC8E2B0E5E96ULL,
		0x84811BD1E6540B6EULL,
		0xC2C9F3CFF5AC3A29ULL,
		0xFEFD017B1751F6DCULL,
		0xE2470445591E8FF4ULL,
		0x0EB722644EDE4642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5FE726CA006A72CULL,
		0xA661C0D62D385AFFULL,
		0x057E22C449E14515ULL,
		0x6A6A9BEA48DAA9C6ULL,
		0x78359650B476C206ULL,
		0x6D41777EA282509DULL,
		0x9C89E8AEE6E12224ULL,
		0x35047F5C68BAD407ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11689769129FD26CULL,
		0xF6B7E70EC06A54EBULL,
		0xADF9D9C9E12D1980ULL,
		0x1A167FE79D7961A8ULL,
		0x4A945D7F41357823ULL,
		0x91BB89FC74CFA63FULL,
		0x45BD1B96723D6DD0ULL,
		0xD9B2A307E623723BULL
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
		0x235798A3D24C185FULL,
		0xBCBEDDB8F4056305ULL,
		0x9E489677ED78201EULL,
		0x9A4753D766F1CF6FULL,
		0x2D3CF29358D4CFB9ULL,
		0x0CCC7A2F00FB2794ULL,
		0x571FC27E3DF45070ULL,
		0x2AB6E8FA779BDF9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA73031B290B9988ULL,
		0x72FBCBBFE33E7D2FULL,
		0x159F0BB192551C0AULL,
		0x53354211A86726BBULL,
		0x413478B01AF97C4FULL,
		0xD8D566E9A50841CCULL,
		0x6234C708875D5E51ULL,
		0xF5AF6E1D0A7404CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48E49588A9407ED7ULL,
		0x49C311F910C6E5D5ULL,
		0x88A98AC65B230414ULL,
		0x471211C5BE8AA8B4ULL,
		0xEC0879E33DDB536AULL,
		0x33F713455BF2E5C7ULL,
		0xF4EAFB75B696F21EULL,
		0x35077ADD6D27DAD3ULL
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
		0xC5EB87D5E473CCEEULL,
		0xEBCD54B9EE258300ULL,
		0x8864DEB6D4DA846FULL,
		0xE2B07FA5CDB19C22ULL,
		0x1EA551E54B6C1F8DULL,
		0xD6FE7BD353E2B0EDULL,
		0x4419E57288A824C8ULL,
		0x56998CBF7F508319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DAEA6879A2B9C2EULL,
		0x84FE323848092C79ULL,
		0x7A64429CF7792742ULL,
		0x65C64FAA8AE2406CULL,
		0x49791BE59608AE14ULL,
		0x214DC6A4597631E6ULL,
		0x71425D73278FD630ULL,
		0x34AC6E6CFB5C7300ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x683CE14E4A4830C0ULL,
		0x66CF2281A61C5687ULL,
		0x0E009C19DD615D2DULL,
		0x7CEA2FFB42CF5BB6ULL,
		0xD52C35FFB5637179ULL,
		0xB5B0B52EFA6C7F06ULL,
		0xD2D787FF61184E98ULL,
		0x21ED1E5283F41018ULL
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
		0xD777A76971939A70ULL,
		0xDA0093F2B9266F3DULL,
		0x7ADD526BCB7A2BBCULL,
		0x2A5EDA46138B341BULL,
		0x28706F11242513A4ULL,
		0x91B9DCBC1E521C76ULL,
		0xD24C20C1B6AD2DEBULL,
		0xB1129B1F1E7B7EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C067F94C4F12578ULL,
		0x3D7E088D3DC63B96ULL,
		0xC84B29060567EBC5ULL,
		0xD3D8EA8E2035187AULL,
		0xCA8461E368CBAA11ULL,
		0x1E18C737AE871CD1ULL,
		0x47A47496B1F1382FULL,
		0x8FABEF7FDFD77E97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBB7127D4ACA274F8ULL,
		0x9C828B657B6033A7ULL,
		0xB2922965C6123FF7ULL,
		0x5685EFB7F3561BA0ULL,
		0x5DEC0D2DBB596992ULL,
		0x73A115846FCAFFA4ULL,
		0x8AA7AC2B04BBF5BCULL,
		0x2166AB9F3EA4002EULL
	}};
	sign = 0;
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
		0xEBAE45756B4F1263ULL,
		0xD9324AE61E9879E2ULL,
		0xE41798DF23394D2FULL,
		0xCD84ADF436FF0953ULL,
		0x0EEC2442E02A5661ULL,
		0xB3333A71B7867F4CULL,
		0x2712A98F08EDB6E5ULL,
		0xE9E534291BFD360BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B52EA4ABFC0FA5ULL,
		0x211BBAFBF648AB48ULL,
		0xD692A72680873891ULL,
		0x12BE09C80F74300BULL,
		0xEA1D708DA8CFE0FEULL,
		0x8B194D100A4CF33CULL,
		0x65093C6D3738DE63ULL,
		0x7DCA7916C8107707ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9F916D0BF5302BEULL,
		0xB8168FEA284FCE9AULL,
		0x0D84F1B8A2B2149EULL,
		0xBAC6A42C278AD948ULL,
		0x24CEB3B5375A7563ULL,
		0x2819ED61AD398C0FULL,
		0xC2096D21D1B4D882ULL,
		0x6C1ABB1253ECBF03ULL
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
		0x05F26D4B7D714060ULL,
		0xE5860D77A6E90072ULL,
		0xB43897A7D053674FULL,
		0xC89C88AE63E880A3ULL,
		0x5303E1AC779E4C6FULL,
		0x0AAA8546AA43A233ULL,
		0xC7BC4F29CFC6E41CULL,
		0xF7ED0A5D37BEA455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F979B00C60DB8CULL,
		0x664850375C624C6DULL,
		0x3F1304897EE851EAULL,
		0x442974293860159CULL,
		0x1C9D9318315BF33DULL,
		0x9C4D6AE813F8245BULL,
		0x36830530A1BF671EULL,
		0x6E4390A82DDB76A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72F8F39B711064D4ULL,
		0x7F3DBD404A86B404ULL,
		0x7525931E516B1565ULL,
		0x847314852B886B07ULL,
		0x36664E9446425932ULL,
		0x6E5D1A5E964B7DD8ULL,
		0x913949F92E077CFDULL,
		0x89A979B509E32DB4ULL
	}};
	sign = 0;
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
		0x5DDE01AEED3A3A32ULL,
		0xDFBDE1BA85F1C499ULL,
		0x2EB2BCDAFB791C1FULL,
		0xDB319641DABA6348ULL,
		0x61170E4C4F8750C5ULL,
		0x3D8470454DB6D5CEULL,
		0x950C26B2B2F1C0F2ULL,
		0x31EBC80B7E913E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF354D9C93EA9D45CULL,
		0x96BD8D58A95E070BULL,
		0x24D690AF70037B3AULL,
		0xCBE88107A40B1E46ULL,
		0x2F949A24763D2092ULL,
		0xE75BCC0CC8CCBDABULL,
		0xC6FD8361ACC33375ULL,
		0xE374FB65386E359FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A8927E5AE9065D6ULL,
		0x49005461DC93BD8DULL,
		0x09DC2C2B8B75A0E5ULL,
		0x0F49153A36AF4502ULL,
		0x31827427D94A3033ULL,
		0x5628A43884EA1823ULL,
		0xCE0EA351062E8D7CULL,
		0x4E76CCA64623088EULL
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
		0x9725D4F81F1F0BC5ULL,
		0x367DB3BC37EC89BEULL,
		0xBE88FCDEE5F5CEA2ULL,
		0xF8CA56786BB26AB4ULL,
		0x6C9A46E9050D0737ULL,
		0x96DADD9AE3BF1AE6ULL,
		0x131535D7F516DE7CULL,
		0xDC4555EBA672BD29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9238FF24542ED6DFULL,
		0xDA401BF8D9BD06CAULL,
		0x205DBB97219DCE0AULL,
		0xBCBCE8E9671AEEA5ULL,
		0xE5BB4122A2F6A428ULL,
		0xABFE1367D69DD452ULL,
		0xBF919161B26855BEULL,
		0xE422BAF4E74515A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04ECD5D3CAF034E6ULL,
		0x5C3D97C35E2F82F4ULL,
		0x9E2B4147C4580097ULL,
		0x3C0D6D8F04977C0FULL,
		0x86DF05C66216630FULL,
		0xEADCCA330D214693ULL,
		0x5383A47642AE88BDULL,
		0xF8229AF6BF2DA783ULL
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
		0x53015C5AFDAD5C7AULL,
		0x2719674C86A44E32ULL,
		0x3B7CE05848E41950ULL,
		0xBC627F9044432F21ULL,
		0x2C9A76E0B0023187ULL,
		0xAEBA9B23571AE780ULL,
		0x4E8F055A9CA02F0BULL,
		0x74C733C2367CF8D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E9BE0FF46002656ULL,
		0x61445D688724E172ULL,
		0x574C0BB06C9BB40CULL,
		0xA60A78E9120EE1E1ULL,
		0xF23E5536B2662E12ULL,
		0x8001AA895388C59BULL,
		0xC67AC01E070010B7ULL,
		0xA4F94D3002E61E84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4657B5BB7AD3624ULL,
		0xC5D509E3FF7F6CBFULL,
		0xE430D4A7DC486543ULL,
		0x165806A732344D3FULL,
		0x3A5C21A9FD9C0375ULL,
		0x2EB8F09A039221E4ULL,
		0x8814453C95A01E54ULL,
		0xCFCDE6923396DA51ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF6EE152B9EA4266FULL,
		0x1C92385C5FEAFCC0ULL,
		0xDC097196A6508A40ULL,
		0x8CF5E181F0FACC7CULL,
		0xF782EBEECEA49891ULL,
		0xBDB1CA4C0FB7A7FAULL,
		0x025E8F7FDF8296C5ULL,
		0x213D306960C1304FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013D4FF0F585E51BULL,
		0x4F724A38FA58838EULL,
		0x105CBD5636DAB9DCULL,
		0x818E16C5A685E9BAULL,
		0x5CF8EFDF9210CB79ULL,
		0xA0D05403DC631289ULL,
		0x9A837625DEBCBC51ULL,
		0x69933CE231A04F03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF5B0C53AA91E4154ULL,
		0xCD1FEE2365927932ULL,
		0xCBACB4406F75D063ULL,
		0x0B67CABC4A74E2C2ULL,
		0x9A89FC0F3C93CD18ULL,
		0x1CE1764833549571ULL,
		0x67DB195A00C5DA74ULL,
		0xB7A9F3872F20E14BULL
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
		0x90EAE44D2BC59AD3ULL,
		0x9C596DCD899D4B7DULL,
		0x8B94E745FE0E4819ULL,
		0x13B08E6C2E79C418ULL,
		0x8045A1A6E0312415ULL,
		0xDD11129CBC75FF1AULL,
		0xAD6FC57C19677E06ULL,
		0x61B931BA49FDAA23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5F4D4BF495ECA03ULL,
		0x06A6D98A5DE16C20ULL,
		0xF2F4A62A2641E33BULL,
		0xEF133B9CB0AF6599ULL,
		0xDCDD19174F417C21ULL,
		0xA699C20DAF2C4457ULL,
		0x0672BBEAC2FC18E3ULL,
		0x8E6EEEB7B1EC91D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBAF60F8DE266D0D0ULL,
		0x95B294432BBBDF5CULL,
		0x98A0411BD7CC64DEULL,
		0x249D52CF7DCA5E7EULL,
		0xA368888F90EFA7F3ULL,
		0x3677508F0D49BAC2ULL,
		0xA6FD0991566B6523ULL,
		0xD34A430298111853ULL
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
		0x4BE74876A66975AAULL,
		0x77A37123B6B734F6ULL,
		0x0D65295C3132FCBCULL,
		0x0F1BC94E25C6AC52ULL,
		0x5836BC39AF6AE5D7ULL,
		0xA4463B5F8F2FE782ULL,
		0x01237AAE61115973ULL,
		0xD0D6BD832773F5F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB396E18C3B53569AULL,
		0x6B8E1F946B932288ULL,
		0x7A3C3BFE427111BCULL,
		0xCFB3A0CA0C73EAB9ULL,
		0x88B2668930E702D1ULL,
		0xA24879D7B5B9DB7AULL,
		0xE034D2FA9DF4163BULL,
		0x73A5740610037480ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x985066EA6B161F10ULL,
		0x0C15518F4B24126DULL,
		0x9328ED5DEEC1EB00ULL,
		0x3F6828841952C198ULL,
		0xCF8455B07E83E305ULL,
		0x01FDC187D9760C07ULL,
		0x20EEA7B3C31D4338ULL,
		0x5D31497D17708175ULL
	}};
	sign = 0;
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
		0x2042B1B13E3AF098ULL,
		0x401C55DE7F5A08AFULL,
		0xF0367E119B966067ULL,
		0x4B4752135AECA520ULL,
		0x8DF257735A2A16C0ULL,
		0x9864798F7ADA8479ULL,
		0x55978911317C0D67ULL,
		0xCE770D5C04DD8594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9F0105C2514BEEULL,
		0x78C22F83DD401091ULL,
		0x3C1A8DD1EBA4F632ULL,
		0x208E2B939C0F1627ULL,
		0xF0D82267B489C842ULL,
		0x3F51409088A3450AULL,
		0xBE24A09FF0309E9DULL,
		0x15D12267589D48A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x23A3B0AB7BE9A4AAULL,
		0xC75A265AA219F81DULL,
		0xB41BF03FAFF16A34ULL,
		0x2AB9267FBEDD8EF9ULL,
		0x9D1A350BA5A04E7EULL,
		0x591338FEF2373F6EULL,
		0x9772E871414B6ECAULL,
		0xB8A5EAF4AC403CF2ULL
	}};
	sign = 0;
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
		0xBE6CC1341FD26418ULL,
		0xA8D418BB06B2B6AFULL,
		0x38FE842280A130E7ULL,
		0xEC6C765E3E84E10AULL,
		0xA969C2A85D4B311FULL,
		0xFACBB60E5EB81CFCULL,
		0x6FFE9A36E49F8F17ULL,
		0x33BA847670A87AC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x653BA193D344CBE8ULL,
		0x500EC1EC2912D9E9ULL,
		0xBB9669EDBA43B09CULL,
		0x344E44399F71B1D2ULL,
		0x81650546F3C7734BULL,
		0xA84A74E0D49759D7ULL,
		0x1CD0A9719D90BBB9ULL,
		0xDD658B8750BD38C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59311FA04C8D9830ULL,
		0x58C556CEDD9FDCC6ULL,
		0x7D681A34C65D804BULL,
		0xB81E32249F132F37ULL,
		0x2804BD616983BDD4ULL,
		0x5281412D8A20C325ULL,
		0x532DF0C5470ED35EULL,
		0x5654F8EF1FEB41FFULL
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
		0xDA70D37375747028ULL,
		0xD2163ADEA9864C34ULL,
		0xF817D689B7AA1B06ULL,
		0x16873A86A6975D45ULL,
		0xDFAF89063A34F431ULL,
		0xECBC5C931026427FULL,
		0x99A15D348744ABBEULL,
		0x9EECBC1ED8AB4F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x388061B573D1978EULL,
		0xC1AEDA41B16356F5ULL,
		0x86E1BB3D95DD8D38ULL,
		0xEC367F7AC55EE783ULL,
		0xB013364C62AC93C1ULL,
		0xA1291EA768883A46ULL,
		0xE9FAA418B9D02664ULL,
		0xEABF956F0CFA60B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1F071BE01A2D89AULL,
		0x1067609CF822F53FULL,
		0x71361B4C21CC8DCEULL,
		0x2A50BB0BE13875C2ULL,
		0x2F9C52B9D788606FULL,
		0x4B933DEBA79E0839ULL,
		0xAFA6B91BCD74855AULL,
		0xB42D26AFCBB0EEADULL
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
		0xC5F58676FF7F78F3ULL,
		0x9627B0331DBD1755ULL,
		0x2BD1B0FEC5CA580BULL,
		0xE75F83DF602E6B99ULL,
		0xB3684D34DF4CE0AAULL,
		0x5F9DF484167A2275ULL,
		0x550AD6A81FD1F3B2ULL,
		0x1E2B91B457A3DDD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56F8BD19DAC0585EULL,
		0x79C80B8C211BB12DULL,
		0x9EF6AD96BA75A38DULL,
		0x414F9903EE1B82D3ULL,
		0x6C37A6D2F04C0203ULL,
		0x0B350BF66716C2CEULL,
		0x7D4AAD9E4A86FDF0ULL,
		0x712C4067B7A28350ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EFCC95D24BF2095ULL,
		0x1C5FA4A6FCA16628ULL,
		0x8CDB03680B54B47EULL,
		0xA60FEADB7212E8C5ULL,
		0x4730A661EF00DEA7ULL,
		0x5468E88DAF635FA7ULL,
		0xD7C02909D54AF5C2ULL,
		0xACFF514CA0015A84ULL
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
		0xD46B80C1D368A224ULL,
		0x8BAED431799A3EF6ULL,
		0x93F773AA9265E33FULL,
		0x9914F4047A928602ULL,
		0x63C5CA0A9F00BBA8ULL,
		0x019BF6213A8518F6ULL,
		0x45FD19CDEF0B75B9ULL,
		0xFDDC0284259DBC24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EC507333C0C4286ULL,
		0x0666CF3A1D2A772DULL,
		0xC82D1EEDA0DAEB4FULL,
		0x425CE885EEDEC947ULL,
		0x94EC28EA3E52153CULL,
		0x643FEF7B251BFBB5ULL,
		0x36B2096D10148221ULL,
		0x8B59E3FCA2634D3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x75A6798E975C5F9EULL,
		0x854804F75C6FC7C9ULL,
		0xCBCA54BCF18AF7F0ULL,
		0x56B80B7E8BB3BCBAULL,
		0xCED9A12060AEA66CULL,
		0x9D5C06A615691D40ULL,
		0x0F4B1060DEF6F397ULL,
		0x72821E87833A6EE6ULL
	}};
	sign = 0;
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
		0x81BAD04E85C16172ULL,
		0x7227F0F660A3977DULL,
		0x2E5845724229A048ULL,
		0xE7C12A2055FE38F7ULL,
		0x94ABA925B35A1D85ULL,
		0xD695DE0B96059DD1ULL,
		0xE33A220BE70776DBULL,
		0x97F9655238F816EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x087A389EE6C256D8ULL,
		0xEA3247568818FCBAULL,
		0xC83F7C7C59705274ULL,
		0x54B4B89B82BF1DCFULL,
		0x9716B37343698501ULL,
		0x6A1520F459BB4960ULL,
		0x2C88C2B81382D57AULL,
		0x066898FBC0514CCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x794097AF9EFF0A9AULL,
		0x87F5A99FD88A9AC3ULL,
		0x6618C8F5E8B94DD3ULL,
		0x930C7184D33F1B27ULL,
		0xFD94F5B26FF09884ULL,
		0x6C80BD173C4A5470ULL,
		0xB6B15F53D384A161ULL,
		0x9190CC5678A6CA23ULL
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
		0xEBC5C507FFA03101ULL,
		0x3BD4EF71A2A40C53ULL,
		0x20CC2F26719E43B0ULL,
		0x759476D25E3EEE0DULL,
		0xCF8F37772A71407CULL,
		0xFB678FE563C036C6ULL,
		0x46B8B0632EEA85B4ULL,
		0x92BCE78240177554ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC755B0866C97F349ULL,
		0x05E27D50F897FD59ULL,
		0x63CCB972E50C90D8ULL,
		0xDBB0C15FF4F66C4DULL,
		0x71223689A9C579C4ULL,
		0xDFA60E6F00905196ULL,
		0xDB31D6402BBF5FF1ULL,
		0x1E79D3E651C225DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2470148193083DB8ULL,
		0x35F27220AA0C0EFAULL,
		0xBCFF75B38C91B2D8ULL,
		0x99E3B572694881BFULL,
		0x5E6D00ED80ABC6B7ULL,
		0x1BC18176632FE530ULL,
		0x6B86DA23032B25C3ULL,
		0x7443139BEE554F79ULL
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
		0x99BDFB49E6191AA8ULL,
		0x044E4CDC0C791D32ULL,
		0x48C576EF2A11835EULL,
		0x3674FF2A83F937A6ULL,
		0x8AA8C6898BC94968ULL,
		0x1D09DC6440C3EB0EULL,
		0xC28CD4538012A809ULL,
		0x25349BE46C12C776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4B1CB9CE32E1B7ULL,
		0x72C4ADE82A3C09D6ULL,
		0x9691D291E8C8D8F9ULL,
		0x3A329176D733500EULL,
		0x86007C69365313BDULL,
		0xD25704A5655441CEULL,
		0x6CEEDEEA7FD37F86ULL,
		0x47809DA748A29DC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB72DE9017E638F1ULL,
		0x91899EF3E23D135BULL,
		0xB233A45D4148AA64ULL,
		0xFC426DB3ACC5E797ULL,
		0x04A84A20557635AAULL,
		0x4AB2D7BEDB6FA940ULL,
		0x559DF569003F2882ULL,
		0xDDB3FE3D237029AEULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x6E3D2191D28A2FB4ULL,
		0x122BB590269A8B92ULL,
		0x3DDE4CC5EEA05543ULL,
		0x0FE3D53359DAED09ULL,
		0xB542D2A58BDB5985ULL,
		0xB49336EED497C7F7ULL,
		0x7E475B97C52E5F7FULL,
		0xF41D791882DB610DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE62E24285F2796F2ULL,
		0xD8F294A52638FD9DULL,
		0xBCA9D667F6895184ULL,
		0xDFB5716EC063DB9DULL,
		0xF6FC50E44A0F5C65ULL,
		0x70A9C81FD93706E9ULL,
		0x4E69775D0A76801EULL,
		0xCA5AC267D463FA48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x880EFD69736298C2ULL,
		0x393920EB00618DF4ULL,
		0x8134765DF81703BEULL,
		0x302E63C49977116BULL,
		0xBE4681C141CBFD1FULL,
		0x43E96ECEFB60C10DULL,
		0x2FDDE43ABAB7DF61ULL,
		0x29C2B6B0AE7766C5ULL
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
		0x361DAED2A597896AULL,
		0x7531E9B644B82630ULL,
		0x45D00CB948484516ULL,
		0x6FE88C2E89366731ULL,
		0x3A706FBBA3253C32ULL,
		0x7F66EE6FA2C88AFBULL,
		0x70CE99A7F63978A8ULL,
		0xC7B93DF8ABBEB968ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA244289CE024F02ULL,
		0xEA009D16E8500614ULL,
		0x0D4F2A9021E91078ULL,
		0x082CF96F7B69627DULL,
		0xB6128C1A57AA3549ULL,
		0x041F64D58ED259F5ULL,
		0xDD23480AC622CCFAULL,
		0x2B5EF6956C5B8537ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BF96C48D7953A68ULL,
		0x8B314C9F5C68201BULL,
		0x3880E229265F349DULL,
		0x67BB92BF0DCD04B4ULL,
		0x845DE3A14B7B06E9ULL,
		0x7B47899A13F63105ULL,
		0x93AB519D3016ABAEULL,
		0x9C5A47633F633430ULL
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
		0xA8A8EA504F237911ULL,
		0x7C6B2531D911F1C7ULL,
		0xCE6927CAC4535C14ULL,
		0xBF9966D446AF6EF5ULL,
		0x9AE6DF7F2D037957ULL,
		0xD8CA8F2BEDA67BDAULL,
		0x97AB712A2D0922FDULL,
		0xE1B50A214C1D654EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A5A82EFD2C18FBULL,
		0x80BF1AF0134F9CD4ULL,
		0x797A2309082EEC8BULL,
		0xC3D3ECBBC9E48EE6ULL,
		0x765F04FAE3C7E11CULL,
		0x6412B7340ED5420CULL,
		0xB07AEA31A4CA5F0DULL,
		0xC8609322CCD7C02AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3203422151F76016ULL,
		0xFBAC0A41C5C254F3ULL,
		0x54EF04C1BC246F88ULL,
		0xFBC57A187CCAE00FULL,
		0x2487DA84493B983AULL,
		0x74B7D7F7DED139CEULL,
		0xE73086F8883EC3F0ULL,
		0x195476FE7F45A523ULL
	}};
	sign = 0;
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
		0xD6374DCFC1696ED5ULL,
		0x34C39EC906672ADCULL,
		0x1C4A4730C3C94DA3ULL,
		0x3CF0384BAA7CAF79ULL,
		0x8A5D7D890DE52D0FULL,
		0x5BA43468100CBA5AULL,
		0x7BBCF4894EC55B7CULL,
		0x228D3BC9BD46EF55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01554E7D1BC5540CULL,
		0x05A8B65FD9A71D4FULL,
		0x0AE4C9A8648D7885ULL,
		0x800DEC8F8A3C736FULL,
		0x31ACDE8D57E0A3EBULL,
		0x7879EB5948686C16ULL,
		0x69D04DFD780AA67FULL,
		0xCB31278CCEC356ECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4E1FF52A5A41AC9ULL,
		0x2F1AE8692CC00D8DULL,
		0x11657D885F3BD51EULL,
		0xBCE24BBC20403C0AULL,
		0x58B09EFBB6048923ULL,
		0xE32A490EC7A44E44ULL,
		0x11ECA68BD6BAB4FCULL,
		0x575C143CEE839869ULL
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
		0xD61B2FCD7A489B77ULL,
		0x1334E497C25125A0ULL,
		0x0664E2A706B44D05ULL,
		0x09D5469113A397E4ULL,
		0xD016FDD37693238CULL,
		0xCFD722304322C173ULL,
		0xBCDA006E75E1BF69ULL,
		0xBFA8826ED6762148ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x732935B49693F1F3ULL,
		0x272FBBCE2CF7541AULL,
		0xD94545C8F2FB8663ULL,
		0xBC88F6876DE9EEEDULL,
		0xD454C4E49407C8C4ULL,
		0xE68C4B87D2E776B0ULL,
		0x7DBA783D70AB847FULL,
		0x3A224311BA92E686ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62F1FA18E3B4A984ULL,
		0xEC0528C99559D186ULL,
		0x2D1F9CDE13B8C6A1ULL,
		0x4D4C5009A5B9A8F6ULL,
		0xFBC238EEE28B5AC7ULL,
		0xE94AD6A8703B4AC2ULL,
		0x3F1F883105363AE9ULL,
		0x85863F5D1BE33AC2ULL
	}};
	sign = 0;
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
		0x7F70E6B185A707F4ULL,
		0x89C21FB1407FE4ECULL,
		0xA738B4BF5CDF1C27ULL,
		0xB54620BA1F17E959ULL,
		0xA57C1C869460309BULL,
		0x4020811084C4B0BBULL,
		0x86D2E4A9C3709400ULL,
		0x73FACF4EBCE8179AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E693830986C4DB3ULL,
		0x299CB6629CD8EF38ULL,
		0x45BC5429F2E9BBD2ULL,
		0x31564D5C357BA070ULL,
		0xD1F50E9CAB48F55EULL,
		0x30C6B82347FE4597ULL,
		0x78376AB304807659ULL,
		0x19ACC30EC9F7D583ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF107AE80ED3ABA41ULL,
		0x6025694EA3A6F5B3ULL,
		0x617C609569F56055ULL,
		0x83EFD35DE99C48E9ULL,
		0xD3870DE9E9173B3DULL,
		0x0F59C8ED3CC66B23ULL,
		0x0E9B79F6BEF01DA7ULL,
		0x5A4E0C3FF2F04217ULL
	}};
	sign = 0;
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
		0xB0EA5E3EF6313FC7ULL,
		0xE3C4E4C2B9F7E6F7ULL,
		0xBEF5FB3394970507ULL,
		0xFA104C90BE28B3B2ULL,
		0xBC16CED8E007447FULL,
		0x38AC0D9AF615415FULL,
		0x8ED07101EB8B322EULL,
		0xF3C8E737D8B7E0D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8DD852788A58748ULL,
		0x760AB4DF9EE79788ULL,
		0x4A713DE9FC3A309BULL,
		0xA54B55A3CC7BA6E2ULL,
		0x56EB1475F6B860F5ULL,
		0x0AEBD406FFE4D515ULL,
		0x8A77E85566C69851ULL,
		0xC2D69164E81987CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080CD9176D8BB87FULL,
		0x6DBA2FE31B104F6FULL,
		0x7484BD49985CD46CULL,
		0x54C4F6ECF1AD0CD0ULL,
		0x652BBA62E94EE38AULL,
		0x2DC03993F6306C4AULL,
		0x045888AC84C499DDULL,
		0x30F255D2F09E590CULL
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
		0xBB55302787B8E16AULL,
		0x24FA1D1758A2D4DBULL,
		0x59604254170B861CULL,
		0xBD5C02B699A35058ULL,
		0x558943A7E10F039EULL,
		0xF9FC309E8F355883ULL,
		0x773264248B1ED679ULL,
		0x7C6371AD4580E31DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5460F2E795A1E1A3ULL,
		0xFAD01732A9F3F9A6ULL,
		0xE510AB4621CB6352ULL,
		0xA7F4DF91116BAE87ULL,
		0x7B179DE34F07A5EFULL,
		0x030D62F455690ADFULL,
		0xA62913CA4D1FE920ULL,
		0x239431440A2C5D07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66F43D3FF216FFC7ULL,
		0x2A2A05E4AEAEDB35ULL,
		0x744F970DF54022C9ULL,
		0x156723258837A1D0ULL,
		0xDA71A5C492075DAFULL,
		0xF6EECDAA39CC4DA3ULL,
		0xD109505A3DFEED59ULL,
		0x58CF40693B548615ULL
	}};
	sign = 0;
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
		0x17ADA62668172467ULL,
		0x41A7FA3A5AF4A890ULL,
		0xFC4F223CB9766FB0ULL,
		0xAB04A909E36B491CULL,
		0xE749BD1BE9EE8A63ULL,
		0x346FB9D2817DA7C6ULL,
		0x4EB346F221C57196ULL,
		0x7A85FFAD98D4B14DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEBD8135BD904FF1ULL,
		0xFB3F66A755E18F9BULL,
		0xAE42AA781E9A24A5ULL,
		0x5502C197387F65D7ULL,
		0x8DD07D5121774B19ULL,
		0x6C4DD72BECC47AC5ULL,
		0x947A23E9E438722DULL,
		0x1D01DFC620552D1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68F024F0AA86D476ULL,
		0x46689393051318F4ULL,
		0x4E0C77C49ADC4B0AULL,
		0x5601E772AAEBE345ULL,
		0x59793FCAC8773F4AULL,
		0xC821E2A694B92D01ULL,
		0xBA3923083D8CFF68ULL,
		0x5D841FE7787F842FULL
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
		0x6F519F7900554001ULL,
		0x7D31E2690FD37F0DULL,
		0xE6A0EFAF2A23335BULL,
		0xD7D3A70319CADBC3ULL,
		0xF8AD42B4B3075CA1ULL,
		0x390244281A218928ULL,
		0x34A1C1A7111E5483ULL,
		0x571429A2CE65ED0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1A70CB95332C77ULL,
		0xD6509820F7EFBE1AULL,
		0x0DAFC866EEF051A2ULL,
		0xF8207AC45C7D4880ULL,
		0x54BF607366827CA5ULL,
		0x14248042A0F0C7D6ULL,
		0xFD0CB7D452940652ULL,
		0xCAD23DA1E5F176A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0372EAD6B22138AULL,
		0xA6E14A4817E3C0F2ULL,
		0xD8F127483B32E1B8ULL,
		0xDFB32C3EBD4D9343ULL,
		0xA3EDE2414C84DFFBULL,
		0x24DDC3E57930C152ULL,
		0x379509D2BE8A4E31ULL,
		0x8C41EC00E8747663ULL
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
		0x86313B3FEFC0FDBEULL,
		0x481BB11C9FD1C21FULL,
		0xB8D6CD29EB020A09ULL,
		0x955FB3BE0CC604E4ULL,
		0x50CDC31BAE2EF4B9ULL,
		0x799C313F39795175ULL,
		0xE3B890A21A831905ULL,
		0x5CEFFDEE7D28125DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FCB1B9B89B4648CULL,
		0x3F4FCC1F6731594AULL,
		0xF4BC2C58216B2779ULL,
		0x8B04D06840A76258ULL,
		0xED946DA894C76373ULL,
		0x69B2B46D76781CFCULL,
		0xD72BBD5334D65B20ULL,
		0xEB783F04CA523BC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6661FA4660C9932ULL,
		0x08CBE4FD38A068D4ULL,
		0xC41AA0D1C996E290ULL,
		0x0A5AE355CC1EA28BULL,
		0x6339557319679146ULL,
		0x0FE97CD1C3013478ULL,
		0x0C8CD34EE5ACBDE5ULL,
		0x7177BEE9B2D5D69CULL
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
		0x851E1464CBB17B91ULL,
		0x13E79CC52BBCB59DULL,
		0xBFFB87587686BC5BULL,
		0xABEA0C6F94044548ULL,
		0x134269D6C48CF90FULL,
		0x31BFAE2D74F80038ULL,
		0x3B149277DAC44295ULL,
		0xEF9476B64BE17BC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x144F663A41712B94ULL,
		0xE42F3BD4739AC7CEULL,
		0x5152833759A71B19ULL,
		0x942E8F731B6C243FULL,
		0xDC4F9E23107D6C41ULL,
		0x042A751A3E4A4935ULL,
		0xEF5666048AA7D52BULL,
		0xB3D5559D4715ECC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x70CEAE2A8A404FFDULL,
		0x2FB860F0B821EDCFULL,
		0x6EA904211CDFA141ULL,
		0x17BB7CFC78982109ULL,
		0x36F2CBB3B40F8CCEULL,
		0x2D95391336ADB702ULL,
		0x4BBE2C73501C6D6AULL,
		0x3BBF211904CB8F01ULL
	}};
	sign = 0;
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
		0xCE856D6AB7A00863ULL,
		0x01BC81161638C947ULL,
		0x65F93C1F7DB0B2AAULL,
		0xB2A38D08D8AEA37BULL,
		0x659E0CEAFAD54DE5ULL,
		0xB6746D1643FDEBB6ULL,
		0xA8E93573E296DA3EULL,
		0x3F38E3E4F0945A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD6FD5D00B7BBA7ULL,
		0x035DF2D8E9E1D10FULL,
		0x32576E473D36A1E0ULL,
		0x0BDD27F98F361D63ULL,
		0x0DF62A33B8D176C2ULL,
		0xD4AB3DBE703B6110ULL,
		0x001D8A52321DF38BULL,
		0xF8938FC87D85CB3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EAE700DB6E84CBCULL,
		0xFE5E8E3D2C56F838ULL,
		0x33A1CDD8407A10C9ULL,
		0xA6C6650F49788618ULL,
		0x57A7E2B74203D723ULL,
		0xE1C92F57D3C28AA6ULL,
		0xA8CBAB21B078E6B2ULL,
		0x46A5541C730E8F35ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF8EFF953A2BA4077ULL,
		0xBDBBE3239F7AD18CULL,
		0x9FB1F0A859B907EEULL,
		0xE60507B71C31B72AULL,
		0xD48523E0801203C5ULL,
		0x485FE00E4D44A7F5ULL,
		0x8B70F17019DA5480ULL,
		0x0BA99495A9D61762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5662C80EA269642ULL,
		0x3A5E5CC91115EC6DULL,
		0xB29BCBAE99555C03ULL,
		0xEE2F6440559A4A68ULL,
		0x5DB5BC2ACCBA0F24ULL,
		0x50F6E0D803AFF78DULL,
		0xE7321EC650BB2806ULL,
		0xE348200F2796DBCBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5389CCD2B893AA35ULL,
		0x835D865A8E64E51FULL,
		0xED1624F9C063ABEBULL,
		0xF7D5A376C6976CC1ULL,
		0x76CF67B5B357F4A0ULL,
		0xF768FF364994B068ULL,
		0xA43ED2A9C91F2C79ULL,
		0x28617486823F3B96ULL
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
		0xAC1322DF07976CEEULL,
		0xA0BAD804816C2956ULL,
		0xE580A5F9FB26EC39ULL,
		0x35A846C831B3D2F7ULL,
		0x2DE6747B3174103CULL,
		0xAAE9116FBAE1816FULL,
		0x0D26DD4DFA9F3ED1ULL,
		0x2EA7C0C87A31B78DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1A7526AFB0E941ULL,
		0xAF5D72A97B3B036FULL,
		0x889779FFDBE20C82ULL,
		0x6249644E94DDD1B5ULL,
		0x052135E989CDF906ULL,
		0x3C0187C487CD8BA7ULL,
		0xEE17ED5E42C55FABULL,
		0x0C8B22FB49FDB6D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9CF8ADB857E683ADULL,
		0xF15D655B063125E7ULL,
		0x5CE92BFA1F44DFB6ULL,
		0xD35EE2799CD60142ULL,
		0x28C53E91A7A61735ULL,
		0x6EE789AB3313F5C8ULL,
		0x1F0EEFEFB7D9DF26ULL,
		0x221C9DCD303400B5ULL
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
		0xBC5BD4EFC01E57D4ULL,
		0x070BBD28760D535DULL,
		0xCA4E2554F5BB263FULL,
		0x5F564D309DAE5D90ULL,
		0xA3025443C1047308ULL,
		0x7E03AC700FC06865ULL,
		0x0632FD49D875DAB2ULL,
		0x85242E51E57D7FC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863A57F7FDD5314FULL,
		0x43E3FA3E03097B6AULL,
		0xFD7BC06ECE834751ULL,
		0xA7A78997160AD1C3ULL,
		0x52FF14D5BB6B8FC6ULL,
		0x8834FAB43BB1C591ULL,
		0xE1E506A553C73744ULL,
		0x2292F14CF6CDB3B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36217CF7C2492685ULL,
		0xC327C2EA7303D7F3ULL,
		0xCCD264E62737DEEDULL,
		0xB7AEC39987A38BCCULL,
		0x50033F6E0598E341ULL,
		0xF5CEB1BBD40EA2D4ULL,
		0x244DF6A484AEA36DULL,
		0x62913D04EEAFCC16ULL
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
		0x869ED0153868A02CULL,
		0xBB94730DCCE8842DULL,
		0x6D3022CD5F3C3C91ULL,
		0xCF2FFA059269A136ULL,
		0x8B931AEC40F89491ULL,
		0xBC2C1579307178D1ULL,
		0x31F1588F7F5C7168ULL,
		0xED391E4223413FE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x518B781BEAC4862EULL,
		0xDAE802293FE0F860ULL,
		0x083D2263BF8AB7D4ULL,
		0xC18936150D84533DULL,
		0x69C6588F81010C8AULL,
		0x5C484453BC21F793ULL,
		0xF3E2CBBB4216ACB2ULL,
		0xC3674D9A4AF91EA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x351357F94DA419FEULL,
		0xE0AC70E48D078BCDULL,
		0x64F300699FB184BCULL,
		0x0DA6C3F084E54DF9ULL,
		0x21CCC25CBFF78807ULL,
		0x5FE3D125744F813EULL,
		0x3E0E8CD43D45C4B6ULL,
		0x29D1D0A7D8482140ULL
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
		0xE1F235F8CA14521BULL,
		0xBEF716AE1B2D43B3ULL,
		0x829BD6B4B8E0AF72ULL,
		0x1B6D7D761E1E9FC6ULL,
		0x6E5F270C5E17470BULL,
		0x78BC181922433F01ULL,
		0xB3A12D6566CFCED6ULL,
		0xC1EEE5A37F05D120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC691C7079E82D8DEULL,
		0xE51BD0C53C04F416ULL,
		0x64EC45FCA6B0670FULL,
		0x51EE7361176D6B45ULL,
		0xAC0843E878517D60ULL,
		0xD1513491F68D8FDDULL,
		0x9F60351BBDC1781BULL,
		0xEBB15486AE52580AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B606EF12B91793DULL,
		0xD9DB45E8DF284F9DULL,
		0x1DAF90B812304862ULL,
		0xC97F0A1506B13481ULL,
		0xC256E323E5C5C9AAULL,
		0xA76AE3872BB5AF23ULL,
		0x1440F849A90E56BAULL,
		0xD63D911CD0B37916ULL
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
		0xCAAC87404FF52F0DULL,
		0x3EEE8382A11B1B88ULL,
		0x04CC1FB0E56FC9B1ULL,
		0x2BC69AD8146BAA3FULL,
		0x08B7F374A85752DAULL,
		0xA3860FC23EC25466ULL,
		0xF1E1512B89444B58ULL,
		0xC0899C118928A37DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD6E8D8BF2EC123ULL,
		0xAA27A12C12483EE6ULL,
		0xF7F5EC302648ED54ULL,
		0x5ABA1FDA1EDFA4BAULL,
		0x11FA9685B2F13447ULL,
		0x14CF082B934EFFF1ULL,
		0xA922CB1F44922325ULL,
		0x40C5772746B824AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAAD59E6790C66DEAULL,
		0x94C6E2568ED2DCA2ULL,
		0x0CD63380BF26DC5CULL,
		0xD10C7AFDF58C0584ULL,
		0xF6BD5CEEF5661E92ULL,
		0x8EB70796AB735474ULL,
		0x48BE860C44B22833ULL,
		0x7FC424EA42707ED3ULL
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
		0x00805D81243674C0ULL,
		0x6E0B8AE57E834A24ULL,
		0x23DED316C5772C05ULL,
		0x4894CDFEA2739A98ULL,
		0xBB729301F45CBB8BULL,
		0x3F77057D7A93FE55ULL,
		0x1C36C3B4D4EAC356ULL,
		0x96835A791CC73059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x257C23142E275906ULL,
		0xCF0A72B419C97655ULL,
		0x5B7C289E02D59B44ULL,
		0xA78A937F21EBD499ULL,
		0xDE2E1185DF6977B2ULL,
		0xFE468834EB66E2B2ULL,
		0xB8356A47CD936CE0ULL,
		0xC7EDB7E300775A0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB043A6CF60F1BBAULL,
		0x9F01183164B9D3CEULL,
		0xC862AA78C2A190C0ULL,
		0xA10A3A7F8087C5FEULL,
		0xDD44817C14F343D8ULL,
		0x41307D488F2D1BA2ULL,
		0x6401596D07575675ULL,
		0xCE95A2961C4FD649ULL
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
		0x8A627D463F7716D0ULL,
		0xFA323C8FA5F918D7ULL,
		0x86D0636456905F2AULL,
		0x305D836497194A0AULL,
		0xD384E0DC7F1E5FA7ULL,
		0x7A7EA99630EB201FULL,
		0x0CC3043CDF5F57FCULL,
		0xB9775825877962B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4CF5A2B4FD4B1FAULL,
		0x1084172108EA87F1ULL,
		0xA91BBDD0ADAD7114ULL,
		0x96A3C943A3B74459ULL,
		0x93CE1A99C1EA8E21ULL,
		0x43F7C7E46A595006ULL,
		0xA3B9D78B804FAC9EULL,
		0xFC501DFD08F2A01BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA593231AEFA264D6ULL,
		0xE9AE256E9D0E90E5ULL,
		0xDDB4A593A8E2EE16ULL,
		0x99B9BA20F36205B0ULL,
		0x3FB6C642BD33D185ULL,
		0x3686E1B1C691D019ULL,
		0x69092CB15F0FAB5EULL,
		0xBD273A287E86C29AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC8B4FE035D300846ULL,
		0x0229E100D282CF7FULL,
		0x23A3B6764C56DEEFULL,
		0xCC1BF967A8082BD3ULL,
		0x8BC72443BFCB536DULL,
		0x5B0CFDD2ECD463B7ULL,
		0x65E984B48A3267E6ULL,
		0x61276C5A7BB44B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2E136B8020EA23AULL,
		0xA4031D2D34D7A6C8ULL,
		0xD524178EC8B50FACULL,
		0x2B397936BD584B78ULL,
		0x67FAC1E589B8A19EULL,
		0x9BB9F1CD4E0D82DAULL,
		0x8F5CD7AE7CCB64BAULL,
		0x7DF8FAF5CADA3254ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5D3C74B5B21660CULL,
		0x5E26C3D39DAB28B6ULL,
		0x4E7F9EE783A1CF42ULL,
		0xA0E28030EAAFE05AULL,
		0x23CC625E3612B1CFULL,
		0xBF530C059EC6E0DDULL,
		0xD68CAD060D67032BULL,
		0xE32E7164B0DA1944ULL
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
		0x6E3E87AD6A045759ULL,
		0x8A8B1231A5A45556ULL,
		0x1BB013BDC9A677B2ULL,
		0x79CBB095D29682E1ULL,
		0xD0677737B0651B61ULL,
		0x5EAC423DDA6EE22FULL,
		0x454EE6893EDE39E3ULL,
		0xE8B27804D9C84CD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC4A5C2FC164B574ULL,
		0x01A811F18A5E6D7AULL,
		0xFF6E7F00B258A737ULL,
		0x9C3ED9456BC6964CULL,
		0x993A99631B0213FFULL,
		0xC53A25745755A4ABULL,
		0x9E3C58B981C599E1ULL,
		0xFE877D637F3A0642ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1F42B7DA89FA1E5ULL,
		0x88E300401B45E7DBULL,
		0x1C4194BD174DD07BULL,
		0xDD8CD75066CFEC94ULL,
		0x372CDDD495630761ULL,
		0x99721CC983193D84ULL,
		0xA7128DCFBD18A001ULL,
		0xEA2AFAA15A8E4693ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0E4A84C92255995DULL,
		0x5DD8B55AF6E427C2ULL,
		0xD84104BEDB5513E6ULL,
		0x28B85EB9B891B48AULL,
		0xFA4E85390038BC35ULL,
		0x7842FBC1937A6673ULL,
		0x8A1A64ACF2DCBA72ULL,
		0x50EEB47FF7BCDD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF3265B1626EC9FULL,
		0xAAB4986636DF4C16ULL,
		0xD1984B788053A53BULL,
		0xF6DEE7DCC1239FA9ULL,
		0x4FC967B34AF123BBULL,
		0xA1CDF1F1F75C374BULL,
		0x20281AF20725009BULL,
		0xAB259C5CB8874AA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF575E6E0C2EACBEULL,
		0xB3241CF4C004DBABULL,
		0x06A8B9465B016EAAULL,
		0x31D976DCF76E14E1ULL,
		0xAA851D85B5479879ULL,
		0xD67509CF9C1E2F28ULL,
		0x69F249BAEBB7B9D6ULL,
		0xA5C918233F35929BULL
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
		0x02DE1FB056A6FE9CULL,
		0x71E6B4C9E3D668BDULL,
		0xAD1B047C0FF326BDULL,
		0xACEFD89ABD3FE687ULL,
		0x33E515FC65321EAFULL,
		0x6DF5B299333A4771ULL,
		0x9267AAD0DED9990DULL,
		0xFAB97FC53D84BE92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF471C00D56A5C49BULL,
		0x006B3EECE2ADA3D3ULL,
		0x7C08365BBC33EB57ULL,
		0xB077FDF6905A93A0ULL,
		0x33574A0E6EE1DC9AULL,
		0xDEFC33A514D26EA2ULL,
		0x59544532CCC45C15ULL,
		0x3642D2669C282217ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E6C5FA300013A01ULL,
		0x717B75DD0128C4E9ULL,
		0x3112CE2053BF3B66ULL,
		0xFC77DAA42CE552E7ULL,
		0x008DCBEDF6504214ULL,
		0x8EF97EF41E67D8CFULL,
		0x3913659E12153CF7ULL,
		0xC476AD5EA15C9C7BULL
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
		0x66450F8884B903F1ULL,
		0xF13E4E42F7442CF9ULL,
		0x474DBD0A972BE302ULL,
		0xBE5F04F286C5ED4CULL,
		0x479359BC681C81B4ULL,
		0xA38CC299D0D62FDCULL,
		0xAAFCFF1644D6A2FAULL,
		0x81932DC16CE6F2A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA86BE1A5B9296FCULL,
		0x7EA569D0099A39C5ULL,
		0xB7ED80DA92ED0051ULL,
		0x7B0B8CF2CF328463ULL,
		0x20B321CCCF6BC7B9ULL,
		0x1D87AAFC75C0599CULL,
		0x4B4ECB45BE304C24ULL,
		0x596F5BE3143834B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABBE516E29266CF5ULL,
		0x7298E472EDA9F333ULL,
		0x8F603C30043EE2B1ULL,
		0x435377FFB79368E8ULL,
		0x26E037EF98B0B9FBULL,
		0x8605179D5B15D640ULL,
		0x5FAE33D086A656D6ULL,
		0x2823D1DE58AEBDEDULL
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
		0x5677D4C1416A6285ULL,
		0x551BFF489F776125ULL,
		0xF123DE322A38689CULL,
		0xC065772C2910391BULL,
		0x3015273E5DDDC8F8ULL,
		0xECA7854518641F9CULL,
		0xC40B8B1C5D54AAA5ULL,
		0x2FA8698D870FFA82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4265C1F5759F54ULL,
		0x62E02B1197667854ULL,
		0x4F8CD4DCB042F814ULL,
		0xBF6AA9CC318603A7ULL,
		0xAFB5CE6039898A01ULL,
		0x6CB4D9D35756B078ULL,
		0xA4146059C11D52BDULL,
		0x0A1BAFA759C01BCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A356EFF4BF4C331ULL,
		0xF23BD4370810E8D0ULL,
		0xA197095579F57087ULL,
		0x00FACD5FF78A3574ULL,
		0x805F58DE24543EF7ULL,
		0x7FF2AB71C10D6F23ULL,
		0x1FF72AC29C3757E8ULL,
		0x258CB9E62D4FDEB3ULL
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
		0xE942FD2F1DC7B84DULL,
		0xC208D41F69613C4AULL,
		0xADC3DAF7BE8239FFULL,
		0x39F29665D76E80A7ULL,
		0x9886876F1CBACDEDULL,
		0x0B72864F9001E2E1ULL,
		0xD0D656D6BF0DA397ULL,
		0x110936912D013D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AFD21C31148BEFULL,
		0x93492A224B4AA543ULL,
		0xCDBE7FC7D3AC65EDULL,
		0xBD61FC620381F74DULL,
		0xF99200156F288B31ULL,
		0x217B5336328BFF24ULL,
		0x628890C78D42E215ULL,
		0x10B2BDAB068C673CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F932B12ECB32C5EULL,
		0x2EBFA9FD1E169707ULL,
		0xE0055B2FEAD5D412ULL,
		0x7C909A03D3EC8959ULL,
		0x9EF48759AD9242BBULL,
		0xE9F733195D75E3BCULL,
		0x6E4DC60F31CAC181ULL,
		0x005678E62674D654ULL
	}};
	sign = 0;
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
		0x2F407C462DB905C6ULL,
		0x86329A8E24C24AA4ULL,
		0xC788DA90F005C8DBULL,
		0x8BEBCAEBE07DA63EULL,
		0x234F54F89AD74B30ULL,
		0xFC9D0EE939032E3DULL,
		0xFE6960D5F188F122ULL,
		0xF39209CDD6CF1361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAE3CDF06FDF9866ULL,
		0xDC6E88C26294FB64ULL,
		0x49AC9B0EA94FBFD9ULL,
		0x84AEBC9ABFB81A31ULL,
		0x8352EB2A58925A25ULL,
		0x3601425B53B58F68ULL,
		0x3D6175888766CB0CULL,
		0x9284B7747060ECC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x445CAE55BDD96D60ULL,
		0xA9C411CBC22D4F3FULL,
		0x7DDC3F8246B60901ULL,
		0x073D0E5120C58C0DULL,
		0x9FFC69CE4244F10BULL,
		0xC69BCC8DE54D9ED4ULL,
		0xC107EB4D6A222616ULL,
		0x610D5259666E2699ULL
	}};
	sign = 0;
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
		0x223A4495C3CF5905ULL,
		0x532B699D41501B4CULL,
		0xB8EDB80B5B4A0E36ULL,
		0x3CF9CC6E0525F7F5ULL,
		0xCE3B5FF6C77ACB21ULL,
		0x864A0251253E4084ULL,
		0xA86FF88B8439F6E2ULL,
		0x7ED88E0CB6C5CFA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FEF02236BAFB9E1ULL,
		0xA74DA4DA6553CE71ULL,
		0xDD07FB4F20039EFAULL,
		0xAF2E563AFB102922ULL,
		0x6BA784488BA714EFULL,
		0x9D7721B9BB614677ULL,
		0x0C9ED11250523B56ULL,
		0x0E278129BBD2DAE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x024B4272581F9F24ULL,
		0xABDDC4C2DBFC4CDBULL,
		0xDBE5BCBC3B466F3BULL,
		0x8DCB76330A15CED2ULL,
		0x6293DBAE3BD3B631ULL,
		0xE8D2E09769DCFA0DULL,
		0x9BD1277933E7BB8BULL,
		0x70B10CE2FAF2F4C0ULL
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
		0xF65C709175DC137CULL,
		0xF5A586B95BA1C4CCULL,
		0xFBA474A367D63E9CULL,
		0x22794B459442F628ULL,
		0xC17A2788E4BA31A6ULL,
		0xDBD6848411D327A3ULL,
		0xF75BDBD83BC2A01FULL,
		0xAB0375FB20829B9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C9329865DD2F646ULL,
		0xE32628EB8EBA42F4ULL,
		0x9242B01C624215EDULL,
		0x8DB91E1E097B73D6ULL,
		0x8A1CC265F5EA3567ULL,
		0x141DD25B69E101B2ULL,
		0x847D2697401D069FULL,
		0xBF381631AC41A0FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x79C9470B18091D36ULL,
		0x127F5DCDCCE781D8ULL,
		0x6961C487059428AFULL,
		0x94C02D278AC78252ULL,
		0x375D6522EECFFC3EULL,
		0xC7B8B228A7F225F1ULL,
		0x72DEB540FBA59980ULL,
		0xEBCB5FC97440FAA1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x096F96058687EA8DULL,
		0xA864CEDD81D7024FULL,
		0xAB5952EC568739D7ULL,
		0x829AA44842C82477ULL,
		0x087C340D799AA9C4ULL,
		0x313645A6F466F0B0ULL,
		0x541C3473B8F04D91ULL,
		0xB869D2A4D1057911ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8615331B04C8E597ULL,
		0x1D2EF11A2ECCA36DULL,
		0xE55EBC8732951B44ULL,
		0xDED2CB0E9D3D7420ULL,
		0xEE19D49DBE664D46ULL,
		0x1576B7F285AA054DULL,
		0x050BB8F561A6741FULL,
		0x7745CFB02785A627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x835A62EA81BF04F6ULL,
		0x8B35DDC3530A5EE1ULL,
		0xC5FA966523F21E93ULL,
		0xA3C7D939A58AB056ULL,
		0x1A625F6FBB345C7DULL,
		0x1BBF8DB46EBCEB62ULL,
		0x4F107B7E5749D972ULL,
		0x412402F4A97FD2EAULL
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
		0xB72875E59E3737BEULL,
		0xFB3E974F3B8D09D2ULL,
		0xAD240CB6288A99D2ULL,
		0xEAB3B8D6B00E5840ULL,
		0xFA90DC1F307DE5E1ULL,
		0x72B6ECD181B5AA42ULL,
		0xF661D9DECFAA8BD8ULL,
		0xABA26C4250C38AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F3054B404ACBA7FULL,
		0xBDE192E941E5CABAULL,
		0x8FE3C9C84B6738C0ULL,
		0x26446CDB7D7F2EF4ULL,
		0xA081ECDD068F37A2ULL,
		0x9B6BC64291806B1CULL,
		0x2763E336100A2D34ULL,
		0xE47EC95B2BB184C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F82131998A7D3FULL,
		0x3D5D0465F9A73F18ULL,
		0x1D4042EDDD236112ULL,
		0xC46F4BFB328F294CULL,
		0x5A0EEF4229EEAE3FULL,
		0xD74B268EF0353F26ULL,
		0xCEFDF6A8BFA05EA3ULL,
		0xC723A2E72512062EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF91726A289C67802ULL,
		0xCD9FE913340AA95CULL,
		0xFBFEC349F08A4EFAULL,
		0xFA3897507569DD38ULL,
		0x5B3687A13F8249F9ULL,
		0xC59DADB5C718C088ULL,
		0x9F5E5EC5AA4452AFULL,
		0xE7555260D32C9389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A3D494196739AE6ULL,
		0x39F52C45E4052BF3ULL,
		0x31FE6F36E013ED90ULL,
		0xCE7504A05D5669ADULL,
		0x8BB1AF0133A5B4D7ULL,
		0xCB032B18C9317CF0ULL,
		0x877C30B2C5026F86ULL,
		0x95DC2F9B45454E5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6ED9DD60F352DD1CULL,
		0x93AABCCD50057D69ULL,
		0xCA0054131076616AULL,
		0x2BC392B01813738BULL,
		0xCF84D8A00BDC9522ULL,
		0xFA9A829CFDE74397ULL,
		0x17E22E12E541E328ULL,
		0x517922C58DE7452AULL
	}};
	sign = 0;
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
		0x2D68153CDFAEA88EULL,
		0x26F8B73F34EA5124ULL,
		0xBA47D24204EF1F29ULL,
		0xACDC78DBDF948D5FULL,
		0x80AF557D37736E4BULL,
		0x5E8E3E6DBAE943C1ULL,
		0x78E7228C67594735ULL,
		0xBAF6C5C0FC9B7F19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB6892E57E6DDCC4ULL,
		0xA05F56558456F533ULL,
		0x3EF44CD87FF670E0ULL,
		0x31B1D9C7205132D6ULL,
		0x7F5E98F0E9529D34ULL,
		0x5C49787E4A6BB111ULL,
		0x5558601B438F94F9ULL,
		0x22E642613E78C233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51FF82576140CBCAULL,
		0x869960E9B0935BF0ULL,
		0x7B53856984F8AE48ULL,
		0x7B2A9F14BF435A89ULL,
		0x0150BC8C4E20D117ULL,
		0x0244C5EF707D92B0ULL,
		0x238EC27123C9B23CULL,
		0x9810835FBE22BCE6ULL
	}};
	sign = 0;
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
		0xA92299030E8659F1ULL,
		0x8C448B815E1FBFAAULL,
		0x09F0CEC13C43CB1EULL,
		0xAA8A9EBF110C72FEULL,
		0x818226BF08A8A4A4ULL,
		0xE00E5C55727841DAULL,
		0xEEC029C4EC151809ULL,
		0xB6DBBA6D895E176DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCECE2B2A2E7D95C0ULL,
		0x9B91301387724201ULL,
		0xCEB17BBB59C668F0ULL,
		0x32E507ED503A3EB0ULL,
		0x0A2E493BBC70EF34ULL,
		0xFC4B498C60615159ULL,
		0x428F88F5FF4197DEULL,
		0x3B4BBF886B9486B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA546DD8E008C431ULL,
		0xF0B35B6DD6AD7DA8ULL,
		0x3B3F5305E27D622DULL,
		0x77A596D1C0D2344DULL,
		0x7753DD834C37B570ULL,
		0xE3C312C91216F081ULL,
		0xAC30A0CEECD3802AULL,
		0x7B8FFAE51DC990B5ULL
	}};
	sign = 0;
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
		0x1294EBB94722E164ULL,
		0xE372C5F84F034BD5ULL,
		0xDF8701D7E22DFDA6ULL,
		0xCBB08CEDC725272CULL,
		0xA5F4E205D4E3BFF7ULL,
		0xAC86A2053ED59505ULL,
		0x2EC2347C55227251ULL,
		0x55C90218BBA41602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5472DF8C7B251F7ULL,
		0xF0285A6CE3E28442ULL,
		0x66E6B2FC8056DA44ULL,
		0x3776C7A991C85DEDULL,
		0xF802232765CE4FF0ULL,
		0xD761912CD03D4765ULL,
		0x306E4ECD03565FF2ULL,
		0xD373ECE8C70429C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D4DBDC07F708F6DULL,
		0xF34A6B8B6B20C792ULL,
		0x78A04EDB61D72361ULL,
		0x9439C544355CC93FULL,
		0xADF2BEDE6F157007ULL,
		0xD52510D86E984D9FULL,
		0xFE53E5AF51CC125EULL,
		0x8255152FF49FEC38ULL
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
		0x59B7FA3667863845ULL,
		0x9F61D30B29E7E991ULL,
		0x33E7995BD85144B1ULL,
		0x01741EC70F111A50ULL,
		0xAF613C5FA9CA6CCDULL,
		0x171ADE3B3C6708A9ULL,
		0xFB1F415FBE35F4B3ULL,
		0xA491F0FA46C3D93DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB699048E04DDC28ULL,
		0xFDA51EAED95DD679ULL,
		0xC3AB3A2BFA9F0784ULL,
		0x2592A9BEE27548EBULL,
		0x5562E9F29822EB21ULL,
		0x26D58025893DB127ULL,
		0x7597FEBDAB3DDD0DULL,
		0xDA006F6CBF2F024EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5E4E69ED87385C1DULL,
		0xA1BCB45C508A1317ULL,
		0x703C5F2FDDB23D2CULL,
		0xDBE175082C9BD164ULL,
		0x59FE526D11A781ABULL,
		0xF0455E15B3295782ULL,
		0x858742A212F817A5ULL,
		0xCA91818D8794D6EFULL
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
		0xB06AA7CB5AAADABDULL,
		0x47EA9935A63749A9ULL,
		0x74018FFCF21BC437ULL,
		0x81999CADD4295D3DULL,
		0x29951BB1D4FFCDF1ULL,
		0x2FDC505CF97B783CULL,
		0x7B3B88E5D097D215ULL,
		0xB3CFF5B1C49E5B8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x767A4E450FF99153ULL,
		0x1BFD38F6DF0AAF46ULL,
		0x5BCBB367AD600C76ULL,
		0x48AE63842EA5139CULL,
		0xE4E8866D9C60A966ULL,
		0xED3DEEEF794C9AF0ULL,
		0x41D622AFE09EB920ULL,
		0xB444E9E044169D4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39F059864AB1496AULL,
		0x2BED603EC72C9A63ULL,
		0x1835DC9544BBB7C1ULL,
		0x38EB3929A58449A1ULL,
		0x44AC9544389F248BULL,
		0x429E616D802EDD4BULL,
		0x39656635EFF918F4ULL,
		0xFF8B0BD18087BE3FULL
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
		0xE120065DFA787785ULL,
		0x715B9DDDAA1D85DDULL,
		0x70A2EDA8741BBF00ULL,
		0x74B9E3A3CCE317FFULL,
		0x72C0E94FCCF20644ULL,
		0xF5171A7942865500ULL,
		0x455032F23EDA5FA8ULL,
		0xDD15B7F8BBFBCCC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD788AEFA35206628ULL,
		0x6B8FA57028FCB81DULL,
		0xAC4A3737867C678FULL,
		0x69780877E126EBE8ULL,
		0x06065A31CA9B4A81ULL,
		0x65E8B7AEE7CB677CULL,
		0x81BB43EFA9F6F94FULL,
		0x6F9942173BD39C19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09975763C558115DULL,
		0x05CBF86D8120CDC0ULL,
		0xC458B670ED9F5771ULL,
		0x0B41DB2BEBBC2C16ULL,
		0x6CBA8F1E0256BBC3ULL,
		0x8F2E62CA5ABAED84ULL,
		0xC394EF0294E36659ULL,
		0x6D7C75E1802830ADULL
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
		0xFE9B76E14707DBEAULL,
		0x0257CA198F3C9A0BULL,
		0x6D762459A5D04A91ULL,
		0x781ED27BBE83CE28ULL,
		0x6FF48F9E65D3E377ULL,
		0xFC26BE163B6728CBULL,
		0x9D98AEFBB9C939ECULL,
		0xD809D4704602512FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA425732D52E0D774ULL,
		0x33097C8CF796135CULL,
		0x882564538333B1CDULL,
		0xA101465B8652DEDCULL,
		0xC7C99682B1E9E0EAULL,
		0x896CE0501FD52100ULL,
		0x0FF63AFB2B89ED21ULL,
		0x9E81247A58C34468ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A7603B3F4270476ULL,
		0xCF4E4D8C97A686AFULL,
		0xE550C006229C98C3ULL,
		0xD71D8C203830EF4BULL,
		0xA82AF91BB3EA028CULL,
		0x72B9DDC61B9207CAULL,
		0x8DA274008E3F4CCBULL,
		0x3988AFF5ED3F0CC7ULL
	}};
	sign = 0;
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
		0x7EA9C81A6B068EACULL,
		0xFF49AB7EB4D341C7ULL,
		0xDD8085A096933B61ULL,
		0x80B0D68F68DFB403ULL,
		0xE839E91131C36D27ULL,
		0x0B2369D26DFF1E8BULL,
		0x93747157C72502E3ULL,
		0x3D75035221B5C6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1067FA13385A38CULL,
		0x304AB960A55F5EA3ULL,
		0xEABCA4AB40331F92ULL,
		0x2F5F763F5D79A7AFULL,
		0x58E36BA0CE814D9BULL,
		0x5B276ACA03154F6CULL,
		0x433B725E2F358387ULL,
		0x150CAA8FFB88789AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA348793780EB20ULL,
		0xCEFEF21E0F73E323ULL,
		0xF2C3E0F556601BCFULL,
		0x515160500B660C53ULL,
		0x8F567D7063421F8CULL,
		0xAFFBFF086AE9CF1FULL,
		0x5038FEF997EF7F5BULL,
		0x286858C2262D4E55ULL
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
		0x06E4B2A2AAF8092DULL,
		0xF6A06A68155E0382ULL,
		0x2E7BE8AD74FE4F90ULL,
		0xA8805C382D361931ULL,
		0xF25C1A5CEBD6C09EULL,
		0xDEC3FCBFCDD381F4ULL,
		0xBD561FD78C548298ULL,
		0x13279F212C322BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EDE5751419201FULL,
		0x3E8B6FA4FF812564ULL,
		0x4F6994D06B9FB2A9ULL,
		0x91AC283789B01B10ULL,
		0x72A1CB4926D3A1BFULL,
		0xB0886B6182CFD806ULL,
		0x606CC0FADAF35699ULL,
		0xB03A60423902ECB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32F6CD2D96DEE90EULL,
		0xB814FAC315DCDE1DULL,
		0xDF1253DD095E9CE7ULL,
		0x16D43400A385FE20ULL,
		0x7FBA4F13C5031EDFULL,
		0x2E3B915E4B03A9EEULL,
		0x5CE95EDCB1612BFFULL,
		0x62ED3EDEF32F3F3DULL
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
		0xBFD48E71D980B04CULL,
		0xB0FA77C5BC59D7E9ULL,
		0xE2873A4DFE907FFEULL,
		0xF904022F696867C2ULL,
		0x032BE328B86B924CULL,
		0x783D40E9518BF36BULL,
		0x2B6E22EA524B3FDFULL,
		0x82DE5F7420195F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E48DA14A1E9ACBCULL,
		0x34DB8FCD5B3BACB5ULL,
		0x52F73CE303931219ULL,
		0x88278369E7503B6BULL,
		0x943DE1C6B390BF2AULL,
		0x44EC9C251D08B58DULL,
		0xFDBB483D921C1B8DULL,
		0xDB78CDE0ADE282B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x818BB45D37970390ULL,
		0x7C1EE7F8611E2B34ULL,
		0x8F8FFD6AFAFD6DE5ULL,
		0x70DC7EC582182C57ULL,
		0x6EEE016204DAD322ULL,
		0x3350A4C434833DDDULL,
		0x2DB2DAACC02F2452ULL,
		0xA76591937236DC77ULL
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
		0xE1EB648759E71B2EULL,
		0xD8E41439AC26848FULL,
		0x8D17F6F603A58C5EULL,
		0x33CE000E8115B1EAULL,
		0xC408AD940E2FF4CDULL,
		0xE1B3004180D9ED68ULL,
		0xA9F99F496E8A5C56ULL,
		0x290C55D2C9632E97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F650AD9829F6DEULL,
		0x9ECFC5A57E180B57ULL,
		0x03201BD8DDC95BCCULL,
		0x4440FC63A886325DULL,
		0x27BC2C2D04636EBCULL,
		0x261719C21DBD1B41ULL,
		0xBA577878C89B3951ULL,
		0xC15883986F288881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9F513D9C1BD2450ULL,
		0x3A144E942E0E7938ULL,
		0x89F7DB1D25DC3092ULL,
		0xEF8D03AAD88F7F8DULL,
		0x9C4C816709CC8610ULL,
		0xBB9BE67F631CD227ULL,
		0xEFA226D0A5EF2305ULL,
		0x67B3D23A5A3AA615ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFE9792787E10B8C1ULL,
		0x17A4630B09C109A9ULL,
		0xFC674D2A2D39EB06ULL,
		0x13463E917AC35367ULL,
		0xF1E84F3B93E25AF4ULL,
		0x9A5852C58A42D89CULL,
		0x7484FA57446ADCCCULL,
		0x594009868E5267AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5781E035402AE6C6ULL,
		0xC2B9978A7D2EE7C7ULL,
		0xD44814B0DB1788A3ULL,
		0xF2DDB59E1AC2F663ULL,
		0x84BC74982E9F576FULL,
		0xAA43535F05C163A0ULL,
		0x426909D93295BE34ULL,
		0xC61441C650371C17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA715B2433DE5D1FBULL,
		0x54EACB808C9221E2ULL,
		0x281F387952226262ULL,
		0x206888F360005D04ULL,
		0x6D2BDAA365430384ULL,
		0xF014FF66848174FCULL,
		0x321BF07E11D51E97ULL,
		0x932BC7C03E1B4B93ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x381EEDCBC04933E0ULL,
		0xDE7FC0CFD283748CULL,
		0x4E25CAB0CE14D686ULL,
		0x1E308A328494336CULL,
		0x335EE6CF8F6161DEULL,
		0x548778ED74396A35ULL,
		0x4A011C3E254A584AULL,
		0xCB9EF0671DA09E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB909A1D9C141ADCULL,
		0xDD23B78E3104FBF2ULL,
		0x8D79438B412FE719ULL,
		0xFD64D9A1195704C3ULL,
		0x6736315C84E83C38ULL,
		0xE3AD46AF549A94CFULL,
		0x9FE00357430AB78AULL,
		0xBDB302427F003CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8E53AE24351904ULL,
		0x015C0941A17E7899ULL,
		0xC0AC87258CE4EF6DULL,
		0x20CBB0916B3D2EA8ULL,
		0xCC28B5730A7925A5ULL,
		0x70DA323E1F9ED565ULL,
		0xAA2118E6E23FA0BFULL,
		0x0DEBEE249EA061C6ULL
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
		0x0A6D5AB7081E7934ULL,
		0x5B88B5CA93941325ULL,
		0x27ED02A99DE6606AULL,
		0x0B08359A85049B99ULL,
		0xB19880E4122918F6ULL,
		0x4BD3F91586311844ULL,
		0xF4542D88578BFCF3ULL,
		0x7F2FA7013123451DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26C60DD47255CB43ULL,
		0x1031DC644E6D39A1ULL,
		0xAF0D3763CA0094D4ULL,
		0xF6E35B3BC5CD443CULL,
		0x65D19E0BA4DF3CF1ULL,
		0x88800D5995A9775FULL,
		0xF54EBC4FEE2997D4ULL,
		0xC77D86DDE7A25C7EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3A74CE295C8ADF1ULL,
		0x4B56D9664526D983ULL,
		0x78DFCB45D3E5CB96ULL,
		0x1424DA5EBF37575CULL,
		0x4BC6E2D86D49DC04ULL,
		0xC353EBBBF087A0E5ULL,
		0xFF0571386962651EULL,
		0xB7B220234980E89EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCC9940DE27A84E01ULL,
		0x5B7928F6D3383CB8ULL,
		0x1C6A24C6F64CD7D1ULL,
		0xAF50335173075FBCULL,
		0x8999D599DE794868ULL,
		0xA4E728440F51D313ULL,
		0x01CB49EE19308972ULL,
		0xAEBA04B63F6C786BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x771392CA52AF43ECULL,
		0x6B0C5595672FDEAFULL,
		0x535F6034C6C37001ULL,
		0xF35953F7B895FBB6ULL,
		0x5E8B063FA5A8C81BULL,
		0x19033FC4F40DD483ULL,
		0x535A8F359F509704ULL,
		0x700A054DC11F6819ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5585AE13D4F90A15ULL,
		0xF06CD3616C085E09ULL,
		0xC90AC4922F8967CFULL,
		0xBBF6DF59BA716405ULL,
		0x2B0ECF5A38D0804CULL,
		0x8BE3E87F1B43FE90ULL,
		0xAE70BAB879DFF26EULL,
		0x3EAFFF687E4D1051ULL
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
		0x6D80DFCAA070BC60ULL,
		0x5BBA17C9CB0FEE82ULL,
		0x2E38AA6147039015ULL,
		0x7EECD797BF16CFF4ULL,
		0x6EFDB45431BDFD05ULL,
		0xF23581C7698AD608ULL,
		0xE61120451B29B112ULL,
		0x9F7774DC30D7FB23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55D3D598242B5E8BULL,
		0x95626BB559EB247AULL,
		0xEC83D171C9FA031CULL,
		0xCB70BED66C5C5B75ULL,
		0x5D233F56C129C92BULL,
		0x3DF9E9C2EFF352D8ULL,
		0x5F841EC3FC62CF37ULL,
		0xE279B1EB13CF80EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17AD0A327C455DD5ULL,
		0xC657AC147124CA08ULL,
		0x41B4D8EF7D098CF8ULL,
		0xB37C18C152BA747EULL,
		0x11DA74FD709433D9ULL,
		0xB43B980479978330ULL,
		0x868D01811EC6E1DBULL,
		0xBCFDC2F11D087A36ULL
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
		0x4B8B943AF8428069ULL,
		0x6EA9333180616CC5ULL,
		0x014C2068B16CE699ULL,
		0x6E6DAFC6EDBF7765ULL,
		0x897D77EB985EB943ULL,
		0xF0CEFA60C93FB08FULL,
		0x69E96046E72D39EDULL,
		0x182C5499ED59F1C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A11E524FA3313FULL,
		0x34FAD70AC3ED0C5AULL,
		0x44E17528A7BA4CF5ULL,
		0xBF11DB2196D009F1ULL,
		0xAEF907957312FE5AULL,
		0xEA4E0482C1D9386AULL,
		0x710B896C593E9F3CULL,
		0x32F69DECBA00A508ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44EA75E8A89F4F2AULL,
		0x39AE5C26BC74606BULL,
		0xBC6AAB4009B299A4ULL,
		0xAF5BD4A556EF6D73ULL,
		0xDA847056254BBAE8ULL,
		0x0680F5DE07667824ULL,
		0xF8DDD6DA8DEE9AB1ULL,
		0xE535B6AD33594CBDULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x41440D3F145B0BC3ULL,
		0x7985C08678D47F2AULL,
		0xE26E9223FED855A3ULL,
		0x70FC616ED3DC9163ULL,
		0xB5865254C67D7761ULL,
		0x50BC1D9BCB2BBBE9ULL,
		0x634073ED01DDD8B3ULL,
		0x98D210501339ED93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D262517E42E89EBULL,
		0x8A6712FC6E0970D3ULL,
		0x8940E9291509162DULL,
		0xCC2F0383E6720637ULL,
		0x6B27EE62B3344A40ULL,
		0xD4C7DF45AFAEA3A6ULL,
		0xBA57EC9962620BB0ULL,
		0x9675F3094AB1DC77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x341DE827302C81D8ULL,
		0xEF1EAD8A0ACB0E57ULL,
		0x592DA8FAE9CF3F75ULL,
		0xA4CD5DEAED6A8B2CULL,
		0x4A5E63F213492D20ULL,
		0x7BF43E561B7D1843ULL,
		0xA8E887539F7BCD02ULL,
		0x025C1D46C888111BULL
	}};
	sign = 0;
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
		0x11806A8A0ADB21E7ULL,
		0xBAA2EDE876A634EFULL,
		0x67011745B0D078F1ULL,
		0x1D79891F9E41F61EULL,
		0xF48BDF02E132B541ULL,
		0x4ABFE0F1477FFFD3ULL,
		0x99E833A3CE0D597CULL,
		0x74D014521749CDEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B217FDEE739C10ULL,
		0x015C2EBEDDAF0DCEULL,
		0xF57DE82BEC2E08CCULL,
		0xADCD4710CFFAB5B5ULL,
		0x4837CBF915723548ULL,
		0x70EA716D4A456151ULL,
		0x4F3F723EA5C504CFULL,
		0x8B4A137EA5D6A820ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFCE528C1C6785D7ULL,
		0xB946BF2998F72720ULL,
		0x71832F19C4A27025ULL,
		0x6FAC420ECE474068ULL,
		0xAC541309CBC07FF8ULL,
		0xD9D56F83FD3A9E82ULL,
		0x4AA8C165284854ACULL,
		0xE98600D3717325CAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC7DE595D241CD423ULL,
		0xAA5A73E73875360BULL,
		0x5511835D866183B0ULL,
		0x6236F9584350115AULL,
		0xE023A01F0F61901EULL,
		0x220B5467070F7491ULL,
		0x71C0854C4EF18852ULL,
		0x20266FE32DCD8F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC10A822103F618F0ULL,
		0x8CA59579D5E0A8F8ULL,
		0xC190B60A666D53CBULL,
		0x1EFCD1AF356CDD6BULL,
		0x9CFA3A9C3AFB8140ULL,
		0xEC3E91BC61D89BE9ULL,
		0x878DF89CD5EA8EF1ULL,
		0x10513733A5EE8A88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06D3D73C2026BB33ULL,
		0x1DB4DE6D62948D13ULL,
		0x9380CD531FF42FE5ULL,
		0x433A27A90DE333EEULL,
		0x43296582D4660EDEULL,
		0x35CCC2AAA536D8A8ULL,
		0xEA328CAF7906F960ULL,
		0x0FD538AF87DF04F7ULL
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
		0x464D84346D29403AULL,
		0xE2FDC40BA94EA8DCULL,
		0x3E5140FC3A160E5BULL,
		0x617081B6A60028BDULL,
		0x3166F2CD2DB32A6DULL,
		0xB30AF6330137D9A3ULL,
		0x29161C1BFE35D8E9ULL,
		0xB6C928C2FB991122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD79F81E4BDAAC3DBULL,
		0x1312E5DCCD842EAAULL,
		0x4EDE0F93722173F3ULL,
		0x6F921A3EB05E5E78ULL,
		0x15E20F9530210607ULL,
		0x3ED4CAF5173944E6ULL,
		0x135DD5B6B62B6B86ULL,
		0xD8FFB5C7C2B655B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EAE024FAF7E7C5FULL,
		0xCFEADE2EDBCA7A31ULL,
		0xEF733168C7F49A68ULL,
		0xF1DE6777F5A1CA44ULL,
		0x1B84E337FD922465ULL,
		0x74362B3DE9FE94BDULL,
		0x15B84665480A6D63ULL,
		0xDDC972FB38E2BB72ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xAD39FF3F9587AC71ULL,
		0x51F16C9754D0348DULL,
		0xA5DA19DFF886CC12ULL,
		0x51D3436B780CF081ULL,
		0xD0AA76FE7BD374F0ULL,
		0xFDBA951F0A9884ECULL,
		0xF7A4964098A6DD34ULL,
		0x09BF094E30315415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC96ACCA00921AC13ULL,
		0x6D071299B2B83424ULL,
		0x9D94723353150D50ULL,
		0xE471AC0A05EE316DULL,
		0xDB76D75F2C93467BULL,
		0x0A22617C3926B9B3ULL,
		0xC62A09F6D5C69F43ULL,
		0x19D2772036383276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3CF329F8C66005EULL,
		0xE4EA59FDA2180068ULL,
		0x0845A7ACA571BEC1ULL,
		0x6D619761721EBF14ULL,
		0xF5339F9F4F402E74ULL,
		0xF39833A2D171CB38ULL,
		0x317A8C49C2E03DF1ULL,
		0xEFEC922DF9F9219FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x84AFDEE1705301E3ULL,
		0x9E622FC51C4734EDULL,
		0x3994AB2B50DF2136ULL,
		0x9E8B58BF88BE5B32ULL,
		0xA1502950F7EAFB46ULL,
		0xEA4258E0D5491204ULL,
		0x739509C26B27A1C9ULL,
		0x29C4113218335A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A45B4BD924ED65ULL,
		0x6EA529733A046660ULL,
		0x6F54C01FADF849C3ULL,
		0xB075E6A9AE319BE5ULL,
		0x57DBBA4CA7C5DCEAULL,
		0x57D399C3D6F55C40ULL,
		0x5C019B228F0AD010ULL,
		0x46203F7A87F65E2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE0B8395972E147EULL,
		0x2FBD0651E242CE8CULL,
		0xCA3FEB0BA2E6D773ULL,
		0xEE157215DA8CBF4CULL,
		0x49746F0450251E5BULL,
		0x926EBF1CFE53B5C4ULL,
		0x17936E9FDC1CD1B9ULL,
		0xE3A3D1B7903CFC2EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0D8FABA3D5F91ADCULL,
		0xAFDF61DF2DC24326ULL,
		0x48912E0B8F6BE56BULL,
		0x8BDFE6E155238C77ULL,
		0x8701FC7EC9A091CFULL,
		0x5617D4F9658ED8BFULL,
		0x569C95ACAFAD2EFAULL,
		0xDB9F750AB5E5BEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D36AF6DC525C80ULL,
		0x85A726EFB5122A71ULL,
		0x76B6B8D75D232985ULL,
		0x669164115AEBD762ULL,
		0x582A54B753815853ULL,
		0x06E51C3F5B858711ULL,
		0x94B3C56DAA033037ULL,
		0xE754A5F9DF53B5E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7BC40ACF9A6BE5CULL,
		0x2A383AEF78B018B4ULL,
		0xD1DA75343248BBE6ULL,
		0x254E82CFFA37B514ULL,
		0x2ED7A7C7761F397CULL,
		0x4F32B8BA0A0951AEULL,
		0xC1E8D03F05A9FEC3ULL,
		0xF44ACF10D69208F7ULL
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
		0x0416E7CF8F551E9FULL,
		0x873DA0449C8DDC7FULL,
		0x2991CA21FABB6103ULL,
		0xE8870A8B732BB33AULL,
		0xD4AD0F675DF242E6ULL,
		0x6B54A8211FF52D35ULL,
		0x5E551D5A559147BCULL,
		0x2230454C691DB882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DC698481EC756C6ULL,
		0xD0C25453FD285C62ULL,
		0x320E31386560F28FULL,
		0xBE63AF0202BF1B85ULL,
		0x20815D1BFDE20677ULL,
		0xD11BAA0D5E21F99EULL,
		0xBDFF7A6EE3FEB407ULL,
		0xB17F878E6A403DFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x66504F87708DC7D9ULL,
		0xB67B4BF09F65801CULL,
		0xF78398E9955A6E73ULL,
		0x2A235B89706C97B4ULL,
		0xB42BB24B60103C6FULL,
		0x9A38FE13C1D33397ULL,
		0xA055A2EB719293B4ULL,
		0x70B0BDBDFEDD7A87ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xFF3075CFC92A2C83ULL,
		0xF666EC89E3E3A02CULL,
		0xA7AD213D6AA9865BULL,
		0x4A56D383990EC457ULL,
		0x03D08AF442A45FF4ULL,
		0xE8A24775D40D0C61ULL,
		0x2980E1131AE61519ULL,
		0xBA6C89B12ADADD19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C4ECEB5D66D7E3ULL,
		0xB435377A1EE71FD0ULL,
		0x51F96B56DD826A73ULL,
		0xEBBA01A1187B8680ULL,
		0xB31AE84DDBFF917AULL,
		0x2AE3D4E34BB48E88ULL,
		0xAABD70F8486B1F29ULL,
		0xF1BC01370E9A8348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA6B88E46BC354A0ULL,
		0x4231B50FC4FC805CULL,
		0x55B3B5E68D271BE8ULL,
		0x5E9CD1E280933DD7ULL,
		0x50B5A2A666A4CE79ULL,
		0xBDBE729288587DD8ULL,
		0x7EC3701AD27AF5F0ULL,
		0xC8B0887A1C4059D0ULL
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
		0xFD24704977A90D40ULL,
		0xFDAA9FC7C79FA9ECULL,
		0xD9E621CB1D90D863ULL,
		0xB50C986A249CC39BULL,
		0x7700473DBA46E279ULL,
		0x38FD3ED860E8B82AULL,
		0x5C6D0A2C1D13C250ULL,
		0xC9540F8468A866EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665237DE900FEFAEULL,
		0xA98379069C9BA39AULL,
		0x7B28595043451E9BULL,
		0x1C41882B00A5C5E8ULL,
		0xEC2614C3F87EE177ULL,
		0xF52163A39F24D59DULL,
		0xB548690CA7207E2FULL,
		0x6F1B0EBB1D40DF6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96D2386AE7991D92ULL,
		0x542726C12B040652ULL,
		0x5EBDC87ADA4BB9C8ULL,
		0x98CB103F23F6FDB3ULL,
		0x8ADA3279C1C80102ULL,
		0x43DBDB34C1C3E28CULL,
		0xA724A11F75F34420ULL,
		0x5A3900C94B67877DULL
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
		0x42EC75B2CC396EC8ULL,
		0xFBCF87CCC607D1D6ULL,
		0x79618DA609AF0C87ULL,
		0x031893C5F867D110ULL,
		0x3A273569D01174E9ULL,
		0x49D43298D62932A1ULL,
		0x27EFEF29A6C09725ULL,
		0xF9BA594ACA97CEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC20CDC2496100E97ULL,
		0x6BBB0381592E9D92ULL,
		0x91922D91EE4E12C9ULL,
		0xBCB7D0EA9E4EF987ULL,
		0x58279D268B0FE80BULL,
		0x249DC7E71E875775ULL,
		0xAE42920E84B91302ULL,
		0xAFA44E604AD56201ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80DF998E36296031ULL,
		0x9014844B6CD93443ULL,
		0xE7CF60141B60F9BEULL,
		0x4660C2DB5A18D788ULL,
		0xE1FF984345018CDDULL,
		0x25366AB1B7A1DB2BULL,
		0x79AD5D1B22078423ULL,
		0x4A160AEA7FC26CB0ULL
	}};
	sign = 0;
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
		0xAA4DE3CC0EE25B9EULL,
		0xD93CAFB15D632523ULL,
		0x4890A76A037282E1ULL,
		0x098AD1DDEEB78521ULL,
		0xA5F436E5F09ABF3FULL,
		0x9823D55E0D40D267ULL,
		0x1284EED1FE8E0947ULL,
		0xF74F8CD885AB6974ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA429736C55FAB3CULL,
		0xED3DA1B9ED344151ULL,
		0x82B5B7A2980FB5C6ULL,
		0xD8C7E40FEA59E1B0ULL,
		0xA8145C9E065E08F9ULL,
		0x4DB26F9C92042764ULL,
		0x5A7343712EC80721ULL,
		0xCB6B6B0BFBB73238ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF00B4C954982B062ULL,
		0xEBFF0DF7702EE3D1ULL,
		0xC5DAEFC76B62CD1AULL,
		0x30C2EDCE045DA370ULL,
		0xFDDFDA47EA3CB645ULL,
		0x4A7165C17B3CAB02ULL,
		0xB811AB60CFC60226ULL,
		0x2BE421CC89F4373BULL
	}};
	sign = 0;
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
		0x1B53D8D16D47286EULL,
		0xEE3FB24636E47419ULL,
		0x9015CE2F3E1B71E3ULL,
		0xC8D9EA1979D19E99ULL,
		0x137B3564F99A690CULL,
		0x6D3157BCCD9A4F74ULL,
		0xDDB5E19617DE1ED3ULL,
		0x43948DC7AF89798DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2F356AF9BDF80EEULL,
		0xF62EF875E229E780ULL,
		0xCECFDA45B3F3F407ULL,
		0x9F1EEF597CED36DFULL,
		0xC22233CE5E07A780ULL,
		0x00B27E848C375CEFULL,
		0x3CAFF9717B520635ULL,
		0xB384D7105BFC2409ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28608221D167A780ULL,
		0xF810B9D054BA8C98ULL,
		0xC145F3E98A277DDBULL,
		0x29BAFABFFCE467B9ULL,
		0x515901969B92C18CULL,
		0x6C7ED9384162F284ULL,
		0xA105E8249C8C189EULL,
		0x900FB6B7538D5584ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA2DE494CAB64DC53ULL,
		0x1FED66CF7A2511B9ULL,
		0xCC99BF07538E20E2ULL,
		0x8C66EE33920EB19BULL,
		0xA229E36B92A8AFADULL,
		0xC23A6B52ED9293D8ULL,
		0x41F53D8D780CA4C2ULL,
		0xCE0BC138D7E2DCE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF2B75C3E4CFEFDFULL,
		0x99F6ADCD6DBA863BULL,
		0xF78CC9FD942CC350ULL,
		0x1E490759DE8E3D05ULL,
		0x917999802E4AE708ULL,
		0x72EC962A6DF96822ULL,
		0xA3E643DF57157943ULL,
		0xB508A8DABDA59DCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3B2D388C694EC74ULL,
		0x85F6B9020C6A8B7DULL,
		0xD50CF509BF615D91ULL,
		0x6E1DE6D9B3807495ULL,
		0x10B049EB645DC8A5ULL,
		0x4F4DD5287F992BB6ULL,
		0x9E0EF9AE20F72B7FULL,
		0x1903185E1A3D3F15ULL
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
		0xA84FF5651F6E4830ULL,
		0x18A228986E291D34ULL,
		0x3FA74D5506429F0BULL,
		0x2456C8DCF1FEC469ULL,
		0x27EF23630EBAA4F0ULL,
		0x9DB4AFFF4B55CF58ULL,
		0x4EB76CA1F6542EF1ULL,
		0x5BC1B9512189673EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C53F22DE44E8F1ULL,
		0xFA3AA8F110243328ULL,
		0x4FED9CFE0DF23C99ULL,
		0x9C16B9186F8550DDULL,
		0x7F7006E2621F5430ULL,
		0xF64CBD5971835B1CULL,
		0xA8EAF1DAD5FECA9BULL,
		0xA6453A8C09C30832ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD48AB64241295F3FULL,
		0x1E677FA75E04EA0BULL,
		0xEFB9B056F8506271ULL,
		0x88400FC48279738BULL,
		0xA87F1C80AC9B50BFULL,
		0xA767F2A5D9D2743BULL,
		0xA5CC7AC720556455ULL,
		0xB57C7EC517C65F0BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xDD9E271459330F61ULL,
		0xDE4986723DA08013ULL,
		0xA8B51632D7260FA9ULL,
		0x999FF4971CD8995AULL,
		0x0ACBF8123407C096ULL,
		0x80896CDB150CBF3EULL,
		0x70079CD43DDE4BA9ULL,
		0xE62F7B72A6275E8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB753AB6BA5548CULL,
		0x70519BE77E88A11CULL,
		0x4D7B625BCB7C062CULL,
		0xE60622E5D6B56076ULL,
		0xE959562CD26F3D72ULL,
		0x8D9C142AB9C9B88DULL,
		0x28A247A7B38A302EULL,
		0xC804A15940A62297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2E6D368ED8DBAD5ULL,
		0x6DF7EA8ABF17DEF6ULL,
		0x5B39B3D70BAA097DULL,
		0xB399D1B1462338E4ULL,
		0x2172A1E561988323ULL,
		0xF2ED58B05B4306B0ULL,
		0x4765552C8A541B7AULL,
		0x1E2ADA1965813BF3ULL
	}};
	sign = 0;
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
		0xF6E224CBE24759B4ULL,
		0x908472A15F090BE7ULL,
		0xC1386322FC90D674ULL,
		0xE60E1DE7E0B4FE48ULL,
		0x00D29B9B967B8C53ULL,
		0xB7A2F7E6515ACA83ULL,
		0x874303C2C79DBBDDULL,
		0x23B7B6CC9CBC5980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0E48C0AE59234E6ULL,
		0x6D5BB55AFAE2947DULL,
		0xE70AB4C94DD259D0ULL,
		0x2389119AFD086126ULL,
		0xE3CBD1D91EB1E609ULL,
		0x2A1E0AB936AF7F6EULL,
		0xBDBE8AE326FB32F3ULL,
		0x4D294B87B06DF435ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05FD98C0FCB524CEULL,
		0x2328BD466426776AULL,
		0xDA2DAE59AEBE7CA4ULL,
		0xC2850C4CE3AC9D21ULL,
		0x1D06C9C277C9A64AULL,
		0x8D84ED2D1AAB4B14ULL,
		0xC98478DFA0A288EAULL,
		0xD68E6B44EC4E654AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x1366665614BD123FULL,
		0x257B6D495C5DA508ULL,
		0x7F11519A022C127AULL,
		0xD3C0E3AD51FEA7D9ULL,
		0xEC6340D1A1897612ULL,
		0x5FA53B6C742273C9ULL,
		0x13E66F34384020C1ULL,
		0x574A29301D0A5AC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73BA3E996CF06272ULL,
		0x0B1CBC7E8A29F9B4ULL,
		0xE59E3BAFE451DC84ULL,
		0xC4E0B85711FE7006ULL,
		0x48EE67D3C3A6B629ULL,
		0x0F18B3AB1850A2BFULL,
		0x11863FF72A928862ULL,
		0xB61CF42B4CAE142BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FAC27BCA7CCAFCDULL,
		0x1A5EB0CAD233AB53ULL,
		0x997315EA1DDA35F6ULL,
		0x0EE02B56400037D2ULL,
		0xA374D8FDDDE2BFE9ULL,
		0x508C87C15BD1D10AULL,
		0x02602F3D0DAD985FULL,
		0xA12D3504D05C469DULL
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
		0x403F2CF29F224720ULL,
		0x2240C5CE3FAE5454ULL,
		0x988AF9A10BAA0ADDULL,
		0x50C412FCECE6E442ULL,
		0x32DD4FA99651D41CULL,
		0xC74AE31C0C730EFDULL,
		0xEEDDF84692E3A278ULL,
		0x6A869A702CB794C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA4CDD9544ADD47ULL,
		0x793C048CA6E2DD77ULL,
		0x32A60579E4B8BC55ULL,
		0x2E8782CE08367795ULL,
		0xEFC9C4FDF32E6C1EULL,
		0x34818DDDA944AF86ULL,
		0x0B39152A50FFD2BAULL,
		0x9BF4AEC5B85F8A67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x649A5F194AD769D9ULL,
		0xA904C14198CB76DCULL,
		0x65E4F42726F14E87ULL,
		0x223C902EE4B06CADULL,
		0x43138AABA32367FEULL,
		0x92C9553E632E5F76ULL,
		0xE3A4E31C41E3CFBEULL,
		0xCE91EBAA74580A61ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9063BEDD635DBE47ULL,
		0x79C1AE4B94A11CE3ULL,
		0x16088E094DA8AE2EULL,
		0x72C8E35135AE6790ULL,
		0x893A23AD25A488DFULL,
		0x3FFB60ED9DFF1151ULL,
		0x608841F4CC1F81AAULL,
		0x905CAD1949F66265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DA60849C054B1D9ULL,
		0x572376D2899A9CBEULL,
		0x22DAE07672CDDAB5ULL,
		0x4EA855AED6C16FEFULL,
		0x78829B956E8BA08EULL,
		0x387DB635057FA01BULL,
		0xB584D36D611A9697ULL,
		0x204AA5CA22CDA160ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52BDB693A3090C6EULL,
		0x229E37790B068025ULL,
		0xF32DAD92DADAD379ULL,
		0x24208DA25EECF7A0ULL,
		0x10B78817B718E851ULL,
		0x077DAAB8987F7136ULL,
		0xAB036E876B04EB13ULL,
		0x7012074F2728C104ULL
	}};
	sign = 0;
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
		0x9DF6D463B8F1DEC9ULL,
		0xB026FFBD632E4248ULL,
		0xA5F6715870C7B17FULL,
		0x8625278E5FD51BCCULL,
		0x4A62F2E631DA72C2ULL,
		0x2C8614FBE6B21CBCULL,
		0x38038058852CDFE5ULL,
		0x09F55D5418059397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ED55CA8B5700D0ULL,
		0x5C092F85EFE2F8E2ULL,
		0x15D31166C31F2185ULL,
		0x400ED19EF2EF9522ULL,
		0xB282D00011710952ULL,
		0xB0A4BD45ADE3C71CULL,
		0xA06BB35AC83E0434ULL,
		0x49B5CC2DF3CFEB51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB097E992D9ADDF9ULL,
		0x541DD037734B4965ULL,
		0x90235FF1ADA88FFAULL,
		0x461655EF6CE586AAULL,
		0x97E022E620696970ULL,
		0x7BE157B638CE559FULL,
		0x9797CCFDBCEEDBB0ULL,
		0xC03F91262435A845ULL
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
		0x7746EE2E799B30C8ULL,
		0x189001EC308C868FULL,
		0xD22441D20153BDD1ULL,
		0xAAE17C603091792CULL,
		0x63FC2909353BDE08ULL,
		0x8FB0AAA4437B4735ULL,
		0x2603E1E763C4DED1ULL,
		0x28F6EB8237A8F4AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F4DEAACE258519ULL,
		0xF8C3ED0D9DFD0D6FULL,
		0x54F5435B86EE106DULL,
		0x60139F8268BCA9FAULL,
		0x9BD683E03E0B694CULL,
		0x97A308617C37E36BULL,
		0x56B65921B5BF35CFULL,
		0xBD0928A93E20117EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5520F83AB75ABAFULL,
		0x1FCC14DE928F791FULL,
		0x7D2EFE767A65AD63ULL,
		0x4ACDDCDDC7D4CF32ULL,
		0xC825A528F73074BCULL,
		0xF80DA242C74363C9ULL,
		0xCF4D88C5AE05A901ULL,
		0x6BEDC2D8F988E32FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x7EB6EE66B408425AULL,
		0xE61B91836533C579ULL,
		0xD8BD0805F2377649ULL,
		0x1E1352D26C941084ULL,
		0x77EE52D17FAD90ECULL,
		0xF230EC1E8FD97DD6ULL,
		0x5EA075A5746A76C5ULL,
		0xC8CB521D70F0A096ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ADEF07A0EFFD530ULL,
		0x56C4BB72B5C96998ULL,
		0xB60A2BAB9B8DB051ULL,
		0x8BAA339096244346ULL,
		0xBBEDEE5777D8E3F0ULL,
		0x1A4CA5C80C82BC35ULL,
		0x73366CD075176F90ULL,
		0x585EA58A52632824ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33D7FDECA5086D2AULL,
		0x8F56D610AF6A5BE1ULL,
		0x22B2DC5A56A9C5F8ULL,
		0x92691F41D66FCD3EULL,
		0xBC00647A07D4ACFBULL,
		0xD7E446568356C1A0ULL,
		0xEB6A08D4FF530735ULL,
		0x706CAC931E8D7871ULL
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
		0x2391B136700A7E05ULL,
		0xAF19819EFA319958ULL,
		0x41EF0CA9C70E2FA2ULL,
		0x20DB45A1622EEF2FULL,
		0x1E38297F81626F02ULL,
		0xDAF73D762EC3C83DULL,
		0xB0137056A25423CAULL,
		0xD16FEBA031416BA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2167FF23B7640CFAULL,
		0xBCA2A23A5F350D59ULL,
		0x0CAEFE2FD33641A3ULL,
		0xF9A0C0CEE477595EULL,
		0xF72C300A7D655371ULL,
		0x2B4DF3B8DEE247B8ULL,
		0x3EB1F5259D8C0695ULL,
		0xE41DE1A78E5BCE78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0229B212B8A6710BULL,
		0xF276DF649AFC8BFFULL,
		0x35400E79F3D7EDFEULL,
		0x273A84D27DB795D1ULL,
		0x270BF97503FD1B90ULL,
		0xAFA949BD4FE18084ULL,
		0x71617B3104C81D35ULL,
		0xED5209F8A2E59D2AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3D4BFBB9375A3EEEULL,
		0xF3873732C01C9826ULL,
		0xFBF0442164F9049AULL,
		0xAEA2EA36D9B10839ULL,
		0xC52670DB2B6254C7ULL,
		0x538C130ACCEB7DD4ULL,
		0x1B000BFDB16683E7ULL,
		0xAF8ED609CD46A737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7594A4113473E9B4ULL,
		0x790F9DCD3873D6D9ULL,
		0xB1F1AE8C4F193296ULL,
		0x882189C63ED66BC2ULL,
		0xF5805A7BFBA0A8EBULL,
		0x2600C7894BCA63ECULL,
		0xF740F61A6EEA5848ULL,
		0x4DA46070DF3F2F8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7B757A802E6553AULL,
		0x7A77996587A8C14CULL,
		0x49FE959515DFD204ULL,
		0x268160709ADA9C77ULL,
		0xCFA6165F2FC1ABDCULL,
		0x2D8B4B81812119E7ULL,
		0x23BF15E3427C2B9FULL,
		0x61EA7598EE0777ACULL
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
		0x2901F4391EBE3BC8ULL,
		0xE874B3A2AFA58AE1ULL,
		0x13196A443240F841ULL,
		0x742C8B7110EAD477ULL,
		0xB6AB1B6FE726885EULL,
		0x4D8F3ACB94451D4EULL,
		0xFB7E58172120508EULL,
		0xEFFA9726F52CC47CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7181B22E3E882833ULL,
		0x3BFCFCFB78FB33FBULL,
		0xEA846F31F7BF7108ULL,
		0x3A2993E2C7B919EFULL,
		0xE8EB8F05D761BF57ULL,
		0x3B7B6D8AB9391A9FULL,
		0xAC28FB06FC687599ULL,
		0xBBEE6DFDB1F75436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB780420AE0361395ULL,
		0xAC77B6A736AA56E5ULL,
		0x2894FB123A818739ULL,
		0x3A02F78E4931BA87ULL,
		0xCDBF8C6A0FC4C907ULL,
		0x1213CD40DB0C02AEULL,
		0x4F555D1024B7DAF5ULL,
		0x340C292943357046ULL
	}};
	sign = 0;
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
		0xFCDC20D4C338FE6BULL,
		0x65F8E481D2498BA0ULL,
		0x84588C314FD4870DULL,
		0xDF89F5765B218020ULL,
		0x5DE71C3339A0A9FDULL,
		0x1DDDD3136D5EDEBEULL,
		0x58653866ED5C2F9DULL,
		0xF8FF42B7D9721E59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A181F79D8D4F94FULL,
		0x252DBB58658A1069ULL,
		0x039915C64FD810FDULL,
		0x29D8823D450717C7ULL,
		0xE29E12D53710BC6BULL,
		0xB3F0DFF53C1F2D79ULL,
		0xA6F048DA5ECB06A0ULL,
		0x85B47AC70047EEDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2C4015AEA64051CULL,
		0x40CB29296CBF7B37ULL,
		0x80BF766AFFFC7610ULL,
		0xB5B17339161A6859ULL,
		0x7B49095E028FED92ULL,
		0x69ECF31E313FB144ULL,
		0xB174EF8C8E9128FCULL,
		0x734AC7F0D92A2F7DULL
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
		0x2549D9153E461708ULL,
		0x3D16DF9BCAEB9793ULL,
		0xBB246416878855A8ULL,
		0xCE7236DCACC31C49ULL,
		0x152D2EB0B86D652AULL,
		0x3124DDC8A65AD074ULL,
		0x1E45BCFD73113272ULL,
		0x0384342294B7BB5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF4AE0892D1AF2DULL,
		0x199A2312A9ED8C93ULL,
		0xFED088A4BD44E7CBULL,
		0x594A55FE6048D0D7ULL,
		0x4034A8EC85197054ULL,
		0x7DBA73B0C0D8BA45ULL,
		0x75C0064A932CD112ULL,
		0x724966742B6555E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC6552B0CAB7467DBULL,
		0x237CBC8920FE0AFFULL,
		0xBC53DB71CA436DDDULL,
		0x7527E0DE4C7A4B71ULL,
		0xD4F885C43353F4D6ULL,
		0xB36A6A17E582162EULL,
		0xA885B6B2DFE4615FULL,
		0x913ACDAE69526575ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x5FB9A17100459D3CULL,
		0x62947C429DF849C5ULL,
		0x3D64603AF1A03803ULL,
		0xFDBAC520CD9658CAULL,
		0xDD7035264C7104C2ULL,
		0xDC47DB478DE97B06ULL,
		0x2770F2892CE5A224ULL,
		0x71F7AFC1EAF72C10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x119D11E6521C4E29ULL,
		0xF78685320BAABA43ULL,
		0x08B46063EEFBAA30ULL,
		0xFAD8845DB2EA181AULL,
		0xFA7B0C0A9BDD95E6ULL,
		0xC237F1C94593C218ULL,
		0x37CE0AFC3F209CCFULL,
		0x22B469D2132763E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E1C8F8AAE294F13ULL,
		0x6B0DF710924D8F82ULL,
		0x34AFFFD702A48DD2ULL,
		0x02E240C31AAC40B0ULL,
		0xE2F5291BB0936EDCULL,
		0x1A0FE97E4855B8EDULL,
		0xEFA2E78CEDC50555ULL,
		0x4F4345EFD7CFC827ULL
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
		0x196F22BAB15D677EULL,
		0xC8E0CAC5D519C29EULL,
		0x88794C8BD8D955F9ULL,
		0xE5B2441CA6D2FFA5ULL,
		0x36336A079F547E9AULL,
		0xC04CCD2716663233ULL,
		0xBDC1E5479E808A6CULL,
		0x3F1DBB7B56BFE78AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E89B3AA11D634BCULL,
		0x979B4D1FF24C38AAULL,
		0x1EC701D6DD3361FEULL,
		0x78BC31AB09AF50A0ULL,
		0x66F7416E9FA3C431ULL,
		0xE9BF9E6393F6E9F8ULL,
		0x712678973DDE0832ULL,
		0x914927CE9E00FE49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9AE56F109F8732C2ULL,
		0x31457DA5E2CD89F3ULL,
		0x69B24AB4FBA5F3FBULL,
		0x6CF612719D23AF05ULL,
		0xCF3C2898FFB0BA69ULL,
		0xD68D2EC3826F483AULL,
		0x4C9B6CB060A28239ULL,
		0xADD493ACB8BEE941ULL
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
		0x3DEDF72220FCD2F8ULL,
		0x76E33F92C758773CULL,
		0xF7A1F036E8680F3BULL,
		0xC90BF947A906FB73ULL,
		0x5E57A8124E07A304ULL,
		0x4C37CC41BC9FB5D0ULL,
		0x108C52F45B59D421ULL,
		0x20F626F1E51D4008ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C24E10636CD15C7ULL,
		0x676054A544AEFFAFULL,
		0x73F5F82F224EF4CEULL,
		0xB050A9FFD9BA9F63ULL,
		0x00BA653601F543FCULL,
		0xEF0480D2814472DCULL,
		0x3277085B90CF9583ULL,
		0x9A4E27D92C1A4A28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1C9161BEA2FBD31ULL,
		0x0F82EAED82A9778CULL,
		0x83ABF807C6191A6DULL,
		0x18BB4F47CF4C5C10ULL,
		0x5D9D42DC4C125F08ULL,
		0x5D334B6F3B5B42F4ULL,
		0xDE154A98CA8A3E9DULL,
		0x86A7FF18B902F5DFULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9B41267930DC16A4ULL,
		0x02DCAB2D0ADC2AECULL,
		0x924328A264FF92DAULL,
		0x9E1D6714638E22E6ULL,
		0xEB9A5C0167865CB1ULL,
		0x3D6053CECBDDF111ULL,
		0x15000DCD6F317CA1ULL,
		0xFD1064A54987ED20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD08121DFEB9D2CD1ULL,
		0x38FD6CE5198CBA64ULL,
		0x750DC9F9D87BA7B6ULL,
		0x080C506625979A75ULL,
		0xBD52A4E3D1B842C3ULL,
		0x46CCC32237973C53ULL,
		0xF9D00AD4150E95E5ULL,
		0xFBB98A509D3F3A1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAC00499453EE9D3ULL,
		0xC9DF3E47F14F7087ULL,
		0x1D355EA88C83EB23ULL,
		0x961116AE3DF68871ULL,
		0x2E47B71D95CE19EEULL,
		0xF69390AC9446B4BEULL,
		0x1B3002F95A22E6BBULL,
		0x0156DA54AC48B301ULL
	}};
	sign = 0;
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
		0x64C67B383F688090ULL,
		0x1D99CBBCE6E18097ULL,
		0x8B7FBB6C063EA3C4ULL,
		0xA86CF3C3663CD1FFULL,
		0x721B0BBA9AC91813ULL,
		0xD72D906C78DF9F19ULL,
		0xFCC62395FE08E6EAULL,
		0x6EDA18B54CC4CE68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52AFF34D6672C620ULL,
		0x2448C18A758E9968ULL,
		0xD358179F92FF64A1ULL,
		0xD9905EC01A3DDA9EULL,
		0xA9E77B26A815176CULL,
		0x01F2129AB193E9E2ULL,
		0x42B9E17B96B0AF22ULL,
		0x14869DD4EB2D590BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x121687EAD8F5BA70ULL,
		0xF9510A327152E72FULL,
		0xB827A3CC733F3F22ULL,
		0xCEDC95034BFEF760ULL,
		0xC8339093F2B400A6ULL,
		0xD53B7DD1C74BB536ULL,
		0xBA0C421A675837C8ULL,
		0x5A537AE06197755DULL
	}};
	sign = 0;
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
		0x6C9D58866EAA9FABULL,
		0xA7D575F4A91C95D0ULL,
		0x2DF5989C596F7637ULL,
		0x7EA80CD65B23AEDBULL,
		0x7057B31A5424C608ULL,
		0x9A4116C662F19B20ULL,
		0x1002E4F2A2CF5FEAULL,
		0x5B117D3B0CD224D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87847272E0B5A469ULL,
		0x5B33923BAD186C96ULL,
		0x138274606BF14E14ULL,
		0x29680F7E75094ABCULL,
		0x97B68CEDE34F49F6ULL,
		0xCBA406BD715CF4D5ULL,
		0xA2533D0D04C1008DULL,
		0x19D320D6F51251DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE518E6138DF4FB42ULL,
		0x4CA1E3B8FC042939ULL,
		0x1A73243BED7E2823ULL,
		0x553FFD57E61A641FULL,
		0xD8A1262C70D57C12ULL,
		0xCE9D1008F194A64AULL,
		0x6DAFA7E59E0E5F5CULL,
		0x413E5C6417BFD2F7ULL
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
		0x5FD25FA76574A912ULL,
		0x9D14796E0FC3FBECULL,
		0x76A985540E1BA04AULL,
		0x0AEF0823B2AA963AULL,
		0x6D9FD2A0F6D33674ULL,
		0x9A8EBE293F047A64ULL,
		0x3F71639F004DEB51ULL,
		0x3B1BC5A6521329CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6219BD8947C14B2CULL,
		0x435F4B37CAB8A69DULL,
		0xFDAACFB407F90384ULL,
		0xFB078019224E2DD6ULL,
		0xAFF183471AA8B1A3ULL,
		0x071B473B2DA727B0ULL,
		0x929CA0DC63B27527ULL,
		0x78FD75940019D1E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDB8A21E1DB35DE6ULL,
		0x59B52E36450B554EULL,
		0x78FEB5A006229CC6ULL,
		0x0FE7880A905C6863ULL,
		0xBDAE4F59DC2A84D0ULL,
		0x937376EE115D52B3ULL,
		0xACD4C2C29C9B762AULL,
		0xC21E501251F957E6ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x887E0FF046D72AC5ULL,
		0xDE00795D58B226BAULL,
		0xDED6A723118D6B3EULL,
		0xB13DF4900383E5FCULL,
		0x22A060F18F96E63BULL,
		0x4D073BF961F25D9DULL,
		0x49D8AB9C974595E5ULL,
		0xF24F4C5C9469D4E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0668B065DD406935ULL,
		0xA5F58632400A7DB7ULL,
		0xDE4E0001CA1857B1ULL,
		0x434504F9810893A3ULL,
		0x45D85FFC28166C5CULL,
		0xC5EA9EBF8965217CULL,
		0xFA210E2A59896436ULL,
		0x3813FB425B5E20C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82155F8A6996C190ULL,
		0x380AF32B18A7A903ULL,
		0x0088A7214775138DULL,
		0x6DF8EF96827B5259ULL,
		0xDCC800F5678079DFULL,
		0x871C9D39D88D3C20ULL,
		0x4FB79D723DBC31AEULL,
		0xBA3B511A390BB41CULL
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
		0xEBD519F650C067E6ULL,
		0x3A889C90CABA85D7ULL,
		0x4E1107278C1021A0ULL,
		0xB998F43BCBB5CFE5ULL,
		0x7C3C613C2BE12D71ULL,
		0x8225406976786D71ULL,
		0xCD2BE1776CE29A3CULL,
		0x33D26EB0907CB144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E42753D21C1B7EULL,
		0x89EC078AA1650B2EULL,
		0xF56A093021C9C39CULL,
		0xEE760B5E175E73C0ULL,
		0xCC939386DA4CDD50ULL,
		0x40ADF0DA75DA70B9ULL,
		0xBD91AC249AB71AD8ULL,
		0xADF5411FBB777969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44F0F2A27EA44C68ULL,
		0xB09C950629557AA9ULL,
		0x58A6FDF76A465E03ULL,
		0xCB22E8DDB4575C24ULL,
		0xAFA8CDB551945020ULL,
		0x41774F8F009DFCB7ULL,
		0x0F9A3552D22B7F64ULL,
		0x85DD2D90D50537DBULL
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
		0x11F4A8E274B98042ULL,
		0xE8D87639775E981EULL,
		0xCB2B725C6B0506B5ULL,
		0xAEBCB8A71477CF09ULL,
		0x90F97AD0E176B777ULL,
		0x39001B6F372972F0ULL,
		0xB948F7252A63CD54ULL,
		0xA9FF35B5703AC694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A2F5715BAB164AULL,
		0xF4CF0C9C9FA93A09ULL,
		0xE3AC105B1F243F8EULL,
		0xD26E5002FDBCB57DULL,
		0xF4294AB7F051E980ULL,
		0x841C91E60E3CDE83ULL,
		0xD1032536325F017EULL,
		0x09D237E7C5CBDE49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C51B371190E69F8ULL,
		0xF409699CD7B55E14ULL,
		0xE77F62014BE0C726ULL,
		0xDC4E68A416BB198BULL,
		0x9CD03018F124CDF6ULL,
		0xB4E3898928EC946CULL,
		0xE845D1EEF804CBD5ULL,
		0xA02CFDCDAA6EE84AULL
	}};
	sign = 0;
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
		0x9225DB495B04F6D6ULL,
		0x576BE47D042DC8A9ULL,
		0x98FC85E1F8A44E68ULL,
		0x92D5927ABA6C3876ULL,
		0xE2FEC0D8B7536AE8ULL,
		0x62FF6AA41D509AF9ULL,
		0x7AC1C627EEA07AF4ULL,
		0x138B94C7E1B42CE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B22C4E516B2D103ULL,
		0x12F5C8609E8C889FULL,
		0x3A324E7F9358E165ULL,
		0xC56358E276C3585BULL,
		0x4F3EC701C978BED5ULL,
		0xAD368DF600A8544FULL,
		0x216FD0A86671CB40ULL,
		0x9D35860DFD81E8F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07031664445225D3ULL,
		0x44761C1C65A1400AULL,
		0x5ECA3762654B6D03ULL,
		0xCD72399843A8E01BULL,
		0x93BFF9D6EDDAAC12ULL,
		0xB5C8DCAE1CA846AAULL,
		0x5951F57F882EAFB3ULL,
		0x76560EB9E43243F1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xCF6445E4C48B4E12ULL,
		0x3FE0B778ABF46B4EULL,
		0x3F59FB5FD8B6C50DULL,
		0x2147EBC5A8DCC4EFULL,
		0xE9BDA6F403BB96C7ULL,
		0x0D55BB95EF303681ULL,
		0x8DFF2278C97D8E2CULL,
		0x8AFACBA559014442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC336155C6457ECF7ULL,
		0xABF27267EBD3E864ULL,
		0xF1E5C767FE48086FULL,
		0xE92ABD47189CB935ULL,
		0x83E8AA638D03B8FFULL,
		0xA5C842CCF6252E40ULL,
		0x765BA21205DF564DULL,
		0x0E8A396E1A9506DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C2E30886033611BULL,
		0x93EE4510C02082EAULL,
		0x4D7433F7DA6EBC9DULL,
		0x381D2E7E90400BB9ULL,
		0x65D4FC9076B7DDC7ULL,
		0x678D78C8F90B0841ULL,
		0x17A38066C39E37DEULL,
		0x7C7092373E6C3D64ULL
	}};
	sign = 0;
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
		0x01BF93EB4156F431ULL,
		0x26E555991D7ED760ULL,
		0xB9E50162CC2F2B6AULL,
		0x259CAE0CE34F415CULL,
		0x8E6174B9FD36FAFCULL,
		0x8678100B8ED3217EULL,
		0xA8DE2AFADDC805DDULL,
		0x02F9C930DA3E2CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81876BD627E3187CULL,
		0x4F9F102114F6C86FULL,
		0x0E48BEC66445D1A6ULL,
		0x499DFEAC57670E42ULL,
		0x55D364F643090539ULL,
		0x2B0AC5BE7805DAC8ULL,
		0xE12C282257547126ULL,
		0x80500BA81D95DB67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x803828151973DBB5ULL,
		0xD746457808880EF0ULL,
		0xAB9C429C67E959C3ULL,
		0xDBFEAF608BE8331AULL,
		0x388E0FC3BA2DF5C2ULL,
		0x5B6D4A4D16CD46B6ULL,
		0xC7B202D8867394B7ULL,
		0x82A9BD88BCA85148ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA3E2D569196BA821ULL,
		0x85FEFC5B461FB3FBULL,
		0xCC98C790866E0E32ULL,
		0xAC60DF7AA35B01F7ULL,
		0xA2D5A0DF40FFBF0BULL,
		0x3ABEA13F430B1997ULL,
		0xBF6368864767DF58ULL,
		0x54C04897796A5DE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF325C2DC26FA4DD8ULL,
		0xB271E222C3AD0EC9ULL,
		0x744711FB3F9AE835ULL,
		0x9E5483AC7483B9EBULL,
		0x26B88BFB6787862AULL,
		0x5062C33EB8C40969ULL,
		0x6712968123376579ULL,
		0xCA8B60A76EB7C487ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0BD128CF2715A49ULL,
		0xD38D1A388272A531ULL,
		0x5851B59546D325FCULL,
		0x0E0C5BCE2ED7480CULL,
		0x7C1D14E3D97838E1ULL,
		0xEA5BDE008A47102EULL,
		0x5850D205243079DEULL,
		0x8A34E7F00AB2995EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x879D6AF0DFF506E9ULL,
		0xA4DA20D613D528FFULL,
		0x93D936C7EC74E8EFULL,
		0xE31A2918B6113764ULL,
		0xA875F5CBD3296D0AULL,
		0xB4A044DC4C67EEABULL,
		0xB8EB0DCC3D21AF16ULL,
		0x0B1E7779F532DC33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5FBAB27ED462AD2ULL,
		0x70557500DB7A5274ULL,
		0xE003922E96F6FBE2ULL,
		0xA4773F07046F4D5FULL,
		0xDD67F1773CE3E6DBULL,
		0xF8F4FD4207DCC0FAULL,
		0x25A9C536BA900FCEULL,
		0xB96B245FD08B28DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1A1BFC8F2AEDC17ULL,
		0x3484ABD5385AD68AULL,
		0xB3D5A499557DED0DULL,
		0x3EA2EA11B1A1EA04ULL,
		0xCB0E04549645862FULL,
		0xBBAB479A448B2DB0ULL,
		0x9341489582919F47ULL,
		0x51B3531A24A7B359ULL
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
		0x24F3976272F95E68ULL,
		0x4D820381FB331CCAULL,
		0x3D4138C8ABAEE323ULL,
		0x75B0B1DC4F1BD727ULL,
		0x10CB1473B132BB06ULL,
		0x68C5858AB5C3A611ULL,
		0xFB09141313E15286ULL,
		0xB05C2DC6F629993AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC48D6193AC1EB71ULL,
		0x3DCC1211CE6055BCULL,
		0xC8AABB378B23040CULL,
		0x8E2037E083EFD50CULL,
		0x535F297E8E8286CAULL,
		0x95BF21BABF984491ULL,
		0x300FE736210CC33FULL,
		0x9B0EC0E2F4A8DBAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28AAC149383772F7ULL,
		0x0FB5F1702CD2C70DULL,
		0x74967D91208BDF17ULL,
		0xE79079FBCB2C021AULL,
		0xBD6BEAF522B0343BULL,
		0xD30663CFF62B617FULL,
		0xCAF92CDCF2D48F46ULL,
		0x154D6CE40180BD8CULL
	}};
	sign = 0;
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
		0xF8D594A3DFE3604BULL,
		0xF73164085D340821ULL,
		0x6DF8914C451840A1ULL,
		0xAE3A89721C93EF4CULL,
		0x24D86B64F430FF9EULL,
		0xACEFF968ED9EEF2BULL,
		0x9025E651E984A4A3ULL,
		0x23E7E8C69D41BAFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC079EE7FEE05F0ULL,
		0xAC0090C17C8A09F7ULL,
		0xDA757218A34C730BULL,
		0xD172111046B577BFULL,
		0x9856D0A1AC588984ULL,
		0x2FAAC39D49138A09ULL,
		0x8CCDEF645B3E6216ULL,
		0x55374F2C8DE824BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29151AB55FF55A5BULL,
		0x4B30D346E0A9FE2AULL,
		0x93831F33A1CBCD96ULL,
		0xDCC87861D5DE778CULL,
		0x8C819AC347D87619ULL,
		0x7D4535CBA48B6521ULL,
		0x0357F6ED8E46428DULL,
		0xCEB0999A0F59963CULL
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
		0x1E152F1C13370655ULL,
		0x92BFAE42A382B038ULL,
		0xACEB56D838D46A74ULL,
		0xD35780139ACA94E8ULL,
		0x70D484F0157C11DEULL,
		0xDE1D553AD162B374ULL,
		0x38F6CA3C65DB8817ULL,
		0xF0B0C62B2646CEC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1F6ABEEEACDB515ULL,
		0x3B44AC025120A752ULL,
		0x14938C250EEA0F8DULL,
		0xF585EE58C3A3ED36ULL,
		0x826B8A8CA90BBF94ULL,
		0x33AEBA857E235049ULL,
		0x8F1597ABCCCC984BULL,
		0xA365C138327CE129ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C1E832D28695140ULL,
		0x577B0240526208E5ULL,
		0x9857CAB329EA5AE7ULL,
		0xDDD191BAD726A7B2ULL,
		0xEE68FA636C705249ULL,
		0xAA6E9AB5533F632AULL,
		0xA9E13290990EEFCCULL,
		0x4D4B04F2F3C9ED96ULL
	}};
	sign = 0;
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
		0x299EB9B4409B46A3ULL,
		0x143F1B7A3E408650ULL,
		0xA2191EBFA8A89E87ULL,
		0xBA7FCCA88FE93AD6ULL,
		0xB4164F62F24714E8ULL,
		0xE485B648979FDFB7ULL,
		0x44460EF0220B2863ULL,
		0x97F891816AEDE72EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1CCD8A5173ADD2AULL,
		0x32C3D3F722236935ULL,
		0x8A2E17E72B44CAA6ULL,
		0x7EE734D5CADCEDC5ULL,
		0x86E44F93328AEBC8ULL,
		0x2DFC2A1BD6A09A25ULL,
		0x08071738FDE93155ULL,
		0xAEB1FD1AB36A4DC5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67D1E10F29606979ULL,
		0xE17B47831C1D1D1AULL,
		0x17EB06D87D63D3E0ULL,
		0x3B9897D2C50C4D11ULL,
		0x2D31FFCFBFBC2920ULL,
		0xB6898C2CC0FF4592ULL,
		0x3C3EF7B72421F70EULL,
		0xE9469466B7839969ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x8E73C893372EA3D5ULL,
		0xF62D4C6BA0C25D46ULL,
		0xB241898DF86C675EULL,
		0xB8FFDA577BE90A0CULL,
		0x22C2DD8F376AB3B8ULL,
		0x92B4CFB09FA6836DULL,
		0xF97FDF0D82C7368DULL,
		0x124644A156A07587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB4320F5C4FC951ULL,
		0x2AFCF487F4CADF0FULL,
		0xE7595DDAC7E8E075ULL,
		0x6B082C1ADF2E8DE3ULL,
		0xD98C9CC683235568ULL,
		0x50D36548A5412630ULL,
		0xB748BE449DDB8B57ULL,
		0x3D316F683D6C74F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3FBF9683DADEDA84ULL,
		0xCB3057E3ABF77E37ULL,
		0xCAE82BB3308386E9ULL,
		0x4DF7AE3C9CBA7C28ULL,
		0x493640C8B4475E50ULL,
		0x41E16A67FA655D3CULL,
		0x423720C8E4EBAB36ULL,
		0xD514D5391934008EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF85D634818C2DCD9ULL,
		0x8BCF25CF51C2A22CULL,
		0xD1D2A45837E1D0CEULL,
		0x70BC8E4E3ED89727ULL,
		0xBE27B2163F104738ULL,
		0x878173DE30C249F0ULL,
		0x4B87152DCFEBD9D7ULL,
		0x8054F609E5360EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A751B870CE31B1FULL,
		0x077870D6E6AF0532ULL,
		0x54686470AE266796ULL,
		0xA5E4468409A17B27ULL,
		0x9740F24EC6A6CE46ULL,
		0xD8DC8E1A924DB330ULL,
		0xF6AD1FE807A09E2FULL,
		0x13EBB423696EEF6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDE847C10BDFC1BAULL,
		0x8456B4F86B139CFAULL,
		0x7D6A3FE789BB6938ULL,
		0xCAD847CA35371C00ULL,
		0x26E6BFC7786978F1ULL,
		0xAEA4E5C39E7496C0ULL,
		0x54D9F545C84B3BA7ULL,
		0x6C6941E67BC71F80ULL
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
		0x0185F117E8E3B630ULL,
		0x4D1770C13D672029ULL,
		0xDFF2A2539327D52DULL,
		0x84315752A2BF578DULL,
		0x61DED01CBC5C858FULL,
		0x325F27B51964C481ULL,
		0x57E201A7E8943755ULL,
		0xF104E0BC1D318A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF6C9771BA4383AULL,
		0x276A6A89D1300D2EULL,
		0x7C055FB230641D2FULL,
		0x6E741CC0637BF509ULL,
		0xBC7866A8E1EB0C57ULL,
		0xB18DEC72C3404D25ULL,
		0xC4193D6CDE54CF10ULL,
		0xB9F99E2E93AB14BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x318F27A0CD3F7DF6ULL,
		0x25AD06376C3712FAULL,
		0x63ED42A162C3B7FEULL,
		0x15BD3A923F436284ULL,
		0xA5666973DA717938ULL,
		0x80D13B425624775BULL,
		0x93C8C43B0A3F6844ULL,
		0x370B428D898675BBULL
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
		0x385744AF49454B83ULL,
		0x9EE6FB489C43A3A2ULL,
		0xFD5528954E454B26ULL,
		0x64F3E43D0075DF80ULL,
		0x6717206B44805034ULL,
		0x14C926A0EE44AE68ULL,
		0xD217D6F30001A3A2ULL,
		0x0DE15C8FA1B532BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88667358F1E544BULL,
		0x2035717EE2F3DD69ULL,
		0x333456AB24A76ABBULL,
		0x037450B1F3B68506ULL,
		0x9B404B54FD969CCBULL,
		0xB08496F43B68C430ULL,
		0xE9F1DEEB376BE03CULL,
		0x918769867C9ABB0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5FD0DD79BA26F738ULL,
		0x7EB189C9B94FC638ULL,
		0xCA20D1EA299DE06BULL,
		0x617F938B0CBF5A7AULL,
		0xCBD6D51646E9B369ULL,
		0x64448FACB2DBEA37ULL,
		0xE825F807C895C365ULL,
		0x7C59F309251A77AFULL
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
		0xB41DB440272A35C0ULL,
		0x1046F376D71C560BULL,
		0xAE5BB972BC889620ULL,
		0x62FD7B4E92A1B857ULL,
		0x423AD8F4529E968EULL,
		0x57F163F4E4D72388ULL,
		0x89970CC1D0006402ULL,
		0xCC52BAF3B2F9DC7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28D5F7812ACED9AFULL,
		0x809E8E80A1651A8BULL,
		0x2F35B069AEB9E1A9ULL,
		0xA102E48879AF680FULL,
		0xF4A40765C2F5B2A6ULL,
		0xD7F1769343A5AEB6ULL,
		0x7CC848DA9C1123ABULL,
		0xA41F8A492A17A3B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B47BCBEFC5B5C11ULL,
		0x8FA864F635B73B80ULL,
		0x7F2609090DCEB476ULL,
		0xC1FA96C618F25048ULL,
		0x4D96D18E8FA8E3E7ULL,
		0x7FFFED61A13174D1ULL,
		0x0CCEC3E733EF4056ULL,
		0x283330AA88E238C8ULL
	}};
	sign = 0;
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
		0x4B48A29A7ACC8DDEULL,
		0x240A7B5CA982E504ULL,
		0xBCBA7DBE80A96957ULL,
		0x8DCCA1C6715C8BE8ULL,
		0xDC55D345D4D595B8ULL,
		0x0A7F72D99B57A2E0ULL,
		0xF94BADD7779D2888ULL,
		0x2AA12CC0344EEBDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF61035972F802671ULL,
		0x387CFDC65BC7B7FFULL,
		0x754F56803093CF4EULL,
		0xED47EBEF6D1DED2AULL,
		0x95C65C616FDCF1F8ULL,
		0x1EE85D80167F8E44ULL,
		0xE47DE827F4390EA8ULL,
		0x4C2AB21984CEAA2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x55386D034B4C676DULL,
		0xEB8D7D964DBB2D04ULL,
		0x476B273E50159A08ULL,
		0xA084B5D7043E9EBEULL,
		0x468F76E464F8A3BFULL,
		0xEB97155984D8149CULL,
		0x14CDC5AF836419DFULL,
		0xDE767AA6AF8041B2ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x324363876DA3C20FULL,
		0x2843CEE1963113D6ULL,
		0x9736AF3BD4604BC2ULL,
		0x728E79DCCA1DB229ULL,
		0x139A9C423FFFF80FULL,
		0xAF9D1B495EA0FAB5ULL,
		0x193F1B5ABE045623ULL,
		0x82C869B4E29C0C1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5B32DF79EFEFDFEULL,
		0x5931BB070838B1A4ULL,
		0x24E011CDA6CF309AULL,
		0xC300D01EC8959967ULL,
		0x7867B2F928A55F2FULL,
		0x50D6567E62725F35ULL,
		0x997A66B426813422ULL,
		0x78B95D26F75C744AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C90358FCEA4C411ULL,
		0xCF1213DA8DF86231ULL,
		0x72569D6E2D911B27ULL,
		0xAF8DA9BE018818C2ULL,
		0x9B32E949175A98DFULL,
		0x5EC6C4CAFC2E9B7FULL,
		0x7FC4B4A697832201ULL,
		0x0A0F0C8DEB3F97D4ULL
	}};
	sign = 0;
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
		0x68DDC8B82CE5780EULL,
		0x1109E2A84B23C4C7ULL,
		0x827C360B09F471D4ULL,
		0x6297AF6D1E389D02ULL,
		0x8003639329F777FDULL,
		0x1CD60A3BB4C76767ULL,
		0x4F7DF263DF674952ULL,
		0xD32AE34E97B833E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD89BBE8B18ABA84FULL,
		0x618E04CF4DEEB42CULL,
		0xCABE671CE4027569ULL,
		0x147116B507A2D336ULL,
		0x2FF01E2D64077D61ULL,
		0x6D336EBF943DAB8BULL,
		0x9E31AC9121A553F0ULL,
		0x40EF7F21479A1C74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90420A2D1439CFBFULL,
		0xAF7BDDD8FD35109AULL,
		0xB7BDCEEE25F1FC6AULL,
		0x4E2698B81695C9CBULL,
		0x50134565C5EFFA9CULL,
		0xAFA29B7C2089BBDCULL,
		0xB14C45D2BDC1F561ULL,
		0x923B642D501E1771ULL
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
		0x0849D7636BAE590BULL,
		0x391C5EBCA42F3A01ULL,
		0x274EBE3F788E3C35ULL,
		0xCFF13CEF44F2415DULL,
		0xC973421F9FCB6552ULL,
		0x85C1C5A6B1C2B8B3ULL,
		0xF877B09EA1D8D071ULL,
		0x13EEA2BD6D79E243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F48E2C18735D740ULL,
		0x224DEDAF597485D8ULL,
		0x06D856E2391D95CCULL,
		0x286140CAC59B1800ULL,
		0x9B73AB6DB6384F3DULL,
		0x3EE1249CD9410494ULL,
		0x240FA0CD1AE7C030ULL,
		0xE71738F7FB33738AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6900F4A1E47881CBULL,
		0x16CE710D4ABAB428ULL,
		0x2076675D3F70A669ULL,
		0xA78FFC247F57295DULL,
		0x2DFF96B1E9931615ULL,
		0x46E0A109D881B41FULL,
		0xD4680FD186F11041ULL,
		0x2CD769C572466EB9ULL
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
		0x88893B68143ACDF1ULL,
		0xFAD3FB820AAE2983ULL,
		0x790D2FF8D6671313ULL,
		0x0C5BD7D387539FB8ULL,
		0x6AA902AFDDFC8F48ULL,
		0xB3902506A37BB2B8ULL,
		0x737A18DC17365C06ULL,
		0x427C5F1062FF9E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72895675545752C5ULL,
		0x1ABE7E0F39BC001CULL,
		0xDDB4EE0594118F0CULL,
		0x373D13EC90144ED2ULL,
		0xFE2EF408D48D362EULL,
		0x8D5B859DED3A8A0DULL,
		0x3D933B5CF724B04DULL,
		0x19A683F5361FE7BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15FFE4F2BFE37B2CULL,
		0xE0157D72D0F22967ULL,
		0x9B5841F342558407ULL,
		0xD51EC3E6F73F50E5ULL,
		0x6C7A0EA7096F5919ULL,
		0x26349F68B64128AAULL,
		0x35E6DD7F2011ABB9ULL,
		0x28D5DB1B2CDFB672ULL
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
		0x5D8A244AA46E673DULL,
		0x448C651257E8A1F4ULL,
		0x5864066B97BF570DULL,
		0x0260D7E595F21AC8ULL,
		0x4CC73663EE74DAC3ULL,
		0xF405A2A131F5B14CULL,
		0x1CD8DCDB255BE5C3ULL,
		0xC879113E82538846ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87E1B77EBD0742D7ULL,
		0x5ADBBC1362122329ULL,
		0xCF73117634A57852ULL,
		0xA40C7146518972FFULL,
		0x9D1599387E3FD553ULL,
		0xB5DBFB767CCFD292ULL,
		0x67552CB3F777B9D2ULL,
		0x39E380098167AE97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD5A86CCBE7672466ULL,
		0xE9B0A8FEF5D67ECAULL,
		0x88F0F4F56319DEBAULL,
		0x5E54669F4468A7C8ULL,
		0xAFB19D2B7035056FULL,
		0x3E29A72AB525DEB9ULL,
		0xB583B0272DE42BF1ULL,
		0x8E95913500EBD9AEULL
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
		0x62647362095669DDULL,
		0xE645FECB07E2BF31ULL,
		0xA91266F4A1F88D80ULL,
		0x1A76F91A308EF650ULL,
		0x3263565C7B9A02ACULL,
		0x3CAB516D2CA23744ULL,
		0x04C5408ECE5B0B55ULL,
		0x35447B827843E8B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECE072AD202830F0ULL,
		0xFB2DDC47A2270867ULL,
		0xDA929253D4FEE7C6ULL,
		0xD24BC888EFB80183ULL,
		0xA624280B3232A8ECULL,
		0xC8AA87815F2DE22AULL,
		0x7D750883C18AEB6DULL,
		0xDBF2B02240FD9654ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x758400B4E92E38EDULL,
		0xEB18228365BBB6C9ULL,
		0xCE7FD4A0CCF9A5B9ULL,
		0x482B309140D6F4CCULL,
		0x8C3F2E51496759BFULL,
		0x7400C9EBCD745519ULL,
		0x8750380B0CD01FE7ULL,
		0x5951CB6037465263ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0F7A67A0E2F739DDULL,
		0x5E52170EE110B387ULL,
		0xB1352D69DAC53EF6ULL,
		0x4A700EB70DB986BFULL,
		0xF06E720039401DCCULL,
		0x4C7981C79BD82955ULL,
		0xA0D6C5B4707493C6ULL,
		0x6E189092DD816B40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E14BC943692E3AAULL,
		0x8705B8203DC18F08ULL,
		0x979379EDAB2304DFULL,
		0x2F94E617345500F0ULL,
		0x678C5E6B567F9D9CULL,
		0x30C623E03AC156CDULL,
		0xFABF95AB7197A11AULL,
		0x0579DB3A93402EE4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9165AB0CAC645633ULL,
		0xD74C5EEEA34F247EULL,
		0x19A1B37C2FA23A16ULL,
		0x1ADB289FD96485CFULL,
		0x88E21394E2C08030ULL,
		0x1BB35DE76116D288ULL,
		0xA6173008FEDCF2ACULL,
		0x689EB5584A413C5BULL
	}};
	sign = 0;
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
		0xA04B91237EDEF3DDULL,
		0xCFDE030B2E838F99ULL,
		0x986CD94C8240442DULL,
		0x88808AC73140FB4DULL,
		0x7E0F6D09433F4278ULL,
		0xFBB632EDE323B240ULL,
		0x7C8FC9F697835879ULL,
		0x5ED050A2F915A37CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4336E84BB5580ACBULL,
		0x346B88CF26846735ULL,
		0x9A98BC95352D8B42ULL,
		0x3C178CB631E616CAULL,
		0x00875A89EAE8FEFAULL,
		0xDB8484E766C1CAA6ULL,
		0x97A5DB16F294B323ULL,
		0x83B2F3944BCD37ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D14A8D7C986E912ULL,
		0x9B727A3C07FF2864ULL,
		0xFDD41CB74D12B8EBULL,
		0x4C68FE10FF5AE482ULL,
		0x7D88127F5856437EULL,
		0x2031AE067C61E79AULL,
		0xE4E9EEDFA4EEA556ULL,
		0xDB1D5D0EAD486BD0ULL
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
		0x225F03D27CCF8593ULL,
		0x97FC71E14B514E4AULL,
		0x20AA1C80A79390D7ULL,
		0x7B6A271F06179933ULL,
		0x4EC11BD96782AE57ULL,
		0x10CBA26814C845A0ULL,
		0x8CF11B369A3953FFULL,
		0x330F7A8B578545E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8310A04938FC2FC8ULL,
		0x11D5BF6992625AA5ULL,
		0x8FDC31D005632CADULL,
		0x20BC98A65169A0D0ULL,
		0xA1C8BDBC1C5C1D86ULL,
		0xBDF28EB3AB0E7090ULL,
		0x21D65EC71578FCF4ULL,
		0x0A71C44DBECED856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F4E638943D355CBULL,
		0x8626B277B8EEF3A4ULL,
		0x90CDEAB0A230642AULL,
		0x5AAD8E78B4ADF862ULL,
		0xACF85E1D4B2690D1ULL,
		0x52D913B469B9D50FULL,
		0x6B1ABC6F84C0570AULL,
		0x289DB63D98B66D8EULL
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
		0xB7CF3AB415787B2FULL,
		0x97A5E9AF2855618CULL,
		0x2C8BAF0A8C3CFFA0ULL,
		0x9125AA6EC17C3A60ULL,
		0x653D48E8319B8454ULL,
		0x65CB13E75BE60595ULL,
		0x853107F33D075965ULL,
		0xC4C95DDE707889C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98294F9476E14994ULL,
		0xBD68CD33A98F9C15ULL,
		0xF269552F28D430EAULL,
		0x4E6C9335C58BAE06ULL,
		0xDA57774AD62DDABFULL,
		0x8E0A22C7BF4DE61CULL,
		0x42DE0962894EFB83ULL,
		0xC9088322F5749798ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FA5EB1F9E97319BULL,
		0xDA3D1C7B7EC5C577ULL,
		0x3A2259DB6368CEB5ULL,
		0x42B91738FBF08C59ULL,
		0x8AE5D19D5B6DA995ULL,
		0xD7C0F11F9C981F78ULL,
		0x4252FE90B3B85DE1ULL,
		0xFBC0DABB7B03F22BULL
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
		0xEC8D993E8ED64B77ULL,
		0xFB8D813707B356EFULL,
		0xC013695E88631A9CULL,
		0x32C6200EB0C3FB32ULL,
		0xEBD8CCE1BB00C9EFULL,
		0xCCDA66F6DB297525ULL,
		0x69B90703480992DDULL,
		0x34AC66B09920A1B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BF923923FD02E74ULL,
		0xD8AA00C956CF87DEULL,
		0x1FD830F85313178AULL,
		0x52DA2E3E64A9D8BDULL,
		0x7A620F69351B24CEULL,
		0x7E156369EAAEF961ULL,
		0xB95FEC08EC0805ADULL,
		0x239E7DEF144D7E07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x509475AC4F061D03ULL,
		0x22E3806DB0E3CF11ULL,
		0xA03B386635500312ULL,
		0xDFEBF1D04C1A2275ULL,
		0x7176BD7885E5A520ULL,
		0x4EC5038CF07A7BC4ULL,
		0xB0591AFA5C018D30ULL,
		0x110DE8C184D323ABULL
	}};
	sign = 0;
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
		0x96F7D1AA5C2C03BCULL,
		0xF471FF9F86337CF9ULL,
		0x6BE6197E1F1642A6ULL,
		0x89CF2558232BEA14ULL,
		0xFBC8FC20CBC274D8ULL,
		0x055FCE258E5AAD10ULL,
		0x5938D99DF8591DE6ULL,
		0x80E3BCA8021C0A57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB04E27F32639230ULL,
		0x646D76EDA23202D3ULL,
		0xC20C93CA1CE18286ULL,
		0x01ACAA5970A95D6CULL,
		0x700EA5413D1A70CEULL,
		0xB66A57B68137C416ULL,
		0x8040FA59C0CECC0EULL,
		0x9CDDD82212E08E7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBF2EF2B29C8718CULL,
		0x900488B1E4017A25ULL,
		0xA9D985B40234C020ULL,
		0x88227AFEB2828CA7ULL,
		0x8BBA56DF8EA8040AULL,
		0x4EF5766F0D22E8FAULL,
		0xD8F7DF44378A51D7ULL,
		0xE405E485EF3B7BDBULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x809BB3E5A2FDCF99ULL,
		0xE763ACC2599A08F7ULL,
		0x4AFC3719899FED5CULL,
		0xB537E291103C93C0ULL,
		0x58BACEB431C89049ULL,
		0x6AD20F424140AD60ULL,
		0x714CEE2DF180A513ULL,
		0x6AAF886A9B03D437ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74EE0A3AA7CE6565ULL,
		0x2B756131F3CCF85AULL,
		0x97D8C08E4A6F391BULL,
		0x06D4AE792DF7352AULL,
		0x4C5615196DCF623EULL,
		0x339720B54F3B5020ULL,
		0x90446A7AA8A57C1BULL,
		0x05948F185223C6DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0BADA9AAFB2F6A34ULL,
		0xBBEE4B9065CD109DULL,
		0xB323768B3F30B441ULL,
		0xAE633417E2455E95ULL,
		0x0C64B99AC3F92E0BULL,
		0x373AEE8CF2055D40ULL,
		0xE10883B348DB28F8ULL,
		0x651AF95248E00D5AULL
	}};
	sign = 0;
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
		0xFC5144E1734B9FAEULL,
		0xFA30621713EFC90FULL,
		0xAC0093FA28EC2DF3ULL,
		0x76783EEC96AAE986ULL,
		0x647D5F01BD1D11F6ULL,
		0xA978425C53189416ULL,
		0x2BA0500428667797ULL,
		0x9C9B2F3B63F399B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5AADB38B59B81E9ULL,
		0x5C3071A908B99C83ULL,
		0x8C401493980132DFULL,
		0x677C70796355B649ULL,
		0xDC889CCCE51F6211ULL,
		0xBF0EF49719E9FB46ULL,
		0xF447A9F2005036FCULL,
		0x5742570E82E6F639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26A669A8BDB01DC5ULL,
		0x9DFFF06E0B362C8CULL,
		0x1FC07F6690EAFB14ULL,
		0x0EFBCE733355333DULL,
		0x87F4C234D7FDAFE5ULL,
		0xEA694DC5392E98CFULL,
		0x3758A6122816409AULL,
		0x4558D82CE10CA37DULL
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
		0xA6887FC8D802301CULL,
		0xD2EC249F1931AF34ULL,
		0xF029386EE261E7E6ULL,
		0x91EE475F17F1CF25ULL,
		0xDCE21F95D6364381ULL,
		0xAAF753133DEB976AULL,
		0x3D6805CA47FE4F3EULL,
		0x437818733F3FBADDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC638EFD179ECADULL,
		0x4DD797F3D3256808ULL,
		0xBAEE0827C4E15DE1ULL,
		0x628A87D5F99A1F8AULL,
		0x152F4D180ADBC6C3ULL,
		0xBB29E39528822D0CULL,
		0x573461C1A76A54DDULL,
		0x1FA1F8F4650C1002ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xABC246D90688436FULL,
		0x85148CAB460C472BULL,
		0x353B30471D808A05ULL,
		0x2F63BF891E57AF9BULL,
		0xC7B2D27DCB5A7CBEULL,
		0xEFCD6F7E15696A5EULL,
		0xE633A408A093FA60ULL,
		0x23D61F7EDA33AADAULL
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
		0x1DA36D7523D93E04ULL,
		0x381B976997815B55ULL,
		0xB9C2BF8995AC9B52ULL,
		0x5F8C5DAEF43903AEULL,
		0x92EEEA559A4F3C76ULL,
		0x258E75BE72A08572ULL,
		0x49DB443C08587ED7ULL,
		0xBEEA9CCFA02D9734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B085D13B4E93E2ULL,
		0x6A716FD086B2526FULL,
		0x83707CB933B75A3EULL,
		0xECC4B2C142900517ULL,
		0x47DFF011CC46A88AULL,
		0x3A879BC141515DCCULL,
		0xFB6F3BDCD3EC9EDAULL,
		0xB25B0BDC70F81B86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3F2E7A3E88AAA22ULL,
		0xCDAA279910CF08E5ULL,
		0x365242D061F54113ULL,
		0x72C7AAEDB1A8FE97ULL,
		0x4B0EFA43CE0893EBULL,
		0xEB06D9FD314F27A6ULL,
		0x4E6C085F346BDFFCULL,
		0x0C8F90F32F357BADULL
	}};
	sign = 0;
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
		0x4D8B75FFE370E6E2ULL,
		0x0498EF053D008CF8ULL,
		0x2C3FC3BD8CB998F0ULL,
		0x6758762F1A8ABC0AULL,
		0x53EB7D7F3F4F37E9ULL,
		0x40A2E518665086B2ULL,
		0x10BF9B6B75E40722ULL,
		0xDB5C6DD3D1842795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A8D65A7B66357B3ULL,
		0x07B4F45A11241A9DULL,
		0xDCAA2BD24DB38112ULL,
		0xBC8970775E24BE69ULL,
		0x2632551D781182E6ULL,
		0x56E29694687C6FF8ULL,
		0xC967B67422A9A5CEULL,
		0x5CF74162B385DF9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2FE10582D0D8F2FULL,
		0xFCE3FAAB2BDC725AULL,
		0x4F9597EB3F0617DDULL,
		0xAACF05B7BC65FDA0ULL,
		0x2DB92861C73DB502ULL,
		0xE9C04E83FDD416BAULL,
		0x4757E4F7533A6153ULL,
		0x7E652C711DFE47F5ULL
	}};
	sign = 0;
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
		0x0C0FDB251F08739DULL,
		0xC9FE5ABDAB545BCCULL,
		0xB535AB3257D35613ULL,
		0x72EEC9214CB94885ULL,
		0x8BAA7D54CA0FE952ULL,
		0x6FE1A6ED4014A1D9ULL,
		0x68CD02CA7BEACA2FULL,
		0x69C95161D0754BA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1818D29FCC87FDULL,
		0xB669C5529D6E4EB3ULL,
		0x3F4F9B480245F58FULL,
		0x807B9F4DA477270FULL,
		0x516555D0DAACAC51ULL,
		0x4F4B12DB8CAD77EEULL,
		0x5954E9F4E41A96A5ULL,
		0xE54DFE3B37FF6C20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1F7C2527F3BEBA0ULL,
		0x1394956B0DE60D18ULL,
		0x75E60FEA558D6084ULL,
		0xF27329D3A8422176ULL,
		0x3A452783EF633D00ULL,
		0x20969411B36729EBULL,
		0x0F7818D597D0338AULL,
		0x847B53269875DF87ULL
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
		0x4583C79D69A59EA5ULL,
		0x1813D670418DEEB1ULL,
		0x6975E51AFD767F98ULL,
		0xAC188BA8AC72BFFBULL,
		0x878E29D26C28C1E2ULL,
		0xD2ABF915C97EED03ULL,
		0xC929F09E3A8C9F85ULL,
		0xBF063CC735B9423BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17F9E4D5172B5774ULL,
		0x8C30645AC13B8071ULL,
		0x004EF91AE96A32E5ULL,
		0x041D80F65F11E161ULL,
		0x2CBFA5339585B549ULL,
		0x5E1A5E307BDDC82FULL,
		0x0DD1A5C896B5C124ULL,
		0x16BF7E53A03AD916ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D89E2C8527A4731ULL,
		0x8BE3721580526E40ULL,
		0x6926EC00140C4CB2ULL,
		0xA7FB0AB24D60DE9AULL,
		0x5ACE849ED6A30C99ULL,
		0x74919AE54DA124D4ULL,
		0xBB584AD5A3D6DE61ULL,
		0xA846BE73957E6925ULL
	}};
	sign = 0;
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
		0x7D75D1D0781EE487ULL,
		0x05445F42486015E8ULL,
		0xC7AA384406C2635AULL,
		0x0B8D4C56830D7006ULL,
		0x32C50A53A881770EULL,
		0x4F32AAED7E15F1C4ULL,
		0xF689811EF0279546ULL,
		0xFEBA33AE5AACE25DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD55F480DFD35CA31ULL,
		0xE307AAF398859F91ULL,
		0x3C04F736E7AA5610ULL,
		0xA01C847F9E60D642ULL,
		0xF88813BB0D8E8349ULL,
		0xDAAF1BB7F5FCF62DULL,
		0x98D686CEE656D453ULL,
		0x55E7CB6255A85C39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA81689C27AE91A56ULL,
		0x223CB44EAFDA7656ULL,
		0x8BA5410D1F180D49ULL,
		0x6B70C7D6E4AC99C4ULL,
		0x3A3CF6989AF2F3C4ULL,
		0x74838F358818FB96ULL,
		0x5DB2FA5009D0C0F2ULL,
		0xA8D2684C05048624ULL
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
		0x93F812B69571EDBAULL,
		0xED2189A98D7E0B47ULL,
		0xE958A7CA2106628EULL,
		0x0BE7CE32666AD5A7ULL,
		0xEEB4495C283E89CCULL,
		0xD12FF4BBD6D30723ULL,
		0x1981E73EB52073A3ULL,
		0xD5519C81A23CA109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB14B40071087B60ULL,
		0x37C605A3EFC02D51ULL,
		0x53BEE60453A9D4F2ULL,
		0x48C70D67657C0157ULL,
		0x37E913CD2ABDD825ULL,
		0x155EE1849CDC0996ULL,
		0x5335E2F5C53B077EULL,
		0x8DB6FBF7088D06FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8E35EB62469725AULL,
		0xB55B84059DBDDDF5ULL,
		0x9599C1C5CD5C8D9CULL,
		0xC320C0CB00EED450ULL,
		0xB6CB358EFD80B1A6ULL,
		0xBBD1133739F6FD8DULL,
		0xC64C0448EFE56C25ULL,
		0x479AA08A99AF9A0CULL
	}};
	sign = 0;
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
		0x15ECF590721E903BULL,
		0xB089344AF43E5887ULL,
		0x6DB23BB2262339FBULL,
		0x87FA54B043631421ULL,
		0x0BF42E66356A82DFULL,
		0x19454C98C583B47DULL,
		0xAFD0D1ADF5C5B512ULL,
		0xE11EEA3FE756B376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E05E6F9568B932ULL,
		0xA4F3E544578A29F2ULL,
		0x79D452C48BF00654ULL,
		0x9BACC362A3E69A7FULL,
		0x1124AA4D1897A858ULL,
		0x69C3568F762F4517ULL,
		0x0E8E68082DDE84A5ULL,
		0x6AE19DB91BA85C5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C0C9720DCB5D709ULL,
		0x0B954F069CB42E94ULL,
		0xF3DDE8ED9A3333A7ULL,
		0xEC4D914D9F7C79A1ULL,
		0xFACF84191CD2DA86ULL,
		0xAF81F6094F546F65ULL,
		0xA14269A5C7E7306CULL,
		0x763D4C86CBAE5717ULL
	}};
	sign = 0;
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
		0x1028D0803CFC7D7AULL,
		0xB48A439C5A258342ULL,
		0x2A186C490E45C26FULL,
		0x00CC8393CDD2EEBBULL,
		0x1EA8916851FD0F1EULL,
		0xF93B12E67FF78922ULL,
		0x887D99AFB3324745ULL,
		0xF205ECB637C9BD36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76672A7BDB4A69F4ULL,
		0xD88518D519E1CF5FULL,
		0xD1B08199395A41F6ULL,
		0x3FA1FDA94E5248B3ULL,
		0x8CCEE233B33FDDE8ULL,
		0x12B836594A7EE71EULL,
		0x4B754D85123532A3ULL,
		0x866B5C53ECC2C857ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x99C1A60461B21386ULL,
		0xDC052AC74043B3E2ULL,
		0x5867EAAFD4EB8078ULL,
		0xC12A85EA7F80A607ULL,
		0x91D9AF349EBD3135ULL,
		0xE682DC8D3578A203ULL,
		0x3D084C2AA0FD14A2ULL,
		0x6B9A90624B06F4DFULL
	}};
	sign = 0;
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
		0xA67815DF35CB6D97ULL,
		0x1FC5D982B5A61E73ULL,
		0x4DEA6520E4FCBE5FULL,
		0xFE71B1CD19544FA7ULL,
		0x32784B1ECB650A23ULL,
		0xF4CE22CB9CAA5E3FULL,
		0xE6F87EC642AEEF32ULL,
		0xA7081D0A047B06A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD986AB5B95FAEBAEULL,
		0x00CB2EA19A81BEB5ULL,
		0x4EFDAAF8F364862DULL,
		0xA6634B80EDA9D823ULL,
		0x4677DFEC7792127CULL,
		0xF72B52227691E521ULL,
		0xD0147442964D4DB4ULL,
		0x96C55B9EB041A3E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCF16A839FD081E9ULL,
		0x1EFAAAE11B245FBDULL,
		0xFEECBA27F1983832ULL,
		0x580E664C2BAA7783ULL,
		0xEC006B3253D2F7A7ULL,
		0xFDA2D0A92618791DULL,
		0x16E40A83AC61A17DULL,
		0x1042C16B543962C4ULL
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
		0x80B0528D48C67CDFULL,
		0x09896509F819B44BULL,
		0x8EA5E4BE244E68E0ULL,
		0xA14BBBDB43FB655EULL,
		0x4244E5AAF8885A23ULL,
		0xE1450047D22CDF58ULL,
		0x33EB9E88F3DE7533ULL,
		0x3C745B45D031A728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x110E34DDAC815AE4ULL,
		0xE86DB56A8E080AF5ULL,
		0x55CF3D627B3706C1ULL,
		0x0DD53D878581F7ABULL,
		0xC83AEE63034ADD62ULL,
		0xB863384347ED304BULL,
		0xE90CBDD21DED7EA4ULL,
		0xE070B7427E0AE46BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FA21DAF9C4521FBULL,
		0x211BAF9F6A11A956ULL,
		0x38D6A75BA917621EULL,
		0x93767E53BE796DB3ULL,
		0x7A09F747F53D7CC1ULL,
		0x28E1C8048A3FAF0CULL,
		0x4ADEE0B6D5F0F68FULL,
		0x5C03A4035226C2BCULL
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
		0x0E821EC1DC13A92FULL,
		0x61D93CCF684DD874ULL,
		0x3442D7B43C079647ULL,
		0x22C70244FFC01509ULL,
		0xA0F41E6A7580572FULL,
		0x7806C8AEB7859F5AULL,
		0x357029F59549D30CULL,
		0xCAE0AE67F08F8773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82E4AF8477DE25D5ULL,
		0xDC8D0537D3DB033DULL,
		0x3FE3296FAC6A03A3ULL,
		0x50F7704C43CDA439ULL,
		0x379FB45387280E47ULL,
		0x02F183B9D3BABD7AULL,
		0x7A90BB254046888DULL,
		0x6F985CA1F2AEA0DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B9D6F3D6435835AULL,
		0x854C37979472D536ULL,
		0xF45FAE448F9D92A3ULL,
		0xD1CF91F8BBF270CFULL,
		0x69546A16EE5848E7ULL,
		0x751544F4E3CAE1E0ULL,
		0xBADF6ED055034A7FULL,
		0x5B4851C5FDE0E694ULL
	}};
	sign = 0;
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
		0x5961EE3527704FE1ULL,
		0x625850DD13A03EEDULL,
		0x3C69D758A43E69C6ULL,
		0xC590620632C858D8ULL,
		0x2EFD1F4D28DB9515ULL,
		0x77B5E3BC3140014DULL,
		0x26BAEFF51FAE40C2ULL,
		0x4EBAD45482BD6DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C6C352A585F04CULL,
		0x9FBF38C45DE83E04ULL,
		0xE9089D3C0199A21EULL,
		0x07C8CA93CA93386CULL,
		0xBF633B46F57C89E4ULL,
		0x546EBAF4A3D257C5ULL,
		0x2A48631C0D5AD0E5ULL,
		0x2B4064D1ED0DA51DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x269B2AE281EA5F95ULL,
		0xC2991818B5B800E9ULL,
		0x53613A1CA2A4C7A7ULL,
		0xBDC797726835206BULL,
		0x6F99E406335F0B31ULL,
		0x234728C78D6DA987ULL,
		0xFC728CD912536FDDULL,
		0x237A6F8295AFC89EULL
	}};
	sign = 0;
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
		0x88CD792A378EF0DBULL,
		0xF340C23B5DC88B8AULL,
		0x17632C595FCA4063ULL,
		0xA0D5E59346EE2E43ULL,
		0x8BE897856CB903E6ULL,
		0xA52F8CCB69448E19ULL,
		0x39A62F1B9CAE622CULL,
		0xB74A4320EF42CE9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD6CFC5B48A2D2DDULL,
		0x4937C536E26D6B88ULL,
		0x7A1CE9FD562E7CD2ULL,
		0x1AADD0A8EBD87F06ULL,
		0x3B74121C50538FC2ULL,
		0xE932FB77EBD13746ULL,
		0x1E80750A6BDB9844ULL,
		0x84B78F6F984969E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB607CCEEEEC1DFEULL,
		0xAA08FD047B5B2001ULL,
		0x9D46425C099BC391ULL,
		0x862814EA5B15AF3CULL,
		0x507485691C657424ULL,
		0xBBFC91537D7356D3ULL,
		0x1B25BA1130D2C9E7ULL,
		0x3292B3B156F964B7ULL
	}};
	sign = 0;
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
		0xB5ACEEA303BCB7D1ULL,
		0x950062467C735F08ULL,
		0x15D29A390553D16CULL,
		0x2E2332F3B0D77C59ULL,
		0x082A1F1A14071EB8ULL,
		0xFB037059465DB0B7ULL,
		0x57E2671E4CFB387CULL,
		0x84E07F6AB8FE4697ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8842593FCDE63343ULL,
		0x6AB2341ACC28C398ULL,
		0x1EF4C63BD20D9280ULL,
		0xEA4C03EBEE1A192DULL,
		0x880B157BEC3B96ACULL,
		0x9385288EECE65EBAULL,
		0xDB81A49B0ED1332FULL,
		0x6920E3C5A11B3E86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D6A956335D6848EULL,
		0x2A4E2E2BB04A9B70ULL,
		0xF6DDD3FD33463EECULL,
		0x43D72F07C2BD632BULL,
		0x801F099E27CB880BULL,
		0x677E47CA597751FCULL,
		0x7C60C2833E2A054DULL,
		0x1BBF9BA517E30810ULL
	}};
	sign = 0;
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
		0x8E8ABFACEEFD815BULL,
		0xEDF141967575D328ULL,
		0x2DDCDD47522B399AULL,
		0x61F3B65193E52390ULL,
		0xA92742A10351467DULL,
		0x514BC29257C732FAULL,
		0xC546E3ACD168FB32ULL,
		0x5A24ACA8FB9712FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3847A0DD8891B893ULL,
		0x2E5F3CBA39D474A8ULL,
		0xD9EF811454270F8FULL,
		0x652499F7CC090669ULL,
		0x0ABFA1BF6E31F0B2ULL,
		0x4E7E37176564B1F8ULL,
		0xBBAAC456D2090274ULL,
		0xE5E57F979F07B172ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56431ECF666BC8C8ULL,
		0xBF9204DC3BA15E80ULL,
		0x53ED5C32FE042A0BULL,
		0xFCCF1C59C7DC1D26ULL,
		0x9E67A0E1951F55CAULL,
		0x02CD8B7AF2628102ULL,
		0x099C1F55FF5FF8BEULL,
		0x743F2D115C8F618BULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x19140554011751E2ULL,
		0xB5839DA2B8DE504FULL,
		0x23AF9EFAAE4A989DULL,
		0x00C37394C085065FULL,
		0xB854A3CBE0E8CF91ULL,
		0x1995FD4140581931ULL,
		0x789B9FB9223A9BE1ULL,
		0x7DD5E77719916318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78E5CA74E066A0AAULL,
		0x9F2E662337FF0DFFULL,
		0xB046A5A2B30324B0ULL,
		0xEB8A7E4B30FCC9F9ULL,
		0x53C84431EF55D77BULL,
		0x298AE802CA3AEBAFULL,
		0xEBA1F30579223659ULL,
		0xF5796764085B52FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA02E3ADF20B0B138ULL,
		0x1655377F80DF424FULL,
		0x7368F957FB4773EDULL,
		0x1538F5498F883C65ULL,
		0x648C5F99F192F815ULL,
		0xF00B153E761D2D82ULL,
		0x8CF9ACB3A9186587ULL,
		0x885C801311361018ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x678FB6F94D44C380ULL,
		0x67EBD84B28036B1DULL,
		0x3A1C75E9FD19B94AULL,
		0x16613BAFF9A6D5D2ULL,
		0xAB134CC0A8DF3448ULL,
		0xAFDFC9E134E5AAA6ULL,
		0x5616ABF7F2D941A0ULL,
		0xF14E1ACD3F9B7873ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C54814CB66398AULL,
		0xDBA0CC7144BE1E33ULL,
		0xFA5F0DC7D9097D8FULL,
		0x0D3AACD619711BC3ULL,
		0x5A0FD2D0BB544E09ULL,
		0x14FCE8F652415D19ULL,
		0xC8B9F7258E7E4E04ULL,
		0xA4728641D0BCFB54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51CA6EE481DE89F6ULL,
		0x8C4B0BD9E3454CEAULL,
		0x3FBD682224103BBAULL,
		0x09268ED9E035BA0EULL,
		0x510379EFED8AE63FULL,
		0x9AE2E0EAE2A44D8DULL,
		0x8D5CB4D2645AF39CULL,
		0x4CDB948B6EDE7D1EULL
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
		0xAD6B6FEEE2EBD4EBULL,
		0x6901A4E27C7689FCULL,
		0x54F6A8F898CDC0A7ULL,
		0x95FCA4967937C95BULL,
		0x8B2B050D787713F6ULL,
		0xF686D07747154C51ULL,
		0x46215F199D0BDBA9ULL,
		0xEDDE84DE73F3B02DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7968EBB9B86FEA08ULL,
		0x81907BA20D11605FULL,
		0x72AA913EC2BADF6EULL,
		0xD4555BFDEF6A91BEULL,
		0x4CC206DBB7177894ULL,
		0xD667901A0B195236ULL,
		0xDBB30F1D2A64A75BULL,
		0x7ADF84E508232043ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x340284352A7BEAE3ULL,
		0xE77129406F65299DULL,
		0xE24C17B9D612E138ULL,
		0xC1A7489889CD379CULL,
		0x3E68FE31C15F9B61ULL,
		0x201F405D3BFBFA1BULL,
		0x6A6E4FFC72A7344EULL,
		0x72FEFFF96BD08FE9ULL
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
		0x5A6E99B1FB242DA8ULL,
		0x761DC4150BB17FB9ULL,
		0x178218E24FB665C8ULL,
		0x12F16917931AE497ULL,
		0x1203E374A27EDCAAULL,
		0xEDCB8725DE37890CULL,
		0xE3B37EB1E7892AE8ULL,
		0xB02A6D2D83F9CA40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x149C15C12AAEDF45ULL,
		0x7AC275A28E5A3037ULL,
		0xCC06EB5342DB4467ULL,
		0x7413857A0446B3E1ULL,
		0x47C0D330CDDA891EULL,
		0x4A39991555C7DE0EULL,
		0x53A9F5D21A7EE600ULL,
		0x7CB83C2435F9AF87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45D283F0D0754E63ULL,
		0xFB5B4E727D574F82ULL,
		0x4B7B2D8F0CDB2160ULL,
		0x9EDDE39D8ED430B5ULL,
		0xCA431043D4A4538BULL,
		0xA391EE10886FAAFDULL,
		0x900988DFCD0A44E8ULL,
		0x337231094E001AB9ULL
	}};
	sign = 0;
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
		0x7432E83BB77187B4ULL,
		0xC7C06EE48872AFDEULL,
		0xAA2B0ACD9D074A16ULL,
		0x54029DEBEBFAF66EULL,
		0xBD264A2785329824ULL,
		0xA850B8D6012E5E82ULL,
		0x75D8FDDE3A6B80E3ULL,
		0xCD36D1B3E85FF050ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x952AB7552DF8BA42ULL,
		0x8F4A907B85B4FAE8ULL,
		0x474BF591A09E3ED2ULL,
		0xD5AAC8013DF2CC61ULL,
		0x6ADE672AD43749C9ULL,
		0x814D95A5714A3436ULL,
		0x96B89A43A8DE581AULL,
		0x3C5D7A3442FAF57FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF0830E68978CD72ULL,
		0x3875DE6902BDB4F5ULL,
		0x62DF153BFC690B44ULL,
		0x7E57D5EAAE082A0DULL,
		0x5247E2FCB0FB4E5AULL,
		0x270323308FE42A4CULL,
		0xDF20639A918D28C9ULL,
		0x90D9577FA564FAD0ULL
	}};
	sign = 0;
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
		0xF9E818AC6EC0BCCDULL,
		0xD3933C73E809AAAFULL,
		0x2F570DD8C3883111ULL,
		0xC2B6E99875EBB7CDULL,
		0x9CCE60DA87FC37C1ULL,
		0x5B54A575DEC09C7BULL,
		0x9915E8B9064CFFC0ULL,
		0xFB347710AB79722BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F59A40BC92EBCCULL,
		0x7DEDB72E1FCE0670ULL,
		0xDFF7B23B589BA5D0ULL,
		0x946C13856F205EC2ULL,
		0x68513EAC88B21628ULL,
		0x75005C46F0A933CAULL,
		0x8586E5519660590AULL,
		0xA7BD59E89E384763ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCFF27E6BB22DD101ULL,
		0x55A58545C83BA43FULL,
		0x4F5F5B9D6AEC8B41ULL,
		0x2E4AD61306CB590AULL,
		0x347D222DFF4A2199ULL,
		0xE654492EEE1768B1ULL,
		0x138F03676FECA6B5ULL,
		0x53771D280D412AC8ULL
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
		0xF1BE10C56443A2A0ULL,
		0x83C94EA981AFEEFDULL,
		0xEC7DD99AF861906AULL,
		0xB779F63F88B2822CULL,
		0x2E35BA9E01E42908ULL,
		0x4DB10F3E43B4631FULL,
		0x78789D2A5F2D9475ULL,
		0xB3363903F3FD74D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0239705A6F2DF9ECULL,
		0xE31E8F0A16AE6E22ULL,
		0xC3657A58D03FB175ULL,
		0xA1295E2DA1E41119ULL,
		0xE289F56EFCD5CA05ULL,
		0xF7C67CAC157CEB62ULL,
		0x0CA7AD9C33FF3FD3ULL,
		0x7911AC7CA54B19DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF84A06AF515A8B4ULL,
		0xA0AABF9F6B0180DBULL,
		0x29185F422821DEF4ULL,
		0x16509811E6CE7113ULL,
		0x4BABC52F050E5F03ULL,
		0x55EA92922E3777BCULL,
		0x6BD0EF8E2B2E54A1ULL,
		0x3A248C874EB25AF6ULL
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
		0xDE8538AFE0ABCEBCULL,
		0x16DF3E5696447252ULL,
		0xBC2BD2FB3EE8176FULL,
		0x1E4AC56038D7C0D7ULL,
		0x8BEAAFA685BA82B2ULL,
		0x51B8299D14F6965DULL,
		0x55CD2C326CECA175ULL,
		0xB466985939949BBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB198053D5CF42D2ULL,
		0x7DF363A46F6916E2ULL,
		0x5798931CD0A3BB4FULL,
		0x8F1D7EC3AEE4C6CFULL,
		0xFFF4C095F5179CAEULL,
		0xD17AD9E31E973D5AULL,
		0xEDE930B101CE5193ULL,
		0x09C57BF691C08E13ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x236BB85C0ADC8BEAULL,
		0x98EBDAB226DB5B70ULL,
		0x64933FDE6E445C1FULL,
		0x8F2D469C89F2FA08ULL,
		0x8BF5EF1090A2E603ULL,
		0x803D4FB9F65F5902ULL,
		0x67E3FB816B1E4FE1ULL,
		0xAAA11C62A7D40DA8ULL
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
		0x9FA45796493D43F7ULL,
		0x3B1ED78989340E5CULL,
		0x8F9AB0E9349D6BB0ULL,
		0xF3FB7AE61EE95AB3ULL,
		0x9A4412465F736BF5ULL,
		0xEB9DD69CDA8341CCULL,
		0x9F44BCC2E0E6A063ULL,
		0x465C31C1412F32A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB397248839BF561BULL,
		0xDFEF355DC935CA53ULL,
		0x0C09B53C82E3008AULL,
		0x43856972E6C6BC7BULL,
		0x7651C76BE845B2B0ULL,
		0xE2BCFD1407199A8EULL,
		0x44CDCA08B95C195AULL,
		0xC6D9FB9312BC3A2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC0D330E0F7DEDDCULL,
		0x5B2FA22BBFFE4408ULL,
		0x8390FBACB1BA6B25ULL,
		0xB076117338229E38ULL,
		0x23F24ADA772DB945ULL,
		0x08E0D988D369A73EULL,
		0x5A76F2BA278A8709ULL,
		0x7F82362E2E72F874ULL
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
		0xA2E0571B81C80F54ULL,
		0x33D8ABDAD61D5F43ULL,
		0x820ABA0E290E1F2CULL,
		0x5EE2B9B940B631FAULL,
		0x2BBFECD02A033080ULL,
		0x8108FF836BBB9DC0ULL,
		0x508F19DEB9139077ULL,
		0xB667D9C8270CFA91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACC297EDA44AB9EEULL,
		0x5780201DCB4E4C4AULL,
		0x821CDD8B954C2E37ULL,
		0x296DF4BA59B9BB0DULL,
		0xF671DE3AC2CC981FULL,
		0xDB6A817789D945AFULL,
		0x6C5C6EA4F37F8C1BULL,
		0xAEB8FD7D1FC023D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF61DBF2DDD7D5566ULL,
		0xDC588BBD0ACF12F8ULL,
		0xFFEDDC8293C1F0F4ULL,
		0x3574C4FEE6FC76ECULL,
		0x354E0E9567369861ULL,
		0xA59E7E0BE1E25810ULL,
		0xE432AB39C594045BULL,
		0x07AEDC4B074CD6B7ULL
	}};
	sign = 0;
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
		0xC17CC44DAAAD9831ULL,
		0x03C4F79C3FF28507ULL,
		0x680D6B527161F2C7ULL,
		0x643F73A6EEB13815ULL,
		0x115EDB1627B6637DULL,
		0xC8675134F715E38EULL,
		0xC61C18A925A51981ULL,
		0x8D195B126EDEEF2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29D167470582F2C1ULL,
		0x81F4842318FB0664ULL,
		0xDCD86FE2CB27D289ULL,
		0xFBED6CA8E279EDE2ULL,
		0x7BA5DE9EC69AFB79ULL,
		0x17DD96276183353AULL,
		0x24A68FC76E914541ULL,
		0x8EE89511E602C727ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97AB5D06A52AA570ULL,
		0x81D0737926F77EA3ULL,
		0x8B34FB6FA63A203DULL,
		0x685206FE0C374A32ULL,
		0x95B8FC77611B6803ULL,
		0xB089BB0D9592AE53ULL,
		0xA17588E1B713D440ULL,
		0xFE30C60088DC2806ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x2F2D6673A4890698ULL,
		0xF9B9AE52267FD0A9ULL,
		0x5258E197D8E6E916ULL,
		0x54F39215A4064491ULL,
		0x534A510C500DB70FULL,
		0x41944F2DF81C0D53ULL,
		0xF352974E2D04C673ULL,
		0xA51CAF5CA9181B44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB057EA3021B7FA2ULL,
		0x569F39E41D94FF44ULL,
		0x198EE2C1035FB06FULL,
		0x48E52475AE34B1F4ULL,
		0xF45BF5EDEED8715DULL,
		0x1B83DAE9F1857F5EULL,
		0x6AB7DBABF8612714ULL,
		0xE2A82C9451BDB10BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7427E7D0A26D86F6ULL,
		0xA31A746E08EAD164ULL,
		0x38C9FED6D58738A7ULL,
		0x0C0E6D9FF5D1929DULL,
		0x5EEE5B1E613545B2ULL,
		0x2610744406968DF4ULL,
		0x889ABBA234A39F5FULL,
		0xC27482C8575A6A39ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x17FEB82408735E80ULL,
		0xBD5012B00028DF53ULL,
		0xD47434AAA73D08A3ULL,
		0x9B696333A0FC3C81ULL,
		0x13D3418A301FFFC3ULL,
		0x46A795009B8FFB6DULL,
		0x884089A89062985DULL,
		0xF28FBE8BACD37630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D6E12A361AC2DBEULL,
		0x89532845402F5F66ULL,
		0x9195A8D6F6435749ULL,
		0x04C0C772A774A7A9ULL,
		0x1AFA1A7EB4EBEB3CULL,
		0xB8E4F4F83D2A9F61ULL,
		0xEAE62E0B8AAEACE6ULL,
		0x7B8CE450892B9C61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA90A580A6C730C2ULL,
		0x33FCEA6ABFF97FECULL,
		0x42DE8BD3B0F9B15AULL,
		0x96A89BC0F98794D8ULL,
		0xF8D9270B7B341487ULL,
		0x8DC2A0085E655C0BULL,
		0x9D5A5B9D05B3EB76ULL,
		0x7702DA3B23A7D9CEULL
	}};
	sign = 0;
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
		0x924FAD34743C0E6BULL,
		0xE17136DFAE36C803ULL,
		0x3AC4948A582C428BULL,
		0x7516D0FB25F30762ULL,
		0x427E98D4BD77C3E9ULL,
		0xF81E5FEC6C4E0F06ULL,
		0x3693E4EC25E17CC1ULL,
		0x163A5D8E750F428FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05C2BD393010BE20ULL,
		0x7461464FB82525FBULL,
		0xCDF38A254C9130F2ULL,
		0xC8E4704AACACC02BULL,
		0xD63BF88E88237ED4ULL,
		0x810E55D849C4FD9DULL,
		0xD94558FE590FDB7FULL,
		0x3D0920C59F7F8DE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C8CEFFB442B504BULL,
		0x6D0FF08FF611A208ULL,
		0x6CD10A650B9B1199ULL,
		0xAC3260B079464736ULL,
		0x6C42A04635544514ULL,
		0x77100A1422891168ULL,
		0x5D4E8BEDCCD1A142ULL,
		0xD9313CC8D58FB4A7ULL
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
		0xC11869B5A04A6E21ULL,
		0xA42C87D2498ECEEAULL,
		0x1BDCAA91D6635F97ULL,
		0x3054C3512CD44664ULL,
		0xB0151E3F029DAA20ULL,
		0x7C3B55FD5BAF6BF4ULL,
		0xB7F64E604E68994EULL,
		0x421F4D1C5FEF3827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80D36D1EFB167174ULL,
		0x5BB02927F139C25BULL,
		0x94A7212D0A2C3D05ULL,
		0x7628860AE43FDDEDULL,
		0x2F62333316BFADBEULL,
		0x02599A9B33C73362ULL,
		0x7EE179A6D4F30509ULL,
		0x24EB4C4B7C4DA901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4044FC96A533FCADULL,
		0x487C5EAA58550C8FULL,
		0x87358964CC372292ULL,
		0xBA2C3D4648946876ULL,
		0x80B2EB0BEBDDFC61ULL,
		0x79E1BB6227E83892ULL,
		0x3914D4B979759445ULL,
		0x1D3400D0E3A18F26ULL
	}};
	sign = 0;
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
		0xE7528DDBA333DC90ULL,
		0xD1A67DCDA886CFACULL,
		0xAC82EDD430273FB4ULL,
		0x73B5F9B556E9428CULL,
		0x86A35D6B68CA38E7ULL,
		0xC458F13886BAC774ULL,
		0xEB6B3ECC9F040196ULL,
		0x365B9B92D8875D70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E41E53C948B97EULL,
		0xA110401447ADF011ULL,
		0x659E0685E0D9CCFAULL,
		0x5FEB45D0C57F42C8ULL,
		0x76EE2EF616030547ULL,
		0xED852D5D2C79B9E5ULL,
		0x760144814E7F5BC4ULL,
		0x5EBDA57494B22AA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE36E6F87D9EB2312ULL,
		0x30963DB960D8DF9BULL,
		0x46E4E74E4F4D72BAULL,
		0x13CAB3E49169FFC4ULL,
		0x0FB52E7552C733A0ULL,
		0xD6D3C3DB5A410D8FULL,
		0x7569FA4B5084A5D1ULL,
		0xD79DF61E43D532CDULL
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
		0x8A07553EE37CDCD5ULL,
		0x8628C3902ADC27C7ULL,
		0xABE6F559F5014CDCULL,
		0x616B8EE163897777ULL,
		0x444EB655D8460352ULL,
		0x26EDC3EBD5169573ULL,
		0xA8CDA2FBBA6748A8ULL,
		0xE1FD6199273D1407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B695ABDCD702224ULL,
		0x878C0BDEDB9DA503ULL,
		0xF718F5EA8ED94BEBULL,
		0xBB2299C8CB365D2AULL,
		0x49AC30657295C6D6ULL,
		0x85C51FD7FAFDA7D7ULL,
		0x635681E30B66AD46ULL,
		0xDBBBFB10A9B64370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E9DFA81160CBAB1ULL,
		0xFE9CB7B14F3E82C4ULL,
		0xB4CDFF6F662800F0ULL,
		0xA648F51898531A4CULL,
		0xFAA285F065B03C7BULL,
		0xA128A413DA18ED9BULL,
		0x45772118AF009B61ULL,
		0x064166887D86D097ULL
	}};
	sign = 0;
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
		0x8DB2CA0C2145832BULL,
		0xB43CDF794E588771ULL,
		0x7032C80F880EF12CULL,
		0xCE08B03FA165C1BCULL,
		0x00B83C877B9D7196ULL,
		0x108783685BD5A548ULL,
		0xC04E146369E901A7ULL,
		0x8C1E25F074416CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE5AFE0485DFF94ULL,
		0x3A00CC74F3C026A7ULL,
		0xB296488023148E59ULL,
		0xCC1DC792F03B782DULL,
		0x82E8B81F45DCD662ULL,
		0x532D1B35BA4D0A85ULL,
		0x1EC1E3F780B5E0A9ULL,
		0x26398EBF9CFB8F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE0CD1A2BD8E78397ULL,
		0x7A3C13045A9860C9ULL,
		0xBD9C7F8F64FA62D3ULL,
		0x01EAE8ACB12A498EULL,
		0x7DCF846835C09B34ULL,
		0xBD5A6832A1889AC2ULL,
		0xA18C306BE93320FDULL,
		0x65E49730D745DD8EULL
	}};
	sign = 0;
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
		0x30C57B16B6D32A44ULL,
		0x7860172AE64EB5E3ULL,
		0x4C9AD385511678BEULL,
		0xD32155B63991DEE4ULL,
		0x551ADF9E895EE5E3ULL,
		0x6496F3ED92621C46ULL,
		0x4ABE4FD20B6167B2ULL,
		0xA2F6D4B46580AEE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x651A27770E6B32CEULL,
		0x3C1777E03919D8E1ULL,
		0x6A761948D648D7A1ULL,
		0xEB50F431424217CCULL,
		0x7D0F767F8EBF4B79ULL,
		0x6E566ECA38C0E31CULL,
		0xBD5F2B2D76FA7432ULL,
		0x91F128A2BEA386F1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBAB539FA867F776ULL,
		0x3C489F4AAD34DD01ULL,
		0xE224BA3C7ACDA11DULL,
		0xE7D06184F74FC717ULL,
		0xD80B691EFA9F9A69ULL,
		0xF640852359A13929ULL,
		0x8D5F24A49466F37FULL,
		0x1105AC11A6DD27F5ULL
	}};
	sign = 0;
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
		0xD860BB524998E04FULL,
		0x7093EC7BCF16D52DULL,
		0x3FE3E79DCDF02CD0ULL,
		0x16C5498BE500BC32ULL,
		0xDC447FBFF887AA1EULL,
		0x77F99D8876EE6A16ULL,
		0x03C81AE584813C00ULL,
		0xB11071126A3404D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB12A527259490D6BULL,
		0xCF703E4E80099F82ULL,
		0x2620C05A719A239FULL,
		0x87F8AD7BF59BE7A5ULL,
		0xC894044B587F7C8AULL,
		0xF0981F1E4EAEB432ULL,
		0x04FF7EAA17729C13ULL,
		0x3C5BC1C2887C045FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x273668DFF04FD2E4ULL,
		0xA123AE2D4F0D35ABULL,
		0x19C327435C560930ULL,
		0x8ECC9C0FEF64D48DULL,
		0x13B07B74A0082D93ULL,
		0x87617E6A283FB5E4ULL,
		0xFEC89C3B6D0E9FECULL,
		0x74B4AF4FE1B80073ULL
	}};
	sign = 0;
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
		0x3BCBE5909CB5E8F9ULL,
		0x9AA478BCE62C4E85ULL,
		0x8901D2AD2EAA8A14ULL,
		0x0A525C8A110420D6ULL,
		0x7344161F71CF6BA0ULL,
		0x4E70CF60F16398D6ULL,
		0x49446339E72AD97EULL,
		0xE0C8E4EA86F4E1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE01C674C5625BA85ULL,
		0x0DBD734DEDCC1AA2ULL,
		0xD7BFD24995082875ULL,
		0x3BBE4A8F5A912A61ULL,
		0x260CA1C5C4EB3A61ULL,
		0x5E18B051AC6948ABULL,
		0x38BC1F49C1416BA0ULL,
		0xFCF5562171545F01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BAF7E4446902E74ULL,
		0x8CE7056EF86033E2ULL,
		0xB142006399A2619FULL,
		0xCE9411FAB672F674ULL,
		0x4D377459ACE4313EULL,
		0xF0581F0F44FA502BULL,
		0x108843F025E96DDDULL,
		0xE3D38EC915A082CAULL
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
		0xA2301573473B75DAULL,
		0xD86A51C626508A56ULL,
		0x21591FD035244C5BULL,
		0x99E44918DA2FAB9EULL,
		0xF1CE95A655A0BAAEULL,
		0xBC5CF79DCD38DAAEULL,
		0xCC97554799BE4359ULL,
		0x442C8CFE222AB5DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6CB9C1737E6E13EULL,
		0xEA75A366AFCD81B9ULL,
		0x385F5E0908234080ULL,
		0x59F5F7C6C7D1C3C2ULL,
		0x239A27CEE3DBFED1ULL,
		0xE47FA2F22FA49302ULL,
		0xCDB8CED5B1D362DEULL,
		0x8D28D5B65F349A54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB64795C0F54949CULL,
		0xEDF4AE5F7683089CULL,
		0xE8F9C1C72D010BDAULL,
		0x3FEE5152125DE7DBULL,
		0xCE346DD771C4BBDDULL,
		0xD7DD54AB9D9447ACULL,
		0xFEDE8671E7EAE07AULL,
		0xB703B747C2F61B89ULL
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
		0xBF1E99D14A9A83C0ULL,
		0x25ECFAC7CB482BC0ULL,
		0x0E90AA1BAB98BD23ULL,
		0x68B7223192313715ULL,
		0x25DE1F705D9C56EFULL,
		0xE73DE8324BD1B0E4ULL,
		0xB9ECBC0D224361A2ULL,
		0xB111AEAAE3D12173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2858AAAD37B606EEULL,
		0x49855E56AF133589ULL,
		0xAC1B4BDD557090BEULL,
		0xBC4B8C849612B3C1ULL,
		0xCE794A40B28D68F2ULL,
		0x808FE9E1406E7C93ULL,
		0x89559D38E22548E3ULL,
		0xCF76BDB87FC695D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96C5EF2412E47CD2ULL,
		0xDC679C711C34F637ULL,
		0x62755E3E56282C64ULL,
		0xAC6B95ACFC1E8353ULL,
		0x5764D52FAB0EEDFCULL,
		0x66ADFE510B633450ULL,
		0x30971ED4401E18BFULL,
		0xE19AF0F2640A8B9CULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0BA899BC19A1BBD3ULL,
		0xE632B6E70C0AC0D0ULL,
		0xAF6363D0CA65E8C6ULL,
		0x014E34FB0859E4FAULL,
		0xDE12152710068AC1ULL,
		0xB333B9490EAEC154ULL,
		0x7279A4DD92A63F73ULL,
		0x33FDA7FA73F987ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF441C3F0D2AE7E71ULL,
		0x3534DF5E630A2BAEULL,
		0x857925BB563A3543ULL,
		0x967D9C3F8DD880B7ULL,
		0x388C8BA91B5AA5CDULL,
		0x4B89E6A4E152F6B5ULL,
		0x3AA6966B2E4871C8ULL,
		0x1A2869C21904A151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1766D5CB46F33D62ULL,
		0xB0FDD788A9009521ULL,
		0x29EA3E15742BB383ULL,
		0x6AD098BB7A816443ULL,
		0xA585897DF4ABE4F3ULL,
		0x67A9D2A42D5BCA9FULL,
		0x37D30E72645DCDABULL,
		0x19D53E385AF4E65AULL
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
		0xB3E0BC2E90A9049AULL,
		0xACAFB66B0D010A63ULL,
		0x370C9DEA68F731BCULL,
		0x24B65560AC0BDF01ULL,
		0x8843C6C77EE2B035ULL,
		0x617B6779EFFB1F38ULL,
		0x76A759FD4770FE8AULL,
		0xAFBC1ECCA1E17D60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934C9400FCC73DAAULL,
		0x93F59547C8A7601CULL,
		0xC6FAF372EFD71D6AULL,
		0x0E3056C6EDFCF851ULL,
		0x3B194FC07ADED46FULL,
		0xBE0B76374CAFD66EULL,
		0xB6CEB89F83656202ULL,
		0x2BE34541BF1F84DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2094282D93E1C6F0ULL,
		0x18BA21234459AA47ULL,
		0x7011AA7779201452ULL,
		0x1685FE99BE0EE6AFULL,
		0x4D2A77070403DBC6ULL,
		0xA36FF142A34B48CAULL,
		0xBFD8A15DC40B9C87ULL,
		0x83D8D98AE2C1F881ULL
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
		0x0A633FA9D8063718ULL,
		0x54DC63F5326FBF89ULL,
		0xA08EC65672E7D8FDULL,
		0x9FC65008382B39F7ULL,
		0xBCF7004DF58E439CULL,
		0x619F10531DF80703ULL,
		0xDC4F26FB026DA45BULL,
		0x2C410AEBD0969267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1984D2A2F9B684EULL,
		0xE33DC2221DCBADDFULL,
		0xB5E8ABDD32A217D2ULL,
		0x183B598CD8B9FB7BULL,
		0x7E6B88F62A876074ULL,
		0x29EB1BBAFA59BF93ULL,
		0xBAEA9B080981B28FULL,
		0xE2925CB2B3ABF79BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28CAF27FA86ACECAULL,
		0x719EA1D314A411A9ULL,
		0xEAA61A794045C12AULL,
		0x878AF67B5F713E7BULL,
		0x3E8B7757CB06E328ULL,
		0x37B3F498239E4770ULL,
		0x21648BF2F8EBF1CCULL,
		0x49AEAE391CEA9ACCULL
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
		0x60D911A200F95C67ULL,
		0x4F637FCC94FF2347ULL,
		0xEBEE98A36DE83330ULL,
		0xA63955F3CCD194D1ULL,
		0x5E061DE4E0AC47A8ULL,
		0xE56EA8BBC3AB293EULL,
		0xADF3E495BC0768FCULL,
		0xC08E26810055557FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4F1990A7756148CULL,
		0x0D1A0155D8DDAED1ULL,
		0x7C37AA35743614C4ULL,
		0xB845E04F9A9976CDULL,
		0xBCD7310F5F7ACDA2ULL,
		0xBB6A08E8E0D523C0ULL,
		0xEE6882AF6CFF14F8ULL,
		0xB8B2913A639CE436ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBE7789789A347DBULL,
		0x42497E76BC217475ULL,
		0x6FB6EE6DF9B21E6CULL,
		0xEDF375A432381E04ULL,
		0xA12EECD581317A05ULL,
		0x2A049FD2E2D6057DULL,
		0xBF8B61E64F085404ULL,
		0x07DB95469CB87148ULL
	}};
	sign = 0;
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
		0x8DC6CFAD7EEB676CULL,
		0x1B177762A893BBD5ULL,
		0x5521497DB5CC6CA5ULL,
		0xE2E9313193AE4035ULL,
		0x733F6DAE97C9F2ABULL,
		0xCE8814819C70429CULL,
		0x1466192F2FD2D41FULL,
		0x1D0FF662F0E91DC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C78E120AA448B4FULL,
		0x451608C2BE2B1B3CULL,
		0x3C2D3557F8B79C68ULL,
		0xC8AC7C014B4310B7ULL,
		0x0641DFE3E16F051FULL,
		0x297659AB191E88DAULL,
		0xE2D9273A63474C97ULL,
		0x3B96316696E4528CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x414DEE8CD4A6DC1DULL,
		0xD6016E9FEA68A099ULL,
		0x18F41425BD14D03CULL,
		0x1A3CB530486B2F7EULL,
		0x6CFD8DCAB65AED8CULL,
		0xA511BAD68351B9C2ULL,
		0x318CF1F4CC8B8788ULL,
		0xE179C4FC5A04CB38ULL
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
		0x362E6219EAEC96ABULL,
		0xE01915C216F3C473ULL,
		0xF9EB8FDDA959C136ULL,
		0x47049CC3EF41714CULL,
		0x8F16F63D402EF732ULL,
		0x351FD847CEEE72C7ULL,
		0xD854E0B54859EFD7ULL,
		0xA4111221608CD9B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0F2BF5E09D2954ULL,
		0x332746301A7654B7ULL,
		0xBC7BC07F0355C536ULL,
		0xAC3721CCA2291378ULL,
		0xD7ED4DDACDFA68F6ULL,
		0xF0AC09D54EF418EFULL,
		0xCB5687174AED3364ULL,
		0xEE63004C3AE85B3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB1F36240A4F6D57ULL,
		0xACF1CF91FC7D6FBBULL,
		0x3D6FCF5EA603FC00ULL,
		0x9ACD7AF74D185DD4ULL,
		0xB729A86272348E3BULL,
		0x4473CE727FFA59D7ULL,
		0x0CFE599DFD6CBC72ULL,
		0xB5AE11D525A47E73ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xA5259FDC1B56B040ULL,
		0xFC3FF2DB11C5B533ULL,
		0x02EEB7D8F9BC62B6ULL,
		0x3D7A3084E3482C5EULL,
		0x997607214BE12314ULL,
		0xE5BA91849014DBC6ULL,
		0x5F218F8C1413B053ULL,
		0x17D64443BE3D81DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4E67D03A8B1139AULL,
		0x1151FDD854DA952EULL,
		0x2D6FD88A95CD9C69ULL,
		0x0C0597AB08B72647ULL,
		0xB2F2651C3281A6D2ULL,
		0x46F030D0F2F947FEULL,
		0xE9C508343EABFE2AULL,
		0x487453E7EF838E41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB03F22D872A59CA6ULL,
		0xEAEDF502BCEB2004ULL,
		0xD57EDF4E63EEC64DULL,
		0x317498D9DA910616ULL,
		0xE683A205195F7C42ULL,
		0x9ECA60B39D1B93C7ULL,
		0x755C8757D567B229ULL,
		0xCF61F05BCEB9F399ULL
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
		0x54E8DEF8CA6C82E6ULL,
		0x298257FB277E155CULL,
		0x2A9CAB8240744768ULL,
		0x9F685863548807A0ULL,
		0xE4C1C8B8354B4DE8ULL,
		0x54EAF881A1B4A12DULL,
		0x8AEB439FEC07B61CULL,
		0x7A94FE224598023FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80391A404EC9712DULL,
		0xA5A9B0AE8E0C4D98ULL,
		0x5BA7774DF545D971ULL,
		0xD415854E6CF562FAULL,
		0x52DBFBDDD53966C4ULL,
		0x43314C87B73A3E83ULL,
		0xDD96A185916445D7ULL,
		0xEA41631123EC4E39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4AFC4B87BA311B9ULL,
		0x83D8A74C9971C7C3ULL,
		0xCEF534344B2E6DF6ULL,
		0xCB52D314E792A4A5ULL,
		0x91E5CCDA6011E723ULL,
		0x11B9ABF9EA7A62AAULL,
		0xAD54A21A5AA37045ULL,
		0x90539B1121ABB405ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x4BE4E1B9FE7C17ECULL,
		0xD992E288B7B5E444ULL,
		0x952D5D1408701D52ULL,
		0x87E137CC204BCA3DULL,
		0xDE1BDA93D7FF5D6BULL,
		0xF0D15E3FBBD5BCFCULL,
		0xE20C97F70CE946EEULL,
		0x6971AB0D91625CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FDB49029A9E68DEULL,
		0xCF58F8FB2AB88D36ULL,
		0xDCAC42C1E2841020ULL,
		0x2CCE700719EE983CULL,
		0x85F06D155C51FFAEULL,
		0x1BCB7601BFEBB0A4ULL,
		0xB9550492A9B887FDULL,
		0x809E2D56C3ECA05AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C0998B763DDAF0EULL,
		0x0A39E98D8CFD570EULL,
		0xB8811A5225EC0D32ULL,
		0x5B12C7C5065D3200ULL,
		0x582B6D7E7BAD5DBDULL,
		0xD505E83DFBEA0C58ULL,
		0x28B793646330BEF1ULL,
		0xE8D37DB6CD75BC86ULL
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
		0x628B6D4DB6CDC663ULL,
		0xF5919D5106433A28ULL,
		0xF9FAD7562C7029FDULL,
		0x14F4F6B32453D93EULL,
		0x1BD184959AD623E9ULL,
		0xFB6A364399A62CB0ULL,
		0x539FE34F0E700A35ULL,
		0x9772D1AE6A98B642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D3473831AB9091ULL,
		0x7C3AA3AFDD9BB11CULL,
		0x9DF50F5F9113E59CULL,
		0x4E0106E93C71FEAEULL,
		0x3903EC5F31B22B67ULL,
		0x39DC477780CC1784ULL,
		0x2D7554BEEB0FDC42ULL,
		0xD9A8D6978DF3CBF5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0B82615852235D2ULL,
		0x7956F9A128A7890BULL,
		0x5C05C7F69B5C4461ULL,
		0xC6F3EFC9E7E1DA90ULL,
		0xE2CD98366923F881ULL,
		0xC18DEECC18DA152BULL,
		0x262A8E9023602DF3ULL,
		0xBDC9FB16DCA4EA4DULL
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
		0xD7C717F954261B96ULL,
		0x6A5B77ED8F724AE8ULL,
		0x4604F7300C017731ULL,
		0xA15E9B7366556878ULL,
		0x61AF6431C9DEE3E6ULL,
		0x81032114CC423160ULL,
		0xD3BAF42629D7BE87ULL,
		0xAEEE639F3A1E9C2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB97D8C21A966C3CULL,
		0x6E33535BBD01AF87ULL,
		0x9A2639CE797CE1DAULL,
		0xD5AC3D683D033BF1ULL,
		0x8889A9066A713A39ULL,
		0xCBC64DAEB3318E62ULL,
		0x100A2850E70E863EULL,
		0x0B55B3C3C30C29B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC2F3F37398FAF5AULL,
		0xFC282491D2709B60ULL,
		0xABDEBD6192849556ULL,
		0xCBB25E0B29522C86ULL,
		0xD925BB2B5F6DA9ACULL,
		0xB53CD3661910A2FDULL,
		0xC3B0CBD542C93848ULL,
		0xA398AFDB77127278ULL
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
		0x402F36908CDB7416ULL,
		0xC28636301D9F221DULL,
		0x25DB873F46147E5BULL,
		0xB2259D17D1116823ULL,
		0x62A3A77F467A491EULL,
		0xA7254BCA496922DEULL,
		0xC3A55FA97D8D0DC4ULL,
		0x6BFE2A3AB279D545ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x483B0077783E79FEULL,
		0xCCFA467E5777A92EULL,
		0x8B952501282B7307ULL,
		0x36E07E9E4AF8AD95ULL,
		0x77458D1242115130ULL,
		0x9327EA2FD56EC7AFULL,
		0x83DB6F8399AEAADAULL,
		0xF3C064209C6D6BA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF7F43619149CFA18ULL,
		0xF58BEFB1C62778EEULL,
		0x9A46623E1DE90B53ULL,
		0x7B451E798618BA8DULL,
		0xEB5E1A6D0468F7EEULL,
		0x13FD619A73FA5B2EULL,
		0x3FC9F025E3DE62EAULL,
		0x783DC61A160C699FULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xADE9057B18CEEB23ULL,
		0x8F814496C697FB47ULL,
		0xF52ED5C67A130667ULL,
		0x7EB1656F76AB44B2ULL,
		0x06AE5BC33205D5C0ULL,
		0x9448878F33CB07EEULL,
		0xCECBE180431C09FFULL,
		0x8D08794FC80D2AAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E48AD0B7A20D57ULL,
		0xCDA72A9D3E794136ULL,
		0x3C1A7AEF14E9EE95ULL,
		0x1CAEA8A9B8C1761DULL,
		0xC1475638D72A0DC1ULL,
		0x1D45C3817777E634ULL,
		0x2458FCA0760E448FULL,
		0xADC68B5BC0A605EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6047AAA612CDDCCULL,
		0xC1DA19F9881EBA11ULL,
		0xB9145AD7652917D1ULL,
		0x6202BCC5BDE9CE95ULL,
		0x4567058A5ADBC7FFULL,
		0x7702C40DBC5321B9ULL,
		0xAA72E4DFCD0DC570ULL,
		0xDF41EDF4076724C1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD6A005961CAB211BULL,
		0xA6AACB18A6B22A26ULL,
		0xAC322134340D03C9ULL,
		0x1E908A840F0ED597ULL,
		0x651C997FA8798DFAULL,
		0x21952B86897C7E1FULL,
		0xFB4890DF1A3226EBULL,
		0x39D7221FA2A81B3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9C702DF50D57588ULL,
		0x20C8E49AD8B51320ULL,
		0xF67B10342480D692ULL,
		0x9E0D55610558F444ULL,
		0xB5C748CC098612EDULL,
		0xA85A58CA9669D79DULL,
		0xC47776B67BCE8C22ULL,
		0xE4D77EB4DF1A0811ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CD902B6CBD5AB93ULL,
		0x85E1E67DCDFD1706ULL,
		0xB5B711000F8C2D37ULL,
		0x8083352309B5E152ULL,
		0xAF5550B39EF37B0CULL,
		0x793AD2BBF312A681ULL,
		0x36D11A289E639AC8ULL,
		0x54FFA36AC38E132EULL
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
		0x31A3546B8F2C12EBULL,
		0xB36C2FA1A7E6E130ULL,
		0xF5347E56ECBD3EF6ULL,
		0x03BF51500491A3B5ULL,
		0x6A7C4ADF68E3FE0FULL,
		0x0E8F57120D8186A6ULL,
		0x83E8948F6FC0299BULL,
		0x1BDA74139B5DB1FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC116265FBC88D84ULL,
		0x9D2BBA2173E2B466ULL,
		0x6A5B698426AC5B74ULL,
		0x4267FA63F9644AA2ULL,
		0x5BAC938AB9AC1EA3ULL,
		0x49467EA723DCFDD8ULL,
		0xBBBB27A04A03AE15ULL,
		0x9E435EFD637FCF99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8591F20593638567ULL,
		0x1640758034042CC9ULL,
		0x8AD914D2C610E382ULL,
		0xC15756EC0B2D5913ULL,
		0x0ECFB754AF37DF6BULL,
		0xC548D86AE9A488CEULL,
		0xC82D6CEF25BC7B85ULL,
		0x7D97151637DDE263ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x3D39AB1FA2858D19ULL,
		0x1F3C72654A6E3B61ULL,
		0x13864EAF2FE5795AULL,
		0xCFC0AD553721A716ULL,
		0x1618F83F2AA25E20ULL,
		0xA8BEC234D40F6C58ULL,
		0xC232026960E7BED8ULL,
		0xC99AF3AF08C1069DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AFEC43A7256A5C4ULL,
		0x22CAF554FA4A9765ULL,
		0xB45CB4B63916588AULL,
		0xA2AD32BC856440E9ULL,
		0xE6BF00379B7A8BAAULL,
		0x018CFB00F7C04E36ULL,
		0xB9297EF26DDCAA9CULL,
		0x4F9D8AE1C08BEEB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB23AE6E5302EE755ULL,
		0xFC717D105023A3FBULL,
		0x5F2999F8F6CF20CFULL,
		0x2D137A98B1BD662CULL,
		0x2F59F8078F27D276ULL,
		0xA731C733DC4F1E21ULL,
		0x09088376F30B143CULL,
		0x79FD68CD483517EAULL
	}};
	sign = 0;
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
		0x3EFA20DF07C1CD62ULL,
		0x40316D293ECFB5C2ULL,
		0x0FC310A09ED54233ULL,
		0x1CF895D5356EEA6CULL,
		0xFF80F846DDF1DCE3ULL,
		0x3FA4179203B4AEFFULL,
		0xF007E0B1A719512DULL,
		0x6A2D81C8C2573F2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5DFEF942B805079ULL,
		0x2BB46E004A27ECB1ULL,
		0xCE74A26C504A9668ULL,
		0x6097E39D7DCC895DULL,
		0x8D19213357BBDC62ULL,
		0x3635A29549A98134ULL,
		0x345C9252C326672BULL,
		0x97A180A66921DC6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x591A314ADC417CE9ULL,
		0x147CFF28F4A7C910ULL,
		0x414E6E344E8AABCBULL,
		0xBC60B237B7A2610EULL,
		0x7267D71386360080ULL,
		0x096E74FCBA0B2DCBULL,
		0xBBAB4E5EE3F2EA02ULL,
		0xD28C0122593562C2ULL
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
		0x64AE6043E031388AULL,
		0x7DFD7ABB802E7067ULL,
		0x8F8610BE2B4E67C1ULL,
		0x28355A18EA146DCEULL,
		0xB0CA750EADF65D26ULL,
		0x68CFCF137A17AB8AULL,
		0xE16A9BC9D6B818C7ULL,
		0x16DF064F1466F5C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x856E82908A5A7428ULL,
		0x37580346777E1315ULL,
		0xF2A117A5EF423FB4ULL,
		0x22F7D15B3E54DDFBULL,
		0x3E9537E4C6462F7CULL,
		0x9D7B78E0205F9998ULL,
		0x7F1C638AF91A1ED3ULL,
		0xAC26F3572F48B27EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF3FDDB355D6C462ULL,
		0x46A5777508B05D51ULL,
		0x9CE4F9183C0C280DULL,
		0x053D88BDABBF8FD2ULL,
		0x72353D29E7B02DAAULL,
		0xCB54563359B811F2ULL,
		0x624E383EDD9DF9F3ULL,
		0x6AB812F7E51E4345ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x0780DD3392EC957BULL,
		0xB3F52FD0D1291561ULL,
		0xCE9D370FA042764DULL,
		0x3318A9CB28BF65EAULL,
		0xE516E4DE62031C14ULL,
		0xB6E62FA5AF990ECEULL,
		0xAF6ACC9B52BE4C2CULL,
		0xF6213E1C1E23F6BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6093A9F6D3CF0538ULL,
		0x91FB592DC10D1458ULL,
		0xEF4B4AAD89A3FC47ULL,
		0x9A52CA140FB93AE9ULL,
		0x4FA3AC824CA33E0FULL,
		0x3EEEB6162D63CDC0ULL,
		0x87E51E0E08411321ULL,
		0xE2A7D159AE61C8C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6ED333CBF1D9043ULL,
		0x21F9D6A3101C0108ULL,
		0xDF51EC62169E7A06ULL,
		0x98C5DFB719062B00ULL,
		0x9573385C155FDE04ULL,
		0x77F7798F8235410EULL,
		0x2785AE8D4A7D390BULL,
		0x13796CC26FC22DFCULL
	}};
	sign = 0;
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
		0xC177C2862224CE28ULL,
		0xDC26E068874DF2D8ULL,
		0x7DB07AA53A18842AULL,
		0x80CE7BF1FD71EC61ULL,
		0xF3A1A6FD5AE2E213ULL,
		0x93475D25D434DBAFULL,
		0xDEC3703F8DA00ABFULL,
		0x0B1D5CAB57DF1C51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC53EF991AE719E9ULL,
		0x6168354314EB6042ULL,
		0x6B549E0B50C73B1CULL,
		0x04789DD187B00A4CULL,
		0x714338C209F36E04ULL,
		0xA78F688537B629EDULL,
		0x8F23B58297967A24ULL,
		0x52B75C4C8017855EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE523D2ED073DB43FULL,
		0x7ABEAB2572629295ULL,
		0x125BDC99E951490EULL,
		0x7C55DE2075C1E215ULL,
		0x825E6E3B50EF740FULL,
		0xEBB7F4A09C7EB1C2ULL,
		0x4F9FBABCF609909AULL,
		0xB866005ED7C796F3ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x12A271DA75E5FAF6ULL,
		0xA41F0E1058AF2E81ULL,
		0x78C9C95166AA67EFULL,
		0x04543A92F911BD6FULL,
		0x2035A169B8BBD31AULL,
		0x7D039109EF255D4AULL,
		0x6ADA517E229DF47EULL,
		0xF6C574C7E404A80FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8772FE18EEE5E85FULL,
		0xCC04873CBDBD48ECULL,
		0x28CF20B68AE6BF0AULL,
		0x3772C4E8ED18C888ULL,
		0x74544BE49A1839CEULL,
		0xC94100F7FFEC4E03ULL,
		0xD91AFF849501F7D7ULL,
		0x79DEDC622A43DF54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B2F73C187001297ULL,
		0xD81A86D39AF1E594ULL,
		0x4FFAA89ADBC3A8E4ULL,
		0xCCE175AA0BF8F4E7ULL,
		0xABE155851EA3994BULL,
		0xB3C29011EF390F46ULL,
		0x91BF51F98D9BFCA6ULL,
		0x7CE69865B9C0C8BAULL
	}};
	sign = 0;
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
		0x56537B50B00AF249ULL,
		0x48B560CB4371E300ULL,
		0xCBFE0768895F2A32ULL,
		0x36C38C4C8F245A96ULL,
		0x67F0FDC69EE185A0ULL,
		0x4DB297BF43927588ULL,
		0x3BB03AE6BD25A9D6ULL,
		0x1FC0841EABC095DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0319DFAC87D0B210ULL,
		0x359D987AE0DC4133ULL,
		0x9A5A48B66EF118A7ULL,
		0x630BBDEBDAE31926ULL,
		0x688D53A644A6A983ULL,
		0xFF8AED4ACAB88407ULL,
		0x4A7FA411DB3B435BULL,
		0x8AF992B68C9546A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53399BA4283A4039ULL,
		0x1317C8506295A1CDULL,
		0x31A3BEB21A6E118BULL,
		0xD3B7CE60B4414170ULL,
		0xFF63AA205A3ADC1CULL,
		0x4E27AA7478D9F180ULL,
		0xF13096D4E1EA667AULL,
		0x94C6F1681F2B4F35ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x61111314BE664D71ULL,
		0x2F8D2A2F56515D86ULL,
		0x1B1DBCD7DD1B0CCDULL,
		0x4286176132C3B65BULL,
		0x7C341411AD8526D0ULL,
		0xBB2BBBF573857AA4ULL,
		0xB474E5BEE3B9F30EULL,
		0x140AECC6C32AEF5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AD6673A9F62C1BULL,
		0x52E0A94CA5B45BAEULL,
		0x44BCE723153A73AEULL,
		0x1BA5FA6EE1D146ECULL,
		0x1F069F9B11C4A1A2ULL,
		0x29CC59B97F8A3505ULL,
		0xA52D7DF1CED4B599ULL,
		0xD77E219188AC2FD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBE63ACA114702156ULL,
		0xDCAC80E2B09D01D7ULL,
		0xD660D5B4C7E0991EULL,
		0x26E01CF250F26F6EULL,
		0x5D2D74769BC0852EULL,
		0x915F623BF3FB459FULL,
		0x0F4767CD14E53D75ULL,
		0x3C8CCB353A7EBF8AULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x9C21D9238FA37382ULL,
		0x3AEF43C477537452ULL,
		0x1254FB582A45B36CULL,
		0x3DDF1ACF17648A53ULL,
		0xEB230D45466E8156ULL,
		0x016D3DE76116407EULL,
		0xCAFB23CD0B1C21F2ULL,
		0xB11C080E308DDB1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C929026DFF47D6AULL,
		0x8C0B2CF0CE5759C5ULL,
		0xF98212FED84863ABULL,
		0x308A11B4F8A29EC0ULL,
		0x8BDCE6197AFC9AF7ULL,
		0xF888C09BD11461E5ULL,
		0x6C2F902355E51497ULL,
		0xB0515E99798DF4E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F8F48FCAFAEF618ULL,
		0xAEE416D3A8FC1A8DULL,
		0x18D2E85951FD4FC0ULL,
		0x0D55091A1EC1EB92ULL,
		0x5F46272BCB71E65FULL,
		0x08E47D4B9001DE99ULL,
		0x5ECB93A9B5370D5AULL,
		0x00CAA974B6FFE638ULL
	}};
	sign = 0;
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
		0xD45E91A0618A26F1ULL,
		0x23443D7C7D562251ULL,
		0x3B5EE648072025C7ULL,
		0xEF7A996E76668281ULL,
		0x898BE26E795F2BB8ULL,
		0x291312F5036B04B4ULL,
		0xDA60D54D9F024573ULL,
		0xBBE0519971794336ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C5193A0169BF57CULL,
		0xBFC4D4FF15E8E160ULL,
		0xAC6E70D62DCDECE2ULL,
		0x4B66DC288A2FFF53ULL,
		0x092178D1A131C0F4ULL,
		0x5370A49109C87114ULL,
		0x310DB944C3B74BFCULL,
		0x5A9717006268B3F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB80CFE004AEE3175ULL,
		0x637F687D676D40F1ULL,
		0x8EF07571D95238E4ULL,
		0xA413BD45EC36832DULL,
		0x806A699CD82D6AC4ULL,
		0xD5A26E63F9A293A0ULL,
		0xA9531C08DB4AF976ULL,
		0x61493A990F108F40ULL
	}};
	sign = 0;
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
		0xD8347B7D48C36A2FULL,
		0x1281DA180694B58EULL,
		0x314BCC008280A6CAULL,
		0xC88AF4F2C7D372B0ULL,
		0xF583038CD1FE71CEULL,
		0xD98F229185AC3650ULL,
		0xBC4BB4F1676DEE21ULL,
		0xEC07E8C1DEFF0800ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF369B91E0FD0174ULL,
		0x9AB0F80220B99850ULL,
		0x75901239D61CA724ULL,
		0x896A1D83132FC7BCULL,
		0x5B7ED5B06DE2F2F0ULL,
		0x18C05135385D8E62ULL,
		0x48CDC3C895879260ULL,
		0xA366C8B384E8D5CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8FDDFEB67C668BBULL,
		0x77D0E215E5DB1D3DULL,
		0xBBBBB9C6AC63FFA5ULL,
		0x3F20D76FB4A3AAF3ULL,
		0x9A042DDC641B7EDEULL,
		0xC0CED15C4D4EA7EEULL,
		0x737DF128D1E65BC1ULL,
		0x48A1200E5A163234ULL
	}};
	sign = 0;
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
		0xEF3749D083DDE6D4ULL,
		0x13AC5A47AE938ADBULL,
		0xC5DE68C996CBBF88ULL,
		0x5CA98176F4EBDDC7ULL,
		0x211F36DAADFCD72FULL,
		0x97A09CCA2A28CDB7ULL,
		0x5B756AEF10523663ULL,
		0xBCAB63838B19074FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x808A2705356A8AFDULL,
		0x15D84CDCC1BDD147ULL,
		0x9048BDE21EBB33B8ULL,
		0xDD86949112E25A3DULL,
		0x41DFFA3E66340597ULL,
		0x984FE9A514DBA3E4ULL,
		0xC0F9BC9B98BFDB6FULL,
		0x57182BC197941500ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EAD22CB4E735BD7ULL,
		0xFDD40D6AECD5B994ULL,
		0x3595AAE778108BCFULL,
		0x7F22ECE5E209838AULL,
		0xDF3F3C9C47C8D197ULL,
		0xFF50B325154D29D2ULL,
		0x9A7BAE5377925AF3ULL,
		0x659337C1F384F24EULL
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
		0x9E5F9101F5EBF2DEULL,
		0x7AE0D66EB970DB5FULL,
		0x9CAEF2A26A476378ULL,
		0xD3C156B932FA1605ULL,
		0xF58A13E64FD19EABULL,
		0x0C68AF693B86AB83ULL,
		0xE5B34C0EA9F12521ULL,
		0x71621D31BB114C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE253D047568FA282ULL,
		0xD09EB9E6ED12F40DULL,
		0xE879954A5EAB4181ULL,
		0xC721E878E36EDFB5ULL,
		0x22C2123A3A65B7D6ULL,
		0xA041E0B2425A4867ULL,
		0xD764813419E28F7AULL,
		0x03C0C91BC9CDAC3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC0BC0BA9F5C505CULL,
		0xAA421C87CC5DE751ULL,
		0xB4355D580B9C21F6ULL,
		0x0C9F6E404F8B364FULL,
		0xD2C801AC156BE6D5ULL,
		0x6C26CEB6F92C631CULL,
		0x0E4ECADA900E95A6ULL,
		0x6DA15415F1439FD1ULL
	}};
	sign = 0;
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
		0xB09C0B6637C78B00ULL,
		0xE3FD27FDC0CE2BB9ULL,
		0x6DEA430C60FAE1C6ULL,
		0x45AE149A76451FEDULL,
		0xEA36D9FDFD9BC1CCULL,
		0x89EC47239545D55DULL,
		0x5FFBE7CBBF394F57ULL,
		0xACD2F90A636BE6F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C8858A2D0CDC7EULL,
		0x6D5F54CA53AABF17ULL,
		0x8D9A6FBED35ED729ULL,
		0xA380A91C85AEAC31ULL,
		0xF709D63909829530ULL,
		0xA1B4DC535A10B3A1ULL,
		0x6EE7C262515D1B4FULL,
		0x21BF7A0ECC58524EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x37D385DC0ABAAE82ULL,
		0x769DD3336D236CA2ULL,
		0xE04FD34D8D9C0A9DULL,
		0xA22D6B7DF09673BBULL,
		0xF32D03C4F4192C9BULL,
		0xE8376AD03B3521BBULL,
		0xF11425696DDC3407ULL,
		0x8B137EFB971394A2ULL
	}};
	sign = 0;
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
		0xE9B480529990A505ULL,
		0xE7F41AB015F9362FULL,
		0x7625C1C235A99AABULL,
		0x528D8924DB0A30B3ULL,
		0xA15F11EEE2E6832FULL,
		0x139AFA573C7A6C5EULL,
		0xE9EEA83AD6FCC992ULL,
		0xE4DA251014EAFD3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D04AD4B7988928CULL,
		0x8B6567AE397EF8AFULL,
		0x58385032CCB302ECULL,
		0x3CD68014877959F1ULL,
		0xE5E38F919922AFA0ULL,
		0x02F3439631A12545ULL,
		0xCECAADC983CC3D84ULL,
		0x72BE7EC6BE205150ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCAFD30720081279ULL,
		0x5C8EB301DC7A3D80ULL,
		0x1DED718F68F697BFULL,
		0x15B709105390D6C2ULL,
		0xBB7B825D49C3D38FULL,
		0x10A7B6C10AD94718ULL,
		0x1B23FA7153308C0EULL,
		0x721BA64956CAABEBULL
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
		0x4E6DCFC3D60DBFEAULL,
		0xCB065C29D10F44EFULL,
		0x3376F343FFE9BFB2ULL,
		0xAFC3DE5656637C26ULL,
		0xAB3A88DA0DA4A57FULL,
		0xFEF178868764AB47ULL,
		0xD240E8D95C7FF772ULL,
		0xD17E21B3C33D4531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x188E1F27B608AB7CULL,
		0x1B990E1E43FB33BFULL,
		0xBB9CD3449A5A9FB9ULL,
		0x544099A017DB6202ULL,
		0x10271DA30383731CULL,
		0x935B200D40CF492DULL,
		0x3A76F3102483FF27ULL,
		0x0A4E6CC5B6410F42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35DFB09C2005146EULL,
		0xAF6D4E0B8D141130ULL,
		0x77DA1FFF658F1FF9ULL,
		0x5B8344B63E881A23ULL,
		0x9B136B370A213263ULL,
		0x6B9658794695621AULL,
		0x97C9F5C937FBF84BULL,
		0xC72FB4EE0CFC35EFULL
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
		0xD4F81D067F39F4D3ULL,
		0x091CE1120C2BCE6EULL,
		0xD8C7E9299032AF00ULL,
		0xBC9A13BAAEF2BB4BULL,
		0x4D54C837352BE83DULL,
		0x99918CDAEC22474BULL,
		0x5E62B8E85D7ED8E0ULL,
		0xBFD37FCF334AD942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF085A5AD11AA98ULL,
		0xCCEF82194C758247ULL,
		0xA2BCF170D3CA0009ULL,
		0xCAE549C8BD71ACBAULL,
		0x674504870A34B93DULL,
		0x9B2E5BA676D85200ULL,
		0x00722325D02F7E42ULL,
		0x458B77EC81FF9C74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8079760D2284A3BULL,
		0x3C2D5EF8BFB64C27ULL,
		0x360AF7B8BC68AEF6ULL,
		0xF1B4C9F1F1810E91ULL,
		0xE60FC3B02AF72EFFULL,
		0xFE6331347549F54AULL,
		0x5DF095C28D4F5A9DULL,
		0x7A4807E2B14B3CCEULL
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
		0xD7E1C4897B5A534CULL,
		0xFEECFBB306FBF1E1ULL,
		0x6060FC2CA18107A4ULL,
		0xA5C793DE6204F178ULL,
		0xCDFAD58E17604EFEULL,
		0xA5FDD4011D2C17F3ULL,
		0xA8D183A4DFEA1E4DULL,
		0x9933BBA7EF13A2EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06C98A01DC5EB96BULL,
		0x658197CE4F094892ULL,
		0x7883F074B7365DC4ULL,
		0xA63911DF4C4D1664ULL,
		0xDB8BCBB54532520DULL,
		0x5CBD021DEAC0CC58ULL,
		0x172CD934027660FDULL,
		0xFB4FA10513E1DD48ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1183A879EFB99E1ULL,
		0x996B63E4B7F2A94FULL,
		0xE7DD0BB7EA4AA9E0ULL,
		0xFF8E81FF15B7DB13ULL,
		0xF26F09D8D22DFCF0ULL,
		0x4940D1E3326B4B9AULL,
		0x91A4AA70DD73BD50ULL,
		0x9DE41AA2DB31C5A2ULL
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
		0x7E3CCDF6E94A8337ULL,
		0x32D3C9CE95974E12ULL,
		0xB8D4640A86677898ULL,
		0x3E2E69BE65551341ULL,
		0xF3BE04D19D17542CULL,
		0x61006C715B298CF8ULL,
		0xCCD56B6ACF4B3313ULL,
		0xB8CC4CD46EE49452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC17861F3946ED5E8ULL,
		0xBF187ECDA5CEEDAEULL,
		0xDDF1035C72CB8B91ULL,
		0xE22FD346F0F29089ULL,
		0x96EC1D1496F95127ULL,
		0xC48C0CCC5B7D1337ULL,
		0xD58AC5ECD01EB934ULL,
		0x6FA137DAFD8C05AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBCC46C0354DBAD4FULL,
		0x73BB4B00EFC86063ULL,
		0xDAE360AE139BED06ULL,
		0x5BFE9677746282B7ULL,
		0x5CD1E7BD061E0304ULL,
		0x9C745FA4FFAC79C1ULL,
		0xF74AA57DFF2C79DEULL,
		0x492B14F971588EA3ULL
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
		0xDE25A3EAA9F37A29ULL,
		0xECC8C839737794AFULL,
		0xA9212CBF3B31901AULL,
		0xDC36B3C9F482E942ULL,
		0xC9753BB166D72385ULL,
		0x8DC8A06E99129ABFULL,
		0xDD5FFD5FBC0301EAULL,
		0x3A386A465D5DAB9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4347CF2CC5847722ULL,
		0x2292DB5DEE03BDF5ULL,
		0xA4DD0691C8DC3B0AULL,
		0x32C58597727DD74CULL,
		0x36A732AA75F455FCULL,
		0xB7018AF60E988ADBULL,
		0xFF8C394DD37A2E66ULL,
		0xAEE05F1B2B14F2C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9ADDD4BDE46F0307ULL,
		0xCA35ECDB8573D6BAULL,
		0x0444262D72555510ULL,
		0xA9712E32820511F6ULL,
		0x92CE0906F0E2CD89ULL,
		0xD6C715788A7A0FE4ULL,
		0xDDD3C411E888D383ULL,
		0x8B580B2B3248B8D7ULL
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
		0x572F82BF731D0F61ULL,
		0xA1BD94399FF13C2DULL,
		0xBB58698488B801FFULL,
		0x5AE8E4F8B0FC9BF6ULL,
		0x3BC444EE2103A8FAULL,
		0x17A22E3E73021C40ULL,
		0x4C09DD4F0D11B121ULL,
		0x5500625934DE3025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD22DFE910B8B486EULL,
		0xDF0733BFB5C9289EULL,
		0xE6F08C1ABD32BC15ULL,
		0x47F9420F96FCEEDEULL,
		0x708D17B9AE84B863ULL,
		0x62E3FE14370CBCC2ULL,
		0x24529225C98C1BC0ULL,
		0x3A3CFDD27CD0566BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8501842E6791C6F3ULL,
		0xC2B66079EA28138EULL,
		0xD467DD69CB8545E9ULL,
		0x12EFA2E919FFAD17ULL,
		0xCB372D34727EF097ULL,
		0xB4BE302A3BF55F7DULL,
		0x27B74B2943859560ULL,
		0x1AC36486B80DD9BAULL
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
		0x88626515F947C172ULL,
		0xD0C63FA4F65464C2ULL,
		0x83E984759B155D0BULL,
		0xB8FF3C387831AC9DULL,
		0x50B38E724423A470ULL,
		0x900219AEDC2EEC49ULL,
		0xA05C544C7DD5CD67ULL,
		0xCC0ABBA5F92343DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6CDBACD2B41711ULL,
		0x80F9DED9E90DE587ULL,
		0x8CAB5BF67085030DULL,
		0xDA84088CB0ED314FULL,
		0x6E1C0DA660C23F92ULL,
		0x926CC387D59ECD9FULL,
		0xAF564E15C7054768ULL,
		0xD70C2E6B2728B71CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DF589692693AA61ULL,
		0x4FCC60CB0D467F3BULL,
		0xF73E287F2A9059FEULL,
		0xDE7B33ABC7447B4DULL,
		0xE29780CBE36164DDULL,
		0xFD95562706901EA9ULL,
		0xF1060636B6D085FEULL,
		0xF4FE8D3AD1FA8CC1ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xF4F2A14890226E1FULL,
		0x01BA447CD2BBA0C6ULL,
		0x3CC3DA621F262F57ULL,
		0x9561B326DC2119DAULL,
		0x981A13F6EA2E6975ULL,
		0x2984B97DEF06D971ULL,
		0x404C7A1205BFAC1DULL,
		0xB411E5890B8AE93EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x386656FB66416A39ULL,
		0x94316CD5FE95C29FULL,
		0x4B88024895674340ULL,
		0x0371CBF057BBFB99ULL,
		0x2D1FB62716560772ULL,
		0xD0B1BE186729443DULL,
		0xB56BC1DEE1322206ULL,
		0x931BCFAD60E12D60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBC8C4A4D29E103E6ULL,
		0x6D88D7A6D425DE27ULL,
		0xF13BD81989BEEC16ULL,
		0x91EFE73684651E40ULL,
		0x6AFA5DCFD3D86203ULL,
		0x58D2FB6587DD9534ULL,
		0x8AE0B833248D8A16ULL,
		0x20F615DBAAA9BBDDULL
	}};
	sign = 0;
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
		0xA4046857047485B0ULL,
		0xAF0B0608DBE2478EULL,
		0x22AC388C0298EDE1ULL,
		0x5DB0633327206994ULL,
		0xEBC76D4AA163A53CULL,
		0x4317116A0C662A13ULL,
		0xA6B92508E8C9236BULL,
		0x0B7CA6708C4C0155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948479F4109293B0ULL,
		0xE006D58B56FF833DULL,
		0xD5E820FE8718C1FBULL,
		0xDDF4A45ACAFD0BB5ULL,
		0x5D29CB7D9A5B1703ULL,
		0x011C2F95CF765C1FULL,
		0x035B777A87420BC8ULL,
		0x21D29995BF2431DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F7FEE62F3E1F200ULL,
		0xCF04307D84E2C451ULL,
		0x4CC4178D7B802BE5ULL,
		0x7FBBBED85C235DDEULL,
		0x8E9DA1CD07088E38ULL,
		0x41FAE1D43CEFCDF4ULL,
		0xA35DAD8E618717A3ULL,
		0xE9AA0CDACD27CF7AULL
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
		0x1281835E38C0C00FULL,
		0x163D638A37BECCE4ULL,
		0xBE11A20B681E9C99ULL,
		0xA1E6AD81B493B68BULL,
		0xB45FD6EE523D4672ULL,
		0x0C86E2EE4FD9506AULL,
		0xC14C53CF05833C35ULL,
		0x63D6560C788B8A25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58B63BD61354CB7CULL,
		0xBE80AFBE987E98F6ULL,
		0xEA661DD590C53CF3ULL,
		0xA8433CCACDC0E1DDULL,
		0x32A7BA5F7025AAA6ULL,
		0xEDFD475BD00AFB37ULL,
		0x7AA3E1476EDB664CULL,
		0x0C4DF3000F80EFE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9CB4788256BF493ULL,
		0x57BCB3CB9F4033EDULL,
		0xD3AB8435D7595FA5ULL,
		0xF9A370B6E6D2D4ADULL,
		0x81B81C8EE2179BCBULL,
		0x1E899B927FCE5533ULL,
		0x46A8728796A7D5E8ULL,
		0x5788630C690A9A3CULL
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
		0xA24F0222D5892236ULL,
		0x4AFFA9C32DE736B8ULL,
		0xFCC5896820F04E47ULL,
		0x19F6D59188D5CED5ULL,
		0xAA876449E755919BULL,
		0x17C29A122C7828F1ULL,
		0x74891CF234F12163ULL,
		0xCBA46DCD1842366BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E510C910CC80846ULL,
		0x72C58479A3601F85ULL,
		0x971BA87475F5C692ULL,
		0x1800916609ECEE8EULL,
		0xA6A2EEAB5DE2888CULL,
		0xDE26859F9A3A9BEAULL,
		0x4839F479C07C1235ULL,
		0xBBEF933AE0353D95ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63FDF591C8C119F0ULL,
		0xD83A25498A871733ULL,
		0x65A9E0F3AAFA87B4ULL,
		0x01F6442B7EE8E047ULL,
		0x03E4759E8973090FULL,
		0x399C1472923D8D07ULL,
		0x2C4F287874750F2DULL,
		0x0FB4DA92380CF8D6ULL
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
		0x21F14F3350EB86C8ULL,
		0x29D7BF6DEDC56DC4ULL,
		0x8A6E8DEF5A9ABDD5ULL,
		0xC4B8DB2D8E62BF0EULL,
		0xCED6B4C3C5CB074EULL,
		0x25FFCCC51AE41660ULL,
		0x88A799DAE09BCB0DULL,
		0xB1900BFAAF0BA593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF523210D3846C0F8ULL,
		0xAD746552E1506833ULL,
		0xF3A87F2A3A70DD20ULL,
		0xD0A722C500FE756FULL,
		0x642185F0835F9AB6ULL,
		0xED22EE39B03AD73EULL,
		0xC883B0953EC75C23ULL,
		0xA2DFFDF59E8F8577ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2CCE2E2618A4C5D0ULL,
		0x7C635A1B0C750590ULL,
		0x96C60EC52029E0B4ULL,
		0xF411B8688D64499EULL,
		0x6AB52ED3426B6C97ULL,
		0x38DCDE8B6AA93F22ULL,
		0xC023E945A1D46EE9ULL,
		0x0EB00E05107C201BULL
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
		0x7AB6CF0AE7FCAC3DULL,
		0xC1BFF5F09E18A596ULL,
		0x89A077BC2940E722ULL,
		0x9D81D7D19CABB1B6ULL,
		0xE445572207A2CB5EULL,
		0x6AD72550766EB6BCULL,
		0x76A5925D53A10D63ULL,
		0x571017149E43C2A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C032E189A7B3F06ULL,
		0x3DAEC459DD2F4E64ULL,
		0x61BEEF8F681CFEBBULL,
		0xAC1B3430A154CAF7ULL,
		0x31B1C7D0A8C84512ULL,
		0x3A8034F1D0EF415DULL,
		0x61F1FBE86924E5AAULL,
		0xF401342806E21039ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EB3A0F24D816D37ULL,
		0x84113196C0E95732ULL,
		0x27E1882CC123E867ULL,
		0xF166A3A0FB56E6BFULL,
		0xB2938F515EDA864BULL,
		0x3056F05EA57F755FULL,
		0x14B39674EA7C27B9ULL,
		0x630EE2EC9761B26FULL
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
		0x1965EE2E6F6E58A2ULL,
		0x9AC86A4443CF18D7ULL,
		0xA30ACCA86A546E57ULL,
		0x42DCEC147B747E03ULL,
		0x4F0436C91E4EF8EBULL,
		0x84A86D25F63289DEULL,
		0x1465FE123D91CDE7ULL,
		0xAC6137CAE98C6A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D032D54BB29D843ULL,
		0xA6EAEC88CB1E3CBFULL,
		0x2790DDACCA148A3DULL,
		0x54541C47B9D8ADC9ULL,
		0x5606460BDFD7AE2FULL,
		0x27B713D6E33453B1ULL,
		0x43301F808BAEC529ULL,
		0x351B624B140170A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC62C0D9B444805FULL,
		0xF3DD7DBB78B0DC17ULL,
		0x7B79EEFBA03FE419ULL,
		0xEE88CFCCC19BD03AULL,
		0xF8FDF0BD3E774ABBULL,
		0x5CF1594F12FE362CULL,
		0xD135DE91B1E308BEULL,
		0x7745D57FD58AF9DCULL
	}};
	sign = 0;
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
		0x5E3F0A9DE76BBB40ULL,
		0x85470987A79D0E48ULL,
		0x3822008C9F7EC70DULL,
		0x03B0F02EF89F010DULL,
		0xC00BABAACEFA8AA9ULL,
		0xB773A7EAEBE8C5E2ULL,
		0xAE11C58257724E26ULL,
		0xD786D415F7664757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE2763C96ED7DE45ULL,
		0x68613204FB573504ULL,
		0x8F72FB0D12A87DA8ULL,
		0x34BBD0E6426FDB63ULL,
		0x0BA65E8AE1FA8EA2ULL,
		0x55A490F3C8DD9AABULL,
		0x21B1878498F00E6DULL,
		0x5E8134C6B7ADEB76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA017A6D47893DCFBULL,
		0x1CE5D782AC45D943ULL,
		0xA8AF057F8CD64965ULL,
		0xCEF51F48B62F25A9ULL,
		0xB4654D1FECFFFC06ULL,
		0x61CF16F7230B2B37ULL,
		0x8C603DFDBE823FB9ULL,
		0x79059F4F3FB85BE1ULL
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
		0xBDD8CF9167C86311ULL,
		0xFC32FA301E08AA3EULL,
		0x93071C85B0D31F8CULL,
		0x72743057CD185520ULL,
		0xE43BA428A3F200ACULL,
		0x3A87ED4C73D12269ULL,
		0x5E5779640D623597ULL,
		0xE84FE89BAEC397E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x806F7A6BB738686FULL,
		0x0B1954CF81818299ULL,
		0xC5809F957D1BD785ULL,
		0x57D09FE1817F13FBULL,
		0xD253D609E45763D6ULL,
		0x80A7354785D97309ULL,
		0xB5DA90307AC5701FULL,
		0x83A9D5A8E56C6DD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D695525B08FFAA2ULL,
		0xF119A5609C8727A5ULL,
		0xCD867CF033B74807ULL,
		0x1AA390764B994124ULL,
		0x11E7CE1EBF9A9CD6ULL,
		0xB9E0B804EDF7AF60ULL,
		0xA87CE933929CC577ULL,
		0x64A612F2C9572A0EULL
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
		0xE7CA9F745958DEE0ULL,
		0x3D505EE0A1CB208FULL,
		0x6D7CF45689244006ULL,
		0xA4D5706F37FD934BULL,
		0xFA2A42CCA3C3B552ULL,
		0x904F0D07E591E38EULL,
		0x113A46E0912010A3ULL,
		0x706A7AD4EE51E498ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A53ACD281B6BD3AULL,
		0x17C52EECBF7EE584ULL,
		0x85E59E0D76711AE3ULL,
		0xB7C55315566814E0ULL,
		0x33E3D4640B1813C8ULL,
		0xE455A81DC79E988DULL,
		0x0CBA6D3F30AE58ECULL,
		0x50BB0F4D6ADC1E67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D76F2A1D7A221A6ULL,
		0x258B2FF3E24C3B0BULL,
		0xE797564912B32523ULL,
		0xED101D59E1957E6AULL,
		0xC6466E6898ABA189ULL,
		0xABF964EA1DF34B01ULL,
		0x047FD9A16071B7B6ULL,
		0x1FAF6B878375C631ULL
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
		0x45A3EA8558540953ULL,
		0xD7837428E0170BFFULL,
		0xC236F232A35480CEULL,
		0xF426035CCE69083EULL,
		0xB046F0C911C14AA5ULL,
		0x5A46BADEE40BF376ULL,
		0xEF7A339FFFA3E77FULL,
		0x5809302CE87099CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634890A53148BB2BULL,
		0x72A4C268CE10A3A1ULL,
		0x7AD0609E457323E2ULL,
		0x01FA0C442BBECC9FULL,
		0x73E8DC40D7BC95E5ULL,
		0x8F4A082A427D341CULL,
		0x9BF2990401FA1227ULL,
		0x1840F7AD312D0F8BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE25B59E0270B4E28ULL,
		0x64DEB1C01206685DULL,
		0x476691945DE15CECULL,
		0xF22BF718A2AA3B9FULL,
		0x3C5E14883A04B4C0ULL,
		0xCAFCB2B4A18EBF5AULL,
		0x53879A9BFDA9D557ULL,
		0x3FC8387FB7438A40ULL
	}};
	sign = 0;
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
		0xC5F0E913EEDC2955ULL,
		0x8F89BD6F78FF4170ULL,
		0x78638FC96F9A4EC5ULL,
		0x36FFB964BB95734AULL,
		0xF7CC4FFEED2BE84AULL,
		0x5C63E2A88A1FBF1BULL,
		0xE74B98EEC47B0E45ULL,
		0x38FC11AD5837878EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E35741770AD6EEULL,
		0xDE9A62EFF67B7AE6ULL,
		0xF8DE8461D553F7F4ULL,
		0x5D4B29EC8AE636FCULL,
		0x42CCD10A0EA990F6ULL,
		0x9D951F1BAE6B9B27ULL,
		0xC97A4067C966D7C1ULL,
		0x5A583AF3088CD0C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF20D91D277D15267ULL,
		0xB0EF5A7F8283C689ULL,
		0x7F850B679A4656D0ULL,
		0xD9B48F7830AF3C4DULL,
		0xB4FF7EF4DE825753ULL,
		0xBECEC38CDBB423F4ULL,
		0x1DD15886FB143683ULL,
		0xDEA3D6BA4FAAB6CDULL
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
		0x93B4C1415669C4AAULL,
		0xC9829A0B0E2009B1ULL,
		0x2D78C9D005B7FED4ULL,
		0x9F4BF65417F13AFAULL,
		0x2A6061D2404E53BAULL,
		0x04846DA545BFDD82ULL,
		0x2D58AB1DE141F0D7ULL,
		0xB19DC898B997CDBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46FAB0995AA56371ULL,
		0x84303DF9B13121E8ULL,
		0xF06E4922D6E8C7A4ULL,
		0x25A3BB5F16865DC0ULL,
		0x1B2E51EFBC8E8CC9ULL,
		0x825E86C10CA82648ULL,
		0xAF834CB0AC246B98ULL,
		0x17EA51AFBC8E6684ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CBA10A7FBC46139ULL,
		0x45525C115CEEE7C9ULL,
		0x3D0A80AD2ECF3730ULL,
		0x79A83AF5016ADD39ULL,
		0x0F320FE283BFC6F1ULL,
		0x8225E6E43917B73AULL,
		0x7DD55E6D351D853EULL,
		0x99B376E8FD096738ULL
	}};
	sign = 0;
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
		0x5587E500F7AA46B5ULL,
		0x2627AAEE27FBB8AAULL,
		0x3A87C87F906E2F34ULL,
		0x76A778DC8F61D03FULL,
		0x3CCC86E21AE30687ULL,
		0x2871FAEE380AB145ULL,
		0x2B661B6269A400E7ULL,
		0x3E2A5DC7C1505EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACBD1135241FEA10ULL,
		0x290C2D05A755E4A4ULL,
		0xA83DA48570D695ADULL,
		0x9CF3C5B66218E6FAULL,
		0x9C03AA5E2D48EA2BULL,
		0x02B7B36880CBD1BFULL,
		0x481577B1CC996B14ULL,
		0x98A4A14C7F9A8100ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8CAD3CBD38A5CA5ULL,
		0xFD1B7DE880A5D405ULL,
		0x924A23FA1F979986ULL,
		0xD9B3B3262D48E944ULL,
		0xA0C8DC83ED9A1C5BULL,
		0x25BA4785B73EDF85ULL,
		0xE350A3B09D0A95D3ULL,
		0xA585BC7B41B5DDEFULL
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
		0xF4C801F3B4D3B23DULL,
		0xF5F56C1352133ED1ULL,
		0x537C8B03DEA9C6DEULL,
		0x647AC814F8AC024CULL,
		0xCE0B93BAB3C7F95EULL,
		0x3D6F232839ACB95FULL,
		0x4C7AC78A7DAEF91FULL,
		0x60A6D4D7A4C0E488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F6AA9C67C5730FULL,
		0x4F2C30D9545743ACULL,
		0xD5D4C3513CBDE93CULL,
		0x3A431B813749F159ULL,
		0xA2521279FB0BA96BULL,
		0x61E0F7BF07327F3BULL,
		0xE128C0888A471B73ULL,
		0x297878319F60E13EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CD157574D0E3F2EULL,
		0xA6C93B39FDBBFB25ULL,
		0x7DA7C7B2A1EBDDA2ULL,
		0x2A37AC93C16210F2ULL,
		0x2BB98140B8BC4FF3ULL,
		0xDB8E2B69327A3A24ULL,
		0x6B520701F367DDABULL,
		0x372E5CA605600349ULL
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
		0x91A0CE14C5933795ULL,
		0x9C4490FF7E1AD237ULL,
		0x477B4319E8B9EDAAULL,
		0xD05583042C306658ULL,
		0xA9780F4C8D2D9064ULL,
		0x1BC6D3D8BD66C58AULL,
		0x73B077E0D8650DC9ULL,
		0xF0EBFA4E9360A817ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94CF511B07F2EF38ULL,
		0x2C16572DE245816DULL,
		0x25242BBAA7D5AE13ULL,
		0x398FD21DF11CA15DULL,
		0x931203B0CB0F58E0ULL,
		0x33CD135947CB58F6ULL,
		0xDDE97A30C7E19FC3ULL,
		0x5FB1C8B2B72FC55FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCD17CF9BDA0485DULL,
		0x702E39D19BD550C9ULL,
		0x2257175F40E43F97ULL,
		0x96C5B0E63B13C4FBULL,
		0x16660B9BC21E3784ULL,
		0xE7F9C07F759B6C94ULL,
		0x95C6FDB010836E05ULL,
		0x913A319BDC30E2B7ULL
	}};
	sign = 0;
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
		0xD581C388D8C83FABULL,
		0x92C54F56D3F25CB2ULL,
		0x543D46E8ABADCB34ULL,
		0x63FB11F4514B3409ULL,
		0x767379DC6961E0C6ULL,
		0xAD3A9CB54F6FD8FFULL,
		0xB4EB2EBF27B1F924ULL,
		0xC9549BD4144663D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F042474C9C75767ULL,
		0x457976E22B6E7550ULL,
		0xDDC78F9BC6AE2156ULL,
		0x5B9480825AD09B82ULL,
		0xB6B0BB22F4F3AAF7ULL,
		0x43E3AE03BA9B8185ULL,
		0x16BC96EADAF60B25ULL,
		0x71B38E0340FE561AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x467D9F140F00E844ULL,
		0x4D4BD874A883E762ULL,
		0x7675B74CE4FFA9DEULL,
		0x08669171F67A9886ULL,
		0xBFC2BEB9746E35CFULL,
		0x6956EEB194D45779ULL,
		0x9E2E97D44CBBEDFFULL,
		0x57A10DD0D3480DBBULL
	}};
	sign = 0;
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
		0xAFFF041C128ED80CULL,
		0x35BAAEBF2A6E2444ULL,
		0x217F8A8CC521E1BFULL,
		0x8D94AF7EB882E2FBULL,
		0xA7122B9E73BF2111ULL,
		0x86559B5543CBB0BCULL,
		0x156D67E5E5661A1FULL,
		0x0BC3EF7DABD16163ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AA668D6AD40B5ABULL,
		0x0538F39FF42F05C7ULL,
		0xCCF97DF6AC2F011CULL,
		0x36B9168425376B64ULL,
		0xB8101D7DDAE29D14ULL,
		0xEB9AAFD7B9D44224ULL,
		0x22DC763D0BC7142DULL,
		0xC294A6BAA65988EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65589B45654E2261ULL,
		0x3081BB1F363F1E7DULL,
		0x54860C9618F2E0A3ULL,
		0x56DB98FA934B7796ULL,
		0xEF020E2098DC83FDULL,
		0x9ABAEB7D89F76E97ULL,
		0xF290F1A8D99F05F1ULL,
		0x492F48C30577D877ULL
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
		0x02F0F88ADD05BC7DULL,
		0xE36EC29C7F0E71C1ULL,
		0x21349FBB5AD1FD88ULL,
		0x7917A74EAADE94CBULL,
		0xF3B48CCB31537CC8ULL,
		0x0B10589C1C0F698EULL,
		0xE4AF2091ACC4ADADULL,
		0x6EAD66E8C9CF1E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5CD30D206F3E246ULL,
		0x1DE3003332385396ULL,
		0x926FBEEBA3C14D87ULL,
		0xD4E67125973CD845ULL,
		0xE69CC58A66F7AE0DULL,
		0xCFA09874A9B16385ULL,
		0x3B1565336F3B05D3ULL,
		0x629654AA10C4A495ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D23C7B8D611DA37ULL,
		0xC58BC2694CD61E2AULL,
		0x8EC4E0CFB710B001ULL,
		0xA431362913A1BC85ULL,
		0x0D17C740CA5BCEBAULL,
		0x3B6FC027725E0609ULL,
		0xA999BB5E3D89A7D9ULL,
		0x0C17123EB90A79CFULL
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
		0x1409490274BCB304ULL,
		0xF1B7FE824977D88BULL,
		0x6E59C21593464813ULL,
		0x5F26932129DB944BULL,
		0xF8B04156E7F90D69ULL,
		0x6BFCEA4280D71274ULL,
		0x8574875B886B0BB0ULL,
		0xBE9FE7EBD8303F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F6A36368C8ED052ULL,
		0xCAC176A7E59CFB11ULL,
		0x4857BC588AF0E8FBULL,
		0xF5854E496F7204DFULL,
		0xD21EE4F73648CB1AULL,
		0x6628E5109D4489E8ULL,
		0xEDEA1EF68F95B4C8ULL,
		0xD8A35264A2DABEAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF49F12CBE82DE2B2ULL,
		0x26F687DA63DADD79ULL,
		0x260205BD08555F18ULL,
		0x69A144D7BA698F6CULL,
		0x26915C5FB1B0424EULL,
		0x05D40531E392888CULL,
		0x978A6864F8D556E8ULL,
		0xE5FC9587355580ACULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0x46253F7AD5CD939BULL,
		0xB39DC0F4895353E4ULL,
		0x1BC97D5D59A41394ULL,
		0xEE3BFD5B05A40E98ULL,
		0xEF15EE50F435A82AULL,
		0x5E2FDF5821477077ULL,
		0x47E1B55A076D8A01ULL,
		0xD308B013151678C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4EBF3ECC639551EULL,
		0x9230C0F8DB5582FDULL,
		0xE3D0D0AB0C25DD89ULL,
		0x9BCC30D9E80EC7E3ULL,
		0x9DE18D01D5BD89B1ULL,
		0x9DADEBB70F912879ULL,
		0xAB330EAB5E243504ULL,
		0x8EDA800731DF316CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91394B8E0F943E7DULL,
		0x216CFFFBADFDD0E6ULL,
		0x37F8ACB24D7E360BULL,
		0x526FCC811D9546B4ULL,
		0x5134614F1E781E79ULL,
		0xC081F3A111B647FEULL,
		0x9CAEA6AEA94954FCULL,
		0x442E300BE3374755ULL
	}};
	sign = 0;
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
		0x913D5168F0FFB7E8ULL,
		0x52ED03A5C565A079ULL,
		0xCA2FC4DBBE0D7880ULL,
		0xC7BEC8586E7E6AA2ULL,
		0xD5629B172C875726ULL,
		0xAAE8EE19D48A8741ULL,
		0x98EF4FCFB4075FEFULL,
		0x9B3E5F2D3B99E76CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3760156C42F0AF1EULL,
		0x7D88C61A4A2E997EULL,
		0x844A26F5262AECA5ULL,
		0x19965448334B113CULL,
		0x618020257E6D4803ULL,
		0x18557A561CD93300ULL,
		0x0119403B3AD96095ULL,
		0xF0F72A4B8DBDF794ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59DD3BFCAE0F08CAULL,
		0xD5643D8B7B3706FBULL,
		0x45E59DE697E28BDAULL,
		0xAE2874103B335966ULL,
		0x73E27AF1AE1A0F23ULL,
		0x929373C3B7B15441ULL,
		0x97D60F94792DFF5AULL,
		0xAA4734E1ADDBEFD8ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xD4D5B4E702026736ULL,
		0x7914711C71552BB5ULL,
		0x337C74316A8D6730ULL,
		0x88EA2729C1913867ULL,
		0xB3924B6AB36A4DAFULL,
		0xB0398815A8B02A2FULL,
		0xA68495360E6555F5ULL,
		0xD8A4D353168C0C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3317AA36831E818ULL,
		0x9EC6D68864335FC6ULL,
		0x8ABA806B3A9195E0ULL,
		0xC51473041C6C4BC5ULL,
		0xBCDE2F53FFC58276ULL,
		0x39B712E86523270EULL,
		0x9C364AF42BFD0C2AULL,
		0x7E82E9211893AA55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1A43A4399D07F1EULL,
		0xDA4D9A940D21CBEEULL,
		0xA8C1F3C62FFBD14FULL,
		0xC3D5B425A524ECA1ULL,
		0xF6B41C16B3A4CB38ULL,
		0x7682752D438D0320ULL,
		0x0A4E4A41E26849CBULL,
		0x5A21EA31FDF861EEULL
	}};
	sign = 0;
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
		0x538A9298B6D8803EULL,
		0x5B69AB74575EE3A4ULL,
		0xC11B333229DA56C7ULL,
		0xD45C337BB2A4557DULL,
		0xC56AC3FA0D1386ABULL,
		0xAB801CA2810D75C2ULL,
		0x37DEF556FE9D4055ULL,
		0xC71834F750472D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F0E3654895AF3B4ULL,
		0x877C6DB01B84E4A5ULL,
		0xD717F4CCBC9C2228ULL,
		0xC751627E38473C6CULL,
		0x21114C1739DE7DEFULL,
		0x81C9F3A53BA716D3ULL,
		0x60A04463BABAEC50ULL,
		0xD94774FDDAC92B4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC47C5C442D7D8C8AULL,
		0xD3ED3DC43BD9FEFEULL,
		0xEA033E656D3E349EULL,
		0x0D0AD0FD7A5D1910ULL,
		0xA45977E2D33508BCULL,
		0x29B628FD45665EEFULL,
		0xD73EB0F343E25405ULL,
		0xEDD0BFF9757E01FAULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xBC1778D3E3B614CAULL,
		0x38B3D65DDCD576D4ULL,
		0xB71AB8F8C6949AEFULL,
		0x2CA3EBE67FCFDB1DULL,
		0xA3B600E78D7953F1ULL,
		0x5D38E7F93B364167ULL,
		0x2386998C97D6EBB5ULL,
		0xBBC037D7C05DE5BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24F907A18DE760D4ULL,
		0x5C9EA3E5CFC17972ULL,
		0x97782615D8C4C6EDULL,
		0x6E31794005E407B0ULL,
		0x1C6C8C28C80A325AULL,
		0xFFC78D112371D544ULL,
		0xE5DE3EF37B5D9754ULL,
		0x9ED30CEDE0B94D3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x971E713255CEB3F6ULL,
		0xDC1532780D13FD62ULL,
		0x1FA292E2EDCFD401ULL,
		0xBE7272A679EBD36DULL,
		0x874974BEC56F2196ULL,
		0x5D715AE817C46C23ULL,
		0x3DA85A991C795460ULL,
		0x1CED2AE9DFA49880ULL
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
		0xF30D48E9D6CC44FCULL,
		0x5991174FD4225F47ULL,
		0x30EC3BE8AB300443ULL,
		0xA7A7BD45AE33C699ULL,
		0x9BE7AEFFDDEB2852ULL,
		0x1B048425E141A833ULL,
		0xC741C29439412ABCULL,
		0xB1FFF71FED8D78E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78A3BF2D92E521B1ULL,
		0x20B1E1370239B37FULL,
		0x59E74C8E35B87A7AULL,
		0x0958449D22D7796FULL,
		0x68C1A91399EDEE8FULL,
		0x3C675928C4F172E7ULL,
		0x92475D483D5BBB77ULL,
		0x3BB7EBF4EE71FFA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A6989BC43E7234BULL,
		0x38DF3618D1E8ABC8ULL,
		0xD704EF5A757789C9ULL,
		0x9E4F78A88B5C4D29ULL,
		0x332605EC43FD39C3ULL,
		0xDE9D2AFD1C50354CULL,
		0x34FA654BFBE56F44ULL,
		0x76480B2AFF1B7946ULL
	}};
	sign = 0;
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
		0x00526EC56B11E538ULL,
		0xCAA0ECDF2980BD3FULL,
		0x484101905CF12118ULL,
		0x2BEC0B1DE1DBAAB0ULL,
		0xD3C91738992D63C4ULL,
		0xBF71CD630B2B27FFULL,
		0xA2E6E96A8BB4DE78ULL,
		0xBA0AE2E58FF20587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339FDFA0F23285CAULL,
		0xD2FD83274054ACFBULL,
		0x0C86C30BD2C8231CULL,
		0xA8E50C7CB3CEF54CULL,
		0x74B039A3DAC83D2BULL,
		0xD98874DE7FD3A447ULL,
		0xC78356D7A6F2DA06ULL,
		0x457A188B52F93097ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCCB28F2478DF5F6EULL,
		0xF7A369B7E92C1043ULL,
		0x3BBA3E848A28FDFBULL,
		0x8306FEA12E0CB564ULL,
		0x5F18DD94BE652698ULL,
		0xE5E958848B5783B8ULL,
		0xDB639292E4C20471ULL,
		0x7490CA5A3CF8D4EFULL
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
		0xB5D76AC4D0F472D8ULL,
		0x9B5429757294E9E7ULL,
		0x697527585C0241DBULL,
		0xEECC5020854A53A5ULL,
		0x124A2F64C6D05CEAULL,
		0x55C47577C82A07DBULL,
		0xBA84B08941DF7A16ULL,
		0xE7FB979557261529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE40D7F5A37CB15AAULL,
		0x75E48C3518A4AD66ULL,
		0xAD88B5F9857CA7E2ULL,
		0x0A5ADC3E54E702E1ULL,
		0x19C9619C8CB19929ULL,
		0xAE7248AC6016A699ULL,
		0x779909DB627C19DEULL,
		0x6188507F3D020AD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1C9EB6A99295D2EULL,
		0x256F9D4059F03C80ULL,
		0xBBEC715ED68599F9ULL,
		0xE47173E2306350C3ULL,
		0xF880CDC83A1EC3C1ULL,
		0xA7522CCB68136141ULL,
		0x42EBA6ADDF636037ULL,
		0x867347161A240A51ULL
	}};
	sign = 0;
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
		0x6413E92367928CBBULL,
		0xBB3784F220C9F58EULL,
		0xAA634B6A1C6DED4FULL,
		0x12DCEE1590AD8636ULL,
		0xE1D7DDB7C204E796ULL,
		0x34111A9D6F243149ULL,
		0x0CD24F993A6CAFF7ULL,
		0xB573C3209B444853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25DB79C2A5DB3241ULL,
		0x28BC602377BB21D6ULL,
		0x6B50A6325463CF21ULL,
		0x2C8E9D1406B420F8ULL,
		0x09C9CA69521BE98BULL,
		0xE3956DC8693E99E8ULL,
		0xC9C2A8C0926BC141ULL,
		0xD6FD60F7B7815344ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E386F60C1B75A7AULL,
		0x927B24CEA90ED3B8ULL,
		0x3F12A537C80A1E2EULL,
		0xE64E510189F9653EULL,
		0xD80E134E6FE8FE0AULL,
		0x507BACD505E59761ULL,
		0x430FA6D8A800EEB5ULL,
		0xDE766228E3C2F50EULL
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
		0x217B580159DB80A8ULL,
		0xC067A9D07E9D2C56ULL,
		0x5FBAA97AE0083B6AULL,
		0x0A4836064C422F72ULL,
		0x3D2BDE35049D65CEULL,
		0x22CC5265727F4441ULL,
		0x94EA1351AC415FD6ULL,
		0x5C041F4E73BE4D85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE4236D1A51CBFCULL,
		0x1C72508C6452F9C3ULL,
		0xD2AB53FB46FF3F4FULL,
		0x6946333F244AD241ULL,
		0x8B41437D75883082ULL,
		0xFB5CBF924353E03BULL,
		0x4DC1FC542E66EAD4ULL,
		0xC26D11B218FA802CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB69734943F89B4ACULL,
		0xA3F559441A4A3292ULL,
		0x8D0F557F9908FC1BULL,
		0xA10202C727F75D30ULL,
		0xB1EA9AB78F15354BULL,
		0x276F92D32F2B6405ULL,
		0x472816FD7DDA7501ULL,
		0x99970D9C5AC3CD59ULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xC53D29254C72D257ULL,
		0x9B9C3FB0B75D713FULL,
		0x9D35AE0622B8B941ULL,
		0x886C2E2F095AB565ULL,
		0x666527856BA35541ULL,
		0x92729C1F4FD8A92FULL,
		0x18347725D4923131ULL,
		0x028B4EA1A62AFF1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F643DAC63DA60E9ULL,
		0xB2C86A48EA4024EEULL,
		0x1DAAD770A52C753DULL,
		0x7EB1BB23A0587F9DULL,
		0x4EDF8A04A0F0F173ULL,
		0x97AA685697ECE089ULL,
		0xA074B82617860965ULL,
		0x8F1318E5C55E5C80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85D8EB78E898716EULL,
		0xE8D3D567CD1D4C51ULL,
		0x7F8AD6957D8C4403ULL,
		0x09BA730B690235C8ULL,
		0x17859D80CAB263CEULL,
		0xFAC833C8B7EBC8A6ULL,
		0x77BFBEFFBD0C27CBULL,
		0x737835BBE0CCA29EULL
	}};
	printf("Underflow\n");
	sign = 1;
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
		0xB4FF1A37CE724702ULL,
		0x1B97E392B11DE146ULL,
		0xC63F4B0CD69F2ADAULL,
		0xEAE50D5D647EA6F8ULL,
		0x5BE0D2419AF74A56ULL,
		0x974E43B01BB1B2D4ULL,
		0xCAAFF9B94E8F2EF5ULL,
		0xE64186015B981C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x035BFC223AC25142ULL,
		0x5A3D33F759FB63ACULL,
		0x7B7A8A5FA50C671BULL,
		0xF6CC71B2A7F2147DULL,
		0x503738BB261A6F68ULL,
		0x6DF1FEA760506D9AULL,
		0x63A195D51DB0ECBAULL,
		0xCCBCA109E55C6408ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB1A31E1593AFF5C0ULL,
		0xC15AAF9B57227D9AULL,
		0x4AC4C0AD3192C3BEULL,
		0xF4189BAABC8C927BULL,
		0x0BA9998674DCDAEDULL,
		0x295C4508BB61453AULL,
		0x670E63E430DE423BULL,
		0x1984E4F7763BB862ULL
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