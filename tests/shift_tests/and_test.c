#include "../tests.h"

int32_t curve25519_key_and_test(void) {
	printf("Key AND Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xB489E6EF7EFC0244ULL,
		0x7FDFC8E3B3401A37ULL,
		0xB537E00AD92BCED3ULL,
		0xFD80D9B2E2EFDBC0ULL,
		0xC7C2D086660EBFDCULL,
		0xB03D580BD53BDD25ULL,
		0x484EF6E59A428EE0ULL,
		0xEAF4D65284533DA5ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x62367D776AED8EB1ULL,
		0x40C22A85B307CF12ULL,
		0x152424FCB0452FCCULL,
		0x14A679A0F996A5A1ULL,
		0xDB2DEA30292EE357ULL,
		0xF5105CAEB70B81E1ULL,
		0xFBCA9111FD1EF66CULL,
		0x27BE61E1E96E1BF7ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x200064676AEC0200ULL,
		0x40C20881B3000A12ULL,
		0x1524200890010EC0ULL,
		0x148059A0E0868180ULL,
		0xC300C000200EA354ULL,
		0xB010580A950B8121ULL,
		0x484A900198028660ULL,
		0x22B44040804219A5ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x593B5A6EAEBB9925ULL,
		0xC0975A3545D605E6ULL,
		0xC1E26BB279E8FC44ULL,
		0xFED151623F18EEB2ULL,
		0x46A900B4ABA94D80ULL,
		0xF31E0D257CEA359FULL,
		0x092F40484E908235ULL,
		0xE6B8BB49206ABBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5639AA2CCC105E46ULL,
		0x2F24112C0B60AA5FULL,
		0x0E883D7F97E91A8AULL,
		0x35DF02A82A39EC96ULL,
		0xA4EB284D94807F11ULL,
		0x467388EFFF260387ULL,
		0x03A93DE82C199864ULL,
		0xA7B975E6E2B78B7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50390A2C8C101804ULL,
		0x0004102401400046ULL,
		0x0080293211E81800ULL,
		0x34D100202A18EC92ULL,
		0x04A9000480804D00ULL,
		0x421208257C220187ULL,
		0x012900480C108024ULL,
		0xA6B8314020228B24ULL
	}};
	printf("Test Case 2\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFA9D2C787771F463ULL,
		0x734C892A2968D44BULL,
		0xC690752C9186637FULL,
		0x3A8396084CE5EB51ULL,
		0x8BA8CA955C377DABULL,
		0x1035F41BA71D27EAULL,
		0xF85D60925FDE9FA0ULL,
		0x810F71E9C37A6B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35EA95EF47B04B65ULL,
		0xFB13CC906A21CEA0ULL,
		0x37CF3F701204FEF1ULL,
		0xEAAA26F72A88EFA6ULL,
		0x28753D5F1AF5DA46ULL,
		0x737F9EDD58FD3D12ULL,
		0x5EEA9B4AB0840BD8ULL,
		0x399428A8BA23FE19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3088046847304061ULL,
		0x730088002820C400ULL,
		0x0680352010046271ULL,
		0x2A8206000880EB00ULL,
		0x0820081518355802ULL,
		0x10359419001D2502ULL,
		0x5848000210840B80ULL,
		0x010420A882226A18ULL
	}};
	printf("Test Case 3\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC66AC8F694EA037AULL,
		0xFF64E08885E425CEULL,
		0x3E93D8C1DE9D3D8BULL,
		0x146B975156FD8EE3ULL,
		0xFC8312F45C56D937ULL,
		0xBBB267F41F5E3F52ULL,
		0xC212C6EAC4BCE994ULL,
		0xEABCBEFC54E43EF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DEE6A992370EB92ULL,
		0x5277A001AA7B0794ULL,
		0x8B68E20EE5294B91ULL,
		0xB3C0CCA34B1C1453ULL,
		0x68A8ED665E1394DCULL,
		0x617692F7AAA02D8FULL,
		0x0711D63B1ADE51E6ULL,
		0x237CE834CA1D32C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x446A489000600312ULL,
		0x5264A00080600584ULL,
		0x0A00C000C4090981ULL,
		0x10408401421C0443ULL,
		0x688000645C129014ULL,
		0x213202F40A002D02ULL,
		0x0210C62A009C4184ULL,
		0x223CA834400432C0ULL
	}};
	printf("Test Case 4\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8329138CFD1D81E4ULL,
		0x3D23AD2F6088A400ULL,
		0x0AC85F934C53485EULL,
		0xC0E1D02BDF0D78B9ULL,
		0xFD113C19DCDA71B8ULL,
		0xBC169203999A7C66ULL,
		0xE58129ED2B5BD5AEULL,
		0x200C4BC9F711929CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A8B100DF4BB5B1ULL,
		0xC3549A0E49F7B16BULL,
		0x4EB23DAC968485D4ULL,
		0x738567196479D9AEULL,
		0x881A9FF99EC5DF29ULL,
		0x8C81E1A9327B37DFULL,
		0xC7B1B1214FE531DAULL,
		0x7088F9A3C327C872ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02281100DD0981A0ULL,
		0x0100880E4080A000ULL,
		0x0A801D8004000054ULL,
		0x40814009440958A8ULL,
		0x88101C199CC05128ULL,
		0x8C008001101A3446ULL,
		0xC58121210B41118AULL,
		0x20084981C3018010ULL
	}};
	printf("Test Case 5\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1EA41B305CF04860ULL,
		0xA90571CB76D0E7CAULL,
		0xC710AD1296F7CDE4ULL,
		0xD9B92F9A2AD3347DULL,
		0xDFCEF2BCC84713DDULL,
		0x20A0897EFEDBA0ABULL,
		0xF48A0B312EFC4100ULL,
		0x3FD8D59DAD26F4CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195A5E8C93D0FAABULL,
		0x5C0308546D0B4092ULL,
		0x994FF1A744DA3079ULL,
		0x02677F78669249C1ULL,
		0xE1408C084ADCA62FULL,
		0x23EC4F0000B1B8BFULL,
		0x3281F1B0EA5347CCULL,
		0x0412559FD7A47A19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18001A0010D04820ULL,
		0x0801004064004082ULL,
		0x8100A10204D20060ULL,
		0x00212F1822920041ULL,
		0xC14080084844020DULL,
		0x20A009000091A0ABULL,
		0x308001302A504100ULL,
		0x0410559D85247009ULL
	}};
	printf("Test Case 6\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAB04120CFFDB2BD0ULL,
		0xD7BD013735271D22ULL,
		0x10836F7FFAD6900BULL,
		0x833E80E542A697A4ULL,
		0xE6163FFC4E4F54E2ULL,
		0x15FBA0D108E6B068ULL,
		0x6920CDC55FC31EADULL,
		0x17EABAA0582968DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB945C3DBFE903F1ULL,
		0x5259C7E8EBFC1DC9ULL,
		0x3EA01D3A6D920091ULL,
		0x81B2A4CFE473ED5EULL,
		0x70ED02DFA11F639EULL,
		0x9EA7A774D5E2F5EEULL,
		0xBAB0D716DAC100C5ULL,
		0xA9EFC8F3BF645F37ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB04100CBFC903D0ULL,
		0x5219012021241D00ULL,
		0x10800D3A68920001ULL,
		0x813280C540228504ULL,
		0x600402DC000F4082ULL,
		0x14A3A05000E2B068ULL,
		0x2820C5045AC10085ULL,
		0x01EA88A018204812ULL
	}};
	printf("Test Case 7\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3EA88BFF5B1D6A8AULL,
		0xCF24F737E05D3F70ULL,
		0xBA9490345E9DADC8ULL,
		0x9B28EBF5686804FEULL,
		0xFE466F9BAC070272ULL,
		0xD7034349A2372C90ULL,
		0x6F066560568F3BB7ULL,
		0x8FA42C2121794966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35F26E598B95B9E5ULL,
		0x0BBF6C5D9F08714CULL,
		0xD72C2E2ED978AD50ULL,
		0x403415018AAC635FULL,
		0xA8FBAF4223820661ULL,
		0x856990CB68D5022AULL,
		0x998D4674CC8B2E98ULL,
		0x40BB82AE56ED4B46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x34A00A590B152880ULL,
		0x0B24641580083140ULL,
		0x920400245818AD40ULL,
		0x002001010828005EULL,
		0xA8422F0220020260ULL,
		0x8501004920150000ULL,
		0x09044460448B2A90ULL,
		0x00A0002000694946ULL
	}};
	printf("Test Case 8\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9ACF17D4540AF127ULL,
		0x92989EEC12CD8FB8ULL,
		0x532CE138E091BB79ULL,
		0xB609304AD3E4C942ULL,
		0x8E4CD37F16791894ULL,
		0x7A8DB49A29CC1E9EULL,
		0x47DC9721FA073186ULL,
		0x88456AD5621C4E9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC037A0AACEFA3B24ULL,
		0xE44FCD9E9E004CABULL,
		0x2958972AB94BFCF0ULL,
		0x855DC6948EA9FA47ULL,
		0xB011551C6AB7578AULL,
		0xD5AD53E32D742235ULL,
		0x2B7279E65EBF01A2ULL,
		0x249169548053432EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80070080440A3124ULL,
		0x80088C8C12000CA8ULL,
		0x01088128A001B870ULL,
		0x8409000082A0C842ULL,
		0x8000511C02311080ULL,
		0x508D108229440214ULL,
		0x035011205A070182ULL,
		0x000168540010420AULL
	}};
	printf("Test Case 9\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x285710973B632FE4ULL,
		0xF69A64898442E1E4ULL,
		0x96230484CB5E4578ULL,
		0x60B5B51952D6ECF1ULL,
		0x4E7BB6F017B03C46ULL,
		0x300E148F39812D9DULL,
		0x2DD64DBEFA947419ULL,
		0xFCAA8EFA9AC73D58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C68B60DE2A00C58ULL,
		0xC19FBCCE8AD0FB8EULL,
		0x2C48CA8AE160B805ULL,
		0xF97B179E35D2FCF6ULL,
		0x6CECEFDC52C0CAC7ULL,
		0x0548A49719713BCDULL,
		0x9C0921DA43393B5AULL,
		0x3CC6BD40CE6E9CB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2840100522200C40ULL,
		0xC09A24888040E184ULL,
		0x04000080C1400000ULL,
		0x6031151810D2ECF0ULL,
		0x4C68A6D012800846ULL,
		0x000804871901298DULL,
		0x0C00019A42103018ULL,
		0x3C828C408A461C10ULL
	}};
	printf("Test Case 10\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFC5B3CA4776D1B67ULL,
		0xCC4688A3D011F88AULL,
		0x96C5EFA47C27365AULL,
		0x0A0553A5659E27CDULL,
		0xAB51AF6658B65F29ULL,
		0x094D9B2A9B7DC00CULL,
		0x55DDD9EC5CA64B4BULL,
		0xC6C2A970DD1F16B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3030A204E275E1DULL,
		0xDF205AE5D35BECB4ULL,
		0x742CA64CDD1DF300ULL,
		0x6FB3F9D996D192C6ULL,
		0x4B55B5F65DEC7E18ULL,
		0x50C06DFC2F8E7A06ULL,
		0xC1F881A8889D4364ULL,
		0x5CC1C2F1E7828B6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA003082046251A05ULL,
		0xCC0008A1D011E880ULL,
		0x1404A6045C053200ULL,
		0x0A015181049002C4ULL,
		0x0B51A56658A45E08ULL,
		0x004009280B0C4004ULL,
		0x41D881A808844340ULL,
		0x44C08070C5020224ULL
	}};
	printf("Test Case 11\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9684270764D2E119ULL,
		0x4B32C3DC89B7FC98ULL,
		0x21F6EC04EC0F692CULL,
		0x3F0A7A9F7753C256ULL,
		0x322B88D5E4161E98ULL,
		0x146BC9628E5CF43FULL,
		0x4C9CD4567F6809B5ULL,
		0x6FED3C646D6E9E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41808AA7483E698ULL,
		0xBB599D023650D8C0ULL,
		0xF64F5355D8EE52CFULL,
		0x45B7C3001C689567ULL,
		0xD7759675DCAB5786ULL,
		0x671B0B5C462951B0ULL,
		0x7B84FF716EA6C6E7ULL,
		0x39214F48449E7149ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x940000026482E018ULL,
		0x0B1081000010D880ULL,
		0x20464004C80E400CULL,
		0x0502420014408046ULL,
		0x12218055C4021680ULL,
		0x040B094006085030ULL,
		0x4884D4506E2000A5ULL,
		0x29210C40440E1008ULL
	}};
	printf("Test Case 12\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9A3D31DB122CD243ULL,
		0x3536A4D6D64831B9ULL,
		0xF82B5E5C3A5D9AFBULL,
		0x119C67D3C47323B2ULL,
		0xC7C7E9FDCCE873F2ULL,
		0x3F18EBA8DE15ECBFULL,
		0x5E375E0E0C10ABC5ULL,
		0xF936C01B7B9EDD6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8179E2A4404A3D79ULL,
		0xFD71E28E717CBF2DULL,
		0x9937E5CF387FF4B1ULL,
		0x917340032152456EULL,
		0x7619478E9AFBDF88ULL,
		0x54230CC1B4C3E323ULL,
		0x921CAF51164C00ABULL,
		0x2F6717D0F7A5682DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8039208000081041ULL,
		0x3530A08650483129ULL,
		0x9823444C385D90B1ULL,
		0x1110400300520122ULL,
		0x4601418C88E85380ULL,
		0x140008809401E023ULL,
		0x12140E0004000081ULL,
		0x292600107384482DULL
	}};
	printf("Test Case 13\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA25678CC5269202AULL,
		0xEAAD728C9289091CULL,
		0x6B85B89DB911BEEDULL,
		0x9B1DD6E3C5727E48ULL,
		0x92BB048F32CFC040ULL,
		0x26F492987066D1BFULL,
		0x2163DA91B0680BCFULL,
		0x56FE840182A78501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE81B65CC345A0F9ULL,
		0x3B9EA05CCDC2C5EBULL,
		0xC8A75835F972AC57ULL,
		0xFBA5A7633F886CC9ULL,
		0xB6839E8E4F4BB399ULL,
		0x58C27BA27F86CE4BULL,
		0x9292343331ACD3D3ULL,
		0xFA4466AF9325D387ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8200304C42412028ULL,
		0x2A8C200C80800108ULL,
		0x48851815B910AC45ULL,
		0x9B05866305006C48ULL,
		0x9283048E024B8000ULL,
		0x00C012807006C00BULL,
		0x00021011302803C3ULL,
		0x5244040182258101ULL
	}};
	printf("Test Case 14\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8CB0DD584B788539ULL,
		0x6969A3796796657BULL,
		0x35B094785151D6BEULL,
		0x8D72AD4642E44E50ULL,
		0x82F46F2602F1A00EULL,
		0x20B52F786DEBFE38ULL,
		0x6B1EF71062F874BCULL,
		0x3F4D1B98938DF36DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE16AEE33D257C684ULL,
		0xFEF527EE5413CB96ULL,
		0x8574F980704DE674ULL,
		0x9596ED407468E6A8ULL,
		0x7C3E7B4A48DFA054ULL,
		0x1D340AF2F5B414A4ULL,
		0x22B5E7B0C470162CULL,
		0x5AC12EE7EB3D0E5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8020CC1042508400ULL,
		0x6861236844124112ULL,
		0x053090005041C634ULL,
		0x8512AD4040604600ULL,
		0x00346B0200D1A004ULL,
		0x00340A7065A01420ULL,
		0x2214E7104070142CULL,
		0x1A410A80830D0249ULL
	}};
	printf("Test Case 15\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x40121E8E33FC4A49ULL,
		0x6FAACBF69BC65878ULL,
		0x052E0BC28FA282B1ULL,
		0xDA6437DAA2A82613ULL,
		0xFB42D81A1E1AB20FULL,
		0xAC913CBB0F792714ULL,
		0xFC626CD7E3713B68ULL,
		0x8285D7A50DBD7549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50E75F85310F6650ULL,
		0x99CFA9D0E056FE78ULL,
		0x6F6B431E1F011D54ULL,
		0x1105B2987967566FULL,
		0x6F73CC8B36FCD668ULL,
		0x3EFA3B38CD7CF098ULL,
		0xEF8963C4C5707C0BULL,
		0x68E744287F00815FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40021E84310C4240ULL,
		0x098A89D080465878ULL,
		0x052A03020F000010ULL,
		0x1004329820200603ULL,
		0x6B42C80A16189208ULL,
		0x2C9038380D782010ULL,
		0xEC0060C4C1703808ULL,
		0x008544200D000149ULL
	}};
	printf("Test Case 16\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8D15230B8037CBBDULL,
		0x5C5568B93BEBC1A4ULL,
		0x70BCBD98C288014FULL,
		0xEEEE917A9A173EE8ULL,
		0x2C422B7F79EBF64DULL,
		0xC196F69216A95D3BULL,
		0xC3370C70216CD7F5ULL,
		0x7BD0E5A91ED40AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAD3F72EE663763FULL,
		0xA4CC5D7D2F5633FEULL,
		0xDB0B8D16D8D5DD5AULL,
		0x0360C686E0E05CFFULL,
		0x5911472F7D85D04FULL,
		0x21EC3B978070F1E0ULL,
		0x7AA94BE609CBFBF2ULL,
		0xD4676A7FA86B9EA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8811230A8023423DULL,
		0x044448392B4201A4ULL,
		0x50088D10C080014AULL,
		0x0260800280001CE8ULL,
		0x0800032F7981D04DULL,
		0x0184329200205120ULL,
		0x422108600148D3F0ULL,
		0x5040602908400AA4ULL
	}};
	printf("Test Case 17\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x92D7EB7B8BA81877ULL,
		0x889EF8D10A6C7BADULL,
		0x90E6930B326EA342ULL,
		0xB9787A4832EF3DE7ULL,
		0x201D2FAF2FEE90E8ULL,
		0xC34DD7E7A87EFE80ULL,
		0x800F56BE64E46053ULL,
		0xAE02C309C376077BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7344AF82768CC8ABULL,
		0x84A0064EACA8433BULL,
		0x481F7790625E42ACULL,
		0x0FAE1EAF6D91FA96ULL,
		0x89388110E5179FE8ULL,
		0xCF33D759A468F9B2ULL,
		0x36E68592A5414390ULL,
		0xCD79120C0662AEEDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1244AB0202880823ULL,
		0x8080004008284329ULL,
		0x00061300224E0200ULL,
		0x09281A0820813886ULL,
		0x00180100250690E8ULL,
		0xC301D741A068F880ULL,
		0x0006049224404010ULL,
		0x8C00020802620669ULL
	}};
	printf("Test Case 18\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD5D06A73C1C546FDULL,
		0xD2283841DFB25052ULL,
		0xEDE4DEC76AAD7B7DULL,
		0x9D09A23C196515A4ULL,
		0x3A71A82F9B6297E3ULL,
		0xA53089A4FFC97E97ULL,
		0x976641E4BCBF0D2DULL,
		0xDC7A5163B8673680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6198FBD77A7CCDEFULL,
		0xCE648388DDB59C68ULL,
		0xC6B88A23CE768C3AULL,
		0x64B8855821366EADULL,
		0x2F1927B475154D29ULL,
		0xEB682B706AC6CA15ULL,
		0x0E81593D119D2587ULL,
		0xE98E9566D5C8BE3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41906A53404444EDULL,
		0xC2200000DDB01040ULL,
		0xC4A08A034A240838ULL,
		0x04088018012404A4ULL,
		0x2A11202411000521ULL,
		0xA12009206AC04A15ULL,
		0x06004124109D0505ULL,
		0xC80A116290403600ULL
	}};
	printf("Test Case 19\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3CABFFDFE80054E8ULL,
		0xBC52B4B5A7E83374ULL,
		0xE78A2846B3ED46CCULL,
		0x8ED86F578965053BULL,
		0x678426F4F6CEC4ACULL,
		0x924538756AB7D5A3ULL,
		0xD8F4AB687A912DD8ULL,
		0x1E08FD7E4B1A89F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18C0124250F73C51ULL,
		0x1CDE07195FF39269ULL,
		0x62EF36B467094C5BULL,
		0xB512644CBB6261AAULL,
		0xDF25B606A4B412DDULL,
		0xC67C8091D47CEA42ULL,
		0xF544715AC5F3248FULL,
		0x89C53885B20A5AFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1880124240001440ULL,
		0x1C52041107E01260ULL,
		0x628A200423094448ULL,
		0x841064448960012AULL,
		0x47042604A484008CULL,
		0x824400114034C002ULL,
		0xD044214840912488ULL,
		0x08003804020A08F4ULL
	}};
	printf("Test Case 20\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCDFAC393B97C3EBDULL,
		0x1AF133EB40A91C39ULL,
		0x90D9356A15E908B9ULL,
		0x2AAE7EC555D3B61EULL,
		0x5705A404B5D2A8FCULL,
		0xBDAAEFCC786A7302ULL,
		0x6868AE6A4E9C3CB7ULL,
		0xBAF5D0ED546F6EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3778A5A2F3812CULL,
		0x8A531B6A52BCE150ULL,
		0xE473E23DFE0D3653ULL,
		0x99FE5F41290EF35AULL,
		0x085E7D2E88B6853EULL,
		0x9C0F8BC04B453E63ULL,
		0xB8A13E559F43C076ULL,
		0x18696ACA37DF38D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09324081A070002CULL,
		0x0A51136A40A80010ULL,
		0x8051202814090011ULL,
		0x08AE5E410102B21AULL,
		0x000424048092803CULL,
		0x9C0A8BC048403202ULL,
		0x28202E400E000036ULL,
		0x186140C8144F28D0ULL
	}};
	printf("Test Case 21\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9FDE853A82DC8771ULL,
		0x718A483D0B6A9B9FULL,
		0x2BB6817FE74C18C0ULL,
		0x081FC1B59E694C96ULL,
		0x802BA40D5910722BULL,
		0x7A9D2F242F2AE0E0ULL,
		0x2D3C63A514FD41ECULL,
		0x651FCC5A99E47A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA88772D483D6377ULL,
		0x28419E0ED070E3A2ULL,
		0x775B27707D951E01ULL,
		0x10BD629BF32EC0CCULL,
		0xE2F56D5992C7B593ULL,
		0x0558179700F93590ULL,
		0xFD9B6B0F542BDF4DULL,
		0x9B0DF9BE05C419D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A880528001C0371ULL,
		0x2000080C00608382ULL,
		0x2312017065041800ULL,
		0x001D409192284084ULL,
		0x8021240910003003ULL,
		0x0018070400282080ULL,
		0x2D1863051429414CULL,
		0x010DC81A01C41840ULL
	}};
	printf("Test Case 22\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCB1DE4473FCFA9E4ULL,
		0x565FE750F3FDE882ULL,
		0x30B34127A8826862ULL,
		0x9D8E74871068EF68ULL,
		0x8952057258C302D1ULL,
		0xB274D6A80AA41722ULL,
		0x12FCCC7DA13E61B4ULL,
		0x451BC49BE0722DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BD81DB39EC7802ULL,
		0xE1DD0B3B2B863344ULL,
		0xB40773C2CD983F61ULL,
		0x73D069F10A0A74C4ULL,
		0xFA6B6BAEA295938BULL,
		0xAF6345DB80DD232BULL,
		0x466596791F8BB202ULL,
		0x4B26AAF0F84FA935ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x801D804339CC2800ULL,
		0x405D031023842000ULL,
		0x3003410288802860ULL,
		0x1180608100086440ULL,
		0x8842012200810281ULL,
		0xA260448800840322ULL,
		0x02648479010A2000ULL,
		0x41028090E0422925ULL
	}};
	printf("Test Case 23\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x94FF6DA5C50BF85CULL,
		0xB5D76B684941B30FULL,
		0x31C7302C94AC700FULL,
		0x822D84CA83D11BB1ULL,
		0xD389939531D98767ULL,
		0x9B08911DE7102B99ULL,
		0x82691CA1C09FA677ULL,
		0x7B37C3BBFAE745B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B658803A6E2DD26ULL,
		0x6A98A824D927F0AEULL,
		0x8111361B422A4289ULL,
		0x6559F0FECED09333ULL,
		0xC720AD46F409A771ULL,
		0xC0964CB74D1F1F53ULL,
		0x27418EC9B8F0F651ULL,
		0x3A9E0ED6E1158F85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x106508018402D804ULL,
		0x209028204901B00EULL,
		0x0101300800284009ULL,
		0x000980CA82D01331ULL,
		0xC300810430098761ULL,
		0x8000001545100B11ULL,
		0x02410C818090A651ULL,
		0x3A160292E0050580ULL
	}};
	printf("Test Case 24\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0DE2F684F63AC75EULL,
		0x3F488D7C3683136BULL,
		0x6A5CAFF9C2933D23ULL,
		0x5E9DB57B16721E96ULL,
		0xE4DF30C2DABB57EAULL,
		0x97440713BE289A98ULL,
		0x38A4FF621ECCF13DULL,
		0x628B1B665111C1F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE61688160ECB1C3ULL,
		0xC4C6F11CD9E213B4ULL,
		0x3B6BE9EF899BEADEULL,
		0x26C4B26C1143D2CCULL,
		0xDAD4A8C04D1965B6ULL,
		0xA116A677F59B3509ULL,
		0xD431EAE5433E5911ULL,
		0xDA59D3F0A02A4C23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C60608060288142ULL,
		0x0440811C10821320ULL,
		0x2A48A9E980932802ULL,
		0x0684B06810421284ULL,
		0xC0D420C0481945A2ULL,
		0x81040613B4081008ULL,
		0x1020EA60020C5111ULL,
		0x4209136000004020ULL
	}};
	printf("Test Case 25\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDB41404D5E3A5201ULL,
		0xD07123F7F46813ABULL,
		0x8EED803E24F2C0C1ULL,
		0x01D71FEF23A9E391ULL,
		0xBAEC3086B2FF5264ULL,
		0x4ADD492008142D0FULL,
		0xB83D3492E498F054ULL,
		0x6B046E19E6CDB7D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B349092F58B784ULL,
		0xF05740F31B0F1B9BULL,
		0x26C855381B16251BULL,
		0x46D571EA8313C840ULL,
		0xF0F137B4C7B06054ULL,
		0x5EF463767D1BCD6EULL,
		0xC1F46BB13C9009D0ULL,
		0xEAA478C5567B0F19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD00140090E181200ULL,
		0xD05100F31008138BULL,
		0x06C8003800120001ULL,
		0x00D511EA0301C000ULL,
		0xB0E0308482B04044ULL,
		0x4AD4412008100D0EULL,
		0x8034209024900050ULL,
		0x6A04680146490710ULL
	}};
	printf("Test Case 26\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE5E439662DF089C4ULL,
		0x5BF1FDE75748DBA1ULL,
		0x61B62D0B49101A31ULL,
		0xF44373C2EA4BEBA2ULL,
		0xF5595FFF2F587949ULL,
		0x0DB35C095B0E8F0CULL,
		0x216CC6A2D09A1B6EULL,
		0xC6148D9F1C3ACAAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x426D71D9F1020336ULL,
		0x78C2D2AB4F40639AULL,
		0x9A634036A71BB3F5ULL,
		0xD5D48895A32523B8ULL,
		0x167B38EBE583EAA3ULL,
		0x7DE363CB5123E644ULL,
		0x194BE0DA9E834436ULL,
		0x98846B1BFC94F9CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4064314021000104ULL,
		0x58C0D0A347404380ULL,
		0x0022000201101231ULL,
		0xD4400080A20123A0ULL,
		0x145918EB25006801ULL,
		0x0DA3400951028604ULL,
		0x0148C08290820026ULL,
		0x8004091B1C10C88EULL
	}};
	printf("Test Case 27\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC278996EC1342494ULL,
		0x25A3158D42F49190ULL,
		0x944DA1B326D878A0ULL,
		0x2B1DD54D1EE27169ULL,
		0x4E79CC72C19E6BCCULL,
		0xA7614E0DB889138DULL,
		0x8A23FDAE3811FF43ULL,
		0x42AFB1A0F3F0C053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50EC1FDC92D671B6ULL,
		0x8719E9F1CD4455EDULL,
		0x0018C7E413F55CACULL,
		0x817BE78BE965FD43ULL,
		0xCD5E0C31B154B602ULL,
		0xD16E750B6B869A83ULL,
		0x52D1E301E2E5316BULL,
		0x025712B7BA91C24CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4068194C80142094ULL,
		0x0501018140441180ULL,
		0x000881A002D058A0ULL,
		0x0119C50908607141ULL,
		0x4C580C3081142200ULL,
		0x8160440928801281ULL,
		0x0201E10020013143ULL,
		0x020710A0B290C040ULL
	}};
	printf("Test Case 28\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x869549D1CD7BE2B0ULL,
		0x4CB1753B0C40418FULL,
		0x98B2DF96F35D8DA4ULL,
		0xA0DCC6773AE32C8FULL,
		0xBBD1094CF13F9A18ULL,
		0xC8492972527E9120ULL,
		0x7840DD6E40D13467ULL,
		0x4E5E5F9338C1938BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC74030B2017A103CULL,
		0xEDFCED59A891BA6EULL,
		0x7BA0A4745C188F0FULL,
		0xCE3F46BE8AA3F865ULL,
		0x5ECB270B9B18421EULL,
		0xAEA2B2D419094DB0ULL,
		0x2430E9165279A796ULL,
		0x89D81B007706F2A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86000090017A0030ULL,
		0x4CB065190800000EULL,
		0x18A0841450188D04ULL,
		0x801C46360AA32805ULL,
		0x1AC1010891180218ULL,
		0x8800205010080120ULL,
		0x2000C90640512406ULL,
		0x08581B0030009281ULL
	}};
	printf("Test Case 29\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE6DA0108E64781FAULL,
		0x9042F76954DFD117ULL,
		0x53DCD8CBA835F841ULL,
		0xF012F9F477CFDE9DULL,
		0xB1F61D87EB03C131ULL,
		0x0060E43343B495E2ULL,
		0xAAF7D428A4FD6C3CULL,
		0x5CBDF08A3BAB91A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C31F172CA251712ULL,
		0xA129BE5A73712D11ULL,
		0x02BB0EDE036FB92CULL,
		0x2FC7B73DD5C6E7AFULL,
		0xEC777FBBC1F3C0E6ULL,
		0x6A8B4274F4D72D85ULL,
		0x59BED94A45DBA6CFULL,
		0x5E3761A77907D96BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84100100C2050112ULL,
		0x8000B64850510111ULL,
		0x029808CA0025B800ULL,
		0x2002B13455C6C68DULL,
		0xA0761D83C103C020ULL,
		0x0000403040940580ULL,
		0x08B6D00804D9240CULL,
		0x5C35608239039123ULL
	}};
	printf("Test Case 30\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDA185511BFCBD42BULL,
		0x0A7BCD2ADEB5D042ULL,
		0xCEDAC0990E92675DULL,
		0x2087C43DE0347703ULL,
		0x73AF461C2B158DC9ULL,
		0xFC40A129A6F11552ULL,
		0xF19F83B455209F54ULL,
		0x44C2077FF1EFE44DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A347EF564C5D890ULL,
		0x3CBBAE2E6E1AEA78ULL,
		0xEFDBA7194B3AD268ULL,
		0x8E84272CBC0F0726ULL,
		0xBBF68DAE2B6E3E22ULL,
		0x50E4BCBD21DA1BE2ULL,
		0xEAF7F1C1E0DD6E08ULL,
		0x683753BCE19A47B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A10541124C1D000ULL,
		0x083B8C2A4E10C040ULL,
		0xCEDA80190A124248ULL,
		0x0084042CA0040702ULL,
		0x33A6040C2B040C00ULL,
		0x5040A02920D01142ULL,
		0xE097818040000E00ULL,
		0x4002033CE18A4400ULL
	}};
	printf("Test Case 31\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA8977706777EED10ULL,
		0x0DE0F6D2052FADD0ULL,
		0xE18A52D7DAB990F8ULL,
		0x1BF04764BBADA97AULL,
		0xE63A8E19AFFE2745ULL,
		0x288C8109847BFB46ULL,
		0xCCB6AF88888EEA57ULL,
		0xE54541F2FBC4FCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6DE5BA9AB7094CULL,
		0x5D74B8DA7941D8D0ULL,
		0xBA22AB9392A9D618ULL,
		0xF4CFE5EFDDB27ED2ULL,
		0x77A8BF229B3B2CFDULL,
		0xA48CCEBAE839EA64ULL,
		0x104BD8F06BAAB5D7ULL,
		0xE956C8B7B3E51D29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2805650212360900ULL,
		0x0D60B0D2010188D0ULL,
		0xA002029392A99018ULL,
		0x10C0456499A02852ULL,
		0x66288E008B3A2445ULL,
		0x208C80088039EA44ULL,
		0x00028880088AA057ULL,
		0xE14440B2B3C41C21ULL
	}};
	printf("Test Case 32\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x516FA802CFC131E4ULL,
		0xA7516DC5E7389388ULL,
		0x841F65ABCC8511B4ULL,
		0x807858F81F0D97C7ULL,
		0x84B9DCD59B64FD11ULL,
		0x714AF95C2FF31D8BULL,
		0x6278393F8FBD0DB9ULL,
		0xC1904F4E74633D82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15FE7045E59A3F97ULL,
		0x26D075F24A11EB8FULL,
		0x9E295858E554884EULL,
		0xDCA7EE4EE6E8B44EULL,
		0xB77C1F41999217F7ULL,
		0x0536C3169F0BB606ULL,
		0x784FA3A6814F07B6ULL,
		0x338D1F4A955674C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x116E2000C5803184ULL,
		0x265065C042108388ULL,
		0x84094008C4040004ULL,
		0x8020484806089446ULL,
		0x84381C4199001511ULL,
		0x0102C1140F031402ULL,
		0x60482126810D05B0ULL,
		0x01800F4A14423480ULL
	}};
	printf("Test Case 33\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD3D984B52D363836ULL,
		0xC6B1DAD1923AE836ULL,
		0x4F5B51B960B77D75ULL,
		0x7D4DF7C391796300ULL,
		0x4BD716D9D71E90B6ULL,
		0xD68044E31953CF86ULL,
		0xE0E50BD168FD751DULL,
		0xA1F8C04C73CE6209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x661ECFE88E9C5A2DULL,
		0x82E2C63B3745D0D3ULL,
		0x77085ABC430DAD42ULL,
		0x6E377D6728958533ULL,
		0x0DB77F74EC673EBAULL,
		0x9BADC3A918048842ULL,
		0x0633AC8EF9B4F57AULL,
		0xFE04815F7E1DD9D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x421884A00C141824ULL,
		0x82A0C2111200C012ULL,
		0x470850B840052D40ULL,
		0x6C05754300110100ULL,
		0x09971650C40610B2ULL,
		0x928040A118008802ULL,
		0x0021088068B47518ULL,
		0xA000804C720C4001ULL
	}};
	printf("Test Case 34\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x935329F7265EBC6BULL,
		0xC5E6341AC53711D7ULL,
		0xFB197BFB19D5D6ABULL,
		0xD147A4B67DC34EC7ULL,
		0xEB85DDDD8344725AULL,
		0xA13DF935EE777A41ULL,
		0xECB56C81A0046523ULL,
		0xB282D33C25C91205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A9DAC1FED0C757ULL,
		0x082CA6ADE2C7F4B4ULL,
		0x70A9A4C37F4EC479ULL,
		0xE5707B891773BD8AULL,
		0xADA14E97E879BE19ULL,
		0xE0D14EB9E656304FULL,
		0x32013E7172018E88ULL,
		0x22AC90B02B15F117ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010108C126508443ULL,
		0x00242408C0071094ULL,
		0x700920C31944C429ULL,
		0xC140208015430C82ULL,
		0xA9814C9580403218ULL,
		0xA0114831E6563041ULL,
		0x20012C0120000400ULL,
		0x2280903021011005ULL
	}};
	printf("Test Case 35\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x041BB798F192D646ULL,
		0xD7C44C556E7A86ADULL,
		0x7424F60D961405DAULL,
		0x967CACC790378D36ULL,
		0x1D93C039C3E65728ULL,
		0x025F20E2B758F855ULL,
		0x07261BB061D94F14ULL,
		0xE84C8798022B45EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49CB3DE6B68B7F7BULL,
		0x531F4513A3C86769ULL,
		0x2C012E3C445B0D6FULL,
		0x959DB1FCDC09A404ULL,
		0xB85E899B7A588DFDULL,
		0x027AB75823210342ULL,
		0x622915799E685174ULL,
		0x56BB48B549FA56A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000B3580B0825642ULL,
		0x5304441122480629ULL,
		0x2400260C0410054AULL,
		0x941CA0C490018404ULL,
		0x1812801942400528ULL,
		0x025A204023000040ULL,
		0x0220113000484114ULL,
		0x40080090002A44A1ULL
	}};
	printf("Test Case 36\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC7E83F063A9D6AF0ULL,
		0xD3D1D5A16570DEC4ULL,
		0x8A41105A38C09E64ULL,
		0x5B1BBFD4E0184899ULL,
		0xC8F2E4ACFC83F620ULL,
		0xA8FB984642D5B5B3ULL,
		0x9A5C544731BBC632ULL,
		0x01998822C28822BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52C2FAE620C0B58BULL,
		0x729C3A90103DB351ULL,
		0x261C20AD41310062ULL,
		0x98F963C901576C87ULL,
		0xA9B34274541235E9ULL,
		0x92D3B01B5FCBC0EDULL,
		0xB8954CC624C5FB89ULL,
		0x4EAD8E96CF8FCA78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42C03A0620802080ULL,
		0x5290108000309240ULL,
		0x0200000800000060ULL,
		0x181923C000104881ULL,
		0x88B2402454023420ULL,
		0x80D3900242C180A1ULL,
		0x981444462081C200ULL,
		0x00898802C2880238ULL
	}};
	printf("Test Case 37\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7255CBF7D160D614ULL,
		0x31BD23223A2E3292ULL,
		0x36AEB37413E29064ULL,
		0xA6989749DFB072B3ULL,
		0xE10837186B2BEDCAULL,
		0xD200E3A50D833876ULL,
		0x2EE8C8E785B1C207ULL,
		0x6FEB0BA014278A50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0944517142AB3473ULL,
		0x8A61F31BC923E7EBULL,
		0x3612FD8D84836207ULL,
		0x7D7FEBA45D5A2969ULL,
		0xEFEACA2D04309733ULL,
		0xFEF99AC67593A4D4ULL,
		0xF847A589BCC8933FULL,
		0x8A48945CBD5C89ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0044417140201410ULL,
		0x0021230208222282ULL,
		0x3602B10400820004ULL,
		0x241883005D102021ULL,
		0xE108020800208502ULL,
		0xD200828405832054ULL,
		0x2840808184808207ULL,
		0x0A48000014048800ULL
	}};
	printf("Test Case 38\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2373C3CAB02FDAEFULL,
		0x3886E8FD96391077ULL,
		0xAC8B5980495F86BBULL,
		0x7C2208688C4C504BULL,
		0x1B4FC0100BD737B0ULL,
		0x2C9F3A2489340380ULL,
		0xAE33107B5BD2DC24ULL,
		0x7EACD8ABB2F89156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DC2F7B92765D02ULL,
		0x73997E955AE66B8AULL,
		0x742CC5F354865EDBULL,
		0xBCB611994322817FULL,
		0x2385321161FFE7AEULL,
		0x817EEED2CB418837ULL,
		0xEC0ACAB0D97A7A35ULL,
		0x1052261FEB8F9D04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0250034A90265802ULL,
		0x3080689512200002ULL,
		0x240841804006069BULL,
		0x3C2200080000004BULL,
		0x0305001001D727A0ULL,
		0x001E2A0089000000ULL,
		0xAC02003059525824ULL,
		0x1000000BA2889104ULL
	}};
	printf("Test Case 39\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x000E631038F0112EULL,
		0x9F71CB440D6F2D67ULL,
		0x575FC4A8C554EE82ULL,
		0xACE96857F7D5C829ULL,
		0xE48B6681D3CCE178ULL,
		0x29EED2C321B0BCC4ULL,
		0x232B3802C1CE1E04ULL,
		0xD87B28B94100907DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9169A609AD8BBEBCULL,
		0x040CD1D378BD8E6EULL,
		0x2D8FAE141C087ADFULL,
		0xDA25A556255E56A6ULL,
		0xB243D3E886A2D7D8ULL,
		0x6C4DAC417C2C5AF6ULL,
		0x46CE6542ADFB8A91ULL,
		0x453F532B18722F6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000822002880102CULL,
		0x0400C140082D0C66ULL,
		0x050F840004006A82ULL,
		0x8821205625544020ULL,
		0xA00342808280C158ULL,
		0x284C8041202018C4ULL,
		0x020A200281CA0A00ULL,
		0x403B00290000006DULL
	}};
	printf("Test Case 40\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1C5D71BC1AD1C97CULL,
		0xEA06F9126AC43D2EULL,
		0x3D13DB30FAD5DE6FULL,
		0xB58FAA3BE791A386ULL,
		0x06322942DC65F3E3ULL,
		0xE27E07BDDB1FCDBFULL,
		0xBD24144B620D7C98ULL,
		0x8ACA6FF3B50D0B21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715F8A06D3149242ULL,
		0x406E1DD8BC6F0D8FULL,
		0x16622C1C451BE660ULL,
		0xC25353AB9BB6987EULL,
		0xF96559134B7B632AULL,
		0x81FA463DEA11846FULL,
		0xD1E890355E43677CULL,
		0xADBE04C4A5109681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x105D000412108040ULL,
		0x4006191028440D0EULL,
		0x140208104011C660ULL,
		0x8003022B83908006ULL,
		0x0020090248616322ULL,
		0x807A063DCA11842FULL,
		0x9120100142016418ULL,
		0x888A04C0A5000201ULL
	}};
	printf("Test Case 41\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6568D953A39B35AAULL,
		0xF39D50A901DEA46FULL,
		0xA0435749D9925ADDULL,
		0xDBC1B376780A5072ULL,
		0x56CEB75377428B1FULL,
		0xF2B2BAC4A55C77D9ULL,
		0xECFF7E72745FBD16ULL,
		0xA61E926E119C47E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD012F80D32A4450CULL,
		0x7649D4D0B6E3EFCEULL,
		0xC985D75D493A17A0ULL,
		0xA510B59797DD04EAULL,
		0x6449EB4130563BA6ULL,
		0xE987131208FAC5F8ULL,
		0x0F5C99D88402C557ULL,
		0xEAFBAFCA29C9C351ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4000D80122800508ULL,
		0x7209508000C2A44EULL,
		0x8001574949121280ULL,
		0x8100B11610080062ULL,
		0x4448A34130420B06ULL,
		0xE0821200005845D8ULL,
		0x0C5C185004028516ULL,
		0xA21A824A01884341ULL
	}};
	printf("Test Case 42\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3CEA74337A48C719ULL,
		0x940DE8E25CDC92C3ULL,
		0x7FAEA87BEE75E7EBULL,
		0x14A26429002D226DULL,
		0x9ECB9F4ED313ED13ULL,
		0x842C3163B298E776ULL,
		0x8601A35915B979C3ULL,
		0xC93411696C7A4B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F6C57362285777ULL,
		0x8BCC13B8742A26CFULL,
		0x2BA47CD97E204E3BULL,
		0xD71E5D3FABAE4C16ULL,
		0x5C0B6D235D2F4945ULL,
		0x11B3482F2B549061ULL,
		0x8B0F21451BA3C6F0ULL,
		0x90DC0D16BF81FE54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E2443362084711ULL,
		0x800C00A0540802C3ULL,
		0x2BA428596E20462BULL,
		0x14024429002C0004ULL,
		0x1C0B0D0251034901ULL,
		0x0020002322108060ULL,
		0x8201214111A140C0ULL,
		0x801401002C004A14ULL
	}};
	printf("Test Case 43\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEEB085C49A5A0DC1ULL,
		0xB1D794AA0130F1DFULL,
		0xF0CE7F6174AA7870ULL,
		0x4BBA734363E0B030ULL,
		0xBC8F09FF7B8243EDULL,
		0x924F6DAC73BEAF34ULL,
		0x3BD8D559AC6E5A47ULL,
		0x4928917E40BF4B66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDBC779B6B206FE6ULL,
		0xCAF59D4C5B6CF648ULL,
		0x6DCEE1282B1A32EEULL,
		0xDAFDC733F7502AC4ULL,
		0x30277ED27AD4EE25ULL,
		0x87355BE75223709EULL,
		0xEBD9BF7A791EAB73ULL,
		0xCD3A3C43E3B889EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACB005800A000DC0ULL,
		0x80D594080120F048ULL,
		0x60CE6120200A3060ULL,
		0x4AB8430363402000ULL,
		0x300708D27A804225ULL,
		0x820549A452222014ULL,
		0x2BD89558280E0A43ULL,
		0x4928104240B80962ULL
	}};
	printf("Test Case 44\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x06CF9BCEE2A99585ULL,
		0x57233FD86E67CFF2ULL,
		0xA30ADA95054548E9ULL,
		0x0BDDC45A47D83615ULL,
		0xE9AEC2C33B641735ULL,
		0xE75B9FB9086A2225ULL,
		0xBA81DAAB99954BC2ULL,
		0xCD55B339E1CA912DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE535AD0C20EAA020ULL,
		0x284D1774502C022DULL,
		0x2A91567A9BAC3000ULL,
		0x4E02FB0A51E3FBFFULL,
		0x4E8DAFD044EC1625ULL,
		0xB79D56A86A660669ULL,
		0x64518B9F9A4C8A03ULL,
		0xF80AC8A631C8722FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0405890C20A88000ULL,
		0x0001175040240220ULL,
		0x2200521001040000ULL,
		0x0A00C00A41C03215ULL,
		0x488C82C000641625ULL,
		0xA71916A808620221ULL,
		0x20018A8B98040A02ULL,
		0xC800802021C8102DULL
	}};
	printf("Test Case 45\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA1C2816F699D562DULL,
		0xF1CE7BB1DC17D371ULL,
		0x5A33F637DEE22722ULL,
		0x333409B41DA96459ULL,
		0x21799A120E5E41B8ULL,
		0xF73DE3B9BFB7C761ULL,
		0x63EAB5B47E0150ECULL,
		0x0C36A48103D409C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA538710A9C1C9FULL,
		0x7FE15F1D43A593EDULL,
		0xB5E0219AC3C6480EULL,
		0xA2C88A8EA8C10EE3ULL,
		0x2DF952A7A9279EECULL,
		0xD5AF585707ECE9BDULL,
		0xE4D68D02E82D7BC7ULL,
		0xF8A3E531158D442AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20800061089C140DULL,
		0x71C05B1140059361ULL,
		0x10202012C2C20002ULL,
		0x2200088408810441ULL,
		0x21791202080600A8ULL,
		0xD52D401107A4C121ULL,
		0x60C28500680150C4ULL,
		0x0822A40101840000ULL
	}};
	printf("Test Case 46\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF1E0667390F3E0E6ULL,
		0x2E8BF5697EE55F3FULL,
		0xB4E3FAFC12D6FD71ULL,
		0x194D60A5EF1624E4ULL,
		0xC4FD3CE5976AC216ULL,
		0x88F7F6B48DE6D28DULL,
		0x6F2D21DFF7AEB10CULL,
		0x3D783F056A657D75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x164BAC795F96DA9CULL,
		0x6E252615AD9677B9ULL,
		0x19E76C591A576E96ULL,
		0x21AAC5EB74C842A7ULL,
		0xF9E663D60E2FE543ULL,
		0xD25C9ECD853F8173ULL,
		0x998F1409383E822DULL,
		0x0750EA7A9D7DF501ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104024711092C084ULL,
		0x2E0124012C845739ULL,
		0x10E3685812566C10ULL,
		0x010840A1640000A4ULL,
		0xC0E420C4062AC002ULL,
		0x8054968485268001ULL,
		0x090D0009302E800CULL,
		0x05502A0008657501ULL
	}};
	printf("Test Case 47\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x22FD3F92C2DB1874ULL,
		0x25BA8B8711D48FCAULL,
		0x069D547C4A8EAA30ULL,
		0x849F6C5FECB99B5EULL,
		0x99BAE4BDA97FB818ULL,
		0xBDFECEA5CE331535ULL,
		0xC45504192BD841EBULL,
		0x7B71EBB04C0A78F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AC7F11554E65248ULL,
		0x5FC6150F0C400DD3ULL,
		0x7DC3813F97C0A3FCULL,
		0x42EED43FD23A5E6DULL,
		0x6ADB7E7366B6CFF5ULL,
		0xF94FE94E9D7D91D0ULL,
		0x143F39F9D2AFBA97ULL,
		0x3EA9BABEE04E7952ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C5311040C21040ULL,
		0x0582010700400DC2ULL,
		0x0481003C0280A230ULL,
		0x008E441FC0381A4CULL,
		0x089A643120368810ULL,
		0xB94EC8048C311110ULL,
		0x0415001902880083ULL,
		0x3A21AAB0400A7850ULL
	}};
	printf("Test Case 48\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFA3859EEB29F0590ULL,
		0x8DA5526162A680D8ULL,
		0x708B915544AFA96CULL,
		0x6FADA47797994A39ULL,
		0x1FE090F13C1D310BULL,
		0x1DC9DD70DCA07659ULL,
		0xD2FA90C95FAAC187ULL,
		0xAC11BAB90311C797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4DC4DEAEDFA9AA5ULL,
		0xB8879FA20593AF71ULL,
		0x9B6A89D27ECBB8A5ULL,
		0xE1BA4971D85B34E5ULL,
		0xACE9FC2937828CA1ULL,
		0xC168C5A82A48CC94ULL,
		0x3D9C76472DA50330ULL,
		0x9F741587EAC0A951ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01849EAA09A0080ULL,
		0x8885122000828050ULL,
		0x100A8150448BA824ULL,
		0x61A8007190190021ULL,
		0x0CE0902134000001ULL,
		0x0148C52008004410ULL,
		0x109810410DA00100ULL,
		0x8C10108102008111ULL
	}};
	printf("Test Case 49\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x89C7F7BDD6315B3CULL,
		0x9F307F7C7C43456CULL,
		0x2EFAD2A508AE3753ULL,
		0x1740056B7AEAE974ULL,
		0xF9FAB8409E741BDEULL,
		0x26ED92B9AA00D26AULL,
		0xF8EB5EFF06B7B783ULL,
		0x38C2DB3173E7BF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE171C242C370C60EULL,
		0xE4D558F445196DF1ULL,
		0x8FFCAB74597AE607ULL,
		0xCF83E0D5F6AF3AA7ULL,
		0xC23A24CD241B1AC4ULL,
		0x0F07C888C597EF88ULL,
		0x17547EFAA89D0E66ULL,
		0xE04685D0E8034CA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8141C200C230420CULL,
		0x8410587444014560ULL,
		0x0EF88224082A2603ULL,
		0x0700004172AA2824ULL,
		0xC03A204004101AC4ULL,
		0x060580888000C208ULL,
		0x10405EFA00950602ULL,
		0x2042811060030C04ULL
	}};
	printf("Test Case 50\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x97DE24752F94EF16ULL,
		0xC19987AB6429A0ABULL,
		0x17A44928D79E5C38ULL,
		0x1B26B0E626B4B274ULL,
		0x51B8D06CDEC95189ULL,
		0x4BA1C93A114CC5F5ULL,
		0xA0DCD106604B8670ULL,
		0xFD97F2D7F87D4AF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA57175D11B511B2AULL,
		0xC2198303B290BDC5ULL,
		0x73B67BF67859ABB1ULL,
		0x0584C6DD7021F735ULL,
		0x3FDBE1CA2016EC55ULL,
		0xDEB36B4F11462D81ULL,
		0x5826D6F73C68EF9AULL,
		0x3870A1D1A9EDE4C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x855024510B100B02ULL,
		0xC01983032000A081ULL,
		0x13A4492050180830ULL,
		0x010480C42020B234ULL,
		0x1198C04800004001ULL,
		0x4AA1490A11440581ULL,
		0x0004D00620488610ULL,
		0x3810A0D1A86D40C0ULL
	}};
	printf("Test Case 51\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4F18618242DAC783ULL,
		0x99268BF68BCB3BFCULL,
		0x6459842202B569D4ULL,
		0x4B06F2A0C8541422ULL,
		0x2CB4DC7BB1596A2CULL,
		0x200E2B31B187DD40ULL,
		0xF4ACF1FC40DEEB27ULL,
		0x16EF395F0230E712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BA2225D7F1FD4E9ULL,
		0x998D1A7398F12018ULL,
		0x1A83D984DD0CFD1DULL,
		0xD783EBA60585CCBCULL,
		0x1CC75E4D760C3629ULL,
		0x3DEA5F8663C91636ULL,
		0x9BAB8ED769062BEBULL,
		0xF22D8F23D190ED77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B002000421AC481ULL,
		0x99040A7288C12018ULL,
		0x0001800000046914ULL,
		0x4302E2A000040420ULL,
		0x0C845C4930082228ULL,
		0x200A0B0021811400ULL,
		0x90A880D440062B23ULL,
		0x122D09030010E512ULL
	}};
	printf("Test Case 52\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEAA2D8B0BCE51EE6ULL,
		0x274379D72839D309ULL,
		0xFAEB347DC9B0501AULL,
		0x6ECF5720A37EFA6EULL,
		0x10220B900FF8DF8AULL,
		0x51CF49A715DC80AAULL,
		0xC0B1956AF5D93CA0ULL,
		0x70D1E36C1CD318D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8477178DA7E7330ULL,
		0x485BEA825B4139A2ULL,
		0x9CDB8754C2C19B1FULL,
		0xB56AAE14A3D66D11ULL,
		0xA53148BF7C154DB8ULL,
		0x350B46F685571E41ULL,
		0x15723BAE7DBBA743ULL,
		0x42010D098E25362CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC802503098641220ULL,
		0x0043688208011100ULL,
		0x98CB0454C080101AULL,
		0x244A0600A3566800ULL,
		0x002008900C104D88ULL,
		0x110B40A605540000ULL,
		0x0030112A75992400ULL,
		0x400101080C011004ULL
	}};
	printf("Test Case 53\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2855E55D77AF2E62ULL,
		0x73E093EB9B955B34ULL,
		0xB65F3A537139387AULL,
		0xFD92D9F861EFB80CULL,
		0x2B666219ABB66765ULL,
		0x5DDFF0F027E3CD2FULL,
		0x6F951CBAD0997AB4ULL,
		0x84148A1C66AAA7CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C951D4D6FC11AFCULL,
		0xCB3922582453433EULL,
		0x1B156A4B665DAAEBULL,
		0x3712990BF1D80510ULL,
		0xFD5EB52C9018F0B8ULL,
		0x16E8582A49486BEEULL,
		0x941BA00811024E70ULL,
		0x9604CD12E3928870ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2815054D67810A60ULL,
		0x4320024800114334ULL,
		0x12152A436019286AULL,
		0x3512990861C80000ULL,
		0x2946200880106020ULL,
		0x14C850200140492EULL,
		0x0411000810004A30ULL,
		0x8404881062828040ULL
	}};
	printf("Test Case 54\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5622D5DD8E0BB8FDULL,
		0x7429E5D4E4807C14ULL,
		0x8F8A61F6F2341ADDULL,
		0x28CB516273A07F62ULL,
		0x0AF307E83138B6AAULL,
		0x535F4F9411592661ULL,
		0x3FFFA02F5696524EULL,
		0x727CFF5A6BD693E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x345E91FDE312264EULL,
		0xE72E8E1CD22F417CULL,
		0xEDAD8DF5E6790FF1ULL,
		0xBF101B29ADDE3925ULL,
		0x4359857D7230C164ULL,
		0x069DF18790544DEBULL,
		0xDA778FAB26DE5C0EULL,
		0xC6560285602BD112ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x140291DD8202204CULL,
		0x64288414C0004014ULL,
		0x8D8801F4E2300AD1ULL,
		0x2800112021803920ULL,
		0x0251056830308020ULL,
		0x021D418410500461ULL,
		0x1A77802B0696500EULL,
		0x4254020060029102ULL
	}};
	printf("Test Case 55\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x81DC023B23FA138BULL,
		0x32B342AE461CAC30ULL,
		0xACC33B42813598B3ULL,
		0x86F3A88E5127ABCCULL,
		0x7273960682359F3CULL,
		0xE44005EB0E49966DULL,
		0x5B36B458EF05A3B8ULL,
		0x6D3E9F80C452215BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82ADE03481AE6B2BULL,
		0x93200D70E7D42DA2ULL,
		0xFAEAAD204284C599ULL,
		0x0FAFD535067BF55DULL,
		0xBAC76A08EF97DBA5ULL,
		0x8D77877BDEFC56D5ULL,
		0x8808E90876E3C7C3ULL,
		0xD7832FA4F018C99FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808C003001AA030BULL,
		0x1220002046142C20ULL,
		0xA8C2290000048091ULL,
		0x06A380040023A14CULL,
		0x3243020082159B24ULL,
		0x8440056B0E481645ULL,
		0x0800A00866018380ULL,
		0x45020F80C010011BULL
	}};
	printf("Test Case 56\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC0B32DE2130A1F49ULL,
		0x37E0E2DF93F8FD36ULL,
		0xD49938FA8D1C7FD7ULL,
		0x7106200F53AE6629ULL,
		0x32E275391E2ABBD4ULL,
		0xD21ADD99E1772E38ULL,
		0x5C86828FA6C0063FULL,
		0x51A9172BE48C01FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE166A1E852261234ULL,
		0xCF1CAA5B070F3224ULL,
		0x6F13E555577E7027ULL,
		0xD05F7FCEDF45C5EEULL,
		0x27360383EDA13587ULL,
		0xEB347533EC353FA3ULL,
		0xA03A450FFC6B3FB7ULL,
		0x1C6CA576DDA1B5C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC02221E012021200ULL,
		0x0700A25B03083024ULL,
		0x44112050051C7007ULL,
		0x5006200E53044428ULL,
		0x222201010C203184ULL,
		0xC2105511E0352E20ULL,
		0x0002000FA4400637ULL,
		0x10280522C48001C5ULL
	}};
	printf("Test Case 57\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA842FEA5C871FDEAULL,
		0xA18BD18BE9B1FAE5ULL,
		0x6CC4450629E886F5ULL,
		0x686CC05251659060ULL,
		0xE7EB32FB6C1BAFA5ULL,
		0x2601C5B4E9E9D7A0ULL,
		0x8DB68D36729AA421ULL,
		0x014289098FDC92C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC24582C312925D9EULL,
		0xB567C3D199C678E4ULL,
		0x683D338B834B38C7ULL,
		0x0E2B5DCFD088D417ULL,
		0xC09A9ABD5B565726ULL,
		0xECE65B48408CFA97ULL,
		0x90B7FE4061BAE320ULL,
		0xCCACAAA492D55BD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8040828100105D8AULL,
		0xA103C181898078E4ULL,
		0x68040102014800C5ULL,
		0x0828404250009000ULL,
		0xC08A12B948120724ULL,
		0x240041004088D280ULL,
		0x80B68C00609AA020ULL,
		0x0000880082D412C2ULL
	}};
	printf("Test Case 58\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD0CF7D98EAEC43EAULL,
		0x8177AE156967ED24ULL,
		0x18971A3078083C3AULL,
		0x40D4D2E45DCA8897ULL,
		0xE8BFD8ABA7AD15A7ULL,
		0x2FB1862A982AA06DULL,
		0xF18947700CE2157EULL,
		0xE9E88A63B1FF3E88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF004A40F7F87129ULL,
		0x21EAF97FFDCE0492ULL,
		0x53169D0FACE886F0ULL,
		0x3A2D3B9962F8FC58ULL,
		0x72DA7676B1A3C114ULL,
		0x3AABDAB2EC6D7048ULL,
		0x7CE3A9EBE27D1CCEULL,
		0x3A81552CD23CE2E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD0004800E2E84128ULL,
		0x0162A81569460400ULL,
		0x1016180028080430ULL,
		0x0004128040C88810ULL,
		0x609A5022A1A10104ULL,
		0x2AA1822288282048ULL,
		0x708101600060144EULL,
		0x28800020903C2280ULL
	}};
	printf("Test Case 59\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5E61E3A28F637E0CULL,
		0x6A4195A841B02AE5ULL,
		0x0228AA35A107B06BULL,
		0x5855135B361CE1AFULL,
		0xB75580DA417CB924ULL,
		0x8653A19E111A12B5ULL,
		0x12AC3C46186EFAF2ULL,
		0x3A2C4DF06EC1FE56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4B83F6EE70F806ULL,
		0x71509D16620EC2D2ULL,
		0x5B7C3955087BB64DULL,
		0x74BF687D3E3060B4ULL,
		0x0178314F0F39864BULL,
		0xABC83BCB7A9FCAF8ULL,
		0x1E91B3012F7EE264ULL,
		0xCD78D9F0657BD143ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C4183A28E607804ULL,
		0x60409500400002C0ULL,
		0x022828150003B049ULL,
		0x50150059361060A4ULL,
		0x0150004A01388000ULL,
		0x8240218A101A02B0ULL,
		0x12803000086EE260ULL,
		0x082849F06441D042ULL
	}};
	printf("Test Case 60\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDDA796867669DC00ULL,
		0xEBDBBB6C08D4499DULL,
		0xF017CF14304043D3ULL,
		0xE421D8C6BB0C7D8FULL,
		0xFA328C07942204A0ULL,
		0x5536D9B3BBAFCB96ULL,
		0xBCFF300350EB1F1DULL,
		0x534850AF887D4FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4760C3E1E01409BULL,
		0xB529C3139016FDF2ULL,
		0xF9579A0EA6A53164ULL,
		0xA8AA16B80688B277ULL,
		0x0C82E1C835EA0884ULL,
		0x3587299F85E3EE83ULL,
		0x1838EA3921A051F5ULL,
		0x90F4D6D68CFAAE53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC426040616014000ULL,
		0xA109830000144990ULL,
		0xF0178A0420000140ULL,
		0xA020108002083007ULL,
		0x0802800014220080ULL,
		0x1506099381A3CA82ULL,
		0x1838200100A01115ULL,
		0x1040508688780E40ULL
	}};
	printf("Test Case 61\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCE89AAC4E8B8F964ULL,
		0xA9F01F3D06525D26ULL,
		0x977395264AD56D7EULL,
		0x3B64AAD901707762ULL,
		0xC91443ACFFC2B00DULL,
		0x5B4B3E94BCDE9C1EULL,
		0xDA404DBFA2B99474ULL,
		0xDBE05D16E41020B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA5AD4477973AB8ULL,
		0x1E57EAA42EF78381ULL,
		0x5770E8980E8275CBULL,
		0x98B07C21EB600886ULL,
		0x1D9404DF9CC8A59BULL,
		0x88409DA7B70E091AULL,
		0x61E971D0DB5D7650ULL,
		0x476AEB94C9069AF3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E81A84460903820ULL,
		0x08500A2406520100ULL,
		0x177080000A80654AULL,
		0x1820280101600002ULL,
		0x0914008C9CC0A009ULL,
		0x08401C84B40E081AULL,
		0x4040419082191450ULL,
		0x43604914C00000B0ULL
	}};
	printf("Test Case 62\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x910A74B126E21440ULL,
		0xBA9E51CB37E0568DULL,
		0x517E87D68B123790ULL,
		0xC0E6F3095E9251DAULL,
		0xFC0D35951D4C8271ULL,
		0x9C507CA997E83A29ULL,
		0x891BE72A3E9AB036ULL,
		0xE96817012AAB9FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89E166196D3155CULL,
		0xCA271FE4741A5066ULL,
		0xE8A99F50AD894B9DULL,
		0x0DC6998F5B4446FFULL,
		0x4D68EAB48A87C21CULL,
		0x21A250CF5BD0DC3CULL,
		0x4721AD46D17854F0ULL,
		0xBA2287E44FC6BB4DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800A142106C21440ULL,
		0x8A0611C034005004ULL,
		0x4028875089000390ULL,
		0x00C691095A0040DAULL,
		0x4C08209408048210ULL,
		0x0000508913C01828ULL,
		0x0101A50210181030ULL,
		0xA82007000A829B48ULL
	}};
	printf("Test Case 63\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFA656AC01EF9DDCEULL,
		0xB292F672D6F7A441ULL,
		0x26C34AB98F25A2A3ULL,
		0x6D721B8422977E44ULL,
		0x6062DD51087EA26EULL,
		0x8B008904155959C4ULL,
		0xFC8A30C5A017F242ULL,
		0x3BEF9E2316148A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5FEDFE38C9BEABULL,
		0xDB352DE5CF2174C8ULL,
		0xBA14831A98912637ULL,
		0x9968E31DE0749EDEULL,
		0x80A5EFC9D0469ED4ULL,
		0x718738D4B60B8CACULL,
		0x12B8F4269F892220ULL,
		0x70F84C1EED2878CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A4568C018C99C8AULL,
		0x92102460C6212440ULL,
		0x2200021888012223ULL,
		0x0960030420141E44ULL,
		0x0020CD4100468244ULL,
		0x0100080414090884ULL,
		0x1088300480012200ULL,
		0x30E80C0204000848ULL
	}};
	printf("Test Case 64\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB6FEAD81E7077BE9ULL,
		0xDFCFEBB0888EA274ULL,
		0x3C9379AE31654303ULL,
		0x81443F98CE409EBCULL,
		0x547776150BF4BE33ULL,
		0xD7B4264F42E90694ULL,
		0x099D309A2C1C1CCAULL,
		0x6391C38F2E1240ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x746A4315593F5C12ULL,
		0x3C177AF20245DAA9ULL,
		0x13C15275A280666FULL,
		0x40A500EB3E7E4AA2ULL,
		0x02D035C71B3F2224ULL,
		0x24D2633857556C62ULL,
		0xCFEE65DC83848D5DULL,
		0xDF651AC2A8FBADC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x346A010141075800ULL,
		0x1C076AB000048220ULL,
		0x1081502420004203ULL,
		0x000400880E400AA0ULL,
		0x005034050B342220ULL,
		0x0490220842410400ULL,
		0x098C209800040C48ULL,
		0x4301028228120080ULL
	}};
	printf("Test Case 65\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD226CB68A2E13F79ULL,
		0x18F85ED057F2E008ULL,
		0x41FCB4E2BBDA8CE5ULL,
		0xF112CD6E75A11A77ULL,
		0x5C47ED573055E8ACULL,
		0xC70D09206F03F7C6ULL,
		0x5273975605299415ULL,
		0x5B57D67EE3463CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BE4B5CD75ACBEF5ULL,
		0xF687A9DDC4E8BBCFULL,
		0x2ADF56863BF8E99CULL,
		0x90DC8B1B7A216176ULL,
		0x5386F5FD2281A64EULL,
		0x2C286C8C96592FC9ULL,
		0x2B7E8B7AF1D41BF6ULL,
		0x341833AB774BE527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9224814820A03E71ULL,
		0x108008D044E0A008ULL,
		0x00DC14823BD88884ULL,
		0x9010890A70210076ULL,
		0x5006E5552001A00CULL,
		0x04080800060127C0ULL,
		0x0272835201001014ULL,
		0x1010122A63422403ULL
	}};
	printf("Test Case 66\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4D50DE55130C3E25ULL,
		0x34151159F4AC9D69ULL,
		0x48E3423B9C086E28ULL,
		0x9E07A986A7915515ULL,
		0x7E262EBFCF20FE60ULL,
		0xA31E1A64A41D6DE4ULL,
		0x6B4625C43D5A23ECULL,
		0xC46EBC5A0527485DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x836CCD22BDCBE549ULL,
		0x6F6E5581F5712713ULL,
		0x567603F454717795ULL,
		0x013D4CFFF6169332ULL,
		0xC485C105DF756DFEULL,
		0x84453113DE84469EULL,
		0xBE7CB2BDE7CC062DULL,
		0x6C81AD6389D645B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0140CC0011082401ULL,
		0x24041101F4200501ULL,
		0x4062023014006600ULL,
		0x00050886A6101110ULL,
		0x44040005CF206C60ULL,
		0x8004100084044484ULL,
		0x2A4420842548022CULL,
		0x4400AC4201064011ULL
	}};
	printf("Test Case 67\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAA39F532627B2EE9ULL,
		0x123F525A2A66DCC8ULL,
		0x9AA495F9C32ABA8BULL,
		0x9BAF16049D25E591ULL,
		0x436C4C596D5C9E2DULL,
		0x004D3EEC7E2B708AULL,
		0x6400AC9D64D20844ULL,
		0xA77BDBA2A04F7B67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3903147B5FB59F2ULL,
		0x3CADA5D36F82A719ULL,
		0xC532DFDD53C492A9ULL,
		0x0B3F514D3DE85BEDULL,
		0xEE4301F4819FAFF8ULL,
		0xBF01AD01A73CF8DCULL,
		0x40989DFD370A80D1ULL,
		0x08068AF8948A8442ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2103102207B08E0ULL,
		0x102D00522A028408ULL,
		0x802095D943009289ULL,
		0x0B2F10041D204181ULL,
		0x42400050011C8E28ULL,
		0x00012C0026287088ULL,
		0x40008C9D24020040ULL,
		0x00028AA0800A0042ULL
	}};
	printf("Test Case 68\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x41846F466D61DC41ULL,
		0xEB284FCB377F6735ULL,
		0x1A0C12C179969087ULL,
		0x8733BBAE5C77AA5AULL,
		0x2CBACBDA676B2669ULL,
		0xA2061710AF9C899EULL,
		0x9F215018135FD4E7ULL,
		0x848F06A13E22FF2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0AE9DA56422F9C1ULL,
		0x53447530535E7F61ULL,
		0x624B9AC9E5A95283ULL,
		0xAD75A69E2E043F64ULL,
		0x3A2A782142FF762DULL,
		0xD37A64E03FACD8E7ULL,
		0x90EF59158DCF54A2ULL,
		0xAAA925C4F68188D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40840D046420D841ULL,
		0x43004500135E6721ULL,
		0x020812C161801083ULL,
		0x8531A28E0C042A40ULL,
		0x282A4800426B2629ULL,
		0x820204002F8C8886ULL,
		0x90215010014F54A2ULL,
		0x8089048036008802ULL
	}};
	printf("Test Case 69\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1862C878D92EA76EULL,
		0x89F373E8BEA7E00EULL,
		0x6A3E837C15B6111BULL,
		0x9B701FA0D1651AA6ULL,
		0x4F5D76D6422C6CAAULL,
		0x348DFF28BEC77965ULL,
		0xD1D76CBD20738394ULL,
		0x2804DB28CAF167A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD922E2F3E1049D6CULL,
		0xA67CAD11F8AD99D6ULL,
		0x68D98BB311E1CB57ULL,
		0xC9A9CD4871D29687ULL,
		0xA2AB71D71205C37AULL,
		0xA5401E5CC55832C1ULL,
		0x7187555ECFBF0F90ULL,
		0xC83874963FA7DD17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1822C070C104856CULL,
		0x80702100B8A58006ULL,
		0x6818833011A00113ULL,
		0x89200D0051401286ULL,
		0x020970D60204402AULL,
		0x24001E0884403041ULL,
		0x5187441C00330390ULL,
		0x080050000AA14501ULL
	}};
	printf("Test Case 70\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x00214D0D43A20360ULL,
		0xB20BB0A8A72F1825ULL,
		0x52C81D9083EDF6A6ULL,
		0xCC92D4662AC20BF1ULL,
		0x3215CFC53791B4F3ULL,
		0x484AE22375467E71ULL,
		0xD6F982B1BE236277ULL,
		0xA1D7F4E8B73380AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3326A128B1F0502ULL,
		0xC8954A40302C5285ULL,
		0xF25E454C1C5C6EA4ULL,
		0xB1FE4698538192F1ULL,
		0xFB88DDB8953BB6FAULL,
		0x5A9785E826A391F6ULL,
		0xE2C95A9A4C337A0EULL,
		0xEB624644C6D4673BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0020480003020100ULL,
		0x80010000202C1005ULL,
		0x52480500004C66A4ULL,
		0x80924400028002F1ULL,
		0x3200CD801511B4F2ULL,
		0x4802802024021070ULL,
		0xC2C902900C236206ULL,
		0xA14244408610002AULL
	}};
	printf("Test Case 71\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0DCE1FA90651354FULL,
		0xEA69DD544CAF0C4AULL,
		0x1BC4E041309BFFC3ULL,
		0xB3111ECB1562F2F1ULL,
		0x8E08ED851D67806DULL,
		0x39101796861C2B30ULL,
		0x1F4F19B49315BE93ULL,
		0x6C94148EEA254DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F65E5B567705E2DULL,
		0xE9BA5C88BAF96C16ULL,
		0xBCF1455586F4EB11ULL,
		0x284B37E7DB86E19FULL,
		0xE202BF5A29663F10ULL,
		0xC9A6E3E96C72057DULL,
		0x8A59791946E9A7EAULL,
		0x60D50BD7B88CEF83ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D4405A10650140DULL,
		0xE8285C0008A90C02ULL,
		0x18C040410090EB01ULL,
		0x200116C31102E091ULL,
		0x8200AD0009660000ULL,
		0x0900038004100130ULL,
		0x0A4919100201A682ULL,
		0x60940086A8044D82ULL
	}};
	printf("Test Case 72\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF41D71C041459F82ULL,
		0xA9C2A1A61E50268CULL,
		0x3DB0A16AF23CDE96ULL,
		0x03E506F4C333AD4CULL,
		0xCB8DEF7677185562ULL,
		0x043B10E188381BFEULL,
		0xDD3018D8AB9F2611ULL,
		0x025E4C4C2AB82980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x742D26E0A7630DB6ULL,
		0x07353D49EB4E0C78ULL,
		0xE7EA5EF4A97A4388ULL,
		0xCF819246B95C392CULL,
		0xCD926E789559A84EULL,
		0x8BAB0FCDBF75E7BBULL,
		0x58788FBB3486CF1BULL,
		0x4DAA20264114460FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x740D20C001410D82ULL,
		0x010021000A400408ULL,
		0x25A00060A0384280ULL,
		0x038102448110290CULL,
		0xC9806E7015180042ULL,
		0x002B00C1883003BAULL,
		0x5830089820860611ULL,
		0x000A000400100000ULL
	}};
	printf("Test Case 73\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA7B87C8E973C3F5EULL,
		0xAE9040B5F96E7874ULL,
		0x3B0BEBB3C9B168AAULL,
		0x2BDED14B745D5AECULL,
		0xC18DC805172DF97CULL,
		0xA8A81BD358C207B6ULL,
		0xF3DED017D3C286C1ULL,
		0x96A8B96FD8DDA154ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03722652606DA72DULL,
		0x87DDECE43C354BA3ULL,
		0xDF56A9961034CDFEULL,
		0x9BF62006949592D7ULL,
		0x64EF0B57971D314DULL,
		0x5ACE37A5BEC76B29ULL,
		0xA307ADFCC573B7D9ULL,
		0x44B7013634FDE8D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03302402002C270CULL,
		0x869040A438244820ULL,
		0x1B02A992003048AAULL,
		0x0BD60002141512C4ULL,
		0x408D0805170D314CULL,
		0x0888138118C20320ULL,
		0xA3068014C14286C1ULL,
		0x04A0012610DDA054ULL
	}};
	printf("Test Case 74\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8134A0B0511E2AD9ULL,
		0xC216A40568D3A25CULL,
		0x1DD219C53C2DFB31ULL,
		0x9238B83B9C9672C6ULL,
		0xDEF7695322DFECBBULL,
		0x74102BAB43D1D00BULL,
		0x401F0AC2D4B0F8B5ULL,
		0x7227A84AE0758E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC591A442087062EEULL,
		0x26369CFED167B4EDULL,
		0x030DF7F181AA7C39ULL,
		0x9247E4180A32206DULL,
		0x6D160DA4004ADA07ULL,
		0x392B71A9BB797FE1ULL,
		0x9ACCCE471C5D6979ULL,
		0x37D0200E535FC5B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8110A000001022C8ULL,
		0x021684044043A04CULL,
		0x010011C100287831ULL,
		0x9200A01808122044ULL,
		0x4C160900004AC803ULL,
		0x300021A903515001ULL,
		0x000C0A4214106831ULL,
		0x3200200A40558421ULL
	}};
	printf("Test Case 75\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7E35810605936930ULL,
		0x7A17FF00F9A0CE4DULL,
		0x5E0542835B2D44A1ULL,
		0x5BED78395CA5698EULL,
		0x69C61A4A29446546ULL,
		0xAC6B101DE0F6AC85ULL,
		0x388492D4A05318ACULL,
		0xD0A77C55F8DB48CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x714B255D018388D7ULL,
		0xA482C3A1CA8BDE3AULL,
		0xC5F6866386DD7BD7ULL,
		0x52CCE1BC569BAEA9ULL,
		0x8726A75E4488EFF9ULL,
		0xB9F41EE8389F92ABULL,
		0x9ED5D9D71A27863CULL,
		0xF07945D16B216E5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7001010401830810ULL,
		0x2002C300C880CE08ULL,
		0x44040203020D4081ULL,
		0x52CC603854812888ULL,
		0x0106024A00006540ULL,
		0xA860100820968081ULL,
		0x188490D40003002CULL,
		0xD02144516801484CULL
	}};
	printf("Test Case 76\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x42EF65FF46DA6C00ULL,
		0x0035DFD4FE30192CULL,
		0xDB602DA018E2E619ULL,
		0x879A7E6E1C62A720ULL,
		0x4B9142854AF94AA3ULL,
		0xC72F11B5478572E2ULL,
		0x431E8E0564CA2AF3ULL,
		0x879BE55CEA8AA0DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF398AD7A9FCC0E4ULL,
		0xF7B3DF4664C4B9E5ULL,
		0x042B48AB179006CDULL,
		0x3D2C12F561F714DEULL,
		0x0BFFDF28D2219584ULL,
		0x4C145C34B501EC31ULL,
		0xFB8308ADA78E1373ULL,
		0x0ABF8B84A5C8FBDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x422900D700D84000ULL,
		0x0031DF4464001924ULL,
		0x002008A010800609ULL,
		0x0508126400620400ULL,
		0x0B91420042210080ULL,
		0x4404103405016020ULL,
		0x43020805248A0273ULL,
		0x029B8104A088A0DBULL
	}};
	printf("Test Case 77\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE3F3C0083F5E5E08ULL,
		0x2F07644A359649F0ULL,
		0xEFD182098A0C9A44ULL,
		0x6D256464EC9D396FULL,
		0xC083693B10D489D3ULL,
		0xC92072317F6DF4E1ULL,
		0xA6F158A463E50FCFULL,
		0xD3C4E4AF65C0310FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252D22D74B6C49C1ULL,
		0xF81704DCB8CE258AULL,
		0xF542756C2FEEE26FULL,
		0x741E2EDB0974DA59ULL,
		0x69FA33D577176115ULL,
		0xB71C71995B7DCB5BULL,
		0x8D2EFAE7028DCFB9ULL,
		0xEAB06005755FF256ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x212100000B4C4800ULL,
		0x2807044830860180ULL,
		0xE54000080A0C8244ULL,
		0x6404244008141849ULL,
		0x4082211110140111ULL,
		0x810070115B6DC041ULL,
		0x842058A402850F89ULL,
		0xC280600565403006ULL
	}};
	printf("Test Case 78\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5E990498A26B1472ULL,
		0x0CE8C4CDD7365093ULL,
		0xED926FF6599F3ED8ULL,
		0x6262958ADC330ECBULL,
		0xB18DDFEA8B9C147EULL,
		0x7D453E0D39F8D27DULL,
		0x8FF4AEF40A2AD66DULL,
		0x539480100673D488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A48A5E0C1940DD6ULL,
		0x4C86450C2D928F53ULL,
		0x425AF9636EA95010ULL,
		0x6BAB2D7243467059ULL,
		0xCBE7F23EE4BF3148ULL,
		0x72CB4FCFC415193CULL,
		0xE953AF4642E8471FULL,
		0x869D92BA906B7DAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A08048080000452ULL,
		0x0C80440C05120013ULL,
		0x4012696248891010ULL,
		0x6222050240020049ULL,
		0x8185D22A809C1048ULL,
		0x70410E0D0010103CULL,
		0x8950AE440228460DULL,
		0x0294801000635488ULL
	}};
	printf("Test Case 79\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x932DBC038DF84AEAULL,
		0x538C75D99A82F02AULL,
		0xC7C9BE3F0C4EEDD8ULL,
		0x03A96171A4494CEDULL,
		0x1A0E91A54710C30AULL,
		0x5F796767E71D5B16ULL,
		0x04B52CDA18CC08B4ULL,
		0x65E791C2405B8867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA767926AC52A97E9ULL,
		0x023953C1126FEC0DULL,
		0xCED97DBB0F1570AFULL,
		0xA64CEDD82EF36316ULL,
		0x6CB156E0C5330FC7ULL,
		0x7260A89A28DDF06EULL,
		0x0E3D29C42262971AULL,
		0xB655FDAB2D0A391BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83259002852802E8ULL,
		0x020851C11202E008ULL,
		0xC6C93C3B0C046088ULL,
		0x0208615024414004ULL,
		0x080010A045100302ULL,
		0x52602002201D5006ULL,
		0x043528C000400010ULL,
		0x24459182000A0803ULL
	}};
	printf("Test Case 80\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9D57956DB80E14BEULL,
		0x25D25B8AC318C0E6ULL,
		0xC827788C8DE790F4ULL,
		0x78B93B97A13B7996ULL,
		0x0E72FF5A005D795BULL,
		0x595D56275F7FB6D5ULL,
		0x5C9BEC1FD6F69600ULL,
		0xDCEEB42F0E158680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2857C524166BCC3ULL,
		0x367D5D8C7440EB35ULL,
		0xE94FDDAB4F17D1B6ULL,
		0x4352C3993DD0452EULL,
		0x304A8A349BECD80CULL,
		0xD41FCB6021908B3CULL,
		0xFBF91ABE9F1BB4B4ULL,
		0x66BAAC8CFBCA86DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9005144000061482ULL,
		0x245059884000C024ULL,
		0xC80758880D0790B4ULL,
		0x4010039121104106ULL,
		0x00428A10004C5808ULL,
		0x501D422001108214ULL,
		0x5899081E96129400ULL,
		0x44AAA40C0A008680ULL
	}};
	printf("Test Case 81\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB621017F005C471CULL,
		0x3D00E7621DAD58E1ULL,
		0xB2B94D2009B7AD32ULL,
		0x8DD64B1258458ED7ULL,
		0x13B55722D9FB90DBULL,
		0xE69FA961F957B0FBULL,
		0xFF8487C76CFE4CCDULL,
		0x93E84ED693567EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A152908846E0F67ULL,
		0x257C3607E26C3FA7ULL,
		0xA3FB96F5B7316427ULL,
		0x84FBA2351D666AFBULL,
		0x2EA87262A9747DA4ULL,
		0xE091D9F96A58BA81ULL,
		0x04C4C23F9022895FULL,
		0x5684DBBB4356D812ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22010108004C0704ULL,
		0x25002602002C18A1ULL,
		0xA2B9042001312422ULL,
		0x84D2021018440AD3ULL,
		0x02A0522289701080ULL,
		0xE09189616850B081ULL,
		0x048482070022084DULL,
		0x12804A9203565810ULL
	}};
	printf("Test Case 82\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEA57400A92DF1EA9ULL,
		0xD42AF0E13150CE58ULL,
		0x2EC40F4AAD0D3BF5ULL,
		0x92F38BC88DB4675EULL,
		0x17D8FB7C306D8927ULL,
		0xDC9141E4B450B30CULL,
		0xF41D05A8D00DCBFFULL,
		0x2611C804A946C9A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D35CC494DB211F5ULL,
		0xEC792B9C4029009DULL,
		0x5E78583643AAE821ULL,
		0x1156324D5D87C98CULL,
		0x35CEE9FC9C6782E3ULL,
		0x0A6820A26657C878ULL,
		0xF20C66EABE1F226AULL,
		0xF3D8B506AE97E75CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28154008009210A1ULL,
		0xC428208000000018ULL,
		0x0E40080201082821ULL,
		0x105202480D84410CULL,
		0x15C8E97C10658023ULL,
		0x080000A024508008ULL,
		0xF00C04A8900D026AULL,
		0x22108004A806C108ULL
	}};
	printf("Test Case 83\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3CA1983F664FEFECULL,
		0xF65131A2C676588FULL,
		0xB1D59C3D1A3DB58DULL,
		0x7442B91322E8C400ULL,
		0xAE86128E313888C6ULL,
		0xC5D24E4162F4D82FULL,
		0x57291749715AC13AULL,
		0x05D19BA143DCC5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59AF2CB470131A10ULL,
		0x5E100E32DA01F992ULL,
		0xB9C79133140FFE96ULL,
		0x2BAEB36C583BAB00ULL,
		0x295551283C176269ULL,
		0xB806D5AB1D11AEE2ULL,
		0x10C38916DB1C6F2EULL,
		0x92968E5BC1BEEA2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18A1083460030A00ULL,
		0x56100022C2005882ULL,
		0xB1C59031100DB484ULL,
		0x2002B10000288000ULL,
		0x2804100830100040ULL,
		0x8002440100108822ULL,
		0x100101005118412AULL,
		0x00908A01419CC000ULL
	}};
	printf("Test Case 84\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x27D43A40FFE2D23BULL,
		0x18FAB40FF74153C0ULL,
		0x0C2C084082BDA710ULL,
		0x137B36ACAEBA298DULL,
		0xBD40DC039CEDF8BFULL,
		0xEC098D3A37D746DEULL,
		0xC4C56474A0B573E5ULL,
		0xA6223057235B6FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38B421A895EFA69AULL,
		0x0A752C4EFF4C2F33ULL,
		0x1FDC3F48F3499509ULL,
		0x554FD792796E1497ULL,
		0x9999DCA8DD9293FBULL,
		0xA0613EEE7B6D7CFFULL,
		0x44891B6A6913828AULL,
		0x3E9121B872F07D3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2094200095E2821AULL,
		0x0870240EF7400300ULL,
		0x0C0C084082098500ULL,
		0x114B1680282A0085ULL,
		0x9900DC009C8090BBULL,
		0xA0010C2A334544DEULL,
		0x4481006020110280ULL,
		0x2600201022506D2AULL
	}};
	printf("Test Case 85\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDC2480320D660B26ULL,
		0x6578DBCEDB5EBB40ULL,
		0x0841A53171E75856ULL,
		0xDE84F1E979ADC70AULL,
		0x35D751143EEC6EA7ULL,
		0xE08188F1A088223AULL,
		0x93CA19CBBF24009BULL,
		0x11DFF46387F5C3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F4D8A66B6E9733AULL,
		0x015D84B8BA06F413ULL,
		0x83FBD3B8C8F1058FULL,
		0x2B334FA24376A033ULL,
		0x9C38FD37D284884FULL,
		0x0A7BE56D65CC3F7AULL,
		0x4A860E5B384C6157ULL,
		0x6074532C94D995E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C04802204600322ULL,
		0x015880889A06B000ULL,
		0x0041813040E10006ULL,
		0x0A0041A041248002ULL,
		0x1410511412840807ULL,
		0x000180612088223AULL,
		0x0282084B38040013ULL,
		0x0054502084D181E2ULL
	}};
	printf("Test Case 86\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8A1F129D9BF39952ULL,
		0x44671CC078FC9E8FULL,
		0x43D149AC2486A29DULL,
		0x1921B81B9534CE2FULL,
		0x0FD9E61F3CBA71F1ULL,
		0x291E67AFAC5C1744ULL,
		0x121F2435375A9CE1ULL,
		0x7D2CB73711DE4A66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCCCF02AF5AE9242ULL,
		0xEF0DE800274D3F42ULL,
		0xA86EC2A80B19B4DDULL,
		0x3948B64CDD0FE5BBULL,
		0x54EB5F59419A85E3ULL,
		0xF74982A8A3056E35ULL,
		0xEBF8E15427BC5BADULL,
		0xE53E3D8B1EFF82CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x880C100891A29042ULL,
		0x44050800204C1E02ULL,
		0x004040A80000A09DULL,
		0x1900B0089504C42BULL,
		0x04C94619009A01E1ULL,
		0x210802A8A0040604ULL,
		0x02182014271818A1ULL,
		0x652C350310DE0242ULL
	}};
	printf("Test Case 87\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x72D2B99898089F11ULL,
		0x755FA58FFF1D0685ULL,
		0x310E06A14AC706C8ULL,
		0x8278C455BF3A6138ULL,
		0xBB5EA60F2E85C516ULL,
		0xBA2E758EBF39DB57ULL,
		0xF19295DE68EF2199ULL,
		0x436234A93A47C394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADFE30E0012AD6EULL,
		0x6777CAB62FE50764ULL,
		0x521F9888B2CB76E0ULL,
		0xD544243BC691614FULL,
		0x56BDE7C00F006C0BULL,
		0x6960D5FE54684896ULL,
		0xC8D634F5E569A5DDULL,
		0x289AF970173FDDA0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72D2A10800008D00ULL,
		0x655780862F050604ULL,
		0x100E008002C306C0ULL,
		0x8040041186106108ULL,
		0x121CA6000E004402ULL,
		0x2820558E14284816ULL,
		0xC09214D460692199ULL,
		0x000230201207C180ULL
	}};
	printf("Test Case 88\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD61500BFA8753B1AULL,
		0xEC2D44FD02BF0874ULL,
		0xDF866B59DAF8EFA4ULL,
		0xB12414DF83F85EFDULL,
		0xF3AA8EAA645C4B0CULL,
		0x563F89CB9B21BE79ULL,
		0xDEF5CB21B01188DCULL,
		0x994F853AA517B2FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10492540FC07F817ULL,
		0x4170299BA7B48E0BULL,
		0xCFB1BE6FDD5BC1ABULL,
		0xCC256CB25ECB6954ULL,
		0x5FA8E422EF5D571CULL,
		0xA3400FA47C4A9095ULL,
		0xAA2D4552677E293AULL,
		0x74065EC97A2C2ACBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10010000A8053812ULL,
		0x4020009902B40800ULL,
		0xCF802A49D858C1A0ULL,
		0x8024049202C84854ULL,
		0x53A88422645C430CULL,
		0x0200098018009011ULL,
		0x8A25410020100818ULL,
		0x10060408200422C9ULL
	}};
	printf("Test Case 89\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4D0555386F81BE73ULL,
		0x02DB61B6C7EB9C27ULL,
		0x8077BBA8C0AD167FULL,
		0xC85B9D9DB51B8AF5ULL,
		0xF1EAE90BC316E5C0ULL,
		0x5665335A45CD31C8ULL,
		0x9FD9B8581ED43060ULL,
		0x38F34D4DC3369408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B7FA6BC106CF2CULL,
		0xC661ED6F4761C384ULL,
		0x69D07A03E51BB653ULL,
		0x711D5DC7BAC81D11ULL,
		0x32237EBCFA4AC09AULL,
		0x551E9ECBF9DF5C37ULL,
		0x64B393B9E7CB673AULL,
		0x8C31EC43CF1CFAF1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0405502841008E20ULL,
		0x0241612647618004ULL,
		0x00503A00C0091653ULL,
		0x40191D85B0080811ULL,
		0x30226808C202C080ULL,
		0x5404124A41CD1000ULL,
		0x0491901806C02020ULL,
		0x08314C41C3149000ULL
	}};
	printf("Test Case 90\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF3EAFEC492EFBF74ULL,
		0x12178AE307910D66ULL,
		0x571D4ED43670F2A6ULL,
		0xDEAAF53BBA550E10ULL,
		0x47C9D1AE39659B3CULL,
		0x106CA1DB0927CBE5ULL,
		0x93FFEEAAA8657F6BULL,
		0xC981B4E85253A5A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F112113E0A7D50EULL,
		0x0EC7A51787A4395BULL,
		0x17B72C22494177D7ULL,
		0x518EB425B25658ADULL,
		0xF3C55C2D6DA0E2E9ULL,
		0xC36D50554E50D27AULL,
		0x6CD1B184C6B6096AULL,
		0x6E0FE89BC3B1511AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0300200080A79504ULL,
		0x0207800307800942ULL,
		0x17150C0000407286ULL,
		0x508AB421B2540800ULL,
		0x43C1502C29208228ULL,
		0x006C00510800C260ULL,
		0x00D1A0808024096AULL,
		0x4801A08842110102ULL
	}};
	printf("Test Case 91\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x49E2416823DFAAAEULL,
		0x550C619F9C355249ULL,
		0xA4777132C1315BC4ULL,
		0xE09ED57CA9705BD7ULL,
		0x3F8EEFF97C66F676ULL,
		0x572AD02F6EB7F456ULL,
		0xF40EABB1C81F2D53ULL,
		0x6E59D377F51B7A0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DE0EDC00A2F3524ULL,
		0x8E422074638BE41FULL,
		0x694FA473D5989929ULL,
		0xCDE697F0DB96BA70ULL,
		0x4C447925269A4FDAULL,
		0xD6AA2ACE68B309DAULL,
		0x43782AEDC836BA09ULL,
		0x93FCE2CF3CB02B77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09E04140020F2024ULL,
		0x0400201400014009ULL,
		0x20472032C1101900ULL,
		0xC086957089101A50ULL,
		0x0C04692124024652ULL,
		0x562A000E68B30052ULL,
		0x40082AA1C8162801ULL,
		0x0258C24734102A07ULL
	}};
	printf("Test Case 92\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3728AA94B36A36EEULL,
		0x92ABB8F7E338A990ULL,
		0x3BA4F4033E971FD0ULL,
		0x8F65E57A867E8F15ULL,
		0x28642ECB248010C6ULL,
		0xF4533195B28215BBULL,
		0x5E5A262BBAE0774BULL,
		0xDC03C413E7DDC180ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8BE636FA0E710AULL,
		0x5D5AD535F9919FB8ULL,
		0xC4C3C1D62AF3C4B8ULL,
		0xF5A72C085FA24690ULL,
		0x4DE6CAD4CFD9F04AULL,
		0xA1D1E1C20E430242ULL,
		0xF6D2A8CCCBC273F0ULL,
		0x701DE15822B36534ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3308A214B20A300AULL,
		0x100A9035E1108990ULL,
		0x0080C0022A930490ULL,
		0x8525240806220610ULL,
		0x08640AC004801042ULL,
		0xA051218002020002ULL,
		0x565220088AC07340ULL,
		0x5001C01022914100ULL
	}};
	printf("Test Case 93\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3235E2C706CE2F8EULL,
		0x05205396F9632269ULL,
		0x7F75ED5DC1D1AAC6ULL,
		0x85E7F5497FE7D8D4ULL,
		0x5CFB7A1095B83949ULL,
		0x20156191371433D4ULL,
		0xFCAD7C858070BF62ULL,
		0x842A8AF2710E082FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB515A7608A885F2EULL,
		0x33CC554731201B3DULL,
		0x40FE549F9583E161ULL,
		0xAA50BAC08D8166F0ULL,
		0x1F25FDC76461B215ULL,
		0x334B6E925A21BC01ULL,
		0x33C549D396D826BEULL,
		0x37E853411D9272BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3015A24002880F0EULL,
		0x0100510631200229ULL,
		0x4074441D8181A040ULL,
		0x8040B0400D8140D0ULL,
		0x1C21780004203001ULL,
		0x2001609012003000ULL,
		0x3085488180502622ULL,
		0x042802401102002FULL
	}};
	printf("Test Case 94\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x77D175DBAD5173EDULL,
		0xC31B933CE746DE25ULL,
		0xA8A41A5B4E2801BFULL,
		0xF7D2B48ED673B809ULL,
		0x83CBAB5B5A250F5BULL,
		0x61F8787E0780D753ULL,
		0x87F0B11F1AA81241ULL,
		0x83266F087F27FBF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60215116635DABA1ULL,
		0xB3D4302AD7F0A00FULL,
		0xF35B5391E68D0E1BULL,
		0x32B1D1FCA67CA85CULL,
		0xF07E0AA8B6208D5AULL,
		0x9095FFB24035286DULL,
		0x79E1C409EA6F4E87ULL,
		0x4EF893EBE2339B5DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60015112215123A1ULL,
		0x83101028C7408005ULL,
		0xA00012114608001BULL,
		0x3290908C8670A808ULL,
		0x804A0A0812200D5AULL,
		0x0090783200000041ULL,
		0x01E080090A280201ULL,
		0x0220030862239B58ULL
	}};
	printf("Test Case 95\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFEFC359C763F3341ULL,
		0x2509AD750DD6506AULL,
		0x850195DCF294C2D9ULL,
		0xC47556E3692A7EFBULL,
		0x0E2492CC8FD039C7ULL,
		0xFCCAA0339A64D64CULL,
		0x26CC2E89F8BA6BDFULL,
		0x140C27C9DE7846FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EA87A0B6484DB56ULL,
		0x7AD681F38ED4EE39ULL,
		0x8ABE0C1CC3FF4011ULL,
		0x44B7BBD7A6175F86ULL,
		0x7EDE6559C8EEFA81ULL,
		0xC70FC1E1697FC85BULL,
		0x81B0DF95E2FDB496ULL,
		0x6ED65ADD99DE1A97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3EA8300864041340ULL,
		0x200081710CD44028ULL,
		0x8000041CC2944011ULL,
		0x443512C320025E82ULL,
		0x0E04004888C03881ULL,
		0xC40A80210864C048ULL,
		0x00800E81E0B82096ULL,
		0x040402C998580295ULL
	}};
	printf("Test Case 96\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8B5373FE401A145AULL,
		0x79C6077FBE8060F4ULL,
		0xB5FA0E3254356AADULL,
		0x849C96F56D321913ULL,
		0x2920E44ABB570E4BULL,
		0x8E67CFD41A57E2C6ULL,
		0xBAA6BA4F7125B617ULL,
		0x41118FF772C09626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A48855DC738BA53ULL,
		0x2ADC6D307C157E38ULL,
		0x3F274CB1E7506FACULL,
		0x39BD6B40C9F0385DULL,
		0x2A00803EF957966FULL,
		0xC26ADDC0F216B430ULL,
		0xA1F7B68B36D05645ULL,
		0x25233E8D8E1600EFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A40015C40181052ULL,
		0x28C405303C006030ULL,
		0x35220C3044106AACULL,
		0x009C024049301811ULL,
		0x2800800AB957064BULL,
		0x8262CDC01216A000ULL,
		0xA0A6B20B30001605ULL,
		0x01010E8502000026ULL
	}};
	printf("Test Case 97\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x70D59C9F8F1A599DULL,
		0xC7086E8EDB0BA5E8ULL,
		0x811841C689D4C955ULL,
		0x8D555607E03A0FCFULL,
		0x9D775D538B0225C6ULL,
		0xF3CADFD3E0E4144EULL,
		0xA7B5A2C866DDDC3DULL,
		0x857507125F914279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F1DD5DA99F62837ULL,
		0x6D10BAB50F376E37ULL,
		0x60C918EAC3A3C9BFULL,
		0x16A37F23881886A9ULL,
		0xD557DAE523619893ULL,
		0x226C82A923B6B84CULL,
		0xD7438EFD3B9A9DB7ULL,
		0xA685963631AA3BDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0015949A89120815ULL,
		0x45002A840B032420ULL,
		0x000800C28180C915ULL,
		0x0401560380180689ULL,
		0x9557584103000082ULL,
		0x2248828120A4104CULL,
		0x870182C822989C35ULL,
		0x8405061211800258ULL
	}};
	printf("Test Case 98\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEF1AE0A26893B3ADULL,
		0xB6E546BD625A3C91ULL,
		0xA53E4C4FDF504D7EULL,
		0xBFBDF99465F24725ULL,
		0x826CE94CA2CA5477ULL,
		0x15B45BD9347E34BAULL,
		0xEDB2C00485549A0FULL,
		0x8D53B883C0CE9C51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC50DE886648A73F4ULL,
		0x5BDA46FCB9C39A8CULL,
		0xB845E89AE00F481DULL,
		0x07CE201222E2FF51ULL,
		0x6D2C32F603A9BCD9ULL,
		0x289F4AD8C1F1F5A0ULL,
		0x6BBF2C28C4E6457FULL,
		0xB263FF0D2597DE9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC508E082608233A4ULL,
		0x12C046BC20421880ULL,
		0xA004480AC000481CULL,
		0x078C201020E24701ULL,
		0x002C204402881451ULL,
		0x00944AD8007034A0ULL,
		0x69B200008444000FULL,
		0x8043B80100869C10ULL
	}};
	printf("Test Case 99\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x53DF342E3A0DA5A9ULL,
		0x00B8FB2F5536DE53ULL,
		0x543CCDCD68D8EE67ULL,
		0xF87364A58FE5ED41ULL,
		0x2FA9B94521D72579ULL,
		0x68F4F9D352AA5DC1ULL,
		0xDD04F67FEC20BA3FULL,
		0x01D79CD1179B39B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C618F7F74C22CD8ULL,
		0x68E3187ED10FD3AFULL,
		0xB8378674A5B4B0F2ULL,
		0x8FCE00519A223A77ULL,
		0xF06A282E2EA661E5ULL,
		0xB6B827C52C827330ULL,
		0x52E763E09B0D6EB2ULL,
		0x1E38E10A40940850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1041042E30002488ULL,
		0x00A0182E5106D203ULL,
		0x103484442090A062ULL,
		0x884200018A202841ULL,
		0x2028280420862161ULL,
		0x20B021C100825100ULL,
		0x5004626088002A32ULL,
		0x0010800000900810ULL
	}};
	printf("Test Case 100\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x14BA3AE402E42978ULL,
		0xC63E1702AC6F5A8DULL,
		0xA9D507E974167CB3ULL,
		0x5878EE178F2869F2ULL,
		0x0003D281092E6F11ULL,
		0xB6D1A4AA7D0B0D81ULL,
		0x545B7F138D981921ULL,
		0x621EC4BCFDA044EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEBAEC878C453E4DULL,
		0x2DACD4883B470CF1ULL,
		0x6DCE24AC79B79046ULL,
		0x8B60E982CD7BB250ULL,
		0x886E5C152355B452ULL,
		0x6FFAE78ABE599368ULL,
		0x14108289D6134F50ULL,
		0x036009EE36A453FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14BA288400442848ULL,
		0x042C140028470881ULL,
		0x29C404A870161002ULL,
		0x0860E8028D282050ULL,
		0x0002500101042410ULL,
		0x26D0A48A3C090100ULL,
		0x1410020184100900ULL,
		0x020000AC34A040EDULL
	}};
	printf("Test Case 101\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2436E70178EE839FULL,
		0xA224594CD2502183ULL,
		0x6D80778C004142B3ULL,
		0x1E39B74E32960E1AULL,
		0xFF2AC7945BD26A62ULL,
		0xB1CB16CB648735F5ULL,
		0xBAF08DAC9B475836ULL,
		0x8808AE66E75BEF12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582947742B2422A5ULL,
		0x5E39D46AC0EB45CEULL,
		0xBAF960DD85B0A386ULL,
		0x320161EFCB0AA4A7ULL,
		0x2C72C1D31E6AE251ULL,
		0xBF210DE4244E8A6AULL,
		0xA4121C98EF844D88ULL,
		0x1F1276D49902A85EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0020470028240285ULL,
		0x02205048C0400182ULL,
		0x2880608C00000282ULL,
		0x1201214E02020402ULL,
		0x2C22C1901A426240ULL,
		0xB10104C024060060ULL,
		0xA0100C888B044800ULL,
		0x080026448102A812ULL
	}};
	printf("Test Case 102\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x10422A4AD2424E63ULL,
		0xA9A7BD4B38B426B9ULL,
		0x501164641F7D9761ULL,
		0xD87B661F8BB94C9CULL,
		0x1807064FBBA83CB8ULL,
		0x57E30534E0DA979DULL,
		0xBA26F129A820AE39ULL,
		0x8F70B0D2D0AF469BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9395258FA27674A5ULL,
		0xC4FA6A48FE6B96CBULL,
		0x33795EC68EF54B71ULL,
		0xF6E4FA5A5C07FA86ULL,
		0x402122C2702647EDULL,
		0x1EF0F8B0334E21BAULL,
		0xABF8FBA9C72ACAA5ULL,
		0x18710C3F0CE02B30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000200A82424421ULL,
		0x80A2284838200689ULL,
		0x101144440E750361ULL,
		0xD060621A08014884ULL,
		0x00010242302004A8ULL,
		0x16E00030204A0198ULL,
		0xAA20F12980208A21ULL,
		0x0870001200A00210ULL
	}};
	printf("Test Case 103\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x793F54EF0417A31AULL,
		0x9A1D4F1836A92D99ULL,
		0xC4E13422E152E65FULL,
		0x033245936A4DCBD7ULL,
		0x98E99936F4C81BC9ULL,
		0x8374A1BE7555BFD2ULL,
		0x9CAC6A13D2AA55BBULL,
		0xFB06B2BE56FB910CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4676280338F61B08ULL,
		0x3023098AD1D0DE9FULL,
		0xD10FA9E63304FA6BULL,
		0x67B2141FCD32043BULL,
		0x0F4611EC05E34F69ULL,
		0xC22F4555C69D8394ULL,
		0xC436774623635984ULL,
		0x6F300CC4D70B54FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4036000300160308ULL,
		0x1001090810800C99ULL,
		0xC00120222100E24BULL,
		0x0332041348000013ULL,
		0x0840112404C00B49ULL,
		0x8224011444158390ULL,
		0x8424620202225180ULL,
		0x6B000084560B100CULL
	}};
	printf("Test Case 104\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3E801CBA3F1912FBULL,
		0x52F8EEC86277ACF1ULL,
		0x129876A3365C9CA2ULL,
		0x3CD0B39BC8A8490FULL,
		0x2A0A50184997BF02ULL,
		0xE558C3B7D310F76DULL,
		0x61F4644B0BA6388AULL,
		0xC32E19F7DC129362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F942289D444E60ULL,
		0x67C49C6CA7CD4AF4ULL,
		0x4DC3EA7AF505508CULL,
		0x0E575A055A62C44DULL,
		0x22C5785B883761ECULL,
		0xE4223F2376EFAB18ULL,
		0xAD2C4A2BDEBB7F8BULL,
		0x8B53EB8C9FA9859BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x128000281D000260ULL,
		0x42C08C48224508F0ULL,
		0x0080622234041080ULL,
		0x0C5012014820400DULL,
		0x2200501808172100ULL,
		0xE40003235200A308ULL,
		0x2124400B0AA2388AULL,
		0x830209849C008102ULL
	}};
	printf("Test Case 105\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6C6F6566B377C523ULL,
		0x1C10ACDD54FDA456ULL,
		0xC330753CB4818B2EULL,
		0x6349058F98A5B61AULL,
		0xCD0C5E5EBF040B9DULL,
		0xD8FF2C58B6C381BBULL,
		0xBC0FFBCC3CD1F41EULL,
		0x5EE9CFFEBF1FEDE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFACEFD1A6794E7BULL,
		0x4F5E41DFC4C6784AULL,
		0x7FBC536B48FB3357ULL,
		0xC23ABF76D6348E6EULL,
		0x5C0D1F4A702EA57DULL,
		0xA8F9B35672E373ADULL,
		0x33071F1C8140607DULL,
		0xD38B7F702BB9D666ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C2C6540A2714423ULL,
		0x0C1000DD44C42042ULL,
		0x4330512800810306ULL,
		0x420805069024860AULL,
		0x4C0C1E4A3004011DULL,
		0x88F9205032C301A9ULL,
		0x30071B0C0040601CULL,
		0x52894F702B19C462ULL
	}};
	printf("Test Case 106\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8782BC58E5FD0874ULL,
		0x8E62A23628BD609BULL,
		0x4DAAD8419D3E7F0FULL,
		0xFC9CC0F4C27B9210ULL,
		0xEDD5BEFE0D1C933DULL,
		0xAB593E7BF3B1E568ULL,
		0x6260EE0956887711ULL,
		0xCF528AAA7B451B14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32C0298F615B17B7ULL,
		0xCB3DB55B4671B01DULL,
		0x8175DD4A9C1C9291ULL,
		0xC8369440C41084AEULL,
		0x8EA2C15B129909FAULL,
		0x0EB449F9665276F4ULL,
		0xEF95117E347D2176ULL,
		0x477182D1479D35F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0280280861590034ULL,
		0x8A20A01200312019ULL,
		0x0120D8409C1C1201ULL,
		0xC8148040C0108000ULL,
		0x8C80805A00180138ULL,
		0x0A10087962106460ULL,
		0x6200000814082110ULL,
		0x4750828043051114ULL
	}};
	printf("Test Case 107\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD441AE6BDA1EE342ULL,
		0x5057847D056B76ABULL,
		0x065FC0B47A4EC69EULL,
		0xAD7BF8842E4BA863ULL,
		0x2BA8DA5D2E7D33BDULL,
		0x3ED1AD6DE51C1A54ULL,
		0xED7FFC6B29D0EB95ULL,
		0x2AF3D9B89469802FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8E28825515A95DULL,
		0x0747348030671259ULL,
		0x8D66EBF136DFD4C2ULL,
		0x09DD8191ED41DD78ULL,
		0xED72AF0310BB72D1ULL,
		0x52DE9B15564BD4A3ULL,
		0x1B441BF384845128ULL,
		0x5BE5CA26D7E56079ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500028025014A140ULL,
		0x0047040000631209ULL,
		0x0446C0B0324EC482ULL,
		0x095980802C418860ULL,
		0x29208A0100393291ULL,
		0x12D0890544081000ULL,
		0x0944186300804100ULL,
		0x0AE1C82094610029ULL
	}};
	printf("Test Case 108\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x28B8AB42D2EFA256ULL,
		0x7D49B18180B36439ULL,
		0x104142BD88339F48ULL,
		0x2495ED2399DF61E6ULL,
		0xAB782E6259C3A631ULL,
		0x155BADBB010B2B71ULL,
		0x1C9121D03595C3DEULL,
		0xD6CBDD5CDDFF896BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4216C62BAE9C79FULL,
		0x4A7FBCD95962BFF5ULL,
		0xE4AAD3C73A9DDF43ULL,
		0x690D462254D641D4ULL,
		0x1D1FD8F6AAA07233ULL,
		0x4EBA6D86A6CC1234ULL,
		0x5054D44E3F52B605ULL,
		0x3AAC7E344BD4ED21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2020284292E98216ULL,
		0x4849B08100222431ULL,
		0x0000428508119F40ULL,
		0x2005442210D641C4ULL,
		0x0918086208802231ULL,
		0x041A2D8200080230ULL,
		0x1010004035108204ULL,
		0x12885C1449D48921ULL
	}};
	printf("Test Case 109\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4918B53F6A1F6031ULL,
		0x4570C965E77DBB74ULL,
		0x752FB187A0E70B98ULL,
		0xAEEAC4000C9E818CULL,
		0x8E51398FD395F09FULL,
		0xAA7072E3856F559CULL,
		0x0BBC5116C34625DCULL,
		0x4C9C0B316D909DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC61DE5F6BAB148DAULL,
		0x93384BEB360F9577ULL,
		0x14FFE8250A5DCAB4ULL,
		0xAF76F0E3AB3B14B0ULL,
		0x7B1F7E96E73F4BB0ULL,
		0x75D765E15DCAF271ULL,
		0x9A1C4ABE7FEE2812ULL,
		0x0992665815B7CC6CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4018A5362A114010ULL,
		0x01304961260D9174ULL,
		0x142FA00500450A90ULL,
		0xAE62C000081A0080ULL,
		0x0A113886C3154090ULL,
		0x205060E1054A5010ULL,
		0x0A1C401643462010ULL,
		0x0890021005908C4CULL
	}};
	printf("Test Case 110\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x99442E80FE1D6A7BULL,
		0xA251ACC150CBE4C2ULL,
		0x5F89D484399054AAULL,
		0x420F2741B53B0572ULL,
		0x762CD5B8EB26BABDULL,
		0xBFE7D1E83CE5DBA1ULL,
		0xCE7789285900855DULL,
		0xD7F1B181CAC70E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF875EEE256CD6CULL,
		0x7044DCE069324C14ULL,
		0x00874786EF1952C6ULL,
		0xD44B1B8631820B8FULL,
		0xE5287049D634DCA5ULL,
		0x75FC5C8D20B63E6CULL,
		0x3907BADF9E02872DULL,
		0x1C95846E681193EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09402480E2144868ULL,
		0x20408CC040024400ULL,
		0x0081448429105082ULL,
		0x400B030031020102ULL,
		0x64285008C22498A5ULL,
		0x35E4508820A41A20ULL,
		0x080788081800850DULL,
		0x149180004801024AULL
	}};
	printf("Test Case 111\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5CC6407A4FCA0AE5ULL,
		0x13A67E33C6A05E52ULL,
		0xA3AC0AC41085C02BULL,
		0x7A84B1AA861C5CBCULL,
		0x7C934533FCAD7534ULL,
		0x97B018C0C6910EF0ULL,
		0xB0831C2D2C77B517ULL,
		0xC7940B9C110D44F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86EB98F39B0D5CDAULL,
		0xB70524C3C4C4E363ULL,
		0xD5B7F4E68E6930F9ULL,
		0x5E3E0F318DB9982BULL,
		0x6BFDB0679E85F842ULL,
		0x6A31295471D4C3E5ULL,
		0xFFF99DEF1ADAF68BULL,
		0xBA91D44CCC587D3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C200720B0808C0ULL,
		0x13042403C4804242ULL,
		0x81A400C400010029ULL,
		0x5A04012084181828ULL,
		0x689100239C857000ULL,
		0x02300840409002E0ULL,
		0xB0811C2D0852B403ULL,
		0x8290000C00084431ULL
	}};
	printf("Test Case 112\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAEEBF96C356EAD51ULL,
		0xA3B527112D169BECULL,
		0x44B8D4FB1AC7B93FULL,
		0xE06012C835C48311ULL,
		0xB178480490504472ULL,
		0x40EA81AF78715F53ULL,
		0x4D346D8AF35E923FULL,
		0xDAB62290939EB5EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AAFBF9F4EF0F59FULL,
		0x7B584DA32F831A02ULL,
		0xDD94F4C85F160EBFULL,
		0x417C16E5B0864D78ULL,
		0x81A8A0C1FD1A8CD5ULL,
		0x4A79B9D7381F5035ULL,
		0xC0ED4C183CA51A7EULL,
		0x682705E25C72A788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AABB90C0460A511ULL,
		0x231005012D021A00ULL,
		0x4490D4C81A06083FULL,
		0x406012C030840110ULL,
		0x8128000090100450ULL,
		0x4068818738115011ULL,
		0x40244C083004123EULL,
		0x482600801012A588ULL
	}};
	printf("Test Case 113\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA3AB57D1EBB6C562ULL,
		0x410B364044D5CE34ULL,
		0x72CE6586B655BA7DULL,
		0xADAA12A539F007B1ULL,
		0xC9F690BEA3DCCA12ULL,
		0x4BE7164E59369DF7ULL,
		0xDC8480886DF0A1AFULL,
		0x121EC628A4DB1E06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D6B0465A954945AULL,
		0xF8C5C0C32794C8AFULL,
		0x4AC730BA25D628F3ULL,
		0x09784FA1C83AADA7ULL,
		0x858CF350A4125987ULL,
		0x44A50EC0084D4117ULL,
		0x7EF27BCDFF8D58E8ULL,
		0x8E295E911D0AEFFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x212B0441A9148442ULL,
		0x400100400494C824ULL,
		0x42C6208224542871ULL,
		0x092802A1083005A1ULL,
		0x81849010A0104802ULL,
		0x40A5064008040117ULL,
		0x5C8000886D8000A8ULL,
		0x02084600040A0E06ULL
	}};
	printf("Test Case 114\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBCB6C84ED3452A0CULL,
		0x2BF3FDACD3F4BC5FULL,
		0x478AA37B34B8857FULL,
		0x4D957AC88EAEDC22ULL,
		0xB0C4DEB9091200B5ULL,
		0xAF4079B5FFF99166ULL,
		0xE2819E1BA2E1FC3EULL,
		0x053C46490590D6D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB247C5EBB8C4119DULL,
		0x45F71A128C95DAB3ULL,
		0x0A4E22CBBA8C3AC5ULL,
		0x5CFE3ADA5110EF6AULL,
		0x4BF14CB71FD223F7ULL,
		0x445A1151FC95464AULL,
		0x9F3FA68F3AC710BAULL,
		0x913CDDF4F4374603ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB006C04A9044000CULL,
		0x01F3180080949813ULL,
		0x020A224B30880045ULL,
		0x4C943AC80000CC22ULL,
		0x00C04CB1091200B5ULL,
		0x04401111FC910042ULL,
		0x8201860B22C1103AULL,
		0x013C444004104603ULL
	}};
	printf("Test Case 115\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9F1BA0C92A286538ULL,
		0x65F90E645865D4E5ULL,
		0xF2EF36260D9E6CDBULL,
		0x811D00978EC4649FULL,
		0x52466E4B425A8785ULL,
		0xC318BB9A1CE213AFULL,
		0xB5C9F578F721CF81ULL,
		0xD815EF90B237299DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8337393A827F3337ULL,
		0x38D130C199EB8393ULL,
		0xDEB17FA737CACD77ULL,
		0xE9C35E5B05FA5518ULL,
		0x9A11B48CD3DF7CD2ULL,
		0xAFCA668FD1027A0EULL,
		0x2664879CE70240CBULL,
		0x9656498363EB3082ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8313200802282130ULL,
		0x20D1004018618081ULL,
		0xD2A13626058A4C53ULL,
		0x8101001304C04418ULL,
		0x12002408425A0480ULL,
		0x8308228A1002120EULL,
		0x24408518E7004081ULL,
		0x9014498022232080ULL
	}};
	printf("Test Case 116\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7744EA9288A6271CULL,
		0xAC3CB3CC6A2CCD5EULL,
		0x2E0871306E174140ULL,
		0x05AAFA569B70F0FBULL,
		0x5B8D081B7478D90DULL,
		0x73C3A9326B29D75DULL,
		0xA0A415DBEAE20711ULL,
		0x920D38630A48904FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67F51E43718EA74FULL,
		0x94697EFC6D94A89CULL,
		0x32B2DFF856264471ULL,
		0x6F1D91E7CA5966D3ULL,
		0x7181DCAC159754F8ULL,
		0xA219D8BCBA3BEC60ULL,
		0xD3373E404EF6DF3EULL,
		0x2EDF2BFB6734C3BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67440A020086270CULL,
		0x842832CC6804881CULL,
		0x2200513046064040ULL,
		0x050890468A5060D3ULL,
		0x5181080814105008ULL,
		0x220188302A29C440ULL,
		0x802414404AE20710ULL,
		0x020D28630200800EULL
	}};
	printf("Test Case 117\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF3CA3F8EB1205B76ULL,
		0x6E23C71F4B167A41ULL,
		0x0D86A806A01494B8ULL,
		0xB7588FFD1965EAC0ULL,
		0xFD604774F333B13BULL,
		0x62C87067C1574E0EULL,
		0x661A6E8D1BA9AF46ULL,
		0x6B54C805AA7D9BCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53B2662BCD6747BULL,
		0xAB0B1FA7A49859D9ULL,
		0xEDDAA30B02FF1D2FULL,
		0xEBCF7CD18961E01DULL,
		0x051653387DEE69F7ULL,
		0xA5F0C979DCBE1BE1ULL,
		0x143B7DFEDDD48E8BULL,
		0xA9A08A2E1A92DF7DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA10A2602B0005072ULL,
		0x2A03070700105841ULL,
		0x0D82A00200141428ULL,
		0xA3480CD10961E000ULL,
		0x0500433071222133ULL,
		0x20C04061C0160A00ULL,
		0x041A6C8C19808E02ULL,
		0x290088040A109B4CULL
	}};
	printf("Test Case 118\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB7654349490DCE36ULL,
		0x2510ADDC8A375C0AULL,
		0xD8D6AF326A2B7B0DULL,
		0x5C2F21D8CB7ED5FCULL,
		0xDDE1DDADD4829BD8ULL,
		0xE3908C1124361BB9ULL,
		0xFEC6B75958A5C69DULL,
		0x6684EFF7848B65CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2FE9949235F69BFULL,
		0x69452E20FAEA1903ULL,
		0x68A7D66EA4B7CC85ULL,
		0x6709DD275D8ABF7CULL,
		0x9C26C0399D2A3656ULL,
		0xF2771B6C980536C8ULL,
		0x7DCE6B08F502BAC7ULL,
		0x810BB08B50DE15F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2640149010D4836ULL,
		0x21002C008A221802ULL,
		0x4886862220234805ULL,
		0x44090100490A957CULL,
		0x9C20C02994021250ULL,
		0xE210080000041288ULL,
		0x7CC6230850008285ULL,
		0x0000A083008A05C4ULL
	}};
	printf("Test Case 119\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFEC12E249425AFA2ULL,
		0x6C6C675728B6B52FULL,
		0x80777642374E3779ULL,
		0x66905745CDA245C5ULL,
		0x048C6202569F0221ULL,
		0x47D8E9E833661BFCULL,
		0x962C55BE3887A597ULL,
		0x5206FEC97F600946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4473D277930C46ULL,
		0xA78147D1E3003EFBULL,
		0x449EFC90ABEDB948ULL,
		0x94C88B2CE5D1E30CULL,
		0x12EBFC421B0D2C6EULL,
		0x3E8590D12C7B8CABULL,
		0x5363E3211E99C606ULL,
		0x0380CE19EA98D332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE40220014010C02ULL,
		0x240047512000342BULL,
		0x00167400234C3148ULL,
		0x04800304C5804104ULL,
		0x00886002120D0020ULL,
		0x068080C0206208A8ULL,
		0x1220412018818406ULL,
		0x0200CE096A000102ULL
	}};
	printf("Test Case 120\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xACCEC7FE99125FB3ULL,
		0x909F347D2E34F61EULL,
		0xEB16B18A36A338BCULL,
		0x2DB44306AECD3C9CULL,
		0x181C397CBB2A6978ULL,
		0x097A68D1DFE86D0FULL,
		0x24A46D71B6F78DF8ULL,
		0x09834A287F105268ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79AE4610ADBB3F88ULL,
		0x0193C2B32035A300ULL,
		0xAE32E6590D800729ULL,
		0xAF47C4D59956E58EULL,
		0x2CCE37F05D3289A1ULL,
		0xB942F8609D33FBAFULL,
		0x636181BEDC4F25E1ULL,
		0x1383BB94B315B957ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x288E461089121F80ULL,
		0x009300312034A200ULL,
		0xAA12A00804800028ULL,
		0x2D0440048844248CULL,
		0x080C317019220920ULL,
		0x094268409D20690FULL,
		0x20200130944705E0ULL,
		0x01830A0033101040ULL
	}};
	printf("Test Case 121\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC9D21D33AFB3BAA2ULL,
		0x705AAE7737AB3D4AULL,
		0x46573E0C521FB95CULL,
		0x72CA638F80B0180BULL,
		0x6635DBF80960C466ULL,
		0x944FF1DF1904F7FAULL,
		0xCF080A9CA5E77176ULL,
		0x9836D332DC5D19FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87FDC706BC668A0FULL,
		0xB32FF6B8340FC914ULL,
		0x64889E448E576ADFULL,
		0x6D1C1288AD42A87FULL,
		0x0DB7E7560E8CB25CULL,
		0x75698248F8B6AAAEULL,
		0xA3F11182B2607503ULL,
		0xAC6A170D8E14FE8CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81D00502AC228A02ULL,
		0x300AA630340B0900ULL,
		0x44001E040217285CULL,
		0x600802888000080BULL,
		0x0435C35008008044ULL,
		0x144980481804A2AAULL,
		0x83000080A0607102ULL,
		0x882213008C141888ULL
	}};
	printf("Test Case 122\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x042B0FA57CBD465AULL,
		0x86E61E24DA9EBF27ULL,
		0x202AA8BCFB24C183ULL,
		0x1D263C07DB44CFB3ULL,
		0xDC6ECB883B1878F7ULL,
		0xD32CA7AF245E1741ULL,
		0x469011372DDF6CC6ULL,
		0x4140C39F66E5EA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA04BE84DF44627ULL,
		0x0AAB8B8E02F3FD6FULL,
		0x3B6BC7D8AC942196ULL,
		0x305D1666F81282D7ULL,
		0x088E538FAAEEFC36ULL,
		0x3C91C68057094998ULL,
		0x78A3BEBFD9CE1BAEULL,
		0x4CEC0DEA9FBE116DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04200BA04CB44602ULL,
		0x02A20A040292BD27ULL,
		0x202A8098A8040182ULL,
		0x10041406D8008293ULL,
		0x080E43882A087836ULL,
		0x1000868004080100ULL,
		0x4080103709CE0886ULL,
		0x4040018A06A4006DULL
	}};
	printf("Test Case 123\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x595153995237368EULL,
		0x63FB9B5744284A14ULL,
		0x54FF71D853DFB16FULL,
		0xD1F738B9989C3194ULL,
		0x8FDDD540BF3E7123ULL,
		0x72CBF046FCCFDE29ULL,
		0xFF310FC59BC9FEA6ULL,
		0x1571DB2B2353F692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14DB0F15EA06757ULL,
		0x5B9D8811FA0642DAULL,
		0xF2C3DB9BCC2FF9BEULL,
		0xD01ECA8CC64A3DE3ULL,
		0x40C96DE32551D3CDULL,
		0x549E614B0AABEDBAULL,
		0x16D38CE90B2CF19CULL,
		0x92CD65A1969E594AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5141109152202606ULL,
		0x4399881140004210ULL,
		0x50C35198400FB12EULL,
		0xD016088880083180ULL,
		0x00C9454025105101ULL,
		0x508A6042088BCC28ULL,
		0x16110CC10B08F084ULL,
		0x1041412102125002ULL
	}};
	printf("Test Case 124\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5F9B1DD62C268F4FULL,
		0x140E40D205A7F3E2ULL,
		0x4025D1EE3BD9B18FULL,
		0x4BBF57E2A331E9DAULL,
		0x534DFE92CC8418B3ULL,
		0x4DE513DC3C0E53B4ULL,
		0xF6287BE0DEEE2727ULL,
		0x0D42F6CA0DD7DB0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2332D2B2F3D2BF3ULL,
		0xABF7A334E9C53C44ULL,
		0x1129452556109119ULL,
		0xDF702D629A273D4BULL,
		0xF46DDCD2B253E727ULL,
		0x4BF4D16427F42E65ULL,
		0xE8070BD4D3C09D2AULL,
		0xC446B714C3B72DCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x52130D022C240B43ULL,
		0x0006001001853040ULL,
		0x0021412412109109ULL,
		0x4B3005628221294AULL,
		0x504DDC9280000023ULL,
		0x49E4114424040224ULL,
		0xE0000BC0D2C00522ULL,
		0x0442B60001970908ULL
	}};
	printf("Test Case 125\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6BA04E059D99330BULL,
		0xDCE003B97400410BULL,
		0xEBF094030A986B74ULL,
		0xCC4C86E6BE93B0C0ULL,
		0x231FE867B9CA0311ULL,
		0x572BB2643671AFFBULL,
		0x35E0D1887CC7294AULL,
		0x52033C71AFBB5E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EFADB0B0B91A8D0ULL,
		0x0BC58AF08664FE98ULL,
		0x500EC37D60C9A091ULL,
		0xAA559B804FCAD9E3ULL,
		0x4359350A009A9B2DULL,
		0x3C1A23834B13807EULL,
		0xF2112AA60B9D4F96ULL,
		0xA80D723427392F00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AA04A0109912000ULL,
		0x08C002B004004008ULL,
		0x4000800100882010ULL,
		0x884482800E8290C0ULL,
		0x03192002008A0301ULL,
		0x140A22000211807AULL,
		0x3000008008850902ULL,
		0x0001303027390E00ULL
	}};
	printf("Test Case 126\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x25794D54DDFB3C5AULL,
		0x1BE96653EB17D98FULL,
		0x4D794B40688345B6ULL,
		0x289236697251D7F7ULL,
		0x1D191E5B87F21A1AULL,
		0x63247472854A8AD0ULL,
		0xA7635D7D52B73348ULL,
		0x38119E101751550CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F608927CED0B3AULL,
		0x358084CD581AF933ULL,
		0x683644C7988BE230ULL,
		0x22990F840AF8F1E2ULL,
		0x049C7B5F11178C69ULL,
		0xC362E78CF23382F7ULL,
		0x5C7A2F71797E9D74ULL,
		0x03AACE0F73D2FE4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x217008105CE9081AULL,
		0x118004414812D903ULL,
		0x4830404008834030ULL,
		0x209006000250D1E2ULL,
		0x04181A5B01120808ULL,
		0x43206400800282D0ULL,
		0x04620D7150361140ULL,
		0x00008E001350540CULL
	}};
	printf("Test Case 127\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE8294CBEFC36EF84ULL,
		0xD04D0957B1BF0C7EULL,
		0x6D33C8828368550AULL,
		0xFB03AD6B7920B661ULL,
		0xE34CA324445AE5B6ULL,
		0x59FF9CC05E9EA5D4ULL,
		0xC73AA1FB61FC6115ULL,
		0x6F96BCDFBDDFBE57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17531A7BD5D1589AULL,
		0xF0967228F261B779ULL,
		0xE3F9A132DC20102CULL,
		0xF7D1D1DD0EA832FEULL,
		0x320536037CBBFDA5ULL,
		0x7831BE35E1611A6AULL,
		0x2D6B0DB3C82C75FBULL,
		0x568F4FCAB87BE090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0001083AD4104880ULL,
		0xD0040000B0210478ULL,
		0x6131800280201008ULL,
		0xF301814908203260ULL,
		0x22042200441AE5A4ULL,
		0x58319C0040000040ULL,
		0x052A01B3402C6111ULL,
		0x46860CCAB85BA010ULL
	}};
	printf("Test Case 128\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB527A54DE8295159ULL,
		0x236BDD2F205F71C0ULL,
		0xFAEFE962018B965AULL,
		0x3DA65F76DED613A4ULL,
		0xBFB54BC996D17CFCULL,
		0x3747C34771928104ULL,
		0x767E3387447B8786ULL,
		0x180FCED7C364D99AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD534077CB22FEF60ULL,
		0xF9229787463771A7ULL,
		0xA680A4226EF11A23ULL,
		0xBBE9990DE00B2C65ULL,
		0xC09BCDE30D61F8BAULL,
		0x1DBEDD56CCFCFE46ULL,
		0x593EC959A45DB890ULL,
		0x3F6DF8FB2BFF492FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9524054CA0294140ULL,
		0x2122950700177180ULL,
		0xA280A02200811202ULL,
		0x39A01904C0020024ULL,
		0x809149C1044178B8ULL,
		0x1506C14640908004ULL,
		0x503E010104598080ULL,
		0x180DC8D30364490AULL
	}};
	printf("Test Case 129\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4D8C3F10234C329CULL,
		0x476E51365CF575F8ULL,
		0x755BC32023A2B44AULL,
		0xA6E9874632A2132AULL,
		0x9B41CDF3B6B6DC3AULL,
		0x58D8F6FA81F55730ULL,
		0x9E27BD1F8E6EC554ULL,
		0x4063751E0A78AEE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A0C113F041C11BCULL,
		0x9B5F6F6A8E550730ULL,
		0xAC7E9A9B8A1DF634ULL,
		0x50AA43A364C3AE3CULL,
		0x326C7E04961BA45DULL,
		0x99CC097959970215ULL,
		0x7389C70FA13AA9F8ULL,
		0xA0EEF613CA5C044DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080C1110000C109CULL,
		0x034E41220C550530ULL,
		0x245A82000200B400ULL,
		0x00A8030220820228ULL,
		0x12404C0096128418ULL,
		0x18C8007801950210ULL,
		0x1201850F802A8150ULL,
		0x006274120A580444ULL
	}};
	printf("Test Case 130\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB6BB24006441CA0FULL,
		0x643E1AC5D3458371ULL,
		0xE30839EBFAEB9164ULL,
		0x7968521F7AFEFA15ULL,
		0x75C8F4E8112124EEULL,
		0x6FB61C17D06564A4ULL,
		0x369451C8F11CE076ULL,
		0xF564590FEA66B241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x246DBC20BF9A448AULL,
		0xC692A3DE1944D1CBULL,
		0xC04E1E15765D74ABULL,
		0x673653B70FA5AA5AULL,
		0xFA9A2D349D4D48B3ULL,
		0x28800F3C8D525F00ULL,
		0xBB9E98E6A98E3BBDULL,
		0x99AC4C70F4426800ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x242924002400400AULL,
		0x441202C411448141ULL,
		0xC008180172491020ULL,
		0x612052170AA4AA10ULL,
		0x70882420110100A2ULL,
		0x28800C1480404400ULL,
		0x329410C0A10C2034ULL,
		0x91244800E0422000ULL
	}};
	printf("Test Case 131\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0717D5C89F83D710ULL,
		0x95425067939274BEULL,
		0xE64867FBD1989E53ULL,
		0xA256F594EAEE5EB5ULL,
		0x91423BC70252E576ULL,
		0x4C446DDD710C61EBULL,
		0x60F79E16B48D322AULL,
		0xE42EAC5B90AFE1FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD4AA983F909565ULL,
		0xF31A77F4E5A7360DULL,
		0x290D5346FC721911ULL,
		0x26F671DA666E6473ULL,
		0x4F5ED972765EAF1CULL,
		0xF0F14DB22317CAB8ULL,
		0x4E9B3CBA2A1310A7ULL,
		0xBAD0DCBFDEAD0625ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x031480881F809500ULL,
		0x910250648182340CULL,
		0x20084342D0101811ULL,
		0x22567190626E4431ULL,
		0x014219420252A514ULL,
		0x40404D90210440A8ULL,
		0x40931C1220011022ULL,
		0xA0008C1B90AD0020ULL
	}};
	printf("Test Case 132\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x16113D9BD0FD9270ULL,
		0x274B98CB95EFF784ULL,
		0x2058C5B8E37B44A5ULL,
		0x8ED9576D7A2A05D6ULL,
		0x0CD5EA81FE64D9F3ULL,
		0x305A0B57A1D5ED2DULL,
		0x10D5DB1833B4AFD5ULL,
		0xDC50EA21E4459CC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56C1A6E98FB2993ULL,
		0x78A307E8384EB563ULL,
		0x32BF8608318D5445ULL,
		0x9AA92372D36C24B4ULL,
		0xD28FD7EF0BAA417CULL,
		0x372CDF6970DCF7F0ULL,
		0xDB65A6B2D113020CULL,
		0xBED3C94BB5CC6961ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1400180A90F90010ULL,
		0x200300C8104EB500ULL,
		0x2018840821094405ULL,
		0x8A89036052280494ULL,
		0x0085C2810A204170ULL,
		0x30080B4120D4E520ULL,
		0x1045821011100204ULL,
		0x9C50C801A4440841ULL
	}};
	printf("Test Case 133\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCC8325CB60EC330FULL,
		0xA6E953DDFCB671AAULL,
		0x471F205018C2F3FFULL,
		0xF0725B0B652A02DCULL,
		0x2BF1F454A044E09FULL,
		0x3CEB32D04D7D2DEFULL,
		0x3BC70924A2E43FDCULL,
		0xB63A90455A76A06BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0266E9D93047A68CULL,
		0x6F877F8833C3E605ULL,
		0x484017E88FB75A8EULL,
		0x40A6C90342E6B1CBULL,
		0x838DF5BA2E540C1BULL,
		0xD62E76643938191EULL,
		0x12A79DCB2890AFC1ULL,
		0xF6B01D18F6A588FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000221C92044220CULL,
		0x2681538830826000ULL,
		0x400000400882528EULL,
		0x40224903402200C8ULL,
		0x0381F4102044001BULL,
		0x142A32400938090EULL,
		0x1287090020802FC0ULL,
		0xB63010005224806AULL
	}};
	printf("Test Case 134\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDDD74C8560A7887BULL,
		0x2A39C9B4E015DFDEULL,
		0x9BDBE7B9071DA616ULL,
		0x145942071E917552ULL,
		0xF22151D6F816A767ULL,
		0x7074923187F783B5ULL,
		0xE5C1A24DC37B3B89ULL,
		0x5F8E35D0C6A05E43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E05F2611D9E34DULL,
		0x38B9391E10B9B950ULL,
		0xEDC50FCEEB8BA543ULL,
		0x0BF10A911FB338C0ULL,
		0x7EABF43C25A34C00ULL,
		0x6A94E40300ED29F5ULL,
		0x5BFEF2456C9BCD21ULL,
		0xEBAB9CCE0ABBDE54ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49C04C0400818049ULL,
		0x2839091400119950ULL,
		0x89C107880309A402ULL,
		0x005102011E913040ULL,
		0x7221501420020400ULL,
		0x6014800100E501B5ULL,
		0x41C0A245401B0901ULL,
		0x4B8A14C002A05E40ULL
	}};
	printf("Test Case 135\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6B998B95288808B9ULL,
		0xDFCAE8EA09C0DA23ULL,
		0x56EC8A960E350F4CULL,
		0x1678CBBD1C4A4832ULL,
		0xD013F3FB74C703ECULL,
		0x9B9223E9BE5BF13EULL,
		0x12E111E4862BF6A5ULL,
		0x5B2A3AC176B3E0B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D67C0B02ABC2FD6ULL,
		0xF50897C2ECCC7A0FULL,
		0x8BE600004B56313DULL,
		0xD4A9727C39DF426FULL,
		0x8A5F40B2D2780A60ULL,
		0xD0B2995A20D015A2ULL,
		0x78425A0E62BF8713ULL,
		0x4DA643314A8A7EEBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4901809028880890ULL,
		0xD50880C208C05A03ULL,
		0x02E400000A14010CULL,
		0x1428423C184A4022ULL,
		0x801340B250400260ULL,
		0x9092014820501122ULL,
		0x10401004022B8601ULL,
		0x49220201428260A1ULL
	}};
	printf("Test Case 136\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2B394CA28EB112E5ULL,
		0xDC648CE334ADFB31ULL,
		0xF1D8C5D1AC603BC1ULL,
		0x0DD452590A555A21ULL,
		0x5CE905067E05C5D8ULL,
		0x051796532E9151C5ULL,
		0x2C092DB6D9E68C15ULL,
		0xEDABABBA67A1AD4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE75880EEE2D82BD7ULL,
		0xB186BA8D883279C8ULL,
		0x59F9C0D7BA343542ULL,
		0x70D486F419833608ULL,
		0xBB31C7645ED59327ULL,
		0xA7D415F830F17A9FULL,
		0xBFD597EC0236FC1EULL,
		0x9482D8B135627F3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x231800A2829002C5ULL,
		0x9004888100207900ULL,
		0x51D8C0D1A8203140ULL,
		0x00D4025008011200ULL,
		0x182105045E058100ULL,
		0x0514145020915085ULL,
		0x2C0105A400268C14ULL,
		0x848288B025202D0AULL
	}};
	printf("Test Case 137\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5D6D043E7B00DEF2ULL,
		0x3D17E3DB296DE2C8ULL,
		0x1BDC61356276B504ULL,
		0x18BDB3B72A9E77B5ULL,
		0xC352F3990191C07AULL,
		0x2603DD10A3B935E9ULL,
		0x0F25BE91FE73567EULL,
		0xC9BD3D24BB0F689AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F19F4D4CD972909ULL,
		0x20769272C267F7CAULL,
		0xD51BF98D84626C29ULL,
		0x08820060BF61320BULL,
		0xB49C75877DA1D144ULL,
		0xCC854CD280F32D7CULL,
		0x42E6D75A34FCB790ULL,
		0x262625AA8ABF4918ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D09041449000800ULL,
		0x201682520065E2C8ULL,
		0x1118610500622400ULL,
		0x088000202A003201ULL,
		0x801071810181C040ULL,
		0x04014C1080B12568ULL,
		0x0224961034701610ULL,
		0x002425208A0F4818ULL
	}};
	printf("Test Case 138\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD80CE9C6C73CA0B5ULL,
		0x19CFB91E3E1AC3E5ULL,
		0x0B2FD657ABA72907ULL,
		0xB880C99B2AD784B0ULL,
		0xF8C4C21BD1EF558AULL,
		0x8C1AC4E78056E7E5ULL,
		0x081CFAC7EF6122B2ULL,
		0x13420305D14992BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14810AB97FA27409ULL,
		0x955A5F4BD70B8FB4ULL,
		0x0ECF3EC1432A1648ULL,
		0x1C531E1371F7BD36ULL,
		0x0E441CABECDCEEABULL,
		0x16C20F600F650231ULL,
		0x99DACAC4A7D22342ULL,
		0x9FB508D672D7DD56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000088047202001ULL,
		0x114A190A160A83A4ULL,
		0x0A0F164103220000ULL,
		0x1800081320D78430ULL,
		0x0844000BC0CC448AULL,
		0x0402046000440221ULL,
		0x0818CAC4A7402202ULL,
		0x1300000450419012ULL
	}};
	printf("Test Case 139\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x54EEDE21C76CDD6FULL,
		0xDED8C1A9B0164556ULL,
		0xE931198F6416CF48ULL,
		0x094937763148CFC4ULL,
		0x74055D8E8334F856ULL,
		0xEFB7801E012A3260ULL,
		0xBD96FBF768678158ULL,
		0xE6552EDFC31B99F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619E52F591219C43ULL,
		0xAB27FAEE1AD3472CULL,
		0x9D717E7B09141917ULL,
		0x3063CE2E75331879ULL,
		0xA5A7093C9FE7CE23ULL,
		0xC16892AE84EF1064ULL,
		0xE9779E4C52C1D1D0ULL,
		0xA7A8791811E0B7B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408E522181209C43ULL,
		0x8A00C0A810124504ULL,
		0x8931180B00140900ULL,
		0x0041062631000840ULL,
		0x2405090C8324C802ULL,
		0xC120800E002A1060ULL,
		0xA9169A4440418150ULL,
		0xA6002818010091B2ULL
	}};
	printf("Test Case 140\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x48E5E2ED3E7C8F09ULL,
		0x51ABD873B4CF3F67ULL,
		0xF05692F64E9AE3AEULL,
		0x544F63A3D9F1FA99ULL,
		0x9CFE1F51559A2A50ULL,
		0x43976D9214F0D07AULL,
		0x9B34637D632A7351ULL,
		0x1EDC89F5EC12511DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18CFB8C1062B0E7ULL,
		0x1611F87D5CA7CB92ULL,
		0xFAC8E194CEEB0976ULL,
		0x30E5CE8C80F2C3C2ULL,
		0x20389D6198E82AF1ULL,
		0x85FB7E7ED60837CEULL,
		0x16359CEB38D1470BULL,
		0x33D96B519E47A668ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0084E28C10608001ULL,
		0x1001D87114870B02ULL,
		0xF04080944E8A0126ULL,
		0x1045428080F0C280ULL,
		0x00381D4110882A50ULL,
		0x01936C121400104AULL,
		0x1234006920004301ULL,
		0x12D809518C020008ULL
	}};
	printf("Test Case 141\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC7D89623FDDA9C61ULL,
		0x4E5E77E0F3C1CDBDULL,
		0xC54DFEDF87FA403DULL,
		0x301EAEE91D4B4406ULL,
		0x750225377F7BD505ULL,
		0x1150F53BD983FA78ULL,
		0xB7D78179D19E9806ULL,
		0x452ACBE74309706CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD97D7D74CDA0F38BULL,
		0xE5AE243C755265E9ULL,
		0x9961BF17FDB7DAA1ULL,
		0x149C5897EB769483ULL,
		0x93530153D92C787DULL,
		0xB2674320494E0A8CULL,
		0x449EB00BCF87DCFEULL,
		0x5CA26A4B4FF20034ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1581420CD809001ULL,
		0x440E2420714045A9ULL,
		0x8141BE1785B24021ULL,
		0x101C088109420402ULL,
		0x1102011359285005ULL,
		0x1040412049020A08ULL,
		0x04968009C1869806ULL,
		0x44224A4343000024ULL
	}};
	printf("Test Case 142\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFA1C4854980CD4F9ULL,
		0x903BFA45F1C2C28FULL,
		0x9E98601511D63107ULL,
		0xF5448EDF6565A270ULL,
		0x930F04078A9D2915ULL,
		0xF98F6310EF33783DULL,
		0x92E31498B2873ED5ULL,
		0x587FA5B833CA12D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C6F5740F9EF0DC8ULL,
		0xEFC7A844F1C04CA6ULL,
		0x11EE025E1C76AE0EULL,
		0x1B6A3344EFDFF35CULL,
		0x51D33928EFC23ADBULL,
		0xD0A3F3FC04D45850ULL,
		0x3282FF9584402E38ULL,
		0x4E9AA9A52FF2A138ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x580C4040980C04C8ULL,
		0x8003A844F1C04086ULL,
		0x1088001410562006ULL,
		0x114002446545A250ULL,
		0x110300008A802811ULL,
		0xD083631004105810ULL,
		0x1282149080002E10ULL,
		0x481AA1A023C20010ULL
	}};
	printf("Test Case 143\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA24F4E37D5B49BA2ULL,
		0x14AE0931BC3F8DACULL,
		0x76890489B9B8F357ULL,
		0xAEDED262072E10FDULL,
		0x48292C7F62820BAFULL,
		0xB2612FE3F50A4F58ULL,
		0x9CF28F2213A07273ULL,
		0x4614F84A57BAB3B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFAA66CCBAD55450ULL,
		0x359D68B3CA10D4FCULL,
		0xEBDFC4386C131B0FULL,
		0xA6084304184F8670ULL,
		0x39ECC8C148EAD4BAULL,
		0xB31785196B98DC7CULL,
		0x0323735ED97DE442ULL,
		0x5FAD7666DCB1156CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA20A460490941000ULL,
		0x148C0831881084ACULL,
		0x6289040828101307ULL,
		0xA6084200000E0070ULL,
		0x08280841408200AAULL,
		0xB201050161084C58ULL,
		0x0022030211206042ULL,
		0x4604704254B01128ULL
	}};
	printf("Test Case 144\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x509DC81F36257483ULL,
		0xC705B6FDACF34209ULL,
		0x1A841353162F1AD0ULL,
		0x0E890722EA4F239BULL,
		0x13580E08AD653976ULL,
		0x74B8281471C4592CULL,
		0xE2B9C2FA86FC2F58ULL,
		0x41391F93D19982B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x134D4C4FB7C4A39FULL,
		0x2DBD516A977AE5DCULL,
		0x4A12962CEEAE9206ULL,
		0x57C2E3F999C26EECULL,
		0xB220D9A8378BCC30ULL,
		0x551E7C96E0595548ULL,
		0x44141ED28FFDFC6EULL,
		0x828C975F0AB5202FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100D480F36042083ULL,
		0x0505106884724008ULL,
		0x0A001200062E1200ULL,
		0x0680032088422288ULL,
		0x1200080825010830ULL,
		0x5418281460405108ULL,
		0x401002D286FC2C48ULL,
		0x0008171300910024ULL
	}};
	printf("Test Case 145\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5538A470580CB2FAULL,
		0xBC1A6AED0D611E72ULL,
		0xA6CE71D10CFEEAC5ULL,
		0x4F103D6F35D80FD1ULL,
		0xE2158614CFB6009FULL,
		0xAA279180C3B1151CULL,
		0xFA2C8ED581845FDAULL,
		0xF017E9FD4853742EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903223C1276786D5ULL,
		0xAA048B2B791174CCULL,
		0xBBDEDCB9F4629B0EULL,
		0x1FB7B05503885599ULL,
		0x621759C6A254FC29ULL,
		0xF62622A7DA20C05BULL,
		0x99E1BBFCBBD35795ULL,
		0x4CBCB3D9CAEFF561ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10302040000482D0ULL,
		0xA8000A2909011440ULL,
		0xA2CE509104628A04ULL,
		0x0F10304501880591ULL,
		0x6215000482140009ULL,
		0xA2260080C2200018ULL,
		0x98208AD481805790ULL,
		0x4014A1D948437420ULL
	}};
	printf("Test Case 146\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE57DE266D2F0F3F9ULL,
		0x9FD52DC889E9D59EULL,
		0x68C08A842F1FDF38ULL,
		0xD5A9FB78ABD417FBULL,
		0x8AA702C204FED689ULL,
		0x4B7BE310FAD2E073ULL,
		0xDF80AD1EF67C8DAEULL,
		0xD4ECC67E596E06D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECCFF3063B38994FULL,
		0xE6B1CF4FBA70F674ULL,
		0x687927D2C659362AULL,
		0x75B1546EA36679EBULL,
		0xA1179DC0C498783AULL,
		0xC843BFFF5F531D7DULL,
		0x9337404BB810BE42ULL,
		0xB4DDF2695E47AA78ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE44DE20612309149ULL,
		0x86910D488860D414ULL,
		0x6840028006191628ULL,
		0x55A15068A34411EBULL,
		0x800700C004985008ULL,
		0x4843A3105A520071ULL,
		0x9300000AB0108C02ULL,
		0x94CCC26858460250ULL
	}};
	printf("Test Case 147\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x87D20F8B8235428BULL,
		0x3A6DD49F4A68442EULL,
		0x959E7A99AB95B29EULL,
		0xFB1F3F4A9AFEE1BBULL,
		0x4B9A96D377260EEBULL,
		0x6437AC8ADFF46858ULL,
		0x2091CEEC397C784CULL,
		0x6670B36E7752F5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC2B0827F934A1FULL,
		0x550366A3C963DEE9ULL,
		0xE850D0E798F89F34ULL,
		0x6B99DC8EE2981DD9ULL,
		0x6B0E3AC43A0B6AB6ULL,
		0xB941CDD7831EF5F0ULL,
		0xA947F935C681B7C3ULL,
		0x091EF24DC573BF36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86C200820211420BULL,
		0x1001448348604428ULL,
		0x8010508188909214ULL,
		0x6B191C0A82980199ULL,
		0x4B0A12C032020AA2ULL,
		0x20018C8283146050ULL,
		0x2001C82400003040ULL,
		0x0010B24C4552B516ULL
	}};
	printf("Test Case 148\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA78C108FC92C4B3CULL,
		0x5750A685C114878CULL,
		0xB78ABA15E1C2B9E4ULL,
		0x4A97235E4D78245BULL,
		0x6E8C9742BE049AE6ULL,
		0x32839A31EB67D96BULL,
		0xB5D8348651F5D348ULL,
		0x6FF44E329B41B166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02DD1572574F93A6ULL,
		0x05A3B75A44BB27FCULL,
		0x9BF931022A2FB31BULL,
		0x4B39CA09CE5211F4ULL,
		0x8D8D47DBC134E11AULL,
		0x765DE44FEBF92628ULL,
		0x1E1455E7489FDF6BULL,
		0x9DE5CCFB801069F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028C1002410C0324ULL,
		0x0500A6004010078CULL,
		0x938830002002B100ULL,
		0x4A1102084C500050ULL,
		0x0C8C074280048002ULL,
		0x32018001EB610028ULL,
		0x141014864095D348ULL,
		0x0DE44C3280002166ULL
	}};
	printf("Test Case 149\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x396653CA0F3A0175ULL,
		0x9C5E3374E6BAAD53ULL,
		0x82959195C1B27F7DULL,
		0x6717B89A99DE93B8ULL,
		0x02222D99274CA7A6ULL,
		0x164AF63202E8E431ULL,
		0xC8615E043A4F4FA8ULL,
		0x21C2964BEA4200F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7770B0293945D326ULL,
		0x5EDA53232E071C0AULL,
		0x547F3F1C7264E15FULL,
		0x3000C98962EF4925ULL,
		0xAF4F932FADD3E855ULL,
		0x076242AB2ED2941EULL,
		0x80EEDC7BD3920ECEULL,
		0x918192B713D331C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3160100809000124ULL,
		0x1C5A132026020C02ULL,
		0x001511144020615DULL,
		0x2000888800CE0120ULL,
		0x020201092540A004ULL,
		0x0642422202C08410ULL,
		0x80605C0012020E88ULL,
		0x01809203024200C2ULL
	}};
	printf("Test Case 150\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD71C904E9CC8625AULL,
		0xC58D6632663FF631ULL,
		0xB934C1BE18A3760FULL,
		0xF9ABF9EAC07CD0F1ULL,
		0xC4100B1883AF81C0ULL,
		0xF62F86A29D93993FULL,
		0x1128CD9122C998CEULL,
		0xE0725FB6A3F13A4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43AF8A10334FBAC2ULL,
		0x1D2605F6A6709708ULL,
		0x0F21037E6C1B941DULL,
		0xDFFA3D843C8BB17FULL,
		0xCFE3E54F0299B462ULL,
		0xB7B604A9299EBBCEULL,
		0x4A5B62A41F672AB6ULL,
		0xAB20609CEEAC8CDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x430C800010482242ULL,
		0x0504043226309600ULL,
		0x0920013E0803140DULL,
		0xD9AA398000089071ULL,
		0xC400010802898040ULL,
		0xB62604A00992990EULL,
		0x0008408002410886ULL,
		0xA0204094A2A0084AULL
	}};
	printf("Test Case 151\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBA7E0724C165E3F0ULL,
		0x91856F2DAF61F605ULL,
		0x96F9DF36B0103DFEULL,
		0xDB5FA540EA2A6D0CULL,
		0xDDFE2740A9B8538EULL,
		0xBDBE98918D98FEA1ULL,
		0xDC745E4EE6053498ULL,
		0xFCFBD33EA6B04553ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x792C896FA1EE6BE0ULL,
		0xF828E7D02520AA59ULL,
		0xBE7F627ACDBDA1EDULL,
		0x29731D0DC332112DULL,
		0x99830D194EE0DB83ULL,
		0x827DFCD1317789B4ULL,
		0x752FD67C25F6AFC2ULL,
		0x632B09CDA28697E3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x382C0124816463E0ULL,
		0x900067002520A201ULL,
		0x96794232801021ECULL,
		0x09530500C222010CULL,
		0x9982050008A05382ULL,
		0x803C9891011088A0ULL,
		0x5424564C24042480ULL,
		0x602B010CA2800543ULL
	}};
	printf("Test Case 152\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA23C0BB5EA229ACCULL,
		0x6C06CF22456F5A47ULL,
		0x3E8E237E223BA06AULL,
		0x57596D2E72E57AF7ULL,
		0xFBE5187D7938E68AULL,
		0xA0BF90792D51B167ULL,
		0xE29CEE9753D75A91ULL,
		0x4BF535DC1A0C867CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x086C97EB818D0388ULL,
		0x664868F05ABF92EDULL,
		0x78731CDF4850C8D2ULL,
		0x8B94147D38F0F9DDULL,
		0x579F268D08B3F27FULL,
		0x0A3FA4C1DDA7B3EDULL,
		0xB0C6BC19AAC66811ULL,
		0xE87F9370E76EFD99ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002C03A180000288ULL,
		0x64004820402F1245ULL,
		0x3802005E00108042ULL,
		0x0310042C30E078D5ULL,
		0x5385000D0830E20AULL,
		0x003F80410D01B165ULL,
		0xA084AC1102C64811ULL,
		0x48751150020C8418ULL
	}};
	printf("Test Case 153\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x46913E44BC60963CULL,
		0xE5E93A4E1360FB13ULL,
		0x67E9376E6C69BEDFULL,
		0xDC4C81ABB4E3D659ULL,
		0x594474F7E9BDE17EULL,
		0x22B7D4A9524FA2B6ULL,
		0xDA62927D55897471ULL,
		0x0FCB6F6AD6812C7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB38856BFD5AB119ULL,
		0x4DB20345728C42FBULL,
		0x4DC29A2A4AC34BE2ULL,
		0xA827ECCD4891230FULL,
		0x4EA256F759A91DC0ULL,
		0xE26554A71EA000BCULL,
		0xE0E688EC9F5FE7C5ULL,
		0x1F9008FF12C761CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x42100440BC409018ULL,
		0x45A0024412004213ULL,
		0x45C0122A48410AC2ULL,
		0x8804808900810209ULL,
		0x480054F749A90140ULL,
		0x222554A1120000B4ULL,
		0xC062806C15096441ULL,
		0x0F80086A1281204CULL
	}};
	printf("Test Case 154\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCCE3D8A7D99821CFULL,
		0xBAED1E64448D19E5ULL,
		0xD3A5618245C27DD9ULL,
		0x86D4437ADF1185FFULL,
		0x8764D6F3070CCE76ULL,
		0x6F1D176F421E47D9ULL,
		0x166F88C3F8A9E4C2ULL,
		0x38547D8B1D4B68C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x804B45B143B6B715ULL,
		0xDA34201FAF2BAAB4ULL,
		0xE2D4BB94E8184AABULL,
		0x2F3428E9A1C2C10BULL,
		0x91A8130829845EADULL,
		0xB4601E32B9565EB2ULL,
		0xC4E07FC121E42299ULL,
		0x0B543F035A06C3C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x804340A141902105ULL,
		0x9A240004040908A4ULL,
		0xC284218040004889ULL,
		0x061400688100810BULL,
		0x8120120001044E24ULL,
		0x2400162200164690ULL,
		0x046008C120A02080ULL,
		0x08543D03180240C3ULL
	}};
	printf("Test Case 155\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAB971C5805F3B4E5ULL,
		0x8A3F320C2C888E68ULL,
		0x986533DC1C4CE60AULL,
		0xB61E5BA54159552CULL,
		0xC2F0B9BB3F2C006EULL,
		0xBEC4380879B6F1E4ULL,
		0x58A0F3FE2FEF75DCULL,
		0x4B22E850C8CC988EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B6B7EE17D55BC93ULL,
		0xB2C463A1980F87F8ULL,
		0xAD29498BC56A118CULL,
		0xCC0B53FE59CF149EULL,
		0x4010A7149A17602EULL,
		0xB86CBB7AAC5F7DDBULL,
		0xC069FE5D7B231163ULL,
		0xC7E38D44648BC9DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B031C400551B481ULL,
		0x8204220008088668ULL,
		0x8821018804480008ULL,
		0x840A53A44149140CULL,
		0x4010A1101A04002EULL,
		0xB8443808281671C0ULL,
		0x4020F25C2B231140ULL,
		0x432288404088888AULL
	}};
	printf("Test Case 156\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAFAA3EFB9196669BULL,
		0x97D4AE20E3287477ULL,
		0x6FF30F357C1D74C9ULL,
		0xED8C92BBEE3672CEULL,
		0xE741EAC7310721A5ULL,
		0x101E05B215794E0EULL,
		0x221618F67A611E8CULL,
		0x97B3084E8F0A3FA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6AAE3445DCE8B9DULL,
		0xA7F8E605F48670D5ULL,
		0x7B09A6090DFEEDEBULL,
		0xE1D9203F160F2A93ULL,
		0xD6688B479C771DF8ULL,
		0x1F9FDDFE1D12D9CCULL,
		0x114ED9DC736CFBC2ULL,
		0x464D6AC68CE6972FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA6AA224011860299ULL,
		0x87D0A600E0007055ULL,
		0x6B0106010C1C64C9ULL,
		0xE188003B06062282ULL,
		0xC6408A47100701A0ULL,
		0x101E05B21510480CULL,
		0x000618D472601A80ULL,
		0x060108468C021723ULL
	}};
	printf("Test Case 157\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9D0C851C53165D8CULL,
		0x01E0DA8166D60EDCULL,
		0x14E130AF49D49410ULL,
		0x8ED768CD0D444520ULL,
		0xF987082FA150C3F7ULL,
		0x5292E1188700D030ULL,
		0x8CACB022A424FD6DULL,
		0xE93BBE0F2BE68F01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x611E5400EFA219D8ULL,
		0x62F28393A5B93D7BULL,
		0x1D3F8AD0FA2ABE76ULL,
		0x4DC7A59BAC3A16ACULL,
		0x4124B1ECBA3158AFULL,
		0x896B42ABBD6F0E91ULL,
		0xC4226BD58FEFB92CULL,
		0xFD93AAF26A25B02EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010C040043021988ULL,
		0x00E0828124900C58ULL,
		0x1421008048009410ULL,
		0x0CC720890C000420ULL,
		0x4104002CA01040A7ULL,
		0x0002400885000010ULL,
		0x842020008424B92CULL,
		0xE913AA022A248000ULL
	}};
	printf("Test Case 158\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFE519D1208A264DFULL,
		0xCC971604519D9334ULL,
		0x636A65620DDFE8F5ULL,
		0xF073222852E867FCULL,
		0x47A0BE9AA2959130ULL,
		0xC539B53C251F7EF1ULL,
		0x71BCACD0704A83BDULL,
		0xA123AB42DF3A7B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C752F8B13FD4CA1ULL,
		0xB7D3E1405CF2A5F3ULL,
		0x89C9852879D44870ULL,
		0xF7EE12BD3C12D005ULL,
		0x4867226D440CFD61ULL,
		0x3EF6AF2FD6F1769DULL,
		0x41C2D94A381BBEFFULL,
		0x271C53BD7580CF42ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C510D0200A04481ULL,
		0x8493000050908130ULL,
		0x0148052009D44870ULL,
		0xF062022810004004ULL,
		0x4020220800049120ULL,
		0x0430A52C04117691ULL,
		0x41808840300A82BDULL,
		0x2100030055004B40ULL
	}};
	printf("Test Case 159\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x98435D9E8506EBBFULL,
		0x7C71333859C613ECULL,
		0x65F468F2B7501EF4ULL,
		0xA091D5E4CE55DE64ULL,
		0x46479AB0955F79A9ULL,
		0xC4F7A600F1F028FEULL,
		0x7C777840D0EAE4F6ULL,
		0x49B439C285905882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA171E1C053EB0FA0ULL,
		0xFF7864317386F98CULL,
		0x6D5C6027768DC7E2ULL,
		0x75CD40E715CBE348ULL,
		0xA66E301065CF1E07ULL,
		0xEB476EC69898D3C5ULL,
		0x75288882C5BE9994ULL,
		0x9FA5F7BF5F33E623ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8041418001020BA0ULL,
		0x7C7020305186118CULL,
		0x65546022360006E0ULL,
		0x208140E40441C240ULL,
		0x06461010054F1801ULL,
		0xC0472600909000C4ULL,
		0x74200800C0AA8094ULL,
		0x09A4318205104002ULL
	}};
	printf("Test Case 160\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x707CEF890E51A38BULL,
		0xE539F9457FF6C167ULL,
		0x62DCEB039C862ED2ULL,
		0xAA7F99FFD2110EE3ULL,
		0xD4E6DE7EE613F12EULL,
		0xAB0DEDC4FF2366F0ULL,
		0xCB77CD0DC0AA12F6ULL,
		0x579140BC7DBDEC31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C48B329E31C4FC1ULL,
		0x36C036972F2968A9ULL,
		0xAA2B5531240AED28ULL,
		0x69A0B297FFF3926BULL,
		0x8C7925707494B584ULL,
		0x71D479AF05E6C6CAULL,
		0xCCDA78BCA2454FC1ULL,
		0xB7DF95547CFCC25EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0048A30902100381ULL,
		0x240030052F204021ULL,
		0x2208410104022C00ULL,
		0x28209097D2110263ULL,
		0x846004706410B104ULL,
		0x21046984052246C0ULL,
		0xC852480C800002C0ULL,
		0x179100147CBCC010ULL
	}};
	printf("Test Case 161\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x32D958D7578DBD2AULL,
		0xFD557E53C3984496ULL,
		0x66D153DD80BFA39EULL,
		0x8194B31E508D6624ULL,
		0xB0518780487A413FULL,
		0x5B204B32265190C7ULL,
		0x4A5F3C2D8982CCDCULL,
		0x4A7C58C3348647F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB77D20F5281DA8F6ULL,
		0x820614092CA3A753ULL,
		0x1A3CE76CA97320E6ULL,
		0x1F289E3E0EC72D64ULL,
		0xBAEF3A78867DD695ULL,
		0xFB4AFE242B3DFB92ULL,
		0x0DBF80937AC66C8AULL,
		0x0A60282809017430ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x325900D5000DA822ULL,
		0x8004140100800412ULL,
		0x0210434C80332086ULL,
		0x0100921E00852424ULL,
		0xB041020000784015ULL,
		0x5B004A2022119082ULL,
		0x081F000108824C88ULL,
		0x0A60080000004430ULL
	}};
	printf("Test Case 162\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF683E509661BC392ULL,
		0x4BA9427361AD746EULL,
		0x4EB57A7272F90051ULL,
		0x5C7D9E53A87F45D3ULL,
		0x15AFC0AA060BD7E9ULL,
		0xCF0673F0CA5D0716ULL,
		0x554B4BF09F836F74ULL,
		0xEAE9D77390734E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F1360E810267B8DULL,
		0x91A78573BA2C03D7ULL,
		0x7E5DFB778275ACF3ULL,
		0xE96DA78357347377ULL,
		0xBC9E10478C22E3B3ULL,
		0xDEB34E8A2C679698ULL,
		0xC36720BE508EF2BCULL,
		0x767AB60740A27527ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4603600800024380ULL,
		0x01A10073202C0046ULL,
		0x4E157A7202710051ULL,
		0x486D860300344153ULL,
		0x148E00020402C3A1ULL,
		0xCE02428008450610ULL,
		0x414300B010826234ULL,
		0x6268960300224424ULL
	}};
	printf("Test Case 163\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x54BFAAEA1CF87323ULL,
		0xDCD00046469FBFB8ULL,
		0x32FFB8F3CB9EC951ULL,
		0x0EE02B368BB3BDFAULL,
		0x2429D2CDE5416244ULL,
		0x9F9CC64D039008D2ULL,
		0x3B29C4BAB0AAF63FULL,
		0x24BE207715F1F54FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E63036A61F93F58ULL,
		0xFD0F58C0541CB63BULL,
		0xB42BAC7A2E03625EULL,
		0x8F1D6D844C1BABF4ULL,
		0x40E068C6C4456C7CULL,
		0x1762218E76C953E6ULL,
		0x1915E26D0E94801BULL,
		0xF7ED8455B9B3F392ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4423026A00F83300ULL,
		0xDC000040441CB638ULL,
		0x302BA8720A024050ULL,
		0x0E0029040813A9F0ULL,
		0x002040C4C4416044ULL,
		0x1700000C028000C2ULL,
		0x1901C0280080801BULL,
		0x24AC005511B1F102ULL
	}};
	printf("Test Case 164\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3B3C0F11B350A55CULL,
		0x23558943C498C631ULL,
		0xC20FF3ED91023902ULL,
		0x8442E655A5A1A8D5ULL,
		0x1D37A21371C91B75ULL,
		0xD4B87505BE79D107ULL,
		0xA5B5BC151F7DB6F3ULL,
		0x5A268CD11D56015EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD91475A80B5D84C1ULL,
		0xA48CD627DAC6C8C5ULL,
		0xC1ABF9A538A376DEULL,
		0xFA3DFB4AE18F6990ULL,
		0x474917C18EA4A077ULL,
		0xEF12EBB3776616F7ULL,
		0x2E05409F3A57E29FULL,
		0xADFF372E61733B18ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1914050003508440ULL,
		0x20048003C080C001ULL,
		0xC00BF1A510023002ULL,
		0x8000E240A1812890ULL,
		0x0501020100800075ULL,
		0xC410610136601007ULL,
		0x240500151A55A293ULL,
		0x0826040001520118ULL
	}};
	printf("Test Case 165\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1A8F39403192041FULL,
		0x12E1E18DE85E429DULL,
		0xD38A308599D8391EULL,
		0x8AF08E60874F6667ULL,
		0x7FA40306D5364DDDULL,
		0x2461A13410348967ULL,
		0xF8ACDEF0D6D4E04CULL,
		0xB113A1098EA51F69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CFE4229CBBC304ULL,
		0x0CAFBCCA4549EF4FULL,
		0xB253C15CBA08674EULL,
		0xCA6662C7F6EEC7CFULL,
		0x5EA0B60A74D5C7D3ULL,
		0xE606A1BB239AAEC7ULL,
		0x7AF675D83DF84FF5ULL,
		0x518FAF1AB1A18418ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x088F200010920004ULL,
		0x00A1A0884048420DULL,
		0x920200049808210EULL,
		0x8A600240864E4647ULL,
		0x5EA00202541445D1ULL,
		0x2400A13000108847ULL,
		0x78A454D014D04044ULL,
		0x1103A10880A10408ULL
	}};
	printf("Test Case 166\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0E255096CF95E6CCULL,
		0x05172565101CBDCCULL,
		0x953E918232D34D95ULL,
		0xDB9CB1008D643E35ULL,
		0xE35658308AFEC8B2ULL,
		0x033605906A73786BULL,
		0x7F518DE2FCAAF281ULL,
		0x88A94265B5EE0069ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7089639E91DEBC9CULL,
		0xC957D9F210B9C383ULL,
		0xE7D72B5346598A75ULL,
		0x28DE9167345E977EULL,
		0xCA0AB22AF0B3FD4FULL,
		0xB6353530B817E892ULL,
		0x544C617881B13FCAULL,
		0x55834BA6A7BEC148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000140968194A48CULL,
		0x0117016010188180ULL,
		0x8516010202510815ULL,
		0x089C910004441634ULL,
		0xC202102080B2C802ULL,
		0x0234051028136802ULL,
		0x5440016080A03280ULL,
		0x00814224A5AE0048ULL
	}};
	printf("Test Case 167\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x62141372D83A7B96ULL,
		0x3E4FB38951DC2510ULL,
		0x1770617015029F6FULL,
		0x9F1E912E89CD194CULL,
		0x5CE4FF4C62150FBBULL,
		0x35B4EB7FB419FB2CULL,
		0x8770A751176B8B66ULL,
		0x547B76B97372A35EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF3FD335412D7F64ULL,
		0xF1686E96880D5AB3ULL,
		0x718C05C2AF40ADD0ULL,
		0x60E60A29216FF741ULL,
		0xB3841C2F7FF8EB3CULL,
		0x7D43392BE0655FEEULL,
		0xEA1B5B6E4534B292ULL,
		0xD25FADBD46C0DA04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2214133040287B04ULL,
		0x30482280000C0010ULL,
		0x1100014005008D40ULL,
		0x00060028014D1140ULL,
		0x10841C0C62100B38ULL,
		0x3500292BA0015B2CULL,
		0x8210034005208202ULL,
		0x505B24B942408204ULL
	}};
	printf("Test Case 168\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF6C29A719E0A62E3ULL,
		0x38041E00BFEA40C0ULL,
		0x4CAEBB22D6189719ULL,
		0xA7D762662F0D622FULL,
		0x1499198310AC0557ULL,
		0x29113B8AB32BE214ULL,
		0xB5B8194D620B82A7ULL,
		0x9DF3C45D97073833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E561A7222124C37ULL,
		0x3B42EFE91F8B7F4FULL,
		0x7E126D91591B8FF4ULL,
		0xD6758014ADE76FD7ULL,
		0xAE74A284F0B3AF07ULL,
		0xFD9E04302A858285ULL,
		0x31580CB1D0C893FFULL,
		0xB69419AC07C27792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16421A7002024023ULL,
		0x38000E001F8A4040ULL,
		0x4C02290050188710ULL,
		0x865500042D056207ULL,
		0x0410008010A00507ULL,
		0x2910000022018204ULL,
		0x31180801400882A7ULL,
		0x9490000C07023012ULL
	}};
	printf("Test Case 169\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE8EA874FD700BD86ULL,
		0x17FD05C18F27FB3AULL,
		0xE23F99C5B8F1961DULL,
		0x86B8B491B6B15FB1ULL,
		0xA15BB586221A556EULL,
		0x999730D27700C9F5ULL,
		0x43EE27281562AEB9ULL,
		0x8260C7F19383AA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA3C30F00C54C17ULL,
		0xBA211596CDBCD407ULL,
		0x4A53763F49409F0CULL,
		0x55C5F403356DFAC8ULL,
		0x59039B172EC52216ULL,
		0x3EF4CF71F9C8167EULL,
		0x3BEA37A066C3C3B4ULL,
		0xD69D2C709162062BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8A2830F00000C06ULL,
		0x122105808D24D002ULL,
		0x421310050840960CULL,
		0x0480B40134215A80ULL,
		0x0103910622000006ULL,
		0x1894005071000074ULL,
		0x03EA2720044282B0ULL,
		0x820004709102022AULL
	}};
	printf("Test Case 170\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x201AC20A41E104EBULL,
		0x4E0BC4D22804AD07ULL,
		0xDE6D73EAB9CDE924ULL,
		0xE45CFC8AEDEB15B5ULL,
		0x21F487FFBD4CA8CDULL,
		0x63BE79C54B27AAACULL,
		0x95E32BF4B34F96C4ULL,
		0x1A9FA86F2B840E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA56750809F89013ULL,
		0xF812B8162FF0034BULL,
		0xFB7702EB2382101FULL,
		0x1DF52A53CDF20DBDULL,
		0x991B74DE8E01872FULL,
		0xD0598BB79B889B97ULL,
		0x5B71A67EB60BC05CULL,
		0x140836F866ADCBFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2012400801E00003ULL,
		0x4802801228000103ULL,
		0xDA6502EA21800004ULL,
		0x04542802CDE205B5ULL,
		0x011004DE8C00800DULL,
		0x401809850B008A84ULL,
		0x11612274B20B8044ULL,
		0x1008206822840A28ULL
	}};
	printf("Test Case 171\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3B80339F06AAE710ULL,
		0x7E41AA90E5B798AEULL,
		0xD7A18A4F58B0E840ULL,
		0xCC83B3F60B707CA2ULL,
		0x6D0DD5032E582104ULL,
		0x556099890C0F3BE1ULL,
		0xB3470820554F3856ULL,
		0xAECDDBBDBF6353F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A7EF01A5EEFDFDEULL,
		0x8FDB4892C7523C14ULL,
		0xD972BFC66D638ED2ULL,
		0x853414D9E1919255ULL,
		0x16CE70D0316877D7ULL,
		0xEDD406991212DDA3ULL,
		0x602D4E9A273B68C5ULL,
		0x0AF12783F5F016DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A00301A06AAC710ULL,
		0x0E410890C5121804ULL,
		0xD1208A4648208840ULL,
		0x840010D001101000ULL,
		0x040C500020482104ULL,
		0x45400089000219A1ULL,
		0x20050800050B2844ULL,
		0x0AC10381B56012D9ULL
	}};
	printf("Test Case 172\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x87CCD01687275C2FULL,
		0x706E9DCAC61498ACULL,
		0xFEA9B1D914C97E39ULL,
		0xF7F23B34B1802350ULL,
		0x8292511B9E8DE2F1ULL,
		0xD3FD453F890E4C38ULL,
		0x52EC3E3949F89BCCULL,
		0x75CFDD18DF3AE7DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54F3EB6ACDE241CULL,
		0x7219AE478F7DB741ULL,
		0x4405BFA5AD938236ULL,
		0xFCF0FF38AE95E318ULL,
		0xC47839380590F47FULL,
		0x9CC2FCD6731176D1ULL,
		0xCE6A995C8F871C38ULL,
		0x2731EAE987DAFEC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x854C10168406040CULL,
		0x70088C4286149000ULL,
		0x4401B18104810230ULL,
		0xF4F03B30A0802310ULL,
		0x801011180480E071ULL,
		0x90C0441601004410ULL,
		0x4268181809801808ULL,
		0x2501C808871AE6C8ULL
	}};
	printf("Test Case 173\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x696E5C4EA56B50ADULL,
		0x83220DC848595C72ULL,
		0xA393B433922267BAULL,
		0x2A75A6E966123A8FULL,
		0x203153EA33353A26ULL,
		0x7E3AC44323F93486ULL,
		0x47DDBC7F2837F28BULL,
		0x634E96EC6AA07CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09D39A8563FF3AC6ULL,
		0xE98D9C9C2D2D33E2ULL,
		0x4AD2F58DDF844F61ULL,
		0x5D5F736720DB167FULL,
		0x6F84FFA7768AE958ULL,
		0x86ED35AC0E6A369EULL,
		0x4B0526DC7C930D20ULL,
		0xEE69DE89567A516CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09421804216B1084ULL,
		0x81000C8808091062ULL,
		0x0292B40192004720ULL,
		0x085522612012120FULL,
		0x200053A232002800ULL,
		0x0628040002683486ULL,
		0x4305245C28130000ULL,
		0x6248968842205028ULL
	}};
	printf("Test Case 174\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1FCE726B96067EB2ULL,
		0x630F644DD372909AULL,
		0x1F4CEB80E44E1B34ULL,
		0xB17E785F46DCF53FULL,
		0x3A00C145BDE408E4ULL,
		0x8A4ACD9546F12309ULL,
		0x26E2E5B3E2A2EBE1ULL,
		0x8681E4D92AFE528FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE569E32881E3294ULL,
		0x232F7328048CEA05ULL,
		0xFD6A6C9E32B3FABDULL,
		0xBA62334371B77D30ULL,
		0xCEB12E7BDB18DF6DULL,
		0xDC5B804EE33FB80AULL,
		0x0B0C3D2A030EE22FULL,
		0xDECF340F105C7B20ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E46122280063290ULL,
		0x230F600800008000ULL,
		0x1D48688020021A34ULL,
		0xB062304340947530ULL,
		0x0A00004199000864ULL,
		0x884A800442312008ULL,
		0x020025220202E221ULL,
		0x86812409005C5200ULL
	}};
	printf("Test Case 175\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFC0B788B73FF3083ULL,
		0xBC424F9AAD23D1EAULL,
		0x25332B09A26E2E7AULL,
		0x1DE30E72E33370FAULL,
		0xA183DBEAC08287A1ULL,
		0x6140037044D16857ULL,
		0x4CFA29DC81593F59ULL,
		0xD8B265BFBEE03861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E33C429BE6EA039ULL,
		0xFB7FBE0BF816CD8EULL,
		0x545A39DA5C9845ACULL,
		0xB7235B883C9ACEF3ULL,
		0x8E4D969529DFF429ULL,
		0x6111DB2CADD7D366ULL,
		0xE29286F04A347A24ULL,
		0x8B6327AB4DB5D66BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C034009326E2001ULL,
		0xB8420E0AA802C18AULL,
		0x0412290800080428ULL,
		0x15230A00201240F2ULL,
		0x8001928000828421ULL,
		0x6100032004D14046ULL,
		0x409200D000103A00ULL,
		0x882225AB0CA01061ULL
	}};
	printf("Test Case 176\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x952E08D3EAC666A1ULL,
		0xF3EF33BEDB3E39FBULL,
		0x9631FBBEFBB39A75ULL,
		0xB261108BC1945976ULL,
		0xFABA03F70B04E9A5ULL,
		0x338046C49ED97BC5ULL,
		0x56094B751C27B5DEULL,
		0x4163EF5D6629129EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C78FA7033828A95ULL,
		0x3F1639919C86B174ULL,
		0x461AE9961421FF6DULL,
		0x62BAA8E3D0DCF695ULL,
		0x6E763DBFF051D218ULL,
		0x21E652ECAD960880ULL,
		0x40AF06DB81F251A6ULL,
		0x5D9ED07BBE4EC876ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1428085022820281ULL,
		0x3306319098063170ULL,
		0x0610E99610219A65ULL,
		0x22200083C0945014ULL,
		0x6A3201B70000C000ULL,
		0x218042C48C900880ULL,
		0x4009025100221186ULL,
		0x4102C05926080016ULL
	}};
	printf("Test Case 177\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7B3446BD95AE0BD2ULL,
		0x5DF6ABD9A988C2ABULL,
		0x01E3D12F65DD853DULL,
		0x0202814F2C303FA9ULL,
		0x11A4CAC305FE5C9CULL,
		0x707C432AC8C28EDCULL,
		0xDAE18707F5C55F94ULL,
		0x73E3885413351FE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A162C1A69AD7E9ULL,
		0x4F42C1B5EDDBBA27ULL,
		0xD84A83CF89DAEE7EULL,
		0xF450692813A400E1ULL,
		0xC80F0FD04756F393ULL,
		0x50E7B681B10DDFD4ULL,
		0xCB78747379801967ULL,
		0xB6A271D9612826EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10204281848A03C0ULL,
		0x4D428191A9888223ULL,
		0x0042810F01D8843CULL,
		0x00000108002000A1ULL,
		0x00040AC005565090ULL,
		0x5064020080008ED4ULL,
		0xCA60040371801904ULL,
		0x32A20050012006E4ULL
	}};
	printf("Test Case 178\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB18263D8ADABFD4AULL,
		0x7941F2A8E4F114D5ULL,
		0xC81C9C047497723EULL,
		0x545350807375EFFEULL,
		0x8608962C5E80F874ULL,
		0xA3D1C65A9824D216ULL,
		0x22BF51DCE91ADC1BULL,
		0x5E03627A252F616EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FB2CD0A7B1A3339ULL,
		0x03D04C488BF64DE1ULL,
		0x94668261686250D3ULL,
		0x40B4C3117C99FAA2ULL,
		0x1F1187343274FD9EULL,
		0x409C32CC55F28636ULL,
		0xB1B9B03A8E709011ULL,
		0x3000B426C8F2868EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81824108290A3108ULL,
		0x0140400880F004C1ULL,
		0x8004800060025012ULL,
		0x401040007011EAA2ULL,
		0x060086241200F814ULL,
		0x0090024810208216ULL,
		0x20B9101888109011ULL,
		0x100020220022000EULL
	}};
	printf("Test Case 179\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0005F5197C051D17ULL,
		0x6443B9964F3642C5ULL,
		0x7D9A9C9B957CB502ULL,
		0x673C6937C230AFDEULL,
		0x1F9C2AE68874E06BULL,
		0x950B7DE4C394B9E6ULL,
		0x0746CE9DBF81B1F2ULL,
		0x15AD7916855AAD3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B986C70D19F02AEULL,
		0xA4E4AB62AAA4FF4EULL,
		0xE32E08A6B92C2974ULL,
		0xDC505293EE19DDBEULL,
		0x1905FB29F402428EULL,
		0x8EE72785E088AF2CULL,
		0xFBBAF8D4EBD26C73ULL,
		0x0750440ECE1E16CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000641050050006ULL,
		0x2440A9020A244244ULL,
		0x610A0882912C2100ULL,
		0x44104013C2108D9EULL,
		0x19042A208000400AULL,
		0x84032584C080A924ULL,
		0x0302C894AB802072ULL,
		0x05004006841A040DULL
	}};
	printf("Test Case 180\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDA91F5A3D932F857ULL,
		0xAE9E28C5BB956CDAULL,
		0x1867DB762A1A6AC7ULL,
		0x48F5D856992297BEULL,
		0xABAAF3B10679D2B7ULL,
		0xFF9C3BEDE0F3D225ULL,
		0x093AFD8F0A29C960ULL,
		0x2E6CE2702B1F059BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7846F614B93AD6ULL,
		0x94248AA84222AAFDULL,
		0x26BD7C8C0A2ED247ULL,
		0x19313F1C79A458A2ULL,
		0x301A7F6F47729366ULL,
		0xBEC481151EA931E7ULL,
		0x2500D8213BC28422ULL,
		0x3F91D0D8AAC40E88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A1044A210303856ULL,
		0x84040880020028D8ULL,
		0x002558040A0A4247ULL,
		0x08311814192010A2ULL,
		0x200A732106709226ULL,
		0xBE84010500A11025ULL,
		0x0100D8010A008020ULL,
		0x2E00C0502A040488ULL
	}};
	printf("Test Case 181\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x40DDBE3821F1F274ULL,
		0xBCD608928B4528CFULL,
		0x96BE03C3F3806149ULL,
		0x7597510E518C5917ULL,
		0x9FF89BD1754CBEE8ULL,
		0x8E4B11D256161C7EULL,
		0xD46DA096B8D58847ULL,
		0xB887C02BBCD32C22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0023CF7AA3AEF5BDULL,
		0x7F0198E42469606FULL,
		0x1987FEE874E484F8ULL,
		0x14C9F59FB23AC2CBULL,
		0x872E4F5FDC2DD66FULL,
		0x577E7D3E72FAD874ULL,
		0x2F98221F09694D15ULL,
		0xA5BE95419B353731ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00018E3821A0F034ULL,
		0x3C0008800041204FULL,
		0x108602C070800048ULL,
		0x1481510E10084003ULL,
		0x87280B51540C9668ULL,
		0x064A111252121874ULL,
		0x0408201608410805ULL,
		0xA086800198112420ULL
	}};
	printf("Test Case 182\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x16DAEC66911CEB38ULL,
		0xA9AED9A03CF0988DULL,
		0x304A3C24D62DB872ULL,
		0x65A37314997D2970ULL,
		0xD38AF254E7698966ULL,
		0x6410D80A31F6252DULL,
		0x67D6E6981DE14501ULL,
		0x8020204972F31610ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD450D0022CB16A25ULL,
		0x33669320BE01EE63ULL,
		0x26B7A5646972E796ULL,
		0xCF2F89CB0EEB63E0ULL,
		0x828A3DA5118A41C4ULL,
		0x222DBE9FEA3281D0ULL,
		0xAD4B0798B670B4EBULL,
		0xBC1E48F4285F5C9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1450C00200106A20ULL,
		0x212691203C008801ULL,
		0x200224244020A012ULL,
		0x4523010008692160ULL,
		0x828A300401080144ULL,
		0x2000980A20320100ULL,
		0x2542069814600401ULL,
		0x8000004020531410ULL
	}};
	printf("Test Case 183\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC996EBFD8B572878ULL,
		0x5F288AB5DA14C0F7ULL,
		0x6CE5F4F4219FB947ULL,
		0x4E0DB5A5AE23B32CULL,
		0x73E7C7C09EB92D2AULL,
		0x828432D3158AEB93ULL,
		0x68CFD53F2808CD4FULL,
		0x5B0A5598DDB21D56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8497E1338D75DD8CULL,
		0xAE562688739C46A9ULL,
		0x3F5B141D818E653AULL,
		0x5E940F83959601D3ULL,
		0x91F61DD3AA6C55A4ULL,
		0x3F51A507E331551DULL,
		0xF3ED3CDBD288843CULL,
		0xABAE48F3BFCCF903ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8096E13189550808ULL,
		0x0E000280521440A1ULL,
		0x2C411414018E2102ULL,
		0x4E04058184020100ULL,
		0x11E605C08A280520ULL,
		0x0200200301004111ULL,
		0x60CD141B0008840CULL,
		0x0B0A40909D801902ULL
	}};
	printf("Test Case 184\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9592A0BBC2145EC3ULL,
		0x8E108CC68D7C0F88ULL,
		0x30B310DC8FA51BF7ULL,
		0xE64D44FF8FF12CFAULL,
		0xE44841A032137A1AULL,
		0xD12F9F2D55F91403ULL,
		0x3665A49E8F6ED837ULL,
		0x61DA426E868A11B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x046FD3BFDBD39533ULL,
		0x107CADE496BE2ED9ULL,
		0x99D969FD8F2AAB99ULL,
		0x2FE7DFB936B269EEULL,
		0x4A4BDDE6C064473AULL,
		0xA8B72B9E384B8738ULL,
		0xA06D75ECB405747FULL,
		0x6A25E71BA4D53C6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040280BBC2101403ULL,
		0x00108CC4843C0E88ULL,
		0x109100DC8F200B91ULL,
		0x264544B906B028EAULL,
		0x404841A00000421AULL,
		0x80270B0C10490400ULL,
		0x2065248C84045037ULL,
		0x6000420A84801022ULL
	}};
	printf("Test Case 185\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB33C1D6C29AE4AE7ULL,
		0xDE84B4673CE001B0ULL,
		0x1F314A1FA2BE34BAULL,
		0x2C2965AB2E380F90ULL,
		0x149F581DE38B7BF9ULL,
		0xA993307CDA29E6CAULL,
		0x7B4DF7BDA36F06CEULL,
		0x406FA1DB2AA045FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6F498F4EB7F7AAAULL,
		0x40FBF5111708EA28ULL,
		0xB44F15B915A4A0A9ULL,
		0x1821CDCCD757635AULL,
		0x63CA8484CCE3683BULL,
		0x926C2EC4912555D2ULL,
		0x73C3DDB3884BB330ULL,
		0x495DF56F29167C00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2341864292E4AA2ULL,
		0x4080B40114000020ULL,
		0x1401001900A420A8ULL,
		0x0821458806100310ULL,
		0x008A0004C0836839ULL,
		0x80002044902144C2ULL,
		0x7341D5B1804B0200ULL,
		0x404DA14B28004400ULL
	}};
	printf("Test Case 186\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE5BF274BA5D267FEULL,
		0xB06BBB3D2E780FABULL,
		0x343CFC3AF61F684CULL,
		0xA95AF733CA8A8B8CULL,
		0x19E67FA0F7900304ULL,
		0xBDDF0B52959601CAULL,
		0xA2070958F7FA120AULL,
		0xF732E1127021DA4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AEDEBA3F4BC7F11ULL,
		0xDFED65E5D16492A9ULL,
		0xA982DA911F095202ULL,
		0x6A6BDBBA79EBDF15ULL,
		0x63651D74F7E491A7ULL,
		0x43BF507619FE1471ULL,
		0x88745F1B2123626FULL,
		0xB60FA55362BC31C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00AD2303A4906710ULL,
		0x90692125006002A9ULL,
		0x2000D81016094000ULL,
		0x284AD332488A8B04ULL,
		0x01641D20F7800104ULL,
		0x019F005211960040ULL,
		0x800409182122020AULL,
		0xB602A11260201049ULL
	}};
	printf("Test Case 187\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8636949FA9EB2CBDULL,
		0x242D5159A6C5740DULL,
		0x84D4D8076AE24866ULL,
		0x01A62AC9F1FEE75CULL,
		0x66F29338AD4B0A93ULL,
		0x92A6F3AF23886D74ULL,
		0x4C0B24884598D580ULL,
		0x0333449FA559A949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3C43CE684C333BULL,
		0x22F063CBCFE92718ULL,
		0x708F6BA0F69509C9ULL,
		0xEC7DB66DB53963E6ULL,
		0x28F69E19C14D172BULL,
		0xF5CC5B9B045F0469ULL,
		0xEBDCFEC35A098273ULL,
		0xEE3F9FC45A9D21D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8634008E28482039ULL,
		0x2020414986C12408ULL,
		0x0084480062800840ULL,
		0x00242249B1386344ULL,
		0x20F2921881490203ULL,
		0x9084538B00080460ULL,
		0x4808248040088000ULL,
		0x0233048400192141ULL
	}};
	printf("Test Case 188\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x952D612D42C096E2ULL,
		0xFCA265790F9CC007ULL,
		0x0B57831C59CE717FULL,
		0xD0BE1D9A477B79B4ULL,
		0xB8727B33C82DE1E2ULL,
		0xC0B644796D8F3F63ULL,
		0x2BB0F5EFB1AA5CBFULL,
		0x24A12FB0218ED52EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F093524EB3059F2ULL,
		0x5873EA531FA3B134ULL,
		0xDCA3175A57DC5AA0ULL,
		0xCF43FCE527BF7CDDULL,
		0xE1084414D823A120ULL,
		0x751EF193CFE745CFULL,
		0xE9ED1D7CBBA2DA1CULL,
		0x4F58F30A356E6E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05092124420010E2ULL,
		0x582260510F808004ULL,
		0x0803031851CC5020ULL,
		0xC0021C80073B7894ULL,
		0xA0004010C821A120ULL,
		0x401640114D870543ULL,
		0x29A0156CB1A2581CULL,
		0x04002300210E440EULL
	}};
	printf("Test Case 189\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0DDB393EABB7078EULL,
		0x8F9BFF376A7EABF7ULL,
		0x2785F410129C82ABULL,
		0xAF247B235CAF9D90ULL,
		0x3B9A14CFF73CBE92ULL,
		0x53B3485222D833ACULL,
		0xAD9B2FCFFCB1B1B7ULL,
		0x47EA0843CFA6FE85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B901A4B9FF769DFULL,
		0x1932F12E5999A98FULL,
		0x4A1F55C3F06A4774ULL,
		0x5781CE65CFCA5ECCULL,
		0xEFC3BED8688844E3ULL,
		0x2C456335C228F29FULL,
		0xE3D8918EB65F439FULL,
		0x6DBDF26EBCF87E4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0990180A8BB7018EULL,
		0x0912F1264818A987ULL,
		0x0205540010080220ULL,
		0x07004A214C8A1C80ULL,
		0x2B8214C860080482ULL,
		0x000140100208328CULL,
		0xA198018EB4110197ULL,
		0x45A800428CA07E04ULL
	}};
	printf("Test Case 190\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3AC051A667DF55B3ULL,
		0xBAE6E0E286FB01C4ULL,
		0xBB4FD781EAE270BBULL,
		0xB9D644C22A9148CCULL,
		0x46D8AAE81D5BB09EULL,
		0xA17BA1B5C92B03FCULL,
		0x79A10C3292070F69ULL,
		0x1E0E4A5A036BA29CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EA1ADB3D35098A7ULL,
		0x0F894E4CE49D35B4ULL,
		0xB07B54EFA893A968ULL,
		0xE5439889685D37A8ULL,
		0x0163801F6D7822FCULL,
		0xC0CF6D87FB2A74C4ULL,
		0xCF9D1D2FB36E4E04ULL,
		0x8FCB9B579AD1A0A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1A8001A2435010A3ULL,
		0x0A80404084990184ULL,
		0xB04B5481A8822028ULL,
		0xA142008028110088ULL,
		0x004080080D58209CULL,
		0x804B2185C92A00C4ULL,
		0x49810C2292060E00ULL,
		0x0E0A0A520241A088ULL
	}};
	printf("Test Case 191\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8B4057897BDCB99CULL,
		0x937DE0DC0DD08DDEULL,
		0xB482F8AFA56A5981ULL,
		0x6F2A5F524F28160BULL,
		0x77131791DC1C6986ULL,
		0xE4D14AA60F03CC13ULL,
		0xC06A6D745362C362ULL,
		0xEC1E0798290A5E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABA1E6EBC0D72FFULL,
		0x0362AB134EFE8846ULL,
		0x95EFB0DC7045354CULL,
		0xF918003CE63DA310ULL,
		0x61F377C33365364DULL,
		0x7D599565F339206EULL,
		0x4522F4EB57D03A08ULL,
		0x292FE9291EB0DEEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A001608380C309CULL,
		0x0360A0100CD08846ULL,
		0x9482B08C20401100ULL,
		0x6908001046280200ULL,
		0x6113178110042004ULL,
		0x6451002403010002ULL,
		0x4022646053400200ULL,
		0x280E010808005E6AULL
	}};
	printf("Test Case 192\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x613EE2DE6FF443F1ULL,
		0x221E1D6B8321147AULL,
		0xD02A06D5CB2DFD3AULL,
		0xE385EFF0DA520119ULL,
		0x4CBF877BEC467B51ULL,
		0xEF796620E11C97DCULL,
		0x07BC06B90AEEEE2BULL,
		0xC02DFF257EBD482CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4797E0858A77CDB9ULL,
		0x96BA08C256E327B1ULL,
		0xB7466637506DABB0ULL,
		0x5C5E316281EE0E6EULL,
		0xD6ADE1180934EE94ULL,
		0xD233B24C75303F67ULL,
		0xBA61680B91A1DB93ULL,
		0xE72815B40EA3B661ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4116E0840A7441B1ULL,
		0x021A084202210430ULL,
		0x90020615402DA930ULL,
		0x4004216080420008ULL,
		0x44AD811808046A10ULL,
		0xC231220061101744ULL,
		0x0220000900A0CA03ULL,
		0xC02815240EA10020ULL
	}};
	printf("Test Case 193\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDA350195BCA43E52ULL,
		0x443243C62FDE2270ULL,
		0x9C18491E6D7A1AA6ULL,
		0xF601FBFF6FCFE785ULL,
		0x0BA1350DD68FA735ULL,
		0xCF5085367D716DF2ULL,
		0x604F22450EE61067ULL,
		0xCE375D20A68F9BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7E67D5653446BC4ULL,
		0xDB424C3D8F5E60CEULL,
		0xAC0ADFB6EFBA4156ULL,
		0x9149F2553C5DA240ULL,
		0xEE21BBB4E3062BDBULL,
		0x078A6111FE3A3DA4ULL,
		0x48172013466997BBULL,
		0xB6C84B1C87442AFDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9224011410042A40ULL,
		0x400240040F5E2040ULL,
		0x8C0849166D3A0006ULL,
		0x9001F2552C4DA200ULL,
		0x0A213104C2062311ULL,
		0x070001107C302DA0ULL,
		0x4007200106601023ULL,
		0x8600490086040ACDULL
	}};
	printf("Test Case 194\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x661ED9BB859C4372ULL,
		0x928128663FF5B755ULL,
		0x560C5898C022DDF8ULL,
		0x15A3BEEA91FA2601ULL,
		0x5BE01CF9A074DF4DULL,
		0xD6D2894AE6B849EBULL,
		0xF97EDCDBAAC932CBULL,
		0x6FE054205F7C2C07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A0A4B4C11BED061ULL,
		0x0E44E4C0C0F264AAULL,
		0x95304D7C32AB0DC0ULL,
		0xAC5C04FB9CC38842ULL,
		0x4C8C4CB3351136CBULL,
		0x4B2D0EBDADD7E397ULL,
		0xCC9CBCBC33EE6867ULL,
		0x5F7B79377D6914BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x620A4908019C4060ULL,
		0x0200204000F02400ULL,
		0x1400481800220DC0ULL,
		0x040004EA90C20000ULL,
		0x48800CB120101649ULL,
		0x42000808A4904183ULL,
		0xC81C9C9822C82043ULL,
		0x4F6050205D680403ULL
	}};
	printf("Test Case 195\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8C4E2D624A5C6E31ULL,
		0xD37B6E005A1547A4ULL,
		0x3944F81B87249780ULL,
		0xCEDEBE1431A3FD19ULL,
		0x23E16D124B8FDD60ULL,
		0xD8920C909B0EB6C2ULL,
		0x3E2C88887603D7CCULL,
		0x045F5BCA7DDB955BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9401679E1C918AEBULL,
		0x0D65B66BDD5A3265ULL,
		0x412FF6DEE9F82A48ULL,
		0x9EFA9112E68AAA6DULL,
		0x9B02144207684B44ULL,
		0xC3F56B7E3B0F38ADULL,
		0x23636B2DFDE424DDULL,
		0x14495AD50093A77BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8400250208100A21ULL,
		0x0161260058100224ULL,
		0x0104F01A81200200ULL,
		0x8EDA90102082A809ULL,
		0x0300040203084940ULL,
		0xC09008101B0E3080ULL,
		0x22200808740004CCULL,
		0x04495AC00093855BULL
	}};
	printf("Test Case 196\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0807CA37C5A23158ULL,
		0x7084F530515EFAA1ULL,
		0x1358FC6F8BFFB5F6ULL,
		0x628F68A9C1E85084ULL,
		0x79C5DC7871E12F51ULL,
		0x4221DFB8EB68423AULL,
		0xB2F9E85FF8EE4623ULL,
		0x175F4519CDC94942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63E764F8F488DCFAULL,
		0x30739C9B1F15BC67ULL,
		0x57A0B91363849D25ULL,
		0xCC673E46E5FADF3BULL,
		0x95AFFA6AC58F39F2ULL,
		0x7FCC3C49F127705FULL,
		0x9027F6C11369C1A4ULL,
		0xB5F90D91142D8E79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00074030C4801058ULL,
		0x300094101114B821ULL,
		0x1300B80303849524ULL,
		0x40072800C1E85000ULL,
		0x1185D86841812950ULL,
		0x42001C08E120401AULL,
		0x9021E04110684020ULL,
		0x1559051104090840ULL
	}};
	printf("Test Case 197\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x72A1F9302CB00960ULL,
		0x65883322C6BD88DCULL,
		0xCF2911B40BFF870EULL,
		0xB627D2603D44335DULL,
		0x994AD8311739E3FCULL,
		0xBF5D2F151D3990A5ULL,
		0xE28C3F474CCA5733ULL,
		0xD66AFD6261A483FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD739593C01CE59F5ULL,
		0x96DD5A89083750E1ULL,
		0x344790D3F4DDE0EDULL,
		0x60D499939705AFA5ULL,
		0xC6BD9696F6B9A241ULL,
		0x76CFB736D07F9E58ULL,
		0xB536FA1128F25A02ULL,
		0x4293EC0DF6B5732DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5221593000800960ULL,
		0x04881200003500C0ULL,
		0x0401109000DD800CULL,
		0x2004900015042305ULL,
		0x800890101639A240ULL,
		0x364D271410399000ULL,
		0xA0043A0108C25202ULL,
		0x4202EC0060A40328ULL
	}};
	printf("Test Case 198\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF4B5C9BE8F8F43D8ULL,
		0xD71FA709A09B4E94ULL,
		0xE30AF0E34F40BC7CULL,
		0x17386D540512E1D9ULL,
		0x24AEC0869989DADCULL,
		0x4EBA80E01B0C4BEEULL,
		0x25A6B0639E7723ABULL,
		0xEE2568B88B25D181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x780922BF7854FDF7ULL,
		0x6C863BB392EEE9E7ULL,
		0xB8177B9C0FFA1380ULL,
		0x479D91484E4F696DULL,
		0x238DB63DF03BDF69ULL,
		0xD75C1183B07697B4ULL,
		0x17F9B2E24BE34BE1ULL,
		0x6FB7BF35628011EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x700100BE080441D0ULL,
		0x44062301808A4884ULL,
		0xA00270800F401000ULL,
		0x0718014004026149ULL,
		0x208C80049009DA48ULL,
		0x46180080100403A4ULL,
		0x05A0B0620A6303A1ULL,
		0x6E25283002001181ULL
	}};
	printf("Test Case 199\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA6B3C3D98581C608ULL,
		0xABA0C9F221299EC5ULL,
		0xEF19F06828A70487ULL,
		0x5BC787478ED09012ULL,
		0xCF7F0E55D70574E3ULL,
		0x31C1B3FA0AEC8FFDULL,
		0x64DBF488A29ED36EULL,
		0x7099B37BD3BD3F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDAD3D7EA4027B5CULL,
		0x336536D4BAA2B8B7ULL,
		0xD630F7B718D0B56AULL,
		0xB47113630335251DULL,
		0xC1A61A799C7D7494ULL,
		0xE06249B461D03C84ULL,
		0xB7AF082709352C17ULL,
		0x6FC307F73457A7E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84A1015884004208ULL,
		0x232000D020209885ULL,
		0xC610F02008800402ULL,
		0x1041034302100010ULL,
		0xC1260A5194057480ULL,
		0x204001B000C00C84ULL,
		0x248B000000140006ULL,
		0x6081037310152760ULL
	}};
	printf("Test Case 200\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE80DEFB0C85289DAULL,
		0xCFA5AEBDE9AFDCCCULL,
		0xDF742DFF4CBC232FULL,
		0x4F1F7FE2D7337AE7ULL,
		0x5B1D959E8902D8E5ULL,
		0x7E2F29BDD9EF5B1FULL,
		0x340F41F19B96D4B9ULL,
		0x502CFAD19C30E639ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06A1EF9A5CD30ABULL,
		0xB021E0C0C52AD0BDULL,
		0x6718F42CB8307495ULL,
		0x41CFA29FBA43CA88ULL,
		0x9427052AC71267EEULL,
		0xD09F3DCD7C7B9570ULL,
		0x2C0118681A81D853ULL,
		0x93DE4CB4F8AC7C14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0080EB08040008AULL,
		0x8021A080C12AD08CULL,
		0x4710242C08302005ULL,
		0x410F228292034A80ULL,
		0x1005050A810240E4ULL,
		0x500F298D586B1110ULL,
		0x240100601A80D011ULL,
		0x100C489098206410ULL
	}};
	printf("Test Case 201\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC8E025A7CF6F6FBDULL,
		0x95EC5BCE6F69F7E6ULL,
		0x714BE2985BD8FF87ULL,
		0x1F054383B96B06C3ULL,
		0x73474C4B1D34581CULL,
		0x3014F87B6EAE8C19ULL,
		0x2F885B10009D97D3ULL,
		0x9D20254EB571137CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5997FF6C39023965ULL,
		0xBB39B5359FE74104ULL,
		0x43807F688075B501ULL,
		0x080AF636D69DAF81ULL,
		0x72BEF37540AFE389ULL,
		0x36E5AB4A2B2D0420ULL,
		0xAC8A9ADFE053B43BULL,
		0xE229599BB9B2D733ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4880252409022925ULL,
		0x912811040F614104ULL,
		0x410062080050B501ULL,
		0x0800420290090681ULL,
		0x7206404100244008ULL,
		0x3004A84A2A2C0400ULL,
		0x2C881A1000119413ULL,
		0x8020010AB1301330ULL
	}};
	printf("Test Case 202\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8C3990DE7656704CULL,
		0xF6B09A26ED464604ULL,
		0xE22B184FB008311EULL,
		0x95970D3646D94321ULL,
		0x1E8A2B3459D28F7DULL,
		0xD55F1EE610ED5792ULL,
		0xA107C70F8929340CULL,
		0xF0037A5AE5696CD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A5ED7DBF69A015ULL,
		0xE7FE24A087BC484DULL,
		0x5BD0F6959368C0E2ULL,
		0xF19F8813E3025761ULL,
		0x114E29EDE1ED8A7BULL,
		0xD6DAB88754F4B628ULL,
		0x678FE3594CD68731ULL,
		0x6F48EB5ED3AC1A45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0021805C36402004ULL,
		0xE6B0002085044004ULL,
		0x4200100590080002ULL,
		0x9197081242004321ULL,
		0x100A292441C08A79ULL,
		0xD45A188610E41600ULL,
		0x2107C30908000400ULL,
		0x60006A5AC1280845ULL
	}};
	printf("Test Case 203\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDA91781572DD9AC9ULL,
		0x437693488E62CAD8ULL,
		0x38FF0A5B3B401BC3ULL,
		0x8D11335BA112118FULL,
		0x69D14D6B8CC77B96ULL,
		0xF967A5F6FE698E39ULL,
		0xA98A05FA6FAC84BBULL,
		0xB320A73A0B62F8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF104A5F47FDC231ULL,
		0x4482BC3E8BA2B04EULL,
		0xEDA646C82408C77BULL,
		0x89FFEC3DA44E5E22ULL,
		0x701307BF827549F6ULL,
		0x8F2CFAE53A845A84ULL,
		0x7CE74E254C79AC15ULL,
		0x64D689218DB729DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA10481542DD8201ULL,
		0x400290088A228048ULL,
		0x28A6024820000343ULL,
		0x89112019A0021002ULL,
		0x6011052B80454996ULL,
		0x8924A0E43A000A00ULL,
		0x288204204C288411ULL,
		0x20008120092228C0ULL
	}};
	printf("Test Case 204\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4F2215C8C59123FEULL,
		0x26DB7B139A890E70ULL,
		0x4934899FC8373090ULL,
		0xC28DE603075C04FEULL,
		0xD583857985BBB9AAULL,
		0x4CFBD17A53902714ULL,
		0xC981AFEDB50B201AULL,
		0xE42BA904A201B20BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x057968C0007257E9ULL,
		0x5206664D7EEE3269ULL,
		0x9A6673FA094849C0ULL,
		0x4E43DE4EF76C28BCULL,
		0x62216ACCF14196C6ULL,
		0x050EF9AF4E04CE62ULL,
		0x40EE1C1C9A682C94ULL,
		0xD6C0F8F4F3683EBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x052000C0001003E8ULL,
		0x020262011A880260ULL,
		0x0824019A08000080ULL,
		0x4201C602074C00BCULL,
		0x4001004881019082ULL,
		0x040AD12A42000600ULL,
		0x40800C0C90082010ULL,
		0xC400A804A200320BULL
	}};
	printf("Test Case 205\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9D7366A95474EAA5ULL,
		0x8AD2B5268B0F453DULL,
		0x635E01AB9FFFB2F0ULL,
		0x306CBBBF36040BADULL,
		0x25FC15EFCB00A95AULL,
		0xD5DB9C90B9CEA34FULL,
		0x26919BA235AF54A7ULL,
		0x26E3DF027EB7E636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E04DF932F6DE18AULL,
		0xEBAB232D40E1E15AULL,
		0xA7D724F761ADE445ULL,
		0x25003E4E6D17F96CULL,
		0xDA6D57F241522D61ULL,
		0x52EE486F80E31BC5ULL,
		0x6ED0A73600227A7AULL,
		0xE3E04D7EA00A57B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0046810464E080ULL,
		0x8A82212400014118ULL,
		0x235600A301ADA040ULL,
		0x20003A0E2404092CULL,
		0x006C15E241002940ULL,
		0x50CA080080C20345ULL,
		0x2690832200225022ULL,
		0x22E04D0220024630ULL
	}};
	printf("Test Case 206\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8F2E45FE33B1097CULL,
		0x58BAFEEFBC83F23EULL,
		0x343502F530E68274ULL,
		0x84326C0D04B29FEFULL,
		0x28716474861DF4F6ULL,
		0xD85FEBE63EA43A13ULL,
		0xE5662C65A5166BCCULL,
		0xC6158DA632504376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD672E5DCE2CC03CULL,
		0x48965C96864EE32EULL,
		0x9E20618FA1B91662ULL,
		0x5642B327A9042D1CULL,
		0x0003A7D29E4554A1ULL,
		0x4C67CE288ED337C8ULL,
		0xE601F8BF64C41D2DULL,
		0x441163CAC1A00264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D26045C0220003CULL,
		0x48925C868402E22EULL,
		0x1420008520A00260ULL,
		0x0402200500000D0CULL,
		0x00012450860554A0ULL,
		0x4847CA200E803200ULL,
		0xE40028252404090CULL,
		0x4411018200000264ULL
	}};
	printf("Test Case 207\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1DD31F707326E62CULL,
		0x3319343EE16BB96FULL,
		0x73197535F9B210DEULL,
		0x648133D507FD0692ULL,
		0xD146710CA039A477ULL,
		0xB802029DA1D14F25ULL,
		0x51ACBFB557512CDEULL,
		0x1E05773D355F0CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8693F9627C0FEB1ULL,
		0x992C985CF3F3CB4EULL,
		0xE24D75D127DE7EF9ULL,
		0xB236C7A01846460AULL,
		0x870C57DB9EE08905ULL,
		0x99725D5CB009B1C4ULL,
		0xD117A1CDBA9511C7ULL,
		0x1244A67DA36C4334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08411F102300E620ULL,
		0x1108101CE163894EULL,
		0x62097511219210D8ULL,
		0x2000038000440602ULL,
		0x8104510880208005ULL,
		0x9802001CA0010104ULL,
		0x5104A185121100C6ULL,
		0x1204263D214C0004ULL
	}};
	printf("Test Case 208\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5C7F6E07216B6488ULL,
		0xF251E7D0C39B420BULL,
		0xC16A2A7F627D83B9ULL,
		0x12696E7F6D753A7BULL,
		0x6BDA51BDA80F2A2BULL,
		0xBCF7E25FA10D2F6BULL,
		0x199CC51F38E0ACE1ULL,
		0xF39C456206B5B0BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C79F8C3F9EFE3ADULL,
		0xB26D59B8EBE4179EULL,
		0x9CE95D13D2DCAA4FULL,
		0x6D496FE99A5478D2ULL,
		0x3DBFCC445CD75DE9ULL,
		0x562EF0ED233C7F24ULL,
		0xCDDAD76275DB78B8ULL,
		0x2D7228E231B6EA02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C796803216B6088ULL,
		0xB2414190C380020AULL,
		0x80680813425C8209ULL,
		0x00496E6908543852ULL,
		0x299A400408070829ULL,
		0x1426E04D210C2F20ULL,
		0x0998C50230C028A0ULL,
		0x2110006200B4A000ULL
	}};
	printf("Test Case 209\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x99EB8DD807BE60CCULL,
		0x2CB002C29A4864B2ULL,
		0xE47C3F55D2A775DBULL,
		0xF7E1CA8D40F4CE7CULL,
		0x8D77E0C998F55925ULL,
		0x89670C5409A69728ULL,
		0xD81AC45E99480278ULL,
		0xF0559D71DDA38819ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B471EA81D308209ULL,
		0x354D5214D801F6FEULL,
		0x4DE4C3EF38F44B80ULL,
		0xB85561C9E3E21D3CULL,
		0x41F55FCE4AD3FAFAULL,
		0x9F54782149E83A3BULL,
		0x393FB8B060D2A827ULL,
		0xCA9F1913CEFC196BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09430C8805300008ULL,
		0x24000200980064B2ULL,
		0x4464034510A44180ULL,
		0xB041408940E00C3CULL,
		0x017540C808D15820ULL,
		0x8944080009A01228ULL,
		0x181A801000400020ULL,
		0xC0151911CCA00809ULL
	}};
	printf("Test Case 210\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCF134AAAA2A123DFULL,
		0x4F35051588E71DE2ULL,
		0x912B16155712FB4DULL,
		0xD819820D6CCCC943ULL,
		0xF4CBF53724B7FCAAULL,
		0xFF129685E34E3E5FULL,
		0x20345FE0592DE630ULL,
		0x2232BCA9350143FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754F5DF38D26423DULL,
		0x78233422FDF6764EULL,
		0xD616F58336805F3CULL,
		0x74A32918482C6C10ULL,
		0xF2862DF019B0CBA7ULL,
		0x5C007936C7F322F7ULL,
		0x811AA776BEF54331ULL,
		0x7F587323D85321FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x450348A28020021DULL,
		0x4821040088E61442ULL,
		0x9002140116005B0CULL,
		0x50010008480C4800ULL,
		0xF082253000B0C8A2ULL,
		0x5C001004C3422257ULL,
		0x0010076018254230ULL,
		0x22103021100101FCULL
	}};
	printf("Test Case 211\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC3462BDB820847FEULL,
		0xB4330B3141A58558ULL,
		0x404F2507588B4678ULL,
		0x232567576486BD70ULL,
		0x29F2A905813A4183ULL,
		0xB4FB0A4D15C0EF40ULL,
		0x9D24FCD39DC2AD78ULL,
		0x81E20026E99C5112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x437AE9C5891F138BULL,
		0xB565145D710A2AF3ULL,
		0x86F983A33E816A91ULL,
		0x486CBCE0EC771350ULL,
		0xC03BE32D739496ACULL,
		0x9627081E3F07C429ULL,
		0x542223EA88BA0641ULL,
		0xF5E089E4AEFCA80DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x434229C18008038AULL,
		0xB421001141000050ULL,
		0x0049010318814210ULL,
		0x0024244064061150ULL,
		0x0032A10501100080ULL,
		0x9423080C1500C400ULL,
		0x142020C288820440ULL,
		0x81E00024A89C0000ULL
	}};
	printf("Test Case 212\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC3818BC1569DB930ULL,
		0xD7005D6D4781465BULL,
		0xADF0AB81C2ACF864ULL,
		0xA6EC0BD17360A530ULL,
		0xFD53D5E44954EDB0ULL,
		0xDB19DB283F729E51ULL,
		0x091F05DF90274A59ULL,
		0xBB3ED6379A9F51B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83B38C742387456BULL,
		0xB664BB3435851777ULL,
		0x33F91E27668123F7ULL,
		0x63A0DD44F3592EA7ULL,
		0x8EC6514F1226CB39ULL,
		0xAED46AEF02F85441ULL,
		0x5105EF8AFC8DD6E1ULL,
		0x3F18FA3784D916BDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8381884002850120ULL,
		0x9600192405810653ULL,
		0x21F00A0142802064ULL,
		0x22A0094073402420ULL,
		0x8C4251440004C930ULL,
		0x8A104A2802701441ULL,
		0x0105058A90054241ULL,
		0x3B18D237809910B5ULL
	}};
	printf("Test Case 213\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x87211BBF5B4D5E8FULL,
		0x4CCA07FE5EF2460CULL,
		0x684DB12FEF39DFE8ULL,
		0x65A9DA2A1477271FULL,
		0x7E6F88CD4208D264ULL,
		0xF1190267C50350F8ULL,
		0x0A057BAD45B7E38EULL,
		0x844AA2985A5AD1B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E27697640DC6815ULL,
		0x8FBBDAA1122E0F4BULL,
		0x956EDB19D7276A80ULL,
		0xEE28FF67FD95CC97ULL,
		0x74C6C647DC55811BULL,
		0xEDA82D6F816B305BULL,
		0xB8CC86EA233DFF5FULL,
		0xF8E251A3BF26745DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06210936404C4805ULL,
		0x0C8A02A012220608ULL,
		0x004C9109C7214A80ULL,
		0x6428DA2214150417ULL,
		0x7446804540008000ULL,
		0xE108006781031058ULL,
		0x080402A80135E30EULL,
		0x804200801A025010ULL
	}};
	printf("Test Case 214\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7534208A487A5D0FULL,
		0x43BB323E201F7D21ULL,
		0x9AE42CB5F4C2C865ULL,
		0xA3CE0F0FFA93BDE3ULL,
		0x754B1387F3711EE7ULL,
		0xE163A36F77CF71F4ULL,
		0xF64F8772FCD1AC2DULL,
		0x168BFE32070D826AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C200F3F78A780DULL,
		0xDCF57E5157C028EAULL,
		0xE7119FC7EC2C886BULL,
		0x1E5C02D15E89A7A4ULL,
		0xEEEEC6A984D5A602ULL,
		0x83C5AF23C5C8EA05ULL,
		0x64C0BDE941F5906DULL,
		0x3209718E84E2E216ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51000082400A580DULL,
		0x40B1321000002820ULL,
		0x82000C85E4008861ULL,
		0x024C02015A81A5A0ULL,
		0x644A028180510602ULL,
		0x8141A32345C86004ULL,
		0x6440856040D1802DULL,
		0x1209700204008202ULL
	}};
	printf("Test Case 215\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBF1D2A71E6E5FDB7ULL,
		0x7B4DA2D35105F5FDULL,
		0x0D17698FF575B24FULL,
		0x8B316C6CF2B595BFULL,
		0x3233AF1D6C8CED8EULL,
		0xCC5982A585E9A69EULL,
		0xF8264A0774496FAAULL,
		0xDEB5996CCBA801ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x024A2E30F7FFC255ULL,
		0x08A87438F1F05531ULL,
		0x1C7D278799CBBDB3ULL,
		0x933C4BE39FFAEA58ULL,
		0x8255AFEBA02B9367ULL,
		0xEB3E481FC7F83B94ULL,
		0x48C6D4C28644CDC3ULL,
		0x940C916887605559ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02082A30E6E5C015ULL,
		0x0808201051005531ULL,
		0x0C1521879141B003ULL,
		0x8330486092B08018ULL,
		0x0211AF0920088106ULL,
		0xC818000585E82294ULL,
		0x4806400204404D82ULL,
		0x9404916883200109ULL
	}};
	printf("Test Case 216\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x826673A788348D10ULL,
		0x35F28AF4C91D0D33ULL,
		0x6A1C1AC55CEA236CULL,
		0xDE5123A74BCB3D3AULL,
		0x1427AD8A9A01AF0AULL,
		0x84AB3444227382B4ULL,
		0x9341FDE1F57BF2E7ULL,
		0x06113588A86558EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E8B08AA70D9ADEBULL,
		0x0DD4CDC13F0C7ECEULL,
		0x99A0F9906B9E9A21ULL,
		0x691CA063355320EEULL,
		0x1636B37CFC347D23ULL,
		0x2E36E1832C8BF41FULL,
		0xF3E3C8F97315FCCDULL,
		0xAA49028B5470C7DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020200A200108D00ULL,
		0x05D088C0090C0C02ULL,
		0x08001880488A0220ULL,
		0x481020230143202AULL,
		0x1426A10898002D02ULL,
		0x0422200020038014ULL,
		0x9341C8E17111F0C5ULL,
		0x02010088006040C8ULL
	}};
	printf("Test Case 217\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3CD960DD15CD3975ULL,
		0x9D1E63142CAED280ULL,
		0x37D93B564175021BULL,
		0x2892A7D3980E1988ULL,
		0xA89FC9FD26D6517FULL,
		0xC98C37326DFD7B76ULL,
		0xD836B7C152EDE210ULL,
		0xFEB18643A85EA00BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95372160D3329DA8ULL,
		0xFE02B56B2FFB9275ULL,
		0xB4E21105116808AAULL,
		0x32038DC3BBD11413ULL,
		0xF0A90DE71F453F08ULL,
		0xF9D1A96DFE171392ULL,
		0x3059B6B9B528F557ULL,
		0xF597589866896705ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1411204011001920ULL,
		0x9C0221002CAA9200ULL,
		0x34C011040160000AULL,
		0x200285C398001000ULL,
		0xA08909E506441108ULL,
		0xC98021206C151312ULL,
		0x1010B6811028E010ULL,
		0xF491000020082001ULL
	}};
	printf("Test Case 218\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFC9B1B605BAED78CULL,
		0xA6A78E236C709669ULL,
		0x09F2C2FBFFF9CA78ULL,
		0xAAE827DAC7B4DE47ULL,
		0xD53F848AC6DEEE4CULL,
		0x7ADA62FE2711B439ULL,
		0x089B9DF063BCF051ULL,
		0x2C322AB0EF2B2F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC419AE25FDA0416ULL,
		0x0EB79CB62B461F82ULL,
		0x1A3B006C14BD7063ULL,
		0xE65BB4B63B5B9289ULL,
		0x576A2AB4F223B599ULL,
		0xFDD64DD10441C5E7ULL,
		0x5C20C8A0B20EB1B6ULL,
		0xC7262988CA5CBDEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC011A605B8A0404ULL,
		0x06A78C2228401600ULL,
		0x0832006814B94060ULL,
		0xA248249203109201ULL,
		0x552A0080C202A408ULL,
		0x78D240D004018421ULL,
		0x080088A0220CB010ULL,
		0x04222880CA082D8CULL
	}};
	printf("Test Case 219\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x08C73A0536EB9912ULL,
		0x150F70B249DECFE4ULL,
		0xCBB056F6836A036FULL,
		0x467DE51C65F00667ULL,
		0xC3BCA77FBD326BF0ULL,
		0x3017A504EB744961ULL,
		0x25DE50C02AAAD6B5ULL,
		0x68428D6E41BC870BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63919567D84D9792ULL,
		0x0CD156BE8A5C948CULL,
		0xA8DEFF743C43A619ULL,
		0x9504BE4D89682BA5ULL,
		0x7B35E30E48D46049ULL,
		0x8B5881485572466BULL,
		0x46529DF89E2FCF8CULL,
		0x3BCACA9503840256ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0081100510499112ULL,
		0x040150B2085C8484ULL,
		0x8890567400420209ULL,
		0x0404A40C01600225ULL,
		0x4334A30E08106040ULL,
		0x0010810041704061ULL,
		0x045210C00A2AC684ULL,
		0x2842880401840202ULL
	}};
	printf("Test Case 220\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC4992B96714F3360ULL,
		0xB9F49A64EF0A1857ULL,
		0x36F87F4B94EF1139ULL,
		0x1D68C0E96AB4EE17ULL,
		0x32A1F21D5719D362ULL,
		0xBA81CAB6B41C1232ULL,
		0x958F9D4D056F47B9ULL,
		0x6CD35E6444ABFEA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3D104CCB187CE0BULL,
		0x3081A9B3D68B8432ULL,
		0xC635AA41CCD74766ULL,
		0x61BB1CCFD9697DB4ULL,
		0xC5893080F8214C87ULL,
		0x1F99D25BE4579A47ULL,
		0x02D187A551F10EBAULL,
		0x6DB24B6763790E58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC091008431070200ULL,
		0x30808820C60A0012ULL,
		0x06302A4184C70120ULL,
		0x012800C948206C14ULL,
		0x0081300050014002ULL,
		0x1A81C212A4141202ULL,
		0x00818505016106B8ULL,
		0x6C924A6440290E00ULL
	}};
	printf("Test Case 221\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5EF7375E69A52674ULL,
		0xC2FA2568E7AF1204ULL,
		0xB3A5481538D66436ULL,
		0xC1C2813DDB03630AULL,
		0x48F8DB85467D18FEULL,
		0xEB3C226A476F2CD7ULL,
		0x1FF16294528B1FC9ULL,
		0x704CEDA6D6ECAF0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BBE17E53CD8CD76ULL,
		0x331ED7EFEA1C271BULL,
		0xDC4673C9B07EB93EULL,
		0x8CE069D550E8FDBFULL,
		0xDE58B34DF1ABA9A2ULL,
		0x88003F94DE55EB4BULL,
		0x78DAFB8EB509A33EULL,
		0xB00A3A35E010007BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AB6174428800474ULL,
		0x021A0568E20C0200ULL,
		0x9004400130562036ULL,
		0x80C001155000610AULL,
		0x48589305402908A2ULL,
		0x8800220046452843ULL,
		0x18D0628410090308ULL,
		0x30082824C0000009ULL
	}};
	printf("Test Case 222\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6F5E84A8CF1D04D4ULL,
		0x1EFA68E5C4B6E207ULL,
		0x75A1560D10D549F3ULL,
		0x26348AD682275BB3ULL,
		0x27FA942650D0D0E8ULL,
		0x27D16112E97D8B6EULL,
		0x3144B5624C3A6142ULL,
		0x69DD6339E2F4D048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA92B3DAB2ECF01ECULL,
		0xDE03A663A21C5785ULL,
		0xED04CB607D237F91ULL,
		0xCB5B0C8475EA13EEULL,
		0xB011A4FA49D0FCA3ULL,
		0x434C655FCA4CD9A8ULL,
		0x4CF66949AE2ED739ULL,
		0x99F352494BF05955ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x290A04A80E0D00C4ULL,
		0x1E02206180144205ULL,
		0x6500420010014991ULL,
		0x02100884002213A2ULL,
		0x2010842240D0D0A0ULL,
		0x03406112C84C8928ULL,
		0x004421400C2A4100ULL,
		0x09D1420942F05040ULL
	}};
	printf("Test Case 223\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xECFFFA2439A765DEULL,
		0x001EF466A63D5BA2ULL,
		0xB6B645012698F941ULL,
		0x00052D6B3BFF7ED6ULL,
		0x7D1FE6945E6C038DULL,
		0xFED8DC305023F065ULL,
		0x34572FE6B05EBC53ULL,
		0x7850A92959F29B51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3057DE0F3058D627ULL,
		0x026F354835525C03ULL,
		0x0CBA18F7064F27F2ULL,
		0x70D06190D505EDECULL,
		0x54308807C042C6EDULL,
		0x70A059E3FB47A19EULL,
		0x1556E2A4BE62C3A6ULL,
		0x37064E3A19CA25FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2057DA0430004406ULL,
		0x000E344024105802ULL,
		0x04B2000106082140ULL,
		0x0000210011056CC4ULL,
		0x541080044040028DULL,
		0x708058205003A004ULL,
		0x145622A4B0428002ULL,
		0x3000082819C20151ULL
	}};
	printf("Test Case 224\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x756E78BAB7A7DDEEULL,
		0x9A908EA2BF74DAEBULL,
		0xAC4181C89C2A1A90ULL,
		0x0C1D34C37E6F1DEEULL,
		0x29C1D68314D09BB6ULL,
		0x79A142252996E2E4ULL,
		0x48584A6DA6A430E9ULL,
		0x3D463F6F4BDF2004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71AB8D4014ADAC14ULL,
		0xEC3C392C5F048167ULL,
		0xF6F0AE21591F43D4ULL,
		0x80B60590C92D8A72ULL,
		0x5499245F9ABDE593ULL,
		0x2839EF3187AAD893ULL,
		0x120D45D0A588D02CULL,
		0xDC27FB35396C5E9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x712A080014A58C04ULL,
		0x881008201F048063ULL,
		0xA4408000180A0290ULL,
		0x00140480482D0862ULL,
		0x0081040310908192ULL,
		0x282142210182C080ULL,
		0x00084040A4801028ULL,
		0x1C063B25094C0004ULL
	}};
	printf("Test Case 225\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD81E3DD89DB22203ULL,
		0x8A94C11C87364C5AULL,
		0x7AC49FD95BBAF4A9ULL,
		0xDE5864839B66DB54ULL,
		0xA562064C84C42942ULL,
		0xAF8600EA23A7CBAAULL,
		0xE17523F4179A1FABULL,
		0xB2CFF78CB1430B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB0244D0EA1E6E42ULL,
		0x608DA8EC796A8E8FULL,
		0xCC4AACA94F6549D7ULL,
		0x940013FD3D2CD690ULL,
		0xE4E20673C8199BD0ULL,
		0x2410A111B2EA1322ULL,
		0xD89478EA2DCBA6CBULL,
		0xBC4D863DD6AEB1DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x980204D088122202ULL,
		0x0084800C01220C0AULL,
		0x48408C894B204081ULL,
		0x940000811924D210ULL,
		0xA462064080000940ULL,
		0x2400000022A20322ULL,
		0xC01420E0058A068BULL,
		0xB04D860C9002015AULL
	}};
	printf("Test Case 226\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE5710F72C810222EULL,
		0x94A3FACF190CE0D2ULL,
		0xCDD64D412901E5FEULL,
		0xDDC33414C87CCC3CULL,
		0x87837C8C07FA17C4ULL,
		0x67CA8F09F87F9D0DULL,
		0x04A56A933B4EC155ULL,
		0x2D3D662B2BE9FE55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B43A5378B4CA98ULL,
		0xF96AA402E1F80F7CULL,
		0x75B3518143F4A00EULL,
		0xA6617AED11210CB1ULL,
		0x7B8CD0F42AF88813ULL,
		0xDD3E9936E9356706ULL,
		0xEF298CB0E6B4E401ULL,
		0xAFE7C81E70E8FFB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01300A5248100208ULL,
		0x9022A00201080050ULL,
		0x459241010100A00EULL,
		0x8441300400200C30ULL,
		0x0380508402F80000ULL,
		0x450A8900E8350504ULL,
		0x042108902204C001ULL,
		0x2D25400A20E8FE11ULL
	}};
	printf("Test Case 227\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x84B1B4C2FACA8051ULL,
		0xB4EEAD46792BA0E6ULL,
		0x65E53E219FEDCB6AULL,
		0x13986AFA5B4CBE1CULL,
		0x4BE359216F625621ULL,
		0xD486E1FDFE4385A3ULL,
		0x90D17736D225B5B1ULL,
		0xBEAB3EE8B5BAA10EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2DF6708142645ABULL,
		0xF2D25ACD3EC8F640ULL,
		0xA1EF95B16A60D7BBULL,
		0x5C50EB532C8E0282ULL,
		0x69E79A03678D0203ULL,
		0x59CAF498153ABFDEULL,
		0x0A293D50B37B1080ULL,
		0x29565EB1B0FB5148ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8091240010020001ULL,
		0xB0C208443808A040ULL,
		0x21E514210A60C32AULL,
		0x10106A52080C0200ULL,
		0x49E3180167000201ULL,
		0x5082E09814028582ULL,
		0x0001351092211080ULL,
		0x28021EA0B0BA0108ULL
	}};
	printf("Test Case 228\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5E47BB2D94F20283ULL,
		0xB34AB6FA5FC495ABULL,
		0xDE51D7D1E41659FBULL,
		0xB38D03C793BD52EDULL,
		0xECE50DC6A70D1123ULL,
		0x8F79E9D8DF2CADB5ULL,
		0x37CAAF40183F6DF7ULL,
		0x920BA2F1D07850E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5475FBE04410C60ULL,
		0x285F346EDC6FBBD9ULL,
		0xBADBB903395FD5B1ULL,
		0x151A6BEBAEC37662ULL,
		0x811C266BED70FB4EULL,
		0x9ED07DA0AF5F0235ULL,
		0xD73A4AE865E1F08FULL,
		0x293F6298F9947F0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44471B2C04400000ULL,
		0x204A346A5C449189ULL,
		0x9A519101201651B1ULL,
		0x110803C382815260ULL,
		0x80040442A5001102ULL,
		0x8E5069808F0C0035ULL,
		0x170A0A4000216087ULL,
		0x000B2290D0105000ULL
	}};
	printf("Test Case 229\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBFC21F397A709411ULL,
		0x1DCD8AB778700301ULL,
		0xD5FE85B79CE1F58CULL,
		0xF14F943287604924ULL,
		0x0B5E88C4E12D9837ULL,
		0xFC4D87062D260FA1ULL,
		0x70AB5838AFA8708DULL,
		0x7435973ABC21BF34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC361130018898F6FULL,
		0x334BA4C0ECEC2850ULL,
		0x63D1C78758FC7878ULL,
		0x80A9FBF081E89E15ULL,
		0x42F43C6F2E5DEBBDULL,
		0x8BB5DD8E95683FE8ULL,
		0x6A6C8EF78C3AD946ULL,
		0x9D20B640A07BFB89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8340130018008401ULL,
		0x1149808068600000ULL,
		0x41D0858718E07008ULL,
		0x8009903081600804ULL,
		0x02540844200D8835ULL,
		0x8805850605200FA0ULL,
		0x602808308C285004ULL,
		0x14209600A021BB00ULL
	}};
	printf("Test Case 230\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6F5ACD6FA7F9DBDAULL,
		0x995D94E7D5BF0986ULL,
		0x59657FB9520DB41BULL,
		0x788D0DA830CB6E4BULL,
		0x6FDE829B1CFEC632ULL,
		0x62A24EB189C5E0C9ULL,
		0x11BA13F71F3EF184ULL,
		0x024FFE69564BDD2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6083E69C623E7779ULL,
		0x83C1466C554BC978ULL,
		0xBA3ACCF81162DC81ULL,
		0x256B4E9DBC9AC8BAULL,
		0x96D38401A9F71C58ULL,
		0x5E01A4791C7195C1ULL,
		0x3D8ED8D67FEC8BBDULL,
		0x30CBDCA39D0BB26FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6002C40C22385358ULL,
		0x81410464550B0900ULL,
		0x18204CB810009401ULL,
		0x20090C88308A480AULL,
		0x06D2800108F60410ULL,
		0x42000431084180C1ULL,
		0x118A10D61F2C8184ULL,
		0x004BDC21140B902EULL
	}};
	printf("Test Case 231\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x39EB3AEBA49A03D3ULL,
		0x2E74F00B93B7BA94ULL,
		0x26438C896B278B66ULL,
		0x68DA52C83DE0ECC3ULL,
		0x0E6E9C1A842BDFCAULL,
		0x6FCB7BCE8376115BULL,
		0x99BCE3B7ADB70126ULL,
		0xEF3A244C4E443092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B63D73684A2CC83ULL,
		0x843728DCA66AF1FBULL,
		0x7C39781510C91D6FULL,
		0x4DA66048D19DEAB8ULL,
		0xCB825616AB40B55CULL,
		0x3EA7BAF40D79A994ULL,
		0x71791AAFDE353471ULL,
		0x15A93A613420A84BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0963122284820083ULL,
		0x043420088222B090ULL,
		0x2401080100010966ULL,
		0x488240481180E880ULL,
		0x0A02141280009548ULL,
		0x2E833AC401700110ULL,
		0x113802A78C350020ULL,
		0x0528204004002002ULL
	}};
	printf("Test Case 232\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1D7E0A598D42904FULL,
		0xAFAD866FB98B7501ULL,
		0x2686D14EB4516EAEULL,
		0xF62FD414E2D20592ULL,
		0xFDF02007EB4ABF45ULL,
		0x9CC0AB22DDF1C50DULL,
		0x7634D08214255271ULL,
		0x332BA7A9D41638B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE89E59F4E5BA823CULL,
		0x01FBAF285913F61DULL,
		0x140ED11E7403EF8EULL,
		0xD8BFE19B68691B75ULL,
		0x0C96D36B760FC95AULL,
		0x2F1A43A163969948ULL,
		0x41A9D0A8626C070FULL,
		0x47F788D5C5E5B829ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081E08508502800CULL,
		0x01A9862819037401ULL,
		0x0406D10E34016E8EULL,
		0xD02FC01060400110ULL,
		0x0C900003620A8940ULL,
		0x0C00032041908108ULL,
		0x4020D08000240201ULL,
		0x03238081C4043820ULL
	}};
	printf("Test Case 233\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE50BC8D76CEF2A02ULL,
		0x5801D9CE4F733795ULL,
		0xBE1D9926AB347342ULL,
		0xA3D5C8852EA6AF78ULL,
		0x5C514177DD4A795DULL,
		0x87F77D461591F90BULL,
		0x074BEA0ADAEB2BFAULL,
		0x846A781D2145EDA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC03737B1F2C3CD60ULL,
		0xE670E2C3E6C324F5ULL,
		0x8AD7709D5FC52949ULL,
		0xE31835E88E30D72AULL,
		0xDA927CD782B9FE69ULL,
		0x61AC370A1FB0218BULL,
		0x1ABBD27142291BADULL,
		0xB4888BB9FDF508CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC003009160C30800ULL,
		0x4000C0C246432495ULL,
		0x8A1510040B042140ULL,
		0xA31000800E208728ULL,
		0x5810405780087849ULL,
		0x01A435021590210BULL,
		0x020BC20042290BA8ULL,
		0x8408081921450884ULL
	}};
	printf("Test Case 234\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x674EA057541888BDULL,
		0xAFFC94AC2E8E15F2ULL,
		0x1E0660AE01D6B313ULL,
		0xACFA69F4FA1E3890ULL,
		0x2A58676BF86C234AULL,
		0xE22B643286BB2992ULL,
		0x25544E380418D9BAULL,
		0xDBB98118CB0ECCD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BAAE61DC2B559BDULL,
		0xDCFAF4959F2FE889ULL,
		0x136BB86865BED335ULL,
		0x523FABBAB068C533ULL,
		0x026BB3C9C67219DEULL,
		0x00858E9DACAF963CULL,
		0x2E610DA1CB258934ULL,
		0xC9D94C34980DD680ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x030AA015401008BDULL,
		0x8CF894840E0E0080ULL,
		0x1202202801969311ULL,
		0x003A29B0B0080010ULL,
		0x02482349C060014AULL,
		0x0001041084AB0010ULL,
		0x24400C2000008930ULL,
		0xC9990010880CC480ULL
	}};
	printf("Test Case 235\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD297D97C3C69DA58ULL,
		0x3195B67AF75E56BAULL,
		0xDF656F9958450EE1ULL,
		0x96B0E1A4F9580FA1ULL,
		0x280B61B5661463FFULL,
		0xA25972DF3F21F8CDULL,
		0x38337B3B6FCD87FCULL,
		0x771A44F0F99843DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6669902AB31948ULL,
		0x0266D70BE9629FEFULL,
		0xE5A787065B09608CULL,
		0xC40D4EA051238CE8ULL,
		0xED50AB929695B3D8ULL,
		0xA55342DABC8692BBULL,
		0x52864DB3D10D67FEULL,
		0x4017A11512D9C5A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4206491028211848ULL,
		0x0004960AE14216AAULL,
		0xC525070058010080ULL,
		0x840040A051000CA0ULL,
		0x28002190061423D8ULL,
		0xA05142DA3C009089ULL,
		0x10024933410D07FCULL,
		0x4012001010984184ULL
	}};
	printf("Test Case 236\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6484D4C1E2625D73ULL,
		0x6AF93499C14DC797ULL,
		0xB0B01E255D143470ULL,
		0x74AAE70919FF0AE0ULL,
		0x6D8AE1400D61F4A8ULL,
		0x4497415D853028E3ULL,
		0xE7919165F8076E52ULL,
		0xF90DFAA78BE8FFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF73B5CAEDEB59C8AULL,
		0x59EDD2DCDDE97EEDULL,
		0x679680C292BDB427ULL,
		0xAAEA8D5128527C74ULL,
		0xFD1E116C2DCD8424ULL,
		0xA7E4EF0FF3EC4480ULL,
		0xD4E86F86ACE1E345ULL,
		0xB8970C963A39A193ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x64005480C2201C02ULL,
		0x48E91098C1494685ULL,
		0x2090000010143420ULL,
		0x20AA850108520860ULL,
		0x6D0A01400D418420ULL,
		0x0484410D81200080ULL,
		0xC4800104A8016240ULL,
		0xB80508860A28A182ULL
	}};
	printf("Test Case 237\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x97447A435CF9FD4DULL,
		0x9EEC3AAE02741969ULL,
		0xCD3C8B15552325E6ULL,
		0x9C810F945233C314ULL,
		0x0117D1F794108542ULL,
		0x9045AC52B5519113ULL,
		0xCB6D93B9F9B97395ULL,
		0x319F3616FCD48692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DB0FF9A936BE77ULL,
		0xA58BDDD7535B8C20ULL,
		0x19DBC5098E3469FBULL,
		0xCFDBD812EBB702C1ULL,
		0xE78A8889A12C439FULL,
		0xD36E5B21D89C5FC4ULL,
		0x6529143C6949018CULL,
		0x7AB9FB18CF3A28A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87400A410830BC45ULL,
		0x8488188602500820ULL,
		0x09188101042021E2ULL,
		0x8C81081042330200ULL,
		0x0102808180000102ULL,
		0x9044080090101100ULL,
		0x4129103869090184ULL,
		0x30993210CC100080ULL
	}};
	printf("Test Case 238\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x317CE71B2BFA7132ULL,
		0x9AD5E7E6D26E4F47ULL,
		0x6E72AB4312995E8FULL,
		0x71802D07ECF34E3AULL,
		0x9D02EE097F35DCE3ULL,
		0xF99BE37C4F904B48ULL,
		0x23F1D7CFC47CA94AULL,
		0x355AC54942C24CECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C750E17C7586514ULL,
		0x952D41338409D838ULL,
		0xDA5350F171EFFF18ULL,
		0x316ACF1004CE272AULL,
		0x9E02AD81946CB881ULL,
		0xACF2FF7FBD17E8A4ULL,
		0x4286A8D9E9923F89ULL,
		0x23844ED40BF474D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1074061303586110ULL,
		0x9005412280084800ULL,
		0x4A52004110895E08ULL,
		0x31000D0004C2062AULL,
		0x9C02AC0114249881ULL,
		0xA892E37C0D104800ULL,
		0x028080C9C0102908ULL,
		0x2100444002C044C4ULL
	}};
	printf("Test Case 239\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2B72D052CF646660ULL,
		0xD146E6C3E4A9CC64ULL,
		0x1750078820F11F5BULL,
		0xE8B188E1BC935B6FULL,
		0xEEAE42D687D18273ULL,
		0x3EB65FF9DADEEB67ULL,
		0xCD5ECDBDC07A7053ULL,
		0xE8C34358CDC4E490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B3E5FF605466D06ULL,
		0x4C9AE7BCF3E5E9D6ULL,
		0x9C9244E95D4085F0ULL,
		0x6519F4D3478C44E5ULL,
		0x1E78742B38DEFD79ULL,
		0x6D50547C5F8237DFULL,
		0x95CEC613B325FC59ULL,
		0xA85FDC36C97859D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B32505205446400ULL,
		0x4002E680E0A1C844ULL,
		0x1410048800400550ULL,
		0x601180C104804065ULL,
		0x0E28400200D08071ULL,
		0x2C1054785A822347ULL,
		0x854EC41180207051ULL,
		0xA8434010C9404090ULL
	}};
	printf("Test Case 240\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2AABEA7B6E4F494DULL,
		0x4B48AD02E5FB365FULL,
		0x653B3439F90A7331ULL,
		0x1855E71D7C7C5AC1ULL,
		0x55FEE1CE1A369D14ULL,
		0x845E06B24D0454AFULL,
		0xE45C6FBB2F0DFA68ULL,
		0xA32E8EC5DC79B629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19EEFAF3D5478371ULL,
		0xDCFD06678BEA0496ULL,
		0xDE3525E4E35F655CULL,
		0x7A76099CF528CFF3ULL,
		0xD40C1E23DCF54D08ULL,
		0x872E02793A3AD3FBULL,
		0xCA0EA17608ED77B5ULL,
		0xE8E295765A00D932ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08AAEA7344470141ULL,
		0x4848040281EA0416ULL,
		0x44312420E10A6110ULL,
		0x1854011C74284AC1ULL,
		0x540C000218340D00ULL,
		0x840E0230080050ABULL,
		0xC00C2132080D7220ULL,
		0xA022844458009020ULL
	}};
	printf("Test Case 241\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7BCC428C14394A9DULL,
		0x3F9FB08C602A4E4CULL,
		0xB9E905A953C9BB1AULL,
		0xFA0CE24877BF9E8AULL,
		0xB2E42408C2F1D477ULL,
		0x565007B2DDC51E71ULL,
		0x74E434FA69B9694FULL,
		0xB65DDF2B806C8F31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59ADC96DD19B943DULL,
		0x4C2B7830CE951277ULL,
		0x1F75ECCB4E790B9BULL,
		0x16D398809F0B044DULL,
		0xFDE26289109F5730ULL,
		0xB1F62C19A82BCD85ULL,
		0xCDC2E75D9A2070CBULL,
		0xBF0AF199D13857D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x598C400C1019001DULL,
		0x0C0B300040000244ULL,
		0x1961048942490B1AULL,
		0x12008000170B0408ULL,
		0xB0E0200800915430ULL,
		0x1050041088010C01ULL,
		0x44C024580820604BULL,
		0xB608D10980280711ULL
	}};
	printf("Test Case 242\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0BC6583A405CC59EULL,
		0x8144513F9E10C9F7ULL,
		0xB28BB0CC43A27828ULL,
		0x2FF271A7C3FE0149ULL,
		0xC98FCF805B3AB771ULL,
		0xFDCD17D00F3F9C01ULL,
		0xE8E3A0A90CE748B4ULL,
		0xA17699006425D41AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E103B21AEA8DAD0ULL,
		0x7FA66DBE9A22E887ULL,
		0xFA150B66BE9641FAULL,
		0x59EDBAF75BB9DA00ULL,
		0x100C829C8761E2D7ULL,
		0x298C107581284FAAULL,
		0x985B61138C00EB36ULL,
		0x3698CA0AE24E65C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A0018200008C090ULL,
		0x0104413E9A00C887ULL,
		0xB201004402824028ULL,
		0x09E030A743B80000ULL,
		0x000C82800320A251ULL,
		0x298C105001280C00ULL,
		0x884320010C004834ULL,
		0x2010880060044402ULL
	}};
	printf("Test Case 243\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x60B5845434CE6CE5ULL,
		0x30D5C2AE1853AC64ULL,
		0xD04BF38962E059BDULL,
		0x5037844F952589F5ULL,
		0xA1384FFF38DA127AULL,
		0x1AA78AC6E58AB164ULL,
		0x9CEAAA58EC2A3BD9ULL,
		0x86AA7D7333E021BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1B00F2E520103F8ULL,
		0xEA5EEBFD47B155C2ULL,
		0x7943EBBD599A4323ULL,
		0xA5100344D445CE1DULL,
		0x4A94C58CE8285194ULL,
		0x2A0A0C3CC8310A81ULL,
		0x6D7833D56FEBF065ULL,
		0x0DC072525D151165ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40B00404100000E0ULL,
		0x2054C2AC00110440ULL,
		0x5043E38940804121ULL,
		0x0010004494058815ULL,
		0x0010458C28081010ULL,
		0x0A020804C0000000ULL,
		0x0C6822506C2A3041ULL,
		0x0480705211000125ULL
	}};
	printf("Test Case 244\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3E7D17180FD5D95CULL,
		0x178A01983146D27AULL,
		0x2BDCE35F33AE8ABEULL,
		0x6A4086A0621A5A0DULL,
		0x2548DE3678F397D3ULL,
		0xCC306B244D6F71F9ULL,
		0x74CEB8164FC2C362ULL,
		0xA626CA4C95769349ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B27152C20122C00ULL,
		0xE8953BB598C921DFULL,
		0x6573BE2CDA0EDD71ULL,
		0x2E97AC63ACAA9355ULL,
		0x391B7242F0E5ADCCULL,
		0x22725F2EF1C2A2D1ULL,
		0xBDEDB5DDB212587BULL,
		0x15F7258191791EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2A25150800100800ULL,
		0x008001901040005AULL,
		0x2150A20C120E8830ULL,
		0x2A008420200A1205ULL,
		0x2108520270E185C0ULL,
		0x00304B24414220D1ULL,
		0x34CCB01402024062ULL,
		0x0426000091701200ULL
	}};
	printf("Test Case 245\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x039593E8D9A9DF5DULL,
		0x4F1BC48DDEBE1BBEULL,
		0x593980F63797E5BCULL,
		0x87CADAB0C7F8F693ULL,
		0xE1AFE3E8D04E3EE0ULL,
		0x475E4865A8B76A00ULL,
		0xD5E5C7E606AC2B0CULL,
		0xA534B18D5AD656B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83500B80F297A448ULL,
		0xFB9FF07A2847A174ULL,
		0x94C25E92B0091712ULL,
		0x1D4936E53BDA6775ULL,
		0x7B8278B91B96427FULL,
		0x01974EF575D45CCBULL,
		0x8D25C276F13E6F13ULL,
		0x92DD464070E0F280ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03100380D0818448ULL,
		0x4B1BC00808060134ULL,
		0x1000009230010510ULL,
		0x054812A003D86611ULL,
		0x618260A810060260ULL,
		0x0116486520944800ULL,
		0x8525C266002C2B00ULL,
		0x8014000050C05280ULL
	}};
	printf("Test Case 246\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3DD7F7161C238FAFULL,
		0x934DE09AC19F2F7EULL,
		0x4E88AB996587A990ULL,
		0xCE1BB9BEAC732D74ULL,
		0x334BA6FCBEF96F29ULL,
		0x1188A0338598F8D7ULL,
		0x232D31D6BC56D155ULL,
		0x7EDD184B6403342EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FCA3A450CC09BE4ULL,
		0x12AE9AF4AC012F16ULL,
		0x9900B6C865575289ULL,
		0x924FCC8F27D61A28ULL,
		0xD9C447E7C3D5A294ULL,
		0xB1E053AA3D4068E2ULL,
		0xF66A96DC8EDF6C4AULL,
		0x80412D185AC581B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DC232040C008BA4ULL,
		0x120C809080012F16ULL,
		0x0800A28865070080ULL,
		0x820B888E24520820ULL,
		0x114006E482D12200ULL,
		0x11800022050068C2ULL,
		0x222810D48C564040ULL,
		0x0041080840010028ULL
	}};
	printf("Test Case 247\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD9CD88C5B35625AAULL,
		0xC682B86610B2FD71ULL,
		0xBD81B998A511B2B9ULL,
		0x74FEA5BCD89C135DULL,
		0xAD7F17C933BB286DULL,
		0x11441467E17890A3ULL,
		0xB0A688FC669C067BULL,
		0x3206767C095C3680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD360350B7C7F67A4ULL,
		0x193E68D9AC29C810ULL,
		0x9F64BA3436EF3051ULL,
		0x66E3E043D3AF0E68ULL,
		0x294E7D1C14B544B2ULL,
		0x7744AE183AB1FD2EULL,
		0xC56AE2D2813576B4ULL,
		0xF3C393C6FA403792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD1400001305625A0ULL,
		0x000228400020C810ULL,
		0x9D00B81024013011ULL,
		0x64E2A000D08C0248ULL,
		0x294E150810B10020ULL,
		0x1144040020309022ULL,
		0x802280D000140630ULL,
		0x3202124408403680ULL
	}};
	printf("Test Case 248\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC47ADD0494CBC939ULL,
		0xC8C23C9917C4DC8AULL,
		0x303A5568BCB32080ULL,
		0x9992384C033654F9ULL,
		0xFA7D84C2BD660E9CULL,
		0x455E5CA7F07BC8DFULL,
		0xE1D99D481835ADE6ULL,
		0x54822207B8AF48EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32D41D189232D022ULL,
		0x4DE677786C3F8B18ULL,
		0x679DE402F7C28A92ULL,
		0xB8C2FB0B1AA954A9ULL,
		0x2DB7C7DFF0B363BAULL,
		0x7C0018640855B322ULL,
		0x75163FD49563DE20ULL,
		0x385FEDB20F9BEB59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00501D009002C020ULL,
		0x48C2341804048808ULL,
		0x20184400B4820080ULL,
		0x98823808022054A9ULL,
		0x283584C2B0220298ULL,
		0x4400182400518002ULL,
		0x61101D4010218C20ULL,
		0x10022002088B4849ULL
	}};
	printf("Test Case 249\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD91E24A90F4E3212ULL,
		0xD4F6331EFB493000ULL,
		0x3200514DAFD7370EULL,
		0x26634C84EF5ED3D4ULL,
		0x36A3C88E2B10610AULL,
		0x370214121A4AFBB8ULL,
		0xD340D25CDC0F4C9FULL,
		0xABBD44399475053AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3CFB69DF44D15D7ULL,
		0xA52DF934E0C47C34ULL,
		0x41C35303EE171A99ULL,
		0x92484B0B7788A6B0ULL,
		0x4F57126776513DC1ULL,
		0xE289650107AF7762ULL,
		0xC21D43706B75D3CEULL,
		0xDBF0B4B143F21C5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x810E2489044C1012ULL,
		0x84243114E0403000ULL,
		0x00005101AE171208ULL,
		0x0240480067088290ULL,
		0x0603000622102100ULL,
		0x22000400020A7320ULL,
		0xC20042504805408EULL,
		0x8BB004310070041AULL
	}};
	printf("Test Case 250\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8A119941229D9DFCULL,
		0xE0E121C2AC557AF7ULL,
		0x51047DB6EB55CA17ULL,
		0xEF8AC8B5220EE172ULL,
		0xA8878FFAC938BD06ULL,
		0x60DA8A90CC3326F2ULL,
		0xF621C3111A6A47B1ULL,
		0x175FD8776AC9AF9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58DF35A302CCA28ULL,
		0x9353B2BB1340950BULL,
		0x9A8A8AD8212591C7ULL,
		0x1A059CA43E43124CULL,
		0x7E079DCEDEF6CDD0ULL,
		0x3B21C0B3A3FF6AA8ULL,
		0x52435D5C54D101B8ULL,
		0xBDF72FBEE86D53E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80019140200C8828ULL,
		0x8041208200401003ULL,
		0x1000089021058007ULL,
		0x0A0088A422020040ULL,
		0x28078DCAC8308D00ULL,
		0x20008090803322A0ULL,
		0x52014110104001B0ULL,
		0x1557083668490384ULL
	}};
	printf("Test Case 251\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBF15A8DC1508BEBEULL,
		0x4739E7C00FE2773BULL,
		0xA840DBDD07BA1B6DULL,
		0x3E82727A32468C72ULL,
		0xDC63453FF4670E03ULL,
		0x91438408AB39CC59ULL,
		0x4D9886EC294F9746ULL,
		0x309EE0FA2AB6ADC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36716EF988B2C00AULL,
		0x4B56FB8C0FE357FFULL,
		0x906374E60F28BCD1ULL,
		0x31F935CE80C245E6ULL,
		0x80765D1A1F420694ULL,
		0x40EB7673B799C8A9ULL,
		0x55B0149DB76A5699ULL,
		0xDDB69FF25E1DED44ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x361128D80000800AULL,
		0x4310E3800FE2573BULL,
		0x804050C407281841ULL,
		0x3080304A00420462ULL,
		0x8062451A14420600ULL,
		0x00430400A319C809ULL,
		0x4590048C214A1600ULL,
		0x109680F20A14AD40ULL
	}};
	printf("Test Case 252\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD0CB1FFB2C56F49AULL,
		0x12FEE006A4E58BEEULL,
		0x17DBD09065A01062ULL,
		0x820C36F67C5E9BCFULL,
		0x44BADFD54583FE7FULL,
		0xF9D08B044D84F5D0ULL,
		0xF46BED9F75ACC340ULL,
		0x884FFC685107C967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF7D95489F56D68ULL,
		0x7AE93E19A17726FAULL,
		0xEC98D66B8356D891ULL,
		0xA2F8C02091DED39BULL,
		0x6171B62832A2E4FBULL,
		0xCB69A8E08D4CB079ULL,
		0x1433CBC9B2361E71ULL,
		0xF8D3E1809CF6F1A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0C3195008546408ULL,
		0x12E82000A06502EAULL,
		0x0498D00001001000ULL,
		0x82080020105E938BULL,
		0x403096000082E47BULL,
		0xC94088000D04B050ULL,
		0x1423C98930240240ULL,
		0x8843E0001006C127ULL
	}};
	printf("Test Case 253\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x828DE4B0E71CE36FULL,
		0xC268DE28731DB316ULL,
		0xB459B495C6B3BD92ULL,
		0x17179EDEFC1D6110ULL,
		0x9B65DF0B7A0FBF41ULL,
		0xFEB693691EDFE27FULL,
		0xEED1E0D435C358F1ULL,
		0xDC8B1E369280D77CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDDA3930428EC135ULL,
		0x835D6D79A1C2D1ACULL,
		0x2A44FD05A49F878EULL,
		0x5DE0F3059B3BA974ULL,
		0x589359AE7A13E5B2ULL,
		0x05DED24863F472BDULL,
		0xC6210DF3A56F023BULL,
		0xEF0451FD92FE285FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80882030420CC125ULL,
		0x82484C2821009104ULL,
		0x2040B40584938582ULL,
		0x1500920498192110ULL,
		0x1801590A7A03A500ULL,
		0x0496924802D4623DULL,
		0xC60100D025430031ULL,
		0xCC0010349280005CULL
	}};
	printf("Test Case 254\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x553FE02EFD6AEBA7ULL,
		0xA6E88421A57BD80AULL,
		0x9A3B164EA331B1EAULL,
		0x97E2BAA4C72A0AD6ULL,
		0x603C863ECA400901ULL,
		0xDFB1469825A35BB5ULL,
		0xA4267975AB53B91EULL,
		0x6A476A25F4F282ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29EFA713C4E4E209ULL,
		0xE4F424B7A7BBABDCULL,
		0x8A7F51F776C0A043ULL,
		0x2C2CC21543561C47ULL,
		0xC88147285E01A73FULL,
		0x4CB7683C4552A082ULL,
		0xEE1B9A59750D681EULL,
		0xD24247D20381077BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x012FA002C460E201ULL,
		0xA4E00421A53B8808ULL,
		0x8A3B10462200A042ULL,
		0x0420820443020846ULL,
		0x400006284A000101ULL,
		0x4CB1401805020080ULL,
		0xA40218512101281EULL,
		0x424242000080022BULL
	}};
	printf("Test Case 255\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9CABE47ADAD1BCF8ULL,
		0x68165CA94334B0B2ULL,
		0xEECF069833520639ULL,
		0xC3531C4FBA29027BULL,
		0x60A3765188CB02B7ULL,
		0x75DDD82C0D471C77ULL,
		0xA7F4AC7C5D7F1042ULL,
		0x606B0C8DC8F1E344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED08D7647D99A4A8ULL,
		0xAF3276F102325C31ULL,
		0xA1273BD19B0BDB62ULL,
		0x03763047E8590BC6ULL,
		0x10C5CE6C70354130ULL,
		0xEFEB2DCC00156102ULL,
		0x6A9F811879E2D383ULL,
		0xD442723BF310359BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C08C4605891A4A8ULL,
		0x281254A102301030ULL,
		0xA007029013020220ULL,
		0x03521047A8090242ULL,
		0x0081464000010030ULL,
		0x65C9080C00050002ULL,
		0x2294801859621002ULL,
		0x40420009C0102100ULL
	}};
	printf("Test Case 256\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD0183DB23A13C4A5ULL,
		0x6C9F17EBBB67F3A6ULL,
		0x5167ECF24A2E2536ULL,
		0x7BD9652F9ED4FFEAULL,
		0xAD7116EB0155624DULL,
		0x0BD8650FA8D431D2ULL,
		0xAF69643E36671DA8ULL,
		0x4B8A75CEB2ADA8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05EF85EF121B7C0AULL,
		0x7DB25336AC43FB45ULL,
		0xD2C62A3178A81DA0ULL,
		0x207E68A0365264B1ULL,
		0x84C4A0C95C130567ULL,
		0x5E6418B83C8F4112ULL,
		0xD18657FB211E548DULL,
		0x7D0290CE3ED8F36DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000805A212134400ULL,
		0x6C921322A843F304ULL,
		0x5046283048280520ULL,
		0x20586020165064A0ULL,
		0x844000C900110045ULL,
		0x0A40000828840112ULL,
		0x8100443A20061488ULL,
		0x490210CE3288A060ULL
	}};
	printf("Test Case 257\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x591F3E57CE21F2B8ULL,
		0x8747597801A0753FULL,
		0xEA922B19A9190DFCULL,
		0x5BECA6D388186247ULL,
		0x94AD75A2BFA6B322ULL,
		0xE97C9831CB4C5FB0ULL,
		0xFBFAAA7E0FCBA85BULL,
		0x41ABC8EE0954DAE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ACE3A3A48ACC810ULL,
		0xEF6278AFF151759DULL,
		0x3177B3CCFDEE79A4ULL,
		0x68CE2BAAF15D1E02ULL,
		0x59A00EE228A1B2B6ULL,
		0x98687054AAA9CFCBULL,
		0xCE014AF9F206E8DEULL,
		0x2B1504A8DBF46C00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x480E3A124820C010ULL,
		0x874258280100751DULL,
		0x20122308A90809A4ULL,
		0x48CC228280180202ULL,
		0x10A004A228A0B222ULL,
		0x886810108A084F80ULL,
		0xCA000A780202A85AULL,
		0x010100A809544800ULL
	}};
	printf("Test Case 258\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2C88078929338785ULL,
		0x8C1F118A6575B7A2ULL,
		0x511157CBD0BD3944ULL,
		0x104DE1940EE311DAULL,
		0x035D3B84E6F3AD31ULL,
		0x7F0F776F66133EBFULL,
		0xE683CCE20011E756ULL,
		0x82560E55EF1B408DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D93172E34750119ULL,
		0xE0932871CDF19268ULL,
		0xFCF53496984B8410ULL,
		0x9E16DDD4E80F1B7CULL,
		0xADB4811A52BB05AEULL,
		0x30F61C1FB7372957ULL,
		0xD6F4360B0B8CED58ULL,
		0x89918F85D010B6F9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C80070820310101ULL,
		0x8013000045719220ULL,
		0x5011148290090000ULL,
		0x1004C19408031158ULL,
		0x0114010042B30520ULL,
		0x3006140F26132817ULL,
		0xC68004020000E550ULL,
		0x80100E05C0100089ULL
	}};
	printf("Test Case 259\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x838E597729A14B45ULL,
		0x42EE8E640AA821B1ULL,
		0x3672C448FF3B74A1ULL,
		0xE7A1CD8CB3F2AE86ULL,
		0x24DD65799E455324ULL,
		0x678AEFFC56BE6C4EULL,
		0x2CC46C8A517A265CULL,
		0x986E64DFA2574EB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECF7DC82A1A21CC5ULL,
		0x8EBE36C3346A2DC0ULL,
		0xA32471017DBD167DULL,
		0x055425D4A06C6D75ULL,
		0x63A2603A256C4747ULL,
		0xCB7C6A99B7E14ABDULL,
		0x15053B304176BC7FULL,
		0x7BAA2A4F9017ECB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8086580221A00845ULL,
		0x02AE064000282180ULL,
		0x222040007D391421ULL,
		0x05000584A0602C04ULL,
		0x2080603804444304ULL,
		0x43086A9816A0480CULL,
		0x040428004172245CULL,
		0x182A204F80174CB0ULL
	}};
	printf("Test Case 260\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x76151460BBD16B3CULL,
		0x27413D7D1E3EC1DEULL,
		0x0495DBE89B1886E8ULL,
		0xD851FF3908CB8740ULL,
		0xDCA77AC44CC2026AULL,
		0x06107B01D5EB0671ULL,
		0x1291EA3503E7ED91ULL,
		0x203E6BCE3E24A56AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E4CC6ECA0E735EFULL,
		0xF5EF965060B6964CULL,
		0x8D33B72B8448F67DULL,
		0x6E2082CD099EE425ULL,
		0x8DD3784EB318D34AULL,
		0xCA58CD39D81607A2ULL,
		0xDEA842FF06830A0BULL,
		0xB2C9367642FD17DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36040460A0C1212CULL,
		0x254114500036804CULL,
		0x0411932880088668ULL,
		0x48008209088A8400ULL,
		0x8C8378440000024AULL,
		0x02104901D0020620ULL,
		0x1280423502830801ULL,
		0x200822460224054AULL
	}};
	printf("Test Case 261\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB85F13D764135E35ULL,
		0x31DAA080CD50753CULL,
		0x5117351630FA4954ULL,
		0x622498ADDE2E198AULL,
		0x78E697229F7465A5ULL,
		0x2387FDD82A0759A6ULL,
		0x204B2FC2C37CEDB8ULL,
		0xC5FA5D791EDA2D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA9CDEC9BE3F4256ULL,
		0xA097FF753423C9C2ULL,
		0x2BB9FD8780DE8FA1ULL,
		0xA49089C8095CC379ULL,
		0x3912BCB172FD1CAFULL,
		0x6DC94F4B1EA05227ULL,
		0x812E13D43D76B35DULL,
		0xD32D65AB28B95CD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA81C12C124134214ULL,
		0x2092A00004004100ULL,
		0x0111350600DA0900ULL,
		0x20008888080C0108ULL,
		0x38029420127404A5ULL,
		0x21814D480A005026ULL,
		0x000A03C00174A118ULL,
		0xC128452908980C01ULL
	}};
	printf("Test Case 262\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5A7B57C24AAF732FULL,
		0xD655BD3682CB8A52ULL,
		0xA6A35620D4C93453ULL,
		0x11838ECAB16C48F8ULL,
		0x1B9F65E6B2845705ULL,
		0xA123B41FEB45CB88ULL,
		0xD2FE51318A078E3AULL,
		0x76F55FCB35071785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51760C1D5C9060D9ULL,
		0x68E0E034EF5FCCCDULL,
		0x55BFB28C0E669DFBULL,
		0x1FE5E57F4CC996AEULL,
		0x63E0B9E21B8F6AE3ULL,
		0x9ACC6F2745DEDE1AULL,
		0x5669C6362352DCB8ULL,
		0x3FE615BE989FDF74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5072040048806009ULL,
		0x4040A034824B8840ULL,
		0x04A3120004401453ULL,
		0x1181844A004800A8ULL,
		0x038021E212844201ULL,
		0x800024074144CA08ULL,
		0x5268403002028C38ULL,
		0x36E4158A10071704ULL
	}};
	printf("Test Case 263\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4799B32E13920533ULL,
		0x54C051BA7502BF17ULL,
		0x7A7E7F66A3BF57A4ULL,
		0x965542678D82EFE5ULL,
		0xDE70A78CFE9A1190ULL,
		0x8E7FF188C7BEB1A0ULL,
		0x015E90A0D1A71D5BULL,
		0xA49FDC029FF7E55CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5573038BB43CEF68ULL,
		0xFCEEE4948B835B71ULL,
		0xDAB6C77D579458ECULL,
		0x2E1A953B5FB419AFULL,
		0x8905D2B550C4ED4AULL,
		0x2F3E5565E8EBABD8ULL,
		0x5506D033031ABAECULL,
		0xB99E61AFA8E605BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4511030A10100520ULL,
		0x54C0409001021B11ULL,
		0x5A364764039450A4ULL,
		0x061000230D8009A5ULL,
		0x8800828450800100ULL,
		0x0E3E5100C0AAA180ULL,
		0x0106902001021848ULL,
		0xA09E400288E60518ULL
	}};
	printf("Test Case 264\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE502CA64422970EBULL,
		0xC1E0F831C4EB8F35ULL,
		0x17021168A5955B84ULL,
		0x84F146755B4A1951ULL,
		0xB57B2A0F951B5EB0ULL,
		0xA55A9222FC31C87DULL,
		0xBB5C328BF29F5DB4ULL,
		0xDC7005EEE33237DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE95C1596696F0AAULL,
		0x04C11B6761518EFCULL,
		0x3B845DDE0DD119E8ULL,
		0x5F2748AFCD7D5D09ULL,
		0x09187C0C5FE5D020ULL,
		0xC90B4306811084CDULL,
		0x434BF4F551902528ULL,
		0xE859EE3690E00E16ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA400C040420070AAULL,
		0x00C0182140418E34ULL,
		0x1300114805911980ULL,
		0x0421402549481901ULL,
		0x0118280C15015020ULL,
		0x810A02028010804DULL,
		0x0348308150900520ULL,
		0xC850042680200614ULL
	}};
	printf("Test Case 265\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x47FB32B8FCA606FAULL,
		0xA0A6A921A9DA135CULL,
		0x076ADB24259485D6ULL,
		0xE50DE7AC944917CDULL,
		0xC4646E2405C390DAULL,
		0xE0F1D01F52207247ULL,
		0x38F2A712433D638AULL,
		0xA35CD75F9B8337BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC42AB978215C47FULL,
		0x913AEC7281D0DCD0ULL,
		0x7ADFF1DE82A15C3FULL,
		0x2DDDD9B77FAF13EBULL,
		0x754AC9FC79BBC952ULL,
		0x0E2A7DAAEC71726CULL,
		0xD56A3B9E973D7676ULL,
		0x3A6C4D03A1ADC6B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x444222908004047AULL,
		0x8022A82081D01050ULL,
		0x024AD10400800416ULL,
		0x250DC1A4140913C9ULL,
		0x4440482401838052ULL,
		0x0020500A40207244ULL,
		0x10622312033D6202ULL,
		0x224C4503818106B6ULL
	}};
	printf("Test Case 266\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC4553463F16BB7BEULL,
		0xDE3A7304CB31E5C2ULL,
		0x4F71B9202681CD39ULL,
		0x03E1BAE782764F4CULL,
		0x5536C86EA7F5BD62ULL,
		0xA69DA7ACB4A0476CULL,
		0x09ECD05EE80B526FULL,
		0x0B919CD097A81570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEA95864B6E26D91ULL,
		0xF3BA4DB406F4761AULL,
		0xBA60407F97BCE065ULL,
		0xFE88A4317C0B56EFULL,
		0x56DF19E7C1F30736ULL,
		0xAD151FB7202CFC58ULL,
		0x0ABDBF08EC7404E5ULL,
		0xE6BF2510AF5F86E6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4011060B0622590ULL,
		0xD23A410402306402ULL,
		0x0A6000200680C021ULL,
		0x0280A0210002464CULL,
		0x5416086681F10522ULL,
		0xA41507A420204448ULL,
		0x08AC9008E8000065ULL,
		0x0291041087080460ULL
	}};
	printf("Test Case 267\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFB77436D6846A500ULL,
		0xB9CB5886BBD2089AULL,
		0xD194BAFCD0AC2A78ULL,
		0x733759EC26E69D29ULL,
		0x014CC929B0FBBC94ULL,
		0x826C86FDBF6C3A1BULL,
		0x5D81606A4F9257CDULL,
		0xB9F7C0990616E11BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x603F77D87C5A830AULL,
		0x080DF10342FD7C6AULL,
		0x72B0B5D7A31D41C2ULL,
		0x45C552F5473B68B8ULL,
		0x9BA4FFC21DA5AE29ULL,
		0x36DFAA47C8B624D9ULL,
		0xFD7759D13CC51E5DULL,
		0xBCC4A204F2576420ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6037434868428100ULL,
		0x0809500202D0080AULL,
		0x5090B0D4800C0040ULL,
		0x410550E406220828ULL,
		0x0104C90010A1AC00ULL,
		0x024C824588242019ULL,
		0x5D0140400C80164DULL,
		0xB8C4800002166000ULL
	}};
	printf("Test Case 268\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x89801D835D74F6D7ULL,
		0x158D942AD9BA3EEAULL,
		0xAADB305697156AFEULL,
		0xED4CB4720A5FA83CULL,
		0x61718306430AFB48ULL,
		0x7773FE187225C61FULL,
		0x598A699399C1BA63ULL,
		0x1BE44677BCA6B7CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD097781CE8AAF844ULL,
		0x223AF7EAFC5978C0ULL,
		0xB7F168BEE330664DULL,
		0xF53DD6BE6EA4FE3EULL,
		0xEA83CD9B06195DFCULL,
		0x335DD409C2EFE83EULL,
		0xCFCBDFAECDB3D3DFULL,
		0x7BFCD2D4F878E8CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808018004820F044ULL,
		0x0008942AD81838C0ULL,
		0xA2D120168310624CULL,
		0xE50C94320A04A83CULL,
		0x6001810202085948ULL,
		0x3351D4084225C01EULL,
		0x498A498289819243ULL,
		0x1BE44254B820A0C8ULL
	}};
	printf("Test Case 269\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x19DA53CB8B22C7E0ULL,
		0x972991C0E3496904ULL,
		0xE4F64FBD965EB9B2ULL,
		0xBDFC8B74E74FC2FCULL,
		0x3E0BD025E0F4ABECULL,
		0x9BCF0857B92297BAULL,
		0xB3D926375FEC90C1ULL,
		0x0BA2C57795EAC94BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E4DDD261E623BFDULL,
		0xBE7A9082D66452DBULL,
		0x2259027D6714BDF7ULL,
		0x3E4F531C535F37F9ULL,
		0x2FBAAC4473303D02ULL,
		0x737A388B2D518901ULL,
		0x354C8460AE79A4C1ULL,
		0x10B34ED89D7E3D52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x184851020A2203E0ULL,
		0x96289080C2404000ULL,
		0x2050023D0614B9B2ULL,
		0x3C4C0314434F02F8ULL,
		0x2E0A800460302900ULL,
		0x134A080329008100ULL,
		0x314804200E6880C1ULL,
		0x00A24450956A0942ULL
	}};
	printf("Test Case 270\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC2E4008EDD812790ULL,
		0xF45B91862FB6E35DULL,
		0xF80BB2F276AD2097ULL,
		0xB3F0C2885DF1B7A4ULL,
		0x55B84D00731B5891ULL,
		0xD3CBB182D3AB88E5ULL,
		0x44F7784DF56DADE4ULL,
		0x6B341301E3FBAF01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4690053C67FD3EDULL,
		0x5C9C0D885E7A183CULL,
		0x67FFED9648D5F80DULL,
		0x2FF44EB003419112ULL,
		0xC275C854BC464E12ULL,
		0x484395E84F889C3AULL,
		0x659E773AE40636F9ULL,
		0x19BAC4D70C71EBD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0600002C4010380ULL,
		0x541801800E32001CULL,
		0x600BA09240852005ULL,
		0x23F0428001419100ULL,
		0x4030480030024810ULL,
		0x4043918043888820ULL,
		0x44967008E40424E0ULL,
		0x093000010071AB01ULL
	}};
	printf("Test Case 271\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA9DE8E372C3F068FULL,
		0x6FC340DC410C8A2EULL,
		0x726FE5FFB2D64A6EULL,
		0xE82ACC000EBDEE77ULL,
		0x09705BF103659E7BULL,
		0x15FBE6A0E304DCECULL,
		0xA9FAE5E7A78F720AULL,
		0x5B6749CD6ED92404ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC9A2DD4359BD49EULL,
		0xCA934AE7B10CB5E4ULL,
		0x53E2F43C711690C3ULL,
		0x95FFADAC3645F4F5ULL,
		0x66A308E6AD90D6AFULL,
		0xF251BC982B74864AULL,
		0xA3F7FE2E9D2B654BULL,
		0xCDF215B37E5D6867ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x889A0C14241B048EULL,
		0x4A8340C4010C8024ULL,
		0x5262E43C30160042ULL,
		0x802A8C000605E475ULL,
		0x002008E00100962BULL,
		0x1051A48023048448ULL,
		0xA1F2E426850B600AULL,
		0x496201816E592004ULL
	}};
	printf("Test Case 272\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x46B8B513F79010B7ULL,
		0x3BBE5A1EE3DAA10EULL,
		0x13B43F31439C3447ULL,
		0x2B23C692130A014CULL,
		0x5E10F10726F51979ULL,
		0x74F27DA150D70B47ULL,
		0x48973B27F9794208ULL,
		0xB7B11BFD95889AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x289C4D98D24F8E3DULL,
		0x1B3CFCE327B978F6ULL,
		0xED994D09972C394DULL,
		0x32E90505FB475FA0ULL,
		0xC640BF747DBCAD26ULL,
		0xAF7DC32A0615B427ULL,
		0x7AAB8E7DEF105ADAULL,
		0xEB28B171F37F463CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00980510D2000035ULL,
		0x1B3C580223982006ULL,
		0x01900D01030C3045ULL,
		0x2221040013020100ULL,
		0x4600B10424B40920ULL,
		0x2470412000150007ULL,
		0x48830A25E9104208ULL,
		0xA320117191080210ULL
	}};
	printf("Test Case 273\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3B5C3CACA9D9EB58ULL,
		0x403991B73036558BULL,
		0x3472714F687A01A2ULL,
		0x1AE0A773B1EF278FULL,
		0x779E571607D26C4DULL,
		0x45C0485F25EBB73AULL,
		0xCFFAB283747062C2ULL,
		0xB5BCE77572977FF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x593F5E36AE44AE0DULL,
		0x78860E5270AB9013ULL,
		0x3179F63E79930C83ULL,
		0x5FBA8BEC80EC4BCFULL,
		0x676FEC180A400F2FULL,
		0xBB82A0CFE34546F8ULL,
		0xF792D3BC1A593FF8ULL,
		0x53ADDBC24393B14CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x191C1C24A840AA08ULL,
		0x4000001230221003ULL,
		0x3070700E68120082ULL,
		0x1AA0836080EC038FULL,
		0x670E441002400C0DULL,
		0x0180004F21410638ULL,
		0xC7929280105022C0ULL,
		0x11ACC34042933148ULL
	}};
	printf("Test Case 274\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBA664E316FE828E9ULL,
		0x3060B130C92095FBULL,
		0xE618E868664750DCULL,
		0xE4E9F2F6E435BBBFULL,
		0x209AB1DD0ECC77AEULL,
		0x46E79BB4EDE2A791ULL,
		0xC9C0E0BD83846CB4ULL,
		0x7ED18FBB370217CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD666F71AB60E87AULL,
		0xAF58ABFCF1C20D8BULL,
		0xB2581F32521D584CULL,
		0x1346299FE34A595FULL,
		0xF55B82331267269EULL,
		0xC7877E6FD347E138ULL,
		0x7D6D685A13C10A12ULL,
		0xB65A909D3E90F296ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98664E312B602868ULL,
		0x2040A130C100058BULL,
		0xA21808204205504CULL,
		0x00402096E000191FULL,
		0x201A80110244268EULL,
		0x46871A24C142A110ULL,
		0x4940601803800810ULL,
		0x3650809936001286ULL
	}};
	printf("Test Case 275\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4F66BD3B2C17C753ULL,
		0xBF7B58849DDAE99DULL,
		0xCBA2D684933823A8ULL,
		0xD808BAE71CCAAAB6ULL,
		0x4983BCC193013B07ULL,
		0x432DC17C70EBC0C9ULL,
		0x65F2B2855F6ED9D7ULL,
		0x936A75993A92A635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x346DD3CF82B93685ULL,
		0xB110B8B4B618DA6EULL,
		0x40CBDB4265FEA1D3ULL,
		0x17113B00E9E02CB0ULL,
		0xD2A5850D8A2EB4D2ULL,
		0x4ABEEA8D7D724E58ULL,
		0x2B56F5FCFA8BC222ULL,
		0x081D7FF22B01A888ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0464910B00110601ULL,
		0xB11018849418C80CULL,
		0x4082D20001382180ULL,
		0x10003A0008C028B0ULL,
		0x4081840182003002ULL,
		0x422CC00C70624048ULL,
		0x2152B0845A0AC002ULL,
		0x000875902A00A000ULL
	}};
	printf("Test Case 276\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA6FC220748A1193EULL,
		0x7E994E82A1640396ULL,
		0xED74E2100C9CAC93ULL,
		0x8E18DB1B677C4503ULL,
		0xEF8E4B948A8068DCULL,
		0xBD91A2501A4B1800ULL,
		0xB410FE5B42B34F0FULL,
		0x8CC80890159D0D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FE871E9AD4764D1ULL,
		0x0B0514B055BB66E5ULL,
		0x76FFBFD4D8A9B901ULL,
		0x5D9238BAB333168DULL,
		0xAC24931F2C37A9E2ULL,
		0x185FBA4D600FD972ULL,
		0x0563171E96DFE85DULL,
		0x9B41E852122CED9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06E8200108010010ULL,
		0x0A01048001200284ULL,
		0x6474A2100888A801ULL,
		0x0C10181A23300401ULL,
		0xAC040314080028C0ULL,
		0x1811A240000B1800ULL,
		0x0400161A0293480DULL,
		0x88400810100C0D84ULL
	}};
	printf("Test Case 277\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9DE4C9D05B818BD7ULL,
		0xC514C253CBC7247EULL,
		0xC20D7C59F6D99609ULL,
		0xFEAAFB59D4071054ULL,
		0x8612DEE5C2A1909DULL,
		0xEC6AF5EB4C0A1298ULL,
		0xE166B468C0BEA8BDULL,
		0x63E9CBA809523952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x940E78437C4EADBFULL,
		0x477B0DD9319A9DACULL,
		0xFF54748F3D90D22AULL,
		0xC6BAC5D9957C59BAULL,
		0x6303A3166E90D3EDULL,
		0x4E32D5A699D0FE6FULL,
		0x48CF508E07C45319ULL,
		0xEA37B27777456800ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9404484058008997ULL,
		0x451000510182042CULL,
		0xC204740934909208ULL,
		0xC6AAC15994041010ULL,
		0x020282044280908DULL,
		0x4C22D5A208001208ULL,
		0x4046100800840019ULL,
		0x6221822001402800ULL
	}};
	printf("Test Case 278\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6A3BB280E10A15F3ULL,
		0x046508519FF18D66ULL,
		0xA9498809F4CE5466ULL,
		0xBF03819B746E0F5FULL,
		0x3945900DE0CAA9ADULL,
		0x9362542E9F0E0411ULL,
		0x1609BD910377352BULL,
		0xFAC979C458AEAE0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x384E91A5469A87F5ULL,
		0xB2CD293C31D709CEULL,
		0x4B8603B292B3FEFDULL,
		0x5B96F8302D7A902FULL,
		0xC13F78D246DF56D4ULL,
		0xE77A08DDF9CFC82FULL,
		0x4F58F118722AA790ULL,
		0x10535503E5C7A91FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x280A9080400A05F1ULL,
		0x0045081011D10946ULL,
		0x0900000090825464ULL,
		0x1B028010246A000FULL,
		0x0105100040CA0084ULL,
		0x8362000C990E0001ULL,
		0x0608B11002222500ULL,
		0x104151004086A80CULL
	}};
	printf("Test Case 279\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA5947A7893CE9976ULL,
		0x13973CF6A42C5C72ULL,
		0x212A3FCCFC08C75BULL,
		0x103D02A14AA38110ULL,
		0xECFBFC5267832AD5ULL,
		0x5CAC597E46CEE04AULL,
		0xA7D40AD09684605AULL,
		0xDDB199DE5386676EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA402F8B7210C31ULL,
		0x92AAC79393A754A7ULL,
		0xE7A703815F527904ULL,
		0xB61EB8652BA8A859ULL,
		0x2C62932C96E67929ULL,
		0x9FFD3B028045C0E5ULL,
		0x75D2302E3E89A707ULL,
		0xE903757C58D29F61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA584027893000830ULL,
		0x1282049280245422ULL,
		0x212203805C004100ULL,
		0x101C00210AA08010ULL,
		0x2C62900006822801ULL,
		0x1CAC19020044C040ULL,
		0x25D0000016802002ULL,
		0xC901115C50820760ULL
	}};
	printf("Test Case 280\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x899E27F4B07570FCULL,
		0xC49CE27ED6BAD609ULL,
		0x670123E74FA30729ULL,
		0x9DF522071C1ABB5DULL,
		0xE00D62E4D045A95FULL,
		0xCCE646DCC197A7B9ULL,
		0x79855BD15058C444ULL,
		0xC8625757EB000AC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B8944F0DF8B9AAULL,
		0x257E23BF941951AEULL,
		0x95269E302CFF7266ULL,
		0x44AAEBB80EB55ACCULL,
		0xDAB14842006B0F7EULL,
		0x3B0AC1474A4ACD05ULL,
		0xA08E470657F607D6ULL,
		0x1E670912EC2377ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01980444007030A8ULL,
		0x041C223E94185008ULL,
		0x050002200CA30220ULL,
		0x04A022000C101A4CULL,
		0xC00140400041095EULL,
		0x0802404440028501ULL,
		0x2084430050500444ULL,
		0x08620112E8000284ULL
	}};
	printf("Test Case 281\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEED59DB130AD81C4ULL,
		0x39CFDA623A527E15ULL,
		0xD3606F35220D3E96ULL,
		0x74A205244BA613FEULL,
		0x4C1CFAB2A814BFD1ULL,
		0x0ADD28AA53015950ULL,
		0xF4CB17641EE8E24EULL,
		0xF3ED7425D0614EA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC962106FB3FFDED5ULL,
		0xFD14051793B97870ULL,
		0x8A9BFC85249D8ECBULL,
		0x637C00C6714B71ADULL,
		0x32CCE1D27E80288DULL,
		0x743D30DC8A20F42DULL,
		0xD3775D56A6CDC591ULL,
		0x5EBC7FF30F3F25B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC840102130AD80C4ULL,
		0x3904000212107810ULL,
		0x82006C05200D0E82ULL,
		0x60200004410211ACULL,
		0x000CE09228002881ULL,
		0x001D208802005000ULL,
		0xD043154406C8C000ULL,
		0x52AC7421002104A1ULL
	}};
	printf("Test Case 282\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x195C9121CF5458F4ULL,
		0xB7C6B6164C19D20BULL,
		0xDAAB5F8F107121CFULL,
		0xBEFA4B91E9C09DE9ULL,
		0x29196C7DFFA91AC2ULL,
		0x7586A4D91BDE1E91ULL,
		0xCE4A670855B63B1AULL,
		0xE84AA1357C922739ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB871372F2BB19538ULL,
		0x66A4C0E7286A599CULL,
		0x8BD567568179477FULL,
		0xEFE34C86CB5E695EULL,
		0xFA518CF205485363ULL,
		0xF4ACA622D7C3C7FFULL,
		0x9B8E4BBE25503802ULL,
		0x876B50E01DC7B9C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x185011210B101030ULL,
		0x2684800608085008ULL,
		0x8A8147060071014FULL,
		0xAEE24880C9400948ULL,
		0x28110C7005081242ULL,
		0x7484A40013C20691ULL,
		0x8A0A430805103802ULL,
		0x804A00201C822108ULL
	}};
	printf("Test Case 283\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFDE1B0F1779DA92CULL,
		0x5661584A01B9598CULL,
		0x786BF73D10B4D634ULL,
		0xB90F54C3878CE790ULL,
		0xB9D1C2D9D06CFD65ULL,
		0x3B70C47C5E65E8D1ULL,
		0x22DA4125BCF16172ULL,
		0x4D3011D6CEF4E96DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5184370CFA28DD47ULL,
		0xFAB5D01D1E85AD2EULL,
		0xDFF403777F4E9EDDULL,
		0xF3C373A0A875FF88ULL,
		0xC590599410DE51B4ULL,
		0xD22397673A9021C0ULL,
		0x488F45936A8DB99BULL,
		0x1C7FDFB2301B95A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5180300072088904ULL,
		0x522150080081090CULL,
		0x5860033510049614ULL,
		0xB10350808004E780ULL,
		0x81904090104C5124ULL,
		0x122084641A0020C0ULL,
		0x008A410128812112ULL,
		0x0C30119200108125ULL
	}};
	printf("Test Case 284\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE39C32A45726CBF1ULL,
		0x27C1E9C0FEE19C98ULL,
		0xED268F6D4CFC6C80ULL,
		0x1DA8CE3028C3DA5CULL,
		0x4D876430EC448D27ULL,
		0x0D68EAC9AEBE06FEULL,
		0xDE392A83EB5E1E65ULL,
		0xB09429D7A4E9D092ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE37557CECACDABE8ULL,
		0x005D2D6B9712F612ULL,
		0x0644C9BDB1E3F48EULL,
		0x9AA15BB3C0310FF5ULL,
		0x791D400544F6CDF0ULL,
		0xC090E5C6473FEC20ULL,
		0x79DC1B434191B6A5ULL,
		0xF81D775BD8013AA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE314128442048BE0ULL,
		0x0041294096009410ULL,
		0x0404892D00E06480ULL,
		0x18A04A3000010A54ULL,
		0x4905400044448D20ULL,
		0x0000E0C0063E0420ULL,
		0x58180A0341101625ULL,
		0xB014215380011082ULL
	}};
	printf("Test Case 285\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD431C2C686B0FFDBULL,
		0xD3BA779D4E82270DULL,
		0xDC33CEDF0C69F1A9ULL,
		0x7DA6D0A20B8BD2CAULL,
		0x6B48F02E442DF087ULL,
		0x0F6077DBD91B7A44ULL,
		0x8ED7C20962DC65C0ULL,
		0xECCE677E7E702AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE4721B1B3F99E9FULL,
		0x12C674EEECABABD0ULL,
		0x865A4785E1769ADCULL,
		0xBF9BEF7151DD3C7EULL,
		0x5CAE7D3155FF027DULL,
		0x6259D2834BAA1BFAULL,
		0xD3F82B2646E01977ULL,
		0x6EDBA8F8DB021090ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC401008082B09E9BULL,
		0x1282748C4C822300ULL,
		0x8412468500609088ULL,
		0x3D82C0200189104AULL,
		0x48087020442D0005ULL,
		0x02405283490A1A40ULL,
		0x82D0020042C00140ULL,
		0x6CCA20785A000080ULL
	}};
	printf("Test Case 286\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA5531E6082670430ULL,
		0x00CF6ABA1E5A3AACULL,
		0x480D4F852BD7775BULL,
		0x55A6F35C250AED11ULL,
		0x374E05CB96CB801CULL,
		0x4C1896862B547FCBULL,
		0x51488A3AE979BF68ULL,
		0x648EB259C48329A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA33984BF9A560221ULL,
		0x15211F5851F13CB4ULL,
		0x41400E56BCF784E9ULL,
		0xC0FFBE3AE226C429ULL,
		0x5926CE1A88772048ULL,
		0x9C30A481D8DE3C2FULL,
		0xB31C4CB5FDF25C4DULL,
		0x9203C72BAB1A2D00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA111042082460020ULL,
		0x00010A18105038A4ULL,
		0x40000E0428D70449ULL,
		0x40A6B2182002C401ULL,
		0x1106040A80430008ULL,
		0x0C10848008543C0BULL,
		0x11080830E9701C48ULL,
		0x0002820980022900ULL
	}};
	printf("Test Case 287\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA993001B5BA50CD1ULL,
		0xDBF0BFDF943DD3B3ULL,
		0xFE6FE84E14B828C0ULL,
		0xDFCC72DB175F164CULL,
		0x59634930DFB1099EULL,
		0x88B9BB9F650EB3C1ULL,
		0x2E0B3D44061FC926ULL,
		0x42A2D0BF18248D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9066315F76B8CA66ULL,
		0x73346D4454031DE2ULL,
		0xD8F49F00C1F0DD64ULL,
		0x67B075F0197DD626ULL,
		0x37E09C529DF8052AULL,
		0x636A283ECF9A4996ULL,
		0x8CC388566D5DD348ULL,
		0x7E5275082699C7E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8002001B52A00840ULL,
		0x53302D44140111A2ULL,
		0xD864880000B00840ULL,
		0x478070D0115D1604ULL,
		0x116008109DB0010AULL,
		0x0028281E450A0180ULL,
		0x0C030844041DC100ULL,
		0x4202500800008564ULL
	}};
	printf("Test Case 288\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEE62A156D94BD32BULL,
		0xBC905882C25ECDE7ULL,
		0xE65D7E1D23EA8996ULL,
		0x87C87013DFD09F14ULL,
		0xBA42C285A352312DULL,
		0x061968CBCCD4279FULL,
		0xB1713E252F4E0148ULL,
		0xE4C1E650C8DE83B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFA8903CF304A440ULL,
		0x10F4440CB519BF1DULL,
		0xF56A20DAA0B1115BULL,
		0xC3747FD0799256F3ULL,
		0xDE0C7A050CDAAE4FULL,
		0x9985CB1898BF552DULL,
		0x75E444CDE0024041ULL,
		0x42F00EA516310E50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCE208014D1008000ULL,
		0x1090400080188D05ULL,
		0xE448201820A00112ULL,
		0x8340701059901610ULL,
		0x9A0042050052200DULL,
		0x000148088894050DULL,
		0x3160040520020040ULL,
		0x40C0060000100210ULL
	}};
	printf("Test Case 289\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBFCABFE6AE4EAA02ULL,
		0xF5BA08D67B2E6C19ULL,
		0x63E0D4AB801A2AC5ULL,
		0xA20FB97EB9121A24ULL,
		0x61554BA68A31A5B5ULL,
		0xAA7D689193D267B1ULL,
		0xBA65CFF0FF56A4FEULL,
		0xDFDD78B174703CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67C779B4B46D4C5AULL,
		0x477788DE6166A47FULL,
		0x0186B78BDFEAD4B1ULL,
		0x1EA6222AFA638DECULL,
		0xAE788FD0C1CD952EULL,
		0x052C43AC823D1C00ULL,
		0x756CAC223CB455F3ULL,
		0xBF042667F805D0EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x27C239A4A44C0802ULL,
		0x453208D661262419ULL,
		0x0180948B800A0081ULL,
		0x0206202AB8020824ULL,
		0x20500B8080018524ULL,
		0x002C408082100400ULL,
		0x30648C203C1404F2ULL,
		0x9F042021700010CEULL
	}};
	printf("Test Case 290\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x699F1EC6AF377D3DULL,
		0x1EC94A65C0D190D0ULL,
		0xAE41CA130CBE4ED2ULL,
		0xA75FAB8FE99A2452ULL,
		0x985ED3888A4B2791ULL,
		0x9FD99574F4B2F850ULL,
		0x8846387F5E99F965ULL,
		0x9C548F9BB4318AB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2141A6F6DF02E93AULL,
		0xCF2822E3DE42D19CULL,
		0x38D52656CE08B55DULL,
		0x843992989758B0E3ULL,
		0xFD4164DA2B775BC1ULL,
		0xD23C41F1C8F3F903ULL,
		0x9E152EF1A5F36200ULL,
		0xDCC604F59B0F6FA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x210106C68F026938ULL,
		0x0E080261C0409090ULL,
		0x284102120C080450ULL,
		0x8419828881182042ULL,
		0x984040880A430381ULL,
		0x92180170C0B2F800ULL,
		0x8804287104916000ULL,
		0x9C44049190010AA0ULL
	}};
	printf("Test Case 291\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x204941EB33346884ULL,
		0xBF7E96242AFC5EF3ULL,
		0xC5F037EE1AE44D98ULL,
		0x06F9856DE5F809E7ULL,
		0xFB36AD2A31BE616CULL,
		0x8EC6C18E8F3EFEDAULL,
		0xA0B4C2843B3F537EULL,
		0xB7C06B2B50E72A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07051DDC66605B8BULL,
		0x0CA4756B64F72AF7ULL,
		0x13F161249B902119ULL,
		0xADA04AFC71AD16F3ULL,
		0xD69CD967251CB2EAULL,
		0x3B1579A301FA9D22ULL,
		0xF4EDF30C4B0B4DC8ULL,
		0x5DF2902329CBB591ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000101C822204880ULL,
		0x0C24142020F40AF3ULL,
		0x01F021241A800118ULL,
		0x04A0006C61A800E3ULL,
		0xD2148922211C2068ULL,
		0x0A044182013A9C02ULL,
		0xA0A4C2040B0B4148ULL,
		0x15C0002300C32000ULL
	}};
	printf("Test Case 292\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x30C1FC1B0FEF68D0ULL,
		0x5D55E6E11027EC0AULL,
		0x52A5ECFC0B23A2BCULL,
		0xCC187D98ACA9A146ULL,
		0xCB4E85E38A9F704FULL,
		0x4CF087BF780F38F2ULL,
		0xF65ED424CCD80461ULL,
		0x29DE0B5E3225A4DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4488695B0725C588ULL,
		0x1DE4008FBFDEFF26ULL,
		0x2074B5546B27D749ULL,
		0x5E21CF954069B529ULL,
		0x568AF28B49BC980DULL,
		0xA13FA06BC7AF6162ULL,
		0x807CCDA1C4E666DDULL,
		0xB7DF02F6936E5A0AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0080681B07254080ULL,
		0x1D4400811006EC02ULL,
		0x0024A4540B238208ULL,
		0x4C004D900029A100ULL,
		0x420A8083089C100DULL,
		0x0030802B400F2062ULL,
		0x805CC420C4C00441ULL,
		0x21DE02561224000AULL
	}};
	printf("Test Case 293\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE1E9F47624E98E9EULL,
		0xA24F9C8927D35B0AULL,
		0x1694A52CBAD5FCB1ULL,
		0x8E981517146FF45AULL,
		0xE33D9E8134F52FD3ULL,
		0xA9A44AF04A9C9A45ULL,
		0x8F9A3B6560AEA656ULL,
		0x20D9F04950EC1E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5857118F52D39288ULL,
		0xBA690A81849C9CC9ULL,
		0xCC20235005EB6935ULL,
		0x3594B9FF67C9424DULL,
		0x98558C815B54DDA7ULL,
		0x17BA14D188A09D22ULL,
		0xBF0BFC145C48622EULL,
		0x7A0A3462F0295640ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4041100600C18288ULL,
		0xA249088104901808ULL,
		0x0400210000C16831ULL,
		0x0490111704494048ULL,
		0x80158C8110540D83ULL,
		0x01A000D008809800ULL,
		0x8F0A380440082206ULL,
		0x2008304050281640ULL
	}};
	printf("Test Case 294\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8A80B412583D5269ULL,
		0xC3464905AA5054E3ULL,
		0xA4BE7B5CDE866D0CULL,
		0x805ABD3BE790F7E0ULL,
		0x3CFB7B58CDEE9715ULL,
		0x63BC4C259DECA414ULL,
		0xFFA7723BCEDDB71FULL,
		0x307CE25CD5F947C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E13E74731F58003ULL,
		0x976DA820445CEB64ULL,
		0x0F6AE9B3A20E56F3ULL,
		0xC98CD411BCA4D4DBULL,
		0x7CDE3DF71920A52CULL,
		0xF5F4792F277BC0D9ULL,
		0x77CAE2C3A59FB171ULL,
		0x95C69BF2021F6802ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A00A40210350001ULL,
		0x8344080000504060ULL,
		0x042A691082064400ULL,
		0x80089411A480D4C0ULL,
		0x3CDA395009208504ULL,
		0x61B4482505688010ULL,
		0x77826203849DB111ULL,
		0x1044825000194002ULL
	}};
	printf("Test Case 295\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA00230FF7265B8DCULL,
		0x1EB042CA0659C83BULL,
		0x3D9EC97361B13B1AULL,
		0x56D63EFC202BD1CEULL,
		0x7D6F0B700C812031ULL,
		0x179DC25E02FAF087ULL,
		0x587CC391BCD401BDULL,
		0x12C61B68DCB76893ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7907EBE7BFA68105ULL,
		0xCB55908EAD9C1595ULL,
		0xA71F75BBB8AE4152ULL,
		0x4379C4DEE370D4AAULL,
		0x4DDE2560EDFFF64DULL,
		0x32EE939A0204115FULL,
		0x748C27D9C3F6B45DULL,
		0x7C9C75EF4C0C5662ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200220E732248004ULL,
		0x0A10008A04180011ULL,
		0x251E413320A00112ULL,
		0x425004DC2020D08AULL,
		0x4D4E01600C812001ULL,
		0x128C821A02001007ULL,
		0x500C039180D4001DULL,
		0x108411684C044002ULL
	}};
	printf("Test Case 296\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD514C79C34544B68ULL,
		0x2668275EF2F94096ULL,
		0x612DC7F9904D5DF2ULL,
		0xC0C8F2462D845CB6ULL,
		0x88265FD8030A4053ULL,
		0x8603ED85FDCE6423ULL,
		0xE2AB6AA407B21DF5ULL,
		0x31E9340A4C004386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9ED54776B8D849EULL,
		0xE14EC10D442A6247ULL,
		0x566F9B1E0FA7F141ULL,
		0x4818D95EF6F6DA07ULL,
		0xD30536B1F7258DD3ULL,
		0x374CC0477705437AULL,
		0xF9575ED970E20767ULL,
		0x4C0A398A2433238BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8104441420040008ULL,
		0x2048010C40284006ULL,
		0x402D831800055140ULL,
		0x4008D04624845806ULL,
		0x8004169003000053ULL,
		0x0600C00575044022ULL,
		0xE0034A8000A20565ULL,
		0x0008300A04000382ULL
	}};
	printf("Test Case 297\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA78F2A20FD6625C9ULL,
		0x751BA1D833FD7FD3ULL,
		0x9C54A0C3F96B4BD6ULL,
		0xE7DC206E97EEFA9EULL,
		0x5F8B94526A17536DULL,
		0x1589111517B6EC20ULL,
		0x40BBEEB3141B89CEULL,
		0xEF255ADBF31C76B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB08B1FAC92728E9ULL,
		0x7B7D5486E36C44F1ULL,
		0x076B2ABD2091436FULL,
		0x633F46565257E651ULL,
		0x57B430F83958FC1BULL,
		0x4D31A52B1B65B0B4ULL,
		0xAE5795793933AD0FULL,
		0xF2DDDD6BFF9A61EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83082020C92620C9ULL,
		0x71190080236C44D1ULL,
		0x0440208120014346ULL,
		0x631C00461246E210ULL,
		0x5780105028105009ULL,
		0x050101011324A020ULL,
		0x001384311013890EULL,
		0xE205584BF31860A8ULL
	}};
	printf("Test Case 298\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x59974454DC7AC978ULL,
		0x27C3B4D1995603DFULL,
		0x7B68AE27D2C9D46BULL,
		0xD043A4402AB50435ULL,
		0xA13D23B11A4F7446ULL,
		0x98DA87710994FEF7ULL,
		0x5FABCE01CBDBE1F6ULL,
		0x5E5B55A5A62A06FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C62AED0FCEC4C15ULL,
		0x0A4A08EDB6D5D3A7ULL,
		0xCCAD707415F6B66AULL,
		0xF85B1878EE5C324BULL,
		0xD8C1CD5D76AA178DULL,
		0x0622C418DFF94400ULL,
		0x82C0C5EBBE67BB8BULL,
		0xA1BFBBD9C893BE9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08020450DC684810ULL,
		0x024200C190540387ULL,
		0x4828202410C0946AULL,
		0xD04300402A140001ULL,
		0x80010111120A1404ULL,
		0x0002841009904400ULL,
		0x0280C4018A43A182ULL,
		0x001B11818002069AULL
	}};
	printf("Test Case 299\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF6C92BF6C88E73D5ULL,
		0x0D7FBE55D59C7AADULL,
		0xDFB78277F80F9E55ULL,
		0x6E6164ED071D174BULL,
		0x7D8E58755333AD83ULL,
		0x364757224AC9CF12ULL,
		0x9146E603C369C5C7ULL,
		0x08D083537271B7C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1A9AC2EC77D9E65ULL,
		0xFE5C61F6CF23FA44ULL,
		0xB72597F57E5BD33CULL,
		0x78664CBE51CD18F1ULL,
		0x66A0D73C649EC594ULL,
		0xD17B17DC3774633BULL,
		0xFC2E768071FBE0C6ULL,
		0xFF92D52364C7D272ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF0892826C00C1245ULL,
		0x0C5C2054C5007A04ULL,
		0x97258275780B9214ULL,
		0x686044AC010D1041ULL,
		0x6480503440128580ULL,
		0x1043170002404312ULL,
		0x900666004169C0C6ULL,
		0x0890810360419240ULL
	}};
	printf("Test Case 300\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xECD502F95792D68AULL,
		0x6B8780E0DB45E1E9ULL,
		0xD883B02E4CC4FEC1ULL,
		0x47631D6E4FDCFE24ULL,
		0x0695DAEFFFA71997ULL,
		0x0FD600CE0A11C7FEULL,
		0x45A9E3D30BF9FA62ULL,
		0xBF24DBCA637DFFC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADE2CC659F4E381BULL,
		0x365FE0A83F9A39D1ULL,
		0xF80533ED09DC715BULL,
		0xD663B7743824F25DULL,
		0x6967832EBEAED320ULL,
		0xA22DEC03937AF543ULL,
		0x3AA701BDB3FF06C0ULL,
		0xF1D06D9489BC77F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACC000611702100AULL,
		0x220780A01B0021C1ULL,
		0xD801302C08C47041ULL,
		0x466315640804F204ULL,
		0x0005822EBEA61100ULL,
		0x020400020210C542ULL,
		0x00A1019103F90240ULL,
		0xB1004980013C77C2ULL
	}};
	printf("Test Case 301\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7F9AFE63C767DED4ULL,
		0x88F509E4BE51D994ULL,
		0x640A8C4A1C27566AULL,
		0xF640C0A29B71A20DULL,
		0x6299B4B067659013ULL,
		0xD6FA6F41F4BDB762ULL,
		0xD8F63B6C6CBA9B4DULL,
		0xF9EA324BE36A9877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA4B08A070FB929EULL,
		0x653686538354DAA5ULL,
		0x212F30FDDAC51FA0ULL,
		0xB0D288D0C5D9A75AULL,
		0x6F88F5A37A3DBE72ULL,
		0xB724A45608D9D498ULL,
		0x11ADF422C81F1E0AULL,
		0x495030A808B5B765ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A0A082040639294ULL,
		0x003400408250D884ULL,
		0x200A004818051620ULL,
		0xB04080808151A208ULL,
		0x6288B4A062259012ULL,
		0x9620244000999400ULL,
		0x10A43020481A1A08ULL,
		0x4940300800209065ULL
	}};
	printf("Test Case 302\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x22C32876E233F2ADULL,
		0xDAD9492323705E31ULL,
		0x564CB1BA28072DA6ULL,
		0x67113FEAB00B5A12ULL,
		0xC023310BAA48F97CULL,
		0x50F3AF4F4DB215E1ULL,
		0x439733C04127478CULL,
		0xD752D1F98763C735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB309A70D868E73A9ULL,
		0x194F30BAB80F36FAULL,
		0x0FA9B7A8964E982FULL,
		0x7BE748BF5F7828C5ULL,
		0xAF78680CE5EC9A11ULL,
		0xBBD45560375441CCULL,
		0x07E79C06694D4C4DULL,
		0xD9F3927AF99551C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22012004820272A9ULL,
		0x1849002220001630ULL,
		0x0608B1A800060826ULL,
		0x630108AA10080800ULL,
		0x80202008A0489810ULL,
		0x10D00540051001C0ULL,
		0x038710004105440CULL,
		0xD152907881014100ULL
	}};
	printf("Test Case 303\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA4926D8B44C09675ULL,
		0x078593D24DC8A2E2ULL,
		0x6D491DB9B49EE53BULL,
		0x1745C378B41FF06BULL,
		0x6950D67802C3D77AULL,
		0x9C68FA171A184CC5ULL,
		0xA89E202F335A6396ULL,
		0x0500AB0CDBA71FFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33CF10AC193761A2ULL,
		0x708CF04154AA040BULL,
		0xE7656EEB12D729ABULL,
		0x987F5765697B0664ULL,
		0x4137951FBBBFBACBULL,
		0x0D768D9E73FAE7AFULL,
		0xA1E4375F5C0AFAB4ULL,
		0x146D736068ED7C9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2082008800000020ULL,
		0x0084904044880002ULL,
		0x65410CA91096212BULL,
		0x10454360201B0060ULL,
		0x411094180283924AULL,
		0x0C60881612184485ULL,
		0xA084200F100A6294ULL,
		0x0400230048A51C9AULL
	}};
	printf("Test Case 304\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7DE0FCDD5C347181ULL,
		0x40CF0E117F23FEFEULL,
		0x5B5C730EE39E5632ULL,
		0x40831A8A440D77D0ULL,
		0x6935B7568217CDBBULL,
		0xDAD7BC7D914BFAF3ULL,
		0x964A9685EEFF22DCULL,
		0xC824EC3A6E072B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DFC7A16377CAD6EULL,
		0x6DD8210606ABE888ULL,
		0xF119A078FE50C1CCULL,
		0x52111B40D2EB9C8FULL,
		0x9797A4E9DE5F81C7ULL,
		0x12EE60C46ACF5EEBULL,
		0xE5860C58E85A82DDULL,
		0xB2FF6E8C084A7E5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DE0781414342100ULL,
		0x40C800000623E888ULL,
		0x51182008E2104000ULL,
		0x40011A0040091480ULL,
		0x0115A44082178183ULL,
		0x12C62044004B5AE3ULL,
		0x84020400E85A02DCULL,
		0x80246C0808022A10ULL
	}};
	printf("Test Case 305\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEE8444192263E22DULL,
		0x9BDE5CD83F7BE3EDULL,
		0x503D5088D67E7067ULL,
		0x3369F24BFCD3679EULL,
		0xD071AF45327658A4ULL,
		0x715C7B255AD793E6ULL,
		0xE291C31E1C60A243ULL,
		0xFEDFA3EAA0C9D41BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C179190910D87CULL,
		0x2E737AACC586C656ULL,
		0x4A2B7F384807708AULL,
		0x734A149243A39184ULL,
		0xAD3C88D5C68C72F0ULL,
		0xCAE462CC92D0F553ULL,
		0xD4C51F076E47B7C8ULL,
		0xBAF985F6291413A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008040190000C02CULL,
		0x0A5258880502C244ULL,
		0x4029500840067002ULL,
		0x3348100240830184ULL,
		0x80308845020450A0ULL,
		0x4044620412D09142ULL,
		0xC08103060C40A240ULL,
		0xBAD981E220001001ULL
	}};
	printf("Test Case 306\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1ACEFB2194622A3BULL,
		0x0AFD36EA10B6CBDAULL,
		0x2C0D1299852A398DULL,
		0xE7A12DD4052C8F4AULL,
		0xBEFC383F2FCAE681ULL,
		0x854EC5C491785BADULL,
		0x9F2A5D40F35C5778ULL,
		0xD32295801496E683ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF59AFE85584BFBULL,
		0xFD52FF996CCD634CULL,
		0x1CF7D6F50B9CF940ULL,
		0xE85AA04C0B3DE373ULL,
		0xFD984625F7067049ULL,
		0xDD94D28FB3A32B9EULL,
		0x6996B9F1DFCB86CCULL,
		0x9938145B9C589416ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AC49A2084400A3BULL,
		0x0850368800844348ULL,
		0x0C05129101083900ULL,
		0xE0002044012C8342ULL,
		0xBC98002527026001ULL,
		0x8504C08491200B8CULL,
		0x09021940D3480648ULL,
		0x9120140014108402ULL
	}};
	printf("Test Case 307\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD53C42FDF14BFBB3ULL,
		0x995CD7B56838884DULL,
		0x9BDF25B38307F59AULL,
		0x2CA237BB3CD77373ULL,
		0xC7102866622BBED1ULL,
		0xB6F91F46F46710DDULL,
		0xF8B0D9BE371F5ABEULL,
		0x04F8775E50CFD20FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6ECFC1F06DC5AA0ULL,
		0x8D8DF054779A6EFFULL,
		0x2DF78473ACAC0F73ULL,
		0x32DB2F26751C5581ULL,
		0xDA3EE80E501C9FE8ULL,
		0xACE7D63FE36C7FD1ULL,
		0xE00A24566AC336BBULL,
		0xA2E09BCE79776D65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC42C401D00485AA0ULL,
		0x890CD0146018084DULL,
		0x09D7043380040512ULL,
		0x2082272234145101ULL,
		0xC210280640089EC0ULL,
		0xA4E11606E06410D1ULL,
		0xE0000016220312BAULL,
		0x00E0134E50474005ULL
	}};
	printf("Test Case 308\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x26D374895BB9EAD8ULL,
		0x3468036CFCAE6293ULL,
		0x3FF80D3CDA0A6C8EULL,
		0xD66B9B4CB2D394E2ULL,
		0x6EF6666DAD67F952ULL,
		0x80E6A5930BA47527ULL,
		0x819A5AC510DB3CB3ULL,
		0xE08669835903B2BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x278E71EEAB21BFDAULL,
		0x55835B28401CBFA3ULL,
		0xDB55CE953E4AAE00ULL,
		0x40764399CCBC398FULL,
		0x24B1CFE2D0662CDFULL,
		0x8EF3735D5D22C662ULL,
		0x1299B26994924391ULL,
		0xF529D1A776916218ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x268270880B21AAD8ULL,
		0x14000328400C2283ULL,
		0x1B500C141A0A2C00ULL,
		0x4062030880901082ULL,
		0x24B0466080662852ULL,
		0x80E2211109204422ULL,
		0x0098124110920091ULL,
		0xE000418350012218ULL
	}};
	printf("Test Case 309\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA0E5CAE2E3C749DAULL,
		0xAA26E1CDA68E7257ULL,
		0x567B1280EC47EDEBULL,
		0x3CD48F7C2C62268CULL,
		0x92E118662C8E39E4ULL,
		0x797DD55EA8F634A0ULL,
		0x8C741E6ECAA11757ULL,
		0x278F1C177D0AC962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x211207DB62F8B18BULL,
		0xD1F1C88165490E54ULL,
		0xF3DAF35CA2E6C63EULL,
		0x21BB5793ECD30DB8ULL,
		0x9894268007CC5FF7ULL,
		0x776D8C59F85B9191ULL,
		0xAEC60C3FB6987AC3ULL,
		0xC80A37E1C232EB97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200002C262C0018AULL,
		0x8020C08124080254ULL,
		0x525A1200A046C42AULL,
		0x209007102C420488ULL,
		0x90800000048C19E4ULL,
		0x716D8458A8521080ULL,
		0x8C440C2E82801243ULL,
		0x000A14014002C902ULL
	}};
	printf("Test Case 310\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x219AC08CA68B9FC7ULL,
		0xFE89EE48A7E03863ULL,
		0xB251BADE5035291AULL,
		0xBF27DF12455BEA67ULL,
		0x0E1E83FDDF1C2920ULL,
		0x7CAD305FCE0E9215ULL,
		0xAB1CBD76F0C2FCEFULL,
		0xC0578878D5BA8081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF85FF96B868CD317ULL,
		0x0CD0FC427F71B5ADULL,
		0xD7E5ED9DD3430F46ULL,
		0x74CA666DC12BDFC8ULL,
		0x184B11E263375FCCULL,
		0xB8098DF713F12959ULL,
		0x728190C6E4E81435ULL,
		0xAD7EC320F77D51F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x201AC00886889307ULL,
		0x0C80EC4027603021ULL,
		0x9241A89C50010902ULL,
		0x34024600410BCA40ULL,
		0x080A01E043140900ULL,
		0x3809005702000011ULL,
		0x22009046E0C01425ULL,
		0x80568020D5380080ULL
	}};
	printf("Test Case 311\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF86EB1DA2371BCB4ULL,
		0xA8D11206C1676D83ULL,
		0x12CB44C807342484ULL,
		0xF08C932942A58E08ULL,
		0xBE5752E832182F3FULL,
		0xA9D7FD07EC58D38FULL,
		0xE2646109EBB38865ULL,
		0x7A550FEA4FDBAF51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF6DAECC74A5210ULL,
		0xB24841191D8B4C8BULL,
		0x224BE8CFF481AD23ULL,
		0x0F20B9AD4FBB2B51ULL,
		0xBD48085F97857B0EULL,
		0xCE66EBA24CB68321ULL,
		0x31A2A9DBD66E8C8EULL,
		0x4C7FACFDB291200FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF86690C803401010ULL,
		0xA040000001034C83ULL,
		0x024B40C804002400ULL,
		0x0000912942A10A00ULL,
		0xBC40004812002B0EULL,
		0x8846E9024C108301ULL,
		0x20202109C2228804ULL,
		0x48550CE802912001ULL
	}};
	printf("Test Case 312\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF6AEE882D3CC01B6ULL,
		0xB77241A9D1780816ULL,
		0xE53B6B24F71BB9D3ULL,
		0x0055CD15A0E19B59ULL,
		0x9FB4D7433847840BULL,
		0xE9AC3CA09DCAC1B8ULL,
		0xC1DE9E0C1197512AULL,
		0x2A0505086AB65F56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68CD72E5D45E29ABULL,
		0xEDD4DC068B83B579ULL,
		0x2E19745182830DCDULL,
		0x900CEE7F35136B6CULL,
		0xBEB7D230F9DC9162ULL,
		0x776C3CF66DA42725ULL,
		0x66A9D86705847B33ULL,
		0xEC1C8C09E0707CDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x608C6080D04C01A2ULL,
		0xA550400081000010ULL,
		0x24196000820309C1ULL,
		0x0004CC1520010B48ULL,
		0x9EB4D20038448002ULL,
		0x612C3CA00D800120ULL,
		0x4088980401845122ULL,
		0x2804040860305C56ULL
	}};
	printf("Test Case 313\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x580928919E12EAFFULL,
		0x2ACB553FFE912221ULL,
		0x132D2B2331D2EDCAULL,
		0x40FE31C172F4836CULL,
		0x5581512D14AF39B2ULL,
		0x92646B3DB33688E7ULL,
		0x01A90F75F12362EAULL,
		0x8213F098E9F9F399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6E2B0F72A9D4B0ULL,
		0xD13FAFBDF8B103C7ULL,
		0x74A9D61EBFF1470FULL,
		0x031D659EB1531E06ULL,
		0xFDB2E6A73ECCA881ULL,
		0xD07093C02B7B5F28ULL,
		0xBEFD499E28ADA101ULL,
		0xDA565C14F9574917ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x580828011200C0B0ULL,
		0x000B053DF8910201ULL,
		0x1029020231D0450AULL,
		0x001C218030500204ULL,
		0x55804025148C2880ULL,
		0x9060030023320820ULL,
		0x00A9091420212000ULL,
		0x82125010E9514111ULL
	}};
	printf("Test Case 314\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x40873791C84F7B26ULL,
		0xCA450301BDC8875AULL,
		0x142C963168B4F5A2ULL,
		0x69BEC7862EEE95E0ULL,
		0x321E20CB62003AA4ULL,
		0xC89C88BE639BC795ULL,
		0x81446DDEEFCCE4C0ULL,
		0xDF1483DEF2D851CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F873540CC92056ULL,
		0x9641B2BCB1F9212DULL,
		0x0A04EC7A6996B9CBULL,
		0x3E670B402DE368E2ULL,
		0x39CD12E941983DBDULL,
		0x7DD376961F018BCCULL,
		0x6AD09FE1C249E554ULL,
		0x66835BDD482AB4A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4080331008492006ULL,
		0x82410200B1C80108ULL,
		0x000484306894B182ULL,
		0x282603002CE200E0ULL,
		0x300C00C9400038A4ULL,
		0x4890009603018384ULL,
		0x00400DC0C248E440ULL,
		0x460003DC40081080ULL
	}};
	printf("Test Case 315\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFFCF6F328BDF78B9ULL,
		0x7468AAD0113E52D4ULL,
		0x08693419D65C2EDDULL,
		0x8A03D295EF7B0AE1ULL,
		0x713B0C3E82CA1CBBULL,
		0x0F04BB9AC3316C83ULL,
		0x2A3DF2F801CE5C5EULL,
		0x42FC3644B98AAEACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A6D0875AF043C4EULL,
		0xD53D44ED8E1E810EULL,
		0x3FABDE65F756C681ULL,
		0x7B739B464545F66AULL,
		0x58CD653B016F47FAULL,
		0x5329264012D49073ULL,
		0x47D41C55C03D5E46ULL,
		0x6C638FD38701F119ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A4D08308B043808ULL,
		0x542800C0001E0004ULL,
		0x08291401D6540681ULL,
		0x0A03920445410260ULL,
		0x5009043A004A04BAULL,
		0x0300220002100003ULL,
		0x02141050000C5C46ULL,
		0x406006408100A008ULL
	}};
	printf("Test Case 316\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDB9AD4F54B7C1A16ULL,
		0x560B60B4A279ED5CULL,
		0x25314DE5C951168DULL,
		0x5FB91D99088B2D83ULL,
		0xAA0971C2F6F5A79BULL,
		0xD6B7AA4C2DEA5DB0ULL,
		0x599B4931B6E38020ULL,
		0x8A33FB72C5C2CF35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB072DFE3E05BD444ULL,
		0xA3EC5A08C7DDDFCCULL,
		0xFE8AEB1F446D28EFULL,
		0xF84F0C600531B53DULL,
		0xBC0CE960541CA23CULL,
		0x135BACB6D9BD0B20ULL,
		0xDE9280DC8CC10CD2ULL,
		0x06B9F39BBFAB4A61ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9012D4E140581004ULL,
		0x020840008259CD4CULL,
		0x240049054041008DULL,
		0x58090C0000012501ULL,
		0xA80861405414A218ULL,
		0x1213A80409A80920ULL,
		0x5892001084C10000ULL,
		0x0231F31285824A21ULL
	}};
	printf("Test Case 317\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB8D6C3BB6C66310BULL,
		0x8A8941A2C62D704DULL,
		0x194ADFAB2D6BFA8AULL,
		0xC9B8471FF2379322ULL,
		0x9CD03E73880916CBULL,
		0xDDEA5DB52351CFB5ULL,
		0x5FC74D28A6319AC9ULL,
		0x1D0CA12F75CEB7E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E1FAD2AEC4EC11ULL,
		0xC46BF2CB909BFFD2ULL,
		0x391D077A3E715897ULL,
		0xB7466F2406CAF7A5ULL,
		0x0DAFB6203C042F1AULL,
		0x98FD1DF70A5E58ABULL,
		0x9DF4952BE7DB4F7AULL,
		0xCA50BAC5D5E81B56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB0C0C2922C442001ULL,
		0x8009408280097040ULL,
		0x1908072A2C615882ULL,
		0x8100470402029320ULL,
		0x0C8036200800060AULL,
		0x98E81DB5025048A1ULL,
		0x1DC40528A6110A48ULL,
		0x0800A00555C81340ULL
	}};
	printf("Test Case 318\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE469AEB4EABD4564ULL,
		0x547F9D3C881B27CFULL,
		0x21E9F107D8EAB8DDULL,
		0xF9B237F6BBAA4926ULL,
		0x1C3C5DD1601F09C2ULL,
		0x425828EFEF8E4768ULL,
		0xA649DFDDDC5B4C06ULL,
		0x1A8E3C18324AAAF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7FD95DBB9E381CULL,
		0xFEA899C345009E3AULL,
		0x30A338CED366BB8CULL,
		0x7BEB239E98E85C02ULL,
		0xE74252F6AD59AD00ULL,
		0x1914C76402F51B41ULL,
		0x02A9100CC088B7CFULL,
		0x2011DF05347FEC57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0698814AA9C0004ULL,
		0x542899000000060AULL,
		0x20A13006D062B88CULL,
		0x79A2239698A84802ULL,
		0x040050D020190900ULL,
		0x0010006402840340ULL,
		0x0209100CC0080406ULL,
		0x00001C00304AA852ULL
	}};
	printf("Test Case 319\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x718B950FC1574CC4ULL,
		0xC6B41F74C7CC4C28ULL,
		0x81736F9C588CC65DULL,
		0x7F152C00642F80A4ULL,
		0xD7AF5D3011641479ULL,
		0xE2A3B5A782101CC5ULL,
		0xBDD48997B8CE6FD1ULL,
		0xC1A75D11E9298D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBF11C1EE10AD50ULL,
		0xB8A5ED245D74F594ULL,
		0xDC3382BC81658A08ULL,
		0xF99D9DB5310D95A2ULL,
		0x4967CA4C28B61D96ULL,
		0x18B8A53CE3339FEDULL,
		0x0EB85C25917F2CDEULL,
		0x5D06C7BE8D018DE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x118B1101C0100C40ULL,
		0x80A40D2445444400ULL,
		0x8033029C00048208ULL,
		0x79150C00200D80A0ULL,
		0x4127480000241410ULL,
		0x00A0A52482101CC5ULL,
		0x0C900805904E2CD0ULL,
		0x4106451089018D61ULL
	}};
	printf("Test Case 320\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x49FFB52EDFFDE0FCULL,
		0x8A724A386243E188ULL,
		0x4C2BB0EC5B38D7ABULL,
		0x1DC04D028E6B8461ULL,
		0x364B6A84A7FE6225ULL,
		0x2C185A09ED7F0DACULL,
		0x15DCCFD1D4C266BEULL,
		0x45AC0C4696AC3AFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027EE73190F51AA0ULL,
		0x3BE5C3DBA54738E1ULL,
		0x019A3EEC63C33640ULL,
		0xDF8E3E3C856188B3ULL,
		0x403ED63B721DD171ULL,
		0x7EFE1535B49778C3ULL,
		0x69D0C3DD51C06A1AULL,
		0xEBD5ABC6018C58AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x007EA52090F500A0ULL,
		0x0A60421820432080ULL,
		0x000A30EC43001600ULL,
		0x1D800C0084618021ULL,
		0x000A4200221C4021ULL,
		0x2C181001A4170880ULL,
		0x01D0C3D150C0621AULL,
		0x41840846008C18AEULL
	}};
	printf("Test Case 321\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7ACB08C8C78B1D13ULL,
		0xE1A454DDF3B5892AULL,
		0x329AB3D10CEF9550ULL,
		0x47AF335A14B55FCFULL,
		0x79CB42FE30C2D86AULL,
		0xC99CA705FFFC3650ULL,
		0x81E175AF9477147CULL,
		0xCD7F213C29099CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C6BA3754D4F959ULL,
		0xE723C0BF4D4F5DC2ULL,
		0xF3608E8354E604C7ULL,
		0x47FBA2276A80171BULL,
		0xDE9356387452C6E7ULL,
		0xCABAE5D71B7F7636ULL,
		0xF1B68F1E49082343ULL,
		0xD5D6C93659D324C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40C2080044801911ULL,
		0xE120409D41050902ULL,
		0x3200828104E60440ULL,
		0x47AB22020080170BULL,
		0x588342383042C062ULL,
		0xC898A5051B7C3610ULL,
		0x81A0050E00000040ULL,
		0xC556013409010480ULL
	}};
	printf("Test Case 322\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x371CEE18B780E9DBULL,
		0x57F8A92796133184ULL,
		0xFA4BC60DFC7BA57EULL,
		0x6E55DCA3F8D5E615ULL,
		0x4940F46AE7B15A86ULL,
		0x0AAE4564EBDEB268ULL,
		0x6B5F6D431D0F840CULL,
		0x5F97792A4583AFF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF572815ABB8DFD03ULL,
		0x1A6BA55238DD185CULL,
		0xD13DF4392F3E57DDULL,
		0x4DF7734C7210537BULL,
		0xD703C71A4938ACD7ULL,
		0xBF500FD5EFFB64EBULL,
		0x11D160FB7197BF20ULL,
		0x6A5F9EE92B1DA922ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35108018B380E903ULL,
		0x1268A10210111004ULL,
		0xD009C4092C3A055CULL,
		0x4C55500070104211ULL,
		0x4100C40A41300886ULL,
		0x0A000544EBDA2068ULL,
		0x0151604311078400ULL,
		0x4A1718280101A920ULL
	}};
	printf("Test Case 323\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF15B5916BF7B4CD8ULL,
		0x3DD0D4B27AC03183ULL,
		0xC60A76DD35E3DD3BULL,
		0xD32FD300007F445DULL,
		0xAC4FD8132E4ED913ULL,
		0x33378DB011C059A6ULL,
		0x40BDDCB78EB83EFDULL,
		0x6E4771065CC50F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A653F723EDBA77ULL,
		0x6FBC00DEF89E6048ULL,
		0x60AF51B9137744C7ULL,
		0x820677235157CB73ULL,
		0x5E0E44E2216E6EABULL,
		0xE72EAFC826291BD4ULL,
		0x4995462B49DCE85FULL,
		0xE2EC9E08A12FC3F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4002511623690850ULL,
		0x2D90009278802000ULL,
		0x400A509911634403ULL,
		0x8206530000574051ULL,
		0x0C0E4002204E4803ULL,
		0x23268D8000001984ULL,
		0x409544230898285DULL,
		0x6244100000050320ULL
	}};
	printf("Test Case 324\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3F9303374DF125B9ULL,
		0x537055E2255BFA5BULL,
		0xCE705E493AAAF5F2ULL,
		0x6B77F16C5EBA824CULL,
		0xB55BE19CF62865F5ULL,
		0x3CEE7757C6024B0EULL,
		0x67EEF0BE7A10A456ULL,
		0x6A9F51F8C759D6C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F02B2CA47AB18EFULL,
		0x7F57868921BF6F9DULL,
		0x808FAA4B9E8E438AULL,
		0xE1CE6924C6C10969ULL,
		0x945D6569D7845079ULL,
		0x81482624D623CD0DULL,
		0x6E8F4282D6A111BEULL,
		0x0BF2C02502B21543ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F02020245A100A9ULL,
		0x53500480211B6A19ULL,
		0x80000A491A8A4182ULL,
		0x6146612446800048ULL,
		0x94596108D6004071ULL,
		0x00482604C602490CULL,
		0x668E408252000016ULL,
		0x0A92402002101440ULL
	}};
	printf("Test Case 325\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB259C1A88F898209ULL,
		0x024ECEDD096AABDAULL,
		0x466B8DE56A9A5751ULL,
		0xBC7F21D876588195ULL,
		0x340C8EB5F5B42414ULL,
		0x7A153865D3C52811ULL,
		0x473718B4EA11F8C1ULL,
		0x5F2FD6C3A906979CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28514306AF771292ULL,
		0x5E7FC98E88E5B7E8ULL,
		0x81ACC851AB07294EULL,
		0x9DFA771B0A7D23E8ULL,
		0x212211490EED5C9DULL,
		0xA98CD0225A0E8925ULL,
		0xDDE8E19CE03D4EECULL,
		0x1A17BD7E512DD5CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x205141008F010200ULL,
		0x024EC88C0860A3C8ULL,
		0x002888412A020140ULL,
		0x9C7A211802580180ULL,
		0x2000000104A40414ULL,
		0x2804102052040801ULL,
		0x45200094E01148C0ULL,
		0x1A0794420104958CULL
	}};
	printf("Test Case 326\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x39C1BB8E093E2341ULL,
		0x105D99DCF9BE4D01ULL,
		0x56C020FCC17821D7ULL,
		0x82ADB611287F7D6BULL,
		0x113B43DACAFD311EULL,
		0x39F35E0A0900EEB9ULL,
		0x4A83E228626691C1ULL,
		0x06642E829AB542A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BD2017D84B105DEULL,
		0xE9E0E788BE49429BULL,
		0x85CC6C1993461614ULL,
		0xCF1BAB33098D0EAEULL,
		0x1512AE0E0EC1D251ULL,
		0x7522084623D50E5BULL,
		0xF376A0AB21E4126CULL,
		0x0AC9973166434CFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29C0010C00300140ULL,
		0x00408188B8084001ULL,
		0x04C0201881400014ULL,
		0x8209A211080D0C2AULL,
		0x1112020A0AC11010ULL,
		0x3122080201000E19ULL,
		0x4202A02820641040ULL,
		0x02400600020140A1ULL
	}};
	printf("Test Case 327\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x77DF3BD788CF766AULL,
		0x09A7D346103285E1ULL,
		0x96A6C952EEE71AEFULL,
		0x74EA1521FFABA286ULL,
		0x231A19711B391F61ULL,
		0xB4D20562A540DC21ULL,
		0x85C737577756B4A0ULL,
		0x9AF653E1F19ABC1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9556FDDD6ADF99AULL,
		0xD3F4F32F40DF17A1ULL,
		0x6DC1C36B97F2F3B3ULL,
		0xF790DA91AB90D064ULL,
		0x9C4D11D638D8AF1DULL,
		0x37D35D00BD250CC3ULL,
		0x3755638775963B89ULL,
		0x203CF86C51C28BE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41552BD5808D700AULL,
		0x01A4D306001205A1ULL,
		0x0480C14286E212A3ULL,
		0x74801001AB808004ULL,
		0x0008115018180F01ULL,
		0x34D20500A5000C01ULL,
		0x0545230775163080ULL,
		0x0034506051828802ULL
	}};
	printf("Test Case 328\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5991707BA39CEC08ULL,
		0xF47A25A66711EA9AULL,
		0x85D1B9E3D55BCF0CULL,
		0x90B85AEFF63619FBULL,
		0xCBDC4800D7148D1CULL,
		0xF23ED6CFE6F97E76ULL,
		0x6A9BC1D7A5C6BF5AULL,
		0xC95CD3630D8CAC7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E1F2A539506B67ULL,
		0x3C33349D9E48D41AULL,
		0x0E56EB8764A9806AULL,
		0x57400C8DE179B14DULL,
		0xBB54296084F8EDC3ULL,
		0xE46F2DD7E3F8DBAEULL,
		0x734A0F2BD060E2B4ULL,
		0xBDD4F2E71E57F25FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5081702121106800ULL,
		0x343224840600C01AULL,
		0x0450A98344098008ULL,
		0x1000088DE0301149ULL,
		0x8B54080084108D00ULL,
		0xE02E04C7E2F85A26ULL,
		0x620A01038040A210ULL,
		0x8954D2630C04A05EULL
	}};
	printf("Test Case 329\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE5A11496E9471E64ULL,
		0xBE289D32AB3135B1ULL,
		0x6FCBB5B444A428EAULL,
		0x3F8EBB8115059E6FULL,
		0x2B3B44ED2528F8C7ULL,
		0xB863CAC9F0BB5359ULL,
		0xFE29BE5832D298C9ULL,
		0xB26C98EF5643086EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x098025B5B35807B7ULL,
		0xFBC81659710437B2ULL,
		0x4D4141AA4DA5A183ULL,
		0x604487F945245E2CULL,
		0x525DBB6ADCDEABFCULL,
		0xD41B2B79AB39550CULL,
		0x36E7519BB789D8A0ULL,
		0x8543030634571D2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01800494A1400624ULL,
		0xBA081410210035B0ULL,
		0x4D4101A044A42082ULL,
		0x2004838105041E2CULL,
		0x021900680408A8C4ULL,
		0x90030A49A0395108ULL,
		0x3621101832809880ULL,
		0x804000061443082AULL
	}};
	printf("Test Case 330\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7F0C80177DDC100FULL,
		0x81B26E680F40A595ULL,
		0x3597B517969AB5D4ULL,
		0x4F67D5139BED601BULL,
		0xA6ACB27BA2939803ULL,
		0xD8F646B37D2E743AULL,
		0x18A21164A4FBD0C4ULL,
		0x34BF0701DCF02AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF0F38FB5200CFB8ULL,
		0xFAF03B9D2561F356ULL,
		0x735950E0BE880508ULL,
		0xB15F31D10207D9FCULL,
		0x7B6DB1F1A2947780ULL,
		0x0F3FBC3B478E2431ULL,
		0x0A07C74C618DD683ULL,
		0x5891AD6DA4514A68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F0C001350000008ULL,
		0x80B02A080540A114ULL,
		0x3111100096880500ULL,
		0x0147111102054018ULL,
		0x222CB071A2901000ULL,
		0x08360433450E2430ULL,
		0x080201442089D080ULL,
		0x1091050184500A60ULL
	}};
	printf("Test Case 331\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBDCFEC37F7422FF6ULL,
		0x8F5E289AC5BAE1D8ULL,
		0x64F6AEE6EB13F379ULL,
		0x428C880555D33038ULL,
		0x7A40C274AFC534E2ULL,
		0x9D3F93B3B5355368ULL,
		0x77BF3CBDD54EE780ULL,
		0xA2EFF98B86942BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEFF6C950862AF9ULL,
		0xC60C0A858A3EB7E3ULL,
		0x05F7C77FF24F282CULL,
		0x114BA1F6DF4F080FULL,
		0x9FE45CC53D8B0194ULL,
		0x9F114C724B70502EULL,
		0x4B8494595DDBE9BCULL,
		0x83A6F2E85FF70346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DCFE40150022AF0ULL,
		0x860C0880803AA1C0ULL,
		0x04F68666E2032028ULL,
		0x0008800455430008ULL,
		0x1A4040442D810080ULL,
		0x9D11003201305028ULL,
		0x43841419554AE180ULL,
		0x82A6F08806940340ULL
	}};
	printf("Test Case 332\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF2FFA6DC30190185ULL,
		0xAC5B650BD874FBBDULL,
		0x08731088BCB5FD71ULL,
		0xD4D49F416FE078C1ULL,
		0xBD166929CE38C136ULL,
		0x19BFE3F6BBD059E5ULL,
		0x8112DB4C6C492902ULL,
		0x1DF6DF45247235FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FF280EA4ECA540BULL,
		0x8E5B07867EF13032ULL,
		0xD999B81F14FDA3D9ULL,
		0x04694DD01CF5B453ULL,
		0xDD0E4CA108F2AC29ULL,
		0x339ED4109C7CECE1ULL,
		0x93A1067D05A9FA24ULL,
		0xF3807FC779300903ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92F280C800080001ULL,
		0x8C5B050258703030ULL,
		0x0811100814B5A151ULL,
		0x04400D400CE03041ULL,
		0x9D06482108308020ULL,
		0x119EC010985048E1ULL,
		0x8100024C04092800ULL,
		0x11805F4520300103ULL
	}};
	printf("Test Case 333\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6788CB1BC2CD2C16ULL,
		0x83B8A959CA563817ULL,
		0x8F4C085D4A35DAA0ULL,
		0x1BEDDD22DB40B8BEULL,
		0x052FA1447C5CC337ULL,
		0x095E49AA8D809334ULL,
		0xE8E4E8A84745CD15ULL,
		0x9A59B35D4C62766EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC730F04EDE3E161ULL,
		0x6727DE75CA7AE14DULL,
		0x8857E1B841A80EFEULL,
		0xAC4F01C40C3A3D03ULL,
		0xC5A6AEDD61DF8772ULL,
		0xE7DE3E060ECC1703ULL,
		0x8220B99364C3D57DULL,
		0x29160DABE84B8498ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44000B00C0C12000ULL,
		0x03208851CA522005ULL,
		0x8844001840200AA0ULL,
		0x084D010008003802ULL,
		0x0526A044605C8332ULL,
		0x015E08020C801300ULL,
		0x8020A8804441C515ULL,
		0x0810010948420408ULL
	}};
	printf("Test Case 334\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7D766D16C47F2575ULL,
		0x7C4AA6554E57D1C9ULL,
		0xB9277AE98D1CBB93ULL,
		0x84DA970422A79AE3ULL,
		0xCA97BD86F3A9AF95ULL,
		0x825CA25B037E11FCULL,
		0x26125269EC471D4CULL,
		0xBB6A3B08A4814841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFF9900E1D077C0EULL,
		0x00C99126419A4E5FULL,
		0x8EB7D1641539E307ULL,
		0xF09A0164B4C7E2E0ULL,
		0x144360779DD06B57ULL,
		0x012B737E756492C1ULL,
		0x44A6960D9934D173ULL,
		0x947D49F4EA5EB097ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D70000604072404ULL,
		0x0048800440124049ULL,
		0x882750600518A303ULL,
		0x809A0104208782E0ULL,
		0x0003200691802B15ULL,
		0x0008225A016410C0ULL,
		0x0402120988041140ULL,
		0x90680900A0000001ULL
	}};
	printf("Test Case 335\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0C45CD87481ACCA3ULL,
		0x7888F267DB5DC3ACULL,
		0xADD74776E39DF7FFULL,
		0x1AC3C2336A17A470ULL,
		0x700543943F38BB94ULL,
		0x640026BDDEC325FDULL,
		0x6C6DA0FF7093DD4AULL,
		0x0F5281DB3550E8F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66F024C0E52562B8ULL,
		0x60432E469A8C308CULL,
		0x1D38FE1F43417CD9ULL,
		0x0BB05F3F18B08546ULL,
		0xAE6CB96D18DFC6CCULL,
		0x8F88889A3A065525ULL,
		0xFC2547722C5ED6C9ULL,
		0xA5BB1D6B4BB9975DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04400480400040A0ULL,
		0x600022469A0C008CULL,
		0x0D104616430174D9ULL,
		0x0A80423308108440ULL,
		0x2004010418188284ULL,
		0x040000981A020525ULL,
		0x6C2500722012D448ULL,
		0x0512014B01108058ULL
	}};
	printf("Test Case 336\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8C40D84EE631DB03ULL,
		0x95D135F2C3C11D92ULL,
		0xD50A190EDB797C3EULL,
		0x3849D5C557D302B5ULL,
		0x5880626956323572ULL,
		0x7AA5D51C678161B2ULL,
		0x409E8D55E3DE7168ULL,
		0xDA27B37D1D8DE2A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A331FCA1166B99ULL,
		0x1761A2510D3046B8ULL,
		0xCD4B53FFFDBB2807ULL,
		0x98891EECD1878F7BULL,
		0x3EA4DB3C06EDFB6BULL,
		0x1760E4B81C4ABC5DULL,
		0xE29FE3E124081FD3ULL,
		0xD3E3CA6A9EB473E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8000104CA0104B01ULL,
		0x1541205001000490ULL,
		0xC50A110ED9392806ULL,
		0x180914C451830231ULL,
		0x1880422806203162ULL,
		0x1220C41804002010ULL,
		0x409E814120081140ULL,
		0xD22382681C8462A0ULL
	}};
	printf("Test Case 337\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x559595A1FB57E9A2ULL,
		0x01A4C454E57D7BE8ULL,
		0x46C8E93C809D562DULL,
		0x385B7FE0B933893BULL,
		0x5B55702BA927ED17ULL,
		0x8CDF09D69CB4D94AULL,
		0x4BD16793C7AC33D9ULL,
		0x4E48D0049C77F2B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA755E6BA09CFB768ULL,
		0xF3B6B96670ED2F8DULL,
		0xA58A44C3B14B6FDDULL,
		0xB726DEC134DF685BULL,
		0x46A52318B2287853ULL,
		0x6727BF64BEF2C70FULL,
		0x3494A68EA9204F85ULL,
		0xE0A6E174E1014360ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x051584A00947A120ULL,
		0x01A48044606D2B88ULL,
		0x048840008009460DULL,
		0x30025EC03013081BULL,
		0x42052008A0206813ULL,
		0x040709449CB0C10AULL,
		0x0090268281200381ULL,
		0x4000C00480014220ULL
	}};
	printf("Test Case 338\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD4209800A365BD3CULL,
		0x1ED9F2339C6A226EULL,
		0x81D8C1DCCFF08602ULL,
		0x5F45DD8EC520FDB7ULL,
		0x850921B9B88CE5EBULL,
		0xF2803905C7B174D3ULL,
		0xB325270197FA8D80ULL,
		0xAD5B438D8180CA15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x960C45FA23C99456ULL,
		0xE4BD72486C0C1C56ULL,
		0x717DD96DB863C583ULL,
		0x1562C4BECEA7C00DULL,
		0xD95527E9D54186B6ULL,
		0x9C0C718404E103DBULL,
		0x2B432EBB025E105AULL,
		0x085957FF34CB5971ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9400000023419414ULL,
		0x049972000C080046ULL,
		0x0158C14C88608402ULL,
		0x1540C48EC420C005ULL,
		0x810121A9900084A2ULL,
		0x9000310404A100D3ULL,
		0x23012601025A0000ULL,
		0x0859438D00804811ULL
	}};
	printf("Test Case 339\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9FC287266C9A4F89ULL,
		0x9C021EA29142A3DEULL,
		0x046F8D4258E5EFCBULL,
		0x9E0AB2C31F5E39EAULL,
		0x4A5E1F3792F02A2BULL,
		0x402D66B3B0E49344ULL,
		0x5CCC6B7960A7E409ULL,
		0x66DFA0E679E98E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DED9B10D45169F4ULL,
		0xE5E8B2787DFB0F5DULL,
		0x609F6DDD33A9D6C6ULL,
		0xC07312DE8DED3ED2ULL,
		0x9539C4D054F6B806ULL,
		0x557AF30C1DB3D7A8ULL,
		0x83BA64F3B93CCC37ULL,
		0x44FC707F7253A3B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DC0830044104980ULL,
		0x840012201142035CULL,
		0x000F0D4010A1C6C2ULL,
		0x800212C20D4C38C2ULL,
		0x0018041010F02802ULL,
		0x4028620010A09300ULL,
		0x008860712024C401ULL,
		0x44DC206670418214ULL
	}};
	printf("Test Case 340\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC82FC19CAA5F1255ULL,
		0xC00542B58800CF36ULL,
		0xEEACBD1C7BB7F3D1ULL,
		0x9D7C7409AF072610ULL,
		0x9675ADC93CEE4AAFULL,
		0xD0E6CFACD9F71D28ULL,
		0xBEEA778101DD84ECULL,
		0x09B181D9CFC8DC56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2F9DEEBF2DAACD3ULL,
		0xF56414B5A2ACA63AULL,
		0xC84A7430A0C13253ULL,
		0xAAA29FD81B5C5C73ULL,
		0x12AF77B1DE8EAE01ULL,
		0x9A74596863E9201CULL,
		0x4409D70107BCB439ULL,
		0x0992A11F1AB9B0AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC029C088A25A0051ULL,
		0xC00400B580008632ULL,
		0xC808341020813251ULL,
		0x882014080B040410ULL,
		0x122525811C8E0A01ULL,
		0x9064492841E10008ULL,
		0x04085701019C8428ULL,
		0x099081190A889006ULL
	}};
	printf("Test Case 341\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9E5A3A14F6A8E032ULL,
		0x84F14029E960BCCDULL,
		0xF5EE6073D1B22BCAULL,
		0x08E3ABD5C2ACD109ULL,
		0x833FC7F8835474F2ULL,
		0x41A22E9EA2B45C2AULL,
		0x6522BC31EF2F44D8ULL,
		0x587CABD614CA1C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D08E02319C979B0ULL,
		0xB890805BD2986B58ULL,
		0x39C2B4591803507FULL,
		0x95B12A102809E044ULL,
		0x00EF8E65D9FC6E62ULL,
		0x473138C1DB3479A8ULL,
		0xB4B4ACF41A41BD3DULL,
		0xD16D87DC958425BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C08200010886030ULL,
		0x80900009C0002848ULL,
		0x31C220511002004AULL,
		0x00A12A100008C000ULL,
		0x002F866081546462ULL,
		0x4120288082345828ULL,
		0x2420AC300A010418ULL,
		0x506C83D414800412ULL
	}};
	printf("Test Case 342\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x286033EDE5F4E1DAULL,
		0x77CC3C96FED8F2B9ULL,
		0xB0B57620FBAE0DC6ULL,
		0xE79078B997F755E0ULL,
		0x84F2804A3D057BE6ULL,
		0x9CD5E6C49D73D39FULL,
		0xFA4CA46C9F031E9BULL,
		0x3F68EBFEF555081EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF17840C8CFBE3EULL,
		0x75349E5D146E4E3EULL,
		0x2FF47A3AC6AF8FF1ULL,
		0x01EE2532AF04BEB2ULL,
		0xD7A038A01C309294ULL,
		0x30DDB6A500093566ULL,
		0x816BF2F00F345377ULL,
		0x75B138F462540366ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08603040C0C4A01AULL,
		0x75041C1414484238ULL,
		0x20B47220C2AE0DC0ULL,
		0x01802030870414A0ULL,
		0x84A000001C001284ULL,
		0x10D5A68400011106ULL,
		0x8048A0600F001213ULL,
		0x352028F460540006ULL
	}};
	printf("Test Case 343\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAC3DB84B63AB14BEULL,
		0x57C186BB36735841ULL,
		0x0B91899518F93D29ULL,
		0x9C6262808FA5A577ULL,
		0x0B8A890C7F12B731ULL,
		0x7DE64A9330B16973ULL,
		0x261F1D002213C76AULL,
		0x79980892FE007EE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x268974A67E2EC519ULL,
		0x706AA3236C5526B7ULL,
		0x6622BB4434A47757ULL,
		0xDAE8302C1A4C1882ULL,
		0x786DB9C673B37FEDULL,
		0xAEB3B89581653DA1ULL,
		0x690CC24E116F0065ULL,
		0xE44ECA009FE016F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24093002622A0418ULL,
		0x5040822324510001ULL,
		0x0200890410A03501ULL,
		0x986020000A040002ULL,
		0x0808890473123721ULL,
		0x2CA2089100212921ULL,
		0x200C000000030060ULL,
		0x600808009E0016E5ULL
	}};
	printf("Test Case 344\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x17104BBD64F6D07EULL,
		0x960F3DE915EF6247ULL,
		0x0633CB1766E79100ULL,
		0x7FE4EA761A869FF7ULL,
		0xE326B7F5782C8E73ULL,
		0x4C3243D9D82D8C0FULL,
		0xA00C85535E98B588ULL,
		0x7520974F682D908FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89C71657FC82F158ULL,
		0xA9EA31134094A514ULL,
		0xE02CB0352208E15BULL,
		0xE08F0B5023621BF0ULL,
		0xAB902CB1F64EA920ULL,
		0x21965997678B94D3ULL,
		0xA1611E0C0CA0C965ULL,
		0xF3D761163E0809ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010002156482D058ULL,
		0x800A310100842004ULL,
		0x0020801522008100ULL,
		0x60840A5002021BF0ULL,
		0xA30024B1700C8820ULL,
		0x0012419140098403ULL,
		0xA00004000C808100ULL,
		0x710001062808008BULL
	}};
	printf("Test Case 345\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB6E81D7B03EA4B58ULL,
		0x020F5561F7A0FAB4ULL,
		0xEE09D38D351F0D9BULL,
		0x2ADD595A1EA5E35EULL,
		0xDAFCDC1376D390DEULL,
		0x0FEA6B831BA981D5ULL,
		0x083EE6B2F1B46E65ULL,
		0xF9ACC71236D25C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB86B8A388988E91ULL,
		0x98CA275B0C37F5F3ULL,
		0x27313D6AF4FAC3A8ULL,
		0xC6AAC6E84B206B3BULL,
		0xF0AE70FA27D2DF45ULL,
		0xDBDC95BDFDD19E60ULL,
		0xD5AA848F0D031FF1ULL,
		0x6EE570C41AF7F63EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8280182300880A10ULL,
		0x000A05410420F0B0ULL,
		0x26011108341A0188ULL,
		0x028840480A20631AULL,
		0xD0AC501226D29044ULL,
		0x0BC8018119818040ULL,
		0x002A848201000E61ULL,
		0x68A4400012D25424ULL
	}};
	printf("Test Case 346\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFB7A6910380067EFULL,
		0x1C0F8EC77D388D16ULL,
		0x3438C8EF747EC3FCULL,
		0x1D029B4BD89F0BF6ULL,
		0x8CCDB7D9109B5813ULL,
		0xAC82D8B40352DE92ULL,
		0x6E057689290A5459ULL,
		0x6E4479DDDF961E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E719A0C0034321EULL,
		0xEE78771CE87AD751ULL,
		0xD61267580DF738E2ULL,
		0xF6C1F7C2F1DC42F1ULL,
		0x7D69040B85F7119CULL,
		0x657548D5CDDD101EULL,
		0xD45C4DE4F8848865ULL,
		0x8044083182037C35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A7008000000220EULL,
		0x0C08060468388510ULL,
		0x14104048047600E0ULL,
		0x14009342D09C02F0ULL,
		0x0C49040900931010ULL,
		0x2400489401501012ULL,
		0x4404448028000041ULL,
		0x0044081182021C15ULL
	}};
	printf("Test Case 347\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF7C1649AAEAD743BULL,
		0xEA4758B4524A62BBULL,
		0x12CAB4C40436EF1EULL,
		0x5AA3C3C1F57F9458ULL,
		0x377A24035F34CE11ULL,
		0x6E0BA1295830D020ULL,
		0x6E57CEC0CB89191FULL,
		0x984AD93E6D0F756EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D3D60C473F00741ULL,
		0x1E817E6849AD64CBULL,
		0x9872A736455E3689ULL,
		0xE4D2BE32C69DE222ULL,
		0x57089C82F9DB58EFULL,
		0x9C95DD523F900AFDULL,
		0x0C10092C5E4CF571ULL,
		0xF758D659AF70BCFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8501608022A00401ULL,
		0x0A0158204008608BULL,
		0x1042A40404162608ULL,
		0x40828200C41D8000ULL,
		0x1708040259104801ULL,
		0x0C01810018100020ULL,
		0x0C1008004A081111ULL,
		0x9048D0182D00346AULL
	}};
	printf("Test Case 348\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAC9584E1EA543AD8ULL,
		0x134990A314BAAA94ULL,
		0x163DF61AD38F59E8ULL,
		0xCDD957EE2DD9C6C4ULL,
		0xA9F33B3FB3F6EA26ULL,
		0xBA6D38EAB66D3F10ULL,
		0x1B5FF83529A96DA8ULL,
		0x0219C0CF1199E590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB4DD149678557E7ULL,
		0xF766DB7360EB05E6ULL,
		0x87E62F594D0E3E81ULL,
		0xA38E471A20BFE4E1ULL,
		0xE39318D9F99D0B9FULL,
		0x9B2809A9658B257FULL,
		0x647D704C3938E130ULL,
		0x4C68100E71B5A713ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8058041620412C0ULL,
		0x1340902300AA0084ULL,
		0x06242618410E1880ULL,
		0x8188470A2099C4C0ULL,
		0xA1931819B1940A06ULL,
		0x9A2808A824092510ULL,
		0x005D700429286120ULL,
		0x0008000E1191A510ULL
	}};
	printf("Test Case 349\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x23F79457C259F7E5ULL,
		0x6DE1F76360E3B72AULL,
		0xA249BB6F11A4A861ULL,
		0x980B4B8A546BD6C2ULL,
		0xA70996BE7A9CCE14ULL,
		0x16B9DB280542F2F2ULL,
		0x2B02AED51F5B0031ULL,
		0x1EEB655D76268D9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CC5F9A7BD5BEE0ULL,
		0x8B6EFA6F10B51342ULL,
		0x00B0D079E94B641EULL,
		0x0B2F6D028A477264ULL,
		0x2315D44E86B46982ULL,
		0x4414D1A9777C2151ULL,
		0xC4135A4530705BF2ULL,
		0x6A9DBEC8D5DED63BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22C414124251B6E0ULL,
		0x0960F26300A11302ULL,
		0x0000906901002000ULL,
		0x080B490200435240ULL,
		0x2301940E02944800ULL,
		0x0410D12805402050ULL,
		0x00020A4510500030ULL,
		0x0A8924485406841AULL
	}};
	printf("Test Case 350\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFE97D8D13A681BACULL,
		0xA49D18A67AD151FCULL,
		0x88D7E61656CE2D6CULL,
		0xFDB042A9110AAD03ULL,
		0xA50114FE0B4D16B7ULL,
		0xC3D64770EB6ADDB8ULL,
		0x7D1B43EE261831CEULL,
		0x77EC07CF3394F4EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x268FD854E9D64B19ULL,
		0x11A7A22C3F3BB895ULL,
		0x49A239258EA184C8ULL,
		0xE98F7E1D4377CA37ULL,
		0x1CDD8F743C9E2FD0ULL,
		0x785FD5F6BE7D1B3EULL,
		0x36BFD53426766A69ULL,
		0x6C9A347464E7FBD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2687D85028400B08ULL,
		0x008500243A111094ULL,
		0x0882200406800448ULL,
		0xE980420901028803ULL,
		0x04010474080C0690ULL,
		0x40564570AA681938ULL,
		0x341B412426102048ULL,
		0x648804442084F0C1ULL
	}};
	printf("Test Case 351\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF45E1FAE3C0D6F17ULL,
		0xA3ABB37F51946E3CULL,
		0xA7607143AA8C5212ULL,
		0xA3DD1AB57233BF34ULL,
		0xA35AAC7962D6A2B0ULL,
		0xBC94A5F1190B2B96ULL,
		0xCBADDB3B2C673E30ULL,
		0x4F69A2BCE4DEF5EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088A533F7D1E92AFULL,
		0x7EE52DEF1D1DDA47ULL,
		0xDA68DE77CD4BAB3EULL,
		0x3287656D13A757BAULL,
		0x56865941643EAB07ULL,
		0x20F9D4CCC4CCB4CCULL,
		0xF059B694EF34D555ULL,
		0x62E66821A8DB1BD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000A132E3C0C0207ULL,
		0x22A1216F11144A04ULL,
		0x8260504388080212ULL,
		0x2285002512231730ULL,
		0x020208416016A200ULL,
		0x209084C000082084ULL,
		0xC00992102C241410ULL,
		0x42602020A0DA11C8ULL
	}};
	printf("Test Case 352\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x579C30C06EEAEEACULL,
		0x0CCDA26292E13A1AULL,
		0xF72CAFE9101ACFBBULL,
		0x144EA2CC64CE0F7DULL,
		0x55433C91226CA5E5ULL,
		0x3EE3FBBC0152F74BULL,
		0xB2F704AC8D095DE4ULL,
		0x12F9D1A4BAF4DBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9949B3CF2E6AD38ULL,
		0xBEA94E4B71A03943ULL,
		0xBFF487B419CC2D3FULL,
		0x08EE9ABD6A22A24DULL,
		0xC9C506A891C8345AULL,
		0x24ECD5A1B9BAA192ULL,
		0x81AA3B0C6F57EF45ULL,
		0x01CB00C64127FC6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4194100062E2AC28ULL,
		0x0C89024210A03802ULL,
		0xB72487A010080D3BULL,
		0x004E828C6002024DULL,
		0x4141048000482440ULL,
		0x24E0D1A00112A102ULL,
		0x80A2000C0D014D44ULL,
		0x00C900840024D84EULL
	}};
	printf("Test Case 353\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBB893601631D312EULL,
		0x4BE3515D87641133ULL,
		0xB3BE80F1375727C4ULL,
		0x0AB5A7C50AC70BDEULL,
		0x9EC53C38E07CDF24ULL,
		0x10C65A2B7FDE090DULL,
		0xC532C5866DABA7CDULL,
		0xAF6A323DF86F62B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88972AB292764070ULL,
		0x98A56D509F0DBDA5ULL,
		0xB7C1191AADDDF5FEULL,
		0xE7C163594E6EDDC9ULL,
		0xC7B32F3B51A3E9E5ULL,
		0x21499EDDF9F68469ULL,
		0x130A3A127C44A5BFULL,
		0xC5CC4B50D63C1A6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8881220002140020ULL,
		0x08A1415087041121ULL,
		0xB3800010255525C4ULL,
		0x028123410A4609C8ULL,
		0x86812C384020C924ULL,
		0x00401A0979D60009ULL,
		0x010200026C00A58DULL,
		0x85480210D02C0220ULL
	}};
	printf("Test Case 354\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB240737936210BCAULL,
		0x8D866ADCC89A42C5ULL,
		0x32BFC92EF60A8DCCULL,
		0x730B29490D57FA18ULL,
		0xD6446A13FA2A458FULL,
		0x29DBE5B522A3295BULL,
		0x3FBD8CC3B6800EEFULL,
		0x9288BC04F547294FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64CDF16384A5E3FEULL,
		0x89974F1DF7258587ULL,
		0xD4BE54FC2D8B0B61ULL,
		0x5DA67E1A3DA74169ULL,
		0x726D77787ED0A15DULL,
		0xBA6BF13452621449ULL,
		0x5E39094139B2F697ULL,
		0xFC7FF90C0ACD9803ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20407161042103CAULL,
		0x89864A1CC0000085ULL,
		0x10BE402C240A0940ULL,
		0x510228080D074008ULL,
		0x524462107A00010DULL,
		0x284BE13402220049ULL,
		0x1E39084130800687ULL,
		0x9008B80400450803ULL
	}};
	printf("Test Case 355\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9AF046048D6F6ACDULL,
		0x7D695C1AAD2B9B27ULL,
		0x7782AB6F952F8267ULL,
		0xBBAB6A1581701B4DULL,
		0xD479BC7E0856857BULL,
		0xA48121DDD2A48CC4ULL,
		0xE5F5A5EFC0AFA195ULL,
		0x17E092BD9AB65ED7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07332E0BB908F88FULL,
		0x698C1C5C8E884A28ULL,
		0xB192CA58BDD41680ULL,
		0x4975C729141D5B86ULL,
		0x3CB69E03C639E003ULL,
		0x3D8D5B940054123FULL,
		0x329A679315A5E224ULL,
		0xF98950BB3539489EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x023006008908688DULL,
		0x69081C188C080A20ULL,
		0x31828A4895040200ULL,
		0x0921420100101B04ULL,
		0x14309C0200108003ULL,
		0x2481019400040004ULL,
		0x2090258300A5A004ULL,
		0x118010B910304896ULL
	}};
	printf("Test Case 356\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA59F18AA499382DDULL,
		0x2D83EAAED44F70CAULL,
		0x1F59E480E67CC96AULL,
		0x7A43AEB9F1DE7D8BULL,
		0xD4220FFE3806F2F6ULL,
		0xB2BCE3348B14B2B4ULL,
		0xAE8F172CD022E21EULL,
		0x091D93DB5811C602ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D7AE29F224688AFULL,
		0xA7CB3262B083D4D0ULL,
		0x524E78CEA774F67AULL,
		0x4325F8AAE7A62426ULL,
		0x947E3319F97760F7ULL,
		0x262E4C3D8DE2C181ULL,
		0x37094712A2B43755ULL,
		0x4A63FB3B5375D03AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x251A008A0002808DULL,
		0x25832222900350C0ULL,
		0x12486080A674C06AULL,
		0x4201A8A8E1862402ULL,
		0x94220318380660F6ULL,
		0x222C403489008080ULL,
		0x2609070080202214ULL,
		0x0801931B5011C002ULL
	}};
	printf("Test Case 357\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x40D50722864D01ECULL,
		0xEBA31A90A3868E8BULL,
		0x3AB07F1B3B774270ULL,
		0x40E616CAC1BE386AULL,
		0x13ADD53330A15D13ULL,
		0x7EE4687B94A282FBULL,
		0x1C6FC0A03E96FA47ULL,
		0x603466BECE2A5DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DB37D9105BE9E0AULL,
		0x6D7B4D4D3A067A7EULL,
		0xEB6323755F23DE6AULL,
		0xB9E59CFDCFFD901CULL,
		0x2F75CB21104AB3E2ULL,
		0xA18C412B66EE1657ULL,
		0x2B92763FFC7D42B8ULL,
		0x0A1E5368BE0C44CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00910500040C0008ULL,
		0x6923080022060A0AULL,
		0x2A2023111B234260ULL,
		0x00E414C8C1BC1008ULL,
		0x0325C12110001102ULL,
		0x2084402B04A20253ULL,
		0x080240203C144200ULL,
		0x001442288E0844C1ULL
	}};
	printf("Test Case 358\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC16B7111152204E6ULL,
		0xDAE2E7A1A287DB80ULL,
		0x61D127B6D5036CA9ULL,
		0x2475D1DFD7DBB710ULL,
		0xC0B4DF6D29F7B738ULL,
		0x51C7621BA8A232E9ULL,
		0x0FA6B4DC652B3710ULL,
		0xD9D320CABD17826CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49A6FCF246919D9FULL,
		0xDDBDEFB7B89AEB11ULL,
		0xF1BA0679E9944C5DULL,
		0x435C8A3027C7D40EULL,
		0x827D847BE5626A2CULL,
		0xF640ACC1642232D1ULL,
		0xD4C6A414F9BA5C2BULL,
		0xE6A9940BDBB797BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4122701004000486ULL,
		0xD8A0E7A1A082CB00ULL,
		0x61900630C1004C09ULL,
		0x0054801007C39400ULL,
		0x8034846921622228ULL,
		0x50402001202232C1ULL,
		0x0486A414612A1400ULL,
		0xC081000A9917822CULL
	}};
	printf("Test Case 359\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x44FE800012DF74C0ULL,
		0x9B92E2AD23707D45ULL,
		0x773DC5F9FDA80979ULL,
		0xFD001BE9A8042AB1ULL,
		0xDE012DE5AE62F9BCULL,
		0x68CEDA71C490241BULL,
		0x3F5E9A51FF84C427ULL,
		0x22430F9E851A60ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39141574BD3DBB55ULL,
		0x4C15EC53034194D9ULL,
		0x261A2B4C4D8FFCA1ULL,
		0xB61E4101E5D5F1F6ULL,
		0x8ED9AED0EAE143DBULL,
		0xAFF528111802A60CULL,
		0xDDC273172CE1EA75ULL,
		0xCC83B6C2D431650CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00140000101D3040ULL,
		0x0810E00103401441ULL,
		0x261801484D880821ULL,
		0xB4000101A00420B0ULL,
		0x8E012CC0AA604198ULL,
		0x28C4081100002408ULL,
		0x1D4212112C80C025ULL,
		0x0003068284106008ULL
	}};
	printf("Test Case 360\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBEE055DFDB663A9CULL,
		0x90B86D7F66DDA1BCULL,
		0x227EE96E25EBEF41ULL,
		0x2EC205F0BC166A18ULL,
		0xC2DF4962C43D601CULL,
		0xEA602781F1B0FBBEULL,
		0x3AAAC3509036290CULL,
		0x34F9BB554B6CB4F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x304DC3FAD1727B9EULL,
		0x4F5C11694317DCE8ULL,
		0xAD847C1FD3F252EFULL,
		0x6936C717BA5FE858ULL,
		0xD44DC0C2732C6333ULL,
		0x98F200F850EF6C69ULL,
		0xCC10DCA26A01FFE2ULL,
		0x7B55BE53AC7DB334ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x304041DAD1623A9CULL,
		0x00180169421580A8ULL,
		0x2004680E01E24241ULL,
		0x28020510B8166818ULL,
		0xC04D4042402C6010ULL,
		0x8860008050A06828ULL,
		0x0800C00000002900ULL,
		0x3051BA51086CB034ULL
	}};
	printf("Test Case 361\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x571F685974AC2E0BULL,
		0x5F7A522A9DFB37A2ULL,
		0xB1726D55C884CDD5ULL,
		0xE764559055CE5339ULL,
		0x9ECE800CAF273CE7ULL,
		0xDB01D9533C80CF6DULL,
		0x888AE275B61A66A8ULL,
		0x502952D612BBA627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2D7F2A5CCA2F1BEULL,
		0xED745C159C77D649ULL,
		0x305B2916EB9C5EF1ULL,
		0x3E70BC0C3FCDE22CULL,
		0xDB59473E5CBDAE8EULL,
		0x118F52E7D04F3491ULL,
		0xDA90DC1046042ADDULL,
		0x30F1C6C89379552BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5217600144A0200AULL,
		0x4D7050009C731600ULL,
		0x30522914C8844CD1ULL,
		0x2660140015CC4228ULL,
		0x9A48000C0C252C86ULL,
		0x1101504310000401ULL,
		0x8880C01006002288ULL,
		0x102142C012390423ULL
	}};
	printf("Test Case 362\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9AEE2590F7793E86ULL,
		0x934173A2A1C9EBE9ULL,
		0x6B4A498F40E4CCEBULL,
		0xD4B469844F063265ULL,
		0xE77DC17C8AC717D3ULL,
		0x73374A37170C6DBCULL,
		0x0DE8EA2E430C5876ULL,
		0x466AC647DFFA1C86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A552341ACA0282ULL,
		0xF0BCC7E087700FFCULL,
		0xE598636AAFCDBDCCULL,
		0xED4D9ED5101144F7ULL,
		0x819F6CC04C8CC968ULL,
		0xB9F361864B6695D8ULL,
		0xBBCAB0637A500439ULL,
		0x6C7CB59BE7EB8E3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A4001012480282ULL,
		0x900043A081400BE8ULL,
		0x6108410A00C48CC8ULL,
		0xC404088400000065ULL,
		0x811D404008840140ULL,
		0x3133400603040598ULL,
		0x09C8A02242000030ULL,
		0x44688403C7EA0C06ULL
	}};
	printf("Test Case 363\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x15F663B52652486AULL,
		0x3A096BCD479D99ABULL,
		0x75E8A6A2FD88BB80ULL,
		0x1DB2F310C082F725ULL,
		0xA0CD4E7AB9FD9ECEULL,
		0x18E3A019B031ECB0ULL,
		0xBBB5C7DB71876BD1ULL,
		0xF42C2A356B77C80FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46E4EA68FD0918B1ULL,
		0x10BB4C0CF34FECB3ULL,
		0xAFB81F7C962AF88FULL,
		0x9746AE4ADCF7C2E3ULL,
		0xB9043AC5BCE59CB3ULL,
		0xDB5230E96D89CE2BULL,
		0x2BE70C42DEC9F655ULL,
		0x3ED4BE38DDCD1606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E4622024000820ULL,
		0x1009480C430D88A3ULL,
		0x25A806209408B880ULL,
		0x1502A200C082C221ULL,
		0xA0040A40B8E59C82ULL,
		0x184220092001CC20ULL,
		0x2BA5044250816251ULL,
		0x34042A3049450006ULL
	}};
	printf("Test Case 364\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x669C3ED150B41827ULL,
		0xC9C0E7EA1E934EBAULL,
		0x7D282DFD0933898DULL,
		0x7B03C1BD84A73161ULL,
		0x11C5A6AC5BFA846AULL,
		0xAED22EE945569696ULL,
		0x302155C6A98FA0D8ULL,
		0xF01E51FDFFF5BE0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AC75A7439A414BBULL,
		0xB913D1067044659AULL,
		0xB401B64454D4B20FULL,
		0xDEA0603FFCBB4CC2ULL,
		0x9FC3FF05218998D0ULL,
		0x3E88915646097E33ULL,
		0xBFAC89E6E1FF879DULL,
		0x19E9F50FEC7C52ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02841A5010A41023ULL,
		0x8900C1021000449AULL,
		0x340024440010800DULL,
		0x5A00403D84A30040ULL,
		0x11C1A60401888040ULL,
		0x2E80004044001612ULL,
		0x302001C6A18F8098ULL,
		0x1008510DEC74120AULL
	}};
	printf("Test Case 365\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x804D58E9F824C23AULL,
		0x4A079CADBBEB07E1ULL,
		0x9EFE61EEF4151AD4ULL,
		0xEEE9D002094FF86BULL,
		0xED89F947EBAFE248ULL,
		0xC647DB85416C1CF5ULL,
		0x0096352C98E0C8CAULL,
		0x61C78E55F9255594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA7C32C4BFAFFACULL,
		0x2674F217A94F890FULL,
		0x1CE4DDEFFFAAEBC1ULL,
		0x3056F97795C6936CULL,
		0x2D9DA83B7D84D783ULL,
		0xE7296173830773A5ULL,
		0x3F574CF472F29B95ULL,
		0x0A63885D7BE47AC7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800540284820C228ULL,
		0x02049005A94B0101ULL,
		0x1CE441EEF4000AC0ULL,
		0x2040D00201469068ULL,
		0x2D89A8036984C200ULL,
		0xC6014101010410A5ULL,
		0x0016042410E08880ULL,
		0x0043885579245084ULL
	}};
	printf("Test Case 366\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF3F64F80AE7FCF3BULL,
		0x3DCBA70A7C606131ULL,
		0xFD62814B5CCD4F2BULL,
		0x80644373698C2793ULL,
		0xBEFAC6FAC800C697ULL,
		0x9501BD46BD9AC30BULL,
		0x38B96D42A05112C8ULL,
		0xCAF402B372EEC0E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BF4B56A8EC4B88ULL,
		0xE1C0FFA3DCE1A864ULL,
		0xB99ADA655A0B9D41ULL,
		0x4B12E4E8267BB175ULL,
		0x9AF4842899004524ULL,
		0x079D6573254E6509ULL,
		0xB30E129990573699ULL,
		0x3736AC1E49632722ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63B64B00A86C4B08ULL,
		0x21C0A7025C602020ULL,
		0xB902804158090D01ULL,
		0x0000406020082111ULL,
		0x9AF0842888004404ULL,
		0x05012542250A4109ULL,
		0x3008000080511288ULL,
		0x0234001240620020ULL
	}};
	printf("Test Case 367\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC550274DFD249A2BULL,
		0x1D3C6D6561E9517CULL,
		0x248219A9FBAE99D0ULL,
		0xBA25AAF7ECA7A532ULL,
		0x3E5DF90F1C4F270BULL,
		0x7A5B0674B2EFE200ULL,
		0xE8F62AB57C42BE98ULL,
		0xBD0D1324EB9713FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEF82885CFB7C26ULL,
		0x037F995861695849ULL,
		0x1822953554466672ULL,
		0xEA42FE67B494B9D7ULL,
		0x9B96BCE643ADBFF4ULL,
		0x3B07671169147067ULL,
		0x44F1315CB5B7CA04ULL,
		0x330F9A6BFC491CFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x454002085C201822ULL,
		0x013C094061695048ULL,
		0x0002112150060050ULL,
		0xAA00AA67A484A112ULL,
		0x1A14B806000D2700ULL,
		0x3A03061020046000ULL,
		0x40F0201434028A00ULL,
		0x310D1220E80110FBULL
	}};
	printf("Test Case 368\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8C209584FE6F9439ULL,
		0x60D14D759A26DDDAULL,
		0x4A67C5A22CC98CB5ULL,
		0xFAE9F2FB539CEFE6ULL,
		0xE99CC763F3B115F2ULL,
		0x3B53E68CCBA231D0ULL,
		0x59AA83517229AE15ULL,
		0xFD5AEB01B3A752B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192437C9E234CB46ULL,
		0xB7C56C2A162844D2ULL,
		0x4BCE764B146982FDULL,
		0x178E056CCBDB837AULL,
		0xC1A4CCE73D6F7DACULL,
		0x81669682B46F5048ULL,
		0x543FAC0D7AF2CD57ULL,
		0x24DBC720709C3759ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08201580E2248000ULL,
		0x20C14C20122044D2ULL,
		0x4A464402044980B5ULL,
		0x1288006843988362ULL,
		0xC184C463312115A0ULL,
		0x0142868080221040ULL,
		0x502A800172208C15ULL,
		0x245AC30030841219ULL
	}};
	printf("Test Case 369\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x49E544B2ADF6821DULL,
		0x0B4FBFAD1B5E5830ULL,
		0xC1C09398F80CB50BULL,
		0x54FDC43A8BFB4761ULL,
		0x0354CBFFC7055950ULL,
		0xEB965DF08A20E23EULL,
		0xE5C5A4E134FE307CULL,
		0x10E2DEDF389F6663ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE88EF7E071E4629ULL,
		0xB242210F2D0C041EULL,
		0x684710D145268905ULL,
		0xCBFDE2BB17C044D4ULL,
		0x7FCBA179CD6F9A08ULL,
		0x65151A630D80092DULL,
		0xF348131DFDB8F59DULL,
		0xD0BD9A7D920A6B62ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4880443205160209ULL,
		0x0242210D090C0010ULL,
		0x4040109040048101ULL,
		0x40FDC03A03C04440ULL,
		0x03408179C5051800ULL,
		0x611418600800002CULL,
		0xE140000134B8301CULL,
		0x10A09A5D100A6262ULL
	}};
	printf("Test Case 370\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA115E5A541503BFEULL,
		0x072ACB845F898E4DULL,
		0xC573B9AC55B41743ULL,
		0xB022A551D413EFF4ULL,
		0x2A0B8ADEDB6BACAAULL,
		0x5F6BEB91D9077F8DULL,
		0x50C21DF842DB4B3BULL,
		0xB69CEF1DB5FF1D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16BBDE10F5A91C09ULL,
		0x9EEEE519E8E970C7ULL,
		0x4D55ABA0812AF316ULL,
		0xC76545D76A820E6AULL,
		0x21CD1E47014BAA1EULL,
		0x924665CF1713FE35ULL,
		0x78F64D5378D48A59ULL,
		0x99DCD96434185F41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0011C40041001808ULL,
		0x062AC10048890045ULL,
		0x4551A9A001201302ULL,
		0x8020055140020E60ULL,
		0x20090A46014BA80AULL,
		0x1242618111037E05ULL,
		0x50C20D5040D00A19ULL,
		0x909CC90434181D00ULL
	}};
	printf("Test Case 371\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDDE66DC5E2B0A690ULL,
		0x68B2C310AA74C2F2ULL,
		0x9013653A1BBB4CAEULL,
		0xF78CEF2635201D34ULL,
		0x321BD6B8DCC11BF7ULL,
		0x276EC8034CA6CBE4ULL,
		0x72CA7A06D42CA75EULL,
		0x0E98635F830539D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4968E1314821E5DCULL,
		0xA9A9CD6FC744F8C3ULL,
		0x6475AF78F63124D8ULL,
		0xB28D80A6AD6E077FULL,
		0x11F769DE3F0A5026ULL,
		0x28660C7871F765A1ULL,
		0x3E1B624662B1A558ULL,
		0x4193724FEA17DF35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x496061014020A490ULL,
		0x28A0C1008244C0C2ULL,
		0x0011253812310488ULL,
		0xB28C802625200534ULL,
		0x101340981C001026ULL,
		0x2066080040A641A0ULL,
		0x320A62064020A558ULL,
		0x0090624F82051910ULL
	}};
	printf("Test Case 372\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x816BE6F257CD425BULL,
		0x43C1A865A68D3266ULL,
		0xE3E68989B412E4D3ULL,
		0x1566F7D5B0341AABULL,
		0xEB05FA0780AF3D1FULL,
		0x0180068BD546416DULL,
		0x059B27127C085C5DULL,
		0xA2D3DFBB8017674BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE7459138AF7ADAULL,
		0xB050A5474818B9F9ULL,
		0xA960A13A22007E43ULL,
		0x25F0C20A0506707FULL,
		0x66DD9857F4AC2A79ULL,
		0x6A0DD0BB7DEBC195ULL,
		0x56451569F6530164ULL,
		0x97EF5CAD1B770B57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00634490108D425AULL,
		0x0040A04500083060ULL,
		0xA160810820006443ULL,
		0x0560C2000004102BULL,
		0x6205980780AC2819ULL,
		0x0000008B55424105ULL,
		0x0401050074000044ULL,
		0x82C35CA900170343ULL
	}};
	printf("Test Case 373\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC09E55E3D364233AULL,
		0x2D8B00C23B375DF4ULL,
		0x97A9286AA966FBD1ULL,
		0x60102AD3DA193BEAULL,
		0x49D0778E79CBEF83ULL,
		0x85EE74726B1E6663ULL,
		0x1831709820C9CA1EULL,
		0xB70984BF43324852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05BC8F51DAB13B2ULL,
		0x16082D961717891CULL,
		0x4776D62ED978C667ULL,
		0x9A9DF1A625A514BFULL,
		0x43C664235E4D7998ULL,
		0x5986C02B2C255A04ULL,
		0x35B73BF1A5030343ULL,
		0x5950F0735D821627ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01A40E111200332ULL,
		0x0408008213170914ULL,
		0x0720002A8960C241ULL,
		0x00102082000110AAULL,
		0x41C0640258496980ULL,
		0x0186402228044200ULL,
		0x1031309020010202ULL,
		0x1100803341020002ULL
	}};
	printf("Test Case 374\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8B050F55C55EEF25ULL,
		0xD3AEE401B8F4B01BULL,
		0xD13F0F000AFB708EULL,
		0xC4C4D13E8721039BULL,
		0x35AD5211ADC6D6C9ULL,
		0x3CD79AD96F44CCB1ULL,
		0xC900C8EA33BDB199ULL,
		0xF08D89A90580DE4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042C1C2A38A202FCULL,
		0xFECDCE3D573E0D41ULL,
		0xA250C4065FE7D00DULL,
		0x501BA81B115F226FULL,
		0x98FDD7BB0B340D40ULL,
		0xADB0F465DEBABF2EULL,
		0xC90EAD9593A5816AULL,
		0xE42AA4458ECE7081ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00040C0000020224ULL,
		0xD28CC40110340001ULL,
		0x801004000AE3500CULL,
		0x4000801A0101020BULL,
		0x10AD521109040440ULL,
		0x2C9090414E008C20ULL,
		0xC900888013A58108ULL,
		0xE008800104805001ULL
	}};
	printf("Test Case 375\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x116773F5CC1C000DULL,
		0x06AAEBB2BF0B42FCULL,
		0xEA85BBBB4954DAC7ULL,
		0x2EC425B0D1C103C2ULL,
		0xBD69008734D5DB19ULL,
		0x33D57244E95A41ACULL,
		0x838520784B56B70BULL,
		0x856C57D8393E9072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FA34A5D7BCC426EULL,
		0x3A804D1830CD8C4AULL,
		0x106218BE886262FAULL,
		0x70222D1DD75C8458ULL,
		0xBFF23F41762059CBULL,
		0x858B3D1ED111C28FULL,
		0x4A168655719FAA27ULL,
		0x45AB5A578D62ED04ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11234255480C000CULL,
		0x0280491030090048ULL,
		0x000018BA084042C2ULL,
		0x20002510D1400040ULL,
		0xBD60000134005909ULL,
		0x01813004C110408CULL,
		0x020400504116A203ULL,
		0x0528525009228000ULL
	}};
	printf("Test Case 376\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAB5BC1D0F118A1E4ULL,
		0x4E179CF6EA1FC810ULL,
		0xEDF9EFF79FDAA71AULL,
		0x6BCAC366FCB74EA2ULL,
		0xE601E46AE0A1440AULL,
		0xE96921379E986CB1ULL,
		0xC25CDEDBD5FE6F3DULL,
		0x658D89DFF575E659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBC191EF4FA4EE5ULL,
		0x4D16FBBD60BF4EF4ULL,
		0x4B4838CDF9A597AEULL,
		0xD0ADBD736142DF3FULL,
		0x2B554CD8310A4F27ULL,
		0xC97B4C3587E7BADCULL,
		0xFE5F3A2FB9BFEAB0ULL,
		0x15DCF97665E6FC8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB180110F01800E4ULL,
		0x4C1698B4601F4810ULL,
		0x494828C59980870AULL,
		0x4088816260024E22ULL,
		0x2201444820004402ULL,
		0xC969003586802890ULL,
		0xC25C1A0B91BE6A30ULL,
		0x058C89566564E409ULL
	}};
	printf("Test Case 377\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCDFC5B20AE24A078ULL,
		0x0D0BA4B9A4C408AAULL,
		0x27A0CC3F30070477ULL,
		0x3D052A97D4C9073EULL,
		0x74406C5F8AC4773FULL,
		0x9F264AAA296132ECULL,
		0x0F85FBC205A37ED0ULL,
		0x8524C6DAB09DA15BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27837D38DFBFEE42ULL,
		0xCD0D33DDBA49E0E4ULL,
		0x4BDDA0F93FB6EE7BULL,
		0xDDF59E8A2C09C008ULL,
		0x1BE6DB5A23A242F4ULL,
		0x8D87DFC955C91780ULL,
		0x66225CADF734C86AULL,
		0x1BE27849795AF9D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x058059208E24A040ULL,
		0x0D092099A04000A0ULL,
		0x0380803930060473ULL,
		0x1D050A8204090008ULL,
		0x1040485A02804234ULL,
		0x8D064A8801411280ULL,
		0x0600588005204840ULL,
		0x012040483018A153ULL
	}};
	printf("Test Case 378\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2027805CE96CCFF1ULL,
		0x0866AB39BC04087EULL,
		0x82487BC2AEE449CEULL,
		0xB908C5F143579D5AULL,
		0x0F0087591434AF41ULL,
		0x4C02EAEC7090F209ULL,
		0xB81E87EA6DC9E09EULL,
		0x1C86108F97A7AFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x511EA69320484BF9ULL,
		0x423E0DDB2466EECDULL,
		0x78E52E3A9816E1BCULL,
		0x9B268AC64C09EE13ULL,
		0x56E48B8B0666038EULL,
		0x668B4A25F785340CULL,
		0x1AC306DA2B814C00ULL,
		0xBA435DE9B6113CABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0006801020484BF1ULL,
		0x002609192404084CULL,
		0x00402A028804418CULL,
		0x990080C040018C12ULL,
		0x0600830904240300ULL,
		0x44024A2470803008ULL,
		0x180206CA29814000ULL,
		0x1802108996012CA8ULL
	}};
	printf("Test Case 379\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB88721D5408F1C3BULL,
		0x57C8C53BED792617ULL,
		0xC03DCF4B7F092DC6ULL,
		0xDEB7EF421225ABDFULL,
		0xF1945BC51DE1293BULL,
		0x33FE902D68A51053ULL,
		0xAD4EF76F4B25C9FCULL,
		0xF3B79D99A38E4130ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4945BE7E53FCE81ULL,
		0x21BEA343D3899305ULL,
		0x5A012FF8E6DB8B6FULL,
		0x8DCD4CB07ABB80DDULL,
		0x6D05A85F7AB07C64ULL,
		0x982D57999E415363ULL,
		0x7AA34F99D146AFCCULL,
		0x199FB8BFE301110DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x908401C5400F0C01ULL,
		0x01888103C1090205ULL,
		0x40010F4866090946ULL,
		0x8C854C00122180DDULL,
		0x6104084518A02820ULL,
		0x102C100908011043ULL,
		0x28024709410489CCULL,
		0x11979899A3000100ULL
	}};
	printf("Test Case 380\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6D5FD98BB3719390ULL,
		0x34590D3CB23C7906ULL,
		0x86565542E80929F9ULL,
		0xB5DEBF039A79C25AULL,
		0x30B0A9E9B0045A60ULL,
		0x3EBB546EECD02B81ULL,
		0x90CD690B00937B8DULL,
		0x75978ED9F515998FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0272E56C1C59AACDULL,
		0x5FE601DBE611CF03ULL,
		0x89B748582962B67FULL,
		0xAA2A18A49E2FDCB2ULL,
		0x585B8FEF984B2AB7ULL,
		0x0F04D49466DCA8F6ULL,
		0x3EF08FB5A5F9DD0EULL,
		0x3B08B5438620B4E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0052C10810518280ULL,
		0x14400118A2104902ULL,
		0x8016404028002079ULL,
		0xA00A18009A29C012ULL,
		0x101089E990000A20ULL,
		0x0E00540464D02880ULL,
		0x10C009010091590CULL,
		0x3100844184009085ULL
	}};
	printf("Test Case 381\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCC934A8021FF0CA2ULL,
		0x29CDE38A356D5D91ULL,
		0x52452998533F3E92ULL,
		0xE4380AE7248AE400ULL,
		0x2CF689AF4BBBE955ULL,
		0x1554650AB33593C9ULL,
		0xA85ACD8511E20358ULL,
		0x4B9AAF7503379812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEAF98C4F4AFAED4ULL,
		0x7E019CF469EE8D81ULL,
		0x359BB9739A0C674CULL,
		0x11DBD4FAEF32391FULL,
		0x499E3DA00FB41BEEULL,
		0xD212C75A59F3E8D5ULL,
		0xC7C9F0CE3F36DFE3ULL,
		0xB6D353664F8F270DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC83088020AF0C80ULL,
		0x28018080216C0D81ULL,
		0x10012910120C2600ULL,
		0x001800E224022000ULL,
		0x089609A00BB00944ULL,
		0x1010450A113180C1ULL,
		0x8048C08411220340ULL,
		0x0292036403070000ULL
	}};
	printf("Test Case 382\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD27C78BDC86901C2ULL,
		0x4F8FC636C3B854CFULL,
		0xFF7FEE5809278CAAULL,
		0x727889E91F5D5E8CULL,
		0x05C21502902EDFCBULL,
		0x49D6C04FF04C1C26ULL,
		0xBA36FF95230A6C17ULL,
		0xE59AC1C7F167E1E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF44A5839DDE248AULL,
		0x27CFFAD6D1BE54C2ULL,
		0x5EBA405CB9DE8F67ULL,
		0x67075872A7EC0D7DULL,
		0xB4D684AD820CBF41ULL,
		0x9BD0602662EBD2FFULL,
		0xBD6E047920C074DFULL,
		0xFD7F46269FD07D97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC244208188480082ULL,
		0x078FC216C1B854C2ULL,
		0x5E3A405809068C22ULL,
		0x62000860074C0C0CULL,
		0x04C20400800C9F41ULL,
		0x09D0400660481026ULL,
		0xB826041120006417ULL,
		0xE51A400691406183ULL
	}};
	printf("Test Case 383\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x41EAFB5FDD728A24ULL,
		0xCFA6A18966B32B49ULL,
		0x34A970D21C64079FULL,
		0xEFF80257667297E2ULL,
		0x89CC1C515CDD3DB5ULL,
		0x0D03131857FEE235ULL,
		0x4763B7358D89A45CULL,
		0xC679B8102695DE07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF274D3DF565FB5E0ULL,
		0xF7760EEFB421B3F9ULL,
		0xE86CF4E44D4D2439ULL,
		0x12C5C13C4E30698AULL,
		0x90B6252A7F3024B4ULL,
		0x4C9C4C96BC51D1A2ULL,
		0xAFC6F9A49D2EBC21ULL,
		0xBD1BD270929210B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4060D35F54528020ULL,
		0xC726008924212349ULL,
		0x202870C00C440419ULL,
		0x02C0001446300182ULL,
		0x808404005C1024B4ULL,
		0x0C0000101450C020ULL,
		0x0742B1248D08A400ULL,
		0x8419901002901002ULL
	}};
	printf("Test Case 384\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x22B6915E2587B1FBULL,
		0x86B560088030A665ULL,
		0x07AF35CF86400024ULL,
		0xCE080A64C22EF97BULL,
		0x226C1446F3DE081AULL,
		0x267E2E29BF567879ULL,
		0x5FE7A3DE5B30C08CULL,
		0xA3D7059477FFF466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B21A2B0E0529583ULL,
		0x12911AA11913FA88ULL,
		0x375832BCE1785BEEULL,
		0xF62CEDC5FEE873B1ULL,
		0xB3531D4053A7BBFCULL,
		0x0003D4AC306155E5ULL,
		0x34F33A29CBAA40C4ULL,
		0x373FDA41D652DE67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2220801020029183ULL,
		0x029100000010A200ULL,
		0x0708308C80400024ULL,
		0xC6080844C2287131ULL,
		0x2240144053860818ULL,
		0x0002042830405061ULL,
		0x14E322084B204084ULL,
		0x231700005652D466ULL
	}};
	printf("Test Case 385\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE3C78E97E54F707DULL,
		0xFFCE5DC5490DA4FEULL,
		0x2A5253A50C8D06D4ULL,
		0xDE64091F8B227C90ULL,
		0xBF4552EC30A3D3D6ULL,
		0xDEF5B625B435B3EBULL,
		0x3FA80B11772B5083ULL,
		0x277F296180B00DE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B0A6EDE2360E5CBULL,
		0x0D38E8A994CDFAA1ULL,
		0xA096AD09CCCE2F67ULL,
		0xB44B9520DECB969AULL,
		0x826792FEC02B25ABULL,
		0x28E67509AC529FD1ULL,
		0x04047245BBA9586EULL,
		0xFA14D135E327A780ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83020E9621406049ULL,
		0x0D084881000DA0A0ULL,
		0x201201010C8C0644ULL,
		0x944001008A021490ULL,
		0x824512EC00230182ULL,
		0x08E43401A41093C1ULL,
		0x0400020133295002ULL,
		0x2214012180200580ULL
	}};
	printf("Test Case 386\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE046B39029A0AF1EULL,
		0xA8DF6647CA68A383ULL,
		0xFC86E6DD023580F1ULL,
		0xC5906BD26FF8B921ULL,
		0x45549CAE3CD57132ULL,
		0x177B83DBEECBA15EULL,
		0xC147295FD1428D14ULL,
		0xD2DFE5B35FA18F13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x302980DA1AFAF5CEULL,
		0x88833FFA5AEC5F13ULL,
		0xE0247423517D7299ULL,
		0x8AEFD127F4C149A3ULL,
		0xB41A58E81F23E1FCULL,
		0xE901684C01850E1AULL,
		0xBADA5E039FC6BCABULL,
		0x13AD6EFA84F8F75FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000809008A0A50EULL,
		0x888326424A680303ULL,
		0xE004640100350091ULL,
		0x8080410264C00921ULL,
		0x041018A81C016130ULL,
		0x010100480081001AULL,
		0x8042080391428C00ULL,
		0x128D64B204A08713ULL
	}};
	printf("Test Case 387\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD7F998FA073537CCULL,
		0x3C9AF11BF8E30DE3ULL,
		0x89B5D454BC641C52ULL,
		0x64A8B89EA33A8216ULL,
		0x4E3E1F93896F3B4DULL,
		0x62E03064CEFB6122ULL,
		0x094B0E1AFA57C629ULL,
		0xADE938CB4B337F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E88F99775BFFE1ULL,
		0xD6EBCF2BEFFF72A3ULL,
		0x33FDE7B881A542C4ULL,
		0x84629979D72720C2ULL,
		0xDA7280397FDD9F09ULL,
		0xBA12FEAEF135EE4FULL,
		0x550EDA63EBE55014ULL,
		0x36BBD0FBFF44B76FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80E88898071137C0ULL,
		0x148AC10BE8E300A3ULL,
		0x01B5C41080240040ULL,
		0x0420981883220002ULL,
		0x4A320011094D1B09ULL,
		0x22003024C0316002ULL,
		0x010A0A02EA454000ULL,
		0x24A910CB4B003701ULL
	}};
	printf("Test Case 388\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7028FDCBF3C51171ULL,
		0xF91D75E0200192E5ULL,
		0xFD11D64833D06B0CULL,
		0xA6E27217F0EBD444ULL,
		0xE2E4CABB39DC6CB9ULL,
		0xB58532A65ED8BEBBULL,
		0xD2A316DA1094CFFFULL,
		0xB5BB26FEC6CEB367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5463BB74E84FB36CULL,
		0x151C46753BD23058ULL,
		0xAB799F62DD5FB1CCULL,
		0x892F06C5F15636E3ULL,
		0x10F09E7DD74BACD2ULL,
		0x9B8685CAE5026A4FULL,
		0xA9B0A4AE25FD5939ULL,
		0xAAC775A187B0A681ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5020B940E0451160ULL,
		0x111C446020001040ULL,
		0xA91196401150210CULL,
		0x80220205F0421440ULL,
		0x00E08A3911482C90ULL,
		0x9184008244002A0BULL,
		0x80A0048A00944939ULL,
		0xA08324A08680A201ULL
	}};
	printf("Test Case 389\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x74165B056A8A80F0ULL,
		0x5FCEAC44CD150E98ULL,
		0x54D6CDCF907A0815ULL,
		0x21F9F3BDDDD7CECBULL,
		0x9586485C08500C16ULL,
		0x5B3B41FEE3BB658AULL,
		0x50E36BFDDA0564D4ULL,
		0x9747E9181F71C306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1677887940B65FC5ULL,
		0x354D0639C66368D7ULL,
		0x3431BCD9BAF49DDEULL,
		0xCDC543599568E693ULL,
		0xA2CCD9D3C21AB25AULL,
		0x17DA76B236CF57ACULL,
		0xED845944CE9A3B93ULL,
		0x84D360E3F84DE055ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14160801408200C0ULL,
		0x154C0400C4010890ULL,
		0x14108CC990700814ULL,
		0x01C143199540C683ULL,
		0x8084485000100012ULL,
		0x131A40B2228B4588ULL,
		0x40804944CA002090ULL,
		0x844360001841C004ULL
	}};
	printf("Test Case 390\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7593FF3916FCAEC2ULL,
		0xA652A842E3C00858ULL,
		0x7695C0ECE14F124CULL,
		0x4A62D6389CD2DB9AULL,
		0xF4F2C7B3CBD51C5EULL,
		0xC2019C7DB691B46BULL,
		0x6F2C21AB27F192A0ULL,
		0x84613171511CCA1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5B6C8AC0A043D2ULL,
		0xFE87FFBF3A0073D9ULL,
		0x21B483A28FA821B7ULL,
		0x264EB95AC5A17A78ULL,
		0x9D67F5309F09DCEBULL,
		0x248C9B7839F6DF1CULL,
		0x1DC5110FF77E2282ULL,
		0x23ACC82288E451B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04136C0800A002C2ULL,
		0xA602A80222000058ULL,
		0x209480A081080004ULL,
		0x0242901884805A18ULL,
		0x9462C5308B011C4AULL,
		0x0000987830909408ULL,
		0x0D04010B27700280ULL,
		0x0020002000044014ULL
	}};
	printf("Test Case 391\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x134610CEE812E924ULL,
		0xC90F863A2979B0E3ULL,
		0x4E048AFA05B57AECULL,
		0xF26E4BDD51C0A297ULL,
		0x31E5D92E75A6D75CULL,
		0x35999A71C5AB33FCULL,
		0x9D4E3B6EDECBED8FULL,
		0x02FE152B63E073D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA605C9F34AD26DC7ULL,
		0x6F1B5233CF30C7A7ULL,
		0xA2E733EF93E95D73ULL,
		0xFB3F4BAC46A357EBULL,
		0xA441874CB50C1683ULL,
		0x2A7124AF698CD198ULL,
		0x88BB89F4731BA368ULL,
		0xD649E1843A83404BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020400C248126904ULL,
		0x490B0232093080A3ULL,
		0x020402EA01A15860ULL,
		0xF22E4B8C40800283ULL,
		0x2041810C35041600ULL,
		0x2011002141881198ULL,
		0x880A0964520BA108ULL,
		0x0248010022804042ULL
	}};
	printf("Test Case 392\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFE8E09264A1AC807ULL,
		0xB6374F02EEFE0911ULL,
		0x3553CEF688158952ULL,
		0xD9976CBB00415A1DULL,
		0x2B04A22EF024DDC8ULL,
		0x36ABA56586CB2361ULL,
		0xE6EB94501853C755ULL,
		0xCD6EF86A77DD7544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5130291702D992E6ULL,
		0x815BC581C408FC6CULL,
		0xEB55EFB8A3EC8627ULL,
		0xFE28522FE955DD19ULL,
		0xA5EF9F017112D715ULL,
		0xABE90204D63CC779ULL,
		0x4D2CAE4178C5E755ULL,
		0x145718B41155D29BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5000090602188006ULL,
		0x80134500C4080800ULL,
		0x2151CEB080048002ULL,
		0xD800402B00415819ULL,
		0x210482007000D500ULL,
		0x22A9000486080361ULL,
		0x442884401841C755ULL,
		0x0446182011555000ULL
	}};
	printf("Test Case 393\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8DBDBB433BF39B09ULL,
		0x4C38E22446883A51ULL,
		0xE0CD524184B640DCULL,
		0xDCC6F5C16A260870ULL,
		0x757CA30F4C89C437ULL,
		0xA78EE225F7AB1CF9ULL,
		0x564C2B5539A5E895ULL,
		0xBB13E43975BAC1B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53B0CA843EFAE57AULL,
		0xED8CA8424B5F466FULL,
		0x65B720653D656FEEULL,
		0x828F81F0228844BFULL,
		0x54CC8759B9334412ULL,
		0x5C05A7477C1D5F6DULL,
		0xF32F35E5DCD0170FULL,
		0x1820AE38D78808E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01B08A003AF28108ULL,
		0x4C08A00042080241ULL,
		0x60850041042440CCULL,
		0x808681C022000030ULL,
		0x544C830908014412ULL,
		0x0404A20574091C69ULL,
		0x520C214518800005ULL,
		0x1800A438558800A0ULL
	}};
	printf("Test Case 394\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3A9CF5011EDE11D2ULL,
		0x1543ADAB1482F676ULL,
		0x145F7C9963083246ULL,
		0xB64A8D16DA2033FBULL,
		0xDBFDF8673CC260CBULL,
		0xB9F5A56AC45A9F66ULL,
		0x52DFF67B906E126CULL,
		0xB0198DBFB80639BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94FE66B4F959E0C8ULL,
		0xBB28597D0C9DB4D3ULL,
		0x2963B45D1BC62F5FULL,
		0x61694DA8230C105BULL,
		0xEDFBBA410D662AB0ULL,
		0x38ABA9BBC7BE3A96ULL,
		0x2C15BB59499420CCULL,
		0x013C41ACDB430832ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x109C6400185800C0ULL,
		0x110009290480B452ULL,
		0x0043341903002246ULL,
		0x20480D000200105BULL,
		0xC9F9B8410C422080ULL,
		0x38A1A12AC41A1A06ULL,
		0x0015B2590004004CULL,
		0x001801AC98020832ULL
	}};
	printf("Test Case 395\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBD1E5B85E3FFC10CULL,
		0x2D1C3E36304849D2ULL,
		0xD97960F5037D1384ULL,
		0xEE179BD5530EF7E7ULL,
		0x1B3B05159BDA1FADULL,
		0x04B3A8C2923F3957ULL,
		0x92DEFF94A4E4701AULL,
		0xDB42DB5BA1D7FF6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C14715A2CF59D4CULL,
		0x2E3BFB873E46BF78ULL,
		0x2B78CD7549108365ULL,
		0x8ACAC7F169E185C9ULL,
		0xCB557828F43B1EC7ULL,
		0x316EA8FAFD1F3A76ULL,
		0x7D8BE0EFB6EDD1DCULL,
		0x12EBEC98C3C2A3CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C14510020F5810CULL,
		0x2C183A0630400950ULL,
		0x0978407501100304ULL,
		0x8A0283D1410085C1ULL,
		0x0B110000901A1E85ULL,
		0x0022A8C2901F3856ULL,
		0x108AE084A4E45018ULL,
		0x1242C81881C2A34CULL
	}};
	printf("Test Case 396\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBD1B17866B42D9AAULL,
		0x5884DC194DCA041EULL,
		0x165D223DB3728F5AULL,
		0x4AE9B30AE029C658ULL,
		0xD400BD25817D7AE3ULL,
		0x9C5ADEBBB911873BULL,
		0x24855B3E0C1D80E6ULL,
		0xCB8EAC476768C5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E863E40DCDA810ULL,
		0xEEED38A1A2066B75ULL,
		0xCB9926E6EBFA8031ULL,
		0x49FFEA5BA22D11C3ULL,
		0xF0709BC6A950D2E6ULL,
		0xEA6D6B9B349C337EULL,
		0xBB393A2679643BE8ULL,
		0xB84156FAFE147BC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9908038409408800ULL,
		0x4884180100020014ULL,
		0x02192224A3728010ULL,
		0x48E9A20AA0290040ULL,
		0xD0009904815052E2ULL,
		0x88484A9B3010033AULL,
		0x20011A26080400E0ULL,
		0x88000442660041C0ULL
	}};
	printf("Test Case 397\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6E163F78817E195FULL,
		0x58757D628CB7127CULL,
		0x79215EACB28BC331ULL,
		0x9C9EF87F6CE713D4ULL,
		0xFC4A7E45CFB4C8B5ULL,
		0x591E0BFF452303BCULL,
		0x4A3B6D884BFD76EBULL,
		0xE907B348104E9BF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5D4501B3180C76AULL,
		0x929F5BA67EF81347ULL,
		0x7A68E4C460612EACULL,
		0xBE06BCB337C221BEULL,
		0xA7CA3CB43138C18DULL,
		0xA17182CA24C4BC0EULL,
		0x329738844E7C1909ULL,
		0x64BDAA0E20A92D6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x441410180100014AULL,
		0x101559220CB01244ULL,
		0x7820448420010220ULL,
		0x9C06B83324C20194ULL,
		0xA44A3C040130C085ULL,
		0x011002CA0400000CULL,
		0x021328804A7C1009ULL,
		0x6005A20800080966ULL
	}};
	printf("Test Case 398\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2D527E339C48884FULL,
		0xC485CD9D92AB6A80ULL,
		0xB4530D61346CA1C5ULL,
		0x915B7B1C896FE1E5ULL,
		0xAFBE95F73310D626ULL,
		0xD4D9B13A21DA9733ULL,
		0x416D26D3D9DBAEDDULL,
		0x419D9D1F0B3C5024ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13D9447179B2F8ABULL,
		0x7957F9240E9DBB5EULL,
		0xDED294BD08B799B4ULL,
		0xB6DC2696370C64C8ULL,
		0x85282BFD8B92B72BULL,
		0xE6B982B49681FF63ULL,
		0xA22A56113751C096ULL,
		0x1BD2E674B6078E08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x015044311800880BULL,
		0x4005C90402892A00ULL,
		0x9452042100248184ULL,
		0x90582214010C60C0ULL,
		0x852801F503109622ULL,
		0xC499803000809723ULL,
		0x0028061111518094ULL,
		0x0190841402040000ULL
	}};
	printf("Test Case 399\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE306FC19229BA49DULL,
		0xC46CF3FF51A209A1ULL,
		0x5E55D6C2CF1F10B7ULL,
		0xCEFA4CC406A38406ULL,
		0xA78A001FAFB47440ULL,
		0xFD08D60D407A43C0ULL,
		0x39F71C41DA4E8FEDULL,
		0xF7C8721569FA59DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EF3018BC8C14BB4ULL,
		0x0BB945833C9599C8ULL,
		0x5B3D18C3FD71F8E5ULL,
		0x94795DFB38866A85ULL,
		0xE3870FFEC70CE70CULL,
		0x2376E3518CDF9372ULL,
		0xC671F4C60E975F43ULL,
		0xD6A74EE059204F21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0202000900810094ULL,
		0x0028418310800980ULL,
		0x5A1510C2CD1110A5ULL,
		0x84784CC000820004ULL,
		0xA382001E87046400ULL,
		0x2100C201005A0340ULL,
		0x007114400A060F41ULL,
		0xD680420049204901ULL
	}};
	printf("Test Case 400\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xAC0C074EB8999DD4ULL,
		0x0C2E346454FBDE47ULL,
		0x3431B72391E1240EULL,
		0x4D30FDAFD6E4D404ULL,
		0xE87000052066F2D7ULL,
		0x24DEED5398FE2F6CULL,
		0xA71DEE6BBF3CF1DBULL,
		0x1F68A341FD973C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x376C49E81DAEEC7FULL,
		0xD2F27E16D8EB547BULL,
		0xDA77897DBF1FDA22ULL,
		0x8AF1265FACB0F9B9ULL,
		0x2BA60D3FF01860C7ULL,
		0x7DDDEBF04E60B724ULL,
		0x1EDE4B3BC6AA4180ULL,
		0x9E4A93963C917022ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x240C014818888C54ULL,
		0x0022340450EB5443ULL,
		0x1031812191010002ULL,
		0x0830240F84A0D000ULL,
		0x28200005200060C7ULL,
		0x24DCE95008602724ULL,
		0x061C4A2B86284180ULL,
		0x1E4883003C913022ULL
	}};
	printf("Test Case 401\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8FAB2997F9839939ULL,
		0x7DA1782A0B05364BULL,
		0x39FFE880147BD4BBULL,
		0xE2883EE74C2F72B6ULL,
		0xAA43D8F738E4E4DDULL,
		0xB3A02284C01949A4ULL,
		0x4BF3CA3225B3BF23ULL,
		0xD36EEF408DE5F6CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F4DD7713FB3C3B1ULL,
		0x5D9FC301FC4B2101ULL,
		0x52EAAE6AA00F17C2ULL,
		0xF35B18983A694E56ULL,
		0x843704CF8FD95E03ULL,
		0x5C5E19D439E9EB5CULL,
		0x765C41FA845C8CA4ULL,
		0xD7498E8C7F631910ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F09011139838131ULL,
		0x5D81400008012001ULL,
		0x10EAA800000B1482ULL,
		0xE208188008294216ULL,
		0x800300C708C04401ULL,
		0x1000008400094904ULL,
		0x4250403204108C20ULL,
		0xD3488E000D611000ULL
	}};
	printf("Test Case 402\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xBB2D293F43D1FB01ULL,
		0xF82B0638F97AEF6FULL,
		0xACCF5D308438D7FCULL,
		0x7E2133B23B6BD7B2ULL,
		0x574FF7DC961B96A8ULL,
		0xDFC1291CFD9388DDULL,
		0xEA0AE7E2FD4E6199ULL,
		0xB8FB75A1651DA51CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462746A2251F1BFFULL,
		0xA7BE9E5DF13180F7ULL,
		0x5198FE30826E9C38ULL,
		0xD393C54DF3E59864ULL,
		0xB2D6B861B5DCFD4DULL,
		0xD59A98B005CF781CULL,
		0x318A5F4B11FA51FCULL,
		0x0A3F13138A9EF608ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0225002201111B01ULL,
		0xA02A0618F1308067ULL,
		0x00885C3080289438ULL,
		0x5201010033619020ULL,
		0x1246B04094189408ULL,
		0xD58008100583081CULL,
		0x200A4742114A4198ULL,
		0x083B1101001CA408ULL
	}};
	printf("Test Case 403\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFC4BAA5F20C3D09CULL,
		0x4133C54AAC034372ULL,
		0xCB16CC63D67A77E1ULL,
		0xD473026F5F60AB2FULL,
		0x1BD1FF34C548A2F2ULL,
		0x9A97BC65320E1BE2ULL,
		0xF89588D14E4EC7DCULL,
		0x87005AECC1BFAF90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52DF66B3B58FBA0CULL,
		0x66D8CF0FABED5DCDULL,
		0xAD977069D5B6E3E1ULL,
		0x2A2B663AFE9259CDULL,
		0xC92749D755801A4EULL,
		0xDAF0B52E353D8B30ULL,
		0x72F59268827A7497ULL,
		0xE68A0F18B7834759ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x504B22132083900CULL,
		0x4010C50AA8014140ULL,
		0x89164061D43263E1ULL,
		0x0023022A5E00090DULL,
		0x0901491445000242ULL,
		0x9A90B424300C0B20ULL,
		0x70958040024A4494ULL,
		0x86000A0881830710ULL
	}};
	printf("Test Case 404\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3016872ED0183D9BULL,
		0xCFEE57237612CB2CULL,
		0x4B1EF01A07F86236ULL,
		0xF5EF60223F1A1D1EULL,
		0xCEE8CAE9C8358F23ULL,
		0x35B8C6A1A381E1A7ULL,
		0x5FDC2C3A5AA6A934ULL,
		0x5C899E219CD76583ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C553CA94AE4DD7ULL,
		0x0CAB171BA3A24833ULL,
		0x5960F4C41DE4F786ULL,
		0xD2FF9074CD49A7D9ULL,
		0x718BC6DF7452E1DDULL,
		0xF427262E73682B24ULL,
		0x50EFC663E77A3225ULL,
		0x8E3DEE197C330845ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2004030A90080D93ULL,
		0x0CAA170322024820ULL,
		0x4900F00005E06206ULL,
		0xD0EF00200D080518ULL,
		0x4088C2C940108101ULL,
		0x3420062023002124ULL,
		0x50CC042242222024ULL,
		0x0C098E011C130001ULL
	}};
	printf("Test Case 405\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x221673C0151AC520ULL,
		0x60A8AC5D79ED5420ULL,
		0x7EF11C4BDBB8481FULL,
		0x22D966F8434E3CF6ULL,
		0xA35875032099C8A0ULL,
		0x1C7292F5EFBE173DULL,
		0xFFF31F5D5AADC011ULL,
		0xE966ADC981D5BFA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD3C4968D5C40679ULL,
		0x708527D85B642199ULL,
		0x86BB08B1061550FCULL,
		0xA609F99198F0C196ULL,
		0x706D542F113EBD7BULL,
		0xD490AD49AFD0C297ULL,
		0xDD88E855D240F320ULL,
		0xE00705B2D0F0F3EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0014414015000420ULL,
		0x6080245859640000ULL,
		0x06B108010210401CULL,
		0x2209609000400096ULL,
		0x2048540300188820ULL,
		0x14108041AF900215ULL,
		0xDD8008555200C000ULL,
		0xE006058080D0B3A1ULL
	}};
	printf("Test Case 406\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x94CC1F276720953BULL,
		0x1D442989636D0236ULL,
		0x09217441BED910B2ULL,
		0xDC33EA663F9E51CDULL,
		0x8B371C9E5D264020ULL,
		0xDDB971EE696BCD26ULL,
		0x882E22A5DCC5FE9FULL,
		0x2C5BDC6128D87231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AF0497BAD28AEF4ULL,
		0xA0A338C9712201F1ULL,
		0x3D96F8E42A920A86ULL,
		0xCB013C727D6FB0A5ULL,
		0xC856DAFFC73AE985ULL,
		0x9F37F51519A18AAAULL,
		0x71669AFBB9A88F51ULL,
		0xFFDFBFCAAF31D091ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C0092325208430ULL,
		0x0000288961200030ULL,
		0x090070402A900082ULL,
		0xC80128623D0E1085ULL,
		0x8816189E45224000ULL,
		0x9D31710409218822ULL,
		0x002602A198808E11ULL,
		0x2C5B9C4028105011ULL
	}};
	printf("Test Case 407\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC74899152F4FD098ULL,
		0x727A177AE244BAD0ULL,
		0x632FECBE6D066626ULL,
		0xE452C49D65329F1AULL,
		0xBD0E277FAF1E16B3ULL,
		0x46A7475145C99F04ULL,
		0x1C9CB2E248D2D2F4ULL,
		0x5073E98104247E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA0B30F6F919D94AULL,
		0x7562B9B079028381ULL,
		0xA661A2660F48272EULL,
		0x3590F866757033E1ULL,
		0x437822C4DAE22590ULL,
		0x9314696954C71AB8ULL,
		0xE492E9F202338AE3ULL,
		0x37E511E592BE31E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC20810142909D008ULL,
		0x7062113060008280ULL,
		0x2221A0260D002626ULL,
		0x2410C00465301300ULL,
		0x010822448A020490ULL,
		0x0204414144C11A00ULL,
		0x0490A0E2001282E0ULL,
		0x1061018100243080ULL
	}};
	printf("Test Case 408\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD354A8CCE244BA2BULL,
		0x6D77AEC0A390F1F9ULL,
		0xCDC6FA693302B163ULL,
		0x0A745FB81D58069AULL,
		0xF3F8C04DD02A7ADCULL,
		0x19D4807B7B2CF492ULL,
		0xD66FA38667C99C74ULL,
		0xE58703CE4655F471ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24D7C2656068E3D4ULL,
		0xD3C31B215046DF91ULL,
		0x13F85EFB707F4109ULL,
		0x756525197C396649ULL,
		0x8EB84199A1AEC965ULL,
		0x054935846E5AD840ULL,
		0x6D15288E5FFDDC9FULL,
		0x8BA5D0AE8E6FDB7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x005480446040A200ULL,
		0x41430A000000D191ULL,
		0x01C05A6930020101ULL,
		0x006405181C180608ULL,
		0x82B84009802A4844ULL,
		0x014000006A08D000ULL,
		0x4405208647C99C14ULL,
		0x8185008E0645D070ULL
	}};
	printf("Test Case 409\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0C0E0DE5E96B0C8CULL,
		0xAFDBE172B4A54B42ULL,
		0x3241394C51389E10ULL,
		0x863F765A2C46567EULL,
		0x595492BBE00EBBF9ULL,
		0x32C996C62BC29B21ULL,
		0x89C66B6B441B3E12ULL,
		0x3F98AC9B59CA28FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DCDAB7C79F1D23BULL,
		0xF6F84A80050F6FB7ULL,
		0xDD0409640247C95EULL,
		0xACE6080F540FE8E1ULL,
		0x6871F6EF713A8A9FULL,
		0x9A0B6E16980BC9DCULL,
		0x48E0C532FDDD7BDAULL,
		0xE851FFA28ABA3F0CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0C096469610008ULL,
		0xA6D8400004054B02ULL,
		0x1000094400008810ULL,
		0x8426000A04064060ULL,
		0x485092AB600A8A99ULL,
		0x1209060608028900ULL,
		0x08C0412244193A12ULL,
		0x2810AC82088A280CULL
	}};
	printf("Test Case 410\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE398A6A55238A529ULL,
		0xD0950DAEE789CDF1ULL,
		0x475A4D65AF4D7FF0ULL,
		0x63DCCF5CA803626BULL,
		0xAA33868B0D0D2C91ULL,
		0x7BF722FA36DE9260ULL,
		0x76DAA718F1E9864CULL,
		0x8EF7D6624151FAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0458A0A1E3B143ULL,
		0x27F0B65A19AC4E72ULL,
		0x7DDBFFBA9EA365D1ULL,
		0xFBC2A026C4A958F9ULL,
		0x362D1A60D808F265ULL,
		0x44DD0B0EAC053CB3ULL,
		0xAA97D1CFE888B7ABULL,
		0xFE4AFDABF83AD256ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x410000A00020A101ULL,
		0x0090040A01884C70ULL,
		0x455A4D208E0165D0ULL,
		0x63C0800480014069ULL,
		0x2221020008082001ULL,
		0x40D5020A24041020ULL,
		0x22928108E0888608ULL,
		0x8E42D4224010D210ULL
	}};
	printf("Test Case 411\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7BE4E3FCB48B4F4EULL,
		0x25DEFC6EC0272A40ULL,
		0x33149CC599A27568ULL,
		0x294C047BBF265C29ULL,
		0xDA1DC82B4F193335ULL,
		0x8B6B29A3431E230EULL,
		0x8AAD81107E6347A6ULL,
		0xC4A636FD627EE992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25517B3579323F83ULL,
		0x36D3C5238B631B5CULL,
		0x9B1E1F1384ACE181ULL,
		0x00E6D0662D8F87BDULL,
		0x785FCA7CE136422FULL,
		0xD4D3591DE1FE8C5AULL,
		0xD2F0BBDB5CBBB6AFULL,
		0xC2A533338AA1E51EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2140633430020F02ULL,
		0x24D2C42280230A40ULL,
		0x13141C0180A06100ULL,
		0x004400622D060429ULL,
		0x581DC82841100225ULL,
		0x80430901411E000AULL,
		0x82A081105C2306A6ULL,
		0xC0A432310220E112ULL
	}};
	printf("Test Case 412\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD8DBCB01DC218F3DULL,
		0x3F6C789A84D29EC0ULL,
		0xD7E1084CFB9DD654ULL,
		0x5C9F783E48180CAAULL,
		0xD38A8975867D309CULL,
		0xF8C05B04CBCD200BULL,
		0xF95DC862D63BA317ULL,
		0xD746A19872FB4FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF60387CC09900D8ULL,
		0x72234338B40A8A87ULL,
		0x34DB2F4AAF0CFC5DULL,
		0xECE331C2C76A575BULL,
		0x356ECBF16A2378BFULL,
		0xF37E9EDC1B05C2B1ULL,
		0x1AC2B43825A7BAF7ULL,
		0xA4297F91BF119ADEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC8400800C0010018ULL,
		0x3220401884028A80ULL,
		0x14C10848AB0CD454ULL,
		0x4C8330024008040AULL,
		0x110A89710221309CULL,
		0xF0401A040B050001ULL,
		0x184080200423A217ULL,
		0x8400219032110AC6ULL
	}};
	printf("Test Case 413\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x25F348F152FD69F5ULL,
		0x1A78E2BF4F66DAF3ULL,
		0xA22E3128F30A0F1BULL,
		0x4A005862C3686F22ULL,
		0x1DC0E1EFC7B8C31BULL,
		0x6A1A71327550099DULL,
		0xD13A68FBE9F41C70ULL,
		0xC833C9D02210C355ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x166C51B7FF232B35ULL,
		0xC7978019A2343747ULL,
		0xCEF1853587A37221ULL,
		0x44057A1E711F7DE4ULL,
		0x4CE4F7FFBFF9CE7AULL,
		0x1ED8F9069B1B5D76ULL,
		0x374EC60C33B02460ULL,
		0x2DDCB5CABC3F614BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x046040B152212935ULL,
		0x0210801902241243ULL,
		0x8220012083020201ULL,
		0x4000580241086D20ULL,
		0x0CC0E1EF87B8C21AULL,
		0x0A18710211100914ULL,
		0x110A400821B00460ULL,
		0x081081C020104141ULL
	}};
	printf("Test Case 414\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x62F59053777E2F31ULL,
		0x77C86EA70A3EF4A9ULL,
		0x20F4A230B6D5AE79ULL,
		0xCC1F02D4FAA2E335ULL,
		0x2D73F4F6262F50A1ULL,
		0xD3F4189D84834B21ULL,
		0x570DE90D6B29DFD8ULL,
		0x49FB72872B49241BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22815E4F9645434ULL,
		0x42F30ADD197E4873ULL,
		0xED3C9E1C8B58567EULL,
		0x8EECBA6305CD61B3ULL,
		0x83D1F4A596107B57ULL,
		0x524596A101125831ULL,
		0x64889967D262D69AULL,
		0x8F755ECA466F6A32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6220104071640430ULL,
		0x42C00A85083E4021ULL,
		0x2034821082500678ULL,
		0x8C0C024000806131ULL,
		0x0151F4A406005001ULL,
		0x5244108100024821ULL,
		0x440889054220D698ULL,
		0x0971528202492012ULL
	}};
	printf("Test Case 415\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x738A9CD0EBD7E0CCULL,
		0x1863713BC3CF21E2ULL,
		0x746E479E4927700CULL,
		0xFAB742AA8EF29440ULL,
		0xFEDC05EAB1535D72ULL,
		0xF7A86186E1DCEA0BULL,
		0x53FF2F719B31B1B0ULL,
		0x85034CB219537CCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A66A725D502D29ULL,
		0x9108EFCF266C8F61ULL,
		0x49B3E70C078931E7ULL,
		0x1B710EDD58AB8523ULL,
		0x84CEF10BFAC309E7ULL,
		0x9EA85F1441DB1DA0ULL,
		0xE75F6D14B6201639ULL,
		0x93F697A5761D4F03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2182085049502008ULL,
		0x1000610B024C0160ULL,
		0x4022470C01013004ULL,
		0x1A31028808A28400ULL,
		0x84CC010AB0430962ULL,
		0x96A8410441D80800ULL,
		0x435F2D1092201030ULL,
		0x810204A010114C03ULL
	}};
	printf("Test Case 416\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x88565341108470A5ULL,
		0x1C5D7D66B608CF81ULL,
		0xFE26400F29C28E96ULL,
		0xA44926DCC59F0EF1ULL,
		0xB11E5A44A92538F8ULL,
		0x8B0F2AE8E886503DULL,
		0x36565A6BA56FCA88ULL,
		0xF8264D9D8414EACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4492160BEE687DBEULL,
		0x33F5A6FA487AAC55ULL,
		0x3CDFFCF595E3E54CULL,
		0x2A343FA77D9686BEULL,
		0x96BCB97E8BE449B7ULL,
		0x6746ED43F1D77D9FULL,
		0x3AA7F7C58E28E433ULL,
		0x2BF8BE1F0B32EE9CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00121201000070A4ULL,
		0x1055246200088C01ULL,
		0x3C06400501C28404ULL,
		0x20002684459606B0ULL,
		0x901C1844892408B0ULL,
		0x03062840E086501DULL,
		0x320652418428C000ULL,
		0x28200C1D0010EA8CULL
	}};
	printf("Test Case 417\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xFFE83864BECC46C7ULL,
		0x283D0DF219941C13ULL,
		0xE8ABC99E98DBD0DAULL,
		0xA2149FCEA872168EULL,
		0x80145F31D6E1E761ULL,
		0x90DBFE6606ACF382ULL,
		0xBA0487FD8077EB03ULL,
		0x356D40CAD8066E9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x264999AA84BAD8F3ULL,
		0x041D2E9AE7B21F6DULL,
		0x6BDEDEB157B8F775ULL,
		0x4E61041043875062ULL,
		0x9360A6A01F3D6946ULL,
		0x762F1D797810969DULL,
		0x63E33EFFDAAB9A05ULL,
		0x5488FA0875A248A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26481820848840C3ULL,
		0x001D0C9201901C01ULL,
		0x688AC8901098D050ULL,
		0x0200040000021002ULL,
		0x8000062016216140ULL,
		0x100B1C6000009280ULL,
		0x220006FD80238A01ULL,
		0x1408400850024884ULL
	}};
	printf("Test Case 418\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x94EDDC160B958D45ULL,
		0xBBC9105BE3457510ULL,
		0x20EB46362D35C78CULL,
		0xA7AA61CD303D418FULL,
		0x85AB7A6258705BCEULL,
		0x79CB88A04EE951D6ULL,
		0x649DBB6ABB693EB2ULL,
		0xA1D08A979E0A7CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA924844CB351253ULL,
		0x7931F23B7F994040ULL,
		0x057C46C52516EE4FULL,
		0x8CDA5043F57096F6ULL,
		0x325FDC26C0E3951BULL,
		0x39FE7522CC09E63AULL,
		0xDF643FA48CB6A611ULL,
		0x796FB751164C1789ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808048040B150041ULL,
		0x3901101B63014000ULL,
		0x006846042514C60CULL,
		0x848A404130300086ULL,
		0x000B58224060110AULL,
		0x39CA00204C094012ULL,
		0x44043B2088202610ULL,
		0x2140821116081489ULL
	}};
	printf("Test Case 419\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCCE226B8455432E9ULL,
		0xE91AF8A680E72C1CULL,
		0xE9AF4B84C8D19C4CULL,
		0x14429704E663EBEBULL,
		0x1FCEF03D70680AA8ULL,
		0xC9DDB4870A38AC18ULL,
		0xDF5771D92159D6A5ULL,
		0x44B4F784E41191D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CBF0CE3A848FB41ULL,
		0xAEB353A0C91F1130ULL,
		0x19FA492C3D0BF831ULL,
		0x566B5BAA2D76EE15ULL,
		0x8D54E0F4A262E6E1ULL,
		0x191DDB3385A295E9ULL,
		0xFF80CE9E387E972AULL,
		0xA9507C090F192201ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CA204A000403241ULL,
		0xA81250A080070010ULL,
		0x09AA490408019800ULL,
		0x144213002462EA01ULL,
		0x0D44E034206002A0ULL,
		0x091D900300208408ULL,
		0xDF00409820589620ULL,
		0x0010740004110000ULL
	}};
	printf("Test Case 420\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x15E431030238BCDFULL,
		0x6AEBC442612D964CULL,
		0xDD23926856CD2687ULL,
		0xB8ABF69AEBFF9126ULL,
		0x6D4D3BF53697B724ULL,
		0xBF3DEDAF932040E0ULL,
		0xEADC0534FF9B0B76ULL,
		0x081E56AFC301D53FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x837D84825C70F3D7ULL,
		0x3D186F6002B31851ULL,
		0xAA9EC8F362D9776CULL,
		0xB745E723C2556642ULL,
		0x7A71AB6E1B3170B6ULL,
		0x9446FB3B2D41AB30ULL,
		0x142B0CE80941EE38ULL,
		0x76CEE65104B9D693ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x016400020030B0D7ULL,
		0x2808444000211040ULL,
		0x8802806042C92604ULL,
		0xB001E602C2550002ULL,
		0x68412B6412113024ULL,
		0x9404E92B01000020ULL,
		0x0008042009010A30ULL,
		0x000E46010001D413ULL
	}};
	printf("Test Case 421\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x2F5B3B12003DDA48ULL,
		0xE9441256DCE27A36ULL,
		0x4C2B744AB689196DULL,
		0x000E6075E7331C77ULL,
		0x34B8BEE9A988B747ULL,
		0x8E4760A2ACDA0D44ULL,
		0x368AD4C727C93467ULL,
		0x7BD6735D8E3787C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35016C54F31C4B1ULL,
		0xC5ABC9B706B72484ULL,
		0x6E71E104BD8799CEULL,
		0x2FBCEF508F3A767BULL,
		0x0488F67E4C726688ULL,
		0x0BCA968DD3A8CE0DULL,
		0xF0E28EA0F7F10A54ULL,
		0xAEC6B9A638C7640EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235012000031C000ULL,
		0xC100001604A22004ULL,
		0x4C216000B481194CULL,
		0x000C605087321473ULL,
		0x0488B66808002600ULL,
		0x0A42008080880C04ULL,
		0x3082848027C10044ULL,
		0x2AC6310408070402ULL
	}};
	printf("Test Case 422\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1E2E7BF649C48428ULL,
		0x642A95A29BE9B9FDULL,
		0x8AAF31FD30A639F9ULL,
		0xA92AF9DB5C32D0BBULL,
		0x5141B39260983DC9ULL,
		0x894E193461A54705ULL,
		0xA242997BAB068401ULL,
		0x61449F32BE954B4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20130F6BD063B470ULL,
		0xF9A818E81363C229ULL,
		0xCA9BF7E70CEE37F3ULL,
		0x07351018CDED1F8FULL,
		0x10AB319A0DCEAFBAULL,
		0xD50559F14CA8E64BULL,
		0x62545235110EE748ULL,
		0xBC8173AF5FA4CE88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00020B6240408420ULL,
		0x602810A013618029ULL,
		0x8A8B31E500A631F1ULL,
		0x012010184C20108BULL,
		0x1001319200882D88ULL,
		0x8104193040A04601ULL,
		0x2240103101068400ULL,
		0x200013221E844A08ULL
	}};
	printf("Test Case 423\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x74296CDCF93E07C7ULL,
		0x0649EA190B1903CBULL,
		0xE456052B57915D7FULL,
		0xDFDE284F82EEC092ULL,
		0x6FE30FD8F7529A1DULL,
		0x299812932B65205EULL,
		0x016E0612466BB5B3ULL,
		0x87DB56E29B21CC77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC40A6CD789AF58C0ULL,
		0x1AB4016D4B756725ULL,
		0xB6DC7BD9E1805B61ULL,
		0x260D8BE9D81B93A4ULL,
		0x513D18F706522F76ULL,
		0x21AFACE26024CC4DULL,
		0xEA59F7A7D879E669ULL,
		0xC3D0FE336A704A4FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44086CD4892E00C0ULL,
		0x020000090B110301ULL,
		0xA454010941805961ULL,
		0x060C0849800A8080ULL,
		0x412108D006520A14ULL,
		0x218800822024004CULL,
		0x004806024069A421ULL,
		0x83D056220A204847ULL
	}};
	printf("Test Case 424\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x591FDEBA33B30DBDULL,
		0xD8F4EFBFD3A6F319ULL,
		0x40E715834C5D40C7ULL,
		0xF068A4D27D1D0F56ULL,
		0x74BB47C32A6ECC78ULL,
		0x8FB2A808BCD47C2DULL,
		0xEDB2E7E898487143ULL,
		0xD60B872F378254FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x132118F25984F3FFULL,
		0x12CF0B1FBFD3D0D7ULL,
		0x6419D59CCBC3ABBAULL,
		0x3F2AF9DB972AACF0ULL,
		0xA4A64B43C54D8EBFULL,
		0xCCB04F31D34FE4A6ULL,
		0xEA72DDA61CA6C808ULL,
		0x30DE2C55270026FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110118B2118001BDULL,
		0x10C40B1F9382D011ULL,
		0x4001158048410082ULL,
		0x3028A0D215080C50ULL,
		0x24A24343004C8C38ULL,
		0x8CB0080090446424ULL,
		0xE832C5A018004000ULL,
		0x100A0405270004FAULL
	}};
	printf("Test Case 425\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x958FEE46173E351BULL,
		0x0C048D14E573C283ULL,
		0x507542893B6706BBULL,
		0xF39A34F4843E0626ULL,
		0x7E288B329AC2C1A6ULL,
		0x4554535F01D13D25ULL,
		0x2212A8099E087ED1ULL,
		0x2B289552CDB9A2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA497E62AB4F4977AULL,
		0x2D52F548D2DB6070ULL,
		0x4913BF3EEF950F08ULL,
		0x899243D3954DAA58ULL,
		0x92E7ECE48039CC7DULL,
		0xE35DC5EADAB913D2ULL,
		0xEFB9265C9C2E0B24ULL,
		0x57E86AD0873ECCE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8487E6021434151AULL,
		0x0C008500C0534000ULL,
		0x401102082B050608ULL,
		0x819200D0840C0200ULL,
		0x122088208000C024ULL,
		0x4154414A00911100ULL,
		0x221020089C080A00ULL,
		0x03280050853880E8ULL
	}};
	printf("Test Case 426\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE6ECBC7485675507ULL,
		0x16DD2E9AB196155FULL,
		0xE7184AD5B9B1006CULL,
		0xF7A6CF74DDE45E40ULL,
		0x33E1286AE0D1D067ULL,
		0xF95FC1F1A9C2B041ULL,
		0x2D8F2D1B24A59536ULL,
		0xE583AFBF6087738FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x080BDBB2FBB03D43ULL,
		0x6A008CA02AA545BBULL,
		0x71636984921A2979ULL,
		0xF09C5DA7A6006F08ULL,
		0x50F52BCEFE6DAC9EULL,
		0x5E8B89BB41031C45ULL,
		0xE8D3D0F2F213F487ULL,
		0x3FCB2441CDB35596ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0008983081201503ULL,
		0x02000C802084051BULL,
		0x6100488490100068ULL,
		0xF0844D2484004E00ULL,
		0x10E1284AE0418006ULL,
		0x580B81B101021041ULL,
		0x2883001220019406ULL,
		0x2583240140835186ULL
	}};
	printf("Test Case 427\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB285C68F54007844ULL,
		0x82A1B38794791937ULL,
		0x53B280F594147C49ULL,
		0xF0AB9BC38A5BC66FULL,
		0xA4364550DD4C5AB7ULL,
		0xBD75692B560282E6ULL,
		0x0C39C908AD5E8353ULL,
		0x0EE55AF435C8441CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E6D5882CD78BB3ULL,
		0x06AC26386CB70542ULL,
		0xE32651D202208459ULL,
		0x87235CF966BEEB12ULL,
		0x6EED0C008E3CB342ULL,
		0x8A84F79851514968ULL,
		0xBD6A04C843F34B40ULL,
		0x77A928AC05F99E8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA284C48804000800ULL,
		0x02A0220004310102ULL,
		0x432200D000000449ULL,
		0x802318C1021AC202ULL,
		0x242404008C0C1202ULL,
		0x8804610850000060ULL,
		0x0C28000801520340ULL,
		0x06A108A405C80408ULL
	}};
	printf("Test Case 428\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x26870E95E8FE8275ULL,
		0x9AD517F9B8891668ULL,
		0x57BD95829933CF83ULL,
		0x9CA722E181FC8458ULL,
		0x28DB3BE6AFA5853BULL,
		0x2A442A0400D7CFA8ULL,
		0x393ECD8E305A76F4ULL,
		0x9589B61C22635601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCBAC5DDA876CD8BULL,
		0x155557CE05277DEAULL,
		0x43C0B7E74F45D62EULL,
		0x8DC37DEBA9092C35ULL,
		0x4CC88F660882834FULL,
		0x3D6F7D0C6FF72F78ULL,
		0xCD292223A7B5BEBCULL,
		0x3CFD3A3DC9A45FA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24820495A8768001ULL,
		0x105517C800011468ULL,
		0x438095820901C602ULL,
		0x8C8320E181080410ULL,
		0x08C80B660880810BULL,
		0x2844280400D70F28ULL,
		0x09280002201036B4ULL,
		0x1489321C00205601ULL
	}};
	printf("Test Case 429\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF8E7DE7C17E885ECULL,
		0xF1341F33867010DDULL,
		0xD7242CBF78BF5400ULL,
		0x16B76F55B10329BAULL,
		0xF0F879E62BC9F31DULL,
		0xF4D0668421805ABBULL,
		0x97021CFD2CDE52B9ULL,
		0xFC5380C7CD2B8776ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69AA7501DAFCF8B5ULL,
		0x848D239A88FBAC11ULL,
		0xDDA86D6ED2401166ULL,
		0xFE1EE8264489C1FCULL,
		0xF84D08CCD271061EULL,
		0xEC5D4745DA8A4DFDULL,
		0x0194EC3F1B8A92CCULL,
		0x099E94785C3401DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A2540012E880A4ULL,
		0x8004031280700011ULL,
		0xD5202C2E50001000ULL,
		0x16166804000101B8ULL,
		0xF04808C40241021CULL,
		0xE4504604008048B9ULL,
		0x01000C3D088A1288ULL,
		0x081280404C200152ULL
	}};
	printf("Test Case 430\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x467CC8B21C73E745ULL,
		0x117475E0BCB590B8ULL,
		0xB6A419C4194DB6E3ULL,
		0xDD6BF17BC8E07611ULL,
		0x9907F4788120CF43ULL,
		0x8B8B56E612396F23ULL,
		0xF951A3B6B5CD492FULL,
		0x49B71E72151150EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70A04BF32C28C7C8ULL,
		0x37EE1ED0BF98463EULL,
		0xCBD1D3B55AA8037FULL,
		0x1060EBA09B102E10ULL,
		0xCD34DF4B54D9950EULL,
		0xBFB4A090E3B99631ULL,
		0xBDBAE2ECEA27AB2CULL,
		0xD101A51046DE169DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x402048B20C20C740ULL,
		0x116414C0BC900038ULL,
		0x8280118418080263ULL,
		0x1060E12088002610ULL,
		0x8904D44800008502ULL,
		0x8B80008002390621ULL,
		0xB910A2A4A005092CULL,
		0x410104100410108DULL
	}};
	printf("Test Case 431\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3AED76E3FCF9737FULL,
		0x8B32BE014B6E3D97ULL,
		0x1CB63332A227899EULL,
		0x168BA68AD062B075ULL,
		0xD25B57D53228DBC5ULL,
		0xBAB378CF6E14C850ULL,
		0xE75E31DD182FB7DCULL,
		0x3967A852A60B9262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CE3B59096AFBF3DULL,
		0x508BDC6CE8B5C360ULL,
		0x8DECFA0E6D7121F5ULL,
		0x7DA56E624106CC21ULL,
		0x7EF823F8888420F9ULL,
		0x3DD47F95D1C068B2ULL,
		0xC7B63464D12D807BULL,
		0x5700AA573DA30911ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28E1348094A9333DULL,
		0x00029C0048240100ULL,
		0x0CA4320220210194ULL,
		0x1481260240028021ULL,
		0x525803D0000000C1ULL,
		0x3890788540004810ULL,
		0xC7163044102D8058ULL,
		0x1100A85224030000ULL
	}};
	printf("Test Case 432\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x878C1C5BBFFBA016ULL,
		0x1862EDCAEA61D922ULL,
		0xA2E9352C26F89BECULL,
		0x2C2C4AFB0814E0A4ULL,
		0x9080FD315A0A0BC3ULL,
		0x0A538C84D1DD4DA4ULL,
		0x733DBF933CD9E2CAULL,
		0x962C92FDD434D88AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF88EE9FBC5AAB3ULL,
		0xBEDDD85C2A3CCF47ULL,
		0x35D6DF067DF5412AULL,
		0x8C5C73C0C730D221ULL,
		0x9A5266F2A6312730ULL,
		0xE8D2E40153302DA1ULL,
		0x9A38E713C15A0E58ULL,
		0xBC1A9417E7CB4C21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85880C49BBC1A012ULL,
		0x1840C8482A20C902ULL,
		0x20C0150424F00128ULL,
		0x0C0C42C00010C020ULL,
		0x9000643002000300ULL,
		0x0852840051100DA0ULL,
		0x1238A71300580248ULL,
		0x94089015C4004800ULL
	}};
	printf("Test Case 433\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE95EA814DC09DCEFULL,
		0xAD06A6BB78211195ULL,
		0x24E1C813340B8680ULL,
		0x984C99D18F90D886ULL,
		0xFDC78790D42B05FAULL,
		0xA53AF45B5B536258ULL,
		0x97D1DCAE919130D9ULL,
		0xDDEB8B92A2BE8517ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6906A7AD31258AULL,
		0xCCC38079BC6AF52FULL,
		0xCDFC82AA7FDD6748ULL,
		0x4C402FB3FFE365F1ULL,
		0x7DCBCCBAE5870EA1ULL,
		0xBB8D1BEFCF6C5C6BULL,
		0x568D9E82BE30DF98ULL,
		0xF3352DF1135DE3BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x684800048C01048AULL,
		0x8C02803938201105ULL,
		0x04E0800234090600ULL,
		0x084009918F804080ULL,
		0x7DC38490C40304A0ULL,
		0xA108104B4B404048ULL,
		0x16819C8290101098ULL,
		0xD1210990021C8113ULL
	}};
	printf("Test Case 434\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x449F59CB831B507EULL,
		0x0A8C7DB3B9BF65E5ULL,
		0xC5B78D24DBF02FF2ULL,
		0x2CF5BC91D45E4B9DULL,
		0xD555C0D61E764DECULL,
		0x061AC8AAB6329234ULL,
		0x4A8F7051A2D4E0C3ULL,
		0x258CB572E81F7273ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BBBC4877109B5BULL,
		0xE75AEC7B6A149099ULL,
		0x085B3A878C62E32BULL,
		0x8CCF83B8613CA01FULL,
		0x60FA4BF471C0884CULL,
		0x2C810D53D87BA950ULL,
		0x4507F4F2107E3AAAULL,
		0x01DBAEFDA9E33538ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x449B18480310105AULL,
		0x02086C3328140081ULL,
		0x0013080488602322ULL,
		0x0CC58090401C001DULL,
		0x405040D41040084CULL,
		0x0400080290328010ULL,
		0x4007705000542082ULL,
		0x0188A470A8033030ULL
	}};
	printf("Test Case 435\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x589BF62F89E2C96EULL,
		0x59BCC22E67A1DD61ULL,
		0xCBFB763936E6A83DULL,
		0xD0873385FCE07F7DULL,
		0xB671AF996BF12BC4ULL,
		0xF50C17409F9C33F0ULL,
		0x8067B28F3C13513CULL,
		0xC9AE8682A98CD213ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1990DC75A21F53A5ULL,
		0x364E91F6213ECF00ULL,
		0xDD17B1ADAD4A8FE2ULL,
		0x0CF343DB93955550ULL,
		0x7842FD20BC10469BULL,
		0x1176F552CD96C12BULL,
		0x00F7215C2906C06AULL,
		0xEE0F5389D646CE45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1890D42580024124ULL,
		0x100C80262120CD00ULL,
		0xC913302924428820ULL,
		0x0083038190805550ULL,
		0x3040AD0028100280ULL,
		0x110415408D940120ULL,
		0x0067200C28024028ULL,
		0xC80E02808004C201ULL
	}};
	printf("Test Case 436\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x47FCC69BF62693FEULL,
		0xA333908983EB3472ULL,
		0xBBE2D2DD57407CF4ULL,
		0x5C16390DC8664372ULL,
		0x3300D14F3CE3992FULL,
		0x0BC9D481BCD81B07ULL,
		0x0D38E6F4E28F0D84ULL,
		0x51AF245F1DBBCBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5395C8009835D12ULL,
		0x41181C3AD66854F7ULL,
		0x2FA36A478FE50D01ULL,
		0xDABB3B3D4968EECFULL,
		0x67604D1B5D2AEA9DULL,
		0xB5B5BFE079CD30FAULL,
		0xF3664E497AFFF497ULL,
		0xC1D758BC42D58E6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0538448000021112ULL,
		0x0110100882681472ULL,
		0x2BA2424507400C00ULL,
		0x5812390D48604242ULL,
		0x2300410B1C22880DULL,
		0x0181948038C81002ULL,
		0x01204640628F0484ULL,
		0x4187001C00918A27ULL
	}};
	printf("Test Case 437\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB34D29057903E34FULL,
		0xFAFBAB6A8820B3D0ULL,
		0x9C86383582FD5F78ULL,
		0xA776FB20117C9E26ULL,
		0x5C71C6709CA79B31ULL,
		0x0E29E65F471FBE56ULL,
		0x3DDEEA75F4275DF3ULL,
		0x8615EA09A322B690ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C81A429A29BF5DBULL,
		0x0C37ECA65E718C97ULL,
		0x41ACBF73A246D94CULL,
		0x33619E2DF5F02384ULL,
		0x4FE27653C309E94EULL,
		0x6CF2DE79225918C7ULL,
		0x983AC90D83D4F9DCULL,
		0x2F5FFAF417831665ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100120012003E14BULL,
		0x0833A82208208090ULL,
		0x0084383182445948ULL,
		0x23609A2011700204ULL,
		0x4C60465080018900ULL,
		0x0C20C65902191846ULL,
		0x181AC805800459D0ULL,
		0x0615EA0003021600ULL
	}};
	printf("Test Case 438\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xDA79F7E79951EEA6ULL,
		0x968A5AE6BCFE7594ULL,
		0xA513EE14CC3F0C1AULL,
		0xF8A6256FEDDAE341ULL,
		0x03522225EA923FEAULL,
		0x94DEFDE6D76C0B54ULL,
		0x49E119695E6998EEULL,
		0xD6B8F8A73DEECD1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E7CE264A7974B2FULL,
		0x62E149127FFD35CDULL,
		0xD16818EE7ECD502CULL,
		0x9131393CB0907D29ULL,
		0xDD4599FAF6CAEEA0ULL,
		0x4176E13C965FABE4ULL,
		0xB0D6909FAB5D61DEULL,
		0xAF6D8382959E2E93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A78E26481114A26ULL,
		0x028048023CFC3584ULL,
		0x810008044C0D0008ULL,
		0x9020212CA0906101ULL,
		0x01400020E2822EA0ULL,
		0x0056E124964C0B44ULL,
		0x00C010090A4900CEULL,
		0x86288082158E0C11ULL
	}};
	printf("Test Case 439\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x80661F525C52EC7BULL,
		0x2B05D7196455CECDULL,
		0x66FD0DE8A6AF673AULL,
		0x05F81D19F0C97CF8ULL,
		0x504DACB22DC4EA3EULL,
		0xC81DDBD5E2021F83ULL,
		0xE43881FE9C35DB23ULL,
		0x3EFB882A53F68483ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2D933F2151C75EFULL,
		0x1339915F85409013ULL,
		0x7A455AF5C9C91575ULL,
		0x82A376B6270E3E70ULL,
		0x95B0FC958E094822ULL,
		0xBDD74AC84EF2BA5BULL,
		0x97EDB3A987563EB2ULL,
		0xC4A5B8CB10E20D10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x804013521410646BULL,
		0x0301911904408001ULL,
		0x624508E080890530ULL,
		0x00A0141020083C70ULL,
		0x1000AC900C004822ULL,
		0x88154AC042021A03ULL,
		0x842881A884141A22ULL,
		0x04A1880A10E20400ULL
	}};
	printf("Test Case 440\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC2AA010E4BBB341DULL,
		0x639CE52E7AC79C33ULL,
		0x7EE97BC56DACED02ULL,
		0x6AC7368E9475A457ULL,
		0x7587FB7A3F8568B3ULL,
		0x52B9CA6A9395FCB2ULL,
		0x3812DC160A204618ULL,
		0x4DE4DB27120809AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2814C0BA04CD510BULL,
		0x271C8CA6CF856F83ULL,
		0x361709AD6AE4E024ULL,
		0x48224D65DB19A834ULL,
		0x05DD818E23E1B10EULL,
		0x1944EA1B6AAFEB51ULL,
		0x761944989D25E173ULL,
		0x981A95A5C75B8F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000000A00891009ULL,
		0x231C84264A850C03ULL,
		0x3601098568A4E000ULL,
		0x480204049011A014ULL,
		0x0585810A23812002ULL,
		0x1000CA0A0285E810ULL,
		0x3010441008204010ULL,
		0x0800912502080907ULL
	}};
	printf("Test Case 441\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4401D9F10EA46C89ULL,
		0x0519A36969E03723ULL,
		0x9A970AB5553E51A6ULL,
		0x4564579D930F244CULL,
		0x0446CE61F4CEAFD4ULL,
		0x0CBEBA8A30EDCC68ULL,
		0x5D01E56E60B090E3ULL,
		0x1E02B09A808C85C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE0708FF50177589ULL,
		0xE0680524430BC287ULL,
		0xA0D88C31C9294BC7ULL,
		0x8D4FA8571553FD71ULL,
		0x9662BE3780A3BBD8ULL,
		0xB0D1DF68442C00BAULL,
		0x814915A9AA84AC17ULL,
		0x1D703494A35315D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x440108F100046489ULL,
		0x0008012041000203ULL,
		0x8090083141284186ULL,
		0x0544001511032440ULL,
		0x04428E218082ABD0ULL,
		0x00909A08002C0028ULL,
		0x0101052820808003ULL,
		0x1C003090800005C4ULL
	}};
	printf("Test Case 442\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x825115A50040CA9DULL,
		0xCF2DF2B95DE85F79ULL,
		0xBDF795C739E1A9D8ULL,
		0x7783FE40270B0029ULL,
		0x920BB37E41857737ULL,
		0x6709ECF632239174ULL,
		0x4C6C13FCAFEE71E7ULL,
		0xF9361CB117A85527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x358EC19CE281B214ULL,
		0xB53623AB74D81CDAULL,
		0x68E98521B07CE591ULL,
		0xC9FC402242803A50ULL,
		0x8A44C7A7C4F9E08FULL,
		0x429D836C7B8F9A77ULL,
		0x32CED32B666DC9CFULL,
		0x18B4ACDAC299EA6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000018400008214ULL,
		0x852422A954C81C58ULL,
		0x28E185013060A190ULL,
		0x4180400002000000ULL,
		0x8200832640816007ULL,
		0x4209806432039074ULL,
		0x004C1328266C41C7ULL,
		0x18340C9002884022ULL
	}};
	printf("Test Case 443\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC1D80D5E37D28276ULL,
		0x40793AE020FAC69DULL,
		0x6DA960FA6C542B8FULL,
		0x2D0498DD385D6FE7ULL,
		0xE74D339A444A476BULL,
		0x9CBA64C25649E99EULL,
		0xEF03E611DB95B4FBULL,
		0x6B5D0E51B3728C0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677B1FA6D4BFFCE2ULL,
		0x108186BAB508C47EULL,
		0x55650D35F1BEA3FCULL,
		0xBD9DAF678BA187B9ULL,
		0x89816630A5DA29A6ULL,
		0xBF028DFF66F928DFULL,
		0x52CA7276D23A2F0FULL,
		0xC6EF1995453153D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41580D0614928062ULL,
		0x000102A02008C41CULL,
		0x452100306014238CULL,
		0x2D048845080107A1ULL,
		0x81012210044A0122ULL,
		0x9C0204C24649289EULL,
		0x42026210D210240BULL,
		0x424D081101300004ULL
	}};
	printf("Test Case 444\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4A49CE50422735CDULL,
		0x260068AA179C56B1ULL,
		0x1BC44A7D450FD658ULL,
		0x79D7120DC1552F80ULL,
		0xB57E625C580D20A2ULL,
		0xA4569ADDDD29FEF9ULL,
		0xC24E11563E2B34B2ULL,
		0xD292AC7D79112669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1440E2607B2683CULL,
		0xE5E278B48220894EULL,
		0xCE61060E259E2424ULL,
		0x3F451D4E8AAB18C1ULL,
		0xFA911FFD953B3943ULL,
		0x73439D35EF0C5DFAULL,
		0x8E4A4ECB836A1477ULL,
		0xF14A5CD10F78ED57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40400E000222200CULL,
		0x240068A002000000ULL,
		0x0A40020C050E0400ULL,
		0x3945100C80010880ULL,
		0xB010025C10092002ULL,
		0x20429815CD085CF8ULL,
		0x824A0042022A1432ULL,
		0xD0020C5109102441ULL
	}};
	printf("Test Case 445\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x220780E73B9267A0ULL,
		0x7AB25568B149A77FULL,
		0xFFB5174A6081862DULL,
		0x1B4DF33FBEBE2DF0ULL,
		0x23831F699950E523ULL,
		0x6D5621CC9EB87A7FULL,
		0x5297C07001F8C0D6ULL,
		0x6698EC3491708B98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70745B2F6A49D7EDULL,
		0xC8DA12B51E5AE300ULL,
		0xC69E9600FD2376B3ULL,
		0xB75477EAD5A718CDULL,
		0xCD50D64882E4BAC4ULL,
		0xA5EF11A6ADC2751AULL,
		0xC9F760598D0E02D4ULL,
		0xA1E42B67AA720552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x200400272A0047A0ULL,
		0x489210201048A300ULL,
		0xC694160060010621ULL,
		0x1344732A94A608C0ULL,
		0x010016488040A000ULL,
		0x254601848C80701AULL,
		0x40974050010800D4ULL,
		0x2080282480700110ULL
	}};
	printf("Test Case 446\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0C0D3EB751552827ULL,
		0xD52F40529A45CDD8ULL,
		0x88E223ED0D72F3F9ULL,
		0xACA0CD7BC2FC68EEULL,
		0x11DBE3FEA8E9FD54ULL,
		0x052F24C5EC03CC2BULL,
		0x3FA0725F8B788BD5ULL,
		0x7DB151A9FC1E0FCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7947ED32189E9709ULL,
		0x5A92CEE3A44DDB99ULL,
		0xAD6EA16DB4239D49ULL,
		0x29DBB7CA1AEC189EULL,
		0x60EE3DBBBBD169FEULL,
		0xC6050F236FDB261AULL,
		0xBC4DFBC3BA40C6A3ULL,
		0xD4E4CB9D2F3166DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08052C3210140001ULL,
		0x500240428045C998ULL,
		0x8862216D04229149ULL,
		0x2880854A02EC088EULL,
		0x00CA21BAA8C16954ULL,
		0x040504016C03040AULL,
		0x3C0072438A408281ULL,
		0x54A041892C1006CCULL
	}};
	printf("Test Case 447\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEB6A850592AF3DE8ULL,
		0x14A775F2FA97E04EULL,
		0x8505D7DDCCFF52D6ULL,
		0x72B3B3E3DB8B19F3ULL,
		0xDEC25564D36C42F0ULL,
		0x564C6756E736C667ULL,
		0x02E9BF5E78535C0FULL,
		0xEBBD32DA8D2C36ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB09178E54ED40F3DULL,
		0xD61815D0C818E6B7ULL,
		0x92020331F16CDADBULL,
		0x6B6003ACEF689916ULL,
		0x28E53645C0C6D8F1ULL,
		0x16B96CE0ACB2B402ULL,
		0xEB28603CB6DA9CEFULL,
		0x76DBCDC7BEE557CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA000000502840D28ULL,
		0x140015D0C810E006ULL,
		0x80000311C06C52D2ULL,
		0x622003A0CB081912ULL,
		0x08C01444C04440F0ULL,
		0x16086440A4328402ULL,
		0x0228201C30521C0FULL,
		0x629900C28C24168CULL
	}};
	printf("Test Case 448\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x37A5D0A03705E02FULL,
		0x6BC41FA77C53D473ULL,
		0x8DA665809F9CD95DULL,
		0xC41199D3130E0D61ULL,
		0x55C25BB4A3DC5FCDULL,
		0x34BFF5691C16CD2AULL,
		0xF11DBAF0B75DC71AULL,
		0xC1BE28621117B2A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35A4C06E20DB3B7AULL,
		0x398BE339C6DDCA92ULL,
		0x9CE1DE49114DB35FULL,
		0xEA96E61FAA959EE7ULL,
		0x48EFD7B36180EA8BULL,
		0x59B815907E960030ULL,
		0xAB1CEC68337CE6AEULL,
		0x8488C011AB3E52BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x35A4C0202001202AULL,
		0x298003214451C012ULL,
		0x8CA04400110C915DULL,
		0xC010801302040C61ULL,
		0x40C253B021804A89ULL,
		0x10B815001C160020ULL,
		0xA11CA860335CC60AULL,
		0x80880000011612A8ULL
	}};
	printf("Test Case 449\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xCD4A35CE855E5BD9ULL,
		0xC91597B30912BC90ULL,
		0x4A7E523AC301FCBAULL,
		0x9AA138C953BAF60CULL,
		0xB8816FA47923FF14ULL,
		0x4FA9372B83F369F5ULL,
		0xBFD359AABF280FD2ULL,
		0x627B86EE1FA4495BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB622DD6B2EEFCC3ULL,
		0xA33B5622B126AE62ULL,
		0xD3A03F5054522FD4ULL,
		0x4886CCEA9F23E27EULL,
		0x993025630C598C18ULL,
		0x249DAAF1D4A0FC77ULL,
		0xD03F520FA121AE46ULL,
		0xFB3BB87BA5911960ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC94225C6804E58C1ULL,
		0x811116220102AC00ULL,
		0x4220121040002C90ULL,
		0x088008C81322E20CULL,
		0x9800252008018C10ULL,
		0x0489222180A06875ULL,
		0x9013500AA1200E42ULL,
		0x623B806A05800940ULL
	}};
	printf("Test Case 450\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3973947CA7E2894DULL,
		0xE0A3E800319BC7C4ULL,
		0x7645E2584418ACCEULL,
		0xAF8B022D4AD0F6DFULL,
		0x67596FC0EDDFE22DULL,
		0x84D8F6DDDBE19F9AULL,
		0x7B797C8EDE5A3B9EULL,
		0x9474E42AD816E941ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE146DE27356378A5ULL,
		0xD0C69DFE8AD0BC5DULL,
		0x068093EA1F6AEB24ULL,
		0xEB546A68366C1695ULL,
		0x95BEBC941E80DEADULL,
		0xDE08BA798293E61CULL,
		0x466E850AE9EC7AAEULL,
		0x0FB2F0A6FB496F28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2142942425620805ULL,
		0xC082880000908444ULL,
		0x060082480408A804ULL,
		0xAB00022802401695ULL,
		0x05182C800C80C22DULL,
		0x8408B25982818618ULL,
		0x4268040AC8483A8EULL,
		0x0430E022D8006900ULL
	}};
	printf("Test Case 451\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC240FFED94B669F4ULL,
		0x78B5AE7D0ACE0A73ULL,
		0x9132D4635E0F0FF2ULL,
		0xA5EE0E459C0D4B25ULL,
		0xC848E66FB1FB6F51ULL,
		0xFDB7DFD4761D118FULL,
		0x34F3AEBA66051406ULL,
		0x73D34D71CC064F8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5658829B8BE7D36ULL,
		0x7435FC3DD7F27905ULL,
		0xC932E29AADD02301ULL,
		0xA5017AE3664FD1EEULL,
		0x903BF64CB707109FULL,
		0x47C7534BA9CAFBE5ULL,
		0x13DA8085A3228D3FULL,
		0x5B7F2D9AD930B192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8040882990B66934ULL,
		0x7035AC3D02C20801ULL,
		0x8132C0020C000300ULL,
		0xA5000A41040D4124ULL,
		0x8008E64CB1030011ULL,
		0x4587534020081185ULL,
		0x10D2808022000406ULL,
		0x53530D10C8000182ULL
	}};
	printf("Test Case 452\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8AF90B9AC3F946ACULL,
		0xF7B01B0A62E30E47ULL,
		0xF1C09FEBB300F15FULL,
		0xA7AE1DB8197EA579ULL,
		0xF7355A6486D2E5E9ULL,
		0x253ED4BF5614777AULL,
		0xA1364EFC4B8220E7ULL,
		0x7178A509DCED346AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D8B175FFC892C6ULL,
		0xC39E58D90DCDCC9CULL,
		0x127F10714564DE3EULL,
		0xF915068FDE39ED25ULL,
		0xA3A79E0B78FF7DA8ULL,
		0xDD092A21166E546EULL,
		0x470B757422CE4582ULL,
		0xC6EDA6CF33170725ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00D80110C3C80284ULL,
		0xC390180800C10C04ULL,
		0x104010610100D01EULL,
		0xA10404881838A521ULL,
		0xA3251A0000D265A8ULL,
		0x050800211604546AULL,
		0x0102447402820082ULL,
		0x4068A40910050420ULL
	}};
	printf("Test Case 453\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x4F77A900384B68A1ULL,
		0x37CC801E743DB7F5ULL,
		0x59A1A52C3769E88DULL,
		0xB696E3A93A6D6D13ULL,
		0x21FBDEBE0B8F9AD2ULL,
		0xAFCC81971D673A8CULL,
		0xFF03B714DEAF7DF3ULL,
		0x39CEE66D5AB0F6BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4323E5465444F5D0ULL,
		0x4725CDE0FC7EDF1BULL,
		0x6D1723435C2E0A0CULL,
		0x0D017F3060F172ADULL,
		0xFF6B12238603C4FEULL,
		0xA6CC170224FA4C5DULL,
		0xBFDC7E68F8DA4306ULL,
		0x528DBA1F5AF55257ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4323A10010406080ULL,
		0x07048000743C9711ULL,
		0x490121001428080CULL,
		0x0400632020616001ULL,
		0x216B1222020380D2ULL,
		0xA6CC01020462080CULL,
		0xBF003600D88A4102ULL,
		0x108CA20D5AB05214ULL
	}};
	printf("Test Case 454\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE78BC1B749D6A8BFULL,
		0x107A51842E4F03E8ULL,
		0x32B84F2424E92EEDULL,
		0x59A5E5D7669F6CB0ULL,
		0x0B5DB3E10C98ACDFULL,
		0x53F470CC1238C171ULL,
		0xC845121BD19DE8AAULL,
		0x535566C55863B358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFECC8184F93A90DULL,
		0x38362147A4DCAE2BULL,
		0x3A61CB4B35023F6BULL,
		0x8107C714F3752310ULL,
		0x996C7E15D90BF1B1ULL,
		0x36CE93261BBC2A5AULL,
		0x16D52FEA2903DAF7ULL,
		0x639089E520EE2341ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE788C0104992A80DULL,
		0x10320104244C0228ULL,
		0x32204B0024002E69ULL,
		0x0105C51462152010ULL,
		0x094C32010808A091ULL,
		0x12C4100412380050ULL,
		0x0045020A0101C8A2ULL,
		0x431000C500622340ULL
	}};
	printf("Test Case 455\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xEA0C85D8F6C62E0FULL,
		0x2B34997B8DD8513CULL,
		0x5EAC2956F929CD3EULL,
		0x91747EA1C9D35BD8ULL,
		0x233469C8E3AC96D3ULL,
		0x60BD22C0A6439800ULL,
		0x792D09C7E6299FBEULL,
		0xCCB9B318A2FDB135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955A39FF874D409FULL,
		0x606856C41794F08AULL,
		0x4626AAD9DB6979C6ULL,
		0xDFC96E35E09D1731ULL,
		0x2CED8921D9A53556ULL,
		0x8581F591E3163386ULL,
		0x844E1DEB1BA00874ULL,
		0xB6FCE1BE78EA88DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800801D88644000FULL,
		0x2020104005905008ULL,
		0x46242850D9294906ULL,
		0x91406E21C0911310ULL,
		0x20240900C1A41452ULL,
		0x00812080A2021000ULL,
		0x000C09C302200834ULL,
		0x84B8A11820E88014ULL
	}};
	printf("Test Case 456\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xA50318C3AE7EF11EULL,
		0x39050AFA54943A61ULL,
		0x36B9C8703562F2D3ULL,
		0xF0DC0E2FEF31897AULL,
		0xE4764CFBDD299807ULL,
		0x49E60E31127AD2F9ULL,
		0x155862FBDC966BE9ULL,
		0x7942A10FBEF8AF5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD83F91184F0092F5ULL,
		0x43EB2EA1719B3DFCULL,
		0x5A3930909B31A601ULL,
		0xAD381ECBD48AEAB9ULL,
		0xBAB5ADDAAA3645CAULL,
		0x0839D4B4AF8F5282ULL,
		0xB3006BFA16B8E1C9ULL,
		0xCCCB26C2469436B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800310000E009014ULL,
		0x01010AA050903860ULL,
		0x123900101120A201ULL,
		0xA0180E0BC4008838ULL,
		0xA0340CDA88200002ULL,
		0x08200430020A5280ULL,
		0x110062FA149061C9ULL,
		0x4842200206902611ULL
	}};
	printf("Test Case 457\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x864C699B49D010F9ULL,
		0xB8CB76606865F6F0ULL,
		0x7FCA32650A145E60ULL,
		0x059F31690D89D239ULL,
		0x85E0797B10DB54A3ULL,
		0xB7802527755B277BULL,
		0x6281794054A6747EULL,
		0x31230DF0BC9F689DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5593EFB5FD69C1F6ULL,
		0xFDEBB04D14357FD1ULL,
		0x03450AAAC97B6380ULL,
		0x07EABE2338C12E95ULL,
		0xD0B931A7BD12657FULL,
		0xCA9B71117BAD367EULL,
		0x2B0A61807CCFB249ULL,
		0x0458156FC37EBBE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04006991494000F0ULL,
		0xB8CB3040002576D0ULL,
		0x0340022008104200ULL,
		0x058A302108810211ULL,
		0x80A0312310124423ULL,
		0x828021017109267AULL,
		0x2200610054863048ULL,
		0x00000560801E2880ULL
	}};
	printf("Test Case 458\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5AF9DEDD41936D81ULL,
		0x1AA7A87F8BA211F7ULL,
		0x1B1892895B5C37B9ULL,
		0xF909DE7365B4AECCULL,
		0xB7436F4634D2228EULL,
		0xB9C07DD220FD2FF1ULL,
		0x466D6569236E7F3AULL,
		0xD250E82D85A8F4F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4220F3EEB98D37C9ULL,
		0x95C8002A0F57C8BCULL,
		0xB4F6F1215D4E0DC8ULL,
		0x1B5B0FC4970D2649ULL,
		0x41017E35AB162E03ULL,
		0x1EF9183EA549FA98ULL,
		0xA0437971F7398FF4ULL,
		0x5D1B77AC7C27FB79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4220D2CC01812581ULL,
		0x1080002A0B0200B4ULL,
		0x10109001594C0588ULL,
		0x19090E4005042648ULL,
		0x01016E0420122202ULL,
		0x18C0181220492A90ULL,
		0x0041616123280F30ULL,
		0x5010602C0420F070ULL
	}};
	printf("Test Case 459\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xE9E895C51DBD57BEULL,
		0x994CA24220E7BDF4ULL,
		0xC88073C6C25577CAULL,
		0x192E0604E734B1A4ULL,
		0x99CC88666F915D8AULL,
		0x073D66A8BF67315DULL,
		0xECEF15501D386A07ULL,
		0xB8B393923D366ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE05EDA87C445F33BULL,
		0xE5A90263DF3B7574ULL,
		0x8100AAC3DDE10084ULL,
		0x69FA323051BD12C7ULL,
		0x8F9420A5C8CF2459ULL,
		0xC55481C31D42E1F8ULL,
		0xBF7111FF2F5AD0BDULL,
		0x9E231BEC348461EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE04890850405533AULL,
		0x8108024200233574ULL,
		0x800022C2C0410080ULL,
		0x092A020041341084ULL,
		0x8984002448810408ULL,
		0x051400801D422158ULL,
		0xAC6111500D184005ULL,
		0x98231380340460CCULL
	}};
	printf("Test Case 460\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB218449E6CC9C252ULL,
		0x502E0AB646C4697CULL,
		0x04E7583A92FC1476ULL,
		0xFF51AEB1AB56F1CEULL,
		0x956117E4AFD491C4ULL,
		0x956152F43F46A778ULL,
		0xF14CDA8E9637CF0BULL,
		0x5970F6DD5D09AC37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62894F962E82AE05ULL,
		0x726BC66F4CA4D6A9ULL,
		0x671878457E79AD51ULL,
		0xD317AC383CB6C166ULL,
		0x35EBB3024382135EULL,
		0xD48750B18F4A9F79ULL,
		0x11F54A2D489ACF48ULL,
		0x42E76906002121B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x220844962C808200ULL,
		0x502A022644844028ULL,
		0x0400580012780450ULL,
		0xD311AC302816C146ULL,
		0x1561130003801144ULL,
		0x940150B00F428778ULL,
		0x11444A0C0012CF08ULL,
		0x4060600400012034ULL
	}};
	printf("Test Case 461\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1D464E902E129E24ULL,
		0x7BEE8CFE1AFEFB1CULL,
		0x97DA2D96ED9EB0F1ULL,
		0xDB2EA0E4647EC807ULL,
		0x71AD2DE49D4A60CFULL,
		0x761009EF5E679DC0ULL,
		0xBC5334EA5002B642ULL,
		0x41AEA8A07E741248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4A571AB771FB0EULL,
		0xFD7B3E67CBB7FCC4ULL,
		0x752C932B905EF760ULL,
		0x669DCDA7D7E0562BULL,
		0xD4F3990FB46E8B7FULL,
		0x0D6BECA70EBE5360ULL,
		0x5D5102C78CACB79FULL,
		0x095C3ABAE4775EBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D42461026109A04ULL,
		0x796A0C660AB6F804ULL,
		0x15080102801EB060ULL,
		0x420C80A444604003ULL,
		0x50A10904944A004FULL,
		0x040008A70E261140ULL,
		0x1C5100C20000B602ULL,
		0x010C28A064741208ULL
	}};
	printf("Test Case 462\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xF7B36F60795A9AFFULL,
		0xE724FA79A7F8860CULL,
		0x3DAE5459D299F5F9ULL,
		0x51D696D0C9CFADABULL,
		0x5B164D6A0864D6B6ULL,
		0x65389F15487AD1C7ULL,
		0xCF0C5E357742A250ULL,
		0xA68D7D9F063FA692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA752DFCFA3C369E8ULL,
		0xFD1362C5D065C999ULL,
		0x3C9636B2CCA8F64BULL,
		0xB0C074507868A943ULL,
		0x0382D0F05005CF7CULL,
		0xB202EB3002A2D4D0ULL,
		0xFC3B50254865FFE2ULL,
		0xE0F3564F315E7365ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7124F40214208E8ULL,
		0xE500624180608008ULL,
		0x3C861410C088F449ULL,
		0x10C014504848A903ULL,
		0x030240600004C634ULL,
		0x20008B100022D0C0ULL,
		0xCC0850254040A240ULL,
		0xA081540F001E2200ULL
	}};
	printf("Test Case 463\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x26CE738096E05335ULL,
		0x5AF0127D5777E958ULL,
		0x8DEF7F9E56BAB11BULL,
		0xEF3BF02D24EBCD81ULL,
		0x6A5548D3A86D59EDULL,
		0x7B012944DC37AC83ULL,
		0x33967F0F9FBA506AULL,
		0x9804B96FF352BD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE63CF56D7A959EFULL,
		0xE3F4EBCC9112E30EULL,
		0x3D1EF477BA695B82ULL,
		0x2C1718D86286BCC6ULL,
		0x67D7BB3E9CD39322ULL,
		0x673A725C5D8B0B03ULL,
		0x1F1CCBF086AC3637ULL,
		0x36CFA93C83697B05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0642430096A05125ULL,
		0x42F0024C1112E108ULL,
		0x0D0E741612281102ULL,
		0x2C13100820828C80ULL,
		0x6255081288411120ULL,
		0x630020445C030803ULL,
		0x13144B0086A81022ULL,
		0x1004A92C83403901ULL
	}};
	printf("Test Case 464\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x76DF1FC494FF44FEULL,
		0x79C57A9DC79B75F0ULL,
		0x6FE252E44D09A401ULL,
		0xC412C2A7199B07F2ULL,
		0xDE9C2CE91B011AF2ULL,
		0xE050AEDE682066FDULL,
		0x68FD5716DCDCF891ULL,
		0x4663C024EF42D6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9F058203F669E7ULL,
		0xCF1A232CE5D96C2CULL,
		0x7D2884308EBD91A4ULL,
		0x2DBE46CA024C0C52ULL,
		0xE634B6C9E124F9B6ULL,
		0xE8EE3854F8EF98EEULL,
		0xE891E11AF067C6BAULL,
		0x591BF50A2D0C83F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x669F058000F640E6ULL,
		0x4900220CC5996420ULL,
		0x6D2000200C098000ULL,
		0x0412428200080452ULL,
		0xC61424C9010018B2ULL,
		0xE0402854682000ECULL,
		0x68914112D044C090ULL,
		0x4003C0002D0082D4ULL
	}};
	printf("Test Case 465\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9096F8D14CFBC22CULL,
		0x6D634BC9544AC4A3ULL,
		0x5BC2DA3D447FC36FULL,
		0xBF86ABB8BCD55475ULL,
		0x3B8F8EF7A81A5C8EULL,
		0x4FB0695DAC594209ULL,
		0xEBA8AE0A28BE3DE2ULL,
		0xDD8AC23AE5E0FB9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933FA1FE3C54883DULL,
		0x5932ABBD38D4D909ULL,
		0x1AB800E6D263571DULL,
		0xD8DC4BD2AB6B9D22ULL,
		0x22734D0AC7937E3CULL,
		0xEA47DF5B1DA22874ULL,
		0x0BAED9840F39CBE9ULL,
		0xDD9784489785590AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9016A0D00C50802CULL,
		0x49220B891040C001ULL,
		0x1A8000244063430DULL,
		0x98840B90A8411420ULL,
		0x22030C0280125C0CULL,
		0x4A0049590C000000ULL,
		0x0BA88800083809E0ULL,
		0xDD82800885805908ULL
	}};
	printf("Test Case 466\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x324131257908CE52ULL,
		0x3F8B621AAFB916E7ULL,
		0x011D4691A9B8CD4AULL,
		0x407A610D9FA9C56CULL,
		0x0CFDB9E9D74706F7ULL,
		0x4148DBAC625EAF09ULL,
		0x2D36328918E67644ULL,
		0x3CBD9E07CBDBD68AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77305EB1BB950AA1ULL,
		0xEC1DC4D0721C0D94ULL,
		0x5B60A7AA1446EC86ULL,
		0xFE171BACF803A36EULL,
		0xCFEC220678C490D8ULL,
		0x332A9F6DAD72FE79ULL,
		0x64B5ACB6D76C4520ULL,
		0xF5951D03F2952569ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3200102139000A00ULL,
		0x2C09401022180484ULL,
		0x010006800000CC02ULL,
		0x4012010C9801816CULL,
		0x0CEC2000504400D0ULL,
		0x01089B2C2052AE09ULL,
		0x2434208010644400ULL,
		0x34951C03C2910408ULL
	}};
	printf("Test Case 467\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x90942EF16D099F41ULL,
		0xCB7FB8FFF16A0595ULL,
		0x3661153347B5266DULL,
		0xDC8296C05A9959A1ULL,
		0xE77B319B479ACBDBULL,
		0x8705B71C78C1BF3BULL,
		0x9CA4DBB3AD920923ULL,
		0x6EF67E4CA6A08A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF254CEDAD5B44D54ULL,
		0x280AFC7A294068B3ULL,
		0x71D1B5A52EE267B8ULL,
		0xFD5C2FCC79B3D07BULL,
		0x21568AC96EC5B919ULL,
		0x4B37F5552724A9DEULL,
		0x13487A4F1A20766BULL,
		0xD7E9F57BB1C364A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90140ED045000D40ULL,
		0x080AB87A21400091ULL,
		0x3041152106A02628ULL,
		0xDC0006C058915021ULL,
		0x2152008946808919ULL,
		0x0305B5142000A91AULL,
		0x10005A0308000023ULL,
		0x46E07448A0800024ULL
	}};
	printf("Test Case 468\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB3F34CDB3B4447C2ULL,
		0xE402E36F2AC4F163ULL,
		0x4CDC24358A8F3ED3ULL,
		0xD806DC22C963E280ULL,
		0x910D6A98C12DBAEFULL,
		0xB845F5BDF610029DULL,
		0xDF77BCFEE0726304ULL,
		0xF5D156B8B0A7F152ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF6A4C655B432B60ULL,
		0x3018F520EEEEF942ULL,
		0x1C3D559E855BA9C5ULL,
		0x9B7A5007FD398907ULL,
		0x0C04715F73D2861FULL,
		0x22F6BAD5136152F8ULL,
		0x050A5A547450CAC1ULL,
		0x23F03D3DE5F805BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3624C411B400340ULL,
		0x2000E1202AC4F142ULL,
		0x0C1C0414800B28C1ULL,
		0x98025002C9218000ULL,
		0x000460184100820FULL,
		0x2044B09512000298ULL,
		0x0502185460504200ULL,
		0x21D01438A0A00112ULL
	}};
	printf("Test Case 469\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC08BEB1C4E2B481EULL,
		0x2E5E77175E6AA901ULL,
		0x723BE96E6E5D20C7ULL,
		0xA2DE6FEF722A75D6ULL,
		0x59F898C92CF8ED12ULL,
		0x1995104D485AE191ULL,
		0x90BB7EF56C99F389ULL,
		0x16A932790E204BC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB3014800617A963ULL,
		0x75DD728B4764A5F1ULL,
		0xF2658BECEF6A6265ULL,
		0x55B96822E2A27547ULL,
		0xA6FA12D63BF05CA9ULL,
		0xEDAAE613B76393C4ULL,
		0x2E85343204BDA15EULL,
		0x5BFEC9F31D5DCDBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC000000006030802ULL,
		0x245C72034660A101ULL,
		0x7221896C6E482045ULL,
		0x0098682262227546ULL,
		0x00F810C028F04C00ULL,
		0x0980000100428180ULL,
		0x008134300499A108ULL,
		0x12A800710C004988ULL
	}};
	printf("Test Case 470\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x7C3C3709B3FAF827ULL,
		0x310DE478ED535000ULL,
		0x390ABEC0EEEE182DULL,
		0x2BD9A38583F0D46AULL,
		0x5AB9C8008461B889ULL,
		0xBB39BD5B04E605AEULL,
		0x5CF758CE7471D41BULL,
		0x24C899D30F201D69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42107072440EAD5EULL,
		0xF030E071A5727A1AULL,
		0x39D0A3E425847131ULL,
		0x835D9D98F1596431ULL,
		0xE015CF2F141FA949ULL,
		0xA1258E159A58C957ULL,
		0x70621EBC157717D5ULL,
		0xD2E8BBA352F543E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40103000000AA806ULL,
		0x3000E070A5525000ULL,
		0x3900A2C024841021ULL,
		0x0359818081504420ULL,
		0x4011C8000401A809ULL,
		0xA1218C1100400106ULL,
		0x5062188C14711411ULL,
		0x00C8998302200160ULL
	}};
	printf("Test Case 471\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x74267CEA4E158443ULL,
		0xA197A59731E9146DULL,
		0xC1847840E01CB2D6ULL,
		0xCDDA9A534B3D9732ULL,
		0xC13CC999FB078E7CULL,
		0x3E5D1C9EB31552BBULL,
		0x817ABF8D498577D6ULL,
		0x05E3B43EC7EB9E9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B49A42B1482959BULL,
		0x40BE877315552B53ULL,
		0x6E10838443A4EE88ULL,
		0xC671D4F9A58EC229ULL,
		0x2D3B2B306C827BCEULL,
		0xB0AB005F13A75BB4ULL,
		0xAB8579DCFB138E98ULL,
		0x74A4FC10D9B2C821ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000242A04008403ULL,
		0x0096851311410041ULL,
		0x400000004004A280ULL,
		0xC4509051010C8220ULL,
		0x0138091068020A4CULL,
		0x3009001E130552B0ULL,
		0x8100398C49010690ULL,
		0x04A0B410C1A28801ULL
	}};
	printf("Test Case 472\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x12B1322C5D9065D2ULL,
		0xBAB53485199C09FDULL,
		0x0393E18997584AD5ULL,
		0xBB62DDEA4293ECD0ULL,
		0xB0C8F7816556E320ULL,
		0xA16CC1427A586CBEULL,
		0xCB60A637EC78F198ULL,
		0x90F879236F74229FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA818334D9C4FA9ULL,
		0xC38530A26B6FF035ULL,
		0xDFCA310A19CE0BE0ULL,
		0x971AA61BAD5D25E9ULL,
		0x45776D0F16CDD89BULL,
		0x4FC5384CDB110713ULL,
		0xEECE60A7C26D8467ULL,
		0x8E9C5EE9FB57AA90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A010204D904580ULL,
		0x82853080090C0035ULL,
		0x0382210811480AC0ULL,
		0x9302840A001124C0ULL,
		0x004065010444C000ULL,
		0x014400405A100412ULL,
		0xCA402027C0688000ULL,
		0x809858216B542290ULL
	}};
	printf("Test Case 473\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x589CCE87BF61BAB9ULL,
		0xF7CC82A0EF2F4EB2ULL,
		0xC4FFBD3EB096595AULL,
		0xDF447FCA10821EA9ULL,
		0xA51C91B0D806BA6BULL,
		0xC6B470131B3A64C5ULL,
		0x5144393ADBF9346EULL,
		0x0140C881F7110C64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39B587A58D5CD3F9ULL,
		0x771B2AE0036CDFBEULL,
		0x84093A13739BCB97ULL,
		0x5E9B20C4941D9BC6ULL,
		0x1E4AA5C39D34D66DULL,
		0xA3868C679AE11CC9ULL,
		0x0F7C81134D114775ULL,
		0x1EB0672A2903F1A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x189486858D4092B9ULL,
		0x770802A0032C4EB2ULL,
		0x8409381230924912ULL,
		0x5E0020C010001A80ULL,
		0x0408818098049269ULL,
		0x828400031A2004C1ULL,
		0x0144011249110464ULL,
		0x0000400021010024ULL
	}};
	printf("Test Case 474\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6E49D19996846642ULL,
		0x00CF60AC72DBAEBCULL,
		0x63F3FF9549677BEDULL,
		0x01EC88C282CEF930ULL,
		0x73F79DA9F38419EDULL,
		0x51C62BD7C16ADBB0ULL,
		0x9B70CEEA45D16C97ULL,
		0x740C5B1BEE6250CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8B49DA8ADCF540ULL,
		0x5D1DCBC4F2AEA848ULL,
		0x899D481BF2B21994ULL,
		0xEA85D8F40508320DULL,
		0x0606735EE3DD15ADULL,
		0xD7F4494FA4FE685AULL,
		0x299FD37C936699CAULL,
		0xC100744CAF0601C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A09419882846440ULL,
		0x000D4084728AA808ULL,
		0x0191481140221984ULL,
		0x008488C000083000ULL,
		0x02061108E38411ADULL,
		0x51C40947806A4810ULL,
		0x0910C26801400882ULL,
		0x40005008AE0200C0ULL
	}};
	printf("Test Case 475\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB4FFB3D71B4F7E5AULL,
		0xF2EF9726012D076CULL,
		0x8C52DF840AD1BE72ULL,
		0xB8970B43B2950BE9ULL,
		0xD03A91B7B0510BD2ULL,
		0x1ECAAF5810DA182DULL,
		0x40FC5D542C0BB2ECULL,
		0xA7DF1FEF1F8E4F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44715F8C73164FE7ULL,
		0x7F201D7D3D37EA1CULL,
		0x7DB4FC06E7EC1C62ULL,
		0xCDFC1D0AA8E51B5AULL,
		0xBAE5CA03DBEF2719ULL,
		0xD232B101E00350FDULL,
		0xBA83F4FB8506FCC0ULL,
		0x89720D1A503F5941ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0471138413064E42ULL,
		0x722015240125020CULL,
		0x0C10DC0402C01C62ULL,
		0x88940902A0850B48ULL,
		0x9020800390410310ULL,
		0x1202A1000002102DULL,
		0x008054500402B0C0ULL,
		0x81520D0A100E4940ULL
	}};
	printf("Test Case 476\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9A5E3B563A773689ULL,
		0x1AB28C1E6A4451F4ULL,
		0xE86E7AC420D24585ULL,
		0x0F857ED240EB3738ULL,
		0x1367A975FC83A3F2ULL,
		0x49526AC29D117288ULL,
		0x001CA408352CECE1ULL,
		0x77C720111344E401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD088D37508F6AFCULL,
		0x31B946F3811AAF3CULL,
		0x805BDD1AAD3A5209ULL,
		0x4F2D32373FDBF98DULL,
		0x7C0B33F249487CAFULL,
		0x98F1E44BE98D87C5ULL,
		0x7557B95D8B0D0412ULL,
		0xDA9595CBFA10DA68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8808091610072288ULL,
		0x10B0041200000134ULL,
		0x804A580020124001ULL,
		0x0F05321200CB3108ULL,
		0x10032170480020A2ULL,
		0x0850604289010280ULL,
		0x0014A008010C0400ULL,
		0x528500011200C000ULL
	}};
	printf("Test Case 477\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD260761D7F4D1C21ULL,
		0xE8AA339C2863AA06ULL,
		0x8585066E1E5F4325ULL,
		0x20A92261947EC688ULL,
		0x1C96B7F0E2764A9BULL,
		0x89E031D4A8616F70ULL,
		0x2C39F28F86794F58ULL,
		0x4F94E8196009BDEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DBBB0C9467657D6ULL,
		0xA37E08FC3F4C7DD9ULL,
		0x2AA04A7E387AC046ULL,
		0xA98CFC276807CF6DULL,
		0x87569BD5F094157EULL,
		0x0C871996EBDDC6E9ULL,
		0x051E3401D64F4440ULL,
		0x3EC3F96DDE1BF3C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1020300946441400ULL,
		0xA02A009C28402800ULL,
		0x0080026E185A4004ULL,
		0x208820210006C608ULL,
		0x041693D0E014001AULL,
		0x08801194A8414660ULL,
		0x0418300186494440ULL,
		0x0E80E8094009B1C2ULL
	}};
	printf("Test Case 478\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC46B2EFE23032257ULL,
		0xE75CA79C97973919ULL,
		0x728030BBAFEA2117ULL,
		0x56F979C5D9F47B86ULL,
		0x20D914AEB40BEF59ULL,
		0x0DF7665D5D0384ECULL,
		0x9CB2B76A39952743ULL,
		0x4867CB862FA7455CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF8EC26D9BC1A33CULL,
		0xDFED712FDC79E410ULL,
		0xA9FD780D5FFF353CULL,
		0xEF357F1BBC675CEBULL,
		0x061991C7845E1E14ULL,
		0xD41C130DCE31C9D3ULL,
		0xA48406FCF40967C0ULL,
		0x65DE95F7522D8BA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC40A026C03012214ULL,
		0xC74C210C94112010ULL,
		0x208030090FEA2114ULL,
		0x4631790198645882ULL,
		0x00191086840A0E10ULL,
		0x0414020D4C0180C0ULL,
		0x8480066830012740ULL,
		0x4046818602250100ULL
	}};
	printf("Test Case 479\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0F5CA50E422616FCULL,
		0x1055905D6A620665ULL,
		0x5BE5677EBDE48931ULL,
		0x57603C27DC8328AFULL,
		0x13BAA3CEA9519A99ULL,
		0xE28E02EA50959ADCULL,
		0x65396C0048B5AB06ULL,
		0xB126527F5169AF38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F2D13AFF4E54C93ULL,
		0x7A5D9F3493DFAEBDULL,
		0xA1B51E87968617B0ULL,
		0x6A85B323801C91B6ULL,
		0xF97C6CF55A47A437ULL,
		0x951D2CACE48B6829ULL,
		0x10AA9507D753FAE1ULL,
		0xAFAD848581FAAE8AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F0C010E40240490ULL,
		0x1055901402420625ULL,
		0x01A5060694840130ULL,
		0x42003023800000A6ULL,
		0x113820C408418011ULL,
		0x800C00A840810808ULL,
		0x002804004011AA00ULL,
		0xA12400050168AE08ULL
	}};
	printf("Test Case 480\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC69A726A2F97B66BULL,
		0x3B8B866D6A3E97FBULL,
		0xAC9E09BB816888FBULL,
		0x9E3DEBE6FB5F85F3ULL,
		0x9DE56B658AA46D94ULL,
		0xF827501D203C4395ULL,
		0x5C885DBE63F81321ULL,
		0xC6F7C4B41C30B7ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40BC179EA35D711CULL,
		0x8F4CF336E90E9AD0ULL,
		0x2D702DFC6FDA8E0EULL,
		0x721C7831E2EAB802ULL,
		0x5E0F8D6704B6C33BULL,
		0x35DDBDF6D25CE449ULL,
		0x4FFC7A24940BA265ULL,
		0x0EED8863A804176BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4098120A23153008ULL,
		0x0B088224680E92D0ULL,
		0x2C1009B80148880AULL,
		0x121C6820E24A8002ULL,
		0x1C05096500A44110ULL,
		0x30051014001C4001ULL,
		0x4C88582400080221ULL,
		0x06E5802008001729ULL
	}};
	printf("Test Case 481\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9B7A126C9D79AFF6ULL,
		0xB34E7B4B9391A8BEULL,
		0x11C80618266A49E8ULL,
		0x7C66E9D622B18233ULL,
		0x4968F27EEEEBF343ULL,
		0x5A588189F5CE1F74ULL,
		0x8CB9139543AC8AFFULL,
		0x826BC224D2430E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205F9D739D9F925EULL,
		0x64628EC95C0D898AULL,
		0x0348FA944F1DF8AFULL,
		0x184E95F5C8E873E2ULL,
		0x6636CA27BB7AF5FCULL,
		0x8979E58DAFFA6B0FULL,
		0x75C33F92C7EF085FULL,
		0x5B8C9A3514AFDE87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x005A10609D198256ULL,
		0x20420A491001888AULL,
		0x01480210060848A8ULL,
		0x184681D400A00222ULL,
		0x4020C226AA6AF140ULL,
		0x08588189A5CA0B04ULL,
		0x0481139043AC085FULL,
		0x0208822410030E00ULL
	}};
	printf("Test Case 482\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x83A94160B3DAAA20ULL,
		0x7BA4A9D962AC676EULL,
		0x8A2D0A4028C4189BULL,
		0x9DF40B45A79DB64AULL,
		0x28785B6ED92FA6D3ULL,
		0x213D85B4BB85D116ULL,
		0x20A3672AD6E54F55ULL,
		0x46DD4716D1E2C222ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EAEAC0CE5CAB089ULL,
		0x46C61D897C10EE75ULL,
		0xC209EE07983DDFADULL,
		0x42BFF14DDFF05D31ULL,
		0xB52DB06FF950B0D5ULL,
		0x06049FE8B0DA2DC8ULL,
		0xC8F09AA739517ED2ULL,
		0x31D146B709CC4480ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A80000A1CAA000ULL,
		0x4284098960006664ULL,
		0x82090A0008041889ULL,
		0x00B4014587901400ULL,
		0x2028106ED900A0D1ULL,
		0x000485A0B0800100ULL,
		0x00A0022210414E50ULL,
		0x00D1461601C04000ULL
	}};
	printf("Test Case 483\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x6146663A31EECC8EULL,
		0xF6C02E611BA42C77ULL,
		0xE661CC47C2F0C9ACULL,
		0x08C14543741C4B1BULL,
		0x25B4981F65DA4D45ULL,
		0xF3771B8855F63907ULL,
		0xE2DA9555CE86D5D6ULL,
		0x727CC8DCA66B57C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x205C4F4C24A710DFULL,
		0x28E40ACE5D0CA1D5ULL,
		0x47FDAE06786ED9E0ULL,
		0x5D6339CFBB605554ULL,
		0xB2632C907CC96B50ULL,
		0xA9FA9F99B05D760EULL,
		0x4C586CBE13E03395ULL,
		0xE5206F94484D55BAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2044460820A6008EULL,
		0x20C00A4019042055ULL,
		0x46618C064060C9A0ULL,
		0x0841014330004110ULL,
		0x2020081064C84940ULL,
		0xA1721B8810543006ULL,
		0x4058041402801194ULL,
		0x6020489400495582ULL
	}};
	printf("Test Case 484\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x9D3FE8C7088B1078ULL,
		0x0EFC2CC15C7F51CDULL,
		0x2367BEE77A0D9872ULL,
		0xC298492BA0599B7BULL,
		0xD713C530A02BCCEEULL,
		0x069F86304C0701BDULL,
		0xD637EC37203ECD8CULL,
		0xF86F299DD2DC87BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x402F4433AEFD8144ULL,
		0x176A63E01706877CULL,
		0x033C9F6568C9DAB3ULL,
		0x9B482687889EA121ULL,
		0x6CFBCA54B2CAA96EULL,
		0x506A77E7BBF51CE8ULL,
		0x472CB5A7160D18BAULL,
		0xC0D29F3A15F63166ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002F400308890040ULL,
		0x066820C01406014CULL,
		0x03249E6568099832ULL,
		0x8208000380188121ULL,
		0x4413C010A00A886EULL,
		0x000A0620080500A8ULL,
		0x4624A427000C0888ULL,
		0xC042091810D40124ULL
	}};
	printf("Test Case 485\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x1AD3312351AA5ABDULL,
		0x08140D59DB4317FCULL,
		0x27BEB2EF82372C4DULL,
		0x628DC1A2B901D7B9ULL,
		0xC735FBF1515CFF07ULL,
		0xA6F42635971ACBD8ULL,
		0xE924DA19DEE53F56ULL,
		0x132D41E5F51A3DF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5469A56B2EB54871ULL,
		0xF72C8295F10C2F20ULL,
		0x637BCE5A78F2AC10ULL,
		0x330A2B5B151C1FDAULL,
		0xE795745897434A00ULL,
		0xCAA808D7CF41BA30ULL,
		0x12F6C4952631F42FULL,
		0x6CC2C2D0EC629D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1041212300A04831ULL,
		0x00040011D1000720ULL,
		0x233A824A00322C00ULL,
		0x2208010211001798ULL,
		0xC715705011404A00ULL,
		0x82A0001587008A10ULL,
		0x0024C01106213406ULL,
		0x000040C0E4021D80ULL
	}};
	printf("Test Case 486\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x72E83A905886B04BULL,
		0x72DA2BC8CF18C024ULL,
		0x001F5E846E1F6C2EULL,
		0x4E84EADD1B59FD83ULL,
		0x2A9316F9EEA1CAD8ULL,
		0xE80C7B3AF83417E1ULL,
		0x52EC67A4DDA40E44ULL,
		0x42D69E165B05A53BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D3FF50AF34C79F7ULL,
		0x12905B87C433822AULL,
		0x0DD04F7D807FB0EEULL,
		0x21EC7A34581B6A1CULL,
		0x850420B5B3047A00ULL,
		0xF2C07BBCF1024BECULL,
		0x7B51BE7C3E6007FFULL,
		0xA68FF6CAA94D9849ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0028300050043043ULL,
		0x12900B80C4108020ULL,
		0x00104E04001F202EULL,
		0x00846A1418196800ULL,
		0x000000B1A2004A00ULL,
		0xE0007B38F00003E0ULL,
		0x524026241C200644ULL,
		0x0286960209058009ULL
	}};
	printf("Test Case 487\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x39BD7C632FE1D232ULL,
		0xB574A6D3AE14E3D7ULL,
		0x81086FFDD974F539ULL,
		0x78124FF1BDDE7E3CULL,
		0x1D271CEFBEA0697AULL,
		0x03CC6F7FAFBDA503ULL,
		0xDDAD38530A76748FULL,
		0x628B867DBF547488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x078B6D63CBB8E1A1ULL,
		0x90033ABAAC1D8AF9ULL,
		0x503368F3610D91BAULL,
		0xDB5F4F7D39AD835FULL,
		0xF1FCC70B561F55C3ULL,
		0x90118F9E65AA2C43ULL,
		0xF5E97FD9B9D1CC88ULL,
		0xE8839AD64189B14CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01896C630BA0C020ULL,
		0x90002292AC1482D1ULL,
		0x000068F141049138ULL,
		0x58124F71398C021CULL,
		0x1124040B16004142ULL,
		0x00000F1E25A82403ULL,
		0xD5A9385108504488ULL,
		0x6083825401003008ULL
	}};
	printf("Test Case 488\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x3F709AC3D923F4C5ULL,
		0x1A1A4EA7170D6E41ULL,
		0x92A296DFD650AC2EULL,
		0x17491015D3D8990BULL,
		0x958ED9A5C39F1E22ULL,
		0x1241278AC32A5278ULL,
		0xC2111DA186AD7CCDULL,
		0xC316621BD71F3D31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B06DF122944D48ULL,
		0x1CB77BBCF771146BULL,
		0x2B1020AA015DC28AULL,
		0xEEC77F8627063CF5ULL,
		0x6A8BB6302CFBBBE3ULL,
		0xFBF2CD00908434D3ULL,
		0x31E858EB5A0AA9CCULL,
		0x1637D1DAF04134EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x333008C100004440ULL,
		0x18124AA417010441ULL,
		0x0200008A0050800AULL,
		0x0641100403001801ULL,
		0x008A9020009B1A22ULL,
		0x1240050080001050ULL,
		0x000018A1020828CCULL,
		0x0216401AD0013420ULL
	}};
	printf("Test Case 489\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD1AA689BF2CFCF3EULL,
		0x3098EBEFACD2B855ULL,
		0x8791F45F4DA6D419ULL,
		0x7D39118E9FF4AA22ULL,
		0xA08B6D81EFDA5689ULL,
		0x22DAA11F938F1A27ULL,
		0xEC71395EFDCB6042ULL,
		0xAE13FA0D6979B923ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0DC26C72A61A550ULL,
		0x7B40E36001358E31ULL,
		0xE1AD96D114641F36ULL,
		0xFB0B4FE81ECB76BAULL,
		0xE4F981312D1E1315ULL,
		0x9894F8AE292E6723ULL,
		0x18F7D59AE3A85EF7ULL,
		0x98E93DD2E4F7222DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC088208322418510ULL,
		0x3000E36000108811ULL,
		0x8181945104241410ULL,
		0x790901881EC02222ULL,
		0xA08901012D1A1201ULL,
		0x0090A00E010E0223ULL,
		0x0871111AE1884042ULL,
		0x8801380060712021ULL
	}};
	printf("Test Case 490\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x8F33C855170A75EBULL,
		0xC9AD0FFF53E60D44ULL,
		0x56D47F91682783E3ULL,
		0xF18BD79CF88257DFULL,
		0x0E2272346A135C4EULL,
		0xE9D9C7015E7696C0ULL,
		0x5080E7B61F3CBEEFULL,
		0xE842B34D14A2D4F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35F360D3F31CA1EULL,
		0xF238A1195A6978A0ULL,
		0x829F098F169C4EACULL,
		0x9F68353F892DCA27ULL,
		0xCB223EB2852C97D9ULL,
		0x317E8726F655FAC6ULL,
		0x9C8D0783DD102C65ULL,
		0x8A6D516BE37DD352ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x831300051700400AULL,
		0xC028011952600800ULL,
		0x02940981000402A0ULL,
		0x9108151C88004207ULL,
		0x0A22323000001448ULL,
		0x21588700565492C0ULL,
		0x108007821D102C65ULL,
		0x884011490020D050ULL
	}};
	printf("Test Case 491\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x5EA4C6835FF2A368ULL,
		0x797B4B746BD25286ULL,
		0x03D5B64BD7826321ULL,
		0xF13A6601CFE59775ULL,
		0xD4055C827237270CULL,
		0x58073FCB595AC4A1ULL,
		0xB27570470A43E3F3ULL,
		0x7A041A90BA7E609DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F64CB9E3FC8B841ULL,
		0x308C24D0DAA87171ULL,
		0x9B6F92150CD00BB3ULL,
		0xA25A7D249EB8A1C4ULL,
		0xC03557562E0EB530ULL,
		0xED2A2F1C184FC3C3ULL,
		0x7E0561B57A9D4933ULL,
		0x39A00CB6C08ECD59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E24C2821FC0A040ULL,
		0x300800504A805000ULL,
		0x0345920104800321ULL,
		0xA01A64008EA08144ULL,
		0xC005540222062500ULL,
		0x48022F08184AC081ULL,
		0x320560050A014133ULL,
		0x38000890800E4019ULL
	}};
	printf("Test Case 492\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0F152E604966C7F9ULL,
		0x39A302B696D7EF13ULL,
		0x700542BBBA82264BULL,
		0xAE6381CCFA1C2575ULL,
		0xA0EC1CE905DB10DFULL,
		0xB07F203128400B8FULL,
		0xF508283E16CDA705ULL,
		0xB96D9444AA7E9F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC896212F876085D8ULL,
		0x3EA4DE43E02A8304ULL,
		0xD170FF729A33A5F4ULL,
		0xA58410B1A55F438DULL,
		0xBDDEF1661F2545BFULL,
		0x7A8BD43A8EAA9C25ULL,
		0xB66681E082F2D63DULL,
		0xFED693C1911E6E12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08142020016085D8ULL,
		0x38A0020280028300ULL,
		0x500042329A022440ULL,
		0xA4000080A01C0105ULL,
		0xA0CC10600501009FULL,
		0x300B003008000805ULL,
		0xB400002002C08605ULL,
		0xB8449040801E0E10ULL
	}};
	printf("Test Case 493\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xB9684B7F33367801ULL,
		0x2770ED0779861592ULL,
		0xAB8BC36917F2CA1EULL,
		0x19B54154FB5FCA98ULL,
		0x3BA8818E1F863C0AULL,
		0xE0BA9A4FFC0160F6ULL,
		0xC97E9FC0233464F6ULL,
		0x3D9E4F7B51AA91D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC11F8F71593D75DCULL,
		0x11CF4DC4A4DBC753ULL,
		0xF586A246DB6E4B6AULL,
		0x51B4D71A11681365ULL,
		0x32F3A89A751111AEULL,
		0x6496A9D55B63C78DULL,
		0x21A41F6F81CB581DULL,
		0x38CCE5265CDA7736ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81080B7111347000ULL,
		0x01404D0420820512ULL,
		0xA182824013624A0AULL,
		0x11B4411011480200ULL,
		0x32A0808A1500100AULL,
		0x6092884558014084ULL,
		0x01241F4001004014ULL,
		0x388C4522508A1110ULL
	}};
	printf("Test Case 494\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x0FDAE35D189D905AULL,
		0xBB34A99BB6C4C910ULL,
		0xB35E59AB10F30B47ULL,
		0x9DDC263E698480CCULL,
		0xC220383142F673ADULL,
		0xF572948EF719ABA3ULL,
		0xF4EC8616BA0EBD68ULL,
		0x1E6BCD8C3655411FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24046D4632DF21B2ULL,
		0xB714C420B67B23CFULL,
		0x555E760FE6BBDA2EULL,
		0x195C6DCD6B81CF69ULL,
		0xD98944D247A2738BULL,
		0x76C1F8836E77DB8BULL,
		0x1441C862C65F41DFULL,
		0xF58ABE8FE7E5D826ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04006144109D0012ULL,
		0xB3148000B6400100ULL,
		0x115E500B00B30A06ULL,
		0x195C240C69808048ULL,
		0xC000001042A27389ULL,
		0x7440908266118B83ULL,
		0x14408002820E0148ULL,
		0x140A8C8C26454006ULL
	}};
	printf("Test Case 495\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD621C707BE683B38ULL,
		0x78665F5183368C21ULL,
		0x7627967AC9557B76ULL,
		0x94574CDED46C8209ULL,
		0x59F1C7F6D39C584DULL,
		0x5D19C24A0BD914B7ULL,
		0xEA797A4294210023ULL,
		0x0319C4AAE7335CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A98DE723947B60ULL,
		0x03432FA5DB990DE1ULL,
		0x135B2B29A1E5A982ULL,
		0x62C220842133A684ULL,
		0xBC381495F7A77D18ULL,
		0xA4B254ED291E82F2ULL,
		0x4A2A4610DE6B3D86ULL,
		0x0B2DC2639A3CE6CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1221850722003B20ULL,
		0x00420F0183100C21ULL,
		0x1203022881452902ULL,
		0x0042008400208200ULL,
		0x18300494D3845808ULL,
		0x04104048091800B2ULL,
		0x4A28420094210002ULL,
		0x0309C022823044C0ULL
	}};
	printf("Test Case 496\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0x20BDCEA1DFC6D853ULL,
		0xD5998B88304BAD02ULL,
		0x76D34928393CED38ULL,
		0x3F3DE2819BACF995ULL,
		0xD5690FD6AA22554BULL,
		0xBB70C48BBD24FD72ULL,
		0x9311843F38174CEBULL,
		0x2911A80D69F93BE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x983285B76BE7EDF0ULL,
		0xB6A20CB9EDB183BEULL,
		0x88484D2C50D825C8ULL,
		0x5011E3E1294E5206ULL,
		0x1B7C582AFE6BDC0AULL,
		0x03DE4B0F5ACA074EULL,
		0xAC22CCD46160C99EULL,
		0x0C5B76EED851E861ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x003084A14BC6C850ULL,
		0x9480088820018102ULL,
		0x0040492810182508ULL,
		0x1011E281090C5004ULL,
		0x11680802AA22540AULL,
		0x0350400B18000542ULL,
		0x800084142000488AULL,
		0x0811200C48512860ULL
	}};
	printf("Test Case 497\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xC996C5B9ECEB7A8EULL,
		0x478912E790860718ULL,
		0xDB549CDE6A99319DULL,
		0x773BE449805267A2ULL,
		0x061393F40BDD35D3ULL,
		0xC8574DBF5FB8A9C2ULL,
		0xEBCB498FED6401C6ULL,
		0x2FCDF7111DBAC17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00DE62992391D8C9ULL,
		0xE467E0FD7C093CF3ULL,
		0xCBE526FEA4491905ULL,
		0x6FE250576595DB46ULL,
		0x6CAA86D9AA5A7CBBULL,
		0xC93A8C86489C2F1BULL,
		0x1BA6BEE98F9A763FULL,
		0x7DE9B7BD249A2B50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0096409920815888ULL,
		0x440100E510000410ULL,
		0xCB4404DE20091105ULL,
		0x6722404100104302ULL,
		0x040282D00A583493ULL,
		0xC8120C8648982902ULL,
		0x0B8208898D000006ULL,
		0x2DC9B711049A0150ULL
	}};
	printf("Test Case 498\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD2A7A26AED14D7EBULL,
		0x897AC22278B6FBB7ULL,
		0x820DAD88F9998FBCULL,
		0x17E8F9337B13094CULL,
		0xFC9A5345767E8608ULL,
		0x0559A736517C5D95ULL,
		0xADB1ABC74BFFEC9BULL,
		0xDC5A3D4696EDBF78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E87D460F48CD6DULL,
		0x0F85223F52911FD8ULL,
		0xB89D72B28778DDD3ULL,
		0x25E61D917B5B7F1AULL,
		0xD16BBC453A12A1DAULL,
		0x272E032D968F5D75ULL,
		0x07914105C3F0BC80ULL,
		0x788F99E2D5F1C6F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A020420D00C569ULL,
		0x0900022250901B90ULL,
		0x800D208081188D90ULL,
		0x05E019117B130908ULL,
		0xD00A104532128008ULL,
		0x05080324100C5D15ULL,
		0x0591010543F0AC80ULL,
		0x580A194294E18678ULL
	}};
	printf("Test Case 499\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
		0xD2831C7FBA9AC3A0ULL,
		0xF52E00EA5F594850ULL,
		0xAFDDF5C971284753ULL,
		0x1E70FFA4B4BB95B1ULL,
		0x870E273D5ED348DBULL,
		0xF14A72686718BAEEULL,
		0x5DB5B9C1719FDC2AULL,
		0x3ED51244FC556845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F5168C18373B00FULL,
		0x8ADEDAA788FC88EEULL,
		0x232E275738F3FC31ULL,
		0x2E6EC23D6C9814B8ULL,
		0x902F0F9CD89D5E07ULL,
		0x46BE03F6FD9F61F4ULL,
		0x9CBAC8B157B5CBB2ULL,
		0x2A2E002FB7507D88ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4201084182128000ULL,
		0x800E00A208580840ULL,
		0x230C254130204411ULL,
		0x0E60C224249814B0ULL,
		0x800E071C58914803ULL,
		0x400A0260651820E4ULL,
		0x1CB088815195C822ULL,
		0x2A040004B4506800ULL
	}};
	printf("Test Case 500\n");
	printf("k1: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2: \n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_and(&k1, &k2, &r);
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
}