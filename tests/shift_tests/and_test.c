#include "../tests.h"

int32_t curve25519_key_and_test(void) {
	printf("Key AND Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xA91549525833B44AULL,
		0x6F33EF6321057FE7ULL,
		0xB078178D70FA378FULL,
		0x4D21C0CA2A991193ULL,
		0xE00E6F8A334C31A8ULL,
		0xEE612D1B2F77B774ULL,
		0xF1F99CEF5E2ACB75ULL,
		0x96345D18B1F06940ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xD33165CDB50B64DAULL,
		0x2C2317FB36EB2C39ULL,
		0x3E9433346B737274ULL,
		0xED4DAE429FBAEDA9ULL,
		0xDB9F783380D32152ULL,
		0x3A4C41EBAD5EF17EULL,
		0x2E1B80CAC7E7E443ULL,
		0x95D63B3AF470C975ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x811141401003244AULL,
		0x2C23076320012C21ULL,
		0x3010130460723204ULL,
		0x4D0180420A980181ULL,
		0xC00E680200402100ULL,
		0x2A40010B2D56B174ULL,
		0x201980CA4622C041ULL,
		0x94141918B0704940ULL
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
		0x28904F87EF4F6A51ULL,
		0x6B5773753EA8FF26ULL,
		0x3D0578BE0A5D4BACULL,
		0x1F134B11CD06723DULL,
		0x03E8E2DC918D6AC5ULL,
		0x87D376B09B318039ULL,
		0x765A718C3153486DULL,
		0xF08D67EF585F36BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8972963B8075EF6ULL,
		0xAB13B6782A48B01AULL,
		0x25637197D53FAB75ULL,
		0x84ACF7A8F15C0196ULL,
		0x207586D9A0E839D7ULL,
		0x1D93BA45D1F41682ULL,
		0x49B26028C24EEA98ULL,
		0x0278AA45496D7D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28900903A8074A50ULL,
		0x2B1332702A08B002ULL,
		0x25017096001D0B24ULL,
		0x04004300C1040014ULL,
		0x006082D8808828C5ULL,
		0x0593320091300000ULL,
		0x4012600800424808ULL,
		0x00082245484D3411ULL
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
		0xE7419A1C29925B63ULL,
		0x00C6B7BDC32E2ABBULL,
		0x1CE4D52E6151B0B8ULL,
		0x4A299D72AE948FFAULL,
		0x5F6B107D00688BA9ULL,
		0x5E687166A30D651DULL,
		0x5E23432DE6D820C7ULL,
		0x917DBCD2748ED4DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49C2FC1042C4DC2BULL,
		0xDF6EE97E800D7F24ULL,
		0xD4930DA9CDB93E6AULL,
		0x2474148F0F820172ULL,
		0xBEB35BED7A8E9CD7ULL,
		0xB43BE44DFC77E7D2ULL,
		0x095668033EA35B86ULL,
		0xCA6DDE70ABB65C80ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4140981000805823ULL,
		0x0046A13C800C2A20ULL,
		0x1480052841113028ULL,
		0x002014020E800172ULL,
		0x1E23106D00088881ULL,
		0x14286044A0056510ULL,
		0x0802400126800086ULL,
		0x806D9C5020865480ULL
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
		0x2E0875AEDFB8D98DULL,
		0xE2B6FDB3F7F8CE64ULL,
		0x514AA3F3CAF08989ULL,
		0x5A6ACBAD74D0AA12ULL,
		0x42766B246C8E2E1FULL,
		0x132B2969612E4C0BULL,
		0x267C6FFAF3A8863EULL,
		0xB9E1F73C83F65D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F16CDD441337CB0ULL,
		0x43583A70B40460D9ULL,
		0xC56633FB3382C1E8ULL,
		0x642A4CD07E4AAB38ULL,
		0x4367E972D28B988AULL,
		0xCAFEBCF162CBF2ABULL,
		0x51C8764010E0531AULL,
		0x9C4A516970790379ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E00458441305880ULL,
		0x42103830B4004040ULL,
		0x414223F302808188ULL,
		0x402A48807440AA10ULL,
		0x42666920408A080AULL,
		0x022A2861600A400BULL,
		0x0048664010A0021AULL,
		0x9840512800700110ULL
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
		0xECF1520BB3DBF06DULL,
		0x6BDC12614CA8DDFCULL,
		0xF8CA12D71733DA86ULL,
		0xAA364665A3FF6C47ULL,
		0x9E6D87A0670B5E67ULL,
		0xBBDF5419BF84A436ULL,
		0x1826D2E9A0A651DDULL,
		0x9926C6EBFB83BD9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97DFB4CE63F02A5AULL,
		0x729F06BCAE5139D7ULL,
		0x6F809A707712594FULL,
		0x22E3504BAA3E7C4FULL,
		0x9AC5EF00842FAE5DULL,
		0x5742F6F0BA0DFB1EULL,
		0x21E0015CBDD4468AULL,
		0x092E7683CE141ABFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84D1100A23D02048ULL,
		0x629C02200C0019D4ULL,
		0x6880125017125806ULL,
		0x22224041A23E6C47ULL,
		0x9A458700040B0E45ULL,
		0x13425410BA04A016ULL,
		0x00200048A0844088ULL,
		0x09264683CA00189AULL
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
		0xA2BAE5AB8FBEDF3AULL,
		0x547CC9F9CA02052AULL,
		0x23D2B246B34318DCULL,
		0xC13F1F8846687FA3ULL,
		0x8819D105E4A4D917ULL,
		0x96AD09F066D74073ULL,
		0x9022FBF974FA25DDULL,
		0x65CD4D9E631E8C1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2761A92FA5D8C83ULL,
		0xE1E4A1CC7D907205ULL,
		0xC0E44AF2CBABD078ULL,
		0xB92E80FFB3653D7DULL,
		0x5A7DB67AAE7512A2ULL,
		0x21AC2A9B54F97847ULL,
		0x69268EEEF070CB1EULL,
		0xF26D484E4ADFD70BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA23200828A1C8C02ULL,
		0x406481C848000000ULL,
		0x00C0024283031058ULL,
		0x812E008802603D21ULL,
		0x08199000A4241002ULL,
		0x00AC089044D14043ULL,
		0x00228AE87070011CULL,
		0x604D480E421E8409ULL
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
		0xCEB2A6BA4AC65E82ULL,
		0x5AB54686FD3CEB2DULL,
		0x36EF4606A65F793BULL,
		0x2C81A2DBCE1503FCULL,
		0x513527DCA4B9C0ECULL,
		0x6169F5E09FC74208ULL,
		0x61F969AE80529673ULL,
		0x4937EA0DA42EA2F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25EA2BB1BA546F18ULL,
		0x732B0A3A32F29BE1ULL,
		0xA8440C3A3D66155EULL,
		0x25E94580E6D02EFCULL,
		0x16E63302E08FF4AEULL,
		0x64488205BB20425EULL,
		0x2C4DBA908AC30429ULL,
		0x88EDA0B7AEEC1BDBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04A222B00A444E00ULL,
		0x5221020230308B21ULL,
		0x204404022446111AULL,
		0x24810080C61002FCULL,
		0x10242300A089C0ACULL,
		0x604880009B004208ULL,
		0x2049288080420421ULL,
		0x0825A005A42C02D9ULL
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
		0x9776482AAE32F792ULL,
		0x500A4CE4F2E7D7C8ULL,
		0x370C322F50FE4183ULL,
		0xC8753787C1E99A69ULL,
		0x56C338A4B1D8A095ULL,
		0x88BA9FA75A7C7837ULL,
		0x9BE33D891AD2A6F5ULL,
		0xA0545AD985790F6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF5355E1C5681EAULL,
		0xE98FDC8AC6C84761ULL,
		0x6F462C3AA011DFD7ULL,
		0x47390A24159AA1A5ULL,
		0xB2CE6C08C2FDFED0ULL,
		0xD86447A5D179BC3AULL,
		0xA5011DDE47DC0E65ULL,
		0x996ABB380C604227ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0574000A0C128182ULL,
		0x400A4C80C2C04740ULL,
		0x2704202A00104183ULL,
		0x4031020401888021ULL,
		0x12C2280080D8A090ULL,
		0x882007A550783832ULL,
		0x81011D8802D00665ULL,
		0x80401A1804600226ULL
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
		0x335795F207907FB2ULL,
		0xF5A0B05F989D3613ULL,
		0xC93FDE74B5981A0AULL,
		0x069AE6A61550A06AULL,
		0x16764FCABC6647D2ULL,
		0x89477A91B25F9F3AULL,
		0x60824E20906699E7ULL,
		0x8FBA43E619582C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F3A37F0F2C8185FULL,
		0x645FB8C7F110D3DBULL,
		0xC324C1401658ADCFULL,
		0xD45A5377F6968619ULL,
		0x52FF1C8DACA5AE2BULL,
		0x7E976D16BEBDE7B1ULL,
		0xADCDA012415C8478ULL,
		0xDFF8F599518B0363ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x031215F002801812ULL,
		0x6400B04790101213ULL,
		0xC124C0401418080AULL,
		0x041A422614108008ULL,
		0x12760C88AC240602ULL,
		0x08076810B21D8730ULL,
		0x2080000000448060ULL,
		0x8FB8418011080001ULL
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
		0x70E9C8F1AAD22D1DULL,
		0xEED86578A1CF5633ULL,
		0x85DB695D0CFACE30ULL,
		0x67479BEF488C2F44ULL,
		0x212C8185223D7D94ULL,
		0x2BB147A3E07DDA54ULL,
		0x1D94CFE1DAEAA262ULL,
		0xD199C94291665A10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29B39A373C648A9FULL,
		0xD742DFAE9536ED99ULL,
		0xC653F25E6A37B3E4ULL,
		0x0019995930D04CA0ULL,
		0xE364435C72A59D52ULL,
		0x2B9929FABEB77975ULL,
		0x0F7BDD826DBDCF13ULL,
		0xEA98B2F0DED7893CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20A188312840081DULL,
		0xC640452881064411ULL,
		0x8453605C08328220ULL,
		0x0001994900800C00ULL,
		0x2124010422251D10ULL,
		0x2B9101A2A0355854ULL,
		0x0D10CD8048A88202ULL,
		0xC098804090460810ULL
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
		0xA81E89670C78BAFDULL,
		0x14810D91D3879681ULL,
		0x0A5EB47FD7F8AAD4ULL,
		0x372D417F456CF4B6ULL,
		0x91E434820AB958E1ULL,
		0x09798373FE4777F2ULL,
		0x17D99861270D9EACULL,
		0x9CFD0697B3154D38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D99E4A0124534E6ULL,
		0x4F7713E024765C2FULL,
		0x7408AACC570DBAA4ULL,
		0xEF5458745D2F5C81ULL,
		0x2B9EDE64E5B6B0D3ULL,
		0xF6EB7FFE31C7E4CEULL,
		0xED3F5FC307A01E0CULL,
		0x1099CFDC5DCB83A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28188020004030E4ULL,
		0x0401018000061401ULL,
		0x0008A04C5708AA84ULL,
		0x27044074452C5480ULL,
		0x0184140000B010C1ULL,
		0x00690372304764C2ULL,
		0x0519184107001E0CULL,
		0x1099069411010120ULL
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
		0x7B94B5928D00BBC8ULL,
		0xC5A7B707A98DF567ULL,
		0xFA14FFF996459777ULL,
		0xD14856FFB1F2CFFBULL,
		0xA911890880C41D36ULL,
		0x24C04839CDDA04A1ULL,
		0xA27E66B621C00C7DULL,
		0xEB8751869B0E74AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807ACEE3ADF98246ULL,
		0xFA1B4A1E2EC85F40ULL,
		0xA69F971187801374ULL,
		0x53EC94C586B63E36ULL,
		0xC92345F19575586BULL,
		0xD9AC51841B1528A5ULL,
		0x021454C4DB12DCBEULL,
		0x312FD62D41BB6376ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001084828D008240ULL,
		0xC003020628885540ULL,
		0xA214971186001374ULL,
		0x514814C580B20E32ULL,
		0x8901010080441822ULL,
		0x00804000091000A1ULL,
		0x0214448401000C3CULL,
		0x21075004010A6026ULL
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
		0xC5C5D58239711809ULL,
		0x30439ECA742BFACBULL,
		0xE0E0221C9344F6E5ULL,
		0xA6336BB0B4430D43ULL,
		0x6866C03C2A60570FULL,
		0x94916B4B0507735DULL,
		0x6556AD044214C9D0ULL,
		0x747130099E5BD782ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93034FEF6FD30E93ULL,
		0xD4030F835703C41EULL,
		0xCD64E1E5056E1164ULL,
		0xD5F9231C6169DB4AULL,
		0x1B50FBB2B7B5F05FULL,
		0x3CBFA682794E5634ULL,
		0xF0261A9FBD10F9F8ULL,
		0x67FA47815F4E5937ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8101458229510801ULL,
		0x10030E825403C00AULL,
		0xC060200401441064ULL,
		0x8431231020410942ULL,
		0x0840C0302220500FULL,
		0x1491220201065214ULL,
		0x600608040010C9D0ULL,
		0x647000011E4A5102ULL
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
		0xE2C0850BEC0627CBULL,
		0x6DE9444592933F9CULL,
		0xD749A7B0EE0FD8EDULL,
		0x6A08C6D42F4F6445ULL,
		0x4D78158C60BBD15CULL,
		0x14EE94D2582B6639ULL,
		0xAB3B4474AAB7FD8DULL,
		0x9909F755F357C965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89D33299D200105BULL,
		0x92D06D8166F5A0B0ULL,
		0xF13CAD34407A9865ULL,
		0x0EDF3871C8898CB3ULL,
		0x1151AECE25CAABE0ULL,
		0x63CF4B7A0D79C07BULL,
		0xBD6E5EB2E52787FDULL,
		0x1B6018528897F6D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C00009C000004BULL,
		0x00C0440102912090ULL,
		0xD108A530400A9865ULL,
		0x0A08005008090401ULL,
		0x0150048C208A8140ULL,
		0x00CE005208294039ULL,
		0xA92A4430A027858DULL,
		0x190010508017C041ULL
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
		0x9956BD9B7648C70FULL,
		0xE6CAF73BFB892F2BULL,
		0xD80C4273A9DA3BF0ULL,
		0x10626DFEE2E51584ULL,
		0x979D08CFEC98A650ULL,
		0xE4EB7D8269EFA7AAULL,
		0xCDAB8B6185309B22ULL,
		0xDC7750A724A82469ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D29E50660FFD57ULL,
		0x2EFD87E48FA31FEBULL,
		0xA83BB9981FD2D15DULL,
		0x92D468D2CF51EAEBULL,
		0x7D809D6D8B6FFCF2ULL,
		0xA62D907F8CCAD9C2ULL,
		0x62996A73FDA8C150ULL,
		0xAD21DE2ADCBEE34CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90529C106608C507ULL,
		0x26C887208B810F2BULL,
		0x8808001009D21150ULL,
		0x104068D2C2410080ULL,
		0x1580084D8808A450ULL,
		0xA429100208CA8182ULL,
		0x40890A6185208100ULL,
		0x8C21502204A82048ULL
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
		0xE426D38760AABFA8ULL,
		0xE6DE82738168EBAEULL,
		0xF345E22983D64429ULL,
		0xB555800401A28669ULL,
		0x191036D85962E3D5ULL,
		0x0A60EF06BF70717FULL,
		0x657794EF32170E8AULL,
		0xF853E409C94C475DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79BD87E6F31E98EDULL,
		0x567BDABBB1A0E33BULL,
		0xB9C6D1C94D65F4A6ULL,
		0xA1E6B47B142E753FULL,
		0x04001C7C99317600ULL,
		0x2D9D18038C3729C5ULL,
		0x1C93BA01B53A6EACULL,
		0x4D7C0AA5536CE38BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60248386600A98A8ULL,
		0x465A82338120E32AULL,
		0xB144C00901444420ULL,
		0xA144800000220429ULL,
		0x0000145819206200ULL,
		0x080008028C302145ULL,
		0x0413900130120E88ULL,
		0x48500001414C4309ULL
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
		0xC72DA5C7747A5128ULL,
		0xBEEC562BE8BF6E60ULL,
		0x23DCB3F5479412A9ULL,
		0xE517543ACE836969ULL,
		0xF89E98BD42AA4B02ULL,
		0x02CC5C77504E7B5AULL,
		0x50DCA68E6CD82D68ULL,
		0xB002CB3D89600439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x984F43D55CB45CE3ULL,
		0xF3E0E217860D21CCULL,
		0xE577193429C39AB7ULL,
		0xFE0965512E1B2655ULL,
		0x5C150EDADA13E737ULL,
		0xAB7C71FC41AF39B9ULL,
		0xF453DE88645EFB7DULL,
		0x6B6985B7DF05B1E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800D01C554305020ULL,
		0xB2E04203800D2040ULL,
		0x21541134018012A1ULL,
		0xE40144100E032041ULL,
		0x5814089842024302ULL,
		0x024C5074400E3918ULL,
		0x5050868864582968ULL,
		0x2000813589000029ULL
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
		0x80A4DB0113D3D63CULL,
		0x0B00C5CF69D4AABAULL,
		0x48B0D9DC306D2A1DULL,
		0x5BF5A1B274613DB9ULL,
		0x88B637CF2556EFF2ULL,
		0x38635B44509E3D22ULL,
		0xA9CE44384C749325ULL,
		0xB6CA46F5773BD5C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B5E7DB15A815C2ULL,
		0x5766ABDCC56995B8ULL,
		0xA10746D2A20AD0F8ULL,
		0x9822DB3F17A68B83ULL,
		0x7201B8D4619A0D2BULL,
		0x4F26AD8472AB52D6ULL,
		0xB0FDC93C9D28E208ULL,
		0x867FE6E6D3FF4C3DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80A4C30111801400ULL,
		0x030081CC414080B8ULL,
		0x000040D020080018ULL,
		0x1820813214200981ULL,
		0x000030C421120D22ULL,
		0x08220904508A1002ULL,
		0xA0CC40380C208200ULL,
		0x864A46E4533B4400ULL
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
		0xFDD2C07DF9C48474ULL,
		0x1AE92D71348104DFULL,
		0x62D0D9372082DB4AULL,
		0x5E5D3B2C35E53468ULL,
		0xE95DE6873D3C6234ULL,
		0x341B2C797C2F99E1ULL,
		0x9E55D9BE69BD35FBULL,
		0x382FF4C703DD9669ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF99396176433878AULL,
		0x9DE41FEB5DD960B3ULL,
		0x3ACDB5438E87B38CULL,
		0xA7F5A64EECD3C71BULL,
		0x9B6036AE636BA0A8ULL,
		0xDBC3F6D63DB8C2AAULL,
		0xCD333CEB36F1D2C7ULL,
		0x843782BA6E77E1B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF992801560008400ULL,
		0x18E00D6114810093ULL,
		0x22C0910300829308ULL,
		0x0655220C24C10408ULL,
		0x8940268621282020ULL,
		0x100324503C2880A0ULL,
		0x8C1118AA20B110C3ULL,
		0x0027808202558020ULL
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
		0x15ABF54A69C7A86AULL,
		0x317C160FF20F9B4AULL,
		0x5978D454B674DC98ULL,
		0x5361564FB36ECB1CULL,
		0x4A155276818F0E94ULL,
		0x295A3919B48C7602ULL,
		0xD63B96553D9E161AULL,
		0x2EE4124F15F88CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x592FE145700EA950ULL,
		0xF80072FF0E31DD0EULL,
		0x235039D0A0511A32ULL,
		0x970182CB2E446D1AULL,
		0xFB582BD29DD39E4CULL,
		0x2EE870FE1E3E4F25ULL,
		0xFA34CC3D913FD868ULL,
		0x473307BC850564AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x112BE1406006A840ULL,
		0x3000120F0201990AULL,
		0x01501050A0501810ULL,
		0x1301024B22444918ULL,
		0x4A10025281830E04ULL,
		0x28483018140C4600ULL,
		0xD2308415111E1008ULL,
		0x0620020C050004A1ULL
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
		0x944C6EBFD1210F57ULL,
		0x7D8A4AB5D09A2DA9ULL,
		0x02A54F725F3B6534ULL,
		0x2A38E59AE87BCBE9ULL,
		0x40D5EFBEB2212C80ULL,
		0xF184734E5C30B0E6ULL,
		0xE3330A8B4E4154ADULL,
		0xA8F8355F3B417497ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F957E5A190302EBULL,
		0x8EFF1A706C9FC3A9ULL,
		0x7CE3DB8BB524DB9BULL,
		0x08D7049D28792548ULL,
		0x511C64EC42262C28ULL,
		0x7CEF33F5DD382363ULL,
		0x2DEF7108E2A2A0BFULL,
		0xBED934B9F6A2B2C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14046E1A11010243ULL,
		0x0C8A0A30409A01A9ULL,
		0x00A14B0215204110ULL,
		0x0810049828790148ULL,
		0x401464AC02202C00ULL,
		0x708433445C302062ULL,
		0x21230008420000ADULL,
		0xA8D8341932003087ULL
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
		0xAB3E56364CECB0F1ULL,
		0xA7A6E5A0187EFBCBULL,
		0x630D47AA9D14112CULL,
		0xE818AF7F65CCBC7BULL,
		0xF4EDC9F07ABA49F5ULL,
		0x72CA19487719C2F0ULL,
		0xA20B6256E5D53C7FULL,
		0x1DAF210F25990C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB326C5FBDF122F29ULL,
		0x2E2BD761728541DDULL,
		0xE403B7A579CDE05CULL,
		0x3CA8D09A75FF2AD8ULL,
		0x73B816BE5DF89BB2ULL,
		0xFF8A447A2ACD48AAULL,
		0x590BF44E56203497ULL,
		0x311B65F82B987E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA32644324C002021ULL,
		0x2622C520100441C9ULL,
		0x600107A01904000CULL,
		0x2808801A65CC2858ULL,
		0x70A800B058B809B0ULL,
		0x728A0048220940A0ULL,
		0x000B604644003417ULL,
		0x110B210821980C10ULL
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
		0xEEF3298C45CA0C97ULL,
		0x9FEA92B3900DB773ULL,
		0x6EC220C46A53B855ULL,
		0x353C35A9EE0D3F47ULL,
		0x204273B68003A1D1ULL,
		0x53E242E250A22D18ULL,
		0x44BD98B35B6C06ECULL,
		0x0CA94ED43E040CAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF47B3E56F77B50ULL,
		0x57CE544ABBFDD3EDULL,
		0x0D3E0B46C1076F11ULL,
		0xD7AF858AA03E3138ULL,
		0x3D29455EA743A7F4ULL,
		0xF7F205DAAF06BC9BULL,
		0x56D08DC392373383ULL,
		0x510CDCDFDA5E9851ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4CF0290C44C20810ULL,
		0x17CA1002900D9361ULL,
		0x0C02004440032811ULL,
		0x152C0588A00C3100ULL,
		0x200041168003A1D0ULL,
		0x53E200C200022C18ULL,
		0x4490888312240280ULL,
		0x00084CD41A040800ULL
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
		0xA2488D2E8DB6DD00ULL,
		0x6796A61EDF3CC7AFULL,
		0x5C4A3188626EA546ULL,
		0x1CEC0F2A198AF4D6ULL,
		0x09DF5CBB3FB500FAULL,
		0x1415E8F59F831C38ULL,
		0xEDBE771C64B95764ULL,
		0xE3EBE42949254970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE27B4C147174A2F6ULL,
		0x534835707B0C0D7CULL,
		0x055E8F4425896396ULL,
		0x7AFF64EA6151C8CFULL,
		0xF509D5F37035C0B9ULL,
		0xE8E7AA70CA9A39CBULL,
		0x518AA08DE311A622ULL,
		0x19DFD4CE96B0F317ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2480C0401348000ULL,
		0x430024105B0C052CULL,
		0x044A010020082106ULL,
		0x18EC042A0100C0C6ULL,
		0x010954B3303500B8ULL,
		0x0005A8708A821808ULL,
		0x418A200C60110620ULL,
		0x01CBC40800204110ULL
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
		0x16753A54CF007480ULL,
		0xEDA2CB2551F022DCULL,
		0x4BFC6C19FFEF3552ULL,
		0x20026964018F77D5ULL,
		0x8F7AACF1F5CC5E1BULL,
		0xCEC3BC28E07B6388ULL,
		0x2045AC406B4D42A3ULL,
		0xB7A313B386C3ABC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51557A478F384A47ULL,
		0xE91764A23C20E6F5ULL,
		0x56C47F4645156B63ULL,
		0x0C2586EC3F8DA28CULL,
		0x60B99E6E27FC2B64ULL,
		0xD80527FD96227A52ULL,
		0x636FFD03EB117861ULL,
		0x41B4DC6CD96EEE69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10553A448F004000ULL,
		0xE9024020102022D4ULL,
		0x42C46C0045052142ULL,
		0x00000064018D2284ULL,
		0x00388C6025CC0A00ULL,
		0xC801242880226200ULL,
		0x2045AC006B014021ULL,
		0x01A010208042AA41ULL
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
		0x5E3521BF911FF383ULL,
		0x2A4AB017508AD2C1ULL,
		0x4802FA2D8AD2F018ULL,
		0xF670CAE09CE976ABULL,
		0x03082666B078F1E6ULL,
		0x51EB9749E328EC40ULL,
		0x6FC512C54C078C42ULL,
		0x768FEDA76087433DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63BDDA1D9E9C75AULL,
		0xE5B526BD3BAAA1BAULL,
		0x42581666155345B9ULL,
		0xBB993AAA057564BBULL,
		0xAD13EC9E6F737DA4ULL,
		0xF7BBE76F9798E541ULL,
		0x9571D1E1D9B0EAF2ULL,
		0xA17543E99375DD92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x463101A19109C302ULL,
		0x20002015108A8080ULL,
		0x4000122400524018ULL,
		0xB2100AA0046164ABULL,
		0x01002406207071A4ULL,
		0x51AB87498308E440ULL,
		0x054110C148008842ULL,
		0x200541A100054110ULL
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
		0x0EBBC76FA6B1F2E7ULL,
		0x9B306D5DDB89F764ULL,
		0x04F028189FD1EC01ULL,
		0xBB37ED870379553AULL,
		0x2199FC6A22700842ULL,
		0xB1D540C768ADA5BEULL,
		0x8A65ACC1CFE43E42ULL,
		0xC0EF9780AB35F9C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6B2F882AD77E3BDULL,
		0xECD4C9B809020E45ULL,
		0xCD24C94BF19AAD9EULL,
		0x35FF61E83E4EA521ULL,
		0xA0C784A777B6FF63ULL,
		0x840AF85A11496894ULL,
		0x8784F25337A83C5FULL,
		0xAD465C80A8E3591AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06B2C002A431E2A5ULL,
		0x8810491809000644ULL,
		0x042008089190AC00ULL,
		0x3137618002480520ULL,
		0x2081842222300842ULL,
		0x8000404200092094ULL,
		0x8204A04107A03C42ULL,
		0x80461480A8215900ULL
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
		0x0E82BCAE43965984ULL,
		0x61758C6B3364F19DULL,
		0x8C97780BB990F3B4ULL,
		0x09B97B2AA46C89B9ULL,
		0x1DE42BBCF3A18AE7ULL,
		0x4D2EAD43B82794C3ULL,
		0xFB4DD466F5BFA862ULL,
		0x6241A04F82D379AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF602C2DDB4F46F60ULL,
		0x60CE5E2EF75F09EDULL,
		0xA5CD3BAB64E4BA5BULL,
		0x3AEDDCCC370A078DULL,
		0x614872DB078000F1ULL,
		0x1755CF426C495493ULL,
		0xBA54CF1A37C5565AULL,
		0xE4707F7420AA14E0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0602808C00944900ULL,
		0x60440C2A3344018DULL,
		0x8485380B2080B210ULL,
		0x08A9580824080189ULL,
		0x01402298038000E1ULL,
		0x05048D4228011483ULL,
		0xBA44C40235850042ULL,
		0x60402044008210A0ULL
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
		0x5EEA7F9323B76501ULL,
		0x29691CB56D6AA4BDULL,
		0x9CAAEA2020B44C50ULL,
		0x2E2EBFE38D0BE47BULL,
		0xD17AA5901CB4D0DDULL,
		0x086D3697D8AF16CBULL,
		0xC1DBD1C960AE8459ULL,
		0xAD83B0B75157495CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35E4A74CFDB85A56ULL,
		0x3F94300F0C37EEC7ULL,
		0x7490272B8B9E9249ULL,
		0xAC08DE2977FAD8C3ULL,
		0x03A1F6AA0BCEB931ULL,
		0xBF11DD6491332C9BULL,
		0xDF63AFECFD71704EULL,
		0x6D4B190E56EA0CF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14E0270021B04000ULL,
		0x290010050C22A485ULL,
		0x1480222000940040ULL,
		0x2C089E21050AC043ULL,
		0x0120A48008849011ULL,
		0x080114049023048BULL,
		0xC14381C860200048ULL,
		0x2D03100650420858ULL
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
		0x6F8C3E7B3AB1C504ULL,
		0x5363A5C99A4D2792ULL,
		0x1E4891A8B41AAE53ULL,
		0xAB4D142F31990040ULL,
		0xC7657F3821434FA6ULL,
		0xEEE04D5749FDFE17ULL,
		0xF04BDA262D488ADAULL,
		0x7A1A0A80915EF6AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x106FCE00F112BC68ULL,
		0x0B696B22ED582BF9ULL,
		0x53C5171C8A4B29A5ULL,
		0xDC18F4B18E77E97EULL,
		0x2B405A5FB137E5B0ULL,
		0xE02BD1106622003FULL,
		0x96B95F4AD18AF57DULL,
		0xCC4881E795B4E59FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000C0E0030108400ULL,
		0x0361210088482390ULL,
		0x12401108800A2801ULL,
		0x8808142100110040ULL,
		0x03405A18210345A0ULL,
		0xE020411040200017ULL,
		0x90095A0201088058ULL,
		0x480800809114E48FULL
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
		0x152E18DD235716C1ULL,
		0x424B408CE62A5C48ULL,
		0x1A49239757824F72ULL,
		0x216A9CD8159B1644ULL,
		0x5CB61C06C8557E0EULL,
		0xC15649B01797689FULL,
		0xBBB2EBDD4B7E0A1CULL,
		0x702B3E0436177908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93470423F0035808ULL,
		0x3F0F519B4BD11490ULL,
		0xA1B3DE99E34471E5ULL,
		0xE127F8B75C4ADBEFULL,
		0x5BC65D08F4F73388ULL,
		0x71C4E3830D9739F4ULL,
		0x198C3D389B2B1466ULL,
		0x8FCB25886FE747C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1106000120031000ULL,
		0x020B408842001400ULL,
		0x0001029143004160ULL,
		0x21229890140A1244ULL,
		0x58861C00C0553208ULL,
		0x4144418005972894ULL,
		0x198029180B2A0004ULL,
		0x000B240026074100ULL
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
		0x9DB0E72E8320FE19ULL,
		0x6E62B5DB15E19CC4ULL,
		0x5DDABF925DEDDA69ULL,
		0x9B0ADF7068AE72B0ULL,
		0xF49810E904D9884CULL,
		0x322CD3176CA5107AULL,
		0x3B3AA8D46BE75AFFULL,
		0x6BE8FCE07238B2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4E0E422D6494F8ULL,
		0x3B30D6162656CA23ULL,
		0xB4DD6023F02E560BULL,
		0xA15239796F9BE91FULL,
		0x25931805D8C3CDDCULL,
		0x3AD935C71C261C1BULL,
		0xAD255CD007A6E9C1ULL,
		0xA02999DC67B52E92ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C00060201209418ULL,
		0x2A20941204408800ULL,
		0x14D82002502C5209ULL,
		0x81021970688A6010ULL,
		0x2490100100C1884CULL,
		0x320811070C24101AULL,
		0x292008D003A648C1ULL,
		0x202898C062302280ULL
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
		0xE5BDA97B94251C86ULL,
		0x8375D2C64EC8977BULL,
		0xFA958887AA8A58CEULL,
		0xF3466C246469E567ULL,
		0x56128CAFA4D9E628ULL,
		0x136A4A352B33B56FULL,
		0x2EBB141F5E71D2BAULL,
		0x61F6B9DB90466094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D762BC74E30611ULL,
		0x1E1F5E90DAABD1B8ULL,
		0xAE7D83CDA960CA8FULL,
		0x60673584F5518C66ULL,
		0x0B3B26B8EC900A3DULL,
		0xCB90F70CE5F1E8CDULL,
		0x15B753127268409DULL,
		0xE7D4E3C6F7CDBF70ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA595203814210400ULL,
		0x021552804A889138ULL,
		0xAA158085A800488EULL,
		0x6046240464418466ULL,
		0x021204A8A4900228ULL,
		0x030042042131A04DULL,
		0x04B3101252604098ULL,
		0x61D4A1C290442010ULL
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
		0x61AB89AA62AEA869ULL,
		0xE2E54E46738DEBC4ULL,
		0xDE5CF850A0CE0DC6ULL,
		0x01E0BE44C63B4335ULL,
		0xA5ECF44DF8913384ULL,
		0xCE7CC11B04F7FEBAULL,
		0x19FCBBD973095D33ULL,
		0xE6D75C004080861EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD1005957827296ULL,
		0xDD6396FB2118C8F9ULL,
		0x7BF83C6C0BA0F1FEULL,
		0x14265283699170D3ULL,
		0x28372A17517FE580ULL,
		0x4BDA6186102EE6C0ULL,
		0xA04722B64EE843E9ULL,
		0xBFBD0C79D6DD33B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2181000842822000ULL,
		0xC06106422108C8C0ULL,
		0x5A583840008001C6ULL,
		0x0020120040114011ULL,
		0x2024200550112180ULL,
		0x4A5841020026E680ULL,
		0x0044229042084121ULL,
		0xA6950C0040800212ULL
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
		0x64E8D4D95E7CA45FULL,
		0x6778E6E219D15601ULL,
		0xC8349B5FD6DDF3BBULL,
		0x811AEF8B18CB58BEULL,
		0x891016D78DF1CD5DULL,
		0xEF9C2B3C2EB0D312ULL,
		0x330731B32E958B4AULL,
		0x45AD626EABCE36CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F7A450C0958E57ULL,
		0xA7B26CDF0F2242BCULL,
		0x0DA1815B6E31E2E4ULL,
		0x4D5B5EFB36CD3C0FULL,
		0x39C823AC8AE7D866ULL,
		0x64C56DAE3B051AB0ULL,
		0xDE21D647CDBA26F7ULL,
		0xC2A23196D54CE2C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40E0845040148457ULL,
		0x273064C209004200ULL,
		0x0820815B4611E2A0ULL,
		0x011A4E8B10C9180EULL,
		0x0900028488E1C844ULL,
		0x6484292C2A001210ULL,
		0x120110030C900242ULL,
		0x40A02006814C22C2ULL
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
		0x87142E664D17AB07ULL,
		0x8FCF3569107119EFULL,
		0x7AE0944583108E78ULL,
		0xB335D1962F7053B2ULL,
		0x16AA77F74A325971ULL,
		0x545E4EDFD7E15122ULL,
		0x68BAC02F36802BBCULL,
		0x994C91BAF93AAFF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x435E0370226C2222ULL,
		0xB6731802F2442AC7ULL,
		0x9F53A273D868812EULL,
		0xC861C762FCD8CBA3ULL,
		0xC6C86622AA9CB22CULL,
		0x94704538CFD20CF4ULL,
		0x439B3341DD5C4140ULL,
		0x7A4805E7A022113FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0314026000042202ULL,
		0x86431000104008C7ULL,
		0x1A40804180008028ULL,
		0x8021C1022C5043A2ULL,
		0x068866220A101020ULL,
		0x14504418C7C00020ULL,
		0x409A000114000100ULL,
		0x184801A2A0220136ULL
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
		0xE52244A520AD537CULL,
		0x9A06E1C38CE057D3ULL,
		0x823936EF8BAFAF07ULL,
		0xBFC708BD5D8ECA92ULL,
		0xE5B8D52173BA86B2ULL,
		0x2D0BF048A626876DULL,
		0x64573E6982C9FA9DULL,
		0x7F214724DBF023ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96A784C33B40A04ULL,
		0x0CFAC4D83464CE11ULL,
		0x27D754035931C5AFULL,
		0xF9AE9A8690E2E7A7ULL,
		0x8CA39C0994F981EBULL,
		0x39B65EC5D323DD98ULL,
		0x71DB350FC2FAB29DULL,
		0x36F139BEA61251B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC122400420A40204ULL,
		0x0802C0C004604611ULL,
		0x0211140309218507ULL,
		0xB98608841082C282ULL,
		0x84A0940110B880A2ULL,
		0x2902504082228508ULL,
		0x6053340982C8B29DULL,
		0x36210124821001A4ULL
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
		0x335826D5A22490B6ULL,
		0xD83B9DEE47DF0809ULL,
		0xDC8CD81DB5CC5625ULL,
		0x7049E82FB1B56F28ULL,
		0x8CCE5F66A56CCB74ULL,
		0x7CB161160542FBB4ULL,
		0x901510D7AFA0B282ULL,
		0x1330B5042CCDED2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EA7735251661BE5ULL,
		0x5DB242519F35C0E6ULL,
		0xD7AA1E0FECE8EE80ULL,
		0x0A9401EC5B47D214ULL,
		0x801AC247F18CC5B7ULL,
		0xFC1EC3782260F050ULL,
		0x8A24F6D7E31971A3ULL,
		0x7AE1C2D72C583882ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x22002250002410A4ULL,
		0x5832004007150000ULL,
		0xD488180DA4C84600ULL,
		0x0000002C11054200ULL,
		0x800A4246A10CC134ULL,
		0x7C1041100040F010ULL,
		0x800410D7A3003082ULL,
		0x122080042C482802ULL
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
		0xCFA55038E0BBEB8CULL,
		0xBE45C55F77D0F60EULL,
		0x11F49F5F9A5F9264ULL,
		0x3DBE02C419DE232DULL,
		0x19797927F0B85438ULL,
		0xCB58FD988A85E7C9ULL,
		0x68E210F5DB750048ULL,
		0xC3F08D3749F251FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDBF12A9EB5F6CDDULL,
		0x1D77813E6950E566ULL,
		0xF6A709754F158ED8ULL,
		0xD89103D6FA6A9782ULL,
		0x07D7B6DC58ABE787ULL,
		0xEF93B1F684265843ULL,
		0xB69D37BA3B4A9A9EULL,
		0xA2CA3BBAF943A113ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDA51028E01B688CULL,
		0x1C45811E6150E406ULL,
		0x10A409550A158240ULL,
		0x189002C4184A0300ULL,
		0x0151300450A84400ULL,
		0xCB10B19080044041ULL,
		0x208010B01B400008ULL,
		0x82C0093249420113ULL
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
		0x67E7E147394BC3CCULL,
		0xA6D355E16EC94492ULL,
		0xBB0D4CC6308B10FDULL,
		0x5ACDF4435B1282D3ULL,
		0x2E94FB0D8DA70B80ULL,
		0x76A5056481211C1FULL,
		0xB9479FCC5E9B0E9CULL,
		0x9AB61BC4FE77E64AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x367FD1542F298DE4ULL,
		0xA40D629EB5C6F3FCULL,
		0x64DC8E57216461F4ULL,
		0x71707C8F4CABADFEULL,
		0x968E6AAD754D0A04ULL,
		0x2ABDF5682BEE6931ULL,
		0x458D997842E44965ULL,
		0x2D01DDD29E6940CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2667C144290981C4ULL,
		0xA401408024C04090ULL,
		0x200C0C46200000F4ULL,
		0x50407403480280D2ULL,
		0x06846A0D05050A00ULL,
		0x22A5056001200811ULL,
		0x0105994842800804ULL,
		0x080019C09E61404AULL
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
		0xC0417F54CB9540CCULL,
		0x03EF2A9945480646ULL,
		0x12F631B1B1918674ULL,
		0xA3E0CE54E03EE5A4ULL,
		0x512190ECB8AAD178ULL,
		0x0837666642FBDC2CULL,
		0x1155C5A5CD4ABAD4ULL,
		0x732F7C5F5FD4DC7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44AF59B6374A4701ULL,
		0x638789AA68AE29FAULL,
		0x174102A22155D40CULL,
		0x37A674DBFACC7CA5ULL,
		0x59FD0B9A6F4106AEULL,
		0x2D42EDC386BF0858ULL,
		0xDC60E750B0959C55ULL,
		0x475D81FBC084C963ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4001591403004000ULL,
		0x0387088840080042ULL,
		0x124000A021118404ULL,
		0x23A04450E00C64A4ULL,
		0x5121008828000028ULL,
		0x0802644202BB0808ULL,
		0x1040C50080009854ULL,
		0x430D005B4084C863ULL
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
		0xAA170A777FB5F81AULL,
		0xD366848798ED2651ULL,
		0x72504BBB7BF5C845ULL,
		0x48AD76089C2ADBEEULL,
		0xCDA9E8AA86794CADULL,
		0x772353EF9471B31DULL,
		0x81872B6FBE2CEB1EULL,
		0xA7DBFEABDDF6FEF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE4BB38E865573AULL,
		0x0BA3A8F3BBE07719ULL,
		0x5D82303F0319D4D1ULL,
		0x90BC49EF6F5F7B17ULL,
		0x0F85B78C9EFC2496ULL,
		0xF60CE2875BE9A193ULL,
		0x78C8B65FEA81B6B0ULL,
		0xB17A97F148FEBDDFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A040A306825501AULL,
		0x0322808398E02611ULL,
		0x5000003B0311C041ULL,
		0x00AC40080C0A5B06ULL,
		0x0D81A08886780484ULL,
		0x760042871061A111ULL,
		0x0080224FAA00A210ULL,
		0xA15A96A148F6BCD9ULL
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
		0xE2CC552A020E30E4ULL,
		0xEF9DAD44656EA1B0ULL,
		0x20B1748446113A63ULL,
		0xC712516A593F35ECULL,
		0x901763464BF4ED43ULL,
		0x25E088821507ED89ULL,
		0x428AC7D29C22F1E7ULL,
		0xA1F84814FDDF25F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x419CE1EF928BC17DULL,
		0x74DC3C20E7D65868ULL,
		0x0C9B946364873D4BULL,
		0x25E55C065684D53EULL,
		0xC3A72D90B880E0A8ULL,
		0xF80DC4646665661BULL,
		0xDC46C9CDEAD977DFULL,
		0x68AC3BA93A5B941BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x408C412A020A0064ULL,
		0x649C2C0065460020ULL,
		0x0091140044013843ULL,
		0x050050025004152CULL,
		0x800721000880E000ULL,
		0x2000800004056409ULL,
		0x4002C1C0880071C7ULL,
		0x20A80800385B0411ULL
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
		0xE9C14758AF4692B3ULL,
		0xB14EFF7EBF944CC1ULL,
		0x578358CF0DE4C814ULL,
		0xF5B273DA9B61BCB9ULL,
		0x905885110D3C387FULL,
		0xDF615B77550CCA6BULL,
		0xEE22F2F11AB4A955ULL,
		0x99518FDB0BE7C9A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F3039CC484FFACBULL,
		0x4DE99887A4CEEDF0ULL,
		0x67D9D9ECD468A8B6ULL,
		0xBD50404A6E6AB5CEULL,
		0x6DAFC5F6AA0E8C6BULL,
		0x6D490FBF86C6F3D9ULL,
		0x376BC8BB4BB54BA4ULL,
		0xD5C3169EE6B1C2E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6900014808469283ULL,
		0x01489806A4844CC0ULL,
		0x478158CC04608814ULL,
		0xB510404A0A60B488ULL,
		0x00088510080C086BULL,
		0x4D410B370404C249ULL,
		0x2622C0B10AB40904ULL,
		0x9141069A02A1C0A0ULL
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
		0xA28AAC659727BF39ULL,
		0xA262F17D74164AFDULL,
		0xB96A98D30C4501A9ULL,
		0xD0C98FA0E520091AULL,
		0x164A1DBA26F035A2ULL,
		0x96D56F881CE9D3B0ULL,
		0xED03A13D0DF5F9C4ULL,
		0xF431EBCD8C491B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08589FBEF0439F5BULL,
		0x85866E8B8B96CF2FULL,
		0x1DE2D992140D20AEULL,
		0xF6452F9E3B28A800ULL,
		0xD10C6F0AF480F9DEULL,
		0xB97568E8D4959B35ULL,
		0xD92BF34583FF0B24ULL,
		0x1F422B6C1AE803C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00088C2490039F19ULL,
		0x8002600900164A2DULL,
		0x19629892040500A8ULL,
		0xD0410F8021200800ULL,
		0x10080D0A24803182ULL,
		0x9055688814819330ULL,
		0xC903A10501F50904ULL,
		0x14002B4C08480340ULL
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
		0x6ABCFFDA5E4FCD53ULL,
		0x4B34AD10F4051A86ULL,
		0x42033009E4B56584ULL,
		0x96EDEB3D2E807A48ULL,
		0x564359599626FC8FULL,
		0x9C2704D0F9660BBBULL,
		0x1EC39AF6F64360BEULL,
		0x724FB763DD52F589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8E029B5E127C0A4ULL,
		0xD9A0D8D897C12CFAULL,
		0xD6CD197300CC7067ULL,
		0x1558ADA4381C3941ULL,
		0x0AA4E472FF52F00EULL,
		0x1E37BC3DA28252C2ULL,
		0xD90313875DCB7377ULL,
		0x0DE49E0C5FBFD7A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x68A029904007C000ULL,
		0x4920881094010882ULL,
		0x4201100100846004ULL,
		0x1448A92428003840ULL,
		0x020040509602F00EULL,
		0x1C270410A0020282ULL,
		0x1803128654436036ULL,
		0x004496005D12D589ULL
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
		0x3C51B7159C3D1E05ULL,
		0x02852C8AB02E924CULL,
		0xC5AFC2DBE5986910ULL,
		0x7D0E861264D3D6EAULL,
		0xFA42F82D9F26634EULL,
		0xAA5E57E458E1192DULL,
		0xC31728CA708D3C9BULL,
		0x41D255BEAF2D89E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F6F6086E72614FULL,
		0xDEEFAB7D07F62E46ULL,
		0xEAA89CF6BF78C24BULL,
		0x6D5A5D75EF5D48A1ULL,
		0x836273E92E0D9BC1ULL,
		0x11B46DB5A4D2C3AAULL,
		0x8E58A953B5379A59ULL,
		0xD69378165BD2209CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0050B6000C300005ULL,
		0x0285280800260244ULL,
		0xC0A880D2A5184000ULL,
		0x6D0A0410645140A0ULL,
		0x824270290E040340ULL,
		0x001445A400C00128ULL,
		0x8210284230051819ULL,
		0x409250160B000084ULL
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
		0x879D05620A2B807FULL,
		0x7018B25799EBF6A6ULL,
		0xD41E16F4DC9BC50EULL,
		0xAED2302557F4EB64ULL,
		0x252833617C601F10ULL,
		0x52320ECBFA1D38A0ULL,
		0x4E54E1E2CECD5359ULL,
		0xBB3A68BE0F8089F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA2EF11C8353AE0ULL,
		0xC18AB086D66D12F1ULL,
		0xE3105180C2978B74ULL,
		0x3E9C114FB238FFF1ULL,
		0xF9BC014052252A9CULL,
		0xA96FB0D53FA1CD9CULL,
		0x73012EBAB85A5BA5ULL,
		0x3155C2B9F8DB95C7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8280050008210060ULL,
		0x4008B006906912A0ULL,
		0xC0101080C0938104ULL,
		0x2E9010051230EB60ULL,
		0x2128014050200A10ULL,
		0x002200C13A010880ULL,
		0x420020A288485301ULL,
		0x311040B8088081C6ULL
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
		0xE35D47F0A0325557ULL,
		0x1A3445E46DEDEC22ULL,
		0x80BD2F9B1A041AB4ULL,
		0xE05F1687C49D4665ULL,
		0x71C3A47661F8A4F0ULL,
		0x5B9798DF21B26856ULL,
		0x3841313931B716B7ULL,
		0x017E491EA69426E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67C830B674E2B5B3ULL,
		0x60429490F2DE5722ULL,
		0x58F815052A3B11DBULL,
		0xAF5D21BB65ADC447ULL,
		0x8E9BAD52640A816DULL,
		0xEB48193FC82AA834ULL,
		0x8BCAC0E7478A8EDCULL,
		0xD5A9F06CCBC0E677ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x634800B020221513ULL,
		0x0000048060CC4422ULL,
		0x00B805010A001090ULL,
		0xA05D0083448D4445ULL,
		0x0083A45260088060ULL,
		0x4B00181F00222814ULL,
		0x0840002101820694ULL,
		0x0128400C82802665ULL
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
		0x47A46AD74B86AE08ULL,
		0x0A630FEDF87F9805ULL,
		0x3C874A7B1F906782ULL,
		0x8D8A647263CCA24BULL,
		0x235EBF269CFFA759ULL,
		0xE84B15AAF56638B3ULL,
		0xEC0E5A7BDC60F429ULL,
		0x9D0E7BA67D560FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6BDB801BAEA9281ULL,
		0xF8ACD23DB99736C9ULL,
		0x0BDBA27AF2A93EE0ULL,
		0x7D7C6CB164B952F8ULL,
		0x520EEB688512DB54ULL,
		0x95DDF75E75FD2DB2ULL,
		0x77D7D9719045E2F9ULL,
		0x8F48DCBFCFD95916ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46A428010A828200ULL,
		0x0820022DB8171001ULL,
		0x0883027A12802680ULL,
		0x0D08643060880248ULL,
		0x020EAB2084128350ULL,
		0x8049150A756428B2ULL,
		0x640658719040E029ULL,
		0x8D0858A64D500914ULL
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
		0x3F25DA3FD4116721ULL,
		0xBEFBFF46522A5B6DULL,
		0x0F261BD37B8D85F1ULL,
		0xB3386DB93787D67AULL,
		0xFF9BE9C607D63566ULL,
		0x2187564E8589B9E4ULL,
		0xA12155FDBFC0E79AULL,
		0xACA52AB0B9D7082EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D9FB8AFBC8296F8ULL,
		0x86CF6B6285053A66ULL,
		0xA7F008FBAED9B58DULL,
		0xE8623F892DA290CCULL,
		0x326E53A6D561672CULL,
		0xA0BBFA0C07416400ULL,
		0x04274999FDD6B665ULL,
		0xF9056098EB5E8CFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D05982F94000620ULL,
		0x86CB6B4200001A64ULL,
		0x072008D32A898581ULL,
		0xA0202D8925829048ULL,
		0x320A418605402524ULL,
		0x2083520C05012000ULL,
		0x00214199BDC0A600ULL,
		0xA8052090A956082EULL
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
		0x4457E60B18E283F1ULL,
		0x8B3D5876001D7B04ULL,
		0x424FA25798F34171ULL,
		0xAE30788B875A99E5ULL,
		0xF16A9048F9A4AD59ULL,
		0xC40EA440C62CBEA8ULL,
		0x37F9EA42E8E4DD9DULL,
		0x421BE2718E03119FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EBAA8B958F0414BULL,
		0x729F9FDA3DE70475ULL,
		0x4712EA397C725125ULL,
		0x66169E27DD0798D8ULL,
		0x69E4FEEB1611FF3BULL,
		0xC35E8A73E3031478ULL,
		0xF39064BFC9687FC2ULL,
		0xF38B27A4E6574673ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4412A00918E00141ULL,
		0x021D185200050004ULL,
		0x4202A21118724121ULL,
		0x26101803850298C0ULL,
		0x616090481000AD19ULL,
		0xC00E8040C2001428ULL,
		0x33906002C8605D80ULL,
		0x420B222086030013ULL
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
		0x8B4990A6FA720C37ULL,
		0x663573AFE682DC57ULL,
		0x4A5E7440E9E41FA5ULL,
		0x4576E471D0A85879ULL,
		0x90F32405455BBE64ULL,
		0xD4CE36BF26BA0895ULL,
		0xBB5F0FFD3CCA004DULL,
		0x685BFA90D3348384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA162AD9F6811EAEBULL,
		0xAC7249026BD7C2F3ULL,
		0xBD2893DD2D9D2AC9ULL,
		0x8FBEBD6BC3778C73ULL,
		0x84B4A868E44436CAULL,
		0x6CEA28582F67FB69ULL,
		0x85A71D94D6963164ULL,
		0x42D71A8BAE76BAFEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8140808668100823ULL,
		0x243041026282C053ULL,
		0x0808104029840A81ULL,
		0x0536A461C0200871ULL,
		0x80B0200044403640ULL,
		0x44CA201826220801ULL,
		0x81070D9414820044ULL,
		0x40531A8082348284ULL
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
		0xC8669FC0A8C8C363ULL,
		0xA5982C67330ADCEFULL,
		0xB70EFE56CDD9BEBEULL,
		0x416D384BD4E1871FULL,
		0xEE1C95FC1B7861E3ULL,
		0x761E45E986E00818ULL,
		0xE4969472A88A600CULL,
		0xBEAB26F2366251E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C82D2408392430ULL,
		0x3DB242F09E5150C0ULL,
		0x61AF6CDFFD1D1C52ULL,
		0xCC35D4818E6E5CB2ULL,
		0xFA4A0C3B764CA546ULL,
		0x6706503484F87BB0ULL,
		0x9A343B0686B065EDULL,
		0xA98C8B8770F4786EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48400D0008080020ULL,
		0x25900060120050C0ULL,
		0x210E6C56CD191C12ULL,
		0x4025100184600412ULL,
		0xEA08043812482142ULL,
		0x6606402084E00810ULL,
		0x801410028080600CULL,
		0xA888028230605068ULL
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
		0xA0D663E755B589F7ULL,
		0x779EEEEFCF19E564ULL,
		0xAAB80FAC7BAE02FEULL,
		0x0C3F1988A2066946ULL,
		0xFBF5A355521A8153ULL,
		0x6D1155C03A5A7FC1ULL,
		0x23BF01002B6191D4ULL,
		0x943B5C0C96A672F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8DE7218C52B5965ULL,
		0x11AA76D93E29E637ULL,
		0xCD8621BCBBD5BB72ULL,
		0xF5AE2B4DAD7621D4ULL,
		0x8AA4773BC55F8134ULL,
		0xC2681881178E93A6ULL,
		0x4C3720EC5C43657FULL,
		0x6642753FBD566326ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0D6620045210965ULL,
		0x118A66C90E09E424ULL,
		0x888001AC3B840272ULL,
		0x042E0908A0062144ULL,
		0x8AA42311401A8110ULL,
		0x40001080120A1380ULL,
		0x0037000008410154ULL,
		0x0402540C94066220ULL
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
		0xA223489B4FD0B4D4ULL,
		0x4AB4AC2507993045ULL,
		0xF30361DA34A22C55ULL,
		0x64979CDC27EF39E6ULL,
		0x58FE3EFDD5F57501ULL,
		0x441BB3439AE9E471ULL,
		0x5E7C06FEA8EF4A2EULL,
		0xDFAEF55AE13B13C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF03CB7C14F488EBULL,
		0x4CA60454F58D4703ULL,
		0x4A109EE096536AE9ULL,
		0x67D68FC7F1BFA700ULL,
		0x242DBA557C475BCDULL,
		0xDD9ABE97BFB54DCDULL,
		0x2341190FB6AAB8A9ULL,
		0x047885149CF391A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8203481804D080C0ULL,
		0x48A4040405890001ULL,
		0x420000C014022841ULL,
		0x64968CC421AF2100ULL,
		0x002C3A5554455101ULL,
		0x441AB2039AA14441ULL,
		0x0240000EA0AA0828ULL,
		0x0428851080331187ULL
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
		0x4F55339F22A0C836ULL,
		0x4B4E1F0B2F15D4B0ULL,
		0x3D4C580F90375901ULL,
		0xAF7E59DAA23D6ECCULL,
		0xC774FE841364F653ULL,
		0xAD7AC2E9EB66A8D4ULL,
		0x436EF06053BA9EAAULL,
		0x8605936F53E47489ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD927C9906FA5EBULL,
		0x0253D4844489E037ULL,
		0xE6DB24B13D1B6DBEULL,
		0x6C764180C9AD0923ULL,
		0xC90CE8AE75AC63C4ULL,
		0xC0370B6163ED0DC1ULL,
		0xABB7CD6C75EF9930ULL,
		0xA7DE5088D5C21AF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D51238900208022ULL,
		0x024214000401C030ULL,
		0x2448000110134900ULL,
		0x2C764180802D0800ULL,
		0xC104E88411246240ULL,
		0x80320261636408C0ULL,
		0x0326C06051AA9820ULL,
		0x8604100851C01080ULL
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
		0x40BC34D3D9ED870BULL,
		0x172151B0EC8B56D8ULL,
		0x9C874EAD1FCC4BFEULL,
		0xA144BAA9E93E4E1AULL,
		0x0E22413E231484F6ULL,
		0x0F51EAB51CD005BCULL,
		0x3998EA2A62FCB130ULL,
		0x97CAB9802E035711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8E6C85665CF816EULL,
		0x8EFE89971C5B1721ULL,
		0x47B199AF650FA39AULL,
		0xF14D46AA5365C554ULL,
		0x12D825A6B5DD1AC5ULL,
		0xCB692BED67BD2A59ULL,
		0xA9D6FAEF4EBC58B4ULL,
		0xF236CB51A309F4C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A4005241CD810AULL,
		0x062001900C0B1600ULL,
		0x048108AD050C039AULL,
		0xA14402A841244410ULL,
		0x02000126211400C4ULL,
		0x0B412AA504900018ULL,
		0x2990EA2A42BC1030ULL,
		0x9202890022015401ULL
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
		0x3480881088038DF3ULL,
		0xDA571892A84E8F3BULL,
		0x05866AEE9526A870ULL,
		0xDF37E116AF9E626EULL,
		0xC804335EF9143F55ULL,
		0x43370D9220804FE7ULL,
		0x7BE0FBF3ED3B3F12ULL,
		0xBE199E245A7C1F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE75E2122552EA7EULL,
		0x60CD01A2EE6A974EULL,
		0xAE0C9A0DA6A2D3B4ULL,
		0x539C03A3CCFD7D3AULL,
		0x9CC8234022C77651ULL,
		0xA30DC728F8F0F1F1ULL,
		0x60E78DAAE7559580ULL,
		0x1B9D81E86B9FC6B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1400801000028872ULL,
		0x40450082A84A870AULL,
		0x04040A0C84228030ULL,
		0x531401028C9C602AULL,
		0x8800234020043651ULL,
		0x03050500208041E1ULL,
		0x60E089A2E5111500ULL,
		0x1A1980204A1C0611ULL
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
		0x6B2F0B2B317DAAA1ULL,
		0x55FB5A43BA250008ULL,
		0x57401A4DFC984BABULL,
		0xEC1FE0B0B66EB659ULL,
		0xF3BF11D98C5DF68EULL,
		0xE3991B730EE48DFFULL,
		0x4D8AD5B1B74BCD26ULL,
		0x7F975487BC9D362BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x390A22C8F26CEB13ULL,
		0xC560C5F6796E736CULL,
		0x828D0BF96C071009ULL,
		0xF8A9E1E4228B30EAULL,
		0x8953897A7D3E9DC3ULL,
		0x1FA5F83823FAC9C6ULL,
		0x4F58336AF11A29FBULL,
		0xD0CD015B62476BF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x290A0208306CAA01ULL,
		0x4560404238240008ULL,
		0x02000A496C000009ULL,
		0xE809E0A0220A3048ULL,
		0x811301580C1C9482ULL,
		0x0381183002E089C6ULL,
		0x4D081120B10A0922ULL,
		0x5085000320052220ULL
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
		0x6D85C7AA58D05E8EULL,
		0xCBDBD482E37B5FCCULL,
		0xB1AE0D84451DB6EEULL,
		0x00365EFA3A0AAED3ULL,
		0x9BCE88A6B5D32953ULL,
		0x0016A300B78FA733ULL,
		0x2A4FDA5B31830F76ULL,
		0x3605E994BD066370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCCB26BF5EFEC358ULL,
		0x67CFF891F962AFE6ULL,
		0x13C734D7B1A9596BULL,
		0x2BF026F97A3B1C8AULL,
		0x526E80F22E79E2CAULL,
		0xAC47F4CEE0675146ULL,
		0x6417930065DD3A90ULL,
		0xA25F67CE1F4ED0C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C8106AA58D04208ULL,
		0x43CBD080E1620FC4ULL,
		0x118604840109106AULL,
		0x003006F83A0A0C82ULL,
		0x124E80A224512042ULL,
		0x0006A000A0070102ULL,
		0x2007920021810A10ULL,
		0x220561841D064040ULL
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
		0x943E35EC1B4C1FD8ULL,
		0x7CC39928E6A36981ULL,
		0xAF167D079755DD21ULL,
		0x84C854F39DEA9292ULL,
		0xB8CACC0193DC37CAULL,
		0x9EE3A52C399DEF2BULL,
		0x8020ABE6A9350FDAULL,
		0x17206A7E5F6F4D48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D30A192FEF7098ULL,
		0x6BD76BA0F4B587BEULL,
		0xAB561A7934ACC350ULL,
		0xDBFF646E435DAEFAULL,
		0x6277D67006D21541ULL,
		0x0297C2718A0A08D9ULL,
		0x9705CA0E175567FFULL,
		0x34DBD876295BDFB1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x041200080B4C1098ULL,
		0x68C30920E4A10180ULL,
		0xAB1618011404C100ULL,
		0x80C8446201488292ULL,
		0x2042C40002D01540ULL,
		0x0283802008080809ULL,
		0x80008A06011507DAULL,
		0x14004876094B4D00ULL
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
		0x8E9FCF13BE6ED1F7ULL,
		0x7F533241E17921BAULL,
		0x2A865E8DB248232AULL,
		0xECE85D0376037477ULL,
		0x90201E1D3D46A0B7ULL,
		0x720C57428EFA62B4ULL,
		0x47471F1C19C5B194ULL,
		0x8FAE47CFB5A22A25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E07263C686D654ULL,
		0x03B24485E5A0FB0FULL,
		0xDB986CBFD6090269ULL,
		0x065CCA3BF7902042ULL,
		0x929C4D15F8458336ULL,
		0x400B7F22961D0C22ULL,
		0xAB3E0DC96B92B146ULL,
		0xBD94AF437D7103AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x848042038606D054ULL,
		0x03120001E120210AULL,
		0x0A804C8D92080228ULL,
		0x0448480376002042ULL,
		0x90000C1538448036ULL,
		0x4008570286180020ULL,
		0x03060D080980B104ULL,
		0x8D84074335200220ULL
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
		0x6BD30B8714D107EBULL,
		0xD0100605CC8B2F96ULL,
		0x0D879E3E435A0158ULL,
		0xEB37F9FC3BB1713BULL,
		0x1379E6E0769B75BDULL,
		0x89B40C03686C2E61ULL,
		0xEF1D2528346958B3ULL,
		0x02B77B91E06239D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDD4DDB008EAB122ULL,
		0x967109302EAF8CF7ULL,
		0x7655E029A673936EULL,
		0xF62C44FCBBF696EDULL,
		0x5699E42BBB7C37CCULL,
		0x284085A3988421ABULL,
		0x318799E6F53217DFULL,
		0xF83E1B213437CD41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69D0098000C00122ULL,
		0x901000000C8B0C96ULL,
		0x0405802802520148ULL,
		0xE22440FC3BB01029ULL,
		0x1219E4203218358CULL,
		0x0800040308042021ULL,
		0x2105012034201093ULL,
		0x00361B0120220940ULL
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
		0x75CB3493F71E29DBULL,
		0xAFC24116CEF715B7ULL,
		0x58D8CD60A8108C44ULL,
		0xD65EF32C7E52E32BULL,
		0xB7CD5FE7890B162AULL,
		0x03054DDF565CFC3CULL,
		0xEEB146DA6FC10F48ULL,
		0xABCE8B55B2D82BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x296084CA057C3FA0ULL,
		0x2838E14EF9C07DE5ULL,
		0x50A491A3B04F4678ULL,
		0x26704B0FA95C93F5ULL,
		0x4E26A075F02A026DULL,
		0xEA2FEA2E49FAAD2BULL,
		0xEC16A9D46252A6A7ULL,
		0x85235A2C2A476F17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x21400482051C2980ULL,
		0x28004106C8C015A5ULL,
		0x50808120A0000440ULL,
		0x0650430C28508321ULL,
		0x06040065800A0228ULL,
		0x0205480E4058AC28ULL,
		0xEC1000D062400600ULL,
		0x81020A0422402B00ULL
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
		0x18AB1E2808104D51ULL,
		0xB5EF7AEB13E8A87EULL,
		0x9509CA49E743CFC9ULL,
		0xAAD661A82D3A98F9ULL,
		0x1592BC1506800D82ULL,
		0x5970840EEEB25CAFULL,
		0x90A6924D1064C665ULL,
		0x74F8102E8565DAB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x869846CBC46DFD19ULL,
		0xCBCBE463F4093275ULL,
		0x9C5BCCE4AFB9BEF0ULL,
		0xA8C0F3AFF4FC1C46ULL,
		0x690563C7782F14D2ULL,
		0xBE22387D58E2964CULL,
		0xE34F2F083E90A611ULL,
		0xC192B598FE0C820DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0088060800004D11ULL,
		0x81CB606310082074ULL,
		0x9409C840A7018EC0ULL,
		0xA8C061A824381840ULL,
		0x0100200500000482ULL,
		0x1820000C48A2140CULL,
		0x8006020810008601ULL,
		0x4090100884048205ULL
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
		0xC182B72DE7B1EA05ULL,
		0x93D6B181C6A69C0CULL,
		0x56410A639F56701BULL,
		0x62FEB49327964D09ULL,
		0x405F0E53347D475AULL,
		0x3B6345CBC3E3ABA3ULL,
		0x08125A3FFB9847F2ULL,
		0x28D336FA6D36F281ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE5FF9B956D708AULL,
		0x4791377886A509A3ULL,
		0x0F8215DBA0E1498BULL,
		0xF9A8E02FF7A780CFULL,
		0x24434EC29E43391FULL,
		0xCA3838F75E6BF4B7ULL,
		0xDDC2638AA914C590ULL,
		0xF0BC61EDD8A4F6C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC180B70985216000ULL,
		0x0390310086A40800ULL,
		0x060000438040400BULL,
		0x60A8A00327860009ULL,
		0x00430E421441011AULL,
		0x0A2000C34263A0A3ULL,
		0x0802420AA9104590ULL,
		0x209020E84824F280ULL
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
		0xC7A65CF45400CA69ULL,
		0xF78229BB56068CD2ULL,
		0x7995B841978949C2ULL,
		0xE41024E78BA7F3E9ULL,
		0x79EF4210E6236E30ULL,
		0x6B95BD92ABC54D88ULL,
		0x28640971610A33AAULL,
		0x11544D2EB9288670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DCC9AA0F35D01FULL,
		0x95EBD2C73B88664AULL,
		0x2E7C7100EEAAC0FDULL,
		0x7799C269A5C1AE13ULL,
		0xF73E035670CDF196ULL,
		0xEF546B6C3D4A3D83ULL,
		0x25B8E2D84CC3A5C4ULL,
		0xD36E43B9F8ED604DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x018448A00400C009ULL,
		0x9582008312000442ULL,
		0x28143000868840C0ULL,
		0x641000618181A201ULL,
		0x712E021060016010ULL,
		0x6B14290029400D80ULL,
		0x2020005040022180ULL,
		0x11444128B8280040ULL
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
		0x9E9E803620F0C79BULL,
		0xA1CEC9926973E60CULL,
		0x1DD125828B1E5F79ULL,
		0xEFABB6E9766E07B5ULL,
		0x078721DFF3C49049ULL,
		0x6A69DEF16AD2F28AULL,
		0x30BB53A8318ABA1BULL,
		0xE7EB8F10824E0104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8123781F66323734ULL,
		0x72764E4D95196443ULL,
		0xB6DA33300344E511ULL,
		0x99A5E4E85D8601BCULL,
		0x171EC19FE5EADB27ULL,
		0x0CC61A1C3BFB72FAULL,
		0xC896C533E2EC9AEAULL,
		0x6849DFAC7C343FA2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8002001620300710ULL,
		0x2046480001116400ULL,
		0x14D0210003044511ULL,
		0x89A1A4E8540601B4ULL,
		0x0706019FE1C09001ULL,
		0x08401A102AD2728AULL,
		0x0092412020889A0AULL,
		0x60498F0000040100ULL
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
		0x202378B94D0053D8ULL,
		0x48727DD5AA6D5919ULL,
		0x3E4AC61D04E31CCAULL,
		0x93E08701B7844003ULL,
		0x764B280A5ACCB0E3ULL,
		0xEF6C4F49E42E9E66ULL,
		0x82AB3999BE42D6C7ULL,
		0x195BE4A82D14933BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FD3AFC34D0F5FBCULL,
		0xA7B192598D57930DULL,
		0x6122A66B392A8095ULL,
		0xE691C58FDEF4FBE6ULL,
		0x600FE86636EDB4F2ULL,
		0x2DDFCAE5C7547CAEULL,
		0xDC22B94013A44B88ULL,
		0xC54DB21D6075B3B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000328814D005398ULL,
		0x0030105188451109ULL,
		0x2002860900220080ULL,
		0x8280850196844002ULL,
		0x600B280212CCB0E2ULL,
		0x2D4C4A41C4041C26ULL,
		0x8022390012004280ULL,
		0x0149A00820149331ULL
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
		0x9FA8DF4FD46BBDF8ULL,
		0xAD541F1EA24D199DULL,
		0xABC112960072602CULL,
		0x5D6067A53812AFC4ULL,
		0x0E35BAB28FA02920ULL,
		0xFEDE57242D9A29C6ULL,
		0xC37B77F097C44787ULL,
		0xEB07A885829760AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9826FA889F54527CULL,
		0xE11249BA34801249ULL,
		0xCA63105459621CFFULL,
		0xFD85800B0DBFB2C9ULL,
		0xF89AA967170EAAF6ULL,
		0xB40F2EC2034C968CULL,
		0xACC7453DF66052CBULL,
		0xF70F412B8998496EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9820DA0894401078ULL,
		0xA110091A20001009ULL,
		0x8A4110140062002CULL,
		0x5D0000010812A2C0ULL,
		0x0810A82207002820ULL,
		0xB40E060001080084ULL,
		0x8043453096404283ULL,
		0xE30700018090402EULL
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
		0x1B47021B312DA387ULL,
		0x3336C6C4955B69CFULL,
		0x616578960E4ADF84ULL,
		0x17D886609186B09FULL,
		0xD765733AB766A046ULL,
		0xA7068A2C83F5475DULL,
		0xEB03C05116436F69ULL,
		0xA58FF907699C5E13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE544111C01AF6C6EULL,
		0x17BB5CFFFC11F67AULL,
		0x00DA414AA32555B9ULL,
		0xA904DB3318AD0BB4ULL,
		0x2342086689410B86ULL,
		0xAA07BBD06AAE38FEULL,
		0xB8C76FC995DE9BD7ULL,
		0xD70B6A46C4CB3054ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01440018012D2006ULL,
		0x133244C49411604AULL,
		0x0040400202005580ULL,
		0x0100822010840094ULL,
		0x0340002281400006ULL,
		0xA2068A0002A4005CULL,
		0xA803404114420B41ULL,
		0x850B680640881010ULL
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
		0xDD5FBF52AAF17E07ULL,
		0x1838654566508336ULL,
		0xC11FBE5DA3E7BE39ULL,
		0x3A0FABB7E2A3017AULL,
		0x610D5FAC3F60D531ULL,
		0xB46B331890F4FB58ULL,
		0x8071776E3A71E19AULL,
		0xDFB12031ADDC31BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1DE5384D313800CULL,
		0xF20C932C7EBBA537ULL,
		0x4608EE267E8A5445ULL,
		0x0900C980B3736A45ULL,
		0xA229A06AE823BA07ULL,
		0x862ED28CB68314C1ULL,
		0x72C25BF5FDB96583ULL,
		0x35C13A5A77660FC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD15E130082110004ULL,
		0x1008010466108136ULL,
		0x4008AE0422821401ULL,
		0x08008980A2230040ULL,
		0x2009002828209001ULL,
		0x842A120890801040ULL,
		0x0040536438316182ULL,
		0x1581201025440188ULL
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
		0xABA6AC845B719A65ULL,
		0x8EB5D1C779E4D84BULL,
		0x94840A198667E4C7ULL,
		0xA2773679675ACB2DULL,
		0x0B1E9FA5DA5BED38ULL,
		0x91B2A900435D1008ULL,
		0x3CDD9285C0B0B524ULL,
		0x441C82DE6023AFA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB665D2CD5800CA1BULL,
		0xEA2D44102FAC0EA1ULL,
		0x7E5746BC90F1B25FULL,
		0xB36952C3ABF255AAULL,
		0x0C4FF35EADF54EDBULL,
		0xF9D0AC7D8E037B87ULL,
		0xE9A4A6E836E84216ULL,
		0x974A57D0876802EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA224808458008A01ULL,
		0x8A25400029A40801ULL,
		0x140402188061A047ULL,
		0xA261124123524128ULL,
		0x080E930488514C18ULL,
		0x9190A80002011000ULL,
		0x2884828000A00004ULL,
		0x040802D0002002A0ULL
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
		0x1330A8F270F9985AULL,
		0x1034852E709D747CULL,
		0x8517BD12FDC84E41ULL,
		0x26D685644E9C056FULL,
		0x334E72F8A73C14EBULL,
		0xC9C3E53FA7E5D19EULL,
		0x073FA906AE54B64EULL,
		0x865DC4A602479871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0084780A992664A1ULL,
		0x8A6649FC2B1C3CF8ULL,
		0xF2E2E95E1E1CFB1EULL,
		0xF6D2AE94DB245FC8ULL,
		0xCD7290D37A6695AEULL,
		0x2D3773A2ADB2C1C8ULL,
		0x0DE23164671057ADULL,
		0x9671754A831F1D66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0000280210200000ULL,
		0x0024012C201C3478ULL,
		0x8002A9121C084A00ULL,
		0x26D284044A040548ULL,
		0x014210D0222414AAULL,
		0x09036122A5A0C188ULL,
		0x052221042610160CULL,
		0x8651440202071860ULL
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
		0x2EAE25A48CB619C5ULL,
		0xF9C9FE62A137FC98ULL,
		0x7A5756B28A220F62ULL,
		0x2F98E136FF5E4CE6ULL,
		0xF2A49F97ADAA85B3ULL,
		0xF2FE6F0F847F61EDULL,
		0x97F8C70485DD092FULL,
		0xD90010BF05A252CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BE3A9957DC6151BULL,
		0x6B251EBE956D3414ULL,
		0x61D01FD94F0FE073ULL,
		0xD4B68928AC406182ULL,
		0xBA84503A44D9C915ULL,
		0xB9034D76F4CFC6A9ULL,
		0x6D8A9E17D6E25834ULL,
		0x01471EF8E10214D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AA221840C861101ULL,
		0x69011E2281253410ULL,
		0x605016900A020062ULL,
		0x04908120AC404082ULL,
		0xB284101204888111ULL,
		0xB0024D06844F40A9ULL,
		0x0588860484C00824ULL,
		0x010010B8010210C3ULL
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
		0x1EC26F9C1D80B2A0ULL,
		0x6AB602005743EB2FULL,
		0x11266F269C0A6DB9ULL,
		0x8FD9DDDA6BF65D3AULL,
		0x0CA17D9E2F406320ULL,
		0x7ACB4A072CEFB93DULL,
		0xD9E3329ECA08B49AULL,
		0x1D07AFE7E3D3D850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DBF5D6C0A5FE193ULL,
		0x3F7D912F09D756B7ULL,
		0xD4D25F4F683B63FFULL,
		0x6CD6FF33BD0FE18AULL,
		0x91ACC9745C4170A1ULL,
		0x28D0A67ABC8C8AB1ULL,
		0xEF7409E72BF299BFULL,
		0xC86B417CBFD4BCDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C824D0C0800A080ULL,
		0x2A34000001434227ULL,
		0x10024F06080A61B9ULL,
		0x0CD0DD122906410AULL,
		0x00A049140C406020ULL,
		0x28C002022C8C8831ULL,
		0xC96000860A00909AULL,
		0x08030164A3D09850ULL
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
		0x3E8501D6032D1F3DULL,
		0x8FFDB7789F98F9BCULL,
		0x03714D1D75021104ULL,
		0xF7E0AA9184C4B446ULL,
		0x8826A2DBE43680AAULL,
		0x1DB04CE9F314782AULL,
		0xA975C73ECA1AC774ULL,
		0x189C3A2119DFB543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x548F9AF57D1F56F1ULL,
		0xF07163696468E8D4ULL,
		0xFA62903C09817FAFULL,
		0x02E44E96465D9FC4ULL,
		0x358ECEE6BAA3AC42ULL,
		0xEC1E031CB5C96977ULL,
		0xB3960AB4AC02AE04ULL,
		0xB1AEAF64EFC45D28ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x148500D4010D1631ULL,
		0x807123680408E894ULL,
		0x0260001C01001104ULL,
		0x02E00A9004449444ULL,
		0x000682C2A0228002ULL,
		0x0C100008B1006822ULL,
		0xA114023488028604ULL,
		0x108C2A2009C41500ULL
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
		0x01A5DD42CF3B238CULL,
		0x005C029CE54F8D33ULL,
		0x0FB11C7ECA8FDA67ULL,
		0x7514936AB7F1BD57ULL,
		0xD5ED97234FD2B8CBULL,
		0xA86491A5D99BCF8CULL,
		0x96136D45784503B2ULL,
		0x48A0962EF226E86AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x923322B15BBBC9C6ULL,
		0x72D24BB7D762FA2BULL,
		0x71633D0E68CB70F1ULL,
		0xED803DD5FBF412BEULL,
		0xC3B46BD1AD55647BULL,
		0x0469E5B6E4ED1CC3ULL,
		0x2B7430474D53644BULL,
		0x9CE8925E5181AD49ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002100004B3B0184ULL,
		0x00500294C5428823ULL,
		0x01211C0E488B5061ULL,
		0x65001140B3F01016ULL,
		0xC1A403010D50204BULL,
		0x006081A4C0890C80ULL,
		0x0210204548410002ULL,
		0x08A0920E5000A848ULL
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
		0xAC2CA47FBEB85893ULL,
		0xC3E7748FA8F2266FULL,
		0x8D00E08F83C0BC91ULL,
		0x717E3F904C2FEE27ULL,
		0x2A7DCA98BB5D3CDAULL,
		0xF640A0E7AF5CF002ULL,
		0xC0572E80499C68D6ULL,
		0xFCE80DA8D09A3DD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E221B0583765C43ULL,
		0x099D2D3B067E2D31ULL,
		0x999D2DDF99E800BEULL,
		0xF2B2DC98C27778C0ULL,
		0xB0229BF9E5C771F6ULL,
		0xD227708D9E2509C2ULL,
		0xB88E1D1AAB867A65ULL,
		0x3380F0F7FC9ECE23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C20000582305803ULL,
		0x0185240B00722421ULL,
		0x8900208F81C00090ULL,
		0x70321C9040276800ULL,
		0x20208A98A14530D2ULL,
		0xD20020858E040002ULL,
		0x80060C0009846844ULL,
		0x308000A0D09A0C01ULL
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
		0x6C022C4FC3916B6EULL,
		0x053A827E99416C02ULL,
		0x867867AEC513F3F3ULL,
		0xF06458EDFCC12F51ULL,
		0x8E39E553270B548EULL,
		0xB743EB04498BB6A9ULL,
		0xEA16351779A66749ULL,
		0x86DB1DB2D384BF28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC6DDDAEED2AB649ULL,
		0xBF3AE7E6974EA44FULL,
		0x02C9270CD49904DAULL,
		0xE902C8FDE6E6F8CBULL,
		0x0505DFB1E8D63EC5ULL,
		0x860A932F3E8D95F0ULL,
		0xB74ADC5CB604E1BBULL,
		0xFD4A60C65B27DE9BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C000C0EC1002248ULL,
		0x053A826691402402ULL,
		0x0248270CC41100D2ULL,
		0xE00048EDE4C02841ULL,
		0x0401C51120021484ULL,
		0x86028304088994A0ULL,
		0xA202141430046109ULL,
		0x844A008253049E08ULL
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
		0x5BEB390BCD73AA22ULL,
		0xF1C1E3E90724BE21ULL,
		0x709F5763CE2AAEE2ULL,
		0x4A9BA1E694E0DC5AULL,
		0x4F4F24F6EBBF588EULL,
		0x985177EC56879853ULL,
		0xF706A3DC67001485ULL,
		0xB6D8D65B4589A9C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x235FB08C4EFF602CULL,
		0x58A3EA55D25B022DULL,
		0x0F7D099201565B68ULL,
		0x58F3119F771669FCULL,
		0x4516CD0877E5F055ULL,
		0xA912F6889F791417ULL,
		0xA0656512A37A1D77ULL,
		0x61CE78A073715F21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x034B30084C732020ULL,
		0x5081E24102000221ULL,
		0x001D010200020A60ULL,
		0x4893018614004858ULL,
		0x4506040063A55004ULL,
		0x8810768816011013ULL,
		0xA004211023001405ULL,
		0x20C8500041010900ULL
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
		0x953195572A5E75C6ULL,
		0xD4D2CCE9F6BFA244ULL,
		0x6F8CA865D964013AULL,
		0x30E443C9757B04D1ULL,
		0x36EC76519D773723ULL,
		0xE7B9AA66CC90F32DULL,
		0x4B2734898CF2D201ULL,
		0xFA47572F2B5510F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB258DC6B9CC531B2ULL,
		0xF9925D490587CB97ULL,
		0x975D0BFAC0DF3835ULL,
		0x6884795CD1856887ULL,
		0xF2ADA5CDD986181AULL,
		0x5342FB2E29B06D97ULL,
		0x2846816BECFE065AULL,
		0x97AC80A2B95068B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9010944308443182ULL,
		0xD0924C4904878204ULL,
		0x070C0860C0440030ULL,
		0x2084414851010081ULL,
		0x32AC244199061002ULL,
		0x4300AA2608906105ULL,
		0x080600098CF20200ULL,
		0x92040022295000B4ULL
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
		0x9EF09D813CEE3F25ULL,
		0xF3F8BD8E3EDB7B00ULL,
		0x561EB370247027A7ULL,
		0xCD75C4E621E751AFULL,
		0x2953FB9F5373C635ULL,
		0x34A8A11A3AB7FB98ULL,
		0x6A4D59B3E7A3CC5DULL,
		0xB70AA4D4AA1D2525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FF8FD702A4C8FFULL,
		0xDA7796B9679268F8ULL,
		0x28212D55BAA44481ULL,
		0x6F3EE00A78193A22ULL,
		0x6F73E9007EB61C95ULL,
		0x689DDBCA649CCB67ULL,
		0xA53207ACAB34F1A0ULL,
		0x282B9BF6D4E6A024ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86F08D8100A40825ULL,
		0xD270948826926800ULL,
		0x0000215020200481ULL,
		0x4D34C00220011022ULL,
		0x2953E90052320415ULL,
		0x2088810A2094CB00ULL,
		0x200001A0A320C000ULL,
		0x200A80D480042024ULL
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
		0xCF96110DC20DB439ULL,
		0x645F5E5D15D286FBULL,
		0x5BFB29BC5810EF7FULL,
		0x8EC40906F42E594CULL,
		0xA91940926860A66EULL,
		0xB476322A05667722ULL,
		0xDFDEA05B23A1D512ULL,
		0xF5159A5DD0254E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65A708569A759236ULL,
		0xC712A73E75C7EEBFULL,
		0x4630E459E0692089ULL,
		0xF3149AD2B80AE4F0ULL,
		0x3353048F57159B99ULL,
		0xC0331B918CA7E5E6ULL,
		0xB8EF3B81B874AFAAULL,
		0x4C467094236C7248ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4586000482059030ULL,
		0x4412061C15C286BBULL,
		0x4230201840002009ULL,
		0x82040802B00A4040ULL,
		0x2111008240008208ULL,
		0x8032120004266522ULL,
		0x98CE200120208502ULL,
		0x4404101400244240ULL
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
		0xFE9FA305FF4C863DULL,
		0x7F8A80AFBC40965EULL,
		0xED25E3D506D180AFULL,
		0xD5A199C9E063139CULL,
		0x3DBA17B69158E687ULL,
		0x970A422E54A0CDBDULL,
		0x1BCEC05EB0398432ULL,
		0xA68D85B4CBAF63E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51690A62E5FC9611ULL,
		0x6AF99FF1C47177E9ULL,
		0x30970DE9927DF19BULL,
		0x42693B721A0E0E96ULL,
		0x586C567CCDC78C05ULL,
		0x5119F7AB296818EFULL,
		0xB3FD0CE1117B5FBFULL,
		0x02465C6F6C6C8519ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50090200E54C8611ULL,
		0x6A8880A184401648ULL,
		0x200501C10251808BULL,
		0x4021194000020294ULL,
		0x1828163481408405ULL,
		0x1108422A002008ADULL,
		0x13CC004010390432ULL,
		0x02040424482C0100ULL
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
		0x2106F0A4ED612E3AULL,
		0x2C2355659A8AF0C1ULL,
		0x415D5E5ED6A64849ULL,
		0xCA0A2064A2183292ULL,
		0xCABB5754A5C53DD7ULL,
		0x735FF939DA742C2EULL,
		0xCD1E90A61F70D126ULL,
		0x9FBE4AAA267CCA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD767044F9C036A5BULL,
		0x6B3F0D08F06AE52CULL,
		0x701D9829B9C9CCEDULL,
		0xF7C209A17C68B33EULL,
		0xF791BA4510374C09ULL,
		0x65F03C0FDC92AC22ULL,
		0x3640AE0F2487322DULL,
		0xFBCF26570D54CA65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010600048C012A1AULL,
		0x28230500900AE000ULL,
		0x401D180890804849ULL,
		0xC202002020083212ULL,
		0xC291124400050C01ULL,
		0x61503809D8102C22ULL,
		0x0400800604001024ULL,
		0x9B8E02020454CA01ULL
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
		0x2D70E60CAAE2F866ULL,
		0x472B422B7E77805DULL,
		0x75D1EC57604317D0ULL,
		0x816E5D7E2032F072ULL,
		0x9A57EE95D8DEBE42ULL,
		0xC7F78ACBEB65AF78ULL,
		0x7DA2091837A2D36EULL,
		0x5E8D4090C7BB4142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE683584158DD0E2DULL,
		0x8142FE0C9D33E6B1ULL,
		0x3FB28AE736F843F0ULL,
		0x1EF299552F1565ACULL,
		0x5F70AF31CDC78950ULL,
		0x4B38A40B955E0D1FULL,
		0x6CD80127B8B33E9FULL,
		0x5DABE00C32275DD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2400400008C00824ULL,
		0x010242081C338011ULL,
		0x35908847204003D0ULL,
		0x0062195420106020ULL,
		0x1A50AE11C8C68840ULL,
		0x4330800B81440D18ULL,
		0x6C80010030A2120EULL,
		0x5C89400002234140ULL
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
		0x1935DA94EA1452E0ULL,
		0xF9D1A5EADDD57589ULL,
		0xB1428D96FBEAEA81ULL,
		0xF97AE758BC031199ULL,
		0xC0867641A7AC1483ULL,
		0x4BF515F487FC2220ULL,
		0xF2FCA8DAD2F93D90ULL,
		0xB83BF24E9F38F969ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADDF4A906DA3316DULL,
		0xDDEF63D8E653A5DDULL,
		0xEFF343368EA9BEF6ULL,
		0x838BE9BE0EC02738ULL,
		0x1F2F8C4D9BECD27AULL,
		0x33B43D6374290460ULL,
		0xBC0B983D61952471ULL,
		0xF095677AF67A2DADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09154A9068001060ULL,
		0xD9C121C8C4512589ULL,
		0xA14201168AA8AA80ULL,
		0x810AE1180C000118ULL,
		0x0006044183AC1002ULL,
		0x03B4156004280020ULL,
		0xB008881840912410ULL,
		0xB011624A96382929ULL
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
		0x5BE14C6004E462A0ULL,
		0x1493FD93F78618E1ULL,
		0x6C340342AC52ECDEULL,
		0xC9B77CA3FFF810F6ULL,
		0xC108A6F9B6B58A10ULL,
		0xEEAF7425D3C7FF48ULL,
		0xAD2682DFEAC0C337ULL,
		0xD582EDE581E9F69CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCAD2946F57FBB44ULL,
		0xEAFFC56D3ABD4DF4ULL,
		0x53892BBDB6FB58F0ULL,
		0x5B352BABFA80ADFAULL,
		0xA16F98A4BB30B1BEULL,
		0x29AEDDE20B1D5133ULL,
		0x82A412DE4856B42DULL,
		0x21FB92C6E9680D86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x58A1084004642200ULL,
		0x0093C501328408E0ULL,
		0x40000300A45248D0ULL,
		0x493528A3FA8000F2ULL,
		0x810880A0B2308010ULL,
		0x28AE542003055100ULL,
		0x802402DE48408025ULL,
		0x018280C481680484ULL
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
		0x0B0A33D7D8500627ULL,
		0x17BC39623A573BEAULL,
		0xFD422FFC7E7005C7ULL,
		0x01481433D6C7E6BDULL,
		0xFA3419B4B87C6641ULL,
		0xB59A69AF68DA3C2DULL,
		0xBAF67B45F2A37B65ULL,
		0x8C2E70588C8D0967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB40E80ADAB16DB00ULL,
		0x427EB342BB3BE29CULL,
		0x4B1BC16CBCABFDACULL,
		0xC6D85891F5C6B91EULL,
		0x06CBFE46A2746138ULL,
		0x6129B24ECE3CC0FCULL,
		0x0B4FEFA9ADFBF5E3ULL,
		0x3560417721E338A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000A008588100200ULL,
		0x023C31423A132288ULL,
		0x4902016C3C200584ULL,
		0x00481011D4C6A01CULL,
		0x02001804A0746000ULL,
		0x2108200E4818002CULL,
		0x0A466B01A0A37161ULL,
		0x0420405000810827ULL
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
		0xA80ED368FC14E1CAULL,
		0x1B16B58E10705D28ULL,
		0x9674B0545AF19CA3ULL,
		0x4158DD0F47A1729BULL,
		0xFE73AAF8CAA72030ULL,
		0xD68A2BCD4CE4502FULL,
		0xE15D42564DD6A55DULL,
		0x9F3A89E0FE50EE61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8C8FCD4595DB1F0ULL,
		0x00164FCE74D62E01ULL,
		0x756806FDBA59296DULL,
		0x27C36457F5B8340EULL,
		0x66CC10FA1AC70953ULL,
		0xA75E1188FCEB16ACULL,
		0x5762CF3163A832C1ULL,
		0xF8FA80A412C6F182ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8808D0405814A1C0ULL,
		0x0016058E10500C00ULL,
		0x146000541A510821ULL,
		0x0140440745A0300AULL,
		0x664000F80A870010ULL,
		0x860A01884CE0102CULL,
		0x4140421041802041ULL,
		0x983A80A01240E000ULL
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
		0xBC2059DEB6FE533CULL,
		0xD36D244F769CB57CULL,
		0x8CD2E83F369887D6ULL,
		0x8DA696FC16008F2DULL,
		0x9AB0E9D821232CA4ULL,
		0x9B288564D5C054DBULL,
		0xC00030D46C5A512CULL,
		0x9D8F4543CE35523DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B6D9F6FA33571EULL,
		0x36A5C0A171A751CBULL,
		0x1097E22408B292C1ULL,
		0xF704B9DB89E6C40DULL,
		0x895A6AA52165CAEDULL,
		0x48B7AFDD5E8CF6B4ULL,
		0xDA7642B51CC33047ULL,
		0xE9152B690913FC05ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x882059D6B232531CULL,
		0x1225000170841148ULL,
		0x0092E024009082C0ULL,
		0x850490D80000840DULL,
		0x88106880212108A4ULL,
		0x0820854454805490ULL,
		0xC00000940C421004ULL,
		0x8905014108115005ULL
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
		0x55F2D95B48F09888ULL,
		0x7969F8C9C2B90294ULL,
		0xAAA496E1C130D934ULL,
		0xBF35897EC5062129ULL,
		0x32D29B6303DB8799ULL,
		0xB00DA33AE1DA43D4ULL,
		0x63D47F9E92FCDA0CULL,
		0x85BAF9EFCABD3B89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B745126B67E00A8ULL,
		0x8EAB3AA80A4B92CFULL,
		0x71832B7B1913CC39ULL,
		0xBACB4EF6B2D2695BULL,
		0x916E98C558E7508BULL,
		0x2A5358BD38C2A006ULL,
		0x2BBCB0D019139088ULL,
		0x5823E13909F2B9D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4170510200700088ULL,
		0x0829388802090284ULL,
		0x208002610110C830ULL,
		0xBA01087680022109ULL,
		0x1042984100C30089ULL,
		0x2001003820C20004ULL,
		0x2394309010109008ULL,
		0x0022E12908B03981ULL
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
		0x6E1831202B48BD98ULL,
		0x50656982E2E8B9A5ULL,
		0xAFE7E0F92CC8F511ULL,
		0x5710E716B27DABA7ULL,
		0x7960BA74C4360560ULL,
		0xF554AA54689117FFULL,
		0xEAD7ACCD7BBC1FA8ULL,
		0xE443C2E290A202F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB5982B212E28FCULL,
		0xAF3E5DA09CCA4140ULL,
		0xCB18A6E3E7F40086ULL,
		0xCE34EBA617809AD4ULL,
		0xB2CEDE232E8592B5ULL,
		0xDE270D845229CFBBULL,
		0xF776758683C0D5E0ULL,
		0x1D9A0A6072D5A4CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4E10102021082898ULL,
		0x0024498080C80100ULL,
		0x8B00A0E124C00000ULL,
		0x4610E30612008A84ULL,
		0x30409A2004040020ULL,
		0xD4040804400107BBULL,
		0xE2562484038015A0ULL,
		0x04020260108000C5ULL
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
		0x84C8890DEC9081C3ULL,
		0x1A802E545FF38A28ULL,
		0x620C8EFFF4637E1EULL,
		0x2073CDFF5D39F392ULL,
		0x833D52521FE148FAULL,
		0x4EE9AC5D99260354ULL,
		0x1204C09EE661954BULL,
		0x94BED3A84AFC92A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE64E058B370EA4B0ULL,
		0x1FCFD122A25C2488ULL,
		0x14CE3E10D68F1833ULL,
		0xB2B06CC11030A6B9ULL,
		0xFBC117B2E6CCD3A2ULL,
		0xFBC48D7C10C4BF3EULL,
		0xDB49F6EAF9270E3CULL,
		0x719445BA27E4C5A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8448010924008080ULL,
		0x1A80000002500008ULL,
		0x000C0E10D4031812ULL,
		0x20304CC11030A290ULL,
		0x8301121206C040A2ULL,
		0x4AC08C5C10040314ULL,
		0x1200C08AE0210408ULL,
		0x109441A802E480A0ULL
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
		0xAD79A18C8D83C8D7ULL,
		0x6FD84D9E1DAA7A04ULL,
		0x1C04006C0FD985DAULL,
		0x80D9CD2D119E5A1AULL,
		0xE675F59559851D61ULL,
		0xD9BCA8B38DB42A04ULL,
		0x385DE4FBD66963F5ULL,
		0x53291F3612D47E41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AC472B37A3B0DE3ULL,
		0xBCE26B48A9A2EC27ULL,
		0x07AA75CAC02FD0C6ULL,
		0x06BCB4BBE837F62BULL,
		0x4973BAB176D1834BULL,
		0x806E6C594A499E3FULL,
		0xC4C82315A920C18FULL,
		0x54367A6E933C398CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28402080080308C3ULL,
		0x2CC0490809A26804ULL,
		0x04000048000980C2ULL,
		0x009884290016520AULL,
		0x4071B09150810141ULL,
		0x802C281108000A04ULL,
		0x0048201180204185ULL,
		0x50201A2612143800ULL
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
		0x6E1D253C50349411ULL,
		0x44741B40CC5BAE1DULL,
		0xBF983C39833FBAC1ULL,
		0xC266067E6F1AFCD5ULL,
		0x8E2273C6C414012BULL,
		0x0AD44969BC99038AULL,
		0xB79BF998DAFCE3A7ULL,
		0xD9F6E911312BBD8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171538F84F46C07CULL,
		0x08D2369374FF9AA0ULL,
		0xDB14EF4BC6A8774DULL,
		0x9D2218D83F87C2EBULL,
		0x3FC10FEACF56F01AULL,
		0x3A348139876AAD6AULL,
		0x3EF78E7FFAE7A024ULL,
		0xCC0B9F424110F9C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0615203840048010ULL,
		0x00501200445B8A00ULL,
		0x9B102C0982283241ULL,
		0x802200582F02C0C1ULL,
		0x0E0003C2C414000AULL,
		0x0A1401298408010AULL,
		0x36938818DAE4A024ULL,
		0xC80289000100B981ULL
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
		0xF38C3705BD5CB93AULL,
		0x1F837C8EAEC92CDCULL,
		0xC3479A4D58EDFF32ULL,
		0x2F006FC839F3B32DULL,
		0x93EBA9753A262E97ULL,
		0x01CBCCA41E651196ULL,
		0x081EF5C5D8284FEAULL,
		0x151830F91040CC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B60248D67FBAC0CULL,
		0xFF103B5A0983C6BCULL,
		0x57E544127719E707ULL,
		0xF3EE9346A0DFF292ULL,
		0xD80107CA673FC3ABULL,
		0xCCA0D89B5D039CD5ULL,
		0x54D6B0D58248A3D1ULL,
		0x856BC5F7D75E3041ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x430024052558A808ULL,
		0x1F00380A0881049CULL,
		0x434500005009E702ULL,
		0x2300034020D3B200ULL,
		0x9001014022260283ULL,
		0x0080C8801C011094ULL,
		0x0016B0C5800803C0ULL,
		0x050800F110400000ULL
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
		0xA69D360A30471EB7ULL,
		0xB83372ED63ACB196ULL,
		0x62B7F451C7D8AEFCULL,
		0x14882AD17281712EULL,
		0x18482B5AE24FF420ULL,
		0x49D6EA92B12C3ADCULL,
		0x92367CA4D0F45BDCULL,
		0xAFF0AC835F8FEF86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDCBE36BAF47942BULL,
		0xD867B3103DBE60D7ULL,
		0x13D7F92733091D48ULL,
		0x9D339D4E1BBAC49CULL,
		0xFAE31A69DE9E2788ULL,
		0x5FBB7483F2286EFAULL,
		0x70DB3DCC0AAF2911ULL,
		0x0DAC125D56593764ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8489220A20471423ULL,
		0x9823320021AC2096ULL,
		0x0297F00103080C48ULL,
		0x140008401280400CULL,
		0x18400A48C20E2400ULL,
		0x49926082B0282AD8ULL,
		0x10123C8400A40910ULL,
		0x0DA0000156092704ULL
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
		0xA221F30781C27D0BULL,
		0x2916B04618A5AE58ULL,
		0x66A1C2E2FBEB0C82ULL,
		0xBCE7F839467D8312ULL,
		0x543EFC8E622877BAULL,
		0xF730057723B9FE4BULL,
		0x6C20454AD4B6BBBDULL,
		0x8AA24D248398305CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3511DFED8797B2ULL,
		0xC15EDE9D4D4C605EULL,
		0x2149BC3EF73F5FDFULL,
		0xC7D3A7B08B4EB271ULL,
		0x214FF7C569BDDFA6ULL,
		0xC27401CDC9C786C9ULL,
		0x855D7AB2AF52FD04ULL,
		0xFB07804D47246756ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA021110781821502ULL,
		0x0116900408042058ULL,
		0x20018022F32B0C82ULL,
		0x84C3A030024C8210ULL,
		0x000EF484602857A2ULL,
		0xC230014501818649ULL,
		0x040040028412B904ULL,
		0x8A02000403002054ULL
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
		0x57ACEC94D77AB245ULL,
		0xB6FB0F63A6D51DFAULL,
		0xB9786C54CC227881ULL,
		0x56A6A115E0635BDBULL,
		0xE676A24856CF81D5ULL,
		0x80BC939FC91A9FF2ULL,
		0xD28B108E328FBB83ULL,
		0x328A9344AAD84C57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEA05F0953ACAB17ULL,
		0xF8C47DF7FABDECF3ULL,
		0x829C8BD2EEBD5923ULL,
		0x091D7BCAF1F5C4A3ULL,
		0x9E7F2DA6D993327DULL,
		0x03598C1CB667893FULL,
		0x694EB1FA12DD7507ULL,
		0xB45D86CFA4741F06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46A04C005328A205ULL,
		0xB0C00D63A2950CF2ULL,
		0x80180850CC205801ULL,
		0x00042100E0614083ULL,
		0x8676200050830055ULL,
		0x0018801C80028932ULL,
		0x400A108A128D3103ULL,
		0x30088244A0500C06ULL
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
		0x38D96EB741D8E85AULL,
		0x5E3D29E9A04DA88AULL,
		0x7F5A15F1ECEAF81AULL,
		0xDD7E5FA46458A855ULL,
		0xA895A1C4CFA6E5EFULL,
		0x659AE4DFC38A2A37ULL,
		0xE121F32C6EF0701CULL,
		0x1C4C6306DD987F2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x497C0599F9DC5F7FULL,
		0xAD5099BAA9F91508ULL,
		0x70D71C089A8C5400ULL,
		0x5C311EE139BEBAEAULL,
		0xCC51D33209204407ULL,
		0xBF8872699D55E869ULL,
		0x75B04932916831C1ULL,
		0x189D92B0FB395901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0858049141D8485AULL,
		0x0C1009A8A0490008ULL,
		0x7052140088885000ULL,
		0x5C301EA02018A840ULL,
		0x8811810009204407ULL,
		0x2588604981002821ULL,
		0x6120412000603000ULL,
		0x180C0200D9185900ULL
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
		0xA9B89BBDA601F7C5ULL,
		0xF15C3FBD39995BE2ULL,
		0x29A7EC1520EBB14FULL,
		0x1406CEB1064BAE11ULL,
		0x7AE039E5FE38F48DULL,
		0x713C03B91C8E538EULL,
		0x137A2279E356DBADULL,
		0x1BA46B120EABFDC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76B9E60F7B92B3FULL,
		0x24551A05F14911C2ULL,
		0xFAE32E5DF6F38A9FULL,
		0xA3708BAAF7EF6110ULL,
		0xAC48E0C99209D0C8ULL,
		0x09470ED310CF0635ULL,
		0x0F9BFABD44059B3AULL,
		0x16C5E9AA50C8CFFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81289A20A6012305ULL,
		0x20541A05310911C2ULL,
		0x28A32C1520E3800FULL,
		0x00008AA0064B2010ULL,
		0x284020C19208D088ULL,
		0x01040291108E0204ULL,
		0x031A223940049B28ULL,
		0x128469020088CDC0ULL
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
		0xDF1EA2E36E5939A7ULL,
		0x2366004C52F4D96AULL,
		0x1F98C314E9102B55ULL,
		0x9D05BA284C1CBAD8ULL,
		0xE1982DD2067877E5ULL,
		0xC7F4D98126473AB1ULL,
		0x735909F3F2A98AB9ULL,
		0x7C963A03EFD1D5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9688ABA1E06352EULL,
		0xBB525934CE80D22AULL,
		0xD7EA93EEA488DD51ULL,
		0x6887FCA7439F2F19ULL,
		0x6E5F6ADE1B77E73FULL,
		0xA7F2E6640D99A349ULL,
		0x2CEA9A869C28984FULL,
		0xB97ABEF4E505453EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD90882A20E003126ULL,
		0x234200044280D02AULL,
		0x17888304A0000951ULL,
		0x0805B820401C2A18ULL,
		0x601828D202706725ULL,
		0x87F0C00004012201ULL,
		0x2048088290288809ULL,
		0x38123A00E5014522ULL
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
		0x8582A394C64D334DULL,
		0xAFCCC35502061FA6ULL,
		0x67513FF02DE12431ULL,
		0x88A1499B241A4AD5ULL,
		0x17F569FF6638AAE1ULL,
		0xCD29E6E4A69DE519ULL,
		0xBC3976802CCFC67AULL,
		0xE8474489A5902304ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D724170A2916F1DULL,
		0xE802C9029B828529ULL,
		0xA51F30D8525370CCULL,
		0x208A5130FE7BDEBAULL,
		0x4F8BC8DE6FCB512DULL,
		0x77C39069BE880B68ULL,
		0x91DF5EA04B062ABBULL,
		0xF2876D8FF1F4902CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050201108201230DULL,
		0xA800C10002020520ULL,
		0x251130D000412000ULL,
		0x00804110241A4A90ULL,
		0x078148DE66080021ULL,
		0x45018060A6880108ULL,
		0x901956800806023AULL,
		0xE0074489A1900004ULL
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
		0x8A9C062AD6986D0DULL,
		0x4B6921BA89151CCBULL,
		0x44BBE7419EFAF384ULL,
		0x21C7E730534E665AULL,
		0x81BC94AB6B777DB1ULL,
		0x2118CD3A96246403ULL,
		0x97B81BE1D6B2D9A2ULL,
		0x1848351C0C158BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34B19FE023B8726FULL,
		0x0C4B9E41A6DD5F78ULL,
		0xC5CFEA3DDF437798ULL,
		0xFB4E836A88CC25A1ULL,
		0xF59FA8CC1E4E1E41ULL,
		0xC68C6F4F042F2B12ULL,
		0xA0CB3E5DCEBE0046ULL,
		0x718FBF54BF265EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x009006200298600DULL,
		0x0849000080151C48ULL,
		0x448BE2019E427380ULL,
		0x21468320004C2400ULL,
		0x819C80880A461C01ULL,
		0x00084D0A04242002ULL,
		0x80881A41C6B20002ULL,
		0x100835140C040AB0ULL
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
		0x755582196522D002ULL,
		0x54E57EE5C5BA5A76ULL,
		0x5C2D300EE29F1424ULL,
		0xFB2D2CAAEEE5D68EULL,
		0xDB50A07D091A9C3AULL,
		0xE895D18C49728F7EULL,
		0x06360B84CFD32674ULL,
		0xB3BFAF0D2B14904DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x755F9193573B64E9ULL,
		0x1D96FD4BE88A28A8ULL,
		0xF574001580452FA0ULL,
		0x3D74FEB0DC10F4CDULL,
		0x1A4A17561A9289F8ULL,
		0x748215FE9631500CULL,
		0xBF9F2885C308BC26ULL,
		0x901846947D440568ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7555801145224000ULL,
		0x14847C41C08A0820ULL,
		0x5424000480050420ULL,
		0x39242CA0CC00D48CULL,
		0x1A40005408128838ULL,
		0x6080118C0030000CULL,
		0x06160884C3002424ULL,
		0x9018060429040048ULL
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
		0x102859B858DC71A8ULL,
		0xC096F959389FC773ULL,
		0xA88D2C28882082DBULL,
		0x6253FC54B5166B7FULL,
		0x0AA260174034F644ULL,
		0xD495EF00CF9A2B54ULL,
		0xA2FBA1D3AB19D205ULL,
		0xF05E2BF241B17BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78932A4591CA5C5BULL,
		0x3C45A388C98B8956ULL,
		0xBF4BAA0A13E95DBCULL,
		0x09EAFE6851F4C15CULL,
		0xED806A223354E03DULL,
		0x93A01DF21DA9B8A0ULL,
		0xECDA4D63B23317FEULL,
		0x7C9E895A909410A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000080010C85008ULL,
		0x0004A108088B8152ULL,
		0xA809280800200098ULL,
		0x0042FC401114415CULL,
		0x088060020014E004ULL,
		0x90800D000D882800ULL,
		0xA0DA0143A2111204ULL,
		0x701E0952009010A0ULL
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
		0xBFF919C1A396E473ULL,
		0xC5EBF7388D7BD6A6ULL,
		0x346990AEF342B63EULL,
		0x60831D706D733740ULL,
		0xB66C9D6B95B73FBCULL,
		0x4DBE4F3CED317833ULL,
		0x900B503954056F52ULL,
		0x588C495A4F66DA75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66E92AEF0AE5FCCULL,
		0xA42DA4A73426A353ULL,
		0x9AB4641436643B09ULL,
		0x4BED51F773E49C67ULL,
		0x140F864B9F468D79ULL,
		0x19C0B29949442998ULL,
		0xA78FB7B42B86BC3BULL,
		0x637224E5F8C4EB9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6681080A0864440ULL,
		0x8429A42004228202ULL,
		0x1020000432403208ULL,
		0x4081117061601440ULL,
		0x140C844B95060D38ULL,
		0x0980021849002810ULL,
		0x800B103000042C12ULL,
		0x400000404844CA10ULL
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
		0x85CD615CD6645E90ULL,
		0x4602D24F63B05D9CULL,
		0x9D8B0911516AF195ULL,
		0x07E2D51F01EC8B8BULL,
		0x6AAE6518A1DA99B9ULL,
		0x3A522F99112ECEB0ULL,
		0xF70D31889CB1AA4CULL,
		0x2C9043B29358E1BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA58CB692F49F1FF5ULL,
		0x36212EDF8A40B347ULL,
		0x984213B058C67666ULL,
		0xC70C0BEC1248D027ULL,
		0x8C5FCEBE47EC47E5ULL,
		0x52D566A286E6B438ULL,
		0xEF65D92C6E73984EULL,
		0xBF7DEABEF0AEBB77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x858C2010D4041E90ULL,
		0x0600024F02001104ULL,
		0x9802011050427004ULL,
		0x0700010C00488003ULL,
		0x080E441801C801A1ULL,
		0x1250268000268430ULL,
		0xE70511080C31884CULL,
		0x2C1042B29008A136ULL
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
		0xEBB960F3442361E9ULL,
		0xE68E11E685A36F1FULL,
		0xFFB57BC302C9D185ULL,
		0xF01E072E4F7CE459ULL,
		0xE501B49D2D736E03ULL,
		0xBBF66553E3E25937ULL,
		0xC0C8154BD2B3542CULL,
		0x312C85D94FC05508ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF4E4420D3B3FA6BULL,
		0x70F3A2E216158DE9ULL,
		0x691C6292C1745CB1ULL,
		0x9D37AD01040C6969ULL,
		0xEC98A9849D1A6EA1ULL,
		0xAB8CE29CA6DD222FULL,
		0x3938A7F02AFD9BD5ULL,
		0x8ADF4DBB70A56AA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB08402040236069ULL,
		0x608200E204010D09ULL,
		0x6914628200405081ULL,
		0x90160500040C6049ULL,
		0xE400A0840D126E01ULL,
		0xAB846010A2C00027ULL,
		0x0008054002B11004ULL,
		0x000C059940804000ULL
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
		0xFB348CE315F860A6ULL,
		0x9B9D750F6D8DF804ULL,
		0x3DDFAB232EFE8F42ULL,
		0xE856D906D2229AA3ULL,
		0x8CA6A0F8F802209DULL,
		0x9E8472B59E6CEED0ULL,
		0xF1BE3FB148C1996FULL,
		0x73376C971DA21350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09809D9DEBBCF9FBULL,
		0x0CA8B966B23870D6ULL,
		0x7581AE9DD195E124ULL,
		0x2A47D4BEEEDC172CULL,
		0xCBE353C42A24D874ULL,
		0x3EE336FEDBB2C422ULL,
		0x050A3DD258298643ULL,
		0xD071A2744A1B2656ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09008C8101B860A2ULL,
		0x0888310620087004ULL,
		0x3581AA0100948100ULL,
		0x2846D006C2001220ULL,
		0x88A200C028000014ULL,
		0x1E8032B49A20C400ULL,
		0x010A3D9048018043ULL,
		0x5031201408020250ULL
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
		0x2B6C5BE4B28EFE00ULL,
		0xC6B6B1782A8742C7ULL,
		0x551285B4611E16CEULL,
		0xE365633A2E0A4C89ULL,
		0xD6C81DA07D4C47BAULL,
		0x02F848FD316E624EULL,
		0x7E174B1AD91DF25CULL,
		0x48E1205ACD32B4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C14AEB6BDCF2DAFULL,
		0x0421F911CD0CFA40ULL,
		0x775031CE03F037B0ULL,
		0x835E96A01D1002B7ULL,
		0xBC7D2FE95CC94223ULL,
		0xB25E916F32D49ACCULL,
		0x9FD30BC3E0C7AFEFULL,
		0xC5CC1F01FDF435A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08040AA4B08E2C00ULL,
		0x0420B11008044240ULL,
		0x5510018401101680ULL,
		0x834402200C000081ULL,
		0x94480DA05C484222ULL,
		0x0258006D3044024CULL,
		0x1E130B02C005A24CULL,
		0x40C00000CD3034A1ULL
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
		0x090889CF3FC2BFDCULL,
		0x5B196AB8CE4E471AULL,
		0xD7CA89392C77224AULL,
		0x2F657B99A69D06AEULL,
		0x76DF71585ACE6CFEULL,
		0x9A59532B1BADA8CCULL,
		0xE776644211B25761ULL,
		0xD247B0EBFB0C4720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93EDD0D020B2AEB3ULL,
		0xB34C68BEAFC8816AULL,
		0x7D841FCC8C74F9E7ULL,
		0xEAEFD20BC9E0A72EULL,
		0xC081516EFED7BEF3ULL,
		0x2EE4464CF943498EULL,
		0xE37A28107BB29DAEULL,
		0xFE719B01B30C5E9EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010880C02082AE90ULL,
		0x130868B88E48010AULL,
		0x558009080C742042ULL,
		0x2A6552098080062EULL,
		0x408151485AC62CF2ULL,
		0x0A4042081901088CULL,
		0xE372200011B21520ULL,
		0xD2419001B30C4600ULL
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
		0x03AAEC55173618A3ULL,
		0x8F2DB69CBAFC664CULL,
		0xAC8ABE6C1E0AFA28ULL,
		0xCDFF17AD38580B55ULL,
		0xBC908010602FDA21ULL,
		0xC1A5A6138B2F0BC4ULL,
		0xEDD0A5E15EA54C43ULL,
		0x3E909A35BBBF58ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0320D9690386AD2CULL,
		0xBD904812723DED17ULL,
		0x5CC3BE7AA617B25BULL,
		0xA5B660E22AD0E129ULL,
		0x783CB7DA894B418EULL,
		0xD7214BD73E2389F4ULL,
		0xB87344E5DE3A7FF3ULL,
		0x9E283947C403F0E4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0320C84103060820ULL,
		0x8D000010323C6404ULL,
		0x0C82BE680602B208ULL,
		0x85B600A028500101ULL,
		0x38108010000B4000ULL,
		0xC12102130A2309C4ULL,
		0xA85004E15E204C43ULL,
		0x1E001805800350A4ULL
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
		0xE73B8AE173E2562CULL,
		0xC1181DF6D4E44835ULL,
		0x9104EB6322B40C82ULL,
		0x466D49CA6990C3ACULL,
		0x8C54C01F12535416ULL,
		0xDEEBDC016A662968ULL,
		0x88F51F23065191B7ULL,
		0xFA3201D1516F0779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3268A6940F422D2ULL,
		0xCE4549B85B3EAC91ULL,
		0x41D87C2CD2C7C7ABULL,
		0x9827010E3A6854CCULL,
		0x719323AC027C7B81ULL,
		0x6A934BC9CF3FF564ULL,
		0x6510ABAE1237707AULL,
		0x022B438F9C80A57FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3228A6140E00200ULL,
		0xC00009B050240811ULL,
		0x0100682002840482ULL,
		0x0025010A2800408CULL,
		0x0010000C02505000ULL,
		0x4A8348014A262160ULL,
		0x00100B2202111032ULL,
		0x0222018110000579ULL
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
		0x98E1A0D547127C4DULL,
		0x7D494EE81565FFBAULL,
		0x33163AF9CB047FA9ULL,
		0x348F0D823525B54EULL,
		0x7F502B35EBB0455BULL,
		0xD9264D88EAE7C484ULL,
		0x666A332B580DD9D1ULL,
		0xD826C91FA5621B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87EAEBECF2B84C96ULL,
		0x0D54600A2D1572ADULL,
		0x1D98E910F52F87BDULL,
		0x8B10571C78B90F7DULL,
		0x8F2B5DB8F77C8F78ULL,
		0x48DA00D8A4B115A1ULL,
		0xE75E385513073740ULL,
		0xBD5A0AFD213C2D47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80E0A0C442104C04ULL,
		0x0D404008050572A8ULL,
		0x11102810C10407A9ULL,
		0x000005003021054CULL,
		0x0F000930E3300558ULL,
		0x48020088A0A10480ULL,
		0x664A300110051140ULL,
		0x9802081D21200904ULL
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
		0x8575A4261AC8CA2DULL,
		0x00224880E91F0DA0ULL,
		0xC7579BB086A45EC8ULL,
		0x5172E410B0F61EE6ULL,
		0xE8E5987C1A527F96ULL,
		0x962771B7418FC71AULL,
		0xADB02DE8ECFA9C13ULL,
		0xCB69F2899E454260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5929794CDA32002AULL,
		0x803DE18D9A18CC6DULL,
		0x83367FE6CB9A826BULL,
		0x66859FD437462D7FULL,
		0x0FFF651E933A1ABFULL,
		0x47523783A90FC5BCULL,
		0x5FB1D906F001AAF6ULL,
		0x201FEF590101F640ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x012120041A000028ULL,
		0x0020408088180C20ULL,
		0x83161BA082800248ULL,
		0x4000841030460C66ULL,
		0x08E5001C12121A96ULL,
		0x06023183010FC518ULL,
		0x0DB00900E0008812ULL,
		0x0009E20900014240ULL
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
		0x45DC3C23987143EEULL,
		0x47934930965CE85FULL,
		0x3EA49177F88ED32DULL,
		0x39F77E1EE079633EULL,
		0x332A97D97C95E810ULL,
		0xC2ABD76AC89DCC8BULL,
		0x733C787D173F6A63ULL,
		0x9C792B753D171F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51C6E83138627488ULL,
		0x3D529C35AD4626CAULL,
		0x2B984BF17A3DE91EULL,
		0x250072D0CBF4F678ULL,
		0x7511C3CD4B9340D0ULL,
		0x16E1B40D712607B2ULL,
		0xF5953E3FD836BDD9ULL,
		0xC2B3B70513196B46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41C4282118604088ULL,
		0x051208308444204AULL,
		0x2A800171780CC10CULL,
		0x21007210C0706238ULL,
		0x310083C948914010ULL,
		0x02A1940840040482ULL,
		0x7114383D10362841ULL,
		0x8031230511110B42ULL
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
		0x84B44D3BED66A420ULL,
		0xD485528A598B12A6ULL,
		0x68F0328BD27673DDULL,
		0xBFD093D905618EE6ULL,
		0x007DB14845E5CE8BULL,
		0xB6692A1B89CCE071ULL,
		0xDA81663A2E5DD737ULL,
		0xADF33D2320E8BE3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08092E0860AE4DCBULL,
		0x85FB936F2CA6682CULL,
		0xB75AD0BDAD6F7224ULL,
		0x8DE912CCCF7869D0ULL,
		0x86021FA9A8E41E89ULL,
		0xAE2EED0A408B46C4ULL,
		0xCD175B459CB9BCCEULL,
		0x3C0EBA2390C0AFBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00000C0860260400ULL,
		0x8481120A08820024ULL,
		0x2050108980667204ULL,
		0x8DC012C8056008C0ULL,
		0x0000110800E40E89ULL,
		0xA628280A00884040ULL,
		0xC80142000C199406ULL,
		0x2C02382300C0AE3BULL
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
		0xDE97C157E6BB2F89ULL,
		0xF82ACB2944C76F20ULL,
		0x9D644F762A71A9EBULL,
		0xF9B5643F4C3347BDULL,
		0xF277E84771F4DCA3ULL,
		0xAA8484349A0C756FULL,
		0xD5C3A49AAFF25A87ULL,
		0xFB6D18C01BF607E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11B16CCA5BBD2E39ULL,
		0x0CE0597EC18DE7E3ULL,
		0xAD9CA99E830C2D72ULL,
		0xF8568E6C0E056F51ULL,
		0xCD156B70A95B6202ULL,
		0x8C1A2AD94E231CEDULL,
		0x77428BE2B1B524D8ULL,
		0xD7DB13792DC751CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1091404242B92E09ULL,
		0x0820492840856720ULL,
		0x8D04091602002962ULL,
		0xF814042C0C014711ULL,
		0xC015684021504002ULL,
		0x880000100A00146DULL,
		0x55428082A1B00080ULL,
		0xD349104009C601C4ULL
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
		0x92BF94C9EABD5002ULL,
		0x950809BD2988CE08ULL,
		0x7FAA0C1B6B5C5B36ULL,
		0xF9440455E589A4CAULL,
		0x13C5AB2CFA4C8707ULL,
		0x3568543448D68DABULL,
		0x51C2DF589F1DB75CULL,
		0x9686A029DAA66F58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DCD67BBCB40A06CULL,
		0xD8DBEF486A4EF677ULL,
		0xDAD2502D834E174CULL,
		0x2A699405571D7B69ULL,
		0xA226E002D2AEFB0FULL,
		0x26C39299A55712A1ULL,
		0xEB947B6C83FF46F0ULL,
		0xFBCAE9A7411AD12DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x108D0489CA000000ULL,
		0x900809082808C600ULL,
		0x5A820009034C1304ULL,
		0x2840040545092048ULL,
		0x0204A000D20C8307ULL,
		0x24401010005600A1ULL,
		0x41805B48831D0650ULL,
		0x9282A02140024108ULL
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
		0xAB0ECCA68F87270CULL,
		0xB463D49D479917EAULL,
		0x30E1C781E87CCD4BULL,
		0x7AC8F0381A5AF254ULL,
		0xCCA1BF2ABF76D1D2ULL,
		0x312FB514F8A315F1ULL,
		0x40DEEAE8FD7F5438ULL,
		0xAB6907A16478F521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC64A119B80DB1EBAULL,
		0xEEF7B0D32926341EULL,
		0x72E8728218313F1CULL,
		0x94B7D1CA6DF5D7A0ULL,
		0xEA54641AFBB6E024ULL,
		0xCFC3626EFEE27181ULL,
		0x8D2FE262FE2EE391ULL,
		0x85D54515BF1925B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x820A008280830608ULL,
		0xA46390910100140AULL,
		0x30E0428008300D08ULL,
		0x1080D0080850D200ULL,
		0xC800240ABB36C000ULL,
		0x01032004F8A21181ULL,
		0x000EE260FC2E4010ULL,
		0x8141050124182520ULL
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
		0xE8177D5674211CDBULL,
		0x3BA5F0D0EF223B3DULL,
		0x015518C9152E00E5ULL,
		0xB57FE8463A5C58A7ULL,
		0x040F959A20B9F6F6ULL,
		0xC09761702F6FDDFFULL,
		0x8F2A5E0808B81311ULL,
		0x775666E846430A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0B2641B82A1A32AULL,
		0xAAC568246D1C6CCBULL,
		0x97EC293AD0D4B178ULL,
		0x5BD5593D9EE568B6ULL,
		0xA8B8F0A25E384F79ULL,
		0x742EEC01705A3FD0ULL,
		0x07ECF50F755CAE62ULL,
		0x6373C4C19FC87B19ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC01264120021000AULL,
		0x2A8560006D002809ULL,
		0x0144080810040060ULL,
		0x115548041A4448A6ULL,
		0x0008908200384670ULL,
		0x40066000204A1DD0ULL,
		0x0728540800180200ULL,
		0x635244C006400A00ULL
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
		0x1D7523F13B7C214BULL,
		0x4AE2AD4237AB1140ULL,
		0x80047B3D1E829E9DULL,
		0x29B6C5A3592EE383ULL,
		0x025DC5E0AAB2F51EULL,
		0x82808C56C81540C5ULL,
		0x15DC652FB2F52653ULL,
		0xBB5B78275BB5A3C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5BCEA5976DF0835ULL,
		0xEA24BFFBA642FD3AULL,
		0x519812C0520A6C3AULL,
		0x622797FB4AEB8191ULL,
		0x22A3BD0A2C66EA19ULL,
		0x5A078A3E0D34BA86ULL,
		0x72120A05C8706A3AULL,
		0x96705B230CA8A833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05342251325C0001ULL,
		0x4A20AD4226021100ULL,
		0x0000120012020C18ULL,
		0x202685A3482A8181ULL,
		0x020185002822E018ULL,
		0x0200881608140084ULL,
		0x1010000580702212ULL,
		0x9250582308A0A000ULL
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
		0x788997CC6467FADCULL,
		0x00D700AAA35BA0A8ULL,
		0x334EA6520EC892C1ULL,
		0x63C858DCD3B27EA4ULL,
		0x2FF8E19236A31163ULL,
		0x2D62BDD9D5925371ULL,
		0xDB1C58DCBC9E06C3ULL,
		0x27C387306F0E9511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C3A2BA32B5F6B9ULL,
		0x6D50220CBFBB3622ULL,
		0xC8CC71BAAA5EF15CULL,
		0x0C8073C6754BEA0AULL,
		0x9EA7E53DF9AFE921ULL,
		0xCAC28A4484CF327EULL,
		0xF7BE4B507798E62BULL,
		0xB7FDA2318871FF91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x588182882025F298ULL,
		0x00500008A31B2020ULL,
		0x004C20120A489040ULL,
		0x008050C451026A00ULL,
		0x0EA0E11030A30121ULL,
		0x0842884084821270ULL,
		0xD31C485034980603ULL,
		0x27C1823008009511ULL
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
		0x4C338000FB3E1FBEULL,
		0x0D6A57BB6B1C3CB0ULL,
		0x5E9322C4490C30F1ULL,
		0x0F07836680B1B378ULL,
		0x9AC6A686896C730EULL,
		0xFD7A9FDE9F66AA1BULL,
		0x1AE730AEB27246FAULL,
		0xC4D94ED0489ED526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE8FFD4577F30F3FULL,
		0x36F21CF50E98F90EULL,
		0x66F15524608842A4ULL,
		0xE7C2F6A2645A6967ULL,
		0xBD4355877FF6DE09ULL,
		0x86AD2CF33788F806ULL,
		0x7CBB7CAED15362C2ULL,
		0xE04962EFC73770B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C03800073320F3EULL,
		0x046214B10A183800ULL,
		0x46910004400800A0ULL,
		0x0702822200102160ULL,
		0x9842048609645208ULL,
		0x84280CD21700A802ULL,
		0x18A330AE905242C2ULL,
		0xC04942C040165026ULL
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
		0x273DC7970F591CEFULL,
		0xC61CDA83ED2A5C66ULL,
		0xCD154F846CAE5B35ULL,
		0xDE4E0FD9B329A360ULL,
		0xB6B5D679D5FC2571ULL,
		0xF1B4E8C3E2B4EFBBULL,
		0x0D664AB54697CB15ULL,
		0xF8F60C8DA6E92418ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CCF8CD7136A23EFULL,
		0x525885FE69F71A8EULL,
		0x2DBB4FE0D40D2B36ULL,
		0xABEE6B2B56259967ULL,
		0x7B4F7B3573B6FA6CULL,
		0xD317F57880478A81ULL,
		0x6084CFDB62430331ULL,
		0xE8135A825D5A4D75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x240D8497034800EFULL,
		0x4218808269221806ULL,
		0x0D114F80440C0B34ULL,
		0x8A4E0B0912218160ULL,
		0x3205523151B42060ULL,
		0xD114E04080048A81ULL,
		0x00044A9142030311ULL,
		0xE812088004480410ULL
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
		0xCAADFEF08C5D5AB6ULL,
		0xB8B37BC9B4D6A46CULL,
		0x122FA52E5FD98A8CULL,
		0x95F2CC802C78122EULL,
		0xA609F98E9B05A494ULL,
		0xC1C433418A338FF5ULL,
		0x3A7B665C0EFD5689ULL,
		0xE3B228FA20D0B64FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD362139197656726ULL,
		0xEEBB5F7C5C56A2BAULL,
		0xFE313FD934D6CE04ULL,
		0x08F5E9CC3D6470DDULL,
		0x2AC3C8EABDECEFB2ULL,
		0xCD43B70DCAD1DDEDULL,
		0x3B54DADCD6FA4BD0ULL,
		0xD2D3221BB7E4B71BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC220129084454226ULL,
		0xA8B35B481456A028ULL,
		0x1221250814D08A04ULL,
		0x00F0C8802C60100CULL,
		0x2201C88A9904A490ULL,
		0xC14033018A118DE5ULL,
		0x3A50425C06F84280ULL,
		0xC292201A20C0B60BULL
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
		0xD6E03CB1BFCBA88AULL,
		0xE421380E7818F871ULL,
		0x2037BC528B97B650ULL,
		0xB3402042DCB6FA7FULL,
		0x00362B060B5477F8ULL,
		0xA29B63C01EE775F8ULL,
		0x2C5936611099B157ULL,
		0x5FDEDCA047B93241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF66491D230D7A52ULL,
		0xA1D293A31EBD0FB6ULL,
		0xB3D908E22FC1806EULL,
		0xA94DD42C3962F0E2ULL,
		0x136A7C69C4F819E1ULL,
		0x24D092F4C4305CF5ULL,
		0x802E714E3D2C3F38ULL,
		0x2CBBE4FEE30B4915ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD660081123092802ULL,
		0xA000100218180830ULL,
		0x201108420B818040ULL,
		0xA14000001822F062ULL,
		0x00222800005011E0ULL,
		0x209002C0042054F0ULL,
		0x0008304010083110ULL,
		0x0C9AC4A043090001ULL
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
		0x05A703688676818DULL,
		0xB92FF5A783E47B3FULL,
		0x06E9F8B3E439823EULL,
		0xC8C79FE5820ADFD4ULL,
		0x329B6E13DFDE9BF3ULL,
		0x7530A6E8FFDEA311ULL,
		0x238290C9E2C49577ULL,
		0xF3686B09AA6B8D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7B58F0FAD113E1ULL,
		0x65CC10866A2F650BULL,
		0xCEFF3BE6F1677A0DULL,
		0xC6ED6BB175024A9CULL,
		0x8426AF2A2E3312E5ULL,
		0x7AB0237DA18A0820ULL,
		0x3D072A9B16057E2BULL,
		0x35BF9AD019615BFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0123006082500181ULL,
		0x210C10860224610BULL,
		0x06E938A2E021020CULL,
		0xC0C50BA100024A94ULL,
		0x00022E020E1212E1ULL,
		0x70302268A18A0000ULL,
		0x2102008902041423ULL,
		0x31280A0008610949ULL
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
		0x2255BB1BC7B402EEULL,
		0x120964BF5F935296ULL,
		0x0DA30D4F94B0853EULL,
		0x0585EC62A0BD844BULL,
		0x49A97A0CB2F75F56ULL,
		0x7101EEDF850C23AEULL,
		0xC13339AD5F6EE8E4ULL,
		0xEC6250678D0789CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ABAC77D60273D0EULL,
		0xEB65FD164385133AULL,
		0xFC107DA2CB3E48C8ULL,
		0x7796516927E479BAULL,
		0x604C4C3BA3B23EC3ULL,
		0x2A13F800168E4B79ULL,
		0xD42C96761D5D1D7AULL,
		0x9E22CBC090A0EC6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x221083194024000EULL,
		0x0201641643811212ULL,
		0x0C000D0280300008ULL,
		0x0584406020A4000AULL,
		0x40084808A2B21E42ULL,
		0x2001E800040C0328ULL,
		0xC02010241D4C0860ULL,
		0x8C2240408000884AULL
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
		0x184CA94B36C1D461ULL,
		0x6801662AC84694E2ULL,
		0x51B7C22A196F9D38ULL,
		0x82A87F1154857345ULL,
		0x94EC180FA2053FFBULL,
		0xEA1D982365E6AEE2ULL,
		0xDAC0B582C359B428ULL,
		0x80418DAB9DC29A48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A0E7B1CD30C8B17ULL,
		0xE8C6F407248FF115ULL,
		0x87EFCFF3B2ECD6D4ULL,
		0xFC2D3DEF036544E8ULL,
		0xF0EE35B0E658D5A8ULL,
		0x786854DF060E53B2ULL,
		0xE1A49A5C9CEB8EA1ULL,
		0xBC0C8241C59A8266ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080C290812008001ULL,
		0x6800640200069000ULL,
		0x01A7C222106C9410ULL,
		0x80283D0100054040ULL,
		0x90EC1000A20015A8ULL,
		0x68081003040602A2ULL,
		0xC080900080498420ULL,
		0x8000800185828240ULL
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
		0xA91C53CFF0209862ULL,
		0x58DDB3F2625A8C2EULL,
		0x8D16CF50E4D0A32EULL,
		0x35196B9ED8046FF1ULL,
		0x09F55F468B82F6A7ULL,
		0xDC557761A04AD30FULL,
		0x6A7A4E7B6682A070ULL,
		0x2ABDE2B7F3D09E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B96DD5DAB7AB21FULL,
		0xD234301B92A5316DULL,
		0xECECB3F2412BD98BULL,
		0x8067930A51F1A3DCULL,
		0xCA16B7B3EB01B98BULL,
		0xBDC63BF04D7C0BB0ULL,
		0x0100AB0C8AAC1276ULL,
		0x1B848298EDE938AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8914514DA0209002ULL,
		0x501430120200002CULL,
		0x8C0483504000810AULL,
		0x0001030A500023D0ULL,
		0x081417028B00B083ULL,
		0x9C44336000480300ULL,
		0x00000A0802800070ULL,
		0x0A848290E1C01822ULL
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
		0xAAB2225366AE8BF2ULL,
		0xE18D9F358ED41773ULL,
		0xC25D6735BDBE6512ULL,
		0x19A682990BA359A2ULL,
		0xA59578F1BB9B86C4ULL,
		0x246600692999A8E3ULL,
		0x50A38F853A3A5C66ULL,
		0x5E5E08049C1C38C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7805BC42F952717ULL,
		0x7EFEC614674451B9ULL,
		0x373D11D82CA87696ULL,
		0xCBCCA40705FFDD36ULL,
		0xBA2D3294FD7E9F9DULL,
		0xA0E62E69FA45C65CULL,
		0xE5AF87A3467AAF77ULL,
		0x38C7C06ECE9198F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA280024026840312ULL,
		0x608C861406441131ULL,
		0x021D01102CA86412ULL,
		0x0984800101A35922ULL,
		0xA0053090B91A8684ULL,
		0x2066006928018040ULL,
		0x40A38781023A0C66ULL,
		0x184600048C1018C6ULL
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
		0x0DBDC4AAB2185F65ULL,
		0x775D0C32F8A41EB2ULL,
		0xE6BD885D6E17F573ULL,
		0x31B0E919A7E65B16ULL,
		0xCB3FC06A585C5856ULL,
		0x95E30096E3ADD5A8ULL,
		0xF59931B93B466A61ULL,
		0x7B59E82D88CF3488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A304546879D465AULL,
		0x7362F5DAEC7AEF55ULL,
		0x88B76A41C464004EULL,
		0x50E6705A6554F597ULL,
		0xF92F46D83F2ED8E7ULL,
		0x79AC4DCB3C435C08ULL,
		0x367637BF1658DED4ULL,
		0x76B257DEE33053D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0830440282184640ULL,
		0x73400412E8200E10ULL,
		0x80B5084144040042ULL,
		0x10A0601825445116ULL,
		0xC92F4048180C5846ULL,
		0x11A0008220015408ULL,
		0x341031B912404A40ULL,
		0x7210400C80001080ULL
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
		0x804C7E05F9568AD7ULL,
		0x958B42E1723C4E4FULL,
		0x9087EB7635CCBB88ULL,
		0x41F701127A1A8425ULL,
		0x2A528D8908E3C097ULL,
		0x3D77A3F0D8DC0A52ULL,
		0xE47119D914614E52ULL,
		0xCDAAE5942F49CFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0D7D1A99297A7AFULL,
		0x505D2176DB65F9CAULL,
		0x7CB5CFD0F4E172C7ULL,
		0x4932E5D334450AA9ULL,
		0x9B969AEA129AC0D0ULL,
		0x4F3C01C6F48B64C2ULL,
		0x40B94626EB14B57DULL,
		0xB653FA7DCD087C6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8044500190168287ULL,
		0x100900605224484AULL,
		0x1085CB5034C03280ULL,
		0x4132011230000021ULL,
		0x0A1288880082C090ULL,
		0x0D3401C0D0880042ULL,
		0x4031000000000450ULL,
		0x8402E0140D084C68ULL
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
		0x94CAEC1929767852ULL,
		0x3A32F79AB1729684ULL,
		0x12B666BCB1FE692BULL,
		0x2C329344F9CFCEACULL,
		0x8FC5A3D12A398DFEULL,
		0x471C9E71F9B3B553ULL,
		0x65667EBF5709A882ULL,
		0x1A90651BD1CA29F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D87C483163D7DBULL,
		0x87F2EEE75D0ED9FAULL,
		0x39099452B976129CULL,
		0x0E970662FCFFB63BULL,
		0x5A4F9719B49C0C37ULL,
		0x4C0FD4BCFBA7324AULL,
		0x474F4D1F0C4346A3ULL,
		0x6D0DACE8564943FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C86C0821625052ULL,
		0x0232E68211029080ULL,
		0x10000410B1760008ULL,
		0x0C120240F8CF8628ULL,
		0x0A45831120180C36ULL,
		0x440C9430F9A33042ULL,
		0x45464C1F04010082ULL,
		0x08002408504801F9ULL
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
		0x282C15A1175E4E2DULL,
		0xD5BEB9E4D7A693A6ULL,
		0x11E7F740F94B1DDEULL,
		0x63E41CF16DAF229EULL,
		0x995F0E474BAE2681ULL,
		0xA47B6A1FDA679B49ULL,
		0xE3A2EDC51927BB02ULL,
		0xA8FC33B5E3D041FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85E4EDD927A1E6CBULL,
		0x5E1B94682C509B7EULL,
		0x9FFD5B3293ADE0A3ULL,
		0xA91D16709229415AULL,
		0xDAEDF2304B5BFD1BULL,
		0x5C091234B0157640ULL,
		0x1EC3332836F70011ULL,
		0xF835A399E53F7524ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0024058107004609ULL,
		0x541A906004009326ULL,
		0x11E5530091090082ULL,
		0x210414700029001AULL,
		0x984D02004B0A2401ULL,
		0x0409021490051240ULL,
		0x0282210010270000ULL,
		0xA8342391E1104124ULL
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
		0x01ED4DB7A4F5C98CULL,
		0xF326E12E06631098ULL,
		0xABA1A09C1B9C7A83ULL,
		0x86298CB18288A9D3ULL,
		0x00BE21F19E2CC698ULL,
		0x934B865812273832ULL,
		0x4DC4A1EFD0626865ULL,
		0x0842F174DFBA87DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DB0F05588D8B3B4ULL,
		0xB6413E3F382364ABULL,
		0x002A5E245560BC59ULL,
		0x1053AB9472DDBE61ULL,
		0x9ED5E63B62182863ULL,
		0x966D8DD8CDF7B6DAULL,
		0xC7E6F20D73D7A50BULL,
		0xE74239A01D82FA68ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01A0401580D08184ULL,
		0xB200202E00230088ULL,
		0x0020000411003801ULL,
		0x000188900288A841ULL,
		0x0094203102080000ULL,
		0x9249845800273012ULL,
		0x45C4A00D50422001ULL,
		0x004231201D828248ULL
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
		0xBEC3C23966172663ULL,
		0x391735FE312F9DAAULL,
		0x67760F0DA5DE0DC3ULL,
		0xBDE20448B642EC29ULL,
		0x908683233993632BULL,
		0xFDE0B76CF16CDEE5ULL,
		0xA15E73D55E2FD860ULL,
		0xE070E89306CE0609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E6CC7E9A4CCBC65ULL,
		0x9D73126488C114DEULL,
		0x1673B68CC8E79839ULL,
		0xA8850F63309514B1ULL,
		0x2ED2431206010BE7ULL,
		0x32C343767088DA06ULL,
		0xF406801F0445A9B3ULL,
		0xA8197E85F882DD2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3E40C22924042461ULL,
		0x191310640001148AULL,
		0x0672060C80C60801ULL,
		0xA880044030000421ULL,
		0x0082030200010323ULL,
		0x30C003647008DA04ULL,
		0xA006001504058820ULL,
		0xA010688100820408ULL
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
		0x32D2955FB25BD6F7ULL,
		0xB77B34C15B1E2381ULL,
		0x2C39A11FA2F0C206ULL,
		0xF46279B732F66164ULL,
		0x81204EB12C0BED6CULL,
		0xB4A517CC84EAD557ULL,
		0x4A637D21306F3D0BULL,
		0x2358C108372E1A51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38D993F1EE1A3F10ULL,
		0xC209E7933FF4ADECULL,
		0xFEA93D238FEEF843ULL,
		0x866FD7A9E74762F6ULL,
		0x3597C5C96A90157BULL,
		0x599DAF9FB0A413B2ULL,
		0x7881687B8D9557D5ULL,
		0x303BD9E87D9B2602ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30D09151A21A1610ULL,
		0x820924811B142180ULL,
		0x2C29210382E0C002ULL,
		0x846251A122466064ULL,
		0x0100448128000568ULL,
		0x1085078C80A01112ULL,
		0x4801682100051501ULL,
		0x2018C108350A0200ULL
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
		0x5ADD970F991AA8CAULL,
		0x69996444F4576F7DULL,
		0xD549E6E77AD7E26CULL,
		0x26C94D29FCD7CD63ULL,
		0xA286845B44EC8E4EULL,
		0x4E22E20DA7B401D7ULL,
		0x48F9B28BC79F9EDFULL,
		0x3B32BE55EE866136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23FB037F00C90ECDULL,
		0x876CF8783DAD2ACCULL,
		0x4AD734AF053A2683ULL,
		0x1636FFB64D717C92ULL,
		0xCFCDE86AD834B06DULL,
		0x64B87E14B3B7402DULL,
		0xAAEDB1291F503126ULL,
		0x1DC7A83B131FD2F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02D9030F000808C8ULL,
		0x0108604034052A4CULL,
		0x404124A700122200ULL,
		0x06004D204C514C02ULL,
		0x8284804A4024804CULL,
		0x44206204A3B40005ULL,
		0x08E9B00907101006ULL,
		0x1902A81102064030ULL
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
		0x4300F4503E7DE72FULL,
		0xE90DBD278A7A19AFULL,
		0x629A596881986850ULL,
		0xA93078453BDC6BD9ULL,
		0x20CEF2F344D89227ULL,
		0xCF70C5A9831809ACULL,
		0xC94A3882F8A1FE4FULL,
		0x5B7FFA16B2FE9E15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA26E4A74E4F2A2AFULL,
		0x3B61AC0CF49A1DECULL,
		0x6DE50BC78D5D771CULL,
		0x42765C3BED451857ULL,
		0xA9F871EFD6F67A3BULL,
		0xBA0483499925BA2DULL,
		0x0FF63D806BFB5794ULL,
		0x7583789974BA6D56ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020040502470A22FULL,
		0x2901AC04801A19ACULL,
		0x6080094081186010ULL,
		0x0030580129440851ULL,
		0x20C870E344D01223ULL,
		0x8A0081098100082CULL,
		0x0942388068A15604ULL,
		0x5103781030BA0C14ULL
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
		0x4BE91F062887A97BULL,
		0x4CDD7164AA2DE35BULL,
		0xA3F7337016E03309ULL,
		0xB0E28CA55950A132ULL,
		0x3680241345A01461ULL,
		0xCF5A9135E861B486ULL,
		0xD3D18E07246C823BULL,
		0xAE3CE324925B99BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A88C296A571F3CDULL,
		0xCE7BDC64E6890ADBULL,
		0xD6DA1B6277FD2C81ULL,
		0x865256B94DD020B1ULL,
		0xF22C768C2EC6FD97ULL,
		0xDE687B78AC39A080ULL,
		0x14F67A772E8F99E4ULL,
		0xB7B9451E2CE3EEAEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A8802062001A149ULL,
		0x4C595064A209025BULL,
		0x82D2136016E02001ULL,
		0x804204A149502030ULL,
		0x3200240004801401ULL,
		0xCE481130A821A080ULL,
		0x10D00A07240C8020ULL,
		0xA6384104004388AEULL
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
		0xF12797C26876AC34ULL,
		0x7BA368372BABF5EDULL,
		0x7028C0A084E58A5EULL,
		0xFD6CA7F2AD087373ULL,
		0x5759D4C563A6FAD3ULL,
		0xEEEEF63E7F8DAFD8ULL,
		0xEC4C3945EE7D2510ULL,
		0xBDB32B96EA411ABFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB9CA85EE212652FULL,
		0xE2CC3F000A66FC6AULL,
		0xC42D3DCB4E251D99ULL,
		0x381697A78E5969EBULL,
		0x8BDFA40F476B00CCULL,
		0x91B1E7125D385B39ULL,
		0x596D9A978E4359D0ULL,
		0xB9796F1AF7992BEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA104804260122424ULL,
		0x628028000A22F468ULL,
		0x4028008004250818ULL,
		0x380487A28C086163ULL,
		0x03598405432200C0ULL,
		0x80A0E6125D080B18ULL,
		0x484C18058E410110ULL,
		0xB9312B12E2010AAAULL
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
		0x2C79122134DA3C14ULL,
		0x51DAF80498DCC347ULL,
		0xF0C229489A2C3C42ULL,
		0x9DEA46E42F39E500ULL,
		0xC1D26FBEA0F70AE2ULL,
		0x6660764012EEAE65ULL,
		0x0960C2DE2ED42EE2ULL,
		0x59477CB97F580D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14B6CF8FB9FBBA85ULL,
		0xEA528E99AFE03957ULL,
		0x11EDC18D139F8CB7ULL,
		0x1540709F88AC3D21ULL,
		0xF6FAB1633F77D919ULL,
		0x47D5E048925F1D89ULL,
		0x016EBEE419524F65ULL,
		0x00F7C71921A29573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0430020130DA3804ULL,
		0x4052880088C00147ULL,
		0x10C00108120C0C02ULL,
		0x1540408408282500ULL,
		0xC0D2212220770800ULL,
		0x46406040124E0C01ULL,
		0x016082C408500E60ULL,
		0x0047441921000562ULL
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
		0x1E02B3783C107602ULL,
		0x08069FBDCBD1F779ULL,
		0xC56E5F4D95689E5DULL,
		0x559D42D3114C6B00ULL,
		0x8268C5226B30C76FULL,
		0x2D10A39B74F49B93ULL,
		0xE6940B83B0174933ULL,
		0x263B32F53B9FC279ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5984F47EDD6EBE34ULL,
		0xF7463ABA1098271BULL,
		0xEFF34D8A8EFA625EULL,
		0x74CF96105D92FEEBULL,
		0x9132962414465F07ULL,
		0x5EB52F9803F4BD6EULL,
		0x0C0173909E923EAAULL,
		0xA91DEB13C7D773B8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1800B0781C003600ULL,
		0x00061AB800902719ULL,
		0xC5624D088468025CULL,
		0x548D021011006A00ULL,
		0x8020842000004707ULL,
		0x0C10239800F49902ULL,
		0x0400038090120822ULL,
		0x2019221103974238ULL
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
		0x84F7046F2827D4F3ULL,
		0x499CE5DEA5372E6EULL,
		0xC1108E89BD40D698ULL,
		0x588159F783179062ULL,
		0xCB2709B58833A8F9ULL,
		0x45A5D1B04976A19CULL,
		0xADDD7FA29AA20215ULL,
		0x6EB9604B66BA7495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7D0A5DC6F96C5D1ULL,
		0xFC54FC99F501359DULL,
		0x91C6610056A8B2CBULL,
		0x264D81FD26482903ULL,
		0xAFB4F9AA57686216ULL,
		0x38777273D466EA51ULL,
		0xEE11DC08EC7BC580ULL,
		0x5327DD71200274DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84D0044C2806C4D1ULL,
		0x4814E498A501240CULL,
		0x8100000014009288ULL,
		0x000101F502000002ULL,
		0x8B2409A000202010ULL,
		0x002550304066A010ULL,
		0xAC115C0088220000ULL,
		0x4221404120027490ULL
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
		0xF3D3A5DC149B791FULL,
		0x5632EE06411DCD8AULL,
		0x0CB7D7D165ABDA91ULL,
		0x9CCCDA4586C74825ULL,
		0x806E6DB8C102D36CULL,
		0xE1B156A9A124847BULL,
		0x34CCC82225872930ULL,
		0x6597371C79F16C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B80D95D752DC9F7ULL,
		0xA564637748263666ULL,
		0xB5C8F7B776325F80ULL,
		0x307E7CD0BF0780C1ULL,
		0x82DAEDC29D27BD49ULL,
		0xF39248AE95BDEB86ULL,
		0xB8D91096DABE8962ULL,
		0x6FB01BBD9DE7EA23ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2380815C14094917ULL,
		0x0420620640040402ULL,
		0x0480D79164225A80ULL,
		0x104C584086070001ULL,
		0x804A6D8081029148ULL,
		0xE19040A881248002ULL,
		0x30C8000200860920ULL,
		0x6590131C19E16801ULL
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
		0x8EA22A5F6C16FF49ULL,
		0x33CC8720C50EC7B3ULL,
		0xA3C19866C776B068ULL,
		0xBE1B93440F212929ULL,
		0xE9D15FFB62733683ULL,
		0xA2B07EE81FD9CA1EULL,
		0xBADBE0CFB62EE46FULL,
		0xCEB45FC2616A6830ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21E344EBF2398E19ULL,
		0xE0CEF729B7E98924ULL,
		0x1E783D2F236CC4E7ULL,
		0x1E4967A585C115E5ULL,
		0x37EA36CA66F571F9ULL,
		0x2A39821EB3AB9CC3ULL,
		0xBCF3B3948854707DULL,
		0x48AE794B12653467ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A2004B60108E09ULL,
		0x20CC872085088120ULL,
		0x0240182603648060ULL,
		0x1E09030405010121ULL,
		0x21C016CA62713081ULL,
		0x2230020813898802ULL,
		0xB8D3A0848004606DULL,
		0x48A4594200602020ULL
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
		0xEF1C9E922FEADAE7ULL,
		0xD5D38AED06F7032AULL,
		0x7A97DF944D17C323ULL,
		0xBC7FEE3036B568B8ULL,
		0xDBF19277AF5EC707ULL,
		0x628A6CB491F589EBULL,
		0x3D5AD42B4034C009ULL,
		0xC212030CAE663A17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2324912ED9B2E9ULL,
		0xEDAB81C3F8F1954BULL,
		0xDBD2AFBF132DCF55ULL,
		0x0CB3E56F51C64DDFULL,
		0xAD70D2DDA4AB5464ULL,
		0xC03F39D654DA4F00ULL,
		0x987EBF0D95BFB738ULL,
		0xB51695E8760ECB7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0D0004902EC892E1ULL,
		0xC58380C100F1010AULL,
		0x5A928F940105C301ULL,
		0x0C33E42010844898ULL,
		0x89709255A40A4404ULL,
		0x400A289410D00900ULL,
		0x185A940900348008ULL,
		0x8012010826060A14ULL
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
		0x98C4E775890C2806ULL,
		0x8CF404AA432512A2ULL,
		0x2B157B9A796A42D5ULL,
		0x39B6DE9566130260ULL,
		0x451C9967EBBDA240ULL,
		0x811552725A6BBA11ULL,
		0xF5E894C150297C0AULL,
		0x1105507BA81D34EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF050CF95E07BEAULL,
		0xC01C2421484B4003ULL,
		0x0C4AAD1937B8DC1DULL,
		0xEB9ABA5C87FB7468ULL,
		0x4A44956BD9062D95ULL,
		0x05B4389321B6F9BCULL,
		0x9A0EFF1E1ACC6630ULL,
		0xD27C12FFA74ECFE8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x18C0404581002802ULL,
		0x8014042040010002ULL,
		0x0800291831284015ULL,
		0x29929A1406130060ULL,
		0x40049163C9042000ULL,
		0x011410120022B810ULL,
		0x9008940010086400ULL,
		0x1004107BA00C04E8ULL
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
		0xFF65077EB720B2D8ULL,
		0x0542519BB9899DA4ULL,
		0x1C3C51AF510D5958ULL,
		0xB84B50F7EC1D6A3CULL,
		0xC2ECCBC2F424276AULL,
		0xF38413107A36A05AULL,
		0x08265D3F9BE6A8DCULL,
		0xADA8A6189D09E3AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4316877A4112E0ULL,
		0xF8A3B2AD0CE4EFFAULL,
		0x6A7C205C02F8094DULL,
		0xBD2FAEC305821E5CULL,
		0x4669DE921C95DA50ULL,
		0x9755372CBFFD0288ULL,
		0xDAE4854E54BFC82DULL,
		0x5AE6F571CA1C8833ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBF410606320012C0ULL,
		0x0002108908808DA0ULL,
		0x083C000C00080948ULL,
		0xB80B00C304000A1CULL,
		0x4268CA8214040240ULL,
		0x930413003A340008ULL,
		0x0824050E10A6880CULL,
		0x08A0A41088088023ULL
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
		0x991A87690EB78D00ULL,
		0x466B3B42485AF127ULL,
		0x3E1BC12687CB3EC1ULL,
		0x2C07D0E7E4FDD2F9ULL,
		0x3F758DA85B2FD312ULL,
		0x8A8FB834E0FDADEAULL,
		0xF0C21BF7E52D3397ULL,
		0x0F6307DF400BBF7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19A9DE798B5BA252ULL,
		0xEAA2793CCC230C88ULL,
		0x6D0DCD8061118B6BULL,
		0xD249B75B612CC593ULL,
		0x1A26696741FD961BULL,
		0xD041705ED9C75625ULL,
		0xBDE0C03F0D0EF7CDULL,
		0x3361EB48CCDA39F7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x190886690A138000ULL,
		0x4222390048020000ULL,
		0x2C09C10001010A41ULL,
		0x00019043602CC091ULL,
		0x1A240920412D9212ULL,
		0x80013014C0C50420ULL,
		0xB0C00037050C3385ULL,
		0x03610348400A3973ULL
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
		0xBC0237A8DB7B1B2BULL,
		0xBB489D43B956DB00ULL,
		0xFD48ABD921A84547ULL,
		0xD06EEF452627F4C1ULL,
		0x863DA9EDC9EEE176ULL,
		0x2E65BC4DF9E8E534ULL,
		0x42A1F32688DE0CDAULL,
		0xA9D9740A9DBD0B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6813BB16EFAC45B5ULL,
		0x4BA35E284E849B45ULL,
		0x65518151517C0A1CULL,
		0xFB9FA458A07E1AE4ULL,
		0xA6A2FB02B3524F6BULL,
		0x350A8FABF77D6AA7ULL,
		0x3E29EB16A73AAFE2ULL,
		0xC1D84FED69F8E5A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28023300CB280121ULL,
		0x0B001C0008049B00ULL,
		0x6540815101280004ULL,
		0xD00EA440202610C0ULL,
		0x8620A90081424162ULL,
		0x24008C09F1686024ULL,
		0x0221E306801A0CC2ULL,
		0x81D8440809B80106ULL
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
		0x91410E8AB4F75F7FULL,
		0x169483A38819094EULL,
		0xBF0B1DD3039C6CF1ULL,
		0x7213A0C4DB76F358ULL,
		0x5728A8AE0A87A99AULL,
		0xC596F99581DD210CULL,
		0x37AAEE0C352AEBEDULL,
		0x3BF5366BBD97275DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F41C99864DC053AULL,
		0x3AD078EB3FE6CDC2ULL,
		0xDC832BA9C7C0224CULL,
		0x4902CFF48748E291ULL,
		0xA3212F979F95E079ULL,
		0x6D16DAACA1AF72FFULL,
		0x99B2A680078086E7ULL,
		0x31DD1EBB97AF2DBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1141088824D4053AULL,
		0x129000A308000942ULL,
		0x9C03098103802040ULL,
		0x400280C48340E210ULL,
		0x032028860A85A018ULL,
		0x4516D884818D200CULL,
		0x11A2A600050082E5ULL,
		0x31D5162B9587251CULL
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
		0x0A6171977577D90BULL,
		0x760FF7EF7430CB59ULL,
		0xCDDA40046F970E53ULL,
		0xB434F830496E4AABULL,
		0x1A877798A83E3ADCULL,
		0xEE312EC37EC90D6FULL,
		0xFFF460636D4234F0ULL,
		0x3CF04AEC2A7ECFCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4D7FAF159BFBF43ULL,
		0xE12D7A1A493EEDECULL,
		0x0B06B2ECC7BCE8A0ULL,
		0xC47BFF973BA316BFULL,
		0xB0F36F08CA59982FULL,
		0x0D94C544AAFC8B48ULL,
		0xD69E0C828905CFEEULL,
		0xA4EEE402E5AA08F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0041709151379903ULL,
		0x600D720A4030C948ULL,
		0x0902000447940800ULL,
		0x8430F810092202ABULL,
		0x108367088818180CULL,
		0x0C1004402AC80948ULL,
		0xD6940002090004E0ULL,
		0x24E04000202A08C6ULL
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
		0xE7BA8CEC929C2316ULL,
		0x78043D3864E51F67ULL,
		0x9158356075D11707ULL,
		0x1E29714A8D022F02ULL,
		0xF4BCC458BF2ED936ULL,
		0x2909DC0DF43E333BULL,
		0xFEA80CC959240C8EULL,
		0xB5CDD4262A8FD57FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65481515BC10F6D6ULL,
		0x4B9B59C229C5DB83ULL,
		0x1683962FAF4B0178ULL,
		0x5FC81D6CC4C931C6ULL,
		0x79AC001151EF3D16ULL,
		0xBC8A945B4AC60537ULL,
		0xB3A223C443CF95BDULL,
		0xF18386761A38FAACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6508040490102216ULL,
		0x4800190020C51B03ULL,
		0x1000142025410100ULL,
		0x1E08114884002102ULL,
		0x70AC0010112E1916ULL,
		0x2808940940060133ULL,
		0xB2A000C04104048CULL,
		0xB18184260A08D02CULL
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
		0x5F7AA9F91B155F42ULL,
		0x6019F3CA71C8B181ULL,
		0x7B16F845B0951EBFULL,
		0x1E4F5A2E53D051EAULL,
		0x19BE43D1143EF517ULL,
		0xCB1EDE5E5A65F7C9ULL,
		0xD48F7265DF62A302ULL,
		0x53D19A8754AFAE6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F0A8D9F161B1AB9ULL,
		0x08B263E448FF4251ULL,
		0xDC619CDCE4F74026ULL,
		0xDBBA207A63635566ULL,
		0x6508100B29E9B770ULL,
		0xA55458FD4245D121ULL,
		0x8425BF8550960BD7ULL,
		0xCD5899B7584A9322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F0A899912111A00ULL,
		0x001063C040C80001ULL,
		0x58009844A0950026ULL,
		0x1A0A002A43405162ULL,
		0x010800010028B510ULL,
		0x8114585C4245D101ULL,
		0x8405320550020302ULL,
		0x41509887500A8220ULL
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
		0xE6577D59294EA377ULL,
		0x4BF958EE5DDE32C2ULL,
		0x35FC17F3766F6DFDULL,
		0x1956F7BDF048AEF8ULL,
		0xC0680B33262987B0ULL,
		0x42C3234B265E7458ULL,
		0x3BC680A0EF970EDAULL,
		0x3BF690E127F88C8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD14FBB9D39854562ULL,
		0x4DE8939EFA558FE1ULL,
		0xA229A6E5E061F007ULL,
		0x850CC207EBF448A6ULL,
		0xC05E6C5D144DC1A5ULL,
		0x01B9D4DAC9C9E281ULL,
		0xA809BD719BEE126FULL,
		0x89D80DF60421D7D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC047391929040162ULL,
		0x49E8108E585402C0ULL,
		0x202806E160616005ULL,
		0x0104C205E04008A0ULL,
		0xC0480811040981A0ULL,
		0x0081004A00486000ULL,
		0x280080208B86024AULL,
		0x09D000E004208486ULL
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
		0x4EDADC4AEBC31624ULL,
		0x86597BAEF359859FULL,
		0x25A5FB4271663C72ULL,
		0xF673A5C976371585ULL,
		0xBB564B5763531B22ULL,
		0x68569CDD75D7666FULL,
		0x472C94E568E6C2E8ULL,
		0x3B33625686CCFD1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2FC80F7BB895F5ULL,
		0x23A662411E6A6145ULL,
		0x0D22052A3D87A6A1ULL,
		0xC5CF45EF162535D9ULL,
		0x012F1047E990865AULL,
		0x7703D5715FC1ADBBULL,
		0x90E4B9AF4AC8750FULL,
		0x47057FF0D4542D57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C0AC80A6B801424ULL,
		0x0200620012480105ULL,
		0x0520010231062420ULL,
		0xC44305C916251581ULL,
		0x0106004761100202ULL,
		0x6002945155C1242BULL,
		0x002490A548C04008ULL,
		0x0301625084442D16ULL
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
		0xAB6DFB098BB7082AULL,
		0x6A4F75C0C28DF322ULL,
		0x551AF33DB93A7422ULL,
		0x829236B9AFBDC9A3ULL,
		0xFF5644FD29B83769ULL,
		0x8432D5F85966B21AULL,
		0x1B15CE198B82D682ULL,
		0xB3710F20156435A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B898E5AD7BA5561ULL,
		0xC6A0B324B07EE8D1ULL,
		0x01A426D348203734ULL,
		0x03243B42B6A4BD64ULL,
		0xFB2F954C5F2317E4ULL,
		0xABFC45FA5A0ACA47ULL,
		0xE4D21F99B12E1AC0ULL,
		0x748592048B2F4606ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B098A0883B20020ULL,
		0x42003100800CE000ULL,
		0x0100221108203420ULL,
		0x02003200A6A48920ULL,
		0xFB06044C09201760ULL,
		0x803045F858028202ULL,
		0x00100E1981021280ULL,
		0x3001020001240400ULL
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
		0x3EDA05C20178193CULL,
		0x7E11F7239E75BC6CULL,
		0xF965105B21C68774ULL,
		0xE693C6B89BD37A68ULL,
		0x2158CFA89CC97CABULL,
		0x93A871E45A038C24ULL,
		0x2A142FC2FDD37527ULL,
		0x8385436BDAEB10F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048F99F342FEDDEEULL,
		0x9B1FF89B5CD7AA4AULL,
		0xDDB8222FA911288AULL,
		0xFA979A9497BBD3F6ULL,
		0x0FB8F72BC032A1D5ULL,
		0xBD89E56E94F06470ULL,
		0xACA71220098FC485ULL,
		0x00266E0641CD6846ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x048A01C20078192CULL,
		0x1A11F0031C55A848ULL,
		0xD920000B21000000ULL,
		0xE293829093935260ULL,
		0x0118C72880002081ULL,
		0x9188616410000420ULL,
		0x2804020009834405ULL,
		0x0004420240C90046ULL
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
		0xFF60073806CBEE44ULL,
		0xC05BE4365AB15A54ULL,
		0x0A6E49259A2CA2A7ULL,
		0x8F9291881CA7BF93ULL,
		0xE929C6FDA68F5E12ULL,
		0xCC170E7C7CFD01BAULL,
		0x967DA009332612D5ULL,
		0x01C95C8672C38187ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06405A82C4322EDEULL,
		0x1729D5DC00DCEB48ULL,
		0x4ABCED544A8193B1ULL,
		0xEE9B9F74D8993063ULL,
		0x368E346084C61555ULL,
		0x780C3A3DC597D86EULL,
		0x80853801E50FBB95ULL,
		0xE2696669F426909CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0640020004022E44ULL,
		0x0009C41400904A40ULL,
		0x0A2C49040A0082A1ULL,
		0x8E92910018813003ULL,
		0x2008046084861410ULL,
		0x48040A3C4495002AULL,
		0x8005200121061295ULL,
		0x0049440070028084ULL
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
		0x324F5EB6515C606EULL,
		0x091F53B74C7B4477ULL,
		0xD3597FBF1F9E0485ULL,
		0x1E3E15BED4D5325DULL,
		0xF8D1298D5E2BF9C0ULL,
		0xBF9D743AEF8CF11CULL,
		0x4EF3978E6986C139ULL,
		0x071E9E58653BEBEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B423AFDA65C2EE2ULL,
		0xD6B32413DED6A459ULL,
		0xFC1228119C3AA8BCULL,
		0x07427A9C7C83014BULL,
		0xB6FE98EDB6173426ULL,
		0xB5D86370E041A42BULL,
		0x75572E89A95575ECULL,
		0xEC61BDA2FD1CDC03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32421AB4005C2062ULL,
		0x001300134C520451ULL,
		0xD01028111C1A0084ULL,
		0x0602109C54810049ULL,
		0xB0D0088D16033000ULL,
		0xB5986030E000A008ULL,
		0x4453068829044128ULL,
		0x04009C006518C802ULL
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
		0xF63E14733F3B4D33ULL,
		0xE4EB65DCDB1BF796ULL,
		0x6E432C2F68C93B6EULL,
		0xF0A7D4D1A7577C77ULL,
		0xE538A55F08ECB795ULL,
		0x078E6C6AB9271323ULL,
		0x6A42D18D94C63210ULL,
		0x80AE1CBBD243A7D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC9C33BF285C8D2ULL,
		0x5B43E0E5E04595BCULL,
		0x5A88D0ECA16A948CULL,
		0x0EA289EBB9CE5C28ULL,
		0x1B4021B9A2599D8EULL,
		0xCC3F711EA1EAAA08ULL,
		0x5A4514EE5F030E1AULL,
		0xF94DC99FD69FA572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3208003332014812ULL,
		0x404360C4C0019594ULL,
		0x4A00002C2048100CULL,
		0x00A280C1A1465C20ULL,
		0x0100211900489584ULL,
		0x040E600AA1220200ULL,
		0x4A40108C14020210ULL,
		0x800C089BD203A552ULL
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
		0x45843DC6C8152D0FULL,
		0x1293F570482BC39EULL,
		0xA153EDAF69E42D47ULL,
		0x3C9B57CB3BFB3CF6ULL,
		0xDDF4BF9EFCC56489ULL,
		0x713C0A3B3C1B4FB4ULL,
		0x893CCFE630D37E1CULL,
		0xB04ACAD0AF78AD8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC248061F4E6A008ULL,
		0xEBB8A840F72C944BULL,
		0x221F68601D5B13F7ULL,
		0x0768C4B6B4488A94ULL,
		0x96588B24DAAAAD32ULL,
		0x00B9DB86A9C23D18ULL,
		0x40529ABA371A3BEFULL,
		0x000D83C4EF49DE9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x44040040C0042008ULL,
		0x0290A0404028800AULL,
		0x2013682009400147ULL,
		0x0408448230480894ULL,
		0x94508B04D8802400ULL,
		0x00380A0228020D10ULL,
		0x00108AA230123A0CULL,
		0x000882C0AF488C8DULL
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
		0x1A11943CADC3F217ULL,
		0x5A38C4E303FB2FB8ULL,
		0xD2CE4CBB2BBD9BEBULL,
		0xEFF35131C81CB588ULL,
		0x73BE2B4393815B61ULL,
		0x3136003D6F932406ULL,
		0x613069BBDFC815FFULL,
		0x7A2D540664431704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35CEBB310A670323ULL,
		0xA6B91F887EE86E65ULL,
		0x5D3975123E6EC6A8ULL,
		0x26B798FB09BF4BFCULL,
		0x744EA2937DEF7708ULL,
		0x8658EC894EB3145BULL,
		0xA63013B1FE65295DULL,
		0xCEC4461B005663D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000903008430203ULL,
		0x0238048002E82E20ULL,
		0x500844122A2C82A8ULL,
		0x26B31031081C0188ULL,
		0x700E220311815300ULL,
		0x001000094E930402ULL,
		0x203001B1DE40015DULL,
		0x4A04440200420300ULL
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
		0xCC01D5FCE2318184ULL,
		0x2537038CD2E4761FULL,
		0xCF3BB2866C92B6D4ULL,
		0x8F9461C0D816A5B8ULL,
		0xD2EEFC8A3BC0D331ULL,
		0x8FF3C5142C8B379AULL,
		0x786B0874D69F2C96ULL,
		0x69388D0AC361250DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F080FC5B3C5261ULL,
		0xAF13939802D13261ULL,
		0x9A5BBA21423465FEULL,
		0x995964EC48777E70ULL,
		0x3BDDD587B2A22C5CULL,
		0xA8B737F38C6522B0ULL,
		0x13F02DC5927B812CULL,
		0xD27FDE9F1BED6609ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x880080FC42300000ULL,
		0x2513038802C03201ULL,
		0x8A1BB200401024D4ULL,
		0x891060C048162430ULL,
		0x12CCD48232800010ULL,
		0x88B305100C012290ULL,
		0x10600844921B0004ULL,
		0x40388C0A03612409ULL
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
		0x158E8641A3DDACD3ULL,
		0xD3F14680611CB46FULL,
		0x6E27CA3BB8C0355CULL,
		0x52A73E8E3F787AA2ULL,
		0x77216449DB16495FULL,
		0x2E6CB47F269116F0ULL,
		0x51442B0A812CD4A8ULL,
		0x4D8B54FFFDF2D28BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0EA5FB40230D768ULL,
		0x7D8C2381C5EAC97CULL,
		0x4217AF79B2F7EDFCULL,
		0xD4AFA0C4E1C16F7BULL,
		0x4F8183FA079F136AULL,
		0x7711E51FD10FAFF9ULL,
		0x253A2145872D10B9ULL,
		0xD6038F4019AF60EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008A060002108440ULL,
		0x518002804108806CULL,
		0x42078A39B0C0255CULL,
		0x50A7208421406A22ULL,
		0x470100480316014AULL,
		0x2600A41F000106F0ULL,
		0x01002100812C10A8ULL,
		0x4403044019A2408AULL
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
		0x765D1890D99AC8C3ULL,
		0x2A12653D12E66AEBULL,
		0xF926E2AF12E4D575ULL,
		0xC23D8ECD287DC897ULL,
		0x371595E427CC7ECDULL,
		0x5D3A495DE8BC8DA6ULL,
		0x4F277BF357F0E142ULL,
		0xBDB305127188A144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679EE86CCDB95213ULL,
		0x28743A489249FB24ULL,
		0x8A6E3D16DD107470ULL,
		0xD68BA46D7BE14FDBULL,
		0x7B6ECE1B968F4301ULL,
		0x495F477ACBC3D7B0ULL,
		0x702DB67F663C3851ULL,
		0x84067D57A6DAAB15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x661C0800C9984003ULL,
		0x2810200812406A20ULL,
		0x8826200610005470ULL,
		0xC209844D28614893ULL,
		0x33048400068C4201ULL,
		0x491A4158C88085A0ULL,
		0x4025327346302040ULL,
		0x840205122088A104ULL
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
		0x5287347CE1B93FB7ULL,
		0xE2DC78B7812E7D2BULL,
		0x396B9678940FD5AAULL,
		0x4BAA69629591CD00ULL,
		0x219A23A69A2F529FULL,
		0x36A2062AAB9B59A8ULL,
		0x36CF9891ACDEC049ULL,
		0xA9AF2FF27D3C9AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7339934079220FE9ULL,
		0x7F9CDADF24D07B47ULL,
		0x26038B7808E3F00CULL,
		0xEE7281DF1925B1C4ULL,
		0xABC8AB7B86DDE217ULL,
		0x13C0A648B439C8B3ULL,
		0xE7DC5EFABAAD2CABULL,
		0xCD7BF6DFF2FDBDC9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5201104061200FA1ULL,
		0x629C589700007903ULL,
		0x200382780003D008ULL,
		0x4A22014211018100ULL,
		0x21882322820D4217ULL,
		0x12800608A01948A0ULL,
		0x26CC1890A88C0009ULL,
		0x892B26D2703C98C9ULL
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
		0x2F3C8E2A25BE0691ULL,
		0x91213E8CFF24AB38ULL,
		0xC5C267F747623585ULL,
		0x18A4B48FF67B14F5ULL,
		0xB06147882F459BEAULL,
		0xACD6E5D3CBBE9A62ULL,
		0xC0367D3D15984805ULL,
		0x3A8902DC5E7D7BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C298AAB5A10A6BULL,
		0xBA21ECEB19BA4EDBULL,
		0x9AEFDA3CA0462AC8ULL,
		0x6061126221836A26ULL,
		0x182A3EB25C0F2D37ULL,
		0x09F8070867B58E6CULL,
		0xE35911583957BE56ULL,
		0x9C37DF95DF57D607ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0800882A25A00201ULL,
		0x90212C8819200A18ULL,
		0x80C2423400422080ULL,
		0x0020100220030024ULL,
		0x102006800C050922ULL,
		0x08D0050043B48A60ULL,
		0xC010111811100804ULL,
		0x180102945E555202ULL
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
		0x8B344DD841FFDAC9ULL,
		0xE37B52CA902E4244ULL,
		0x93BBEF96BE5AF890ULL,
		0xAEA413EC6E20AEB1ULL,
		0xEA1278EF8FA3A864ULL,
		0xCC1CE631E37D06DCULL,
		0x95DC70E558F04DF5ULL,
		0x3AC1B7225280951CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x127E8D244787D81CULL,
		0x9439F7E9FD7D115CULL,
		0xE912E829AD570FF1ULL,
		0x1D051B26E878909FULL,
		0x20CF939257FC7CE0ULL,
		0x1F669277F54F56D5ULL,
		0x2A06A3BD24DEE28BULL,
		0x290CC38C18426F86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02340D004187D808ULL,
		0x803952C8902C0044ULL,
		0x8112E800AC520890ULL,
		0x0C04132468208091ULL,
		0x2002108207A02860ULL,
		0x0C048231E14D06D4ULL,
		0x000420A500D04081ULL,
		0x2800830010000504ULL
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
		0xD210ACB99EB7390AULL,
		0xA7B01A23AC7E3EB8ULL,
		0x29BFF5DD0115AAF6ULL,
		0x7576250F08AFC590ULL,
		0x2529AC307AC8F226ULL,
		0xC5BD04F86CFE28C6ULL,
		0x17F6E4BA1F383265ULL,
		0xBCF471D8AFAC5C96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8DA20CFD579300DULL,
		0x6D61FC20B40E250DULL,
		0xD85DB1039A48F8D1ULL,
		0x52DB64D8A28D05ECULL,
		0x730DA92D6B19AA61ULL,
		0xAFAB390AC8FAFB10ULL,
		0x6B69407835C56FCBULL,
		0x638FF4282942ABCDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD010208994313008ULL,
		0x25201820A40E2408ULL,
		0x081DB1010000A8D0ULL,
		0x50522408008D0580ULL,
		0x2109A8206A08A220ULL,
		0x85A9000848FA2800ULL,
		0x0360403815002241ULL,
		0x2084700829000884ULL
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
		0x5B4138C0A1A2E571ULL,
		0xE6E4E46F16E97EFFULL,
		0x3B205D0F4A7DAF2EULL,
		0x3FCAF185E6313097ULL,
		0xCE6E286C8B6980B4ULL,
		0x62EE3270178F7F72ULL,
		0xEBC3B7227B397AC0ULL,
		0xD9460D821B245847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BC38806121ACAAFULL,
		0xE5954FD97913B07FULL,
		0x4457E6F1F4562FA5ULL,
		0xCDCF5AA97DBB75A5ULL,
		0xC6A914A0170398E2ULL,
		0x152EAF26FB875275ULL,
		0x34F61A7C0FDF4781ULL,
		0x2D98E60B48E3590EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5B4108000002C021ULL,
		0xE48444491001307FULL,
		0x0000440140542F24ULL,
		0x0DCA508164313085ULL,
		0xC6280020030180A0ULL,
		0x002E222013875270ULL,
		0x20C212200B194280ULL,
		0x0900040208205806ULL
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
		0xAF3FA965D4128EDFULL,
		0xBD68B6190172AA7DULL,
		0xF112298722232FB5ULL,
		0x57EAD78AA35EBDAFULL,
		0xB7D480FBAC5CC376ULL,
		0x4E5806523DDABB48ULL,
		0x9566928AF6FD31ECULL,
		0xBF4694AAE52A593BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B52A4C5CE7916C4ULL,
		0xDB198D92E302D7C8ULL,
		0x743E26E1A294CF79ULL,
		0xADF58C02882F40C0ULL,
		0xA3CEA0AB882E9C8CULL,
		0x4BF1C99B67DD83B6ULL,
		0xAFCF2AA76C123F26ULL,
		0xB46B0401714FB82BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B12A045C41006C4ULL,
		0x9908841001028248ULL,
		0x7012208122000F31ULL,
		0x05E08402800E0080ULL,
		0xA3C480AB880C8004ULL,
		0x4A50001225D88300ULL,
		0x8546028264103124ULL,
		0xB4420400610A182BULL
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
		0x7209EE7AB652E735ULL,
		0x3C52992DFCC2BC2BULL,
		0xFABFED87CAD5BFB5ULL,
		0xF517D436BB16B4FAULL,
		0x2AE7A272B621379AULL,
		0xC65500C538C6918FULL,
		0x40450440F2D83F48ULL,
		0xC296FC51D2836771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA2A8D95C5FEFADFULL,
		0x3318053F2FB4A575ULL,
		0xA26B456A6D0A6CC0ULL,
		0x0DB33C5456ECC670ULL,
		0x0B78221C9EC3A22BULL,
		0x70EA0475C40D0789ULL,
		0x3BE0B2D2EAF8185DULL,
		0x4DEED0FAC75E4A4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62088C108452E215ULL,
		0x3010012D2C80A421ULL,
		0xA22B450248002C80ULL,
		0x0513141412048470ULL,
		0x0A6022109601220AULL,
		0x4040004500040189ULL,
		0x00400040E2D81848ULL,
		0x4086D050C2024240ULL
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
		0x36EBEBE77F1FC7DDULL,
		0x849B2BFB9F60EE23ULL,
		0x3AEF4DCD273358BAULL,
		0x3C99618A272BB2C9ULL,
		0x01B764D125F5E5BBULL,
		0x8C92244921202314ULL,
		0x4B85BA7E709BD9A0ULL,
		0xC4D2C7D8550453F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06E10ECF194D0017ULL,
		0x3B5B6B8D0D45A7C0ULL,
		0x57AC166D56636319ULL,
		0xA306C421C7BFF423ULL,
		0x3BF1D656C6BA13CBULL,
		0x615CF9E15260BEAFULL,
		0x27762791920A032AULL,
		0xD225F3C85B94FE53ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x06E10AC7190D0015ULL,
		0x001B2B890D40A600ULL,
		0x12AC044D06234018ULL,
		0x20004000072BB001ULL,
		0x01B1445004B0018BULL,
		0x0010204100202204ULL,
		0x03042210100A0120ULL,
		0xC000C3C851045253ULL
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
		0x4265C11C9E3723AEULL,
		0x2D7610252396B416ULL,
		0x4E9A8ABAB6535686ULL,
		0x1A01ED0664962343ULL,
		0x7454158EEC3F532DULL,
		0x6D07B430E2EA980FULL,
		0xC0FB661CB28E2503ULL,
		0xDD510C14BD97430AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x297C1F9F674B9B55ULL,
		0x57C20A26BDB3820EULL,
		0xD9BC2F97ECE7B13FULL,
		0x7912E0E6A638C7CEULL,
		0xB6BEB6E47EACB16DULL,
		0xF4E27F245CDA6E28ULL,
		0xF3C0CC67DBD5055AULL,
		0xE0F5A973DA87A11AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0064011C06030304ULL,
		0x0542002421928006ULL,
		0x48980A92A4431006ULL,
		0x1800E00624100342ULL,
		0x341414846C2C112DULL,
		0x6402342040CA0808ULL,
		0xC0C0440492840502ULL,
		0xC05108109887010AULL
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
		0x3B001CF4696A421FULL,
		0xEFA655BFC24ED55FULL,
		0x1A30ECEBC365447DULL,
		0x3A6A5F4A5B31E396ULL,
		0x692597DC97A56797ULL,
		0xAF650B826E241E9DULL,
		0xD71D17653CA0B341ULL,
		0x375F07F4F390728AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0D614097F26D632ULL,
		0xFB1E164551BFBBDDULL,
		0xF89AF0039188376DULL,
		0x90D07FD32E7A227EULL,
		0xD533FD2CFB239931ULL,
		0x86C52A1F630E9697ULL,
		0x4646AB662642435FULL,
		0xC0F2EA0723E371A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1000140069224212ULL,
		0xEB061405400E915DULL,
		0x1810E0038100046DULL,
		0x10405F420A302216ULL,
		0x4121950C93210111ULL,
		0x86450A0262041695ULL,
		0x4604036424000341ULL,
		0x0052020423807088ULL
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
		0x9EB41DDCF1D47D15ULL,
		0xD7AA74D3A5DA55B6ULL,
		0xAD2D67CAF4214FA1ULL,
		0xE90519E4E3DF8374ULL,
		0xD2AE597B1074BAE5ULL,
		0x7AB7E9BC3414B6DCULL,
		0x2FD89B29667E73BAULL,
		0x60C679ABD9CCAD36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E90E561D71CCCBAULL,
		0x8BBED43776386BB1ULL,
		0x13DF52FE1C228E70ULL,
		0xA61A1E499800AEBFULL,
		0x1E17CE98B7B4B486ULL,
		0x20A1FC2FEE5620FCULL,
		0x08919C6579C91DB6ULL,
		0x4683B4BBFC9E29CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E900540D1144C10ULL,
		0x83AA5413241841B0ULL,
		0x010D42CA14200E20ULL,
		0xA000184080008234ULL,
		0x120648181034B084ULL,
		0x20A1E82C241420DCULL,
		0x08909821604811B2ULL,
		0x408230ABD88C2902ULL
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
		0x0A49D539F7B09F26ULL,
		0x96C48D068F28E066ULL,
		0xC280B4E96712987DULL,
		0x97E884E7A884DCE6ULL,
		0xBBCF8307BCE517DCULL,
		0xFCF892EA09A2CD50ULL,
		0x45F12FFE73A7FBDAULL,
		0xB50C167FBB3612C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E52DB66AFDE571CULL,
		0xDF25B2F6014C0CD9ULL,
		0xEC9665C3138C0703ULL,
		0x4EA5F68163FD2E75ULL,
		0x07EEE532C30BE1F4ULL,
		0xB5886F07CC5AB830ULL,
		0x0B86186728CA8873ULL,
		0x54302A13F67AD1C0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A40D120A7901704ULL,
		0x9604800601080040ULL,
		0xC08024C103000001ULL,
		0x06A0848120840C64ULL,
		0x03CE8102800101D4ULL,
		0xB488020208028810ULL,
		0x0180086620828852ULL,
		0x14000213B23210C0ULL
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
		0x557D835FD6804BE8ULL,
		0xADF1E12670711CFAULL,
		0xDDB0FA6611A870B4ULL,
		0x0B5EF391A06682FAULL,
		0x3C770E20642895A1ULL,
		0x7D91D6A761A9C585ULL,
		0x47D9630B0D03FF17ULL,
		0x125F1E98621ABEFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA89F99A20FC83473ULL,
		0xAC765776E8FA80F4ULL,
		0xCDF7D2885463B3B4ULL,
		0xA5E4FC496B0D5186ULL,
		0x0A21CDB511E52D42ULL,
		0xBBCC7C912393827CULL,
		0xE156A70FEACCA93BULL,
		0xC4216BD0C1263468ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x001D810206800060ULL,
		0xAC704126607000F0ULL,
		0xCDB0D200102030B4ULL,
		0x0144F00120040082ULL,
		0x08210C2000200500ULL,
		0x3980548121818004ULL,
		0x4150230B0800A913ULL,
		0x00010A9040023468ULL
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
		0xB6BDB921CDF7097FULL,
		0x8B91C31C68D7F631ULL,
		0x8A591678560A5CF9ULL,
		0x5FA38BB0D960CCC7ULL,
		0xA3D7855EE8B33264ULL,
		0x55BDECE1ECA8F4DAULL,
		0xF179834274F9591BULL,
		0x62F0A77C3139D2C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3B2D7958CE55E96ULL,
		0xFE00E4C7D197BA2BULL,
		0xC9FF5EB64C71A755ULL,
		0x0725451CCACDF336ULL,
		0xD122F4FF57C9124AULL,
		0xA538CF055B598A23ULL,
		0x2D5371B62269FDDFULL,
		0x7A412FC36A033887ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82B091018CE50816ULL,
		0x8A00C0044097B221ULL,
		0x8859163044000451ULL,
		0x07210110C840C006ULL,
		0x8102845E40811240ULL,
		0x0538CC0148088002ULL,
		0x215101022069591BULL,
		0x6240274020011083ULL
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
		0xD877D216509E0E89ULL,
		0x56EA73026EE20E63ULL,
		0x014BC44480DEB4CDULL,
		0xB3A4365A8A385DB2ULL,
		0x57AD261800572897ULL,
		0x768A0909359533C8ULL,
		0x95E2D30E30C0D473ULL,
		0x0944DD9BC435BC86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE90B2473CDB35129ULL,
		0xAD65AE4B93818AAFULL,
		0xB7A7C535D1035043ULL,
		0xA1B04A78913A216AULL,
		0xE1C1A42C331C53F0ULL,
		0xADDC6D4F9295DE7FULL,
		0x59E0CB2728EA394DULL,
		0x2450D92D2BB1A8BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC803001240920009ULL,
		0x0460220202800A23ULL,
		0x0103C40480021041ULL,
		0xA1A0025880380122ULL,
		0x4181240800140090ULL,
		0x2488090910951248ULL,
		0x11E0C30620C01041ULL,
		0x0040D9090031A882ULL
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
		0xDA18EAF0CAD9CC07ULL,
		0x2CA558530E3F7150ULL,
		0x53EB9A4AD6934D92ULL,
		0xAD9879B8396CFBDCULL,
		0xB3609043F0770B91ULL,
		0x82B5AE927C5F7145ULL,
		0x722F3F59EC398A0BULL,
		0x771B545C92481BC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBA998A6A0784E29ULL,
		0x17BC0EEA55F3AB03ULL,
		0xAFF484984D893AA6ULL,
		0x708ABCEDF48886D2ULL,
		0x640B1033204DB674ULL,
		0x4A518C1493981535ULL,
		0xBD7CD44B205BF666ULL,
		0xFE1AE07470582F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA0888A080584C01ULL,
		0x04A4084204332100ULL,
		0x03E0800844810882ULL,
		0x208838A8300882D0ULL,
		0x2000100320450210ULL,
		0x02118C1010181105ULL,
		0x302C144920198202ULL,
		0x761A405410480B40ULL
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
		0x681935DB02506EEBULL,
		0xAA24AFDC79E81DA7ULL,
		0xDCF8E7B280899638ULL,
		0x85CB08665518E63BULL,
		0x008D2B42B2122C6AULL,
		0x63A6E0F567B69E3BULL,
		0xE02188F3702AA1C1ULL,
		0x5D0DE2E7F46F4F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC98B74DF4A872B34ULL,
		0x78F9FD3D47F95BB4ULL,
		0x4B31B9E0D8E386A0ULL,
		0xB37201731542F0C9ULL,
		0x6481829C6DD44841ULL,
		0xF4FA7A1F44A981B9ULL,
		0x540C91B48C58AC88ULL,
		0x352299199E703690ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x480934DB02002A20ULL,
		0x2820AD1C41E819A4ULL,
		0x4830A1A080818620ULL,
		0x814200621500E009ULL,
		0x0081020020100840ULL,
		0x60A2601544A08039ULL,
		0x400080B00008A080ULL,
		0x1500800194600610ULL
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
		0x9839063D4226CB1EULL,
		0x5D1DC517A943EC0CULL,
		0xBCF509C2D65ECC7DULL,
		0x8B5AB84CC86AFEFEULL,
		0x3952A80A1CF5FA04ULL,
		0xF39D3C4604A9D9E0ULL,
		0xAA861D81D9DFF632ULL,
		0x5C2663771932045DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAFF26A784F7B8F3ULL,
		0x377FA014B0B43CC0ULL,
		0x320EC84BE4D88EE3ULL,
		0x9847F4246C365106ULL,
		0x98D0A1683DE270B8ULL,
		0x307AF7C4ADA8EF1EULL,
		0x6570290E797C6966ULL,
		0x6E4FDFECE3D92A7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9839062500268812ULL,
		0x151D8014A0002C00ULL,
		0x30040842C4588C61ULL,
		0x8842B00448225006ULL,
		0x1850A0081CE07000ULL,
		0x3018344404A8C900ULL,
		0x20000900595C6022ULL,
		0x4C0643640110005DULL
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
		0xD7905E8BA10DEC45ULL,
		0xC76B03F0EA37B967ULL,
		0x5C881FCB18D57360ULL,
		0xB07425A242522B14ULL,
		0x71DD4BED602C50CFULL,
		0x5E37EB51D6A1A951ULL,
		0x4ECD6F8B678080D1ULL,
		0x2A6E4EF3846361ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309B1383C986EFA0ULL,
		0x98A54324F22CA962ULL,
		0x4772DC128A0AB183ULL,
		0x12A0A41E44CE8EE4ULL,
		0xEFAB16E47726A77FULL,
		0x33B68A0477F6F31CULL,
		0x616A5126873CA8D2ULL,
		0x078C9B1511091BD1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x109012838104EC00ULL,
		0x80210320E224A962ULL,
		0x44001C0208003100ULL,
		0x1020240240420A04ULL,
		0x618902E46024004FULL,
		0x12368A0056A0A110ULL,
		0x40484102070080D0ULL,
		0x020C0A1100010180ULL
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
		0xF48E866F109126A7ULL,
		0x081510D7D51F2732ULL,
		0xA9C1EAC771E9C4FCULL,
		0x299030227F754CA0ULL,
		0x9BA8FBE0F987AB0BULL,
		0x9DD41BF8C97000CCULL,
		0xC89373137CD90378ULL,
		0x80F30BC759D23155ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2883D26B83FD9DCULL,
		0x8B57E5401EB6E8EBULL,
		0x8F96A15423C87FE6ULL,
		0x46E1081EA50108EFULL,
		0xCB1191A66A889EB7ULL,
		0x207509198F4793A0ULL,
		0xD68B41A118319E69ULL,
		0x62FDCBA7DFBFA301ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE088042610110084ULL,
		0x0815004014162022ULL,
		0x8980A04421C844E4ULL,
		0x00800002250108A0ULL,
		0x8B0091A068808A03ULL,
		0x0054091889400080ULL,
		0xC083410118110268ULL,
		0x00F10B8759922101ULL
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
		0xD10A359A2A9933BBULL,
		0x3DA414388DDB5732ULL,
		0x5A44601302B7BC16ULL,
		0xE064F8B255CD4C23ULL,
		0xA8696F1B8622C0ABULL,
		0x32ED85F39F57C6D1ULL,
		0x502C93897E38E0E3ULL,
		0xD9D1082EBB0FA084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11AF8CDE5BE6B257ULL,
		0xFCC965F3B55B2EF4ULL,
		0x20E7BF4BCD352BFEULL,
		0x8DA773FDD5944BB8ULL,
		0xCE06724B507E7C57ULL,
		0xE44F60DA711AD329ULL,
		0x4FFBD5347F3060AAULL,
		0x2E76D8D088AC8A96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x110A049A0A803213ULL,
		0x3C800430855B0630ULL,
		0x0044200300352816ULL,
		0x802470B055844820ULL,
		0x8800620B00224003ULL,
		0x204D00D21112C201ULL,
		0x402891007E3060A2ULL,
		0x08500800880C8084ULL
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
		0x9BF6F8A9FD73F33AULL,
		0x748EC7E807A63C02ULL,
		0x2AF2BFC4C9D329FCULL,
		0x1CC1D6997E94E0A0ULL,
		0x8AE2D60495E8D130ULL,
		0xC30CE08033829C21ULL,
		0x69F2A0B8B6E53E44ULL,
		0xF86FFBCAB517E1A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA07C723A6E7FBF23ULL,
		0x0CF89E31F1665399ULL,
		0x3132419664FF6BFBULL,
		0x2641C955B82C867BULL,
		0x42417F3C67F13D9CULL,
		0x215E2AC4B2CB69BDULL,
		0x745F1F5A1C43D505ULL,
		0x5C214888E77512E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x807470286C73B322ULL,
		0x0488862001261000ULL,
		0x2032018440D329F8ULL,
		0x0441C01138048020ULL,
		0x0240560405E01110ULL,
		0x010C208032820821ULL,
		0x6052001814411404ULL,
		0x58214888A51500A0ULL
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
		0x75CADDAD7311C986ULL,
		0x17C34013E01D188DULL,
		0x75013A9F4DA74A20ULL,
		0x6EBDE79F6A7CFE16ULL,
		0xC3BFC462A1062361ULL,
		0x6300E2DB82F25135ULL,
		0xB506C711B1535C18ULL,
		0x4D1EF198C3F75EACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9099F4A191844CAULL,
		0x06236B6F13A20555ULL,
		0x33781DBCF7B004F9ULL,
		0x137DAB18F9C13DDCULL,
		0x98CC0D361E0426D9ULL,
		0x14B1E95E2939758AULL,
		0x8ADC80D38E192BD4ULL,
		0xB2B324B54C10BBB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51089D0811104082ULL,
		0x0603400300000005ULL,
		0x3100189C45A00020ULL,
		0x023DA31868403C14ULL,
		0x808C042200042241ULL,
		0x0000E05A00305100ULL,
		0x8004801180110810ULL,
		0x0012209040101AA4ULL
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
		0xD70BD65FCDB7DB45ULL,
		0xBC89CBF5930181C7ULL,
		0x8FFDC745CB854EFFULL,
		0xAB4C4D5AFA07CF2AULL,
		0x1596DB0FADB08DDEULL,
		0xB49CB014723951A3ULL,
		0xE60D7E925CCC6CCAULL,
		0x125DBB902F2CC03BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20876384D68F1650ULL,
		0x07BFAAE26CA720AFULL,
		0xD2BF9EA8BE6A1104ULL,
		0x72A1B1CE9C6453A8ULL,
		0xAAACB37384E9DA2DULL,
		0x8F19C37581EF0871ULL,
		0xCE50ADC00029FC96ULL,
		0x11F7C4B73CBF0127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00034204C4871240ULL,
		0x04898AE000010087ULL,
		0x82BD86008A000004ULL,
		0x2200014A98044328ULL,
		0x0084930384A0880CULL,
		0x8418801400290021ULL,
		0xC6002C8000086C82ULL,
		0x105580902C2C0023ULL
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
		0xAA0FC052CCA5902CULL,
		0xBFB9D121B35AFB90ULL,
		0xABF39C4C0B93A025ULL,
		0xC2A29A1A7483DA54ULL,
		0xBB0E716DB0E1D8C2ULL,
		0xAA58BD5DC07EC6F3ULL,
		0x450F219218B9DB90ULL,
		0xB9873240D17A3B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38A6A421575E1E6BULL,
		0x06ECB3E2C17FAD09ULL,
		0xA328FBD2DC9E7D1EULL,
		0x484B3CFEACA92E90ULL,
		0x51A1DCB5D08FE7ECULL,
		0xE4552175575ABC01ULL,
		0xF32E218E4D384E72ULL,
		0xD19B503BA2B82740ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2806800044041028ULL,
		0x06A89120815AA900ULL,
		0xA320984008922004ULL,
		0x4002181A24810A10ULL,
		0x110050259081C0C0ULL,
		0xA0502155405A8401ULL,
		0x410E218208384A10ULL,
		0x9183100080382300ULL
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
		0xD07DC45B11F8922DULL,
		0xACDD3C96DA73AF00ULL,
		0x68D0387B9A742985ULL,
		0x3E96F13AA1E4B42CULL,
		0x1719166F50C14CF5ULL,
		0x5CE5456C42705819ULL,
		0x063D860321285F33ULL,
		0x2B3BFEEF024BD94AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DFE6686085A6E1BULL,
		0x9CCE7C7267FB3ACAULL,
		0x6C58EE207B74A0ECULL,
		0xAAC3E57112C8E9C6ULL,
		0x05E569B857C31C9BULL,
		0x6537DF847A19A7D1ULL,
		0x720B0FCB569D86C1ULL,
		0xABDE7B731A72DB0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x007C440200580209ULL,
		0x8CCC3C1242732A00ULL,
		0x685028201A742084ULL,
		0x2A82E13000C0A004ULL,
		0x0501002850C10C91ULL,
		0x4425450442100011ULL,
		0x0209060300080601ULL,
		0x2B1A7A630242D90AULL
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
		0x1DCD6BAC8115823FULL,
		0xB06B80915AB901ADULL,
		0xF8AEC032AC828FDDULL,
		0x67D39236DADD22B0ULL,
		0x3B9C33166E05FBD7ULL,
		0xB6046413B3A9FE02ULL,
		0x11604E469E3AAC11ULL,
		0xAE370A07B624E5CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA342591D643B2C9ULL,
		0x117B06B6208666BDULL,
		0x64D94B31EEBD1759ULL,
		0xDFEE5245DD386E8DULL,
		0xED018F08F97FF6F9ULL,
		0x4A9BC0B955A6A370ULL,
		0x9A3E4C6E0B0BA566ULL,
		0xB101F34E97956697ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0804218080018209ULL,
		0x106B0090008000ADULL,
		0x60884030AC800759ULL,
		0x47C21204D8182280ULL,
		0x290003006805F2D1ULL,
		0x0200401111A0A200ULL,
		0x10204C460A0AA400ULL,
		0xA001020696046485ULL
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
		0xA88EBD8CD2336FBDULL,
		0x65874E359A9433D0ULL,
		0x7A122C6F773AA91CULL,
		0x1FEC467BEAAD6F8AULL,
		0x9F15D3076D697C44ULL,
		0xC8007DBE6F87C611ULL,
		0xBED2976BEE5178B3ULL,
		0x086482EC9840E9F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC29D2910B890D56DULL,
		0x6D1946E174E472DFULL,
		0x7944CC096AD24EC6ULL,
		0x99675732D882F8A2ULL,
		0x90F3D2B25DA3A097ULL,
		0x7D8B1BFA9B92DD88ULL,
		0xBC126F9C563C229DULL,
		0x74CB779EFDE5AB10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x808C29009010452DULL,
		0x65014621108432D0ULL,
		0x78000C0962120804ULL,
		0x19644632C8806882ULL,
		0x9011D2024D212004ULL,
		0x480019BA0B82C400ULL,
		0xBC12070846102091ULL,
		0x0040028C9840A910ULL
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
		0x4B00E105B27590B7ULL,
		0x9FEB2F1FD2F748D2ULL,
		0xF917B1C7CE169D2DULL,
		0x20D6755E41C59D6BULL,
		0x3E2E89811C578F08ULL,
		0x2EF4FAA9DBB21602ULL,
		0xAC0D3CDF15C8590CULL,
		0x3544D687F388A0CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6B9F6AF3277B243ULL,
		0xD6EC025563F42ACEULL,
		0xAD82EA8DBA0F3855ULL,
		0x7378D2A52F61CA3FULL,
		0x6C3BF4F4C9302955ULL,
		0xB9936C70A3AF4CC3ULL,
		0xEBC794004A2011BCULL,
		0xF091034590B47E26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4200E00532759003ULL,
		0x96E8021542F408C2ULL,
		0xA902A0858A061805ULL,
		0x205050040141882BULL,
		0x2C2A808008100900ULL,
		0x2890682083A20402ULL,
		0xA80514000000110CULL,
		0x3000020590802006ULL
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
		0xF57CAD3EBA26E493ULL,
		0x601B704A7F5C7496ULL,
		0x28059332DC24B984ULL,
		0xC5BAE79BE2D80966ULL,
		0xADCB48983AB5000BULL,
		0x2EDC3430F43BF820ULL,
		0xB29DB5862653BDA2ULL,
		0x1C36DAB87B08704DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2FBBF33C42C438ULL,
		0x2E30F814EFD840BCULL,
		0x0A879E1DB33AF68FULL,
		0xC603BEA08D889117ULL,
		0x285AD55FFE896C28ULL,
		0x1F27EF8A691DFF01ULL,
		0x437B86B13EFAAC5DULL,
		0xD0B83D829A369EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x302CA9323802C410ULL,
		0x201070006F584094ULL,
		0x080592109020B084ULL,
		0xC402A68080880106ULL,
		0x284A40183A810008ULL,
		0x0E0424006019F800ULL,
		0x021984802652AC00ULL,
		0x103018801A001000ULL
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
		0x14D66E114985D227ULL,
		0x959F00BACB77A0E1ULL,
		0xF5D104A55A6C7E42ULL,
		0x7D2D57209E6D896BULL,
		0x4E29429C775978A2ULL,
		0x7B6548895BEA7FF9ULL,
		0x2C50A106DAEC17B1ULL,
		0x0CD3CC6182B6DE9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF32E2AA42EE63AF4ULL,
		0xD0821B4F1570E3C0ULL,
		0x3BBC5FCAF268F012ULL,
		0x2433B2A07576839EULL,
		0x12948EC11750D160ULL,
		0xBE419E97D75D6E12ULL,
		0x2D60E91DB9B1DD3CULL,
		0x8434FB24C60754E5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10062A0008841224ULL,
		0x9082000A0170A0C0ULL,
		0x3190048052687002ULL,
		0x242112201464810AULL,
		0x0200028017505020ULL,
		0x3A41088153486E10ULL,
		0x2C40A10498A01530ULL,
		0x0410C82082065480ULL
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
		0x01FCFDFB2DBDCBC2ULL,
		0x86C42E0D608FA2FFULL,
		0xCED45F3610A7F80BULL,
		0x9EE32062A6D36DEFULL,
		0x674DD2B4800321DDULL,
		0x3E348A17BAF04935ULL,
		0xFFB4AAAE2C3E7862ULL,
		0xDF74100EEC17D681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x633BAE6A440E3F9BULL,
		0xA270F986E509D4CEULL,
		0x538EC404589B4F62ULL,
		0xC057E1F01C2D4938ULL,
		0x4CB974EACD8E0DA5ULL,
		0x07E119DCA54E66D7ULL,
		0x9B75343DD9E78FD3ULL,
		0x9C63F4ED86364063ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0138AC6A040C0B82ULL,
		0x82402804600980CEULL,
		0x4284440410834802ULL,
		0x8043206004014928ULL,
		0x440950A080020185ULL,
		0x06200814A0404015ULL,
		0x9B34202C08260842ULL,
		0x9C60100C84164001ULL
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
		0xA8889D609AE0A37FULL,
		0xF450511178F5A9DCULL,
		0xD1FE7901798496D6ULL,
		0x114F265FE78CDD93ULL,
		0xA6B354B59DEF8FEAULL,
		0x81BF516E56BF0FC8ULL,
		0x9FEC90671E540F11ULL,
		0x9D19EDBE76D3D68DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE9B017C73A5A5EBULL,
		0x5D9923167568B0CEULL,
		0x971C7E7C8FABE5E4ULL,
		0x3938F1128126746DULL,
		0x8B9AD46AD6715EBFULL,
		0x6DB699546D5E49D1ULL,
		0x9809A41A437EE290ULL,
		0x6D947F148DCA1F12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA888016012A0A16BULL,
		0x541001107060A0CCULL,
		0x911C7800098084C4ULL,
		0x1108201281045401ULL,
		0x8292542094610EAAULL,
		0x01B61144441E09C0ULL,
		0x9808800202540210ULL,
		0x0D106D1404C21600ULL
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
		0x05CDDF0E5CE1DEC4ULL,
		0x3415451BABB5670AULL,
		0xF6515E5C2E80C15BULL,
		0xA052633538CC1592ULL,
		0x3E7EC8A290E2B7BAULL,
		0xDB105D7058B00B42ULL,
		0xB0E69B5B06486CDBULL,
		0xE18697297F70BA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x962666A935B395B7ULL,
		0xDAF8C71A5EE6296FULL,
		0x631AD18DD4F318E2ULL,
		0x9CF36A422058DE2EULL,
		0x2046128DBE6BB8A4ULL,
		0x50E2553677437AFBULL,
		0x3C61EA4D9B92215EULL,
		0x83CCD27C0BEC1AC8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0404460814A19484ULL,
		0x1010451A0AA4210AULL,
		0x6210500C04800042ULL,
		0x8052620020481402ULL,
		0x204600809062B0A0ULL,
		0x5000553050000A42ULL,
		0x30608A490200205AULL,
		0x818492280B601A00ULL
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
		0x1E2EA21EEF25F270ULL,
		0x18E51A80EA40B6DEULL,
		0x7280424774DA4BF7ULL,
		0xDEFBC137EF42588EULL,
		0x26A1956456DDFC72ULL,
		0x0DC100153181B7B5ULL,
		0xC6B5DDFF211D32A3ULL,
		0x922B94B5DD0C3CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DA27426B4363320ULL,
		0xB291B33F60626DD0ULL,
		0xAF9CAA4BD269133CULL,
		0xBC5881A20E279788ULL,
		0xA27B45B52CB283F9ULL,
		0x7919C53219429DE4ULL,
		0xE5F08939668FDF0DULL,
		0x084D2BDA22E8CC6FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C222006A4243220ULL,
		0x10811200604024D0ULL,
		0x2280024350480334ULL,
		0x9C5881220E021088ULL,
		0x2221052404908070ULL,
		0x09010010110095A4ULL,
		0xC4B08939200D1201ULL,
		0x0009009000080C21ULL
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
		0xBF748C02657A48A9ULL,
		0x278A502A1D06092FULL,
		0xDDAD6AFC505E1C69ULL,
		0x72D481A7B467645BULL,
		0xFA65FFAA688C7D79ULL,
		0x4DCC7856B87B697CULL,
		0xD5CA78F5CEA78D29ULL,
		0x2A308944FC3FDD62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8CE2BF912B10497ULL,
		0xFD575E0631FC350AULL,
		0x06CAE2361DCC8134ULL,
		0x8260DAF0ED86DD05ULL,
		0xD9F814BB8DD60F68ULL,
		0x7F78DFAB218B6A5EULL,
		0x2BDE03114F6F389CULL,
		0x295B05A1468B152DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9844080000300081ULL,
		0x250250021104010AULL,
		0x04886234104C0020ULL,
		0x024080A0A4064401ULL,
		0xD86014AA08840D68ULL,
		0x4D485802200B685CULL,
		0x01CA00114E270808ULL,
		0x28100100440B1520ULL
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
		0x7D12F0EA4CBF13C0ULL,
		0x5BC320A6E28D9683ULL,
		0xB2F6AC390450D8AAULL,
		0xB744128F57492289ULL,
		0xD2C8C9EBAC5212F9ULL,
		0xA259D1369B47BBF4ULL,
		0x729D4546D0881853ULL,
		0x5D085E36C26EA43DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A8B5B4A4A42E221ULL,
		0x9A383C9A6D843BFCULL,
		0xACF1DA4D9EAFC925ULL,
		0xA8F1B7E893D46BE9ULL,
		0xC3965E753F5C008DULL,
		0xD9C7B4996AED1D8BULL,
		0x59870326D091B8FDULL,
		0xA9C5E1BCE3E1F704ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5802504A48020200ULL,
		0x1A00208260841280ULL,
		0xA0F088090400C820ULL,
		0xA040128813402289ULL,
		0xC28048612C500089ULL,
		0x804190100A451980ULL,
		0x50850106D0801851ULL,
		0x09004034C260A404ULL
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
		0x5A45BF98C61FFEADULL,
		0xE77322792CC584B8ULL,
		0x28A69DD039C6E278ULL,
		0xC9A0C018DA11D703ULL,
		0xD68CE4697C0BE534ULL,
		0xE7EB0B526D418F1FULL,
		0x11B931209642AD66ULL,
		0xDD13F5CD06AF8804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37EA9FF131D3EA11ULL,
		0x0789FF458A31A905ULL,
		0xE17476483FDFD0E5ULL,
		0x4C55CAFF6DDF7D07ULL,
		0xBABFB719B136B225ULL,
		0xC3A6C4854EAF6369ULL,
		0xC5C1E7EF38EC3643ULL,
		0x09771AE4DD796924ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12409F900013EA01ULL,
		0x0701224108018000ULL,
		0x2024144039C6C060ULL,
		0x4800C01848115503ULL,
		0x928CA4093002A024ULL,
		0xC3A200004C010309ULL,
		0x0181212010402442ULL,
		0x091310C404290804ULL
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
		0xC51946967811EF9AULL,
		0xB69F11834EF8CF18ULL,
		0xA82F8AFCA41116AEULL,
		0xF1E3B0812D5EAC79ULL,
		0x4BB2398769557498ULL,
		0xE2AA18B959B84A80ULL,
		0xFF854628396FBC82ULL,
		0x3816ECE961A5ED08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x759A91D11ACF4A1FULL,
		0x572623DB7C9D5054ULL,
		0xB4B6145F19118832ULL,
		0x4CB0D85DCF6C3B2BULL,
		0x34A17E5390BF0F84ULL,
		0xEFA99A8B8596EF86ULL,
		0xB3371899E2A2477EULL,
		0xA6243F0AA77EF8C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4518009018014A1AULL,
		0x160601834C984010ULL,
		0xA026005C00110022ULL,
		0x40A090010D4C2829ULL,
		0x00A0380300150480ULL,
		0xE2A8188901904A80ULL,
		0xB305000820220402ULL,
		0x20042C082124E800ULL
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
		0x43098246E6979DCEULL,
		0xDB8618E550C2B406ULL,
		0x951C4BB1FECFC5E9ULL,
		0x366A372E4CC44F2EULL,
		0xB7932DEC5616D1CAULL,
		0x5CC44AD20EE3357FULL,
		0x99261A90AFA11979ULL,
		0x6107E90BE86A33DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E30B6DEF4422B29ULL,
		0x53A7AA3FEFD588E5ULL,
		0x719049588CD9162DULL,
		0x08CD09258164A9F5ULL,
		0x9DAB178561288131ULL,
		0x1B4E6B069B6C4D23ULL,
		0x7E22BBEDEA433A14ULL,
		0x645C908F91102DD0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02008246E4020908ULL,
		0x5386082540C08004ULL,
		0x111049108CC90429ULL,
		0x0048012400440924ULL,
		0x9583058440008100ULL,
		0x18444A020A600523ULL,
		0x18221A80AA011810ULL,
		0x6004800B800021D0ULL
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
		0x779FC8D67CC6817AULL,
		0x928AB88E4AC2CBE1ULL,
		0x3ADFBC37DCC5BB3CULL,
		0xC525DF9689FC3262ULL,
		0xBCA22AFE432DF62FULL,
		0xA4B609D56FCFAC76ULL,
		0x3D7E9E66864B354AULL,
		0xB702BF3A62826BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D62A72F5AAF022ULL,
		0x0977A20BAC842C85ULL,
		0x9F8F07F78A64B24CULL,
		0xE5E0AB4A5B1792BCULL,
		0x671197DC7DEE816EULL,
		0x35AB9BA3DA82F676ULL,
		0x59845BB0E9B399DBULL,
		0xA230D068ABD6081AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7396085274828022ULL,
		0x0002A00A08800881ULL,
		0x1A8F04378844B20CULL,
		0xC5208B0209141220ULL,
		0x240002DC412C802EULL,
		0x24A209814A82A476ULL,
		0x19041A208003114AULL,
		0xA200902822820812ULL
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
		0xB96AA4C014CB317CULL,
		0xC8FB73E54F5C1B56ULL,
		0x0AE713862C51FCECULL,
		0xEFBD3257E94B0280ULL,
		0xD1EE9462571440BDULL,
		0x5C51329BBD271900ULL,
		0xFF355D84461F3D2DULL,
		0x62E5987CC0F3FC99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DE56D171F1A4B72ULL,
		0x2967C8909DA5B82EULL,
		0xB1D3FEF15047B170ULL,
		0xDEF788C2236EB011ULL,
		0x8E791A52C2D24A1EULL,
		0x8D1DD7FD15B6F214ULL,
		0x00A8CDBF90D9FD7CULL,
		0x13BD174E1B43B90BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09602400140A0170ULL,
		0x086340800D041806ULL,
		0x00C312800041B060ULL,
		0xCEB50042214A0000ULL,
		0x806810424210401CULL,
		0x0C11129915261000ULL,
		0x00204D8400193D2CULL,
		0x02A5104C0043B809ULL
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
		0xDE9CBEEC1DC9F6FAULL,
		0x73B534D076384DBDULL,
		0x86D7C70DA61F0F20ULL,
		0xFD5073868877FDF6ULL,
		0x85D8A6D6914FD84FULL,
		0x1C5925AC576DB739ULL,
		0xC7250E7210BD5867ULL,
		0x8D59B48B120BCFEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE351BCB317D2FCFDULL,
		0x54B37BD17021786BULL,
		0x202781698574E24AULL,
		0x29DF26A06C5EDC89ULL,
		0x64913096AF646AA1ULL,
		0xD68E78023850D625ULL,
		0xDC134CC0256D391FULL,
		0x57CCF38D74B2B653ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC210BCA015C0F4F8ULL,
		0x50B130D070204829ULL,
		0x0007810984140200ULL,
		0x295022800856DC80ULL,
		0x0490209681444801ULL,
		0x1408200010409621ULL,
		0xC4010C40002D1807ULL,
		0x0548B08910028643ULL
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
		0x0A23FA44ABB10AD1ULL,
		0xE3EAD793C5378A7CULL,
		0xCD147E349ABE3DC2ULL,
		0x13DC904B3F6763F5ULL,
		0xC87C91C118BEBE47ULL,
		0xA241CA337A9CDD60ULL,
		0x780DD16B68CFBD40ULL,
		0xA57C60A5326225DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AD79A7D9935BE4ULL,
		0x5B0B27533C187D9CULL,
		0xEF78A5F985E69BC9ULL,
		0x159B2D15A2BF4B62ULL,
		0x616A1530929D9381ULL,
		0x574799D46A0A493AULL,
		0x4510B15636B5EF15ULL,
		0xA21E19C9C59E15DFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0821780489910AC0ULL,
		0x430A07130410081CULL,
		0xCD10243080A619C0ULL,
		0x1198000122274360ULL,
		0x40681100109C9201ULL,
		0x024188106A084920ULL,
		0x400091422085AD00ULL,
		0xA01C0081000205DDULL
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
		0x3DB15BBB32E999B0ULL,
		0x3FD6C983788FB882ULL,
		0x777AA943B8E5AABCULL,
		0x7D584B78F97A5EC4ULL,
		0x1073E4B074F6AEA3ULL,
		0x901768E4E3805EA0ULL,
		0xC466DB21C7889FCAULL,
		0x40C2E72FA03C4880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719EE94F022109ADULL,
		0x4BE7B710D6C2E1E0ULL,
		0x786B3BB092DB965AULL,
		0x88844011AF8A7A83ULL,
		0x1DD4440719D089F5ULL,
		0xA6393553EB227F48ULL,
		0x8F931E83B12FC272ULL,
		0x0CD5F942F20CCFF6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3190490B022109A0ULL,
		0x0BC681005082A080ULL,
		0x706A290090C18218ULL,
		0x08004010A90A5A80ULL,
		0x1050440010D088A1ULL,
		0x80112040E3005E00ULL,
		0x84021A0181088242ULL,
		0x00C0E102A00C4880ULL
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
		0xEA966D0C0B156FAFULL,
		0xE10A6FCD11059451ULL,
		0xA0A3DF3425D79CF7ULL,
		0x0BBD14791E648C1DULL,
		0x732D128EBEEF2B6CULL,
		0x2972F4A28BE85D27ULL,
		0xA5575FB2A5B02EAAULL,
		0x7D89600602EC696AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9636EEE4A414F363ULL,
		0xD90335D26EE12FD1ULL,
		0xC0A2D4981263D363ULL,
		0x7D6E7486B7827BDAULL,
		0xA327240467C9B771ULL,
		0x95FADB93F1DCB74FULL,
		0x3C286182BA4E7D67ULL,
		0x763FD5B57AD59AD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82166C0400146323ULL,
		0xC10225C000010451ULL,
		0x80A2D41000439063ULL,
		0x092C140016000818ULL,
		0x2325000426C92360ULL,
		0x0172D08281C81507ULL,
		0x24004182A0002C22ULL,
		0x7409400402C40848ULL
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
		0x7C92DC73DDB59CFEULL,
		0x03BE0F7F2721A63FULL,
		0xEDB33232F124260EULL,
		0x6C2CF9CBCA9C43FCULL,
		0xD03CC21520B4ACFFULL,
		0xD5959EB17A5D3DA5ULL,
		0xBC75E4E300A1F859ULL,
		0xB536DE04CCA81587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4A2865F3BA03026ULL,
		0xE79C947EAE592476ULL,
		0x5314B04C26D1BD53ULL,
		0x69AF0C36EB79C4C8ULL,
		0x18211D5CC7CD7B67ULL,
		0x74494C3A48AA5363ULL,
		0x6C564F5D060578C1ULL,
		0x80292D6A68E6FF9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3482845319A01026ULL,
		0x039C047E26012436ULL,
		0x4110300020002402ULL,
		0x682C0802CA1840C8ULL,
		0x1020001400842867ULL,
		0x54010C3048081121ULL,
		0x2C54444100017841ULL,
		0x80200C0048A01587ULL
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
		0x27969B4BD1948452ULL,
		0x79EC63C0CF3C880DULL,
		0x63498642F9964331ULL,
		0x01D10A463EF953E7ULL,
		0x8E19C264A96F421CULL,
		0x037FB93214C398EAULL,
		0x890567B09B90F237ULL,
		0xC21BF2CB78E777DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AD0CC73EEFB620ULL,
		0x0D3BB152715C139FULL,
		0x3B088B6B7F8F8E25ULL,
		0x696FBE89C64902F8ULL,
		0x1FA07F2F4670720DULL,
		0x3F55A27F213872BFULL,
		0x617DBFDFF5B598D2ULL,
		0x0BC89EE329D9519DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2484084310848400ULL,
		0x09282140411C000DULL,
		0x2308824279860221ULL,
		0x01410A00064902E0ULL,
		0x0E0042240060420CULL,
		0x0355A032000010AAULL,
		0x0105279091909012ULL,
		0x020892C328C1519CULL
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
		0x417807681DF2CD6DULL,
		0xECAE64C72B37905EULL,
		0xDC2253F3C4328220ULL,
		0x2CD7950145BEDE00ULL,
		0x600C9AC51A349CCFULL,
		0x56010C62A1E185CAULL,
		0xE2370301248B6203ULL,
		0xF66DA5F5850BE33DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C074FC9EB33595ULL,
		0x9E9CF85CFAECCE11ULL,
		0x4EF5E0123F91C1D3ULL,
		0xDB6E3D69C72F8538ULL,
		0xA88A39FF12DE1F47ULL,
		0x7589651A61F2F900ULL,
		0x58D60282350D905FULL,
		0x284AFECC9F0E25AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x014004681CB20505ULL,
		0x8C8C60442A248010ULL,
		0x4C20401204108000ULL,
		0x08461501452E8400ULL,
		0x200818C512141C47ULL,
		0x5401040221E08100ULL,
		0x4016020024090003ULL,
		0x2048A4C4850A2128ULL
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
		0x88FDF0C1F913756DULL,
		0x59FEBA97133EDFEBULL,
		0x4E5EF29788404805ULL,
		0x82A41A0249816084ULL,
		0xCB884E2A00C72C24ULL,
		0x1065247DE229B0B9ULL,
		0x9589F65FFF9C4AB0ULL,
		0xE90697AAC43E7E63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8ACCDCA3D56BDCULL,
		0xEFD2E2D173334CBFULL,
		0x879E7BB5BC9F63E8ULL,
		0xA25AD172736FEED3ULL,
		0x94F663AB316E6830ULL,
		0x86CDE587A7E66F4FULL,
		0x63EC921129D7724EULL,
		0x80877983C5D73B77ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0888C0C0A111614CULL,
		0x49D2A29113324CABULL,
		0x061E729588004000ULL,
		0x8200100241016080ULL,
		0x8080422A00462820ULL,
		0x00452405A2202009ULL,
		0x0188921129944200ULL,
		0x80061182C4163A63ULL
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
		0x2507F47011CA9808ULL,
		0x7A18ADB69D5EAF5EULL,
		0xF146D8C19A634ACFULL,
		0x07135DF3C96069E7ULL,
		0x68F28AB234EAC930ULL,
		0x305219D43685205EULL,
		0x6A0E32F65AEDF507ULL,
		0xBE0861E7B5798AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51BAD545FA673B7AULL,
		0x37A543B1F9B6C800ULL,
		0xA4B5CD5A32B541E0ULL,
		0xFE42508EFB86F81DULL,
		0x7868DB1A4E2AC497ULL,
		0x489430BCC642EAE7ULL,
		0xB48AE958CF5FD195ULL,
		0x4904C3B5A10E3626ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0102D44010421808ULL,
		0x320001B099168800ULL,
		0xA004C840122140C0ULL,
		0x06025082C9006805ULL,
		0x68608A12042AC010ULL,
		0x0010109406002046ULL,
		0x200A20504A4DD105ULL,
		0x080041A5A1080220ULL
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
		0xD9198538D08BB32BULL,
		0xD9A08B89E8CDF239ULL,
		0xE4D7144DDBA7138DULL,
		0x0AD1A8D29CFB85B3ULL,
		0xE7E9CAEB8D988050ULL,
		0x0F40D1526BABCBD6ULL,
		0xBCEDD545D0F965E2ULL,
		0xD8265E4B5E243A9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D91780704AFD0BULL,
		0x543380FB8D761649ULL,
		0xF23886E6F6B6B3BAULL,
		0x10AA66CEE356D873ULL,
		0x0E0EE61197B4DA8BULL,
		0xEC56449F8F444C68ULL,
		0x4E720A89FC3742B1ULL,
		0x9C008071A2BBED0FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81190500500AB10BULL,
		0x5020808988441209ULL,
		0xE0100444D2A61388ULL,
		0x008020C280528033ULL,
		0x0608C20185908000ULL,
		0x0C4040120B004840ULL,
		0x0C600001D03140A0ULL,
		0x980000410220280BULL
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
		0x1F30123A40208E82ULL,
		0x5F319821E61545CAULL,
		0xC00F8301BEF1CC41ULL,
		0x5F328A563536A525ULL,
		0x7D229C0F12707C8FULL,
		0x5BB15ADC434DBE50ULL,
		0xDA874F4C3A05C5C8ULL,
		0xCD587827342328C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D2425F140174D0ULL,
		0xC59D47F54A431932ULL,
		0x14A574D01C360D80ULL,
		0xF8C2C08AD03FAF04ULL,
		0x090ED607B938C420ULL,
		0xB870133239C13D77ULL,
		0x55BF45237423C7BDULL,
		0x82CE7EA33E0C2383ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0710021A00000480ULL,
		0x4511002142010102ULL,
		0x000500001C300C00ULL,
		0x580280021036A504ULL,
		0x0902940710304400ULL,
		0x1830121001413C50ULL,
		0x508745003001C588ULL,
		0x8048782334002083ULL
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
		0xEBCE413C40AB1732ULL,
		0xEBA4A75C2142D1B8ULL,
		0x48A60F8B77FDCACDULL,
		0x616B514BA518DDE9ULL,
		0x5AFDBCB142B0E4F5ULL,
		0x661E07419B1B7048ULL,
		0x1162D2FAAC215AF8ULL,
		0x28BA8F8A76B51BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61EB6970CEE7EFCDULL,
		0xA3E2F85F7A6A6FCFULL,
		0xC0BA8EA8FE06770CULL,
		0x7FA40EACABE6A92DULL,
		0xFC219CFD9A577D7AULL,
		0x0178EEB8915ECAF8ULL,
		0x5E562BAD97920950ULL,
		0x998D79750A3E7331ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x61CA413040A30700ULL,
		0xA3A0A05C20424188ULL,
		0x40A20E887604420CULL,
		0x61200008A1008929ULL,
		0x58219CB102106470ULL,
		0x00180600911A4048ULL,
		0x104202A884000850ULL,
		0x0888090002341331ULL
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
		0x6F77B49F735E28B8ULL,
		0x50D15E5057B046C8ULL,
		0xB100A88BFED65184ULL,
		0x4ED7EA829240F638ULL,
		0xAF50821E64218C84ULL,
		0x207E7FC63EFD607EULL,
		0x233537742AD08234ULL,
		0x2B4F7E7224737455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0730A3D50E6D970CULL,
		0x0907A265F97CA0F6ULL,
		0x87B5DA04069B1E08ULL,
		0xFF9DC90C403FA81AULL,
		0x48330F1EA7562025ULL,
		0xFFB1A33D191D2B0EULL,
		0xB1114B8A86B63E69ULL,
		0x872EFDE02DCA4275ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0730A095024C0008ULL,
		0x00010240513000C0ULL,
		0x8100880006921000ULL,
		0x4E95C8000000A018ULL,
		0x0810021E24000004ULL,
		0x20302304181D200EULL,
		0x2111030002900220ULL,
		0x030E7C6024424055ULL
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
		0x7BAFF1B3DE773B31ULL,
		0x0C6DBBE9D6AF6DD3ULL,
		0xCA4DC232B89429D1ULL,
		0xA7D17CDF2DAC31B3ULL,
		0x0EEE70CA8C609288ULL,
		0x35C7A6195946D51FULL,
		0x91450A646787331DULL,
		0x1E35F51BED4BF88BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F8C898367D2844ULL,
		0x944BE33D35D6CEF9ULL,
		0xE21427427B2A2384ULL,
		0x091B89C7707989CAULL,
		0x00A8C642FB2812C0ULL,
		0xB98C1FEB8FD769DEULL,
		0x0714836AC161027CULL,
		0xF42F01465E85C32AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02A8C09016752800ULL,
		0x0449A32914864CD1ULL,
		0xC204020238002180ULL,
		0x011108C720280182ULL,
		0x00A8404288201280ULL,
		0x318406090946411EULL,
		0x010402604101021CULL,
		0x142501024C01C00AULL
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
		0x33E11B9FDD39FD0DULL,
		0xFD8FA28DDCCE1EAEULL,
		0xB9C397DABCA1792EULL,
		0xEAA00390DE0EF5C8ULL,
		0xF564556CE53BCB06ULL,
		0x4816397564DFDAE8ULL,
		0xD541F2D4F20D6E61ULL,
		0x93FE2BF4BD94BBA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7756D53DBB0E9C73ULL,
		0x480BD2263F1C66BEULL,
		0x326AEDEA715DD1D5ULL,
		0x65FA70639D3E9B52ULL,
		0x5EBE1E40FE07A8FFULL,
		0x090FCA9A9E176F35ULL,
		0xEFE52511BD63A2E9ULL,
		0xB7979FAC29D42F45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3340111D99089C01ULL,
		0x480B82041C0C06AEULL,
		0x304285CA30015104ULL,
		0x60A000009C0E9140ULL,
		0x54241440E4038806ULL,
		0x0806081004174A20ULL,
		0xC5412010B0012261ULL,
		0x93960BA429942B05ULL
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
		0x8E5A795929E9E955ULL,
		0xECD30C47F68747D9ULL,
		0x12BAF6D6E92D1079ULL,
		0x35C5E35BDBEFC4F7ULL,
		0x5148124518CE43F8ULL,
		0x3D92CB523279339FULL,
		0x9067BA5BE1D8933EULL,
		0x3537A6F7F747A80DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD90A9B543927DAULL,
		0x101DF6B15153186AULL,
		0xAD67126A5668190AULL,
		0x5724FEA243D28490ULL,
		0x9D31F647A3BEA1EDULL,
		0x6E86D4D9395C80C9ULL,
		0xB927A2875E0FEB6EULL,
		0x290CB21EA8899584ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8E58081900292150ULL,
		0x0011040150030048ULL,
		0x0022124240281008ULL,
		0x1504E20243C28490ULL,
		0x11001245008E01E8ULL,
		0x2C82C05030580089ULL,
		0x9027A2034008832EULL,
		0x2104A216A0018004ULL
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
		0x250ECC5FA717736DULL,
		0x2BFB8205EF53F5A9ULL,
		0xBFDA0ACD9B1B00C8ULL,
		0x948D081BC6D695ACULL,
		0x6E7513E8775C209BULL,
		0xD92EDF1623A2DF37ULL,
		0x1AB0DB5CBBF752C6ULL,
		0xDFD559954B3ACBCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x943F80CF77E7DA8CULL,
		0x48DB1A8207F1AAF5ULL,
		0x50CCFFA18B381E43ULL,
		0x7FC317497C2E6FEFULL,
		0x5859A95AA8711070ULL,
		0x5848747C82BA347BULL,
		0x2E55C487E9AC009CULL,
		0x91827E806E2DCC24ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040E804F2707520CULL,
		0x08DB02000751A0A1ULL,
		0x10C80A818B180040ULL,
		0x14810009440605ACULL,
		0x4851014820500010ULL,
		0x5808541402A21433ULL,
		0x0A10C004A9A40084ULL,
		0x918058804A28C804ULL
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
		0x92EAA9DA2D0E1C7FULL,
		0xF9185E81E10475DBULL,
		0xBB2BAA1A10ED7653ULL,
		0xE213EB04EB107522ULL,
		0x31393893D93304F9ULL,
		0xA3E8F1AB222AF6BAULL,
		0xFCFAF077BA1D13FBULL,
		0xE10359A5F2168530ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8673C9F2EE7311E0ULL,
		0xD5C776AE7C29C624ULL,
		0x9CA801C61325BE22ULL,
		0x4236053B1AC747C5ULL,
		0x30C6D8F14A9EC17CULL,
		0x75A1496AC4BA36A1ULL,
		0x385C5039E70DC95BULL,
		0x8EDB1AEE42B28D36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x826289D22C021060ULL,
		0xD100568060004400ULL,
		0x9828000210253602ULL,
		0x421201000A004500ULL,
		0x3000189148120078ULL,
		0x21A0412A002A36A0ULL,
		0x38585031A20D015BULL,
		0x800318A442128530ULL
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
		0xE5E0AAE3DD22A8CEULL,
		0xB20BA3F96F075533ULL,
		0x7EEAED67298CE4A6ULL,
		0x6122707971A7110CULL,
		0xBC0B5B0FC3973B02ULL,
		0x0AA46AEB66368BB8ULL,
		0xB68EA6D32696044AULL,
		0x8D120C5A36055635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD73137D6379E6FC1ULL,
		0x6BCB417A4BA4B629ULL,
		0x37AE011E9645B1C4ULL,
		0xAB9814D7670221BBULL,
		0x497AEFA730F1C6F6ULL,
		0x64A2FC12827A3795ULL,
		0x66B41810ED24CC91ULL,
		0x9BB00102879CCB6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC52022C2150228C0ULL,
		0x220B01784B041421ULL,
		0x36AA01060004A084ULL,
		0x2100105161020108ULL,
		0x080A4B0700910202ULL,
		0x00A0680202320390ULL,
		0x2684001024040400ULL,
		0x8910000206044220ULL
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
		0x6A97D5785BF78472ULL,
		0x2CC595AEEF3140B7ULL,
		0xB94AC4DADB98A4EFULL,
		0x7DC2B1DDF2CA01E0ULL,
		0x10A004356890A640ULL,
		0x403739A43A82F403ULL,
		0x979AC10A748C422AULL,
		0x19341609DA8880EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31B4A0B4A301231CULL,
		0x008B0E265B82DB1FULL,
		0x809509B99CDF5A72ULL,
		0xC18BD4C2525E7313ULL,
		0xEED16A506149C86BULL,
		0x8C8541BCFAC57587ULL,
		0x68B2AA91AE5030D2ULL,
		0x1D6AD1132C8FDC15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2094803003010010ULL,
		0x008104264B004017ULL,
		0x8000009898980062ULL,
		0x418290C0524A0100ULL,
		0x0080001060008040ULL,
		0x000501A43A807403ULL,
		0x0092800024000002ULL,
		0x1920100108888001ULL
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
		0x390D18FC5EC88B8FULL,
		0x7FA8170DD3579789ULL,
		0x544D4B247B89B843ULL,
		0xFDA591689C651C40ULL,
		0x8C3D8CC6817328A4ULL,
		0xB540C0ABD6B3DB5EULL,
		0x07E0EAC9034CBF40ULL,
		0x85DD639C26CB192CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x616E6A5A52D7F7E6ULL,
		0x94B1740131F52456ULL,
		0x65FE65E59874B4C3ULL,
		0x0A40AEA319B0A71DULL,
		0x226EAD6C26773235ULL,
		0xF8B3BD5F3CFCA866ULL,
		0xD9EACCFA7B03B255ULL,
		0x8402C5E46AC3A60CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x210C085852C08386ULL,
		0x14A0140111550400ULL,
		0x444C41241800B043ULL,
		0x0800802018200400ULL,
		0x002C8C4400732024ULL,
		0xB000800B14B08846ULL,
		0x01E0C8C80300B240ULL,
		0x8400418422C3000CULL
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
		0xB17A3051E2E976F3ULL,
		0xEBCB54A0E306D804ULL,
		0x2B20C3F36DB9BF93ULL,
		0x1E8EC3B6709C2930ULL,
		0x30385ED0B5B4CAF2ULL,
		0xCCFAC9636F2710FAULL,
		0xE63B1144D9880ADEULL,
		0x248E048DB9D04C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C5B68C4C3EC48D4ULL,
		0x1CE2A3C33B7FAA26ULL,
		0xDA4D4B27F9F17CD3ULL,
		0x67F3E831CB690420ULL,
		0xFCE6A00425DA3150ULL,
		0x6F7E06FC9DD42511ULL,
		0x40786929B1335CBFULL,
		0x9F6847B9848BF7B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x905A2040C2E840D0ULL,
		0x08C2008023068804ULL,
		0x0A00432369B13C93ULL,
		0x0682C03040080020ULL,
		0x3020000025900050ULL,
		0x4C7A00600D040010ULL,
		0x403801009100089EULL,
		0x0408048980804420ULL
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
		0x74969374E9921618ULL,
		0xA71D2A9E8E73CE28ULL,
		0x255DF6969B9F867DULL,
		0x44C73C83B185260AULL,
		0xB4414895CF9369ECULL,
		0x1FF7996A4269B0D7ULL,
		0x80C5CE83735AFDB2ULL,
		0x29979A514300C144ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE9676E0594FCB3ULL,
		0x650281D5A04BE9AFULL,
		0xC4EDCC8E56359E6EULL,
		0xFE6D71E93821873CULL,
		0xF419C3CC5EE298E9ULL,
		0x778033C82BC5762CULL,
		0x8814CC33A4F48FCCULL,
		0x2AE957ADD9CECAF0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7080036401901410ULL,
		0x250000948043C828ULL,
		0x044DC4861215866CULL,
		0x4445308130010608ULL,
		0xB40140844E8208E8ULL,
		0x1780114802413004ULL,
		0x8004CC0320508D80ULL,
		0x288112014100C040ULL
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
		0x8AE13F6ACD9EA25DULL,
		0xEF65030549EE9A26ULL,
		0x6346F131B34C62DEULL,
		0xE7BDC86024F3E169ULL,
		0x891E8FC2497D750BULL,
		0x93D64D4348EB5934ULL,
		0x84F10D95FE4320A1ULL,
		0x11F43C064B50C65DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x177A83AFE48325F2ULL,
		0x812EDBDD6AB41705ULL,
		0x2E6439B432BEAD09ULL,
		0xB2A1A385C352AC49ULL,
		0x40DB6882E2AEACB4ULL,
		0xBF0FD5D7A31E8094ULL,
		0xBDCF21B001BBF214ULL,
		0x620F0C934AE4AC7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0260032AC4822050ULL,
		0x8124030548A41204ULL,
		0x22443130320C2008ULL,
		0xA2A180000052A049ULL,
		0x001A0882402C2400ULL,
		0x93064543000A0014ULL,
		0x84C1019000032000ULL,
		0x00040C024A408458ULL
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
		0xEEACC6BD55F3F215ULL,
		0x04B800E821DD9552ULL,
		0x5FC7A0E0A760F6BCULL,
		0xDDBB1005B9CD2593ULL,
		0xCA52F8DFE0ABB119ULL,
		0x96BC2EF301B0E631ULL,
		0xED98DE05B315F775ULL,
		0xE735A423B069FEB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61DA8CA2C17F4A88ULL,
		0xD8B8A2B1208B1BDAULL,
		0x97C4B3FA0E5ED5F8ULL,
		0xFBCED4B2C069FA5CULL,
		0x86E70FE9C5734A88ULL,
		0x4F02BEB2A402B900ULL,
		0xCE32D930DD781D26ULL,
		0xD7BC5D7A319A5D4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x608884A041734200ULL,
		0x00B800A020891152ULL,
		0x17C4A0E00640D4B8ULL,
		0xD98A100080492010ULL,
		0x824208C9C0230008ULL,
		0x06002EB20000A000ULL,
		0xCC10D80091101524ULL,
		0xC734042230085C02ULL
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
		0x6BB125DB2CAC69BAULL,
		0xA1ABDBC6C7E3D4AEULL,
		0x05FC5BF1C96CAB54ULL,
		0x0E1F4D838760484AULL,
		0x9A92DFB0C8DE3800ULL,
		0x8500B5B8EF4538FCULL,
		0x4CA8742A63A5DF24ULL,
		0x155E9CB9A2E1FFFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9C775051CE01F1AULL,
		0x382E7CBB14E67CD1ULL,
		0xD4988F91FCDC1390ULL,
		0xEBA22655AB07B353ULL,
		0x60334F672666A0C6ULL,
		0x9F3E30D53DEAC53AULL,
		0x658507DCC3DA31C9ULL,
		0x1F76801004FF31B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x498125010CA0091AULL,
		0x202A588204E25480ULL,
		0x04980B91C84C0310ULL,
		0x0A02040183000042ULL,
		0x00124F2000462000ULL,
		0x850030902D400038ULL,
		0x4480040843801100ULL,
		0x1556801000E131B2ULL
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
		0x64A2A370F14F12E8ULL,
		0x91587C020337C157ULL,
		0x5D62AA9ACB2B9849ULL,
		0x00D6368DD91314CBULL,
		0x1D11C2E196AA938CULL,
		0xEBAED848A987F1B9ULL,
		0xC702275E01B1D2A3ULL,
		0xBA8FBC7EC7DF57B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B33615E0BA932F9ULL,
		0xD6B1FB73CEC698C8ULL,
		0x01F498B983B469FDULL,
		0xBCBC34696224D651ULL,
		0xA43CA652E1731FA4ULL,
		0x17554FCEE02780D2ULL,
		0xDFD6D73CAFA72B9AULL,
		0x1DB2D5FE7553A4B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00222150010912E8ULL,
		0x9010780202068040ULL,
		0x0160889883200849ULL,
		0x0094340940001441ULL,
		0x0410824080221384ULL,
		0x03044848A0078090ULL,
		0xC702071C01A10282ULL,
		0x1882947E455304B1ULL
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
		0xB14DBAD52F170EAEULL,
		0x75E3E3AB35BF0BBDULL,
		0x5CCF9822DE83CDFFULL,
		0x23FEA4AB2391D0B8ULL,
		0x9E7B121CCDD36B88ULL,
		0xE4C1745C8761B58AULL,
		0x209263578A0625F4ULL,
		0x5347F9FF11E12DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0541A0C36FC56218ULL,
		0xA6B69C5C54FD424CULL,
		0xE73A71FA464935DBULL,
		0x7B6E3BC9C0FFE2C9ULL,
		0x090ABD45165E10CAULL,
		0x350CAA353CD1D9E7ULL,
		0xBA92D28FD5FEB9F2ULL,
		0x1747A63C3AB493ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0141A0C12F050208ULL,
		0x24A2800814BD020CULL,
		0x440A1022460105DBULL,
		0x236E20890091C088ULL,
		0x080A100404520088ULL,
		0x2400201404419182ULL,
		0x20924207800621F0ULL,
		0x1347A03C10A00180ULL
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
		0x382E2588FE48180EULL,
		0x46B888017A519C15ULL,
		0x6CD770C70CD20589ULL,
		0x83965F9FBA3D32D2ULL,
		0x02CDF0960FBB3D1CULL,
		0x6F74C8AA24E0D821ULL,
		0xF53B000F71813003ULL,
		0x6CEA510BFDE20596ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ACCA4612BD2A601ULL,
		0x8DBE90F243C3CEA7ULL,
		0xC01C91B19BBEA381ULL,
		0x15585BE20EE16BF0ULL,
		0x0B0991A60395E099ULL,
		0xF28BD96AF2138488ULL,
		0x661F9CA363E7677BULL,
		0x24B26D132D20E783ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080C24002A400000ULL,
		0x04B8800042418C05ULL,
		0x4014108108920181ULL,
		0x01105B820A2122D0ULL,
		0x0209908603912018ULL,
		0x6200C82A20008000ULL,
		0x641B000361812003ULL,
		0x24A241032D200582ULL
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
		0x81227C1D294E2096ULL,
		0x94366BBA4FBCE4B7ULL,
		0x2011BC6335371361ULL,
		0x9EA17448517ECA3DULL,
		0xCB19433171092083ULL,
		0x5A2F9F5DF7919A5AULL,
		0xB3AC2636DC78EE18ULL,
		0xC510BFE50F5467F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA74977B18BB76E6DULL,
		0x9166A0784293CB6FULL,
		0xC3ED683B3306CC14ULL,
		0x28D44C56FA4D8C4BULL,
		0x57C54B442C1A1399ULL,
		0xBAC234053C3C3E2CULL,
		0xC4358EF7C276FEA8ULL,
		0x704FA343C0BD92B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8100741109062004ULL,
		0x902620384290C027ULL,
		0x0001282331060000ULL,
		0x08804440504C8809ULL,
		0x4301430020080081ULL,
		0x1A02140534101A08ULL,
		0x80240636C070EE08ULL,
		0x4000A341001402B2ULL
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
		0x258ACDF9029A52CCULL,
		0x28B94A5B79D409E2ULL,
		0xC40B141AA68FD0CDULL,
		0x8134D7BE3755B39DULL,
		0x86423186FA78AC5CULL,
		0xCA6C609CC7CE976BULL,
		0xA370A09BFB502A77ULL,
		0xFF92E759142F47B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DEC024F40ED50B5ULL,
		0x049E6FA568BEF487ULL,
		0x376173E747DBF1D6ULL,
		0xB8551496EE8AD5B5ULL,
		0x35A1CE7B5C79F1B4ULL,
		0x280D8FAD9D55969BULL,
		0x9E08085C58A22D4DULL,
		0x687F1B5FE1543CDAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0588004900885084ULL,
		0x00984A0168940082ULL,
		0x04011002068BD0C4ULL,
		0x8014149626009195ULL,
		0x040000025878A014ULL,
		0x080C008C8544960BULL,
		0x8200001858002845ULL,
		0x6812035900040490ULL
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
		0x9154D77C9E7D0410ULL,
		0x11DC135119B8A6A4ULL,
		0x9BB38F231322871DULL,
		0x53B03FBFAAE487D4ULL,
		0x28B17F5BD1D20FDFULL,
		0xB2D59EDC76DBA167ULL,
		0x12DD62FC7EFFC7E8ULL,
		0xDC63CF5F12B230B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA898D06EC179F2ULL,
		0xCC0D87C5404E31CFULL,
		0xBCAB7D86A412EF75ULL,
		0xF5C09590EBA3EA65ULL,
		0xAD2D06ADDEA1508FULL,
		0xAF9EE13A27DA5952ULL,
		0x6E2E902612CC2C36ULL,
		0xA394185F7F82D5CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x810090500E410010ULL,
		0x000C034100082084ULL,
		0x98A30D0200028715ULL,
		0x51801590AAA08244ULL,
		0x28210609D080008FULL,
		0xA294801826DA0142ULL,
		0x020C002412CC0420ULL,
		0x8000085F12821082ULL
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
		0x8E2E35B2B80164B9ULL,
		0x59129282D89E87A0ULL,
		0xA94B364E73E65333ULL,
		0x0CEE37859C353714ULL,
		0x68F4954BFABC7B61ULL,
		0xB53E599A925E65F2ULL,
		0x64F48A1A19ECE841ULL,
		0xB1B291BE5175C670ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EBFB9997E560E70ULL,
		0x83089353E9A19636ULL,
		0x110E54C789664074ULL,
		0x92F034D34A8EA246ULL,
		0x51C2688CB26BD3D5ULL,
		0xC412302506EB90B3ULL,
		0x4C4CB9B68A191AFEULL,
		0x061F13DC67FE0767ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E2E319038000430ULL,
		0x01009202C8808620ULL,
		0x010A144601664030ULL,
		0x00E0348108042204ULL,
		0x40C00008B2285341ULL,
		0x84121000024A00B2ULL,
		0x4444881208080840ULL,
		0x0012119C41740660ULL
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
		0x6A9D2AEC218A7B4CULL,
		0x5286A074D4BA7834ULL,
		0x15167B35515C2565ULL,
		0x026269D798C02EADULL,
		0x27AD73F8C40EF7F5ULL,
		0x908CD75E9EB7BC98ULL,
		0x8495107848DA9F04ULL,
		0x744F1A3D542A58CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC41F06CF22A3EC45ULL,
		0x03A09A783B9B2B4CULL,
		0x01BE2FBA959F03E9ULL,
		0x2091A810F37877D4ULL,
		0x92018B3E09DE56A0ULL,
		0xED8A5822C2AEB71CULL,
		0xDF2220BBBE9D2238ULL,
		0x512BB42853EFECECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401D02CC20826844ULL,
		0x02808070109A2804ULL,
		0x01162B30111C0161ULL,
		0x0000281090402684ULL,
		0x02010338000E56A0ULL,
		0x8088500282A6B418ULL,
		0x8400003808980200ULL,
		0x500B1028502A48CCULL
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
		0xD9DBC76B056868AEULL,
		0x5F6441BA2D0630C1ULL,
		0xF49740B9745B7261ULL,
		0xCF655FB9950E5F17ULL,
		0x6C344B0974EC1A54ULL,
		0xF2ECEEDF50789D2FULL,
		0xD4182A851A2C5134ULL,
		0x379392C603257188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83AB7D35BF4C7807ULL,
		0xEB8A0FDB13F20EABULL,
		0x4F2469F519A0C2C7ULL,
		0xCE49B0B7772657ADULL,
		0x1A46FEEE9FCB490DULL,
		0x549805DFF55A77DFULL,
		0x6BEF73C61FD36752ULL,
		0xD740C07E96413BBBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x818B452105486806ULL,
		0x4B00019A01020081ULL,
		0x440440B110004241ULL,
		0xCE4110B115065705ULL,
		0x08044A0814C80804ULL,
		0x508804DF5058150FULL,
		0x400822841A004110ULL,
		0x1700804602013188ULL
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
		0xC6DA2728366F1246ULL,
		0x6ED5CB28289BA859ULL,
		0xBD862B9B2ED40526ULL,
		0xC570E6A99E48B348ULL,
		0x1953AD8FAFB81D10ULL,
		0x9DB82BE3B3FCBD70ULL,
		0x0BF765B7878D2621ULL,
		0x23A0A1DFF8CD842AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C733AC517091F0DULL,
		0x299E341533D99E7AULL,
		0xBE1C879C2EF5F332ULL,
		0x111BCE8E966199D0ULL,
		0x36E55BDE55A6D8ECULL,
		0x2F37AC2508605D42ULL,
		0xE66C8DD629578BC9ULL,
		0x31B9ED169B7B6C26ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0452220016091204ULL,
		0x2894000020998858ULL,
		0xBC0403982ED40122ULL,
		0x0110C68896409140ULL,
		0x1041098E05A01800ULL,
		0x0D30282100601D40ULL,
		0x0264059601050201ULL,
		0x21A0A11698490422ULL
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
		0x6875965BA10FDACEULL,
		0x0A6EE211F9FF2653ULL,
		0xCC9D10442F9D93B2ULL,
		0xB10CB659EB79FC75ULL,
		0x0A86C3E9781E24C6ULL,
		0x2F27E2FA8D438D4EULL,
		0x22DE0D1EBE45FD6FULL,
		0x6E7A84069B44BA77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CB00147077B15B3ULL,
		0x7F46272C7FEDB0F9ULL,
		0xD878B3A69CDF5A75ULL,
		0x413244833C78D7B6ULL,
		0xCC7927978C54F4FBULL,
		0x2E8405C96C9190E6ULL,
		0x052FF4BBFD8DA37BULL,
		0x61C05E7BACFAD839ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08300043010B1082ULL,
		0x0A46220079ED2051ULL,
		0xC81810040C9D1230ULL,
		0x010004012878D434ULL,
		0x08000381081424C2ULL,
		0x2E0400C80C018046ULL,
		0x000E041ABC05A16BULL,
		0x6040040288409831ULL
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
		0xF64DEF5445FF4332ULL,
		0x24DD4BA1DECEA985ULL,
		0x27B5368980701BB8ULL,
		0xA914EE0684C8D355ULL,
		0xE2E1C4F7C3E04F80ULL,
		0xF96DA59C69B4471FULL,
		0x52499847D93700CCULL,
		0x26123364FF8FA548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB42F3970E535397ULL,
		0xACAFD8CE086161D8ULL,
		0xFAF62FE74F93BFB7ULL,
		0x6664F0C3A9815CBAULL,
		0xA0BB772A0E7A33AEULL,
		0x8E464F4597C2EE9BULL,
		0xA0705908FADF3155ULL,
		0x9ABC25593ADC0C5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA240E31404534312ULL,
		0x248D488008402180ULL,
		0x22B4268100101BB0ULL,
		0x2004E00280805010ULL,
		0xA0A1442202600380ULL,
		0x884405040180461BULL,
		0x00401800D8170044ULL,
		0x021021403A8C0448ULL
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
		0x2F01B86676D4B7E6ULL,
		0x4862CEFD97A73C24ULL,
		0x68EF9A0C2AB337F6ULL,
		0xE987B9180D06273FULL,
		0x1E01C1A88B90A997ULL,
		0xF9DBDF781C1D1249ULL,
		0xC4912CBA6FCE231AULL,
		0x6B5ADF4FF6E330EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD364C1BAF69E3C0BULL,
		0x7CAAC1658F4E111BULL,
		0xCAE5594C971817F1ULL,
		0x6FEE4FF17C67F5C9ULL,
		0x41A7603C897980F5ULL,
		0x51ED3C98D4E69404ULL,
		0xF531D3C519F6B5A4ULL,
		0x7D73C7372805D9FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0300802276943402ULL,
		0x4822C06587061000ULL,
		0x48E5180C021017F0ULL,
		0x698609100C062509ULL,
		0x0001402889108095ULL,
		0x51C91C1814041000ULL,
		0xC411008009C62100ULL,
		0x6952C707200110EEULL
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
		0xC003145D5B6D0A13ULL,
		0xA8727A0EDACD5542ULL,
		0x8A18C1C37153FBA3ULL,
		0x06668A0F8FC0A82FULL,
		0x8108D840E60AF46CULL,
		0xD2DF2D5AC091B094ULL,
		0x71ECFB050728DBA2ULL,
		0x1C285F27B6230239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74E49EF3681F0FBFULL,
		0x1B92CC116D926E4CULL,
		0x281A9AFDFE49DA36ULL,
		0xBBFE21E731E848ABULL,
		0xE01143181E8505C8ULL,
		0x9983C2263C0E3551ULL,
		0xD273085A018BB00FULL,
		0xC4968C34201365D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40001451480D0A13ULL,
		0x0812480048804440ULL,
		0x081880C17041DA22ULL,
		0x0266000701C0082BULL,
		0x8000400006000448ULL,
		0x9083000200003010ULL,
		0x5060080001089002ULL,
		0x04000C2420030019ULL
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
		0x9AC151B4B5739EB9ULL,
		0xE5E536B803D90632ULL,
		0x06C1B51BF913C18BULL,
		0xD54224FFF0472754ULL,
		0x328A23D39973825EULL,
		0x5C97D79068501B6BULL,
		0x1FD6BAD76C45E90BULL,
		0x8D3BEC51AA9347E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE43015EBB664E64AULL,
		0x03722B0F847C8598ULL,
		0x961FAA2F25E936EFULL,
		0xA51839C7A7DD2164ULL,
		0xA03D8A5C6C50FD67ULL,
		0x3D2D68C2FAD403A6ULL,
		0x1803855CB3E627A2ULL,
		0x6ABFD7AE4A3E1E98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x800011A0B4608608ULL,
		0x0160220800580410ULL,
		0x0601A00B2101008BULL,
		0x850020C7A0452144ULL,
		0x2008025008508046ULL,
		0x1C05408068500322ULL,
		0x1802805420442102ULL,
		0x083BC4000A120680ULL
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
		0x7243FFF2127615CEULL,
		0x50760037E4010296ULL,
		0x09C69E0CB645DA1FULL,
		0x7D7565B9619332E8ULL,
		0xFA7289B3C7CCBBF8ULL,
		0xAA898974B09FF35FULL,
		0x2E6F99281BD8D2E0ULL,
		0x54FD9CF73D18D5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87041E13E4E555D2ULL,
		0x14C87362329EB320ULL,
		0x006AB7B86517EB3AULL,
		0x9664997B5B800CC9ULL,
		0x4123BB4A93AA781DULL,
		0xBC48BD16857D68F1ULL,
		0x4C44851378FDE8D0ULL,
		0x3D56649807F6D41EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02001E12006415C2ULL,
		0x1040002220000200ULL,
		0x004296082405CA1AULL,
		0x14640139418000C8ULL,
		0x4022890283883818ULL,
		0xA8088914801D6051ULL,
		0x0C44810018D8C0C0ULL,
		0x145404900510D412ULL
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
		0x4B6E7427D7235056ULL,
		0x59A841CF0ED96A5BULL,
		0x6B33E4609CBB822AULL,
		0x008CE8111BBD6DCBULL,
		0x1A95395143C8DBEDULL,
		0xC6599D194A250F21ULL,
		0xC7C1DEFEFBB93AE7ULL,
		0x01AE03B4D11426CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F1211FADD6E7F31ULL,
		0x733BD50EEFB2EEFCULL,
		0x9890A08BC5CDDD13ULL,
		0x95C1EE1C36118AF1ULL,
		0xD0C76C7EFE8F5573ULL,
		0x6386E3F55A885078ULL,
		0xC447D106FAB7F6DEULL,
		0x02E03BCD8E0471DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B021022D5225010ULL,
		0x5128410E0E906A58ULL,
		0x0810A00084898002ULL,
		0x0080E810121108C1ULL,
		0x1085285042885161ULL,
		0x420081114A000020ULL,
		0xC441D006FAB132C6ULL,
		0x00A00384800420C8ULL
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
		0xDD1B136A3365C7ECULL,
		0xBF1631521FE9FEC9ULL,
		0xD8D16516635EA4C7ULL,
		0xE6A01B7BF50D731FULL,
		0xBA0888C00FC86482ULL,
		0xAD3FF433CEAB84F3ULL,
		0xEA7BDB215A8B404BULL,
		0xF31465CF99AC4150ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0706EFFC5160FFB3ULL,
		0xFDF01DA368C02182ULL,
		0xF1AEBBD04AEF8B18ULL,
		0x0B7CD7C4CEDC3576ULL,
		0x911A6FC94B2417DDULL,
		0x37D05BC2DDFCE657ULL,
		0x27AD437DB04AE7A3ULL,
		0x8FCD1740A445900EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050203681160C7A0ULL,
		0xBD10110208C02080ULL,
		0xD0802110424E8000ULL,
		0x02201340C40C3116ULL,
		0x900808C00B000480ULL,
		0x25105002CCA88453ULL,
		0x22294321100A4003ULL,
		0x8304054080040000ULL
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
		0xFF9CEC55BB5FA44DULL,
		0x483912B41AD10F30ULL,
		0x718176F5AFDF92F5ULL,
		0x2DF12D7BE507EBFEULL,
		0x1469BF7DF64881DEULL,
		0xFF5A4992D5EC2E48ULL,
		0xBC67E6F40D7FA74EULL,
		0x865D221E641B6682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x441CF9CECCC64DBFULL,
		0x6109B04FE3D1478BULL,
		0x0A20E4488648215BULL,
		0x83BC712E07A48147ULL,
		0xA832B400B49FD0BEULL,
		0xD7B9B778416F5A34ULL,
		0xACD27B3E38FF22BBULL,
		0xA5E5220A15AD8981ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x441CE8448846040DULL,
		0x4009100402D10700ULL,
		0x0000644086480051ULL,
		0x01B0212A05048146ULL,
		0x0020B400B408809EULL,
		0xD7180110416C0A00ULL,
		0xAC426234087F220AULL,
		0x8445220A04090080ULL
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
		0x7F9A8CB397917F03ULL,
		0x44D1A4F4B198EF81ULL,
		0xB6FA9C3A629D2ED3ULL,
		0x74E8D44695832FD2ULL,
		0xD841674EDFA9B1E1ULL,
		0x1DA8E14600D4CC41ULL,
		0xAC5472148573B023ULL,
		0x1C8FA457647E3FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F23479BCCF1B2C7ULL,
		0x36560CF1A8E1D68BULL,
		0xFA2E9CC46490176FULL,
		0x92A4440D727DF58CULL,
		0xC1224374A674E9FAULL,
		0x42F04AB013E92961ULL,
		0x0E4FD544894CA980ULL,
		0x6CE1C1619227D044ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6F02049384913203ULL,
		0x045004F0A080C681ULL,
		0xB22A9C0060900643ULL,
		0x10A0440410012580ULL,
		0xC00043448620A1E0ULL,
		0x00A0400000C00841ULL,
		0x0C4450048140A000ULL,
		0x0C81804100261044ULL
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
		0x844F0E59E0D3C4BDULL,
		0x1636AC8426E3F635ULL,
		0xE4D109A9B47DA169ULL,
		0x6456111EA0F8F146ULL,
		0xD08AA219F131EDE7ULL,
		0x0692A5FA701DC315ULL,
		0x5FB213EC44E45C56ULL,
		0x40E4E56DE255B9F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F975EF4681B17BBULL,
		0x93B9F9B97707AE45ULL,
		0x9AFA7FF194A2D063ULL,
		0x3890AFB75AC29F6FULL,
		0xD4AB7A1B8FDF494DULL,
		0x8C8C8AF9A78DD94DULL,
		0xA4133A4A45962300ULL,
		0xC353640DDFDB6CA7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04070E50601304B9ULL,
		0x1230A8802603A605ULL,
		0x80D009A194208061ULL,
		0x2010011600C09146ULL,
		0xD08A221981114945ULL,
		0x048080F8200DC105ULL,
		0x0412124844840000ULL,
		0x4040640DC25128A0ULL
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
		0xE729836E44086C84ULL,
		0xC14721D06041A3B9ULL,
		0x7A6BCCA58454AA42ULL,
		0xC8A9B20BDB01BA41ULL,
		0xC8EC039EABBFA007ULL,
		0x7407FE05ECA124BCULL,
		0x57383A71B329556EULL,
		0xBA5CAA434B228F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA92C534403B43D87ULL,
		0x8B3F324B62BB07EFULL,
		0x12751B74982216DFULL,
		0xF7CAA19E0FF89E59ULL,
		0x9489217DD85068EEULL,
		0xD7C27D72B9CF2A89ULL,
		0x3A41C23DFB3A727DULL,
		0xA78869833641B608ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA128034400002C84ULL,
		0x81072040600103A9ULL,
		0x1261082480000242ULL,
		0xC088A00A0B009A41ULL,
		0x8088011C88102006ULL,
		0x54027C00A8812088ULL,
		0x12000231B328506CULL,
		0xA208280302008600ULL
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
		0xD8A7359C5039E0BBULL,
		0x774017B416EDD434ULL,
		0x2763966A13870F91ULL,
		0xA3B2325CF16AFF63ULL,
		0x6CA639EA266B0555ULL,
		0xB64AAD915D273A00ULL,
		0x98C24AA4A8D41688ULL,
		0x0DD4D3419F824EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28FAFF07B779A407ULL,
		0xC1620FEC24867F3BULL,
		0x10DBCC0069EA1312ULL,
		0x3626A49F492F60A2ULL,
		0x678A68DD419B42FFULL,
		0x58ED67CF03A40D60ULL,
		0xF3199BB2BF4541B4ULL,
		0xF98C4ECCF35D348AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08A235041039A003ULL,
		0x414007A404845430ULL,
		0x0043840001820310ULL,
		0x2222201C412A6022ULL,
		0x648228C8000B0055ULL,
		0x1048258101240800ULL,
		0x90000AA0A8440080ULL,
		0x0984424093000480ULL
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
		0xB6F29033EE35EF37ULL,
		0x053511F962551908ULL,
		0xB1E3A8F90C2D2CDEULL,
		0x22CE717182826CF4ULL,
		0xD46CFB2796E6790FULL,
		0x98C3723C9A4ACEBAULL,
		0x7277D439CBD9AE7FULL,
		0xA12C1DF7CCD01413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3604844CD4D0BCB7ULL,
		0xC74509C5716857B6ULL,
		0xE73223F87093D496ULL,
		0x34A998AB94FDCBC6ULL,
		0xD962C661F1EB6217ULL,
		0x7DD8A27EB5BEEEC0ULL,
		0xACE534752293F041ULL,
		0x08A04B9C244F4650ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x36008000C410AC37ULL,
		0x050501C160401100ULL,
		0xA12220F800010496ULL,
		0x20881021808048C4ULL,
		0xD060C22190E26007ULL,
		0x18C0223C900ACE80ULL,
		0x206514310291A041ULL,
		0x0020099404400410ULL
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
		0xB7D120FC21237A8CULL,
		0xA6AFCFC70A452E25ULL,
		0x3143A7A8B27B4F24ULL,
		0xD42252CDED5EB841ULL,
		0x5DF6F0464AFA119CULL,
		0x020A0300786042D5ULL,
		0x40F771AA4573D571ULL,
		0xC14B63F5D81FEC92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38BFDCB8CAF1C2D7ULL,
		0xA67CD6DE722CD2DBULL,
		0x7016DD08008BBE71ULL,
		0xCEECFF0D77765E6BULL,
		0x363FC1666D2C8EC2ULL,
		0x002B09BCC22604E6ULL,
		0xDD68F9FD9E34EFE7ULL,
		0xB9E59120A49D67BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x309100B800214284ULL,
		0xA62CC6C602040201ULL,
		0x30028508000B0E20ULL,
		0xC420520D65561841ULL,
		0x1436C04648280080ULL,
		0x000A0100402000C4ULL,
		0x406071A80430C561ULL,
		0x81410120801D6492ULL
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
		0xE0D7E4C4BB1D31CCULL,
		0x0B650272020D0A9AULL,
		0xAC91CBA618FF8092ULL,
		0x8051960CCF5C8A54ULL,
		0x6443CAFD136C813DULL,
		0xB505840F0D3E802FULL,
		0xBCCF79D5286A69A2ULL,
		0xAFD6F3B1CA73A54CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x319D6AE081731BA4ULL,
		0xF240C0328C928607ULL,
		0x174003AAC23E5348ULL,
		0xEFE0BD1FEB83A532ULL,
		0xA702F09C023DFC74ULL,
		0x37178BC15E96694EULL,
		0xADF4A1442F39B591ULL,
		0x10EAAC45FAB69652ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x209560C081111184ULL,
		0x0240003200000202ULL,
		0x040003A2003E0000ULL,
		0x8040940CCB008010ULL,
		0x2402C09C022C8034ULL,
		0x350580010C16000EULL,
		0xACC4214428282180ULL,
		0x00C2A001CA328440ULL
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
		0x9D85BD6D76609909ULL,
		0xDDAB75DB1A651062ULL,
		0x475E9302C82B7D54ULL,
		0xE1DC552D50F89009ULL,
		0xA34E8AA5B6234A3BULL,
		0xE03CEB710EE6775CULL,
		0x4A0220F1726C11D7ULL,
		0xEE67DAF1EAE4B431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC46AA0BFA3DD0C5AULL,
		0x238C08482441E54EULL,
		0x62AEE516CDA1994AULL,
		0x37C58808693B8B04ULL,
		0xDB917F2D37BE3669ULL,
		0xF5FFF70190589505ULL,
		0x28D085449DE26CE3ULL,
		0xDB8C5606728159F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8400A02D22400808ULL,
		0x0188004800410042ULL,
		0x420E8102C8211940ULL,
		0x21C4000840388000ULL,
		0x83000A2536220229ULL,
		0xE03CE30100401504ULL,
		0x08000040106000C3ULL,
		0xCA04520062801030ULL
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
		0x888DF9F2E667D1E3ULL,
		0xCE72A89BB82F9D1AULL,
		0xB905B4C9CAA88A03ULL,
		0xD1F852EA8E5B5785ULL,
		0xB66AFAF955869FA3ULL,
		0xE587FE8CE00B51A9ULL,
		0x6D92C8F4EB500EDFULL,
		0x4BE0C324EEE75756ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E6CFF361CFA9EF0ULL,
		0x4B6E0054261EEF22ULL,
		0x95806B879C73B1C3ULL,
		0xD68DBA9FB2115FE3ULL,
		0xFF574B9B3BF97EB3ULL,
		0x62B41408F44839FAULL,
		0xAB80C7E7B152F92DULL,
		0xE11554CA8C30D88EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x080CF932046290E0ULL,
		0x4A620010200E8D02ULL,
		0x9100208188208003ULL,
		0xD088128A82115781ULL,
		0xB6424A9911801EA3ULL,
		0x60841408E00811A8ULL,
		0x2980C0E4A150080DULL,
		0x410040008C205006ULL
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
		0xF76A832935AE3043ULL,
		0x0B8114F1A195DF29ULL,
		0x7FDE4D25253B56BDULL,
		0xDD4E16BB92529DC7ULL,
		0x731EB5420E304505ULL,
		0x7ABF0D94FFC1ABEDULL,
		0x494C7F5BEC030632ULL,
		0x87B182E6A2EED8E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6059D7D77A01C98ULL,
		0x12B03A4F23B4B47EULL,
		0x26CB681E158C97D8ULL,
		0xE414FA642D0DF834ULL,
		0xCCD872DFFC12A1C0ULL,
		0x1A797E4C55A25B4BULL,
		0x240821FD8F3D11FCULL,
		0x564A10CFAF655A00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE600812935A01000ULL,
		0x0280104121949428ULL,
		0x26CA480405081698ULL,
		0xC404122000009804ULL,
		0x401830420C100100ULL,
		0x1A390C0455800B49ULL,
		0x000821598C010030ULL,
		0x060000C6A2645800ULL
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
		0x6EBC4871BB43F998ULL,
		0x58101F364D1685D4ULL,
		0x0BFF1D544ADF61CFULL,
		0x6358E16DB54FF253ULL,
		0x1D0CBF57B1502115ULL,
		0x5055BD14F82E5A06ULL,
		0xF4A35C54CFA97A4FULL,
		0xF0CAF8899DA20BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0F6D06BF49B8611ULL,
		0xAA805A13522B947BULL,
		0xFEF5777BD57BFC5FULL,
		0x7FD0CEF5201DAB77ULL,
		0xD169943C2920F2DAULL,
		0x44F4975B5953271BULL,
		0x34C2B22328DAE4D4ULL,
		0xE369E5C977D99287ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60B44061B0038010ULL,
		0x08001A1240028450ULL,
		0x0AF51550405B604FULL,
		0x6350C065200DA253ULL,
		0x1108941421002010ULL,
		0x4054951058020202ULL,
		0x3482100008886044ULL,
		0xE048E08915800287ULL
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
		0xB2C9B3EE848E78EBULL,
		0xC0800ABB018071F1ULL,
		0xD0F4A4BD7DDA8C25ULL,
		0x76462033AA550186ULL,
		0xCD98CA53EC60E0D4ULL,
		0xD5917697C01183BBULL,
		0xE0D6C85E0DE09EF5ULL,
		0xA5AF2D8429635D91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7505868AA9FCFE9ULL,
		0xC74419C9662FA8FCULL,
		0xF16D37447B4A84E4ULL,
		0x7375B7D3F03083B0ULL,
		0xA0E661B0AABE2A35ULL,
		0xC6D8F4DBA05C21B5ULL,
		0x2724DABA7D493C41ULL,
		0x677A69FA3F6397A0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2401068808E48E9ULL,
		0xC0000889000020F0ULL,
		0xD0642404794A8424ULL,
		0x72442013A0100180ULL,
		0x80804010A8202014ULL,
		0xC4907493801001B1ULL,
		0x2004C81A0D401C41ULL,
		0x252A298029631580ULL
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
		0x50579AB6EC30EC6AULL,
		0x8514B1687D66F65FULL,
		0x217E7E4F08F18650ULL,
		0x5355B63E36E3CBF9ULL,
		0x72C2579A6E1A8BB5ULL,
		0x21F821643B31BF2AULL,
		0xED365EF41B444929ULL,
		0x52F064318EB6891DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2F0E6C691B120E1ULL,
		0xC1F1DF733CE12BADULL,
		0xB062EDF75F352881ULL,
		0xE835BD27C09CA7D3ULL,
		0x11399CDF6C2E3112ULL,
		0x196997E76367B021ULL,
		0x381F1C4A60083FA4ULL,
		0xEB554E207A85E4D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5050828680302060ULL,
		0x811091603C60220DULL,
		0x20626C4708310000ULL,
		0x4015B426008083D1ULL,
		0x1000149A6C0A0110ULL,
		0x016801642321B020ULL,
		0x28161C4000000920ULL,
		0x425044200A848010ULL
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
		0xA3824F1895BAE9B8ULL,
		0x0653FF0D1B5BE768ULL,
		0x142F1B33B19A182DULL,
		0xAF9CA19606DDFED0ULL,
		0xDD9AB33B2358B077ULL,
		0x45844C62A8C51098ULL,
		0xF3610B872C5EFAB7ULL,
		0xF6713509F9C99680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAB6958CA1C40CB0ULL,
		0xB7986D6C81A401EDULL,
		0xE53D8C43B82F9D27ULL,
		0x9DF85BCEA93B23EEULL,
		0x6148BE91B42182BAULL,
		0x610C44C5292C591AULL,
		0x02B67097431632EFULL,
		0xD51DB88DAB08A990ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2820508818008B0ULL,
		0x06106D0C01000168ULL,
		0x042D0803B00A1825ULL,
		0x8D980186001922C0ULL,
		0x4108B21120008032ULL,
		0x4104444028041018ULL,
		0x02200087001632A7ULL,
		0xD4113009A9088080ULL
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
		0xB5EFF710BBDE95ABULL,
		0xB14533126E231E84ULL,
		0x2432FC96544CDBA2ULL,
		0xF7EE1E9835DA0C4BULL,
		0x32A6547E71DEB365ULL,
		0x4BC0417C39EC8082ULL,
		0x06CF43B1371BD51AULL,
		0xF2CB6405AEC1C206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213934A453EC0941ULL,
		0x83187F0534B73BE5ULL,
		0xD866F3EC70DD8A4EULL,
		0x6767B4339653B161ULL,
		0xE44ED526DC75A158ULL,
		0xF37F2F9D1C1B6FE5ULL,
		0x0A5D81EE689045FCULL,
		0x3C867593038548D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2129340013CC0101ULL,
		0x8100330024231A84ULL,
		0x0022F084504C8A02ULL,
		0x6766141014520041ULL,
		0x200654265054A140ULL,
		0x4340011C18080080ULL,
		0x024D01A020104518ULL,
		0x3082640102814000ULL
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
		0x8561E2C0F3346947ULL,
		0xDBB4041DFDD31EB8ULL,
		0x6FAF287376106981ULL,
		0x7CE4E86988D6B132ULL,
		0x35F8D66D56F0BF94ULL,
		0xCD3C1DA965568C45ULL,
		0xC5C37B10D1CE77BEULL,
		0xDFB77F8F227A49B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61908CC08CDC8CDFULL,
		0xB9992DEF8D842561ULL,
		0x0E6C51786FA74173ULL,
		0xD67813CD1B60456CULL,
		0x297F1FCDD14848E2ULL,
		0x4AF7D8324D03ED5EULL,
		0xD7448C7A573B7150ULL,
		0x10527FD89D4F4A5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x010080C080140847ULL,
		0x9990040D8D800420ULL,
		0x0E2C007066004101ULL,
		0x5460004908400120ULL,
		0x2178164D50400880ULL,
		0x4834182045028C44ULL,
		0xC5400810510A7110ULL,
		0x10127F88004A4813ULL
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
		0x132334009C74A173ULL,
		0xEF5F1749D7FAA310ULL,
		0x0847D0099D8FAAC1ULL,
		0x9B869FE0FE769A34ULL,
		0x9B18878B48320096ULL,
		0xDA8047D7A9D496D6ULL,
		0xFB754DB878CB297FULL,
		0x56E02A8C55AF62F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1B9298B3E5E6CE1ULL,
		0xD75CA725895CE3CFULL,
		0xE8EEAF739B1F546DULL,
		0xEE907C19F21FAFB4ULL,
		0x3D2D1AE89DBEA439ULL,
		0x3C49E6DB4D7307BAULL,
		0xAB416C744743E63EULL,
		0x28500492224B246FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x112120001C542061ULL,
		0xC75C07018158A300ULL,
		0x08468001990F0041ULL,
		0x8A801C00F2168A34ULL,
		0x1908028808320010ULL,
		0x180046D309500692ULL,
		0xAB414C304043203EULL,
		0x00400080000B2066ULL
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
		0x2C00545187D9DEDFULL,
		0x1D9F3E1F445580A8ULL,
		0x04BCFC0D35B51424ULL,
		0x713EEE5FFCC38AB4ULL,
		0x6BF0075896C872B7ULL,
		0xD4E5E08150BB0056ULL,
		0xE33160EF30CA61EDULL,
		0x4CAB071CDCA52B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5A758C613AFFE81ULL,
		0x1B92E7DB05391A37ULL,
		0x8F2DC45D4251C89AULL,
		0x0A1471754FB466F7ULL,
		0x1A63DF4DE1993301ULL,
		0xCFDD78516A6FAC6DULL,
		0x1156BF0EA116E075ULL,
		0x3630CE5B74B32206ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040050400389DE81ULL,
		0x1992261B04110020ULL,
		0x042CC40D00110000ULL,
		0x001460554C8002B4ULL,
		0x0A60074880883201ULL,
		0xC4C56001402B0044ULL,
		0x0110200E20026065ULL,
		0x0420061854A12202ULL
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
		0x96580EF72AEEEFF6ULL,
		0xC73BEC17E46335EDULL,
		0xD359832EBCDABF77ULL,
		0xBF45FB08E3520C02ULL,
		0x1804D8CF001521CBULL,
		0x03D3F2A01164CA29ULL,
		0xD1D3EBCDDA214F76ULL,
		0xEF0E92CA218C0840ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA758ABC4CB1149ULL,
		0x8192592B2C58766DULL,
		0x12795176FA383E71ULL,
		0xD045E10189E5B8A2ULL,
		0x50071FADD6BD0F0AULL,
		0xB5BDDBBDF2D668D0ULL,
		0x7BFAC99E854ED56CULL,
		0x7A5EF60ADD49E6F2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x960008A300CA0140ULL,
		0x811248032440346DULL,
		0x12590126B8183E71ULL,
		0x9045E10081400802ULL,
		0x1004188D0015010AULL,
		0x0191D2A010444800ULL,
		0x51D2C98C80004564ULL,
		0x6A0E920A01080040ULL
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
		0x125B8BD8F8A75C37ULL,
		0xDAA324A3DDC5B213ULL,
		0xD27A6106EBD8227CULL,
		0x83BFCB462DFAE3F3ULL,
		0xA108A7BD0D5BEE09ULL,
		0x0649F3AA964BB6FBULL,
		0xECB5743E5DE4A19FULL,
		0xA76007DAB1CB2958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A2B9C09C2D1BCAEULL,
		0x25F28BCB9688FFCFULL,
		0xA3D6A5B92114E3FDULL,
		0x890E2B8315B2D3DDULL,
		0x8CC1CFFE8F88CA6BULL,
		0x51628B3EBBD8D3CAULL,
		0xEE6F4D1A9B8627F9ULL,
		0xD5A35BBA70830127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x120B8808C0811C26ULL,
		0x00A200839480B203ULL,
		0x825221002110227CULL,
		0x810E0B0205B2C3D1ULL,
		0x800087BC0D08CA09ULL,
		0x0040832A924892CAULL,
		0xEC25441A19842199ULL,
		0x8520039A30830100ULL
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
		0xF5A33582D240BC34ULL,
		0x2BA8F1D9B168D454ULL,
		0x3094A89BA6F3FBEAULL,
		0xADC146C8BAB71C2FULL,
		0x234F25B90F2B696CULL,
		0x0BB0AB648CF7854AULL,
		0xE34FE95C3BF7A142ULL,
		0x42A51F0DC5456077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9023327CC684C1DBULL,
		0xA59DD61DD0D80867ULL,
		0xFDEE2E43AF64CCBFULL,
		0xA5E73A40AAF69BBBULL,
		0xD9DC4197761B1A1EULL,
		0x438F356F9D5C1C48ULL,
		0x623FF2288A198645ULL,
		0x3F2B3337DED491D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90233000C2008010ULL,
		0x2188D01990480044ULL,
		0x30842803A660C8AAULL,
		0xA5C10240AAB6182BULL,
		0x014C0191060B080CULL,
		0x038021648C540448ULL,
		0x620FE0080A118040ULL,
		0x02211305C4440050ULL
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
		0xD585DBB897FB970CULL,
		0x7CF07B4C63AE0E4AULL,
		0xAD8D3F40EACE68F6ULL,
		0xF6D2BF9197412E9AULL,
		0x96C220133DE93138ULL,
		0xEC13612DC4FE3231ULL,
		0xC310B29C4F669329ULL,
		0x387C898009423AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E3519A2A40BCC0ULL,
		0x112EFCD3CF5F76A9ULL,
		0xB2AA092B9DE1DF4DULL,
		0x3C98642B59E374A2ULL,
		0xD1344A72E9A67B47ULL,
		0xAACA692524DD145FULL,
		0x29F7A9F28B2241ABULL,
		0xB69FE10367447DF9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9481519802409400ULL,
		0x10207840430E0608ULL,
		0xA088090088C04844ULL,
		0x3490240111412482ULL,
		0x9000001229A03100ULL,
		0xA802612504DC1011ULL,
		0x0110A0900B220129ULL,
		0x301C8100014038B9ULL
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
		0x9B4A9103E780E7DEULL,
		0xAFC873D3563F1336ULL,
		0x5D6C3184A5713D70ULL,
		0x3AC9BC03FEF25A7AULL,
		0x9ECD0A49D62164B6ULL,
		0x520C417BBC7809C6ULL,
		0x68FFE3AABAC31AB5ULL,
		0xB5CF99A4BC6FCCC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3C20593983DA0F5ULL,
		0x5306B7D8FF1C6B97ULL,
		0x12950F796B60F86CULL,
		0x3279C1A3BFF60D2CULL,
		0x5061B148EDDF6835ULL,
		0xCA0D5D2D9BA5607BULL,
		0xCDCF7C84442EC29AULL,
		0xA089DC1071B766B1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x834201038000A0D4ULL,
		0x030033D0561C0316ULL,
		0x1004010021603860ULL,
		0x32498003BEF20828ULL,
		0x10410048C4016034ULL,
		0x420C412998200042ULL,
		0x48CF608000020290ULL,
		0xA089980030274480ULL
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
		0xD3D86673AE9584D2ULL,
		0x500BCED865C3C52FULL,
		0x71DD2BAD58B1CF7FULL,
		0x7EF63F13A034C0D1ULL,
		0x70112A607CD04D3AULL,
		0x6B04536006D57D4EULL,
		0x73F2C47804B92ED9ULL,
		0xB30A081B6C375BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC3F4855CECF5FD1ULL,
		0xF6F0492979D05153ULL,
		0x69153DBE33570679ULL,
		0x381CAA3F484619CBULL,
		0xB788C2C585EFDE2DULL,
		0xFC587244DFF70E0FULL,
		0x15426BE56C0216B8ULL,
		0x0C69F0F5AE7560C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x901840518E8504D0ULL,
		0x5000480861C04103ULL,
		0x611529AC10110679ULL,
		0x38142A13000400C1ULL,
		0x3000024004C04C28ULL,
		0x6800524006D50C0EULL,
		0x1142406004000698ULL,
		0x000800112C3540C1ULL
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
		0x184BA35037D78BBEULL,
		0x7A56296517F59271ULL,
		0xD9354CCC628192A2ULL,
		0x795C4421B7CB9E0AULL,
		0x82CDBD20A3A98194ULL,
		0xFC8D585DB7F8C16AULL,
		0xD2C122E04289D3A0ULL,
		0xDC6507ED35929106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF275968C8DBAC91ULL,
		0x31762B6A0F4DFDD3ULL,
		0xF8ECF400C70F24D9ULL,
		0xAD7B6F08D532B6D1ULL,
		0x29B740518932DA87ULL,
		0x0481C111837EE727ULL,
		0xBA60A52DBB7AD749ULL,
		0x4106188423167639ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0803014000D38890ULL,
		0x3056296007459051ULL,
		0xD824440042010080ULL,
		0x2958440095029600ULL,
		0x0085000081208084ULL,
		0x048140118378C122ULL,
		0x924020200208D300ULL,
		0x4004008421121000ULL
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
		0xAF0CB2884EDC4467ULL,
		0x6D5D15F3BFBB3690ULL,
		0x6A3D5A21246DF6F5ULL,
		0x3E449554889D616CULL,
		0x3C07CD69BF4BB357ULL,
		0x2EEA838888A71FABULL,
		0x420D5CBD67EBA9A7ULL,
		0xA6FDBF04108888D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA594880ABB260348ULL,
		0xF2A2038CD24BC047ULL,
		0xA3BC49955F307506ULL,
		0x1AD73D39A2095B88ULL,
		0x26D28ADFA35E18C0ULL,
		0x7D2478309133A132ULL,
		0x7B73F5519589BC3DULL,
		0x99D6E6FF28E581C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA50480080A040040ULL,
		0x60000180920B0000ULL,
		0x223C480104207404ULL,
		0x1A44151080094108ULL,
		0x24028849A34A1040ULL,
		0x2C20000080230122ULL,
		0x420154110589A825ULL,
		0x80D4A604008080C1ULL
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
		0x0B6F3C636C457EF2ULL,
		0x3E490DAFA4AB422FULL,
		0x15DA3B7DFA287B30ULL,
		0x55073A3FD98DAB92ULL,
		0x79DC0406C3D3898BULL,
		0x9CB0209CDD9D1ECCULL,
		0x80482F8D585B25FCULL,
		0x9A470336A25C6619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x480255DEDBCB60AEULL,
		0xA084835D4B0991D8ULL,
		0xAC899E942A9E1947ULL,
		0xD6F9211FF04ADC88ULL,
		0xBDE70FB3DF03237EULL,
		0x4DBDAD40016D3DA4ULL,
		0x712F537A15C3198FULL,
		0xFCDE7070FA76DC06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08021442484160A2ULL,
		0x2000010D00090008ULL,
		0x04881A142A081900ULL,
		0x5401201FD0088880ULL,
		0x39C40402C303010AULL,
		0x0CB02000010D1C84ULL,
		0x000803081043018CULL,
		0x98460030A2544400ULL
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
		0x64D4E79D1044A64BULL,
		0x01658025540D7344ULL,
		0x681D7A2C17FCEBC2ULL,
		0x05D7AF60E6D18972ULL,
		0xC8E73CF20FF186AFULL,
		0xB32C27609CC1B237ULL,
		0x8FE373A68E091550ULL,
		0x0D3A444C634F9869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88711BBB3388B18CULL,
		0x874550F628F8FC90ULL,
		0x1931A4D49BBBDDDEULL,
		0x197D94D8D144DD61ULL,
		0xC89EAA7D083B0047ULL,
		0x58EB2B673DBDA6E0ULL,
		0xB9DCBADFB50E8222ULL,
		0x522058655F7A2FBCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x005003991000A008ULL,
		0x0145002400087000ULL,
		0x0811200413B8C9C2ULL,
		0x01558440C0408960ULL,
		0xC886287008310007ULL,
		0x102823601C81A220ULL,
		0x89C0328684080000ULL,
		0x00204044434A0828ULL
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
		0x8042FC67FE1AA237ULL,
		0xAA9893B220E2E90BULL,
		0xF0783F856AA91F89ULL,
		0xB233F7AF4E062826ULL,
		0x6055292B6E687157ULL,
		0x4AE43A07EF3C63B1ULL,
		0xADA435267A690C7AULL,
		0x84AC22066B75223AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FB989A17D6BDEBBULL,
		0xEFB4ABCDC33FCD51ULL,
		0x4D17AB1B96E04473ULL,
		0xDBC9EDC39F39B7A2ULL,
		0xF33EB15B8F39C684ULL,
		0x0EFE45C19F8C7CFAULL,
		0x724E4D121E880F19ULL,
		0x18FE39E4407AC28CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000088217C0A8233ULL,
		0xAA9083800022C901ULL,
		0x40102B0102A00401ULL,
		0x9201E5830E002022ULL,
		0x6014210B0E284004ULL,
		0x0AE400018F0C60B0ULL,
		0x200405021A080C18ULL,
		0x00AC200440700208ULL
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
		0xD047DFF9707F85A7ULL,
		0xBD0AB4E1143A1B52ULL,
		0x0F4B5459718E7264ULL,
		0x00EB6A745C758385ULL,
		0x83E14AEFBCAFA409ULL,
		0xA67C18315A0CF992ULL,
		0xE5612665E039C902ULL,
		0xB64D777B04B4233BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F688F0DCF5B4365ULL,
		0x2351BEDB061E2800ULL,
		0x8101DB9045D7EB03ULL,
		0x70455D0C9EF4B4B9ULL,
		0xE3F7DC2368AB9DB5ULL,
		0x15A76EF0DCFE9B8BULL,
		0xF70CB5871FAD4F05ULL,
		0x1794662F1B2BD2B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80408F09405B0125ULL,
		0x2100B4C1041A0800ULL,
		0x0101501041866200ULL,
		0x004148041C748081ULL,
		0x83E1482328AB8401ULL,
		0x04240830580C9982ULL,
		0xE500240500294900ULL,
		0x1604662B00200230ULL
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
		0x422EB66F374B218EULL,
		0xDD15C9BB3FBDCF44ULL,
		0x56E9445D4E5E01B8ULL,
		0x056F80C1C9CBE068ULL,
		0xFF443E6A379F26C7ULL,
		0x83E0E84EBD7A800AULL,
		0xB8903C6EAD19F322ULL,
		0xEB5449C687413771ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C32C5890B16606ULL,
		0x4EDE42BC31BBE473ULL,
		0x2833612BD7553ACFULL,
		0x01F3C37FDFBEE062ULL,
		0xD30BAB07B2F61A9CULL,
		0xA11CD8977EA046A9ULL,
		0x4E610487030BAF10ULL,
		0x4FBCBD703666DB7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4002244810012006ULL,
		0x4C1440B831B9C440ULL,
		0x0021400946540088ULL,
		0x01638041C98AE060ULL,
		0xD3002A0232960284ULL,
		0x8100C8063C200008ULL,
		0x080004060109A300ULL,
		0x4B14094006401370ULL
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
		0xC6080AEE97CF1498ULL,
		0x9F95E135F0CDDFD0ULL,
		0x51F2B12E2B359A89ULL,
		0x99BD5DE97E8FBC54ULL,
		0x790814A278F40038ULL,
		0xE1596461B3196D46ULL,
		0xF2E7001194A4788AULL,
		0x08E0F309FF3EBCEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63DAB197FC28E6CBULL,
		0x291D9A9FE449BDF9ULL,
		0x9C9C0A474E9B8B46ULL,
		0x4A61B612600323CBULL,
		0x466CE63CA3578FFBULL,
		0x032976B4C5C92529ULL,
		0xD8BB888E37983946ULL,
		0xA68B533388570E6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4208008694080488ULL,
		0x09158015E0499DD0ULL,
		0x109000060A118A00ULL,
		0x0821140060032040ULL,
		0x4008042020540038ULL,
		0x0109642081092500ULL,
		0xD0A3000014803802ULL,
		0x0080530188160C6AULL
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
		0x89DC1EC8E2FB13FFULL,
		0x38D2420BF30A7709ULL,
		0x1C77FDD0727369A9ULL,
		0xDFECF959FF27BA78ULL,
		0x062F7FF5CF306E23ULL,
		0x09A931F56962D04AULL,
		0x638BE499960E8AC4ULL,
		0xE4F1DA8A32EAF6FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E8291408F7D4B6ULL,
		0x1CA4D504794273E7ULL,
		0x89D985995492E21EULL,
		0x819616BF2B5A4C8AULL,
		0xFF49D9CCBE5BECCBULL,
		0x4AF93279CA574758ULL,
		0x541EADC9AE3F468BULL,
		0xBEDC6181453BF73DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80C8080000F310B6ULL,
		0x1880400071027301ULL,
		0x0851859050126008ULL,
		0x818410192B020808ULL,
		0x060959C48E106C03ULL,
		0x08A9307148424048ULL,
		0x400AA489860E0280ULL,
		0xA4D04080002AF639ULL
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
		0x2F99249DE49AED7BULL,
		0x1AF3F3C9BBE53BFFULL,
		0x458496B415D0A04AULL,
		0x196EF8B8530CD1EFULL,
		0x088817721DA9AF89ULL,
		0xE8989ACC65E239C5ULL,
		0x207D349D265B277AULL,
		0xB61B16C20D6CB28EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4CCA03BEBCA35D1ULL,
		0x63F325B8C2283F05ULL,
		0x2671E758CD40BF8AULL,
		0x2E970B4CEAA3F8A5ULL,
		0x63BAA34887B278B8ULL,
		0x4A01DF50C4306D6BULL,
		0xD5D5449807CF55F1ULL,
		0xE3DC931CE52726FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24882019E08A2551ULL,
		0x02F3218882203B05ULL,
		0x040086100540A00AULL,
		0x080608084200D0A5ULL,
		0x0088034005A02888ULL,
		0x48009A4044202941ULL,
		0x00550498064B0570ULL,
		0xA21812000524228CULL
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
		0x480A8EB4F3C1D534ULL,
		0xB01679236AB7FF82ULL,
		0xAB3E4EFB0FED17A0ULL,
		0x26FF1DE02F93F0A4ULL,
		0x97B9ECD02E0AE5BAULL,
		0xD39FEA58BF378DB0ULL,
		0x49050F1E77F5AECAULL,
		0x6B64B30723811292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38176F59FE57EA07ULL,
		0x2C1E7862094BB561ULL,
		0x1F62D9357F850EC3ULL,
		0x6EE9BD9EE294B363ULL,
		0x2CDC39C69A345815ULL,
		0xE0F29F9A2B98B692ULL,
		0xCD09D31B65ED3C11ULL,
		0xE8ED6FE7D7756178ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08020E10F241C004ULL,
		0x201678220803B500ULL,
		0x0B2248310F850680ULL,
		0x26E91D802290B020ULL,
		0x049828C00A004010ULL,
		0xC0928A182B108490ULL,
		0x4901031A65E52C00ULL,
		0x6864230703010010ULL
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
		0xDCB00C4E63923A57ULL,
		0x882F367779C49318ULL,
		0x5977BBB4E29B0029ULL,
		0x21B4CA5FD5F0AB81ULL,
		0x0EEF17DA833BCD1CULL,
		0xF28F14E802933F00ULL,
		0x8A018C7AE6BD1C84ULL,
		0xD4A5A8378AF993AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5949C6491A7124ULL,
		0x43767F6D446B74B1ULL,
		0xE813084751B1BE66ULL,
		0x9992BF2BCCC59FD1ULL,
		0x4391D619993D6ABEULL,
		0x42C51F1D3E534497ULL,
		0x1FE6A26EAF856687ULL,
		0x5CE5A6F0DE892346ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C10084641123004ULL,
		0x0026366540401010ULL,
		0x4813080440910020ULL,
		0x01908A0BC4C08B81ULL,
		0x028116188139481CULL,
		0x4285140802130400ULL,
		0x0A00806AA6850484ULL,
		0x54A5A0308A890306ULL
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
		0x74D0CB6A9F2E74B1ULL,
		0x8D8FFE47BA0C64A1ULL,
		0xB65643D9660F3D86ULL,
		0x16B47F812B7FFFE2ULL,
		0xB63D0AE4A2B5BD37ULL,
		0xAAC723E468DDD4DDULL,
		0x4D86774E0060E05DULL,
		0x7368AF4B09B8C04AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A046C404E6F574EULL,
		0xFA9BB2F1A79366F9ULL,
		0xD2E6A6FCCDDB7CF9ULL,
		0xAEB29B18847AEA19ULL,
		0xFB2D3BF3AB55639EULL,
		0xC031D4BCAC33ECCDULL,
		0x60D21659032560C6ULL,
		0xFB1F46D5F33FD0CDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x700048400E2E5400ULL,
		0x888BB241A20064A1ULL,
		0x924602D8440B3C80ULL,
		0x06B01B00007AEA00ULL,
		0xB22D0AE0A2152116ULL,
		0x800100A42811C4CDULL,
		0x4082164800206044ULL,
		0x730806410138C048ULL
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
		0x35A128EE40BBB034ULL,
		0x1018C5DD1927AD95ULL,
		0x603BA6A8566AF07CULL,
		0xD3C1DAACC1A45E26ULL,
		0xFD290BABE24FD0DEULL,
		0x0D35953CAC7DB39FULL,
		0x557EB857F886C3BEULL,
		0x9AC7FD33F6A5C134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78D793AEF83194FFULL,
		0x166C3FD1DCC82BC4ULL,
		0x00EFC7CD0C739888ULL,
		0x9DB91C5AF3F74693ULL,
		0x5B3ABA7B2F723E1CULL,
		0xB989D93C3A38F4EEULL,
		0xD5A191F1CD740F04ULL,
		0xB6B22E83FD21FB5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x308100AE40319034ULL,
		0x100805D118002984ULL,
		0x002B868804629008ULL,
		0x91811808C1A44602ULL,
		0x59280A2B2242101CULL,
		0x0901913C2838B08EULL,
		0x55209051C8040304ULL,
		0x92822C03F421C114ULL
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
		0x3E9B4E77C06AC424ULL,
		0xB5B601B97DBEFC97ULL,
		0xF9710412B41CC49FULL,
		0xA0D7F92AA8149714ULL,
		0x4E6DA31E0E424A14ULL,
		0xF6BE7475FAB05F8AULL,
		0xABBDEBBF10DAE82FULL,
		0xF622D4A401E12D41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD423F955C5219BC7ULL,
		0xB7210D85DCFEBA82ULL,
		0xEC27CAE4F943D9FDULL,
		0x1246CA57FBCFC6F6ULL,
		0x14968F1A4CC8F124ULL,
		0x8CF4E6E07AEE9A64ULL,
		0x12730F9BC2700472ULL,
		0x009EF60A0DDB6289ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14034855C0208004ULL,
		0xB52001815CBEB882ULL,
		0xE8210000B000C09DULL,
		0x0046C802A8048614ULL,
		0x0404831A0C404004ULL,
		0x84B464607AA01A00ULL,
		0x02310B9B00500022ULL,
		0x0002D40001C12001ULL
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
		0xDD304F4491665378ULL,
		0xDF7F05420A28E1C9ULL,
		0xFB4F1200A194037CULL,
		0x65328DB4C6E70966ULL,
		0x0EF4B592B0C3C453ULL,
		0xE47F207C0EB6DB3CULL,
		0xB6F808EF523F04B8ULL,
		0x02A217F42096B853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA62DAE4D87A86164ULL,
		0x29E4F5100843F0FFULL,
		0x857E20605868AD22ULL,
		0xDEEC5C520CF5DE85ULL,
		0xB8DC86902DB462B7ULL,
		0x8E6F7AD97C541D0BULL,
		0xB73B6C5980A8BA7AULL,
		0x5B011F799990E871ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84200E4481204160ULL,
		0x096405000800E0C9ULL,
		0x814E000000000120ULL,
		0x44200C1004E50804ULL,
		0x08D4849020804013ULL,
		0x846F20580C141908ULL,
		0xB638084900280038ULL,
		0x020017700090A851ULL
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
		0x40DE0965D28A1A56ULL,
		0xAAC60196E3F300BEULL,
		0xABE0F3B45F75A973ULL,
		0x61FE8FC4BE943F0CULL,
		0x5C627F329E42E3B5ULL,
		0x4AED78F9BC87F74DULL,
		0xD9B97CA10BDB3E7CULL,
		0x6D72D049193DF0D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF139901733E1628ULL,
		0x572C028AB6E0ED8DULL,
		0x75C2C7DA9FC5DD61ULL,
		0x06F602C6CE2B669CULL,
		0x048A5661316F7DC7ULL,
		0xAD950E49CC1CB6BAULL,
		0x0033585FCD1EDDCDULL,
		0xF85CF07488ED3CADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00120901520A1200ULL,
		0x02040082A2E0008CULL,
		0x21C0C3901F458961ULL,
		0x00F602C48E00260CULL,
		0x0402562010426185ULL,
		0x088508498C04B608ULL,
		0x00315801091A1C4CULL,
		0x6850D040082D3080ULL
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
		0x12CA3170437ED7A3ULL,
		0xCC89DEF524CDFA94ULL,
		0x95AA45A8EBF7F4CBULL,
		0x0DEF7E37145104F4ULL,
		0xC6F71C499CEB51D1ULL,
		0xE3C44AF139F0AB61ULL,
		0x3C1A422611148835ULL,
		0x2CD50FD4C85B23FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA32A3E218BBC190ULL,
		0x47799213411D6880ULL,
		0x46DBE5E6EC5389AEULL,
		0x27C8FDCF47E962CEULL,
		0x7D94B3CFCDE5D2A0ULL,
		0xDDCCF2A9955C00C6ULL,
		0xFBE5F3EB663492F6ULL,
		0x09300D92874F9C97ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x12022160003AC180ULL,
		0x44099211000D6880ULL,
		0x048A45A0E853808AULL,
		0x05C87C07044100C4ULL,
		0x449410498CE15080ULL,
		0xC1C442A111500040ULL,
		0x3800422200148034ULL,
		0x08100D90804B0093ULL
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
		0xB7E74774F7A56E88ULL,
		0x0A2F7C62114DB10AULL,
		0xDF0C6ACBEECDF03FULL,
		0xC73B252989A36883ULL,
		0x21D9C40B3DFCF177ULL,
		0x02B8C0F4E9D92613ULL,
		0x7FEFA831D6FFDBE5ULL,
		0x15888A327ABFC07DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E689C2D4D4B40E3ULL,
		0x5C24EC02326E4868ULL,
		0x9376001895CB800FULL,
		0x121F5343F2F46ADAULL,
		0xD8D13869901A9477ULL,
		0x52994725B4B50DBBULL,
		0x7D771967577C4B29ULL,
		0x0C38E0D9CEE43A39ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8660042445014080ULL,
		0x08246C02104C0008ULL,
		0x9304000884C9800FULL,
		0x021B010180A06882ULL,
		0x00D1000910189077ULL,
		0x02984024A0910413ULL,
		0x7D670821567C4B21ULL,
		0x040880104AA40039ULL
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
		0x3FBD8011352D4FF1ULL,
		0xBBA9048F453F4AC5ULL,
		0x8F46CDD7F436246EULL,
		0x8607AFAF1FAD84D3ULL,
		0x9CEDE73610F97421ULL,
		0xE002C74685C62974ULL,
		0x14B03BE9652B043BULL,
		0x8773327CA1355466ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE05350F6CDDC0030ULL,
		0x40DA442BE9FFEE16ULL,
		0xDDE2DD99E2332204ULL,
		0x00FF13C60A62BE74ULL,
		0xFC167201B1C6343DULL,
		0x7861F652A2A17623ULL,
		0x0187445870D6536CULL,
		0xA08B8EBE2D364A87ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20110010050C0030ULL,
		0x0088040B413F4A04ULL,
		0x8D42CD91E0322004ULL,
		0x000703860A208450ULL,
		0x9C04620010C03421ULL,
		0x6000C64280802020ULL,
		0x0080004860020028ULL,
		0x8003023C21344006ULL
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
		0xFCA32C2A7AF9A1C3ULL,
		0x81F84E691A7100D5ULL,
		0x0433AE5EF026851BULL,
		0x6EBE47A570E7BF00ULL,
		0x3A977F169FE0E409ULL,
		0x0025D14F7F3AE883ULL,
		0xFE51A56AC1160C3EULL,
		0xA4CC8B44CF8A65F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF20C723AF82BA8DULL,
		0x67D3E03952C5B428ULL,
		0x58590ECCB337FDC8ULL,
		0x565D4101474577B9ULL,
		0xCD5EB778805C1ED5ULL,
		0x8B32FA62DD2A44E7ULL,
		0x53ED61EA53FCC69CULL,
		0xD6DA8A26142CE081ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC2004222A80A081ULL,
		0x01D0402912410000ULL,
		0x00110E4CB0268508ULL,
		0x461C410140453700ULL,
		0x0816371080400401ULL,
		0x0020D0425D2A4083ULL,
		0x5241216A4114041CULL,
		0x84C88A0404086080ULL
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
		0x3C06F176DF856F46ULL,
		0x900D04915CFF97CBULL,
		0x91EA3E8799190BAAULL,
		0x3E6EDBC8E9F93F25ULL,
		0x49603076D5E83641ULL,
		0xEEF1CB5790D66F9FULL,
		0x384B03858F4727D2ULL,
		0x6F17C8A46E9D12B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C37E2F6D92B910FULL,
		0x61C629EAFE137AF6ULL,
		0xB2A9E6E6788338F1ULL,
		0x90C2B7ABC6FA0E85ULL,
		0x52F4E5E47640084CULL,
		0x831523A612B570FAULL,
		0x463446DC74D5D505ULL,
		0x5A97492C54A1DEAFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2C06E076D9010106ULL,
		0x000400805C1312C2ULL,
		0x90A82686180108A0ULL,
		0x10429388C0F80E05ULL,
		0x4060206454400040ULL,
		0x821103061094609AULL,
		0x0000028404450500ULL,
		0x4A174824448112A8ULL
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
		0x893BC6BC670891E3ULL,
		0x0106D3D90B642903ULL,
		0xEFC98C7C4DB60977ULL,
		0x237F51504CB476E9ULL,
		0xA736D22D614C9465ULL,
		0x74C566ED489F7008ULL,
		0xD3CE4CA640E56DCEULL,
		0xB2EEAC68CA4CA8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74EDE0FA70F8E8FULL,
		0xBDEEE0E260A20703ULL,
		0x3972155070FCD665ULL,
		0x61EC152A4F27CBA3ULL,
		0x74EC6BC0E8EFACA1ULL,
		0xC65B22ECCC8FC096ULL,
		0x4B27FC0AC86FF25AULL,
		0x85986948FA2204CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x810AC60C27088083ULL,
		0x0106C0C000200103ULL,
		0x2940045040B40065ULL,
		0x216C11004C2442A1ULL,
		0x24244200604C8421ULL,
		0x444122EC488F4000ULL,
		0x43064C024065604AULL,
		0x80882848CA0000CAULL
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
		0xD6ADA9695A60821CULL,
		0x58765C3835EAD590ULL,
		0xA3672803A9CD1324ULL,
		0x6A67C01A99AE1086ULL,
		0xA19E7880BED67B1DULL,
		0xE477D2C80183A97CULL,
		0x84F0FDE1C69C3BD9ULL,
		0x3BCFE5A8175185E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A0D3ACACE0E745ULL,
		0xD8A503D6E98E3DB5ULL,
		0xD797748A0CD421B4ULL,
		0xBACAF0047FDF8DE7ULL,
		0x1E7DB67F4532CBB0ULL,
		0x8663E174906CCBF6ULL,
		0xB9C52E7F190B6FE6ULL,
		0xB1ACAF18B545B5E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4A0812808608204ULL,
		0x58240010218A1590ULL,
		0x8307200208C40124ULL,
		0x2A42C000198E0086ULL,
		0x001C300004124B10ULL,
		0x8463C04000008974ULL,
		0x80C02C6100082BC0ULL,
		0x318CA508154185E0ULL
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
		0xC6B5B474C40144FDULL,
		0x03E972EA0EAE8DD8ULL,
		0x64703B8DCF311AE8ULL,
		0x9B1B4AD5FADC87F1ULL,
		0xAC99630AD8AA7522ULL,
		0xBF5684EABAD2B80EULL,
		0xCF01DB1434FF9D02ULL,
		0x322AF56FCC550A38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB25EF21D1D2412D4ULL,
		0xBAB7FFD03F0DDB7AULL,
		0xAB3BBC45D2F09F9EULL,
		0xE871D0FE41DF371DULL,
		0x12C1644CF6FB8C6CULL,
		0x00C8586D5E8792CBULL,
		0x5843270A87A4BAD4ULL,
		0xA7FAC355E357BD32ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8214B014040000D4ULL,
		0x02A172C00E0C8958ULL,
		0x20303805C2301A88ULL,
		0x881140D440DC0711ULL,
		0x00816008D0AA0420ULL,
		0x004000681A82900AULL,
		0x4801030004A49800ULL,
		0x222AC145C0550830ULL
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
		0x84341C03791690FCULL,
		0x97B99634C3E1C5E1ULL,
		0xD7895D709261C7FDULL,
		0x2B5D475494009E27ULL,
		0x97D4C10DB832B4EBULL,
		0x7B417D2F9CC91710ULL,
		0x79B8F4B6AEEB67ACULL,
		0x9DD54A0113855097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5390F09B1FE248EULL,
		0xBCB55C4B784553BEULL,
		0x2FE077CF61F283B1ULL,
		0x5811BBA0FE4760D7ULL,
		0x59EE42B6F6278018ULL,
		0xE33AA8C4B83FE559ULL,
		0x0DA275A7CFD9240EULL,
		0x4874E57ECA773C57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84300C013116008CULL,
		0x94B11400404141A0ULL,
		0x07805540006083B1ULL,
		0x0811030094000007ULL,
		0x11C44004B0228008ULL,
		0x6300280498090510ULL,
		0x09A074A68EC9240CULL,
		0x0854400002051017ULL
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
		0x8E96FB6B4D94936BULL,
		0x29C98BC50F9FA875ULL,
		0x4E796292546F46B6ULL,
		0x74DD37041FB8ACCAULL,
		0x93FFEB0765DFBC9AULL,
		0xE0A2EB5E6B120DCBULL,
		0x3DF3A0024E803DE2ULL,
		0x5C1CEA03E0044081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x529C14F4EB2095F2ULL,
		0x976FCFBE79220FC9ULL,
		0x2175500F40D9ABB4ULL,
		0x76C5FC32A067A047ULL,
		0x0B51ABB1FC54E884ULL,
		0xE579924ACF8B7689ULL,
		0x86188296B648038BULL,
		0x9D4F81E31635F91FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0294106049009162ULL,
		0x01498B8409020841ULL,
		0x00714002404902B4ULL,
		0x74C534000020A042ULL,
		0x0351AB016454A880ULL,
		0xE020824A4B020489ULL,
		0x0410800206000182ULL,
		0x1C0C800300044001ULL
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
		0x2CC54507BF4F9253ULL,
		0x02264B8410868B98ULL,
		0x660D07A6AC78A3E5ULL,
		0x25FBFF32AD90B7B6ULL,
		0x8D5F3E8366CB51BAULL,
		0x608B3CCAFE7FC52AULL,
		0xAEDE57450D5885B5ULL,
		0x7D66138BA6499495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6662EFEEF3D8B597ULL,
		0xFC3E79B8C2F54C5CULL,
		0x98D20835E6882D6FULL,
		0x864B52E9A6F84AEBULL,
		0xF40A3AE3B40E422FULL,
		0xA9A032C9EDECB3E2ULL,
		0x7F6AF45E2C7D4DCDULL,
		0xFFC8D35D450755B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24404506B3489013ULL,
		0x0026498000840818ULL,
		0x00000024A4082165ULL,
		0x044B5220A49002A2ULL,
		0x840A3A83240A402AULL,
		0x208030C8EC6C8122ULL,
		0x2E4A54440C580585ULL,
		0x7D40130904011494ULL
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
		0x917ABACF01E0143EULL,
		0xCA305D36F6361702ULL,
		0xFA585D05A73C88C6ULL,
		0x6B99A3E47EADC59DULL,
		0x04F43A89D9A40F52ULL,
		0x46FB304EA7ECA942ULL,
		0x1A30579672B45364ULL,
		0x9838A82A73C0C680ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AB119F909D9E49CULL,
		0x5431781F00CB54A9ULL,
		0x27AC670F71F8F32FULL,
		0x998219497FA349C2ULL,
		0x0339F7A21CE993DEULL,
		0x9B4948310F412DF7ULL,
		0x0D91AFD0702F86DAULL,
		0x4E7D61B7830C3A4BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x103018C901C0041CULL,
		0x4030581600021400ULL,
		0x2208450521388006ULL,
		0x098001407EA14180ULL,
		0x0030328018A00352ULL,
		0x0249000007402942ULL,
		0x0810079070240240ULL,
		0x0838202203000200ULL
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
		0x79414699EB786B0BULL,
		0x356922DF5CED8710ULL,
		0x51032A95B197DBBCULL,
		0x096FB4A20CE54895ULL,
		0x73EF6ECC61CF9BAEULL,
		0x1DECF4856971D13BULL,
		0x8CBBA3DBC37AFFC1ULL,
		0xB29101F8E4694FF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B61CA8F621C0309ULL,
		0xBEA536085F34F40DULL,
		0xFA465953ED4CE395ULL,
		0x43D874F9F04C4C65ULL,
		0x6A96FBF8BA4E49C9ULL,
		0xAC6809DBF363065FULL,
		0xAC9E9C623D3182D8ULL,
		0x02884EAA6A29FDD6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7941428962180309ULL,
		0x342122085C248400ULL,
		0x50020811A104C394ULL,
		0x014834A000444805ULL,
		0x62866AC8204E0988ULL,
		0x0C6800816161001BULL,
		0x8C9A8042013082C0ULL,
		0x028000A860294DD2ULL
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
		0xC673BC8665B11201ULL,
		0xC4EA65AF5E81CA35ULL,
		0x38FBE2B7C58FDB97ULL,
		0xE9F118670DBC4611ULL,
		0xB3D28C6A4ABAC205ULL,
		0x86FF6A6BF4C7DDE1ULL,
		0x4597CE222CA94AE8ULL,
		0xABB93D09AE2C1FB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E1E7007357D41FAULL,
		0xBBD1AA47B75551B0ULL,
		0x897977B6AA994ED6ULL,
		0xEC879BC9DD0B6F24ULL,
		0x032D64090F70F0C3ULL,
		0xA0ABDDCAC45F4B44ULL,
		0x2B2459EC4B2B48D7ULL,
		0xC95E32C237C99358ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4612300625310000ULL,
		0x80C0200716014030ULL,
		0x087962B680894A96ULL,
		0xE88118410D084600ULL,
		0x030004080A30C001ULL,
		0x80AB484AC4474940ULL,
		0x01044820082948C0ULL,
		0x8918300026081310ULL
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
		0x5017A3EA3F7FAED9ULL,
		0x1A2473B8D626386BULL,
		0x1041B15A8AFBDBCFULL,
		0xF7067B9425D34603ULL,
		0x7EA8B6E4CCA5EF86ULL,
		0x8BA44B9BE3DD6F7BULL,
		0xF530CDCD723896E0ULL,
		0x43B4F5ED4DBBE5BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB96EF10028B4390ULL,
		0xDB2D455D38C1850EULL,
		0x461F52E0ECE6C395ULL,
		0x4D69C37C526124BAULL,
		0x126C294D2EE2A30FULL,
		0x72EAEC0AF912F005ULL,
		0x8E6ACEE2145CAB75ULL,
		0x03B9F9B029EF9AE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1016A300020B0290ULL,
		0x1A2441181000000AULL,
		0x0001104088E2C385ULL,
		0x4500431400410402ULL,
		0x122820440CA0A306ULL,
		0x02A0480AE1106001ULL,
		0x8420CCC010188260ULL,
		0x03B0F1A009AB80A4ULL
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
		0xC61176ADA67931A4ULL,
		0xAD0843FCD3402D90ULL,
		0x1CA8233936F648D1ULL,
		0xD01ED64EE4E22AF1ULL,
		0xAE812327CC1B9508ULL,
		0x1B76D8B439DE48E5ULL,
		0xC53322A687B92E29ULL,
		0x475A894DE287369EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C89FFBAE18EF4B1ULL,
		0xAE022802F8856778ULL,
		0x49DC593F0AFFC22BULL,
		0x29E1819A53628590ULL,
		0x12F462F2C354CED2ULL,
		0xDD2C649C6B20955DULL,
		0xB0EDC92A0CF34175ULL,
		0x5C101C0C2604C183ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040176A8A00830A0ULL,
		0xAC000000D0002510ULL,
		0x0888013902F64001ULL,
		0x0000800A40620090ULL,
		0x02802222C0108400ULL,
		0x1924409429000045ULL,
		0x8021002204B10021ULL,
		0x4410080C22040082ULL
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
		0x17F3ED841607F143ULL,
		0x90A5D9A4D600CF46ULL,
		0xF3BF33CA71245AFCULL,
		0xA566101430858845ULL,
		0x2B09119F86F4DEE2ULL,
		0x68E440F15B6492C5ULL,
		0x43BFE0EA662B007EULL,
		0x19D78AE1A2BD46C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82C880870E025856ULL,
		0xDC2888FC9070FA72ULL,
		0x85160A0CFC6FB3EFULL,
		0x08CC293AA3E94FD0ULL,
		0xA366D994B1DD786EULL,
		0x06085116647CA8F1ULL,
		0x89FA4880A7BB3423ULL,
		0xF20413569A4C6558ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x02C0808406025042ULL,
		0x902088A49000CA42ULL,
		0x81160208702412ECULL,
		0x0044001020810840ULL,
		0x2300119480D45862ULL,
		0x00004010406480C1ULL,
		0x01BA4080262B0022ULL,
		0x10040240820C4440ULL
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
		0x9BC5D1FD32A67CD7ULL,
		0x82E0F2E77D59CDC9ULL,
		0x1F5580677E4FF013ULL,
		0xB8FE0706AD51E3F3ULL,
		0x22BD169B6DB96D94ULL,
		0xC28A5B5DE7032D6BULL,
		0x71F8DEBD8B220E16ULL,
		0x6C6BCE2904F2A2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBAA53C564CB8C8DULL,
		0xCC04CBAC22EB4D2FULL,
		0x2069FD54DF234317ULL,
		0xC39C3D922FA4EE6BULL,
		0x5BAAC8FE47D94D20ULL,
		0xE653262AF4316F4FULL,
		0xBE42E2B29F6A46D3ULL,
		0x925FB6CB857C6750ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B8051C520820C85ULL,
		0x8000C2A420494D09ULL,
		0x004180445E034013ULL,
		0x809C05022D00E263ULL,
		0x02A8009A45994D00ULL,
		0xC2020208E4012D4BULL,
		0x3040C2B08B220612ULL,
		0x004B860904702240ULL
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
		0xEA684B912DB287C2ULL,
		0x15F200A6B0871233ULL,
		0xFDD5426FE118CB88ULL,
		0x9680C4C414740713ULL,
		0x2C5500E52E75359DULL,
		0x6849AF480074453EULL,
		0xFC0BFDF1FB94E05AULL,
		0x4C4E76A061CA2457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55FB43AF84912817ULL,
		0x15AFC01FCD17147BULL,
		0xCBA16667017A2AADULL,
		0x3878AA1DFE9D80E0ULL,
		0x86CC57E6C74763A0ULL,
		0x2B61F5B07EAE8523ULL,
		0x0DCAD35B5B018042ULL,
		0x2BC459DA70C0A750ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4068438104900002ULL,
		0x15A2000680071033ULL,
		0xC981426701180A88ULL,
		0x1000800414140000ULL,
		0x044400E406452180ULL,
		0x2841A50000240522ULL,
		0x0C0AD1515B008042ULL,
		0x0844508060C02450ULL
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
		0x9C5970C4C89156B2ULL,
		0xC2036D54B26CF01AULL,
		0x4D256C692DFDC32AULL,
		0xD38D1EF40AC65049ULL,
		0x1CEE4309951195B9ULL,
		0x4C8AC73A71AC7104ULL,
		0xD1E7809CAA30C052ULL,
		0x32E7285153376D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7C13E43212EE2DFULL,
		0x5718E4D34B1D49F9ULL,
		0x7B2C05FB09C3038FULL,
		0x4A56BCAF1DC1F177ULL,
		0xD789725A431549B4ULL,
		0x8075C83603BD88A9ULL,
		0x02703EE4FF9E6563ULL,
		0x6C36CD8F8FBD4E57ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9441304000004292ULL,
		0x42006450020C4018ULL,
		0x4924046909C1030AULL,
		0x42041CA408C05041ULL,
		0x14884208011101B0ULL,
		0x0000C03201AC0000ULL,
		0x00600084AA104042ULL,
		0x2026080103354C03ULL
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
		0x344B92A4A86E8E69ULL,
		0x9C44D9A1F0AA37CDULL,
		0xEFFFC7B9D9358036ULL,
		0x6BFE81EE5A231543ULL,
		0x14A1C397D96BA406ULL,
		0xD0DEDDE17F532BA2ULL,
		0xC7CB5E80AC562982ULL,
		0x50E45142F81007BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54B68FFA87DF4AB6ULL,
		0xCB872FCB938B4178ULL,
		0x87E935638E1DF3CAULL,
		0x7955052186AD36ABULL,
		0x0C6B39472D2D5094ULL,
		0xE5F129CE74AFC96EULL,
		0x37CEAC49DC02F8A7ULL,
		0x67AD7327B9D61D74ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x140282A0804E0A20ULL,
		0x88040981908A0148ULL,
		0x87E9052188158002ULL,
		0x6954012002211403ULL,
		0x0421010709290004ULL,
		0xC0D009C074030922ULL,
		0x07CA0C008C022882ULL,
		0x40A45102B8100534ULL
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
		0x0F9D76BD8557606BULL,
		0x82272E719C263AD9ULL,
		0x66150694E29A5922ULL,
		0xF8DD7677C0154A9FULL,
		0x1E6B286F98A9F447ULL,
		0x81E33B657A32B1D8ULL,
		0x9E02C185AE48D808ULL,
		0xD455E7EF69ED5722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EC6182651B15E92ULL,
		0xD04A03511F734EAEULL,
		0x913322EEB0C69B47ULL,
		0x6BDF7F94215A601EULL,
		0xFA8EFE8A8E40A1B1ULL,
		0x75E947353004274DULL,
		0x30CA54A6B180DADDULL,
		0xC7E3F7F955E30418ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E84102401114002ULL,
		0x800202511C220A88ULL,
		0x00110284A0821902ULL,
		0x68DD76140010401EULL,
		0x1A0A280A8800A001ULL,
		0x01E1032530002148ULL,
		0x10024084A000D808ULL,
		0xC441E7E941E10400ULL
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
		0x17B847049336900DULL,
		0xC5D2840AA051DE04ULL,
		0x2C7DA0607F7A35C7ULL,
		0x719E442DBB4C4698ULL,
		0x09576B5068AF8CF3ULL,
		0x656939F1EC543DF9ULL,
		0x3D3ACCF000595384ULL,
		0xF06D446B2831F762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6AF90F05DAACD81ULL,
		0x8FE4226BB07E7306ULL,
		0x7C4AFB97B7E18F00ULL,
		0x078C2986B618D5C8ULL,
		0xA3C166177F63A089ULL,
		0xE009E4F8D2820661ULL,
		0xDF3197D4D91475BCULL,
		0x0C1CA5F15C3F2823ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x16A8000011228001ULL,
		0x85C0000AA0505204ULL,
		0x2C48A00037600500ULL,
		0x018C0004B2084488ULL,
		0x0141621068238081ULL,
		0x600920F0C0000461ULL,
		0x1D3084D000105184ULL,
		0x000C046108312022ULL
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
		0x3FF5C6BAF5B06981ULL,
		0x06A2A9E1D96A90F4ULL,
		0x0D2D87F0CF3EB613ULL,
		0x0FE7BFE42CE6797FULL,
		0x35A1F99A41E1748AULL,
		0x206AA6B460346497ULL,
		0x05AD427B69F3DFE9ULL,
		0xB70544EF1288B0EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8357B3C7CF5B8128ULL,
		0x76B5A98DF232D198ULL,
		0x1DD82F75829290AFULL,
		0xA1CFC9DA08FBE321ULL,
		0xA2F7D78B8078C689ULL,
		0x67AEEF3350730AE9ULL,
		0x766D4D3A5AAC24EDULL,
		0x97004FA6B2B43880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03558282C5100100ULL,
		0x06A0A981D0229090ULL,
		0x0D08077082129003ULL,
		0x01C789C008E26121ULL,
		0x20A1D18A00604488ULL,
		0x202AA63040300081ULL,
		0x042D403A48A004E9ULL,
		0x970044A612803080ULL
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
		0x5D99AA94A6A83620ULL,
		0x5843E146D09492B6ULL,
		0x18657292623DCEECULL,
		0xAC5ABB7895D22F6FULL,
		0x8BD1B0F1D20BBFDCULL,
		0x17ED9B19A8B32F2DULL,
		0x929741448634B518ULL,
		0x7D945FEBB2E47D8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CA900F98936FB3EULL,
		0x7D41562B36F3000AULL,
		0x9B0FF5FD7517CE2DULL,
		0xF9E2013C68400FBAULL,
		0xA9B582711778F560ULL,
		0x55DCAA9AF24E2C41ULL,
		0xB6B2D7C20E5501A2ULL,
		0xEE44D83E08779C43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C89009080203220ULL,
		0x5841400210900002ULL,
		0x180570906015CE2CULL,
		0xA842013800400F2AULL,
		0x899180711208B540ULL,
		0x15CC8A18A0022C01ULL,
		0x9292414006140100ULL,
		0x6C04582A00641C03ULL
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
		0xD5F71427B960E594ULL,
		0x18B2FB2FBD3E9E9FULL,
		0x307913F0805A1D9BULL,
		0xD3B328EF2385AA9AULL,
		0x1FAEB17FA940A5BEULL,
		0xC5EADF1A72F6FDADULL,
		0x3AB7666F738325F8ULL,
		0x14B5B0D040415D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B6ABB43CB070ED3ULL,
		0xD8B7033C9C699BB2ULL,
		0x536131D00EBCE193ULL,
		0xCEB91B09324E2466ULL,
		0x6A64E119D49F501BULL,
		0x55D98AF17CD41B9CULL,
		0x243B7ED8D8AB3B51ULL,
		0xBFC13745EDF79031ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1162100389000490ULL,
		0x18B2032C9C289A92ULL,
		0x106111D000180193ULL,
		0xC2B1080922042002ULL,
		0x0A24A1198000001AULL,
		0x45C88A1070D4198CULL,
		0x2033664850832150ULL,
		0x1481304040411010ULL
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
		0x076D1999BE11BBCFULL,
		0x7944BE8E31FB986AULL,
		0x64B8DDEEF7C4661DULL,
		0x01E398533436C74BULL,
		0x77EB61B4A10BF792ULL,
		0xF43F50204B35E1ACULL,
		0x2940A7A62EDA1B4AULL,
		0xAF0D26A3C5BF0D47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA96341ACCB11165ULL,
		0xD322D68703904C4DULL,
		0x02105699754ACEA0ULL,
		0x920E44F8835B430AULL,
		0xC77CA00507E46296ULL,
		0x4DDFAF5856955689ULL,
		0x2213A05DF70EBB11ULL,
		0xC1292540846439C9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020410188C111145ULL,
		0x5100968601900848ULL,
		0x0010548875404600ULL,
		0x000200500012430AULL,
		0x4768200401006292ULL,
		0x441F000042154088ULL,
		0x2000A004260A1B00ULL,
		0x8109240084240941ULL
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
		0x9027AFAD7002B8F4ULL,
		0x3E7CB6FC715F8A62ULL,
		0x1E12121FF41E6934ULL,
		0xC0942A3705A9E762ULL,
		0x9B80BF1EF7BA4CD6ULL,
		0xB9869CE31B425167ULL,
		0xDBA64CE53FDBC00DULL,
		0x7FC483339BF1B2BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4C48A465405F03DULL,
		0xE8C6D98212FB39E1ULL,
		0x74F04CF5B214269BULL,
		0x71504DE3E853C13FULL,
		0x281658DD980F7CE6ULL,
		0x7B8FE6B7CF1F11C5ULL,
		0xA6304A7230B9771FULL,
		0x4E53C40BCB0CC9CBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90048A045000B034ULL,
		0x28449080105B0860ULL,
		0x14100015B0142010ULL,
		0x401008230001C122ULL,
		0x0800181C900A4CC6ULL,
		0x398684A30B021145ULL,
		0x822048603099400DULL,
		0x4E4080038B00808BULL
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
		0xB68FF1B5FB9CE0F7ULL,
		0x9F2D7A538CAEA9D4ULL,
		0xCDDED08469B5A9A5ULL,
		0xDB9818A3953C9465ULL,
		0x1A6A19626CC4EA4FULL,
		0x9679000F88A022EDULL,
		0x686CD7E39B432382ULL,
		0x4CEBA12704B91942ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52F4E8AD1682BE42ULL,
		0xB7A852CBDC6BBDB2ULL,
		0xC71BB16F3E7418C5ULL,
		0x9837CF840EE5586AULL,
		0x8D9DF4219DD56F62ULL,
		0x52D5447C657B4806ULL,
		0x4A2C258750985E30ULL,
		0x16E93D53DD4B87D6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1284E0A51280A042ULL,
		0x972852438C2AA990ULL,
		0xC51A900428340885ULL,
		0x9810088004241060ULL,
		0x080810200CC46A42ULL,
		0x1251000C00200004ULL,
		0x482C058310000200ULL,
		0x04E9210304090142ULL
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
		0xDBD26F142A4FB3A7ULL,
		0x2497D5EDF668E2A0ULL,
		0xEB851D5E4F54E996ULL,
		0x4ADBC26EFD77EF6BULL,
		0xDBD65182A471FAD8ULL,
		0xD10A449FBE05E741ULL,
		0xAB08F6E7A2775410ULL,
		0x4DFB2B656452C6E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF6B08616B0773E4ULL,
		0x05D0832244F52D8BULL,
		0x7BE83B0A03BA1BE7ULL,
		0x821E267BA63F1772ULL,
		0x15B80D3A6ACDD095ULL,
		0x0B18336FD8EE6163ULL,
		0xC242685BDED7AEE2ULL,
		0xA35D82976ED320EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B4208002A0733A4ULL,
		0x0490812044602080ULL,
		0x6B80190A03100986ULL,
		0x021A026AA4370762ULL,
		0x119001022041D090ULL,
		0x0108000F98046141ULL,
		0x8200604382570400ULL,
		0x01590205645200E6ULL
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
		0x6D778241106217F2ULL,
		0x5FD5583EB5F6A510ULL,
		0xAA1BC8C2D0991F68ULL,
		0x96350B8E24436424ULL,
		0x5F1E258D0F80DCEBULL,
		0x8EBBD0B5F0825164ULL,
		0x8F02E0604F0826BBULL,
		0xC9DD390887DDF0CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EEF663C0E960BBDULL,
		0x886A7569BE731DEFULL,
		0x638CC025F8900D76ULL,
		0x811EE011108CF94BULL,
		0x639E60AD4F0A9E52ULL,
		0x6A8F5ED9E40E3452ULL,
		0xE6A556645AB38597ULL,
		0xCB08CB71940E4880ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4C670200000203B0ULL,
		0x08405028B4720500ULL,
		0x2208C000D0900D60ULL,
		0x8014000000006000ULL,
		0x431E208D0F009C42ULL,
		0x0A8B5091E0021040ULL,
		0x860040604A000493ULL,
		0xC9080900840C4080ULL
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
		0x5BBA79073DB7746FULL,
		0x85E5E852425EA8B8ULL,
		0x7E9D1AA1CE6C801BULL,
		0x22582D8778189E84ULL,
		0xB3BE4D6EEEC0ED8DULL,
		0xCA05B5BEF48402FEULL,
		0x7807364490064D5EULL,
		0x732220BE4454EBAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEEA825DB00DF5C6ULL,
		0xF5694B854803840CULL,
		0x79350A641B104E74ULL,
		0xD7EAA77587E57AF7ULL,
		0x09045ED12F354C28ULL,
		0xA8B50D9547512AEFULL,
		0xEDDD5DD8B565587FULL,
		0x4A207CF8100CAD09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4AAA000530057446ULL,
		0x8561480040028008ULL,
		0x78150A200A000010ULL,
		0x0248250500001A84ULL,
		0x01044C402E004C08ULL,
		0x88050594440002EEULL,
		0x680514409004485EULL,
		0x422020B80004A908ULL
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
		0x3C7A45E9476F345EULL,
		0xED1A7820FBA3CC9EULL,
		0xBADA6F94193C6474ULL,
		0xC73EBE26B217C241ULL,
		0xD1DF0A8F0D00CC09ULL,
		0xC0C71C153938C624ULL,
		0xB2D76B0B12C74D8EULL,
		0xEB40FF3E682B0627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34893E65EF60D117ULL,
		0xEB47CEB95EEA5804ULL,
		0xA4E2EAAF5D8D5CFEULL,
		0x283988A7B713AD18ULL,
		0xDFA9DB77855D7190ULL,
		0x163C659B8BF60FF9ULL,
		0xD909D17FF24C5970ULL,
		0xD62697E0FE64722DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3408046147601016ULL,
		0xE90248205AA24804ULL,
		0xA0C26A84190C4474ULL,
		0x00388826B2138000ULL,
		0xD1890A0705004000ULL,
		0x0004041109300620ULL,
		0x9001410B12444900ULL,
		0xC200972068200225ULL
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
		0xCCC1CA477D963D73ULL,
		0xB94914211CF20459ULL,
		0xFE3ACB60F8F9F488ULL,
		0x991161E727089420ULL,
		0x2A409C769CD9B45EULL,
		0x161952188DA1ECFAULL,
		0xA814EBF8E9EFD3AEULL,
		0x341B59B06BAAA786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x505E564EF58212A1ULL,
		0x56FD624763849610ULL,
		0x422953119F497A01ULL,
		0xA8DCCB1B4DB33200ULL,
		0x0294A9BFA1B8AE1DULL,
		0xCC0CD992991DFB4CULL,
		0xCC136A88F7FCD425ULL,
		0xC09F5BEC51359AE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4040424675821021ULL,
		0x1049000100800410ULL,
		0x4228430098497000ULL,
		0x8810410305001000ULL,
		0x020088368098A41CULL,
		0x040850108901E848ULL,
		0x88106A88E1ECD024ULL,
		0x001B59A041208282ULL
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
		0x686B8AD5D645A0F2ULL,
		0xE56D1DB039451259ULL,
		0x7EB8CC43F476BB83ULL,
		0x2AA80702602E95B2ULL,
		0x648AA84A4DC4B0C8ULL,
		0x29FE34F6E1657613ULL,
		0x4D60A9207E03ACC2ULL,
		0xBCA9604C30BAC2CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D5BDBB5753179DDULL,
		0xDB707D1FE327BDD4ULL,
		0x71B5ADDFCC5B77E1ULL,
		0x1FF0DF65ECF64CA3ULL,
		0xA558D5B48C442212ULL,
		0xDE276E064FDEC07DULL,
		0xFB8BB63F49E8649EULL,
		0x0CB02AF41EECB762ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x484B8A95540120D0ULL,
		0xC1601D1021051050ULL,
		0x70B08C43C4523381ULL,
		0x0AA00700602604A2ULL,
		0x240880000C442000ULL,
		0x0826240641444011ULL,
		0x4900A02048002482ULL,
		0x0CA0204410A88242ULL
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
		0xCA401174C5EF5980ULL,
		0x6F660083933D4758ULL,
		0x60285F18FD7B96ECULL,
		0x78EB26781E103224ULL,
		0xE9345CA444EDF02FULL,
		0xA73549D71A7354F2ULL,
		0xF5478C5CAF38A2FEULL,
		0xE91720BF62ECADE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF24FB323232D0CULL,
		0x6B258F319135FC9FULL,
		0x8B0873584BB0002EULL,
		0x66FED1C16817DD8BULL,
		0x4FE5DA6DFC804767ULL,
		0x1377BD304DF832DAULL,
		0xDBA01DCDCF74E890ULL,
		0xFA762CE026366F47ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4840013001230900ULL,
		0x6B24000191354418ULL,
		0x000853184930002CULL,
		0x60EA004008101000ULL,
		0x4924582444804027ULL,
		0x03350910087010D2ULL,
		0xD1000C4C8F30A090ULL,
		0xE81620A022242D47ULL
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
		0xDD08F171117D4E09ULL,
		0x60708F1B4DA209FAULL,
		0x7453EC7278C32234ULL,
		0xD5BE4160E1744418ULL,
		0x6D18EA071C97297CULL,
		0x7198C54DF56D3580ULL,
		0xB3CC405F7753A715ULL,
		0x69F1434EA0F8CF81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3334EAF8B64C9E79ULL,
		0x103D2FA341E6748DULL,
		0xC106E1648595AD87ULL,
		0x0A954B1858A639EAULL,
		0x0456BD7D102676AAULL,
		0x7DA3F6A1FB338546ULL,
		0x04C58F1BC9839EDCULL,
		0xF3E8F7FB1DC1B080ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1100E070104C0E09ULL,
		0x00300F0341A20088ULL,
		0x4002E06000812004ULL,
		0x0094410040240008ULL,
		0x0410A80510062028ULL,
		0x7180C401F1210500ULL,
		0x00C4001B41038614ULL,
		0x61E0434A00C08080ULL
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
		0xF58C34FA0F540649ULL,
		0x7A06A2C4B2DB26A9ULL,
		0x71F35319A6A5CEDBULL,
		0x9685404D900C1032ULL,
		0xBE840E3D2EE656BEULL,
		0x6BBD95207D7C064AULL,
		0xF07D539CA3C534AAULL,
		0x8F02796EA7AED397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DCF848A537E8F3AULL,
		0x61C4CD47E8D04726ULL,
		0x9E97C0189D53A8DEULL,
		0xB5A0813AB5135385ULL,
		0xB7F69AC4E707CDB6ULL,
		0x4F082984BCC9B400ULL,
		0xB1EFC331934FA120ULL,
		0x79A5650BCDC3DC5AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x658C048A03540608ULL,
		0x60048044A0D00620ULL,
		0x10934018840188DAULL,
		0x9480000890001000ULL,
		0xB6840A04260644B6ULL,
		0x4B0801003C480400ULL,
		0xB06D431083452020ULL,
		0x0900610A8582D012ULL
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
		0x5E48A40E687B1FB2ULL,
		0xBEEC5D003E6A4993ULL,
		0x9D6B3116F913FA2AULL,
		0xA6430F6803A1BB02ULL,
		0x12D5E973BEF624D1ULL,
		0x2F87E35457DA9753ULL,
		0xFDC6051E76F33C69ULL,
		0x04BC2AF23FAFC981ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7097E3CC4FC43FULL,
		0x944BF8F47F8CF87FULL,
		0x17CC8683AAF5B983ULL,
		0x829DAD2990F8E22AULL,
		0xCE7027E58A09CD7BULL,
		0x78621912E613C507ULL,
		0x268E0AF25AE95C51ULL,
		0xAD7D0E33777E9013ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C408402484B0432ULL,
		0x944858003E084813ULL,
		0x15480002A811B802ULL,
		0x82010D2800A0A202ULL,
		0x025021618A000451ULL,
		0x2802011046128503ULL,
		0x2486001252E11C41ULL,
		0x043C0A32372E8001ULL
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
		0xBE42B3CCEECE4D4CULL,
		0xD0FC19CCA5168FB6ULL,
		0xBF2A077F5B7DC8F9ULL,
		0xC6B0836F55DF0D8CULL,
		0x0335EEE308AD599CULL,
		0xB664EE9232F18AC9ULL,
		0x11C816C486E91C7EULL,
		0xEF8BE92D4F83A14CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x930AB195B3B21C40ULL,
		0xFB11E6BF85FB6281ULL,
		0x4A1B8C1D4785CD05ULL,
		0x900266FA52991C4FULL,
		0x64E8CB14EFEF16F3ULL,
		0x2A0C8B86CA06640AULL,
		0x3707A5911F9A0042ULL,
		0x69B66F27D6020BE9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9202B184A2820C40ULL,
		0xD010008C85120280ULL,
		0x0A0A041D4305C801ULL,
		0x8000026A50990C0CULL,
		0x0020CA0008AD1090ULL,
		0x22048A8202000008ULL,
		0x1100048006880042ULL,
		0x6982692546020148ULL
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
		0xA4D2678455027F9FULL,
		0xD8261830E8B08B19ULL,
		0x3EA4C74C3286AE93ULL,
		0xFB8FD9333FECE532ULL,
		0x3E619C5154079CC8ULL,
		0xAF9443D7AD9DC81DULL,
		0x2AD2BCE61F7BAD65ULL,
		0x750ECCC066E4CA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D0FD0C7998E09B3ULL,
		0x94F98E74E8BED5E5ULL,
		0x0EE81486474AB843ULL,
		0xB2AB74466489DAFAULL,
		0xA99ADCE92AB3838DULL,
		0x0DD0984A6225C422ULL,
		0xBA7AF430EBAB14FBULL,
		0x574B64F7BC6A1076ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0402408411020993ULL,
		0x90200830E8B08101ULL,
		0x0EA004040202A803ULL,
		0xB28B50022488C032ULL,
		0x28009C4100038088ULL,
		0x0D9000422005C000ULL,
		0x2A52B4200B2B0461ULL,
		0x550A44C024600040ULL
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
		0x37527B42639F1960ULL,
		0xC35476C4986226B2ULL,
		0xEF7A03F2CC9DDD70ULL,
		0x216EE7953142E2CAULL,
		0x27B015BAA9C86482ULL,
		0x5A19C32126884DA4ULL,
		0xCD8B78D191DF491CULL,
		0x5A971ACE8AAFDF62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1231E02971436A94ULL,
		0xA88DAAB79332B9DCULL,
		0xC7546564128DB176ULL,
		0x580778D384FA8311ULL,
		0xD0E579D1A70A98FBULL,
		0xFE0CF3C9DAB3A3E9ULL,
		0xD12A95BE62973D51ULL,
		0x1370D2C4A20FD134ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1210600061030800ULL,
		0x8004228490222090ULL,
		0xC7500160008D9170ULL,
		0x0006609100428200ULL,
		0x00A01190A1080082ULL,
		0x5A08C301028001A0ULL,
		0xC10A109000970910ULL,
		0x121012C4820FD120ULL
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
		0x9BC208AC43223278ULL,
		0x1B038347EC3E769EULL,
		0x66DDC2CE906BA1B5ULL,
		0xCDE3E46B68BB2C06ULL,
		0x65F925FEAAB3D30DULL,
		0x405B8CBEC0A1DA97ULL,
		0x617849EF4D80A185ULL,
		0x9CD99D3048F1C994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8380EF6B3C49FE35ULL,
		0x86B6E6CEAAFC5421ULL,
		0x7E003AB8BC20B51AULL,
		0xBF2CB3F08FF69802ULL,
		0xD163E91BA903686AULL,
		0x80732A98008F63C3ULL,
		0xFF1BA14F382F2217ULL,
		0x2D0434F38939B3FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8380082800003230ULL,
		0x02028246A83C5400ULL,
		0x660002889020A110ULL,
		0x8D20A06008B20802ULL,
		0x4161211AA8034008ULL,
		0x0053089800814283ULL,
		0x6118014F08002005ULL,
		0x0C00143008318194ULL
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
		0x9A07A68851706739ULL,
		0xA153CF8ECC04F36CULL,
		0x603297D132212B33ULL,
		0x9A3DB9493690F77EULL,
		0x42E2FEC74BD75188ULL,
		0x74803BDA9E7AC9B4ULL,
		0xD2B9CA6A7B819AF8ULL,
		0x5475C09993D40424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13FEB4C9685ED4C2ULL,
		0x26A5BCFB5BBA34BEULL,
		0x634688A11FE18E01ULL,
		0xFAE0F73CE36E9789ULL,
		0x92F83CF4D6DF0CD0ULL,
		0xC6310C25F1A6576CULL,
		0xFB82343AEEAD6D73ULL,
		0x77F6A13879972322ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1206A48840504400ULL,
		0x20018C8A4800302CULL,
		0x6002808112210A01ULL,
		0x9A20B10822009708ULL,
		0x02E03CC442D70080ULL,
		0x4400080090224124ULL,
		0xD280002A6A810870ULL,
		0x5474801811940020ULL
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
		0x99D0AF9694FD743CULL,
		0xC96F86731B91C0D1ULL,
		0x238B60A80CFEAEB9ULL,
		0xF45C8FBAF174CEBAULL,
		0xA2DF206F50915F06ULL,
		0x3C99FEFA9F684480ULL,
		0xA0A0EB928BB9B28CULL,
		0xBDE9F28E98594487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0323FD1D6DD4B50ULL,
		0xBBF8EA9DF8B17AC3ULL,
		0x83F96558A5179582ULL,
		0x593772F9CFC74806ULL,
		0x5D4B8852744A51ACULL,
		0x4CD7EA87D6E7F6DBULL,
		0x135D8D6EAE4F184BULL,
		0x8095EA16335FB12FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x90102F9094DD4010ULL,
		0x89688211189140C1ULL,
		0x0389600804168480ULL,
		0x501402B8C1444802ULL,
		0x004B004250005104ULL,
		0x0C91EA8296604480ULL,
		0x000089028A091008ULL,
		0x8081E20610590007ULL
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
		0xF37AF0E916D4F073ULL,
		0x351074F6C6FD615CULL,
		0xA1E2674BF0678848ULL,
		0x69C921823E4435F0ULL,
		0x017464EAE8CCE4F6ULL,
		0xF87DCF0EEDEC9380ULL,
		0x108A022158BAE0CAULL,
		0xDC1C397E7740747FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B60DEF12632AF42ULL,
		0x34197B9544C4AA0AULL,
		0x87FB67884BBB0178ULL,
		0x91F62CABFEDFD3CDULL,
		0xBAD5BC1828EA26EDULL,
		0x10D1DEB301415289ULL,
		0x75D1A2AA0118EA0DULL,
		0x833E1E09F97932ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0360D0E10610A042ULL,
		0x3410709444C42008ULL,
		0x81E2670840230048ULL,
		0x01C020823E4411C0ULL,
		0x0054240828C824E4ULL,
		0x1051CE0201401280ULL,
		0x108002200018E008ULL,
		0x801C18087140302DULL
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
		0x8A1B5417DB283904ULL,
		0x28AF69ADAB929A26ULL,
		0x5516775894D0626FULL,
		0x7ACE88E231A0F82FULL,
		0x0C8CF34E72C8086AULL,
		0x5469EC0D853BB113ULL,
		0xC26A5BCEBE25D4C2ULL,
		0x90EAA3CD37B004E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2996C506B40A4B4ULL,
		0x62EEFB87FC501CE3ULL,
		0x1C17B7FE29EFD121ULL,
		0x45CCB90B61821CDBULL,
		0xD3528F6F398CA187ULL,
		0x0ED49580E98ED411ULL,
		0xDD8E9B09283F316EULL,
		0x0DADBB51A12B02E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x821944104B002004ULL,
		0x20AE6985A8101822ULL,
		0x1416375800C04021ULL,
		0x40CC88022180180BULL,
		0x0000834E30880002ULL,
		0x04408400810A9011ULL,
		0xC00A1B0828251042ULL,
		0x00A8A341212000E2ULL
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
		0x133704821C10812FULL,
		0xF1D8836F5E9E8ABDULL,
		0xCEE4C2901F05E49CULL,
		0x8AADE1E2A86CB470ULL,
		0x57A36EA0189406E5ULL,
		0x31555444AE68F029ULL,
		0x8FB6285AF28B365DULL,
		0xCA1C267D43F70389ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E37E76D9FDBEEFULL,
		0x61DB4B0B1DB61C22ULL,
		0xCC48CCCD76A3225CULL,
		0x2DCA52953A2E83A3ULL,
		0xF8F8ECC415F4B4F4ULL,
		0x234182912F2C50E6ULL,
		0x50ED88EFDC3D0E35ULL,
		0xD5303E2C70187B76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x012304021810802FULL,
		0x61D8030B1C960820ULL,
		0xCC40C0801601201CULL,
		0x08884080282C8020ULL,
		0x50A06C80109404E4ULL,
		0x214100002E285020ULL,
		0x00A4084AD0090615ULL,
		0xC010262C40100300ULL
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
		0xA85A2D679B3E8669ULL,
		0xFA36B5EF779D3B12ULL,
		0x6766E05A0557BFD7ULL,
		0xBAAF947EDC4A10CEULL,
		0x56FCD2C094CDA73CULL,
		0xAA4C91A16CA3998BULL,
		0x44BCAC6BAAAF6C7BULL,
		0x3857F2E4D7476442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E5EAAD6357D2DFULL,
		0x2A14E4E9035ED2D8ULL,
		0x54EBB8F8DF960D5FULL,
		0xFAB4139A926C7863ULL,
		0x17F273B3CB7A2814ULL,
		0xED8A355D733F5F33ULL,
		0x934482AD564A1F28ULL,
		0xED97C343F8B09FE2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8040282503168249ULL,
		0x2A14A4E9031C1210ULL,
		0x4462A05805160D57ULL,
		0xBAA4101A90481042ULL,
		0x16F0528080482014ULL,
		0xA808110160231903ULL,
		0x00048029020A0C28ULL,
		0x2817C240D0000442ULL
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
		0x7495820053ECBD5BULL,
		0x226D47EF71624BA2ULL,
		0x14191FE0C00A70A6ULL,
		0xE5765061BE264139ULL,
		0x94C7B9FC5F9908FCULL,
		0xC7B0A46F37478A56ULL,
		0x830E03515E2A17AFULL,
		0xE841F980C7D7687DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB32E5F5C2664D1A6ULL,
		0x4CD1F37DCE497EB1ULL,
		0x15428054403C3FA6ULL,
		0xCD8AA63585F651DFULL,
		0xB8BB273A554F39CEULL,
		0x5104E5DE7902CA7FULL,
		0xE34DDFEF4AFD1365ULL,
		0x8275D9C4E55D1EE5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3004020002649102ULL,
		0x0041436D40404AA0ULL,
		0x14000040400830A6ULL,
		0xC502002184264119ULL,
		0x90832138550908CCULL,
		0x4100A44E31028A56ULL,
		0x830C03414A281325ULL,
		0x8041D980C5550865ULL
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
		0x84D4157F1F02B703ULL,
		0x097C3C1301FD68B4ULL,
		0x8DEF10EBA382F50AULL,
		0xA4322C7FB829BC7BULL,
		0x2C018332BEB0599DULL,
		0xFBE50D9071AE3D10ULL,
		0x40105D662A14D715ULL,
		0x6117B41502CDC319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x979FA5A8A1416C69ULL,
		0xA278DF8BCB7ABE46ULL,
		0x8B71B504CFF140C9ULL,
		0xABACE54C0F95C07FULL,
		0x56D425811121E4B8ULL,
		0xE91B424E810892D0ULL,
		0x08DB19ACAE6096B0ULL,
		0xA02F163802F0EBE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8494052801002401ULL,
		0x00781C0301782804ULL,
		0x8961100083804008ULL,
		0xA020244C0801807BULL,
		0x0400010010204098ULL,
		0xE901000001081010ULL,
		0x001019242A009610ULL,
		0x2007141002C0C301ULL
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
		0xDA3FC1CEC4A9EF8AULL,
		0x5C534E4FE4A0FE0BULL,
		0x7F3835FCDBC5C80EULL,
		0xB05D7B23DDCC1E95ULL,
		0x9215F276A3274ACBULL,
		0x9DE54A01A2ADB093ULL,
		0x069BA3B032D76BB3ULL,
		0x793888E7F608322FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x377D8BF5A562D259ULL,
		0x7E90A9D7B3BD8928ULL,
		0xA539ABC33718B343ULL,
		0x1BB5ADCE9F7A2940ULL,
		0x71BECE641437369EULL,
		0x62714834E3D7C353ULL,
		0x64617D2C70C54D6EULL,
		0xCDAC64148636C348ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x123D81C48420C208ULL,
		0x5C100847A0A08808ULL,
		0x253821C013008002ULL,
		0x101529029D480800ULL,
		0x1014C2640027028AULL,
		0x00614800A2858013ULL,
		0x0401212030C54922ULL,
		0x4928000486000208ULL
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
		0x945A07F813DFB064ULL,
		0x27B2C9EDCB11CF8AULL,
		0xFC7E4FDB2D493627ULL,
		0xD52FEDF03004BCA7ULL,
		0x03346D2EB8BE475BULL,
		0x5A05773C7FC2110AULL,
		0xDC660171EC4A1432ULL,
		0x29B4E8022F4946FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07A810B72B1A58F7ULL,
		0x339EB7BB2F797117ULL,
		0x2812874EC92B78DDULL,
		0xC06867719AE9BB38ULL,
		0x1B4969E15A822225ULL,
		0x2C82865D83003310ULL,
		0xE8A0BA0E46C2BEA3ULL,
		0xB0EC549970AE943EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040800B0031A1064ULL,
		0x239281A90B114102ULL,
		0x2812074A09093005ULL,
		0xC02865701000B820ULL,
		0x0300692018820201ULL,
		0x0800061C03001100ULL,
		0xC820000044421422ULL,
		0x20A440002008043EULL
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
		0x2A2A8808D57A9FECULL,
		0xABF2DF1BDC6CCE21ULL,
		0xEAC243C40E739000ULL,
		0xF0E7D1D26E6F94C2ULL,
		0xC844481345ADB632ULL,
		0x06EFC047EE490982ULL,
		0x04758A9E48262FA2ULL,
		0xE8777327694BD329ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC18A80C450176FAULL,
		0x97A6FD429CABFF21ULL,
		0x015EFC75F2D458F5ULL,
		0xDD9624EA07808C08ULL,
		0xDC6A84048DF29333ULL,
		0x24652FDC5C91A058ULL,
		0x7858AE16A7C4D376ULL,
		0xD89BBB4FD74C889CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28088808450016E8ULL,
		0x83A2DD029C28CE21ULL,
		0x0042404402501000ULL,
		0xD08600C206008400ULL,
		0xC840000005A09232ULL,
		0x046500444C010000ULL,
		0x00508A1600040322ULL,
		0xC813330741488008ULL
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
		0x4C9A4B0C22F95865ULL,
		0x5E57FB4CD967FB42ULL,
		0xD008F757AA264BD6ULL,
		0x687799016A3ECD9AULL,
		0xBB4BB9FCF19D5EF6ULL,
		0x2E410922FCD2C433ULL,
		0x998D64B50C767C32ULL,
		0x0782A3A2053339B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6314FFBA88A7416CULL,
		0xB201C90084696CCDULL,
		0x941999D005AB386DULL,
		0x437F4FE88C64FCC5ULL,
		0x4059F8C07AE2CA53ULL,
		0x1FD16BACE004D56BULL,
		0x12E08572BCEA4406ULL,
		0x078A0E73883C19B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40104B0800A14064ULL,
		0x1201C90080616840ULL,
		0x9008915000220844ULL,
		0x407709000824CC80ULL,
		0x0049B8C070804A52ULL,
		0x0E410920E000C423ULL,
		0x108004300C624402ULL,
		0x07820222003019B1ULL
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
		0x34CCB2AA0BF260E6ULL,
		0xDA017A8E242961DFULL,
		0x5DC0668BF02DA27EULL,
		0xA85C997646BEE372ULL,
		0x12875AAFC80C9F03ULL,
		0x66C35210569F2AC4ULL,
		0x01C7547E5437AEA0ULL,
		0x6A46ECEA09E28D34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2060704206C32664ULL,
		0x80B575257E16C937ULL,
		0x8F782BFA31A2A6C6ULL,
		0x964BBC44229D2845ULL,
		0xA1BCE43AECD84B5DULL,
		0xF751EA3EB41A0464ULL,
		0xE289900869A0A638ULL,
		0xEB341102FA2CD0ADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2040300202C22064ULL,
		0x8001700424004117ULL,
		0x0D40228A3020A246ULL,
		0x80489844029C2040ULL,
		0x0084402AC8080B01ULL,
		0x66414210141A0044ULL,
		0x008110084020A620ULL,
		0x6A04000208208024ULL
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
		0x0DEEADCFED6C1634ULL,
		0xCF74648C58B212DCULL,
		0x934CE141DB287D74ULL,
		0x45E1604DBC875C82ULL,
		0xB965FDAC07905D36ULL,
		0xE7C7DDB585AA39BBULL,
		0xDBB3169305CF522BULL,
		0xBFBD4804E3F17DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F211327679ABC9ULL,
		0x4442661693F1880EULL,
		0xF5C49343DAC34E9CULL,
		0xCF1386671F2DF93DULL,
		0xF7C8F1D3CEAA1629ULL,
		0xE7647AE0FD80E959ULL,
		0x41FD71373AFFF0AAULL,
		0x89C9371A9266D1D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04E2010264680200ULL,
		0x4440640410B0000CULL,
		0x91448141DA004C14ULL,
		0x450100451C055800ULL,
		0xB140F18006801420ULL,
		0xE74458A085802919ULL,
		0x41B1101300CF502AULL,
		0x89890000826051D0ULL
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
		0x7C6342A3B82C5A8BULL,
		0x8BE6E0362F7D00D4ULL,
		0xE6592B34A702A314ULL,
		0x3D73C0042A5DA33BULL,
		0xD72326A06CA01F64ULL,
		0xE24C05D23C6AD383ULL,
		0x79B5800353043BD6ULL,
		0xBB9818A00DFA006FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E78E770002171A4ULL,
		0x4631AE021C8A4BA6ULL,
		0x3AF82753FA34F1ADULL,
		0x6F09344130ED5452ULL,
		0x5E6E495A8CC7E6C3ULL,
		0x326AFC898E67C06DULL,
		0x062748AEC37BF154ULL,
		0x9C61FDEFA4FDC4D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C60422000205080ULL,
		0x0220A0020C080084ULL,
		0x22582310A200A104ULL,
		0x2D010000204D0012ULL,
		0x562200000C800640ULL,
		0x224804800C62C001ULL,
		0x0025000243003154ULL,
		0x980018A004F80040ULL
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
		0x6FA43335B3B9A5A2ULL,
		0x592199BEEF5647DCULL,
		0x167671FD906A1BAAULL,
		0x06488198EE4EC58FULL,
		0x9B8824CC07141D8BULL,
		0x5221CB3F0733C0B4ULL,
		0x481E6890565163C6ULL,
		0xEFDAAF0645CD62F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5476D450515F87DULL,
		0x0AA71F3BF320E058ULL,
		0x50BC215549D0580DULL,
		0x2DA680BE8B88DD30ULL,
		0x5E3FE76BC1479902ULL,
		0x0CE70A01E4EF935DULL,
		0xA718F77FBD2FD99BULL,
		0x0A32B7CCD86D9E14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x250421050111A020ULL,
		0x0821193AE3004058ULL,
		0x1034215500401808ULL,
		0x040080988A08C500ULL,
		0x1A08244801041902ULL,
		0x00210A0104238014ULL,
		0x0018601014014182ULL,
		0x0A12A704404D0214ULL
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
		0x05A9CAD9B986A077ULL,
		0xBC1E4CE62A4A8D10ULL,
		0x80E89409DD060B6BULL,
		0xA53CC2BE1CC00F85ULL,
		0x93FFBFDCB7ECE8E1ULL,
		0x395DD8B85D8F3B53ULL,
		0x90590D98A08650A3ULL,
		0x3AA3D46E180E0D9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FB3AE532136E034ULL,
		0x7BBD11470C31DA3FULL,
		0xE79D260AEC76823BULL,
		0xA0352377154AECAFULL,
		0xFA5B0E2922B5C90AULL,
		0x1BF1EBE4B56B97E1ULL,
		0x0A7E04B3605BEDC5ULL,
		0x7ABBD255F3DD998BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05A18A512106A034ULL,
		0x381C004608008810ULL,
		0x80880408CC06022BULL,
		0xA034023614400C85ULL,
		0x925B0E0822A4C800ULL,
		0x1951C8A0150B1341ULL,
		0x0058049020024081ULL,
		0x3AA3D044100C098BULL
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
		0x273B86BEDF39E063ULL,
		0x9B599CEC88FADFB9ULL,
		0x79BBA7F166CC08E6ULL,
		0x7C98206A7C047F90ULL,
		0xA4B895AB73DE1F04ULL,
		0xF9E62A680068EDEEULL,
		0x46F7651BF925D5D5ULL,
		0x8A08DE2AC3C320DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE28AD90C07319484ULL,
		0x7728B89BCED17DC6ULL,
		0x645B4799152E9757ULL,
		0x83898A938E452814ULL,
		0x829D8ECC215E3A97ULL,
		0x1E40ACE352C3A42CULL,
		0x06CBCD23E7C6B6BFULL,
		0x49C4629482F4B88DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x220A800C07318000ULL,
		0x1308988888D05D80ULL,
		0x601B0791040C0046ULL,
		0x008800020C042810ULL,
		0x80988488215E1A04ULL,
		0x184028600040A42CULL,
		0x06C34503E1049495ULL,
		0x0800420082C0208CULL
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
		0x85EC43F5FB5175C6ULL,
		0x9CBAF85FA35F95BDULL,
		0xC6E3847486938ADFULL,
		0x2A888A6834B2621CULL,
		0xD3418D6EBDC7E799ULL,
		0x0BFC5ADDB69C0D57ULL,
		0xFF9DA0B21FDC686AULL,
		0xCBC4A5CFD85A8EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA905A57DC6E37140ULL,
		0x9BC41BEA7AC23FF1ULL,
		0xFBB4E02E43CBB338ULL,
		0xC3FF6821B41447CCULL,
		0x9EFCD5B5D540E28FULL,
		0xCC23A7D1DB575AFFULL,
		0x0AE1BF4FFA466796ULL,
		0x4CA7E946C8D682EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81040175C2417140ULL,
		0x9880184A224215B1ULL,
		0xC2A0802402838218ULL,
		0x028808203410420CULL,
		0x924085249540E289ULL,
		0x082002D192140857ULL,
		0x0A81A0021A446002ULL,
		0x4884A146C85282E0ULL
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
		0xB8BADA14C9ED41FDULL,
		0xAE1BD55C05A6C0C0ULL,
		0x801548EF26C0E8B5ULL,
		0x37743A3D84E90FE9ULL,
		0x59CEF817A40C13D0ULL,
		0xA303C3875741D7BAULL,
		0x6647A2EB431F5484ULL,
		0xDC8ECC7C8A371A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B5E01A4F2E35DBAULL,
		0x26B7F1640D2B725CULL,
		0xA510B61B5061ABA5ULL,
		0xFCC4496131F0E717ULL,
		0xE15A67211471928EULL,
		0xD63483EA87E0429AULL,
		0xC04BC81149EB104DULL,
		0xC110FE3EAE6A77B2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x081A0004C0E141B8ULL,
		0x2613D14405224040ULL,
		0x8010000B0040A8A5ULL,
		0x3444082100E00701ULL,
		0x414A600104001280ULL,
		0x820083820740429AULL,
		0x40438001410B1004ULL,
		0xC000CC3C8A221230ULL
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
		0x977DCED1C80C1A7BULL,
		0x4A92A777D90A93A4ULL,
		0xD9EB31A3DD7E189AULL,
		0xF80B45863D9088BEULL,
		0xFCDF1856067AD8A9ULL,
		0x807D36E8A04C5AFBULL,
		0x5BBAE15CDA5AD48EULL,
		0x2AF991A7DABF9DC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC48B6F3B069EC8E0ULL,
		0x244A5D4F3B356E7BULL,
		0x848D382B4D724EBEULL,
		0x3F464FA50AFAF0E7ULL,
		0x0F524D465782DEF7ULL,
		0x011EF57588CDCF37ULL,
		0x530FA2BB78430A25ULL,
		0xC7EA695C3E080A08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84094E11000C0860ULL,
		0x0002054719000220ULL,
		0x808930234D72089AULL,
		0x38024584089080A6ULL,
		0x0C5208460602D8A1ULL,
		0x001C3460804C4A33ULL,
		0x530AA01858420004ULL,
		0x02E801041A080808ULL
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
		0xE54777AE42412576ULL,
		0x82F34ED6DC5D788EULL,
		0xFE61D4A8CDF6A595ULL,
		0xF55769179447ADCDULL,
		0x9049E1C6B95EB375ULL,
		0x193BEFEE1B418C98ULL,
		0x3AC4A59D398B9596ULL,
		0xAB270EBDF660C900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F636531FD703FA0ULL,
		0x29AE95AF8A764482ULL,
		0x6D2DA7F611D05A8AULL,
		0x96419492A97CA160ULL,
		0x015510819DA0E457ULL,
		0xDC8C65EA381BBD4DULL,
		0x8BBCBC0CEE6493D0ULL,
		0x3B2478ED9372EFB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0543652040402520ULL,
		0x00A2048688544082ULL,
		0x6C2184A001D00080ULL,
		0x944100128044A140ULL,
		0x004100809900A055ULL,
		0x180865EA18018C08ULL,
		0x0A84A40C28009190ULL,
		0x2B2408AD9260C900ULL
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
		0x07760826B922F472ULL,
		0x9E0E97CD08196778ULL,
		0x13CF92479813652AULL,
		0x05F03D67E1B25338ULL,
		0x4D458528B18A4D5DULL,
		0x51FA4DD59D734BD5ULL,
		0xF0E167F93FA872E2ULL,
		0x85BE215A0345F185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB843E03F87AFE474ULL,
		0xA439875B2AFB9B44ULL,
		0x070E43F97BD69FE6ULL,
		0x7B806AF5AC7449E7ULL,
		0x7C37C8F83A4CAFD6ULL,
		0x29372E7B5662D24DULL,
		0x21E332509A9DB6E9ULL,
		0x19ACB68954C0D77AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x004200268122E470ULL,
		0x8408874908190340ULL,
		0x030E024118120522ULL,
		0x01802865A0304120ULL,
		0x4C05802830080D54ULL,
		0x01320C5114624245ULL,
		0x20E122501A8832E0ULL,
		0x01AC20080040D100ULL
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
		0xFCBF0E52E4A6A522ULL,
		0x028F37982B6F564CULL,
		0x0F6F8AC4DD6E3855ULL,
		0xB5DB3FAE8DDE08AAULL,
		0xC06E865EC38795CFULL,
		0x416130B2356380F3ULL,
		0xAB2E4FA40645014EULL,
		0xD361F2C68C72F027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E38CF52EB8C77C3ULL,
		0xE606805F06E635FAULL,
		0x3DEA74F580E19D53ULL,
		0x43934CEB7E545490ULL,
		0xB728E52E40413710ULL,
		0x3F8883B3060E57F8ULL,
		0xD5828E28F7F09011ULL,
		0xB224EC5B9C1C29ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C380E52E0842502ULL,
		0x0206001802661448ULL,
		0x0D6A00C480601851ULL,
		0x01930CAA0C540080ULL,
		0x8028840E40011500ULL,
		0x010000B2040200F0ULL,
		0x81020E2006400000ULL,
		0x9220E0428C102023ULL
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
		0xD6D5ECAE8C548BBEULL,
		0xD7DF00A023DB10F3ULL,
		0x8ED805EC3748A88DULL,
		0xF8A9E2B2F24FF39AULL,
		0x589932611C8BEB40ULL,
		0x8A1124230A9D1DC2ULL,
		0x8A70A0D0384E9CB5ULL,
		0xD3FC73F942EB8C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B2884DE6846114FULL,
		0xF5DF82B7636E2C0BULL,
		0x414938CEEBE3E757ULL,
		0x89315097426FA8A9ULL,
		0x6ADCD8A3E14078A0ULL,
		0x033A702F6EC9A0DAULL,
		0xB20BA55E7A776A1DULL,
		0x979F4F2C54F55C76ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4200848E0844010EULL,
		0xD5DF00A0234A0003ULL,
		0x004800CC2340A005ULL,
		0x88214092424FA088ULL,
		0x4898102100006800ULL,
		0x021020230A8900C2ULL,
		0x8200A05038460815ULL,
		0x939C432840E10C52ULL
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
		0x47B2C11B8CA1E09AULL,
		0xCB6448163562C6C2ULL,
		0x4DD0692B32D41D13ULL,
		0x554B568549B7B647ULL,
		0x191760C2CED38C9FULL,
		0x2A8B3EDEDA9A9CB3ULL,
		0xC50AE59CB0590EDFULL,
		0x24A78F2D9B535E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F0FC849E1E401FEULL,
		0x5CD08BD774E570BDULL,
		0xA97F10463C7A34D1ULL,
		0xF4DE80B9C0E874BFULL,
		0x34E930B97E5C1E72ULL,
		0x80530BD0966F7744ULL,
		0x758968C55810440EULL,
		0x5084D9B08E0F3292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0702C00980A0009AULL,
		0x4840081634604080ULL,
		0x0950000230501411ULL,
		0x544A008140A03407ULL,
		0x100120804E500C12ULL,
		0x00030AD0920A1400ULL,
		0x450860841010040EULL,
		0x008489208A031200ULL
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
		0x302FA7C8F88BFFDEULL,
		0xEA4EC3C82FEF31F0ULL,
		0xDAB5E7D5BC2D0DFAULL,
		0xC5C8437998B432D5ULL,
		0xD512890103587CFFULL,
		0x6D0ED5FDF3A33607ULL,
		0xCE9B0E9538C28B83ULL,
		0x5E561B77BD809982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DBBBB320CFA67A8ULL,
		0x0FE0748FCD33C635ULL,
		0xE39C69C0A615D73EULL,
		0xAFA25644A2E57B40ULL,
		0x156457060CE981B5ULL,
		0x217D9505352E9AEFULL,
		0x72C6F6868097D42AULL,
		0xDC4FBB785E8EB6A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x102BA300088A6788ULL,
		0x0A4040880D230030ULL,
		0xC29461C0A405053AULL,
		0x8580424080A43240ULL,
		0x15000100004800B5ULL,
		0x210C950531221207ULL,
		0x4282068400828002ULL,
		0x5C461B701C809080ULL
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
		0xB5D6C658BFE2F355ULL,
		0xC1F9CCDC3A01DE30ULL,
		0xC61BC464BFD97B14ULL,
		0x6F752D2941885EEBULL,
		0x99DF092D1713C24EULL,
		0x2968C5F9AE833969ULL,
		0xBDCD89BFA4D33251ULL,
		0x3B042B8998BC8301ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0185D783D92A67FULL,
		0xF82B15F21281929DULL,
		0x4B37CA41CEC6A178ULL,
		0x0131EC2FE3EE5F75ULL,
		0x6415FE0982D3CE05ULL,
		0x9DAFCB36D0A29EE0ULL,
		0xFD754986C4F2AB25ULL,
		0x3FCFD34FEE8A8D84ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA01044583D82A255ULL,
		0xC02904D012019210ULL,
		0x4213C0408EC02110ULL,
		0x01312C2941885E61ULL,
		0x001508090213C204ULL,
		0x0928C13080821860ULL,
		0xBD45098684D22201ULL,
		0x3B04030988888100ULL
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
		0x9097A28CE64E9137ULL,
		0x7E51A1390441EB06ULL,
		0x6D80A37F64DA97CFULL,
		0x7E0154612153DB6FULL,
		0xE3F8F138E8C94D8EULL,
		0x2D714B111547D147ULL,
		0x99C3CC1A10F3ABBBULL,
		0x01379079FD3F55D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF04B93771189F9DULL,
		0x64542F5A56C9A4CFULL,
		0xB1BAEEEB60F577B6ULL,
		0xC18FD26E7C70B50CULL,
		0xA4FC4CB4F45A3AD3ULL,
		0x9207B82E93766841ULL,
		0x8BAC7E368579E7F7ULL,
		0x51FA6C26E0A8F75DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9004A00460089115ULL,
		0x645021180441A006ULL,
		0x2180A26B60D01786ULL,
		0x400150602050910CULL,
		0xA0F84030E0480882ULL,
		0x0001080011464041ULL,
		0x89804C120071A3B3ULL,
		0x01320020E0285559ULL
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
		0x50FC727419E2303CULL,
		0x22D7A74D3BDBA535ULL,
		0xDEA029DEC102FAD7ULL,
		0xAFFB73D2117AE765ULL,
		0xE691FA518BBABA4AULL,
		0xD782B2DFFB0E3926ULL,
		0xA59324A7FF74E037ULL,
		0x2054D98DAD79B36DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0405C04809B3ED25ULL,
		0x610371111E01F1CFULL,
		0x5AEDE1E42EB5A438ULL,
		0x07ABF25CAB902A84ULL,
		0xBBC3044B6D7E64E4ULL,
		0x9D220551C672D877ULL,
		0x76BE974E5A474465ULL,
		0xEBE6A0A3B8DAE21DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0004404009A22024ULL,
		0x200321011A01A105ULL,
		0x5AA021C40000A010ULL,
		0x07AB725001102204ULL,
		0xA2810041093A2040ULL,
		0x95020051C2021826ULL,
		0x249204065A444025ULL,
		0x20448081A858A20DULL
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
		0x8E7F2D10D8870F0CULL,
		0x624373F2A93A2B70ULL,
		0x12B566CEB6E26A54ULL,
		0x8C6645F05EA56895ULL,
		0xC0B39D4FE4207951ULL,
		0x8E36FA20585753A6ULL,
		0x552162CD1AFD3DB3ULL,
		0x72DA758D419E8E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B89A51A526BDFAULL,
		0xB6CDF0B52FD42FC7ULL,
		0xBECBC072408E055CULL,
		0xF11334271A07EE98ULL,
		0x9541A75FA939069FULL,
		0x112EA05590C7D5E7ULL,
		0xE8A73825CC1CBA41ULL,
		0x3CBDB76938A9C3DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0838081080060D08ULL,
		0x224170B029102B40ULL,
		0x1281404200820054ULL,
		0x800204201A056890ULL,
		0x8001854FA0200011ULL,
		0x0026A000104751A6ULL,
		0x40212005081C3801ULL,
		0x3098350900888258ULL
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
		0xA75FD450EEF25BC2ULL,
		0xE75A6C3E79B39937ULL,
		0xA279FF3C8B8E1013ULL,
		0x297E08FC2C302949ULL,
		0x8FA8179FC52403B1ULL,
		0x2C619FE4F15742E1ULL,
		0xB7B44256F8B92A0CULL,
		0x88FC505D86E5B1DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5FE25C7B188706ULL,
		0x586FEF3FD43000C4ULL,
		0x82AC7855882B0D6AULL,
		0x9F5039B292C1BA80ULL,
		0x8BF27DBFA1467B03ULL,
		0x0C4F023C7365769BULL,
		0xD29B9968A8FE63ECULL,
		0x1BAB9480B0F51B21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x235FC0506A100302ULL,
		0x404A6C3E50300004ULL,
		0x82287814880A0002ULL,
		0x095008B000002800ULL,
		0x8BA0159F81040301ULL,
		0x0C41022471454281ULL,
		0x92900040A8B8220CULL,
		0x08A8100080E51101ULL
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
		0x12ADDF70A26589E8ULL,
		0x8AAB9DCF65D5993AULL,
		0x4FC3A5D25105C9A4ULL,
		0x07F810AD910932AFULL,
		0x4CEF2E690529287FULL,
		0x81B2002613A3D44AULL,
		0x81682195B001B652ULL,
		0x492B8ABD94E5802BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51218781F7FD4632ULL,
		0xAE1F5A5F6A19C36AULL,
		0x875EBD42A7EDC038ULL,
		0x76D43C9394256C30ULL,
		0xE70CB027F44F66F9ULL,
		0x2CB0222C381385E1ULL,
		0x78507B8726724CA9ULL,
		0xB55991B7BFFDEF0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10218700A2650020ULL,
		0x8A0B184F6011812AULL,
		0x0742A5420105C020ULL,
		0x06D0108190012020ULL,
		0x440C202104092079ULL,
		0x00B0002410038440ULL,
		0x0040218520000400ULL,
		0x010980B594E5800AULL
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
		0x7C3E31AE973B47EEULL,
		0x5D7963B466EB7B61ULL,
		0xA03ED0FF92ABD4F0ULL,
		0x21907894310F6709ULL,
		0xCBCFB41E1AE44CD8ULL,
		0xEE1748AF127E3B48ULL,
		0xA6BFDCAD696393F0ULL,
		0x136B4E606C75D25EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3F3AE12C254EFBBULL,
		0xC4EC25C77DE3B674ULL,
		0x0F999E0028E737B4ULL,
		0x9D4CCACE7BEFDA20ULL,
		0xEE460264E58DB9F0ULL,
		0xCF34C3091009C207ULL,
		0x874FD3BFDE426631ULL,
		0x9339D45EF8F0A9C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20322002821047AAULL,
		0x4468218464E33260ULL,
		0x0018900000A314B0ULL,
		0x01004884310F4200ULL,
		0xCA460004008408D0ULL,
		0xCE14400910080200ULL,
		0x860FD0AD48420230ULL,
		0x1329444068708044ULL
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
		0xD368929E60BBABEEULL,
		0x0E5525E10104326DULL,
		0xD3E2A575888984B9ULL,
		0x847EEB843380F20AULL,
		0xB73EEFBC3596C7A7ULL,
		0x016647963CAC6516ULL,
		0x89A69F976807F808ULL,
		0x29BB51E4BC071019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0259A39920A1EAULL,
		0xE286372B2ECB9481ULL,
		0x6A11F6B7902CA60CULL,
		0xB898760196F89B8AULL,
		0x99CBFD4043B2C0F7ULL,
		0x5338809F71E18749ULL,
		0xB1A2ABEAB07A26D0ULL,
		0x03D9FF3A22DE9292ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD20010820020A1EAULL,
		0x0204252100001001ULL,
		0x4200A43580088408ULL,
		0x801862001280920AULL,
		0x910AED000192C0A7ULL,
		0x0120009630A00500ULL,
		0x81A28B8220022000ULL,
		0x0199512020061010ULL
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
		0x9214D8EB5EDC112FULL,
		0x3037689CCA6A046FULL,
		0x26C3E8CF1C85C7B5ULL,
		0x4810E9DDE8DA41F9ULL,
		0x07CF1E7B7F89B3C6ULL,
		0x4F4D7E4EC9FCB102ULL,
		0x5C9DE3BF4AF56D2EULL,
		0x30403455CAC0785DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EC24A6742D6868FULL,
		0xECC67B36BE88D626ULL,
		0x9D8E9F04030CF8ECULL,
		0xE1E8A4B5EE43F12EULL,
		0xA2AECDEA3428BF97ULL,
		0x6EF300B839EFCB88ULL,
		0x6ACF37E3BC346A88ULL,
		0x004C8EC644955169ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0200486342D4000FULL,
		0x200668148A080426ULL,
		0x048288040004C0A4ULL,
		0x4000A095E8424128ULL,
		0x028E0C6A3408B386ULL,
		0x4E41000809EC8100ULL,
		0x488D23A308346808ULL,
		0x0040044440805049ULL
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
		0x95DE6A590E2D1100ULL,
		0x5332379B591681C9ULL,
		0x47E1938522866D15ULL,
		0xF3015F44E11C9BCBULL,
		0xC3090264D0F76A9DULL,
		0x37DCEE338C35C9ADULL,
		0x8E527E860DB01FC6ULL,
		0x33F17180DA9E9E6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14D7A205E3377BFFULL,
		0x05C893D1B59E2D62ULL,
		0x2B3FC888F888B32DULL,
		0xC221176D81D3D2CAULL,
		0x6634C75EEB2547DDULL,
		0xFAE3D1CD6ACCC74DULL,
		0x8CC59E048551983CULL,
		0x76F7D5EDD62C41C6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14D6220102251100ULL,
		0x0100139111160140ULL,
		0x0321808020802105ULL,
		0xC2011744811092CAULL,
		0x42000244C025429DULL,
		0x32C0C0010804C10DULL,
		0x8C401E0405101804ULL,
		0x32F15180D20C0044ULL
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
		0x92E4532B10AD42D4ULL,
		0x94BD500C4ED97A4DULL,
		0xCE3BF6326CA1BB20ULL,
		0x23FD6673A4B9AB34ULL,
		0xFE59BDE416818836ULL,
		0xAE207DF688AFB8F2ULL,
		0xCB03376B56485AF9ULL,
		0xC403EB0585720C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DB31DDCDBE542DULL,
		0x86991C6845296B89ULL,
		0xF684B7423950218DULL,
		0x7F78039CC64E4939ULL,
		0x6CEA0A1207A38A3EULL,
		0x5FE849A532BF205DULL,
		0xF9258E2400B838CBULL,
		0xB6C1388A38367945ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82C0110900AC4004ULL,
		0x8499100844096A09ULL,
		0xC600B60228002100ULL,
		0x2378021084080930ULL,
		0x6C48080006818836ULL,
		0x0E2049A400AF2050ULL,
		0xC9010620000818C9ULL,
		0x8401280000320800ULL
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
		0x7550B0442795543EULL,
		0xACCFEA28B29E3BE5ULL,
		0xD81C41316A484DFDULL,
		0x22E4D12FE7DD20B9ULL,
		0xCE41AF40DBE84D94ULL,
		0xE45393E652E3C837ULL,
		0xAB67CD89299FBD29ULL,
		0x212EC42A5FD947FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22A6B05BF21D25A1ULL,
		0x445999145D3FAEC0ULL,
		0x1322B2A928376E73ULL,
		0x76D4EE3522E5926DULL,
		0x8C8E91EF2AF03C70ULL,
		0xA1963C9F3B3294C9ULL,
		0x9F4718E68F3FFDB1ULL,
		0x03C86C6955EF1C3BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2000B04022150420ULL,
		0x04498800101E2AC0ULL,
		0x1000002128004C71ULL,
		0x22C4C02522C50029ULL,
		0x8C0081400AE00C10ULL,
		0xA012108612228001ULL,
		0x8B470880091FBD21ULL,
		0x0108442855C90439ULL
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
		0x88B5E83AA8E0FA8FULL,
		0xE0520BFBB5FD8678ULL,
		0xA5D071076C5AFAA2ULL,
		0xBB695C76CB4277D4ULL,
		0x8A36881828363B1DULL,
		0x3709882C170CA32AULL,
		0xC60CC7351BB73237ULL,
		0x2D9E4C40C7D3BF4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB62676A1A1AD9DA3ULL,
		0x3BE93395D8A6A0F7ULL,
		0x751A268EAAE7BB95ULL,
		0xBBA8133BFFB992F4ULL,
		0x922B6CC7CCA9444FULL,
		0x2A41F13FC5185392ULL,
		0x4F30C153D88A7DD6ULL,
		0x9FDE77A1716549DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80246020A0A09883ULL,
		0x2040039190A48070ULL,
		0x251020062842BA80ULL,
		0xBB281032CB0012D4ULL,
		0x822208000820000DULL,
		0x2201802C05080302ULL,
		0x4600C11118823016ULL,
		0x0D9E440041410948ULL
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
		0x15958D060893ECFBULL,
		0x72F7FDA568F1B9B3ULL,
		0x603A37B9E1ED0F17ULL,
		0x4E85E3B035D091EDULL,
		0x1F52DB1CCEEE1DCBULL,
		0xF458D02D58EB50D3ULL,
		0xC09DB8FC62EC596AULL,
		0xAC3A41D5A4968A95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB765071649EB5DC7ULL,
		0xE83F965590C0C13FULL,
		0x86C8AC9975F5220BULL,
		0x06A23A344B0069D4ULL,
		0xEE6D2A643FB805E2ULL,
		0xC4DF015E3C5B7E5BULL,
		0x363D95C688070762ULL,
		0x2DCF67ACDF2A4834ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1505050608834CC3ULL,
		0x6037940500C08133ULL,
		0x0008249961E50203ULL,
		0x06802230010001C4ULL,
		0x0E400A040EA805C2ULL,
		0xC458000C184B5053ULL,
		0x001D90C400040162ULL,
		0x2C0A418484020814ULL
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
		0xF706BCF7EDD9B767ULL,
		0x8CAB575C3F7DC1ADULL,
		0x1852C92E0666A18AULL,
		0xCDAB4CE7018A6B5EULL,
		0x70E29EFE1E752B7AULL,
		0x690161AFE600CA3FULL,
		0x2561AA5B12354406ULL,
		0x58FF40E2C1ED45A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF56E3F2A7FBCC3DULL,
		0xA2F8470BA25D3ABAULL,
		0x931A0E16D270BCE5ULL,
		0x0DBB097FC6B7D1A3ULL,
		0x84F3290C968F3EECULL,
		0x9EE35C6E26973597ULL,
		0xAFE9C8289A890030ULL,
		0xD770981DECED5779ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC706A0F2A5D98425ULL,
		0x80A84708225D00A8ULL,
		0x101208060260A080ULL,
		0x0DAB086700824102ULL,
		0x00E2080C16052A68ULL,
		0x0801402E26000017ULL,
		0x2561880812010000ULL,
		0x50700000C0ED4520ULL
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
		0x1E7F29C7D5F7A961ULL,
		0x50C336E150FA0998ULL,
		0x8C341805834FF120ULL,
		0x3692ECD26B6DB449ULL,
		0x03E198D4B3457B14ULL,
		0x3EAE7A28D54E5111ULL,
		0x1073238D8FBCA973ULL,
		0x3F5C1E81EA54E2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D80C206F8C8FA1DULL,
		0x9FA2F7D527441380ULL,
		0x9DC09E5A421D2D56ULL,
		0x0C2660317D9FE20CULL,
		0x963861256808C807ULL,
		0x83F8D285C22804B0ULL,
		0x9C3AE7A07D676426ULL,
		0x077FFF833AA1266AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C000006D0C0A801ULL,
		0x108236C100400180ULL,
		0x8C001800020D2100ULL,
		0x04026010690DA008ULL,
		0x0220000420004804ULL,
		0x02A85200C0080010ULL,
		0x103223800D242022ULL,
		0x075C1E812A002220ULL
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
		0x943E4FA22C49AC65ULL,
		0x40B87199C290971EULL,
		0xB8A8282DB3D01FDDULL,
		0x043962732038A49EULL,
		0xC4405028557ECA50ULL,
		0x0D045257E1FB2992ULL,
		0x9300E036F1FDD634ULL,
		0x44D0510B1B1D64A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE477E9DDFEC13FA6ULL,
		0x0DE667246FCB89E5ULL,
		0x918C76EBFC604ACCULL,
		0x5DA0A19FFB9A6609ULL,
		0x6E861FEDBBBD9A02ULL,
		0xF4DB20F15540B826ULL,
		0x3FB4F12EC4BA6A92ULL,
		0x8EBDCAE88EDB7B89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x843649802C412C24ULL,
		0x00A0610042808104ULL,
		0x90882029B0400ACCULL,
		0x0420201320182408ULL,
		0x44001028113C8A00ULL,
		0x0400005141402802ULL,
		0x1300E026C0B84210ULL,
		0x049040080A196081ULL
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
		0x202F522E84E1034EULL,
		0x118FE58BD61D877EULL,
		0x7708A4A0C4E822AFULL,
		0x4025AC79D159ECD8ULL,
		0x65F71ED304F775C2ULL,
		0xF0122BD224D8478AULL,
		0x310897B71FCB346EULL,
		0x8ACB35C9588230B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9392DD36260F7993ULL,
		0xF5AD3B7AB6C2DB12ULL,
		0x6F1ABB90BFEBEA77ULL,
		0x585C5BD26A5E063BULL,
		0x26B4014D37FE359FULL,
		0xE230E7372BB89192ULL,
		0x972F5C0C7F358443ULL,
		0x9E29426C8C1ABF5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0002502604010102ULL,
		0x118D210A96008312ULL,
		0x6708A08084E82227ULL,
		0x4004085040580418ULL,
		0x24B4004104F63582ULL,
		0xE010231220980182ULL,
		0x110814041F010442ULL,
		0x8A09004808023012ULL
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
		0xC0F045FF5D683072ULL,
		0x1D4B16AE15EB46F1ULL,
		0x3A44EF9804E6C02CULL,
		0xC6D0EA20C5E41A6CULL,
		0x8888528A6B02B3F7ULL,
		0xA4B07BC7FDE1D745ULL,
		0x88E7C737DAFC597CULL,
		0x84C8DECBD4986815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB6B125DBB2599F1ULL,
		0xBF2FBBD5C9702319ULL,
		0x35CE57C9B5C0213EULL,
		0x990681222FF59A3AULL,
		0x3B40DDFAFE18E685ULL,
		0xE8CAD7AEC79488BAULL,
		0x0F3D2F72061D4112ULL,
		0x55A7DCDCBED8D0F4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8060005D19201070ULL,
		0x1D0B128401600211ULL,
		0x3044478804C0002CULL,
		0x8000802005E41A28ULL,
		0x0800508A6A00A285ULL,
		0xA0805386C5808000ULL,
		0x08250732021C4110ULL,
		0x0480DCC894984014ULL
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
		0xBE457564A1A21938ULL,
		0x4A23E4EBA67D037FULL,
		0xE42CB2F930AD5226ULL,
		0x53F0E0869F2043F1ULL,
		0xDCDB85A967275D55ULL,
		0x0C033C9E50B1FCADULL,
		0xD7AA8200C525164EULL,
		0x54DD46FBBE4381C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA240B73F09D33D5DULL,
		0xA0210F316CBF5F90ULL,
		0xC0CF54A0CD743F4DULL,
		0xBE39E8AECB6EA9CEULL,
		0xF75009EA0C33FBE9ULL,
		0x59CC40AD1A4E1453ULL,
		0xA127518A8ED4899EULL,
		0x28B5719413C3BDFBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA240352401821918ULL,
		0x00210421243D0310ULL,
		0xC00C10A000241204ULL,
		0x1230E0868B2001C0ULL,
		0xD45001A804235941ULL,
		0x0800008C10001401ULL,
		0x812200008404000EULL,
		0x00954090124381C2ULL
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
		0x458F77F16A61AF38ULL,
		0xDFEF5549117DBDF5ULL,
		0x67E7E831B78568C4ULL,
		0x3D1AC332E10D17AAULL,
		0xCD1BCABB2E0196B1ULL,
		0xC2B6A2D8D1FD0700ULL,
		0x61470C2B4B0BB4EEULL,
		0x27CFE03940AFEB07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69C1494BDA5E7558ULL,
		0x310818C31F19BB0BULL,
		0x678D79B109DA5176ULL,
		0x3CBCE687C69AB505ULL,
		0x3AC94F6476E850BBULL,
		0x9A02BA8FDD139DBEULL,
		0x0E23E20E207EF455ULL,
		0x89CF123D83E1D58BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x418141414A402518ULL,
		0x110810411119B901ULL,
		0x6785683101804044ULL,
		0x3C18C202C0081500ULL,
		0x08094A20260010B1ULL,
		0x8202A288D1110500ULL,
		0x0003000A000AB444ULL,
		0x01CF003900A1C103ULL
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
		0x8173FA5C85E8C3C8ULL,
		0x24D972220DBC4557ULL,
		0x5A6B89E0E942DB64ULL,
		0x687D3DE74C5A626FULL,
		0xA10995794ACB7AC4ULL,
		0x374E1F696FFC76ACULL,
		0xA933C388049C6D86ULL,
		0x72DA8356876A7219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBC2CE0C8B5F8231ULL,
		0x3A3A5E8F56953DCDULL,
		0x450C1E33D1D623A0ULL,
		0x0436EC263396C646ULL,
		0xC2998A1ACC47A57BULL,
		0x2AE0D3CBBD18DE41ULL,
		0x9FC22E5255471E09ULL,
		0xEEFA9AC8FAC549ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8142CA0C81488200ULL,
		0x2018520204940545ULL,
		0x40080820C1420320ULL,
		0x00342C2600124246ULL,
		0x8009801848432040ULL,
		0x224013492D185600ULL,
		0x8902020004040C00ULL,
		0x62DA824082404009ULL
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
		0x8E1350682F54ADAAULL,
		0x8635FA52547F7836ULL,
		0x8F3A26589164846EULL,
		0xC80E90ED45447292ULL,
		0x3A868C069D3B85DBULL,
		0x41C3D3CF4D081231ULL,
		0x3356F30BDAAB26FFULL,
		0xCE644CD312BB2880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D04B27B50A7B53FULL,
		0x9810B8DD6DAFE70CULL,
		0x0D963EE3AD05969FULL,
		0xD59EC99331BE222FULL,
		0x9EDFE18C9A6331C3ULL,
		0x5C7D199C543186EBULL,
		0x9F978C1992999A8FULL,
		0x383033EA6EC464DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C0010680004A52AULL,
		0x8010B850442F6004ULL,
		0x0D1226408104840EULL,
		0xC00E808101042202ULL,
		0x1A868004982301C3ULL,
		0x4041118C44000221ULL,
		0x131680099289028FULL,
		0x082000C202802080ULL
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
		0xCA98D1B41D0C7D7BULL,
		0x1A4403D0BC6A7E45ULL,
		0x943D52F986461995ULL,
		0x8CFD4777B7E3F0BEULL,
		0x1D9E269C2379EE1EULL,
		0x638C0786804B14E0ULL,
		0x52A99FBEB49ACC18ULL,
		0xB9C63CCC69AE5397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6AF3DEBB87455E8ULL,
		0x5425E52ECCD521FEULL,
		0x435577E987037251ULL,
		0x765998776626A10CULL,
		0xA701363CACD28B8FULL,
		0x41A12614048540A8ULL,
		0xB5C484FDA2BD82B7ULL,
		0x442C76574D62FA67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC28811A018045568ULL,
		0x100401008C402044ULL,
		0x001552E986021011ULL,
		0x045900772622A00CULL,
		0x0500261C20508A0EULL,
		0x41800604000100A0ULL,
		0x108084BCA0988010ULL,
		0x0004344449225207ULL
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
		0xA96CCDC931C10636ULL,
		0x5FE12F778C317FD9ULL,
		0x8C5352F52C1E40DDULL,
		0x83089B37C76CC680ULL,
		0x2CB9760127A43AA3ULL,
		0xEC763FCB72D34993ULL,
		0xBA386BF53E61AF51ULL,
		0xFBC5A195B227EAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB611FAF12D9FFCF6ULL,
		0xDC0925E9A8259B80ULL,
		0xE56F5DCFD204CB8BULL,
		0x126038CF0C057979ULL,
		0xDDD03E407FAB7595ULL,
		0xD80F0283994D6B33ULL,
		0x6039C03233F68073ULL,
		0x31F87B5665F5C234ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA000C8C121810436ULL,
		0x5C01256188211B80ULL,
		0x844350C500044089ULL,
		0x0200180704044000ULL,
		0x0C90360027A03081ULL,
		0xC806028310414913ULL,
		0x2038403032608051ULL,
		0x31C021142025C220ULL
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
		0x931D2D6C84BFC14CULL,
		0xFCC4BC3811157806ULL,
		0x6AFF91E885D01FBDULL,
		0x7BBCDFC6E3F7A55BULL,
		0x1CF165D231D9D08DULL,
		0x5CBEF1C207155B98ULL,
		0xC794F0A9F04BEFFAULL,
		0xCDF9E5AD39169A9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8E3EF410CD2B64ULL,
		0xE58462F439147349ULL,
		0xDCBA16077BF26603ULL,
		0x8827E67E535451FAULL,
		0x002DDBE7E6376C48ULL,
		0xD6A4953796DD73C1ULL,
		0x275BF1A191E74D52ULL,
		0x864C47110D06B249ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x000C2C64008D0144ULL,
		0xE484203011147000ULL,
		0x48BA100001D00601ULL,
		0x0824C6464354015AULL,
		0x002141C220114008ULL,
		0x54A4910206155380ULL,
		0x0710F0A190434D52ULL,
		0x8448450109069208ULL
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
		0xF88254E4151DD30DULL,
		0x5A72F84A7BE4E032ULL,
		0xFDC9367606DAEC30ULL,
		0x132F9E4F3D9ACA8BULL,
		0x7B926DD635A0C720ULL,
		0xC629C0CFC9F45A2CULL,
		0x3D5A2522E752BE34ULL,
		0xBB777573350C3BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36C0B3F4D6A8152BULL,
		0x94DBCD92386D06A4ULL,
		0x71351F0792AF67CBULL,
		0x1F7D5E2E37C04B44ULL,
		0x4A3791C67E2BF3A9ULL,
		0x1A07FA69F8EC5E75ULL,
		0x935438D000541754ULL,
		0xCE8B6791ADF3B0E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x308010E414081109ULL,
		0x1052C80238640020ULL,
		0x71011606028A6400ULL,
		0x132D1E0E35804A00ULL,
		0x4A1201C63420C320ULL,
		0x0201C049C8E45A24ULL,
		0x1150200000501614ULL,
		0x8A036511250030C4ULL
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
		0x4FC7DCEA51EC7269ULL,
		0x5F9117CEE80426FDULL,
		0xC72EDA7B6DE9A731ULL,
		0x792FC2EA10E8635BULL,
		0x105C5F6F8AFC726EULL,
		0x86505D0BA0254F5CULL,
		0xACBEA94B1B8D0916ULL,
		0x6059997689CEEBA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FA00FB747A9B76EULL,
		0xE98E69AF746842D8ULL,
		0x5F87C70B9B45F895ULL,
		0x45A24833CF81DB84ULL,
		0x5C51AF493F47550EULL,
		0x6FE4ADF1E62D23ADULL,
		0xA640BF5C241443D6ULL,
		0x2D6E65C5AFAE4FCFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F800CA241A83268ULL,
		0x4980018E600002D8ULL,
		0x4706C20B0941A011ULL,
		0x4122402200804300ULL,
		0x10500F490A44500EULL,
		0x06400D01A025030CULL,
		0xA400A94800040116ULL,
		0x20480144898E4B89ULL
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
		0xB5AEC5DAB2B5BC00ULL,
		0xDF0D80A6BA651F14ULL,
		0x14C55E9F894F9DA0ULL,
		0x2C53B62E5C6E33A8ULL,
		0xD5E62F7006034953ULL,
		0x75E0168CE88FD159ULL,
		0x95A7F91C64E066ABULL,
		0xD3EAD1DE3F6F4F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3EF84B702078752ULL,
		0x4926383C07092F00ULL,
		0x2295C54285072DC3ULL,
		0x17904028910C71C9ULL,
		0x3B861912C06E5AF1ULL,
		0x1EEDB7046CD1F6FDULL,
		0x7D0A7FA9206ED8AEULL,
		0x5108F203D10F0E8EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA1AE849202058400ULL,
		0x4904002402010F00ULL,
		0x0085440281070D80ULL,
		0x04100028100C3188ULL,
		0x1186091000024851ULL,
		0x14E016046881D059ULL,
		0x15027908206040AAULL,
		0x5108D002110F0E0AULL
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
		0x59049550569256D7ULL,
		0x31638D6014C9309CULL,
		0x4F53AA22BAF258FAULL,
		0xA27EA66B510C052EULL,
		0x73F2B9094EE9B8CCULL,
		0xABB90CCF2E47F6CCULL,
		0x4C88CC7EFC4CDB27ULL,
		0x988088CA300E3F94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A1F5FB4740B147ULL,
		0x2BD77BE781ED5829ULL,
		0x3A9F374D6703D66DULL,
		0x55120BD1E85AE7C0ULL,
		0x54F03719164130E6ULL,
		0x2392958359D3DC3FULL,
		0x0BE0273D08B60E03ULL,
		0xC396EDED29D7C8B4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4100955046001047ULL,
		0x2143096000C91008ULL,
		0x0A13220022025068ULL,
		0x0012024140080500ULL,
		0x50F03109064130C4ULL,
		0x239004830843D40CULL,
		0x0880043C08040A03ULL,
		0x808088C820060894ULL
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
		0xF7B53A6A243FD36FULL,
		0xE78200748B07F040ULL,
		0x7E308F4F910F4FA9ULL,
		0x3E4087FF38B215CCULL,
		0x3C4A78ADAB5FC8FCULL,
		0x0A99341DD3D19F1AULL,
		0xAEC874E45FAA022EULL,
		0x30B1C276F13F307EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99213495D727AC55ULL,
		0x661930040F459521ULL,
		0xC270FF70E3F44EA6ULL,
		0xC8A4058F8F8F0FC6ULL,
		0x198C5161D3F47CE0ULL,
		0x5CFC3DA33B31B79DULL,
		0xAE21E2C4EF9956FBULL,
		0x076FBB994D947B69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9121300004278045ULL,
		0x660000040B059000ULL,
		0x42308F4081044EA0ULL,
		0x0800058F088205C4ULL,
		0x18085021835448E0ULL,
		0x0898340113119718ULL,
		0xAE0060C44F88022AULL,
		0x0021821041143068ULL
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
		0xA0A9895BF249F5E7ULL,
		0xB10789B8316AAF87ULL,
		0x6BC36B069AD2771FULL,
		0xFE575E299F8306AFULL,
		0x59468D48641AD5C8ULL,
		0xC753256877A845ABULL,
		0xA6AEA82CA35272E9ULL,
		0x06DB11ADB5EC1B20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA83D8D666C059EB1ULL,
		0x253FE304549A1F3CULL,
		0x538213A25528078FULL,
		0x2F93A8669A9CA41AULL,
		0x138B35AEC064D1CEULL,
		0x1C1B16DD0E2A51E3ULL,
		0x44EC63CDCD0CB9E5ULL,
		0x29A7F94A85968AFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0298942600194A1ULL,
		0x21078100100A0F04ULL,
		0x438203021000070FULL,
		0x2E1308209A80040AULL,
		0x110205084000D1C8ULL,
		0x04130448062841A3ULL,
		0x04AC200C810030E1ULL,
		0x0083110885840A20ULL
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
		0x6BEC6A14F02F54EAULL,
		0xDFF2834020C84D24ULL,
		0xF830050B1D226307ULL,
		0x2B1A23B468A106C0ULL,
		0xBFC16375B969306BULL,
		0x7633998D16CF708DULL,
		0xF20158163E3401ECULL,
		0xC84AD61C621B1689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EB8D63B832C1D76ULL,
		0xACAD138324A1BE3EULL,
		0xE3FA0FFE7DEBBDFFULL,
		0x8A0B5145A57D7BCBULL,
		0xD80E1D51F30E96C7ULL,
		0xD4EAC11EA2F223DFULL,
		0xC3958E0287B2FFE4ULL,
		0x03A5835CFED06BCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0AA84210802C1462ULL,
		0x8CA0030020800C24ULL,
		0xE030050A1D222107ULL,
		0x0A0A0104202102C0ULL,
		0x98000151B1081043ULL,
		0x5422810C02C2208DULL,
		0xC2010802063001E4ULL,
		0x0000821C62100288ULL
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
		0x6807B84E3D8273B0ULL,
		0x1DA013190922732EULL,
		0xD9EC6573350B9C9AULL,
		0xA59215ADA19CBE7FULL,
		0x023E0C84180D0F71ULL,
		0xE8ECCF4BA7D81306ULL,
		0x828E0A8DE9BEB539ULL,
		0xFA178E64453943A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60CCD515E7341EA2ULL,
		0xCA6F66D32DF7F768ULL,
		0xF8A09B405A1783DCULL,
		0x5BFEDA2CA422EA63ULL,
		0x6B9D684C459D62CEULL,
		0xB3496074751975C9ULL,
		0x10B85E8760FF2A35ULL,
		0x1FE667D0125A9319ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60049004250012A0ULL,
		0x0820021109227328ULL,
		0xD8A0014010038098ULL,
		0x0192102CA000AA63ULL,
		0x021C0804000D0240ULL,
		0xA048404025181100ULL,
		0x00880A8560BE2031ULL,
		0x1A06064000180300ULL
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
		0xEACC017E311E5191ULL,
		0x5A75DDBA64C03799ULL,
		0x13A6E99213FCEA8CULL,
		0x8B7562F198DA8754ULL,
		0x77F23D4D50D1779CULL,
		0x61532A057D2EDEC8ULL,
		0x5409D4F6B3ECF2EAULL,
		0xE4D9FDCD8CE25907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCDF54F7320F0DCBULL,
		0x8145E7A5700BCD03ULL,
		0xF31F45854C27B39BULL,
		0x8349D17D02327E7BULL,
		0x586909964A540769ULL,
		0x6D8621F0B30D0F99ULL,
		0x6DBB9153C45B8B8AULL,
		0x1D110640B598130CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8CC0076300E0181ULL,
		0x0045C5A060000501ULL,
		0x130641800024A288ULL,
		0x8341407100120650ULL,
		0x5060090440500708ULL,
		0x61022000310C0E88ULL,
		0x440990528048828AULL,
		0x0411044084801104ULL
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
		0x9E85AFA412F1BB43ULL,
		0x1B0A898E4B8DEC6AULL,
		0xF7488A2AC32CCC6FULL,
		0xD3FD1607218AC29BULL,
		0x30363E231EA17693ULL,
		0xE1E8659FE8C3C2F7ULL,
		0x64A556B260AD9EBCULL,
		0x44B9C0C675E0FCA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDEC9DFF289C3F0DULL,
		0xE6F7CFBA59C38E4FULL,
		0xCA036E0A037D5B19ULL,
		0xB4C4FABD46A82268ULL,
		0x8E4087ECD73651FFULL,
		0x456D6B1DE44F11D4ULL,
		0x704E59E844DC8C76ULL,
		0xF3DCBC80BDC89212ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C848DA400903B01ULL,
		0x0202898A49818C4AULL,
		0xC2000A0A032C4809ULL,
		0x90C4120500880208ULL,
		0x0000062016205093ULL,
		0x4168611DE04300D4ULL,
		0x600450A0408C8C34ULL,
		0x4098808035C09002ULL
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
		0x741FCB01D4B18DA7ULL,
		0x1C870BB89576C472ULL,
		0x1D68D20AAB7D75C3ULL,
		0x352DB83B0DF6C4FEULL,
		0x4EC309E67091B6F4ULL,
		0x4813F9AC71F04DABULL,
		0x137AAD1590E53B24ULL,
		0x90EE99FDDA8495E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB04C46A0A1C5989ULL,
		0x79862735CA58C1C1ULL,
		0xC39D503BE5D82C1DULL,
		0x0D12BE1F37746BBEULL,
		0x568E1762AE95F818ULL,
		0xF611F43C2B79BF69ULL,
		0xD5F11DB74FE4F42FULL,
		0x402DA02DDB235CD2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4004C00000100981ULL,
		0x188603308050C040ULL,
		0x0108500AA1582401ULL,
		0x0500B81B057440BEULL,
		0x468201622091B010ULL,
		0x4011F02C21700D29ULL,
		0x11700D1500E43024ULL,
		0x002C802DDA0014C2ULL
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
		0xEE7EAA8F27EF2457ULL,
		0xB2C4801E82CB8FBBULL,
		0x0304205F00D54219ULL,
		0xD87259C6F5977353ULL,
		0xFBD6E0E2F3589065ULL,
		0xE796778993915ADFULL,
		0x1F6BD75A2DB944BBULL,
		0x768986BB5F733F5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2A514D4C657D1ABULL,
		0xF6F1A1EA53A12F4CULL,
		0x693F293C2C2B0913ULL,
		0x3B8A41E28EE9D7BBULL,
		0xC7CF11C1778B1713ULL,
		0xCCF01C00D78C33F0ULL,
		0xA033D3040B9133A8ULL,
		0x9C27DD88AE8E2283ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA224008406470003ULL,
		0xB2C0800A02810F08ULL,
		0x0104201C00010011ULL,
		0x180241C284815313ULL,
		0xC3C600C073081001ULL,
		0xC4901400938012D0ULL,
		0x0023D300099100A8ULL,
		0x140184880E022201ULL
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
		0x933D352176774952ULL,
		0xB0EAF2E81A1D734AULL,
		0xF346D366913F51AAULL,
		0x10B459C720E353F9ULL,
		0x993E2E6F698C9FC9ULL,
		0x6229714ECC2A9431ULL,
		0x0DB6740D7B68CB94ULL,
		0x170713547780758FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9877687FA3B31951ULL,
		0x655012A249B514CEULL,
		0xB891EF2BE075A60DULL,
		0x9E816762F12465F6ULL,
		0x4549B2A6CCBD3DABULL,
		0x7130DA9195657C94ULL,
		0xC2E5A1793519CA36ULL,
		0x0FE0ABC3CA5CFBAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9035202122330950ULL,
		0x204012A00815104AULL,
		0xB000C32280350008ULL,
		0x10804142202041F0ULL,
		0x01082226488C1D89ULL,
		0x6020500084201410ULL,
		0x00A420093108CA14ULL,
		0x070003404200718AULL
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
		0x353C094AF5874980ULL,
		0x009B6ACF6A3CC339ULL,
		0x095FBAC2E8E82915ULL,
		0xE0376C39F4DE221BULL,
		0x283E2F87E242C141ULL,
		0x9BE69054199131F9ULL,
		0x9F4B3BE0B33F5922ULL,
		0x6314A474B7C88D26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB6851C923B52EFBULL,
		0xD570167ABC5956C1ULL,
		0x5B92BB0F5BCB4F83ULL,
		0x4DDD132AD708A319ULL,
		0x39DEB89C1F7F4428ULL,
		0x9F2A57D89E7AF56AULL,
		0x47817B5C08FE6A99ULL,
		0xAAF351DA4E58B69EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3128014821850880ULL,
		0x0010024A28184201ULL,
		0x0912BA0248C80901ULL,
		0x40150028D4082219ULL,
		0x281E288402424000ULL,
		0x9B22105018103168ULL,
		0x07013B40003E4800ULL,
		0x2210005006488406ULL
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
		0x9FC069E594395EB4ULL,
		0x2768C9C3CB01BB75ULL,
		0xBEAF145CCE953543ULL,
		0xD3EA36AB2EF40318ULL,
		0x5FC36815BCEDA958ULL,
		0x49C875A5EA606996ULL,
		0x80449C9853715CDDULL,
		0xB506FFCE0255A90BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91FB59880185C74FULL,
		0x45B7DED1076C49B0ULL,
		0xEE56837CB517735EULL,
		0xBCA513CB5C65ACADULL,
		0x0D05570A445A0623ULL,
		0x717684AD04ADE825ULL,
		0xF4C3F9D71A87F1E8ULL,
		0xA481F2D9DB2198D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x91C0498000014604ULL,
		0x0520C8C103000930ULL,
		0xAE06005C84153142ULL,
		0x90A0128B0C640008ULL,
		0x0D01400004480000ULL,
		0x414004A500206804ULL,
		0x80409890120150C8ULL,
		0xA400F2C802018803ULL
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
		0x0485CFD3FEDC2060ULL,
		0x0EC7D584ACEC961BULL,
		0x8146B620DCD38208ULL,
		0xD3A0DC672784DC93ULL,
		0xC4A05C406EF50698ULL,
		0x81F492798BFCA7E3ULL,
		0x9687CE66A57EB0F6ULL,
		0x703BACE05E54FDB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C86DD0083ED644ULL,
		0xA3C854617003B59DULL,
		0x9D4642383128C588ULL,
		0x1A3772154F0C6989ULL,
		0xB475FADA7D952EB4ULL,
		0x170B781D68EA92C3ULL,
		0x0C046A858E9AE30CULL,
		0x83ED0F6C2DE65ECDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00804DD0081C0040ULL,
		0x02C0540020009419ULL,
		0x8146022010008008ULL,
		0x1220500507044881ULL,
		0x842058406C950690ULL,
		0x0100101908E882C3ULL,
		0x04044A04841AA004ULL,
		0x00290C600C445C84ULL
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
		0x55A4ECF08155AC75ULL,
		0x752C09DB77889283ULL,
		0xEF4F173326BDFEE9ULL,
		0x37C90E3BF142F066ULL,
		0xF3DB663C3EC37795ULL,
		0x5DDF91187BA9BB93ULL,
		0x847D4AE68E6AB94AULL,
		0xC9AA50A8CC8309B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4418ADB3F99544F7ULL,
		0xB53C05673483AE28ULL,
		0x2DC92C6E0800BBB6ULL,
		0x44C18996980EA769ULL,
		0x067994A536281D3DULL,
		0xB286758C6B11BBBAULL,
		0xBF3F5EF678A4EF96ULL,
		0xAED9D64DE1BC937EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4400ACB081150475ULL,
		0x352C014334808200ULL,
		0x2D4904220000BAA0ULL,
		0x04C108129002A060ULL,
		0x0259042436001515ULL,
		0x108611086B01BB92ULL,
		0x843D4AE60820A902ULL,
		0x88885008C0800136ULL
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
		0x6F55EA594099C5FDULL,
		0xB38C79E0BE38AB63ULL,
		0xC27959FA0337FD1CULL,
		0x8A47F459B1346F2DULL,
		0x2F842CE6F4D71A9BULL,
		0x527EBA0A16F836F0ULL,
		0xC539AC8F43ADEA32ULL,
		0x51469FEF1E108A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3CC7EEBA889020ULL,
		0xF1FD361CB5750D1CULL,
		0x8B82DEDAC30AF390ULL,
		0x5442495EF792D143ULL,
		0x6ED4BE85AB8A9D69ULL,
		0xCE3AF55EF0DCB687ULL,
		0x5715AECACA41BB65ULL,
		0x76BF45F133D853FCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B14C24800888020ULL,
		0xB18C3000B4300900ULL,
		0x820058DA0302F110ULL,
		0x00424058B1104101ULL,
		0x2E842C84A0821809ULL,
		0x423AB00A10D83680ULL,
		0x4511AC8A4201AA20ULL,
		0x500605E112100280ULL
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
		0xB539DFD0CE4B58EAULL,
		0x8F08E42235412CC3ULL,
		0x6948C12E016C0601ULL,
		0xA9CFE0A0D0346600ULL,
		0x5523A5CED8EB5F3EULL,
		0x55E70B44135A0405ULL,
		0x30D63AA3A562C318ULL,
		0x00915249EAEDD20AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1BB960E5D10DE98ULL,
		0x429DFFBD78DBA4EBULL,
		0xFC1676BBC5B26C33ULL,
		0xAC99DB82C19871ADULL,
		0x906C4874B426968DULL,
		0xF426A60C95440067ULL,
		0x97CB7D4CD83C279BULL,
		0x89372423CECF366FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x813996004C005888ULL,
		0x0208E420304124C3ULL,
		0x6800402A01200401ULL,
		0xA889C080C0106000ULL,
		0x102000449022160CULL,
		0x5426020411400005ULL,
		0x10C2380080200318ULL,
		0x00110001CACD120AULL
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
		0x7788BE0D8C044E6BULL,
		0xD979432EF0457B53ULL,
		0x95F61BE7AA6796EAULL,
		0xC995BC22978BF182ULL,
		0x5C472F22185B7D57ULL,
		0x702290BEDF2CCAA7ULL,
		0x6001A7BFB1EB30E8ULL,
		0xAD9E058C7A67649CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5928118074546E17ULL,
		0x218AFBD5D36EB5ECULL,
		0xFEE102AD55909E84ULL,
		0x5808287FFC54D8A1ULL,
		0x6D4F97CDBF8C9BF5ULL,
		0x158C3017372311A1ULL,
		0x918663234C6BB8D4ULL,
		0x806DF76B23F7DF3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5108100004044E03ULL,
		0x01084304D0443140ULL,
		0x94E002A500009680ULL,
		0x480028229400D080ULL,
		0x4C47070018081955ULL,
		0x10001016172000A1ULL,
		0x00002323006B30C0ULL,
		0x800C05082267441CULL
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
		0x110D44E10EA6DC4BULL,
		0x8140AD01A6918984ULL,
		0xA5F9FE9261EECD5BULL,
		0x0A17CF7BB71BB797ULL,
		0xF06ED7D9BE2BF333ULL,
		0x5D70956D28BE986FULL,
		0xAFAE957B0D10DCC7ULL,
		0xA80ABD2FD6F0D081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CFDB495A5D96340ULL,
		0x3BAC13518B9C16C3ULL,
		0x142D372CF6714B57ULL,
		0x7B16AED511E21407ULL,
		0x0E8886DA3EAAD3FDULL,
		0x12094886D68A0E70ULL,
		0xD9C421A12220E651ULL,
		0x4BAC5D466DB12687ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x100D048104804040ULL,
		0x0100010182900080ULL,
		0x0429360060604953ULL,
		0x0A168E5111021407ULL,
		0x000886D83E2AD331ULL,
		0x10000004008A0860ULL,
		0x898401210000C441ULL,
		0x08081D0644B00081ULL
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
		0x739933C64E0658D2ULL,
		0x13A881720802F4C9ULL,
		0x0165B19742545B3CULL,
		0x0CC9BD7BBD7FB72BULL,
		0xA5367032FA273959ULL,
		0x5E0E750000A78C35ULL,
		0xA426411587F2247FULL,
		0x1A228F9F3807AE50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD997A7AA9A3B7EULL,
		0x21EC4C6CC32E95FFULL,
		0x9820A5B3D06D58F3ULL,
		0x03773B26697847FFULL,
		0x614BDF92A9A06A8CULL,
		0x8F544FE9D1FDA52EULL,
		0x0ABE6FE99971A16DULL,
		0xE4485972CEA54582ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x439913860A021852ULL,
		0x01A80060000294C9ULL,
		0x0020A19340445830ULL,
		0x004139222978072BULL,
		0x21025012A8202808ULL,
		0x0E04450000A58424ULL,
		0x002641018170206DULL,
		0x0000091208050400ULL
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
		0xCBDF3B09F69F3E66ULL,
		0xACAD923DC085C3A2ULL,
		0xFA9D1C8B050BA5CAULL,
		0x9391496452B94434ULL,
		0xA1F65BAB6361D990ULL,
		0x95C088062A04E2D8ULL,
		0x0C47DF627FDD5A2AULL,
		0x4C640280C5CF155EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B4917A667A602AFULL,
		0xAD0100E167B1F0D7ULL,
		0x08030F224F29165AULL,
		0x653B58B742F7C31DULL,
		0x871705283EA5B033ULL,
		0xB219B704F96C24DAULL,
		0x4F08C73056912D84ULL,
		0x59E05610C919206CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B49130066860226ULL,
		0xAC0100214081C082ULL,
		0x08010C020509044AULL,
		0x0111482442B14014ULL,
		0x8116012822219010ULL,
		0x90008004280420D8ULL,
		0x0C00C72056910800ULL,
		0x48600200C109004CULL
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
		0x2F4EF6CE872F5BCFULL,
		0x6AD0ED4B414D1684ULL,
		0x02FD41FC7B19032AULL,
		0x2547EC65749DD6F4ULL,
		0xEBDEF66D5B2E0279ULL,
		0x07C4A30A0FFB3744ULL,
		0x48459301A895E604ULL,
		0xFC5085BD353970ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA90E1320EC6AA4BULL,
		0x10F0B3DB07DC1AFFULL,
		0x9568F3A2A548CD46ULL,
		0x114764324EF0932AULL,
		0x692AE21E3086886BULL,
		0xDBD388E858E91901ULL,
		0x51101F62FA4AD182ULL,
		0xA6A871DB8E3F5C46ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A00E00206060A4BULL,
		0x00D0A14B014C1284ULL,
		0x006841A021080102ULL,
		0x0147642044909220ULL,
		0x690AE20C10060069ULL,
		0x03C0800808E91100ULL,
		0x40001300A800C000ULL,
		0xA400019904395044ULL
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
		0xE90A662B2A8AE7B5ULL,
		0x312FD67D26AF0011ULL,
		0xB56416E64EF9298DULL,
		0x975D0C011430F715ULL,
		0x4D92F8EC3BE70C9CULL,
		0x3B14FAA5D391072BULL,
		0x13B6D7ECBA386966ULL,
		0xEF318DA60123637CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9BF6A8E09CEE603ULL,
		0x7C8614FF3D490A50ULL,
		0xA1F23C13E8303256ULL,
		0x7BC48A447673CA21ULL,
		0x1544F596EC083BBDULL,
		0x82334210705EE707ULL,
		0x3876AB408E4287A3ULL,
		0xF3C8CE96DA8B5CBFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC90A620A088AE601ULL,
		0x3006147D24090010ULL,
		0xA160140248302004ULL,
		0x134408001430C201ULL,
		0x0500F0842800089CULL,
		0x0210420050100703ULL,
		0x103683408A000122ULL,
		0xE3008C860003403CULL
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
		0x23CC833D19A4C3DBULL,
		0x78F66D67B7CAB049ULL,
		0x6E0A760F7438BCB1ULL,
		0x6C94ED1D5A86B549ULL,
		0x36369BBD8104329BULL,
		0x6A3E1F585C2601F7ULL,
		0xAA4F1B0DE2388CF3ULL,
		0xA350BBED424B4AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x204352E3A9C6E819ULL,
		0x38D7114764FD3C0CULL,
		0xD0B9388716F8DF9DULL,
		0xF28717EFCA4140FAULL,
		0x5CBD74B232C5E20DULL,
		0xA126ACBDEDAFFCC6ULL,
		0xA292AB55DD961988ULL,
		0xDA12A1C7A1651592ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x204002210984C019ULL,
		0x38D6014724C83008ULL,
		0x4008300714389C91ULL,
		0x6084050D4A000048ULL,
		0x143410B000042209ULL,
		0x20260C184C2600C6ULL,
		0xA2020B05C0100880ULL,
		0x8210A1C500410092ULL
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
		0xF4F2A6EBFA824B94ULL,
		0x02E768988453932EULL,
		0x35D6C67D44623C3EULL,
		0xA7DC14CF7C858272ULL,
		0x07B77DB5A7A88310ULL,
		0x33AFCDE7D3CE1CEFULL,
		0x51870AF953593F1FULL,
		0xAE843D5B40FD1013ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E2708BFEA6CB08AULL,
		0x2BD2105393CDE929ULL,
		0x0184CE5AEB5981D1ULL,
		0x8947A4C19F7E0F05ULL,
		0xD41126813C2C14DBULL,
		0x9D23543C77D5D079ULL,
		0xA04070C55B5C5397ULL,
		0x63370C3D3D0FFA07ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x442200ABEA000080ULL,
		0x02C2001080418128ULL,
		0x0184C65840400010ULL,
		0x814404C11C040200ULL,
		0x0411248124280010ULL,
		0x1123442453C41069ULL,
		0x000000C153581317ULL,
		0x22040C19000D1003ULL
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
		0x473CC80F819B4837ULL,
		0x7186A82697559DC8ULL,
		0xB5F741618E7D6989ULL,
		0x29102EF07061E3E0ULL,
		0xF97BC4C11E4F61EAULL,
		0xAC03BB757C4F8877ULL,
		0xBEC562BF40970BBAULL,
		0xBB70AA3418039C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ABAF087FBE3CCCEULL,
		0x10D6D0B35DC4D946ULL,
		0xCD8EDA3F20C091E7ULL,
		0xA131875386904041ULL,
		0x8CA51357DDEFCC0DULL,
		0xDFE575AF9B233BB0ULL,
		0x20A3F66C7016D1CEULL,
		0x51A72A1401A66799ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0238C00781834806ULL,
		0x1086802215449940ULL,
		0x8586402100400181ULL,
		0x2110065000004040ULL,
		0x882100411C4F4008ULL,
		0x8C01312518030830ULL,
		0x2081622C4016018AULL,
		0x11202A1400020401ULL
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
		0x5B837682C9963D1CULL,
		0x095668863203DDD7ULL,
		0xF47B3C25C45B275EULL,
		0xCD430F07D7CAD434ULL,
		0x00BD5D76F3F5B6BCULL,
		0x2C0221D7583B6406ULL,
		0x22B6564D955C9476ULL,
		0x28C58D8DF0879F20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA4CB08FAB57A78BULL,
		0x010F46C9879B6B1EULL,
		0xE3EA31BB9561A7F5ULL,
		0xDAEE5B478A26CBE2ULL,
		0x4ACAA2B0CCF2A010ULL,
		0x88B3A44308B84E67ULL,
		0xDC49A22E0AF0F338ULL,
		0x677FCCFB7C9F36A6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4A00308289162508ULL,
		0x0106408002034916ULL,
		0xE06A302184412754ULL,
		0xC8420B078202C020ULL,
		0x00880030C0F0A010ULL,
		0x0802204308384406ULL,
		0x0000020C00509030ULL,
		0x20458C8970871620ULL
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
		0x4A24503450C4D87CULL,
		0x35DD079C98D29C97ULL,
		0xED3E74E428348D36ULL,
		0xF34CA6C2C4CE82E3ULL,
		0x2275DDA4D20F8CD8ULL,
		0x07AA2B0B717CDD7CULL,
		0xC7C2DF195DBACFCCULL,
		0xB5506145B753FD59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19D051DE7B90F1EULL,
		0x9507D489EF167D19ULL,
		0xEE0D24F0215EFAC2ULL,
		0x247FEDE716B3A8B5ULL,
		0x3CED74F9F6A5A820ULL,
		0xFD5FBF4AABB0F6C1ULL,
		0x754606F1AC600BD0ULL,
		0xD853B77AE02A59A2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400400144080081CULL,
		0x1505048888121C11ULL,
		0xEC0C24E020148802ULL,
		0x204CA4C2048280A1ULL,
		0x206554A0D2058800ULL,
		0x050A2B0A2130D440ULL,
		0x454206110C200BC0ULL,
		0x90502140A0025900ULL
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
		0x8E583DD762DABFD1ULL,
		0x4E9B1BD7FB3BE245ULL,
		0x5DBF1A49B03A8134ULL,
		0x0A46BBE34CA7CEBBULL,
		0x77F3947D321A5CE5ULL,
		0xCB99203FBE414278ULL,
		0xC62361F6C14C786CULL,
		0x284EECADACB35844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30711333B2497443ULL,
		0x3222D82D6A79FFA0ULL,
		0x1757610F6BF029ECULL,
		0xD7A28B65F4B81CEDULL,
		0x5D7E041452FB5DC4ULL,
		0xF5F29ED5C780BAFCULL,
		0x7EFA848532173C91ULL,
		0xEB0BFD0446A9067AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0050111322483441ULL,
		0x020218056A39E200ULL,
		0x1517000920300124ULL,
		0x02028B6144A00CA9ULL,
		0x55720414121A5CC4ULL,
		0xC190001586000278ULL,
		0x4622008400043800ULL,
		0x280AEC0404A10040ULL
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
		0x9EDCACAC0B55A88DULL,
		0x439C8DF540BF93F5ULL,
		0x69F3C98682D64CECULL,
		0x9005524365E77186ULL,
		0xC43D319637D87F99ULL,
		0x1D26CC8ACD2A4002ULL,
		0x1EC3ADA61DAE842EULL,
		0x216D215D010ADC6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC14B397DEC6C08EULL,
		0xA6E82E78161D3D4DULL,
		0x968ADD009CC341CAULL,
		0x9239D3C89DB67AC6ULL,
		0xC10D0DEA9778E8E8ULL,
		0x865ACF476DF34A2BULL,
		0x19DDF090220F9BF4ULL,
		0x203679A0DC1DDB91ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8C14A0840A44808CULL,
		0x02880C70001D1145ULL,
		0x0082C90080C240C8ULL,
		0x9001524005A67086ULL,
		0xC00D018217586888ULL,
		0x0402CC024D224002ULL,
		0x18C1A080000E8024ULL,
		0x202421000008D801ULL
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
		0x2D39EAC23E971549ULL,
		0xB9B820D4D2806BF6ULL,
		0x96B80C437072C3DCULL,
		0x005507E8054937A0ULL,
		0xAB07748FAAB3EBDBULL,
		0x25BCA40D5B1196D2ULL,
		0xA0B8E247B85C00C7ULL,
		0xD94B201F0B2FAA88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x571A4EB84D57D4C0ULL,
		0x6AE3B887D930DD08ULL,
		0xE91159E12A6B8963ULL,
		0x1647F71ADF598FBEULL,
		0xFBAC920F0481AA04ULL,
		0x0DE30E720962AE49ULL,
		0xF25E9E50C2D6D1B1ULL,
		0x4309A8A430350FA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x05184A800C171440ULL,
		0x28A02084D0004900ULL,
		0x8010084120628140ULL,
		0x00450708054907A0ULL,
		0xAB04100F0081AA00ULL,
		0x05A0040009008640ULL,
		0xA018824080540081ULL,
		0x4109200400250A88ULL
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
		0x0C36D7ED4CF716CCULL,
		0x407E609AF47C2706ULL,
		0xB09BC1B1D56E75F0ULL,
		0x0ABF06FBBC1CF248ULL,
		0xAB35E3E4916679ADULL,
		0x05A36308B69D2C16ULL,
		0x315DE3866858FE10ULL,
		0x752BE7DEC70514FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEED674467FFD064ULL,
		0xA8C8CF99381C5CB1ULL,
		0xC294F06D5F001984ULL,
		0x2C574BE35EBB3861ULL,
		0x378898761BDE2E7EULL,
		0x6E09515B23493D20ULL,
		0xA73F80455B315B4DULL,
		0x69E7F52E81793BADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C24474444F71044ULL,
		0x00484098301C0400ULL,
		0x8090C02155001180ULL,
		0x081702E31C183040ULL,
		0x230080641146282CULL,
		0x0401410822092C00ULL,
		0x211D800448105A00ULL,
		0x6123E50E810110ACULL
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
		0x0D6C3FA3A7CD6714ULL,
		0x8AD6C129E46BA734ULL,
		0xADE7F6F731959191ULL,
		0x1CCD2BFFFFA62D5FULL,
		0x77DB8240D3AA175AULL,
		0x1B3B3E1A61AA99EFULL,
		0x9FA84241A754FDB0ULL,
		0x959E64D36EC2EF30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB457A1E034C99BC5ULL,
		0xD4B085CDBFBE6D5DULL,
		0x757AE55035AD803AULL,
		0x5936BD018FCA57BAULL,
		0x8DDC9055A35B7A77ULL,
		0x6CDAE4D4807D024BULL,
		0x84F4B4DDD9AA777EULL,
		0xD27E76F80EB67545ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x044421A024C90304ULL,
		0x80908109A42A2514ULL,
		0x2562E45031858010ULL,
		0x180429018F82051AULL,
		0x05D88040830A1252ULL,
		0x081A24100028004BULL,
		0x84A0004181007530ULL,
		0x901E64D00E826500ULL
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
		0xFDBF1C58662FB79EULL,
		0xFE48248A1F350339ULL,
		0x3E40262B33A8267CULL,
		0x8BBDF80F32762D4BULL,
		0x6931A3B66B8774B0ULL,
		0x0FEF14261EA60598ULL,
		0xB96D1B89AA9C223CULL,
		0x03D47FC4859BD9BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA279B46F9FED94DEULL,
		0x097025217BF86243ULL,
		0x3ACD2FD0A3CED9D6ULL,
		0xF91CFCF10B5440B2ULL,
		0x6A51884A3C724EF1ULL,
		0x7EC620BC2CF89C35ULL,
		0x3706F9437FCA464CULL,
		0x7E5477D8941177C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0391448062D949EULL,
		0x084024001B300201ULL,
		0x3A40260023880054ULL,
		0x891CF80102540002ULL,
		0x68118002280244B0ULL,
		0x0EC600240CA00410ULL,
		0x310419012A88020CULL,
		0x025477C084115182ULL
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
		0xCF768BD819D5151AULL,
		0xEF93C6F2CA742EE4ULL,
		0x3835AC9B9F5266AEULL,
		0x234D8A732C79316FULL,
		0xD42B0BE5DB76DF2BULL,
		0x00008D441F8CD824ULL,
		0x6D94EB8EFBF9EA52ULL,
		0x92AA4225209080F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x714697EACA6145B7ULL,
		0xFC2376196341CBC9ULL,
		0x889C1D4BE5BAE9A6ULL,
		0xF1C434B30EAC2907ULL,
		0x961915F1EE0183F9ULL,
		0xAAFA835201C7B683ULL,
		0xBB4C20B459E42652ULL,
		0xA87E75164AB46FA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x414683C808410512ULL,
		0xEC03461042400AC0ULL,
		0x08140C0B851260A6ULL,
		0x214400330C282107ULL,
		0x940901E1CA008329ULL,
		0x0000814001849000ULL,
		0x2904208459E02252ULL,
		0x802A4004009000A0ULL
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
		0xEB88FB2A50F2014CULL,
		0x7BAB8CA40660E84EULL,
		0x75B66B3CEFF8826BULL,
		0x1C37B132EE690C4CULL,
		0x8C484291A96EECACULL,
		0x3A3DC7565F402C83ULL,
		0x87FF2312730A2904ULL,
		0xC4FF90BCD18E4A5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E06B90ED6D62A3ULL,
		0x9024BE3CF9551652ULL,
		0x6EF5238CACEA04ABULL,
		0x6816DC97BE130A88ULL,
		0x0B66E2FA99886E32ULL,
		0x85F80D24D059FD8CULL,
		0x68E0693CC8E01FB8ULL,
		0xF2901D5ED224D21FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62806B0040600000ULL,
		0x10208C2400400042ULL,
		0x64B4230CACE8002BULL,
		0x08169012AE010808ULL,
		0x0840429089086C20ULL,
		0x0038050450402C80ULL,
		0x00E0211040000900ULL,
		0xC090101CD004421CULL
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
		0x7C43C0EE1E8757AAULL,
		0x914BD5654DACB2E9ULL,
		0x0F0BF03D8138E20AULL,
		0xE656690E61468158ULL,
		0xA897C8889A192FC2ULL,
		0x5664DF75CCAD69ABULL,
		0xC6F0B51AE1A06C67ULL,
		0x56692DA3D77C64ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EEFE1FA504EB632ULL,
		0xA39CE868575A0F21ULL,
		0xC368FA20558E7375ULL,
		0xCFF34DAFCE59C2B7ULL,
		0xFF8490B5DCE8AA08ULL,
		0x32ECBE0D7BF78260ULL,
		0x20D4106975DD6788ULL,
		0xC9E20D477BE82AD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C43C0EA10061622ULL,
		0x8108C06045080221ULL,
		0x0308F02001086200ULL,
		0xC652490E40408010ULL,
		0xA884808098082A00ULL,
		0x12649E0548A50020ULL,
		0x00D0100861806400ULL,
		0x40600D0353682083ULL
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
		0x425FD15A34A65DE2ULL,
		0x2B4D2DCF1C2E42BDULL,
		0x91A765E511C9CB7DULL,
		0xE0D1B87FD5AB19AEULL,
		0xD642B516DB5729BEULL,
		0x10CAB46B6B965AA2ULL,
		0x4FADFD959A140BEAULL,
		0x57C52C503221C31BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD64F45C013C99303ULL,
		0xA487196D9C4AD6FEULL,
		0xC90B206E3EEFC633ULL,
		0x4F7FA773422F29CBULL,
		0x06AEE0E3DD7B84D3ULL,
		0x5FCC469F2CCB94E1ULL,
		0x8F37900276E5CA15ULL,
		0x13654D4640C0EAA5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424F414010801102ULL,
		0x2005094D1C0A42BCULL,
		0x8103206410C9C231ULL,
		0x4051A073402B098AULL,
		0x0602A002D9530092ULL,
		0x10C8040B288210A0ULL,
		0x0F25900012040A00ULL,
		0x13450C400000C201ULL
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
		0xFAF22E0BDA70350EULL,
		0x9A205D952BA9D0D1ULL,
		0xA358073077EEAC81ULL,
		0xD1DC2F3730512099ULL,
		0xA0AF9C0D98FBD515ULL,
		0x78F7F5AC6A376C92ULL,
		0xCEB021616EE3AD79ULL,
		0x3195B90A7FD9C649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84946F3E9F04C2C9ULL,
		0xB1E78876B77424CCULL,
		0x3A048D0D4C06E699ULL,
		0x67303529C409EE84ULL,
		0x67D0207CEFC8AA45ULL,
		0x4258AF574CA0625FULL,
		0x46691549809351F7ULL,
		0x8B5FC6F3C0EF5BA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x80902E0A9A000008ULL,
		0x90200814232000C0ULL,
		0x220005004406A481ULL,
		0x4110252100012080ULL,
		0x2080000C88C88005ULL,
		0x4050A50448206012ULL,
		0x4620014100830171ULL,
		0x0115800240C94209ULL
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
		0xCB4B36BBF6E732DBULL,
		0xA4463CCB7854F689ULL,
		0x63EDE04534383CEBULL,
		0x51FB45B1A88B0883ULL,
		0xA8648447A3CA669CULL,
		0x6F2E97A3D678224CULL,
		0xE02FFF12BEC8026EULL,
		0xA3B32D299390E149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D854F7AF2F6256ULL,
		0xD343852AD730383AULL,
		0xAF1930F0811834A5ULL,
		0x57B2FD50F4525B35ULL,
		0x4DEE275F5064A07CULL,
		0xDA1746C362B1B8DBULL,
		0x7A0B87807F86AB73ULL,
		0xBE2DE7F5D0535233ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x414814B3A6272252ULL,
		0x8042040A50103008ULL,
		0x23092040001834A1ULL,
		0x51B24510A0020801ULL,
		0x086404470040201CULL,
		0x4A06068342302048ULL,
		0x600B87003E800262ULL,
		0xA221252190104001ULL
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
		0x8508CFF7E05F7C4DULL,
		0xCF18AE5245435BEEULL,
		0x4FC696D560EB2055ULL,
		0x11AC95B06361FF7CULL,
		0x4EE23F6E6F6AB957ULL,
		0x335223DC23E37F59ULL,
		0x39628DFCFC660553ULL,
		0xCB0F5313D690CF04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C7AE8F7FFAE4ABULL,
		0x585A52C57F76939AULL,
		0x937F3C0208474E81ULL,
		0xE53A3BFB08F94F90ULL,
		0x8155D4EF647BAFF9ULL,
		0xFE1AB03BC42D6B49ULL,
		0x9D06661BC7C8F2EDULL,
		0xA7E88D704CE47920ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04008E87605A6409ULL,
		0x481802404542138AULL,
		0x0346140000430001ULL,
		0x012811B000614F10ULL,
		0x0040146E646AA951ULL,
		0x3212201800216B49ULL,
		0x19020418C4400041ULL,
		0x8308011044804900ULL
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
		0x62F507FE8C9C0EA7ULL,
		0xF9D38F58ACF2940BULL,
		0xAF59526418C6E948ULL,
		0xCFF1202360F86DD9ULL,
		0x4CC41754A1883697ULL,
		0x4BE5C887560B4D2CULL,
		0x43B6F5C7E5779EE8ULL,
		0x935BE3318A5ABFAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0039608F439BF679ULL,
		0x8ADC310824555A48ULL,
		0x8AEA79A6C49BEA82ULL,
		0x23D0604E2D6D7668ULL,
		0x140DE78846DF3B1FULL,
		0x64A22FECB97644AFULL,
		0x3DCB451A56FDF941ULL,
		0xA428A2509C024D59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0031008E00980621ULL,
		0x88D0010824501008ULL,
		0x8A4850240082E800ULL,
		0x03D0200220686448ULL,
		0x0404070000883217ULL,
		0x40A008841002442CULL,
		0x0182450244759840ULL,
		0x8008A21088020D08ULL
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
		0x58C77C7227B664F3ULL,
		0xD03BE49AA9C20516ULL,
		0xB45BB71722A8FA95ULL,
		0x4E99A7AC3FDB0FEBULL,
		0x7CF8116012DACE0DULL,
		0x76BBA5802C1CFC3FULL,
		0xAE8280BD22CE4EDEULL,
		0x2003E6D6BF7F537DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAD778903DDE334ULL,
		0x6C345FEAE2C72156ULL,
		0x1C19D3BCC1C1E097ULL,
		0x0A8BC5973C5AE23FULL,
		0xF46AFBA0B64252B9ULL,
		0xD33ECEA820E49980ULL,
		0xC868AA9BF4BC2043ULL,
		0xE82CBBF6276C005DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0885740003946030ULL,
		0x4030448AA0C20116ULL,
		0x141993140080E095ULL,
		0x0A8985843C5A022BULL,
		0x7468112012424209ULL,
		0x523A848020049800ULL,
		0x88008099208C0042ULL,
		0x2000A2D6276C005DULL
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
		0x5F060F0EA33FEA72ULL,
		0x2C0ECB90D03DC6CCULL,
		0x574BC0AC3AA28A0BULL,
		0xFBC2F3A3F754DD8CULL,
		0xF7080E5D8968252BULL,
		0xD9E6E44295C7DFD9ULL,
		0x7F758B78C55ACE43ULL,
		0xA27C0B0A6F0A3F06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF42E6CAB9146B8DCULL,
		0xCDB4CE5FE70748E1ULL,
		0xC16E90C5D1BEEBAAULL,
		0xD40C3AE8C974A04EULL,
		0x3A39EEA1AFBA9E71ULL,
		0x13665C4F2495D6F0ULL,
		0x711FDC85C2F934A6ULL,
		0x2E4AC56CC54D6151ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54060C0A8106A850ULL,
		0x0C04CA10C00540C0ULL,
		0x414A808410A28A0AULL,
		0xD00032A0C154800CULL,
		0x32080E0189280421ULL,
		0x116644420485D6D0ULL,
		0x71158800C0580402ULL,
		0x2248010845082100ULL
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
		0xF1D74F7C1F970AEBULL,
		0x82EE197A1DE03CD4ULL,
		0xE8F08A2E93F3AEECULL,
		0x75E9AB9D2C7ACB4AULL,
		0xE5DD473C0D868A6FULL,
		0x2776B15FDCD553C4ULL,
		0x84A8CACF1B5DBF7BULL,
		0x0F5FAED0047AD276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA2BD51EC039C290ULL,
		0x10A8335016608293ULL,
		0xE8EB9D630323C395ULL,
		0xF34C7A2752A5CEF6ULL,
		0x7D3E61F4EB61D07BULL,
		0x7240B25BE95CAEC8ULL,
		0x297161FDFC97396AULL,
		0x7B7EE8A14D643841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD003451C00110280ULL,
		0x00A8115014600090ULL,
		0xE8E0882203238284ULL,
		0x71482A050020CA42ULL,
		0x651C41340900806BULL,
		0x2240B05BC85402C0ULL,
		0x002040CD1815396AULL,
		0x0B5EA88004601040ULL
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
		0x90DA413184C0C7ABULL,
		0x675F036ECCC7316DULL,
		0x0ED8B03F5715F195ULL,
		0x79EE0F3AE4CFF061ULL,
		0x69D9310E674FB38AULL,
		0x37B51DAA4FE4695BULL,
		0xB5D7C1DBD9DAB93BULL,
		0x23B6C5D0D7BB7C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AA99B7B1A19614ULL,
		0x5E36BCE8E7C0AD36ULL,
		0x6A5012E64D75B11BULL,
		0x1751D065BC06F5ACULL,
		0x718C7AE1C5546835ULL,
		0x9E5686F2DC49CE15ULL,
		0x63CC0D0DFA291072ULL,
		0xAEDFC94B36271C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x008A013180808600ULL,
		0x46160068C4C02124ULL,
		0x0A5010264515B111ULL,
		0x11400020A406F020ULL,
		0x6188300045442000ULL,
		0x161404A24C404811ULL,
		0x21C40109D8081032ULL,
		0x2296C14016231C00ULL
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
		0xCD84C18F22684C47ULL,
		0xC1C9224F73A7AE41ULL,
		0x0EA5E7407FBBBA2EULL,
		0x9D7FC36544019A6DULL,
		0x72DD2872A4FF5C49ULL,
		0xDCBB608260CC6642ULL,
		0xA8023C1B4DF2EFF5ULL,
		0x6516B6B6C5B7CBDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x163B95B28500CA47ULL,
		0xA1D69BFCB43FB57FULL,
		0x52C334AECC2AC4D7ULL,
		0xABE1D6F6C6443C6AULL,
		0xA98C44139807BBEBULL,
		0xBD73DFE8FF5A0F13ULL,
		0x5016883DF8956535ULL,
		0xE6F1FF1FF926990EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0400818200004847ULL,
		0x81C0024C3027A441ULL,
		0x028124004C2A8006ULL,
		0x8961C26444001868ULL,
		0x208C001280071849ULL,
		0x9C33408060480602ULL,
		0x0002081948906535ULL,
		0x6410B616C126890EULL
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
		0x53EAB1FA55149B33ULL,
		0x15FAE867ECB9AEFDULL,
		0xE0ACC059DA502B58ULL,
		0x29B9B8858BAB7102ULL,
		0xE6929956DF4DAADFULL,
		0x38628CF13FB67B78ULL,
		0x04C1FB0C6E6487D6ULL,
		0xFDFA2F479E0D44F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD548F43E9DC34EFDULL,
		0xB79E19E6A3D4F15DULL,
		0x39E30876624CB9F7ULL,
		0xB11DA56F6F9F5F0DULL,
		0xDB6C60C88904BE1CULL,
		0x390564301BD2996DULL,
		0x27ECB20D39994F63ULL,
		0x41D26B4370F8CD5CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5148B03A15000A31ULL,
		0x159A0866A090A05DULL,
		0x20A0005042402950ULL,
		0x2119A0050B8B5100ULL,
		0xC20000408904AA1CULL,
		0x380004301B921968ULL,
		0x04C0B20C28000742ULL,
		0x41D22B4310084454ULL
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
		0x2C3A0B410BF270B8ULL,
		0xFFFF9ABEBA68E902ULL,
		0xE4C6C627BFBAB640ULL,
		0x1B65119D761E27E4ULL,
		0xDB8096C03D3E0F98ULL,
		0x75069EBEA417F607ULL,
		0xF1FC4E70FDD0CF05ULL,
		0x37FB6B67EA36A7D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84ED70B473100E2ULL,
		0x7BE12F422E64133EULL,
		0x4359EA34CB04C73DULL,
		0x983EFD5C558EAD7DULL,
		0xBA603A0FBCD8F026ULL,
		0xD926F94A7F0E9711ULL,
		0xAF510772C0830220ULL,
		0x137BFE7F8A57C152ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x280A0301033000A0ULL,
		0x7BE10A022A600102ULL,
		0x4040C2248B008600ULL,
		0x1824111C540E2564ULL,
		0x9A0012003C180000ULL,
		0x5106980A24069601ULL,
		0xA1500670C0800200ULL,
		0x137B6A678A168150ULL
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
		0x0676C7211D9F2DC6ULL,
		0x7C3BFDEDD924CE72ULL,
		0x787482275C482980ULL,
		0x8A6BFBBE6D5661E2ULL,
		0x25EFD40DD560AC84ULL,
		0x54B7BEA4D822E12AULL,
		0x4E553766D9D80FD2ULL,
		0xE036CA160E11CA3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91FFF7BFA988C5F0ULL,
		0xBAF907D4EAA9FFA1ULL,
		0x2017B61BEF4DDF0EULL,
		0x92E2BC6DBEAC60BBULL,
		0x57BF3D4DACDE9463ULL,
		0x90CDAD3B02A81CE7ULL,
		0x63816DB8F814A5CBULL,
		0xDB1D586862025881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0076C721098805C0ULL,
		0x383905C4C820CE20ULL,
		0x201482034C480900ULL,
		0x8262B82C2C0460A2ULL,
		0x05AF140D84408400ULL,
		0x1085AC2000200022ULL,
		0x42012520D81005C2ULL,
		0xC014480002004800ULL
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
		0x4458E97BE5AD049CULL,
		0x2311828C00A07D0AULL,
		0x69BB2C99C5B7D130ULL,
		0x695ED72FC362DC87ULL,
		0x52C453E9BE8695ADULL,
		0xBF2DCC7189F92928ULL,
		0x7EF42D87F7719BA9ULL,
		0x341AF9E2019EC2A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCBDE7EE8E713000ULL,
		0xD59E5436656DD685ULL,
		0xC06A5E5DBF23182AULL,
		0xDD356E3B85664B41ULL,
		0x611646CE27DE25BDULL,
		0x6B7009890045A6CAULL,
		0x51D5E1B692896725ULL,
		0xC0D0942166749941ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4418E16A84210000ULL,
		0x0110000400205400ULL,
		0x402A0C1985231020ULL,
		0x4914462B81624801ULL,
		0x400442C8268605ADULL,
		0x2B20080100412008ULL,
		0x50D4218692010321ULL,
		0x0010902000148000ULL
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
		0xE6B9B83EDB1E45BAULL,
		0x0783CF857DE93ED8ULL,
		0xFAC91670E60ACFA6ULL,
		0xD1BEAA7BCD289770ULL,
		0x59A23045BFB6657CULL,
		0xBFBB9529744CCF91ULL,
		0xB10F998B8D98E968ULL,
		0x94C8222D0BF5ED5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0AC3DD4B9B732BDULL,
		0xA2EC69DFF4B184E5ULL,
		0x00D176AD818C99F9ULL,
		0xEADD517BE76A7C8FULL,
		0x10F1DFE14C4EC358ULL,
		0x71E2A5A96966F5C7ULL,
		0x40BDDEF01B9A0248ULL,
		0x502911B7E5B50F35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A83814991600B8ULL,
		0x0280498574A104C0ULL,
		0x00C11620800889A0ULL,
		0xC09C007BC5281400ULL,
		0x10A010410C064158ULL,
		0x31A285296044C581ULL,
		0x000D988009980048ULL,
		0x1008002501B50D15ULL
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
		0xABC8D97ABBD59E6EULL,
		0x322858F94126A607ULL,
		0xF42DC03AA6943125ULL,
		0xEA97AAACD0F0FF6AULL,
		0x8F63BBE989C955A3ULL,
		0x7B0FD11086DEE2CEULL,
		0x7688B13DC2BB2926ULL,
		0xA272559B934B2C66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8B1C3E1A42C32CULL,
		0xB502A7F7EA9CBE16ULL,
		0x5D06E6ECD7ECFC7BULL,
		0xAA380BA095EA5B6FULL,
		0x485630A92896A22AULL,
		0xFFEBB35E809CFE71ULL,
		0xDC0B076BCE46BB7AULL,
		0x8EEEBD910B2D253DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB88183A1A40822CULL,
		0x300000F14004A606ULL,
		0x5404C02886843021ULL,
		0xAA100AA090E05B6AULL,
		0x084230A908800022ULL,
		0x7B0B9110809CE240ULL,
		0x54080129C2022922ULL,
		0x8262159103092424ULL
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
		0x97E407F87BFED939ULL,
		0xD82E63049B72AADEULL,
		0x394CA40821B212F3ULL,
		0xA0A42116C09DBB88ULL,
		0xA30D88EB76D005B2ULL,
		0x916AC53A27104671ULL,
		0xA0B5EEFF5809AD4FULL,
		0xF94132AE18058182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05041CC7EB9584F5ULL,
		0x19EA440995B7E4DCULL,
		0x4D82FF216FEBAA44ULL,
		0xEFC1101F71684683ULL,
		0xDF46D14054A266C8ULL,
		0x36F253003C5531F0ULL,
		0x35054CEA9F162900ULL,
		0x30EC857CFBD7FCC6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x050404C06B948031ULL,
		0x182A40009132A0DCULL,
		0x0900A40021A20240ULL,
		0xA080001640080280ULL,
		0x8304804054800480ULL,
		0x1062410024100070ULL,
		0x20054CEA18002900ULL,
		0x3040002C18058082ULL
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
		0x69A230E3C97BA77BULL,
		0x50DE176C6B661CB2ULL,
		0xB2DC8532CE380571ULL,
		0x2B6EF76BDBFD3A4EULL,
		0x889C963655629D98ULL,
		0xAFE7862062C052E4ULL,
		0x21A622B9DDF87C36ULL,
		0xC60E2E3DF74025B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EDA26F209A37B7ULL,
		0xC130404B49CEDAEDULL,
		0x32953B6640880B6FULL,
		0x13B10E7A89EF35ECULL,
		0x4BFEEA35BB288D8CULL,
		0x3EEF2DCCBF8AC32FULL,
		0xAAD2A7F2AEAD30C7ULL,
		0xCC9E77974E253CB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40A02063001A2733ULL,
		0x40100048494618A0ULL,
		0x3294012240080161ULL,
		0x0320066A89ED304CULL,
		0x089C823411208D88ULL,
		0x2EE7040022804224ULL,
		0x208222B08CA83006ULL,
		0xC40E2615460024B0ULL
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
		0x2E96BA4D2713566FULL,
		0x74293CC6CBFF2992ULL,
		0x88E036267BC97BACULL,
		0x54FF69F036A73A68ULL,
		0xD0E35B5FEE9D9C60ULL,
		0x4AEBB1E489D7379CULL,
		0xFCD763B5FF763236ULL,
		0x1ACCAB4E47A52B22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D277B15CF8D06DAULL,
		0x9994476913B3F72EULL,
		0x17EAE4D04E1E4AA0ULL,
		0x5794E0F2A6A9E1D4ULL,
		0x73FA29A0598B1496ULL,
		0x65D618EB169057C8ULL,
		0x833A08EF5B416994ULL,
		0x31144715909B8E30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C063A050701064AULL,
		0x1000044003B32102ULL,
		0x00E024004A084AA0ULL,
		0x549460F026A12040ULL,
		0x50E2090048891400ULL,
		0x40C210E000901788ULL,
		0x801200A55B402014ULL,
		0x1004030400810A20ULL
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
		0x6815E97922133C0BULL,
		0xEA8D268904EC9A1DULL,
		0x54287DE1431B5ACEULL,
		0x875A1D5D6093A467ULL,
		0x112AB5F35F065C18ULL,
		0x3AF137DF9E408A6FULL,
		0x3EC7EBC5A88AEE7AULL,
		0x097B035F3406019EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D7C54F52B7C4AC3ULL,
		0x3D98B3FAF30ACD1EULL,
		0x53C776980312C78BULL,
		0xC5ABF78B97E9FC75ULL,
		0xAC31A0B6CBE7ED24ULL,
		0x4287C082493BE6F7ULL,
		0x86794B9359810134ULL,
		0x676BC0E557054859ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0814407122100803ULL,
		0x288822880008881CULL,
		0x500074800312428AULL,
		0x850A15090081A465ULL,
		0x0020A0B24B064C00ULL,
		0x0281008208008267ULL,
		0x06414B8108800030ULL,
		0x016B004514040018ULL
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
		0x1BAE471C4B6AEB6BULL,
		0x77CF7189CFDFD47EULL,
		0xBFAA4B21275C71ACULL,
		0x7C14B2974A376B93ULL,
		0xFEC148C65C5C0144ULL,
		0x75FD25A5D2365D0AULL,
		0x30867F7DE39EF798ULL,
		0x3C35CC31C1E032CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x802C23173FF7ED15ULL,
		0x3BF5CC154105BC6BULL,
		0x356E5583B6FD4E44ULL,
		0x18BEA098C17A0CAFULL,
		0x162724171FD4BA21ULL,
		0x6CB0290F1FD8EF08ULL,
		0x0BFE053B1D6F41F6ULL,
		0xE13B494DA9544F3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002C03140B62E901ULL,
		0x33C540014105946AULL,
		0x352A4101265C4004ULL,
		0x1814A09040320883ULL,
		0x160100061C540000ULL,
		0x64B0210512104D08ULL,
		0x00860539010E4190ULL,
		0x203148018140020CULL
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
		0x314F390EC0D9C638ULL,
		0x6B06A23904D256E6ULL,
		0x3EAEA04A71356852ULL,
		0x0F3425BB5DA70377ULL,
		0xE3A20CE0DD8CB62CULL,
		0x1F03A1789198B5D2ULL,
		0x164AD3108C6546D4ULL,
		0x0C2116370D3297D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564F7E34493A1DF2ULL,
		0x118A5900EA1743F7ULL,
		0x78543ECC72820DC9ULL,
		0x98B2A1010D776E57ULL,
		0xA22A12B6478C25D5ULL,
		0x0D82658CAE7FCB2EULL,
		0xC3B7F4E5AED5A2EDULL,
		0x532D24A2589A7C55ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x104F380440180430ULL,
		0x01020000001242E6ULL,
		0x3804204870000840ULL,
		0x083021010D270257ULL,
		0xA22200A0458C2404ULL,
		0x0D02210880188102ULL,
		0x0202D0008C4502C4ULL,
		0x0021042208121450ULL
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
		0x335A41F581638807ULL,
		0x2539AB645A5CB757ULL,
		0x3587A07F239CEE3DULL,
		0xDB9F4D15D57E3872ULL,
		0x1F4AF436F3C4079BULL,
		0xD141E80114453CBBULL,
		0x643640A72D13CA3DULL,
		0x04D77B5985F9C25BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9252C6C18C33AFULL,
		0xC27B859C76E94B77ULL,
		0x612D0628515EE950ULL,
		0xD14F789C8398B67CULL,
		0x86347941871F26C8ULL,
		0xC56F94F10F13756EULL,
		0x26DE82B1367E07F1ULL,
		0xAC837E6845578C50ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x131240C481000007ULL,
		0x0039810452480357ULL,
		0x21050028011CE810ULL,
		0xD10F481481183070ULL,
		0x0600700083040688ULL,
		0xC14180010401342AULL,
		0x241600A124120231ULL,
		0x04837A4805518050ULL
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
		0xD6FAB0E20887A257ULL,
		0x97E4B53E04A07CE2ULL,
		0x51F2826051F4AF52ULL,
		0x6FD91693F81E6712ULL,
		0x044EE254E3A2446EULL,
		0x7451015D13B1D204ULL,
		0xB4FBA68E1352D0D1ULL,
		0xE075F590CDCEA0D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F1473545102F8BAULL,
		0x78C77E94429E5886ULL,
		0x2D257C8215591DC0ULL,
		0xD89740E8E9E0716DULL,
		0xDC8EE82D70F9CB0DULL,
		0x75032573C14CEB03ULL,
		0x09D73F0E4065CC9DULL,
		0xF30EC489F9110F82ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x461030400002A012ULL,
		0x10C4341400805882ULL,
		0x0120000011500D40ULL,
		0x48910080E8006100ULL,
		0x040EE00460A0400CULL,
		0x740101510100C200ULL,
		0x00D3260E0040C091ULL,
		0xE004C480C9000082ULL
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
		0x41F80EA33F21FE63ULL,
		0xCCB522DAAF7033CDULL,
		0x6F091AB98A486097ULL,
		0x1E7A597C27C7C73EULL,
		0xAD3FFB4EB68A75A2ULL,
		0x13CC928571191EDDULL,
		0xFA4775A95AEB1F9FULL,
		0x0F63EED62F0A627FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146A534D7398669EULL,
		0xD2348A8A1609023FULL,
		0x87B64C3D61E59724ULL,
		0x1B3B741EAB1C8045ULL,
		0x27D529FE14AE2047ULL,
		0xE6CE808358901C6CULL,
		0x80488F47B208E486ULL,
		0xA68446A5ED21DBD4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0068020133006602ULL,
		0xC034028A0600020DULL,
		0x0700083900400004ULL,
		0x1A3A501C23048004ULL,
		0x2515294E148A2002ULL,
		0x02CC808150101C4CULL,
		0x8040050112080486ULL,
		0x060046842D004254ULL
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
		0xD7ADCFE15D49F9CCULL,
		0x613D631EF1FD437CULL,
		0x47EFC10B1F41A5ACULL,
		0x36FDEA7CBD56550AULL,
		0xBA4EC887E5116287ULL,
		0x415F356FEF8303DCULL,
		0x028DA540F1DD1F10ULL,
		0x287CEBEAC0F88EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EE3C8D2B228B8E4ULL,
		0x041C7EAFCD1FFA33ULL,
		0xAA359D23F1E82650ULL,
		0xB4BE0BF0F50C9B6FULL,
		0x8B5FEAB4530BA9E7ULL,
		0x2A16C7F2B98B9EA8ULL,
		0x8D3B870937D62EF0ULL,
		0x94691558E352B889ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x46A1C8C01008B8C4ULL,
		0x001C620EC11D4230ULL,
		0x0225810311402400ULL,
		0x34BC0A70B504110AULL,
		0x8A4EC88441012087ULL,
		0x00160562A9830288ULL,
		0x0009850031D40E10ULL,
		0x00680148C0508888ULL
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
		0xDE806D26E01A85BEULL,
		0x58C0C9545727B9C9ULL,
		0x352AFBA5047787AEULL,
		0x6F0B4EC5C776A78BULL,
		0xE051EBB4EACA5EC7ULL,
		0x95E13DE4A099C82FULL,
		0x4321C0FF18FAB22FULL,
		0x7C1DC9118D8495B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x285AA716E8AC079BULL,
		0x752B9C5E6CAE568AULL,
		0x571D44788FFFF995ULL,
		0xDEAD20AABFB2848AULL,
		0x922886741AFC3E7AULL,
		0x53CDABB1225D67FEULL,
		0x5E2907CEB5E95F3BULL,
		0x4C470DC3C1448278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x08002506E008059AULL,
		0x5000885444261088ULL,
		0x1508402004778184ULL,
		0x4E0900808732848AULL,
		0x800082340AC81E42ULL,
		0x11C129A02019402EULL,
		0x422100CE10E8122BULL,
		0x4C05090181048030ULL
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
		0x2D45758CB97E05D1ULL,
		0x0FC9BBE48A73BC9EULL,
		0xBBE2119E1A6FE080ULL,
		0xCDB6B68795445751ULL,
		0xC24BD34A76549F8AULL,
		0x145174E9057EEB68ULL,
		0x8B821AEBD543BFB6ULL,
		0x84354CB6B228A7A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03914336962A0595ULL,
		0x474115100E3441ADULL,
		0xDB942AE6D4D7FAE4ULL,
		0x2A735D42FA9A84AEULL,
		0xC07DCC7673848D85ULL,
		0x371D53BCB2AAE6B7ULL,
		0x6661D9186D903064ULL,
		0x7D074C9B08CC3BCEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01014104902A0591ULL,
		0x074111000A30008CULL,
		0x9B8000861047E080ULL,
		0x0832140290000400ULL,
		0xC049C04272048D80ULL,
		0x141150A8002AE220ULL,
		0x0200180845003024ULL,
		0x04054C9200082386ULL
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
		0x14ED1BB36C261143ULL,
		0x8D95C081289B57D7ULL,
		0xE1D5DEF899210BACULL,
		0x7F8D1F4CE82DF122ULL,
		0x607744097397758CULL,
		0xF6A6179AF7E632FCULL,
		0x90C18D823A394DF9ULL,
		0xBAF3A9169EE14D7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96EE953A0E5E40ABULL,
		0x3AE876AFFDD88E17ULL,
		0x6624DC0D57059452ULL,
		0x7BB73DF6EB564C63ULL,
		0x4380ABDB7E846113ULL,
		0x3FE745CBEFD9AB44ULL,
		0xFCEDFB5A4D60D3E0ULL,
		0x51368956B55095C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x14EC11320C060003ULL,
		0x0880408128980617ULL,
		0x6004DC0811010000ULL,
		0x7B851D44E8044022ULL,
		0x4000000972846100ULL,
		0x36A6058AE7C02244ULL,
		0x90C18902082041E0ULL,
		0x1032891694400548ULL
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
		0x30B4632F09070357ULL,
		0x04EB87CB53D1E850ULL,
		0x1418FEFB3B69033FULL,
		0x5645453EBEBA7203ULL,
		0xD0E5E57F09C8511DULL,
		0x010F07E89FA38940ULL,
		0x37B8C36E8E70472DULL,
		0xB56963D10AFEE036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49E16F744DF48D1EULL,
		0xB8008763D8138BEDULL,
		0xA20B7AF2C125D09BULL,
		0xCBD34075C1EF44CCULL,
		0x91F68DEDB82F89D8ULL,
		0xD1C199D1F861FEAAULL,
		0x334096410A6BAA48ULL,
		0x0024FFE16A0E9B75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0632409040116ULL,
		0x0000874350118840ULL,
		0x00087AF20121001BULL,
		0x4241403480AA4000ULL,
		0x90E4856D08080118ULL,
		0x010101C098218800ULL,
		0x330082400A600208ULL,
		0x002063C10A0E8034ULL
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
		0x5B205A501FDC600EULL,
		0xB21F500AC44B8B53ULL,
		0x41182230A55DFBC5ULL,
		0x1C41C75154DFDC2DULL,
		0x157157C53F009615ULL,
		0xB3F844F367559DC8ULL,
		0xBF221C588D703529ULL,
		0x6AA533C785E0B823ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1FEAC1657A07AF6ULL,
		0xF80CF7AE2C326461ULL,
		0x7F4B7202D5886FF8ULL,
		0x162B08B770E37376ULL,
		0x778E2CBECAC51D6AULL,
		0x483D8144DED15D46ULL,
		0x266F1C286C39DCC7ULL,
		0x02B41D3E0DDD5901ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4120081017806006ULL,
		0xB00C500A04020041ULL,
		0x4108220085086BC0ULL,
		0x1401001150C35024ULL,
		0x150004840A001400ULL,
		0x0038004046511D40ULL,
		0x26221C080C301401ULL,
		0x02A4110605C01801ULL
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
		0xEE480FC772461B66ULL,
		0x46313290658A1575ULL,
		0x30CF98E409890C07ULL,
		0x731A754B3A4C060DULL,
		0x0096BE030CCBD88BULL,
		0x5C43D610020B5921ULL,
		0x7F74682C8B7B9845ULL,
		0x76195CFA01E3631EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58FE2F5FE9F13F1AULL,
		0x68558EEDF1AE38D4ULL,
		0x3E5D38B1FB3E2A05ULL,
		0x19DD658D30B217B9ULL,
		0xB7F5A46E3DBED184ULL,
		0x29EE8F8C767D2F82ULL,
		0xFB9EBC73FB04453AULL,
		0x4F82C8ADF0AE0D9FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x48480F4760401B02ULL,
		0x40110280618A1054ULL,
		0x304D18A009080805ULL,
		0x1118650930000609ULL,
		0x0094A4020C8AD080ULL,
		0x0842860002090900ULL,
		0x7B1428208B000000ULL,
		0x460048A800A2011EULL
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
		0x118AB3F231373AF8ULL,
		0x4465CDE04FB2B0DDULL,
		0x202AC1C8F0DEC9FBULL,
		0xFF899734E5C31B0BULL,
		0x7411583D34C26111ULL,
		0x66407E3409B1612BULL,
		0x349DE012BE9A271EULL,
		0x0DFB366B1F3D4929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC76D2C635C1522D9ULL,
		0x7CC99B7B0B49E34AULL,
		0x54DE4AE5CED36665ULL,
		0x9B97B5801F0542D5ULL,
		0x48B7642A53DC01BCULL,
		0xB8867D7EFFFB5135ULL,
		0x72D4DD5F94FE2D88ULL,
		0x51DBDBBD0C0D584FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01082062101522D8ULL,
		0x444189600B00A048ULL,
		0x000A40C0C0D24061ULL,
		0x9B81950005010201ULL,
		0x4011402810C00110ULL,
		0x20007C3409B14121ULL,
		0x3094C012949A2508ULL,
		0x01DB12290C0D4809ULL
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
		0x5634D2F605E08C56ULL,
		0xB5E4A6F9F5B59C8EULL,
		0xDE0AAA8EC7E1B8D4ULL,
		0x8452A102769AE6B0ULL,
		0xBF87AB53FCCC3310ULL,
		0xC5F7B50B66AE3046ULL,
		0x9DBEB208C5749D95ULL,
		0x7B673B7FEBBC5539ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF0879463AF6AF0BULL,
		0x81186FE424770179ULL,
		0xC556226928D3D69CULL,
		0x280D242825CC1724ULL,
		0x90DCC6900AC2BC10ULL,
		0x70D4953EAA242462ULL,
		0xA3320D3C04A0DC7BULL,
		0xB58CE54A28FCD332ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5600504600E08C02ULL,
		0x810026E024350008ULL,
		0xC402220800C19094ULL,
		0x0000200024880620ULL,
		0x9084821008C03010ULL,
		0x40D4950A22242042ULL,
		0x8132000804209C11ULL,
		0x3104214A28BC5130ULL
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
		0x7781F624721A5BFDULL,
		0x82E6337A8EB79184ULL,
		0x9143EDB80A861639ULL,
		0xB0A092D6B71B847FULL,
		0xA0A79D2F0B8D852BULL,
		0x94F759BC54C99870ULL,
		0xB3A049F315D5C14BULL,
		0xFA7ABDBC4B60ACBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x545AD49D676E3814ULL,
		0x135A08897FF2B1F7ULL,
		0x8933504781A1F162ULL,
		0x9890D3148E2D1A46ULL,
		0xD359932275043453ULL,
		0x2663743845BD20D1ULL,
		0xC22F8685DDE14DD7ULL,
		0x113C2091B378F8AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5400D404620A1814ULL,
		0x024200080EB29184ULL,
		0x8103400000801020ULL,
		0x9080921486090046ULL,
		0x8001912201040403ULL,
		0x0463503844890050ULL,
		0x8220008115C14143ULL,
		0x103820900360A8ABULL
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
		0x2E8E7C46568EE484ULL,
		0x4F4DC810CCD6FD3DULL,
		0x1776972F12FF2BA1ULL,
		0x84917907F1C88681ULL,
		0x4C8377EBCD4BE981ULL,
		0x1F7E3203BB7C146BULL,
		0xBF921BD3737535F4ULL,
		0x780F4F17623B7528ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42BA3CE90623997AULL,
		0xB4FFB3C598B23F88ULL,
		0xD642DDAF65A11D4DULL,
		0x7B2692D98FED32B1ULL,
		0xE37EF1BAFB8A2372ULL,
		0xF2BBEEFA692DC4A9ULL,
		0x569306172609B019ULL,
		0xCE13FD7DB1A708EDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x028A3C4006028000ULL,
		0x044D800088923D08ULL,
		0x1642952F00A10901ULL,
		0x0000100181C80281ULL,
		0x400271AAC90A2100ULL,
		0x123A2202292C0429ULL,
		0x1692021322013010ULL,
		0x48034D1520230028ULL
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
		0x5A1F0283CC1C9825ULL,
		0x97279180D70FB521ULL,
		0x7153D9DC07DF2895ULL,
		0x0F0F9A9F51685E9CULL,
		0xE0B3E3B35EB04E10ULL,
		0xA077B819E50CBEFBULL,
		0xE3A45B98E81F0354ULL,
		0x1C7CC07C1D9DE0E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE19DE11B25140709ULL,
		0xFB8DA63F61DA2390ULL,
		0xB7C31A013E8C672DULL,
		0x9C9166DFABA6441BULL,
		0xBF906B79D7E6CC88ULL,
		0xB8C9FC453FAEFFC6ULL,
		0x9EC2F230539B9C1EULL,
		0xDF1F11D48339EF30ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x401D000304140001ULL,
		0x93058000410A2100ULL,
		0x31431800068C2005ULL,
		0x0C01029F01204418ULL,
		0xA090633156A04C00ULL,
		0xA041B801250CBEC2ULL,
		0x82805210401B0014ULL,
		0x1C1C00540119E020ULL
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
		0xE1B92D1E9084E553ULL,
		0xD3832FFF0462327AULL,
		0xDDCE967031028BF9ULL,
		0x9AA0F419E8B0E66AULL,
		0xB71656B08BBA8934ULL,
		0xB9C2B65AD4EB5980ULL,
		0x695165953DF34AC6ULL,
		0x849C050E6C84A83DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51381A0666EDFB6ULL,
		0x718641195D1F0A86ULL,
		0xC0C194FD4E545D3AULL,
		0x5587CDD8438876E8ULL,
		0xA237403E4A6E6471ULL,
		0x5E94664B3C245352ULL,
		0x90FE1621A5D04320ULL,
		0x9974C201A254B060ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE11101000004C512ULL,
		0x5182011904020202ULL,
		0xC0C0947000000938ULL,
		0x1080C41840806668ULL,
		0xA21640300A2A0030ULL,
		0x1880264A14205100ULL,
		0x0050040125D04200ULL,
		0x801400002004A020ULL
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
		0x985B2048CBFC5B2BULL,
		0xA7826B44B26F408EULL,
		0xD236146C36D2D4BDULL,
		0x8166470F6E09F29CULL,
		0x681D22AF84682FABULL,
		0x86781485670C1501ULL,
		0xFD3E632E08998050ULL,
		0xC5931078C44054F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1FE5B0AFD43EC1FULL,
		0x64796C35FA8A2C02ULL,
		0x821DCAD98807E29DULL,
		0x419CA048E71AB3BBULL,
		0x9BDD365DCF4C1069ULL,
		0x7447B5D60B60501AULL,
		0x4506F59A17B4B60DULL,
		0x54309EB0DBCB53C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x905A0008C940480BULL,
		0x24006804B20A0002ULL,
		0x821400480002C09DULL,
		0x010400086608B298ULL,
		0x081D220D84480029ULL,
		0x0440148403001000ULL,
		0x4506610A00908000ULL,
		0x44101030C04050C1ULL
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
		0x9431CC1FC340F311ULL,
		0xF7C8CC694B51B2D7ULL,
		0x341503337EE1215CULL,
		0xE8B2754E2E282C43ULL,
		0xCCC2E757466C7104ULL,
		0x7007AE8A31B5B123ULL,
		0x4315B94EC3B134DAULL,
		0xA6B1118C4F852053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CDD371C92B7B4A3ULL,
		0x7462FD70B1C2B3D8ULL,
		0x691AD7981B4039CDULL,
		0x7FA175D0BC959925ULL,
		0x647AFC40377C617FULL,
		0x59FC194B5888F8E3ULL,
		0xE1B18FF4206912B3ULL,
		0x9985E7A256A1EA69ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1411041C8200B001ULL,
		0x7440CC600140B2D0ULL,
		0x201003101A40214CULL,
		0x68A075402C000801ULL,
		0x4442E440066C6104ULL,
		0x5004080A1080B023ULL,
		0x4111894400211092ULL,
		0x8081018046812041ULL
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
		0x597A46CED6CFB0D7ULL,
		0x5675A0C796293335ULL,
		0xD4AE96F06DBA1130ULL,
		0xD28B432D6676CC86ULL,
		0xD5A652C9D57B8854ULL,
		0x985D556B44CD75BDULL,
		0xD44C568BD5C1C320ULL,
		0x52F697BBF335B5B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD13104F377846768ULL,
		0xA0BEC31F597A5384ULL,
		0xCA61B573CE4AA7EFULL,
		0x12F33C3A07C740E8ULL,
		0x2782E7243F0F06FBULL,
		0x8656A9DA408F141DULL,
		0xC7B785014F31BAAAULL,
		0x968A922FAB0E91DEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x513004C256842040ULL,
		0x0034800710281304ULL,
		0xC02094704C0A0120ULL,
		0x1283002806464080ULL,
		0x05824200150B0050ULL,
		0x8054014A408D141DULL,
		0xC404040145018220ULL,
		0x1282922BA3049192ULL
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
		0x91B6C81074EEC4D8ULL,
		0x9C54C5D338046550ULL,
		0xE5DE7D5BF3180667ULL,
		0xA40D2A009391C8B8ULL,
		0x052781A1F24E302CULL,
		0xE7C12E948B574314ULL,
		0xEF4ABF6951CC4371ULL,
		0xBD04DFD985EE28C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC556AFD6B550D357ULL,
		0xCC738077A18672D6ULL,
		0x1E4913065BE19135ULL,
		0x4D09877D5E73DABAULL,
		0x13EA1C2B74176FFCULL,
		0x20BE6888C781CBF1ULL,
		0xEB6893B604A0E289ULL,
		0xB981F160259BD0F0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x811688103440C050ULL,
		0x8C50805320046050ULL,
		0x0448110253000025ULL,
		0x040902001211C8B8ULL,
		0x012200217006202CULL,
		0x2080288083014310ULL,
		0xEB48932000804201ULL,
		0xB900D140058A00C0ULL
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
		0xABA291F67936CA52ULL,
		0x685D213A767E7609ULL,
		0x60D96CBA904AE406ULL,
		0xC93E2A5FFC195362ULL,
		0xC53ECD201F4F8847ULL,
		0x4FBFD58BCAFED0C9ULL,
		0xD1FB7441AD0F4B8BULL,
		0x72DBF82476A7D2D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8609024113DDF227ULL,
		0x2D3572A18223FD76ULL,
		0x923274E24179A75EULL,
		0x1B931D02C0978464ULL,
		0x75A20A1FF384D4BDULL,
		0xB0827AF2258BEE5FULL,
		0x92D42F8CA40A9CF6ULL,
		0x4E4EE0F5F3924936ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x820000401114C202ULL,
		0x2815202002227400ULL,
		0x001064A20048A406ULL,
		0x09120802C0110060ULL,
		0x4522080013048005ULL,
		0x00825082008AC049ULL,
		0x90D02400A40A0882ULL,
		0x424AE02472824010ULL
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
		0xC46A19CEFE2D1830ULL,
		0xBB50F974135EA675ULL,
		0xFA672BF8EEF5C49CULL,
		0x9FCF89C87DDD0118ULL,
		0x5FF0649210703ADAULL,
		0x961E6630BA500711ULL,
		0x91629FCA6919F6EDULL,
		0x5EDF9EF17295354DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21AC12EBCD774A02ULL,
		0x62311682C14B220AULL,
		0x2FE2C6B983D2D0BCULL,
		0xCACCA374D1CD6E17ULL,
		0xC646DAEE8E6B0962ULL,
		0xB197ED8FB685EFA8ULL,
		0x7C0B43F8A32D85CAULL,
		0x00DE7CBA938B4192ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x002810CACC250800ULL,
		0x22101000014A2200ULL,
		0x2A6202B882D0C09CULL,
		0x8ACC814051CD0010ULL,
		0x4640408200600842ULL,
		0x90166400B2000700ULL,
		0x100203C8210984C8ULL,
		0x00DE1CB012810100ULL
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
		0x3F180EA61A3ACDE5ULL,
		0x61DEBEA23C7E57CFULL,
		0xCBB6744E44C446A9ULL,
		0x9FDCEBF8262D4AB5ULL,
		0x366511B2167C1459ULL,
		0x7F1A0457D161F671ULL,
		0x93E948477C9293F2ULL,
		0xF1877E5DE80401E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A7A9BD656A4E57ULL,
		0x867CFEC5C204DD40ULL,
		0xFCECFF5C9F684B46ULL,
		0xE9395C89A33F03DFULL,
		0x4059324B2ACC0D3DULL,
		0xC7D9AF6FB533FE20ULL,
		0x21DDE6159639C70CULL,
		0x77AD2408072888D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x020008A4002A4C45ULL,
		0x005CBE8000045540ULL,
		0xC8A4744C04404200ULL,
		0x89184888222D0295ULL,
		0x00411002024C0419ULL,
		0x471804479121F620ULL,
		0x01C9400514108300ULL,
		0x71852408000000C0ULL
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
		0x44FBE53830E05A5AULL,
		0xA54A45137450AE9CULL,
		0x84C01733CB8753A1ULL,
		0x70EC72E02D304F47ULL,
		0x5D83C3D265EC3022ULL,
		0x261A77F5A88A560FULL,
		0x89185BEA56E61BBBULL,
		0x040AB1A822936057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99EE40D3D51565E7ULL,
		0x4023D99780C8379CULL,
		0x3A4B97D028BA0FECULL,
		0xBFE7E01F99A24D49ULL,
		0x16E18AC886354A03ULL,
		0xDD856A9375CCD15BULL,
		0x58A70AC152BF1497ULL,
		0xDFDCF6CF1D344101ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00EA401010004042ULL,
		0x000241130040269CULL,
		0x00401710088203A0ULL,
		0x30E4600009204D41ULL,
		0x148182C004240002ULL,
		0x040062912088500BULL,
		0x08000AC052A61093ULL,
		0x0408B08800104001ULL
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
		0x77B9C3002A81F8FBULL,
		0x8F4515A54A081CB4ULL,
		0x4DF46A049BCA2AFEULL,
		0x33B43F2B0719CED4ULL,
		0xE093055094CB92B2ULL,
		0x5898FFD9B536ED0EULL,
		0x0927CE53ABD767B0ULL,
		0x4A62B7A0A045F43AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x995EDA6440801385ULL,
		0x176C4218FE32DE27ULL,
		0x0EEF705A14E76B21ULL,
		0x76174657D2FE3BEBULL,
		0x4E52280639B3465EULL,
		0xAC996E3C7C2345C7ULL,
		0xDB2801D46F69C241ULL,
		0x583EEC200C072361ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1118C20000801081ULL,
		0x074400004A001C24ULL,
		0x0CE4600010C22A20ULL,
		0x3214060302180AC0ULL,
		0x4012000010830212ULL,
		0x08986E1834224506ULL,
		0x092000502B414200ULL,
		0x4822A42000052020ULL
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
		0x86ABF77BB48A9A9AULL,
		0x86321740B61D5E24ULL,
		0x595188A676E263E9ULL,
		0x795905BA7EA1749DULL,
		0xEF84AEB4CD2D83ADULL,
		0x702621CA904BC060ULL,
		0xA5840C51329EAB47ULL,
		0x9487139DF4A54671ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7459B399E19F21F2ULL,
		0x4827877249AACCD7ULL,
		0x584EDE1D435D0727ULL,
		0xC00B688B8B194061ULL,
		0xB230DE1E7ACD3252ULL,
		0xE2C138BA657E1800ULL,
		0xE0036D94F823BDDCULL,
		0x141415B47CFF3C25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0409B319A08A0092ULL,
		0x0022074000084C04ULL,
		0x5840880442400321ULL,
		0x4009008A0A014001ULL,
		0xA2008E14480D0200ULL,
		0x6000208A004A0000ULL,
		0xA0000C103002A944ULL,
		0x1404119474A50421ULL
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
		0xA3DAB31B7FD72650ULL,
		0xE82067E27A6E6515ULL,
		0x5242691AF93A04B8ULL,
		0xC63C18F771CCDEB1ULL,
		0x6421118D2E687EEBULL,
		0xC5F2719FBB208452ULL,
		0xE37FF519B2797606ULL,
		0x368A9FABAAA41780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9A3841B5D50B86ULL,
		0x05C720C04F62E931ULL,
		0x62F7F0D5D1DA5F02ULL,
		0xF44CEAA909BFC5DAULL,
		0xCF3801BC63DD6009ULL,
		0x958CBCCB7D664073ULL,
		0x26F157E04F3C4C5EULL,
		0x40BF5136E878FD3CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x839A300135D50200ULL,
		0x000020C04A626111ULL,
		0x42426010D11A0400ULL,
		0xC40C08A1018CC490ULL,
		0x4420018C22486009ULL,
		0x8580308B39200052ULL,
		0x2271550002384406ULL,
		0x008A1122A8201500ULL
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
		0xC38FBA88A18B7E88ULL,
		0xA47FECA0C2FBC3CFULL,
		0x71EB153EA23B26A8ULL,
		0xB999695BA99B7D02ULL,
		0xD06594A438239F05ULL,
		0xE13B827A0ADC8437ULL,
		0xBEBB25EA5D98A201ULL,
		0x2E42D1ADEEAFFA3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FA7F8B8FA457CE2ULL,
		0x52372F94DCF8B9E3ULL,
		0x0DB27E9F26C02EC8ULL,
		0xDD614CBB6F3DB243ULL,
		0x61084B4D332124E3ULL,
		0xAF21F5EEB6F3F655ULL,
		0xE19A327FAC1894F0ULL,
		0xCF1A21741C0C49AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0387B888A0017C80ULL,
		0x00372C80C0F881C3ULL,
		0x01A2141E22002688ULL,
		0x9901481B29193002ULL,
		0x4000000430210401ULL,
		0xA121806A02D08415ULL,
		0xA09A206A0C188000ULL,
		0x0E0201240C0C482BULL
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
		0x13003FE4FC9B466BULL,
		0xD2871AD76DC410C8ULL,
		0x8FFC677AB4F61248ULL,
		0xE8F90632D2DA08C8ULL,
		0x394C4C8CDDAA9AACULL,
		0xCD7CBE3D693ED858ULL,
		0x70E9850457B475D3ULL,
		0x8740460959B5CA9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC58F3B40705388ECULL,
		0xC0A8F70756CA487AULL,
		0x638DFE3D08911246ULL,
		0x31215D9C4F90BD25ULL,
		0x0DA568551DD549EEULL,
		0xC510C231FACADABCULL,
		0x2A32F5FF745F4499ULL,
		0x1703A6BBB1861035ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x01003B4070130068ULL,
		0xC080120744C00048ULL,
		0x038C663800901240ULL,
		0x2021041042900800ULL,
		0x090448041D8008ACULL,
		0xC5108231680AD818ULL,
		0x2020850454144491ULL,
		0x0700060911840010ULL
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
		0x79B17483E2F620F7ULL,
		0x01C224B7FEE8B54BULL,
		0xAB17EFD661E81E40ULL,
		0xEB5ECFB35B5C7D7FULL,
		0x070EFEB3720ADA28ULL,
		0x3217A9379A7920E3ULL,
		0x6A1C783D24A8A402ULL,
		0xBFAC3527A6702EEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DF6C40D1F2781F5ULL,
		0xAD8C77884CA3A328ULL,
		0x65395972B9708329ULL,
		0x701CBB82ACEF158AULL,
		0xED3105768D77F8AFULL,
		0x2337271F64302519ULL,
		0x76CE502C2438B089ULL,
		0x3699D5833BB96FBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59B04401022600F5ULL,
		0x018024804CA0A108ULL,
		0x2111495221600200ULL,
		0x601C8B82084C150AULL,
		0x050004320002D828ULL,
		0x2217211700302001ULL,
		0x620C502C2428A000ULL,
		0x3688150322302EA9ULL
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
		0xBF8832339DC2FE87ULL,
		0x51AA69E996F1EE3BULL,
		0x8CCF7731EEED419DULL,
		0xDE312CA9FFAF3611ULL,
		0xC43FD2A1C1CD49FAULL,
		0x6D7C3B9DEEF5DC40ULL,
		0xAD007E829EA1EB6FULL,
		0x62751988302DC55DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F01EB0264F9AAA6ULL,
		0xC4CEEC07807D603CULL,
		0xBEEDD5576CD7A752ULL,
		0x3C19F15CEE7862C3ULL,
		0xE1C9CBAC4AC3B062ULL,
		0x9F0AFF61BA66EB8DULL,
		0xE07DB65C49587B1CULL,
		0xE21905E58FCF8552ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F00220204C0AA86ULL,
		0x408A680180716038ULL,
		0x8CCD55116CC50110ULL,
		0x1C112008EE282201ULL,
		0xC009C2A040C10062ULL,
		0x0D083B01AA64C800ULL,
		0xA000360008006B0CULL,
		0x62110180000D8550ULL
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
		0x5584CE1FF40027AAULL,
		0xD0F5D57B3A3280E5ULL,
		0xFC2EDE9F9908697BULL,
		0xEDA6957C12118D25ULL,
		0xB7F62813225CDC34ULL,
		0x2FFDA616C43BF3C4ULL,
		0xBEFC3773BF29A90FULL,
		0xD389F3931374A176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1531FD7A53EC5C03ULL,
		0x6BE0E2589A6E0FCBULL,
		0x65A6B517D5E280F6ULL,
		0xD5A63DDC1D6B2266ULL,
		0x07F09889B15DC4B5ULL,
		0xC9BB408A66D6FC67ULL,
		0xB27EC4E8D6518D02ULL,
		0x40A05DDD5FDB8EB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1500CC1A50000402ULL,
		0x40E0C0581A2200C1ULL,
		0x6426941791000072ULL,
		0xC5A6155C10010024ULL,
		0x07F00801205CC434ULL,
		0x09B900024412F044ULL,
		0xB27C046096018902ULL,
		0x4080519113508034ULL
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
		0x15938788FC42FD42ULL,
		0x872A3E77F7D3217DULL,
		0x7EB774E1E76DA386ULL,
		0xD8B9CD3F74461D45ULL,
		0x1E954C86D6E005B0ULL,
		0x3BAE0A9A2D5D1322ULL,
		0xC1DB827CC67A7E4CULL,
		0x58A775D39652EAF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x937C3883917263DEULL,
		0xD527FED30B738941ULL,
		0x34009204743EC679ULL,
		0xBA26C0D05B250763ULL,
		0x640F9EB77BFF7454ULL,
		0x06F204C0E9010D27ULL,
		0x3D80D16C5DB3076CULL,
		0xE0EC4B16ED53D6D4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1110008090426142ULL,
		0x85223E5303530141ULL,
		0x34001000642C8200ULL,
		0x9820C01050040541ULL,
		0x04050C8652E00410ULL,
		0x02A2008029010122ULL,
		0x0180806C4432064CULL,
		0x40A441128452C2D0ULL
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
		0x411D568FC28542D6ULL,
		0xF1897BDCF922084DULL,
		0x3B4F7831BA8339DBULL,
		0x73414CEEED8AF1C9ULL,
		0x8F1036F775C1A841ULL,
		0x79B5265865D4CC27ULL,
		0xC4DDFDA6798CD3FFULL,
		0x468A836294F24BAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666C090A8BF9643AULL,
		0xC6F8DB7C0136AD69ULL,
		0x42222BCBC6B3B8CFULL,
		0xDCAD1D8153787988ULL,
		0x33BA31CE8CEEB615ULL,
		0xB104BCD60D49C8A3ULL,
		0xD8B0DA86F571979FULL,
		0xEA22A67676D29F6DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x400C000A82814012ULL,
		0xC0885B5C01220849ULL,
		0x02022801828338CBULL,
		0x50010C8041087188ULL,
		0x031030C604C0A001ULL,
		0x310424500540C823ULL,
		0xC090D8867100939FULL,
		0x4202826214D20B28ULL
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
		0x01F9766651972ECEULL,
		0xB1AE6F46266EB1ECULL,
		0x17CEFD7B8055B88FULL,
		0x55F9CEE9C7430852ULL,
		0x9672F6E7AD16050FULL,
		0x4B707BAD2D9098A2ULL,
		0xE10F24BC298CA01EULL,
		0x28AE8375B9FFF6CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C96D5A2263D464ULL,
		0xD348793DE7540BA7ULL,
		0x494C3664EAB8FDBEULL,
		0x13C302E5D973685DULL,
		0xA531CF54A4BE1426ULL,
		0x183CE07915623A2EULL,
		0x6C94DC42E69A8509ULL,
		0xDB8EC343DBE807C1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00C9644200030444ULL,
		0x91086904264401A4ULL,
		0x014C34608010B88EULL,
		0x11C102E1C1430850ULL,
		0x8430C644A4160406ULL,
		0x0830602905001822ULL,
		0x6004040020888008ULL,
		0x088E834199E806C1ULL
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
		0xF4B67868C688DEC9ULL,
		0x4CC244EA72D0A9F3ULL,
		0x13503CE888F60F76ULL,
		0x43212C48C54D2A70ULL,
		0x118622F228862374ULL,
		0x08558FF91945AE63ULL,
		0x76138EA9D569BE43ULL,
		0xFCF2CBA13964315CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB292B6501B96DC3DULL,
		0xF70F70B6E8BF80EDULL,
		0xE7260047BF342DDEULL,
		0xC98B291899595219ULL,
		0x266491B90CB151A6ULL,
		0x97FCB7DF49413DC9ULL,
		0xD0456FE66DB86622ULL,
		0x6517D8ACCC5415EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB09230400280DC09ULL,
		0x440240A2609080E1ULL,
		0x0300004088340D56ULL,
		0x4101280881490210ULL,
		0x000400B008800124ULL,
		0x005487D909412C41ULL,
		0x50010EA045282602ULL,
		0x6412C8A00844114CULL
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
		0x24E4C174B1489DDBULL,
		0x1EEF0FF68A7753B3ULL,
		0x47DAE379D7576ADCULL,
		0xEC3A406915EA8523ULL,
		0x8084526820896DE4ULL,
		0x76572F8695BE15A8ULL,
		0xDD59EE7027519009ULL,
		0x47875820E810B768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BA0E15E5F62E52BULL,
		0x1FF3F2FBC183C3E8ULL,
		0x289FF983BD2CA3E9ULL,
		0x3CAC42981890F0B7ULL,
		0x69C97EAD8FB93021ULL,
		0x2CE25F51D2D74AB5ULL,
		0x46110D81CB664DAFULL,
		0xEF824BE047FA7F75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x00A0C1541140850BULL,
		0x1EE302F2800343A0ULL,
		0x009AE101950422C8ULL,
		0x2C28400810808023ULL,
		0x0080522800892020ULL,
		0x24420F00909600A0ULL,
		0x44110C0003400009ULL,
		0x4782482040103760ULL
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
		0xBD55BC9BEF651FDAULL,
		0x96EA53CA718F793BULL,
		0x0393106363C2164EULL,
		0x57EEA4C40CF312EAULL,
		0xAA6E9108A5908F00ULL,
		0xD3D3C86984C8708DULL,
		0x58288B1EF36CB5F0ULL,
		0x72F89E820CE693DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE5C745E13195D4CULL,
		0xE07C4E61C3BC6A9EULL,
		0x53A25A86B192C98BULL,
		0x7A883CC0C472162FULL,
		0x9677EF0745016535ULL,
		0x5E888F112ABDC502ULL,
		0x100C8D61F3C39AE2ULL,
		0x433F91C8FD0F32AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC54341A03011D48ULL,
		0x80684240418C681AULL,
		0x038210022182000AULL,
		0x528824C00472122AULL,
		0x8266810005000500ULL,
		0x5280880100884000ULL,
		0x10088900F34090E0ULL,
		0x423890800C06128AULL
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
		0x9A96D66917881E3EULL,
		0x8E904E70B667FC2BULL,
		0x1B554C70A163BD5AULL,
		0x5F9E450BACE0A2F4ULL,
		0xF09B3A18AA6C8D6DULL,
		0xDC38BBD7C9E93CC1ULL,
		0x3A03F4847E232C59ULL,
		0x3F84BD155939A121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3970EA1F67804A52ULL,
		0x4BDD9A560CEA84A8ULL,
		0xBF0E30F419D0001DULL,
		0xAB2294D9E029F4A2ULL,
		0xD3E7242C0732808FULL,
		0x82747637E0D83778ULL,
		0xF90967074D0E11E2ULL,
		0xBD0C1D5D21A2F389ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1810C20907800A12ULL,
		0x0A900A5004628428ULL,
		0x1B04007001400018ULL,
		0x0B020409A020A0A0ULL,
		0xD08320080220800DULL,
		0x80303217C0C83440ULL,
		0x380164044C020040ULL,
		0x3D041D150120A101ULL
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
		0xB370404CD61F9271ULL,
		0xC624B434D769D95AULL,
		0xBB119D5ED8821B86ULL,
		0x5BDA29975A4C3BB8ULL,
		0x8EA8FAB638EC7D5FULL,
		0xFEA03630C51FF3C5ULL,
		0x185F97295F0A5157ULL,
		0x909BF1722ACB740AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB1560A2C2724FD0ULL,
		0x2775FE1C2D054924ULL,
		0x9AFBD758BE31A896ULL,
		0xA5998593CDA925B1ULL,
		0x0730A994C57CE9ACULL,
		0x154F3AD5C440257BULL,
		0x91737DCE0F3F09A4ULL,
		0x0359DFBEA35BFB63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3104000C2120250ULL,
		0x0624B41405014900ULL,
		0x9A11955898000886ULL,
		0x01980193480821B0ULL,
		0x0620A894006C690CULL,
		0x14003210C4002141ULL,
		0x105315080F0A0104ULL,
		0x0019D132224B7002ULL
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
		0xC68D4F5C8CEC3C16ULL,
		0xA486159F1755B30EULL,
		0x2446003D95D5520AULL,
		0x2EE9A8A641B3A3A1ULL,
		0xFA7DBFA315D4D0A5ULL,
		0x6DCE5CF1DD73ADC2ULL,
		0x066E4FE989F38BDAULL,
		0x78F60CBC47FCDCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD085236659C02EC2ULL,
		0x6E3E1FD22F229AD8ULL,
		0xDA14F81FE6CFDBD2ULL,
		0x776F6F12EC7EFF49ULL,
		0x23733008B21CA2BAULL,
		0x8AAF9C5970575AA4ULL,
		0xC73116C96C42CA30ULL,
		0x0C92B5C124880C96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC085034408C02C02ULL,
		0x2406159207009208ULL,
		0x0004001D84C55202ULL,
		0x266928024032A301ULL,
		0x22713000101480A0ULL,
		0x088E1C5150530880ULL,
		0x062006C908428A10ULL,
		0x0892048004880C90ULL
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
		0x776CD7679C5CE6FDULL,
		0xED51BC92A5EEE64BULL,
		0xC4933D610535B4FCULL,
		0x3F49EB7D07168E82ULL,
		0xF6BE10206F953E5BULL,
		0xD2B2AC26196D90F0ULL,
		0xD2C949CCA09969A0ULL,
		0x1873B114D2A462DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83F13569568B51EDULL,
		0xB42DBE3B235312E9ULL,
		0x861FFFEA04EA7F43ULL,
		0x88F79C4EE152E735ULL,
		0xF2EBABEFB9BB79C5ULL,
		0x45285FA8E577A389ULL,
		0xEBDD957872FA41B8ULL,
		0x75AEEB02746A5772ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x03601561140840EDULL,
		0xA401BC1221420249ULL,
		0x84133D6004203440ULL,
		0x0841884C01128600ULL,
		0xF2AA002029913841ULL,
		0x40200C2001658080ULL,
		0xC2C90148209841A0ULL,
		0x1022A10050204252ULL
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