import random

TEST_COUNT = 200
BITMASK = 2 ** 64 - 1

def write_init_test():
	i = 0
	with open("tests/init_tests/priv_key_init_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_priv_key_init_test(void) {\n")
		f.write('\tprintf("Private Key Initialization Test\\n");\n')
		f.write("\tcurve25519_key_t key = {.key64 = { }};\n")
		f.write("\tcurve25519_key_t prev_key = {.key64 = { }};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tif (curve25519_priv_key_init(&key)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\treturn -1;\n\t}}\n')
		f.write(f'\tfor (size_t i = 0; i < 4; ++i) {{\n\t\tif (prev_key.key64[i] == key.key64[i]) {{\n\t\t\tprintf("Test Case {i + 1} FAILED\\n");\n\t\t\treturn -{i + 2};\n\t\t}}\n\t\tprev_key.key64[i] = key.key64[i];\n\t}}\n\tprintf("Test Case {i+1} PASSED\\n---\\n\\n");\n')
		for i in range(1, TEST_COUNT * 2, 2):
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tif (curve25519_priv_key_init(&key)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\treturn -{i + 1};\n\t}}\n')
			f.write(f'\tfor (size_t i = 0; i < 4; ++i) {{\n\t\tif (prev_key.key64[i] == key.key64[i]) {{\n\t\t\tprintf("Test Case {i + 1} FAILED\\n");\n\t\t\treturn -{i + 2};\n\t\t}}\n\t\tprev_key.key64[i] = key.key64[i];\n\t}}\n\tprintf("Test Case {i+1} PASSED\\n---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_cmp_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = "0"
	t = 0
	if (n - m < 0): 
		r = "< 0"
		t = -1
	elif (n - m > 0): 
		r = "> 0"
		t = 1
	i = 0
	with open("tests/init_tests/cmp_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_test(void) {\n")
		f.write('\tprintf("Key Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			if (i % 4 == 0):
				n = m
			r = "0"
			t = 0
			if (n - m < 0): 
				r = "< 0"
				t = -1
			elif (n - m > 0): 
				r = "> 0"
				t = 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tt = {t};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_cmp_high_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = "0"
	t = 0
	if (n - m < 0): 
		r = "< 0"
		t = -1
	elif (n - m > 0): 
		r = "> 0"
		t = 1
	i = 0
	with open("tests/init_tests/cmp_high_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_high_test(void) {\n")
		f.write('\tprintf("Key High Bytes Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp_high(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			if (i % 4 == 0):
				n = m
			r = "0"
			t = 0
			if (n - m < 0): 
				r = "< 0"
				t = -1
			elif (n - m > 0): 
				r = "> 0"
				t = 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0,\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tt = {t};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp_high(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_cmp_low_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = "0"
	t = 0
	if (n - m < 0): 
		r = "< 0"
		t = -1
	elif (n - m > 0): 
		r = "> 0"
		t = 1
	i = 0
	with open("tests/init_tests/cmp_low_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_low_test(void) {\n")
		f.write('\tprintf("Key Low Bytes Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp_low(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			if (i % 4 == 0):
				n = m
			r = "0"
			t = 0
			if (n - m < 0): 
				r = "< 0"
				t = -1
			elif (n - m > 0): 
				r = "> 0"
				t = 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tt = {t};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp_low(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_tests/add_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_test():
	n = random.getrandbits(510)
	m = random.getrandbits(510)
	r = (n + m)
	i = 0
	with open("tests/add_tests/add_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_test(void) {\n")
		f.write('\tprintf("Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = random.getrandbits(510)
			r = (n + m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_self_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19) 
	m = n
	r = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_tests/add_modulo_self_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_self_test(void) {\n")
		f.write('\tprintf("Self Modular Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = n
			r = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_self_test():
	n = random.getrandbits(510) 
	m = n
	r = (n * 2) 
	i = 0
	with open("tests/add_tests/add_self_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_self_test(void) {\n")
		f.write('\tprintf("Self Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = n
			r = (n * 2)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_self_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19) 
	m = n
	r = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_tests/add_self_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_self_modulo_test(void) {\n")
		f.write('\tprintf("Self Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = n
			r = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_tests/add_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Modular Inplace Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_inplace_test():
	n = random.getrandbits(510)
	m = random.getrandbits(510)
	r = (n + m)
	i = 0
	with open("tests/add_tests/add_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = random.getrandbits(510)
			r = (n + m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	if (n < m):
		n, m = m, n
	r = (n - m)
	i = 0
	with open("tests/sub_tests/sub_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_test(void) {\n")
		f.write('\tprintf("Key Subtraction Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			if (n < m):
				n, m = m, n
			r = (n - m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_inplace_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = (n - m)
	if (n < m):
		n, m = m, n
	i = 0
	with open("tests/sub_tests/sub_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Subtraction Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			if (n < m):
				n, m = m, n
			r = (n - m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/sub_tests/sub_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Subtraction Test\\n");\n')
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_modulo_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/sub_tests/sub_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Modular Key Subtraction Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_modulo_test():
	n = random.getrandbits(512)
	m = n % ((2 ** 255) - 19)
	i = 0
	with open("tests/init_tests/modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_modulo_test(void) {\n")
		f.write('\tprintf("Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcompute_modulo_25519(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = n % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcompute_modulo_25519(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_test():
	n = random.getrandbits(510)
	m = (n * 2) 
	i = 0
	with open("tests/shift_tests/double_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_test(void) {\n")
		f.write('\tprintf("Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = (n * 2)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_inplace_test():
	n = random.getrandbits(510)
	m = (n * 2)
	i = 0
	with open("tests/shift_tests/double_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_inplace(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = (n * 2)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_inplace(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19) 
	m = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/shift_tests/double_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19) 
			m = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_modulo_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/shift_tests/double_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Modular Inplace Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo_inplace(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo_inplace(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_lshift_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n << s
	i = 0
	with open("tests/shift_tests/lshift_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_lshift_test(void) {\n")
		f.write('\tprintf("Key Left Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift(&k1, shift, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 256)
			s = random.randrange(0, 64, 4)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_rshift_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n >> s
	i = 0
	with open("tests/shift_tests/rshift_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_rshift_test(void) {\n")
		f.write('\tprintf("Key Right Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift(&k1, shift, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 256)
			s = random.randrange(0, 64, 4)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_lshift_inplace_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n << s
	i = 0
	with open("tests/shift_tests/lshift_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_lshift_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Left Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 256)
			s = random.randrange(0, 64, 4)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		
		f.write("\treturn 0;\n")
		f.write("}")

def write_rshift_inplace_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n >> s
	i = 0
	with open("tests/shift_tests/rshift_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_rshift_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Right Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 256)
			s = random.randrange(0, 64, 4)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_mul_test():
	n = random.getrandbits(256)
	m = random.getrandbits(256)
	r = (n * m)
	i = 0
	with open("tests/prod_tests/mul_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_mul_test(void) {\n")
		f.write('\tprintf("Key Multiplication Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256)
			m = random.getrandbits(256)
			r = (n * m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_log2_test():
	n = max(random.getrandbits(512), 1)
	k = 1
	m = 1
	while k < n:
		if (k & n):
			m = k
		k = k << 1
	i = 0
	with open("tests/shift_tests/log2_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_log2_test(void) {\n")
		f.write('\tprintf("Key Log2 Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_log2(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT * 5):
			n = max(random.getrandbits(512), 1)
			k = 1
			m = 1
			while k < n:
				if (k & n):
					m = k
				k = k << 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_log2(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")



def write_mul_modulo_test():
	n = random.getrandbits(256)
	m = random.getrandbits(256)
	r = (n * m) % ((2 ** 255) - 19) 
	i = 0
	with open("tests/prod_tests/mul_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_mul_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Multiplication Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256)
			m = random.getrandbits(256)
			r = (n * m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_divmod_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	q = (n // m)
	r = (n % m)
	i = 0
	with open("tests/prod_tests/div_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_divmod_test(void) {\n")
		f.write('\tprintf("Key Division + Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k4 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t q = {};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\t// q = 0x{q:0128X}\n\t// r = 0x{r:0128X}\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_divmod(&k1, &k2, &q, &r);\n\tint32_t res = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			q = (n // m)
			r = (n % m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk4 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// q = 0x{q:0128X}\n\t// r = 0x{r:0128X}\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_divmod(&k1, &k2, &q, &r);\n\tres = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT * 2):
			n = random.getrandbits(512)
			m = random.getrandbits(256)
			q = (n // m)
			r = (n % m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk4 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// q = 0x{q:0128X}\n\t// r = 0x{r:0128X}\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_divmod(&k1, &k2, &q, &r);\n\tres = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")
	

def main():
	write_init_test()
	write_cmp_test()
	write_cmp_high_test()
	write_cmp_low_test()
	write_modulo_test()
	write_add_modulo_test()
	write_add_modulo_self_test()
	write_add_modulo_inplace_test()
	write_add_test()
	write_add_self_test()
	write_add_self_modulo_test()
	write_add_inplace_test()
	write_sub_test()
	write_sub_inplace_test()
	write_sub_modulo_test()
	write_sub_modulo_inplace_test()
	write_double_test()
	write_double_inplace_test()
	write_double_modulo_test()
	write_double_modulo_inplace_test()
	write_lshift_test()
	write_rshift_test()
	write_lshift_inplace_test()
	write_rshift_inplace_test()
	write_log2_test()
	write_mul_test()
	write_mul_modulo_test()
	write_divmod_test()

if __name__ == "__main__":
	main()