import random

TEST_COUNT = 50
BITMASK = 2 ** 64 - 1

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
	with open("tests/init_test/cmp_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_test(void) {\n")
		f.write('\tprintf("Key Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
	with open("tests/init_test/cmp_high_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_high_test(void) {\n")
		f.write('\tprintf("Key High Bytes Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp_high(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp_high(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
	with open("tests/init_test/cmp_low_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_cmp_low_test(void) {\n")
		f.write('\tprintf("Key Low Bytes Comparison Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp_low(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp_low(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_test/add_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_test():
	n = random.getrandbits(510)
	m = random.getrandbits(510)
	r = (n + m)
	i = 0
	with open("tests/add_test/add_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_test(void) {\n")
		f.write('\tprintf("Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0, 0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = random.getrandbits(510)
			r = (n + m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_self_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19) 
	m = n
	r = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_test/add_modulo_self_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_self_test(void) {\n")
		f.write('\tprintf("Self Modular Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = n
			r = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_self_test():
	n = random.getrandbits(510) 
	m = n
	r = (n * 2) 
	i = 0
	with open("tests/add_test/add_self_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_self_test(void) {\n")
		f.write('\tprintf("Self Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = n
			r = (n * 2)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_self_modulo_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19) 
	m = n
	r = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_test/add_self_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_self_modulo_test(void) {\n")
		f.write('\tprintf("Self Key Addition Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = n
			r = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/add_test/add_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Modular Inplace Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_inplace_test():
	n = random.getrandbits(510)
	m = random.getrandbits(510)
	r = (n + m)
	i = 0
	with open("tests/add_test/add_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(510)
			m = random.getrandbits(510)
			r = (n + m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/sub_test/sub_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_test(void) {\n")
		f.write('\tprintf("Key Subtraction Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("tests/sub_test/sub_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Subtraction Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_modulo_test():
	n = random.getrandbits(512)
	m = n % ((2 ** 255) - 19)
	i = 0
	with open("tests/init_test/modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_modulo_test(void) {\n")
		f.write('\tprintf("Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcompute_modulo_25519(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			n_mod = n % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcompute_modulo_25519(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	n_mul = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/shift_test/double_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_test(void) {\n")
		f.write('\tprintf("Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			n_mul = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	n_mul = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("tests/shift_test/double_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_inplace(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			n_mul = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_inplace(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_lshift_inplace_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n << s
	i = 0
	with open("tests/shift_test/lshift_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_lshift_inplace_test(void) {\n")
		f.write('\tprintf("Key Left Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_rshift_inplace_test():
	n = random.getrandbits(448)
	s = random.randint(0, 63)
	m = n >> s
	i = 0
	with open("tests/shift_test/rshift_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_rshift_inplace_test(void) {\n")
		f.write('\tprintf("Key Right Shift Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint shift = {s};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(448)
			s = random.randint(0, 63)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def main():
	write_modulo_test()
	write_cmp_test()
	write_cmp_high_test()
	write_cmp_low_test()
	write_add_modulo_test()
	write_add_modulo_self_test()
	write_add_modulo_inplace_test()
	write_add_test()
	write_add_self_test()
	write_add_self_modulo_test()
	write_add_inplace_test()
	write_sub_test()
	write_sub_inplace_test()
	write_double_test()
	write_double_inplace_test()
	write_lshift_inplace_test()
	write_rshift_inplace_test()

if __name__ == "__main__":
	main()