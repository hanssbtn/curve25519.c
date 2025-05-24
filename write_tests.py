import random

TEST_COUNT = 500
BITMASK = 2 ** 64 - 1
M = (2 ** 255) - 19

def modular_inverse(a, modulus):
	t, newt = 0, 1
	r, newr = modulus, a

	while newr != 0:
		q = r // newr
		t, newt = newt, t - q * newt
		r, newr = newr, r - q * newr

	if (r > 1):
		print("a is not invertible")
		return None
	if (t < 0):
		t = t + modulus
	return t

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
	global M
	n = random.getrandbits(256) % M
	m = random.getrandbits(256) % M
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
			n = random.getrandbits(256) % M
			m = random.getrandbits(256) % M
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
	global M
	n = random.getrandbits(256) % M
	m = random.getrandbits(256) % M
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
			n = random.getrandbits(256) % M
			m = random.getrandbits(256) % M
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
	global M
	n = random.getrandbits(256) % M
	m = random.getrandbits(256) % M
	r = (n + m) % M
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
			n = random.getrandbits(256) % M
			m = random.getrandbits(256) % M
			r = (n + m) % M
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
	global M
	n = random.getrandbits(256) % M 
	m = n
	r = (n * 2) % M
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
			n = random.getrandbits(256) % M
			m = n
			r = (n * 2) % M
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
	global M
	n = random.getrandbits(256) % M 
	m = n
	r = (n * 2) % M
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
			n = random.getrandbits(256) % M
			m = n
			r = (n * 2) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_modulo_inplace_test():
	global M
	n = random.getrandbits(256) % M
	m = random.getrandbits(256) % M
	r = (n + m) % M
	i = 0
	with open("tests/add_tests/add_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_add_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Modular Inplace Key Addition Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_add_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % M
			m = random.getrandbits(256) % M
			r = (n + m) % M
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
	r = (n - m)
	i = 0
	with open("tests/sub_tests/sub_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_test(void) {\n")
		f.write('\tprintf("Key Subtraction Test\\n");\n')
		f.write("\tcurve25519_key_signed_t r = {};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		sign = 0
		if (n < m):
			f.write(f"\tprintf(\"Underflow\\n\");\n")
			sign = 1
		f.write(f'\tint sign = {sign};\n')
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tint borrow = curve25519_key_sub(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r.key, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&r.key, COMPLETE);\n\tif (res && ((sign && borrow) || (!sign && !borrow))) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			r = (n - m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			sign = 0
			if (n < m):
				f.write(f"\tprintf(\"Underflow\\n\");\n")
				sign = 1
			f.write(f'\tsign = {sign};\n')
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tborrow = curve25519_key_sub(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r.key, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&r.key, COMPLETE);\n\tif (res && ((sign && borrow) || (!sign && !borrow))) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_inplace_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = (n - m)
	i = 0
	with open("tests/sub_tests/sub_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Subtraction Test\\n");\n')
		f.write(f"\tcurve25519_key_signed_t k1 = {{.key = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		sign = 0
		if (n < m):
			f.write(f"\tprintf(\"Underflow\\n\");\n")
			sign = 1
		f.write(f'\tint sign = {sign};\n')
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1.key, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tint borrow = curve25519_key_sub_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1.key, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&k1.key, COMPLETE);\n\tif (res && ((sign && borrow) || (!sign && !borrow))) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1.key, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			r = (n - m)
			f.write(f"\tk1 = (curve25519_key_signed_t){{.key = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			sign = 0
			if (n < m):
				f.write(f"\tprintf(\"Underflow\\n\");\n")
				sign = 1
			f.write(f'\tsign = {sign};\n')
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1.key, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tborrow = curve25519_key_sub_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1.key, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&k1.key, COMPLETE);\n\tif (res && ((sign && borrow) || (!sign && !borrow))) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1.key, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_modulo_test():
	global M
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = (n - m) % M
	i = 0
	with open("tests/sub_tests/sub_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Subtraction Test\\n");\n')
		f.write("\tcurve25519_key_t r = { };\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&r, COMPLETE);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			r = (n - m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tprintf("Result:\\n");\n\tcurve25519_key_printf(&r, COMPLETE);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		i = 200
		n = 0
		m = 0
		r = 0
		f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_modulo_inplace_test():
	global M
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = (n - m) % M
	i = 0
	with open("tests/sub_tests/sub_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_sub_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Modular Key Subtraction Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			r = (n - m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		i = 200
		n = 0
		m = 0
		r = 0
		f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_sub_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_modulo_test():
	global M
	n = random.getrandbits(512)
	m = n % M
	i = 0
	with open("tests/init_tests/modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_modulo_test(void) {\n")
		f.write('\tprintf("Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		if (n < 0):
			f.write("\tprintf(\"Negative\\n\");\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_compute_modulo(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = n % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			if (n < 0):
				f.write("\tprintf(\"Negative\\n\");\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_compute_modulo(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
	global M
	n = random.getrandbits(256) % M 
	m = (n * 2) % M
	i = 0
	with open("tests/shift_tests/double_modulo_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_modulo_test(void) {\n")
		f.write('\tprintf("Modular Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % M 
			m = (n * 2) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_modulo_inplace_test():
	global M
	n = random.getrandbits(256) % M
	m = (n * 2) % M
	i = 0
	with open("tests/shift_tests/double_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_x2_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Modular Inplace Key Doubling Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo_inplace(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % M
			m = (n * 2) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_x2_modulo_inplace(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_lshift_test():
	n = random.getrandbits(255)
	s = random.randint(0, 256)
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
			n = random.getrandbits(255)
			s = random.randint(0, 256)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 255)
			s = random.randrange(0, 256, 4)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_rshift_test():
	n = random.getrandbits(256) << 256
	s = random.randint(0, 256)
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
			n = random.getrandbits(256) << 256
			s = random.randint(0, 256)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 255)
			s = random.randrange(0, 256, 4)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift(&k1, shift, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_xor_test():
	n = random.getrandbits(512)
	s = random.getrandbits(512)
	m = n ^ s
	i = 0
	with open("tests/shift_tests/xor_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_xor_test(void) {\n")
		f.write('\tprintf("Key XOR Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(s) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_xor(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1:\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tprintf("k2:\\n");\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			s = random.getrandbits(512)
			m = n ^ s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(s) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_xor(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1:\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tprintf("k2:\\n");\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = random.getrandbits(256) << 256
			s = random.getrandbits(256)
			m = n ^ s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(s) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_xor(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1:\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tprintf("k2:\\n");\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_and_test():
	n = random.getrandbits(512)
	s = random.getrandbits(512)
	m = n & s
	i = 0
	with open("tests/shift_tests/and_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_and_test(void) {\n")
		f.write('\tprintf("Key AND Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(s) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_and(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1:\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tprintf("k2:\\n");\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			s = random.getrandbits(512)
			m = n & s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(s) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(s >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_and(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1:\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tprintf("k2:\\n");\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_lshift_inplace_test():
	n = random.getrandbits(255)
	s = random.randint(0, 256)
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
			n = random.getrandbits(255)
			s = random.randint(0, 256)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 255)
			s = random.randrange(0, 256, 4)
			m = n << s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_lshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		
		f.write("\treturn 0;\n")
		f.write("}")

def write_rshift_inplace_test():
	n = random.getrandbits(256) << 256
	s = random.randint(0, 256)
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
			n = random.getrandbits(256) << 256
			s = random.randint(0, 256)
			m = n >> s
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tshift = {s};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tcurve25519_key_rshift_inplace(&k1, shift);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		for i in range(TEST_COUNT, TEST_COUNT + 10):
			n = 2 ** random.randint(0, 255)
			s = random.randrange(0, 256, 4)
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
		i = 200
		n = 2 ** 256 - 1
		m = 2 ** 256 - 1
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
	curr, shift = 0, 0
	while k < n:
		if (k & n):
			m = k
			shift = curr
		curr = curr + 1
		k = k << 1
	i = 0
	with open("tests/shift_tests/log2_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_log2_test(void) {\n")
		f.write('\tprintf("Key Log2 Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint64_t la = {shift};\n")
		f.write("\tcurve25519_key_t r = { };\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tint l2 = curve25519_key_log2(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res || l2 != la) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT * 5):
			n = max(random.getrandbits(512), 1)
			k = 1
			m = 1
			shift, curr = 0, 0
			while k < n:
				if (k & n):
					m = k
					shift = curr
				curr = curr + 1
				k = k << 1
			if (i >= 500):
				f.write(f"\tla = {shift};\n")
				f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
				f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: %lld\\n", la);\n\tl2 = curve25519_key_log2(&k1, NULL);\n\tif (l2 != la) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
			else:
				f.write(f"\tla = {shift};\n")
				f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
				f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
				f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: %lld\\nk2:\\n", la);\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tl2 = curve25519_key_log2(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res || l2 != la) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_mul_modulo_test():
	global M
	n = random.getrandbits(256)
	m = random.getrandbits(256)
	r = (n * m) % M 
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
			r = (n * m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_modulo(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_mul_inplace_test():
	i = 0
	n = random.getrandbits(256)
	m = random.getrandbits(256)
	r = n * m
	with open("tests/prod_tests/mul_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_mul_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Key Multiplication Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256)
			m = random.getrandbits(256)
			r = (n * m)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		i = 200
		n = 2 ** 256 - 1
		m = 2 ** 256 - 1
		r = (n * m)	
		f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_mul_modulo_inplace_test():
	global M
	i = 0
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	r = (n * m) % M
	with open("tests/prod_tests/mul_modulo_inplace_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_mul_modulo_inplace_test(void) {\n")
		f.write('\tprintf("Inplace Modular Key Multiplication Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_modulo_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			m = random.getrandbits(512)
			r = (n * m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tcurve25519_key_mul_modulo_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_div_test():
	n = random.getrandbits(512)
	m = random.getrandbits(512)
	q = (n // m)
	r = (n % m)
	i = 0
	with open("tests/prod_tests/div_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_div_test(void) {\n")
		f.write('\tprintf("Key Division + Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k4 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t q = {};\n")
		f.write("\tcurve25519_key_t r = {};\n")
		f.write(f"\t// q = 0x{q:0128X}\n\t// r = 0x{r:0128X}\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_div(&k1, &k2, &q, &r);\n\tint32_t res = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_div(&k1, &k2, &q, &r);\n\tres = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tprintf("r:\\n");\n\tcurve25519_key_printf(&k4, COMPLETE);\n\tcurve25519_key_div(&k1, &k2, &q, &r);\n\tres = curve25519_key_cmp(&q, &k3) | curve25519_key_cmp(&r, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_inv_test():
	global M
	i = 0
	n = random.getrandbits(512)
	t = modular_inverse(n, M)
	while t is None:
		n = random.getrandbits(512)
		t = modular_inverse(n, M)
	assert (n * t) % M == 1
	with open("tests/prod_tests/inv_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_inv_test(void) {\n")
		f.write('\tprintf("Modular Key Inverse Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = { };\n")
		f.write("\tcurve25519_key_t temp = { };\n")
		f.write("\tcurve25519_key_t ONE = {.key64 = { 1 }};\n")
		f.write(f"\t// q = 0x{n:0128X}\n\t// r = 0x{t:0128X}\n")
		f.write(f"\tcurve25519_key_inv(&k1, &r);\n")
		f.write(f'\tcurve25519_key_mul_modulo(&k1, &r, &temp);\n')
		f.write("\tprintf(\"r:\\n\");\n")
		f.write("\tcurve25519_key_printf(&r, COMPLETE);\n")
		f.write("\tprintf(\"temp:\\n\");\n")
		f.write("\tcurve25519_key_printf(&temp, COMPLETE);\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tint32_t res = curve25519_key_cmp(&k2, &r) | curve25519_key_cmp(&temp, &ONE);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			t = modular_inverse(n, M)
			while t is None:
				n = random.getrandbits(512)
				t = modular_inverse(n, M)
			assert (n * t) % M == 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// n = 0x{n:0128X}\n\t// t = 0x{t:0128X}\n")
			f.write(f"\tcurve25519_key_inv(&k1, &r);\n")
			f.write(f'\tcurve25519_key_mul_modulo(&k1, &r, &temp);\n')
			f.write("\tprintf(\"r:\\n\");\n")
			f.write("\tcurve25519_key_printf(&r, COMPLETE);\n")
			f.write("\tprintf(\"temp:\\n\");\n")
			f.write("\tcurve25519_key_printf(&temp, COMPLETE);\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tres = curve25519_key_cmp(&k2, &r) | curve25519_key_cmp(&temp, &ONE);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT * 2):
			n = random.getrandbits(512)
			t = modular_inverse(n, M)
			while t is None:
				n = random.getrandbits(512)
				t = modular_inverse(n, M)
			assert (n * t) % M == 1
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// n = 0x{n:0128X}\n\t// t = 0x{t:0128X}\n")
			f.write(f"\tcurve25519_key_inv(&k1, &r);\n")
			f.write(f'\tcurve25519_key_mul_modulo(&k1, &r, &temp);\n')
			f.write("\tprintf(\"r:\\n\");\n")
			f.write("\tcurve25519_key_printf(&r, COMPLETE);\n")
			f.write("\tprintf(\"temp:\\n\");\n")
			f.write("\tcurve25519_key_printf(&temp, COMPLETE);\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tres = curve25519_key_cmp(&k2, &r) | curve25519_key_cmp(&temp, &ONE);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("r:\\n");\n\t\tcurve25519_key_printf(&r, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")	

def write_divmod_test():
	global M
	i = 0
	n = random.getrandbits(512)
	t = random.getrandbits(512)
	m = modular_inverse(t, M)
	while t is None:
		t = random.getrandbits(512)
		m = modular_inverse(t, M)
	assert (m * t) % M == 1
	q = (n * m) % M
	with open("tests/prod_tests/divmod_test.c", "w") as f:
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_key_divmod_test(void) {\n")
		f.write('\tprintf("Modular Key Division Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t q = { };\n")
		f.write(f"\t// q = 0x{q:0128X}\n\t// m = 0x{m:0128X}\n\t// t = 0x{t:0128X}\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\n");\n\tcurve25519_key_divmod(&k1, &k2, &q);\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tint32_t res = curve25519_key_cmp(&k3, &q);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			t = random.getrandbits(512)
			m = modular_inverse(t, M)
			while t is None:
				t = random.getrandbits(512)
				m = modular_inverse(t, M)
			assert (m * t) % M == 1
			q = (n * m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// q = 0x{q:0128X}\n\t// m = 0x{m:0128X}\n\t// t = 0x{t:0128X}\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\n");\n\tcurve25519_key_divmod(&k1, &k2, &q);\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tres = curve25519_key_cmp(&k3, &q);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(TEST_COUNT, TEST_COUNT * 2):
			n = random.getrandbits(512)
			t = random.getrandbits(512)
			m = modular_inverse(t, M)
			while t is None:
				t = random.getrandbits(512)
				m = modular_inverse(t, M)
			assert (m * t) % M == 1
			q = (n * m) % M
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(t) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(t >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\t// q = 0x{q:0128X}\n\t// m = 0x{m:0128X}\n\t// t = 0x{t:0128X}\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, COMPLETE);\n\tprintf("Expected:\\nq:\\n");\n\tcurve25519_key_divmod(&k1, &k2, &q);\n\tcurve25519_key_printf(&k3, COMPLETE);\n\tres = curve25519_key_cmp(&k3, &q);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("q:\\n");\n\t\tcurve25519_key_printf(&q, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")	

def main():
	# write_init_test()
	# write_cmp_test()
	# write_cmp_high_test()
	# write_cmp_low_test()
	# write_modulo_test()
	# write_add_modulo_test()
	# write_add_modulo_self_test()
	# write_add_modulo_inplace_test()
	# write_add_test()
	# write_add_self_test()
	# write_add_self_modulo_test()
	# write_add_inplace_test()
	# write_sub_test()
	# write_sub_inplace_test()
	# write_sub_modulo_test()
	# write_sub_modulo_inplace_test()
	# write_double_test()
	# write_double_inplace_test()
	# write_double_modulo_test()
	# write_double_modulo_inplace_test()
	# write_lshift_test()
	# write_rshift_test()
	# write_lshift_inplace_test()
	# write_rshift_inplace_test()
	# write_and_test()
	# write_xor_test()
	# write_log2_test()
	# write_mul_test()
	# write_mul_modulo_test()
	# write_mul_inplace_test()
	# write_mul_modulo_inplace_test()
	# write_div_test()
	# write_inv_test()
	# write_divmod_test()

if __name__ == "__main__":
	main()