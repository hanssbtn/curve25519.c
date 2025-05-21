import random

TEST_COUNT = 100
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
	with open("test/cmp_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_cmp_test(void) {\n")
		f.write('\tprintf("Compare Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tint t = {t};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: {r}\\n");\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("test/add_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_add_test(void) {\n")
		f.write('\tprintf("Add Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_self_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = n
	r = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("test/add_self_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_add_self_test(void) {\n")
		f.write('\tprintf("Add Self Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = n
			r = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("test/add_inplace_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_add_inplace_test(void) {\n")
		f.write('\tprintf("Add Inplace Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("test/sub_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_sub_test(void) {\n")
		f.write('\tprintf("Sub Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_sub(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_sub_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n - m) % ((2 ** 255) - 19)
	i = 0
	with open("test/sub_inplace_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_sub_inplace_test(void) {\n")
		f.write('\tprintf("Sub Inplace Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n - m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(m >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(r >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_sub_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_modulo_test():
	n = random.getrandbits(256)
	n_mod = n % ((2 ** 255) - 19)
	i = 0
	with open("test/modulo_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_modulo_test(void) {\n")
		f.write('\tprintf("Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mod) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcompute_modulo_25519(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256)
			n_mod = n % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mod) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mod >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcompute_modulo_25519(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	n_mul = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("test/double_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_x2_test(void) {\n")
		f.write('\tprintf("Double Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcurve25519_key_x2(&k1, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			n_mul = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcurve25519_key_x2(&k1, &r);\n\tres = curve25519_key_cmp(&r, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_double_inplace_test():
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	n_mul = (n * 2) % ((2 ** 255) - 19)
	i = 0
	with open("test/double_inplace_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_x2_inplace_test(void) {\n")
		f.write('\tprintf("Double Inplace Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcurve25519_key_x2_inplace(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			n_mul = (n * 2) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mul) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n_mul >> (64 * 3)) & BITMASK:016X}ULL\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcurve25519_key_x2_inplace(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def main():
	write_modulo_test()
	write_cmp_test()
	write_add_test()
	write_add_self_test()
	write_add_inplace_test()
	write_sub_test()
	write_sub_inplace_test()
	write_double_test()
	write_double_inplace_test()

if __name__ == "__main__":
	main()