import random
from typing import Callable
import dataclasses

TEST_COUNT = 500
BITMASK = 2 ** 64 - 1
M = (2 ** 255) - 19
A = 486662
A24 = 121665

def format_num(n: int, indent: int = 2, length = 8) -> str:
	return ",".join([f"\n{"".join(["\t" for i in range(indent)])}0x{(n >> (l * 64)) & BITMASK:016X}ULL" for l in range(length)])

def sqrt_25519(n):
	global M
	n_rem = n % M
	if pow(n_rem, (M - 1) // 2, M) != 1:
		return None, None
	v = pow(2 * n_rem, (M - 5)//8, M)
	# print("v: ", v)
	i = ((2 * n_rem) * (v ** 2)) % M
	# print("i: ", i)
	r1 = (n_rem * v * (i - 1)) % M
	r2 = M - r1
	# print("root: ", root)
	return r1, r2

@dataclasses.dataclass
class Point:
	def __init__(self: "Point", x: int, y: int) -> "Point":
		self.x = x
		self.y = y
G_base = Point(9, 14781619447589544791020593568409986887264606134616475288964881837755586237401)

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
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, COMPLETE);\n\tprintf("Expected: {r}\\n");\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, COMPLETE);\n\t\tcurve25519_key_printf(&k2, COMPLETE);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
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
		i = TEST_COUNT
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
		i = TEST_COUNT
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

def write_cswap_test():
	global M
	n = random.getrandbits(512)
	swap = random.getrandbits(1)
	q = random.getrandbits(512)
	i = 0
	with open("tests/ladder_tests/cswap_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_cswap_test(void) {\n")
		f.write('\tprintf("Conditional Key Swap Test\\n");\n')
		f.write(f"\tbool swap = {swap};\n")
		f.write(f"\tcurve25519_proj_point_t k1 = {{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
		if swap:
			f.write(f"\tcurve25519_proj_point_t k2 = {{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tcurve25519_proj_point_t k3 = {{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tcurve25519_proj_point_t k4 = {{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
		else:
			f.write(f"\tcurve25519_proj_point_t k2 = {{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tcurve25519_proj_point_t k3 = {{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = \n\t{{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tcurve25519_proj_point_t k4 = {{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1.X:\\n");\n\tcurve25519_key_printf(&k1.X, COMPLETE);\n\tprintf("k1.Z:\\n");\n\tcurve25519_key_printf(&k1.Z, COMPLETE);\n\tprintf("k2.X:\\n");\n\tcurve25519_key_printf(&k2.X, COMPLETE);\n\tprintf("k2.Z:\\n");\n\tcurve25519_key_printf(&k2.Z, COMPLETE);\n\tprintf("Expected:\\n");\n\tcurve25519_cswap(&k1, &k2, swap);\n\tprintf("k3.X:\\n");\n\tcurve25519_key_printf(&k3.X, COMPLETE);\n\tprintf("k3.Z:\\n");\n\tcurve25519_key_printf(&k3.Z, COMPLETE);\n\tprintf("k4.X:\\n");\n\tcurve25519_key_printf(&k4.X, COMPLETE);\n\tprintf("k4.Z:\\n");\n\tcurve25519_key_printf(&k4.Z, COMPLETE);\n\tint32_t res = curve25519_cmp_eq(&k1, &k3) | curve25519_cmp_eq(&k2, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1.X:\\n");\n\t\tcurve25519_key_printf(&k1.X, COMPLETE);\n\t\tprintf("k1.Z:\\n");\n\t\tcurve25519_key_printf(&k1.Z, COMPLETE);\n\t\tprintf("k2.X:\\n");\n\t\tcurve25519_key_printf(&k2.X, COMPLETE);\n\t\tprintf("k2.Z:\\n");\n\t\tcurve25519_key_printf(&k2.Z, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(512)
			swap = random.getrandbits(1)
			q = random.getrandbits(512)
			f.write(f"\tswap = {swap};\n")
			f.write(f"\tk1 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f"\tk2 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			if swap:
				f.write(f"\tk3 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
				f.write(f"\tk4 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			else:
				f.write(f"\tk3 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
				f.write(f"\tk4 = (curve25519_proj_point_t){{.X = {{.key64 = {{\n\t\t0x{(q) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(q >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}},\n\t .Z = {{.key64 = {{\n\t\t0x{(n) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 1)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 2)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 3)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 4)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 5)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 6)) & BITMASK:016X}ULL,\n\t\t0x{(n >> (64 * 7)) & BITMASK:016X}ULL\n\t}}}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1.X:\\n");\n\tcurve25519_key_printf(&k1.X, COMPLETE);\n\tprintf("k1.Z:\\n");\n\tcurve25519_key_printf(&k1.Z, COMPLETE);\n\tprintf("k2.X:\\n");\n\tcurve25519_key_printf(&k2.X, COMPLETE);\n\tprintf("k2.Z:\\n");\n\tcurve25519_key_printf(&k2.Z, COMPLETE);\n\t\n\tprintf("Expected:\\n");\n\tcurve25519_cswap(&k1, &k2, swap);\n\tprintf("k3.X:\\n");\n\tcurve25519_key_printf(&k3.X, COMPLETE);\n\tprintf("k3.Z:\\n");\n\tcurve25519_key_printf(&k3.Z, COMPLETE);\n\tprintf("k4.X:\\n");\n\tcurve25519_key_printf(&k4.X, COMPLETE);\n\tcurve25519_key_printf(&k4.Z, COMPLETE);\n\tres = curve25519_cmp_eq(&k1, &k3) | curve25519_cmp_eq(&k2, &k4);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tprintf("k1.Z:\\n");\n\t\tcurve25519_key_printf(&k1.Z, COMPLETE);\n\t\tprintf("k2.X:\\n");\n\t\tcurve25519_key_printf(&k2.X, COMPLETE);\n\t\tprintf("k2.Z:\\n");\n\t\tcurve25519_key_printf(&k2.Z, COMPLETE);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def add_point(p1: Point | None, p2: Point | None) -> Point | None:
	if p1 is None:
		return Point(p2.x, p2.y)
	if p2 is None:
		return Point(p1.x, p1.y)
	global A
	global M
	if (p1.x == p2.x):
		if (p1.y + p2.y) % M == 0:
			return None
		if (p1.y == p2.y):
			return double_point(p1)
		
	# y ^ 2 = x ^ 3 + 486662 * x ^ 2 + x mod 2 ^ 255 - 19
	# y = x * m + b mod 2 ^ 255 - 19
	# (x * m + b) ^ 2 = x ^ 3 + 486662 * x ^ 2 + x mod 2 ^ 255 - 19
	# (x * m + b) ^ 2 = x ^ 3 + 486662 * x ^ 2 + x mod 2 ^ 255 - 19
	# x ^ 3 - ((m * x) ^ 2 + b ^ 2 + 2 * x * m * b) + 486662 * x ^ 2 + x = 0 mod 2 ^ 255 - 19
	# x ^ 3 + (486662 - m ^ 2) * x ^ 2 + (1 - 2 * m * b) * x - b ^ 2 =  0 mod 2 ^ 255 - 19
	# - (x1 + x2 + x3) = 486662 - m ^ 2 mod 2 ^ 255 - 19
	# x1 + x2 + x3 = m ^ 2 - 486662 mod 2 ^ 255 - 19
	# x3 = m ^ 2 - 486662 - x2 - x1 mod 2 ^ 255 - 19
	# (y - y1) * (x - x1) ^ (- 1) = m mod 2 ^ 255 - 19
	# y = m * (x - x1) + y1 mod 2 ^ 255 - 19
	# y = -y3, x = x3
	# -y3 = m * (x3 - x1) + y1 mod 2 ^ 255 - 19
	# y3 = - m * (x3 - x1) - y1 mod 2 ^ 255 - 19
	# y3 = m * (x1 - x3) - y1 mod 2 ^ 255 - 19
	dx = (p2.x - p1.x) % M
	if dx == 0:
		raise ValueError("Delta X is zero, points are likely inverses or identical (edge case not handled).")
	dy = (p2.y - p1.y) % M
	
	m =  (dy * modular_inverse(dx, M)) % M
	m2 = (m * m) % M
	x3 = (m2 - p2.x - p1.x - A) % M
	return Point(x3, (m * (p1.x - x3) - p1.y) % M)

def double_point(p1: Point | None) -> Point | None:
	if p1 is None or p1.y == 0:
		return None
	global A
	global M
	# y ^ 2 = x ^ 3 + A * x ^ 2 + x mod 2 ^ 255 - 19
	# 2 * y dy = 3 * x ^ 2 + 973324 * x + 1  mod 2 ^ 255 - 19
	# dy / dx = (3 * x ^ 2 + 973324 * x + 1) * (2 * y) ^ (-1) mod 2 ^ 255 - 19
	m = (((3 * p1.x * p1.x + A * 2 * p1.x + 1) % M) * modular_inverse(2 * p1.y, M)) % M
	m2 = (m * m) % M
	x3 = (m2 - A - 2 * p1.x) % M
	return Point(x3, (m * (p1.x - x3) - p1.y) % M)
		
def scalar_multiply(P: Point | None, n: int) -> Point | None:
	"""
	Performs scalar multiplication k*P using double-and-add.
	This is NOT the Montgomery Ladder and is NOT constant-time.
	For testing purposes only.
	"""
	if P is None or n == 0:
		return None # n*O = O, 0*P = O

	result = None # Represents the point at infinity initially
	current_point = Point(P.x, P.y)

	# Iterate through bits of n (from LSB to MSB)
	# print("n: ", n)
	while n > 0:
		if n & 1: # If the current bit is 1
			result = add_point(result, current_point)
		current_point = double_point(current_point)
		n >>= 1 # Move to the next bit
	return result

def is_on_curve(p: Point) -> bool:
	global A
	if p is None: # Point at infinity is considered on the curve
		return True
		
	# y^2 = x^3 + Ax^2 + x mod M
	lhs = ((p.y % M) * (p.y % M)) % M
	rhs = (p.x * p.x * p.x + A * p.x * p.x + p.x) % M
	# print("lhs: ", lhs)
	# print("rhs: ", rhs)
	# print(lhs - rhs)
	return lhs == rhs

import math

def generate_clamped() -> int:
	n = random.getrandbits(256).to_bytes(32, 'little')
	k_clamped_bytes = bytearray(n)

	# Clear lowest 3 bits
	k_clamped_bytes[0] &= 0xF8

	# Clear highest bit (bit 255)
	k_clamped_bytes[31] &= 0x7F

	# Set second highest bit (bit 254)
	k_clamped_bytes[31] |= 0x40
	n = int.from_bytes(k_clamped_bytes, 'little')
	assert n >= 2 ** 254 and n < (2 ** 255) - 19 and n & 7 == 0 and n & 2 ** 255 == 0 and n & 2 ** 254 > 0
	return n

def cswap(X2: int, Z2: int, X3: int, Z3: int, swap: bool) -> tuple[int, int, int, int]:
	mask = (2 ** 256 - 1) * swap
	T1 = mask & (X2 ^ X3)
	T2 = mask & (Z2 ^ Z3)
	X3 = T1 ^ X3 # X2 or 0
	X2 = T1 ^ X2 # X3 or 0
	Z3 = T2 ^ Z3 # X2 or 0
	Z2 = T2 ^ Z2 # X3 or 0
	return (X2, Z2, X3, Z3)
	
def step(X1: int, X2: int, Z2: int, X3: int, Z3: int) -> tuple[int, int, int, int]:
	global M
	global A
	global A24
	# Steps taken from https://eprint.iacr.org/2020/956.pdf 
	# Step 2: T1 <- X2 + Z2
	T1 = (X2 + Z2) % M
	# Step 6: T5 <- T1 ^ 2
	T1T1 = (T1 * T1) % M
	# Step 3: T2 <- X2 − Z2
	T2 = (X2 - Z2) % M
	# Step 7: T6 <- T2 ^ 2
	T2T = (T2 * T2) % M
	# Step 16: T5 <- T5 − T6
	T5 = (T1T1 - T2T) % M 
	# Step 4: T3 <- X3 + Z3
	T3 = (X3 + Z3) % M
	# Step 5: T4 <- X3 - Z3
	T4 = (X3 - Z3) % M
	# Step 9: T1 <- T1 · T4
	T1T4 = (T4 * T1) % M
	# Step 8: T2 <- T2 · T3
	T2T3 = (T3 * T2) % M
	# Step 10: T1 <- T1 + T2
	# Step 12: X3 <- T1 ^ 2
	X3 = (((T1T4 + T2T3) % M) ** 2) % M
	# Step 11: T2 <- T1 − T2
	# Step 13: T2 <- T2 ^ 2
	# Step 14: Z3 <- T2 · X1
	Z3 = (X1 * (((T1T4 - T2T3) % M) ** 2)) % M
	# Step 15: X2 <- T5 · T6
	X2 = (T1T1 * T2T) % M
	# Step 17: T1 <- ((A + 2)/4) · T5
	# Step 18: T6 <- T6 + T1
	# Step 19: Z2 <- T5 · T6
	Z2 = (T5 * ((T1T1 + (A24 * T5) % M) % M)) % M
		
	return (X2, Z2, X3, Z3)

def ladder(G: Point | None, n: int) -> Point | None:
	if not G:
		return None
	X1, X2, Z2, X3, Z3 = G.x, 1, 0, G.x, 1
	prev_bit = 0
	# R0 = Point(0,0)
	# R1 = Point(G.x, G.y)
	for i in reversed(range(255)):
		bit = (n >> i) & 1
		# if bit == 0:
		# 	R1 = add_point(R0, R1)
		# 	R0 = double_point(R0)
		# else:
		# 	R0 = add_point(R0, R1)
		# 	R1 = double_point(R1)
		swap = bit ^ prev_bit
		prev_bit = bit
		X2, Z2, X3, Z3 = cswap(X2, Z2, X3, Z3, swap)
		X2, Z2, X3, Z3 = step(X1, X2, Z2, X3, Z3)
		assert X2 < M and Z2 < M and X3 < M and Z3 < M
	return (X2 * modular_inverse(Z2, M)) % M

def write_proj_to_affine_test():
	global M
	i = 0
	n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert n < 2 ** 255 and n >= 2 ** 254	
	m = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	m_inv = modular_inverse(m, M)
	r = (m_inv * n) % M
	with open("tests/ladder_tests/proj_to_affine_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_proj_to_affine_test(void) {\n")
		f.write('\tprintf("Affine Projection Test\\n");\n')
		f.write(f'\tcurve25519_key_t n = {{\n\t\t.key64 = {{{format_num(n, 3, 8)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t m = {{\n\t\t.key64 = {{{format_num(m, 3, 8)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t q = {{\n\t\t.key64 = {{{format_num(r, 3, 8)}\n\t\t}}\n\t}};\n')
		f.write('\tcurve25519_key_t r = { };\n')
		f.write(f"\tprintf(\"Test Case {i + 1}\\n\");\n")
		f.write("\tprintf(\"n:\\n\");\n")
		f.write(f"\tcurve25519_key_printf(&n, COMPLETE);\n")
		f.write("\tprintf(\"m:\\n\");\n")
		f.write(f"\tcurve25519_key_printf(&m, COMPLETE);\n")
		f.write("\tprintf(\"q:\\n\");\n")
		f.write(f"\tcurve25519_key_printf(&q, COMPLETE);\n")
		f.write(f"\tcurve25519_key_divmod(&n, &m, &r);\n")
		f.write('\tint res = curve25519_key_cmp(&r, &q);\n')
		f.write('\tif (res) {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
		f.write(f'\t\tcurve25519_key_printf(&r, COMPLETE);\n')
		f.write(f'\t\treturn -{i + 1};\n')
		f.write('\t} else {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
		f.write('\t}\n\n')
		for i in range(1, TEST_COUNT):
			f.write(f'\tn = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(n, 3, 8)}\n\t\t}}\n\t}};\n')
			f.write(f'\tm = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(m, 3, 8)}\n\t\t}}\n\t}};\n')
			f.write(f'\tq = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(r, 3, 8)}\n\t\t}}\n\t}};\n')
			f.write(f"\tprintf(\"Test Case {i + 1}\\n\");\n")
			f.write("\tprintf(\"n:\\n\");\n")
			f.write(f"\tcurve25519_key_printf(&n, COMPLETE);\n")
			f.write("\tprintf(\"m:\\n\");\n")
			f.write(f"\tcurve25519_key_printf(&m, COMPLETE);\n")
			f.write("\tprintf(\"q:\\n\");\n")
			f.write(f"\tcurve25519_key_printf(&q, COMPLETE);\n")
			f.write(f"\tcurve25519_key_divmod(&n, &m, &r);\n")
			f.write('\tres = curve25519_key_cmp(&r, &q);\n')
			f.write('\tif (res) {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
			f.write(f'\t\tcurve25519_key_printf(&r, COMPLETE);\n')
			f.write(f'\t\treturn -{i + 1};\n')
			f.write('\t} else {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
			f.write('\t}\n\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_ladder_step_test():
	global M
	global A
	global G_base
	i = 0
	n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert n < 2 ** 255 and n >= 2 ** 254	
	X1, X2, Z2, X3, Z3 = n, 1, 0, n, 1
	assert is_on_curve(G_base), "Base Point G is not on the curve!"
	steps = random.randint(1, 64)
	X2n, Z2n, X3n, Z3n = X2, Z2, X3, Z3
	for s in range(steps):
		X2n, Z2n, X3n, Z3n = step(X1, X2n, Z2n, X3n, Z3n)
	X1str = format_num(X1, length=4)
	X2str = format_num(X2, 3, 4)
	Z2str = format_num(Z2, 3, 4)
	X3str = format_num(X3, 3, 4)
	Z3str = format_num(Z3, 3, 4)
	X3nstr = format_num(X3n, 3, 4)
	Z3nstr = format_num(Z3n, 3, 4)
	with open("tests/ladder_tests/ladder_step_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_ladder_step_test(void) {\n")
		f.write('\tprintf("Montgomery Ladder Step Test\\n");\n')
		f.write(f'\tint steps = {steps};\n')
		f.write(f'\tcurve25519_key_t X1 = {{.key64 = {{{X1str}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_proj_point_t XZ2 = {{\n\t\t.X = {{.key64 = {{{X2str}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z2str}}}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_proj_point_t XZ3 = {{\n\t\t.X = {{.key64 = {{{X3str}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z3str}}}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_proj_point_t XZ3n = {{\n\t\t.X = {{.key64 = {{{X3nstr}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z3nstr}}}\n\t\t}}\n\t}};\n')
		f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
		f.write(f'\tprintf("X1:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&X1, COMPLETE);\n')
		f.write(f'\tprintf("XZ3.X:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&XZ3.X, COMPLETE);\n')
		f.write(f'\tprintf("Expected:\\n");\n')
		f.write(f'\tprintf("XZ3n.X:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&XZ3n.X, COMPLETE);\n')
		f.write(f'\tprintf("XZ3n.Z:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&XZ3n.Z, COMPLETE);\n')
		f.write('\tfor (int i = 0; i < steps; ++i) ')
		f.write(f'curve25519_ladder_step(&XZ2, &XZ3, &X1);\n')
		f.write(f'\tint res = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);\n')
		f.write('\tif (res) {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
		f.write(f'\t\tprintf("XZ3.X:\\n");\n')
		f.write('\t\tcurve25519_key_printf(&XZ3.X, COMPLETE);\n')
		f.write(f'\t\tprintf("XZ3.Z:\\n");\n')
		f.write('\t\tcurve25519_key_printf(&XZ3.Z, COMPLETE);\n')
		f.write('\t} else {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
		f.write("\t}\n\n")
		for i in range(1, TEST_COUNT):
			n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			assert n < 2 ** 255 and n >= 2 ** 254	
			X1, X3, Z3 = n, n, 1
			assert is_on_curve(G_base), "Base Point G is not on the curve!"
			steps = random.randint(1, 64)
			X2n, Z2n, X3n, Z3n = X2, Z2, X3, Z3
			for s in range(steps):
				X2n, Z2n, X3n, Z3n = step(X1, X2n, Z2n, X3n, Z3n)
			X1str = format_num(X1, length=4)
			X3str = format_num(X3, 3, 4)
			Z3str = format_num(Z3, 3, 4)
			X3nstr = format_num(X3n, 3, 4)
			Z3nstr = format_num(Z3n, 3, 4)
			f.write(f'\tsteps = {steps};\n')
			f.write(f'\tX1 = (curve25519_key_t){{.key64 = {{{X1str}\n\t\t}}\n\t}};\n')
			f.write(f'\tXZ2 = (curve25519_proj_point_t){{\n\t\t.X = {{.key64 = {{{X2str}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z2str}}}\n\t\t}}\n\t}};\n')
			f.write(f'\tXZ3 = (curve25519_proj_point_t){{\n\t\t.X = {{.key64 = {{{X3str}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z3str}}}\n\t\t}}\n\t}};\n')
			f.write(f'\tXZ3n = (curve25519_proj_point_t){{\n\t\t.X = {{.key64 = {{{X3nstr}}}\n\t\t}},\n\t\t.Z = {{.key64 = {{{Z3nstr}}}\n\t\t}}\n\t}};\n')
			f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
			f.write(f'\tprintf("X1:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&X1, COMPLETE);\n')
			f.write(f'\tprintf("XZ3.X:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&XZ3.X, COMPLETE);\n')
			f.write(f'\tprintf("Expected:\\n");\n')
			f.write(f'\tprintf("XZ3n.X:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&XZ3n.X, COMPLETE);\n')
			f.write(f'\tprintf("XZ3n.Z:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&XZ3n.Z, COMPLETE);\n')
			f.write('\tfor (int i = 0; i < steps; ++i) ')
			f.write(f'curve25519_ladder_step(&XZ2, &XZ3, &X1);\n')
			f.write(f'\tres = curve25519_key_cmp(&XZ3.X, &XZ3n.X) | curve25519_key_cmp(&XZ3.Z, &XZ3n.Z);\n')
			f.write('\tif (res) {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
			f.write(f'\t\tprintf("XZ3.X:\\n");\n')
			f.write('\t\tcurve25519_key_printf(&XZ3.X, COMPLETE);\n')
			f.write(f'\t\tprintf("XZ3.Z:\\n");\n')
			f.write('\t\tcurve25519_key_printf(&XZ3.Z, COMPLETE);\n')
			f.write(f'\t\treturn -{i + 1};\n')
			f.write('\t} else {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
			f.write("\t}\n\n")
			
		f.write("\treturn 0;\n")
		f.write("}")

def write_ladder_test():
	global M
	global A
	global G_base
	assert is_on_curve(G_base), "Base point G is not on the curve!"
	i = 0
	n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert n < 2 ** 255 and n >= 2 ** 254	
	G = scalar_multiply(G_base, n)
	assert is_on_curve(G), "Point G is not on the curve!"
	GL = ladder(G_base, n)
	nstr = format_num(n, 4, 4)
	assert GL == G.x, "Point GL does not result in the same point as G"
	with open("tests/ladder_tests/ladder_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_ladder_test(void) {\n")
		f.write('\tprintf("Montgomery Ladder Test\\n");\n')
		f.write(f'\tcurve25519_key_t n = {{\n\t\t.key64 = {{{nstr}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t nBASE = {{\n\t\t.key64 = {{{format_num(GL, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write('\tcurve25519_key_t r = { .key64 = { } };\n')
		f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
		f.write('\tprintf("n:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&n, COMPLETE);\n')
		f.write('\tprintf("Expected:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&nBASE, COMPLETE);\n')
		f.write(f'\tcurve25519_ladder(&n, BASE, &r);\n')
		f.write(f'\tint res = curve25519_key_cmp(&nBASE, &r);\n')
		f.write('\tif (res) {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
		f.write("\t\tprintf(\"r:\\n\");\n")
		f.write("\t\tcurve25519_key_printf(&r, COMPLETE);\n")
		f.write(f"\t\treturn -{i + 1};\n")
		f.write('\t} else {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
		f.write('\t}\n\n')
		for i in range(1, TEST_COUNT):
			n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			assert n < 2 ** 255 and n >= 2 ** 254	
			G = scalar_multiply(G_base, n)
			assert is_on_curve(G), "Point G is not on the curve!"
			GL = ladder(G_base, n)
			nstr = format_num(n, 3, 4)
			assert GL == G.x, "Point GL does not result in the same point as G"
			f.write(f'\tn = (curve25519_key_t){{\n\t\t.key64 = {{{nstr}\n\t\t}}\n\t}};\n')
			f.write(f'\tnBASE = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(GL, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
			f.write('\tprintf("n:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&n, COMPLETE);\n')
			f.write('\tprintf("Expected:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&nBASE, COMPLETE);\n')
			f.write(f'\tcurve25519_ladder(&n, BASE, &r);\n')
			f.write(f'\tres = curve25519_key_cmp(&nBASE, &r);\n')
			f.write('\tif (res) {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
			f.write("\t\tprintf(\"r:\\n\");\n")
			f.write("\t\tcurve25519_key_printf(&r, COMPLETE);\n")
			f.write(f"\t\treturn -{i + 1};\n")
			f.write('\t} else {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
			f.write('\t}\n\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_pub_key_init_test():
	global M
	global A
	i = 0
	n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert n < 2 ** 255 and n >= 2 ** 254
	b = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	r1, _ = sqrt_25519(b ** 3 + A * b ** 2 + b)
	while r1 is None:
		b = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
		r1, _ = sqrt_25519(b ** 3 + A * b ** 2 + b)
	base = Point(b, r1)
	n = generate_clamped()
	G = scalar_multiply(base, n)
	assert is_on_curve(G), "Point G is not on the curve!"
	GL = ladder(base, n)
	assert GL == G.x, "Point GL does not result in the same point as G"
	with open("tests/main_tests/pub_key_init_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_pub_key_init_test(void) {\n")
		f.write('\tprintf("Public Key Generation Test\\n");\n')
		f.write(f'\tcurve25519_key_t n = {{\n\t\t.key64 = {{{format_num(n, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t base = {{\n\t\t.key64 = {{{format_num(base.x, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t nbase = {{\n\t\t.key64 = {{{format_num(GL, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write('\tcurve25519_key_t r = { .key64 = { } };\n')
		f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
		f.write('\tprintf("n:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&n, COMPLETE);\n')
		f.write('\tprintf("base:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&base, COMPLETE);\n')
		f.write('\tprintf("Expected:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&nbase, COMPLETE);\n')
		f.write(f'\tcurve25519_pub_key_init(&n, &base, &r);\n')
		f.write(f'\tint res = curve25519_key_cmp(&nbase, &r);\n')
		f.write('\tif (res) {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
		f.write("\t\tprintf(\"r:\\n\");\n")
		f.write("\t\tcurve25519_key_printf(&r, COMPLETE);\n")
		f.write(f"\t\treturn -{i + 1};\n")
		f.write('\t} else {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
		f.write('\t}\n\n')
		for i in range(1, TEST_COUNT):
			n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			assert n < 2 ** 255 and n >= 2 ** 254
			b = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			r1, _ = sqrt_25519(b ** 3 + A * b ** 2 + b)
			while r1 is None:
				b = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
				r1, _ = sqrt_25519(b ** 3 + A * b ** 2 + b)
			base = Point(b, r1)
			n = generate_clamped()
			G = scalar_multiply(base, n)
			assert is_on_curve(G), "Point G is not on the curve!"
			GL = ladder(base, n)
			assert GL == G.x, "Point GL does not result in the same point as G"
			f.write(f'\tn = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(n, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tbase = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(base.x, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tnbase = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(GL, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
			f.write('\tprintf("n:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&n, COMPLETE);\n')
			f.write('\tprintf("base:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&base, COMPLETE);\n')
			f.write('\tprintf("Expected:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&nbase, COMPLETE);\n')
			f.write(f'\tcurve25519_pub_key_init(&n, &base, &r);\n')
			f.write(f'\tres = curve25519_key_cmp(&nbase, &r);\n')
			f.write('\tif (res) {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
			f.write("\t\tprintf(\"r:\\n\");\n")
			f.write("\t\tcurve25519_key_printf(&r, COMPLETE);\n")
			f.write(f"\t\treturn -{i + 1};\n")
			f.write('\t} else {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
			f.write('\t}\n\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_generate_shared_key_test():
	global M
	global A
	global G_base
	i = 0
	n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert n < 2 ** 255 and n >= 2 ** 254
	Gn = scalar_multiply(G_base, n)
	assert is_on_curve(Gn), "Point G is not on the curve!"
	GLn = ladder(G_base, n)
	assert GLn == Gn.x, "Point GL does not result in the same point as G"
	m = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
	assert m < 2 ** 255 and m >= 2 ** 254
	Gm = scalar_multiply(G_base, m)
	assert is_on_curve(Gm), "Point G is not on the curve!"
	GLm = ladder(G_base, m)
	assert GLm == Gm.x, "Point GL does not result in the same point as G"
	sharedm = ladder(Gn, m)
	sharedn = ladder(Gm, n)
	assert sharedm == sharedn
	with open("tests/main_tests/shared_key_gen_test.c", "w") as f:
		f.write("#include \"../../curve25519.h\"\n")
		f.write("#include \"../tests.h\"\n\nint32_t curve25519_shared_key_gen_test(void) {\n")
		f.write('\tprintf("Public Key Generation Test\\n");\n')
		f.write(f'\tcurve25519_key_t priv_key1 = {{\n\t\t.key64 = {{{format_num(n, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t pub_key1 = {{\n\t\t.key64 = {{{format_num(GLm, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t priv_key2 = {{\n\t\t.key64 = {{{format_num(m, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t pub_key2 = {{\n\t\t.key64 = {{{format_num(GLn, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write(f'\tcurve25519_key_t shared_key = {{\n\t\t.key64 = {{{format_num(sharedn, 3, 4)}\n\t\t}}\n\t}};\n')
		f.write('\tcurve25519_key_t r1 = { .key64 = { } };\n')
		f.write('\tcurve25519_key_t r2 = { .key64 = { } };\n')
		f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
		f.write('\tprintf("priv_key1:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&priv_key1, COMPLETE);\n')
		f.write('\tprintf("pub_key1:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&pub_key1, COMPLETE);\n')
		f.write('\tprintf("priv_key2:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&priv_key2, COMPLETE);\n')
		f.write('\tprintf("pub_key2:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&pub_key2, COMPLETE);\n')
		f.write('\tprintf("Expected:\\n");\n')
		f.write(f'\tcurve25519_key_printf(&shared_key, COMPLETE);\n')
		f.write(f'\tcurve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);\n')
		f.write(f'\tcurve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);\n')
		f.write(f'\tint res = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);\n')
		f.write('\tif (res) {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
		f.write("\t\tprintf(\"r1:\\n\");\n")
		f.write("\t\tcurve25519_key_printf(&r1, COMPLETE);\n")
		f.write("\t\tprintf(\"r2:\\n\");\n")
		f.write("\t\tcurve25519_key_printf(&r2, COMPLETE);\n")
		f.write(f"\t\treturn -{i + 1};\n")
		f.write('\t} else {\n')
		f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
		f.write('\t}\n\n')
		for i in range(1, TEST_COUNT):
			n = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			assert n < 2 ** 255 and n >= 2 ** 254
			Gn = scalar_multiply(G_base, n)
			assert is_on_curve(Gn), "Point G is not on the curve!"
			GLn = ladder(G_base, n)
			assert GLn == Gn.x, "Point GL does not result in the same point as G"
			m = (random.getrandbits(256) & ~((2 ** 255) | 7)) | (2 ** 254)
			assert m < 2 ** 255 and m >= 2 ** 254
			Gm = scalar_multiply(G_base, m)
			assert is_on_curve(Gm), "Point G is not on the curve!"
			GLm = ladder(G_base, m)
			assert GLm == Gm.x, "Point GL does not result in the same point as G"
			sharedm = ladder(Gn, m)
			sharedn = ladder(Gm, n)
			assert sharedm == sharedn
			f.write(f'\tpriv_key1 = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(n, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tpub_key1 = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(GLm, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tpriv_key2 = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(m, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tpub_key2 = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(GLn, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tshared_key = (curve25519_key_t){{\n\t\t.key64 = {{{format_num(sharedn, 3, 4)}\n\t\t}}\n\t}};\n')
			f.write(f'\tprintf("Test Case {i + 1}\\n");\n')
			f.write('\tprintf("priv_key1:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&priv_key1, COMPLETE);\n')
			f.write('\tprintf("pub_key1:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&pub_key1, COMPLETE);\n')
			f.write('\tprintf("priv_key2:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&priv_key2, COMPLETE);\n')
			f.write('\tprintf("pub_key2:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&pub_key2, COMPLETE);\n')
			f.write('\tprintf("Expected:\\n");\n')
			f.write(f'\tcurve25519_key_printf(&shared_key, COMPLETE);\n')
			f.write(f'\tcurve25519_shared_key_gen(&priv_key1, &pub_key1, &r1);\n')
			f.write(f'\tcurve25519_shared_key_gen(&priv_key2, &pub_key2, &r2);\n')
			f.write(f'\tres = curve25519_key_cmp(&shared_key, &r1) | curve25519_key_cmp(&shared_key, &r2);\n')
			f.write('\tif (res) {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} FAILED\\n");\n')
			f.write("\t\tprintf(\"r1:\\n\");\n")
			f.write("\t\tcurve25519_key_printf(&r1, COMPLETE);\n")
			f.write("\t\tprintf(\"r2:\\n\");\n")
			f.write("\t\tcurve25519_key_printf(&r2, COMPLETE);\n")
			f.write(f"\t\treturn -{i + 1};\n")
			f.write('\t} else {\n')
			f.write(f'\t\tprintf("Test Case {i + 1} PASSED\\n");\n')
			f.write('\t}\n\n')
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
	write_and_test()
	write_xor_test()
	write_log2_test()
	write_mul_test()
	write_mul_modulo_test()
	write_mul_inplace_test()
	write_mul_modulo_inplace_test()
	write_div_test()
	write_inv_test()
	write_divmod_test()
	write_cswap_test()
	write_proj_to_affine_test()
	write_ladder_step_test()
	write_ladder_test()
	write_pub_key_init_test()
	write_generate_shared_key_test()

if __name__ == "__main__":
	main()