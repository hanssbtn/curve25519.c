import random

TEST_COUNT = 10

def write_add_test():
	bitmask = (2 ** 64 - 1)
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("test/add_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_add_test(void) {\n")
		f.write('\tprintf("Add Test\\n");\n')
		f.write("\tcurve25519_key_t r = {.key64 = {0, 0, 0, 0}};\n")
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & bitmask:016X},\n\t\t0x{(m >> (64 * 1)) & bitmask:016X},\n\t\t0x{(m >> (64 * 2)) & bitmask:016X},\n\t\t0x{(m >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & bitmask:016X},\n\t\t0x{(r >> (64 * 1)) & bitmask:016X},\n\t\t0x{(r >> (64 * 2)) & bitmask:016X},\n\t\t0x{(r >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tint32_t res = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & bitmask:016X},\n\t\t0x{(m >> (64 * 1)) & bitmask:016X},\n\t\t0x{(m >> (64 * 2)) & bitmask:016X},\n\t\t0x{(m >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & bitmask:016X},\n\t\t0x{(r >> (64 * 1)) & bitmask:016X},\n\t\t0x{(r >> (64 * 2)) & bitmask:016X},\n\t\t0x{(r >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add(&k1, &k2, &r);\n\tres = curve25519_key_cmp(&r, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_add_inplace_test():
	bitmask = (2 ** 64 - 1)
	n = random.getrandbits(256) % ((2 ** 255) - 19)
	m = random.getrandbits(256) % ((2 ** 255) - 19)
	r = (n + m) % ((2 ** 255) - 19)
	i = 0
	with open("test/add_inplace_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_add_inplace_test(void) {\n")
		f.write('\tprintf("Add Inplace Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(m) & bitmask:016X},\n\t\t0x{(m >> (64 * 1)) & bitmask:016X},\n\t\t0x{(m >> (64 * 2)) & bitmask:016X},\n\t\t0x{(m >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k3 = {{.key64 = {{\n\t\t0x{(r) & bitmask:016X},\n\t\t0x{(r >> (64 * 1)) & bitmask:016X},\n\t\t0x{(r >> (64 * 2)) & bitmask:016X},\n\t\t0x{(r >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tint32_t res = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256) % ((2 ** 255) - 19)
			m = random.getrandbits(256) % ((2 ** 255) - 19)
			r = (n + m) % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(m) & bitmask:016X},\n\t\t0x{(m >> (64 * 1)) & bitmask:016X},\n\t\t0x{(m >> (64 * 2)) & bitmask:016X},\n\t\t0x{(m >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f"\tk3 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(r) & bitmask:016X},\n\t\t0x{(r >> (64 * 1)) & bitmask:016X},\n\t\t0x{(r >> (64 * 2)) & bitmask:016X},\n\t\t0x{(r >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("k1:\\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("k2:\\n");\n\tcurve25519_key_printf(&k2, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k3, B64);\n\tcurve25519_key_add_inplace(&k1, &k2);\n\tres = curve25519_key_cmp(&k1, &k3);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t\tcurve25519_key_printf(&k2, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def write_modulo_test():
	bitmask = (2 ** 64 - 1)
	n = random.getrandbits(256)
	n_mod = n % ((2 ** 255) - 19)
	i = 0
	with open("test/modulo_test.c", "w") as f:
		f.write("#include \"tests.h\"\n\nint32_t curve25519_key_modulo_test(void) {\n")
		f.write('\tprintf("Modulo Test\\n");\n')
		f.write(f"\tcurve25519_key_t k1 = {{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f"\tcurve25519_key_t k2 = {{.key64 = {{\n\t\t0x{(n_mod) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
		f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcompute_modulo_25519(&k1);\n\tint32_t res = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -1;\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		for i in range(1, TEST_COUNT):
			n = random.getrandbits(256)
			n_mod = n % ((2 ** 255) - 19)
			f.write(f"\tk1 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n) & bitmask:016X},\n\t\t0x{(n >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f"\tk2 = (curve25519_key_t){{.key64 = {{\n\t\t0x{(n_mod) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 1)) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 2)) & bitmask:016X},\n\t\t0x{(n_mod >> (64 * 3)) & bitmask:016X}\n\t}}}};\n")
			f.write(f'\tprintf("Test Case {i+1}\\n");\n\tprintf("Key: \\n");\n\tcurve25519_key_printf(&k1, B64);\n\tprintf("Expected: \\n");\n\tcurve25519_key_printf(&k2, B64);\n\tcompute_modulo_25519(&k1);\n\tres = curve25519_key_cmp(&k1, &k2);\n\tif (res) {{\n\t	printf("Test Case {i+1} FAILED\\n");\n\t\tcurve25519_key_printf(&k1, STR);\n\t	return -{i+1};\n\t}} else {{\n\t	printf("Test Case {i+1} PASSED\\n");\n\t}}\n\tprintf("---\\n\\n");\n')
		f.write("\treturn 0;\n")
		f.write("}")

def main():
	write_modulo_test()
	write_add_test()
	write_add_inplace_test()

if __name__ == "__main__":
	main()