# Explicitly set the shell for make to use (important for MSYS/MinGW environments)
# This helps ensure GNU utilities like 'find' are used instead of Windows built-ins.
SHELL = sh

# Define the C compiler
CC = gcc

# Define compiler flags
CFLAGS = -Wall -Wextra -mavx512f -mavx512dq -mavx512vl -I -fPIC.

LIBDIR = lib

# Define linker flags
LDFLAGS = -lbcrypt

# Define the directory for object files
OBJDIR = objs

VPATH = . tests

# Common source files (assumed to be in the root directory)
COMMON_SRCS = curve25519_key.c curve25519.c
COMMON_OBJS = $(addprefix $(OBJDIR)/, $(notdir $(COMMON_SRCS:.c=.o)))

STATIC_LIB_NAME = libcurve25519.a
SHARED_LIB_NAME = libcurve25519.so
STATIC_LIB = $(addprefix $(LIBDIR)/, $(STATIC_LIB_NAME))
SHARED_LIB = $(addprefix $(LIBDIR)/, $(SHARED_LIB_NAME))

# Find all run.c files in test subdirectories to determine executable groups
TEST_RUN_FILES = $(wildcard tests/*/run.c)
# Extract the pure directory names (e.g., add_test, init_test) to be used as executable names
TEST_EXEC_NAMES = $(patsubst tests/%/run.c,%,$(TEST_RUN_FILES))

# All executables that will be built
TARGET_EXECS = $(TEST_EXEC_NAMES)

# Initialize ALL_TEST_SPECIFIC_OBJS to ensure it's empty before appending
ALL_TEST_SPECIFIC_OBJS =

# --- DEBUG LINES ---
# $(info COMMON_SRCS is: $(COMMON_SRCS))
# $(info COMMON_OBJS is: $(COMMON_OBJS))
# $(info TEST_RUN_FILES is: $(TEST_RUN_FILES))
# $(info TEST_EXEC_NAMES is: $(TEST_EXEC_NAMES))
# $(info TARGET_EXECS is: $(TARGET_EXECS))
# -------------------

# --- Target and rules for building libraries ---
libraries: $(LIBDIR) $(STATIC_LIB) $(SHARED_LIB)

# Default target: builds all test executables
# Default target: builds all test executables
all: main_process $(OBJDIR) $(TARGET_EXECS) $(STATIC_LIB) $(SHARED_LIB)

# Define the *expected* test files. This list should be exhaustive,
# regardless of whether they exist yet.
# You might need to define this list manually, or generate it
# based on a known structure.
# Example: If you expect 'tests/module1/test1.c' and 'tests/module2/test2.c'
EXPECTED_TEST_FILES := \
    tests/add_tests/add_test.c \
    tests/add_tests/add_modulo_test.c \
    tests/add_tests/add_modulo_inplace_test.c 
# Add all your actual test files here

# (Optional, for example) Let's assume you have an environment variable
# or a specific configuration for where your 'tests' directory is.
# If tests are always relative to the Makefile, you don't strictly need TARGET_DIR for this check.
# TARGET_DIR := tests

# $(info EXPECTED_TEST_FILES is: $(EXPECTED_TEST_FILES))

main_process: | check
	@echo "Starting main process..."
	@echo "Main process completed successfully."

check:
	@echo "Checking for presence of all expected test files..."
	$(eval PRESENT_TEST_FILES := $(wildcard $(EXPECTED_TEST_FILES)))
	$(eval MISSING_FILES := $(filter-out $(PRESENT_TEST_FILES),$(EXPECTED_TEST_FILES)))

	@if [ -n "$(MISSING_FILES)" ]; then \
		echo "WARNING: missing test files. run `make test` to generate them"; \
		exit -1 \
	else \
		echo "All expected test files are present."; \
	fi

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(LIBDIR):
	@mkdir -p $(LIBDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(COMMON_OBJS) | $(LIBDIR)
	ar rcs $@ $^

# Rule for the shared library (.so)
$(SHARED_LIB): $(COMMON_OBJS) | $(LIBDIR)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS)

define GENERATE_TEST_RULES
# $(1) is the test executable name (e.g., add_test)

# Source files specific to the '$(1)' test group
# Double-escape $ to defer evaluation of wildcard until eval is called
TEST_$(1)_SRCS = $$(wildcard tests/$(1)/*.c)
# Use $(value ...) to force immediate expansion for debug output
# $$(info For $(1), TEST_$(1)_SRCS is: $$(TEST_$(1)_SRCS)) # Debug line - Corrected expansion

# Object files for this test group, with mangled names
# Double-escape $ for patsubst and for the TEST_$(1)_SRCS variable itself
TEST_$(1)_OBJS = $$(patsubst tests/$(1)/%.c,$(OBJDIR)/$(1)_%.o,$$(TEST_$(1)_SRCS))
# Use $(alue ...) to force immediate expansion for debug output
# $$(info For $(1), TEST_$(1)_OBJS is: $$(TEST_$(1)_OBJS)) # Debug line - Corrected expansion

# Rule to compile sources from 'tests/$(1)/'
$(OBJDIR)/$(1)_%.o: tests/$(1)/%.c | $$(OBJDIR)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

# Rule to link the executable '$(1)'
$(1): $$(TEST_$(1)_OBJS) $$(COMMON_OBJS) | $$(OBJDIR)
	$$(CC) $$(CFLAGS) $$^ -o $$@ $$(LDFLAGS)

# Append this group's object files to the global list
ALL_TEST_SPECIFIC_OBJS += $(TEST_$(1)_OBJS)
endef

$(foreach exec_name,$(TEST_EXEC_NAMES),$(eval $(call GENERATE_TEST_RULES,$(exec_name))))

ALL_TEST_CLEAN_SRCS = $(foreach test_dir,$(TEST_EXEC_NAMES), \
    $(wildcard tests/$(test_dir)/*.c) \
)
ALL_TEST_CLEAN_SRCS := $(filter-out %/run.c,$(ALL_TEST_CLEAN_SRCS))

run: $(TARGET_EXECS)
	@echo "Running tests..."
	$(foreach exec,$(TARGET_EXECS), \
		./$(exec); \
	)
	@echo "--- All tests finished ---"

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET_EXECS)
	rm -f $(COMMON_OBJS) $(ALL_TEST_SPECIFIC_OBJS)
	rm -rf $(OBJDIR)
	rm -f $(ALL_TEST_CLEAN_SRCS)
	rm $(STATIC_LIB)
	rm $(SHARED_LIB)
	rm -r $(LIBDIR)
	@echo "Cleaning specified test source files (excluding run.c files)..."
	
.PHONY: all clean run test

test:
	python write_tests.py
