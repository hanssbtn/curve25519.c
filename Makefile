# Explicitly set the shell for make to use (important for MSYS/MinGW environments)
# This helps ensure GNU utilities like 'find' are used instead of Windows built-ins.
SHELL = sh

# Define the C compiler
CC = gcc

# Define compiler flags
CFLAGS = -Wall -Wextra -mavx512f -mavx512dq -mavx512vl -I.

# Define linker flags
LDFLAGS = -lbcrypt

# Define the directory for object files
OBJDIR = objs

VPATH = . tests

# Common source files (assumed to be in the root directory)
COMMON_SRCS = curve25519_key.c curve25519.c
COMMON_OBJS = $(addprefix $(OBJDIR)/, $(notdir $(COMMON_SRCS:.c=.o)))

# Find all run.c files in test subdirectories to determine executable groups
TEST_RUN_FILES = $(wildcard tests/*/run.c)
# Extract the pure directory names (e.g., add_test, init_test) to be used as executable names
TEST_EXEC_NAMES = $(patsubst tests/%/run.c,%,$(TEST_RUN_FILES))

# All executables that will be built
TARGET_EXECS = $(TEST_EXEC_NAMES)

# Initialize ALL_TEST_SPECIFIC_OBJS to ensure it's empty before appending
ALL_TEST_SPECIFIC_OBJS =

# --- DEBUG LINES ---
$(info COMMON_SRCS is: $(COMMON_SRCS))
$(info COMMON_OBJS is: $(COMMON_OBJS))
$(info TEST_RUN_FILES is: $(TEST_RUN_FILES))
$(info TEST_EXEC_NAMES is: $(TEST_EXEC_NAMES))
$(info TARGET_EXECS is: $(TARGET_EXECS))
# -------------------

# Default target: builds all test executables
all: $(OBJDIR) $(TARGET_EXECS)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@echo "Compiling common source: $< -> $@"
	$(CC) $(CFLAGS) -c $< -o $@

define GENERATE_TEST_RULES
# $(1) is the test executable name (e.g., add_test)

# Source files specific to the '$(1)' test group
# Double-escape $ to defer evaluation of wildcard until eval is called
TEST_$(1)_SRCS = $$(wildcard tests/$(1)/*.c)
# Use $(value ...) to force immediate expansion for debug output
$$(info For $(1), TEST_$(1)_SRCS is: $$(TEST_$(1)_SRCS)) # Debug line - Corrected expansion

# Object files for this test group, with mangled names
# Double-escape $ for patsubst and for the TEST_$(1)_SRCS variable itself
TEST_$(1)_OBJS = $$(patsubst tests/$(1)/%.c,$(OBJDIR)/$(1)_%.o,$$(TEST_$(1)_SRCS))
# Use $(alue ...) to force immediate expansion for debug output
$$(info For $(1), TEST_$(1)_OBJS is: $$(TEST_$(1)_OBJS)) # Debug line - Corrected expansion

# Rule to compile sources from 'tests/$(1)/'
$(OBJDIR)/$(1)_%.o: tests/$(1)/%.c | $$(OBJDIR)
	@echo "Compiling test-specific source: $$< for $(1) -> $$@"
	$$(CC) $$(CFLAGS) -c $$< -o $$@

# Rule to link the executable '$(1)'
$(1): $$(TEST_$(1)_OBJS) $$(COMMON_OBJS) | $$(OBJDIR)
	@echo "Linking executable: $(1) (Prerequisites: $$^)"
	$$(CC) $$(CFLAGS) $$^ -o $$@ $$(LDFLAGS)

# Append this group's object files to the global list
ALL_TEST_SPECIFIC_OBJS += $(TEST_$(1)_OBJS)
endef

$(foreach exec_name,$(TEST_EXEC_NAMES),$(eval $(call GENERATE_TEST_RULES,$(exec_name))))

# --- DEBUG LINE ---
$(info ALL_TEST_SPECIFIC_OBJS (after loop) is: $(ALL_TEST_SPECIFIC_OBJS))
# ------------------

run: $(TARGET_EXECS)
	@echo "Running tests..."
	$(foreach exec,$(TARGET_EXECS), \
		echo ""; \
		echo "--- Running ./$(exec) ---"; \
		./$(exec); \
	)
	@echo "--- All tests finished ---"

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET_EXECS)
	rm -f $(COMMON_OBJS) $(ALL_TEST_SPECIFIC_OBJS)
	rm -rf $(OBJDIR)
	@echo "Cleaning specified test source files (excluding run.c files)..."
	$(foreach test_dir_with_run_c,$(sort $(dir $(TEST_RUN_FILES))), \
		find $(test_dir_with_run_c) -maxdepth 1 -type f -name '*.c' ! -name 'run.c' -print -delete ;)

.PHONY: all clean run test

test:
	python write_tests.py
