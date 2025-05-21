# Define the C compiler
CC = gcc

# Define compiler flags
# -mavx512f, -mavx512dq -mavx512vl enable specific AVX-512 instruction sets
CFLAGS = -Wall -Wextra -mavx512f -mavx512dq -mavx512vl

# Define linker flags (libraries to link against)
# Added -mconsole for Windows to ensure it links as a console application
LDFLAGS = -lbcrypt

# Define the name of the executable
TARGET = curve25519

# Define the directory for object files
OBJDIR = objs

# VPATH tells make where to look for source files (e.g., tests.c, curve25519_key.c)
# It searches the current directory (.) and then the tests/ directory.
VPATH = . test

# Define all source files with their full paths
SRCS = \
	$(wildcard test/*.c) \
	curve25519_key.c \
	curve25519.c

# --- DEBUG LINE ---
# This will print the value of SRCS when make is run
$(info SRCS is: $(SRCS))
# ------------------

# Automatically generate object file names, placing them in OBJDIR
# and removing the original directory path from the object file name.
# Example: tests/tests.c -> objs/tests.o
# Example: curve25519_key.c -> objs/curve25519_key.o
OBJS = $(addprefix $(OBJDIR)/, $(notdir $(SRCS:.c=.o)))

# Default target: builds the executable
all: $(TARGET)

# Rule to link the executable
# Make the target depend on the object directory being created first
$(TARGET): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to create the object directory if it doesn't exist
# This rule will be executed before any object files are compiled,
# ensuring the directory exists.
$(OBJDIR):
	@mkdir -p $(OBJDIR)

# Rule to compile each C source file into an object file
# The object file is placed in the OBJDIR.
# The `%.c` prerequisite will be found by `make` using the VPATH variable.
# Removed $(OBJDIR) as a prerequisite here, as it's now handled by the $(TARGET) rule.
$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets do not correspond to actual files
.PHONY: all clean test

test:
	python write_tests.py

# Clean target: removes compiled files and the object directory
clean:
	rm -f $(OBJS) $(TARGET)
	@rmdir $(OBJDIR) 2>/dev/null || true # Remove directory, suppress error if not empty or doesn't exist
