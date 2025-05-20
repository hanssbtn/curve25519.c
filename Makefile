# Define the C compiler
CC = gcc

# Define compiler flags
# -mavx512f, -mavx512dq -mavx512vl enable specific AVX-512 instruction sets
CFLAGS = -Wall -Wextra -std=c99 -mavx512f -mavx512dq -mavx512vl

# Define linker flags (libraries to link against)
# Added -mconsole for Windows to ensure it links as a console application
LDFLAGS = -lbcrypt

# Define the name of the executable
TARGET = curve25519

# Define the directory for object files
OBJDIR = objs

VPATH = . test

# Define all source files
# Explicitly list tests/tests.c first as it contains the main function.
# Then include other .c files in the tests/ directory (excluding tests/tests.c to avoid duplication)
# and other project files.
SRCS = \
	$(wildcard test/*.c) \
	curve25519_key.c \
	curve25519.c

# --- DEBUG LINE ---
# This will print the value of SRCS when make is run
# $(info SRCS is: $(SRCS))
# ------------------

# Automatically generate object file names from source files, placing them in OBJDIR
# Replaces .c with .o and prepends the object directory
OBJS = $(addprefix $(OBJDIR)/, $(notdir $(SRCS:.c=.o)))

# Default target: builds the executable
all: $(TARGET)

# Rule to link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to create the object directory if it doesn't exist
$(OBJDIR):
	@mkdir -p $(OBJDIR)

# Rule to compile each C source file into an object file
# The object file is placed in the OBJDIR.
# The `%.c` prerequisite will be found by `make` using the VPATH variable.
$(OBJDIR)/%.o: %.c $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets do not correspond to actual files
.PHONY: all clean

# Clean target: removes compiled files and the object directory
clean:
	rm -f $(OBJS) $(TARGET)
# Remove directory, suppress error if not empty or doesn't exist
	@rmdir $(OBJDIR) 2>/dev/null || true 
