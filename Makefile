# Define the C compiler
CC = gcc

# Define compiler flags
# -mavx512f, -mavx512dq, -mavx512vl enable specific AVX-512 instruction sets
CFLAGS = -Wall -Wextra -Wpedantic -mavx512f -mavx512dq -mavx512vl

# Define linker flags (libraries to link against)
LDFLAGS = -lbcrypt

# Define the name of the executable
TARGET = curve25519

# Define all source files
# The main test file
SRCS = \
	$(wildcard test/*.c) \
	curve25519_key.c \
	curve25519.c

# Automatically generate object file names from source files
# Replaces .c with .o and keeps the directory structure
OBJS = $(SRCS:.c=.o)

# Default target: builds the executable
all: $(TARGET)

# Rule to link the executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Rule to compile each C source file into an object file
# $< refers to the first prerequisite (the .c file)
# $@ refers to the target (the .o file)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets do not correspond to actual files
.PHONY: all clean

# Clean target: removes compiled files
clean:
	rm -f $(OBJS) $(TARGET)
