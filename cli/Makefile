# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror -O2

# Libraries
LIBS = -lrocksdb

# Source files
SRCS = counter_cli.c 

# Object files (in build directory)
OBJS = $(addprefix $(BUILD_DIR)/, $(SRCS:.c=.o))

# Build directory
BUILD_DIR = build

# Executable name
TARGET = counter_cli

# Default target
all: $(BUILD_DIR) $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Linking (update path)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Compiling (update path)
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up (update path)
clean:
	rm -rf $(BUILD_DIR) $(TARGET)

# Phony targets
.PHONY: all clean
