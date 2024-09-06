# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror -O2

# Libraries
LIBS = -lrocksdb

# Source files
SRCS = counter_cli.c 

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = counter_cli

# Default target
all: $(TARGET)

# Linking
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Compiling
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean
