CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lrocksdb

TARGET = counter
SRCS = counter.c
OBJS = $(SRCS:.c=.o)

# Add build directory
BUILD_DIR = build

# Prefix objects with build directory
OBJS := $(addprefix $(BUILD_DIR)/,$(OBJS))

.PHONY: all clean

all: $(BUILD_DIR) $(BUILD_DIR)/$(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Update target rule
$(BUILD_DIR)/$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Update object file rule
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
