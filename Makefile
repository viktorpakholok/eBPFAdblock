# Compiler and tools
CLANG=clang
LLC=llc

# BPF target architecture (e.g., x86, arm64)
BPF_TARGET_ARCH?=x86

# Compiler flags for eBPF
CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -Wall \
       -I/usr/include -I/usr/include/bpf

# Source and output directories
SRC_DIR=bpf
BUILD_DIR=build

# Find all .bpf.c files in SRC_DIR
BPF_SRC=$(wildcard $(SRC_DIR)/*.bpf.c)

# Generate .o output names in BUILD_DIR
BPF_OBJ=$(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRC))

# Default target
all: $(BPF_OBJ)

# Rule to compile .bpf.c to .bpf.o
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean up
clean:
	rm -rf $(BUILD_DIR)
