# Makefile for fastflowips - Fast eBPF Network Flow Collector
# Builds statically linked binary with maximum optimizations

# Build configuration
BINARY_NAME := fastflowips
GO_SOURCE := main.go
BPF_SOURCE := flow.c
BPF_OBJECT := flow.o

# Compiler settings
CC := clang
GO := go

# Architecture detection
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    BPF_TARGET := x86
else ifeq ($(ARCH),aarch64)
    BPF_TARGET := arm64
else
    BPF_TARGET := $(ARCH)
endif

# BPF compile flags - maximum optimization
BPF_CFLAGS := -target bpf \
              -Wall -Wextra -Werror \
              -O3 \
              -g \
              -c \
              -I/usr/include \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I/usr/include/bpf \
              -D__KERNEL__ \
              -D__BPF_TRACING__ \
              -Wno-unused-value \
              -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types

# Go build flags - static linking with optimizations
GO_LDFLAGS := -s -w \
              -extldflags '-static' \
              -X 'main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")'

GO_BUILDFLAGS := -a \
                 -ldflags="$(GO_LDFLAGS)" \
                 -tags 'netgo osusergo static_build' \
                 -installsuffix netgo \
                 -trimpath

# Go optimization flags
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=$(shell go env GOARCH)

# Default target
.PHONY: all
all: $(BINARY_NAME)

# Build eBPF object file
$(BPF_OBJECT): $(BPF_SOURCE)
	@echo "Building eBPF program..."
	$(CC) $(BPF_CFLAGS) -o $@ $<
	@echo "eBPF object created: $@"

# Build Go binary (depends on eBPF object)
$(BINARY_NAME): $(BPF_OBJECT) $(GO_SOURCE)
	@echo "Building static Go binary with embedded eBPF..."
	$(GO) build $(GO_BUILDFLAGS) -o $@ $(GO_SOURCE)
	@echo "Self-contained binary created: $@"
	@echo "Binary size: $(shell ls -lh $(BINARY_NAME) 2>/dev/null | awk '{print $$5}' || echo 'N/A')"

# Install target
.PHONY: install
install: $(BINARY_NAME)
	@echo "Installing $(BINARY_NAME) to /usr/local/bin/"
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installed successfully"
	@echo "  Binary: /usr/local/bin/$(BINARY_NAME)"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME) $(BPF_OBJECT)
	@echo "Clean complete"

# Strip binary (additional size optimization)
.PHONY: strip
strip: $(BINARY_NAME)
	@echo "Stripping binary for minimum size..."
	strip -s $(BINARY_NAME)
	@echo "Stripped binary size: $(shell ls -lh $(BINARY_NAME) | awk '{print $$5}')"

# Compress binary with UPX (optional)
.PHONY: compress
compress: strip
	@echo "Compressing binary with UPX..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma $(BINARY_NAME); \
		echo "Compressed binary size: $(shell ls -lh $(BINARY_NAME) | awk '{print $$5}')"; \
	else \
		echo "UPX not found, skipping compression"; \
		echo "Install with: apt install upx-ucl (Debian/Ubuntu) or yum install upx (RHEL/CentOS)"; \
	fi

# Build with maximum optimization and compression
.PHONY: release
release: clean all strip compress
	@echo "Release build complete"
	@file $(BINARY_NAME)

# Development build (faster, with debug info)
.PHONY: dev
dev: BPF_CFLAGS += -DDEBUG
dev: GO_LDFLAGS := -X 'main.version=dev-$(shell date +%Y%m%d-%H%M%S)'
dev: GO_BUILDFLAGS := -ldflags="$(GO_LDFLAGS)" -race
dev: CGO_ENABLED := 1
dev: $(BINARY_NAME)
	@echo "Development build complete (with race detector)"

# Check dependencies
.PHONY: deps
deps:
	@echo "Checking build dependencies..."
	@command -v $(CC) >/dev/null 2>&1 || (echo "Error: clang not found" && exit 1)
	@command -v $(GO) >/dev/null 2>&1 || (echo "Error: go not found" && exit 1)
	@echo "Checking eBPF headers..."
	@test -f /usr/include/linux/bpf.h || (echo "Error: eBPF headers not found. Install: apt install libbpf-dev" && exit 1)
	@echo "Checking Go modules..."
	@$(GO) mod verify
	@echo "All dependencies satisfied"

# Show build info
.PHONY: info
info:
	@echo "Build Information:"
	@echo "  Target Binary: $(BINARY_NAME)"
	@echo "  Go Source: $(GO_SOURCE)"
	@echo "  BPF Source: $(BPF_SOURCE)"
	@echo "  BPF Object: $(BPF_OBJECT)"
	@echo "  Architecture: $(ARCH) -> $(BPF_TARGET)"
	@echo "  Go Version: $(shell $(GO) version)"
	@echo "  Clang Version: $(shell $(CC) --version | head -n1)"
	@echo "  Build Flags:"
	@echo "    BPF: $(BPF_CFLAGS)"
	@echo "    Go: $(GO_BUILDFLAGS)"

# Test build without running
.PHONY: test-build
test-build: deps all
	@echo "Testing binary..."
	@./$(BINARY_NAME) --help >/dev/null 2>&1 && echo "Binary test passed" || echo "Binary test failed"

# Quick build (parallel)
.PHONY: fast
fast:
	@$(MAKE) -j$(shell nproc) all

# Single binary without external flow.o dependency
.PHONY: single
single: $(BINARY_NAME)
	@echo "Verifying single binary (no external files needed)..."
	@rm -f flow.o
	@./$(BINARY_NAME) --help >/dev/null 2>&1 && echo "✓ Single binary works independently" || echo "✗ Single binary test failed"

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all         - Build eBPF object and self-contained Go binary (default)"
	@echo "  single      - Build and verify single binary (no external files needed)"
	@echo "  dev         - Development build with race detector"
	@echo "  release     - Production build with maximum optimization"
	@echo "  install     - Install binary to /usr/local/bin"
	@echo "  strip       - Strip binary for smaller size"
	@echo "  compress    - Compress binary with UPX"
	@echo "  clean       - Remove build artifacts"
	@echo "  deps        - Check build dependencies"
	@echo "  info        - Show build configuration"
	@echo "  test-build  - Test build without running"
	@echo "  fast        - Parallel build"
	@echo "  help        - Show this help"
	@echo ""
	@echo "Note: The binary embeds flow.o and works independently."