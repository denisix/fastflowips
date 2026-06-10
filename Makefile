BINARY_NAME := fastflowips
BPF_CFLAGS := -target bpf -O3 -g -c -Wall -Werror -D__KERNEL__ -D__BPF_TRACING__ \
              -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu -I/usr/include/bpf \
              -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types
GO_LDFLAGS := -s -w -extldflags '-static'
GO_BUILDFLAGS := -a -ldflags="$(GO_LDFLAGS)" -tags 'netgo osusergo' -trimpath

export CGO_ENABLED=0
export GOOS=linux

.PHONY: all clean install release test vet lint

all: flow.o
	go build $(GO_BUILDFLAGS) -o $(BINARY_NAME) main.go

flow.o: flow.c
	clang $(BPF_CFLAGS) -o $@ $<

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@fmt_files=$$(gofmt -l .); \
	if [ -n "$$fmt_files" ]; then \
		echo "gofmt needed on:"; echo "$$fmt_files"; exit 1; \
	fi
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; fi

clean:
	rm -f $(BINARY_NAME) flow.o
	rm -rf dist/

install: $(BINARY_NAME)
	sudo cp $(BINARY_NAME) /usr/local/bin/

release: clean flow.o
	mkdir -p dist
	GOARCH=amd64 go build $(GO_BUILDFLAGS) -o dist/$(BINARY_NAME)_linux_amd64 main.go
	GOARCH=arm64 go build $(GO_BUILDFLAGS) -o dist/$(BINARY_NAME)_linux_arm64 main.go
	-strip -s dist/$(BINARY_NAME)_linux_amd64
	-upx --best --lzma dist/*
	ls -la dist/

