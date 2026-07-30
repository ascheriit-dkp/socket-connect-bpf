BINARY_NAME := socket-connect-bpf
AMD64_DIR := bin/amd64
ARM64_DIR := bin/arm64

BENCHMARK_COUNT ?= 5
BENCHMARK_TIME ?= 250ms
BENCHMARK_CPU ?= 1,2,4

.PHONY: all generate build test benchmark clean

all: build test

generate:
	go generate

build: generate
	mkdir -p $(AMD64_DIR) $(ARM64_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(AMD64_DIR)/$(BINARY_NAME)
	GOOS=linux GOARCH=arm64 go build -o $(ARM64_DIR)/$(BINARY_NAME)

test:
	go test ./...

benchmark:
	go test ./... \
		-run '^$$' \
		-bench '^Benchmark' \
		-benchmem \
		-count=$(BENCHMARK_COUNT) \
		-benchtime=$(BENCHMARK_TIME) \
		-cpu=$(BENCHMARK_CPU)

clean:
	go clean
	rm -f bpf_*_bpfel.go bpf_*_bpfeb.go
	rm -f bpf_*_bpfel.o bpf_*_bpfeb.o
	rm -f $(AMD64_DIR)/$(BINARY_NAME)
	rm -f $(ARM64_DIR)/$(BINARY_NAME)
