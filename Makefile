APP_NAME := rsbpd
BIN_DIR := bin
BPF_CLANG := clang-15
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: build generate check-bpf-tools test lint docker-build clean strict-build verify-build install-caps

build: generate
	CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/rsbpd

check-bpf-tools:
	@command -v clang-15 >/dev/null 2>&1 || { echo "Missing clang-15. Install with: sudo apt-get install clang-15"; exit 1; }
	@command -v bpftool >/dev/null 2>&1 || { echo "Missing bpftool. Install with: sudo apt-get install bpftool"; exit 1; }
	@if command -v dpkg >/dev/null 2>&1; then \
		dpkg -s libbpf-dev >/dev/null 2>&1 || { echo "Missing libbpf-dev. Install with: sudo apt-get install libbpf-dev"; exit 1; }; \
	elif command -v rpm >/dev/null 2>&1; then \
		rpm -q libbpf-devel >/dev/null 2>&1 || { echo "Missing libbpf-devel. Install with: sudo dnf install libbpf-devel"; exit 1; }; \
	else \
		echo "Could not verify libbpf development package automatically. Ensure libbpf headers are installed."; \
	fi

generate: check-bpf-tools
	cd internal/ebpf && go generate ./...

test:
	go test ./...

verify-build:
	bash ./verify_build.sh

strict-build:
	bash ./scripts/build_strict.sh

lint:
	go vet ./...

docker-build:
	docker build -t rsbp:latest .

clean:
	rm -rf $(BIN_DIR)
	rm -f internal/ebpf/bpf_bpfel.go internal/ebpf/bpf_bpfeb.go internal/ebpf/bpf_bpfel.o internal/ebpf/bpf_bpfeb.o

install-caps:
	sudo setcap cap_sys_admin,cap_bpf,cap_net_admin,cap_net_raw+ep ./bin/rsbpd
	@echo "Capabilities set. Run: ./bin/rsbpd run --config config/rsbp.yaml"
