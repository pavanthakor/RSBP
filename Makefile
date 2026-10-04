APP_NAME := rsbpd
BIN_DIR  := bin
# Any clang works for the BPF target; override with `make BPF_CLANG=clang-18` if needed.
BPF_CLANG ?= clang

.PHONY: build generate check-bpf-tools test lint docker-build clean install-caps demo setup

## build: compile the daemon. The eBPF object is committed, so this needs only Go
## (no clang/libbpf) — regeneration is a separate, explicit `make generate`.
build:
	CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/rsbpd

## setup: prepare a fresh machine for the demo (tracefs, dirs, capabilities).
setup: build
	sudo bash scripts/setup-demo.sh $(BIN_DIR)/$(APP_NAME)

## demo: run the deterministic reverse-shell demo.
demo:
	sudo ./demo/reverse_shell_demo.sh

check-bpf-tools:
	@command -v $(BPF_CLANG) >/dev/null 2>&1 || { echo "Missing clang. Install with: sudo apt-get install clang"; exit 1; }
	@if command -v dpkg >/dev/null 2>&1; then \
		dpkg -s libbpf-dev >/dev/null 2>&1 || { echo "Missing libbpf-dev. Install with: sudo apt-get install libbpf-dev"; exit 1; }; \
	elif command -v rpm >/dev/null 2>&1; then \
		rpm -q libbpf-devel >/dev/null 2>&1 || { echo "Missing libbpf-devel. Install with: sudo dnf install libbpf-devel"; exit 1; }; \
	else \
		echo "Ensure libbpf development headers (<bpf/bpf_helpers.h>) are installed."; \
	fi

## generate: regenerate the eBPF object + bindings from bpf/rsbp.bpf.c (needs clang + libbpf-dev).
generate: check-bpf-tools
	cd internal/ebpf && BPF2GO_CC=$(BPF_CLANG) go generate ./...

test:
	go test ./...

lint:
	go vet ./...

docker-build:
	docker build -t rsbp:latest -f deployments/Dockerfile .

## clean: remove the built binary only (keeps the committed generated eBPF bindings).
clean:
	rm -rf $(BIN_DIR)

install-caps:
	sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ./$(BIN_DIR)/$(APP_NAME)
	@echo "Capabilities set. Run: ./$(BIN_DIR)/$(APP_NAME) run --config config/demo.yaml"
