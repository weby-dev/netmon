# Top-level build orchestration for the XDP traffic monitor.
#
#   make            -> build eBPF object, generate skeleton, build collector
#   make ebpf       -> compile the XDP program only
#   make skeleton   -> generate the libbpf skeleton header
#   make collector  -> build the C++ collector (needs skeleton)
#   make vmlinux    -> (re)generate ebpf/vmlinux.h from the running kernel
#   make install    -> install binary, schema, systemd unit
#   make clean
#
# Toolchain requirements (Debian/Proxmox):
#   apt-get install clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev \
#                   libcurl4-openssl-dev cmake build-essential pkg-config

CLANG       ?= clang
BPFTOOL     ?= bpftool
ARCH        := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

EBPF_DIR    := ebpf
BUILD_DIR   := build
INC_DIR     := collector/include

VMLINUX     := $(EBPF_DIR)/vmlinux.h
BPF_SRC     := $(EBPF_DIR)/xdp_monitor.bpf.c
BPF_OBJ     := $(BUILD_DIR)/xdp_monitor.bpf.o
SKEL        := $(INC_DIR)/xdp_monitor.skel.h

CLANG_BPF_FLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
                   -I$(EBPF_DIR) -Wall -Wno-unused-function

.PHONY: all ebpf skeleton collector vmlinux install clean

all: collector

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Generate vmlinux.h from the running kernel's BTF (commit a copy for CI).
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(VMLINUX):
	@if [ ! -f $(VMLINUX) ]; then \
		echo ">> generating $(VMLINUX) from /sys/kernel/btf/vmlinux"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX); \
	fi

ebpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(EBPF_DIR)/common.h $(VMLINUX) | $(BUILD_DIR)
	$(CLANG) $(CLANG_BPF_FLAGS) -c $(BPF_SRC) -o $@
	llvm-strip -g $@ 2>/dev/null || true

skeleton: $(SKEL)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) name xdp_monitor_bpf > $@

collector: $(SKEL)
	cmake -S collector -B $(BUILD_DIR)/collector -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)/collector -j

install: collector
	install -D -m 0755 $(BUILD_DIR)/collector/netmon-collector /usr/local/bin/netmon-collector
	install -D -m 0644 clickhouse/schema.sql /etc/netmon/schema.sql
	install -D -m 0644 deploy/netmon-collector.service /etc/systemd/system/netmon-collector.service
	install -D -m 0644 config/collector.env /etc/netmon/collector.env
	@echo ">> installed. Edit /etc/netmon/collector.env then: systemctl enable --now netmon-collector"

clean:
	rm -rf $(BUILD_DIR) $(SKEL)
