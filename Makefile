APP = cerberus_agent

BPF_OBJ = ips_core.bpf.o
SKEL = ips_core.skel.h

CXX = g++
CLANG = clang
BPFTOOL = bpftool

CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

INCLUDES = -Iinclude
AGENT_INCLUDES = -Iinclude -Ibuild

BPF_SRC = src/bpf/ips_core.bpf.c
BPF_HDR = $(wildcard src/bpf/*.bpf.h) $(wildcard src/bpf/hooks/*.bpf.h)

AGENT_SRC = $(wildcard src/agent/*.cpp)
AGENT_HDR = $(wildcard src/agent/*.h)

all: build/$(APP)

headers/vmlinux.h:
	mkdir -p headers
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

build/$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) include/cerberus/common.h headers/vmlinux.h
	mkdir -p build
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -Iheaders -c $(BPF_SRC) -o build/$(BPF_OBJ)

build/$(SKEL): build/$(BPF_OBJ)
	$(BPFTOOL) gen skeleton build/$(BPF_OBJ) > build/$(SKEL)

build/$(APP): $(AGENT_SRC) $(AGENT_HDR) include/cerberus/common.h build/$(SKEL)
	$(CXX) $(CFLAGS) $(AGENT_INCLUDES) $(AGENT_SRC) -lbpf -lelf -lz -o build/$(APP)

clean:
	rm -rf build headers/vmlinux.h
