APP = cerberus_agent
BPF_OBJ = ips_core.bpf.o
SKEL = ips_core.skel.h

CC = g++
CLANG = clang
BPFTOOL = bpftool

CFLAGS = -O2 -g -Wall
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86

all: build/$(APP)

headers/vmlinux.h:
	mkdir -p headers
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

build/$(BPF_OBJ): src/ips_core.bpf.c headers/vmlinux.h src/common.h
	mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -Iheaders -Isrc -c src/ips_core.bpf.c -o build/$(BPF_OBJ)

build/$(SKEL): build/$(BPF_OBJ)
	$(BPFTOOL) gen skeleton build/$(BPF_OBJ) > build/$(SKEL)

build/$(APP): src/ips_agent.cpp build/$(SKEL) src/common.h
	$(CC) $(CFLAGS) -Isrc -Ibuild src/ips_agent.cpp -lbpf -lelf -o build/$(APP)

clean:
	rm -rf build headers
