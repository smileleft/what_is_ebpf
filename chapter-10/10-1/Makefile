BPF_CLANG=clang
BPF_LLVM_STRIP=llvm-strip
CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I./common -I./ebpf
USER_FLAGS=-Wall -g -I./common -I./ebpf

BPF_OBJ=build/l7_filter_kern.o
USER_BIN=build/user_loader

.PHONY: all clean

all: $(BPF_OBJ) $(USER_BIN)

build:
	mkdir -p build

$(BPF_OBJ): build ebpf/l7_filter_kern.c ebpf/maps.h
	$(BPF_CLANG) $(CFLAGS) -c ebpf/l7_filter_kern.c -o $(BPF_OBJ)
	$(BPF_LLVM_STRIP) -g $(BPF_OBJ)

$(USER_BIN): user/main.c
	$(CC) $(USER_FLAGS) -o $(USER_BIN) user/main.c -lbpf -lelf -lz

clean:
	rm -rf build

