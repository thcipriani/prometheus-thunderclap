CLANG ?= clang
LIBBPF_BUILD_DIR := $(abspath ./libbpf-build)
LIBBPF_OBJ := $(abspath $(LIBBPF_BUILD_DIR)/libbpf.a)
LIBBPF_SRC := $(abspath ./libbpf/src)

.PHONY: all
all: xdp_tcp_count.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(LIBBPF_BUILD_DIR):
	mkdir -p "$@"

$(LIBBPF_OBJ): $(LIBBPF_SRC) $(LIBBPF_BUILD_DIR)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

xdp_tcp_count.o: xdp_tcp_count.c vmlinux.h $(LIBBPF_OBJ)
	clang -O2 -Wall -g -target bpf -I./libbpf-build -I./libbpf/include/uapi -c xdp_tcp_count.c -o "$@"
	llvm-objdump -h "$@"
