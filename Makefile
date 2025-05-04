XDP_PROG_NAME=XDP_block.c
XDP_OBJ_NAME=XDP_block.o
MANAGE_PROG_NAME=manage.c
MANAGE_EXE_NAME=manage
# BPF_PROG_NAME=XDP_block
BIN_DIR=./bin
OBJ_DIR=./obj

ARCH := $(shell uname -m)

ifeq ($(ARCH), x86_64)
    LINUX_LIB=/usr/include/x86_64-linux-gnu/
else ifeq ($(ARCH), aarch64)
	LINUX_LIB=/usr/include/aarch64-linux-gnu/
else
	$(error Unsupported architecture: $(ARCH))
endif




all: compile move load pin

compile:
	mkdir -p ${OBJ_DIR}
	mkdir -p ${BIN_DIR}
	clang -O2 -target bpf -g -I ${LINUX_LIB} -I /usr/include/bpf -c ${XDP_PROG_NAME} -o ${XDP_OBJ_NAME}
	clang -o ${BIN_DIR}/${MANAGE_EXE_NAME} ${MANAGE_PROG_NAME} -lbpf

move: ${XDP_OBJ_NAME}
	mv ${XDP_OBJ_NAME} ${OBJ_DIR}/${XDP_OBJ_NAME}

.PHONY: load pin info check detach clean

load: ${OBJ_DIR}/${XDP_OBJ_NAME}
	sudo ip link set $$(ip link | grep "^2" | sed -n 's/^2: \([^:]*\):.*/\1/p') xdp obj ${OBJ_DIR}/${XDP_OBJ_NAME} sec xdp

pin:
	sudo bpftool map pin id $$(sudo bpftool map show | grep "ip_map" | cut -d':' -f1) /sys/fs/bpf/xdp/ip_map
	sudo bpftool map pin id $$(sudo bpftool map show | grep "domain_map" | cut -d':' -f1) /sys/fs/bpf/xdp/domain_map

info:
	sudo bpftool prog list
	ip link


check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	rm -rf ${OBJ_DIR}
	rm -rf ${BIN_DIR}
	sudo bpftool net detach xdp dev $$(ip link | grep "^2" | sed -n 's/^2: \([^:]*\):.*/\1/p')
	sudo rm /sys/fs/bpf/xdp/ip_map
	sudo rm /sys/fs/bpf/xdp/domain_map

clean: detach
