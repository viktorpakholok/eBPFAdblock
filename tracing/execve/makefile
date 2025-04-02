BPF_C_FILE=syscall_trace.bpf.c
BPF_OBJ=syscall_trace.bpf.o
LOADER_C_FILE=loader.c
LOADER_PROG=loader
BIN_DIR=bin
OBJ_DIR=obj

all: compile load

.PHONY: compile clean

compile: ${BPF_C_FILE} ${LOADER_C_FILE}
	mkdir -p ${BIN_DIR}
	mkdir -p ${OBJ_DIR}
	cd ${OBJ_DIR} && clang -O2 -g -Wall -target bpf -c ../${BPF_C_FILE} -o ${BPF_OBJ}
	cd ${BIN_DIR} && gcc -Wall -o ${LOADER_PROG} ../${LOADER_C_FILE} -lbpf

load: compile
	sudo bin/loader ./obj/syscall_trace.bpf.o handle_execve

clean:
	rm -rf ${BIN_DIR}
	rm -rf ${OBJ_DIR}