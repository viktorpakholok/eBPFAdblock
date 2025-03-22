file := "ebpf_udp_sendmsg.c"
BIN_DIR := "bin"

all: compile run

compile:
	mkdir -p ${BIN_DIR}
	cp ${file} ${BIN_DIR}/${file}
	cd ${BIN_DIR} && ecc ${file}

run: compile
	cd ${BIN_DIR} && sudo ecli ./package.json


clean:
	rm -rf ${BIN_DIR}
