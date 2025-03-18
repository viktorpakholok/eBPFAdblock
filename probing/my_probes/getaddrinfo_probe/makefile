file := "ebpf_ip_getter.c"
test_code := "ip_getter.c"
BIN_DIR := "bin"

all: compile run

compile:
	mkdir -p ${BIN_DIR}
	cd ${BIN_DIR} && g++ ../${test_code} -o ./test
	cp ${file} ${BIN_DIR}/${file}
	cd ${BIN_DIR} && ecc ${file}

run: compile
	cd ${BIN_DIR} && sudo ecli ./package.json

clean:
	rm -rf ${BIN_DIR}
