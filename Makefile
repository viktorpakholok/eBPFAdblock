ID = 
NI =

all: compile load

compile: XDP_part.bpf.c
	clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c XDP_part.bpf.c -o XDP_part.bpf.o

.PHONY: load info attach check detach

load: XDP_part.bpf.o
	sudo bpftool prog load XDP_part.bpf.o /sys/fs/bpf/XDP_part

info:
	sudo bpftool prog list
	ip link

attach:
	sudo bpftool net attach xdp id $(ID) dev $(NI)

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	sudo bpftool net detach xdp dev $(NI)
	sudo rm /sys/fs/bpf/XDP_part
