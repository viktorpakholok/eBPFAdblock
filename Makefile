# ID = 
# NI =

all: compile load attach

compile: XDP_part.bpf.c
	clang -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c XDP_part.bpf.c -o XDP_part.bpf.o

.PHONY: load info attach check detach

load: XDP_part.bpf.o
	sudo bpftool prog load XDP_part.bpf.o /sys/fs/bpf/XDP_part

info:
	sudo bpftool prog list
	ip link

	# sudo bpftool prog list | grep "xdp" | cut -c 1-2
	# ip link | grep "^2" | sed -n 's/^2: \([^:]*\):.*/\1/p'

attach:
	sudo bpftool net attach xdp id $$(sudo bpftool prog list | grep "xdp" | cut -c 1-2) dev $$(ip link | grep "^2" | sed -n 's/^2: \([^:]*\):.*/\1/p')

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

detach:
	sudo bpftool net detach xdp dev $$(ip link | grep "^2" | sed -n 's/^2: \([^:]*\):.*/\1/p')
	sudo rm /sys/fs/bpf/XDP_part
