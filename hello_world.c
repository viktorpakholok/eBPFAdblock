#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int packet_filter(struct xdp_md *ctx) {
    bpf_printk("Packet received!\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";