#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32); 
    __type(value, __u32);
} ip_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct __sk_buff *skb) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
