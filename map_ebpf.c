#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64);
    __uint(max_entries, 1024);
} ip_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx){
    __u32 key = 1111;
    __u64 *value;

    value = bpf_map_lookup_elem(&ip_map, &key);
    if (!value) {
        __u64 init_value = 1;
        bpf_map_update_elem(&ip_map, &key, &init_value, BPF_ANY);
    } else {
        (*value)++;
        bpf_map_update_elem(&ip_map, &key, value, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
