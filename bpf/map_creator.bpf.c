#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");


char _license[] SEC("license") = "GPL";
