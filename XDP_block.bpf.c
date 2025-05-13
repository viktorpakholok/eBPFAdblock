#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // IPv4 address
    __type(value, __u64);
    __uint(max_entries, 1024);
} ip_map SEC(".maps");


SEC("xdp")
int xdp_check(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }
        
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }

    // bpf_printk("Here1 %x, %d", iph->saddr, iph->saddr);

    __u32 *blockIP = bpf_map_lookup_elem(&ip_map, &iph->saddr);
    if (blockIP) {
        bpf_printk("Blocked %x", iph->saddr);
        return XDP_ABORTED;
    }
    // bpf_printk("Here %x", iph->saddr);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
