#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#define MAX_DOMAIN_NAME_LEN 254

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_map SEC(".maps");


struct domain_name
{
    char name[MAX_DOMAIN_NAME_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct domain_name);
    __type(value, __u8);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_map SEC(".maps");




SEC("xdp")
int xdp_check(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_ABORTED;
    }
        
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return XDP_ABORTED;
    }

    bpf_printk("Here1 %x, %d", iph->saddr, iph->saddr);

    __u8 *blockIP = bpf_map_lookup_elem(&ip_map, &iph->saddr);
    if (blockIP) {
        return XDP_ABORTED;
    }
    bpf_printk("Here %x", iph->saddr);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
