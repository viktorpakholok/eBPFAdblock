#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

    if (iph->protocol != IPPROTO_TCP) {
        bpf_printk("Here1 %x, %d", iph->saddr, iph->saddr);

        if (iph->saddr == 0x01010101) {
            return XDP_ABORTED;
        }

        return XDP_PASS;
    }

    bpf_printk("Here %x", iph->saddr);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
