#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

#define BUFFER_SIZE 50

char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    __u16 dest_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); // Read sk_dport
    bpf_printk("UDP Destination Port: %d\n", dest_port);

    return 0;
}

// SEC("kprobe/sys_x64sendto")
// int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
//     __u16 dest_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)); // Read sk_dport
//     bpf_printk("UDP Destination Port: %d\n", dest_port);

//     return 0;
// }