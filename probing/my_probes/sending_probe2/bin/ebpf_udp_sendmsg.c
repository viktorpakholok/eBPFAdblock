#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define BUFFER_SIZE 50

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg) {
    bpf_printk("udp_sendmsg");
    
}


SEC("kprobe/__x64_sys_sendto")
int BPF_KPROBE(sendto) {
    bpf_printk("sendto");

}

