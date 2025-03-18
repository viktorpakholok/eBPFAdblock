#define __TARGET_ARCH_x86_64
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

#define BUFFER_SIZE 50

char LICENSE[] SEC("license") = "Dual BSD/GPL";



SEC("kprobe/__x64_sys_execve")
int BPF_PROG(sendto, int sockfd) {
    bpf_printk("sockfd: %d", sockfd);
    // sendto_args args();
    
    // bpf_printk("sendto(sockfd: %d)", args.sockfd);
    return 0;
}

