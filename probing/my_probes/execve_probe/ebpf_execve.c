#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(execve)
{
    bpf_printk("execve");
//     if (!pathname) {
//     bpf_printk("Invalid pathname pointer\n");
//     return 0;
// }
//     char pathname_read[50];
//     int res = bpf_probe_read_user_str(pathname_read, sizeof(pathname_read), pathname);
//     if (res < 0) {
//          bpf_printk("bad res: %d", res);
//     } else {
//          bpf_printk("pathname: %s", pathname_read);
//     }
    return 0;
}
