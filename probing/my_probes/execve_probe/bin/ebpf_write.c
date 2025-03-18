#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_execve.s")
int kprobe_execve(struct pt_regs *ctx)
{
    const char *pathname = (const char *)PT_REGS_PARM1(ctx);
    if (!pathname) {
    bpf_printk("Invalid pathname pointer\n");
    return 0;
}
    char pathname_read[50];
    int res = bpf_copy_from_user(pathname_read, sizeof(pathname_read), pathname);
    if (res < 0) {
         bpf_printk("bad res: %d", res);
    } else {
         bpf_printk("pathname: %s", pathname_read);
    }
    return 0;
}
