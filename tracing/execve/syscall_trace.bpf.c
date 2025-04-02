#include <vmlinux.h>
#include <bpf/bpf_helpers.h>


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {

    bpf_printk("SYSCALL TRACEPOINT(execve)");
    const char *filename = (const char *)ctx->args[0];  

    bpf_printk("Program: %s\n", filename);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
