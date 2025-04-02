// syscall_trace.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// static __always_inline size_t bpf_strlen(const char *s) {
//     size_t i = 0;
//     while (s[i])
//         i++;
//     return i;
// }

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

    const char *filename = (const char *)ctx->args[0];  // The program path (first argument)

    // // Print the syscall information and arguments
    bpf_printk("Process %d called execve syscall\n", pid);
    bpf_printk("Program: %s\n", filename);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
