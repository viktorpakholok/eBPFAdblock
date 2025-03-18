#!/usr/bin/python
from bcc import BPF
program = r"""
int hello(void *ctx) {
bpf_trace_printk("Hello World!");
return 0;
}
"""
b = BPF(text=program)
# Attach the uprobe to the getaddrinfo function in libc
libc_path = "/lib/x86_64-linux-gnu/libc.so.6"  # Path to libc
getaddrinfo_func = "getaddrinfo"  # Function name to trace

b.attach_uprobe(name=libc_path, sym=getaddrinfo_func, fn_name="hello")
b.trace_print()
