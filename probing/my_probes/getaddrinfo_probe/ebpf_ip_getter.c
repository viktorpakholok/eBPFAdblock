#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BUFFER_SIZE 50
struct addrinfo {
	int ai_flags;
	int ai_family; 
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe//usr/lib/x86_64-linux-gnu/libc.so.6:getaddrinfo")
int BPF_UPROBE(getaddrinfo, const char *node, const char *service,
                              const struct addrinfo *hints, struct addrinfo **res) {
    bpf_printk("UPROBE(getaddrinfo)");
    

    if (hints) {
        int ai_family;
	long res = bpf_probe_read_user(&ai_family, sizeof(ai_family), (void *)((char *)hints + sizeof(int)));
	if (res < 0) {
	    bpf_printk("res: %ld", res);
	}
	else {
		bpf_printk("ai_family: %d", ai_family);
	}

    } else {
        bpf_printk("hints: (null)");
    }

    char node_str[BUFFER_SIZE];
    char service_name[BUFFER_SIZE];

    if (node) {
        long ret = bpf_probe_read_user_str(node_str, sizeof(node_str), node);
        if (ret > 0) {
            bpf_printk("node: %s", node_str);
        } else {
            bpf_printk("Failed to read node: ret=%ld", ret);
        }
    } else {
        bpf_printk("node: (null)");
    }
    if (service) {
        long ret = bpf_probe_read_user_str(service_name, sizeof(service_name), service);
        if (ret > 0) {
            bpf_printk("service: %s", service_name);
        } else {
            bpf_printk("Failed to read service: ret=%ld", ret);
        }
    } else {
        bpf_printk("service: (null)\n");
    }
    
    return 0;
}




