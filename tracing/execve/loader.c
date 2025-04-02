// loader.c
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    fprintf(stdout, "argc: %d\n", argc);
    if (argc != 3) {
        fprintf(stderr, "Wrong number of arguments\n");
        return 1;
    }
    fprintf(stdout, "%s\n", argv[1]);
    char *filename = argv[1];
    char *progname = argv[2];
    struct bpf_object *obj;
    int err;

    // Load the eBPF object file
    obj = bpf_object__open_file(filename, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    // Load the program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    // Attach the program to the tracepoint
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, progname);
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program FD\n");
        return 1;
    }

    struct bpf_link *tp_link = bpf_program__attach(prog);
    if (libbpf_get_error(tp_link)) {
        fprintf(stderr, "Failed to attach BPF program: %ld\n", libbpf_get_error(tp_link));
        return 1;
    }

    printf("eBPF program attached. Check logs via:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace\n");

    // Keep the program running
    sleep(99999);
    return 0;
}

