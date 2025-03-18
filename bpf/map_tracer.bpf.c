#define __TARGET_ARCH_x86

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/version.h>

struct event_t {
    int key;
    int action;
};

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events;

SEC("kprobe/__x64_sys_bpf")
int trace_map_ops(struct pt_regs *ctx) {
    struct event_t *event;
    int cmd;


    cmd = (int)PT_REGS_PARM1(ctx);

    if (cmd == BPF_MAP_UPDATE_ELEM || cmd == BPF_MAP_LOOKUP_ELEM) {
        event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if (!event)
            return 0;

        event->key = 1; // to bereplaced
        event->action = (cmd == BPF_MAP_UPDATE_ELEM) ? 2 : 1;

        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
