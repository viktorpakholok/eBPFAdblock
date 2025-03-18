#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>  // FIX: Include this for bpf_obj_get()

#define EVENTS_PATH "/sys/fs/bpf/events"

struct event_t {
    int key;
    int action;
};


int handle_event(void *ctx, void *data, size_t data_size) {
    (void)ctx;         //(?)
    (void)data_size;   //(?)

    struct event_t *event = data;
    const char *action_str = (event->action == 1) ? "READ" : "WRITE";
    printf("Interaction: Key=%d, Action=%s\n", event->key, action_str);

    return 0;
}

int main() {
    int ringbuf_fd = bpf_obj_get(EVENTS_PATH);
    if (ringbuf_fd < 0) {
        perror("Failed to open events map");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(ringbuf_fd, handle_event, NULL, NULL);
    if (!rb) {
        perror("Failed to create ring buffer");
        return 1;
    }

    while (1) {
        ring_buffer__poll(rb, -1);
    }

    return 0;
}
