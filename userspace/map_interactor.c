#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#define MAP_PATH "/sys/fs/bpf/my_map"

int main() {
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open map");
        return 1;
    }

    int key = 1, value = 42;
    while (1) {
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
            perror("Failed to write to map");
        } else {
            printf("Wrote: Key=%d, Value=%d\n", key, value);
        }


        int read_value;
        if (bpf_map_lookup_elem(map_fd, &key, &read_value) == 0) {
            printf("Read: Key=%d, Value=%d\n", key, read_value);
        } else {
            perror("Failed to read from map");
        }

        sleep(1);
    }

    return 0;
}
