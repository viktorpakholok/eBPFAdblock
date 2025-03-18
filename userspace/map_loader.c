#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <bpf/libbpf.h>

#define MAP_PATH "/sys/fs/bpf/my_map"

static int bpf_syscall(int cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main() {
    int fd;

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 1024,
        .map_flags = 0,
    };

    fd = bpf_syscall(BPF_MAP_CREATE, &attr);
    if (fd < 0) {
        perror("Failed to create BPF map");
        return 1;
    }

    printf("BPF map created successfully (fd = %d)\n", fd);


    if (bpf_obj_pin(fd, MAP_PATH) < 0) {
        perror("Failed to pin BPF map");
        return 1;
    }

    printf("BPF map pinned at %s\n", MAP_PATH);

    return 0;
}
