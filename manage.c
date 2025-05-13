#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void show_map(int map_fd)
{
    uint32_t key, next_key;
    uint64_t value;
    key = next_key = 0;

    printf("Showing all map entries:\n");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
    {
        key = next_key;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
        {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &key, ip_str, sizeof(ip_str));
            printf("Key: %s, Value: %lu\n", ip_str, value);
        }
        key = next_key;
    }
}

void add_entry(int map_fd, const char *ip_str, uint64_t value)
{
    uint32_t key = inet_addr(ip_str);

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0)
    {
        perror("Failed to add entry");
        exit(1);
    }

    printf("Added: Key = %s, Value = %lu\n", ip_str, value);
}

void delete_entry(int map_fd, const char *ip_str)
{
    uint32_t key = inet_addr(ip_str);

    if (bpf_map_delete_elem(map_fd, &key) < 0)
    {
        perror("Failed to delete entry");
        exit(1);
    }

    printf("Deleted: Key = %s\n", ip_str);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <action> <args>\n", argv[0]);
        fprintf(stderr, "Actions: add <ip> <value>, delete <ip>, show\n");
        return 1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp/map");
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    if (strcmp(argv[1], "show") == 0)
    {
        show_map(map_fd);
    }
    else if (strcmp(argv[1], "add") == 0 && argc == 4)
    {
        const char *ip_str = argv[2];
        uint64_t value = strtoull(argv[3], NULL, 10);
        add_entry(map_fd, ip_str, value);
    }
    else if (strcmp(argv[1], "delete") == 0 && argc == 3)
    {
        const char *ip_str = argv[2];
        delete_entry(map_fd, ip_str);
    }
    else
    {
        fprintf(stderr, "Invalid usage. Usage: %s <action> <args>\n", argv[0]);
        fprintf(stderr, "Actions: add <ip> <value>, delete <ip>, show\n");
        return 1;
    }

    return 0;
}
