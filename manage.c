#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_DOMAIN_LEN 254

struct domain_name {
    char name[MAX_DOMAIN_LEN];
};


static int open_map(const char *path) {
    int fd = bpf_obj_get(path);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    return fd;
}


void show_ip_map(int map_fd) {
    uint32_t key, next_key;
    uint8_t value;
    key = next_key = 0;

    printf("Showing all ip_map entries:\n");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        key = next_key;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &key, ip_str, sizeof(ip_str));
            printf("%s\n", ip_str);
        }
        key = next_key;
    }
}

void add_ip(int map_fd, const char *ip_str) {
    uint32_t key = inet_addr(ip_str);
    uint8_t value = 1;

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
        perror("Failed to add entry");
        exit(1);
    }

    printf("Added IP adress: %s\n", ip_str);
}

void delete_ip(int map_fd, const char *ip_str) {
    uint32_t key = inet_addr(ip_str);

    if (bpf_map_delete_elem(map_fd, &key) < 0) {
        perror("Failed to delete entry");
        exit(1);
    }

    printf("Deleted: Key = %s\n", ip_str);
}


//functions for managing domain map
void show_domain_map(int map_fd) {
    struct domain_name key = {};
    struct domain_name next_key;
    uint8_t value;

    printf("Showing all domain_map entries:\n");
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        memcpy(&key, &next_key, sizeof(key));
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 && value == 1) {
            printf("%s\n", key.name);
        }
    }
}

void add_domain(int map_fd, const char *domain) {
    struct domain_name key = {};
    strncpy(key.name, domain, MAX_DOMAIN_LEN - 1);
    uint8_t value = 1;

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) < 0) {
        perror("Failed to add this domain");
        exit(1);
    }
    printf("Added domain: %s\n", key.name);
}

void delete_domain(int map_fd, const char *domain) {
    struct domain_name key = {};
    strncpy(key.name, domain, MAX_DOMAIN_LEN - 1);

    if (bpf_map_delete_elem(map_fd, &key) < 0) {
        perror("Failed to delete this domain");
        exit(1);
    }
    printf("Deleted domain: %s\n", key.name);
}



int main(int argc, char **argv) {
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <action> <args>\n", argv[0]);
        fprintf(stderr, "Actions for ip_map: add_ip <ip>, delete <ip_ip>, show_ip_map\n");
        fprintf(stderr, "Actions for domain_map: add_domain <domain_name>, delete_domain <domain_name>, show_domain_map\n");
        return 1;
    }

    int ip_fd  = bpf_obj_get("/sys/fs/bpf/xdp/ip_map");
    int dom_fd = bpf_obj_get("/sys/fs/bpf/xdp/domain_map");

    if (ip_fd < 0 || dom_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    if (strcmp(argv[1], "show_ip_map") == 0) {
        show_ip_map(ip_fd);
    } else if (strcmp(argv[1], "add_ip") == 0 && argc == 3) {
        const char *ip_str = argv[2];
        add_ip(ip_fd, ip_str);
    } else if (strcmp(argv[1], "delete_ip") == 0 && argc == 3) {
        const char *ip_str = argv[2];
        delete_ip(ip_fd, ip_str);

    } else if (strcmp(argv[1], "show_domain_map") == 0) {
        show_domain_map(dom_fd);
    } else if (strcmp(argv[1], "add_domain") == 0 && argc == 3) {
        add_domain(dom_fd, argv[2]);
    } else if (strcmp(argv[1], "delete_domain") == 0 && argc == 3) {
        delete_domain(dom_fd, argv[2]);
        
    } else {
        fprintf(stderr, "Invalid usage. Usage: %s <action> <args>\n", argv[0]);
        fprintf(stderr, "Actions for ip_map: add_ip <ip>, delete_ip <ip>, show_ip_map\n");
        fprintf(stderr, "Actions for domain_map: add_domain <domain_name>, delete_domain <domain_name>, show_domain_map\n");
        return 1;
    }
    return 0;
}
