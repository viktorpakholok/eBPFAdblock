import sys
import ctypes
from bcc import libbcc
from socket import inet_pton, AF_INET


def get_map_fd():
    map_fd = bpf_obj_get("/sys/fs/bpf/xdp/map")
    if map_fd < 0:
        print("Failed to open BPF map")
        sys.exit(1)
    return map_fd


def bpf_obj_get(path):
    return libbcc.lib.bpf_obj_get(bytes(path, "utf-8"))


def ip_to_u32(ip_str):
    return ctypes.c_uint32(
        int.from_bytes(inet_pton(AF_INET, ip_str), byteorder="little")
    )


# def show_map(map_fd):
#     # Example, real code needs bpf syscall wrappers
#     print("Showing map entries...")


def add_entry(map_fd, ip_str, value=1):
    key = ip_to_u32(ip_str)
    val = ctypes.c_uint64(value)
    res = libbcc.lib.bpf_update_elem(map_fd, ctypes.byref(key), ctypes.byref(val), 0)
    if res != 0:
        print("Failed to add entry")


def delete_entry(map_fd, ip_str):
    key = ip_to_u32(ip_str)
    res = libbcc.lib.bpf_delete_elem(map_fd, ctypes.byref(key))
    if res != 0:
        print("Failed to delete entry")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <action> <args>")
        print("Actions: add <ip> <value>, delete <ip>, show")
        sys.exit(1)

    map_fd = get_map_fd()

    action = sys.argv[1]
    # if action == "show":
    #     show_map(map_fd)
    if action == "add" and len(sys.argv) == 4:
        ip, value = sys.argv[2], int(sys.argv[3])
        add_entry(map_fd, ip, value)
    elif action == "delete" and len(sys.argv) == 3:
        ip = sys.argv[2]
        delete_entry(map_fd, ip)
    else:
        print(f"Invalid usage. Usage: {sys.argv[0]} <action> <args>")
        print("Actions: add <ip> <value>, delete <ip>, show")
        sys.exit(1)
