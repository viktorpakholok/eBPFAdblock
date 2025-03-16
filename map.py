#!/usr/bin/python
from bcc import BPF
import struct
import socket
import argparse

bpf = BPF(src_file="map_ebpf.c",  cflags=["-I/usr/include/bpf", "-I/usr/include/x86_64-linux-gnu", "-I/usr/include/linux"])
ip_map = bpf["ip_map"]
def ip_to_u32(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0] #Converts an IPv4 string to a 32-bit integer.

def u32_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int)) #Converts a 32-bit integer to an IPv4 string.

def add_ip(ip_str):
    ip_int = ip_to_u32(ip_str)
    ip_map[ip_int] = 1
    print(f"Added IP: {ip_str} ({ip_int})")

def delete_ip(ip_str):
    ip_int = ip_to_u32(ip_str)
    if ip_int in ip_map:
        del ip_map[ip_int]
        print(f"Deleted IP: {ip_str}")
    else:
        print(f"IP {ip_str} not found in map.")

def show_ips():
    print("Stored IPv4 Addresses:")
    for key, value in ip_map.items():
        print(f"- {u32_to_ip(key)} (Count: {value})")

parser = argparse.ArgumentParser(description="Manage eBPF Hash Table (IPv4).")
parser.add_argument("--add", type=str, help="Add an IPv4 address")
parser.add_argument("--delete", type=str, help="Delete an IPv4 address")
parser.add_argument("--show", action="store_true", help="Show all stored IPs")

args = parser.parse_args()

if args.add:
    add_ip(args.add)
elif args.delete:
    delete_ip(args.delete)
elif args.show:
    show_ips()
else:
    parser.print_help()
