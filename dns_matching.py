#!/usr/bin/python

#  This code was partially taken from:
#  https://github.com/iovisor/bcc/blob/master/examples/networking/dns_matching/dns_matching.py

from __future__ import print_function
from bcc import BPF, lib
from ctypes import *

import os
import os.path
import subprocess

# import sys
import fcntl
import dnslib
import argparse
import dns.resolver
from time import time
from manage import get_map_fd, add_entry, delete_entry


def get_ipv4(domain):
    return [r.address for r in dns.resolver.resolve(domain, "A")]


def get_domains(domains_file_path):
    with open(domains_file_path, "r", encoding="utf-8") as domains_file:
        return [line.strip() for line in domains_file.readlines()]


def manage_ip(ip_address, prog_type):
    PROG_PATH = "./bin/manage"
    PROG_FILE = os.path.join(os.getcwd(), PROG_PATH)
    args = ["sudo", PROG_FILE, prog_type, ip_address]
    if prog_type == "add":
        args.append("1")
    return subprocess.run(args, capture_output=True, text=True).stdout.rstrip()


def block_ip(ip, map_fd):
    print("blocking", ip)
    add_entry(map_fd, ip, 1)
    # res = manage_ip(ip, "add")
    # print(res)
    # return res


def unblock_ip(ip, map_fd):
    print("unblocking", ip)
    delete_entry(map_fd, ip)
    # res = manage_ip(ip, "delete")
    # print(res)


def unblock_ips(ips, map_fd):
    for ip in ips:
        unblock_ip(ip, map_fd)


def encode_dns(name):
    if len(name) + 1 > 255:
        raise Exception("DNS Name too long.")
    b = bytearray()
    for element in name.split("."):
        sublen = len(element)
        if sublen > 63:
            raise ValueError("DNS label %s is too long" % element)
        b.append(sublen)
        b.extend(element.encode("ascii"))
    b.append(0)  # Add 0-len octet label for the root server
    return b


def add_cache_entry(cache, name):
    key = cache.Key()
    key_len = len(key.p)
    name_buffer = encode_dns(name)
    # Pad the buffer with null bytes if it is too short
    name_buffer.extend((0,) * (key_len - len(name_buffer)))
    key.p = (c_ubyte * key_len).from_buffer(name_buffer)
    leaf = cache.Leaf()
    leaf.p = (c_ubyte * 4).from_buffer(bytearray(4))
    cache[key] = leaf


def add_cache_entries(cache, names):
    N = len(names)
    K = len(cache.Key().p)
    Keys = (cache.Key * N)()
    Leafs = (cache.Leaf * N)()
    key_bufs, val_bufs = [], []

    for i, name in enumerate(names):
        b = bytearray(encode_dns(name)) + b"\0" * (K - len(name))
        kb = (c_ubyte * K).from_buffer_copy(b)
        key_bufs.append(kb)
        Keys[i].p = kb
        vb = (c_ubyte * 4).from_buffer_copy(b"\0" * 4)
        val_bufs.append(vb)
        Leafs[i].p = vb

    cnt = c_uint(N)
    time_updating_started = time()
    res = lib.bpf_map_update_batch(
        c_uint(cache.get_fd()),
        cast(Keys, c_void_p),
        cast(Leafs, c_void_p),
        byref(cnt),
        c_uint(0),
    )
    if res:
        raise OSError(f"batch update failed: {res}")
    return time() - time_updating_started


def get_ip_header_length(given_packet_bytearray, eth_hlen):
    ip_header_length = given_packet_bytearray[eth_hlen]  # load Byte
    ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
    ip_header_length = ip_header_length << 2  # shift to obtain length
    return ip_header_length


def get_payload_offset(given_packet_bytearray):
    ETH_HLEN = 14
    UDP_HLEN = 8

    return ETH_HLEN + get_ip_header_length(given_packet_bytearray, ETH_HLEN) + UDP_HLEN


def process_dns_answers(given_dns_answers, given_map_fd):
    for dns_answer in given_dns_answers:

        resolved_domain = str(dns_answer.rname).strip(".")
        domain_ip = str(dns_answer.rdata)

        print("answer:", resolved_domain, dns_answer.rtype, domain_ip)
        if domain_ip not in blocked_ips:
            blocked_ips.add(domain_ip)
            block_ip(domain_ip, given_map_fd)


def start_ip_blocker():
    print("\nstarted ip blocker")
    subprocess.run(["make"], capture_output=True)


def stop_ip_blocker():
    print("\nstopped ip blocker")
    subprocess.run(["make", "clean"], capture_output=True)


def add_domains_batched(given_domains, batch_size):
    total_domains_count = len(given_domains)
    added_domains_count = 0

    time_updating = 0

    for i in range(0, total_domains_count, batch_size):
        domains_batch = given_domains[i : i + batch_size]
        if added_domains_count % batch_size * 10 == 0:
            print(
                f"added domains: {added_domains_count:<10} {round(added_domains_count/total_domains_count * 100, 2):>4}%",
                end="\r",
                flush=True,
            )
        added_domains_count += batch_size

        try:
            time_updating += add_cache_entries(cache, domains_batch)
        except Exception as e:
            print(domains_batch)
            raise e
    print()

    time_updating = round(time_updating, 2)
    print(f"{time_updating = }")


def add_domains(given_domains):
    total_domains_count = len(given_domains)
    added_domains_count = 0
    for domain in given_domains:
        if added_domains_count % 10000 == 0:
            print(
                f"added domains: {added_domains_count} {round(added_domains_count/total_domains_count * 100, 2):>8}%",
                end="\r",
                flush=True,
            )
        added_domains_count += 1

        try:
            add_cache_entry(cache, domain)
        except Exception as e:
            print(domain)
            raise e


try:
    parser = argparse.ArgumentParser(
        usage="For detailed information about usage,\
   try with -h option"
    )
    req_args = parser.add_argument_group("Required arguments")
    req_args.add_argument(
        "-d",
        "--domains_path",
        type=str,
        required=True,
        help="A file with listed domains separated by new line",
    )
    args = parser.parse_args()

    bpf = BPF(src_file="dns_matching.c", debug=0, cflags=["-Wno-macro-redefined"])

    function_dns_matching = bpf.load_func("dns_matching", BPF.SOCKET_FILTER)

    # create raw socket, bind it to user provided interface
    # attach bpf program to socket created
    BPF.attach_raw_socket(function_dns_matching, "")

    # Get the table.
    cache = bpf.get_table("cache")

    print(args.domains_path)
    domains = get_domains(args.domains_path)

    time_adding_started = time()

    add_domains_batched(domains, batch_size=10000)

    time_adding = round(time() - time_adding_started, 2)
    print("time adding:", time_adding)

    start_ip_blocker()

    print("\nTry to lookup some domain names using nslookup from another terminal.")
    print("For example:  nslookup foo.bar")
    print("\nBPF program will filter-in DNS packets which match with map entries.")
    print("Packets received by user space program will be printed here")
    print("\nHit Ctrl+C to end...")

    socket_fd = function_dns_matching.sock
    fl = fcntl.fcntl(socket_fd, fcntl.F_GETFL)
    fcntl.fcntl(socket_fd, fcntl.F_SETFL, fl & (~os.O_NONBLOCK))

    iter = 0

    map_fd = get_map_fd()
    blocked_ips = set()
    total_processing_time = 0

    while 1:
        iter += 1
        # retrieve raw packet from socket
        print("waiting for packet:", iter)
        packet_str = os.read(socket_fd, 2048)
        print("processing packet:", iter)
        # continue
        processing_time_started = time()
        packet_bytearray = bytearray(packet_str)

        payload_offset = get_payload_offset(packet_bytearray)

        payload = packet_bytearray[payload_offset:]
        dnsrec = dnslib.DNSRecord.parse(payload)

        # print("dsn rec:", dnsrec)

        # print("DNS Answer Section:")
        dns_answers = [dns_answer for dns_answer in dnsrec.rr if dns_answer.rtype == 1]
        for dns_question in dnsrec.questions:
            if dns_question.qtype != 1:
                continue
            print("question:", dns_question)

        process_dns_answers(dns_answers, map_fd)

        # print()
        processing_time = time() - processing_time_started
        total_processing_time += processing_time
        print(f"{processing_time = }")
        print(f"{total_processing_time = }")
        print(f"{blocked_ips = }")
        print()


except BaseException as e:
    stop_ip_blocker()
    if not isinstance(e, KeyboardInterrupt):
        raise e
