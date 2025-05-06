#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *

import os
import os.path
import subprocess
import sys
import fcntl
import dnslib
import argparse
import dns.resolver
from time import time

def get_ipv4(domain):
    return [r.address for r in dns.resolver.resolve(domain, "A")]

def get_domains(domains_file_path):
  with open(domains_file_path, "r", encoding="utf-8") as domains_file:
    return [line.strip() for line in domains_file.readlines()]

def manage_ip(ip_address, prog_type):
  PROG_PATH = "./bin/manage"
  PROG_FILE = os.path.join(os.getcwd(), PROG_PATH)
  args = ["sudo", PROG_FILE, prog_type, ip_address]
  if (prog_type == "add") :
      args.append("1")
  return subprocess.run(args, capture_output=True, text=True).stdout.rstrip()

def block_ip(ip):
  print("blocking", ip)
  res = manage_ip(ip, "add")
  print(res)

def unblock_ip(ip):
  print("unblocking", ip)
  res = manage_ip(ip, "delete")
  print(res)

def unblock_ips(ips):
  for ip in ips:
    unblock_ip(ip)


def encode_dns(name):
  if len(name) + 1 > 255:
    raise Exception("DNS Name too long.")
  b = bytearray()
  for element in name.split('.'):
    sublen = len(element)
    if sublen > 63:
      raise ValueError('DNS label %s is too long' % element)
    b.append(sublen)
    b.extend(element.encode('ascii'))
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

def start_ip_blocker():
    print("\nstarted ip blocker")
    subprocess.run(["make"], capture_output=True)

def stop_ip_blocker():
    print("\nstopped ip blocker")
    subprocess.run(["make", "clean"], capture_output=True)

parser = argparse.ArgumentParser(usage='For detailed information about usage,\
 try with -h option')
req_args = parser.add_argument_group("Required arguments")
req_args.add_argument("-d", "--domains_path", type=str, required=True,
    help='A file with listed domains separated by new line')
args = parser.parse_args()

# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "dns_matching.c", debug=0)
# print(bpf.dump_func("dns_test"))

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_dns_matching = bpf.load_func("dns_matching", BPF.SOCKET_FILTER)


#create raw socket, bind it to user provided interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_dns_matching, "")

# Get the table.
cache = bpf.get_table("cache")

print(args.domains_path)
domains = get_domains(args.domains_path)
# Add cache entries
for e in domains:
  print(">>>> Adding map entry: ", e)
  add_cache_entry(cache, e)

start_ip_blocker()

print("\nTry to lookup some domain names using nslookup from another terminal.")
print("For example:  nslookup foo.bar")
print("\nBPF program will filter-in DNS packets which match with map entries.")
print("Packets received by user space program will be printed here")
print("\nHit Ctrl+C to end...")

socket_fd = function_dns_matching.sock
fl = fcntl.fcntl(socket_fd, fcntl.F_GETFL)
fcntl.fcntl(socket_fd, fcntl.F_SETFL, fl & (~os.O_NONBLOCK))


last_domains = {"": time()}
iter = 0 
blocked_ips = set()
total_processing_time = 0

while 1:
  iter += 1 
  print("processed packets:", iter)
  #retrieve raw packet from socket
  try:
    packet_str = os.read(socket_fd, 2048)
  except KeyboardInterrupt:
    # unblock_ips(blocked_ips)
    stop_ip_blocker()
    sys.exit(0)
  processing_time_started = time()
  last_domains_copy = {domain: domain_time for domain, domain_time in last_domains.items()}
  for domain, domain_time in last_domains.items():
    if time() - domain_time > 0.5:
      del last_domains_copy[domain]
  last_domains = last_domains_copy
  packet_bytearray = bytearray(packet_str)

  ETH_HLEN = 14
  UDP_HLEN = 8

  #IP HEADER
  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + UDP_HLEN

  payload = packet_bytearray[payload_offset:]
  dnsrec = dnslib.DNSRecord.parse(payload)

  print("rec", dnsrec)
  print("last domains", last_domains)
  print(f"{blocked_ips = }")
  
  for q in dnsrec.questions:
    if q.qtype != 1:
      continue
  
    domain = str(q.qname).strip(".")
    if domain in last_domains:
      print("skipped", last_domains)
      #last_domains.remove(domain)
      continue
    last_domains[domain] = time()

    domain_ips = get_ipv4(domain)
    # print()
    for domain_ip in domain_ips:
      if domain_ip not in blocked_ips:
        blocked_ips.add(domain_ip)
        block_ip(domain_ip)
  processing_time = time() - processing_time_started
  total_processing_time += processing_time
  print(f"{processing_time = }")
  print(f"{total_processing_time = }")
  print()
      
