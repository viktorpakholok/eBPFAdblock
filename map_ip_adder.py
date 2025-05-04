# import sys
import os.path
import subprocess
from sys import argv


def manage_ip(ip_address, prog_type):
    PROG_PATH = "./bin/manage"
    PROG_FILE = os.path.join(os.getcwd(), PROG_PATH)
    args = ["sudo", PROG_FILE, prog_type, ip_address]
    print(args)
    return subprocess.run(args, capture_output=True, text=True).stdout.rstrip().split("\n")


if __name__ == "__main__":
    IP_FILE = argv[1]
    PROG_TYPE = argv[2]
    print(argv)
    with open(IP_FILE, "r", encoding="utf-8") as ip_file:
        for line in ip_file.readlines():
            ip_address = line.strip()

            print(f"'{ip_address}'")
            print(manage_ip(ip_address, PROG_TYPE))
