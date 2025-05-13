#!/bin/bash


echo "Installing dependencies..."

make install


if [ -f all_ips.txt ]; then
    make
    sudo python3 map_ip_adder.py all_ips.txt add
else
    echo "File all_ips.txt not found. Skipping."
fi


# domains handling
echo "Running domain parser"
python3 ./domain_parser.py

echo "Running DNS matching"
sudo python3 dns_matching.py -d "all_domains.txt"


echo "Success."