#!/bin/bash

# hardcoded IP handling
echo "Building and attaching program..."
make
make install

echo "Adding hardcoded IP to block..."
sudo bin/manage add IP_TO_BLOCK 1

if [ -f all_ips.txt ]; then
    sudo python3 map_ip_adder.py all_ips.txt add
else
    echo "File all_ips.txt not found. Skipping."
fi



# domains handling
echo "Running domain parser"
python3 ./domain_parser.py

echo "Running DNS matching"
sudo python3 dns_matching.py -d "all_domains.txt"


echo "Detaching and cleaning up..."
make clean

echo "Success."