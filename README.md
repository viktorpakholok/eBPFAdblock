# eBPFAdblock


### Compilation and attachment of XDP program
`make`


### Usage
Adding/deleting ip addresses which should be blocked:<br>
`sudo bin/manage <add/delete> <ip-address> 1`

Adding/deleting ip addresses from file. ip addresses should be separated by '\n':<br>
`sudo python3 map_ip_adder.py ip_file.txt <add or delete>`

Showing ip addresses from the map:<br>
`sudo bin/manage show`

Testing:
`ping <blocked-ip-address>`


### Detachment of XDP program<br>
`make clean`
