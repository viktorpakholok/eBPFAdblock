# eBPFAdblock


### Compilation and attachment of XDP program
`make`


### Usage
Adding ip addresses which should be blocked:<br>
`sudo bin/manage add <ip-address> 1`

Deleting ip addresses which should be blocked:<br>
`sudo bin/manage delete <ip-address>`

Adding/deleting ip addresses from file. ip addresses should be separated by '\n':<br>
`sudo python3 map_ip_adder.py <file_path> <add | delete>`

Showing ip addresses from the map:<br>
`sudo bin/manage show`

Testing:<br>
`ping <blocked-ip-address>`


### Detachment of XDP program<br>
`make clean`
