### Info
1. I created c file ip_getter.c which uses getaddrinfo for testing how my uprobe works
2. this file is compiled into ./test
3. ebpf_ip_getter.c is used for uprobbing getaddrinfo.
4. ebpf_udp_sendmsg.c just has kprobe for udp_sendmsg and sendto.
5. I did this to see whether firefox browther uses upd_sendmsg and later decided to probe sendto

### compilation and attachment
for ebpf_udp_sendmsg.c<br>
sh ./compile.sh

for ebpf_ip_getter.c<br>
sh ./compile_getaddrinfo.c<br>

### tracing
sh ./show_trace.sh

