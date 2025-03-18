### Installation
[ecc_ecli_installation](https://github.com/eunomia-bpf/eunomia-bpf?tab=readme-ov-file#install-the-project)<br>
here are commands from the link above:

<code>
wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli<br>
sudo ./ecli run https://eunomia-bpf.github.io/eunomia-bpf/sigsnoop/package.json<br>
wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc<br>
./ecc -h</code>


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

