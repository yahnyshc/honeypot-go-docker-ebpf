#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <stdio.h>
#define ntohs(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 length;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct packet_info);
} packet_map SEC(".maps");


SEC("xdp")
int xdp_packet_inspector(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    // Check if packet is large enough for ETH header
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Only intercept IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP)){
        return XDP_PASS;
    }

    // Check if packet is large enough for IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct packet_info pkt_info = {
        .src_ip = ntohl(ip->saddr),
        .dst_ip = ntohl(ip->daddr),
        .length = ntohs(ip->tot_len),
        .src_port = 0,
        .dst_port = 0,
    };

    // Calculate transport header offset
    void *transport_header = data + sizeof(*eth) + (ip->ihl * 4);
    if (transport_header > data_end) {
        return XDP_PASS;
    }

    // Check for TCP or UDP protocol and extract ports
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = transport_header;
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        pkt_info.src_port = ntohs(tcp->source);
        pkt_info.dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = transport_header;
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        pkt_info.src_port = ntohs(udp->source);
        pkt_info.dst_port = ntohs(udp->dest);
    }

    __u32 key = bpf_get_prandom_u32() % 1024;  // Unique key for each packet
    bpf_map_update_elem(&packet_map, &key, &pkt_info, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";