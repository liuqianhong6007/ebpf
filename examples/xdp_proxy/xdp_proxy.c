// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include "bpf_helpers.h"

#define htons(x) __constant_htons((x))

char __license[] SEC("license") = "GPL";

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	bpf_printk("enter xdp_prog process\n");
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__be16 h_proto;
	__u64 nh_off;
	__u32 ipproto;
	__be32 saddr,daddr;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		goto pass_packet;

	h_proto = eth->h_proto;

	/* Handle IP packet */
	if (h_proto == htons(ETH_P_IP)){
		struct iphdr *iph = data + nh_off;
		nh_off += sizeof(struct iphdr);
		if (data + nh_off > data_end)
			goto drop_packet;
		ipproto = iph->protocol;
		saddr = iph->saddr;
		daddr = iph->daddr;

	}else if (h_proto == htons(ETH_P_IPV6)){
		struct ipv6hdr *ip6h = data + nh_off;
		nh_off += sizeof(struct iphdr);
		if (data + nh_off > data_end)
			goto drop_packet;
		ipproto = ip6h->nexthdr;

	}else{
		goto pass_packet;
	}

	/* Handle UDP packet */
	if (ipproto != IPPROTO_UDP)
		goto pass_packet;

	bpf_printk("saddr: %d,daddr: %d",saddr,daddr);	

pass_packet:
        bpf_printk("a packet passed\n");
	return XDP_PASS;

drop_packet:
        bpf_printk("a packet dropped\n");
        return XDP_DROP;
}
