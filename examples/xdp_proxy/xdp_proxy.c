// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include "bpf_helpers.h"

#define htons(x) __constant_htons((x))

char __license[] SEC("license") = "GPL";

struct backend_server{
	__u32 addr;
	__u16 port;
	__u16 padding;
};

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct backend_server),
	.value_size = sizeof(struct backend_server),
	.max_entries = 2048,
};


SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__be16 h_proto;
	__u64 nh_off;
	__be32 saddr = 0,daddr = 0;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_PASS;

	h_proto = eth->h_proto;
	
	/* Only handle IPV4 packet */	
	if  (h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* Handle IPV4 packet */
	struct iphdr *iph = data + nh_off;
	nh_off += sizeof(struct iphdr);
	if (data + nh_off > data_end)
		return XDP_PASS;
	saddr = iph->saddr;
	daddr = iph->daddr;

	/* Only Handle UDP packet */	
	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* Handle UDP packet */
	struct udphdr *udph = data + nh_off;
	nh_off += sizeof(struct udphdr);
	if (data + nh_off > data_end)
		return XDP_PASS;

	/* Match backend server */
	struct backend_server key={};
	key.addr = iph->daddr;
	key.port = udph->dest;
	void *val = bpf_map_lookup_elem(&proxy_map,&key);
	if (!val){
		bpf_printk("backend server not found: addr[%u],port[%u]\n",key.addr,key.port);
		return XDP_PASS;
	}
	struct backend_server *b_server = (struct backend_server*)(val);
	if (b_server->addr == 0 || b_server->port == 0){
                bpf_printk("backend server info error\n");
                return XDP_PASS;
        }
	

	bpf_printk("pass an udp packet: saddr=%u, daddr=%u\n",saddr,daddr);
	return XDP_PASS;

}

