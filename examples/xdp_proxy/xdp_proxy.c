// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#define htons(x) __constant_htons((x))

char __license[] SEC("license") = "GPL";

struct backend_server_key{
	__u32 server_id;
};

struct backend_server{
	__u32 addr;
	__u16 port;
	__u16 padding;
};

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct backend_server),
	.max_entries = 2048,
};

static __always_inline backend_server_key get_backend_server_key(__be16 port){
    return struct backend_server_key{.server_id = port - 30000 > 0? (__u32) port - 30000: 0}
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 nh_off;
	__be32 saddr = 0, daddr = 0;
	__be16 /*sport = 0,*/ dport = 0;
	struct backend_server_key key;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_PASS;

	/* Only handle IPV4 packet */	
	if  (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = data + nh_off;
	nh_off += sizeof(struct iphdr);
	if (data + nh_off > data_end)
		return XDP_DROP;
	saddr = iph->saddr;
	daddr = iph->daddr;

	/* Only Handle TCP packet */	
	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	struct tcphdr *tcph = data + nh_off;
	nh_off += sizeof(struct tcphdr);
	if (data + nh_off > data_end)
		return XDP_DROP;

	//sport = tcph->source;
	dport = tcph->dest;


	/* Match backend server */
	key = get_backend_server_key(dport);
	void *val = bpf_map_lookup_elem(&proxy_map,&key);
	if (!val){
		bpf_printk("backend server not found: key=%u\n",key);
		return XDP_DROP;
	}
	struct backend_server *b_server = (struct backend_server*)(val);
	if (b_server->addr == 0 || b_server->port == 0){
                bpf_printk("backend server info error\n");
                return XDP_PASS;
        }
	

	bpf_printk("pass an tcp packet: saddr=%u, daddr=%u\n",saddr,daddr);
	return XDP_PASS;

}

