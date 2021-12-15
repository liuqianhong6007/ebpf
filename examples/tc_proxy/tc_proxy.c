// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	bpf_printk("enter cls_main\n");
	return -1;
}


SEC("tc")
int tc_proxy_prog(struct __sk_buff *skb)
{
	bpf_printk("enter tc_proxy_prog\n");

	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end) {
		bpf_printk("not ethernet package\n");
		return TC_ACT_OK;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		bpf_printk("not ipv4 package\n");
		return TC_ACT_OK;
	}

	struct iphdr *iph = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		bpf_printk("not ip package\n");
		return TC_ACT_OK;
	}

	if (iph->protocol != IPPROTO_IPIP) {
		bpf_printk("not ip package\n");
		return TC_ACT_OK;
	}
	
	bpf_printk("an ip package pass\n");
	return TC_ACT_OK;
}

