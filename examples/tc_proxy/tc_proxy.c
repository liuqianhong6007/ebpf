// +build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("proxy")
int _proxy(struct __sk_buff *skb)
{
	char msg[] = "enter xxxxxxxxx";
	bpf_trace_printk(msg, sizeof(msg));

	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end) {
		char fmt4[] = "not ethernet package";
		bpf_trace_printk(fmt4, sizeof(fmt4));
		return TC_ACT_OK;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		char fmt4[] = "not ipv4 package";
		bpf_trace_printk(fmt4, sizeof(fmt4));
		return TC_ACT_OK;
	}

	struct iphdr *iph = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		char fmt4[] = "not ip package";
		bpf_trace_printk(fmt4, sizeof(fmt4));
		return TC_ACT_OK;
	}

	if (iph->protocol != IPPROTO_IPIP) {
		char fmt4[] = "not ip package";
		bpf_trace_printk(fmt4, sizeof(fmt4));
		return TC_ACT_OK;
	}
	
	char fmt4[] = "an ip package pass";
	bpf_trace_printk(fmt4, sizeof(fmt4));
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
