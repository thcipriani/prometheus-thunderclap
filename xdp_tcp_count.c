#ifdef BCC_SEC
#define __BCC__
#endif

#ifdef __BCC__
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#else /* __BCC__ */
#include "vmlinux.h"               /* all kernel types */
#include <bpf/bpf_core_read.h>     /* BPF_CORE_READ_BITFIELD_PROBED */
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_endian.h>        /* for bpf_htons */
#endif

#ifndef __BCC__
#define ETH_P_IP   0x0800          /* copied from if_ether.h */
#endif

#ifndef __BCC__
char _license[] SEC("license") = "GPL";
#endif

struct event {
	u32 src;
	u16 sport;
	u32 dst;
	u16 dport;
};

#ifdef __BCC__
BPF_RINGBUF_OUTPUT(buffer, 16);
#else
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	/* <https://stackoverflow.com/q/63415220/2812207> ¯\_(ツ)_/¯ */
    __uint(max_entries, 4096);
} buffer SEC(".maps");
#endif

static u64 get_syn_data(const struct tcphdr *tcp) {
#ifdef __BCC__
    return tcp->syn;
#else
    return BPF_CORE_READ_BITFIELD(tcp, syn);
#endif
}

#ifndef __BCC__
SEC("xdp_tcp_count")
#endif
int xdp_new_tcp_count(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	// Do we have an ethernet packet?
	if ((void *)(eth) + sizeof(*eth) <= data_end) {

		// Is it using the ip protocol?
		if (eth->h_proto == bpf_htons(ETH_P_IP)) {

			struct iphdr *ip = data + sizeof(*eth);
			if ((void *)ip + sizeof(*ip) <= data_end ) {

				// Does it contain a tcp segment?
				if (ip->protocol == IPPROTO_TCP) {
					struct tcphdr *tcp = (void *)ip + sizeof(*ip);
					if ((void *)tcp + sizeof(*tcp) <= data_end) {
                        // Is it a new packet?
						if (get_syn_data(tcp)) {
#ifdef __BCC__
							struct event e = {};
							e.src = (int)ip->saddr;
							e.sport = (int)bpf_htons(tcp->source);
							e.dst = (int)ip->daddr;
							e.dport = (int)bpf_htons(tcp->dest);
							buffer.ringbuf_output(&e, sizeof(e), 0);
#else
							struct event * const e = bpf_ringbuf_reserve(&buffer, sizeof(*e), 0);
							if (!e) {
								return XDP_PASS;
							}
							e->src = (int)ip->saddr;
							e->sport = (int)bpf_htons(tcp->source);
							e->dst = (int)ip->daddr;
							e->dport = (int)bpf_htons(tcp->dest);
                            bpf_ringbuf_submit(e, 0);
#endif
						}
					}
				}
			}
		}
	}
	return XDP_PASS;
}
