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
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_endian.h>        /* for bpf_htons */
#endif

#undef bpf_printk
#define bpf_printk(fmt, ...)                                \
({                                                          \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                    \
})

#ifndef __BCC__
#define ETH_P_IP   0x0800          /* copied from if_ether.h */
#endif

char _license[] SEC("license") = "GPL";

struct event {
	__u32 src;
	__u16 sport;
	__u32 dst;
	__u16 dport;
};

#ifdef __BCC__
BPF_RINGBUF_OUTPUT(buffer, 16);
#else
// struct bpf_map_def SEC("maps") buffer = {
//     .type = BPF_MAP_TYPE_RINGBUF,
//     .max_entries = 1 << 4,
// };
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64); /* <https://stackoverflow.com/q/63415220/2812207> ¯\_(ツ)_/¯ */
} buffer SEC(".maps");
#endif

SEC("xdp_tcp_count")
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
						if (tcp->syn) {
							struct event e = {};
							e.src = (int)ip->saddr;
							e.sport = (int)bpf_htons(tcp->source);
							e.dst = (int)ip->daddr;
							e.dport = (int)bpf_htons(tcp->dest);
#ifdef __BCC__
							buffer.ringbuf_output(&e, sizeof(e), 0);
#else
                            bpf_printk("src: %d, dst: %d\n",
                                (int)ip->saddr,
                                (int)ip->daddr
                            );

                            /*
                            bpf_ringbuf_output(&buffer, &e, sizeof(e), 0);
							bpf_ringbuf_discard(&e, 0);
                            */
#endif
						}
					}
				}
			}
		}
	}
	return XDP_PASS;
}

