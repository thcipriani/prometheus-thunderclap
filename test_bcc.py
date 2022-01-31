#!/usr/bin/env python

import sys
import time

from bcc import BPF

DEVICE = sys.argv[1]
if not DEVICE:
    print('Usage: python3 test.py <device>')
    sys.exit(1)

def ip_from_be32(ipaddr):
    ip = []
    for i in range(0, 25, 8):
        ip.append((ipaddr >> i) & 0xff)
    return '.'.join(map(str, ip))

def callback(ctx, data, size):
    event = b['buffer'].event(data)
    print('src: {}:{}; dst: {}:{}'.format(
        ip_from_be32(event.src),
        event.sport,
        ip_from_be32(event.dst),
        event.dport
    ))

with open('xdp_tcp_count.c') as f:
    bpf_c = f.read()

b = BPF(text=bpf_c)
print('Compiled BPF')
fn = b.load_func('xdp_new_tcp_count', BPF.XDP)
b.attach_xdp(DEVICE, fn, 0)
print(f'Attached to "{DEVICE}"')
b['buffer'].open_ring_buffer(callback)

while True:
    try:
        b.ring_buffer_consume()
        time.sleep(0.5)
    except KeyboardInterrupt:
        b.remove_xdp(DEVICE, 0)
        sys.exit(0)
